#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <dlfcn.h>
#include <fstream>
#include <mutex>
#include <pthread.h>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include <elf.h>

static constexpr const char* SOCK_PATH    = "/tmp/oss_executor.sock";
static constexpr size_t      RECV_BUF     = 1 << 18;
static constexpr int         IDENTITY     = 8;
static constexpr size_t      IDENTITY_OFF = 72;
static constexpr size_t      MAX_STOLEN   = 32;

struct MemRegion { uintptr_t base; size_t size; bool r; bool x; };

static std::vector<MemRegion> get_regions() {
    std::vector<MemRegion> out;
    std::ifstream f("/proc/self/maps");
    std::string line;
    while (std::getline(f, line)) {
        uintptr_t lo, hi;
        char perms[5]{};
        if (sscanf(line.c_str(), "%lx-%lx %4s", &lo, &hi, perms) == 3)
            out.push_back({lo, hi - lo, perms[0] == 'r', perms[2] == 'x'});
    }
    return out;
}

static uintptr_t aob_scan(uintptr_t base, size_t size,
                          const uint8_t* pat, const char* mask, size_t plen) {
    for (size_t i = 0; i + plen <= size; ++i) {
        bool match = true;
        for (size_t j = 0; j < plen && match; ++j)
            if (mask[j] == 'x' && ((const uint8_t*)base)[i + j] != pat[j])
                match = false;
        if (match) return base + i;
    }
    return 0;
}

using lua_State = void;
using fn_compile = char* (*)(const char*, size_t, void*, size_t*);
using fn_load    = int   (*)(lua_State*, const char*, const char*, size_t, int);
using fn_pcall   = int   (*)(lua_State*, int, int, int);
using fn_resume  = int   (*)(lua_State*, lua_State*, int);
using fn_newthread = lua_State* (*)(lua_State*);
using fn_settop  = void  (*)(lua_State*, int);
using fn_tolstring = const char* (*)(lua_State*, int, size_t*);
using fn_gettop  = int   (*)(lua_State*);
using fn_sandbox = void  (*)(lua_State*);

struct {
    uintptr_t     mod_base = 0;
    size_t        mod_size = 0;
    fn_compile    compile  = nullptr;
    fn_load       load     = nullptr;
    fn_pcall      pcall    = nullptr;
    fn_resume     resume   = nullptr;
    fn_newthread  newthread = nullptr;
    fn_settop     settop   = nullptr;
    fn_tolstring  tolstring = nullptr;
    fn_gettop     gettop   = nullptr;
    fn_sandbox    sandbox  = nullptr;
    fn_resume     original_resume = nullptr;
    lua_State*    captured_L = nullptr;
    std::deque<std::string> queue;
    std::mutex              mtx;
    std::atomic<bool>       alive{false};
    std::atomic<bool>       hooked{false};
    uint8_t       stolen[MAX_STOLEN]{};
    size_t        stolen_len = 0;
    uint8_t*      trampoline = nullptr;
    uintptr_t     hook_addr  = 0;
} G;

static thread_local bool g_in = false;

static void set_identity(lua_State* L) {
    auto* extra = *reinterpret_cast<uint8_t**>(L);
    if (extra)
        *reinterpret_cast<int*>(extra + IDENTITY_OFF) = IDENTITY;
}

static void drain_queue(lua_State* L) {
    std::deque<std::string> batch;
    {
        std::lock_guard<std::mutex> lk(G.mtx);
        batch.swap(G.queue);
    }
    for (auto& src : batch) {
        if (src.empty()) continue;

        const char* bc_data = nullptr;
        size_t bc_sz = 0;
        char* compiled = nullptr;

        uint8_t first_byte = static_cast<uint8_t>(src[0]);
        bool is_bytecode = (first_byte >= 1 && first_byte <= 6 && src.size() > 4);

        if (is_bytecode) {
            bc_data = src.data();
            bc_sz = src.size();
        } else if (G.compile) {
            compiled = G.compile(src.c_str(), src.size(), nullptr, &bc_sz);
            if (!compiled || bc_sz == 0) {
                fprintf(stderr, "[payload] compile fail\n");
                free(compiled);
                continue;
            }
            bc_data = compiled;
        } else {
            fprintf(stderr, "[payload] no compiler and received source, skipping %zu bytes\n", src.size());
            continue;
        }

        lua_State* th = G.newthread(L);
        set_identity(th);
        int lr = G.load(th, "=oss", bc_data, bc_sz, 0);
        free(compiled);
        if (lr != 0) {
            size_t len = 0;
            const char* e = G.tolstring(th, -1, &len);
            fprintf(stderr, "[payload] load: %.*s\n", (int)len, e);
            G.settop(L, G.gettop(L) - 1);
            continue;
        }
        int rr = G.original_resume(th, nullptr, 0);
        if (rr != 0 && rr != 1) {
            size_t len = 0;
            const char* e = G.tolstring(th, -1, &len);
            fprintf(stderr, "[payload] run: %.*s\n", (int)len, e);
        }
        G.settop(L, G.gettop(L) - 1);
    }
}

static int resume_detour(lua_State* L, lua_State* from, int nargs) {
    int ret = G.original_resume(L, from, nargs);
    if (g_in) return ret;
    g_in = true;
    if (!G.captured_L) {
        G.captured_L = L;
        fprintf(stderr, "[payload] captured lua_State %p\n", L);
    }
    if (!G.queue.empty())
        drain_queue(G.captured_L);
    g_in = false;
    return ret;
}

static bool make_rwx(void* addr, size_t len) {
    uintptr_t page = (uintptr_t)addr & ~0xFFFULL;
    size_t span = ((uintptr_t)addr + len) - page + 0xFFF;
    span &= ~0xFFFULL;
    return mprotect((void*)page, span, PROT_READ|PROT_WRITE|PROT_EXEC) == 0;
}

static uint8_t* alloc_near(uintptr_t target, size_t sz) {
    for (intptr_t off = 0x1000; off < 0x7FFF0000LL; off += 0x1000) {
        void* p = mmap((void*)(target - off), sz,
                       PROT_READ|PROT_WRITE|PROT_EXEC,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) return (uint8_t*)p;
        p = mmap((void*)(target + off), sz,
                 PROT_READ|PROT_WRITE|PROT_EXEC,
                 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) return (uint8_t*)p;
    }
    return nullptr;
}

static size_t modrm_len(const uint8_t* p, size_t start) {
    size_t i = start;
    uint8_t modrm = p[i++];
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t rm  = modrm & 7;
    if (mod != 3 && rm == 4) {
        uint8_t sib = p[i++];
        if (mod == 0 && (sib & 7) == 5) i += 4;
    }
    if      (mod == 0 && rm == 5) i += 4;
    else if (mod == 1)            i += 1;
    else if (mod == 2)            i += 4;
    return i;
}

static size_t insn_len(const uint8_t* p) {
    if (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA) return 4;

    size_t i = 0;
    while (i < 4 && (p[i] == 0x66 || p[i] == 0x67 || p[i] == 0xF2 || p[i] == 0xF3))
        i++;

    bool rex_w = false;
    if (p[i] >= 0x40 && p[i] <= 0x4F) {
        rex_w = (p[i] & 0x08) != 0;
        i++;
    }

    uint8_t op = p[i++];

    if ((op >= 0x50 && op <= 0x5F) || op == 0x90 || op == 0xC3 ||
        op == 0xCC || op == 0xC9 || op == 0x9C || op == 0x9D ||
        op == 0xF4 || op == 0xCB)
        return i;
    if (op == 0xC2) return i + 2;
    if (op >= 0xB0 && op <= 0xB7) return i + 1;
    if (op >= 0xB8 && op <= 0xBF) return i + (rex_w ? 8 : 4);
    if (op == 0xE8 || op == 0xE9) return i + 4;
    if (op == 0xEB || (op >= 0x70 && op <= 0x7F)) return i + 1;
    if (op == 0x68) return i + 4;
    if (op == 0x6A) return i + 1;
    if (op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C ||
        op == 0x24 || op == 0x2C || op == 0x34 || op == 0x3C || op == 0xA8)
        return i + 1;
    if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D ||
        op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D || op == 0xA9)
        return i + 4;
    if (op == 0x80 || op == 0x82 || op == 0x83 || op == 0xC0 || op == 0xC1)
        return modrm_len(p, i) + 1;
    if (op == 0x81 || op == 0xC7) return modrm_len(p, i) + 4;
    if (op == 0xC6) return modrm_len(p, i) + 1;
    if (op == 0x69) return modrm_len(p, i) + 4;
    if (op == 0x6B) return modrm_len(p, i) + 1;
    if (op == 0xF6) {
        uint8_t m = p[i];
        size_t r = modrm_len(p, i);
        return ((m & 0x38) == 0) ? r + 1 : r;
    }
    if (op == 0xF7) {
        uint8_t m = p[i];
        size_t r = modrm_len(p, i);
        return ((m & 0x38) == 0) ? r + 4 : r;
    }
    if (op == 0x0F) {
        uint8_t op2 = p[i++];
        if (op2 >= 0x80 && op2 <= 0x8F) return i + 4;
        return modrm_len(p, i);
    }
    if ((op & 0xC4) == 0x00 || (op & 0xFE) == 0x84 || (op & 0xFC) == 0x88 ||
        op == 0x8D || op == 0x63 || (op >= 0xD0 && op <= 0xD3) ||
        op == 0xFE || op == 0xFF || op == 0x8F)
        return modrm_len(p, i);

    return 0;
}

static bool install_hook(uintptr_t target, void* detour, uint8_t*& tramp_out) {
    size_t total = 0;
    while (total < 5) {
        size_t il = insn_len((const uint8_t*)(target + total));
        if (il == 0) return false;
        total += il;
        if (total > MAX_STOLEN) return false;
    }
    uint8_t* tramp = alloc_near(target, total + 14);
    if (!tramp) return false;
    memcpy(tramp, (void*)target, total);
    tramp[total]     = 0xFF;
    tramp[total + 1] = 0x25;
    *(uint32_t*)(tramp + total + 2) = 0;
    *(uint64_t*)(tramp + total + 6) = target + total;
    tramp_out = tramp;
    G.original_resume = (fn_resume)tramp;
    memcpy(G.stolen, (void*)target, total);
    G.stolen_len = total;
    G.hook_addr  = target;
    if (!make_rwx((void*)target, total)) return false;
    int32_t rel = (int32_t)((uintptr_t)detour - (target + 5));
    auto* code = (uint8_t*)target;
    code[0] = 0xE9;
    memcpy(code + 1, &rel, 4);
    for (size_t i = 5; i < total; ++i) code[i] = 0x90;
    return true;
}

static void restore_hook() {
    if (G.hook_addr && G.stolen_len) {
        make_rwx((void*)G.hook_addr, G.stolen_len);
        memcpy((void*)G.hook_addr, G.stolen, G.stolen_len);
    }
}

static bool find_module() {
    auto regions = get_regions();
    const char* names[] = {"libroblox", "RobloxPlayer", "RobloxPlayerBeta",
                           "libclient", "Roblox", "Player",
                           "sober", ".sober-wrapped", nullptr};
    std::ifstream maps("/proc/self/maps");
    std::string line;
    uintptr_t lo = UINTPTR_MAX, hi = 0;
    bool found = false;
    while (std::getline(maps, line)) {
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        for (int i = 0; names[i]; ++i) {
            std::string nl = names[i];
            std::transform(nl.begin(), nl.end(), nl.begin(),
                           [](unsigned char c){ return std::tolower(c); });
            if (lower.find(nl) != std::string::npos) {
                uintptr_t a, b;
                if (sscanf(line.c_str(), "%lx-%lx", &a, &b) == 2) {
                    if (a < lo) lo = a;
                    if (b > hi) hi = b;
                    found = true;
                }
                break;
            }
        }
    }

    if (!found) {
        std::ifstream maps2("/proc/self/maps");
        std::string best_file;
        size_t best_sz = 0;
        while (std::getline(maps2, line)) {
            uintptr_t a, b;
            char perms[5]{};
            if (sscanf(line.c_str(), "%lx-%lx %4s", &a, &b, perms) != 3) continue;
            if (perms[0] != 'r' || perms[2] != 'x') continue;
            size_t sz = b - a;
            if (sz <= best_sz || sz < 0x100000) continue;
            auto slash = line.find('/');
            if (slash == std::string::npos) continue;
            std::string filepath = line.substr(slash);
            auto end = filepath.find_last_not_of(" \n\r\t");
            if (end != std::string::npos) filepath = filepath.substr(0, end + 1);
            if (filepath.find("/ld-linux") != std::string::npos) continue;
            if (filepath.find("/libc.so") != std::string::npos) continue;
            if (filepath.find("/libpthread") != std::string::npos) continue;
            if (filepath.find("/libm.so") != std::string::npos) continue;
            if (filepath.find("/libdl") != std::string::npos) continue;
            if (filepath.find("/libstdc++") != std::string::npos) continue;
            if (filepath.find("/libgcc") != std::string::npos) continue;
            if (filepath.find("/librt") != std::string::npos) continue;
            if (filepath.find("/liboss_payload") != std::string::npos) continue;
            if (filepath.find("/libmimalloc") != std::string::npos) continue;
            best_sz = sz;
            best_file = filepath;
        }

        if (!best_file.empty()) {
            std::ifstream maps3("/proc/self/maps");
            while (std::getline(maps3, line)) {
                if (line.find(best_file) != std::string::npos) {
                    uintptr_t a, b;
                    if (sscanf(line.c_str(), "%lx-%lx", &a, &b) == 2) {
                        if (a < lo) lo = a;
                        if (b > hi) hi = b;
                        found = true;
                    }
                }
            }
        }
    }

    if (!found) {
        uintptr_t best_base = 0; size_t best_sz = 0;
        for (auto& r : regions) {
            if (!r.r || !r.x) continue;
            if (r.size > best_sz && r.base > 0x400000) {
                best_base = r.base;
                best_sz   = r.size;
            }
        }
        if (best_sz > 0x100000) { lo = best_base; hi = best_base + best_sz; found = true; }
    }

    if (!found) return false;
    G.mod_base = lo;
    G.mod_size = hi - lo;
    fprintf(stderr, "[payload] module %lx-%lx (%zu MB)\n", lo, hi, G.mod_size >> 20);
    return true;
}

static uintptr_t get_exe_load_offset() {
    char exe_path[512];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) return 0;
    exe_path[len] = '\0';
    char* del = strstr(exe_path, " (deleted)");
    if (del) *del = '\0';

    FILE* ef = fopen(exe_path, "rb");
    if (!ef) return 0;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, ef) != 1 ||
        memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fclose(ef);
        return 0;
    }

    uintptr_t first_vaddr = UINTPTR_MAX;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        fseek(ef, static_cast<long>(ehdr.e_phoff + i * ehdr.e_phentsize), SEEK_SET);
        if (fread(&phdr, sizeof(phdr), 1, ef) != 1) break;
        if (phdr.p_type == PT_LOAD && phdr.p_vaddr < first_vaddr)
            first_vaddr = phdr.p_vaddr;
    }
    fclose(ef);
    if (first_vaddr == UINTPTR_MAX) return 0;

    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(exe_path) == std::string::npos) continue;
        uintptr_t lo;
        unsigned long offset;
        char perms[5]{};
        if (sscanf(line.c_str(), "%lx-%*x %4s %lx", &lo, perms, &offset) == 3 && offset == 0)
            return lo - first_vaddr;
    }
    return 0;
}

static uintptr_t find_elf_sym(const char* name) {
    char exe_path[512];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) return 0;
    exe_path[len] = '\0';
    char* del = strstr(exe_path, " (deleted)");
    if (del) *del = '\0';

    FILE* ef = fopen(exe_path, "rb");
    if (!ef) return 0;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, ef) != 1 ||
        memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fclose(ef);
        return 0;
    }

    if (ehdr.e_shnum == 0 || ehdr.e_shentsize < sizeof(Elf64_Shdr)) {
        fclose(ef);
        return 0;
    }

    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    fseek(ef, static_cast<long>(ehdr.e_shoff), SEEK_SET);
    if (fread(shdrs.data(), sizeof(Elf64_Shdr), ehdr.e_shnum, ef) != ehdr.e_shnum) {
        fclose(ef);
        return 0;
    }

    uintptr_t load_off = get_exe_load_offset();

    for (size_t si = 0; si < shdrs.size(); si++) {
        if (shdrs[si].sh_type != SHT_SYMTAB && shdrs[si].sh_type != SHT_DYNSYM)
            continue;

        uint32_t str_idx = shdrs[si].sh_link;
        if (str_idx >= shdrs.size()) continue;

        size_t strsz = shdrs[str_idx].sh_size;
        if (strsz == 0) continue;
        std::vector<char> strtab(strsz);
        fseek(ef, static_cast<long>(shdrs[str_idx].sh_offset), SEEK_SET);
        if (fread(strtab.data(), 1, strsz, ef) != strsz) continue;

        size_t entsize = shdrs[si].sh_entsize;
        if (entsize < sizeof(Elf64_Sym)) entsize = sizeof(Elf64_Sym);
        size_t nsyms = shdrs[si].sh_size / entsize;

        for (size_t j = 0; j < nsyms; j++) {
            Elf64_Sym sym;
            fseek(ef, static_cast<long>(shdrs[si].sh_offset + j * entsize), SEEK_SET);
            if (fread(&sym, sizeof(sym), 1, ef) != 1) break;
            if (sym.st_name == 0 || sym.st_name >= strsz) continue;
            if (sym.st_shndx == SHN_UNDEF) continue;
            if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            if (strcmp(strtab.data() + sym.st_name, name) == 0) {
                fclose(ef);
                return load_off + sym.st_value;
            }
        }
    }

    fclose(ef);
    return 0;
}

static uintptr_t scan_for_string(const char* str, size_t slen) {
    auto regions = get_regions();
    for (auto& r : regions) {
        if (!r.r) continue;
        if (G.mod_base && (r.base < G.mod_base || r.base >= G.mod_base + G.mod_size))
            continue;
        for (size_t i = 0; i + slen <= r.size; i++) {
            if (memcmp((const void*)(r.base + i), str, slen) == 0)
                return r.base + i;
        }
    }
    for (auto& r : regions) {
        if (!r.r) continue;
        if (G.mod_base && r.base >= G.mod_base && r.base < G.mod_base + G.mod_size)
            continue;
        for (size_t i = 0; i + slen <= r.size; i++) {
            if (memcmp((const void*)(r.base + i), str, slen) == 0)
                return r.base + i;
        }
    }
    return 0;
}

static uintptr_t find_lea_xref(uintptr_t string_addr) {
    auto regions = get_regions();
    for (auto& r : regions) {
        if (!r.r || !r.x) continue;
        if (G.mod_base && (r.base < G.mod_base || r.base >= G.mod_base + G.mod_size))
            continue;
        const uint8_t* code = (const uint8_t*)r.base;
        for (size_t i = 0; i + 7 <= r.size; i++) {
            if (code[i] == 0x8D && (code[i+1] & 0xC7) == 0x05) {
                int32_t disp;
                memcpy(&disp, code + i + 2, 4);
                uintptr_t target = r.base + i + 6 + (uintptr_t)(intptr_t)disp;
                if (target == string_addr) return r.base + i;
            }
            if (code[i] >= 0x40 && code[i] <= 0x4F &&
                code[i+1] == 0x8D && (code[i+2] & 0xC7) == 0x05) {
                int32_t disp;
                memcpy(&disp, code + i + 3, 4);
                uintptr_t target = r.base + i + 7 + (uintptr_t)(intptr_t)disp;
                if (target == string_addr) return r.base + i;
            }
        }
    }
    return 0;
}

static uintptr_t walk_back_to_func(uintptr_t addr) {
    if (!addr || addr < 0x1000) return 0;
    uintptr_t limit = (addr > 4096) ? addr - 4096 : 0x1000;
    for (uintptr_t p = addr - 1; p >= limit; p--) {
        const uint8_t* c = (const uint8_t*)p;
        bool candidate = false;

        if (p + 5 <= addr &&
            c[0] == 0xF3 && c[1] == 0x0F && c[2] == 0x1E && c[3] == 0xFA && c[4] == 0x55)
            candidate = true;
        else if (p + 4 <= addr &&
                 c[0] == 0x55 && c[1] == 0x48 && c[2] == 0x89 && c[3] == 0xE5)
            candidate = true;
        else if (c[0] == 0x55 && p > limit) {
            uint8_t prev = *((const uint8_t*)(p - 1));
            if (prev == 0xC3 || prev == 0xCC)
                candidate = true;
        }

        if (candidate) {
            size_t decoded = 0;
            uintptr_t ip = p;
            int valid_insns = 0;
            while (decoded < 32 && ip < addr + 64) {
                size_t il = insn_len((const uint8_t*)ip);
                if (il == 0) break;
                decoded += il;
                ip += il;
                valid_insns++;
            }
            if (valid_insns >= 3)
                return p;
        }
    }
    return 0;
}

static bool resolve_functions() {
    void* h = RTLD_DEFAULT;
    G.compile   = (fn_compile)dlsym(h, "luau_compile");
    G.load      = (fn_load)dlsym(h, "luau_load");
    G.pcall     = (fn_pcall)dlsym(h, "lua_pcall");
    G.resume    = (fn_resume)dlsym(h, "lua_resume");
    G.newthread = (fn_newthread)dlsym(h, "lua_newthread");
    G.settop    = (fn_settop)dlsym(h, "lua_settop");
    G.tolstring = (fn_tolstring)dlsym(h, "lua_tolstring");
    G.gettop    = (fn_gettop)dlsym(h, "lua_gettop");
    G.sandbox   = (fn_sandbox)dlsym(h, "luaL_sandboxthread");

    if (G.load && G.resume && G.newthread && G.settop && G.tolstring && G.gettop)
        return true;

    struct { const char* name; void** ptr; } syms[] = {
        {"luau_compile",       (void**)&G.compile},
        {"luau_load",          (void**)&G.load},
        {"lua_pcall",          (void**)&G.pcall},
        {"lua_resume",         (void**)&G.resume},
        {"lua_newthread",      (void**)&G.newthread},
        {"lua_settop",         (void**)&G.settop},
        {"lua_tolstring",      (void**)&G.tolstring},
        {"lua_gettop",         (void**)&G.gettop},
        {"luaL_sandboxthread", (void**)&G.sandbox},
    };

    for (auto& s : syms) {
        if (*s.ptr) continue;
        uintptr_t addr = find_elf_sym(s.name);
        if (addr) {
            *s.ptr = (void*)addr;
            fprintf(stderr, "[payload] elf-sym: %s at %lx\n", s.name, addr);
        }
    }

    if (G.load && G.resume && G.newthread && G.settop && G.tolstring && G.gettop)
        return true;

    if (!G.resume) {
        static const char* resume_strings[] = {
            "cannot resume dead coroutine",
            "cannot resume running coroutine",
            "attempt to yield across metamethod/C-call boundary",
            nullptr
        };
        for (int i = 0; resume_strings[i] && !G.resume; i++) {
            size_t slen = strlen(resume_strings[i]);
            uintptr_t str_addr = scan_for_string(resume_strings[i], slen);
            if (!str_addr) continue;
            fprintf(stderr, "[payload] found string '%s' at %lx\n", resume_strings[i], str_addr);
            uintptr_t xref = find_lea_xref(str_addr);
            if (!xref) continue;
            fprintf(stderr, "[payload] xref at %lx\n", xref);
            uintptr_t func = walk_back_to_func(xref);
            if (func) {
                G.resume = (fn_resume)func;
                fprintf(stderr, "[payload] string-ref: lua_resume at %lx\n", func);
            }
        }
    }

    if (!G.resume && G.mod_base) {
        static const uint8_t pat1[] = {0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56};
        static const char mask1[]   = "xxxxxxxxxxxx";
        static const uint8_t pat2[] = {0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56};
        static const char mask2[]   = "xxxxxxxx";
        auto regions = get_regions();
        for (auto& r : regions) {
            if (!r.r || !r.x) continue;
            if (r.base < G.mod_base || r.base >= G.mod_base + G.mod_size) continue;
            if (!G.resume) {
                uintptr_t a = aob_scan(r.base, r.size, pat1, mask1, sizeof(pat1));
                if (!a) a = aob_scan(r.base, r.size, pat2, mask2, sizeof(pat2));
                if (a) {
                    G.resume = (fn_resume)a;
                    fprintf(stderr, "[payload] aob: lua_resume at %lx\n", a);
                }
            }
        }
    }

    fprintf(stderr, "[payload] resolve: compile=%p load=%p resume=%p newthread=%p "
            "settop=%p tolstring=%p gettop=%p\n",
            (void*)G.compile, (void*)G.load, (void*)G.resume,
            (void*)G.newthread, (void*)G.settop, (void*)G.tolstring, (void*)G.gettop);

    return G.load && G.resume && G.newthread && G.settop && G.tolstring && G.gettop;
}

static void* ipc_worker(void*) {
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) return nullptr;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
    unlink(SOCK_PATH);
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(sfd, 4) < 0) { close(sfd); return nullptr; }
    fprintf(stderr, "[payload] ipc listening\n");
    auto* buf = (char*)malloc(RECV_BUF);
    if (!buf) { close(sfd); return nullptr; }
    while (G.alive.load(std::memory_order_relaxed)) {
        int cfd = accept(sfd, nullptr, nullptr);
        if (cfd < 0) break;
        size_t total = 0;
        ssize_t n;
        while ((n = read(cfd, buf + total, RECV_BUF - total - 1)) > 0) {
            total += (size_t)n;
            if (total >= RECV_BUF - 1) break;
        }
        buf[total] = '\0';
        close(cfd);
        if (total > 0) {
            std::lock_guard<std::mutex> lk(G.mtx);
            G.queue.emplace_back(buf, total);
            fprintf(stderr, "[payload] queued %zu bytes\n", total);
        }
    }
    free(buf);
    close(sfd);
    unlink(SOCK_PATH);
    return nullptr;
}

__attribute__((constructor))
static void payload_init() {
    fprintf(stderr, "[payload] init pid %d\n", getpid());
    if (!find_module()) {
        fprintf(stderr, "[payload] FATAL: roblox module not found\n");
        return;
    }
    if (!resolve_functions()) {
        fprintf(stderr, "[payload] FATAL: could not resolve luau functions"
                " (compile=%p load=%p resume=%p newthread=%p settop=%p tolstring=%p gettop=%p)\n",
                (void*)G.compile, (void*)G.load, (void*)G.resume,
                (void*)G.newthread, (void*)G.settop, (void*)G.tolstring, (void*)G.gettop);
        return;
    }
    if (!G.compile)
        fprintf(stderr, "[payload] luau_compile not found, expecting pre-compiled bytecode\n");
    G.alive.store(true, std::memory_order_release);
    pthread_t t;
    pthread_create(&t, nullptr, ipc_worker, nullptr);
    pthread_detach(t);
    uint8_t* tramp = nullptr;
    if (!install_hook((uintptr_t)G.resume, (void*)resume_detour, tramp)) {
        fprintf(stderr, "[payload] FATAL: hook install failed\n");
        return;
    }
    G.trampoline = tramp;
    G.hooked.store(true, std::memory_order_release);
    fprintf(stderr, "[payload] armed — waiting for scripts\n");
}

__attribute__((destructor))
static void payload_fini() {
    fprintf(stderr, "[payload] shutdown\n");
    G.alive.store(false, std::memory_order_release);
    if (G.hooked.load()) {
        restore_hook();
        G.hooked.store(false);
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0) {
        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
        connect(fd, (struct sockaddr*)&addr, sizeof(addr));
        close(fd);
    }
    usleep(50000);
}
