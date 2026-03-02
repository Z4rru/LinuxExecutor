#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstddef>
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
#include <cerrno>
#include <cstdarg>
#include <fcntl.h>
#include <sys/stat.h>

static void plog(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    FILE* f = fopen("/tmp/oss_payload.log", "a");
    if (f) {
        vfprintf(f, fmt, ap);
        fflush(f);
        fclose(f);
    }
    va_end(ap);
}

static constexpr const char* SOCK_PATH    = "/tmp/oss_executor.sock";
static constexpr const char* CMD_PATH     = "/tmp/oss_payload_cmd";
static constexpr const char* READY_PATH   = "/tmp/oss_payload_ready";
static constexpr size_t      RECV_BUF     = 1 << 18;
static constexpr int         IDENTITY     = 8;
static size_t                IDENTITY_OFF = 0;  
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

static int g_mem_fd = -1;

static bool safe_read(uintptr_t addr, void* buf, size_t len) {
    if (g_mem_fd < 0) {
        g_mem_fd = open("/proc/self/mem", O_RDONLY);
        if (g_mem_fd < 0) return false;
    }
    return pread(g_mem_fd, buf, len, (off_t)addr) == (ssize_t)len;
}

static uintptr_t aob_scan(uintptr_t base, size_t size,
                          const uint8_t* pat, const char* mask, size_t plen) {
    const size_t PAGE = 4096;
    uint8_t buf[4096 + 256];
    for (size_t off = 0; off + plen <= size; off += PAGE) {
        size_t avail = size - off;
        size_t chunk = avail;
        if (chunk > PAGE + plen - 1) chunk = PAGE + plen - 1;
        if (chunk > sizeof(buf)) chunk = sizeof(buf);
        if (chunk < plen) break;
        if (!safe_read(base + off, buf, chunk)) continue;
        for (size_t i = 0; i + plen <= chunk; i++) {
            bool match = true;
            for (size_t j = 0; j < plen && match; j++)
                if (mask[j] == 'x' && buf[i + j] != pat[j])
                    match = false;
            if (match) return base + off + i;
        }
    }
    return 0;
}

using lua_State = void;
using fn_compile   = char* (*)(const char*, size_t, void*, size_t*);
using fn_load      = int   (*)(lua_State*, const char*, const char*, size_t, int);
using fn_pcall     = int   (*)(lua_State*, int, int, int);
using fn_resume    = int   (*)(lua_State*, lua_State*, int);
using fn_newthread = lua_State* (*)(lua_State*);
using fn_settop    = void  (*)(lua_State*, int);
using fn_tolstring = const char* (*)(lua_State*, int, size_t*);
using fn_gettop    = int   (*)(lua_State*);
using fn_sandbox   = void  (*)(lua_State*);

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
    std::atomic<int>        queue_count{0};
    uint8_t       stolen[MAX_STOLEN]{};
    size_t        stolen_len = 0;
    uint8_t*      trampoline = nullptr;
    uintptr_t     hook_addr  = 0;
} G;

static thread_local bool g_in = false;

static void set_identity(lua_State* L) {
    uint8_t* extra = *reinterpret_cast<uint8_t**>(L);
    if (!extra) return;

    if (IDENTITY_OFF == 0) {
  
        static const size_t known[] = {72, 48, 80, 88, 56, 64, 96, 104, 24, 32, 40};
        for (size_t off : known) {
            int val;
            if (safe_read((uintptr_t)(extra + off), &val, sizeof(val)) &&
                val >= 0 && val <= 7) {
                IDENTITY_OFF = off;
                plog("[payload] identity offset: %zu (current identity=%d)\n", off, val);
                break;
            }
        }
  
        if (IDENTITY_OFF == 0) {
            for (size_t off = 16; off < 160; off += 4) {
                int val;
                if (!safe_read((uintptr_t)(extra + off), &val, sizeof(val))) continue;
                if (val >= 0 && val <= 7) {
                    IDENTITY_OFF = off;
                    plog("[payload] identity offset (scan): %zu (current=%d)\n", off, val);
                    break;
                }
            }
        }
        if (IDENTITY_OFF == 0) {
            IDENTITY_OFF = 72;
            plog("[payload] identity offset: defaulting to 72\n");
        }
    }
    *reinterpret_cast<int*>(extra + IDENTITY_OFF) = IDENTITY;
}

static void drain_queue(lua_State* L) {
    std::deque<std::string> batch;
    {
        std::lock_guard<std::mutex> lk(G.mtx);
        batch.swap(G.queue);
        G.queue_count.store(0, std::memory_order_relaxed);
    }
    for (auto& src : batch) {
        if (src.empty()) continue;

        const char* bc_data = nullptr;
        size_t bc_sz = 0;
        char* compiled = nullptr;

        uint8_t first_byte = static_cast<uint8_t>(src[0]);
        bool is_bytecode = (first_byte >= 1 && first_byte <= 9 && src.size() > 4);

        if (is_bytecode) {
            bc_data = src.data();
            bc_sz = src.size();
        } else if (G.compile) {
           
            compiled = nullptr;
            bc_sz = 0;
            compiled = G.compile(src.c_str(), src.size(), nullptr, &bc_sz);
            if (!compiled || bc_sz == 0 ||
                (bc_sz > 0 && ((uint8_t)compiled[0] < 1 || (uint8_t)compiled[0] > 9))) {
                plog("[payload] compile failed or produced invalid bytecode (sz=%zu first=0x%02X)\n",
                     bc_sz, compiled ? (uint8_t)compiled[0] : 0);
                free(compiled);
                continue;
            }
            bc_data = compiled;
        } else {
            plog("[payload] no compiler and source received (%zu bytes), skipping\n", src.size());
            continue;
        }

        lua_State* th = G.newthread(L);

       
        if (G.sandbox) {
            G.sandbox(th);
        } else {
            plog("[payload] WARN: luaL_sandboxthread not found, script will lack game globals\n");
        }

        set_identity(th);
        int lr = G.load(th, "=oss", bc_data, bc_sz, 0);
        free(compiled);
        if (lr != 0) {
            if (G.tolstring) {
                size_t len = 0;
                const char* e = G.tolstring(th, -1, &len);
                plog("[payload] load error: %.*s\n", (int)len, e);
            } else {
                plog("[payload] load error (code %d)\n", lr);
            }
            G.settop(L, -2);
            continue;
        }
        plog("[payload] executing script (%zu bytes bc)...\n", bc_sz);
        int rr = G.original_resume(th, nullptr, 0);
        if (rr != 0 && rr != 1) {
            if (G.tolstring) {
                size_t len = 0;
                const char* e = G.tolstring(th, -1, &len);
                plog("[payload] run error: %.*s\n", (int)len, e);
            } else {
                plog("[payload] run error (code %d)\n", rr);
            }
        } else {
            plog("[payload] script executed OK (result=%d)\n", rr);
        }
        G.settop(L, -2);
    }
}

static int resume_detour(lua_State* L, lua_State* from, int nargs) {
    int ret = G.original_resume(L, from, nargs);
    if (g_in) return ret;
    g_in = true;
    G.captured_L = L;
    if (G.queue_count.load(std::memory_order_relaxed) > 0)
        drain_queue(L);
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
    while (i < 4 && (p[i] == 0x66 || p[i] == 0x67 || p[i] == 0xF0 ||
                     p[i] == 0xF2 || p[i] == 0xF3 || p[i] == 0x26 || p[i] == 0x2E ||
                     p[i] == 0x36 || p[i] == 0x3E || p[i] == 0x64 ||
                     p[i] == 0x65))
        i++;

    bool rex_w = false;
    if (p[i] >= 0x40 && p[i] <= 0x4F) {
        rex_w = (p[i] & 0x08) != 0;
        i++;
    }

    uint8_t op = p[i++];

    if ((op >= 0x50 && op <= 0x5F) || op == 0x90 || op == 0xC3 ||
        op == 0xCC || op == 0xC9 || op == 0x9C || op == 0x9D ||
        op == 0xF4 || op == 0xCB || op == 0xF8 || op == 0xF9 ||
        op == 0xFC || op == 0xFD || op == 0xF5 || op == 0x98 ||
        op == 0x99 || op == 0x9E || op == 0x9F || op == 0xCE ||
        op == 0xCF || (op >= 0x91 && op <= 0x97))
        return i;

    if (op == 0xC2) return i + 2;
    if (op >= 0xB0 && op <= 0xB7) return i + 1;
    if (op >= 0xB8 && op <= 0xBF) return i + (rex_w ? 8 : 4);
    if (op == 0xE8 || op == 0xE9) return i + 4;
    if (op == 0xEB || (op >= 0x70 && op <= 0x7F) || op == 0xE3) return i + 1;
    if (op == 0x68) return i + 4;
    if (op == 0x6A) return i + 1;

    if (op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C ||
        op == 0x24 || op == 0x2C || op == 0x34 || op == 0x3C || op == 0xA8)
        return i + 1;
    if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D ||
        op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D || op == 0xA9)
        return i + 4;

    if (op >= 0xA0 && op <= 0xA3) return i + (rex_w ? 8 : 4);
    if (op == 0xCD) return i + 1;
    if (op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7) return i + 1;

    if (op == 0x80 || op == 0x82 || op == 0x83 || op == 0xC0 || op == 0xC1)
        return modrm_len(p, i) + 1;
    if (op == 0x81)
        return modrm_len(p, i) + 4;
    if (op == 0xC7) return modrm_len(p, i) + 4;
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
        if (op2 >= 0x90 && op2 <= 0x9F) return modrm_len(p, i);
        if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF)
            return modrm_len(p, i);
        if (op2 == 0xAF) return modrm_len(p, i);
        if (op2 >= 0x40 && op2 <= 0x4F) return modrm_len(p, i);
        if (op2 == 0xBC || op2 == 0xBD || op2 == 0xB8)
            return modrm_len(p, i);
        if (op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB)
            return modrm_len(p, i);
        if (op2 == 0xBA) return modrm_len(p, i) + 1;
        if (op2 == 0xA4 || op2 == 0xAC) return modrm_len(p, i) + 1;
        if (op2 == 0xA5 || op2 == 0xAD) return modrm_len(p, i);
        if (op2 == 0xB0 || op2 == 0xB1) return modrm_len(p, i);
        if (op2 == 0xC0 || op2 == 0xC1) return modrm_len(p, i);
        if (op2 == 0x1F) return modrm_len(p, i);
        if (op2 == 0x18) return modrm_len(p, i);
        if ((op2 >= 0x10 && op2 <= 0x17) || (op2 >= 0x28 && op2 <= 0x2F) ||
            (op2 >= 0x50 && op2 <= 0x7F) || (op2 >= 0xC2 && op2 <= 0xC6) ||
            (op2 >= 0xD0 && op2 <= 0xFF))
            return modrm_len(p, i);
        if (op2 == 0x05 || op2 == 0x07) return i;
        if (op2 == 0x31) return i;
        if (op2 == 0xA2) return i;
        return modrm_len(p, i);
    }

    if (op == 0x86 || op == 0x87) return modrm_len(p, i);
    if ((op & 0xC4) == 0x00)  return modrm_len(p, i);
    if ((op & 0xFE) == 0x84)  return modrm_len(p, i);
    if ((op & 0xFC) == 0x88 || op == 0x8C || op == 0x8E)
        return modrm_len(p, i);
    if (op == 0x8D) return modrm_len(p, i);
    if (op == 0x63) return modrm_len(p, i);
    if (op >= 0xD0 && op <= 0xD3) return modrm_len(p, i);
    if (op == 0xFE || op == 0xFF) return modrm_len(p, i);
    if (op == 0x8F) return modrm_len(p, i);

    plog("[payload] insn_len: unknown opcode 0x%02X at offset %zu\n", op, i - 1);
    return 0;
}

static void relocate_rip_relative(uint8_t* tramp, size_t len,
                                  uintptr_t orig_addr, uintptr_t tramp_addr) {
    size_t off = 0;
    while (off < len) {
        size_t il = insn_len(tramp + off);
        if (il == 0) break;

        size_t ii = off;
        while (ii < off + il && (tramp[ii] == 0x66 || tramp[ii] == 0x67 ||
               tramp[ii] == 0xF0 || tramp[ii] == 0xF2 || tramp[ii] == 0xF3 ||
               tramp[ii] == 0x26 || tramp[ii] == 0x2E || tramp[ii] == 0x36 ||
               tramp[ii] == 0x3E || tramp[ii] == 0x64 || tramp[ii] == 0x65))
            ii++;
        if (ii < off + il && tramp[ii] >= 0x40 && tramp[ii] <= 0x4F)
            ii++;

        uint8_t opc = (ii < off + il) ? tramp[ii] : 0;
        size_t modrm_pos = 0;
        bool has_modrm = false;

        if (opc == 0xE8 || opc == 0xE9) {
            size_t disp_off = ii + 1;
            if (disp_off + 4 <= off + il) {
                int32_t disp;
                memcpy(&disp, tramp + disp_off, 4);
                uintptr_t abs_target = orig_addr + off + il + (int64_t)disp;
                int64_t new_disp = (int64_t)abs_target - (int64_t)(tramp_addr + off + il);
                if (new_disp >= INT32_MIN && new_disp <= INT32_MAX) {
                    int32_t nd = (int32_t)new_disp;
                    memcpy(tramp + disp_off, &nd, 4);
                }
            }
            off += il;
            continue;
        }

        if (opc == 0x0F) {
            uint8_t op2 = (ii + 1 < off + il) ? tramp[ii + 1] : 0;
            if (op2 >= 0x80 && op2 <= 0x8F) {
                size_t disp_off = ii + 2;
                if (disp_off + 4 <= off + il) {
                    int32_t disp;
                    memcpy(&disp, tramp + disp_off, 4);
                    uintptr_t abs_target = orig_addr + off + il + (int64_t)disp;
                    int64_t new_disp = (int64_t)abs_target - (int64_t)(tramp_addr + off + il);
                    if (new_disp >= INT32_MIN && new_disp <= INT32_MAX) {
                        int32_t nd = (int32_t)new_disp;
                        memcpy(tramp + disp_off, &nd, 4);
                    }
                }
                off += il;
                continue;
            }
            modrm_pos = ii + 2;
            has_modrm = (modrm_pos < off + il);
        } else {
            bool need_modrm = ((opc & 0xC4) == 0x00) || ((opc & 0xFE) == 0x84) ||
                              ((opc & 0xFC) == 0x88) || opc == 0x8C || opc == 0x8E ||
                              opc == 0x8D || opc == 0x63 ||
                              (opc >= 0x80 && opc <= 0x83) || opc == 0xC7 || opc == 0xC6 ||
                              opc == 0x69 || opc == 0x6B || opc == 0x86 || opc == 0x87 ||
                              opc == 0xF6 || opc == 0xF7 || opc == 0xFE || opc == 0xFF ||
                              opc == 0x8F || (opc >= 0xD0 && opc <= 0xD3) ||
                              opc == 0xC0 || opc == 0xC1;
            if (need_modrm) {
                modrm_pos = ii + 1;
                has_modrm = (modrm_pos < off + il);
            }
        }

        if (has_modrm && modrm_pos < off + il) {
            uint8_t modrm = tramp[modrm_pos];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm  = modrm & 7;
            if (mod == 0 && rm == 5) {
                size_t disp_off = modrm_pos + 1;
                if (disp_off + 4 <= off + il) {
                    int32_t disp;
                    memcpy(&disp, tramp + disp_off, 4);
                    uintptr_t abs_target = orig_addr + off + il + (int64_t)disp;
                    int64_t new_disp = (int64_t)abs_target - (int64_t)(tramp_addr + off + il);
                    if (new_disp >= INT32_MIN && new_disp <= INT32_MAX) {
                        int32_t nd = (int32_t)new_disp;
                        memcpy(tramp + disp_off, &nd, 4);
                    }
                }
            }
        }
        off += il;
    }
}

static bool install_hook(uintptr_t target, void* detour, uint8_t*& tramp_out) {
    uint8_t prologue[MAX_STOLEN + 15];
    if (!safe_read(target, prologue, sizeof(prologue))) {
        plog("[payload] hook: cannot read target at %lx\n", target);
        return false;
    }

    size_t total = 0;
    while (total < 5) {
        size_t il = insn_len(prologue + total);
        if (il == 0) {
            plog("[payload] hook: insn_len=0 at target+%zu (byte=0x%02X)\n",
                 total, prologue[total]);
            return false;
        }
        total += il;
        if (total > MAX_STOLEN) {
            plog("[payload] hook: stolen exceeds MAX_STOLEN (%zu)\n", total);
            return false;
        }
    }
    plog("[payload] hook: stealing %zu bytes from %lx\n", total, target);

    uint8_t* tramp = alloc_near(target, total + 14);
    if (!tramp) {
        plog("[payload] hook: alloc_near failed\n");
        return false;
    }

    memcpy(tramp, prologue, total);
    relocate_rip_relative(tramp, total, target, (uintptr_t)tramp);

    tramp[total]     = 0xFF;
    tramp[total + 1] = 0x25;
    *(uint32_t*)(tramp + total + 2) = 0;
    *(uint64_t*)(tramp + total + 6) = target + total;

    tramp_out = tramp;
    G.original_resume = (fn_resume)tramp;
    memcpy(G.stolen, prologue, total);
    G.stolen_len = total;
    G.hook_addr  = target;

    if (!make_rwx((void*)target, total)) {
        plog("[payload] hook: mprotect failed on target\n");
        return false;
    }

    int64_t rel64 = (int64_t)((uintptr_t)detour - (target + 5));
    if (rel64 >= INT32_MIN && rel64 <= INT32_MAX) {
        int32_t rel = (int32_t)rel64;
        auto* code = (uint8_t*)target;
        code[0] = 0xE9;
        memcpy(code + 1, &rel, 4);
        for (size_t j = 5; j < total; ++j) code[j] = 0x90;
        plog("[payload] hook: direct E9 jump installed (rel=%d)\n", rel);
    } else {
        plog("[payload] hook: detour too far (delta=%ld), using relay\n", (long)rel64);

        uint8_t* relay = alloc_near(target, 14);
        if (!relay) {
            plog("[payload] hook: relay alloc failed\n");
            memcpy((void*)target, G.stolen, G.stolen_len);
            return false;
        }
        relay[0] = 0xFF;
        relay[1] = 0x25;
        *(uint32_t*)(relay + 2) = 0;
        *(uint64_t*)(relay + 6) = (uintptr_t)detour;

        int64_t relay_rel64 = (int64_t)((uintptr_t)relay - (target + 5));
        if (relay_rel64 < INT32_MIN || relay_rel64 > INT32_MAX) {
            plog("[payload] hook: even relay is too far, abort\n");
            memcpy((void*)target, G.stolen, G.stolen_len);
            return false;
        }
        int32_t relay_rel = (int32_t)relay_rel64;
        auto* code = (uint8_t*)target;
        code[0] = 0xE9;
        memcpy(code + 1, &relay_rel, 4);
        for (size_t j = 5; j < total; ++j) code[j] = 0x90;
        plog("[payload] hook: relay jump installed at %p\n", relay);
    }

    return true;
}

static void restore_hook() {
    if (G.hook_addr && G.stolen_len) {
        make_rwx((void*)G.hook_addr, G.stolen_len);
        memcpy((void*)G.hook_addr, G.stolen, G.stolen_len);
        plog("[payload] hook restored\n");
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
            plog("[payload] best candidate module: %s (%zu MB)\n",
                 best_file.c_str(), best_sz >> 20);
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
    plog("[payload] module %lx-%lx (%zu MB)\n", lo, hi, G.mod_size >> 20);
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

static uintptr_t find_elf_sym_in_file(const char* filepath, const char* name,
                                       uintptr_t load_bias);

static uintptr_t find_elf_sym(const char* name) {

    char exe_path[512];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) return 0;
    exe_path[len] = '\0';
    char* del = strstr(exe_path, " (deleted)");
    if (del) *del = '\0';

    uintptr_t load_off = get_exe_load_offset();
    uintptr_t result = find_elf_sym_in_file(exe_path, name, load_off);
    if (result) return result;


    std::ifstream maps("/proc/self/maps");
    std::string line;
    std::vector<std::string> searched;
    searched.push_back(exe_path);
    while (std::getline(maps, line)) {
        auto slash = line.find('/');
        if (slash == std::string::npos) continue;
        std::string filepath = line.substr(slash);
        auto end = filepath.find_last_not_of(" \n\r\t");
        if (end != std::string::npos) filepath = filepath.substr(0, end + 1);
        if (filepath.find("/ld-linux") != std::string::npos) continue;
        if (filepath.find("/libc.so") != std::string::npos) continue;
        if (filepath.find("/libpthread") != std::string::npos) continue;
        if (filepath.find("/libstdc++") != std::string::npos) continue;
        if (filepath.find("/libgcc") != std::string::npos) continue;
        if (filepath.find("/liboss_payload") != std::string::npos) continue;
        if (std::find(searched.begin(), searched.end(), filepath) != searched.end())
            continue;
        searched.push_back(filepath);

       
        uintptr_t lib_base = 0;
        unsigned long file_off = 0;
        char perms[5]{};
        if (sscanf(line.c_str(), "%lx-%*x %4s %lx", &lib_base, perms, &file_off) == 3 &&
            file_off == 0) {
            result = find_elf_sym_in_file(filepath.c_str(), name, lib_base);
            if (result) {
                plog("[payload] elf-sym: found %s in %s at %lx\n", name, filepath.c_str(), result);
                return result;
            }
        }
    }
    return 0;
}

static uintptr_t find_elf_sym_in_file(const char* filepath, const char* name,
                                       uintptr_t load_bias) {
    FILE* ef = fopen(filepath, "rb");
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

    uintptr_t load_off = load_bias;

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
    const size_t PAGE = 4096;
    uint8_t buf[4096 + 256];
    for (int pass = 0; pass < 2; pass++) {
        for (auto& r : regions) {
            if (!r.r) continue;
            bool in_mod = G.mod_base && r.base >= G.mod_base &&
                          r.base < G.mod_base + G.mod_size;
            if (pass == 0 && !in_mod && G.mod_base) continue;
            if (pass == 1 && in_mod) continue;
            for (size_t off = 0; off < r.size; off += PAGE) {
                size_t avail = r.size - off;
                size_t chunk = avail;
                if (chunk > PAGE + slen - 1) chunk = PAGE + slen - 1;
                if (chunk > sizeof(buf)) chunk = sizeof(buf);
                if (chunk < slen) break;
                if (!safe_read(r.base + off, buf, chunk)) continue;
                for (size_t i = 0; i + slen <= chunk; i++) {
                    if (memcmp(buf + i, str, slen) == 0)
                        return r.base + off + i;
                }
            }
        }
    }
    return 0;
}

static uintptr_t find_lea_xref(uintptr_t string_addr) {
    auto regions = get_regions();
    const size_t PAGE = 4096;
    uint8_t buf[4096 + 16];
    for (int mode = 0; mode < 2; mode++) {
        uint8_t opc = (mode == 0) ? 0x8D : 0x8B;
        for (auto& r : regions) {
            if (!r.r || !r.x) continue;
            if (G.mod_base && (r.base < G.mod_base || r.base >= G.mod_base + G.mod_size))
                continue;
            for (size_t off = 0; off < r.size; off += PAGE) {
                size_t avail = r.size - off;
                size_t chunk = avail;
                if (chunk > PAGE + 7) chunk = PAGE + 7;
                if (chunk > sizeof(buf)) chunk = sizeof(buf);
                if (chunk < 7) break;
                if (!safe_read(r.base + off, buf, chunk)) continue;
                for (size_t i = 0; i + 7 <= chunk; i++) {
                    if (buf[i] == opc && (buf[i+1] & 0xC7) == 0x05) {
                        int32_t disp;
                        memcpy(&disp, buf + i + 2, 4);
                        uintptr_t target = r.base + off + i + 6 + (int64_t)disp;
                        if (target == string_addr) return r.base + off + i;
                    }
                    if (buf[i] >= 0x40 && buf[i] <= 0x4F &&
                        buf[i+1] == opc && (buf[i+2] & 0xC7) == 0x05) {
                        int32_t disp;
                        memcpy(&disp, buf + i + 3, 4);
                        uintptr_t target = r.base + off + i + 7 + (int64_t)disp;
                        if (target == string_addr) return r.base + off + i;
                    }
                }
            }
        }
    }
    return 0;
}

static uintptr_t walk_back_to_func(uintptr_t addr) {
    if (!addr || addr < 0x1000) return 0;
    uintptr_t limit = (addr > 4096) ? addr - 4096 : 0x1000;
    uint8_t window[8];
    for (uintptr_t p = addr - 1; p >= limit; p--) {
        if (!safe_read(p, window, sizeof(window))) continue;
        bool candidate = false;

        if (p + 5 <= addr &&
            window[0] == 0xF3 && window[1] == 0x0F && window[2] == 0x1E &&
            window[3] == 0xFA && window[4] == 0x55)
            candidate = true;
        else if (p + 4 <= addr &&
                 window[0] == 0x55 && window[1] == 0x48 && window[2] == 0x89 &&
                 window[3] == 0xE5)
            candidate = true;
        else if (p + 4 <= addr &&
                 window[0] == 0xF3 && window[1] == 0x0F && window[2] == 0x1E &&
                 window[3] == 0xFA)
            candidate = true;
        else if (window[0] == 0x55 && p > limit) {
            uint8_t prev;
            if (safe_read(p - 1, &prev, 1) &&
                (prev == 0xC3 || prev == 0xCC || prev == 0x90))
                candidate = true;
        }
        else if (p + 4 <= addr && p > limit && 
                             window[0] == 0x48 && window[1] == 0x83 && window[2] == 0xEC) {
            uint8_t prev;
            if (safe_read(p - 1, &prev, 1) &&
                (prev == 0xC3 || prev == 0xCC))
                candidate = true;
        }

        if (candidate) {
            uint8_t ibuf[96];
            size_t avail = addr + 64 - p;
            if (avail > sizeof(ibuf)) avail = sizeof(ibuf);
            if (!safe_read(p, ibuf, avail)) continue;
            size_t decoded = 0;
            int valid_insns = 0;
            while (decoded + 15 <= avail && decoded < 32) {
                size_t il = insn_len(ibuf + decoded);
                if (il == 0 || decoded + il > avail) break;
                decoded += il;
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

    plog("[payload] dlsym: compile=%p load=%p resume=%p newthread=%p "
         "settop=%p tolstring=%p gettop=%p\n",
         (void*)G.compile, (void*)G.load, (void*)G.resume,
         (void*)G.newthread, (void*)G.settop, (void*)G.tolstring, (void*)G.gettop);

    if (G.load && G.resume && G.newthread && G.settop)
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
            plog("[payload] elf-sym: %s at %lx\n", s.name, addr);
        }
    }

    plog("[payload] elf-sym: compile=%p load=%p resume=%p newthread=%p "
         "settop=%p tolstring=%p gettop=%p\n",
         (void*)G.compile, (void*)G.load, (void*)G.resume,
         (void*)G.newthread, (void*)G.settop, (void*)G.tolstring, (void*)G.gettop);

    if (G.load && G.resume && G.newthread && G.settop)
        return true;

    if (!G.resume) {
        static const char* resume_strings[] = {
            "cannot resume dead coroutine",
            "cannot resume running coroutine",
            "attempt to yield across metamethod/C-call boundary",
            "cannot resume non-suspended coroutine",
            nullptr
        };
        for (int i = 0; resume_strings[i] && !G.resume; i++) {
            size_t slen = strlen(resume_strings[i]);
            uintptr_t str_addr = scan_for_string(resume_strings[i], slen);
            if (!str_addr) continue;
            plog("[payload] found resume string '%s' at %lx\n", resume_strings[i], str_addr);
            uintptr_t xref = find_lea_xref(str_addr);
            if (!xref) continue;
            plog("[payload] xref at %lx\n", xref);
            uintptr_t func = walk_back_to_func(xref);
            if (func) {
                G.resume = (fn_resume)func;
                plog("[payload] string-ref: lua_resume at %lx\n", func);
            }
        }
    }

    if (!G.newthread) {
        static const char* nt_strings[] = {
            "lua_newthread",
            "too many C calls",
            nullptr
        };
        for (int i = 0; nt_strings[i] && !G.newthread; i++) {
            size_t slen = strlen(nt_strings[i]);
            uintptr_t str_addr = scan_for_string(nt_strings[i], slen);
            if (!str_addr) continue;
            uintptr_t xref = find_lea_xref(str_addr);
            if (!xref) continue;
            uintptr_t func = walk_back_to_func(xref);
            if (func) {
                G.newthread = (fn_newthread)func;
                plog("[payload] string-ref: lua_newthread at %lx\n", func);
            }
        }
    }

    if (!G.settop) {
        const char* settop_str = "stack overflow";
        size_t slen = strlen(settop_str);
        uintptr_t str_addr = scan_for_string(settop_str, slen);
        if (str_addr) {
            uintptr_t xref = find_lea_xref(str_addr);
            if (xref) {
                uintptr_t func = walk_back_to_func(xref);
                if (func) {
                    G.settop = (fn_settop)func;
                    plog("[payload] string-ref: lua_settop at %lx\n", func);
                }
            }
        }
    }

        if (!G.compile) {
        
        static const char* comp_strings[] = {
            "exceeded constant limit",
            "exceeded closure limit",
            "exceeded local register limit",
            "exceeded upvalue limit",
            nullptr
        };
        for (int i = 0; comp_strings[i] && !G.compile; i++) {
            size_t slen = strlen(comp_strings[i]);
            uintptr_t str_addr = scan_for_string(comp_strings[i], slen);
            if (!str_addr) continue;
            plog("[payload] found compile string '%s' at %lx\n", comp_strings[i], str_addr);
            uintptr_t xref = find_lea_xref(str_addr);
            if (!xref) continue;
            uintptr_t func = walk_back_to_func(xref);
            if (func) {
                G.compile = (fn_compile)func;
                plog("[payload] string-ref: luau_compile candidate at %lx\n", func);
            }
        }
    }

    if (!G.load) {
        static const char* load_strings[] = {
            "bytecode version mismatch",
            "truncated",
            nullptr
        };
        for (int i = 0; load_strings[i] && !G.load; i++) {
            size_t slen = strlen(load_strings[i]);
            uintptr_t str_addr = scan_for_string(load_strings[i], slen);
            if (!str_addr) continue;
            uintptr_t xref = find_lea_xref(str_addr);
            if (!xref) continue;
            uintptr_t func = walk_back_to_func(xref);
            if (func) {
                G.load = (fn_load)func;
                plog("[payload] string-ref: luau_load at %lx\n", func);
            }
        }
    }

    if (!G.tolstring) {
        static const char* tol_strings[] = {
            "value has no significant digits",
            nullptr
        };
        for (int i = 0; tol_strings[i] && !G.tolstring; i++) {
            size_t slen = strlen(tol_strings[i]);
            uintptr_t str_addr = scan_for_string(tol_strings[i], slen);
            if (!str_addr) continue;
            uintptr_t xref = find_lea_xref(str_addr);
            if (!xref) continue;
            uintptr_t func = walk_back_to_func(xref);
            if (func) {
                G.tolstring = (fn_tolstring)func;
                plog("[payload] string-ref: lua_tolstring at %lx\n", func);
            }
        }
    }

    if (!G.resume && G.mod_base) {
        static const uint8_t pat1[] = {0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5,
                                       0x41, 0x57, 0x41, 0x56};
        static const char mask1[]   = "xxxxxxxxxxxx";
        static const uint8_t pat2[] = {0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56};
        static const char mask2[]   = "xxxxxxxx";
        auto regions = get_regions();
        for (auto& r : regions) {
            if (!r.r || !r.x) continue;
            if (r.base < G.mod_base || r.base >= G.mod_base + G.mod_size) continue;
            uintptr_t a = aob_scan(r.base, r.size, pat1, mask1, sizeof(pat1));
            if (!a) a = aob_scan(r.base, r.size, pat2, mask2, sizeof(pat2));
            if (a) {
                G.resume = (fn_resume)a;
                plog("[payload] aob: lua_resume at %lx\n", a);
                break;
            }
        }
    }

    if (!G.tolstring)
        plog("[payload] NOTE: lua_tolstring not found, error messages unavailable\n");
    if (!G.gettop)
        plog("[payload] NOTE: lua_gettop not found, using settop(-2) fallback\n");

    plog("[payload] final: compile=%p load=%p resume=%p newthread=%p "
         "settop=%p tolstring=%p gettop=%p sandbox=%p\n",
         (void*)G.compile, (void*)G.load, (void*)G.resume,
         (void*)G.newthread, (void*)G.settop, (void*)G.tolstring,
         (void*)G.gettop, (void*)G.sandbox);

    return G.load && G.resume && G.newthread && G.settop;
}

static void write_status(const char* status) {
    FILE* f = fopen("/tmp/oss_payload_status", "w");
    if (f) {
        fprintf(f, "hooked=%d captured_L=%p queue=%d compile=%p load=%p "
                "resume=%p newthread=%p settop=%p gettop=%p tolstring=%p status=%s\n",
                G.hooked.load() ? 1 : 0, G.captured_L,
                G.queue_count.load(),
                (void*)G.compile, (void*)G.load, (void*)G.resume,
                (void*)G.newthread, (void*)G.settop, (void*)G.gettop,
                (void*)G.tolstring, status);
        fflush(f);
        fclose(f);
    }
}

static void* file_cmd_worker(void*) {
    plog("[payload] file-IPC watcher started\n");
    int stale_ticks = 0;
    int reinit_attempts = 0;

    while (G.alive.load(std::memory_order_relaxed)) {
        struct stat st;
        if (stat(CMD_PATH, &st) == 0 && st.st_size > 0) {
            usleep(10000);
            int fd = open(CMD_PATH, O_RDONLY);
            if (fd >= 0) {
                if (fstat(fd, &st) == 0 && st.st_size > 0) {
                    size_t sz = (size_t)st.st_size;
                    char* buf = (char*)malloc(sz);
                    if (buf) {
                        ssize_t total = 0;
                        while (total < (ssize_t)sz) {
                            ssize_t rd = read(fd, buf + total, sz - total);
                            if (rd <= 0) break;
                            total += rd;
                        }
                        close(fd);
                        unlink(CMD_PATH);

                        if (total > 0) {
                            std::string script(buf, (size_t)total);
                            plog("[payload] file-IPC: received %zd bytes, hooked=%d captured_L=%p\n",
                                 total, G.hooked.load() ? 1 : 0, G.captured_L);
                            {
                                std::lock_guard<std::mutex> lk(G.mtx);
                                G.queue.emplace_back(std::move(script));
                                G.queue_count.fetch_add(1, std::memory_order_relaxed);
                            }
                            plog("[payload] file-IPC: queued (queue size=%d)\n",
                                 G.queue_count.load());
                            write_status("queued");
                        }
                        free(buf);
                    } else {
                        close(fd);
                        unlink(CMD_PATH);
                    }
                } else {
                    close(fd);
                }
            }
        }

        bool need_reinit = false;
        {
            std::lock_guard<std::mutex> lk(G.mtx);
            if (!G.queue.empty()) {
                stale_ticks++;
                if (stale_ticks % 40 == 0) {
                    plog("[payload] WARNING: %zu scripts queued for %ds without drain. "
                         "hooked=%d captured_L=%p\n",
                         G.queue.size(), stale_ticks / 20,
                         G.hooked.load() ? 1 : 0, G.captured_L);
                    write_status("stale");
                }
                if (!G.hooked.load() && stale_ticks >= 100 && reinit_attempts < 5) {
                    need_reinit = true;
                    reinit_attempts++;
                    stale_ticks = 0;
                }
            } else {
                stale_ticks = 0;
            }
        }

        if (need_reinit) {
            plog("[payload] hook not installed, re-init attempt %d/5\n", reinit_attempts);
            if (!G.mod_base) find_module();
            if (resolve_functions()) {
                uint8_t* tramp = nullptr;
                if (install_hook((uintptr_t)G.resume, (void*)resume_detour, tramp)) {
                    G.trampoline = tramp;
                    G.hooked.store(true, std::memory_order_release);
                    plog("[payload] re-init: hook installed successfully\n");
                    write_status("armed");
                } else {
                    plog("[payload] re-init: hook install failed\n");
                    write_status("reinit_hook_fail");
                }
            } else {
                plog("[payload] re-init: resolve failed\n");
                write_status("reinit_resolve_fail");
            }
        }

        usleep(50000);
    }
    return nullptr;
}

static void* ipc_worker(void*) {
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) return nullptr;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
    unlink(SOCK_PATH);
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        plog("[payload] bind(%s) failed: %s\n", SOCK_PATH, strerror(errno));
        close(sfd);
        return nullptr;
    }
    if (listen(sfd, 4) < 0) {
        plog("[payload] listen failed: %s\n", strerror(errno));
        close(sfd);
        return nullptr;
    }
    plog("[payload] ipc listening on %s\n", SOCK_PATH);
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
            G.queue_count.fetch_add(1, std::memory_order_relaxed);
            plog("[payload] ipc: queued %zu bytes\n", total);
        }
    }
    free(buf);
    close(sfd);
    unlink(SOCK_PATH);
    return nullptr;
}

static void* init_worker(void*) {
    usleep(500000);

    plog("[payload] init_worker: resolving module...\n");
    if (!find_module()) {
        plog("[payload] WARN: module not found, relaxed scan...\n");
        auto regions = get_regions();
        uintptr_t lo = UINTPTR_MAX, hi = 0;
        for (auto& r : regions) {
            if (!r.r || !r.x) continue;
            if (r.size < 0x10000) continue;
            if (r.base < lo) lo = r.base;
            if (r.base + r.size > hi) hi = r.base + r.size;
        }
        if (hi > lo) {
            G.mod_base = lo;
            G.mod_size = hi - lo;
            plog("[payload] fallback module %lx-%lx (%zu MB)\n", lo, hi, G.mod_size >> 20);
        } else {
            plog("[payload] FATAL: no executable regions\n");
            write_status("fatal_no_regions");
            return nullptr;
        }
    }

    bool resolved = false;
    for (int attempt = 0; attempt < 10; attempt++) {
        if (resolve_functions()) {
            resolved = true;
            break;
        }
        plog("[payload] resolve attempt %d/10 failed, retrying...\n", attempt + 1);
        write_status("resolving");
        usleep(1000000);
    }

    if (!resolved) {
        plog("[payload] FATAL: could not resolve luau functions\n");
        write_status("fatal_no_resolve");
        return nullptr;
    }

    if (!G.compile)
        plog("[payload] NOTE: luau_compile not found, expecting pre-compiled bytecode\n");

    plog("[payload] installing hook on lua_resume at %lx...\n", (uintptr_t)G.resume);

    uint8_t* tramp = nullptr;
    if (!install_hook((uintptr_t)G.resume, (void*)resume_detour, tramp)) {
        plog("[payload] FATAL: hook install failed\n");
        write_status("fatal_hook_fail");
        return nullptr;
    }
    G.trampoline = tramp;
    G.hooked.store(true, std::memory_order_release);

    plog("[payload] armed, waiting for scripts\n");
    write_status("armed");
    return nullptr;
}

__attribute__((constructor))
static void payload_init() {
    unlink("/tmp/oss_payload.log");
    unlink("/tmp/oss_payload_status");

    plog("[payload] init pid %d\n", getpid());

    FILE* marker = fopen(READY_PATH, "w");
    if (marker) {
        fprintf(marker, "%d\n", getpid());
        fflush(marker);
        fclose(marker);
        plog("[payload] ready marker: %s\n", READY_PATH);
    } else {
        plog("[payload] WARN: cannot create ready marker: %s\n", strerror(errno));
    }

    unlink(CMD_PATH);

    G.alive.store(true, std::memory_order_release);
    write_status("initializing");

    pthread_t file_t;
    if (pthread_create(&file_t, nullptr, file_cmd_worker, nullptr) == 0)
        pthread_detach(file_t);
    else
        plog("[payload] WARN: file_cmd_worker thread failed\n");

    pthread_t ipc_t;
    if (pthread_create(&ipc_t, nullptr, ipc_worker, nullptr) == 0)
        pthread_detach(ipc_t);
    else
        plog("[payload] WARN: ipc_worker thread failed\n");

    pthread_t init_t;
    if (pthread_create(&init_t, nullptr, init_worker, nullptr) == 0)
        pthread_detach(init_t);
    else
        plog("[payload] WARN: init_worker thread failed\n");
}

__attribute__((destructor))
static void payload_fini() {
    plog("[payload] shutdown\n");
    G.alive.store(false, std::memory_order_release);
    unlink(READY_PATH);
    unlink(CMD_PATH);
    if (G.hooked.load()) {
        restore_hook();
        G.hooked.store(false);
    }
    if (g_mem_fd >= 0) {
        close(g_mem_fd);
        g_mem_fd = -1;
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
    write_status("shutdown");
}
                 
