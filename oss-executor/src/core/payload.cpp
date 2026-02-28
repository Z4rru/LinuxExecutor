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
using fn_gettop  = int   (*)(lua_State*, ...);
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
        size_t bc_sz = 0;
        char* bc = G.compile(src.c_str(), src.size(), nullptr, &bc_sz);
        if (!bc || bc_sz == 0) {
            fprintf(stderr, "[payload] compile fail\n");
            free(bc);
            continue;
        }
        lua_State* th = G.newthread(L);
        set_identity(th);
        int lr = G.load(th, "=oss", bc, bc_sz, 0);
        free(bc);
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

static size_t insn_len(const uint8_t* p) {
    if (p[0] == 0x55) return 1;
    if (p[0] == 0x53) return 1;
    if (p[0] == 0x41 && (p[1] >= 0x54 && p[1] <= 0x57)) return 2;
    if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0xe5) return 3;
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xec) return 4;
    if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xec) return 7;
    if (p[0] == 0x48 && p[1] == 0x8b) return 3;
    if (p[0] == 0x48 && p[1] == 0x89) return 3;
    if (p[0] == 0x89) return 2;
    if (p[0] == 0x8b) return 2;
    if (p[0] == 0x31 || p[0] == 0x33) return 2;
    if (p[0] == 0x90) return 1;
    if (p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x1e && p[3] == 0xfa) return 4;
    if (p[0] == 0x50 || p[0] == 0x51 || p[0] == 0x52 || p[0] == 0x56 || p[0] == 0x57) return 1;
    if (p[0] == 0x48 && p[1] == 0x8d) return (p[2] & 0xC0) == 0x80 ? 7 : 3;
    if (p[0] == 0x4c && p[1] == 0x8b) return 3;
    if (p[0] == 0x4c && p[1] == 0x89) return 3;
    if (p[0] == 0x49 && (p[1] == 0x89 || p[1] == 0x8b)) return 3;
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
    const char* names[] = {"libroblox", "RobloxPlayer", "libclient", nullptr};
    std::ifstream maps("/proc/self/maps");
    std::string line;
    uintptr_t lo = UINTPTR_MAX, hi = 0;
    bool found = false;
    while (std::getline(maps, line)) {
        for (int i = 0; names[i]; ++i) {
            if (line.find(names[i]) != std::string::npos) {
                uintptr_t a, b;
                if (sscanf(line.c_str(), "%lx-%lx", &a, &b) == 2) {
                    if (a < lo) lo = a;
                    if (b > hi) hi = b;
                    found = true;
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
    if (G.compile && G.load && G.resume && G.newthread && G.settop && G.tolstring && G.gettop)
        return true;
    if (!G.mod_base) return false;
    auto regions = get_regions();
    for (auto& r : regions) {
        if (!r.r || !r.x) continue;
        if (r.base < G.mod_base || r.base >= G.mod_base + G.mod_size) continue;
        if (!G.resume) {
            static const uint8_t pat[] = {0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56};
            static const char mask[]   = "xxxxxxxx";
            uintptr_t a = aob_scan(r.base, r.size, pat, mask, sizeof(pat));
            if (a) G.resume = (fn_resume)a;
        }
    }
    return G.compile && G.load && G.resume && G.newthread && G.settop && G.tolstring && G.gettop;
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
