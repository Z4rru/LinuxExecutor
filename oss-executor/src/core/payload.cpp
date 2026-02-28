// src/core/payload.cpp
// Injection payload shared library — loaded into target process via dlopen/ptrace

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "lua.h"
#include "lualib.h"
#include "luacode.h"

static constexpr const char* SOCKET_PATH = "/tmp/oss_executor.sock";
static constexpr size_t      RECV_BUF    = 1 << 18;   // 256 KiB

// ── helpers ──────────────────────────────────────────────────────────────────

static int compile_and_run(lua_State* L, const char* source, size_t len)
{
    size_t bytecodeSize = 0;
    char*  bytecode     = luau_compile(source, len, nullptr, &bytecodeSize);
    if (!bytecode || bytecodeSize == 0) {
        fprintf(stderr, "[payload] luau_compile returned nullptr or empty\n");
        free(bytecode);           // luau_compile may return error string
        return -1;
    }

    int result = luau_load(L, "=payload", bytecode, bytecodeSize, 0);
    free(bytecode);

    if (result != 0) {
        fprintf(stderr, "[payload] luau_load error: %s\n",
                lua_tostring(L, -1));
        lua_pop(L, 1);
        return -1;
    }

    result = lua_pcall(L, 0, 0, 0);
    if (result != 0) {
        fprintf(stderr, "[payload] lua_pcall error: %s\n",
                lua_tostring(L, -1));
        lua_pop(L, 1);
        return -1;
    }
    return 0;
}

// ── IPC listener thread ─────────────────────────────────────────────────────

struct PayloadState {
    lua_State*         L       = nullptr;
    std::atomic<bool>  running{false};    // FIX: was plain bool — data race
};

static void* ipc_thread(void* arg)
{
    auto* state = static_cast<PayloadState*>(arg);

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[payload] socket");
        return nullptr;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    unlink(SOCKET_PATH);
    if (bind(server_fd, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr)) < 0) {
        perror("[payload] bind");
        close(server_fd);
        return nullptr;
    }

    if (listen(server_fd, 4) < 0) {
        perror("[payload] listen");
        close(server_fd);
        return nullptr;
    }

    fprintf(stderr, "[payload] listening on %s\n", SOCKET_PATH);

    auto* buf = static_cast<char*>(malloc(RECV_BUF));
    if (!buf) {
        close(server_fd);
        return nullptr;
    }

    while (state->running.load(std::memory_order_relaxed)) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            if (state->running.load(std::memory_order_relaxed))
                perror("[payload] accept");
            break;
        }

        // Read the full script
        size_t  total = 0;
        ssize_t n;
        while ((n = read(client_fd, buf + total,
                         RECV_BUF - total - 1)) > 0) {
            total += static_cast<size_t>(n);
            if (total >= RECV_BUF - 1) break;
        }
        buf[total] = '\0';
        close(client_fd);

        if (total > 0) {
            fprintf(stderr, "[payload] received %zu bytes, executing…\n",
                    total);
            compile_and_run(state->L, buf, total);
        }
    }

    free(buf);
    close(server_fd);
    unlink(SOCKET_PATH);
    return nullptr;
}

// ── Entry point (called when .so is dlopen'd) ───────────────────────────────

static PayloadState g_state{};
static pthread_t    g_thread{};

__attribute__((constructor))
static void payload_init()
{
    fprintf(stderr, "[payload] initialising (pid %d)\n", getpid());

    lua_State* L = luaL_newstate();
    if (!L) {
        fprintf(stderr, "[payload] failed to create lua_State\n");
        return;
    }
    luaL_openlibs(L);

    g_state.L = L;
    g_state.running.store(true, std::memory_order_release);

    if (pthread_create(&g_thread, nullptr, ipc_thread, &g_state) != 0) {
        perror("[payload] pthread_create");
        lua_close(L);
        g_state.L = nullptr;
        return;
    }
    pthread_detach(g_thread);

    fprintf(stderr, "[payload] ready\n");
}

__attribute__((destructor))
static void payload_fini()
{
    fprintf(stderr, "[payload] shutting down\n");
    g_state.running.store(false, std::memory_order_release);

    // Poke the socket so accept() unblocks
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0) {
        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
        connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        close(fd);
    }

    // Brief yield so the IPC thread can exit accept() and clean up
    usleep(50000);

    if (g_state.L) {
        lua_close(g_state.L);
        g_state.L = nullptr;
    }
}
