// ══════════════════════════════════════════════════════════════
// GIO/GVFS FIX — Must execute before ANY GLib/GTK header loads
// ══════════════════════════════════════════════════════════════
#include <cstdlib>
#include <cstring>
#include <unistd.h>

__attribute__((constructor(101)))
static void fix_gio_before_anything() {
    setenv("GIO_MODULE_DIR", "", 1);
    setenv("GIO_USE_VFS", "local", 1);
    setenv("GSK_RENDERER", "gl", 0);
}
// ══════════════════════════════════════════════════════════════

#include "ui/app.hpp"
#include "core/executor.hpp"
#include "utils/logger.hpp"

#include <csignal>
#include <iostream>

// ★ FIX: Don't call shutdown() inside a signal handler.
//   shutdown() uses mutexes/memory-allocation which can deadlock.
//   Just set a flag and exit immediately.
static volatile sig_atomic_t g_shutdown_requested = 0;

static void signal_handler(int sig) {
    g_shutdown_requested = 1;
    const char* msg = "\n[!] Signal received, shutting down...\n";
    // write() is async-signal-safe, unlike printf/cout/spdlog
    ssize_t unused = write(STDERR_FILENO, msg, strlen(msg));
    (void)unused;  // suppress unused-result warning
    _exit(0);      // _exit (not exit) is safe in signal handlers
}

int main(int argc, char** argv) {
    fix_gio_before_anything();

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::cout << R"(
   ╔═══════════════════════════════════════════╗
   ║                                           ║
   ║      ◈  OSS Executor v2.0                ║
   ║      Open Source Softworks                ║
   ║      Linux Mint Native                    ║
   ║                                           ║
   ╚═══════════════════════════════════════════╝
    )" << std::endl;

    try {
        oss::App app(argc, argv);
        return app.run();
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << std::endl;
        return 1;
    }
}
