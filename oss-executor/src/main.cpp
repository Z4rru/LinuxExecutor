// ══════════════════════════════════════════════════════════════
// GIO/GVFS FIX — Must execute before ANY GLib/GTK header loads
// Fixes: "undefined symbol: g_task_set_static_name"
// Fixes: "Failed to load module: libgvfsdbus.so"
// ══════════════════════════════════════════════════════════════
#include <cstdlib>

// __attribute__((constructor)) runs before main() and before
// most C++ static initializers — catches GLib init in shared libs
__attribute__((constructor(101)))
static void fix_gio_before_anything() {
    // Prevent GLib from loading system GIO/GVFS modules that may be
    // compiled against a different GLib version (the actual crash).
    // Empty string = don't scan any module directory.
    setenv("GIO_MODULE_DIR", "", 1);

    // Force local-only VFS — disables gvfsd D-Bus backend entirely.
    // We only need local file:// paths, never sftp:// smb:// trash://
    setenv("GIO_USE_VFS", "local", 1);

    // Linux Mint / Cinnamon compositor fix
    setenv("GSK_RENDERER", "gl", 0);  // 0 = don't override if user set it
}
// ══════════════════════════════════════════════════════════════

#include "ui/app.hpp"
#include "core/executor.hpp"   // ← WAS MISSING — signal_handler uses Executor
#include "utils/logger.hpp"

#include <csignal>
#include <iostream>

static void signal_handler(int sig) {
    // Avoid spdlog in signal handler (not async-signal-safe)
    // Use write() which IS async-signal-safe
    const char* msg = "\n[!] Signal received, shutting down...\n";
    if (write(STDERR_FILENO, msg, strlen(msg)) == -1) { /* signal-safe, nothing to do */ }

    oss::Executor::instance().shutdown();
    _exit(0);  // _exit, not exit — safe in signal handlers
}

int main(int argc, char** argv) {
    // Belt-and-suspenders: ensure GIO fix even if constructor didn't fire
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

