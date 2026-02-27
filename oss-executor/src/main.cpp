#include <cstdlib>
#include <cstring>
#include <unistd.h>

__attribute__((constructor(101)))
static void fix_gio_before_anything() {
    setenv("GIO_MODULE_DIR", "", 1);
    setenv("GIO_USE_VFS", "local", 1);
    setenv("GSK_RENDERER", "gl", 0);
    setenv("GTK_IM_MODULE", "", 1);
    setenv("LIBGL_DRI3_DISABLE", "1", 0);
}

#include "ui/app.hpp"
#include "core/executor.hpp"
#include "utils/logger.hpp"

#include <csignal>
#include <iostream>

static void signal_handler(int) {
    const char* msg = "\n[!] Signal received, shutting down...\n";
    ssize_t unused = write(STDERR_FILENO, msg, strlen(msg));
    (void)unused;
    _exit(0);
}

int main(int argc, char** argv) {
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
