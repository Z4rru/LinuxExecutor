#include "ui/app.hpp"
#include "utils/logger.hpp"

#include <csignal>
#include <iostream>

static void signal_handler(int sig) {
    SPDLOG_WARN("Received signal {}, shutting down...", sig);
    oss::Executor::instance().shutdown();
    exit(0);
}

int main(int argc, char** argv) {
    // Handle signals gracefully
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