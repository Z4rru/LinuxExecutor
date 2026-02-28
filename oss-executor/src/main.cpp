#include <cstdlib>
#include <cstring>
#include <unistd.h>

__attribute__((constructor(101)))
static void fix_gio_before_anything() {
    setenv("GIO_MODULE_DIR",       "",      1);
    setenv("GIO_USE_VFS",          "local", 1);
    setenv("GSK_RENDERER",         "gl",    0);
    setenv("GTK_IM_MODULE",        "",      1);
    setenv("LIBGL_DRI3_DISABLE",   "1",     0);
    setenv("EGL_LOG_LEVEL",        "fatal", 0);
    setenv("GTK_A11Y",             "none",  0);
    setenv("NO_AT_BRIDGE",         "1",     0);
}

#include "ui/app.hpp"
#include "core/executor.hpp"
#include "utils/logger.hpp"
#include "utils/config.hpp"

#include <csignal>
#include <iostream>
#include <filesystem>

static void signal_handler(int sig) {
    static constexpr char msg[] = "\n[!] Signal received, shutting down...\n";
    ssize_t unused = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)unused;
    _exit(128 + sig);
}

#ifndef APP_VERSION
#define APP_VERSION "2.0.0"
#endif

static void print_banner() {
    std::cout <<
        "\n"
        "   ╔═══════════════════════════════════════════╗\n"
        "   ║                                           ║\n"
        "   ║      ◈  OSS Executor v" APP_VERSION "            ║\n"
        "   ║      Open Source Softworks                ║\n"
        "   ║      Linux Native                         ║\n"
        "   ║                                           ║\n"
        "   ╚═══════════════════════════════════════════╝\n"
        << std::endl;
}

static void ensure_home_dirs(const std::string& home) {
    static constexpr const char* subdirs[] = {
        "/logs",
        "/scripts",
        "/scripts/autoexec",
        "/themes",
        "/workspace",
        "/cache",
    };
    for (const char* sub : subdirs) {
        try {
            std::filesystem::create_directories(home + sub);
        } catch (const std::filesystem::filesystem_error& e) {
            LOG_WARN("Could not create {}{}: {}", home, sub, e.what());
        }
    }
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    print_banner();

    int exit_code = 0;

    try {
        auto& config = oss::Config::instance();
        std::string home = config.home_dir();

        oss::Logger::init(home + "/logs");
        LOG_INFO("OSS Executor v{} starting", APP_VERSION);

        std::string config_path = home + "/config.json";
        config.load(config_path);
        LOG_INFO("Configuration loaded from {}", config_path);

        ensure_home_dirs(home);

        auto& executor = oss::Executor::instance();

        executor.set_output_callback([](const std::string& msg) {
            LOG_INFO("[output] {}", msg);
        });

        executor.set_error_callback([](const std::string& msg) {
            LOG_ERROR("[script] {}", msg);
        });

        executor.set_status_callback([](const std::string& msg) {
            LOG_INFO("[status] {}", msg);
        });

        executor.init();

        if (!executor.is_initialized()) {
            LOG_ERROR("Executor failed to initialize — exiting");
            std::cerr << "[FATAL] Executor initialization failed" << std::endl;
            return 1;
        }

        if (config.get<bool>("executor.autoexec_on_start", true)) {
            executor.auto_execute();
        }

        LOG_INFO("Starting UI...");
        oss::App app(argc, argv);
        exit_code = app.run();
        LOG_INFO("UI exited with code {}", exit_code);

        executor.shutdown();
        oss::Logger::shutdown();
        LOG_INFO("OSS Executor shut down cleanly");

    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << std::endl;
        exit_code = 1;
    } catch (...) {
        std::cerr << "[FATAL] Unknown exception" << std::endl;
        exit_code = 1;
    }

    return exit_code;
}
