// src/main.cpp
// Entry point — wires together Logger → Config → Executor → App

// ── GIO/GTK environment fixups ──────────────────────────────────────────────
// Must run before any GLib constructor (priority < 200).
// Cannot be in a .hpp — must be in translation unit that is always linked.

#include <cstdlib>
#include <cstring>
#include <unistd.h>

__attribute__((constructor(101)))
static void fix_gio_before_anything() {
    setenv("GIO_MODULE_DIR",       "",      1);  // block missing-module warnings
    setenv("GIO_USE_VFS",          "local", 1);  // avoid D-Bus VFS lookup
    setenv("GSK_RENDERER",         "gl",    0);  // prefer GL (0 = don't overwrite)
    setenv("GTK_IM_MODULE",        "",      1);  // suppress IM warnings
    setenv("LIBGL_DRI3_DISABLE",   "1",     0);
    setenv("EGL_LOG_LEVEL",        "fatal", 0);
    setenv("GTK_A11Y",             "none",  0);  // suppress AT-SPI if no D-Bus
    setenv("NO_AT_BRIDGE",         "1",     0);
}

// ── Normal includes ─────────────────────────────────────────────────────────

#include "ui/app.hpp"
#include "core/executor.hpp"
#include "utils/logger.hpp"
#include "utils/config.hpp"

#include <csignal>
#include <iostream>
#include <filesystem>

// ── Async-signal-safe shutdown ──────────────────────────────────────────────

// FIX 1: use sizeof on literal — strlen is technically async-signal-safe
//        per POSIX but sizeof is zero-cost and guaranteed.
// FIX 2: exit with 128 + signum (Unix convention) instead of always 0.

static void signal_handler(int sig) {
    static constexpr char msg[] = "\n[!] Signal received, shutting down...\n";
    // write() and _exit() are async-signal-safe
    ssize_t unused = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)unused;
    _exit(128 + sig);
}

// ── Banner ──────────────────────────────────────────────────────────────────

// FIX 3: use APP_VERSION macro from CMakeLists.txt instead of hardcoded "v2.0"
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

// ── Ensure home directories exist ───────────────────────────────────────────

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

// ── main ────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    // ── 1. Signal handlers ──
    // FIX 4: ignore SIGPIPE — broken pipe from CURL / socket writes must
    //        not kill the process.
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    print_banner();

    int exit_code = 0;

    try {
        // ── 2. Logger (must be first so all subsequent LOG_* calls work) ──
        // FIX 5: logger was never initialized — all LOG_INFO etc. were no-ops
        //        or crashed depending on spdlog default-logger state.
        oss::Logger::instance().init("oss-executor");
        LOG_INFO("OSS Executor v{} starting", APP_VERSION);

        // ── 3. Config ──
        // FIX 6: config was never loaded — Executor::init() reads settings
        //        like "executor.auto_inject" which returned defaults silently.
        auto& config = oss::Config::instance();
        config.load();
        LOG_INFO("Configuration loaded from {}", config.home_dir());

        // ── 4. Home directory tree ──
        ensure_home_dirs(config.home_dir());

        // ── 5. Executor (Lua engine + hooks + injection) ──
        // FIX 7: executor was never initialized from main — App may or may
        //        not call init().  Wiring it here guarantees it's ready before
        //        the GTK activate signal fires.
        auto& executor = oss::Executor::instance();

        executor.set_output_callback([](const std::string& msg) {
            // Forward to logger until App wires its own console callback
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

        // ── 6. Auto-execute startup scripts ──
        if (config.get<bool>("executor.autoexec_on_start", true)) {
            executor.auto_execute();
        }

        // ── 7. GTK Application ──
        LOG_INFO("Starting UI...");
        oss::App app(argc, argv);
        exit_code = app.run();
        LOG_INFO("UI exited with code {}", exit_code);

        // ── 8. Graceful shutdown (reverse order) ──
        executor.shutdown();
        LOG_INFO("OSS Executor shut down cleanly");

    } catch (const std::exception& e) {
        // Can't use LOG_ERROR here — logger might be the thing that threw.
        std::cerr << "[FATAL] " << e.what() << std::endl;
        exit_code = 1;
    } catch (...) {
        std::cerr << "[FATAL] Unknown exception" << std::endl;
        exit_code = 1;
    }

    return exit_code;
}
