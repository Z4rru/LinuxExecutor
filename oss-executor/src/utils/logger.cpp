#include "logger.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <filesystem>

namespace oss {

void Logger::init(const std::string& log_dir) {
    try {
        std::filesystem::create_directories(log_dir);
    } catch (...) {}

    std::string log_path = log_dir + "/oss-executor.log";

    // ═══════════════════════════════════════════════════════
    // FIX: Console sink was missing in original.
    // Without this, LOG_INFO / LOG_ERROR produce NO
    // terminal output — user sees nothing when debugging.
    //
    // stderr (not stdout) so it doesn't mix with
    // script output that might go to stdout.
    // ═══════════════════════════════════════════════════════
    auto console_sink =
        std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
    console_sink->set_level(spdlog::level::debug);

    auto file_sink =
        std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_path, 1024 * 1024 * 5, 3);
    file_sink->set_level(spdlog::level::debug);

    auto logger = std::make_shared<spdlog::logger>(
        "oss",
        spdlog::sinks_init_list{console_sink, file_sink});

    logger->set_level(spdlog::level::debug);

    // ═══════════════════════════════════════════════════════
    // FIX: flush_on(debug) ensures messages appear
    // immediately in terminal, not buffered until exit.
    // Critical for debugging injection failures where the
    // process might crash/hang before buffer flushes.
    // ═══════════════════════════════════════════════════════
    logger->flush_on(spdlog::level::debug);

    spdlog::set_default_logger(logger);

    LOG_INFO("Logger initialized: {}", log_path);
}

void Logger::shutdown() {
    spdlog::shutdown();
}

} // namespace oss
