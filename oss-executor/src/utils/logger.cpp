#include "logger.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <filesystem>
#include <iostream>
#include <vector>
#include <memory>

namespace oss {

bool Logger::init(const std::string& log_dir) {
    if (initialized_) return true;

    spdlog::drop("oss");

    auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
    console_sink->set_level(spdlog::level::debug);
    console_sink->set_pattern("[%H:%M:%S.%e] [%^%l%$] %v");

    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(console_sink);

    bool file_ok = false;
    std::filesystem::path dir_path(log_dir);
    std::filesystem::path log_file = dir_path / "oss-executor.log";

    try {
        std::filesystem::create_directories(dir_path);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "[logger] Failed to create log directory '"
                  << log_dir << "': " << e.what() << "\n";
    }

    try {
        constexpr std::size_t max_size  = 5 * 1024 * 1024;
        constexpr std::size_t max_files = 3;

        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file.string(), max_size, max_files);
        file_sink->set_level(spdlog::level::debug);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

        sinks.push_back(file_sink);
        file_ok = true;
    } catch (const spdlog::spdlog_ex& e) {
        std::cerr << "[logger] Failed to open log file '"
                  << log_file.string() << "': " << e.what() << "\n";
    }

    auto logger = std::make_shared<spdlog::logger>("oss", sinks.begin(), sinks.end());
    logger->set_level(spdlog::level::debug);
    logger->flush_on(spdlog::level::warn);

    spdlog::set_default_logger(logger);

    initialized_ = true;

    if (file_ok)
        LOG_INFO("Logger initialized — file: {}", log_file.string());
    else
        LOG_WARN("Logger initialized — console only (file sink failed)");

    return file_ok;
}

void Logger::shutdown() {
    if (!initialized_) return;

    spdlog::default_logger()->flush();
    spdlog::drop("oss");
    spdlog::shutdown();

    initialized_ = false;
}

bool Logger::initialized() {
    return initialized_;
}

}
