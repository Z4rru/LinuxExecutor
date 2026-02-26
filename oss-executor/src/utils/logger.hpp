#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <memory>
#include <string>
#include <filesystem>

namespace oss {

class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    void init(const std::string& log_dir) {
        namespace fs = std::filesystem;
        fs::create_directories(log_dir);
        
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);
        console_sink->set_pattern("[%H:%M:%S.%e] [%^%l%$] %v");

        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_dir + "/oss-executor.log", 5 * 1024 * 1024, 3
        );
        file_sink->set_level(spdlog::level::trace);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%s:%#] %v");

        std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
        logger_ = std::make_shared<spdlog::logger>("oss", sinks.begin(), sinks.end());
        logger_->set_level(spdlog::level::trace);
        logger_->flush_on(spdlog::level::warn);
        
        spdlog::set_default_logger(logger_);
        spdlog::info("OSS Executor Logger initialized");
    }

    std::shared_ptr<spdlog::logger>& get() { return logger_; }

    using LogCallback = std::function<void(spdlog::level::level_enum, const std::string&)>;
    
    void set_ui_callback(LogCallback cb) {
        ui_callback_ = std::move(cb);
    }

    void log_to_ui(spdlog::level::level_enum level, const std::string& msg) {
        if (ui_callback_) ui_callback_(level, msg);
    }

private:
    Logger() = default;
    std::shared_ptr<spdlog::logger> logger_;
    LogCallback ui_callback_;
};

#define LOG_TRACE(...)    SPDLOG_TRACE(__VA_ARGS__)
#define LOG_DEBUG(...)    SPDLOG_DEBUG(__VA_ARGS__)
#define LOG_INFO(...)     SPDLOG_INFO(__VA_ARGS__)
#define LOG_WARN(...)     SPDLOG_WARN(__VA_ARGS__)
#define LOG_ERROR(...)    SPDLOG_ERROR(__VA_ARGS__)
#define LOG_CRITICAL(...) SPDLOG_CRITICAL(__VA_ARGS__)

} // namespace oss