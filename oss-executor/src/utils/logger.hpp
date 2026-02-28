#pragma once

#include <spdlog/spdlog.h>
#include <string>

namespace oss {

class Logger {
public:
    /// Initialize console + rotating file sinks.
    /// Safe to call multiple times (subsequent calls are no-ops).
    /// Returns false if file logging could not be established
    /// (console logging will still work).
    static bool init(const std::string& log_dir = ".");

    /// Flush and tear down all spdlog loggers.
    /// Safe to call without prior init, or multiple times.
    static void shutdown();

    /// True between a successful init() and shutdown().
    static bool initialized();

private:
    static inline bool initialized_ = false;
};

} // namespace oss

// These use spdlog's fmt-style placeholders: {}
// NOT printf-style %d / %s.
#define LOG_DEBUG(...) spdlog::debug(__VA_ARGS__)
#define LOG_INFO(...)  spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)  spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...) spdlog::error(__VA_ARGS__)
