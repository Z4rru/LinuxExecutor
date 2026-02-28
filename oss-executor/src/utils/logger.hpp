#pragma once

#include <spdlog/spdlog.h>
#include <string>

namespace oss {

class Logger {
public:
    static bool init(const std::string& log_dir = ".");
    static void shutdown();
    static bool initialized();

private:
    static inline bool initialized_ = false;
};

}

#define LOG_DEBUG(...) spdlog::debug(__VA_ARGS__)
#define LOG_INFO(...)  spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)  spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...) spdlog::error(__VA_ARGS__)
