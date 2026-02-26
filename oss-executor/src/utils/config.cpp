#include "config.hpp"

#include <fstream>
#include <filesystem>
#include <cstdlib>

// If Config is fully implemented in the header (inline/template),
// this translation unit ensures the header compiles and provides
// any non-template definitions.

// If your config.hpp does NOT contain the implementation,
// uncomment and adapt the following:

/*
namespace oss {

Config& Config::instance() {
    static Config inst;
    return inst;
}

Config::Config() {
    const char* env_home = std::getenv("OSS_HOME");
    if (env_home && env_home[0] != '\0') {
        home_dir_ = env_home;
    } else {
        const char* user_home = std::getenv("HOME");
        home_dir_ = std::string(user_home ? user_home : "/tmp") + "/.oss-executor";
    }

    std::filesystem::create_directories(home_dir_);
    std::filesystem::create_directories(home_dir_ + "/workspace");
    std::filesystem::create_directories(home_dir_ + "/logs");
    std::filesystem::create_directories(home_dir_ + "/scripts/autoexec");
    std::filesystem::create_directories(home_dir_ + "/themes");
    std::filesystem::create_directories(home_dir_ + "/cache");
}

std::string Config::home_dir() const {
    return home_dir_;
}

void Config::load(const std::string& path) {
    if (!std::filesystem::exists(path)) return;

    std::ifstream file(path);
    if (!file.is_open()) return;

    try {
        data_ = nlohmann::json::parse(file);
    } catch (const std::exception& e) {
        // Log but don't crash — use defaults
    }
}

void Config::save(const std::string& path) {
    std::ofstream file(path);
    if (file.is_open()) {
        file << data_.dump(4);
    }
}

} // namespace oss
*/
