#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <cstdlib>

namespace oss {

using json = nlohmann::json;

class Config {
public:
    static Config& instance() {
        static Config inst;
        return inst;
    }

    Config(const Config&)            = delete;
    Config& operator=(const Config&) = delete;

    bool load(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        path_ = path;

        try {
            if (!std::filesystem::exists(path)) {
                data_ = get_defaults();
                save_internal();
                return true;
            }

            std::ifstream f(path);
            if (!f.is_open()) return false;

            data_ = json::parse(f, nullptr, /*allow_exceptions=*/true,
                                /*ignore_comments=*/true);

            // Merge with defaults for any missing keys
            auto defaults = get_defaults();
            merge_defaults(data_, defaults);

            return true;
        } catch (const std::exception& /*e*/) {
            data_ = get_defaults();
            return false;
        }
    }

    bool save() {
        std::lock_guard<std::mutex> lock(mutex_);
        return save_internal();
    }

    template<typename T>
    T get(const std::string& key, const T& default_val = T{}) const {
        std::lock_guard<std::mutex> lock(mutex_);
        try {
            auto ptr = json::json_pointer("/" + replace_dots(key));
            if (data_.contains(ptr)) {
                return data_.at(ptr).get<T>();
            }
        } catch (...) {}
        return default_val;
    }

    template<typename T>
    void set(const std::string& key, const T& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto ptr = json::json_pointer("/" + replace_dots(key));
        data_[ptr] = value;
    }

    const json& raw() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return data_;
    }

    std::string home_dir() const {
        // Allow override via environment variable
        const char* oss_home = std::getenv("OSS_HOME");
        if (oss_home && oss_home[0] != '\0') {
            return std::string(oss_home);
        }
        const char* user_home = std::getenv("HOME");
        return std::string(user_home ? user_home : "/tmp") + "/.oss-executor";
    }

private:
    Config() {
        // Ensure essential directories exist on construction
        auto home = home_dir();
        std::filesystem::create_directories(home);
        std::filesystem::create_directories(home + "/workspace");
        std::filesystem::create_directories(home + "/logs");
        std::filesystem::create_directories(home + "/scripts/autoexec");
        std::filesystem::create_directories(home + "/themes");
        std::filesystem::create_directories(home + "/cache");
    }

    std::string replace_dots(const std::string& key) const {
        std::string result = key;
        for (auto& c : result) {
            if (c == '.') c = '/';
        }
        return result;
    }

    bool save_internal() {
        try {
            auto parent = std::filesystem::path(path_).parent_path();
            if (!parent.empty()) {
                std::filesystem::create_directories(parent);
            }
            std::ofstream f(path_);
            if (!f.is_open()) return false;
            f << data_.dump(4);
            return f.good();
        } catch (...) {
            return false;
        }
    }

    void merge_defaults(json& target, const json& defaults) {
        for (auto it = defaults.begin(); it != defaults.end(); ++it) {
            if (!target.contains(it.key())) {
                target[it.key()] = it.value();
            } else if (it.value().is_object() && target[it.key()].is_object()) {
                merge_defaults(target[it.key()], it.value());
            }
        }
    }

    static json get_defaults() {
        return json::parse(R"({
            "version": "2.0.0",
            "executor": {
                "auto_inject": false,
                "auto_execute_folder": "scripts/autoexec",
                "top_most": true,
                "save_tabs": true,
                "max_output_lines": 5000,
                "execution_timeout_ms": 30000
            },
            "editor": {
                "font_family": "JetBrains Mono",
                "font_size": 14,
                "tab_size": 4,
                "word_wrap": true,
                "line_numbers": true,
                "highlight_current_line": true,
                "auto_indent": true
            },
            "theme": "midnight",
            "keybinds": {
                "execute": "Ctrl+Return",
                "clear": "Ctrl+L",
                "save": "Ctrl+S",
                "inject": "F5"
            }
        })");
    }

    json data_;
    std::string path_;
    mutable std::mutex mutex_;
};

} // namespace oss
