#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <filesystem>
#include <fstream>
#include <mutex>

namespace oss {

using json = nlohmann::json;

class Config {
public:
    static Config& instance() {
        static Config inst;
        return inst;
    }

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
            
            data_ = json::parse(f, nullptr, true, true);
            
            // Merge with defaults for any missing keys
            auto defaults = get_defaults();
            merge_defaults(data_, defaults);
            
            return true;
        } catch (const std::exception& e) {
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

    const json& raw() const { return data_; }
    
    std::string home_dir() const {
        const char* home = getenv("HOME");
        return std::string(home ? home : "/tmp") + "/.oss-executor";
    }

private:
    Config() = default;
    
    std::string replace_dots(const std::string& key) const {
        std::string result = key;
        for (auto& c : result) {
            if (c == '.') c = '/';
        }
        return result;
    }

    bool save_internal() {
        try {
            std::filesystem::create_directories(
                std::filesystem::path(path_).parent_path()
            );
            std::ofstream f(path_);
            f << data_.dump(4);
            return true;
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

    json get_defaults() {
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