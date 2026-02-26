#include "script_manager.hpp"
#include "utils/logger.hpp"

#include <algorithm>  // std::sort — was MISSING
#include <ctime>      // localtime_r, strftime — was MISSING

namespace oss {

std::vector<SavedScript> ScriptManager::list_scripts() const {
    std::vector<SavedScript> scripts;

    if (dir_.empty() || !std::filesystem::exists(dir_)) return scripts;

    try {
        for (const auto& entry : std::filesystem::directory_iterator(dir_)) {
            if (!entry.is_regular_file()) continue;

            auto ext = entry.path().extension().string();
            if (ext != ".lua" && ext != ".luau" && ext != ".txt") continue;

            SavedScript script;
            script.name = entry.path().filename().string();
            script.path = entry.path().string();
            script.size = entry.file_size();

            // ═══════════════════════════════════════════════════
            // ██  FIX: std::ctime → localtime_r + strftime     ██
            // ██  std::ctime uses a static buffer (not thread   ██
            // ██  safe).  localtime_r is POSIX thread-safe.     ██
            // ═══════════════════════════════════════════════════
            auto ftime = entry.last_write_time();
            auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ftime - std::filesystem::file_time_type::clock::now()
                      + std::chrono::system_clock::now()
            );
            auto time_val = std::chrono::system_clock::to_time_t(sctp);

            struct tm tm_buf{};
            localtime_r(&time_val, &tm_buf);
            char time_str[64];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
            script.modified_time = time_str;

            scripts.push_back(std::move(script));
        }
    } catch (const std::filesystem::filesystem_error& e) {
        LOG_ERROR("Failed to list scripts in {}: {}", dir_, e.what());
    }

    std::sort(scripts.begin(), scripts.end(),
        [](const SavedScript& a, const SavedScript& b) { return a.name < b.name; });

    return scripts;
}

bool ScriptManager::save_script(const std::string& name, const std::string& content) {
    if (dir_.empty()) {
        LOG_ERROR("Script directory not set");
        return false;
    }

    // Ensure directory exists before writing
    std::filesystem::create_directories(dir_);

    std::string path = dir_ + "/" + name;

    // Ensure .lua extension
    if (path.find('.') == std::string::npos) path += ".lua";

    std::ofstream file(path);
    if (!file.is_open()) {
        LOG_ERROR("Failed to save script: {}", path);
        return false;
    }

    file << content;
    LOG_INFO("Script saved: {}", name);
    return true;
}

std::string ScriptManager::load_script(const std::string& name) const {
    std::string path = dir_ + "/" + name;

    std::ifstream file(path);
    if (!file.is_open()) {
        LOG_ERROR("Failed to load script: {}", path);
        return "";
    }

    return std::string((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
}

bool ScriptManager::delete_script(const std::string& name) {
    std::string path = dir_ + "/" + name;
    try {
        return std::filesystem::remove(path);
    } catch (const std::filesystem::filesystem_error& e) {
        LOG_ERROR("Failed to delete script {}: {}", name, e.what());
        return false;
    }
}

bool ScriptManager::rename_script(const std::string& old_name, const std::string& new_name) {
    std::string old_path = dir_ + "/" + old_name;
    std::string new_path = dir_ + "/" + new_name;

    try {
        std::filesystem::rename(old_path, new_path);
        return true;
    } catch (const std::filesystem::filesystem_error& e) {
        LOG_ERROR("Failed to rename {} → {}: {}", old_name, new_name, e.what());
        return false;
    }
}

} // namespace oss
