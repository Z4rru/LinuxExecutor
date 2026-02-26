#include "script_manager.hpp"
#include "utils/logger.hpp"

namespace oss {

std::vector<SavedScript> ScriptManager::list_scripts() const {
    std::vector<SavedScript> scripts;
    
    if (!std::filesystem::exists(dir_)) return scripts;
    
    for (const auto& entry : std::filesystem::directory_iterator(dir_)) {
        if (!entry.is_regular_file()) continue;
        
        auto ext = entry.path().extension().string();
        if (ext != ".lua" && ext != ".luau" && ext != ".txt") continue;
        
        SavedScript script;
        script.name = entry.path().filename().string();
        script.path = entry.path().string();
        script.size = entry.file_size();
        
        auto ftime = entry.last_write_time();
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        auto time = std::chrono::system_clock::to_time_t(sctp);
        script.modified_time = std::ctime(&time);
        if (!script.modified_time.empty() && script.modified_time.back() == '\n')
            script.modified_time.pop_back();
        
        scripts.push_back(script);
    }
    
    std::sort(scripts.begin(), scripts.end(), 
        [](const SavedScript& a, const SavedScript& b) { return a.name < b.name; });
    
    return scripts;
}

bool ScriptManager::save_script(const std::string& name, const std::string& content) {
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
    return std::filesystem::remove(path);
}

bool ScriptManager::rename_script(const std::string& old_name, const std::string& new_name) {
    std::string old_path = dir_ + "/" + old_name;
    std::string new_path = dir_ + "/" + new_name;
    
    try {
        std::filesystem::rename(old_path, new_path);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace oss