#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

namespace oss {

struct SavedScript {
    std::string name;
    std::string path;
    std::string content;
    size_t size;
    std::string modified_time;
};

class ScriptManager {
public:
    static ScriptManager& instance() {
        static ScriptManager inst;
        return inst;
    }

    void set_directory(const std::string& dir) { 
        dir_ = dir;
        std::filesystem::create_directories(dir);
    }
    
    std::vector<SavedScript> list_scripts() const;
    
    bool save_script(const std::string& name, const std::string& content);
    std::string load_script(const std::string& name) const;
    bool delete_script(const std::string& name);
    bool rename_script(const std::string& old_name, const std::string& new_name);
    
    std::string scripts_directory() const { return dir_; }

private:
    ScriptManager() = default;
    std::string dir_;
};

} // namespace oss