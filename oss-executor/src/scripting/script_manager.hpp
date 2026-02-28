#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <mutex>

namespace oss {

struct SavedScript {
    std::string name;
    std::string path;
    size_t      size = 0;
    std::string modified_time;
};

class ScriptManager {
public:
    static ScriptManager& instance() {
        static ScriptManager inst;
        return inst;
    }

    void set_directory(const std::string& dir);

    std::vector<SavedScript> list_scripts() const;

    bool        save_script(const std::string& name, const std::string& content);
    std::string load_script(const std::string& name) const;
    bool        delete_script(const std::string& name);
    bool        rename_script(const std::string& old_name, const std::string& new_name);

    bool execute_script(const std::string& name) const;
    bool execute_inline(const std::string& source) const;

    std::string scripts_directory() const;

private:
    ScriptManager() = default;
    ScriptManager(const ScriptManager&)            = delete;
    ScriptManager& operator=(const ScriptManager&) = delete;

    std::filesystem::path safe_script_path(const std::string& name) const;

    mutable std::mutex mtx_;
    std::string        dir_;
};

}
