#include "script_manager.hpp"
#include "core/lua_engine.hpp"   // real engine — resolved via -I<src>
#include "utils/logger.hpp"

#include <algorithm>
#include <ctime>

namespace oss {

// ─────────────────────────────────────────────
// Path safety: reject anything that escapes dir_
// ─────────────────────────────────────────────
std::filesystem::path ScriptManager::safe_script_path(const std::string& name) const {
    if (name.empty() || dir_.empty()) return {};

    // Block directory traversal and absolute paths
    if (name.find("..") != std::string::npos ||
        name.front() == '/'                  ||
        name.front() == '\\')
    {
        LOG_ERROR("Rejected unsafe script name: {}", name);
        return {};
    }

    auto candidate = std::filesystem::path(dir_) / name;

    // Canonical parent must still be our dir_ (belt-and-suspenders)
    auto canonical_dir = std::filesystem::weakly_canonical(dir_);
    auto canonical_file = std::filesystem::weakly_canonical(candidate);

    // Verify the resolved file sits inside the scripts directory
    auto [dir_end, _] = std::mismatch(
        canonical_dir.begin(), canonical_dir.end(),
        canonical_file.begin(), canonical_file.end()
    );

    if (dir_end != canonical_dir.end()) {
        LOG_ERROR("Path escape detected: {} resolves outside {}", name, dir_);
        return {};
    }

    return candidate;
}

// ─────────────────────────────────────────────
void ScriptManager::set_directory(const std::string& dir) {
    if (dir.empty()) return;
    std::lock_guard lock(mtx_);
    dir_ = dir;
    try {
        std::filesystem::create_directories(dir);
    } catch (const std::filesystem::filesystem_error& e) {
        LOG_ERROR("Failed to create script directory {}: {}", dir, e.what());
    }
}

std::string ScriptManager::scripts_directory() const {
    std::lock_guard lock(mtx_);
    return dir_;
}

// ─────────────────────────────────────────────
// List
// ─────────────────────────────────────────────
std::vector<SavedScript> ScriptManager::list_scripts() const {
    std::vector<SavedScript> scripts;

    std::string dir;
    {
        std::lock_guard lock(mtx_);
        dir = dir_;
    }

    if (dir.empty() || !std::filesystem::exists(dir)) return scripts;

    try {
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (!entry.is_regular_file()) continue;

            auto ext = entry.path().extension().string();
            if (ext != ".lua" && ext != ".luau" && ext != ".txt") continue;

            SavedScript script;
            script.name = entry.path().filename().string();
            script.path = entry.path().string();
            script.size = entry.file_size();

            // Thread-safe time conversion
            auto ftime = entry.last_write_time();
            auto sctp  = std::chrono::time_point_cast<
                             std::chrono::system_clock::duration>(
                ftime - std::filesystem::file_time_type::clock::now()
                      + std::chrono::system_clock::now()
            );
            auto time_val = std::chrono::system_clock::to_time_t(sctp);

            struct tm tm_buf{};
            localtime_r(&time_val, &tm_buf);

            char time_str[64];
            strftime(time_str, sizeof(time_str),
                     "%Y-%m-%d %H:%M:%S", &tm_buf);
            script.modified_time = time_str;

            scripts.push_back(std::move(script));
        }
    } catch (const std::filesystem::filesystem_error& e) {
        LOG_ERROR("Failed to list scripts in {}: {}", dir, e.what());
    }

    std::sort(scripts.begin(), scripts.end(),
        [](const SavedScript& a, const SavedScript& b) {
            return a.name < b.name;
        });

    return scripts;
}

// ─────────────────────────────────────────────
// Save
// ─────────────────────────────────────────────
bool ScriptManager::save_script(const std::string& name,
                                const std::string& content)
{
    {
        std::lock_guard lock(mtx_);
        if (dir_.empty()) {
            LOG_ERROR("Script directory not set");
            return false;
        }
        std::filesystem::create_directories(dir_);
    }

    auto path = safe_script_path(name);
    if (path.empty()) return false;

    // Append .lua only when the *filename* has no extension
    if (!path.has_extension()) {
        path.replace_extension(".lua");
    }

    std::ofstream file(path);
    if (!file.is_open()) {
        LOG_ERROR("Failed to save script: {}", path.string());
        return false;
    }

    file << content;
    if (!file.good()) {
        LOG_ERROR("Write error for script: {}", path.string());
        return false;
    }

    LOG_INFO("Script saved: {}", path.filename().string());
    return true;
}

// ─────────────────────────────────────────────
// Load
// ─────────────────────────────────────────────
std::string ScriptManager::load_script(const std::string& name) const {
    auto path = safe_script_path(name);
    if (path.empty()) return "";

    std::ifstream file(path);
    if (!file.is_open()) {
        LOG_ERROR("Failed to load script: {}", path.string());
        return "";
    }

    return std::string(std::istreambuf_iterator<char>(file),
                       std::istreambuf_iterator<char>());
}

// ─────────────────────────────────────────────
// Delete
// ─────────────────────────────────────────────
bool ScriptManager::delete_script(const std::string& name) {
    auto path = safe_script_path(name);
    if (path.empty()) return false;

    try {
        bool removed = std::filesystem::remove(path);
        if (removed) LOG_INFO("Script deleted: {}", name);
        return removed;
    } catch (const std::filesystem::filesystem_error& e) {
        LOG_ERROR("Failed to delete script {}: {}", name, e.what());
        return false;
    }
}

// ─────────────────────────────────────────────
// Rename
// ─────────────────────────────────────────────
bool ScriptManager::rename_script(const std::string& old_name,
                                  const std::string& new_name)
{
    auto old_path = safe_script_path(old_name);
    auto new_path = safe_script_path(new_name);
    if (old_path.empty() || new_path.empty()) return false;

    try {
        std::filesystem::rename(old_path, new_path);
        LOG_INFO("Script renamed: {} → {}", old_name, new_name);
        return true;
    } catch (const std::filesystem::filesystem_error& e) {
        LOG_ERROR("Failed to rename {} → {}: {}",
                  old_name, new_name, e.what());
        return false;
    }
}

// ═════════════════════════════════════════════
// Real LuaEngine execution — no mocks
// ═════════════════════════════════════════════
bool ScriptManager::execute_script(const std::string& name) const {
    std::string source = load_script(name);
    if (source.empty()) {
        LOG_ERROR("Cannot execute empty/missing script: {}", name);
        return false;
    }

    LOG_INFO("Executing script: {}", name);
    LuaEngine::instance().queue_script(source, name);
    return true;
}

bool ScriptManager::execute_inline(const std::string& source) const {
    if (source.empty()) {
        LOG_ERROR("Cannot execute empty inline script");
        return false;
    }

    LuaEngine::instance().queue_script(source, "<inline>");
    return true;
}

} // namespace oss
