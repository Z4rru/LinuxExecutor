#pragma once

#include <string>
#include <functional>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <optional>
#include <atomic>

extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

#include "utils/logger.hpp"

namespace oss {

struct LuaError {
    std::string message;
    int         line = -1;
    std::string source;
};

class LuaEngine {
public:
    using OutputCallback = std::function<void(const std::string&)>;
    using ErrorCallback  = std::function<void(const LuaError&)>;

    LuaEngine();
    ~LuaEngine();

    LuaEngine(const LuaEngine&)            = delete;
    LuaEngine& operator=(const LuaEngine&) = delete;

    bool init();
    void shutdown();
    void reset();

    bool execute(const std::string& script,
                 const std::string& chunk_name = "=input");
    bool execute_file(const std::string& path);

    void set_output_callback(OutputCallback cb) { output_cb_ = std::move(cb); }
    void set_error_callback(ErrorCallback  cb)  { error_cb_  = std::move(cb); }

    void register_function(const std::string& name, lua_CFunction func);
    void register_library(const std::string& name, const luaL_Reg* funcs);

    void set_global_string(const std::string& name, const std::string& value);
    void set_global_number(const std::string& name, double value);
    void set_global_bool(const std::string& name, bool value);

    std::optional<std::string> get_global_string(const std::string& name);

    lua_State* state()      { return L_; }
    bool is_running() const { return running_.load(std::memory_order_acquire); }

    void stop() { running_.store(false, std::memory_order_release); }

private:
    // ═══════════════════════════════════════════════════════
    // ██  DEADLOCK FIX: Internal versions of execute() and  ██
    // ██  shutdown() that do NOT acquire mutex_.             ██
    // ██                                                     ██
    // ██  init() holds mutex_ and calls:                     ██
    // ██    → shutdown_internal()  (to reset if re-init)     ██
    // ██    → execute_internal()   (for env_setup/sandbox)   ██
    // ██                                                     ██
    // ██  Public execute()/shutdown() acquire mutex_ then    ██
    // ██  delegate to the _internal versions.                ██
    // ═══════════════════════════════════════════════════════
    bool execute_internal(const std::string& script,
                          const std::string& chunk_name);
    void shutdown_internal();

    // ═══════════════════════════════════════════════════════
    // ██  PATH TRAVERSAL FIX: Validates that resolved path  ██
    // ██  is strictly inside the sandbox directory.          ██
    // ██                                                     ██
    // ██  BEFORE: used string::find which matched            ██
    // ██  /workspace2/ as being inside /workspace/           ██
    // ═══════════════════════════════════════════════════════
    static bool is_sandboxed(const std::string& full_path,
                             const std::string& base_dir);

    void setup_environment();
    void register_custom_libs();
    void sandbox();

    // Lua C callbacks
    static int lua_print(lua_State* L);
    static int lua_warn_handler(lua_State* L);
    static int lua_pcall_handler(lua_State* L);

    static int lua_http_get(lua_State* L);
    static int lua_http_post(lua_State* L);
    static int lua_wait(lua_State* L);
    static int lua_spawn(lua_State* L);
    static int lua_readfile(lua_State* L);
    static int lua_writefile(lua_State* L);
    static int lua_appendfile(lua_State* L);
    static int lua_isfile(lua_State* L);
    static int lua_listfiles(lua_State* L);
    static int lua_delfolder(lua_State* L);
    static int lua_makefolder(lua_State* L);
    static int lua_getclipboard(lua_State* L);
    static int lua_setclipboard(lua_State* L);
    static int lua_identifyexecutor(lua_State* L);
    static int lua_getexecutorname(lua_State* L);
    static int lua_get_hwid(lua_State* L);
    static int lua_rconsole_print(lua_State* L);
    static int lua_rconsole_clear(lua_State* L);
    static int lua_base64_encode(lua_State* L);
    static int lua_base64_decode(lua_State* L);
    static int lua_sha256(lua_State* L);

    lua_State*         L_ = nullptr;
    std::atomic<bool>  running_{false};
    OutputCallback     output_cb_;
    ErrorCallback      error_cb_;
    mutable std::mutex mutex_;
};

} // namespace oss
