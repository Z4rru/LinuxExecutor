#pragma once

#include <string>
#include <functional>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <optional>
#include <atomic>

// PkgConfig::LUAJIT adds -I/usr/include/luajit-2.1 (or -2.0),
// so <lua.h> resolves correctly.  Do NOT use <luajit-2.1/lua.h>
// with IMPORTED_TARGET — that would double the subdirectory.
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
    void reset();   // tear down + re-init (used by cancel_execution)

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

    // Signals the Lua debug hook to abort execution
    void stop() { running_.store(false, std::memory_order_release); }

private:
    void setup_environment();
    void register_custom_libs();
    void sandbox();

    // Lua C callbacks (must be static)
    static int lua_print(lua_State* L);
    static int lua_warn_handler(lua_State* L);
    static int lua_pcall_handler(lua_State* L);

    // Custom library functions
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
    std::atomic<bool>  running_{false};    // cross-thread safe
    OutputCallback     output_cb_;
    ErrorCallback      error_cb_;
    mutable std::mutex mutex_;
};

} // namespace oss
