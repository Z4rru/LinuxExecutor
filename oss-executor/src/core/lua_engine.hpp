#pragma once

#include <string>
#include <functional>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <optional>
#include <atomic>
#include <chrono>

extern "C" {
#include <luajit-2.1/lua.h>
#include <luajit-2.1/lualib.h>
#include <luajit-2.1/lauxlib.h>
}

#include "utils/logger.hpp"

// Forward declaration — avoid pulling in full overlay/drawing headers
// DrawingObject must be fully defined before LuaEngine is instantiated,
// but we only need the forward decl for the header itself.
#include "ui/drawing_object.hpp"

namespace oss {

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

struct LuaError {
    std::string message;
    int line = -1;
    std::string source;
};

struct ScheduledTask {
    enum class Type { Delay, Spawn, Defer };
    Type type = Type::Defer;
    int thread_ref = LUA_NOREF;
    int func_ref   = LUA_NOREF;
    double delay_seconds = 0.0;
    std::chrono::steady_clock::time_point resume_at;
    std::vector<int> arg_refs;
    bool cancelled = false;
    int id = 0;
};

struct Signal {
    struct Connection {
        int callback_ref = LUA_NOREF;
        int id = 0;
        bool connected = true;
    };

    std::string name;
    std::vector<Connection> connections;
    int next_id = 1;
};

// ---------------------------------------------------------------------------
// LuaEngine
// ---------------------------------------------------------------------------

class LuaEngine {
public:
    using OutputCallback = std::function<void(const std::string&)>;
    using ErrorCallback  = std::function<void(const LuaError&)>;

    LuaEngine();
    ~LuaEngine();

    LuaEngine(const LuaEngine&) = delete;
    LuaEngine& operator=(const LuaEngine&) = delete;

    // --- Lifecycle ---
    bool init();
    void shutdown();
    void reset();

    // --- Execution ---
    bool execute(const std::string& script,
                 const std::string& chunk_name = "=input");
    bool execute_file(const std::string& path);

    // --- Per-frame tick (drives task scheduler) ---
    void tick();

    // --- Callbacks ---
    void set_output_callback(OutputCallback cb) { output_cb_ = std::move(cb); }
    void set_error_callback(ErrorCallback cb)   { error_cb_  = std::move(cb); }

    // --- Global registration ---
    void register_function(const std::string& name, lua_CFunction func);
    void register_library(const std::string& name, const luaL_Reg* funcs);

    void set_global_string(const std::string& name, const std::string& value);
    void set_global_number(const std::string& name, double value);
    void set_global_bool(const std::string& name, bool value);

    std::optional<std::string> get_global_string(const std::string& name);

    // --- State access ---
    lua_State* state() { return L_; }
    bool is_running() const { return running_.load(std::memory_order_acquire); }
    void stop()             { running_.store(false, std::memory_order_release); }

    // --- Signal system ---
    int     fire_signal(const std::string& name, int nargs = 0);
    Signal* get_signal(const std::string& name);
    Signal& get_or_create_signal(const std::string& name);

    // --- Task scheduler ---
    int    schedule_task(ScheduledTask task);
    void   cancel_task(int task_id);
    size_t pending_task_count() const;

    // --- Drawing object store ---
    int  create_drawing_object(DrawingObject::Type type);
    bool get_drawing_object(int id, DrawingObject& out);
    bool update_drawing_object(int id, const std::function<void(DrawingObject&)>& fn);
    bool remove_drawing_object(int id);
    void clear_all_drawing_objects();

    // Signals map needs friend access from signal static functions
    // (lua_signal_destroy, lua_signal_gc access signals_ directly)
    std::unordered_map<std::string, Signal> signals_;

    // Callbacks need friend access from static Lua C functions
    OutputCallback output_cb_;
    ErrorCallback  error_cb_;

private:
    // --- Internal execution ---
    bool execute_internal(const std::string& script,
                          const std::string& chunk_name);
    void shutdown_internal();

    // --- Task scheduler internals ---
    void process_tasks();
    void release_task_refs(ScheduledTask& task);
    void execute_task(ScheduledTask& task,
                      std::chrono::steady_clock::time_point now);

    // --- Sandbox ---
    static bool is_sandboxed(const std::string& full_path,
                             const std::string& base_dir);

    // --- Library/environment registration ---
    void setup_environment();
    void register_custom_libs();
    void register_task_lib();
    void register_drawing_lib();
    void register_signal_lib();
    void sandbox();

    // -----------------------------------------------------------------------
    // Static Lua C functions
    // -----------------------------------------------------------------------

    // Core
    static int lua_print(lua_State* L);
    static int lua_warn_handler(lua_State* L);
    static int lua_pcall_handler(lua_State* L);

    // HTTP
    static int lua_http_get(lua_State* L);
    static int lua_http_post(lua_State* L);

    // Global wait/spawn
    static int lua_wait(lua_State* L);
    static int lua_spawn(lua_State* L);

    // Filesystem
    static int lua_readfile(lua_State* L);
    static int lua_writefile(lua_State* L);
    static int lua_appendfile(lua_State* L);
    static int lua_isfile(lua_State* L);
    static int lua_listfiles(lua_State* L);
    static int lua_delfolder(lua_State* L);
    static int lua_makefolder(lua_State* L);

    // Clipboard
    static int lua_getclipboard(lua_State* L);
    static int lua_setclipboard(lua_State* L);

    // Identity
    static int lua_identifyexecutor(lua_State* L);
    static int lua_getexecutorname(lua_State* L);
    static int lua_get_hwid(lua_State* L);

    // Console
    static int lua_rconsole_print(lua_State* L);
    static int lua_rconsole_clear(lua_State* L);

    // Crypto
    static int lua_base64_encode(lua_State* L);
    static int lua_base64_decode(lua_State* L);
    static int lua_sha256(lua_State* L);

    // Task library
    static int lua_task_spawn(lua_State* L);
    static int lua_task_delay(lua_State* L);
    static int lua_task_defer(lua_State* L);
    static int lua_task_wait(lua_State* L);
    static int lua_task_cancel(lua_State* L);
    static int lua_task_desynchronize(lua_State* L);
    static int lua_task_synchronize(lua_State* L);

    // Drawing library
    static int lua_drawing_new(lua_State* L);
    static int lua_drawing_index(lua_State* L);
    static int lua_drawing_newindex(lua_State* L);
    static int lua_drawing_remove(lua_State* L);
    static int lua_drawing_gc(lua_State* L);
    static int lua_drawing_tostring(lua_State* L);
    static int lua_drawing_clear(lua_State* L);
    static int lua_drawing_is_rendered(lua_State* L);
    static int lua_drawing_get_screen_size(lua_State* L);

    // Signal library
    static int lua_signal_new(lua_State* L);
    static int lua_signal_connect(lua_State* L);
    static int lua_signal_fire(lua_State* L);
    static int lua_signal_wait(lua_State* L);
    static int lua_signal_disconnect(lua_State* L);
    static int lua_signal_destroy(lua_State* L);
    static int lua_signal_gc(lua_State* L);

    // -----------------------------------------------------------------------
    // Member data
    // -----------------------------------------------------------------------

    lua_State* L_ = nullptr;
    std::atomic<bool> running_{false};
    mutable std::mutex mutex_;

    // Task scheduler state
    std::vector<ScheduledTask> tasks_;
    int next_task_id_ = 1;

    // Drawing object store (engine-authoritative, synced to Overlay)
    std::mutex drawing_mutex_;
    std::unordered_map<int, DrawingObject> drawing_objects_;
    int next_drawing_id_ = 1;

    // Signal ID counter
    int next_signal_id_ = 1;
};

} // namespace oss
