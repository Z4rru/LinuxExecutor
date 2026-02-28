#pragma once

#include <string>
#include <functional>
#include <vector>
#include <queue>
#include <unordered_map>
#include <mutex>
#include <optional>
#include <atomic>
#include <chrono>

#include "lua.h"
#include "lualib.h"

#include "utils/logger.hpp"
#include "ui/drawing_object.hpp"

namespace oss {

struct LuaError {
    std::string message;
    int         line = -1;
    std::string source;
};

struct ScheduledTask {
    enum class Type { Delay, Spawn, Defer };
    Type   type          = Type::Defer;
    int    thread_ref    = LUA_NOREF;
    int    func_ref      = LUA_NOREF;
    double delay_seconds = 0.0;
    std::chrono::steady_clock::time_point resume_at;
    std::vector<int> arg_refs;
    bool   cancelled     = false;
    int    id            = 0;
};

struct Signal {
    struct Connection {
        int  callback_ref = LUA_NOREF;
        int  id           = 0;
        bool connected    = true;
    };

    std::string             name;
    std::vector<Connection> connections;
    int                     next_id = 1;
};

class LuaEngine {
public:
    using OutputCallback = std::function<void(const std::string&)>;
    using ErrorCallback  = std::function<void(const LuaError&)>;
    using ExecCallback   = std::function<void(bool success, const std::string& error)>;

    static LuaEngine& instance();

    bool init();
    void shutdown();
    void reset();

    bool execute(const std::string& script,
                 const std::string& chunk_name = "=input");
    bool execute_file(const std::string& path);
    bool execute_bytecode(const std::string& bytecode,
                          const std::string& chunk_name = "=bytecode");

    std::string compile(const std::string& source);

    void queue_script(const std::string& source,
                      const std::string& name = "");
    void process_queue();

    void tick();

    void set_output_callback(OutputCallback cb) { output_cb_ = std::move(cb); }
    void set_error_callback(ErrorCallback cb)   { error_cb_  = std::move(cb); }
    void set_exec_callback(ExecCallback cb)     { exec_cb_   = std::move(cb); }

    void register_function(const std::string& name, lua_CFunction func);
    void register_library(const std::string& name, const luaL_Reg* funcs);

    void set_global_string(const std::string& name, const std::string& value);
    void set_global_number(const std::string& name, double value);
    void set_global_bool(const std::string& name, bool value);

    std::optional<std::string> get_global_string(const std::string& name);

    lua_State* state() const { return L_; }
    bool is_ready()   const { return ready_.load(std::memory_order_acquire); }
    bool is_running() const { return running_.load(std::memory_order_acquire); }
    void stop()             { running_.store(false, std::memory_order_release); }

    const std::string& last_error() const { return last_error_; }

    size_t memory_usage() const { return total_allocated_; }
    static constexpr size_t memory_limit() { return MAX_MEMORY; }

    int     fire_signal(const std::string& name, int nargs = 0);
    Signal* get_signal(const std::string& name);
    Signal& get_or_create_signal(const std::string& name);

    int    schedule_task(ScheduledTask task);
    void   cancel_task(int task_id);
    size_t pending_task_count() const;

    int  create_drawing_object(DrawingObject::Type type);
    bool get_drawing_object(int id, DrawingObject& out);
    bool update_drawing_object(int id,
                               const std::function<void(DrawingObject&)>& fn);
    bool remove_drawing_object(int id);
    void clear_all_drawing_objects();
    size_t drawing_object_count() const {
        std::lock_guard<std::mutex> dlock(drawing_mutex_);
        return drawing_objects_.size();
    }

    std::unordered_map<std::string, Signal> signals_;
    OutputCallback output_cb_;
    ErrorCallback  error_cb_;

    friend class Executor;

private:
    LuaEngine();
    ~LuaEngine();
    LuaEngine(const LuaEngine&)            = delete;
    LuaEngine& operator=(const LuaEngine&) = delete;

    bool execute_internal(const std::string& script,
                          const std::string& chunk_name);
    void shutdown_internal();

    bool execute_bytecode_internal(const std::string& bytecode,
                                   const std::string& chunk_name);

    void process_tasks();
    void release_task_refs(ScheduledTask& task);
    void execute_task(ScheduledTask& task,
                      std::chrono::steady_clock::time_point now);

    static bool is_sandboxed(const std::string& full_path,
                             const std::string& base_dir);

    void setup_environment();
    void register_custom_libs();
    void register_task_lib();
    void register_drawing_lib();
    void register_signal_lib();
    void sandbox();

    static void* lua_alloc(void* ud, void* ptr, size_t osize, size_t nsize);
    static void  lua_interrupt(lua_State* L, int gc);

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

    static int lua_task_spawn(lua_State* L);
    static int lua_task_delay(lua_State* L);
    static int lua_task_defer(lua_State* L);
    static int lua_task_wait(lua_State* L);
    static int lua_task_cancel(lua_State* L);

    static int lua_drawing_new(lua_State* L);
    static int lua_drawing_index(lua_State* L);
    static int lua_drawing_newindex(lua_State* L);
    static int lua_drawing_remove(lua_State* L);
    static int lua_drawing_gc(lua_State* L);
    static int lua_drawing_tostring(lua_State* L);
    static int lua_drawing_clear(lua_State* L);
    static int lua_drawing_is_rendered(lua_State* L);
    static int lua_drawing_get_screen_size(lua_State* L);

    static int lua_signal_new(lua_State* L);
    static int lua_signal_connect(lua_State* L);
    static int lua_signal_fire(lua_State* L);
    static int lua_signal_wait(lua_State* L);
    static int lua_signal_disconnect(lua_State* L);
    static int lua_signal_destroy(lua_State* L);
    static int lua_signal_gc(lua_State* L);

    lua_State*        L_ = nullptr;
    std::atomic<bool> ready_{false};
    std::atomic<bool> running_{false};
    mutable std::mutex mutex_;

    std::string last_error_;

    std::vector<ScheduledTask> tasks_;
    int next_task_id_ = 1;

    mutable std::mutex drawing_mutex_;
    std::unordered_map<int, DrawingObject> drawing_objects_;
    int next_drawing_id_ = 1;

    int next_signal_id_ = 1;

    struct QueuedScript {
        std::string source;
        std::string name;
    };
    std::queue<QueuedScript> script_queue_;
    std::mutex               queue_mutex_;

    ExecCallback exec_cb_;

    size_t total_allocated_ = 0;
    static constexpr size_t MAX_MEMORY = 256 * 1024 * 1024;
};

}
