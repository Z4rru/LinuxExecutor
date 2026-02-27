#pragma once

#include <string>
#include <functional>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <optional>
#include <atomic>
#include <queue>
#include <chrono>
#include <any>

extern "C" {
#include <luajit-2.1/lua.h>
#include <luajit-2.1/lualib.h>
#include <luajit-2.1/lauxlib.h>
}

#include "utils/logger.hpp"

namespace oss {

struct LuaError {
    std::string message;
    int line = -1;
    std::string source;
};

struct DrawingObject {
    enum class Type {
        Line, Circle, Rectangle, Triangle, Text, Quad, Image
    };

    int id = 0;
    Type type = Type::Line;
    bool visible = false;
    float thickness = 1.0f;
    float transparency = 1.0f;
    uint32_t color = 0xFFFFFFFF;
    bool filled = false;
    float size = 13.0f;
    std::string text;
    std::string font;

    struct Vec2 { float x = 0, y = 0; };
    Vec2 from, to;
    Vec2 position;
    Vec2 center;
    float radius = 0;
    int num_sides = 64;

    Vec2 point_a, point_b, point_c, point_d;

    bool zindex_changed = false;
    int zindex = 0;
};

struct ScheduledTask {
    enum class Type { Delay, Spawn, Defer };
    Type type;
    int thread_ref = LUA_NOREF;
    int func_ref = LUA_NOREF;
    double delay_seconds = 0;
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

class LuaEngine {
public:
    using OutputCallback = std::function<void(const std::string&)>;
    using ErrorCallback = std::function<void(const LuaError&)>;
    using DrawCallback = std::function<void(const DrawingObject&)>;
    using DrawRemoveCallback = std::function<void(int)>;

    LuaEngine();
    ~LuaEngine();

    LuaEngine(const LuaEngine&) = delete;
    LuaEngine& operator=(const LuaEngine&) = delete;

    bool init();
    void shutdown();
    void reset();

    bool execute(const std::string& script,
                 const std::string& chunk_name = "=input");
    bool execute_file(const std::string& path);

    void tick();

    void set_output_callback(OutputCallback cb) { output_cb_ = std::move(cb); }
    void set_error_callback(ErrorCallback cb) { error_cb_ = std::move(cb); }
    void set_draw_callback(DrawCallback cb) { draw_cb_ = std::move(cb); }
    void set_draw_remove_callback(DrawRemoveCallback cb) { draw_remove_cb_ = std::move(cb); }

    void register_function(const std::string& name, lua_CFunction func);
    void register_library(const std::string& name, const luaL_Reg* funcs);

    void set_global_string(const std::string& name, const std::string& value);
    void set_global_number(const std::string& name, double value);
    void set_global_bool(const std::string& name, bool value);

    std::optional<std::string> get_global_string(const std::string& name);

    lua_State* state() { return L_; }
    bool is_running() const { return running_.load(std::memory_order_acquire); }
    void stop() { running_.store(false, std::memory_order_release); }

    DrawingObject* get_drawing(int id);
    const std::unordered_map<int, DrawingObject>& get_all_drawings() const { return drawings_; }
    void remove_drawing(int id);
    void clear_drawings();

    int fire_signal(const std::string& name, int nargs = 0);
    Signal* get_signal(const std::string& name);
    Signal& get_or_create_signal(const std::string& name);

    int schedule_task(ScheduledTask task);
    void cancel_task(int task_id);
    size_t pending_task_count() const;

private:
    bool execute_internal(const std::string& script,
                          const std::string& chunk_name);
    void shutdown_internal();
    void process_tasks();

    static bool is_sandboxed(const std::string& full_path,
                             const std::string& base_dir);

    void setup_environment();
    void register_custom_libs();
    void register_task_lib();
    void register_drawing_lib();
    void register_signal_lib();
    void sandbox();

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
    static int lua_task_desynchronize(lua_State* L);
    static int lua_task_synchronize(lua_State* L);

    static int lua_drawing_new(lua_State* L);
    static int lua_drawing_index(lua_State* L);
    static int lua_drawing_newindex(lua_State* L);
    static int lua_drawing_remove(lua_State* L);
    static int lua_drawing_gc(lua_State* L);
    static int lua_drawing_clear(lua_State* L);

    static int lua_signal_new(lua_State* L);
    static int lua_signal_connect(lua_State* L);
    static int lua_signal_fire(lua_State* L);
    static int lua_signal_wait(lua_State* L);
    static int lua_signal_disconnect(lua_State* L);
    static int lua_signal_destroy(lua_State* L);
    static int lua_signal_gc(lua_State* L);

    lua_State* L_ = nullptr;
    std::atomic<bool> running_{false};
    OutputCallback output_cb_;
    ErrorCallback error_cb_;
    DrawCallback draw_cb_;
    DrawRemoveCallback draw_remove_cb_;
    mutable std::mutex mutex_;

    std::unordered_map<int, DrawingObject> drawings_;
    int next_drawing_id_ = 1;

    std::vector<ScheduledTask> tasks_;
    int next_task_id_ = 1;

    std::unordered_map<std::string, Signal> signals_;
};

} // namespace oss
