#pragma once

#include <string>

struct lua_State;

namespace oss {

class LuaEngine;

class Environment {
public:
    static Environment& instance();

    // Full environment setup — either entry point
    void setup(LuaEngine& engine);
    void setup(lua_State* L);

private:
    Environment() = default;

    // ── Core registration groups ────────────────────────────
    void register_globals        (lua_State* L);
    void register_data_types     (lua_State* L);
    void register_services       (lua_State* L);

    // ── API surfaces ───────────────────────────────────────
    void register_instance_api   (lua_State* L);
    void register_input_api      (lua_State* L);
    void register_drawing_api    (lua_State* L);
    void register_debug_api      (lua_State* L);

    // ── Executor / script runtime ──────────────────────────
    void register_executor_functions(lua_State* L);
    void register_script_lib     (lua_State* L);
    void register_task_library   (lua_State* L);
    void register_thread_lib     (lua_State* L);
    void register_closure_lib    (lua_State* L);

    // ── Caching & metatables ───────────────────────────────
    void register_cache_lib      (lua_State* L);
    void register_metatable_lib  (lua_State* L);

    // ── Networking ─────────────────────────────────────────
    void register_websocket_lib  (lua_State* L);

    // ── UI / bridge layers ─────────────────────────────────
    void register_gui_bridge     (lua_State* L);
    void register_roblox_mock    (lua_State* L);
};

} // namespace oss
