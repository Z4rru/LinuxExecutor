#pragma once

namespace oss {

class LuaEngine;

class Environment {
public:
    static void setup(LuaEngine& engine);

    static void setup_debug_lib(LuaEngine& engine);
    static void setup_cache_lib(LuaEngine& engine);
    static void setup_metatable_lib(LuaEngine& engine);
    static void setup_input_lib(LuaEngine& engine);
    static void setup_instance_lib(LuaEngine& engine);
    static void setup_script_lib(LuaEngine& engine);
    static void setup_websocket_lib(LuaEngine& engine);
    static void setup_thread_lib(LuaEngine& engine);
    static void setup_closure_lib(LuaEngine& engine);
    static void setup_drawing_bridge(LuaEngine& engine);
    static void setup_gui_bridge(LuaEngine& engine);
    static void setup_roblox_mock(LuaEngine& engine);
};

} // namespace oss
