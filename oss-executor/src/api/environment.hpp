#pragma once

#include "core/lua_engine.hpp"
#include <string>
#include <unordered_map>
#include <functional>

namespace oss {

// Extended Roblox environment compatibility layer
class Environment {
public:
    static void setup(LuaEngine& engine);

private:
    static void register_globals(lua_State* L);
    static void register_drawing_lib(lua_State* L);
    static void register_debug_lib(lua_State* L);
    static void register_cache_lib(lua_State* L);
    
    // Instance mock for standalone testing
    static int lua_typeof(lua_State* L);
    static int lua_checkcaller(lua_State* L);
    static int lua_islclosure(lua_State* L);
    static int lua_iscclosure(lua_State* L);
    static int lua_hookfunction(lua_State* L);
    static int lua_newcclosure(lua_State* L);
    static int lua_getinfo(lua_State* L);
    static int lua_getnamecallmethod(lua_State* L);
    static int lua_setnamecallmethod(lua_State* L);
    static int lua_getrawmetatable(lua_State* L);
    static int lua_setrawmetatable(lua_State* L);
    static int lua_setreadonly(lua_State* L);
    static int lua_isreadonly(lua_State* L);
    static int lua_getgenv(lua_State* L);
    static int lua_getrenv(lua_State* L);
    static int lua_getreg(lua_State* L);
    static int lua_getgc(lua_State* L);
    static int lua_fireclickdetector(lua_State* L);
    static int lua_firetouchinterest(lua_State* L);
    static int lua_fireproximityprompt(lua_State* L);
};

} // namespace oss