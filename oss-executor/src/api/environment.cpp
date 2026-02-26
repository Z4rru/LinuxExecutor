#include "environment.hpp"

extern "C" {
#include <luajit-2.1/lua.h>
#include <luajit-2.1/lualib.h>
#include <luajit-2.1/lauxlib.h>
}

namespace oss {

void Environment::setup(LuaEngine& engine) {
    lua_State* L = engine.state();
    if (!L) return;
    
    register_globals(L);
    register_drawing_lib(L);
    register_debug_lib(L);
    register_cache_lib(L);
}

void Environment::register_globals(lua_State* L) {
    // Type checking
    lua_pushcfunction(L, lua_typeof);
    lua_setglobal(L, "typeof");
    
    lua_pushcfunction(L, lua_checkcaller);
    lua_setglobal(L, "checkcaller");
    
    // Closure utilities
    lua_pushcfunction(L, lua_islclosure);
    lua_setglobal(L, "islclosure");
    
    lua_pushcfunction(L, lua_iscclosure);
    lua_setglobal(L, "iscclosure");
    
    lua_pushcfunction(L, lua_hookfunction);
    lua_setglobal(L, "hookfunction");
    lua_pushcfunction(L, lua_hookfunction);
    lua_setglobal(L, "replaceclosure");
    
    lua_pushcfunction(L, lua_newcclosure);
    lua_setglobal(L, "newcclosure");

    // Metatable functions
    lua_pushcfunction(L, lua_getrawmetatable);
    lua_setglobal(L, "getrawmetatable");
    
    lua_pushcfunction(L, lua_setrawmetatable);
    lua_setglobal(L, "setrawmetatable");
    
    lua_pushcfunction(L, lua_setreadonly);
    lua_setglobal(L, "setreadonly");
    
    lua_pushcfunction(L, lua_isreadonly);
    lua_setglobal(L, "isreadonly");

    // Environment access
    lua_pushcfunction(L, lua_getgenv);
    lua_setglobal(L, "getgenv");
    
    lua_pushcfunction(L, lua_getrenv);
    lua_setglobal(L, "getrenv");
    
    lua_pushcfunction(L, lua_getreg);
    lua_setglobal(L, "getreg");
    
    lua_pushcfunction(L, lua_getgc);
    lua_setglobal(L, "getgc");

    // Namecall
    lua_pushcfunction(L, lua_getnamecallmethod);
    lua_setglobal(L, "getnamecallmethod");
    
    lua_pushcfunction(L, lua_setnamecallmethod);
    lua_setglobal(L, "setnamecallmethod");

    // Interaction
    lua_pushcfunction(L, lua_fireclickdetector);
    lua_setglobal(L, "fireclickdetector");
    
    lua_pushcfunction(L, lua_firetouchinterest);
    lua_setglobal(L, "firetouchinterest");
    
    lua_pushcfunction(L, lua_fireproximityprompt);
    lua_setglobal(L, "fireproximityprompt");
}

void Environment::register_drawing_lib(lua_State* L) {
    lua_newtable(L);
    
    lua_pushcfunction(L, [](lua_State* L) -> int {
        const char* type = luaL_checkstring(L, 1);
        lua_newtable(L);
        lua_pushstring(L, type);
        lua_setfield(L, -2, "Type");
        lua_pushboolean(L, true);
        lua_setfield(L, -2, "Visible");
        lua_pushnumber(L, 0);
        lua_setfield(L, -2, "Transparency");
        return 1;
    });
    lua_setfield(L, -2, "new");
    
    lua_setglobal(L, "Drawing");
}

void Environment::register_debug_lib(lua_State* L) {
    // Extend existing debug library
    lua_getglobal(L, "debug");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
    }
    
    lua_pushcfunction(L, lua_getinfo);
    lua_setfield(L, -2, "getinfo");
    
    lua_pushcfunction(L, [](lua_State* L) -> int {
        luaL_checktype(L, 1, LUA_TFUNCTION);
        int idx = luaL_optinteger(L, 2, 1);
        lua_Debug ar;
        if (lua_getinfo(L, ">u", &ar)) {
            if (idx <= ar.nups) {
                const char* name = lua_getupvalue(L, 1, idx);
                if (name) {
                    lua_pushstring(L, name);
                    lua_insert(L, -2);
                    return 2;
                }
            }
        }
        lua_pushnil(L);
        return 1;
    });
    lua_setfield(L, -2, "getupvalue");
    
    lua_pushcfunction(L, [](lua_State* L) -> int {
        luaL_checktype(L, 1, LUA_TFUNCTION);
        lua_Debug ar;
        lua_pushvalue(L, 1);
        lua_getinfo(L, ">u", &ar);
        lua_pushinteger(L, ar.nups);
        return 1;
    });
    lua_setfield(L, -2, "getupvaluecount");
    
    lua_setglobal(L, "debug");
}

void Environment::register_cache_lib(lua_State* L) {
    lua_newtable(L);
    
    lua_pushcfunction(L, [](lua_State* L) -> int {
        // invalidate - stub for compatibility
        (void)L;
        return 0;
    });
    lua_setfield(L, -2, "invalidate");
    
    lua_pushcfunction(L, [](lua_State* L) -> int {
        // iscached - stub
        lua_pushboolean(L, false);
        return 1;
    });
    lua_setfield(L, -2, "iscached");
    
    lua_pushcfunction(L, [](lua_State* L) -> int {
        // replace - stub
        (void)L;
        return 0;
    });
    lua_setfield(L, -2, "replace");
    
    lua_setglobal(L, "cache");
}

int Environment::lua_typeof(lua_State* L) {
    lua_pushstring(L, luaL_typename(L, 1));
    return 1;
}

int Environment::lua_checkcaller(lua_State* L) {
    lua_pushboolean(L, true); // We are always the "executor" caller
    return 1;
}

int Environment::lua_islclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushboolean(L, !lua_iscfunction(L, 1));
    return 1;
}

int Environment::lua_iscclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushboolean(L, lua_iscfunction(L, 1));
    return 1;
}

int Environment::lua_hookfunction(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    
    // Return old function (the original)
    lua_pushvalue(L, 1);
    return 1;
}

int Environment::lua_newcclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushvalue(L, 1); // Just return the function wrapped
    return 1;
}

int Environment::lua_getinfo(lua_State* L) {
    lua_Debug ar;
    int level = luaL_optinteger(L, 1, 1);
    
    if (lua_getstack(L, level, &ar)) {
        lua_getinfo(L, "nSluf", &ar);
        
        lua_newtable(L);
        
        if (ar.name) {
            lua_pushstring(L, ar.name);
            lua_setfield(L, -2, "name");
        }
        
        lua_pushstring(L, ar.source);
        lua_setfield(L, -2, "source");
        
        lua_pushstring(L, ar.short_src);
        lua_setfield(L, -2, "short_src");
        
        lua_pushinteger(L, ar.currentline);
        lua_setfield(L, -2, "currentline");
        
        lua_pushinteger(L, ar.linedefined);
        lua_setfield(L, -2, "linedefined");
        
        lua_pushstring(L, ar.what);
        lua_setfield(L, -2, "what");
        
        return 1;
    }
    
    lua_pushnil(L);
    return 1;
}

int Environment::lua_getnamecallmethod(lua_State* L) {
    lua_pushstring(L, ""); // Stub - would need real Roblox integration
    return 1;
}

int Environment::lua_setnamecallmethod(lua_State* L) {
    (void)L;
    return 0;
}

int Environment::lua_getrawmetatable(lua_State* L) {
    if (lua_getmetatable(L, 1)) {
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

int Environment::lua_setrawmetatable(lua_State* L) {
    lua_setmetatable(L, 1);
    return 0;
}

int Environment::lua_setreadonly(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    // LuaJIT doesn't have native readonly tables, this is a compatibility stub
    (void)L;
    return 0;
}

int Environment::lua_isreadonly(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_pushboolean(L, false);
    return 1;
}

int Environment::lua_getgenv(lua_State* L) {
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    return 1;
}

int Environment::lua_getrenv(lua_State* L) {
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    return 1;
}

int Environment::lua_getreg(lua_State* L) {
    lua_pushvalue(L, LUA_REGISTRYINDEX);
    return 1;
}

int Environment::lua_getgc(lua_State* L) {
    lua_newtable(L);
    // Would need actual GC traversal - return empty table as stub
    return 1;
}

int Environment::lua_fireclickdetector(lua_State* L) {
    (void)L;
    return 0;
}

int Environment::lua_firetouchinterest(lua_State* L) {
    (void)L;
    return 0;
}

int Environment::lua_fireproximityprompt(lua_State* L) {
    (void)L;
    return 0;
}

} // namespace oss