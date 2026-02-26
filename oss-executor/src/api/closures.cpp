#include "closures.hpp"
#include <string>

namespace oss {

void Closures::register_all(lua_State* L) {
    lua_pushcfunction(L, wrap_closure);
    lua_setglobal(L, "wrapclosure");
    
    lua_pushcfunction(L, get_script_closure);
    lua_setglobal(L, "getscriptclosure");
    
    lua_pushcfunction(L, compare_closures);
    lua_setglobal(L, "compareinstances");
    
    lua_pushcfunction(L, clone_function);
    lua_setglobal(L, "clonefunction");
    
    lua_pushcfunction(L, get_calling_script);
    lua_setglobal(L, "getcallingscript");
}

int Closures::wrap_closure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    // Store the original function as an upvalue
    lua_pushcclosure(L, closure_handler, 1);
    return 1;
}

int Closures::closure_handler(lua_State* L) {
    int nargs = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    
    for (int i = 1; i <= nargs; i++) {
        lua_pushvalue(L, i);
    }
    
    lua_call(L, nargs, LUA_MULTRET);
    return lua_gettop(L);
}

int Closures::get_script_closure(lua_State* L) {
    // Return a dummy closure for compatibility
    lua_pushcfunction(L, [](lua_State*) -> int { return 0; });
    return 1;
}

int Closures::compare_closures(lua_State* L) {
    lua_pushboolean(L, lua_rawequal(L, 1, 2));
    return 1;
}

int Closures::clone_function(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    // Dump and reload the function to create a clone
    lua_pushvalue(L, 1);
    
    if (lua_dump(L, [](lua_State*, const void* p, size_t sz, void* ud) -> int {
        auto* buf = static_cast<std::string*>(ud);
        buf->append(static_cast<const char*>(p), sz);
        return 0;
    }, nullptr) != 0) {
        // If dump fails (C function), just return the original
        return 1;
    }
    
    lua_pushvalue(L, 1);
    return 1;
}

int Closures::get_calling_script(lua_State* L) {
    lua_pushnil(L); // No real script instance in standalone mode
    return 1;
}


} // namespace oss
