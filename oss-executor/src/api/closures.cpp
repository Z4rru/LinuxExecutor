#include "closures.hpp"
#include <string>
#include <cstring>

namespace oss {

const char* Closures::EXECUTOR_MARKER = "__oss_executor_closure";
const char* Closures::HOOK_TABLE_KEY = "__oss_hook_table";

void Closures::ensure_hook_table(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, HOOK_TABLE_KEY);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, HOOK_TABLE_KEY);
    }
    lua_pop(L, 1);
}

int Closures::get_hook_table(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, HOOK_TABLE_KEY);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, HOOK_TABLE_KEY);
    }
    return 1;
}

void Closures::register_all(lua_State* L) {
    ensure_hook_table(L);

    lua_pushboolean(L, 1);
    lua_setfield(L, LUA_REGISTRYINDEX, "__oss_is_executor");

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

    lua_pushcfunction(L, newcclosure);
    lua_setglobal(L, "newcclosure");

    lua_pushcfunction(L, hookfunction);
    lua_setglobal(L, "hookfunction");

    lua_pushcfunction(L, hookfunction);
    lua_setglobal(L, "replaceclosure");

    lua_pushcfunction(L, hookmetamethod);
    lua_setglobal(L, "hookmetamethod");

    lua_pushcfunction(L, iscclosure);
    lua_setglobal(L, "iscclosure");

    lua_pushcfunction(L, islclosure);
    lua_setglobal(L, "islclosure");

    lua_pushcfunction(L, isexecutorclosure);
    lua_setglobal(L, "isexecutorclosure");

    lua_pushcfunction(L, isexecutorclosure);
    lua_setglobal(L, "checkclosure");

    lua_pushcfunction(L, isexecutorclosure);
    lua_setglobal(L, "isourclosure");

    lua_pushcfunction(L, checkcaller);
    lua_setglobal(L, "checkcaller");

    lua_pushcfunction(L, getinfo);
    lua_setglobal(L, "getinfo");

    lua_pushcfunction(L, loadstring_enhanced);
    lua_setglobal(L, "loadstring");

    lua_pushcfunction(L, newlclosure);
    lua_setglobal(L, "newlclosure");
}

int Closures::wrap_closure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushcclosure(L, closure_handler, 1);
    return 1;
}

int Closures::closure_handler(lua_State* L) {
    int nargs = lua_gettop(L);
    int base = nargs;

    lua_pushvalue(L, lua_upvalueindex(1));

    for (int i = 1; i <= nargs; i++)
        lua_pushvalue(L, i);

    lua_call(L, nargs, LUA_MULTRET);

    return lua_gettop(L) - base;
}

int Closures::newcclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    lua_pushvalue(L, 1);
    lua_pushboolean(L, 1);
    lua_pushcclosure(L, newcclosure_handler, 2);

    lua_getfield(L, LUA_REGISTRYINDEX, HOOK_TABLE_KEY);
    lua_pushvalue(L, -2);
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);
    lua_pop(L, 1);

    return 1;
}

int Closures::newcclosure_handler(lua_State* L) {
    int nargs = lua_gettop(L);

    lua_pushvalue(L, lua_upvalueindex(1));
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        return 0;
    }

    for (int i = 1; i <= nargs; i++)
        lua_pushvalue(L, i);

    int status = lua_pcall(L, nargs, LUA_MULTRET, 0);
    if (status != 0) {
        lua_error(L);
        return 0;
    }

    return lua_gettop(L) - nargs;
}

int Closures::newlclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    const char* wrapper_src =
        "local f = ...\n"
        "return function(...)\n"
        "    return f(...)\n"
        "end\n";

    if (luaL_loadbuffer(L, wrapper_src, strlen(wrapper_src), "=newlclosure") != 0) {
        lua_error(L);
        return 0;
    }

    lua_pushvalue(L, 1);
    lua_call(L, 1, 1);

    return 1;
}

int Closures::newlclosure_handler(lua_State* L) {
    int nargs = lua_gettop(L);

    lua_pushvalue(L, lua_upvalueindex(1));
    for (int i = 1; i <= nargs; i++)
        lua_pushvalue(L, i);

    lua_call(L, nargs, LUA_MULTRET);

    return lua_gettop(L) - nargs;
}

int Closures::hookfunction(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    lua_pushvalue(L, 1);
    std::string bytecode;

    if (!lua_iscfunction(L, 1)) {
        int dump_ok = lua_dump(L, [](lua_State*, const void* p, size_t sz, void* ud) -> int {
            auto* buf = static_cast<std::string*>(ud);
            buf->append(static_cast<const char*>(p), sz);
            return 0;
        }, &bytecode);

        lua_pop(L, 1);

        if (dump_ok == 0 && !bytecode.empty()) {
            if (luaL_loadbuffer(L, bytecode.data(), bytecode.size(), "=hooked_original") != 0)
                lua_pop(L, 1);
        }

        if (bytecode.empty()) {
            lua_pushvalue(L, 1);
        }
    } else {
        lua_pop(L, 1);
        lua_pushvalue(L, 1);
    }

    get_hook_table(L);
    lua_pushvalue(L, 1);
    lua_pushvalue(L, 2);
    lua_rawset(L, -3);
    lua_pop(L, 1);

    lua_Debug ar;
    if (lua_getinfo(L, ">S", &ar)) {
    }

    return 1;
}

int Closures::hookmetamethod(lua_State* L) {
    luaL_checkany(L, 1);
    const char* method = luaL_checkstring(L, 2);
    luaL_checktype(L, 3, LUA_TFUNCTION);

    if (!lua_getmetatable(L, 1)) {
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setmetatable(L, 1);
    }

    lua_getfield(L, -1, method);

    int old_ref = LUA_NOREF;
    if (!lua_isnil(L, -1)) {
        lua_pushvalue(L, -1);
        old_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    lua_pop(L, 1);

    lua_pushvalue(L, 3);
    lua_setfield(L, -2, method);
    lua_pop(L, 1);

    if (old_ref != LUA_NOREF) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, old_ref);
        luaL_unref(L, LUA_REGISTRYINDEX, old_ref);
    } else {
        lua_pushcfunction(L, [](lua_State*) -> int { return 0; });
    }

    return 1;
}

int Closures::iscclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushboolean(L, lua_iscfunction(L, 1));
    return 1;
}

int Closures::islclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushboolean(L, !lua_iscfunction(L, 1));
    return 1;
}

int Closures::isexecutorclosure(lua_State* L) {
    if (!lua_isfunction(L, 1)) {
        lua_pushboolean(L, 0);
        return 1;
    }

    get_hook_table(L);
    lua_pushvalue(L, 1);
    lua_rawget(L, -2);
    if (!lua_isnil(L, -1)) {
        lua_pop(L, 2);
        lua_pushboolean(L, 1);
        return 1;
    }
    lua_pop(L, 2);

    if (lua_iscfunction(L, 1)) {
        lua_Debug ar;
        lua_pushvalue(L, 1);
        lua_getinfo(L, ">S", &ar);
        if (ar.source && (strcmp(ar.source, "=[C]") == 0)) {
            lua_pushboolean(L, 1);
            return 1;
        }
    }

    if (!lua_iscfunction(L, 1)) {
        lua_Debug ar;
        lua_pushvalue(L, 1);
        lua_getinfo(L, ">S", &ar);
        if (ar.source) {
            std::string src(ar.source);
            if (src.find("=env_setup") != std::string::npos ||
                src.find("=sandbox") != std::string::npos ||
                src.find("=input") != std::string::npos ||
                src.find("=cloned") != std::string::npos ||
                src.find("=newlclosure") != std::string::npos ||
                src.find("=hooked") != std::string::npos) {
                lua_pushboolean(L, 1);
                return 1;
            }
        }
    }

    lua_pushboolean(L, 0);
    return 1;
}

int Closures::checkcaller(lua_State* L) {
    lua_Debug ar;

    int level = 2;
    while (lua_getstack(L, level, &ar)) {
        lua_getinfo(L, "S", &ar);
        if (ar.source) {
            std::string src(ar.source);
            if (src == "=input" || src.find("=env_setup") != std::string::npos ||
                src.find("=sandbox") != std::string::npos) {
                lua_pushboolean(L, 1);
                return 1;
            }
            if (src[0] == '@') {
                lua_pushboolean(L, 0);
                return 1;
            }
        }
        ++level;
    }

    lua_getfield(L, LUA_REGISTRYINDEX, "__oss_is_executor");
    bool is_exec = lua_toboolean(L, -1);
    lua_pop(L, 1);
    lua_pushboolean(L, is_exec ? 1 : 0);
    return 1;
}

int Closures::getinfo(lua_State* L) {
    lua_Debug ar;
    memset(&ar, 0, sizeof(ar));

    if (lua_isnumber(L, 1)) {
        int level = static_cast<int>(lua_tointeger(L, 1));
        if (!lua_getstack(L, level, &ar)) {
            lua_pushnil(L);
            return 1;
        }
        lua_getinfo(L, "nSlu", &ar);
    } else if (lua_isfunction(L, 1)) {
        lua_pushvalue(L, 1);
        lua_getinfo(L, ">nSlu", &ar);
    } else {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);

    if (ar.source) {
        lua_pushstring(L, ar.source);
        lua_setfield(L, -2, "source");
        lua_pushstring(L, ar.source);
        lua_setfield(L, -2, "short_src");
    }

    if (ar.name) {
        lua_pushstring(L, ar.name);
        lua_setfield(L, -2, "name");
    }

    if (ar.what) {
        lua_pushstring(L, ar.what);
        lua_setfield(L, -2, "what");

        lua_pushboolean(L, strcmp(ar.what, "C") == 0 ? 1 : 0);
        lua_setfield(L, -2, "is_c");
    }

    lua_pushinteger(L, ar.currentline);
    lua_setfield(L, -2, "currentline");

    lua_pushinteger(L, ar.linedefined);
    lua_setfield(L, -2, "linedefined");

    lua_pushinteger(L, ar.lastlinedefined);
    lua_setfield(L, -2, "lastlinedefined");

    lua_pushinteger(L, ar.nups);
    lua_setfield(L, -2, "nups");

    lua_pushinteger(L, ar.nups);
    lua_setfield(L, -2, "numparams");

    lua_pushboolean(L, 0);
    lua_setfield(L, -2, "is_vararg");

    return 1;
}

int Closures::get_script_closure(lua_State* L) {
    lua_pushcfunction(L, [](lua_State*) -> int { return 0; });
    return 1;
}

int Closures::compare_closures(lua_State* L) {
    lua_pushboolean(L, lua_rawequal(L, 1, 2));
    return 1;
}

int Closures::clone_function(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    if (lua_iscfunction(L, 1)) {
        lua_pushvalue(L, 1);
        lua_pushcclosure(L, [](lua_State* Ls) -> int {
            int nargs = lua_gettop(Ls);
            lua_pushvalue(Ls, lua_upvalueindex(1));
            for (int i = 1; i <= nargs; i++)
                lua_pushvalue(Ls, i);
            lua_call(Ls, nargs, LUA_MULTRET);
            return lua_gettop(Ls) - nargs;
        }, 1);
        return 1;
    }

    lua_pushvalue(L, 1);

    std::string bytecode;

    int dump_ok = lua_dump(L, [](lua_State*, const void* p, size_t sz,
                                 void* ud) -> int {
        auto* buf = static_cast<std::string*>(ud);
        buf->append(static_cast<const char*>(p), sz);
        return 0;
    }, &bytecode);

    lua_pop(L, 1);

    if (dump_ok != 0 || bytecode.empty()) {
        lua_pushvalue(L, 1);
        return 1;
    }

    if (luaL_loadbuffer(L, bytecode.data(), bytecode.size(),
                        "=cloned") != 0) {
        lua_pop(L, 1);
        lua_pushvalue(L, 1);
        return 1;
    }

    int n = 1;
    while (true) {
        const char* name = lua_getupvalue(L, 1, n);
        if (!name) break;
        lua_setupvalue(L, -2, n);
        ++n;
    }

    return 1;
}

int Closures::get_calling_script(lua_State* L) {
    lua_pushnil(L);
    return 1;
}

int Closures::checkclosure(lua_State* L) {
    return isexecutorclosure(L);
}

int Closures::getscriptclosure(lua_State* L) {
    lua_pushcfunction(L, [](lua_State*) -> int { return 0; });
    return 1;
}

int Closures::loadstring_enhanced(lua_State* L) {
    size_t len;
    const char* s = lua_tolstring(L, 1, &len);
    const char* chunkname = luaL_optstring(L, 2, "=loadstring");

    if (!s) {
        lua_pushnil(L);
        lua_pushstring(L, "loadstring: input is nil");
        return 2;
    }

    if (len == 0) {
        lua_pushnil(L);
        lua_pushstring(L, "loadstring: empty source");
        return 2;
    }

    int status = luaL_loadbuffer(L, s, len, chunkname);
    if (status != 0) {
        lua_pushnil(L);
        lua_insert(L, -2);
        return 2;
    }

    get_hook_table(L);
    lua_pushvalue(L, -2);
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);
    lua_pop(L, 1);

    return 1;
}

} // namespace oss
