#pragma once

extern "C" {
#include <luajit-2.1/lua.h>
#include <luajit-2.1/lualib.h>
#include <luajit-2.1/lauxlib.h>
}

#include <string>
#include <unordered_map>
#include <vector>
#include <functional>

namespace oss {

class Closures {
public:
    static void register_all(lua_State* L);

    struct HookEntry {
        int original_ref = LUA_NOREF;
        int hook_ref = LUA_NOREF;
        std::string name;
    };

private:
    static int wrap_closure(lua_State* L);
    static int closure_handler(lua_State* L);
    static int get_script_closure(lua_State* L);
    static int compare_closures(lua_State* L);
    static int clone_function(lua_State* L);
    static int get_calling_script(lua_State* L);

    static int newcclosure(lua_State* L);
    static int newcclosure_handler(lua_State* L);
    static int hookfunction(lua_State* L);
    static int hookmetamethod(lua_State* L);
    static int iscclosure(lua_State* L);
    static int islclosure(lua_State* L);
    static int isexecutorclosure(lua_State* L);
    static int checkcaller(lua_State* L);
    static int getinfo(lua_State* L);
    static int checkclosure(lua_State* L);
    static int getscriptclosure(lua_State* L);
    static int loadstring_enhanced(lua_State* L);
    static int newlclosure(lua_State* L);
    static int newlclosure_handler(lua_State* L);

    static const char* EXECUTOR_MARKER;
    static const char* HOOK_TABLE_KEY;

    static void ensure_hook_table(lua_State* L);
    static int get_hook_table(lua_State* L);
};

} // namespace oss
