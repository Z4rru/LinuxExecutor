#pragma once
#include <lua.hpp>

namespace oss {

class Closures {
public:
    static void register_all(lua_State* L);

private:
    static int wrap_closure(lua_State* L);
    static int closure_handler(lua_State* L);
    static int get_script_closure(lua_State* L);
    static int compare_closures(lua_State* L);
    static int clone_function(lua_State* L);
    static int get_calling_script(lua_State* L);
};

} // namespace oss
