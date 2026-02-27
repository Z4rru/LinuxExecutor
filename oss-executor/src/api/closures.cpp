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
    lua_pushcclosure(L, closure_handler, 1);
    return 1;
}

// ═══════════════════════════════════════════════════════════════
// FIX #4: closure_handler RETURN COUNT
//
// BEFORE:
//   lua_call(L, nargs, LUA_MULTRET);
//   return lua_gettop(L);      ← WRONG
//
// Stack before call:
//   [1..nargs] original args  |  [nargs+1] function  |  [nargs+2..] arg copies
//
// After lua_call, everything from [nargs+1] onward is replaced by results.
// So lua_gettop(L) == nargs + num_results.
// Returning lua_gettop(L) tells Lua there are nargs+num_results return
// values, which includes the ORIGINAL arguments as phantom returns.
//
// AFTER:
//   Record stack depth before pushing function+args.
//   After call, return lua_gettop(L) - base.
// ═══════════════════════════════════════════════════════════════
int Closures::closure_handler(lua_State* L) {
    int nargs = lua_gettop(L);
    int base  = nargs;                     // stack depth before we push anything

    lua_pushvalue(L, lua_upvalueindex(1)); // push wrapped function

    for (int i = 1; i <= nargs; i++) {
        lua_pushvalue(L, i);               // copy each original arg
    }

    lua_call(L, nargs, LUA_MULTRET);

    return lua_gettop(L) - base;           // only the actual results
}

int Closures::get_script_closure(lua_State* L) {
    lua_pushcfunction(L, [](lua_State*) -> int { return 0; });
    return 1;
}

int Closures::compare_closures(lua_State* L) {
    lua_pushboolean(L, lua_rawequal(L, 1, 2));
    return 1;
}

// ═══════════════════════════════════════════════════════════════
// FIX #3: clone_function NULLPTR CRASH + ACTUALLY CLONE
//
// BEFORE (3 bugs):
//
//   1. lua_dump(..., nullptr)
//      Writer callback does:
//        auto* buf = static_cast<std::string*>(ud);  // ud == nullptr
//        buf->append(...)                             // SEGFAULT
//
//   2. Even if dump succeeded, the bytecode was never reloaded.
//      The function just returned the ORIGINAL function, not a clone.
//
//   3. Stack leak: lua_pushvalue added a copy that was never popped
//      if lua_dump was somehow skipped.
//
// AFTER:
//   - Allocate a real std::string buffer and pass its address
//   - If the function is a C function (can't dump), return the original
//   - If it's a Lua function, dump → luaL_loadbuffer → return the clone
//   - Clean stack properly in all paths
// ═══════════════════════════════════════════════════════════════
int Closures::clone_function(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    // C functions cannot be dumped — just return the original
    if (lua_iscfunction(L, 1)) {
        lua_pushvalue(L, 1);
        return 1;
    }

    // Push copy of function for lua_dump (it doesn't pop)
    lua_pushvalue(L, 1);

    std::string bytecode;                  // ← actual buffer, not nullptr

    int dump_ok = lua_dump(L, [](lua_State*, const void* p, size_t sz,
                                 void* ud) -> int {
        auto* buf = static_cast<std::string*>(ud);
        buf->append(static_cast<const char*>(p), sz);
        return 0;
    }, &bytecode);                         // ← pass address of real buffer

    lua_pop(L, 1);                         // pop the copy we pushed for dump

    if (dump_ok != 0 || bytecode.empty()) {
        // Dump failed — fall back to returning the original
        lua_pushvalue(L, 1);
        return 1;
    }

    // Load the bytecode back as a NEW function (the actual clone)
    if (luaL_loadbuffer(L, bytecode.data(), bytecode.size(),
                        "=cloned") != 0) {
        // Load failed — return original and discard error message
        lua_pop(L, 1);
        lua_pushvalue(L, 1);
    }

    return 1;
}

int Closures::get_calling_script(lua_State* L) {
    lua_pushnil(L);
    return 1;
}

} // namespace oss
