#pragma once

extern "C" {
#include <luajit-2.1/lua.h>
#include <luajit-2.1/lualib.h>
#include <luajit-2.1/lauxlib.h>
}

#include <string>

// Forward declaration — LuaEngine is defined in core/lua_engine.hpp
namespace oss { class LuaEngine; }

namespace oss {

class Environment {
public:
    // Sets up the full Roblox API mock + executor globals in the given engine
    static void setup(LuaEngine& engine);
};

} // namespace oss
