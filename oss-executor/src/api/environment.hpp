#pragma once

namespace oss {

class LuaEngine;  // forward declaration

class Environment {
public:
    static void setup(LuaEngine& engine);
};

} // namespace oss
