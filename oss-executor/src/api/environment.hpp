#pragma once

namespace oss {

class LuaEngine;

class Environment {
public:
    static void setup(LuaEngine& engine);
};

} // namespace oss
