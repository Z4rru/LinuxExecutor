#pragma once

#include "core/lua_engine.hpp"
#include "core/injection.hpp"

#include <string>
#include <functional>

namespace oss {

class Executor {
public:
    static Executor& instance();

    Executor(const Executor&)            = delete;
    Executor& operator=(const Executor&) = delete;

    void init();
    void shutdown();

    void execute_script(const std::string& script);
    void execute_file(const std::string& path);
    void cancel_execution();
    void auto_execute();

    bool is_initialized() const { return initialized_; }

    LuaEngine&       lua()       { return lua_; }
    const LuaEngine& lua() const { return lua_; }

    // Returns the global Injection singleton
    Injection& injection() { return Injection::instance(); }

    void set_output_callback(std::function<void(const std::string&)> cb);
    void set_error_callback(std::function<void(const std::string&)> cb);
    void set_status_callback(std::function<void(const std::string&)> cb);

private:
    Executor();
    ~Executor();

    LuaEngine lua_;
    bool initialized_ = false;

    std::function<void(const std::string&)> output_cb_;
    std::function<void(const std::string&)> error_cb_;
    std::function<void(const std::string&)> status_cb_;
};

} // namespace oss
