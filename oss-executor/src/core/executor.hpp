#pragma once

#include "core/lua_engine.hpp"
#include "core/injection.hpp"

#include <string>
#include <functional>
#include <atomic>              // ← FIX #2: was missing

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

    // ═══════════════════════════════════════════════════════
    // FIX #3: Return via .load() for atomic consistency.
    //
    // BEFORE: bool is_initialized() const { return initialized_; }
    //         → data race if signal handler checks concurrently
    //
    // With std::atomic<bool>, operator bool() exists but
    // explicit .load() is clearer about intent.
    // ═══════════════════════════════════════════════════════
    bool is_initialized() const {
        return initialized_.load(std::memory_order_acquire);
    }

    LuaEngine&       lua()       { return lua_; }
    const LuaEngine& lua() const { return lua_; }

    Injection& injection() { return Injection::instance(); }

    void set_output_callback(std::function<void(const std::string&)> cb);
    void set_error_callback(std::function<void(const std::string&)> cb);
    void set_status_callback(std::function<void(const std::string&)> cb);

private:
    Executor();
    ~Executor();

    LuaEngine lua_;

    // ═══════════════════════════════════════════════════════
    // FIX #2: bool → std::atomic<bool>
    //
    // BEFORE: bool initialized_ = false;
    //
    // WHY: executor.cpp (fixed version) uses:
    //   initialized_.load()
    //   initialized_.store(true)
    //   initialized_.compare_exchange_strong(expected, false)
    //
    // These are std::atomic methods — won't compile on
    // plain bool. Also prevents data race with signal
    // handler calling shutdown() from another context.
    // ═══════════════════════════════════════════════════════
    std::atomic<bool> initialized_{false};

    std::function<void(const std::string&)> output_cb_;
    std::function<void(const std::string&)> error_cb_;
    std::function<void(const std::string&)> status_cb_;
};

} // namespace oss
