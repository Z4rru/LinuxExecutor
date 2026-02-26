#pragma once

#include "lua_engine.hpp"
#include "injection.hpp"
#include "utils/config.hpp"
#include "utils/logger.hpp"

#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <functional>
#include <atomic>

namespace oss {

class Executor {
public:
    using OutputCallback = std::function<void(const std::string&)>;
    using ErrorCallback = std::function<void(const std::string&)>;
    using StatusCallback = std::function<void(const std::string&)>;

    static Executor& instance() {
        static Executor inst;
        return inst;
    }

    bool init();
    void shutdown();
    
    bool execute_script(const std::string& script);
    bool execute_file(const std::string& path);
    
    void auto_execute();
    
    void set_output_callback(OutputCallback cb) { output_cb_ = std::move(cb); }
    void set_error_callback(ErrorCallback cb) { error_cb_ = std::move(cb); }
    void set_status_callback(StatusCallback cb) { status_cb_ = std::move(cb); }
    
    LuaEngine& lua() { return lua_engine_; }
    Injection& injection() { return Injection::instance(); }
    
    bool is_attached() const;
    std::string status_text() const;
    
    void cancel_execution();

private:
    Executor() = default;
    
    void worker_loop();
    
    LuaEngine lua_engine_;
    
    std::queue<std::string> script_queue_;
    std::mutex queue_mutex_;
    std::thread worker_thread_;
    std::atomic<bool> running_{false};
    
    OutputCallback output_cb_;
    ErrorCallback error_cb_;
    StatusCallback status_cb_;
};

} // namespace oss