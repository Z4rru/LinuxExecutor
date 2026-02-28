#pragma once

#include "core/lua_engine.hpp"
#include "core/injection.hpp"

#include <string>
#include <functional>
#include <atomic>
#include <chrono>              // FIX 1: was missing — QueuedScript uses steady_clock
#include <deque>               // FIX 2: replaces vector for O(1) history trimming
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <vector>

namespace oss {

struct QueuedScript {
    std::string source;
    std::string name;
    bool is_file   = false;
    int  priority  = 0;
    std::chrono::steady_clock::time_point queued_at{};

    bool operator<(const QueuedScript& other) const {
        return priority < other.priority;   // max-heap: higher priority first
    }
};

struct ExecutionResult {
    bool        success           = false;   // FIX 3: default-init all POD members
    std::string output;
    std::string error;
    double      execution_time_ms = 0.0;
    std::string script_name;
};

class Executor {
public:
    static Executor& instance();

    Executor(const Executor&)            = delete;
    Executor& operator=(const Executor&) = delete;
    Executor(Executor&&)                 = delete;   // FIX 4: prevent move
    Executor& operator=(Executor&&)      = delete;

    void init();
    void shutdown();

    void execute_script(const std::string& script);
    void execute_script(const std::string& script, const std::string& name);
    void execute_file(const std::string& path);
    void cancel_execution();
    void auto_execute();

    void   enqueue_script(const std::string& script,
                          const std::string& name = "queued",
                          int priority = 0);
    void   enqueue_file(const std::string& path, int priority = 0);
    void   clear_queue();
    size_t queue_size() const;
    bool   is_executing() const;

    void start_queue_processor();
    void stop_queue_processor();

    bool is_initialized() const {
        return initialized_.load(std::memory_order_acquire);
    }

    LuaEngine&       lua()       { return lua_; }
    const LuaEngine& lua() const { return lua_; }

    Injection& injection() { return Injection::instance(); }

    // NOTE: callbacks must be set BEFORE init() or while no execution is
    //       in progress.  They are read without a lock on the hot path.
    using OutputCallback = std::function<void(const std::string&)>;
    using ErrorCallback  = std::function<void(const std::string&)>;
    using StatusCallback = std::function<void(const std::string&)>;
    using ResultCallback = std::function<void(const ExecutionResult&)>;

    void set_output_callback(OutputCallback cb);
    void set_error_callback(ErrorCallback  cb);
    void set_status_callback(StatusCallback cb);
    void set_result_callback(ResultCallback cb);

    std::vector<ExecutionResult> get_history() const;
    void clear_history();

private:
    Executor();
    ~Executor();

    ExecutionResult execute_internal(const std::string& script,
                                     const std::string& name);
    void        process_queue();
    std::string read_file(const std::string& path);

    LuaEngine lua_;

    std::atomic<bool> initialized_{false};
    std::atomic<bool> executing_{false};
    std::atomic<bool> queue_running_{false};

    // FIX 5: serialises all lua_.execute() calls so the queue thread
    //        and the UI thread cannot run scripts concurrently.
    std::mutex exec_mutex_;

    // FIX 6: protects the init/shutdown transition from races.
    std::mutex init_mutex_;

    std::priority_queue<QueuedScript> script_queue_;
    mutable std::mutex                queue_mutex_;
    std::condition_variable           queue_cv_;
    std::thread                       queue_thread_;

    mutable std::mutex              history_mutex_;
    std::deque<ExecutionResult>     execution_history_;   // FIX 2: was vector
    size_t                          max_history_ = 100;

    OutputCallback output_cb_;
    ErrorCallback  error_cb_;
    StatusCallback status_cb_;
    ResultCallback result_cb_;
};

} // namespace oss
