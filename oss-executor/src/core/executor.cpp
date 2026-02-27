#include "executor.hpp"
#include "utils/logger.hpp"
#include "utils/config.hpp"

#include <filesystem>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <vector>
#include <sstream>

namespace oss {

Executor& Executor::instance() {
    static Executor inst;
    return inst;
}

Executor::Executor() = default;

Executor::~Executor() {
    shutdown();
}

void Executor::init() {
    if (initialized_.load(std::memory_order_acquire)) return;

    LOG_INFO("Initializing OSS Executor...");
    if (status_cb_) status_cb_("Initializing...");

    auto t0 = std::chrono::steady_clock::now();

    if (!lua_.init()) {
        LOG_ERROR("Failed to initialize Lua engine");
        if (error_cb_) error_cb_("Lua engine initialization failed");
        if (status_cb_) status_cb_("Init failed");
        return;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();
    LOG_INFO("Lua engine initialized in {}ms", ms);

    lua_.set_output_callback([this](const std::string& msg) {
        if (output_cb_) output_cb_(msg);
    });

    lua_.set_error_callback([this](const LuaError& err) {
        std::string msg = err.message;
        if (err.line > 0)
            msg = "[" + err.source + ":" + std::to_string(err.line) + "] " + msg;
        if (error_cb_) error_cb_(msg);
    });

    Injection::instance().set_status_callback(
        [this](InjectionStatus, const std::string& msg) {
            if (status_cb_) status_cb_(msg);
        });

    try {
        auto home = Config::instance().home_dir();
        std::filesystem::create_directories(home + "/workspace");
        std::filesystem::create_directories(home + "/scripts/autoexec");
    } catch (const std::filesystem::filesystem_error& e) {
        LOG_WARN("Could not create directories: {}", e.what());
    }

    if (Config::instance().get<bool>("executor.auto_inject", false))
        Injection::instance().start_auto_scan();

    if (Config::instance().get<bool>("executor.queue_autostart", true))
        start_queue_processor();

    initialized_.store(true, std::memory_order_release);
    if (status_cb_) status_cb_("Ready");
    LOG_INFO("OSS Executor initialized successfully");
}

void Executor::shutdown() {
    if (!initialized_.load(std::memory_order_acquire)) return;

    LOG_INFO("Shutting down OSS Executor...");
    stop_queue_processor();
    Injection::instance().stop_auto_scan();
    lua_.shutdown();
    initialized_.store(false, std::memory_order_release);
}

ExecutionResult Executor::execute_internal(const std::string& script, const std::string& name) {
    ExecutionResult result;
    result.script_name = name;
    result.success = false;

    if (script.empty()) {
        result.error = "Empty script";
        return result;
    }

    executing_.store(true, std::memory_order_release);

    auto t0 = std::chrono::steady_clock::now();
    result.success = lua_.execute(script, "=" + name);
    auto t1 = std::chrono::steady_clock::now();

    result.execution_time_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    executing_.store(false, std::memory_order_release);

    {
        std::lock_guard<std::mutex> lock(history_mutex_);
        execution_history_.push_back(result);
        while (execution_history_.size() > max_history_)
            execution_history_.erase(execution_history_.begin());
    }

    if (result_cb_) result_cb_(result);

    return result;
}

void Executor::execute_script(const std::string& script) {
    execute_script(script, "user_script");
}

void Executor::execute_script(const std::string& script, const std::string& name) {
    if (!initialized_.load(std::memory_order_acquire)) {
        if (error_cb_) error_cb_("Executor not initialized");
        return;
    }
    if (script.empty()) {
        if (error_cb_) error_cb_("Empty script");
        return;
    }

    if (status_cb_) status_cb_("Executing...");

    auto result = execute_internal(script, name);

    if (result.success) {
        if (status_cb_) status_cb_("Executed ✓");
    } else {
        if (status_cb_) status_cb_("Execution failed ✗");
    }
}

void Executor::execute_file(const std::string& path) {
    if (!initialized_.load(std::memory_order_acquire)) {
        if (error_cb_) error_cb_("Executor not initialized");
        return;
    }

    std::string content = read_file(path);
    if (content.empty()) return;

    std::string name = std::filesystem::path(path).filename().string();
    execute_script(content, name);
}

std::string Executor::read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        if (error_cb_) error_cb_("Cannot open file: " + path);
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
}

void Executor::cancel_execution() {
    lua_.stop();
    executing_.store(false, std::memory_order_release);
    if (status_cb_) status_cb_("Cancelled");
    LOG_INFO("Execution cancelled by user");
}

void Executor::enqueue_script(const std::string& script, const std::string& name, int priority) {
    QueuedScript qs;
    qs.source = script;
    qs.name = name;
    qs.is_file = false;
    qs.priority = priority;
    qs.queued_at = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        script_queue_.push(std::move(qs));
    }
    queue_cv_.notify_one();
    LOG_INFO("Enqueued script: {} (priority {})", name, priority);
}

void Executor::enqueue_file(const std::string& path, int priority) {
    std::string content = read_file(path);
    if (content.empty()) return;

    std::string name = std::filesystem::path(path).filename().string();
    enqueue_script(content, name, priority);
}

void Executor::clear_queue() {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    std::priority_queue<QueuedScript> empty;
    script_queue_.swap(empty);
    LOG_INFO("Script queue cleared");
}

size_t Executor::queue_size() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return script_queue_.size();
}

bool Executor::is_executing() const {
    return executing_.load(std::memory_order_acquire);
}

void Executor::start_queue_processor() {
    if (queue_running_.load(std::memory_order_acquire)) return;

    queue_running_.store(true, std::memory_order_release);
    queue_thread_ = std::thread(&Executor::process_queue, this);
    LOG_INFO("Queue processor started");
}

void Executor::stop_queue_processor() {
    if (!queue_running_.load(std::memory_order_acquire)) return;

    queue_running_.store(false, std::memory_order_release);
    queue_cv_.notify_all();

    if (queue_thread_.joinable())
        queue_thread_.join();

    LOG_INFO("Queue processor stopped");
}

void Executor::process_queue() {
    while (queue_running_.load(std::memory_order_acquire)) {
        QueuedScript script;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] {
                return !script_queue_.empty() ||
                       !queue_running_.load(std::memory_order_acquire);
            });

            if (!queue_running_.load(std::memory_order_acquire)) break;
            if (script_queue_.empty()) continue;

            script = script_queue_.top();
            script_queue_.pop();
        }

        if (status_cb_) status_cb_("Queue: executing " + script.name);

        auto wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - script.queued_at).count();
        LOG_INFO("Dequeued {} after {}ms wait", script.name, wait_ms);

        auto result = execute_internal(script.source, script.name);

        if (result.success) {
            if (output_cb_) output_cb_("[queue] " + script.name + " completed");
        } else {
            if (error_cb_) error_cb_("[queue] " + script.name + " failed");
        }
    }
}

void Executor::auto_execute() {
    std::string dir = Config::instance().home_dir() + "/scripts/autoexec";
    try {
        if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir))
            return;

        std::vector<std::filesystem::path> scripts;
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (!entry.is_regular_file()) continue;
            auto ext = entry.path().extension().string();
            if (ext == ".lua" || ext == ".luau")
                scripts.push_back(entry.path());
        }
        std::sort(scripts.begin(), scripts.end());

        for (const auto& s : scripts) {
            LOG_INFO("Auto-executing: {}", s.filename().string());
            if (output_cb_)
                output_cb_("[autoexec] Running " + s.filename().string());
            execute_file(s.string());
        }

        if (!scripts.empty())
            LOG_INFO("Auto-executed {} scripts", scripts.size());
    } catch (const std::filesystem::filesystem_error& e) {
        LOG_ERROR("Auto-execute failed: {}", e.what());
        if (error_cb_) error_cb_("Auto-execute error: " + std::string(e.what()));
    }
}

std::vector<ExecutionResult> Executor::get_history() const {
    std::lock_guard<std::mutex> lock(history_mutex_);
    return execution_history_;
}

void Executor::clear_history() {
    std::lock_guard<std::mutex> lock(history_mutex_);
    execution_history_.clear();
}

void Executor::set_output_callback(OutputCallback cb) { output_cb_ = std::move(cb); }
void Executor::set_error_callback(ErrorCallback cb) { error_cb_ = std::move(cb); }
void Executor::set_status_callback(StatusCallback cb) { status_cb_ = std::move(cb); }
void Executor::set_result_callback(ResultCallback cb) { result_cb_ = std::move(cb); }

} // namespace oss
