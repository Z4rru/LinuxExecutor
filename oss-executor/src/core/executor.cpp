#include "executor.hpp"
#include "utils/logger.hpp"
#include "utils/config.hpp"

#include <filesystem>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <vector>
#include <sstream>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static constexpr const char* PAYLOAD_SOCK = "/tmp/oss_executor.sock";

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
    std::lock_guard<std::mutex> lock(init_mutex_);
    if (initialized_.load(std::memory_order_relaxed)) return;

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
        [this](InjectionState, const std::string& msg) {
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
    std::lock_guard<std::mutex> lock(init_mutex_);
    if (!initialized_.load(std::memory_order_relaxed)) return;

    LOG_INFO("Shutting down OSS Executor...");

    lua_.stop();
    stop_queue_processor();
    clear_queue();
    Injection::instance().stop_auto_scan();
    lua_.shutdown();
    initialized_.store(false, std::memory_order_release);
    LOG_INFO("OSS Executor shut down");
}

bool Executor::send_to_payload(const std::string& source) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERROR("payload socket(): {}", strerror(errno));
        return false;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, PAYLOAD_SOCK, sizeof(addr.sun_path) - 1);

    struct timeval tv{};
    tv.tv_sec = 2;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR("payload connect({}): {}", PAYLOAD_SOCK, strerror(errno));
        ::close(fd);
        return false;
    }

    const char* data = source.data();
    size_t remaining = source.size();
    while (remaining > 0) {
        ssize_t n = ::write(fd, data, remaining);
        if (n <= 0) {
            LOG_ERROR("payload write(): {}", strerror(errno));
            ::close(fd);
            return false;
        }
        data += n;
        remaining -= static_cast<size_t>(n);
    }

    ::shutdown(fd, SHUT_WR);
    ::close(fd);
    LOG_INFO("Sent {} bytes to payload via {}", source.size(), PAYLOAD_SOCK);
    return true;
}

ExecutionResult Executor::execute_internal(const std::string& script,
                                           const std::string& name) {
    ExecutionResult result;
    result.script_name = name;

    if (script.empty()) {
        result.error = "Empty script";
        return result;
    }

    std::lock_guard<std::mutex> exec_lock(exec_mutex_);

    executing_.store(true, std::memory_order_release);

    auto t0 = std::chrono::steady_clock::now();

    bool attached = Injection::instance().is_attached();

    if (attached) {
        result.success = send_to_payload(script);
        if (!result.success)
            result.error = "IPC failed — payload socket unreachable";
        else
            LOG_INFO("Script '{}' dispatched to Roblox payload", name);
    } else {
        result.success = lua_.execute(script, "=" + name);
    }

    auto t1 = std::chrono::steady_clock::now();

    result.execution_time_ms =
        std::chrono::duration<double, std::milli>(t1 - t0).count();

    executing_.store(false, std::memory_order_release);

    {
        std::lock_guard<std::mutex> hlk(history_mutex_);
        execution_history_.push_back(result);
        while (execution_history_.size() > max_history_)
            execution_history_.pop_front();
    }

    if (result_cb_) result_cb_(result);

    return result;
}

void Executor::execute_script(const std::string& script) {
    execute_script(script, "user_script");
}

void Executor::execute_script(const std::string& script,
                              const std::string& name) {
    if (!initialized_.load(std::memory_order_acquire)) {
        if (error_cb_) error_cb_("Executor not initialized");
        return;
    }
    if (script.empty()) {
        if (error_cb_) error_cb_("Empty script");
        return;
    }

    bool attached = Injection::instance().is_attached();

    if (status_cb_)
        status_cb_(attached ? "Sending to Roblox..." : "Executing locally...");

    auto result = execute_internal(script, name);

    if (result.success) {
        if (status_cb_)
            status_cb_(attached ? "Sent to Roblox \u2713" : "Executed \u2713");
    } else {
        if (status_cb_) status_cb_("Execution failed \u2717");
        if (error_cb_ && !result.error.empty()) error_cb_(result.error);
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
    if (Injection::instance().is_attached()) {
        if (status_cb_) status_cb_("Cannot cancel remote execution");
        LOG_WARN("Cancel requested but script is running inside Roblox");
        return;
    }
    lua_.stop();
    executing_.store(false, std::memory_order_release);
    if (status_cb_) status_cb_("Cancelled");
    LOG_INFO("Execution cancelled by user");
}

void Executor::enqueue_script(const std::string& script,
                              const std::string& name, int priority) {
    QueuedScript qs;
    qs.source    = script;
    qs.name      = name;
    qs.is_file   = false;
    qs.priority  = priority;
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

            script = std::move(const_cast<QueuedScript&>(script_queue_.top()));
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
        if (!std::filesystem::exists(dir) ||
            !std::filesystem::is_directory(dir))
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
        if (error_cb_)
            error_cb_("Auto-execute error: " + std::string(e.what()));
    }
}

std::vector<ExecutionResult> Executor::get_history() const {
    std::lock_guard<std::mutex> lock(history_mutex_);
    return {execution_history_.begin(), execution_history_.end()};
}

void Executor::clear_history() {
    std::lock_guard<std::mutex> lock(history_mutex_);
    execution_history_.clear();
}

void Executor::set_output_callback(OutputCallback cb) { output_cb_ = std::move(cb); }
void Executor::set_error_callback(ErrorCallback  cb) { error_cb_  = std::move(cb); }
void Executor::set_status_callback(StatusCallback cb) { status_cb_ = std::move(cb); }
void Executor::set_result_callback(ResultCallback cb) { result_cb_ = std::move(cb); }

} // namespace oss
