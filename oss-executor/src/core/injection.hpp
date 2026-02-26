#pragma once

#include "memory.hpp"
#include "utils/logger.hpp"

#include <string>
#include <functional>
#include <optional>
#include <thread>
#include <atomic>

namespace oss {

enum class InjectionStatus {
    Idle,
    Scanning,
    Found,
    Attaching,
    Injected,
    Failed,
    Detached
};

class Injection {
public:
    using StatusCallback = std::function<void(InjectionStatus, const std::string&)>;

    static Injection& instance() {
        static Injection inst;
        return inst;
    }

    Injection(const Injection&)            = delete;
    Injection& operator=(const Injection&) = delete;

    ~Injection() {
        stop_auto_scan();          // ensure thread is joined
    }

    void set_status_callback(StatusCallback cb) { status_cb_ = std::move(cb); }

    InjectionStatus status() const { return status_.load(); }
    pid_t target_pid() const { return memory_.get_pid(); }

    bool scan_for_roblox();
    bool attach();
    bool detach();
    bool inject();

    void start_auto_scan();
    void stop_auto_scan();

    Memory& memory() { return memory_; }

private:
    Injection() = default;

    void set_status(InjectionStatus s, const std::string& msg = "") {
        status_.store(s);
        if (status_cb_) status_cb_(s, msg);
    }

    Memory memory_;
    std::atomic<InjectionStatus> status_{InjectionStatus::Idle};
    StatusCallback status_cb_;
    std::atomic<bool> scanning_{false};
    std::thread scan_thread_;
};

} // namespace oss
