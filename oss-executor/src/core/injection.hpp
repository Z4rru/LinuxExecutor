#pragma once
#include "memory.hpp"
#include <thread>
#include <atomic>
#include <string>
#include <functional>
#include <sys/types.h>

namespace oss {

enum class InjectionStatus {
    Idle, Scanning, Found, Attaching, Injected, Detached, Failed
};

class Injection {
public:
    static Injection& instance() {
        static Injection inst;
        return inst;
    }

    bool scan_for_roblox();
    bool attach();
    bool detach();
    bool inject();
    void start_auto_scan();
    void stop_auto_scan();

    using StatusCallback =
        std::function<void(InjectionStatus, const std::string&)>;
    void set_status_callback(StatusCallback cb) {
        status_cb_ = std::move(cb);
    }

private:
    Injection() = default;
    ~Injection() { stop_auto_scan(); }
    Injection(const Injection&) = delete;
    Injection& operator=(const Injection&) = delete;

    void set_status(InjectionStatus s, const std::string& msg) {
        status_ = s;
        if (status_cb_) status_cb_(s, msg);
    }

    // No is_roblox_wine_process / is_roblox_flatpak_process
    // needed — logic moved to free functions in .cpp

    Memory            memory_{0};
    InjectionStatus   status_ = InjectionStatus::Idle;
    StatusCallback    status_cb_;
    std::atomic<bool> scanning_{false};
    std::thread       scan_thread_;
};

} // namespace oss
