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

// ═══════════════════════════════════════════════════════════════
// FIX #7: Track whether we actually found the Luau VM, separate
// from whether we attached to the process.  inject() no longer
// lies about success when the VM scan fails.
// ═══════════════════════════════════════════════════════════════
enum class InjectionMode {
    None,           // not injected
    LocalOnly,      // attached to process, but no VM found — scripts run locally
    Full            // VM located — can (in theory) execute in-process
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

    InjectionMode mode() const { return mode_; }
    bool          vm_found() const { return mode_ == InjectionMode::Full; }

    using StatusCallback =
        std::function<void(InjectionStatus, const std::string&)>;
    void set_status_callback(StatusCallback cb) {
        status_cb_ = std::move(cb);
    }

private:
    Injection() = default;
    ~Injection() { stop_auto_scan(); }
    Injection(const Injection&)            = delete;
    Injection& operator=(const Injection&) = delete;

    void set_status(InjectionStatus s, const std::string& msg) {
        status_ = s;
        if (status_cb_) status_cb_(s, msg);
    }

    Memory            memory_{0};
    InjectionStatus   status_ = InjectionStatus::Idle;
    InjectionMode     mode_   = InjectionMode::None;
    StatusCallback    status_cb_;
    std::atomic<bool> scanning_{false};
    std::thread       scan_thread_;

    uintptr_t         vm_marker_addr_ = 0;   // address of Luau marker if found
};

} // namespace oss
