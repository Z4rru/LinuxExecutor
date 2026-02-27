#pragma once
#include "memory.hpp"
#include <thread>
#include <atomic>
#include <string>
#include <functional>
#include <vector>
#include <mutex>
#include <sys/types.h>

namespace oss {

enum class InjectionStatus {
    Idle, Scanning, Found, Attaching, Injected, Detached, Failed, Executing
};

enum class InjectionMode {
    None,
    LocalOnly,
    Full
};

struct ProcessInfo {
    pid_t pid = 0;
    std::string name;
    std::string cmdline;
    std::string exe_path;
    pid_t parent_pid = 0;
    bool via_wine = false;
    bool via_sober = false;
    bool via_flatpak = false;
};

struct VMScanResult {
    uintptr_t marker_addr = 0;
    uintptr_t region_base = 0;
    std::string marker_name;
    std::string region_path;
    size_t regions_scanned = 0;
    size_t bytes_scanned = 0;
    bool validated = false;
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
    bool execute_script(const std::string& source);
    void start_auto_scan();
    void stop_auto_scan();

    InjectionMode       mode()         const { return mode_; }
    bool                vm_found()     const { return mode_ == InjectionMode::Full; }
    bool                is_attached()  const;
    InjectionStatus     status()       const { return status_; }
    pid_t               get_pid()      const { return memory_.get_pid(); }
    const ProcessInfo&  process_info() const { return proc_info_; }
    const VMScanResult& vm_scan()      const { return vm_scan_; }

    using StatusCallback = std::function<void(InjectionStatus, const std::string&)>;
    void set_status_callback(StatusCallback cb);

private:
    Injection() = default;
    ~Injection() { stop_auto_scan(); }
    Injection(const Injection&)            = delete;
    Injection& operator=(const Injection&) = delete;

    void set_status(InjectionStatus s, const std::string& msg);
    bool process_alive() const;

    bool scan_direct();
    bool scan_wine_cmdline();
    bool scan_wine_regions();
    bool scan_flatpak();
    bool scan_brute();
    void adopt_target(pid_t pid, const std::string& via);

    bool locate_luau_vm();
    bool cross_validate(uintptr_t rstart, size_t rsize);
    bool should_scan_region(const MemoryRegion& r) const;
    ProcessInfo gather_info(pid_t pid);

    static std::string read_proc_cmdline(pid_t pid);
    static std::string read_proc_comm(pid_t pid);
    static std::string read_proc_exe(pid_t pid);
    static bool has_roblox_token(const std::string& s);
    static std::vector<pid_t> descendants(pid_t root);

    Memory            memory_{0};
    InjectionStatus   status_ = InjectionStatus::Idle;
    InjectionMode     mode_   = InjectionMode::None;
    ProcessInfo       proc_info_{};
    VMScanResult      vm_scan_{};
    StatusCallback    status_cb_;
    std::atomic<bool> scanning_{false};
    std::thread       scan_thread_;
    mutable std::mutex mtx_;
    uintptr_t         vm_marker_addr_ = 0;
};

} // namespace oss
