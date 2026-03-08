#pragma once

#include "memory.hpp"
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdint>
#include <sys/types.h>

namespace oss {

enum class InjectionState {
    Idle,
    Scanning,
    Found,
    Attaching,
    Injecting,
    Initializing,
    Ready,
    Executing,
    Detached,
    Failed
};

enum class InjectionMode {
    None,
    LocalOnly,
    Full
};

struct ProcessInfo {
    pid_t       pid        = -1;
    pid_t       parent_pid = -1;
    std::string name;
    std::string cmdline;
    std::string exe_path;
    bool        via_wine    = false;
    bool        via_sober   = false;
    bool        via_flatpak = false;
};

struct VMScanResult {
    uintptr_t   marker_addr     = 0;
    uintptr_t   region_base     = 0;
    std::string marker_name;
    std::string region_path;
    bool        validated        = false;
    size_t      regions_scanned  = 0;
    size_t      bytes_scanned    = 0;
};

class Injection {
public:
    using StatusCallback = std::function<void(InjectionState, const std::string&)>;

    static Injection& instance();

    bool scan_for_roblox();
    pid_t find_roblox_pid();

    bool attach();
    bool detach();
    bool inject();
    bool inject_library(pid_t pid, const std::string& lib_path);
    bool execute_script(const std::string& source);

    bool is_attached() const;
    bool is_payload_loaded() const { return payload_loaded_; }
    bool process_alive() const;
    bool verify_payload_alive();

    void start_auto_scan();
    void stop_auto_scan();

    void set_status_callback(StatusCallback cb);

    InjectionState      state()        const { return state_; }
    InjectionMode       mode()         const { return mode_; }
    bool                vm_found()     const { return mode_ == InjectionMode::Full; }
    bool                is_ready()     const { return state_ == InjectionState::Ready; }
    pid_t               target_pid()   const { return memory_.get_pid(); }
    const std::string&  error()        const { return error_; }
    const ProcessInfo&  process_info() const { return proc_info_; }
    const VMScanResult& vm_scan()      const { return vm_scan_; }
    uintptr_t           vm_marker_addr() const { return vm_marker_addr_; }

    Memory& memory() { return memory_; }
    bool send_via_mailbox(const void* data, size_t len, uint32_t flags);
    bool is_direct_hook() const { return dhook_.active; }

private:
    Injection() = default;
    ~Injection() { stop_auto_scan(); stop_elevated_helper(); }
    Injection(const Injection&)            = delete;
    Injection& operator=(const Injection&) = delete;

    static std::string read_proc_cmdline(pid_t pid);
    static std::string read_proc_comm(pid_t pid);
    static std::string read_proc_exe(pid_t pid);
    static bool has_roblox_token(const std::string& s);
    static std::vector<pid_t> descendants(pid_t root);
    static uintptr_t find_elf_symbol(const std::string& filepath,
                                      const std::string& symbol);

    ProcessInfo gather_info(pid_t pid);

    void set_state(InjectionState s, const std::string& msg);
    void adopt_target(pid_t pid, const std::string& via);

    bool scan_direct();
    bool scan_wine_cmdline();
    bool scan_wine_regions();
    bool scan_flatpak();
    bool scan_brute();
    pid_t find_roblox_child(pid_t wrapper_pid);

    bool should_scan_region(const MemoryRegion& r) const;
    bool cross_validate(uintptr_t rstart, size_t rsize);
    bool locate_luau_vm();

    std::string find_payload_path();
    uintptr_t find_libc_function(pid_t pid, const std::string& func_name);
    uintptr_t find_remote_symbol(pid_t pid, const std::string& lib_name,
                                  const std::string& symbol);

    bool inject_shellcode(pid_t pid, const std::string& lib_path,
                          uintptr_t dlopen_addr, uint64_t dlopen_flags);
    bool inject_shellcode_ptrace(pid_t pid, const std::string& lib_path,
                                  uintptr_t dlopen_addr, uint64_t dlopen_flags);
    bool inject_via_procmem(pid_t pid, const std::string& lib_path,
                             uintptr_t dlopen_addr, uint64_t dlopen_flags);
    bool inject_via_inline_hook(pid_t pid, const std::string& lib_path,
                                 uintptr_t dlopen_addr, uint64_t dlopen_flags);
    bool freeze_tracer(pid_t tracer_pid);
    void thaw_tracer(pid_t tracer_pid);

    bool proc_mem_write(pid_t pid, uintptr_t addr, const void* data, size_t len);
    bool proc_mem_read(pid_t pid, uintptr_t addr, void* buf, size_t len);
    bool start_elevated_helper();
    bool elevated_mem_write(pid_t pid, uintptr_t addr, const void* data, size_t len);
    void stop_elevated_helper();

    std::string prepare_payload_for_injection(pid_t pid, const std::string& host_path);
    std::string resolve_socket_path();

    bool write_to_process(uintptr_t addr, const void* data, size_t len);
    bool read_from_process(uintptr_t addr, void* buf, size_t len);

    Memory              memory_{0};
    InjectionState      state_ = InjectionState::Idle;
    InjectionMode       mode_  = InjectionMode::None;
    std::string         error_;

    ProcessInfo         proc_info_{};
    VMScanResult        vm_scan_{};
    uintptr_t           vm_marker_addr_ = 0;
    bool                payload_loaded_ = false;

    StatusCallback      status_cb_;
    mutable std::mutex  mtx_;

    std::thread         scan_thread_;
    std::atomic<bool>   scanning_{false};

    pid_t               elevated_pid_ = -1;
    int                 elevated_in_fd_ = -1;
    int                 elevated_out_fd_ = -1;

    struct DirectMailbox {
        char magic[16];
        uint64_t seq;
        uint64_t ack;
        uint32_t data_size;
        uint32_t flags;
        uint8_t guard;
        uint8_t _pad1;
        uint8_t pad[6];
        uint64_t _reserved[2];
        char data[16320];
    };

    struct DirectHookAddrs {
        uintptr_t resume    = 0;
        uintptr_t newthread = 0;
        uintptr_t load      = 0;
        uintptr_t settop    = 0;
        uintptr_t sandbox   = 0;
        uintptr_t compile   = 0;
        uintptr_t free_fn   = 0;
    };

    struct DirectHookState {
        uintptr_t cave_addr    = 0;
        uintptr_t mailbox_addr = 0;
        uintptr_t resume_addr  = 0;
        uintptr_t newthread_addr = 0;
        size_t    cave_size    = 0;
        size_t    stolen_len   = 0;
        uint8_t   stolen_bytes[32] = {};
        uint8_t   orig_patch[32]   = {};
        size_t    patch_len    = 0;
        bool      active       = false;
        bool      has_compile  = false;
        bool      has_sandbox  = false;
    };

    bool inject_via_direct_hook(pid_t pid);
    bool find_remote_luau_functions(pid_t pid, DirectHookAddrs& out);
    void cleanup_direct_hook();

    DirectHookState dhook_;
};

}











