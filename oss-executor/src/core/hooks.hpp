#pragma once

#include "memory.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <optional>
#include <mutex>
#include <cstdint>
#include <sys/types.h>

namespace oss {

class HookManager {
public:
    struct Hook {
        uintptr_t target = 0;
        uintptr_t detour = 0;
        uintptr_t trampoline = 0;
        std::vector<uint8_t> original_bytes;
        std::string name;
        bool active = false;
        int original_prot = 0;
    };

    struct PLTHook {
        uintptr_t got_entry = 0;
        uintptr_t original_func = 0;
        uintptr_t detour_func = 0;
        std::string symbol_name;
        bool active = false;
        int original_prot = 0;
    };

    struct RemoteHook {
        uintptr_t target = 0;
        pid_t pid = 0;
        std::string name;
        std::vector<uint8_t> original_bytes;
        std::vector<uint8_t> patch_bytes;
        bool active = false;
    };

    using NamecallHandler = std::function<int(const std::string&, void*)>;
    using IndexHandler    = std::function<bool(const std::string&, void*)>;
    using NewindexHandler = std::function<bool(const std::string&, void*)>;

    static HookManager& instance();

    HookManager(const HookManager&)            = delete;
    HookManager& operator=(const HookManager&) = delete;
    HookManager(HookManager&&)                 = delete;
    HookManager& operator=(HookManager&&)      = delete;

    bool install_hook(uintptr_t target, uintptr_t detour,
                      uintptr_t* original = nullptr,
                      const std::string& name = "");
    bool remove_hook(uintptr_t target);
    std::optional<Hook> find_hook(uintptr_t target);
    std::optional<Hook> find_hook_by_name(const std::string& name);

    bool install_plt_hook(const std::string& library, const std::string& symbol,
                          uintptr_t detour, uintptr_t* original = nullptr);
    bool remove_plt_hook(const std::string& symbol);

    bool install_remote_hook(Memory& mem, uintptr_t target,
                             const std::vector<uint8_t>& patch,
                             const std::string& name = "");
    bool install_remote_got_hook(Memory& mem, pid_t pid,
                                 const std::string& library,
                                 const std::string& symbol,
                                 uintptr_t detour_addr,
                                 uintptr_t* original = nullptr);
    bool remove_remote_hook(Memory& mem, const std::string& name);
    bool remove_remote_hook(Memory& mem, uintptr_t target);

    uintptr_t find_remote_symbol(pid_t pid, const std::string& library,
                                  const std::string& symbol);
    uintptr_t find_remote_got_entry(pid_t pid, const std::string& library,
                                     const std::string& symbol);

    void set_namecall_handler(NamecallHandler handler);
    void set_index_handler(IndexHandler handler);
    void set_newindex_handler(NewindexHandler handler);

    int  dispatch_namecall(const std::string& method, void* state);
    bool dispatch_index(const std::string& key, void* state);
    bool dispatch_newindex(const std::string& key, void* state);

    void remove_all();
    void remove_all_remote(Memory& mem);
    size_t hook_count() const;
    std::vector<std::string> list_hooks() const;

private:
    struct MemRegionInfo {
        uintptr_t start = 0;
        uintptr_t end = 0;
        int prot = 0;
        std::string path;
    };

    HookManager();
    ~HookManager();

    static std::vector<MemRegionInfo> parse_self_maps();
    static std::vector<MemRegionInfo> parse_proc_maps(pid_t pid);
    static bool is_address_in_own_process(uintptr_t addr);
    static uintptr_t find_got_entry(const std::string& library,
                                     const std::string& symbol);

    int  get_region_protection(uintptr_t addr);
    bool make_writable(uintptr_t addr, size_t size);
    bool restore_protection(uintptr_t addr, size_t size, int old_prot);

    std::unordered_map<uintptr_t, Hook> hooks_;
    std::unordered_map<std::string, PLTHook> plt_hooks_;
    std::unordered_map<std::string, RemoteHook> remote_hooks_;

    NamecallHandler namecall_handler_;
    IndexHandler index_handler_;
    NewindexHandler newindex_handler_;

    mutable std::mutex mutex_;
    size_t page_size_ = 4096;
};

}
