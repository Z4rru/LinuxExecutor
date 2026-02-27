#pragma once

#include <cstdint>
#include <vector>
#include <functional>
#include <unordered_map>
#include <string>
#include <mutex>
#include <memory>
#include <sys/mman.h>
#include <cstring>
#include <fstream>

namespace oss {

class Memory;

class HookManager {
public:
    struct Hook {
        uintptr_t target = 0;
        uintptr_t detour = 0;
        uintptr_t trampoline = 0;
        std::vector<uint8_t> original_bytes;
        bool active = false;
        std::string name;
    };

    struct PLTHook {
        uintptr_t got_entry = 0;
        uintptr_t original_func = 0;
        uintptr_t detour_func = 0;
        std::string symbol_name;
        bool active = false;
    };

    struct RemoteHook {
        uintptr_t target = 0;
        std::vector<uint8_t> original_bytes;
        std::vector<uint8_t> patch_bytes;
        pid_t pid = 0;
        bool active = false;
        std::string name;
    };

    using NamecallHandler = std::function<int(const std::string& method, void* state)>;
    using IndexHandler = std::function<bool(const std::string& key, void* state)>;
    using NewindexHandler = std::function<bool(const std::string& key, void* state)>;

    static HookManager& instance();

    bool install_hook(uintptr_t target, uintptr_t detour, uintptr_t* original,
                      const std::string& name = "");
    bool remove_hook(uintptr_t target);
    Hook* find_hook(uintptr_t target);
    Hook* find_hook_by_name(const std::string& name);

    bool install_plt_hook(const std::string& library, const std::string& symbol,
                          uintptr_t detour, uintptr_t* original);
    bool remove_plt_hook(const std::string& symbol);

    bool install_remote_hook(Memory& mem, uintptr_t target,
                             const std::vector<uint8_t>& patch,
                             const std::string& name = "");
    bool remove_remote_hook(Memory& mem, const std::string& name);
    bool remove_remote_hook(Memory& mem, uintptr_t target);

    void set_namecall_handler(NamecallHandler handler);
    void set_index_handler(IndexHandler handler);
    void set_newindex_handler(NewindexHandler handler);

    int dispatch_namecall(const std::string& method, void* state);
    bool dispatch_index(const std::string& key, void* state);
    bool dispatch_newindex(const std::string& key, void* state);

    void remove_all();
    void remove_all_remote(Memory& mem);
    size_t hook_count() const;
    std::vector<std::string> list_hooks() const;

private:
    HookManager() = default;
    ~HookManager();

    HookManager(const HookManager&) = delete;
    HookManager& operator=(const HookManager&) = delete;

    struct MemRegionInfo {
        uintptr_t start;
        uintptr_t end;
        int prot;
        std::string path;
    };

    bool make_writable(uintptr_t addr, size_t size);
    bool restore_protection(uintptr_t addr, size_t size, int old_prot);
    bool is_address_in_own_process(uintptr_t addr);

    uintptr_t find_got_entry(const std::string& library, const std::string& symbol);
    std::vector<MemRegionInfo> parse_self_maps();

    std::unordered_map<uintptr_t, Hook> hooks_;
    std::unordered_map<std::string, PLTHook> plt_hooks_;
    std::unordered_map<std::string, RemoteHook> remote_hooks_;

    NamecallHandler namecall_handler_;
    IndexHandler index_handler_;
    NewindexHandler newindex_handler_;

    mutable std::mutex mutex_;
};

} // namespace oss
