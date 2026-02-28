#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>          // FIX 1: needed for safe find_hook return
#include <string>
#include <sys/types.h>       // FIX 2: needed for pid_t in RemoteHook
#include <unordered_map>
#include <vector>
// REMOVED: <sys/mman.h>, <cstring>, <fstream>, <memory> — belong in .cpp only

namespace oss {

class Memory;

class HookManager {
public:
    struct Hook {
        uintptr_t target      = 0;
        uintptr_t detour      = 0;
        uintptr_t trampoline  = 0;
        std::vector<uint8_t> original_bytes;
        int  original_prot    = 0;     // FIX 3: saved for restoration on unhook
        bool active           = false;
        std::string name;
    };

    struct PLTHook {
        uintptr_t   got_entry     = 0;
        uintptr_t   original_func = 0;
        uintptr_t   detour_func   = 0;
        int         original_prot = 0; // FIX 3: saved for restoration
        std::string symbol_name;
        bool        active        = false;
    };

    struct RemoteHook {
        uintptr_t target = 0;
        std::vector<uint8_t> original_bytes;
        std::vector<uint8_t> patch_bytes;
        pid_t pid    = 0;
        bool  active = false;
        std::string name;
    };

    using NamecallHandler  = std::function<int(const std::string& method, void* state)>;
    using IndexHandler     = std::function<bool(const std::string& key, void* state)>;
    using NewindexHandler  = std::function<bool(const std::string& key, void* state)>;

    static HookManager& instance();

    HookManager(const HookManager&)            = delete;
    HookManager& operator=(const HookManager&) = delete;
    HookManager(HookManager&&)                 = delete;   // FIX 4: prevent move
    HookManager& operator=(HookManager&&)      = delete;

    // ── Inline hooks ──
    bool install_hook(uintptr_t target, uintptr_t detour, uintptr_t* original,
                      const std::string& name = "");
    bool remove_hook(uintptr_t target);

    // FIX 5: return copies — original returned raw pointers that became
    //        dangling the instant the lock was released.
    std::optional<Hook> find_hook(uintptr_t target);
    std::optional<Hook> find_hook_by_name(const std::string& name);

    // ── PLT / GOT hooks ──
    bool install_plt_hook(const std::string& library, const std::string& symbol,
                          uintptr_t detour, uintptr_t* original);
    bool remove_plt_hook(const std::string& symbol);

    // ── Remote (cross-process) hooks ──
    bool install_remote_hook(Memory& mem, uintptr_t target,
                             const std::vector<uint8_t>& patch,
                             const std::string& name = "");
    bool remove_remote_hook(Memory& mem, const std::string& name);
    bool remove_remote_hook(Memory& mem, uintptr_t target);

    // ── Metamethod dispatch ──
    void set_namecall_handler(NamecallHandler handler);
    void set_index_handler(IndexHandler handler);
    void set_newindex_handler(NewindexHandler handler);

    int  dispatch_namecall(const std::string& method, void* state);
    bool dispatch_index(const std::string& key, void* state);
    bool dispatch_newindex(const std::string& key, void* state);

    // ── Bulk operations ──
    void remove_all();
    void remove_all_remote(Memory& mem);
    size_t hook_count() const;
    std::vector<std::string> list_hooks() const;

private:
    HookManager();
    ~HookManager();

    struct MemRegionInfo {
        uintptr_t   start = 0;   // FIX 6: was uninitialized
        uintptr_t   end   = 0;
        int         prot  = 0;
        std::string path;
    };

    bool make_writable(uintptr_t addr, size_t size);
    bool restore_protection(uintptr_t addr, size_t size, int old_prot);
    bool is_address_in_own_process(uintptr_t addr);
    int  get_region_protection(uintptr_t addr);   // FIX 3: new helper

    uintptr_t find_got_entry(const std::string& library,
                             const std::string& symbol);
    std::vector<MemRegionInfo> parse_self_maps();

    std::unordered_map<uintptr_t, Hook>       hooks_;
    std::unordered_map<std::string, PLTHook>   plt_hooks_;
    std::unordered_map<std::string, RemoteHook> remote_hooks_;

    NamecallHandler  namecall_handler_;
    IndexHandler     index_handler_;
    NewindexHandler  newindex_handler_;

    mutable std::mutex mutex_;
    size_t page_size_ = 4096;   // FIX 7: overwritten in ctor from sysconf
};

} // namespace oss
