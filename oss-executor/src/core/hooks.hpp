#pragma once

#include <cstdint>
#include <vector>
#include <functional>
#include <unordered_map>
#include <sys/mman.h>
#include <cstring>

namespace oss {

class HookManager {
public:
    struct Hook {
        uintptr_t target;
        uintptr_t detour;
        uintptr_t trampoline;
        std::vector<uint8_t> original_bytes;
        bool active;
    };

    static HookManager& instance() {
        static HookManager inst;
        return inst;
    }

    bool install_hook(uintptr_t target, uintptr_t detour, uintptr_t* original) {
        Hook hook;
        hook.target = target;
        hook.detour = detour;
        hook.active = false;

        // Save original bytes (14 bytes for absolute jump on x64)
        hook.original_bytes.resize(14);
        memcpy(hook.original_bytes.data(), reinterpret_cast<void*>(target), 14);

        // Allocate trampoline
        void* tramp = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (tramp == MAP_FAILED) return false;
        
        hook.trampoline = reinterpret_cast<uintptr_t>(tramp);

        // Copy original bytes to trampoline
        memcpy(tramp, hook.original_bytes.data(), 14);
        
        // Add jump back to target + 14
        uint8_t* tramp_ptr = static_cast<uint8_t*>(tramp) + 14;
        tramp_ptr[0] = 0xFF;
        tramp_ptr[1] = 0x25;
        *reinterpret_cast<uint32_t*>(tramp_ptr + 2) = 0;
        *reinterpret_cast<uint64_t*>(tramp_ptr + 6) = target + 14;

        // Write jump to detour at target
        if (!make_writable(target, 14)) {
            munmap(tramp, 4096);
            return false;
        }
        
        uint8_t* target_ptr = reinterpret_cast<uint8_t*>(target);
        target_ptr[0] = 0xFF;
        target_ptr[1] = 0x25;
        *reinterpret_cast<uint32_t*>(target_ptr + 2) = 0;
        *reinterpret_cast<uint64_t*>(target_ptr + 6) = detour;

        hook.active = true;
        
        if (original) *original = hook.trampoline;
        
        hooks_[target] = hook;
        return true;
    }

    bool remove_hook(uintptr_t target) {
        auto it = hooks_.find(target);
        if (it == hooks_.end()) return false;
        
        auto& hook = it->second;
        
        // Restore original bytes
        if (make_writable(target, hook.original_bytes.size())) {
            memcpy(reinterpret_cast<void*>(target), 
                   hook.original_bytes.data(), 
                   hook.original_bytes.size());
        }
        
        // Free trampoline
        if (hook.trampoline) {
            munmap(reinterpret_cast<void*>(hook.trampoline), 4096);
        }
        
        hooks_.erase(it);
        return true;
    }

    void remove_all() {
        auto copy = hooks_;
        for (auto& [target, _] : copy) {
            remove_hook(target);
        }
    }

private:
    HookManager() = default;
    ~HookManager() { remove_all(); }

    bool make_writable(uintptr_t addr, size_t size) {
        uintptr_t page = addr & ~0xFFF;
        size_t page_size = (addr + size - page + 0xFFF) & ~0xFFF;
        return mprotect(reinterpret_cast<void*>(page), page_size,
                       PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
    }

    std::unordered_map<uintptr_t, Hook> hooks_;
};

} // namespace oss