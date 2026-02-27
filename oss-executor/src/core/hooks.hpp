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

    // ═══════════════════════════════════════════════════════════
    // SAFETY: install_hook / remove_hook are designed for
    // IN-PROCESS hooking only. They use memcpy and mprotect
    // on addresses within THIS process's memory space.
    //
    // They CANNOT hook functions in another process (Roblox).
    // Calling them with addresses from /proc/PID/maps of
    // another process WILL segfault.
    //
    // For cross-process work, use Memory::pattern_scan() and
    // /proc/PID/mem read/write instead.
    // ═══════════════════════════════════════════════════════════

    bool install_hook(uintptr_t target, uintptr_t detour, uintptr_t* original) {
        // Safety check: verify target is in our own process's readable memory
        // by attempting a tiny read. If it segfaults, we catch it.
        // Simple approach: check /proc/self/maps
        if (!is_address_in_own_process(target)) {
            return false;  // Don't touch addresses we don't own
        }

        Hook hook;
        hook.target = target;
        hook.detour = detour;
        hook.active = false;

        hook.original_bytes.resize(14);
        memcpy(hook.original_bytes.data(), reinterpret_cast<void*>(target), 14);

        void* tramp = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (tramp == MAP_FAILED) return false;

        hook.trampoline = reinterpret_cast<uintptr_t>(tramp);

        memcpy(tramp, hook.original_bytes.data(), 14);

        uint8_t* tramp_ptr = static_cast<uint8_t*>(tramp) + 14;
        tramp_ptr[0] = 0xFF;
        tramp_ptr[1] = 0x25;
        *reinterpret_cast<uint32_t*>(tramp_ptr + 2) = 0;
        *reinterpret_cast<uint64_t*>(tramp_ptr + 6) = target + 14;

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

        if (make_writable(target, hook.original_bytes.size())) {
            memcpy(reinterpret_cast<void*>(target),
                   hook.original_bytes.data(),
                   hook.original_bytes.size());
        }

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

    // Check if an address belongs to our own process
    bool is_address_in_own_process(uintptr_t addr) {
        std::ifstream maps("/proc/self/maps");
        if (!maps.is_open()) return false;
        std::string line;
        while (std::getline(maps, line)) {
            auto dash = line.find('-');
            auto space = line.find(' ', dash);
            if (dash == std::string::npos || space == std::string::npos)
                continue;
            uintptr_t start = std::stoull(line.substr(0, dash), nullptr, 16);
            uintptr_t end = std::stoull(
                line.substr(dash + 1, space - dash - 1), nullptr, 16);
            if (addr >= start && addr < end) return true;
        }
        return false;
    }

    std::unordered_map<uintptr_t, Hook> hooks_;
};

} // namespace oss
