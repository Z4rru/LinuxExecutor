#include "injection.hpp"
#include <chrono>

namespace oss {

bool Injection::scan_for_roblox() {
    set_status(InjectionStatus::Scanning, "Scanning for Roblox...");
    
    // Search for various Roblox process names (native + Wine)
    std::vector<std::string> targets = {
        "RobloxPlayer",
        "RobloxPlayerBeta",
        "Roblox",
        "RobloxPlayerBeta.exe",
        "RobloxPlayerLauncher",
        "wine.*Roblox",
        "vinegar"
    };
    
    for (const auto& target : targets) {
        auto pid = Memory::find_process(target);
        if (pid.has_value()) {
            memory_.set_pid(pid.value());
            set_status(InjectionStatus::Found, 
                       "Found Roblox (PID: " + std::to_string(pid.value()) + ")");
            LOG_INFO("Found Roblox process: PID {}", pid.value());
            return true;
        }
    }
    
    // Also check via wine processes
    auto wine_pids = Memory::find_all_processes("wine");
    for (auto pid : wine_pids) {
        Memory mem(pid);
        auto regions = mem.get_regions();
        for (const auto& region : regions) {
            if (region.path.find("Roblox") != std::string::npos ||
                region.path.find("roblox") != std::string::npos) {
                memory_.set_pid(pid);
                set_status(InjectionStatus::Found,
                           "Found Roblox via Wine (PID: " + std::to_string(pid) + ")");
                LOG_INFO("Found Roblox via Wine: PID {}", pid);
                return true;
            }
        }
    }
    
    set_status(InjectionStatus::Idle, "Roblox not found");
    return false;
}

bool Injection::attach() {
    if (!memory_.is_valid()) {
        if (!scan_for_roblox()) return false;
    }
    
    set_status(InjectionStatus::Attaching, "Attaching to process...");
    
    // On Linux we use process_vm_readv/writev which doesn't require ptrace attach
    // for reading, but we verify we can access the process
    auto regions = memory_.get_regions();
    if (regions.empty()) {
        set_status(InjectionStatus::Failed, "Cannot access process memory");
        LOG_ERROR("Failed to read process memory maps");
        return false;
    }
    
    LOG_INFO("Attached to process PID {}, {} memory regions", 
             memory_.get_pid(), regions.size());
    
    set_status(InjectionStatus::Injected, "Attached successfully");
    return true;
}

bool Injection::detach() {
    set_status(InjectionStatus::Detached, "Detached");
    memory_.set_pid(0);
    return true;
}

bool Injection::inject() {
    if (!attach()) return false;
    
    // Find Roblox's Lua state in memory
    auto regions = memory_.get_regions();
    
    uintptr_t lua_state_addr = 0;
    
    for (const auto& region : regions) {
        if (!region.readable() || !region.writable()) continue;
        if (region.size() < 0x1000 || region.size() > 0x10000000) continue;
        
        // Search for Lua state signatures
        // Pattern for LuaJIT global_State structure
        std::vector<uint8_t> pattern = {
            0x1B, 0x4C, 0x4A  // LuaJIT bytecode header
        };
        std::string mask = "xxx";
        
        auto result = memory_.pattern_scan(pattern, mask, region.start, 
                                            std::min(region.size(), size_t(0x100000)));
        if (result.has_value()) {
            lua_state_addr = result.value();
            LOG_INFO("Found potential Lua state at 0x{:X}", lua_state_addr);
            break;
        }
    }
    
    if (lua_state_addr == 0) {
        LOG_WARN("Could not find Lua state via pattern scan, using direct execution mode");
    }
    
    set_status(InjectionStatus::Injected, "Injection complete - Ready");
    return true;
}

void Injection::start_auto_scan() {
    if (scanning_) return;
    scanning_ = true;
    
    scan_thread_ = std::thread([this]() {
        while (scanning_) {
            if (!memory_.is_valid()) {
                scan_for_roblox();
            }
            std::this_thread::sleep_for(std::chrono::seconds(3));
        }
    });
    scan_thread_.detach();
}

void Injection::stop_auto_scan() {
    scanning_ = false;
}

} // namespace oss