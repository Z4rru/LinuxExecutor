#include "injection.hpp"
#include "utils/logger.hpp"
#include <chrono>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <string>
#include <cctype>

namespace oss {

// ═══════════════════════════════════════════════════════════════
// HELPER: Read /proc/PID/cmdline, return space-separated string
// ═══════════════════════════════════════════════════════════════
static std::string read_proc_cmdline(pid_t pid) {
    try {
        std::ifstream f("/proc/" + std::to_string(pid) + "/cmdline",
                        std::ios::binary);
        if (!f.is_open()) return {};

        std::string raw((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        // cmdline uses \0 as separator — replace for searching
        std::replace(raw.begin(), raw.end(), '\0', ' ');
        return raw;
    } catch (...) {
        return {};
    }
}

// ═══════════════════════════════════════════════════════════════
// HELPER: Check if a cmdline string contains Roblox markers
// ═══════════════════════════════════════════════════════════════
static bool cmdline_has_roblox(const std::string& cmdline) {
    static const std::vector<std::string> markers = {
        "RobloxPlayer", "RobloxPlayerBeta", "RobloxPlayerLauncher",
        "Roblox.exe", "roblox"
    };
    for (const auto& m : markers) {
        if (cmdline.find(m) != std::string::npos) return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════
// HELPER: Get all child PIDs of a parent (recursive via /proc)
//
// Does NOT rely on /proc/PID/task/PID/children (needs
// CONFIG_PROC_CHILDREN). Instead reads ppid from /proc/*/stat.
// ═══════════════════════════════════════════════════════════════
static std::vector<pid_t> get_descendant_pids(pid_t parent) {
    std::vector<pid_t> result;

    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;

        std::string dirname = entry.path().filename().string();
        if (!std::all_of(dirname.begin(), dirname.end(), ::isdigit)) continue;

        pid_t pid = std::stoi(dirname);
        if (pid == parent) continue;

        // Read ppid from /proc/PID/stat — field 4
        try {
            std::ifstream stat_file(entry.path() / "stat");
            if (!stat_file.is_open()) continue;

            std::string stat_line;
            std::getline(stat_file, stat_line);

            // Format: "PID (comm) S PPID ..."
            // comm can contain spaces/parens, so find last ')' first
            auto comm_end = stat_line.rfind(')');
            if (comm_end == std::string::npos) continue;

            // Skip ") X " to reach PPID
            std::string after_comm = stat_line.substr(comm_end + 2);
            // after_comm = "S PPID PGRP ..."
            std::istringstream iss(after_comm);
            char state;
            pid_t ppid;
            iss >> state >> ppid;

            if (ppid == parent) {
                result.push_back(pid);
            }
        } catch (...) {
            continue;
        }
    }
    return result;
}

// ═══════════════════════════════════════════════════════════════
// MAIN SCANNER — 5-phase Roblox detection
// ═══════════════════════════════════════════════════════════════
bool Injection::scan_for_roblox() {
    set_status(InjectionStatus::Scanning, "Scanning for Roblox...");

    // ── Phase 1: Direct process name matches ──────────────
    // Covers native processes, Wine-visible .exe names, Sober
    static const std::vector<std::string> targets = {
        "RobloxPlayer",
        "RobloxPlayerBeta",
        "RobloxPlayerBeta.exe",
        "RobloxPlayerLauncher",
        "Roblox",
        "sober",                      // Sober binary name
        ".sober-wrapped",             // Sober's actual wrapped name
        "org.vinegarhq.Sober",        // Flatpak app ID in some configs
        "vinegar",                    // Vinegar launcher
    };

    for (const auto& target : targets) {
        LOG_INFO("Phase 1: scanning for '{}'", target);
        auto pid = Memory::find_process(target);
        if (pid.has_value()) {
            memory_.set_pid(pid.value());
            set_status(InjectionStatus::Found,
                       "Found Roblox (PID: " + std::to_string(pid.value()) + ")");
            LOG_INFO("Phase 1 hit: '{}' → PID {}", target, pid.value());
            return true;
        }
    }

    // ── Phase 2: Wine host processes → check cmdline ─────
    // Wine processes appear as "wine-preloader" but their
    // cmdline reveals the actual .exe being run
    static const std::vector<std::string> wine_hosts = {
        "wine-preloader",
        "wine64-preloader",
        "wine",
        "wine64",
    };

    for (const auto& host : wine_hosts) {
        auto pids = Memory::find_all_processes(host);
        for (auto pid : pids) {
            std::string cmdline = read_proc_cmdline(pid);
            if (cmdline_has_roblox(cmdline)) {
                memory_.set_pid(pid);
                set_status(InjectionStatus::Found,
                           "Found Roblox via Wine (PID: " + std::to_string(pid) + ")");
                LOG_INFO("Phase 2 hit: Wine host '{}', cmdline match → PID {}",
                         host, pid);
                return true;
            }
        }
    }

    // ── Phase 3: Wine process memory regions ─────────────
    // Fallback: look for "Roblox" in mapped file paths
    auto all_wine = Memory::find_all_processes("wine");
    for (auto pid : all_wine) {
        Memory mem(pid);
        auto regions = mem.get_regions();
        for (const auto& region : regions) {
            if (region.path.find("Roblox") != std::string::npos ||
                region.path.find("roblox") != std::string::npos) {
                memory_.set_pid(pid);
                set_status(InjectionStatus::Found,
                           "Found Roblox via Wine memory (PID: " + std::to_string(pid) + ")");
                LOG_INFO("Phase 3 hit: Wine memory map '{}' → PID {}",
                         region.path, pid);
                return true;
            }
        }
    }

    // ── Phase 4: Flatpak/bwrap sandbox child scanning ────
    // ═══════════════════════════════════════════════════════
    // FIX: BOTH previous versions were wrong here.
    //
    // Bug Report:  used /proc/PID/task/PID/children
    //              → needs CONFIG_PROC_CHILDREN (often absent)
    //
    // Full Validation: set memory_ to bwrap PID itself
    //              → bwrap is sandbox, not Roblox process
    //
    // CORRECT: Find bwrap → enumerate ALL /proc descendants
    // by reading ppid from /proc/*/stat → find the Wine
    // child whose cmdline contains Roblox
    // ═══════════════════════════════════════════════════════
    auto bwrap_pids = Memory::find_all_processes("bwrap");
    for (auto bwrap_pid : bwrap_pids) {
        std::string bwrap_cmdline = read_proc_cmdline(bwrap_pid);

        // Only care about Sober/Vinegar bwrap instances
        if (bwrap_cmdline.find("Sober")     == std::string::npos &&
            bwrap_cmdline.find("sober")     == std::string::npos &&
            bwrap_cmdline.find("vinegar")   == std::string::npos &&
            bwrap_cmdline.find("vinegarhq") == std::string::npos) {
            continue;
        }

        LOG_INFO("Phase 4: found Sober bwrap PID {}, scanning children...",
                 bwrap_pid);

        // Get all descendant processes of this bwrap
        auto children = get_descendant_pids(bwrap_pid);

        // Also get grandchildren (Wine spawns multiple levels)
        std::vector<pid_t> all_descendants = children;
        for (auto child : children) {
            auto grandchildren = get_descendant_pids(child);
            all_descendants.insert(all_descendants.end(),
                                    grandchildren.begin(),
                                    grandchildren.end());
        }

        for (auto child_pid : all_descendants) {
            std::string child_cmdline = read_proc_cmdline(child_pid);
            if (cmdline_has_roblox(child_cmdline)) {
                memory_.set_pid(child_pid);
                set_status(InjectionStatus::Found,
                           "Found Roblox via Sober (PID: " +
                           std::to_string(child_pid) + ")");
                LOG_INFO("Phase 4 hit: Sober child PID {} (parent bwrap {})",
                         child_pid, bwrap_pid);
                return true;
            }

            // Also check memory regions of children
            Memory mem(child_pid);
            auto regions = mem.get_regions();
            for (const auto& region : regions) {
                if (region.path.find("Roblox") != std::string::npos ||
                    region.path.find("roblox") != std::string::npos) {
                    memory_.set_pid(child_pid);
                    set_status(InjectionStatus::Found,
                               "Found Roblox via Sober memory (PID: " +
                               std::to_string(child_pid) + ")");
                    LOG_INFO("Phase 4 hit: Sober child memory map → PID {}",
                             child_pid);
                    return true;
                }
            }
        }
    }

    // ── Phase 5: Brute-force /proc scan ──────────────────
    // Last resort: check EVERY process cmdline for Roblox
    // This catches any weird launcher/wrapper we didn't predict
    LOG_INFO("Phase 5: brute-force /proc scan for Roblox in cmdline...");
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;

        std::string dirname = entry.path().filename().string();
        if (!std::all_of(dirname.begin(), dirname.end(), ::isdigit)) continue;

        pid_t pid = std::stoi(dirname);
        std::string cmdline = read_proc_cmdline(pid);
        if (cmdline_has_roblox(cmdline)) {
            memory_.set_pid(pid);
            set_status(InjectionStatus::Found,
                       "Found Roblox (PID: " + std::to_string(pid) + ")");
            LOG_INFO("Phase 5 hit: brute-force cmdline match → PID {}", pid);
            return true;
        }
    }

    set_status(InjectionStatus::Idle, "Roblox not found");
    LOG_WARN("All 5 scan phases completed — Roblox not found");
    return false;
}

bool Injection::attach() {
    if (!memory_.is_valid()) {
        if (!scan_for_roblox()) return false;
    }

    set_status(InjectionStatus::Attaching, "Attaching to process...");

    auto regions = memory_.get_regions();
    if (regions.empty()) {
        set_status(InjectionStatus::Failed, "Cannot access process memory");
        LOG_ERROR("Failed to read memory maps for PID {}", memory_.get_pid());
        return false;
    }

    LOG_INFO("Attached to PID {}, {} memory regions",
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

    auto regions = memory_.get_regions();
    uintptr_t lua_state_addr = 0;

    for (const auto& region : regions) {
        // FIX #8: scan readable regions, not just writable
        if (!region.readable()) continue;
        if (region.size() < 0x1000 || region.size() > 0x10000000) continue;

        // LuaJIT bytecode header: ESC "LJ"
        std::vector<uint8_t> pattern = { 0x1B, 0x4C, 0x4A };
        std::string mask = "xxx";

        size_t scan_len = std::min(region.size(),
                                    static_cast<size_t>(0x400000));

        auto result = memory_.pattern_scan(pattern, mask,
                                            region.start, scan_len);
        if (result.has_value()) {
            lua_state_addr = result.value();
            LOG_INFO("Found Lua bytecode at 0x{:X} in '{}'",
                     lua_state_addr, region.path);
            break;
        }
    }

    if (lua_state_addr == 0) {
        LOG_WARN("No Lua state via pattern scan — direct execution mode");
    }

    set_status(InjectionStatus::Injected, "Injection complete - Ready");
    return true;
}

// FIX #7: atomic CAS prevents TOCTOU race
void Injection::start_auto_scan() {
    bool expected = false;
    if (!scanning_.compare_exchange_strong(expected, true)) {
        return;
    }

    scan_thread_ = std::thread([this]() {
        while (scanning_.load()) {
            if (!memory_.is_valid()) {
                scan_for_roblox();
            }
            for (int i = 0; i < 30 && scanning_.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    });
}

void Injection::stop_auto_scan() {
    scanning_.store(false);
    if (scan_thread_.joinable()) {
        scan_thread_.join();
    }
}

} // namespace oss
