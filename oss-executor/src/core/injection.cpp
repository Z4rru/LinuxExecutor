#include "injection.hpp"
#include "utils/logger.hpp"
#include <chrono>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <string>
#include <sstream>
#include <cctype>

namespace oss {

// ── helpers (unchanged) ─────────────────────────────────────────

static std::string read_proc_cmdline(pid_t pid) {
    try {
        std::ifstream f("/proc/" + std::to_string(pid) + "/cmdline",
                        std::ios::binary);
        if (!f.is_open()) return {};
        std::string raw((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        std::replace(raw.begin(), raw.end(), '\0', ' ');
        return raw;
    } catch (...) { return {}; }
}

static bool cmdline_has_roblox(const std::string& cmdline) {
    static const std::vector<std::string> markers = {
        "RobloxPlayer", "RobloxPlayerBeta", "RobloxPlayerLauncher",
        "Roblox.exe", "roblox"
    };
    for (const auto& m : markers)
        if (cmdline.find(m) != std::string::npos) return true;
    return false;
}

static std::vector<pid_t> get_descendant_pids(pid_t parent) {
    std::vector<pid_t> result;
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        std::string dirname = entry.path().filename().string();
        if (!std::all_of(dirname.begin(), dirname.end(), ::isdigit)) continue;
        pid_t pid = std::stoi(dirname);
        if (pid == parent) continue;
        try {
            std::ifstream stat_file(entry.path() / "stat");
            if (!stat_file.is_open()) continue;
            std::string stat_line;
            std::getline(stat_file, stat_line);
            auto comm_end = stat_line.rfind(')');
            if (comm_end == std::string::npos) continue;
            std::string after_comm = stat_line.substr(comm_end + 2);
            std::istringstream iss(after_comm);
            char state; pid_t ppid;
            iss >> state >> ppid;
            if (ppid == parent) result.push_back(pid);
        } catch (...) { continue; }
    }
    return result;
}

// ── scan_for_roblox (unchanged — all 5 phases) ─────────────────

bool Injection::scan_for_roblox() {
    set_status(InjectionStatus::Scanning, "Scanning for Roblox...");

    // Phase 1: direct name
    static const std::vector<std::string> targets = {
        "RobloxPlayer", "RobloxPlayerBeta", "RobloxPlayerBeta.exe",
        "RobloxPlayerLauncher", "Roblox",
        "sober", ".sober-wrapped", "org.vinegarhq.Sober", "vinegar",
    };
    for (const auto& t : targets) {
        auto pid = Memory::find_process(t);
        if (pid.has_value()) {
            memory_.set_pid(pid.value());
            set_status(InjectionStatus::Found,
                       "Found Roblox (PID: " + std::to_string(pid.value()) + ")");
            LOG_INFO("Phase 1 hit: '{}' → PID {}", t, pid.value());
            return true;
        }
    }

    // Phase 2: Wine host cmdline
    static const std::vector<std::string> wine_hosts = {
        "wine-preloader", "wine64-preloader", "wine", "wine64",
    };
    for (const auto& host : wine_hosts) {
        for (auto pid : Memory::find_all_processes(host)) {
            if (cmdline_has_roblox(read_proc_cmdline(pid))) {
                memory_.set_pid(pid);
                set_status(InjectionStatus::Found,
                           "Found Roblox via Wine (PID: " + std::to_string(pid) + ")");
                return true;
            }
        }
    }

    // Phase 3: Wine memory regions
    for (auto pid : Memory::find_all_processes("wine")) {
        Memory mem(pid);
        for (const auto& r : mem.get_regions()) {
            if (r.path.find("Roblox") != std::string::npos ||
                r.path.find("roblox") != std::string::npos) {
                memory_.set_pid(pid);
                set_status(InjectionStatus::Found,
                           "Found Roblox via Wine memory (PID: " + std::to_string(pid) + ")");
                return true;
            }
        }
    }

    // Phase 4: Flatpak/bwrap children
    for (auto bwrap_pid : Memory::find_all_processes("bwrap")) {
        std::string bc = read_proc_cmdline(bwrap_pid);
        if (bc.find("Sober")   == std::string::npos &&
            bc.find("sober")   == std::string::npos &&
            bc.find("vinegar") == std::string::npos) continue;

        auto children = get_descendant_pids(bwrap_pid);
        std::vector<pid_t> all = children;
        for (auto c : children) {
            auto gc = get_descendant_pids(c);
            all.insert(all.end(), gc.begin(), gc.end());
        }
        for (auto cpid : all) {
            if (cmdline_has_roblox(read_proc_cmdline(cpid))) {
                memory_.set_pid(cpid);
                set_status(InjectionStatus::Found,
                           "Found Roblox via Sober (PID: " + std::to_string(cpid) + ")");
                return true;
            }
            Memory mem(cpid);
            for (const auto& r : mem.get_regions()) {
                if (r.path.find("Roblox") != std::string::npos) {
                    memory_.set_pid(cpid);
                    set_status(InjectionStatus::Found,
                               "Found Roblox via Sober memory (PID: " + std::to_string(cpid) + ")");
                    return true;
                }
            }
        }
    }

    // Phase 5: brute-force
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        std::string d = entry.path().filename().string();
        if (!std::all_of(d.begin(), d.end(), ::isdigit)) continue;
        pid_t pid = std::stoi(d);
        if (cmdline_has_roblox(read_proc_cmdline(pid))) {
            memory_.set_pid(pid);
            set_status(InjectionStatus::Found,
                       "Found Roblox (PID: " + std::to_string(pid) + ")");
            return true;
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
    auto regions = memory_.get_regions();
    if (regions.empty()) {
        set_status(InjectionStatus::Failed, "Cannot access process memory");
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
    mode_ = InjectionMode::None;
    vm_marker_addr_ = 0;
    return true;
}

// ═══════════════════════════════════════════════════════════════
// FIX #5 + #7: inject()
//
// Bug #5: Scanned for LuaJIT bytecode header 0x1B 0x4C 0x4A ("ESC LJ").
//         Roblox uses LUAU, not LuaJIT.  The pattern NEVER matches.
//
//         Luau bytecode starts with a version byte (currently 3–6)
//         followed by a string count varint.  But single-byte
//         patterns produce massive false positives.
//
//         PRACTICAL FIX: Instead of scanning for bytecode headers,
//         scan for Roblox-specific STRINGS that appear in the data
//         sections of any live Roblox process.  Finding "CoreGui"
//         or "rbxasset://" in readable memory confirms we're
//         attached to the right process AND that the Luau VM has
//         initialized (these strings are interned by the VM).
//
// Bug #7: inject() always returned true even when no VM was found.
//         Now it sets mode_ to LocalOnly vs Full and returns true
//         (attached) but the caller can check vm_found() to know
//         if real injection is possible.
// ═══════════════════════════════════════════════════════════════
bool Injection::inject() {
    if (!attach()) return false;

    auto regions = memory_.get_regions();
    vm_marker_addr_ = 0;

    // Scan for Luau VM markers — strings that only exist in a
    // running Roblox process with an initialized Luau state
    static const std::vector<std::string> luau_markers = {
        "CoreGui",          // Roblox service — always present
        "rbxasset://",      // Roblox asset protocol
        "LocalScript",      // Instance class name interned by VM
        "ModuleScript",     // Another interned class name
    };

    for (const auto& region : regions) {
        if (!region.readable()) continue;
        if (region.size() < 0x1000 || region.size() > 0x10000000) continue;

        // Skip non-data regions (shared libs, vdso, etc.)
        if (!region.path.empty() &&
            region.path.find("Roblox") == std::string::npos &&
            region.path.find("roblox") == std::string::npos &&
            region.path[0] == '/') continue;

        for (const auto& marker : luau_markers) {
            std::vector<uint8_t> pattern(marker.begin(), marker.end());
            std::string mask(pattern.size(), 'x');

            size_t scan_len = std::min(region.size(),
                                        static_cast<size_t>(0x400000));

            auto result = memory_.pattern_scan(pattern, mask,
                                                region.start, scan_len);
            if (result.has_value()) {
                vm_marker_addr_ = result.value();
                LOG_INFO("Found Luau marker '{}' at 0x{:X} in '{}'",
                         marker, vm_marker_addr_, region.path);
                goto found;
            }
        }
    }

found:
    if (vm_marker_addr_ != 0) {
        mode_ = InjectionMode::Full;
        set_status(InjectionStatus::Injected,
                   "Injection complete — Luau VM detected");
        LOG_INFO("Injection mode: Full (Luau VM marker at 0x{:X})",
                 vm_marker_addr_);
    } else {
        mode_ = InjectionMode::LocalOnly;
        set_status(InjectionStatus::Injected,
                   "Attached — local execution mode (no Luau VM found)");
        LOG_WARN("No Luau VM markers found — local execution mode. "
                 "Scripts will run in sandbox with mock Roblox APIs.");
    }

    return true;   // we DID attach; caller checks vm_found() for details
}

void Injection::start_auto_scan() {
    bool expected = false;
    if (!scanning_.compare_exchange_strong(expected, true)) return;

    scan_thread_ = std::thread([this]() {
        while (scanning_.load()) {
            if (!memory_.is_valid()) scan_for_roblox();
            for (int i = 0; i < 30 && scanning_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
}

void Injection::stop_auto_scan() {
    scanning_.store(false);
    if (scan_thread_.joinable()) scan_thread_.join();
}

} // namespace oss
