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

// ── helpers ─────────────────────────────────────────────────────

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

// ── scan_for_roblox ─────────────────────────────────────────────

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
// ★ FIX: inject() — improved Luau VM detection
//
// BEFORE (3 problems):
//
//   1. Scan cap was 4MB per region (0x400000).
//      Roblox binary regions can be 50-200MB.
//      Markers beyond 4MB offset → never found.
//
//   2. Region filter skipped ALL file-backed regions
//      unless path contained "Roblox"/"roblox".
//      On Wine/Sober, Luau strings can be in heap or
//      in Wine PE loader regions (ntdll, kernelbase)
//      that don't have "Roblox" in the path.
//
//   3. Only 4 marker strings. Some are short ("CoreGui"
//      is 7 bytes) which could false-positive in non-
//      Roblox processes, but the real issue is that
//      they might all be in skipped regions.
//
// AFTER:
//   - Scan cap raised to 32MB per region
//   - Region filter now includes:
//     • All anonymous regions (heap, anonymous mmap)
//     • All regions with Roblox/roblox/Sober/sober in path
//     • All regions with Wine PE extensions (.exe, .dll)
//     • [heap], [stack] etc. (don't start with /)
//   - Added more marker strings
//   - Better logging for diagnosis
// ═══════════════════════════════════════════════════════════════
bool Injection::inject() {
    if (!attach()) return false;

    auto regions = memory_.get_regions();
    vm_marker_addr_ = 0;

    // Strings that only exist in a running Roblox process
    // with an initialized Luau state
    static const std::vector<std::string> luau_markers = {
        "CoreGui",
        "rbxasset://",
        "LocalScript",
        "ModuleScript",
        "RenderStepped",           // RunService signal
        "GetService",              // DataModel method name
        "HumanoidRootPart",        // common part name
        "PlayerAdded",             // Players signal
    };

    // ── Helper: should we scan this region? ──────────────
    auto should_scan_region = [](const MemoryRegion& region) -> bool {
        if (!region.readable()) return false;

        // Skip tiny or impossibly huge regions
        if (region.size() < 0x1000) return false;
        if (region.size() > 0x40000000) return false;  // >1GB, skip

        // Always scan anonymous regions (empty path) — heap, mmap
        if (region.path.empty()) return true;

        // Always scan special pseudo-paths: [heap], [stack], [anon:...]
        if (!region.path.empty() && region.path[0] == '[') return true;

        // Scan regions whose path contains Roblox-related strings
        static const std::vector<std::string> path_keywords = {
            "Roblox", "roblox", "ROBLOX",
            "Sober", "sober", "vinegar",
            ".exe", ".dll",             // Wine PE files
        };
        for (const auto& kw : path_keywords) {
            if (region.path.find(kw) != std::string::npos)
                return true;
        }

        // Skip other file-backed regions (libc, libm, vdso, etc.)
        // to avoid false positives and reduce scan time
        if (region.path[0] == '/') return false;

        // Anything else (shouldn't happen) — scan it
        return true;
    };

    size_t regions_scanned = 0;
    size_t bytes_scanned = 0;

    for (const auto& region : regions) {
        if (!should_scan_region(region)) continue;

        regions_scanned++;

        for (const auto& marker : luau_markers) {
            std::vector<uint8_t> pattern(marker.begin(), marker.end());
            std::string mask(pattern.size(), 'x');

            // ★ FIX: Raised from 4MB to 32MB — Roblox regions
            // can be very large, markers may be far into them
            size_t scan_len = std::min(region.size(),
                                        static_cast<size_t>(0x2000000));
            bytes_scanned += scan_len;

            auto result = memory_.pattern_scan(pattern, mask,
                                                region.start, scan_len);
                       if (result.has_value()) {
                vm_marker_addr_ = result.value();
                LOG_INFO("Found Luau marker '{}' at 0x{:X} in '{}' "
                         "(scanned {} regions, {:.1f}MB total)",
                         marker, vm_marker_addr_,
                         region.path.empty() ? "[anonymous]" : region.path,
                         regions_scanned,
                         bytes_scanned / (1024.0 * 1024.0));
                break;  // break inner loop
            }
        }
        if (vm_marker_addr_ != 0) break;  // break outer loop
    }

    // Remove the "found:" label entirely
    if (vm_marker_addr_ != 0) {
        mode_ = InjectionMode::Full;
        set_status(InjectionStatus::Injected,
                   "Injection complete — Luau VM detected");
        LOG_INFO("Injection mode: Full (Luau VM marker at 0x{:X})",
                 vm_marker_addr_);
    } else {
        mode_ = InjectionMode::LocalOnly;
        set_status(InjectionStatus::Injected,
                   "Attached — local execution mode "
                   "(Luau VM not located, scripts run in sandbox)");
        LOG_WARN("No Luau VM markers found in {} regions ({:.1f}MB scanned). "
                 "Possible causes:\n"
                 "  • Roblox hasn't fully loaded yet (try again in a few seconds)\n"
                 "  • /proc/{}/mem is not readable (check ptrace_scope)\n"
                 "  • Process is a launcher, not the game client\n"
                 "Scripts will run in sandbox with mock Roblox APIs.",
                 regions_scanned,
                 bytes_scanned / (1024.0 * 1024.0),
                 memory_.get_pid());
    }

    return true;
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

