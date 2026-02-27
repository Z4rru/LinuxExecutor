#include "injection.hpp"
#include "utils/logger.hpp"
#include <chrono>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <string>
#include <sstream>
#include <cctype>
#include <cstring>
#include <csignal>
#include <unistd.h>

namespace fs = std::filesystem;

namespace oss {

static constexpr size_t REGION_SCAN_CAP = 0x4000000;
static constexpr size_t REGION_MIN      = 0x1000;
static constexpr size_t REGION_MAX      = 0x80000000ULL;
static constexpr int    AUTOSCAN_TICKS  = 30;
static constexpr int    TICK_MS         = 100;

static const std::string DIRECT_TARGETS[] = {
    "RobloxPlayer", "RobloxPlayerBeta", "RobloxPlayerBeta.exe",
    "RobloxPlayerLauncher", "Roblox",
    "sober", ".sober-wrapped", "org.vinegarhq.Sober", "vinegar"
};

static const std::string WINE_HOSTS[] = {
    "wine-preloader", "wine64-preloader", "wine", "wine64"
};

static const std::string ROBLOX_TOKENS[] = {
    "RobloxPlayer", "RobloxPlayerBeta", "RobloxPlayerLauncher",
    "Roblox.exe", "roblox"
};

static const std::string PRIMARY_MARKERS[] = {
    "rbxasset://",
    "CoreGui",
    "LocalScript",
    "ModuleScript",
    "RenderStepped",
    "GetService",
    "HumanoidRootPart",
    "PlayerAdded",
    "StarterGui",
    "ReplicatedStorage",
    "TweenService",
    "UserInputService"
};

static const std::string SECONDARY_MARKERS[] = {
    "Instance", "workspace", "Enum", "Vector3", "CFrame",
    "game", "Players", "Lighting"
};

static const std::string PATH_KEYWORDS[] = {
    "Roblox", "roblox", "ROBLOX",
    "Sober", "sober", "vinegar",
    ".exe", ".dll", "wine"
};

std::string Injection::read_proc_cmdline(pid_t pid) {
    try {
        std::ifstream f("/proc/" + std::to_string(pid) + "/cmdline",
                        std::ios::binary);
        if (!f.is_open()) return {};
        std::string raw((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        std::replace(raw.begin(), raw.end(), '\0', ' ');
        while (!raw.empty() && raw.back() == ' ') raw.pop_back();
        return raw;
    } catch (...) { return {}; }
}

std::string Injection::read_proc_comm(pid_t pid) {
    try {
        std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
        if (!f.is_open()) return {};
        std::string s;
        std::getline(f, s);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
            s.pop_back();
        return s;
    } catch (...) { return {}; }
}

std::string Injection::read_proc_exe(pid_t pid) {
    try {
        return fs::read_symlink("/proc/" + std::to_string(pid) + "/exe").string();
    } catch (...) { return {}; }
}

bool Injection::has_roblox_token(const std::string& s) {
    for (const auto& t : ROBLOX_TOKENS)
        if (s.find(t) != std::string::npos) return true;
    return false;
}

std::vector<pid_t> Injection::descendants(pid_t root) {
    std::vector<pid_t> all;
    std::vector<pid_t> frontier;

    try {
        for (const auto& entry : fs::directory_iterator("/proc")) {
            if (!entry.is_directory()) continue;
            std::string dn = entry.path().filename().string();
            if (!std::all_of(dn.begin(), dn.end(), ::isdigit)) continue;
            pid_t pid = std::stoi(dn);
            if (pid == root) continue;
            try {
                std::ifstream sf(entry.path() / "stat");
                if (!sf.is_open()) continue;
                std::string line;
                std::getline(sf, line);
                auto ce = line.rfind(')');
                if (ce == std::string::npos) continue;
                std::istringstream iss(line.substr(ce + 2));
                char state; pid_t ppid;
                iss >> state >> ppid;
                if (ppid == root) frontier.push_back(pid);
            } catch (...) {}
        }
    } catch (...) {}

    while (!frontier.empty()) {
        std::vector<pid_t> next;
        for (auto p : frontier) {
            all.push_back(p);
            try {
                for (const auto& entry : fs::directory_iterator("/proc")) {
                    if (!entry.is_directory()) continue;
                    std::string dn = entry.path().filename().string();
                    if (!std::all_of(dn.begin(), dn.end(), ::isdigit)) continue;
                    pid_t pid = std::stoi(dn);
                    try {
                        std::ifstream sf(entry.path() / "stat");
                        if (!sf.is_open()) continue;
                        std::string line;
                        std::getline(sf, line);
                        auto ce = line.rfind(')');
                        if (ce == std::string::npos) continue;
                        std::istringstream iss(line.substr(ce + 2));
                        char state; pid_t ppid;
                        iss >> state >> ppid;
                        if (ppid == p) next.push_back(pid);
                    } catch (...) {}
                }
            } catch (...) {}
        }
        frontier = std::move(next);
    }
    return all;
}

ProcessInfo Injection::gather_info(pid_t pid) {
    ProcessInfo info;
    info.pid      = pid;
    info.name     = read_proc_comm(pid);
    info.cmdline  = read_proc_cmdline(pid);
    info.exe_path = read_proc_exe(pid);

    try {
        std::ifstream sf("/proc/" + std::to_string(pid) + "/stat");
        std::string line;
        std::getline(sf, line);
        auto ce = line.rfind(')');
        if (ce != std::string::npos) {
            std::istringstream iss(line.substr(ce + 2));
            char state;
            iss >> state >> info.parent_pid;
        }
    } catch (...) {}

    auto contains = [](const std::string& hay, const std::string& needle) {
        return hay.find(needle) != std::string::npos;
    };

    info.via_wine    = contains(info.exe_path, "wine") ||
                       contains(info.name, "wine");
    info.via_sober   = contains(info.cmdline, "sober") ||
                       contains(info.cmdline, "Sober");
    info.via_flatpak = contains(info.cmdline, "flatpak") ||
                       contains(info.exe_path, "flatpak");

    return info;
}

bool Injection::process_alive() const {
    pid_t p = memory_.get_pid();
    return p > 0 && kill(p, 0) == 0;
}

bool Injection::is_attached() const {
    return memory_.is_valid() &&
           status_ == InjectionStatus::Injected &&
           process_alive();
}

void Injection::set_status_callback(StatusCallback cb) {
    std::lock_guard<std::mutex> lk(mtx_);
    status_cb_ = std::move(cb);
}

void Injection::set_status(InjectionStatus s, const std::string& msg) {
    status_ = s;
    StatusCallback cb;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        cb = status_cb_;
    }
    if (cb) cb(s, msg);
    LOG_INFO("[injection] {}", msg);
}

void Injection::adopt_target(pid_t pid, const std::string& via) {
    memory_.set_pid(pid);
    proc_info_ = gather_info(pid);
    set_status(InjectionStatus::Found,
               "Found Roblox " + via + " (PID " + std::to_string(pid) + ")");
    LOG_INFO("Target: PID {} name='{}' exe='{}' wine={} sober={} flatpak={}",
             pid, proc_info_.name, proc_info_.exe_path,
             proc_info_.via_wine, proc_info_.via_sober, proc_info_.via_flatpak);
}

bool Injection::scan_direct() {
    for (const auto& t : DIRECT_TARGETS) {
        auto pid = Memory::find_process(t);
        if (pid.has_value()) {
            adopt_target(pid.value(), "direct '" + t + "'");
            return true;
        }
    }
    return false;
}

bool Injection::scan_wine_cmdline() {
    for (const auto& h : WINE_HOSTS) {
        for (auto pid : Memory::find_all_processes(h)) {
            if (has_roblox_token(read_proc_cmdline(pid))) {
                adopt_target(pid, "via Wine cmdline");
                proc_info_.via_wine = true;
                return true;
            }
        }
    }
    return false;
}

bool Injection::scan_wine_regions() {
    for (const auto& h : WINE_HOSTS) {
        for (auto pid : Memory::find_all_processes(h)) {
            Memory mem(pid);
            for (const auto& r : mem.get_regions()) {
                std::string lp = r.path;
                std::transform(lp.begin(), lp.end(), lp.begin(), ::tolower);
                if (lp.find("roblox") != std::string::npos) {
                    adopt_target(pid, "via Wine memory region");
                    proc_info_.via_wine = true;
                    return true;
                }
            }
        }
    }
    return false;
}

bool Injection::scan_flatpak() {
    for (auto bpid : Memory::find_all_processes("bwrap")) {
        std::string bc = read_proc_cmdline(bpid);
        std::string bl = bc;
        std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);
        if (bl.find("sober") == std::string::npos &&
            bl.find("vinegar") == std::string::npos) continue;

        for (auto cpid : descendants(bpid)) {
            if (has_roblox_token(read_proc_cmdline(cpid))) {
                adopt_target(cpid, "via Sober/Flatpak cmdline");
                proc_info_.via_sober = true;
                proc_info_.via_flatpak = true;
                return true;
            }
        }

        for (auto cpid : descendants(bpid)) {
            Memory mem(cpid);
            for (const auto& r : mem.get_regions()) {
                std::string lp = r.path;
                std::transform(lp.begin(), lp.end(), lp.begin(), ::tolower);
                if (lp.find("roblox") != std::string::npos) {
                    adopt_target(cpid, "via Sober/Flatpak memory");
                    proc_info_.via_sober = true;
                    proc_info_.via_flatpak = true;
                    return true;
                }
            }
        }
    }
    return false;
}

bool Injection::scan_brute() {
    try {
        for (const auto& entry : fs::directory_iterator("/proc")) {
            if (!entry.is_directory()) continue;
            std::string d = entry.path().filename().string();
            if (!std::all_of(d.begin(), d.end(), ::isdigit)) continue;
            pid_t pid = std::stoi(d);
            if (pid <= 1) continue;
            if (has_roblox_token(read_proc_cmdline(pid))) {
                adopt_target(pid, "via brute scan");
                return true;
            }
        }
    } catch (...) {}
    return false;
}

bool Injection::scan_for_roblox() {
    set_status(InjectionStatus::Scanning, "Scanning for Roblox...");
    if (scan_direct())        return true;
    if (scan_wine_cmdline())  return true;
    if (scan_wine_regions())  return true;
    if (scan_flatpak())       return true;
    if (scan_brute())         return true;
    set_status(InjectionStatus::Idle, "Roblox not found");
    return false;
}

bool Injection::should_scan_region(const MemoryRegion& r) const {
    if (!r.readable()) return false;
    if (r.size() < REGION_MIN || r.size() > REGION_MAX) return false;

    if (r.path.empty()) return true;

    if (r.path[0] == '[') return true;

    for (const auto& kw : PATH_KEYWORDS)
        if (r.path.find(kw) != std::string::npos) return true;

    if (r.path[0] == '/' && r.path.find("/lib") != std::string::npos)
        return false;

    return r.path[0] != '/';
}

bool Injection::cross_validate(uintptr_t rstart, size_t rsize) {
    size_t check = std::min(rsize, static_cast<size_t>(0x200000));
    for (const auto& sec : SECONDARY_MARKERS) {
        std::vector<uint8_t> pat(sec.begin(), sec.end());
        std::string mask(pat.size(), 'x');
        auto hit = memory_.pattern_scan(pat, mask, rstart, check);
        if (hit.has_value()) return true;
    }
    return false;
}

bool Injection::locate_luau_vm() {
    auto regions = memory_.get_regions();
    vm_scan_ = {};
    vm_marker_addr_ = 0;

    uintptr_t best_addr = 0;
    std::string best_marker;
    std::string best_path;
    uintptr_t best_base = 0;

    for (const auto& region : regions) {
        if (!should_scan_region(region)) continue;
        vm_scan_.regions_scanned++;

        for (const auto& marker : PRIMARY_MARKERS) {
            std::vector<uint8_t> pattern(marker.begin(), marker.end());
            std::string mask(pattern.size(), 'x');
            size_t scan_len = std::min(region.size(), REGION_SCAN_CAP);
            vm_scan_.bytes_scanned += scan_len;

            auto result = memory_.pattern_scan(pattern, mask,
                                                region.start, scan_len);
            if (!result.has_value()) continue;

            bool valid = cross_validate(region.start, region.size());

            if (valid) {
                vm_scan_.marker_addr  = result.value();
                vm_scan_.region_base  = region.start;
                vm_scan_.marker_name  = marker;
                vm_scan_.region_path  = region.path.empty() ? "[anon]" : region.path;
                vm_scan_.validated    = true;
                vm_marker_addr_       = result.value();

                LOG_INFO("Luau VM confirmed: '{}' at 0x{:X} in '{}' "
                         "({} regions, {:.1f}MB scanned)",
                         marker, vm_scan_.marker_addr, vm_scan_.region_path,
                         vm_scan_.regions_scanned,
                         vm_scan_.bytes_scanned / (1024.0 * 1024.0));
                return true;
            }

            if (best_addr == 0) {
                best_addr   = result.value();
                best_marker = marker;
                best_path   = region.path.empty() ? "[anon]" : region.path;
                best_base   = region.start;
            }
        }
    }

    if (best_addr != 0) {
        vm_scan_.marker_addr = best_addr;
        vm_scan_.region_base = best_base;
        vm_scan_.marker_name = best_marker;
        vm_scan_.region_path = best_path;
        vm_scan_.validated   = false;
        vm_marker_addr_      = best_addr;

        LOG_WARN("Luau VM probable (unvalidated): '{}' at 0x{:X} in '{}'",
                 best_marker, best_addr, best_path);
        return true;
    }

    return false;
}

bool Injection::attach() {
    if (memory_.is_valid() && process_alive()) {
        auto regions = memory_.get_regions();
        if (!regions.empty()) return true;
    }

    if (!scan_for_roblox()) return false;

    set_status(InjectionStatus::Attaching,
               "Attaching to PID " + std::to_string(memory_.get_pid()) + "...");

    auto regions = memory_.get_regions();
    if (regions.empty()) {
        set_status(InjectionStatus::Failed,
                   "Cannot read process memory — check ptrace_scope");
        LOG_ERROR("0 readable regions for PID {}. "
                  "Run: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope",
                  memory_.get_pid());
        return false;
    }

    size_t nr = 0, nw = 0, nx = 0, total = 0;
    for (const auto& r : regions) {
        if (r.readable())   nr++;
        if (r.writable())   nw++;
        if (r.executable()) nx++;
        total += r.size();
    }

    LOG_INFO("Attached: PID {} | {} regions ({}R {}W {}X) | {:.1f}MB",
             memory_.get_pid(), regions.size(), nr, nw, nx,
             total / (1024.0 * 1024.0));

    set_status(InjectionStatus::Injected, "Attached to process");
    return true;
}

bool Injection::detach() {
    set_status(InjectionStatus::Detached, "Detached");
    memory_.set_pid(0);
    mode_           = InjectionMode::None;
    vm_marker_addr_ = 0;
    vm_scan_        = {};
    proc_info_      = {};
    return true;
}

bool Injection::inject() {
    if (!attach()) return false;

    if (!process_alive()) {
        set_status(InjectionStatus::Failed, "Process died during injection");
        memory_.set_pid(0);
        return false;
    }

    bool found = locate_luau_vm();

    if (found) {
        mode_ = InjectionMode::Full;

        std::ostringstream hex;
        hex << std::hex << vm_scan_.marker_addr;

        set_status(InjectionStatus::Injected,
                   "Injection complete — Luau VM at 0x" + hex.str());

        LOG_INFO("Mode: Full | marker='{}' @ 0x{:X} | validated={} | "
                 "region='{}' base=0x{:X}",
                 vm_scan_.marker_name, vm_scan_.marker_addr,
                 vm_scan_.validated,
                 vm_scan_.region_path, vm_scan_.region_base);
    } else {
        mode_ = InjectionMode::LocalOnly;
        set_status(InjectionStatus::Injected,
                   "Attached — local execution mode (Luau VM not located)");
        LOG_WARN("No Luau markers in {} regions ({:.1f}MB). "
                 "Game may not be fully loaded. PID: {}",
                 vm_scan_.regions_scanned,
                 vm_scan_.bytes_scanned / (1024.0 * 1024.0),
                 memory_.get_pid());
    }

    return true;
}

bool Injection::execute_script(const std::string& source) {
    if (status_ != InjectionStatus::Injected) {
        LOG_ERROR("execute_script: not injected");
        return false;
    }

    if (!process_alive()) {
        set_status(InjectionStatus::Failed, "Target process exited");
        mode_ = InjectionMode::None;
        memory_.set_pid(0);
        return false;
    }

    set_status(InjectionStatus::Executing,
               "Executing (" + std::to_string(source.size()) + " bytes)...");

    if (mode_ == InjectionMode::Full && vm_marker_addr_ != 0) {
        auto regions = memory_.get_regions();

        uintptr_t write_addr = 0;
        for (const auto& r : regions) {
            if (!r.writable() || !r.readable()) continue;
            if (!r.path.empty() && r.path[0] == '/') continue;
            if (r.size() >= source.size() + 64) {
                write_addr = r.start;
                break;
            }
        }

        if (write_addr != 0) {
            std::vector<uint8_t> payload;
            uint32_t len = static_cast<uint32_t>(source.size());
            payload.resize(4 + source.size());
            std::memcpy(payload.data(), &len, 4);
            std::memcpy(payload.data() + 4, source.data(), source.size());

            bool wrote = memory_.write_buffer(write_addr, payload.data(),
                                               payload.size());
            if (wrote) {
                set_status(InjectionStatus::Injected, "Script dispatched");
                LOG_INFO("Wrote {} bytes to 0x{:X}", payload.size(), write_addr);
                return true;
            }

            LOG_WARN("Memory write failed at 0x{:X}, falling back", write_addr);
        }
    }

    set_status(InjectionStatus::Injected, "Script queued for local execution");
    return true;
}

void Injection::start_auto_scan() {
    bool expected = false;
    if (!scanning_.compare_exchange_strong(expected, true)) return;

    scan_thread_ = std::thread([this]() {
        LOG_INFO("Auto-scan started");
        while (scanning_.load()) {
            if (memory_.is_valid() && !process_alive()) {
                LOG_WARN("Target process exited, resetting");
                mode_           = InjectionMode::None;
                vm_marker_addr_ = 0;
                vm_scan_        = {};
                proc_info_      = {};
                memory_.set_pid(0);
                set_status(InjectionStatus::Idle, "Process exited — rescanning...");
            }

            if (!memory_.is_valid()) scan_for_roblox();

            for (int i = 0; i < AUTOSCAN_TICKS && scanning_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(TICK_MS));
        }
        LOG_INFO("Auto-scan stopped");
    });
}

void Injection::stop_auto_scan() {
    scanning_.store(false);
    if (scan_thread_.joinable()) scan_thread_.join();
}

} // namespace oss
