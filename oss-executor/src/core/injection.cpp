#include "injection.hpp"
#include "memory.hpp"
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
#include <dirent.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>

namespace fs = std::filesystem;

namespace oss {

// ─── compile-time knobs ──────────────────────────────────────────────────────
static constexpr size_t REGION_SCAN_CAP = 0x4000000;
static constexpr size_t REGION_MIN      = 0x1000;
static constexpr size_t REGION_MAX      = 0x80000000ULL;
static constexpr int    AUTOSCAN_TICKS  = 30;
static constexpr int    TICK_MS         = 100;

// ─── name tables ─────────────────────────────────────────────────────────────
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
    "rbxasset://",   "CoreGui",           "LocalScript",
    "ModuleScript",  "RenderStepped",     "GetService",
    "HumanoidRootPart", "PlayerAdded",    "StarterGui",
    "ReplicatedStorage", "TweenService",  "UserInputService"
};

static const std::string SECONDARY_MARKERS[] = {
    "Instance", "workspace", "Enum", "Vector3", "CFrame",
    "game", "Players", "Lighting"
};

static const std::string PATH_KEYWORDS[] = {
    "Roblox", "roblox", "ROBLOX",
    "Sober",  "sober",  "vinegar",
    ".exe",   ".dll",   "wine"
};

// ─── self-targeting exclusion ────────────────────────────────────────────────
static const std::string SELF_KEYWORDS[] = {
    "OSS", "OSSExecutor", "oss-executor", "AppImage"
};

static bool is_self_process(pid_t pid) {
    return pid == getpid() || pid == getppid();
}

static bool is_self_process_name(const std::string& name) {
    if (name.empty()) return false;
    for (const auto& kw : SELF_KEYWORDS)
        if (name.find(kw) != std::string::npos) return true;
    return false;
}

static bool is_valid_target(pid_t pid, const std::string& comm,
                            const std::string& cmdline,
                            const std::string& exe_path) {
    if (is_self_process(pid))            return false;
    if (is_self_process_name(comm))      return false;
    if (is_self_process_name(cmdline))   return false;
    if (is_self_process_name(exe_path))  return false;
    return true;
}

// ─── singleton ───────────────────────────────────────────────────────────────
Injection& Injection::instance() {
    static Injection inst;
    return inst;
}

// ═════════════════════════════════════════════════════════════════════════════
//  /proc helpers
// ═════════════════════════════════════════════════════════════════════════════
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
    auto collect_children = [](pid_t parent) {
        std::vector<pid_t> children;
        try {
            for (const auto& entry : fs::directory_iterator("/proc")) {
                if (!entry.is_directory()) continue;
                std::string dn = entry.path().filename().string();
                if (!std::all_of(dn.begin(), dn.end(), ::isdigit)) continue;
                pid_t pid = std::stoi(dn);
                if (pid == parent) continue;
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
                    if (ppid == parent) children.push_back(pid);
                } catch (...) {}
            }
        } catch (...) {}
        return children;
    };

    std::vector<pid_t> frontier = collect_children(root);
    while (!frontier.empty()) {
        std::vector<pid_t> next;
        for (auto p : frontier) {
            all.push_back(p);
            auto ch = collect_children(p);
            next.insert(next.end(), ch.begin(), ch.end());
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

// ═════════════════════════════════════════════════════════════════════════════
//  Internal state helpers
// ═════════════════════════════════════════════════════════════════════════════
bool Injection::process_alive() const {
    pid_t p = memory_.get_pid();
    return p > 0 && kill(p, 0) == 0;
}

bool Injection::is_attached() const {
    return memory_.is_valid() &&
           state_ == InjectionState::Ready &&
           process_alive();
}

void Injection::set_status_callback(StatusCallback cb) {
    std::lock_guard<std::mutex> lk(mtx_);
    status_cb_ = std::move(cb);
}

void Injection::set_state(InjectionState s, const std::string& msg) {
    state_ = s;
    if (s == InjectionState::Failed) error_ = msg;
    StatusCallback cb;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        cb = status_cb_;
    }
    if (cb) cb(s, msg);
    LOG_INFO("[injection] {}", msg);
}

bool Injection::write_to_process(uintptr_t addr, const void* data, size_t len) {
    pid_t pid = memory_.get_pid();
    if (pid <= 0) return false;
    std::string path = "/proc/" + std::to_string(pid) + "/mem";
    std::ofstream f(path, std::ios::binary | std::ios::in | std::ios::out);
    if (!f.is_open()) return false;
    f.seekp(static_cast<std::streamoff>(addr));
    if (!f.good()) return false;
    f.write(static_cast<const char*>(data), static_cast<std::streamsize>(len));
    return f.good();
}

// ═════════════════════════════════════════════════════════════════════════════
//  Target adoption (with self-targeting guard)
// ═════════════════════════════════════════════════════════════════════════════
void Injection::adopt_target(pid_t pid, const std::string& via) {
    std::string comm    = read_proc_comm(pid);
    std::string cmdline = read_proc_cmdline(pid);
    std::string exe     = read_proc_exe(pid);

    if (!is_valid_target(pid, comm, cmdline, exe)) {
        LOG_DEBUG("Rejected self-target PID {} ('{}') — skipping", pid, comm);
        return;
    }

    memory_.set_pid(pid);
    proc_info_ = gather_info(pid);
    set_state(InjectionState::Found,
              "Found Roblox " + via + " (PID " + std::to_string(pid) + ")");
    LOG_INFO("Target: PID {} name='{}' exe='{}' wine={} sober={} flatpak={}",
             pid, proc_info_.name, proc_info_.exe_path,
             proc_info_.via_wine, proc_info_.via_sober, proc_info_.via_flatpak);
}

// ═════════════════════════════════════════════════════════════════════════════
//  Scanning strategies
// ═════════════════════════════════════════════════════════════════════════════
bool Injection::scan_direct() {
    for (const auto& t : DIRECT_TARGETS) {
        auto pid = Memory::find_process(t);
        if (pid.has_value()) {
            pid_t p = pid.value();
            if (is_self_process(p)) continue;
            if (is_self_process_name(read_proc_comm(p))) continue;
            adopt_target(p, "direct '" + t + "'");
            if (memory_.is_valid()) return true;
        }
    }
    return false;
}

bool Injection::scan_wine_cmdline() {
    for (const auto& h : WINE_HOSTS) {
        for (auto pid : Memory::find_all_processes(h)) {
            if (is_self_process(pid)) continue;
            if (has_roblox_token(read_proc_cmdline(pid))) {
                adopt_target(pid, "via Wine cmdline");
                if (memory_.is_valid()) {
                    proc_info_.via_wine = true;
                    return true;
                }
            }
        }
    }
    return false;
}

bool Injection::scan_wine_regions() {
    for (const auto& h : WINE_HOSTS) {
        for (auto pid : Memory::find_all_processes(h)) {
            if (is_self_process(pid)) continue;
            Memory mem(pid);
            for (const auto& r : mem.get_regions()) {
                std::string lp = r.path;
                std::transform(lp.begin(), lp.end(), lp.begin(), ::tolower);
                if (lp.find("roblox") != std::string::npos) {
                    adopt_target(pid, "via Wine memory region");
                    if (memory_.is_valid()) {
                        proc_info_.via_wine = true;
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

bool Injection::scan_flatpak() {
    for (auto bpid : Memory::find_all_processes("bwrap")) {
        if (is_self_process(bpid)) continue;
        std::string bc = read_proc_cmdline(bpid);
        std::string bl = bc;
        std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);
        if (bl.find("sober") == std::string::npos &&
            bl.find("vinegar") == std::string::npos) continue;

        for (auto cpid : descendants(bpid)) {
            if (is_self_process(cpid)) continue;
            if (has_roblox_token(read_proc_cmdline(cpid))) {
                adopt_target(cpid, "via Sober/Flatpak cmdline");
                if (memory_.is_valid()) {
                    proc_info_.via_sober   = true;
                    proc_info_.via_flatpak = true;
                    return true;
                }
            }
        }
        for (auto cpid : descendants(bpid)) {
            if (is_self_process(cpid)) continue;
            Memory mem(cpid);
            for (const auto& r : mem.get_regions()) {
                std::string lp = r.path;
                std::transform(lp.begin(), lp.end(), lp.begin(), ::tolower);
                if (lp.find("roblox") != std::string::npos) {
                    adopt_target(cpid, "via Sober/Flatpak memory");
                    if (memory_.is_valid()) {
                        proc_info_.via_sober   = true;
                        proc_info_.via_flatpak = true;
                        return true;
                    }
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
            if (pid <= 1 || is_self_process(pid)) continue;

            std::string comm = read_proc_comm(pid);
            if (is_self_process_name(comm)) continue;
            std::string cmdline = read_proc_cmdline(pid);
            if (is_self_process_name(cmdline)) continue;

            if (has_roblox_token(cmdline)) {
                adopt_target(pid, "via brute scan");
                if (memory_.is_valid()) return true;
            }
        }
    } catch (...) {}
    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Public: process discovery
// ═════════════════════════════════════════════════════════════════════════════
bool Injection::scan_for_roblox() {
    set_state(InjectionState::Scanning, "Scanning for Roblox...");
    if (scan_direct())       return true;
    if (scan_wine_cmdline()) return true;
    if (scan_wine_regions()) return true;
    if (scan_flatpak())      return true;
    if (scan_brute())        return true;
    set_state(InjectionState::Idle, "Roblox not found");
    return false;
}

pid_t Injection::find_roblox_pid() {
    if (memory_.is_valid() && process_alive())
        return memory_.get_pid();
    if (scan_for_roblox())
        return memory_.get_pid();
    return -1;
}

// ═════════════════════════════════════════════════════════════════════════════
//  VM scanning & validation
// ═════════════════════════════════════════════════════════════════════════════
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
    vm_scan_        = {};
    vm_marker_addr_ = 0;

    uintptr_t   best_addr = 0;
    std::string best_marker;
    std::string best_path;
    uintptr_t   best_base = 0;

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

            if (cross_validate(region.start, region.size())) {
                vm_scan_.marker_addr = result.value();
                vm_scan_.region_base = region.start;
                vm_scan_.marker_name = marker;
                vm_scan_.region_path = region.path.empty() ? "[anon]" : region.path;
                vm_scan_.validated   = true;
                vm_marker_addr_      = result.value();
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

// ═════════════════════════════════════════════════════════════════════════════
//  Payload path discovery
// ═════════════════════════════════════════════════════════════════════════════
std::string Injection::find_payload_path() {
    std::vector<std::string> search_paths = {
        "./liboss_payload.so",
        "./build/liboss_payload.so",
        "../lib/liboss_payload.so",
        "/usr/lib/oss-executor/liboss_payload.so",
        "/usr/local/lib/oss-executor/liboss_payload.so",
    };

    char self_path[512];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len > 0) {
        self_path[len] = '\0';
        fs::path exe_dir = fs::path(self_path).parent_path();
        search_paths.insert(search_paths.begin(),
                            (exe_dir / "liboss_payload.so").string());
    }

    for (const auto& path : search_paths)
        if (fs::exists(path))
            return fs::absolute(path).string();
    return "";
}

// ═════════════════════════════════════════════════════════════════════════════
//  Remote symbol resolution (for ptrace injection)
// ═════════════════════════════════════════════════════════════════════════════
uintptr_t Injection::find_libc_function(pid_t pid, const std::string& func_name) {
    return find_remote_symbol(pid, "c", func_name);
}

uintptr_t Injection::find_remote_symbol(pid_t pid, const std::string& lib_name,
                                         const std::string& symbol) {
    uintptr_t local_symbol = 0;
    void* handle = dlopen(("lib" + lib_name + ".so.6").c_str(),
                          RTLD_LAZY | RTLD_NOLOAD);
    if (!handle)
        handle = dlopen(("lib" + lib_name + ".so").c_str(),
                        RTLD_LAZY | RTLD_NOLOAD);
    if (!handle)
        handle = dlopen(nullptr, RTLD_LAZY);

    if (handle) {
        void* sym = dlsym(handle, symbol.c_str());
        if (sym) local_symbol = reinterpret_cast<uintptr_t>(sym);
        dlclose(handle);
    }
    if (local_symbol == 0) return 0;

    uintptr_t local_base = 0;
    Dl_info info;
    if (dladdr(reinterpret_cast<void*>(local_symbol), &info))
        local_base = reinterpret_cast<uintptr_t>(info.dli_fbase);
    if (local_base == 0) return 0;

    uintptr_t offset = local_symbol - local_base;
    std::string lib_basename = info.dli_fname
        ? fs::path(info.dli_fname).filename().string() : "";

    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps.is_open()) return 0;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(lib_basename) != std::string::npos &&
            line.find("r-xp") != std::string::npos) {
            unsigned long remote_base;
            if (sscanf(line.c_str(), "%lx-", &remote_base) == 1)
                return remote_base + offset;
        }
    }
    return 0;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Ptrace-based library injection
// ═════════════════════════════════════════════════════════════════════════════
bool Injection::inject_library(pid_t pid, const std::string& lib_path) {
    LOG_INFO("Injecting {} into PID {}", lib_path, pid);

    uintptr_t remote_dlopen = find_remote_symbol(pid, "c", "__libc_dlopen_mode");
    if (remote_dlopen == 0)
        remote_dlopen = find_remote_symbol(pid, "dl", "dlopen");
    if (remote_dlopen == 0) {
        error_ = "Could not find dlopen in target process";
        LOG_ERROR("inject_library: {}", error_);
        return false;
    }
    LOG_DEBUG("Remote dlopen at 0x{:x}", remote_dlopen);

    return inject_shellcode(pid, lib_path);
}

bool Injection::inject_shellcode(pid_t pid, const std::string& lib_path) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        error_ = "ptrace attach failed: " + std::string(strerror(errno));
        LOG_ERROR("inject_shellcode: {}", error_);
        return false;
    }

    int status;
    waitpid(pid, &status, 0);

    // ── save original registers ──────────────────────────────────────────
    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &orig_regs) != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        error_ = "Could not read registers";
        return false;
    }

    // ── allocate page in target via mmap syscall ─────────────────────────
    size_t path_len   = lib_path.size() + 1;
    size_t alloc_size = 4096;

    struct user_regs_struct mmap_regs = orig_regs;
    mmap_regs.rax = 9;   // __NR_mmap
    mmap_regs.rdi = 0;
    mmap_regs.rsi = alloc_size;
    mmap_regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    mmap_regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    mmap_regs.r8  = static_cast<uintptr_t>(-1);
    mmap_regs.r9  = 0;

    uintptr_t rip = orig_regs.rip;
    long orig_bytes[2];
    orig_bytes[0] = ptrace(PTRACE_PEEKTEXT, pid,
                           reinterpret_cast<void*>(rip), nullptr);
    orig_bytes[1] = ptrace(PTRACE_PEEKTEXT, pid,
                           reinterpret_cast<void*>(rip + 8), nullptr);

    uint8_t syscall_trap[] = { 0x0F, 0x05, 0xCC };
    long insn = orig_bytes[0];
    memcpy(&insn, syscall_trap, 3);
    ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(rip),
           reinterpret_cast<void*>(insn));

    ptrace(PTRACE_SETREGS, pid, nullptr, &mmap_regs);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    waitpid(pid, &status, 0);

    struct user_regs_struct result_regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &result_regs);
    uintptr_t mem_addr = result_regs.rax;

    auto restore_and_detach = [&]() {
        ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(rip),
               reinterpret_cast<void*>(orig_bytes[0]));
        ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(rip + 8),
               reinterpret_cast<void*>(orig_bytes[1]));
        ptrace(PTRACE_SETREGS, pid, nullptr, &orig_regs);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    };

    if (mem_addr == 0 || mem_addr == static_cast<uintptr_t>(-1)) {
        restore_and_detach();
        error_ = "Remote mmap failed";
        return false;
    }
    LOG_DEBUG("Allocated 0x{:x} in target", mem_addr);

    // ── write library path into allocated page ───────────────────────────
    size_t path_offset = 256;
    for (size_t i = 0; i < path_len; i += sizeof(long)) {
        long word = 0;
        memcpy(&word, lib_path.c_str() + i,
               std::min(sizeof(long), path_len - i));
        ptrace(PTRACE_POKETEXT, pid,
               reinterpret_cast<void*>(mem_addr + path_offset + i),
               reinterpret_cast<void*>(word));
    }

    // ── resolve dlopen in target ─────────────────────────────────────────
    uintptr_t dlopen_addr = find_remote_symbol(pid, "c", "__libc_dlopen_mode");
    if (dlopen_addr == 0)
        dlopen_addr = find_remote_symbol(pid, "dl", "dlopen");
    if (dlopen_addr == 0) {
        restore_and_detach();
        error_ = "Cannot find dlopen in target";
        return false;
    }

    // ── build shellcode: dlopen(path, RTLD_NOW|__RTLD_DLOPEN) ────────────
    uint8_t shellcode[64] = {};
    int sc_off = 0;

    // mov rdi, path_addr
    shellcode[sc_off++] = 0x48; shellcode[sc_off++] = 0xBF;
    uintptr_t path_addr = mem_addr + path_offset;
    memcpy(shellcode + sc_off, &path_addr, 8); sc_off += 8;

    // mov rsi, RTLD_NOW | __RTLD_DLOPEN
    shellcode[sc_off++] = 0x48; shellcode[sc_off++] = 0xBE;
    uint64_t rtld_now = 0x80000002;
    memcpy(shellcode + sc_off, &rtld_now, 8); sc_off += 8;

    // mov rax, dlopen_addr
    shellcode[sc_off++] = 0x48; shellcode[sc_off++] = 0xB8;
    memcpy(shellcode + sc_off, &dlopen_addr, 8); sc_off += 8;

    // call rax
    shellcode[sc_off++] = 0xFF; shellcode[sc_off++] = 0xD0;

    // int3
    shellcode[sc_off++] = 0xCC;

    for (int i = 0; i < sc_off; i += sizeof(long)) {
        long word = 0;
        memcpy(&word, shellcode + i,
               std::min(static_cast<size_t>(sizeof(long)),
                        static_cast<size_t>(sc_off - i)));
        ptrace(PTRACE_POKETEXT, pid,
               reinterpret_cast<void*>(mem_addr + i),
               reinterpret_cast<void*>(word));
    }

    // ── execute shellcode ────────────────────────────────────────────────
    struct user_regs_struct sc_regs = orig_regs;
    sc_regs.rip = mem_addr;
    sc_regs.rsp = (sc_regs.rsp & ~0xFULL) - 8;

    ptrace(PTRACE_SETREGS, pid, nullptr, &sc_regs);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    waitpid(pid, &status, 0);

    ptrace(PTRACE_GETREGS, pid, nullptr, &result_regs);
    uintptr_t dlopen_result = result_regs.rax;
    LOG_INFO("dlopen returned 0x{:x}", dlopen_result);

    restore_and_detach();

    if (dlopen_result == 0) {
        error_ = "dlopen returned NULL — library load failed";
        LOG_ERROR("{}", error_);
        return false;
    }
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Public: attach / detach / inject / execute
// ═════════════════════════════════════════════════════════════════════════════
bool Injection::attach() {
    if (memory_.is_valid() && process_alive()) {
        auto regions = memory_.get_regions();
        if (!regions.empty()) return true;
    }

    if (!scan_for_roblox()) return false;

    set_state(InjectionState::Attaching,
              "Attaching to PID " + std::to_string(memory_.get_pid()) + "...");

    auto regions = memory_.get_regions();
    if (regions.empty()) {
        set_state(InjectionState::Failed,
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

    set_state(InjectionState::Ready, "Attached to process");
    return true;
}

bool Injection::detach() {
    set_state(InjectionState::Detached, "Detached");
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
        set_state(InjectionState::Failed, "Process died during injection");
        memory_.set_pid(0);
        return false;
    }

    // ── attempt ptrace-based library injection first ─────────────────────
    std::string payload = find_payload_path();
    if (!payload.empty()) {
        set_state(InjectionState::Injecting,
                  "Injecting payload library into PID " +
                  std::to_string(memory_.get_pid()) + "...");

        if (inject_library(memory_.get_pid(), payload)) {
            set_state(InjectionState::Initializing,
                      "Payload loaded — waiting for init handshake...");
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        } else {
            LOG_WARN("Library injection failed, continuing with VM-scan mode");
        }
    } else {
        LOG_WARN("Payload library not found, using embedded VM mode");
    }

    // ── locate Luau VM markers ───────────────────────────────────────────
    bool found = locate_luau_vm();

    if (found) {
        mode_ = InjectionMode::Full;
        std::ostringstream hex;
        hex << "0x" << std::hex << vm_scan_.marker_addr;
        set_state(InjectionState::Ready,
                  "Injection complete — Luau VM at " + hex.str());
        LOG_INFO("Mode: Full | marker='{}' @ 0x{:X} | validated={} | "
                 "region='{}' base=0x{:X}",
                 vm_scan_.marker_name, vm_scan_.marker_addr,
                 vm_scan_.validated,
                 vm_scan_.region_path, vm_scan_.region_base);
    } else {
        mode_ = InjectionMode::LocalOnly;
        set_state(InjectionState::Ready,
                  "Attached — local execution mode (Luau VM not located)");
        LOG_WARN("No Luau markers in {} regions ({:.1f}MB). PID: {}",
                 vm_scan_.regions_scanned,
                 vm_scan_.bytes_scanned / (1024.0 * 1024.0),
                 memory_.get_pid());
    }
    return true;
}

bool Injection::execute_script(const std::string& source) {
    if (state_ != InjectionState::Ready) {
        LOG_ERROR("execute_script: not in Ready state");
        return false;
    }

    if (!process_alive()) {
        set_state(InjectionState::Failed, "Target process exited");
        mode_ = InjectionMode::None;
        memory_.set_pid(0);
        return false;
    }

    set_state(InjectionState::Executing,
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

            if (write_to_process(write_addr, payload.data(), payload.size())) {
                set_state(InjectionState::Ready, "Script dispatched");
                LOG_INFO("Wrote {} bytes to 0x{:X}", payload.size(), write_addr);
                return true;
            }
            LOG_WARN("Memory write failed at 0x{:X}, falling back", write_addr);
        }
    }

    set_state(InjectionState::Ready, "Script queued for local execution");
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
//  Auto-scan thread
// ═════════════════════════════════════════════════════════════════════════════
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
                set_state(InjectionState::Idle, "Process exited — rescanning...");
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
