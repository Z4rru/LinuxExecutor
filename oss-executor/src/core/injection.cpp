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
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <elf.h>
#include <luacode.h>
#include <fcntl.h>
#include <poll.h>



namespace fs = std::filesystem;

namespace oss {

static constexpr size_t REGION_SCAN_CAP = 0x4000000;
static constexpr size_t REGION_MIN      = 0x1000;
static constexpr size_t REGION_MAX      = 0x80000000ULL;
static constexpr int    AUTOSCAN_TICKS  = 30;
static constexpr int    TICK_MS         = 100;
static constexpr const char* PAYLOAD_SOCK = "/tmp/oss_executor.sock";

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

static uintptr_t find_elf_symbol_impl(const std::string& filepath, const std::string& symbol) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f.is_open()) return 0;

    Elf64_Ehdr ehdr;
    f.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    if (!f.good() || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return 0;
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) return 0;

    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
    f.seekg(static_cast<std::streamoff>(ehdr.e_phoff));
    f.read(reinterpret_cast<char*>(phdrs.data()),
           static_cast<std::streamsize>(ehdr.e_phnum * sizeof(Elf64_Phdr)));
    if (!f.good()) return 0;

    uintptr_t load_base = UINTPTR_MAX;
    for (auto& ph : phdrs)
        if (ph.p_type == PT_LOAD && ph.p_vaddr < load_base)
            load_base = ph.p_vaddr;
    if (load_base == UINTPTR_MAX) load_base = 0;

    Elf64_Phdr* dyn_phdr = nullptr;
    for (auto& ph : phdrs)
        if (ph.p_type == PT_DYNAMIC) { dyn_phdr = &ph; break; }
    if (!dyn_phdr) return 0;

    size_t dyn_count = dyn_phdr->p_filesz / sizeof(Elf64_Dyn);
    std::vector<Elf64_Dyn> dyns(dyn_count);
    f.seekg(static_cast<std::streamoff>(dyn_phdr->p_offset));
    f.read(reinterpret_cast<char*>(dyns.data()),
           static_cast<std::streamsize>(dyn_phdr->p_filesz));
    if (!f.good()) return 0;

    uintptr_t symtab_va = 0, strtab_va = 0, hash_va = 0;
    size_t strsz = 0, syment = sizeof(Elf64_Sym);

    for (auto& d : dyns) {
        switch (d.d_tag) {
            case DT_SYMTAB:  symtab_va = d.d_un.d_ptr; break;
            case DT_STRTAB:  strtab_va = d.d_un.d_ptr; break;
            case DT_STRSZ:   strsz     = d.d_un.d_val; break;
            case DT_SYMENT:  syment    = d.d_un.d_val; break;
            case DT_HASH:    hash_va   = d.d_un.d_ptr; break;
            default: break;
        }
    }
    if (!symtab_va || !strtab_va || !strsz) return 0;

    auto va_to_foff = [&](uintptr_t va) -> int64_t {
        for (auto& ph : phdrs) {
            if (ph.p_type != PT_LOAD) continue;
            if (va >= ph.p_vaddr && va < ph.p_vaddr + ph.p_filesz)
                return static_cast<int64_t>(ph.p_offset + (va - ph.p_vaddr));
        }
        return -1;
    };

    int64_t strtab_off = va_to_foff(strtab_va);
    int64_t symtab_off = va_to_foff(symtab_va);
    if (strtab_off < 0 || symtab_off < 0) return 0;

    std::vector<char> strtab(strsz);
    f.seekg(static_cast<std::streamoff>(strtab_off));
    f.read(strtab.data(), static_cast<std::streamsize>(strsz));
    if (!f.good()) return 0;

    size_t nsyms = 0;
    if (hash_va != 0) {
        int64_t hash_off = va_to_foff(hash_va);
        if (hash_off >= 0) {
            uint32_t hdr[2];
            f.seekg(static_cast<std::streamoff>(hash_off));
            f.read(reinterpret_cast<char*>(hdr), sizeof(hdr));
            if (f.good()) nsyms = hdr[1];
        }
    }
    if (nsyms == 0) nsyms = 32768;

    for (size_t i = 0; i < nsyms; i++) {
        Elf64_Sym sym;
        f.seekg(static_cast<std::streamoff>(symtab_off +
                static_cast<int64_t>(i * syment)));
        f.read(reinterpret_cast<char*>(&sym), sizeof(sym));
        if (!f.good()) break;
        if (sym.st_name == 0 || sym.st_name >= strsz) continue;
        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;
        if (sym.st_shndx == SHN_UNDEF) continue;
        if (symbol == (strtab.data() + sym.st_name))
            return sym.st_value - load_base;
    }
    return 0;
}

uintptr_t Injection::find_elf_symbol(const std::string& filepath,
                                      const std::string& symbol) {
    return find_elf_symbol_impl(filepath, symbol);
}

Injection& Injection::instance() {
    static Injection inst;
    return inst;
}

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

    auto contains_lower = [](const std::string& hay, const std::string& needle) {
        std::string h = hay;
        std::string n = needle;
        std::transform(h.begin(), h.end(), h.begin(), ::tolower);
        std::transform(n.begin(), n.end(), n.begin(), ::tolower);
        return h.find(n) != std::string::npos;
    };

    info.via_wine = contains_lower(info.exe_path, "wine") ||
                    contains_lower(info.name, "wine") ||
                    contains_lower(info.cmdline, "wine");

    info.via_sober = contains_lower(info.exe_path, "sober") ||
                     contains_lower(info.cmdline, "sober") ||
                     contains_lower(info.name, "sober") ||
                     contains_lower(info.exe_path, "vinegar") ||
                     contains_lower(info.cmdline, "vinegar");

    info.via_flatpak = contains(info.exe_path, "/app/") ||
                       contains(info.exe_path, "flatpak") ||
                       contains(info.cmdline, "flatpak");

    if (!info.via_sober && info.parent_pid > 1) {
        std::string parent_cmd = read_proc_cmdline(info.parent_pid);
        std::string parent_exe = read_proc_exe(info.parent_pid);
        if (contains_lower(parent_cmd, "sober") ||
            contains_lower(parent_exe, "sober") ||
            contains_lower(parent_cmd, "vinegar")) {
            info.via_sober = true;
        }
    }

    return info;
}

bool Injection::process_alive() const {
    pid_t p = memory_.get_pid();
    return p > 0 && kill(p, 0) == 0;
}

bool Injection::is_attached() const {
    return memory_.is_valid() &&
           state_ == InjectionState::Ready &&
           process_alive() &&
           payload_loaded_;
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

    struct iovec local_iov  = { const_cast<void*>(data), len };
    struct iovec remote_iov = { reinterpret_cast<void*>(addr), len };
    ssize_t written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (written == static_cast<ssize_t>(len)) return true;

    std::string path = "/proc/" + std::to_string(pid) + "/mem";
    int fd = open(path.c_str(), O_RDWR);
    if (fd < 0) return false;
    ssize_t r = pwrite(fd, data, len, static_cast<off_t>(addr));
    close(fd);
    return r == static_cast<ssize_t>(len);
}

bool Injection::read_from_process(uintptr_t addr, void* buf, size_t len) {
    pid_t pid = memory_.get_pid();
    if (pid <= 0) return false;

    struct iovec local_iov  = { buf, len };
    struct iovec remote_iov = { reinterpret_cast<void*>(addr), len };
    ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (nread == static_cast<ssize_t>(len)) return true;

    std::ifstream f("/proc/" + std::to_string(pid) + "/mem", std::ios::binary);
    if (!f.is_open()) return false;
    f.seekg(static_cast<std::streamoff>(addr));
    if (!f.good()) return false;
    f.read(static_cast<char*>(buf), static_cast<std::streamsize>(len));
    return f.gcount() == static_cast<std::streamsize>(len);
}

void Injection::adopt_target(pid_t pid, const std::string& via) {
    std::string comm    = read_proc_comm(pid);
    std::string cmdline = read_proc_cmdline(pid);
    std::string exe     = read_proc_exe(pid);

    if (!is_valid_target(pid, comm, cmdline, exe)) {
        LOG_DEBUG("Rejected self-target PID {} ('{}') — skipping", pid, comm);
        return;
    }

    if (dhook_.active && memory_.get_pid() > 0 && memory_.get_pid() != pid)
        cleanup_direct_hook();

    memory_.set_pid(pid);
    proc_info_ = gather_info(pid);
    set_state(InjectionState::Found,
              "Found Roblox " + via + " (PID " + std::to_string(pid) + ")");
    LOG_INFO("Target: PID {} name='{}' exe='{}' wine={} sober={} flatpak={}",
             pid, proc_info_.name, proc_info_.exe_path,
             proc_info_.via_wine, proc_info_.via_sober, proc_info_.via_flatpak);
}

pid_t Injection::find_roblox_child(pid_t wrapper_pid) {
    auto children = descendants(wrapper_pid);
    if (children.empty()) {
        LOG_DEBUG("No descendants found for wrapper PID {}", wrapper_pid);
        return -1;
    }

    for (auto cpid : children) {
        if (is_self_process(cpid)) continue;
        std::string ccomm = read_proc_comm(cpid);
        std::string ccmd  = read_proc_cmdline(cpid);
        if (has_roblox_token(ccomm) || has_roblox_token(ccmd)) {
            LOG_DEBUG("Found Roblox child PID {} ('{}') via token match", cpid, ccomm);
            return cpid;
        }
    }

    for (auto cpid : children) {
        if (is_self_process(cpid)) continue;
        try {
            std::ifstream maps("/proc/" + std::to_string(cpid) + "/maps");
            std::string line;
            bool has_roblox = false;
            size_t total_size = 0;
            while (std::getline(maps, line)) {
                uintptr_t lo, hi;
                if (sscanf(line.c_str(), "%lx-%lx", &lo, &hi) == 2)
                    total_size += (hi - lo);
                std::string lower = line;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                if (lower.find("roblox") != std::string::npos)
                    has_roblox = true;
            }
            if (has_roblox && total_size > 50 * 1024 * 1024) {
                LOG_DEBUG("Found Roblox child PID {} via maps ({:.0f}MB)",
                          cpid, total_size / (1024.0 * 1024.0));
                return cpid;
            }
        } catch (...) {}
    }

    pid_t best = -1;
    size_t best_sz = 0;
    for (auto cpid : children) {
        if (is_self_process(cpid)) continue;
        try {
            std::ifstream statm("/proc/" + std::to_string(cpid) + "/statm");
            size_t pages = 0;
            if (statm >> pages) {
                size_t bytes = pages * 4096;
                if (bytes > best_sz) {
                    best_sz = bytes;
                    best = cpid;
                }
            }
        } catch (...) {}
    }

    if (best > 0 && best_sz > 100 * 1024 * 1024) {
        LOG_DEBUG("Using largest child PID {} ({:.0f}MB)",
                  best, best_sz / (1024.0 * 1024.0));
        return best;
    }

    try {
        for (const auto& entry : fs::directory_iterator("/proc")) {
            if (!entry.is_directory()) continue;
            std::string d = entry.path().filename().string();
            if (!std::all_of(d.begin(), d.end(), ::isdigit)) continue;
            pid_t cpid = std::stoi(d);
            if (cpid <= 1 || is_self_process(cpid)) continue;
            try {
                std::ifstream env(entry.path() / "environ", std::ios::binary);
                if (!env.is_open()) continue;
                std::string envs((std::istreambuf_iterator<char>(env)),
                                  std::istreambuf_iterator<char>());
                std::string lower = envs;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                if (lower.find("sober") == std::string::npos &&
                    lower.find("vinegar") == std::string::npos)
                    continue;
                std::ifstream statm(entry.path() / "statm");
                size_t pages = 0;
                if (statm >> pages && pages * 4096 > 100 * 1024 * 1024) {
                    LOG_DEBUG("Found Roblox via environ scan PID {} ({:.0f}MB)",
                              cpid, (pages * 4096) / (1024.0 * 1024.0));
                    return cpid;
                }
            } catch (...) {}
        }
    } catch (...) {}

    return -1;
}

bool Injection::scan_direct() {
    for (const auto& t : DIRECT_TARGETS) {
        auto pids = Memory::find_all_processes(t);
        for (auto p : pids) {
            if (is_self_process(p)) continue;
            if (is_self_process_name(read_proc_comm(p))) continue;

            std::string exe  = read_proc_exe(p);
            std::string comm = read_proc_comm(p);

            if (comm == "bwrap" || exe.find("/bwrap") != std::string::npos) {
                pid_t child = find_roblox_child(p);
                if (child > 0) {
                    adopt_target(child,
                        "Sober child (wrapper PID " + std::to_string(p) + ")");
                    if (memory_.is_valid()) {
                        proc_info_.via_sober = true;
                        return true;
                    }
                }
                continue;
            }

            size_t vm_pages = 0;
            try {
                std::ifstream statm("/proc/" + std::to_string(p) + "/statm");
                statm >> vm_pages;
            } catch (...) {}
            if (vm_pages > 0 && vm_pages * 4096 < 20 * 1024 * 1024) {
                LOG_DEBUG("Skipping PID {} ('{}') — {:.1f}MB, likely wrapper",
                          p, comm, (vm_pages * 4096) / (1024.0 * 1024.0));
                continue;
            }

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
            bl.find("vinegar") == std::string::npos &&
            bl.find("roblox") == std::string::npos)
            continue;

        pid_t child = find_roblox_child(bpid);
        if (child > 0) {
            adopt_target(child,
                "via Sober/Flatpak (wrapper PID " + std::to_string(bpid) + ")");
            if (memory_.is_valid()) {
                proc_info_.via_sober   = true;
                proc_info_.via_flatpak = true;
                return true;
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

bool Injection::scan_for_roblox() {
    set_state(InjectionState::Scanning, "Scanning for Roblox...");
    if (scan_flatpak())      return true;
    if (scan_direct())       return true;
    if (scan_wine_cmdline()) return true;
    if (scan_wine_regions()) return true;
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
    int hits = 0;
    for (const auto& sec : SECONDARY_MARKERS) {
        std::vector<uint8_t> pat(sec.begin(), sec.end());
        std::string mask(pat.size(), 'x');
        auto hit = memory_.pattern_scan(pat, mask, rstart, check);
        if (hit.has_value()) {
            hits++;
            if (hits >= 2) return true;
        }
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
    int         best_hits = 0;

    for (const auto& region : regions) {
        if (!should_scan_region(region)) continue;
        vm_scan_.regions_scanned++;

        int region_hits = 0;
        uintptr_t first_hit = 0;
        std::string first_marker;

        for (const auto& marker : PRIMARY_MARKERS) {
            std::vector<uint8_t> pattern(marker.begin(), marker.end());
            std::string mask(pattern.size(), 'x');
            size_t scan_len = std::min(region.size(), REGION_SCAN_CAP);
            vm_scan_.bytes_scanned += scan_len;

            auto result = memory_.pattern_scan(pattern, mask,
                                               region.start, scan_len);
            if (!result.has_value()) continue;

            region_hits++;
            if (first_hit == 0) {
                first_hit    = result.value();
                first_marker = marker;
            }

            if (region_hits >= 3 && cross_validate(region.start, region.size())) {
                vm_scan_.marker_addr = first_hit;
                vm_scan_.region_base = region.start;
                vm_scan_.marker_name = first_marker;
                vm_scan_.region_path = region.path.empty() ? "[anon]" : region.path;
                vm_scan_.validated   = true;
                vm_marker_addr_      = first_hit;
                LOG_INFO("Luau VM confirmed: '{}' at 0x{:X} in '{}' "
                         "({} primary hits, {} regions, {:.1f}MB scanned)",
                         first_marker, vm_scan_.marker_addr, vm_scan_.region_path,
                         region_hits, vm_scan_.regions_scanned,
                         vm_scan_.bytes_scanned / (1024.0 * 1024.0));
                return true;
            }
        }

        if (region_hits > best_hits) {
            best_hits   = region_hits;
            best_addr   = first_hit;
            best_marker = first_marker;
            best_path   = region.path.empty() ? "[anon]" : region.path;
            best_base   = region.start;
        }
    }

    if (best_addr != 0 && best_hits >= 2) {
        vm_scan_.marker_addr = best_addr;
        vm_scan_.region_base = best_base;
        vm_scan_.marker_name = best_marker;
        vm_scan_.region_path = best_path;
        vm_scan_.validated   = false;
        vm_marker_addr_      = best_addr;
        LOG_WARN("Luau VM probable (unvalidated): '{}' at 0x{:X} in '{}' ({} hits)",
                 best_marker, best_addr, best_path, best_hits);
        return true;
    }
    return false;
}

std::string Injection::find_payload_path() {
    std::vector<std::string> search_paths;

    char self_path[512];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len > 0) {
        self_path[len] = '\0';
        fs::path exe_dir = fs::path(self_path).parent_path();
        search_paths.push_back((exe_dir / "liboss_payload.so").string());
        search_paths.push_back((exe_dir / "lib" / "liboss_payload.so").string());
        search_paths.push_back((exe_dir / "lib" / "oss-executor" / "liboss_payload.so").string());
        search_paths.push_back((exe_dir / ".." / "lib" / "liboss_payload.so").string());
        search_paths.push_back((exe_dir / ".." / "lib" / "oss-executor" / "liboss_payload.so").string());
        search_paths.push_back((exe_dir / ".." / "build" / "liboss_payload.so").string());
    }

    char cwd_buf[512];
    if (getcwd(cwd_buf, sizeof(cwd_buf))) {
        fs::path cwd(cwd_buf);
        search_paths.push_back((cwd / "liboss_payload.so").string());
        search_paths.push_back((cwd / "build" / "liboss_payload.so").string());
        search_paths.push_back((cwd / "cmake-build-debug" / "liboss_payload.so").string());
        search_paths.push_back((cwd / "cmake-build-release" / "liboss_payload.so").string());
    }

    search_paths.push_back("./liboss_payload.so");
    search_paths.push_back("./build/liboss_payload.so");
    search_paths.push_back("../build/liboss_payload.so");
    search_paths.push_back("../lib/liboss_payload.so");
    search_paths.push_back("../lib/oss-executor/liboss_payload.so");
    search_paths.push_back("/usr/lib/oss-executor/liboss_payload.so");
    search_paths.push_back("/usr/local/lib/oss-executor/liboss_payload.so");
    search_paths.push_back("/usr/lib64/oss-executor/liboss_payload.so");

    const char* home = getenv("HOME");
    if (home) {
        search_paths.push_back(std::string(home) + "/.oss-executor/liboss_payload.so");
        search_paths.push_back(std::string(home) + "/.local/lib/oss-executor/liboss_payload.so");
        search_paths.push_back(std::string(home) + "/.local/share/oss-executor/liboss_payload.so");
    }

    const char* xdg_data = getenv("XDG_DATA_HOME");
    if (xdg_data)
        search_paths.push_back(std::string(xdg_data) + "/oss-executor/liboss_payload.so");

    const char* appdir = getenv("APPDIR");
    if (appdir) {
        search_paths.push_back(std::string(appdir) + "/usr/lib/liboss_payload.so");
        search_paths.push_back(std::string(appdir) + "/usr/lib/oss-executor/liboss_payload.so");
    }

    for (const auto& path : search_paths) {
        if (fs::exists(path)) {
            LOG_INFO("Payload found at: {}", fs::absolute(path).string());
            return fs::absolute(path).string();
        }
    }

    LOG_WARN("Payload not found. Searched {} paths:", search_paths.size());
    for (const auto& path : search_paths)
        LOG_DEBUG("  checked: {}", path);
    return "";
}

uintptr_t Injection::find_libc_function(pid_t pid, const std::string& func_name) {
    return find_remote_symbol(pid, "c", func_name);
}

uintptr_t Injection::find_remote_symbol(pid_t pid, const std::string& lib_name,
                                         const std::string& symbol) {
    std::string basename_so6 = "lib" + lib_name + ".so.6";
    std::string basename_so  = "lib" + lib_name + ".so";

    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps.is_open()) return 0;

    uintptr_t remote_base = 0;
    std::string lib_file;
    std::string line;
    while (std::getline(maps, line)) {
        bool match = (line.find(basename_so6) != std::string::npos ||
                      line.find(basename_so) != std::string::npos);
        if (!match) continue;

        unsigned long lo;
        unsigned long file_offset;
        char perms[5]{};
        if (sscanf(line.c_str(), "%lx-%*x %4s %lx", &lo, perms, &file_offset) < 3)
            continue;

        if (file_offset == 0 && remote_base == 0) {
            remote_base = lo;
            auto slash = line.find('/');
            if (slash != std::string::npos) {
                lib_file = line.substr(slash);
                auto end = lib_file.find_last_not_of(" \n\r\t");
                if (end != std::string::npos) lib_file = lib_file.substr(0, end + 1);
            }
        }
    }
    if (remote_base == 0) return 0;

    if (!lib_file.empty()) {
        std::string ns_path = "/proc/" + std::to_string(pid) + "/root" + lib_file;
        struct stat st;
        std::string elf_path;
        if (::stat(ns_path.c_str(), &st) == 0)
            elf_path = ns_path;
        else if (::stat(lib_file.c_str(), &st) == 0)
            elf_path = lib_file;

        if (!elf_path.empty()) {
            uintptr_t sym_offset = find_elf_symbol(elf_path, symbol);
            if (sym_offset != 0)
                return remote_base + sym_offset;
        }
    }

    if (proc_info_.via_flatpak || proc_info_.via_sober) {
        LOG_WARN("ELF lookup failed for '{}' in lib{} — "
                 "skipping unsafe local fallback (containerized target)",
                 symbol, lib_name);
        return 0;
    }

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

    return remote_base + (local_symbol - local_base);
}

std::string Injection::prepare_payload_for_injection(pid_t pid,
                                                      const std::string& host_path) {
    if (!proc_info_.via_flatpak && !proc_info_.via_sober)
        return host_path;

    std::string ns_tmp = "/proc/" + std::to_string(pid) + "/root/tmp";
    std::string ns_dest = ns_tmp + "/liboss_payload.so";
    std::string sandbox_path = "/tmp/liboss_payload.so";

    try {
        struct stat st;
        if (::stat(ns_tmp.c_str(), &st) != 0) {
            LOG_WARN("Cannot access target /tmp via {}, using host path", ns_tmp);
            return host_path;
        }

        std::ifstream src(host_path, std::ios::binary);
        if (!src.is_open()) return host_path;

        std::ofstream dst(ns_dest, std::ios::binary | std::ios::trunc);
        if (!dst.is_open()) {
            LOG_WARN("Cannot write to {}, using host path", ns_dest);
            return host_path;
        }

        dst << src.rdbuf();
        dst.close();
        ::chmod(ns_dest.c_str(), 0755);

        LOG_INFO("Payload staged in target namespace: {}", sandbox_path);
        return sandbox_path;
    } catch (...) {
        LOG_WARN("Failed to stage payload in target namespace, using host path");
        return host_path;
    }
}

std::string Injection::resolve_socket_path() {
    if (proc_info_.via_flatpak || proc_info_.via_sober) {
        pid_t pid = memory_.get_pid();
        if (pid > 0) {
            std::string ns_sock = "/proc/" + std::to_string(pid)
                                + "/root" + PAYLOAD_SOCK;
            struct stat st;
            if (::stat(ns_sock.c_str(), &st) == 0)
                return ns_sock;
        }
    }
    return PAYLOAD_SOCK;
}

struct ProcessDetails {
    char state;
    pid_t tracer_pid;
};

static ProcessDetails get_process_details(pid_t pid) {
    ProcessDetails result = {'?', 0};
    char path[64], buf[4096];

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            char* close_paren = strrchr(buf, ')');
            if (close_paren && close_paren[1] == ' ') {
                result.state = close_paren[2];
            }
        }
        close(fd);
    }

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            char* line = strstr(buf, "TracerPid:");
            if (line) {
                result.tracer_pid = atoi(line + 10);
            }
        }
        close(fd);
    }
    return result;
}

static pid_t get_tracer_pid(pid_t pid) {
    return get_process_details(pid).tracer_pid;
}

struct ThreadState {
    uintptr_t rip;
    uintptr_t rsp;
};

static bool get_thread_state(pid_t pid, pid_t tid, ThreadState& out) {
    std::string path = "/proc/" + std::to_string(pid) + "/task/" +
                       std::to_string(tid) + "/syscall";
    std::ifstream f(path);
    if (!f.is_open()) {
        f.open("/proc/" + std::to_string(pid) + "/syscall");
        if (!f.is_open()) return false;
    }
    std::string line;
    std::getline(f, line);
    if (line.empty() || line == "running") return false;

    std::vector<std::string> fields;
    std::istringstream iss(line);
    std::string field;
    while (iss >> field) fields.push_back(field);

    if (fields.size() < 9) return false;

    out.rsp = std::stoull(fields[7], nullptr, 16);
    out.rip = std::stoull(fields[8], nullptr, 16);
    return out.rip != 0;
}

static pid_t pick_injectable_thread(pid_t pid) {
    std::string task_dir = "/proc/" + std::to_string(pid) + "/task";
    pid_t best_tid = -1;

    try {
        for (const auto& entry : fs::directory_iterator(task_dir)) {
            std::string name = entry.path().filename().string();
            if (!std::all_of(name.begin(), name.end(), ::isdigit)) continue;
            pid_t tid = std::stoi(name);
            ThreadState ts;
            if (get_thread_state(pid, tid, ts) && ts.rip != 0) {
                best_tid = tid;
                break;
            }
        }
    } catch (...) {}

    if (best_tid < 0) best_tid = pid;
    return best_tid;
}

struct ExeRegionInfo {
    uintptr_t text_end;
    uintptr_t padding_start;
    size_t    padding_size;
    uintptr_t base;
};

static bool find_code_cave(pid_t pid, const std::vector<MemoryRegion>& regions,
                           size_t needed, ExeRegionInfo& out) {
    for (size_t i = 0; i + 1 < regions.size(); i++) {
        const auto& r = regions[i];
        if (!r.executable() || !r.readable()) continue;
        if (r.path.empty() || r.path[0] == '[') continue;

        uintptr_t end = r.end;
        uintptr_t page_end = (end + 0xFFF) & ~0xFFFULL;

        if (page_end > end && (page_end - end) >= needed) {
            std::vector<uint8_t> probe(needed, 0);
            struct iovec local = { probe.data(), needed };
            struct iovec remote = { reinterpret_cast<void*>(end), needed };
            ssize_t rd = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (rd == static_cast<ssize_t>(needed)) {
                bool all_zero = true;
                for (auto b : probe) {
                    if (b != 0 && b != 0xCC) { all_zero = false; break; }
                }
                if (all_zero) {
                    out.text_end = end;
                    out.padding_start = end;
                    out.padding_size = page_end - end;
                    out.base = r.start;
                    return true;
                }
            }
        }

        if (i + 1 < regions.size()) {
            const auto& next = regions[i + 1];
            uintptr_t gap = next.start - r.end;
            if (gap >= needed && r.end == ((r.end + 0xFFF) & ~0xFFFULL)) continue;
        }
    }

    for (const auto& r : regions) {
        if (!r.executable() || !r.readable()) continue;
        if (r.size() < needed + 64) continue;

        size_t scan_size = std::min(r.size(), static_cast<size_t>(0x10000));
        uintptr_t scan_start = r.end - scan_size;
        std::vector<uint8_t> buf(scan_size);
        struct iovec local = { buf.data(), scan_size };
        struct iovec remote = { reinterpret_cast<void*>(scan_start), scan_size };
        ssize_t rd = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (rd != static_cast<ssize_t>(scan_size)) continue;

        for (size_t off = scan_size - needed; off > 0; off--) {
            bool usable = true;
            for (size_t j = 0; j < needed; j++) {
                if (buf[off + j] != 0x00 && buf[off + j] != 0xCC &&
                    buf[off + j] != 0x90) {
                    usable = false;
                    break;
                }
            }
            if (usable) {
                out.text_end = scan_start + off;
                out.padding_start = scan_start + off;
                out.padding_size = needed;
                out.base = r.start;
                return true;
            }
        }
    }

    return false;
}

bool Injection::freeze_tracer(pid_t tracer_pid) {
    if (tracer_pid <= 0) return false;
    LOG_INFO("Freezing tracer PID {}...", tracer_pid);

    if (kill(tracer_pid, SIGSTOP) != 0) {
        LOG_WARN("Failed to SIGSTOP tracer PID {}: {}", tracer_pid, strerror(errno));
        return false;
    }

    for (int i = 0; i < 50; i++) {
        usleep(10000);
        ProcessDetails pd = get_process_details(tracer_pid);
        if (pd.state == 'T' || pd.state == 't') {
            LOG_INFO("Tracer PID {} frozen (state={})", tracer_pid, pd.state);
            return true;
        }
    }

    LOG_WARN("Tracer PID {} did not stop in time, resuming", tracer_pid);
    kill(tracer_pid, SIGCONT);
    return false;
}

void Injection::thaw_tracer(pid_t tracer_pid) {
    if (tracer_pid <= 0) return;
    kill(tracer_pid, SIGCONT);
    LOG_INFO("Resumed tracer PID {}", tracer_pid);
}

static size_t dh_insn_len(const uint8_t* p);

bool Injection::inject_via_inline_hook(pid_t pid, const std::string& lib_path,
                                        uintptr_t dlopen_addr, uint64_t dlopen_flags) {
    LOG_INFO("Attempting inline hook injection into PID {}...", pid);

    const char* candidates[] = {
        "nanosleep", "clock_nanosleep", "poll", "epoll_wait",
        "usleep", "select", "pselect", "read", "write",
        "clock_gettime", "gettimeofday"
    };

    uintptr_t hook_func_addr = 0;
    const char* hooked_name = nullptr;
    for (const char* name : candidates) {
        uintptr_t addr = find_remote_symbol(pid, "c", name);
        if (addr != 0) {
            hook_func_addr = addr;
            hooked_name = name;
            LOG_INFO("Targeting libc function '{}' at 0x{:X}", name, addr);
            break;
        }
    }
    if (hook_func_addr == 0) {
        error_ = "No hookable libc function found";
        LOG_ERROR("{}", error_);
        return false;
    }

    uint8_t orig_prologue[16];
    if (!proc_mem_read(pid, hook_func_addr, orig_prologue, sizeof(orig_prologue))) {
        error_ = "Failed to read prologue of " + std::string(hooked_name);
        LOG_ERROR("{}", error_);
        return false;
    }

    int steal_size = 0;
    {
        int pos = 0;
        while (pos < 14) {
            size_t il = dh_insn_len(orig_prologue + pos);
            if (il == 0) break;
            if (orig_prologue[pos] == 0xC3 || orig_prologue[pos] == 0xCC) break;
            pos += static_cast<int>(il);
            if (pos >= 5) break;
        }
        steal_size = pos;
    }

    if (steal_size < 5) {
        LOG_WARN("Steal size {} too small for {} — trying other candidates", steal_size, hooked_name);
        const char* skip_name = hooked_name;
        for (const char* name : candidates) {
            if (name == skip_name) continue;
            uintptr_t a2 = find_remote_symbol(pid, "c", name);
            if (a2 == 0) continue;
            uint8_t probe[16];
            if (!proc_mem_read(pid, a2, probe, sizeof(probe))) continue;
            int pos = 0;
            while (pos < 14) {
                size_t il = dh_insn_len(probe + pos);
                if (il == 0) break;
                if (probe[pos] == 0xC3 || probe[pos] == 0xCC) break;
                pos += static_cast<int>(il);
                if (pos >= 5) break;
            }
            if (pos >= 5) {
                hook_func_addr = a2;
                hooked_name = name;
                memcpy(orig_prologue, probe, sizeof(orig_prologue));
                steal_size = pos;
                LOG_INFO("Switched to '{}' at 0x{:X} (steal={})", name, a2, pos);
                break;
            }
        }
        if (steal_size < 5) {
            error_ = "No hookable function with sufficient prologue found";
            LOG_ERROR("{}", error_);
            return false;
        }
    }
    LOG_DEBUG("Stealing {} bytes from prologue of {}", steal_size, hooked_name);

    auto regions = memory_.get_regions();
    uintptr_t data_addr = 0;
    {
        size_t best_size = 0;
        for (const auto& r : regions) {
            if (!r.writable() || !r.readable()) continue;
            if (r.size() < 8192) continue;
            if (r.path.find("[stack") != std::string::npos) continue;
            if (r.path.find("[vvar") != std::string::npos) continue;
            if (r.path.find("[vdso") != std::string::npos) continue;
            if (!r.path.empty() && r.path[0] == '/') continue;
            if (r.path.find("heap") != std::string::npos) continue;
            if (r.size() > best_size) {
                best_size = r.size();
                data_addr = r.start + r.size() - 4096;
            }
        }
        if (data_addr != 0) {
            LOG_DEBUG("Data region (anonymous, {} KB) at 0x{:X}",
                      best_size / 1024, data_addr);
        }
    }
    if (data_addr == 0) {
        for (const auto& r : regions) {
            if (!r.writable() || !r.readable()) continue;
            if (r.size() < 8192) continue;
            if (r.path.find("[stack") != std::string::npos) continue;
            if (r.path.find("[vvar") != std::string::npos) continue;
            if (r.path.find("[vdso") != std::string::npos) continue;
            data_addr = r.start + ((r.size() / 2) & ~static_cast<size_t>(0xFFF));
            LOG_WARN("Data region (named fallback) at 0x{:X} from '{}'",
                     data_addr, r.path.empty() ? "[anon]" : r.path);
            break;
        }
    }
    if (data_addr == 0) {
        error_ = "No writable data region for inline hook";
        LOG_ERROR("{}", error_);
        return false;
    }

    uint8_t orig_data[4096];
    if (!proc_mem_read(pid, data_addr, orig_data, sizeof(orig_data))) {
        error_ = "Failed to save data region";
        LOG_ERROR("{}", error_);
        return false;
    }

    uintptr_t path_addr       = data_addr;
    uintptr_t result_addr     = data_addr + 512;
    uintptr_t guard_addr      = data_addr + 520;
    uintptr_t completion_addr = data_addr + 528;

    uint8_t path_buf[512] = {};
    size_t plen = std::min(lib_path.size(), sizeof(path_buf) - 1);
    memcpy(path_buf, lib_path.c_str(), plen);
    if (!proc_mem_write(pid, path_addr, path_buf, plen + 1)) {
        error_ = "Failed to write library path";
        LOG_ERROR("{}", error_);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }

    static constexpr uint64_t GUARD_MAGIC      = 0x4F53534755415244ULL;
    static constexpr uint64_t COMPLETION_MAGIC  = 0x4F5353444F4E4521ULL;
    uint64_t zero = 0;
    uint64_t magic = GUARD_MAGIC;
    proc_mem_write(pid, result_addr, &zero, 8);
    proc_mem_write(pid, guard_addr, &magic, 8);
    proc_mem_write(pid, completion_addr, &zero, 8);

    usleep(20000);
    uint64_t verify_guard = 0, verify_result = 0, verify_completion = 0;
    proc_mem_read(pid, guard_addr, &verify_guard, 8);
    proc_mem_read(pid, result_addr, &verify_result, 8);
    proc_mem_read(pid, completion_addr, &verify_completion, 8);
    if (verify_guard != GUARD_MAGIC || verify_result != 0 || verify_completion != 0) {
        LOG_WARN("Data region at 0x{:X} corrupted within 20ms by target "
                 "(guard: 0x{:X} vs expected 0x{:X}; result: 0x{:X}; completion: 0x{:X})",
                 data_addr, verify_guard, GUARD_MAGIC, verify_result, verify_completion);
        proc_mem_write(pid, result_addr, &zero, 8);
        proc_mem_write(pid, guard_addr, &magic, 8);
        proc_mem_write(pid, completion_addr, &zero, 8);
        usleep(20000);
        proc_mem_read(pid, guard_addr, &verify_guard, 8);
        if (verify_guard != GUARD_MAGIC) {
            LOG_ERROR("Data region at 0x{:X} unstable after retry — aborting inline hook", data_addr);
            proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
            error_ = "Data region unstable — target actively writing to selected memory area";
            return false;
        }
        LOG_INFO("Data region stabilized on second write — proceeding");
    }

    size_t sc_needed = 256;

    std::vector<MemoryRegion> nearby_regions;
    for (const auto& r : regions) {
        int64_t dist_lo = static_cast<int64_t>(r.start) - static_cast<int64_t>(hook_func_addr);
        int64_t dist_hi = static_cast<int64_t>(r.end) - static_cast<int64_t>(hook_func_addr);
        if ((dist_lo > INT32_MIN && dist_lo < INT32_MAX) ||
            (dist_hi > INT32_MIN && dist_hi < INT32_MAX)) {
            nearby_regions.push_back(r);
        }
    }
    LOG_DEBUG("Filtered {} of {} regions within ±2GB of hook target",
              nearby_regions.size(), regions.size());

    ExeRegionInfo cave;
    if (!find_code_cave(pid, nearby_regions, sc_needed, cave)) {
        error_ = "No reachable code cave within ±2GB of " + std::string(hooked_name);
        LOG_ERROR("{}", error_);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }
    LOG_DEBUG("Inline hook code cave at 0x{:X} ({} bytes)", cave.padding_start, cave.padding_size);

    uint8_t orig_cave[256];
    if (!proc_mem_read(pid, cave.padding_start, orig_cave, sc_needed)) {
        error_ = "Failed to save code cave";
        LOG_ERROR("{}", error_);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }

    uintptr_t code_addr = cave.padding_start;
    uint8_t sc[256];
    memset(sc, 0xCC, sizeof(sc));
    int off = 0;

    sc[off++] = 0x9C;
    sc[off++] = 0x50; sc[off++] = 0x51; sc[off++] = 0x52; sc[off++] = 0x53;
    sc[off++] = 0x55; sc[off++] = 0x56; sc[off++] = 0x57;
    sc[off++] = 0x41; sc[off++] = 0x50;
    sc[off++] = 0x41; sc[off++] = 0x51;
    sc[off++] = 0x41; sc[off++] = 0x52;
    sc[off++] = 0x41; sc[off++] = 0x53;
    sc[off++] = 0x41; sc[off++] = 0x54;
    sc[off++] = 0x41; sc[off++] = 0x55;
    sc[off++] = 0x41; sc[off++] = 0x56;
    sc[off++] = 0x41; sc[off++] = 0x57;

    sc[off++] = 0x55;
    sc[off++] = 0x48; sc[off++] = 0x89; sc[off++] = 0xE5;
    sc[off++] = 0x48; sc[off++] = 0x83; sc[off++] = 0xE4; sc[off++] = 0xF0;

    sc[off++] = 0x48; sc[off++] = 0xBA;
    memcpy(sc + off, &guard_addr, 8); off += 8;
    sc[off++] = 0x48; sc[off++] = 0xB8;
    memcpy(sc + off, &magic, 8); off += 8;
    sc[off++] = 0xB9; sc[off++] = 0x01; sc[off++] = 0x00; sc[off++] = 0x00; sc[off++] = 0x00;
    sc[off++] = 0xF0; sc[off++] = 0x48; sc[off++] = 0x0F; sc[off++] = 0xB1; sc[off++] = 0x0A;
    sc[off++] = 0x0F; sc[off++] = 0x85;
    int jnz_patch_offset = off;
    off += 4;

    sc[off++] = 0x48; sc[off++] = 0xBF;
    memcpy(sc + off, &path_addr, 8); off += 8;
    sc[off++] = 0x48; sc[off++] = 0xBE;
    memcpy(sc + off, &dlopen_flags, 8); off += 8;
    sc[off++] = 0x48; sc[off++] = 0xB8;
    memcpy(sc + off, &dlopen_addr, 8); off += 8;
    sc[off++] = 0xFF; sc[off++] = 0xD0;

    sc[off++] = 0x48; sc[off++] = 0xBA;
    memcpy(sc + off, &result_addr, 8); off += 8;
    sc[off++] = 0x48; sc[off++] = 0x89; sc[off++] = 0x02;

    {
        uint64_t comp_magic = COMPLETION_MAGIC;
        sc[off++] = 0x48; sc[off++] = 0xBA;
        memcpy(sc + off, &completion_addr, 8); off += 8;
        sc[off++] = 0x48; sc[off++] = 0xB8;
        memcpy(sc + off, &comp_magic, 8); off += 8;
        sc[off++] = 0x48; sc[off++] = 0x89; sc[off++] = 0x02;
    }

    int skip_target = off;
    int32_t jnz_rel = skip_target - (jnz_patch_offset + 4);
    memcpy(sc + jnz_patch_offset, &jnz_rel, 4);

    sc[off++] = 0x48; sc[off++] = 0x89; sc[off++] = 0xEC;
    sc[off++] = 0x5D;
    sc[off++] = 0x41; sc[off++] = 0x5F;
    sc[off++] = 0x41; sc[off++] = 0x5E;
    sc[off++] = 0x41; sc[off++] = 0x5D;
    sc[off++] = 0x41; sc[off++] = 0x5C;
    sc[off++] = 0x41; sc[off++] = 0x5B;
    sc[off++] = 0x41; sc[off++] = 0x5A;
    sc[off++] = 0x41; sc[off++] = 0x59;
    sc[off++] = 0x41; sc[off++] = 0x58;
    sc[off++] = 0x5F; sc[off++] = 0x5E; sc[off++] = 0x5D; sc[off++] = 0x5B;
    sc[off++] = 0x5A; sc[off++] = 0x59; sc[off++] = 0x58;
    sc[off++] = 0x9D;

    memcpy(sc + off, orig_prologue, steal_size);
    off += steal_size;

    uintptr_t jmp_from = code_addr + off + 5;
    uintptr_t jmp_to = hook_func_addr + steal_size;
    int64_t jmp_disp = static_cast<int64_t>(jmp_to) - static_cast<int64_t>(jmp_from);

    if (jmp_disp >= INT32_MIN && jmp_disp <= INT32_MAX) {
        sc[off++] = 0xE9;
        int32_t rel32 = static_cast<int32_t>(jmp_disp);
        memcpy(sc + off, &rel32, 4); off += 4;
    } else {
        sc[off++] = 0xFF; sc[off++] = 0x25;
        sc[off++] = 0x00; sc[off++] = 0x00; sc[off++] = 0x00; sc[off++] = 0x00;
        memcpy(sc + off, &jmp_to, 8); off += 8;
    }

    LOG_DEBUG("Inline hook shellcode: {} bytes", off);

    if (static_cast<size_t>(off) > sc_needed) {
        error_ = "Inline hook shellcode too large";
        LOG_ERROR("Shellcode {} > {} bytes", off, sc_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }

    if (!proc_mem_write(pid, code_addr, sc, off)) {
        error_ = "Failed to write inline hook shellcode";
        LOG_ERROR("{}", error_);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }

    uint8_t hook_patch[16];
    int hook_size = 0;

    int64_t hook_disp = static_cast<int64_t>(code_addr) - static_cast<int64_t>(hook_func_addr + 5);
    if (hook_disp >= INT32_MIN && hook_disp <= INT32_MAX && steal_size >= 5) {
        hook_patch[0] = 0xE9;
        int32_t rel32 = static_cast<int32_t>(hook_disp);
        memcpy(hook_patch + 1, &rel32, 4);
        for (int i = 5; i < steal_size; i++) hook_patch[i] = 0x90;
        hook_size = steal_size;
    } else if (steal_size >= 14) {
        hook_patch[0] = 0xFF; hook_patch[1] = 0x25;
        hook_patch[2] = 0x00; hook_patch[3] = 0x00;
        hook_patch[4] = 0x00; hook_patch[5] = 0x00;
        memcpy(hook_patch + 6, &code_addr, 8);
        hook_size = 14;
    } else {
        error_ = "Cannot encode jump: steal_size=" + std::to_string(steal_size) +
                 " disp=" + std::to_string(hook_disp);
        LOG_ERROR("{}", error_);
        proc_mem_write(pid, code_addr, orig_cave, sc_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }

    if (!proc_mem_write(pid, hook_func_addr, hook_patch, hook_size)) {
        error_ = "Failed to install inline hook";
        LOG_ERROR("{}", error_);
        proc_mem_write(pid, code_addr, orig_cave, sc_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }
    LOG_INFO("Inline hook installed on {} ({} bytes patched)", hooked_name, hook_size);

    uint64_t result = 0;
    uint64_t completion = 0;
    uint64_t guard_status = 0;
    bool completed = false;
    for (int i = 0; i < 100; i++) {
        usleep(100000);
        if (kill(pid, 0) != 0) {
            error_ = "Process died during inline hook injection";
            LOG_ERROR("{}", error_);
            return false;
        }
        proc_mem_read(pid, completion_addr, &completion, 8);
        proc_mem_read(pid, result_addr, &result, 8);
        proc_mem_read(pid, guard_addr, &guard_status, 8);
        if (completion == COMPLETION_MAGIC) {
            LOG_INFO("Inline hook dlopen completed, handle=0x{:X}", result);
            completed = true;
            break;
        }
        if (guard_status != GUARD_MAGIC && guard_status != 1) {
            LOG_WARN("Guard value corrupted during wait (0x{:X}), data region unstable",
                     guard_status);
        }
    }

    uint64_t final_guard = 0;
    if (!completed) {
        proc_mem_read(pid, guard_addr, &final_guard, 8);
    }

    if (!proc_mem_write(pid, hook_func_addr, orig_prologue, steal_size)) {
        LOG_ERROR("Failed to restore prologue of {} — process may crash!", hooked_name);
    } else {
        LOG_DEBUG("Restored original prologue of {}", hooked_name);
    }

    usleep(50000);

    proc_mem_write(pid, code_addr, orig_cave, sc_needed);
    proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));

    if (!completed) {
        if (final_guard == GUARD_MAGIC) {
            error_ = "Inline hook timed out — " + std::string(hooked_name) +
                     " was never called during 10s wait (guard untouched)";
        } else if (final_guard == 1) {
            error_ = "Inline hook shellcode executed but dlopen did not write completion marker "
                     "(possible crash inside dlopen or seccomp blocking mmap)";
        } else {
            std::ostringstream oss;
            oss << "Inline hook failed — data region corrupted by target "
                << "(guard=0x" << std::hex << final_guard << ")";
            error_ = oss.str();
        }
        LOG_ERROR("{}", error_);
        return false;
    }

    if (result == 0) {
        error_ = "dlopen returned NULL — library failed to load in target process";
        if (proc_info_.via_flatpak || proc_info_.via_sober) {
            error_ += " (Flatpak/Sober sandbox may block library loading via seccomp — "
                      "check that payload has no unresolved dependencies)";
        }
        LOG_ERROR("{}", error_);
        return false;
    }

    {
        bool lib_mapped = false;
        for (int maps_retry = 0; maps_retry < 10 && !lib_mapped; maps_retry++) {
            if (maps_retry > 0) usleep(100000);
            std::ifstream maps_check("/proc/" + std::to_string(pid) + "/maps");
            if (!maps_check.is_open()) continue;
            std::string maps_line;
            while (std::getline(maps_check, maps_line)) {
                if (maps_line.find("liboss_payload") != std::string::npos) {
                    lib_mapped = true;
                    LOG_INFO("Verified: liboss_payload mapped in target: {} (after {} retries)",
                             maps_line.substr(0, maps_line.find(' ')), maps_retry);
                    break;
                }
            }
        }
        if (!lib_mapped) {
            bool any_new_mapping = false;
            std::ifstream maps_scan("/proc/" + std::to_string(pid) + "/maps");
            std::string scan_line;
            while (std::getline(maps_scan, scan_line)) {
                if (scan_line.find("liboss") != std::string::npos ||
                    scan_line.find("oss_payload") != std::string::npos ||
                    scan_line.find("oss-executor") != std::string::npos) {
                    any_new_mapping = true;
                    LOG_WARN("Found partial match in maps: {}", scan_line);
                    break;
                }
            }
            if (any_new_mapping) {
                LOG_WARN("dlopen handle 0x{:X} — partial mapping found, treating as success", result);
                payload_loaded_ = true;
                stop_elevated_helper();
                return true;
            }
            bool handle_confirmed = false;
            {
                uint8_t probe_buf[16] = {};
                struct iovec pl = { probe_buf, sizeof(probe_buf) };
                struct iovec pr = { reinterpret_cast<void*>(result), sizeof(probe_buf) };
                if (process_vm_readv(pid, &pl, 1, &pr, 1, 0) == static_cast<ssize_t>(sizeof(probe_buf))) {
                    if (probe_buf[0] != 0) {
                        handle_confirmed = true;
                        LOG_DEBUG("dlopen handle 0x{:X} readable, first bytes: "
                                  "{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
                                  result, probe_buf[0], probe_buf[1], probe_buf[2],
                                  probe_buf[3], probe_buf[4], probe_buf[5],
                                  probe_buf[6], probe_buf[7]);
                    }
                }
            }
            if (!handle_confirmed) {
                bool found_new_so = false;
                std::string found_path;
                std::ifstream maps_deep("/proc/" + std::to_string(pid) + "/maps");
                std::string deep_line;
                size_t new_so_count = 0;
                while (std::getline(maps_deep, deep_line)) {
                    if (deep_line.find(".so") == std::string::npos) continue;
                    if (deep_line.find("/tmp/") != std::string::npos) {
                        uintptr_t lo = 0;
                        sscanf(deep_line.c_str(), "%lx", &lo);
                        if (lo != 0) {
                            found_new_so = true;
                            auto slash = deep_line.find('/');
                            if (slash != std::string::npos) {
                                found_path = deep_line.substr(slash);
                                auto end = found_path.find_last_not_of(" \n\r\t");
                                if (end != std::string::npos)
                                    found_path = found_path.substr(0, end + 1);
                            }
                            new_so_count++;
                        }
                    }
                }
                if (found_new_so) {
                    handle_confirmed = true;
                    LOG_WARN("dlopen handle 0x{:X} — found {} .so mappings under /tmp/, "
                             "last: '{}'. Treating as success.", result, new_so_count,
                             found_path);
                }
            }
            if (handle_confirmed) {
                LOG_WARN("dlopen handle 0x{:X} — library loaded under remapped name "
                         "(Flatpak/Sober namespace). Proceeding.", result);
                {
                    std::ifstream maps_name("/proc/" + std::to_string(pid) + "/maps");
                    std::string name_line;
                    while (std::getline(maps_name, name_line)) {
                        uintptr_t lo = 0, hi = 0;
                        if (sscanf(name_line.c_str(), "%lx-%lx", &lo, &hi) == 2) {
                            if (result >= lo && result < hi) {
                                auto slash = name_line.find('/');
                                if (slash != std::string::npos) {
                                    std::string mapped_name = name_line.substr(slash);
                                    auto end = mapped_name.find_last_not_of(" \n\r\t");
                                    if (end != std::string::npos)
                                        mapped_name = mapped_name.substr(0, end + 1);
                                    if (!mapped_name.empty()) {
                                        payload_mapped_name_ = mapped_name;
                                        LOG_INFO("Payload mapped as '{}' in target "
                                                 "(handle 0x{:X} in range 0x{:X}-0x{:X})",
                                                 mapped_name, result, lo, hi);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                payload_loaded_ = true;
                stop_elevated_helper();
                return true;
            }
            std::ostringstream oss;
            oss << "dlopen returned handle 0x" << std::hex << result
                << " but library not found in /proc/maps after 10 retries — silent load failure";
            error_ = oss.str();
            LOG_ERROR("{}", error_);
            return false;
        }
    }
    payload_loaded_ = true;
    stop_elevated_helper();
    LOG_INFO("inject_via_inline_hook: success — library loaded and verified");
    return true;
}

bool Injection::proc_mem_write(pid_t pid, uintptr_t addr,
                                const void* data, size_t len) {
    std::string path = "/proc/" + std::to_string(pid) + "/mem";
    int fd = open(path.c_str(), O_RDWR);
    if (fd >= 0) {
        ssize_t w = pwrite(fd, data, len, static_cast<off_t>(addr));
        close(fd);
        if (w == static_cast<ssize_t>(len)) return true;
    }

    struct iovec local = { const_cast<void*>(data), len };
    struct iovec remote = { reinterpret_cast<void*>(addr), len };
    ssize_t w = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (w == static_cast<ssize_t>(len)) return true;

    return elevated_mem_write(pid, addr, data, len);
}

bool Injection::proc_mem_read(pid_t pid, uintptr_t addr,
                               void* buf, size_t len) {
    struct iovec local = { buf, len };
    struct iovec remote = { reinterpret_cast<void*>(addr), len };
    ssize_t r = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (r == static_cast<ssize_t>(len)) return true;

    std::string path = "/proc/" + std::to_string(pid) + "/mem";
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    ssize_t rd = pread(fd, buf, len, static_cast<off_t>(addr));
    close(fd);
    return rd == static_cast<ssize_t>(len);
}

bool Injection::start_elevated_helper() {
    if (elevated_pid_ > 0) return true;

    std::string script = "/tmp/.oss_mem_helper.py";
    {
        std::ofstream sf(script, std::ios::trunc);
        sf << "import os,sys\n"
              "sys.stdout.write('R\\n')\n"
              "sys.stdout.flush()\n"
              "while True:\n"
              "  l=sys.stdin.readline()\n"
              "  if not l:break\n"
              "  p=l.strip().split(' ',3)\n"
              "  if p[0]=='W':\n"
              "    try:\n"
              "      f=os.open('/proc/'+p[1]+'/mem',os.O_RDWR)\n"
              "      os.pwrite(f,bytes.fromhex(p[3]),int(p[2]))\n"
              "      os.close(f)\n"
              "      sys.stdout.write('K\\n')\n"
              "    except Exception as e:\n"
              "      sys.stdout.write('E '+str(e)+'\\n')\n"
              "    sys.stdout.flush()\n"
              "  elif p[0]=='Q':break\n";
    }
    chmod(script.c_str(), 0644);

    int to_child[2], from_child[2];
    if (pipe(to_child) < 0) {
        unlink(script.c_str());
        return false;
    }
    if (pipe(from_child) < 0) {
        close(to_child[0]); close(to_child[1]);
        unlink(script.c_str());
        return false;
    }

    LOG_INFO("Requesting elevated privileges for memory write access...");

    pid_t child = fork();
    if (child == 0) {
        close(to_child[1]);
        close(from_child[0]);
        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]);
        close(from_child[1]);
        execlp("pkexec", "pkexec", "/usr/bin/python3", "-u", script.c_str(), nullptr);
        _exit(127);
    }
    if (child < 0) {
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]);
        unlink(script.c_str());
        return false;
    }

    close(to_child[0]);
    close(from_child[1]);

    elevated_pid_ = child;
    elevated_in_fd_ = to_child[1];
    elevated_out_fd_ = from_child[0];

    struct pollfd pfd = { elevated_out_fd_, POLLIN, 0 };
    if (poll(&pfd, 1, 30000) <= 0) {
        LOG_ERROR("Elevated helper timeout or auth cancelled");
        stop_elevated_helper();
        return false;
    }

    char buf[16] = {};
    ssize_t n = read(elevated_out_fd_, buf, sizeof(buf) - 1);
    if (n <= 0 || buf[0] != 'R') {
        LOG_ERROR("Elevated helper failed to initialize");
        stop_elevated_helper();
        return false;
    }

    LOG_INFO("Elevated helper ready");
    return true;
}

bool Injection::elevated_mem_write(pid_t pid, uintptr_t addr,
                                    const void* data, size_t len) {
    if (elevated_pid_ <= 0 && !start_elevated_helper())
        return false;

    std::string hex;
    hex.reserve(len * 2);
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; i++) {
        char h[3];
        snprintf(h, sizeof(h), "%02x", bytes[i]);
        hex += h;
    }

    std::string cmd = "W " + std::to_string(pid) + " " +
                      std::to_string(addr) + " " + hex + "\n";

    ssize_t wr = write(elevated_in_fd_, cmd.c_str(), cmd.size());
    if (wr != static_cast<ssize_t>(cmd.size())) return false;

    struct pollfd pfd = { elevated_out_fd_, POLLIN, 0 };
    if (poll(&pfd, 1, 5000) <= 0) return false;

    char buf[256] = {};
    ssize_t n = read(elevated_out_fd_, buf, sizeof(buf) - 1);
    if (n <= 0) return false;

    return buf[0] == 'K';
}

void Injection::stop_elevated_helper() {
    if (elevated_in_fd_ >= 0) {
        if (write(elevated_in_fd_, "Q\n", 2) < 0) { /* ignore */ }
        close(elevated_in_fd_);
        elevated_in_fd_ = -1;
    }
    if (elevated_out_fd_ >= 0) {
        close(elevated_out_fd_);
        elevated_out_fd_ = -1;
    }
    if (elevated_pid_ > 0) {
        int st;
        if (waitpid(elevated_pid_, &st, WNOHANG) == 0) {
            kill(elevated_pid_, SIGTERM);
            usleep(100000);
            if (waitpid(elevated_pid_, &st, WNOHANG) == 0) {
                kill(elevated_pid_, SIGKILL);
                waitpid(elevated_pid_, &st, 0);
            }
        }
        elevated_pid_ = -1;
    }
    unlink("/tmp/.oss_mem_helper.py");
}

    bool Injection::inject_via_procmem(pid_t pid, const std::string& lib_path,
                                    uintptr_t dlopen_addr, uint64_t dlopen_flags) {
    LOG_INFO("inject_via_procmem: PID {} lib={}", pid, lib_path);

    ProcessDetails pd = get_process_details(pid);
    pid_t tracer = pd.tracer_pid;
    bool tracer_frozen = false;

    if (tracer > 0 && tracer != getpid()) {
        LOG_WARN("PID {} is traced by PID {} — freezing tracer first", pid, tracer);
        tracer_frozen = freeze_tracer(tracer);
        if (!tracer_frozen) {
            LOG_WARN("Could not freeze tracer — falling back to inline hook");
            return inject_via_inline_hook(pid, lib_path, dlopen_addr, dlopen_flags);
        }
    }

    auto cleanup_tracer = [&]() {
        if (tracer_frozen) thaw_tracer(tracer);
    };

    auto regions = memory_.get_regions();
    if (regions.empty()) {
        error_ = "No memory regions available";
        LOG_ERROR("{}", error_);
        cleanup_tracer();
        return false;
    }

    uintptr_t data_addr = 0;
    {
        size_t best_size = 0;
        for (const auto& r : regions) {
            if (!r.writable() || !r.readable()) continue;
            if (r.size() < 8192) continue;
            if (r.path.find("[stack") != std::string::npos) continue;
            if (r.path.find("[vvar")  != std::string::npos) continue;
            if (r.path.find("[vdso")  != std::string::npos) continue;
            if (!r.path.empty() && r.path[0] == '/') continue;
            if (r.path.find("heap") != std::string::npos) continue;
            if (r.size() > best_size) {
                best_size = r.size();
                data_addr = r.start + r.size() - 4096;
            }
        }
        if (data_addr != 0) {
            LOG_DEBUG("Data region (anonymous, {} KB) at 0x{:X}",
                      best_size / 1024, data_addr);
        }
    }
    if (data_addr == 0) {
        for (const auto& r : regions) {
            if (!r.writable() || !r.readable()) continue;
            if (r.size() < 8192) continue;
            if (r.path.find("[stack") != std::string::npos) continue;
            if (r.path.find("[vvar")  != std::string::npos) continue;
            if (r.path.find("[vdso")  != std::string::npos) continue;
            data_addr = r.start + ((r.size() / 2) & ~static_cast<size_t>(0xFFF));
            LOG_WARN("Data region (named fallback) at 0x{:X} from '{}'",
                     data_addr, r.path.empty() ? "[anon]" : r.path);
            break;
        }
    }
    if (data_addr == 0) {
        error_ = "No suitable writable region found";
        LOG_ERROR("{}", error_);
        cleanup_tracer();
        return false;
    }

    uint8_t orig_data[4096];
    if (!proc_mem_read(pid, data_addr, orig_data, sizeof(orig_data))) {
        error_ = "Failed to save original data region";
        LOG_ERROR("{}", error_);
        cleanup_tracer();
        return false;
    }

    uintptr_t path_addr   = data_addr;
    uintptr_t result_addr = data_addr + 512;
    uintptr_t done_addr   = data_addr + 520;

    uint8_t path_buf[512] = {};
    size_t path_len = std::min(lib_path.size(), sizeof(path_buf) - 1);
    memcpy(path_buf, lib_path.c_str(), path_len);
    if (!proc_mem_write(pid, data_addr, path_buf, path_len + 1)) {
        error_ = "Failed to write library path to target";
        LOG_ERROR("{}", error_);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        cleanup_tracer();
        return false;
    }

    uint64_t zero = 0;
    proc_mem_write(pid, result_addr, &zero, sizeof(zero));
    proc_mem_write(pid, done_addr,   &zero, sizeof(zero));

    size_t shellcode_needed = 256;
    ExeRegionInfo cave;
    if (!find_code_cave(pid, regions, shellcode_needed, cave)) {
        error_ = "No suitable code cave found for shellcode";
        LOG_ERROR("{}", error_);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        cleanup_tracer();
        return false;
    }
    LOG_DEBUG("Code cave at 0x{:X} ({} bytes)", cave.padding_start, cave.padding_size);

    uint8_t orig_cave[256];
    if (!proc_mem_read(pid, cave.padding_start, orig_cave, shellcode_needed)) {
        error_ = "Failed to save code cave bytes";
        LOG_ERROR("{}", error_);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        cleanup_tracer();
        return false;
    }

    if (kill(pid, SIGSTOP) != 0) {
        error_ = std::string("SIGSTOP failed: ") + strerror(errno);
        LOG_ERROR("{}", error_);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        cleanup_tracer();
        return false;
    }

    bool stopped = false;
    for (int i = 0; i < 50; i++) {
        usleep(10000);
        ProcessDetails tpd = get_process_details(pid);
        if (tpd.state == 'T' || tpd.state == 't') {
            stopped = true;
            LOG_DEBUG("Target stopped (state='{}')", tpd.state);
            break;
        }
    }

    if (!stopped) {
        LOG_WARN("Target didn't stop even with frozen tracer — trying inline hook");
        kill(pid, SIGCONT);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        cleanup_tracer();
        return inject_via_inline_hook(pid, lib_path, dlopen_addr, dlopen_flags);
    }

    pid_t tid = pick_injectable_thread(pid);
    ThreadState ts;
    if (!get_thread_state(pid, tid, ts)) {
        error_ = "Cannot read thread state for TID " + std::to_string(tid);
        LOG_ERROR("{}", error_);
        kill(pid, SIGCONT);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        cleanup_tracer();
        return false;
    }
    LOG_DEBUG("Thread {} state: RIP=0x{:X} RSP=0x{:X}", tid, ts.rip, ts.rsp);

    uint8_t orig_rip_code[16];
    if (!proc_mem_read(pid, ts.rip, orig_rip_code, sizeof(orig_rip_code))) {
        error_ = "Failed to read code at RIP";
        LOG_ERROR("Failed to read code at RIP 0x{:X}", ts.rip);
        kill(pid, SIGCONT);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        cleanup_tracer();
        return false;
    }

    uintptr_t return_addr = ts.rip;
    uint8_t sc[256];
    memset(sc, 0, sizeof(sc));
    int off = 0;

    sc[off++] = 0x48; sc[off++] = 0x81; sc[off++] = 0xEC;
    sc[off++] = 0x80; sc[off++] = 0x00; sc[off++] = 0x00; sc[off++] = 0x00;

    sc[off++] = 0x9C;
    sc[off++] = 0x50; sc[off++] = 0x51; sc[off++] = 0x52; sc[off++] = 0x53;
    sc[off++] = 0x55; sc[off++] = 0x56; sc[off++] = 0x57;
    sc[off++] = 0x41; sc[off++] = 0x50;
    sc[off++] = 0x41; sc[off++] = 0x51;
    sc[off++] = 0x41; sc[off++] = 0x52;
    sc[off++] = 0x41; sc[off++] = 0x53;
    sc[off++] = 0x41; sc[off++] = 0x54;
    sc[off++] = 0x41; sc[off++] = 0x55;
    sc[off++] = 0x41; sc[off++] = 0x56;
    sc[off++] = 0x41; sc[off++] = 0x57;

    sc[off++] = 0x48; sc[off++] = 0x89; sc[off++] = 0xE5;
    sc[off++] = 0x48; sc[off++] = 0x83; sc[off++] = 0xE4; sc[off++] = 0xF0;

    sc[off++] = 0x48; sc[off++] = 0xBF;
    memcpy(sc + off, &path_addr, 8); off += 8;

    sc[off++] = 0x48; sc[off++] = 0xBE;
    memcpy(sc + off, &dlopen_flags, 8); off += 8;

    sc[off++] = 0x48; sc[off++] = 0xB8;
    memcpy(sc + off, &dlopen_addr, 8); off += 8;
    sc[off++] = 0xFF; sc[off++] = 0xD0;

    sc[off++] = 0x48; sc[off++] = 0xB9;
    memcpy(sc + off, &result_addr, 8); off += 8;
    sc[off++] = 0x48; sc[off++] = 0x89; sc[off++] = 0x01;

    int spin_top = off;
    sc[off++] = 0x48; sc[off++] = 0xB9;
    memcpy(sc + off, &done_addr, 8); off += 8;
    sc[off++] = 0x48; sc[off++] = 0x8B; sc[off++] = 0x09;
    sc[off++] = 0x48; sc[off++] = 0x83; sc[off++] = 0xF9; sc[off++] = 0x01;
    sc[off++] = 0x74; sc[off++] = 0x04;
    sc[off++] = 0xF3; sc[off++] = 0x90;
    int8_t spin_disp = static_cast<int8_t>(spin_top - (off + 2));
    sc[off++] = 0xEB; sc[off++] = static_cast<uint8_t>(spin_disp);

    sc[off++] = 0x48; sc[off++] = 0x89; sc[off++] = 0xEC;

    sc[off++] = 0x41; sc[off++] = 0x5F;
    sc[off++] = 0x41; sc[off++] = 0x5E;
    sc[off++] = 0x41; sc[off++] = 0x5D;
    sc[off++] = 0x41; sc[off++] = 0x5C;
    sc[off++] = 0x41; sc[off++] = 0x5B;
    sc[off++] = 0x41; sc[off++] = 0x5A;
    sc[off++] = 0x41; sc[off++] = 0x59;
    sc[off++] = 0x41; sc[off++] = 0x58;
    sc[off++] = 0x5F; sc[off++] = 0x5E; sc[off++] = 0x5D; sc[off++] = 0x5B;
    sc[off++] = 0x5A; sc[off++] = 0x59; sc[off++] = 0x58;
    sc[off++] = 0x9D;

    sc[off++] = 0x48; sc[off++] = 0x81; sc[off++] = 0xC4;
    sc[off++] = 0x80; sc[off++] = 0x00; sc[off++] = 0x00; sc[off++] = 0x00;

    sc[off++] = 0xFF; sc[off++] = 0x25;
    sc[off++] = 0x00; sc[off++] = 0x00; sc[off++] = 0x00; sc[off++] = 0x00;
    memcpy(sc + off, &return_addr, 8); off += 8;

    LOG_DEBUG("Shellcode size: {} bytes (limit {})", off, shellcode_needed);
    if (off > static_cast<int>(shellcode_needed)) {
        error_ = "Shellcode too large";
        LOG_ERROR("Shellcode {} > {} bytes", off, shellcode_needed);
        kill(pid, SIGCONT);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        cleanup_tracer();
        return false;
    }

    if (!proc_mem_write(pid, cave.padding_start, sc, off)) {
        error_ = "Failed to write shellcode to cave";
        LOG_ERROR("{}", error_);
        kill(pid, SIGCONT);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        cleanup_tracer();
        return false;
    }
    LOG_DEBUG("Shellcode written: {} bytes at 0x{:X}", off, cave.padding_start);

    uint8_t trampoline[16];
    memset(trampoline, 0, sizeof(trampoline));
    int toff = 0;

    int64_t jmp_disp = static_cast<int64_t>(cave.padding_start) -
                       static_cast<int64_t>(ts.rip + 5);

    if (jmp_disp >= INT32_MIN && jmp_disp <= INT32_MAX) {
        trampoline[toff++] = 0xE9;
        int32_t rel32 = static_cast<int32_t>(jmp_disp);
        memcpy(trampoline + toff, &rel32, 4); toff += 4;
    } else {
        trampoline[toff++] = 0xFF; trampoline[toff++] = 0x25;
        trampoline[toff++] = 0x00; trampoline[toff++] = 0x00;
        trampoline[toff++] = 0x00; trampoline[toff++] = 0x00;
        uintptr_t cave_addr = cave.padding_start;
        memcpy(trampoline + toff, &cave_addr, 8); toff += 8;
    }

    if (toff > static_cast<int>(sizeof(orig_rip_code))) {
        error_ = "Trampoline too large: " + std::to_string(toff) + " bytes";
        LOG_ERROR("{}", error_);
        kill(pid, SIGCONT);
        proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        cleanup_tracer();
        return false;
    }

    if (!proc_mem_write(pid, ts.rip, trampoline, toff)) {
        error_ = "Failed to write trampoline";
        LOG_ERROR("Failed to write trampoline at 0x{:X}", ts.rip);
        kill(pid, SIGCONT);
        proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        cleanup_tracer();
        return false;
    }
    LOG_DEBUG("Trampoline: {} bytes at 0x{:X}", toff, ts.rip);

    if (tracer_frozen) {
        LOG_DEBUG("Thawing tracer PID {} before resuming target...", tracer);
        thaw_tracer(tracer);
        tracer_frozen = false;
        usleep(50000);
    }

    kill(pid, SIGCONT);

    for (int retry = 0; retry < 20; retry++) {
        usleep(25000);
        ProcessDetails rpd = get_process_details(pid);
        if (rpd.state == 'S' || rpd.state == 'R' || rpd.state == 'D') {
            LOG_DEBUG("Target running (state='{}')", rpd.state);
            break;
        }
        if (rpd.state == 'T' || rpd.state == 't') {
            LOG_DEBUG("Target still stopped (state='{}'), sending SIGCONT", rpd.state);
            kill(pid, SIGCONT);
        }
    }
    LOG_DEBUG("Process resumed, waiting for dlopen...");

    bool completed = false;
    for (int i = 0; i < 100; i++) {
        usleep(50000);
        uint64_t result_val = 0;
        if (proc_mem_read(pid, result_addr, &result_val, sizeof(result_val)) &&
            result_val != 0) {
            LOG_INFO("dlopen completed, handle=0x{:X}", result_val);
            completed = true;
            break;
        }
        if (kill(pid, 0) != 0) {
            error_ = "Process died during injection";
            LOG_ERROR("{}", error_);
            return false;
        }
    }

    if (!completed) {
        error_ = "dlopen did not complete within timeout";
        LOG_ERROR("{}", error_);

        if (tracer > 0) tracer_frozen = freeze_tracer(tracer);
        kill(pid, SIGSTOP);
        usleep(50000);
        proc_mem_write(pid, ts.rip, orig_rip_code, sizeof(orig_rip_code));
        proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        kill(pid, SIGCONT);
        if (tracer_frozen) thaw_tracer(tracer);

        LOG_WARN("Freeze-tracer RIP injection failed, attempting inline hook fallback");
        return inject_via_inline_hook(pid, lib_path, dlopen_addr, dlopen_flags);
    }

    if (tracer > 0) tracer_frozen = freeze_tracer(tracer);
    kill(pid, SIGSTOP);
    usleep(50000);

    proc_mem_write(pid, ts.rip, orig_rip_code, sizeof(orig_rip_code));

    uint64_t done_signal = 1;
    proc_mem_write(pid, done_addr, &done_signal, sizeof(done_signal));

    if (tracer_frozen) {
        thaw_tracer(tracer);
        tracer_frozen = false;
        usleep(50000);
    }
    kill(pid, SIGCONT);
    for (int retry = 0; retry < 20; retry++) {
        usleep(25000);
        ProcessDetails rpd = get_process_details(pid);
        if (rpd.state == 'S' || rpd.state == 'R' || rpd.state == 'D') break;
        if (rpd.state == 'T' || rpd.state == 't') kill(pid, SIGCONT);
    }

    usleep(300000);

    proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);
    proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));

    {
        bool lib_mapped = false;
        std::ifstream maps_check("/proc/" + std::to_string(pid) + "/maps");
        std::string maps_line;
        while (std::getline(maps_check, maps_line)) {
            if (maps_line.find("liboss_payload") != std::string::npos) {
                lib_mapped = true;
                LOG_INFO("Verified: liboss_payload mapped in target: {}",
                         maps_line.substr(0, maps_line.find(' ')));
                break;
            }
        }
        if (!lib_mapped) {
            error_ = "dlopen appeared to succeed but library not found in /proc/maps — "
                     "injection produced false positive";
            LOG_ERROR("{}", error_);
            stop_elevated_helper();
            return false;
        }
    }

    stop_elevated_helper();
    LOG_INFO("inject_via_procmem: complete, process restored");
    payload_loaded_ = true;
    return true;
}

bool Injection::inject_library(pid_t pid, const std::string& lib_path) {
    LOG_INFO("Injecting {} into PID {}", lib_path, pid);

    std::string target_path = prepare_payload_for_injection(pid, lib_path);

    uintptr_t dlopen_addr = 0;
    bool libc_internal = false;

    uintptr_t libc_dlopen = find_libc_function(pid, "__libc_dlopen_mode");
    if (libc_dlopen != 0) {
        dlopen_addr = libc_dlopen;
        libc_internal = true;
        LOG_DEBUG("Found __libc_dlopen_mode at 0x{:X}", libc_dlopen);
    }

    if (dlopen_addr == 0)
        dlopen_addr = find_remote_symbol(pid, "dl", "dlopen");

    if (dlopen_addr == 0)
        dlopen_addr = find_remote_symbol(pid, "c", "dlopen");

    if (dlopen_addr == 0) {
        error_ = "Cannot find dlopen in target process";
        LOG_ERROR("{}", error_);
        return false;
    }

    LOG_DEBUG("Remote dlopen at 0x{:X}", dlopen_addr);

    uint64_t flags = libc_internal ? 0x80000002ULL : 0x00000002ULL;

    pid_t tracer = get_tracer_pid(pid);
    if (tracer > 0 && tracer != getpid())
        LOG_WARN("Target PID {} is already traced by PID {}", pid, tracer);

    bool ptrace_ok = false;
    if (tracer > 0 && tracer != getpid()) {
        LOG_DEBUG("ptrace attach skipped: already traced by PID {}", tracer);
    } else {
        errno = 0;
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == 0) {
        ptrace_ok = true;
        LOG_DEBUG("ptrace attach succeeded");
    } else {
        int saved_errno = errno;
        LOG_DEBUG("ptrace attach failed: {} (errno={})", strerror(saved_errno), saved_errno);
    }

    if (ptrace_ok) {
        int status;
        if (waitpid(pid, &status, 0) == -1 || !WIFSTOPPED(status)) {
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            ptrace_ok = false;
        }
    }
    } // close else from tracer check

    if (ptrace_ok) {
        LOG_INFO("Using ptrace injection path");
        bool result = inject_shellcode_ptrace(pid, target_path, dlopen_addr, flags);
        if (result) return true;
        LOG_WARN("ptrace injection failed: {}", error_);
    }

    LOG_INFO("Falling back to /proc/pid/mem injection path");
    if (inject_via_procmem(pid, target_path, dlopen_addr, flags))
        return true;

    if (error_.find("Inline hook") != std::string::npos ||
        error_.find("dlopen returned") != std::string::npos ||
        error_.find("Data region unstable") != std::string::npos ||
        error_.find("completion marker") != std::string::npos) {
        LOG_WARN("Inline hook already attempted by procmem fallback — not retrying");
        return false;
    }
    LOG_WARN("Procmem failed before reaching inline hook, trying direct inline hook");
    return inject_via_inline_hook(pid, target_path, dlopen_addr, flags);
}

bool Injection::inject_shellcode_ptrace(pid_t pid, const std::string& lib_path,
                                         uintptr_t dlopen_addr, uint64_t dlopen_flags) {
    auto wait_for_trap = [](pid_t p) -> bool {
        for (int i = 0; i < 200; i++) {
            int st;
            int wr = waitpid(p, &st, 0);
            if (wr == -1) return false;
            if (WIFSTOPPED(st)) {
                int sig = WSTOPSIG(st);
                if (sig == SIGTRAP) return true;
                ptrace(PTRACE_CONT, p, nullptr,
                       reinterpret_cast<void*>(static_cast<uintptr_t>(sig)));
                continue;
            }
            if (WIFEXITED(st) || WIFSIGNALED(st)) return false;
        }
        return false;
    };

    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &orig_regs) != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        error_ = "Could not read registers: " + std::string(strerror(errno));
        return false;
    }

    uintptr_t rip = orig_regs.rip;
    long orig_code[2];
    errno = 0;
    orig_code[0] = ptrace(PTRACE_PEEKTEXT, pid,
                          reinterpret_cast<void*>(rip), nullptr);
    if (orig_code[0] == -1 && errno != 0) {
        error_ = "PEEKTEXT failed at RIP";
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    errno = 0;
    orig_code[1] = ptrace(PTRACE_PEEKTEXT, pid,
                          reinterpret_cast<void*>(rip + 8), nullptr);
    if (orig_code[1] == -1 && errno != 0) {
        error_ = "PEEKTEXT failed at RIP+8";
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }

    auto restore_and_detach = [&]() {
        ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(rip),
               reinterpret_cast<void*>(orig_code[0]));
        ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(rip + 8),
               reinterpret_cast<void*>(orig_code[1]));
        ptrace(PTRACE_SETREGS, pid, nullptr, &orig_regs);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    };

    uint8_t syscall_trap[] = { 0x0F, 0x05, 0xCC };
    long insn = orig_code[0];
    memcpy(&insn, syscall_trap, 3);
    ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(rip),
           reinterpret_cast<void*>(insn));

    size_t alloc_size = 4096;
    struct user_regs_struct mmap_regs = orig_regs;
    mmap_regs.rax = 9;
    mmap_regs.rdi = 0;
    mmap_regs.rsi = alloc_size;
    mmap_regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    mmap_regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    mmap_regs.r8  = static_cast<uintptr_t>(-1);
    mmap_regs.r9  = 0;
    mmap_regs.rip = rip;

    ptrace(PTRACE_SETREGS, pid, nullptr, &mmap_regs);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    if (!wait_for_trap(pid)) {
        restore_and_detach();
        error_ = "mmap syscall did not complete";
        return false;
    }

    struct user_regs_struct result_regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &result_regs);
    uintptr_t mem_addr = result_regs.rax;

    if (mem_addr == 0 || static_cast<int64_t>(mem_addr) < 0) {
        restore_and_detach();
        error_ = "Remote mmap failed";
        return false;
    }
    LOG_DEBUG("Allocated 0x{:x} in target", mem_addr);

    size_t path_len    = lib_path.size() + 1;
    size_t path_offset = 256;
    for (size_t i = 0; i < path_len; i += sizeof(long)) {
        long word = 0;
        size_t chunk = std::min(sizeof(long), path_len - i);
        memcpy(&word, lib_path.c_str() + i, chunk);
        if (ptrace(PTRACE_POKETEXT, pid,
                   reinterpret_cast<void*>(mem_addr + path_offset + i),
                   reinterpret_cast<void*>(word)) != 0) {
            restore_and_detach();
            error_ = "Failed to write library path to target";
            return false;
        }
    }

    uint8_t shellcode[64] = {};
    int sc_off = 0;

    shellcode[sc_off++] = 0x48; shellcode[sc_off++] = 0xBF;
    uintptr_t sc_path_addr = mem_addr + path_offset;
    memcpy(shellcode + sc_off, &sc_path_addr, 8); sc_off += 8;

    shellcode[sc_off++] = 0x48; shellcode[sc_off++] = 0xBE;
    memcpy(shellcode + sc_off, &dlopen_flags, 8); sc_off += 8;

    shellcode[sc_off++] = 0x48; shellcode[sc_off++] = 0xB8;
    memcpy(shellcode + sc_off, &dlopen_addr, 8); sc_off += 8;

    shellcode[sc_off++] = 0xFF; shellcode[sc_off++] = 0xD0;
    shellcode[sc_off++] = 0xCC;

    for (int i = 0; i < sc_off; i += static_cast<int>(sizeof(long))) {
        long word = 0;
        memcpy(&word, shellcode + i,
               std::min(static_cast<size_t>(sizeof(long)),
                        static_cast<size_t>(sc_off - i)));
        ptrace(PTRACE_POKETEXT, pid,
               reinterpret_cast<void*>(mem_addr + static_cast<uintptr_t>(i)),
               reinterpret_cast<void*>(word));
    }

    struct user_regs_struct sc_regs = orig_regs;
    sc_regs.rip = mem_addr;
    sc_regs.rsp = (sc_regs.rsp - 256) & ~0xFULL;

    ptrace(PTRACE_SETREGS, pid, nullptr, &sc_regs);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    if (!wait_for_trap(pid)) {
        restore_and_detach();
        error_ = "Shellcode execution did not complete";
        return false;
    }

    ptrace(PTRACE_GETREGS, pid, nullptr, &result_regs);
    uintptr_t dlopen_result = result_regs.rax;
    LOG_INFO("dlopen returned 0x{:x}", dlopen_result);

    struct user_regs_struct munmap_regs = orig_regs;
    munmap_regs.rax = 11;
    munmap_regs.rdi = mem_addr;
    munmap_regs.rsi = alloc_size;
    munmap_regs.rip = rip;

    ptrace(PTRACE_SETREGS, pid, nullptr, &munmap_regs);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    wait_for_trap(pid);

    ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(rip),
           reinterpret_cast<void*>(orig_code[0]));
    ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(rip + 8),
           reinterpret_cast<void*>(orig_code[1]));
    ptrace(PTRACE_SETREGS, pid, nullptr, &orig_regs);
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

    if (dlopen_result == 0) {
        error_ = "dlopen returned NULL — library load failed in target";
        return false;
    }

    payload_loaded_ = true;
    return true;
}

bool Injection::inject_shellcode(pid_t pid, const std::string& lib_path,
                                  uintptr_t dlopen_addr, uint64_t dlopen_flags) {
    return inject_shellcode_ptrace(pid, lib_path, dlopen_addr, dlopen_flags);
}

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
                  "Cannot read process memory — check permissions");
        LOG_ERROR("0 readable regions for PID {}", memory_.get_pid());
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

// *** CHUNK 4 APPLIED: cleanup_direct_hook() added before stop_elevated_helper() ***
bool Injection::detach() {
    if (state_ == InjectionState::Detached && !memory_.is_valid())
        return true;

    cleanup_direct_hook();
    stop_elevated_helper();

    
    if (state_ != InjectionState::Detached) {
        try {
            set_state(InjectionState::Detached, "Detached");
        } catch (...) {}
    }
    state_ = InjectionState::Detached;

    memory_.set_pid(0);
    mode_            = InjectionMode::None;
    vm_marker_addr_  = 0;
    vm_scan_         = {};
    proc_info_       = {};
    payload_loaded_  = false;


    {
        std::lock_guard<std::mutex> lk(mtx_);
        status_cb_ = nullptr;
    }
    return true;
}


static size_t dh_insn_len(const uint8_t* p) {
    if (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA) return 4;
    size_t i = 0;
    while (i < 4 && (p[i]==0x66||p[i]==0x67||p[i]==0xF0||p[i]==0xF2||p[i]==0xF3||
                     p[i]==0x26||p[i]==0x2E||p[i]==0x36||p[i]==0x3E||p[i]==0x64||p[i]==0x65)) i++;
    bool rex_w = false;
    if (p[i] >= 0x40 && p[i] <= 0x4F) { rex_w = (p[i] & 0x08) != 0; i++; }
    uint8_t op = p[i++];
    if (op == 0xC5) {
        if (i >= 14) return 0;
        i++;
        uint8_t vop = p[i++];
        if (vop == 0x77) return i;
        if (i >= 15) return 0;
        uint8_t m = p[i++];
        uint8_t mod = (m >> 6) & 3, rm = m & 7;
        if (mod != 3 && rm == 4) { if (i>=15) return 0; uint8_t sib = p[i++]; if (mod == 0 && (sib & 7) == 5) i += 4; }
        if (mod == 0 && rm == 5) i += 4;
        else if (mod == 1) i += 1;
        else if (mod == 2) i += 4;
        if (vop==0xC6||vop==0xC2||vop==0xC4||vop==0xC5||vop==0x70||
            vop==0x71||vop==0x72||vop==0x73||vop==0xA4||vop==0xAC) i += 1;
        return i;
    }
    if (op == 0xC4) {
        if (i + 1 >= 14) return 0;
        uint8_t vb1 = p[i++];
        i++;
        uint8_t mmmmm = vb1 & 0x1F;
        if (i >= 15) return 0;
        uint8_t vop = p[i++];
        if (i >= 15) return 0;
        uint8_t m = p[i++];
        uint8_t mod = (m >> 6) & 3, rm = m & 7;
        if (mod != 3 && rm == 4) { if (i>=15) return 0; uint8_t sib = p[i++]; if (mod == 0 && (sib & 7) == 5) i += 4; }
        if (mod == 0 && rm == 5) i += 4;
        else if (mod == 1) i += 1;
        else if (mod == 2) i += 4;
        if (mmmmm == 3) i += 1;
        else if (mmmmm == 1 && (vop==0xC6||vop==0xC2||vop==0xC4||vop==0xC5||
                                vop==0x70||vop==0x71||vop==0x72||vop==0x73)) i += 1;
        return i;
    }
    if (op == 0x62) {
        if (i + 2 >= 14) return 0;
        uint8_t eb1 = p[i++];
        i++; i++;
        uint8_t mmmmm = eb1 & 0x07;
        if (i >= 15) return 0;
        uint8_t eop = p[i++];
        (void)eop;
        if (i >= 15) return 0;
        uint8_t m = p[i++];
        uint8_t mod = (m >> 6) & 3, rm = m & 7;
        if (mod != 3 && rm == 4) { if (i>=15) return 0; uint8_t sib = p[i++]; if (mod == 0 && (sib & 7) == 5) i += 4; }
        if (mod == 0 && rm == 5) i += 4;
        else if (mod == 1) i += 1;
        else if (mod == 2) i += 4;
        if (mmmmm == 3) i += 1;
        return i;
    }
    if ((op>=0x50&&op<=0x5F)||op==0x90||op==0xC3||op==0xCC||op==0xC9) return i;
    if (op==0xC2) return i+2;
    if (op>=0xB0&&op<=0xB7) return i+1;
    if (op>=0xB8&&op<=0xBF) return i+(rex_w?8:4);
    if (op==0xE8||op==0xE9) return i+4;
    if (op==0xEB||(op>=0x70&&op<=0x7F)) return i+1;
    auto mlen = [&](size_t s) -> size_t {
        size_t j = s;
        if (j >= 15) return 0;
        uint8_t m = p[j++];
        uint8_t mod = (m>>6)&3, rm = m&7;
        if (mod!=3&&rm==4) { if(j>=15) return 0; uint8_t sib=p[j++]; if(mod==0&&(sib&7)==5) j+=4; }
        if (mod==0&&rm==5) j+=4;
        else if (mod==1) j+=1;
        else if (mod==2) j+=4;
        return j;
    };
    if (op==0x80||op==0x82||op==0x83||op==0xC0||op==0xC1) return mlen(i)+1;
    if (op==0x81||op==0xC7||op==0x69) return mlen(i)+4;
    if (op==0xC6||op==0x6B) return mlen(i)+1;
    if (op==0x0F) {
        uint8_t op2=p[i++];
        if (op2>=0x80&&op2<=0x8F) return i+4;
        if (op2>=0x40&&op2<=0x4F) return mlen(i);
        if (op2>=0x90&&op2<=0x9F) return mlen(i);
        if (op2==0xB6||op2==0xB7||op2==0xBE||op2==0xBF) return mlen(i);
        if (op2==0xAF) return mlen(i);
        if (op2==0xA3||op2==0xAB||op2==0xB3||op2==0xBB) return mlen(i);
        if (op2==0xBC||op2==0xBD) return mlen(i);
        if (op2==0xA4||op2==0xAC) return mlen(i)+1;
        if (op2==0xA5||op2==0xAD) return mlen(i);
        if (op2==0xBA) return mlen(i)+1;
        if (op2==0x1F||op2==0x44||(op2>=0x10&&op2<=0x17)||(op2>=0x28&&op2<=0x2F)) return mlen(i);
        if (op2==0x38) { if (i>=15) return 0; i++; return mlen(i); }
        if (op2==0x3A) { if (i>=15) return 0; i++; return mlen(i)+1; }
        return mlen(i);
    }
    if ((op&0xC4)==0x00||(op&0xFE)==0x84||(op&0xFC)==0x88||op==0x8C||op==0x8E||
        op==0x8D||op==0x63||op==0x86||op==0x87||op==0x8F) return mlen(i);
    if (op>=0xD0&&op<=0xD3) return mlen(i);
    if (op==0xFE||op==0xFF) return mlen(i);
    if (op==0xF6) { uint8_t m=p[i]; return ((m&0x38)==0)?mlen(i)+1:mlen(i); }
    if (op==0xF7) { uint8_t m=p[i]; return ((m&0x38)==0)?mlen(i)+4:mlen(i); }
    if (op>=0xD8&&op<=0xDF) return mlen(i);
    if (op==0x9C||op==0x9D||op==0xF4||op==0xCB||op==0xF8||op==0xF9||
        op==0xFC||op==0xFD||op==0xF5||op==0x98||op==0x99||op==0x9E||
        op==0x9F||op==0xCE||op==0xCF||(op>=0x91&&op<=0x97)) return i;
    if (op==0x68) return i+4;
    if (op==0x6A) return i+1;
    if (op==0x04||op==0x0C||op==0x14||op==0x1C||op==0x24||op==0x2C||
        op==0x34||op==0x3C||op==0xA8) return i+1;
    if (op==0x05||op==0x0D||op==0x15||op==0x1D||op==0x25||op==0x2D||
        op==0x35||op==0x3D||op==0xA9) return i+4;
    if (op>=0xA0&&op<=0xA3) return i+(rex_w?8:4);
    if (op==0xA4||op==0xA5||op==0xA6||op==0xA7||op==0xAA||op==0xAB||
        op==0xAC||op==0xAD||op==0xAE||op==0xAF) return i;
    if (op==0xCD) return i+1;
    if (op==0xE4||op==0xE5||op==0xE6||op==0xE7) return i+1;
    if (op==0xE0||op==0xE1||op==0xE2||op==0xE3) return i+1;
    return 0;
}
static bool extract_lock_internals(pid_t pid, uintptr_t lock_fn_addr,
                                    int32_t& global_offset_out,
                                    int32_t& mutex_offset_out,
                                    uintptr_t& pthread_lock_out) {
    uint8_t code[96];
    struct iovec local_iov = {code, sizeof(code)};
    struct iovec remote_iov = {reinterpret_cast<void*>(lock_fn_addr), sizeof(code)};
    ssize_t rd = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (rd < 20) return false;
    size_t code_len = static_cast<size_t>(rd);

    size_t pos = 0;
    if (pos + 4 <= code_len && code[pos] == 0xF3 && code[pos + 1] == 0x0F &&
        code[pos + 2] == 0x1E && code[pos + 3] == 0xFA)
        pos += 4;

    if (pos < code_len && code[pos] == 0x55) pos++;
    if (pos + 3 <= code_len && code[pos] == 0x48 &&
        code[pos + 1] == 0x89 && code[pos + 2] == 0xE5)
        pos += 3;
    while (pos < code_len && (code[pos] == 0x53 || code[pos] == 0x50 ||
           code[pos] == 0x51 || code[pos] == 0x52 || code[pos] == 0x56 ||
           code[pos] == 0x57)) pos++;
    if (pos + 2 <= code_len && code[pos] == 0x41 &&
        code[pos + 1] >= 0x50 && code[pos + 1] <= 0x57) pos += 2;
    if (pos + 4 <= code_len && code[pos] == 0x48 &&
        code[pos + 1] == 0x83 && code[pos + 2] == 0xEC)
        pos += 4;

    int gs_reg = 7;
    int32_t gs_off = 0;
    int32_t mx_off = 0;
    bool found_global = false;
    bool found_mutex = false;
    uintptr_t call_target = 0;

    for (int iter = 0; iter < 20 && pos + 1 < code_len; iter++) {
        uint8_t b0 = code[pos];
        bool has_rex_w = false;
        size_t rex_skip = 0;
        if (b0 >= 0x48 && b0 <= 0x4F) {
            has_rex_w = (b0 & 0x08) != 0;
            rex_skip = 1;
        }

        if (!found_global && has_rex_w && pos + rex_skip + 2 < code_len) {
            uint8_t op = code[pos + rex_skip];
            uint8_t modrm = code[pos + rex_skip + 1];
            uint8_t mod_field = (modrm >> 6) & 3;
            uint8_t reg_field = (modrm >> 3) & 7;
            uint8_t rm_field = modrm & 7;

            if (op == 0x8B && rm_field == 7 && mod_field != 3 && rm_field != 4) {
                if (mod_field == 1 && pos + rex_skip + 3 <= code_len) {
                    gs_off = static_cast<int8_t>(code[pos + rex_skip + 2]);
                    gs_reg = reg_field;
                    if ((b0 & 0x04) != 0) gs_reg += 8;
                    found_global = true;
                    pos += rex_skip + 3;
                    LOG_DEBUG("[lock-internals] global_State load: [rdi+{}] → r{}", gs_off, gs_reg);
                    continue;
                } else if (mod_field == 2 && pos + rex_skip + 6 <= code_len) {
                    memcpy(&gs_off, &code[pos + rex_skip + 2], 4);
                    gs_reg = reg_field;
                    if ((b0 & 0x04) != 0) gs_reg += 8;
                    found_global = true;
                    pos += rex_skip + 6;
                    LOG_DEBUG("[lock-internals] global_State load: [rdi+{}] → r{}", gs_off, gs_reg);
                    continue;
                } else if (mod_field == 0 && pos + rex_skip + 2 <= code_len) {
                    gs_off = 0;
                    gs_reg = reg_field;
                    if ((b0 & 0x04) != 0) gs_reg += 8;
                    found_global = true;
                    pos += rex_skip + 2;
                    LOG_DEBUG("[lock-internals] global_State load: [rdi+0] → r{}", gs_reg);
                    continue;
                }
            }
        }

        if (found_global && !found_mutex && has_rex_w && pos + rex_skip + 2 < code_len) {
            uint8_t op = code[pos + rex_skip];
            uint8_t modrm = code[pos + rex_skip + 1];
            uint8_t mod_field = (modrm >> 6) & 3;
            uint8_t reg_field = (modrm >> 3) & 7;
            uint8_t rm_field = modrm & 7;
            int src_reg = rm_field;
            if ((b0 & 0x01) != 0) src_reg += 8;
            int dst_reg = reg_field;
            if ((b0 & 0x04) != 0) dst_reg += 8;

            if (op == 0x8D && src_reg == gs_reg && mod_field != 3 && rm_field != 4) {
                if (mod_field == 1 && pos + rex_skip + 3 <= code_len) {
                    mx_off = static_cast<int8_t>(code[pos + rex_skip + 2]);
                    found_mutex = true;
                    pos += rex_skip + 3;
                    LOG_DEBUG("[lock-internals] mutex LEA: [r{}+{}] → r{}", gs_reg, mx_off, dst_reg);
                    continue;
                } else if (mod_field == 2 && pos + rex_skip + 6 <= code_len) {
                    memcpy(&mx_off, &code[pos + rex_skip + 2], 4);
                    found_mutex = true;
                    pos += rex_skip + 6;
                    LOG_DEBUG("[lock-internals] mutex LEA: [r{}+{}] → r{}", gs_reg, mx_off, dst_reg);
                    continue;
                } else if (mod_field == 0 && pos + rex_skip + 2 <= code_len) {
                    mx_off = 0;
                    found_mutex = true;
                    pos += rex_skip + 2;
                    LOG_DEBUG("[lock-internals] mutex LEA: [r{}+0] → r{}", gs_reg, dst_reg);
                    continue;
                }
            }

            if (op == 0x81 && modrm == (0xC0 | (gs_reg & 7)) &&
                pos + rex_skip + 6 <= code_len) {
                bool rex_b_match = ((b0 & 0x01) != 0) == (gs_reg >= 8);
                if (rex_b_match && (modrm >> 3 & 7) == 0) {
                    memcpy(&mx_off, &code[pos + rex_skip + 2], 4);
                    found_mutex = true;
                    pos += rex_skip + 6;
                    LOG_DEBUG("[lock-internals] mutex ADD imm32: r{} += {}", gs_reg, mx_off);
                    continue;
                }
            }

            if (op == 0x83 && (modrm & 0xF8) == (0xC0 | (gs_reg & 7)) &&
                (modrm >> 3 & 7) == 0 && pos + rex_skip + 3 <= code_len) {
                bool rex_b_match = ((b0 & 0x01) != 0) == (gs_reg >= 8);
                if (rex_b_match) {
                    mx_off = static_cast<int8_t>(code[pos + rex_skip + 2]);
                    found_mutex = true;
                    pos += rex_skip + 3;
                    LOG_DEBUG("[lock-internals] mutex ADD imm8: r{} += {}", gs_reg, mx_off);
                    continue;
                }
            }
        }

        if (found_global && !found_mutex && has_rex_w && pos + rex_skip + 2 < code_len) {
            uint8_t op = code[pos + rex_skip];
            uint8_t modrm = code[pos + rex_skip + 1];
            uint8_t reg_field = (modrm >> 3) & 7;
            int dst_reg = reg_field;
            if ((b0 & 0x04) != 0) dst_reg += 8;

            if (op == 0x89 && dst_reg == 7) {
                uint8_t rm_field = modrm & 7;
                int src_reg = rm_field;
                if ((b0 & 0x01) != 0) src_reg += 8;
                uint8_t mod_field = (modrm >> 6) & 3;
                if (mod_field == 3 && src_reg == gs_reg) {
                    pos += rex_skip + 2;
                    LOG_DEBUG("[lock-internals] mov rdi, r{} (forwarding global_State)", gs_reg);
                    continue;
                }
            }
        }

        if (found_global && pos + 5 <= code_len && code[pos] == 0xE8) {
            int32_t disp;
            memcpy(&disp, &code[pos + 1], 4);
            call_target = lock_fn_addr + pos + 5 + static_cast<int64_t>(disp);
            if (!found_mutex) mx_off = 0;
            LOG_DEBUG("[lock-internals] found CALL rel32 → 0x{:X}", call_target);
            break;
        }
        if (found_global && pos + 5 <= code_len && code[pos] == 0xE9) {
            int32_t disp;
            memcpy(&disp, &code[pos + 1], 4);
            call_target = lock_fn_addr + pos + 5 + static_cast<int64_t>(disp);
            if (!found_mutex) mx_off = 0;
            LOG_DEBUG("[lock-internals] found JMP rel32 → 0x{:X}", call_target);
            break;
        }
        if (found_global && pos + 6 <= code_len &&
            code[pos] == 0xFF && code[pos + 1] == 0x25) {
            int32_t disp;
            memcpy(&disp, &code[pos + 2], 4);
            uintptr_t ptr_addr = lock_fn_addr + pos + 6 + static_cast<int64_t>(disp);
            uintptr_t resolved = 0;
            struct iovec pl = {&resolved, 8};
            struct iovec pr = {reinterpret_cast<void*>(ptr_addr), 8};
            if (process_vm_readv(pid, &pl, 1, &pr, 1, 0) == 8 && resolved != 0) {
                call_target = resolved;
                if (!found_mutex) mx_off = 0;
                LOG_DEBUG("[lock-internals] found JMP indirect → 0x{:X}", call_target);
            }
            break;
        }

        if (!found_global && pos + 7 <= code_len && code[pos] == 0xF6) {
            size_t il = dh_insn_len(code + pos);
            if (il == 0) break;
            pos += il;
            if (pos < code_len && (code[pos] == 0x74 || code[pos] == 0x75) &&
                pos + 2 <= code_len) {
                pos += 2;
            } else if (pos + 2 <= code_len && code[pos] == 0x0F &&
                       (code[pos + 1] == 0x84 || code[pos + 1] == 0x85) &&
                       pos + 6 <= code_len) {
                pos += 6;
            }
            continue;
        }

        size_t il = dh_insn_len(code + pos);
        if (il == 0) {
            LOG_DEBUG("[lock-internals] decode failed at offset {} (byte 0x{:02X})", pos, code[pos]);
            break;
        }
        pos += il;
    }

    if (!found_global) {
        LOG_DEBUG("[lock-internals] pass 1 failed (no global_State load), trying MOV-to-rdi scan");
        pos = 0;
        if (pos + 4 <= code_len && code[pos] == 0xF3 && code[pos + 1] == 0x0F &&
            code[pos + 2] == 0x1E && code[pos + 3] == 0xFA)
            pos += 4;

        for (size_t scan = pos; scan + 10 < code_len; scan++) {
            if (scan + 4 <= code_len && code[scan] == 0x48 && code[scan + 1] == 0x8B) {
                uint8_t modrm = code[scan + 2];
                uint8_t mod_field = (modrm >> 6) & 3;
                uint8_t reg_field = (modrm >> 3) & 7;
                uint8_t rm_field = modrm & 7;
                if (rm_field == 7 && rm_field != 4 && mod_field != 3) {
                    int32_t off_val = 0;
                    size_t insn_len = 0;
                    if (mod_field == 1 && scan + 4 <= code_len) {
                        off_val = static_cast<int8_t>(code[scan + 3]);
                        insn_len = 4;
                    } else if (mod_field == 2 && scan + 7 <= code_len) {
                        memcpy(&off_val, &code[scan + 3], 4);
                        insn_len = 7;
                    } else if (mod_field == 0) {
                        off_val = 0;
                        insn_len = 3;
                    }
                    if (insn_len == 0) continue;
                    size_t after = scan + insn_len;
                    for (size_t j = after; j + 5 <= code_len && j < after + 30; j++) {
                        if (code[j] == 0xE8 || code[j] == 0xE9) {
                            int32_t d;
                            memcpy(&d, &code[j + 1], 4);
                            uintptr_t target = lock_fn_addr + j + 5 + static_cast<int64_t>(d);
                            gs_off = off_val;
                            gs_reg = reg_field;
                            found_global = true;
                            mx_off = 0;
                            call_target = target;

                            for (size_t k = after; k < j; k++) {
                                if (k + 4 <= code_len && code[k] == 0x48 && code[k + 1] == 0x83 &&
                                    code[k + 2] == 0xC7) {
                                    mx_off = static_cast<int8_t>(code[k + 3]);
                                    found_mutex = true;
                                } else if (k + 7 <= code_len && code[k] == 0x48 &&
                                           code[k + 1] == 0x81 && code[k + 2] == 0xC7) {
                                    memcpy(&mx_off, &code[k + 3], 4);
                                    found_mutex = true;
                                } else if (k + 4 <= code_len && code[k] == 0x48 &&
                                           code[k + 1] == 0x8D) {
                                    uint8_t lm = code[k + 2];
                                    uint8_t lmod = (lm >> 6) & 3;
                                    uint8_t lreg = (lm >> 3) & 7;
                                    if (lreg == 7 && lmod == 1 && k + 4 <= code_len) {
                                        mx_off = static_cast<int8_t>(code[k + 3]);
                                        found_mutex = true;
                                    } else if (lreg == 7 && lmod == 2 && k + 7 <= code_len) {
                                        memcpy(&mx_off, &code[k + 3], 4);
                                        found_mutex = true;
                                    }
                                }
                            }
                            LOG_DEBUG("[lock-internals] pass 2: global=[rdi+{}]→r{}, "
                                      "mutex_off={}, call→0x{:X}",
                                      gs_off, gs_reg, mx_off, call_target);
                            goto extraction_done;
                        }
                    }
                }
            }
        }
    }

extraction_done:
    if (found_global && call_target != 0) {
        global_offset_out = gs_off;
        mutex_offset_out = mx_off;
        pthread_lock_out = call_target;
        LOG_INFO("[lock-internals] extracted: global_offset={} mutex_offset={} "
                 "pthread_lock=0x{:X} (intermediate_reg=r{})",
                 gs_off, mx_off, call_target, gs_reg);
        return true;
    }

    LOG_DEBUG("[lock-internals] extraction failed: found_global={} call_target=0x{:X} "
              "pos={} code_len={}", found_global, call_target, pos, code_len);
    return false;
}
static uintptr_t dh_find_elf_sym_sections(const std::string& filepath,
                                           const std::string& name,
                                           uintptr_t load_bias) {
    FILE* ef = fopen(filepath.c_str(), "rb");
    if (!ef) return 0;
    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, ef) != 1 ||
        memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_shnum == 0) { fclose(ef); return 0; }
    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    fseek(ef, static_cast<long>(ehdr.e_shoff), SEEK_SET);
    if (fread(shdrs.data(), sizeof(Elf64_Shdr), ehdr.e_shnum, ef) != ehdr.e_shnum)
        { fclose(ef); return 0; }
    for (size_t si = 0; si < shdrs.size(); si++) {
        if (shdrs[si].sh_type != SHT_SYMTAB && shdrs[si].sh_type != SHT_DYNSYM) continue;
        uint32_t str_idx = shdrs[si].sh_link;
        if (str_idx >= shdrs.size()) continue;
        size_t strsz = shdrs[str_idx].sh_size;
        if (strsz == 0) continue;
        std::vector<char> strtab(strsz);
        fseek(ef, static_cast<long>(shdrs[str_idx].sh_offset), SEEK_SET);
        if (fread(strtab.data(), 1, strsz, ef) != strsz) continue;
        size_t entsize = shdrs[si].sh_entsize;
        if (entsize < sizeof(Elf64_Sym)) entsize = sizeof(Elf64_Sym);
        size_t nsyms = shdrs[si].sh_size / entsize;
        for (size_t j = 0; j < nsyms; j++) {
            Elf64_Sym sym;
            fseek(ef, static_cast<long>(shdrs[si].sh_offset + j * entsize), SEEK_SET);
            if (fread(&sym, sizeof(sym), 1, ef) != 1) break;
            if (sym.st_name == 0 || sym.st_name >= strsz) continue;
            if (sym.st_shndx == SHN_UNDEF) continue;
            if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            if (strcmp(strtab.data() + sym.st_name, name.c_str()) == 0) {
                fclose(ef);
                return load_bias + sym.st_value;
            }
        }
    }
    fclose(ef);
    return 0;
}

bool Injection::find_remote_luau_functions(pid_t pid, DirectHookAddrs& out) {
    char exe_link[512];
    std::string exe_path;
    {
        std::string link = "/proc/" + std::to_string(pid) + "/exe";
        ssize_t len = readlink(link.c_str(), exe_link, sizeof(exe_link) - 1);
        if (len > 0) { exe_link[len] = '\0'; exe_path = exe_link; }
    }

    uintptr_t exe_base = 0;
    {
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        std::string line;
        while (std::getline(maps, line)) {
            if (line.find(exe_path) == std::string::npos &&
                line.find("sober") == std::string::npos) continue;
            uintptr_t lo; unsigned long off; char perms[5]{};
            if (sscanf(line.c_str(), "%lx-%*x %4s %lx", &lo, perms, &off) == 3 && off == 0) {
                exe_base = lo;
                break;
            }
        }
    }

    std::string real_path;
    {
        std::string ns = "/proc/" + std::to_string(pid) + "/root" + exe_path;
        struct stat st;
        if (::stat(ns.c_str(), &st) == 0) real_path = ns;
        else if (::stat(exe_path.c_str(), &st) == 0) real_path = exe_path;
    }

    struct { const char* name; uintptr_t* dst; } syms[] = {
        {"lua_resume",          &out.resume},
        {"lua_newthread",       &out.newthread},
        {"luau_load",           &out.load},
        {"lua_settop",          &out.settop},
        {"luaL_sandboxthread",  &out.sandbox},
        {"luau_compile",        &out.compile},
    };

    if (!real_path.empty() && exe_base) {
        uintptr_t first_vaddr = 0;
        {
            FILE* f = fopen(real_path.c_str(), "rb");
            if (f) {
                Elf64_Ehdr eh;
                if (fread(&eh, sizeof(eh), 1, f) == 1 && memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0) {
                    for (int i = 0; i < eh.e_phnum; i++) {
                        Elf64_Phdr ph;
                        fseek(f, static_cast<long>(eh.e_phoff + i * eh.e_phentsize), SEEK_SET);
                        if (fread(&ph, sizeof(ph), 1, f) != 1) break;
                        if (ph.p_type == PT_LOAD) { first_vaddr = ph.p_vaddr; break; }
                    }
                }
                fclose(f);
            }
        }
        uintptr_t bias = exe_base - first_vaddr;
        for (auto& s : syms) {
            uintptr_t addr = dh_find_elf_sym_sections(real_path, s.name, bias);
            if (addr) {
                *s.dst = addr;
                LOG_INFO("[direct-hook] ELF: {} at 0x{:X}", s.name, addr);
            }
        }
    }

    for (auto& s : syms) {
        if (*s.dst) continue;
        uintptr_t addr = find_remote_symbol(pid, "c", s.name);
        if (!addr) addr = find_remote_symbol(pid, "dl", s.name);
        if (addr) {
            *s.dst = addr;
            LOG_INFO("[direct-hook] dlsym: {} at 0x{:X}", s.name, addr);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FAST PRE-VALIDATION: If we have lua_resume from string-ref, extract
    // a preliminary active_lock from lua_settop (if also found) to test
    // whether lua_resume is from the live Luau copy. This avoids the
    // expensive full string-ref scan + cascade that occurs when the first
    // hits are from dead copies (observed: 242MB away, 8+ re-scans).
    //
    // Strategy: If lua_resume is found but lua_settop is also found,
    // check if they share CALL targets. If not, clear lua_resume early
    // so the string-ref fallback scan finds it in a better region.
    // ═══════════════════════════════════════════════════════════════
    if (out.resume && out.settop) {
        int64_t rs_dist = static_cast<int64_t>(out.resume) -
                          static_cast<int64_t>(out.settop);
        if (rs_dist < 0) rs_dist = -rs_dist;
        if (static_cast<uint64_t>(rs_dist) > 0x2800000ULL) {
            LOG_WARN("[direct-hook] pre-validation: lua_resume 0x{:X} is {:.0f}MB "
                     "from lua_settop 0x{:X} — likely different copies, clearing "
                     "both for string-ref re-scan with distance filter",
                     out.resume, rs_dist / (1024.0 * 1024.0), out.settop);
            out.resume = 0;
            out.settop = 0;
        }
    }
    if (out.resume && out.load) {
        int64_t rl_dist = static_cast<int64_t>(out.resume) -
                          static_cast<int64_t>(out.load);
        if (rl_dist < 0) rl_dist = -rl_dist;
        if (static_cast<uint64_t>(rl_dist) > 0x2800000ULL) {
            LOG_WARN("[direct-hook] pre-validation: luau_load 0x{:X} is {:.0f}MB "
                     "from lua_resume 0x{:X} — clearing luau_load for re-scan",
                     out.load, rl_dist / (1024.0 * 1024.0), out.resume);
            out.load = 0;
        }
    }
    
    struct { const char* func_name; uintptr_t* dst; const char* strings[4]; } fallbacks[] = {
        {"lua_resume",     &out.resume,    {"cannot resume dead coroutine", "cannot resume running coroutine", nullptr}},
        {"lua_newthread",  &out.newthread, {"lua_newthread", "too many C calls", nullptr}},
        {"luau_load",      &out.load,      {"bytecode version mismatch", "truncated", nullptr}},
        {"lua_settop",     &out.settop,    {"stack overflow", nullptr}},
        {"luau_compile",   &out.compile,   {"CompileError", "broken string", "compile option", nullptr}},
    };

    auto regions = memory_.get_regions();

    for (auto& fb : fallbacks) {
        if (*fb.dst) continue;
        for (int si = 0; fb.strings[si]; si++) {
            const char* needle = fb.strings[si];
            size_t nlen = strlen(needle);
            for (const auto& r : regions) {
                if (!r.readable() || r.size() < nlen) continue;
                size_t scan = std::min(r.size(), static_cast<size_t>(0x4000000));
                std::vector<uint8_t> pat(needle, needle + nlen);
                std::string mask(nlen, 'x');
                auto hit = memory_.pattern_scan(pat, mask, r.start, scan);
                if (!hit) continue;
                uintptr_t str_addr = *hit;
                for (const auto& xr : regions) {
                    if (!xr.readable() || !xr.executable() || xr.size() < 7) continue;
                    // When we have an anchor function, skip xref regions that are
                    // too far away — they belong to stale Luau copies.
                    uintptr_t anchor = out.resume ? out.resume :
                                       (out.settop ? out.settop : 0);
                    if (anchor != 0) {
                        int64_t xr_dist_lo = static_cast<int64_t>(xr.start) -
                                             static_cast<int64_t>(anchor);
                        int64_t xr_dist_hi = static_cast<int64_t>(xr.end) -
                                             static_cast<int64_t>(anchor);
                        bool xr_near = (xr_dist_lo > -0x2800000LL && xr_dist_lo < 0x2800000LL) ||
                                       (xr_dist_hi > -0x2800000LL && xr_dist_hi < 0x2800000LL);
                        if (!xr_near) continue;
                    }
                    size_t xscan = std::min(xr.size(), static_cast<size_t>(0x4000000));
                    constexpr size_t CHUNK = 4096;
                    std::vector<uint8_t> buf(CHUNK + 16);
                    for (size_t off = 0; off + 7 <= xscan; off += CHUNK) {
                        size_t avail = xscan - off;
                        size_t rd = std::min(avail, CHUNK + 7);
                        struct iovec local_iov = { buf.data(), rd };
                        struct iovec remote_iov = { reinterpret_cast<void*>(xr.start + off), rd };
                        if (process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) != static_cast<ssize_t>(rd)) continue;
                        for (size_t i = 0; i + 7 <= rd; i++) {
                            bool found_xref = false;
                            // LEA reg,[rip+disp32] (0x8D) or MOV reg,[rip+disp32] (0x8B)
                            // Both use ModRM mod=00 rm=101 for RIP-relative addressing
                            if ((buf[i] == 0x8D || buf[i] == 0x8B) && (buf[i+1] & 0xC7) == 0x05) {
                                int32_t disp; memcpy(&disp, &buf[i+2], 4);
                                uintptr_t target = xr.start + off + i + 6 + (int64_t)disp;
                                if (target == str_addr) found_xref = true;
                            }
                            // REX + LEA/MOV reg,[rip+disp32]
                            if (!found_xref && buf[i] >= 0x40 && buf[i] <= 0x4F &&
                                (buf[i+1] == 0x8D || buf[i+1] == 0x8B) && (buf[i+2] & 0xC7) == 0x05) {
                                int32_t disp; memcpy(&disp, &buf[i+3], 4);
                                uintptr_t target = xr.start + off + i + 7 + (int64_t)disp;
                                if (target == str_addr) found_xref = true;
                            }
                            // MOVABS reg, imm64 — absolute address in immediate (non-PIC / JIT code)
                            if (!found_xref && i + 10 <= rd &&
                                buf[i] >= 0x48 && buf[i] <= 0x4F &&
                                buf[i+1] >= 0xB8 && buf[i+1] <= 0xBF) {
                                uintptr_t imm; memcpy(&imm, &buf[i+2], 8);
                                if (imm == str_addr) found_xref = true;
                            }
                            if (!found_xref) continue;
                            uintptr_t xref_addr = xr.start + off + i;
                            uintptr_t limit = (xref_addr > 4096) ? xref_addr - 4096 : 0;
                            for (uintptr_t p = xref_addr - 1; p >= limit; p--) {
                                uint8_t w[8];
                                struct iovec wl = { w, 8 };
                                struct iovec wr = { reinterpret_cast<void*>(p), 8 };
                                if (process_vm_readv(pid, &wl, 1, &wr, 1, 0) != 8) continue;
                                bool candidate = false;
                                if (w[0]==0xF3&&w[1]==0x0F&&w[2]==0x1E&&w[3]==0xFA&&w[4]==0x55) candidate=true;
                                else if (w[0]==0x55&&w[1]==0x48&&w[2]==0x89&&w[3]==0xE5) candidate=true;
                                else if (w[0]==0x55 && p > limit) {
                                    uint8_t prev;
                                    struct iovec pl = { &prev, 1 };
                                    struct iovec pr = { reinterpret_cast<void*>(p-1), 1 };
                                    if (process_vm_readv(pid, &pl, 1, &pr, 1, 0) == 1 &&
                                        (prev==0xC3||prev==0xCC||prev==0x90)) candidate=true;
                                }
                                else if (w[0]==0x53 && p > limit) {
                                    uint8_t prev;
                                    struct iovec pl = { &prev, 1 };
                                    struct iovec pr = { reinterpret_cast<void*>(p-1), 1 };
                                    if (process_vm_readv(pid, &pl, 1, &pr, 1, 0) == 1 &&
                                        (prev==0xC3||prev==0xCC||prev==0x90)) candidate=true;
                                }
                                else if (w[0]==0x41&&w[1]>=0x54&&w[1]<=0x57 && p > limit) {
                                    uint8_t prev;
                                    struct iovec pl = { &prev, 1 };
                                    struct iovec pr = { reinterpret_cast<void*>(p-1), 1 };
                                    if (process_vm_readv(pid, &pl, 1, &pr, 1, 0) == 1 &&
                                        (prev==0xC3||prev==0xCC||prev==0x90)) candidate=true;
                                }
                                if (!candidate) continue;
                                uint8_t ibuf[64];
                                size_t iavail = std::min((size_t)(xref_addr+32-p), sizeof(ibuf));
                                struct iovec il = { ibuf, iavail };
                                struct iovec ir = { reinterpret_cast<void*>(p), iavail };
                                if (process_vm_readv(pid, &il, 1, &ir, 1, 0) != static_cast<ssize_t>(iavail)) continue;
                                size_t decoded=0; int cnt=0;
                                while (decoded+15<=iavail && decoded<32) {
                                    size_t insn = dh_insn_len(ibuf+decoded);
                                    if (insn==0||decoded+insn>iavail) break;
                                    decoded+=insn; cnt++;
                                }
                                if (cnt >= 3) {
                                    *fb.dst = p;
                                    LOG_INFO("[direct-hook] string-ref: {} at 0x{:X}", fb.func_name, p);
                                    goto next_func;
                                }
                            }
                        }
                    }
                }
            }
        }
        next_func:;
    }

        // FIX: lua_newthread has NO string literals in Luau — proximity scan near lua_settop
    // Both live in lapi.cpp. Look for: no string refs, 2-5 calls, 40-200 bytes, stores LUA_TTHREAD=9
    if (!out.newthread) {
        std::vector<uintptr_t> anchors;
        if (out.settop) anchors.push_back(out.settop);
        if (out.resume) anchors.push_back(out.resume);
        if (out.load) anchors.push_back(out.load);
        LOG_INFO("[direct-hook] lua_newthread: proximity scan with {} anchors, +/-512KB each", anchors.size());
        for (uintptr_t anchor : anchors) {
            if (out.newthread) break;
            for (const auto& r : regions) {
                if (!r.readable() || !r.executable()) continue;
                if (anchor < r.start || anchor >= r.end) continue;

                uintptr_t scan_lo = (anchor > r.start + 0x80000) ? anchor - 0x80000 : r.start;
                uintptr_t scan_hi = std::min(anchor + 0x80000, r.end);
                size_t scan_sz = scan_hi - scan_lo;
                if (scan_sz < 512) continue;

            std::vector<uint8_t> code(scan_sz);
            struct iovec li = {code.data(), scan_sz};
            struct iovec ri = {reinterpret_cast<void*>(scan_lo), scan_sz};
            if (process_vm_readv(pid, &li, 1, &ri, 1, 0) != (ssize_t)scan_sz) break;

            int best_score = -1;
            uintptr_t best_addr = 0;
            size_t best_fsz = 0;
            int best_calls = 0;

            for (size_t off = 1; off + 260 < scan_sz; off++) {
                uintptr_t addr = scan_lo + off;
                if (addr == out.resume || addr == out.settop ||
                    addr == out.load || addr == out.sandbox) continue;

                uint8_t prev = code[off - 1];
                if (prev != 0xC3 && prev != 0xCC && prev != 0x90) continue;

                size_t p = off;
                if (p + 3 < scan_sz && code[p]==0xF3 && code[p+1]==0x0F &&
                    code[p+2]==0x1E && code[p+3]==0xFA) p += 4;
                if (p >= scan_sz) continue;
                if (!(code[p]==0x55 || code[p]==0x53 ||
                      (code[p]==0x41 && p+1<scan_sz && code[p+1]>=0x54 && code[p+1]<=0x57) ||
                      (code[p]==0x48 && p+2<scan_sz && code[p+1]==0x83 && code[p+2]==0xEC)))
                    continue;

                int calls = 0, leas = 0;
                size_t fsz = 0;
                bool has_tt9 = false;

                for (size_t j = 0; j < 250 && off+j+8 < scan_sz; j++) {
                    size_t i = off + j;
                    if (code[i] == 0xE8) calls++;
                    if (i+6 < scan_sz) {
                        if ((code[i]==0x48||code[i]==0x4C) && code[i+1]==0x8D && (code[i+2]&0xC7)==0x05) leas++;
                        if (code[i]==0x8D && (code[i+1]&0xC7)==0x05) leas++;
                    }
                    // Broad tt9 scan: look for 09 00 00 00 as 32-bit immediate anywhere
                    if (!has_tt9 && i+3 < scan_sz &&
                        code[i] == 0x09 && code[i+1] == 0x00 &&
                        code[i+2] == 0x00 && code[i+3] == 0x00 && j >= 4) {
                        size_t k = i;
                        // C7/C6 mem-immediate: C7 xx ... 09000000
                        if (k >= 3 && (code[k-3] == 0xC7 || code[k-3] == 0xC6)) has_tt9 = true;
                        if (!has_tt9 && k >= 4 && (code[k-4] >= 0x40 && code[k-4] <= 0x4F) &&
                            (code[k-3] == 0xC7 || code[k-3] == 0xC6)) has_tt9 = true;
                        // mov r32, 9: Bx 09000000
                        if (!has_tt9 && k >= 1 && code[k-1] >= 0xB8 && code[k-1] <= 0xBF) has_tt9 = true;
                        if (!has_tt9 && k >= 2 && (code[k-2] >= 0x40 && code[k-2] <= 0x4F) &&
                            code[k-1] >= 0xB8 && code[k-1] <= 0xBF) has_tt9 = true;
                    }
                    // Single-byte immediate: C6 xx xx 09 or 83 xx 09 or 6A 09
                    if (!has_tt9 && code[i] == 0x09 && j >= 1) {
                        if (i >= 1 && code[i-1] == 0x6A) has_tt9 = true; // push 9
                        if (i >= 2 && code[i-2] == 0x83) has_tt9 = true; // add/or/cmp reg, 9
                        if (i >= 2 && code[i-2] == 0xC6) has_tt9 = true; // mov byte [reg+disp8], 9
                        if (i >= 3 && (code[i-3] >= 0x40 && code[i-3] <= 0x4F) &&
                            code[i-2] == 0xC6) has_tt9 = true; // REX + mov byte
                    }
                    if (code[i]==0xC3 && j >= 30) { fsz = j + 1; break; }
                }
                if (fsz < 40 || fsz > 200 || leas > 0 || calls < 2 || calls > 6) continue;

                // lua_newthread takes exactly 1 arg (rdi). Reject functions
                // that save rsi (second arg) in the first 20 bytes.
                bool uses_rsi = false;
                bool saves_rdi = false;
                for (size_t bi = 0; bi < 20 && off + bi + 3 < scan_sz; bi++) {
                    uint8_t b0 = code[off + bi];
                    uint8_t b1 = code[off + bi + 1];
                    uint8_t b2 = code[off + bi + 2];
                    // Check for mov rXX, rsi patterns:
                    // 89 F0-F7         mov eXX, esi
                    // 48 89 F0-F7      mov rXX, rsi  
                    // 49 89 F0-F7      mov r8-r15, rsi
                    if (b0 == 0x89 && (b1 & 0x38) == 0x30) uses_rsi = true;
                    if ((b0 == 0x48 || b0 == 0x49) && b1 == 0x89 && (b2 & 0x38) == 0x30) uses_rsi = true;
                    // Check for any MOV with rdi as source (reg field=7, bits 5:3 of modrm)
                    if ((b0 == 0x48 || b0 == 0x49) && b1 == 0x89 && (b2 & 0x38) == 0x38) saves_rdi = true;
                }
                if (uses_rsi) {
                    LOG_DEBUG("[direct-hook] rejecting 0x{:X}: uses rsi (2-arg function)", addr);
                    continue;
                }

                int score = 0;
                if (has_tt9) score += 10;
                if (calls >= 2 && calls <= 4) score += 3;
                if (fsz >= 60 && fsz <= 150) score += 2;
                if (addr < out.settop) score += 1;
                if (!saves_rdi) score -= 2;

                // Cross-validate: check if candidate shares call targets with lua_resume
                if (out.resume && score >= 5) {
                    uint8_t resume_code[1024];
                    struct iovec rl = {resume_code, 1024};
                    struct iovec rr_v = {reinterpret_cast<void*>(out.resume), 1024};
                    ssize_t rrd = process_vm_readv(pid, &rl, 1, &rr_v, 1, 0);
                    if (rrd >= 64) {
                        size_t resume_scan = static_cast<size_t>(rrd);
                        for (size_t cj = 0; cj < fsz && off+cj+5 < scan_sz; cj++) {
                            if (code[off+cj] != 0xE8) continue;
                            int32_t cdisp; memcpy(&cdisp, &code[off+cj+1], 4);
                            uintptr_t ctarget = scan_lo + off + cj + 5 + (int64_t)cdisp;
                            for (size_t rj = 0; rj + 5 <= resume_scan; rj++) {
                                if (resume_code[rj] != 0xE8) continue;
                                int32_t rdisp; memcpy(&rdisp, &resume_code[rj+1], 4);
                                uintptr_t rtarget = out.resume + rj + 5 + (int64_t)rdisp;
                                if (ctarget == rtarget) {
                                    score += 5;
                                    goto done_xref;
                                }
                            }
                        }
                        done_xref:;
                    }
                }

                if (score > best_score) { best_score=score; best_addr=addr; best_fsz=fsz; best_calls=calls; }
            }
            if (best_addr && best_score >= 20) {
                out.newthread = best_addr;
                LOG_INFO("[direct-hook] proximity: lua_newthread=0x{:X} ({}B, {} calls, score={}, CROSS-VALIDATED)",
                         best_addr, best_fsz, best_calls, best_score);
                break;
            } else if (best_addr && best_score >= 8) {
                LOG_WARN("[direct-hook] proximity candidate 0x{:X} rejected (score={}, needs cross-validation >=20)",
                         best_addr, best_score);
            }
            break;
        }
        }
    }
    
             // Extract lua_lock AND lua_unlock from lua_newthread.
    // lua_newthread is ~60-80 bytes; first CALL = lock, last CALL = unlock.
    if (out.newthread && !out.lock_fn) {
        uint8_t ntb[128];
        struct iovec ntl = {ntb, sizeof(ntb)};
        struct iovec ntr = {reinterpret_cast<void*>(out.newthread), sizeof(ntb)};
        ssize_t ntrd = process_vm_readv(pid, &ntl, 1, &ntr, 1, 0);
        if (ntrd >= 20) {
            size_t nt_read = static_cast<size_t>(ntrd);
            // Detect function boundary — expanded marker set
            size_t nt_fend = nt_read;
            bool nt_boundary_found [[maybe_unused]] = false;
            for (size_t ni = 25; ni + 1 < nt_read; ni++) {
                if (ntb[ni] != 0xC3) continue;
                uint8_t nx = ntb[ni + 1];
                if (nx == 0xCC || nx == 0x90 || nx == 0x55 || nx == 0x53 ||
                    nx == 0x56 || nx == 0x57 || nx == 0xF3 || nx == 0x00 ||
                    (nx == 0x41 && ni + 2 < nt_read &&
                     ntb[ni + 2] >= 0x50 && ntb[ni + 2] <= 0x57) ||
                    (nx == 0x48 && ni + 2 < nt_read && ntb[ni + 2] == 0x83 &&
                     ni + 3 < nt_read && ntb[ni + 3] == 0xEC)) {
                    nt_fend = ni + 1;
                    nt_boundary_found = true;
                    break;
                }
            }
            // First CALL = lua_lock
            for (int i = 0; i < static_cast<int>(std::min(nt_fend, static_cast<size_t>(30))); i++) {
                if (ntb[i] == 0xE8) {
                    int32_t d; memcpy(&d, &ntb[i+1], 4);
                    out.lock_fn = out.newthread + i + 5 + (int64_t)d;
                    LOG_INFO("[direct-hook] lua_lock at 0x{:X} (from newthread+{})", out.lock_fn, i);
                    break;
                }
            }
                        // Do NOT extract unlock from pre-validation newthread.
            // This address may be from a dead Luau copy — the FINAL GATE
            // frequently rejects the initial newthread. Unlock extraction
            // is deferred to the authoritative cross-validation block.
        }
    }

    if (!out.free_fn) {
        out.free_fn = find_remote_symbol(pid, "c", "free");
        if (out.free_fn)
            LOG_INFO("[direct-hook] libc free at 0x{:X}", out.free_fn);
    }

    // Global scan: if proximity failed, scan ALL exec regions for lua_newthread
    if (!out.newthread && out.resume) {
        LOG_INFO("[direct-hook] proximity scan failed, trying global scan for lua_newthread");
        for (const auto& r : regions) {
            if (!r.readable() || !r.executable()) continue;
            if (r.size() < 512) continue;
            size_t scan_sz = std::min(r.size(), static_cast<size_t>(0x4000000));
            std::vector<uint8_t> code(scan_sz);
            struct iovec li = {code.data(), scan_sz};
            struct iovec ri = {reinterpret_cast<void*>(r.start), scan_sz};
            if (process_vm_readv(pid, &li, 1, &ri, 1, 0) != (ssize_t)scan_sz) continue;

            int best_score = -1;
            uintptr_t best_addr = 0;

            for (size_t off = 1; off + 200 < scan_sz; off++) {
                if (code[off-1] != 0xC3 && code[off-1] != 0xCC && code[off-1] != 0x90) continue;
                uintptr_t addr = r.start + off;
                if (addr == out.resume || addr == out.settop || addr == out.load) continue;

                size_t p = off;
                if (p+3 < scan_sz && code[p]==0xF3 && code[p+1]==0x0F && code[p+2]==0x1E && code[p+3]==0xFA) p+=4;
                if (p >= scan_sz) continue;
                if (!(code[p]==0x55 || code[p]==0x53 ||
                      (code[p]==0x41 && p+1<scan_sz && code[p+1]>=0x54 && code[p+1]<=0x57) ||
                      (code[p]==0x48 && p+2<scan_sz && code[p+1]==0x83 && code[p+2]==0xEC)))
                    continue;

                bool uses_rsi = false, saves_rdi = false, has_tt9 = false;
                int calls = 0, leas = 0;
                size_t fsz = 0;

                for (size_t j = 0; j < 200 && off+j+8 < scan_sz; j++) {
                    size_t i = off + j;
                    if (code[i] == 0xE8) calls++;
                    if (i+6 < scan_sz && ((code[i]==0x48||code[i]==0x4C) && code[i+1]==0x8D && (code[i+2]&0xC7)==0x05)) leas++;

                                        // rsi check — mask 0x38 isolates reg field (bits 5:3) to catch memory-dest MOVs
                    if (j < 20 && i+2 < scan_sz) {
                        if (code[i]==0x89 && (code[i+1]&0x38)==0x30) uses_rsi = true;
                        if ((code[i]==0x48||code[i]==0x49) && code[i+1]==0x89 && (code[i+2]&0x38)==0x30) uses_rsi = true;
                        if ((code[i]==0x48||code[i]==0x49) && code[i+1]==0x89 && (code[i+2]&0x38)==0x38) saves_rdi = true;
                        if (code[i]==0x89 && (code[i+1]&0x38)==0x38) saves_rdi = true;
                    }

                    // tt9 broad scan
                    if (!has_tt9 && i+3 < scan_sz && code[i]==0x09 && code[i+1]==0x00 && code[i+2]==0x00 && code[i+3]==0x00 && j>=4) {
                        if (i>=1 && code[i-1]>=0xB8 && code[i-1]<=0xBF) has_tt9 = true;
                        if (i>=2 && (code[i-2]>=0x40&&code[i-2]<=0x4F) && code[i-1]>=0xB8 && code[i-1]<=0xBF) has_tt9 = true;
                        if (i>=3 && (code[i-3]==0xC7||code[i-3]==0xC6)) has_tt9 = true;
                        if (i>=4 && (code[i-4]>=0x40&&code[i-4]<=0x4F) && (code[i-3]==0xC7||code[i-3]==0xC6)) has_tt9 = true;
                    }

                    if (code[i]==0xC3 && j >= 30) { fsz = j + 1; break; }
                }

                if (!has_tt9 || uses_rsi || !saves_rdi) continue;
                if (fsz < 40 || fsz > 200 || leas > 0 || calls < 2 || calls > 5) continue;

                int score = 10; // tt9 guaranteed
                if (calls >= 2 && calls <= 4) score += 3;
                if (fsz >= 60 && fsz <= 150) score += 2;

                if (score > best_score) {
                    best_score = score;
                    best_addr = addr;
                }
            }
            if (best_addr && best_score >= 10 && out.resume) {
                uint8_t gxr[1024];
                struct iovec gl = {gxr, 1024};
                struct iovec gr = {reinterpret_cast<void*>(out.resume), 1024};
                ssize_t grd = process_vm_readv(pid, &gl, 1, &gr, 1, 0);
                bool xval = false;
                if (grd >= 64) {
                    size_t gscan = static_cast<size_t>(grd);
                    for (size_t gi = 0; gi + 200 < scan_sz && !xval; gi++) {
                        if (r.start + gi != best_addr) continue;
                        for (size_t gj = 0; gj < 200 && gi+gj+5 < scan_sz; gj++) {
                            if (code[gi+gj] != 0xE8) continue;
                            int32_t gd; memcpy(&gd, &code[gi+gj+1], 4);
                            uintptr_t gt = r.start + gi + gj + 5 + (int64_t)gd;
                            for (size_t rk = 0; rk + 5 <= gscan; rk++) {
                                if (gxr[rk] != 0xE8) continue;
                                int32_t rd; memcpy(&rd, &gxr[rk+1], 4);
                                uintptr_t rt = out.resume + rk + 5 + (int64_t)rd;
                                if (gt == rt) { xval = true; break; }
                            }
                            if (xval) break;
                        }
                    }
                }
                if (xval) {
                    out.newthread = best_addr;
                    LOG_INFO("[direct-hook] global scan: lua_newthread=0x{:X} (score={}, CROSS-VALIDATED)", best_addr, best_score);
                    break;
                } else {
                    LOG_WARN("[direct-hook] global candidate 0x{:X} rejected (score={}, no cross-validation)", best_addr, best_score);
                }
            }
        }
    }

    
    if (out.newthread && !out.lock_fn) {
        uint8_t ntb2[128];
        struct iovec ntl2 = {ntb2, sizeof(ntb2)};
        struct iovec ntr2 = {reinterpret_cast<void*>(out.newthread), sizeof(ntb2)};
        ssize_t nt2rd = process_vm_readv(pid, &ntl2, 1, &ntr2, 1, 0);
        if (nt2rd >= 20) {
            size_t nt2_read = static_cast<size_t>(nt2rd);
            size_t nt2_fend = nt2_read;
            bool nt2_boundary [[maybe_unused]] = false;
            for (size_t ni = 25; ni + 1 < nt2_read; ni++) {
                if (ntb2[ni] != 0xC3) continue;
                uint8_t nx = ntb2[ni + 1];
                if (nx == 0xCC || nx == 0x90 || nx == 0x55 || nx == 0x53 ||
                    nx == 0x56 || nx == 0x57 || nx == 0xF3 || nx == 0x00 ||
                    (nx == 0x41 && ni + 2 < nt2_read &&
                     ntb2[ni + 2] >= 0x50 && ntb2[ni + 2] <= 0x57) ||
                    (nx == 0x48 && ni + 2 < nt2_read && ntb2[ni + 2] == 0x83 &&
                     ni + 3 < nt2_read && ntb2[ni + 3] == 0xEC)) {
                    nt2_fend = ni + 1;
                    nt2_boundary = true;
                    break;
                }
            }
            for (int i = 0; i < static_cast<int>(std::min(nt2_fend, static_cast<size_t>(30))); i++) {
                if (ntb2[i] == 0xE8) {
                    int32_t d; memcpy(&d, &ntb2[i+1], 4);
                    out.lock_fn = out.newthread + i + 5 + (int64_t)d;
                    LOG_INFO("[direct-hook] lua_lock at 0x{:X} (from newthread+{}, post-global-scan)", out.lock_fn, i);
                    break;
                }
            }
                        // Do NOT extract unlock here. This newthread may be from a DEAD
            // copy that the FINAL GATE will reject later. Setting unlock_fn
            // from a dead copy caused previous failures where the wrong
            // function was patched. Unlock is extracted post-validation by
            // the authoritative cross-validation block.
        }
    }

   // Validate lua_settop: must be a 2-arg function (saves rdi + rsi, NOT rdx)
    // Also reject 1-CALL settops: they have inlined lua_unlock with struct
    // offsets from a potentially stale Luau build. The inlined unlock fails
    // to release the mutex, causing deadlock when called from the trampoline.
    // A live lua_settop has ≥2 CALLs (lua_lock + lua_unlock, possibly helpers).
    if (out.settop) {
        uint8_t st_buf[128];
        struct iovec st_l = {st_buf, sizeof(st_buf)};
        struct iovec st_r = {reinterpret_cast<void*>(out.settop), sizeof(st_buf)};
        ssize_t st_rd = process_vm_readv(pid, &st_l, 1, &st_r, 1, 0);
        if (st_rd >= 24) {
            size_t st_read = static_cast<size_t>(st_rd);
            bool saves_rsi = false, saves_rdx = false;
            for (int i = 0; i + 2 < 22; i++) {
                if (st_buf[i] == 0x89 && (st_buf[i+1] & 0x38) == 0x30) saves_rsi = true;
                if ((st_buf[i]==0x48||st_buf[i]==0x49) && st_buf[i+1]==0x89 && (st_buf[i+2]&0x38)==0x30) saves_rsi = true;
                if (st_buf[i]==0x48 && st_buf[i+1]==0x63 && (st_buf[i+2]&0xC7)==0xC6) saves_rsi = true;
                if (st_buf[i] == 0x89 && (st_buf[i+1] & 0x38) == 0x10) saves_rdx = true;
                if ((st_buf[i]==0x48||st_buf[i]==0x49) && st_buf[i+1]==0x89 && (st_buf[i+2]&0x38)==0x10) saves_rdx = true;
            }
            if (saves_rdx && !saves_rsi) {
                LOG_WARN("[direct-hook] lua_settop at 0x{:X} saves rdx (3-arg function) — wrong function, clearing", out.settop);
                out.settop = 0;
            } else if (!saves_rsi) {
                LOG_WARN("[direct-hook] lua_settop at 0x{:X} doesn't save rsi — may be wrong function, clearing", out.settop);
                out.settop = 0;
            }

            // Count CALL instructions to detect stale inlined-unlock settops
            if (out.settop && st_rd >= 40) {
                size_t st_fend = 0;
                {
                    size_t pos = 0;
                    while (pos + 15 < st_read && pos < 250) {
                        size_t il = dh_insn_len(st_buf + pos);
                        if (il == 0) break;
                        if (st_buf[pos] == 0xC3) { st_fend = pos + 1; break; }
                        pos += il;
                    }
                }
                if (st_fend > 10) {
                    int call_count = 0;
                    for (size_t ci = 0; ci + 5 <= st_fend; ci++) {
                        if (st_buf[ci] == 0xE8) call_count++;
                    }
                    if (call_count < 2) {
                        LOG_WARN("[direct-hook] lua_settop at 0x{:X} has only {} CALL(s) "
                                 "in {} bytes — inlined lua_unlock from stale build, "
                                 "clearing (need ≥2 for lock+unlock pair)",
                                 out.settop, call_count, st_fend);
                        out.settop = 0;
                    }
                }
            }
        }
    }

    // Proximity scan for lua_settop near lua_resume if not found or invalidated
    if (!out.settop && out.resume) {
        LOG_INFO("[direct-hook] lua_settop: proximity scan near lua_resume (±2MB)");
        for (const auto& r : regions) {
            if (!r.readable() || !r.executable()) continue;
            if (out.resume < r.start || out.resume >= r.end) continue;

            uintptr_t scan_lo = (out.resume > r.start + 0x200000) ? out.resume - 0x200000 : r.start;
            uintptr_t scan_hi = std::min(out.resume + 0x200000, r.end);
            size_t scan_sz = scan_hi - scan_lo;
            if (scan_sz < 512) continue;

            std::vector<uint8_t> code(scan_sz);
            struct iovec st_li = {code.data(), scan_sz};
            struct iovec st_ri = {reinterpret_cast<void*>(scan_lo), scan_sz};
            if (process_vm_readv(pid, &st_li, 1, &st_ri, 1, 0) != (ssize_t)scan_sz) break;

            int best_score = -1;
            uintptr_t best_addr = 0;
            size_t best_fsz = 0;

            for (size_t off = 1; off + 260 < scan_sz; off++) {
                if (code[off-1] != 0xC3 && code[off-1] != 0xCC && code[off-1] != 0x90) continue;
                uintptr_t addr = scan_lo + off;
                if (addr == out.resume || addr == out.newthread || addr == out.load) continue;

                size_t p = off;
                if (p+3 < scan_sz && code[p]==0xF3 && code[p+1]==0x0F && code[p+2]==0x1E && code[p+3]==0xFA) p += 4;
                if (p >= scan_sz) continue;
                if (!(code[p]==0x55 || code[p]==0x53 ||
                      (code[p]==0x41 && p+1<scan_sz && code[p+1]>=0x54 && code[p+1]<=0x57)))
                    continue;

                bool saves_rdi = false, saves_rsi = false, saves_rdx = false;
                int calls = 0, leas = 0;
                size_t fsz = 0;

                for (size_t j = 0; j < 250 && off+j+8 < scan_sz; j++) {
                    size_t i = off + j;
                    if (code[i] == 0xE8) calls++;
                    if (i+6 < scan_sz && ((code[i]==0x48||code[i]==0x4C) &&
                        code[i+1]==0x8D && (code[i+2]&0xC7)==0x05)) leas++;

                    if (j < 20 && i+2 < scan_sz) {
                        // rsi/esi saves (reg field = 110)
                        if (code[i]==0x89 && (code[i+1]&0x38)==0x30) saves_rsi = true;
                        if ((code[i]==0x48||code[i]==0x49) && code[i+1]==0x89 && (code[i+2]&0x38)==0x30) saves_rsi = true;
                        if (code[i]==0x48 && code[i+1]==0x63 && (code[i+2]&0xC7)==0xC6) saves_rsi = true;
                        // rdi saves (reg field = 111)
                        if ((code[i]==0x48||code[i]==0x49) && code[i+1]==0x89 && (code[i+2]&0x38)==0x38) saves_rdi = true;
                        if (code[i]==0x89 && (code[i+1]&0x38)==0x38) saves_rdi = true;
                        // rdx saves → 3-arg, reject
                        if (code[i]==0x89 && (code[i+1]&0x38)==0x10) saves_rdx = true;
                        if ((code[i]==0x48||code[i]==0x49) && code[i+1]==0x89 && (code[i+2]&0x38)==0x10) saves_rdx = true;
                    }

                    if (code[i]==0xC3 && j >= 20) { fsz = j + 1; break; }
                }

                if (!saves_rdi || !saves_rsi) continue;  // must be 2-arg saving both
                if (saves_rdx) continue;                   // reject 3-arg functions
                if (fsz < 30 || fsz > 250 || calls < 1 || calls > 8) continue;

                int score = 5;  // saves both rdi and rsi
                if (calls >= 1 && calls <= 4) score += 2;
                if (fsz >= 40 && fsz <= 150) score += 2;
                if (leas == 0) score += 1;  // lua_settop has no string refs typically

                // Cross-validate: shared call targets with lua_resume
                if (out.resume && score >= 5) {
                    uint8_t rc[1024];
                    struct iovec rc_l = {rc, 1024};
                    struct iovec rc_r = {reinterpret_cast<void*>(out.resume), 1024};
                    ssize_t rrd = process_vm_readv(pid, &rc_l, 1, &rc_r, 1, 0);
                    if (rrd >= 64) {
                        for (size_t cj = 0; cj < fsz && off+cj+5 < scan_sz; cj++) {
                            if (code[off+cj] != 0xE8) continue;
                            int32_t cd; memcpy(&cd, &code[off+cj+1], 4);
                            uintptr_t ct = scan_lo + off + cj + 5 + (int64_t)cd;
                            for (size_t rj = 0; rj + 5 <= (size_t)rrd; rj++) {
                                if (rc[rj] != 0xE8) continue;
                                int32_t rd; memcpy(&rd, &rc[rj+1], 4);
                                uintptr_t rt = out.resume + rj + 5 + (int64_t)rd;
                                if (ct == rt) { score += 10; goto settop_xv_done; }
                            }
                        }
                        settop_xv_done:;
                    }
                }

                if (score > best_score) { best_score = score; best_addr = addr; best_fsz = fsz; }
            }

            if (best_addr && best_score >= 15) {
                out.settop = best_addr;
                LOG_INFO("[direct-hook] proximity: lua_settop=0x{:X} ({}B, score={}, CROSS-VALIDATED)",
                         best_addr, best_fsz, best_score);
            } else if (best_addr) {
                LOG_WARN("[direct-hook] proximity lua_settop candidate 0x{:X} rejected (score={})",
                         best_addr, best_score);
            }
            break;
        }
    }

        // Validate luau_load: must be from the same Luau copy as lua_resume.
    // Functions from the wrong copy use different lock implementations,
    // GOT entries, and internal helpers — causing deadlocks at step 2.
    if (out.load && out.resume) {
        int64_t ld = static_cast<int64_t>(out.load) - static_cast<int64_t>(out.resume);
        if (ld < 0) ld = -ld;
        if (static_cast<uint64_t>(ld) > 0x2800000ULL) { // >40MB
            LOG_WARN("[direct-hook] luau_load at 0x{:X} is {:.0f}MB from lua_resume "
                     "0x{:X} — wrong Luau copy, clearing for proximity re-scan",
                     out.load, ld / (1024.0 * 1024.0), out.resume);
            out.load = 0;
        }
    }

        // Proximity string-ref re-scan for luau_load near lua_resume
    // Strings (.rodata) can be mapped far from code (.text), so search
    // ALL readable regions for strings but only nearby exec regions for xrefs.
    if (!out.load && out.resume) {
        LOG_INFO("[direct-hook] luau_load: proximity string-ref scan "
                 "(strings=all regions, xrefs=±80MB of lua_resume)");
        const char* load_needles[] = {
            "bytecode version mismatch", "truncated", nullptr
        };
        for (int si = 0; load_needles[si] && !out.load; si++) {
            const char* needle = load_needles[si];
            size_t nlen = strlen(needle);
            for (const auto& r : regions) {
                if (out.load) break;
                if (!r.readable() || r.size() < nlen) continue;
                // No distance filter here — .rodata can be anywhere
                size_t scan_len = std::min(r.size(), static_cast<size_t>(0x4000000));
                std::vector<uint8_t> pat(needle, needle + nlen);
                std::string mask_s(nlen, 'x');
                auto hit = memory_.pattern_scan(pat, mask_s, r.start, scan_len);
                if (!hit) continue;
                uintptr_t str_addr = *hit;
                LOG_DEBUG("[direct-hook] found '{}' at 0x{:X} near lua_resume",
                          needle, str_addr);
                for (const auto& xr : regions) {
                    if (out.load) break;
                    if (!xr.readable() || !xr.executable() || xr.size() < 7) continue;
                    int64_t xdist = static_cast<int64_t>(xr.start) -
                                    static_cast<int64_t>(out.resume);
                    if (xdist < -0x2800000LL || xdist > 0x2800000LL) continue;
                    size_t xscan = std::min(xr.size(), static_cast<size_t>(0x4000000));
                    constexpr size_t LR_CHK = 4096;
                    std::vector<uint8_t> lrbuf(LR_CHK + 16);
                    for (size_t lroff = 0; lroff + 7 <= xscan && !out.load;
                         lroff += LR_CHK) {
                        size_t avail = xscan - lroff;
                        size_t rdsz = std::min(avail, LR_CHK + static_cast<size_t>(7));
                        struct iovec lrl = {lrbuf.data(), rdsz};
                        struct iovec lrr = {reinterpret_cast<void*>(xr.start + lroff), rdsz};
                        if (process_vm_readv(pid, &lrl, 1, &lrr, 1, 0) !=
                            static_cast<ssize_t>(rdsz)) continue;
                        for (size_t li = 0; li + 7 <= rdsz && !out.load; li++) {
                            bool xf = false;
                                                        // LEA or MOV reg,[rip+disp32] (0x8D=LEA, 0x8B=MOV)
                            if ((lrbuf[li]==0x8D || lrbuf[li]==0x8B) && (lrbuf[li+1]&0xC7)==0x05) {
                                int32_t d; memcpy(&d, &lrbuf[li+2], 4);
                                if (xr.start+lroff+li+6+(int64_t)d == str_addr) xf=true;
                            }
                            // REX + LEA/MOV reg,[rip+disp32]
                            if (!xf && lrbuf[li]>=0x40 && lrbuf[li]<=0x4F &&
                                (lrbuf[li+1]==0x8D || lrbuf[li+1]==0x8B) && (lrbuf[li+2]&0xC7)==0x05) {
                                int32_t d; memcpy(&d, &lrbuf[li+3], 4);
                                if (xr.start+lroff+li+7+(int64_t)d == str_addr) xf=true;
                            }
                            // MOVABS reg, imm64 — absolute address in immediate
                            if (!xf && li + 10 <= rdsz &&
                                lrbuf[li]>=0x48 && lrbuf[li]<=0x4F &&
                                lrbuf[li+1]>=0xB8 && lrbuf[li+1]<=0xBF) {
                                uintptr_t imm; memcpy(&imm, &lrbuf[li+2], 8);
                                if (imm == str_addr) xf=true;
                            }
                            if (!xf) continue;
                            uintptr_t xa = xr.start + lroff + li;
                            uintptr_t lim = (xa > 4096) ? xa - 4096 : 0;
                            for (uintptr_t p = xa-1; p >= lim && !out.load; p--) {
                                uint8_t w[8];
                                struct iovec wl={w,8};
                                struct iovec wr_v={reinterpret_cast<void*>(p),8};
                                if (process_vm_readv(pid,&wl,1,&wr_v,1,0)!=8) continue;
                                bool cand = false;
                                if (w[0]==0xF3&&w[1]==0x0F&&w[2]==0x1E&&w[3]==0xFA&&
                                    w[4]==0x55) cand=true;
                                else if (w[0]==0x55&&w[1]==0x48&&w[2]==0x89&&
                                         w[3]==0xE5) cand=true;
                                else if (w[0]==0x55 && p > lim) {
                                    uint8_t pv; struct iovec pvl={&pv,1};
                                    struct iovec pvr={reinterpret_cast<void*>(p-1),1};
                                    if (process_vm_readv(pid,&pvl,1,&pvr,1,0)==1 &&
                                        (pv==0xC3||pv==0xCC||pv==0x90)) cand=true;
                                } else if (w[0]==0x53 && p > lim) {
                                    uint8_t pv; struct iovec pvl={&pv,1};
                                    struct iovec pvr={reinterpret_cast<void*>(p-1),1};
                                    if (process_vm_readv(pid,&pvl,1,&pvr,1,0)==1 &&
                                        (pv==0xC3||pv==0xCC||pv==0x90)) cand=true;
                                } else if (w[0]==0x41&&w[1]>=0x54&&w[1]<=0x57 &&
                                           p > lim) {
                                    uint8_t pv; struct iovec pvl={&pv,1};
                                    struct iovec pvr={reinterpret_cast<void*>(p-1),1};
                                    if (process_vm_readv(pid,&pvl,1,&pvr,1,0)==1 &&
                                        (pv==0xC3||pv==0xCC||pv==0x90)) cand=true;
                                }
                                if (!cand) continue;
                                if (p==out.resume || p==out.settop ||
                                    p==out.newthread) continue;
                                uint8_t ib[64];
                                size_t ia = std::min(static_cast<size_t>(xa+32-p),
                                                     sizeof(ib));
                                struct iovec il={ib,ia};
                                struct iovec ir_v={reinterpret_cast<void*>(p),ia};
                                if (process_vm_readv(pid,&il,1,&ir_v,1,0) !=
                                    static_cast<ssize_t>(ia)) continue;
                                size_t dec=0; int cnt=0;
                                while (dec+15<=ia && dec<32) {
                                    size_t insn=dh_insn_len(ib+dec);
                                    if (insn==0||dec+insn>ia) break;
                                    dec+=insn; cnt++;
                                }
                                if (cnt >= 3) {
                                    out.load = p;
                                    int64_t fd = static_cast<int64_t>(p) -
                                                 static_cast<int64_t>(out.resume);
                                    if (fd < 0) fd = -fd;
                                    LOG_INFO("[direct-hook] proximity string-ref: "
                                             "luau_load at 0x{:X} ({:.1f}MB from "
                                             "lua_resume)", p, fd/(1024.0*1024.0));
                                }
                            }
                        }
                    }
                }
            }
        }
        if (!out.load)
            LOG_WARN("[direct-hook] luau_load proximity re-scan found nothing "
                     "near lua_resume");
    }

    // Fallback: proximity signature scan for luau_load near lua_resume.
    // Finds large 3+ arg functions that share CALL targets with lua_resume.
    // Works when string-ref fails (GOT refs, different .rodata layout, etc.)
    if (!out.load && out.resume) {
        LOG_INFO("[direct-hook] luau_load: proximity signature scan "
                 "(cross-validated with lua_resume)");
        std::vector<uintptr_t> resume_calls;
        {
            uint8_t rc[1024];
            struct iovec rl = {rc, 1024};
            struct iovec rr_v = {reinterpret_cast<void*>(out.resume), 1024};
            ssize_t rrd = process_vm_readv(pid, &rl, 1, &rr_v, 1, 0);
            if (rrd >= 64) {
                for (size_t j = 0; j + 5 <= static_cast<size_t>(rrd); j++) {
                    if (rc[j] != 0xE8) continue;
                    int32_t rd; memcpy(&rd, &rc[j+1], 4);
                    uintptr_t t = out.resume + j + 5 + static_cast<int64_t>(rd);
                    bool dup = false;
                    for (auto& ex : resume_calls)
                        if (ex == t) { dup = true; break; }
                    if (!dup) resume_calls.push_back(t);
                }
            }
        }
        LOG_DEBUG("[direct-hook] lua_resume has {} unique CALL targets for "
                  "cross-validation", resume_calls.size());
        if (!resume_calls.empty()) {
            int best_score = -1;
            uintptr_t best_addr = 0;
            size_t best_fsz = 0;
            int best_shared = 0;
            for (const auto& r : regions) {
                if (out.load) break;
                if (!r.readable() || !r.executable()) continue;
                int64_t rd0 = static_cast<int64_t>(r.start) -
                              static_cast<int64_t>(out.resume);
                int64_t rd1 = static_cast<int64_t>(r.end) -
                              static_cast<int64_t>(out.resume);
                if (!((rd0 > -0x2800000LL && rd0 < 0x2800000LL) ||
                      (rd1 > -0x2800000LL && rd1 < 0x2800000LL))) continue;
                size_t scan_sz = std::min(r.size(),
                                          static_cast<size_t>(0x4000000));
                std::vector<uint8_t> code(scan_sz);
                struct iovec lli = {code.data(), scan_sz};
                struct iovec lri = {reinterpret_cast<void*>(r.start), scan_sz};
                if (process_vm_readv(pid, &lli, 1, &lri, 1, 0) !=
                    static_cast<ssize_t>(scan_sz)) continue;
                for (size_t off = 1; off + 500 < scan_sz; off++) {
                    if (code[off-1]!=0xC3 && code[off-1]!=0xCC &&
                        code[off-1]!=0x90) continue;
                    uintptr_t addr = r.start + off;
                    if (addr==out.resume || addr==out.settop ||
                        addr==out.newthread || addr==out.sandbox) continue;
                    size_t p = off;
                    if (p+3<scan_sz && code[p]==0xF3 && code[p+1]==0x0F &&
                        code[p+2]==0x1E && code[p+3]==0xFA) p += 4;
                    if (p >= scan_sz) continue;
                    if (!(code[p]==0x55 || code[p]==0x53 ||
                          (code[p]==0x41 && p+1<scan_sz &&
                           code[p+1]>=0x54 && code[p+1]<=0x57) ||
                          (code[p]==0x48 && p+2<scan_sz &&
                           code[p+1]==0x83 && code[p+2]==0xEC)))
                        continue;
                    bool sr_di=false, sr_si=false, sr_dx=false;
                    for (size_t j=0; j<30 && off+j+2<scan_sz; j++) {
                        size_t i = off+j;
                        if (code[i]==0x89 && (code[i+1]&0x38)==0x38) sr_di=true;
                        if ((code[i]==0x48||code[i]==0x49) &&
                            code[i+1]==0x89 && (code[i+2]&0x38)==0x38) sr_di=true;
                        if (code[i]==0x89 && (code[i+1]&0x38)==0x30) sr_si=true;
                        if ((code[i]==0x48||code[i]==0x49) &&
                            code[i+1]==0x89 && (code[i+2]&0x38)==0x30) sr_si=true;
                        if (code[i]==0x89 && (code[i+1]&0x38)==0x10) sr_dx=true;
                        if ((code[i]==0x48||code[i]==0x49) &&
                            code[i+1]==0x89 && (code[i+2]&0x38)==0x10) sr_dx=true;
                    }
                    if (!sr_di || !sr_si || !sr_dx) continue;
                    int calls = 0;
                    size_t fsz = 0;
                    for (size_t j=0; j<2000 && off+j+5<scan_sz; j++) {
                        if (code[off+j]==0xE8) calls++;
                        if (code[off+j]==0xC3 && j>=200) { fsz=j+1; break; }
                    }
                    if (fsz < 200 || calls < 5) continue;
                    int shared = 0;
                    for (size_t j=0; j<fsz && off+j+5<scan_sz; j++) {
                        if (code[off+j]!=0xE8) continue;
                        int32_t cd; memcpy(&cd, &code[off+j+1], 4);
                        uintptr_t ct = r.start+off+j+5+static_cast<int64_t>(cd);
                        for (auto& rt : resume_calls)
                            if (ct == rt) { shared++; break; }
                    }
                    if (shared < 2) continue;
                    int score = shared*5 + (fsz>=500?3:0) + (calls>=8?2:0);
                    if (score > best_score) {
                        best_score=score; best_addr=addr;
                        best_fsz=fsz; best_shared=shared;
                    }
                }
            }
            if (best_addr && best_score >= 12) {
                out.load = best_addr;
                int64_t fd = static_cast<int64_t>(best_addr) -
                             static_cast<int64_t>(out.resume);
                if (fd < 0) fd = -fd;
                LOG_INFO("[direct-hook] proximity signature: luau_load=0x{:X} "
                         "({}B, {} shared targets, score={}, {:.1f}MB from "
                         "lua_resume, CROSS-VALIDATED)",
                         best_addr, best_fsz, best_shared, best_score,
                         fd / (1024.0 * 1024.0));
            } else if (best_addr) {
                LOG_WARN("[direct-hook] proximity signature: candidate 0x{:X} "
                         "rejected (score={}, need >=12)", best_addr, best_score);
            }
        }
    }

    
    uintptr_t active_lock = 0;
    if (out.settop) {
        uint8_t stbuf[256];
        struct iovec stl = {stbuf, sizeof(stbuf)};
        struct iovec str = {reinterpret_cast<void*>(out.settop), sizeof(stbuf)};
        ssize_t strd = process_vm_readv(pid, &stl, 1, &str, 1, 0);
        if (strd >= 40) {
            size_t st_read = static_cast<size_t>(strd);

            // ═══════════════════════════════════════════════════════════
            // Instruction-decoded boundary detection.
            //
            // Previous approach: scan for C3 followed by a known prologue
            // byte (0x55, 0x53, 0xCC, etc.). This FAILS when the next
            // function starts with an unrecognized byte (e.g., 0x48 8B,
            // 0x8A, mov instructions) — giving boundary=buffer_size.
            //
            // New approach: decode instructions with dh_insn_len from
            // the function start until we hit a RET (0xC3). This finds
            // the EXACT function end regardless of what follows.
            // lua_settop is a simple ~65B function with one exit point.
            // ═══════════════════════════════════════════════════════════
            size_t st_fend = 0;
            {
                size_t pos = 0;
                while (pos + 15 < st_read && pos < 250) {
                    size_t il = dh_insn_len(stbuf + pos);
                    if (il == 0) {
                        LOG_DEBUG("[direct-hook] lua_settop decode failed at offset {}", pos);
                        break;
                    }
                    if (stbuf[pos] == 0xC3) {
                        st_fend = pos + 1;
                        break;
                    }
                    if (il == 2 && stbuf[pos] == 0xF3 &&
                        pos + 1 < st_read && stbuf[pos + 1] == 0xC3) {
                        st_fend = pos + 2;
                        LOG_DEBUG("[direct-hook] lua_settop: REP RET at offset {}", pos);
                        break;
                    }
                    pos += il;
                }
            }

            if (st_fend == 0) {
                // Fallback: byte-pattern boundary detection
                st_fend = st_read;
                for (size_t si = 20; si + 1 < st_read; si++) {
                    if (stbuf[si] != 0xC3) continue;
                    uint8_t nx = stbuf[si + 1];
                    if (nx == 0xCC || nx == 0x90 || nx == 0x55 || nx == 0x53 ||
                        nx == 0x56 || nx == 0x57 || nx == 0xF3 || nx == 0x00 ||
                        (nx == 0x41 && si + 2 < st_read &&
                         stbuf[si + 2] >= 0x50 && stbuf[si + 2] <= 0x57) ||
                        (nx == 0x48 && si + 2 < st_read && stbuf[si + 2] == 0x83 &&
                         si + 3 < st_read && stbuf[si + 3] == 0xEC)) {
                        st_fend = si + 1;
                        break;
                    }
                }
                LOG_DEBUG("[direct-hook] lua_settop body: {}/{} bytes (byte-pattern fallback)",
                          st_fend, st_read);
            } else {
                LOG_DEBUG("[direct-hook] lua_settop body: {}/{} bytes (instruction-decoded)",
                          st_fend, st_read);
            }

            bool boundary_found = (st_fend > 0 && st_fend < st_read);

            // Collect ALL E8 CALL targets within the decoded function body.
            // lua_settop (simple Luau API) calls exactly: lua_lock, body
            // helpers, lua_unlock. We identify lock (first) and unlock
            // (last non-lock) from a reliable set.
            std::vector<std::pair<size_t, uintptr_t>> st_calls;
            if (boundary_found) {
                for (size_t i = 0; i + 5 <= st_fend; i++) {
                    if (stbuf[i] != 0xE8) continue;
                    int32_t d; memcpy(&d, &stbuf[i + 1], 4);
                    uintptr_t target = out.settop + i + 5 + static_cast<int64_t>(d);
                    st_calls.push_back({i, target});
                }
                LOG_DEBUG("[direct-hook] lua_settop has {} CALL instructions in {} bytes",
                          st_calls.size(), st_fend);
            }

            // First CALL = lua_lock
            if (!st_calls.empty()) {
                active_lock = st_calls.front().second;
                LOG_INFO("[direct-hook] active_lock extracted from lua_settop+{}: 0x{:X}",
                         st_calls.front().first, active_lock);
            }
// Unlock extraction removed — trampoline handles re-entrant
            // lua_lock calls by executing the real function body.
        }
    }
        if (active_lock) {
        if (out.lock_fn && out.lock_fn != active_lock) {
            LOG_WARN("[direct-hook] overriding stale lock_fn 0x{:X} → 0x{:X} "
                     "(lua_settop is authoritative)", out.lock_fn, active_lock);
        }
        out.lock_fn = active_lock;
        LOG_INFO("[direct-hook] lock_fn set to active_lock 0x{:X}", active_lock);
    }
    // ═══════════════════════════════════════════════════════════════
    // Validate lua_resume calls active_lock.
    // lua_resume is a Lua C API function — it MUST call lua_lock.
    // If it calls a DIFFERENT lock, it's from a dead/wrong Luau copy
    // whose mutex may be uninitialized or corrupted.  The trampoline
    // calls lua_resume at step 3; a wrong-copy lua_resume would
    // deadlock on the stale mutex even with global unlock bypass.
    // ═══════════════════════════════════════════════════════════════
    if (out.resume && active_lock) {
        uint8_t resume_scan_buf[800];
        size_t resume_scan_len = sizeof(resume_scan_buf);
        struct iovec rsl = {resume_scan_buf, resume_scan_len};
        struct iovec rsr = {reinterpret_cast<void*>(out.resume), resume_scan_len};
        ssize_t rrd = process_vm_readv(pid, &rsl, 1, &rsr, 1, 0);
        bool resume_calls_active_lock = false;
        if (rrd >= 50) {
            size_t resume_fend = static_cast<size_t>(rrd);
            for (size_t ri = 25; ri + 1 < resume_fend; ri++) {
                if (resume_scan_buf[ri] != 0xC3) continue;
                uint8_t nx = resume_scan_buf[ri + 1];
                if (nx == 0xCC || nx == 0x90 || nx == 0x55 ||
                    nx == 0x53 || nx == 0xF3 || nx == 0x00 ||
                    (nx == 0x41 && ri + 2 < resume_fend &&
                     resume_scan_buf[ri + 2] >= 0x54 &&
                     resume_scan_buf[ri + 2] <= 0x57)) {
                    resume_fend = ri + 1;
                    break;
                }
            }
            for (size_t ri = 0; ri + 5 <= resume_fend; ri++) {
                if (resume_scan_buf[ri] != 0xE8) continue;
                int32_t rd;
                memcpy(&rd, &resume_scan_buf[ri + 1], 4);
                uintptr_t rt = out.resume + ri + 5 +
                               static_cast<int64_t>(rd);
                if (rt == active_lock) {
                    resume_calls_active_lock = true;
                    LOG_INFO("[direct-hook] lua_resume confirmed — calls "
                             "active_lock at +{}", ri);
                    break;
                }
            }
            if (!resume_calls_active_lock) {
                for (size_t ri = 0; ri + 5 <= std::min(resume_fend,
                     static_cast<size_t>(50)); ri++) {
                    if (resume_scan_buf[ri] != 0xE8) continue;
                    int32_t rd;
                    memcpy(&rd, &resume_scan_buf[ri + 1], 4);
                    uintptr_t rt = out.resume + ri + 5 +
                                   static_cast<int64_t>(rd);
                    if (rt == active_lock) break;
                    uint8_t hop_buf[30];
                    struct iovec hl = {hop_buf, 30};
                    struct iovec hr = {reinterpret_cast<void*>(rt), 30};
                    if (process_vm_readv(pid, &hl, 1, &hr, 1, 0) == 30) {
                        for (int hi = 0; hi < 25; hi++) {
                            if (hop_buf[hi] != 0xE8) continue;
                            int32_t hd;
                            memcpy(&hd, &hop_buf[hi + 1], 4);
                            uintptr_t ht = rt + hi + 5 +
                                           static_cast<int64_t>(hd);
                            if (ht == active_lock) {
                                resume_calls_active_lock = true;
                                LOG_INFO("[direct-hook] lua_resume "
                                         "confirmed — reaches active_lock "
                                         "via one-hop through 0x{:X} at "
                                         "+{}", rt, ri);
                            }
                            break;
                        }
                    }
                    break;
                }
            }
        }
        if (!resume_calls_active_lock) {
            LOG_WARN("[direct-hook] lua_resume at 0x{:X} does NOT call "
                     "active_lock 0x{:X} — wrong Luau copy, clearing for "
                     "lock-anchored re-scan", out.resume, active_lock);
            out.resume = 0;

            LOG_INFO("[direct-hook] lua_resume: lock-anchored re-scan "
                     "(active_lock=0x{:X})", active_lock);
            int best_rscore = -1;
            uintptr_t best_raddr = 0;
            size_t best_rfsz = 0;
            for (const auto& r : regions) {
                if (best_raddr && best_rscore >= 30) break;
                if (!r.readable() || !r.executable()) continue;
                if (r.size() < 512) continue;
                int64_t rd0 = static_cast<int64_t>(r.start) -
                              static_cast<int64_t>(active_lock);
                if (rd0 < -0x2800000LL || rd0 > 0x2800000LL) continue;
                if (out.resume) {
                    int64_t rdr = static_cast<int64_t>(r.start) -
                                  static_cast<int64_t>(out.resume);
                    int64_t rdr_e = static_cast<int64_t>(r.end) -
                                    static_cast<int64_t>(out.resume);
                    bool near_resume = (rdr > -0xA00000LL && rdr < 0xA00000LL) ||
                                       (rdr_e > -0xA00000LL && rdr_e < 0xA00000LL);
                    if (!near_resume) continue;
                }
                size_t scan_sz = std::min(r.size(),
                                          static_cast<size_t>(0x4000000));
                std::vector<uint8_t> code(scan_sz);
                struct iovec sli = {code.data(), scan_sz};
                struct iovec sri = {reinterpret_cast<void*>(r.start),
                                    scan_sz};
                if (process_vm_readv(pid, &sli, 1, &sri, 1, 0) !=
                    static_cast<ssize_t>(scan_sz)) continue;
                for (size_t off = 1; off + 800 < scan_sz; off++) {
                    if (code[off - 1] != 0xC3 && code[off - 1] != 0xCC &&
                        code[off - 1] != 0x90) continue;
                    uintptr_t addr = r.start + off;
                    if (addr == out.settop || addr == out.newthread ||
                        addr == out.load) continue;
                    size_t p = off;
                    if (p + 3 < scan_sz && code[p] == 0xF3 &&
                        code[p + 1] == 0x0F && code[p + 2] == 0x1E &&
                        code[p + 3] == 0xFA) p += 4;
                    if (p >= scan_sz) continue;
                    if (!(code[p] == 0x55 || code[p] == 0x53 ||
                          (code[p] == 0x41 && p + 1 < scan_sz &&
                           code[p + 1] >= 0x54 &&
                           code[p + 1] <= 0x57) ||
                          (code[p] == 0x48 && p + 2 < scan_sz &&
                           code[p + 1] == 0x83 &&
                           code[p + 2] == 0xEC)))
                        continue;
                    bool has_lock = false;
                    for (size_t fi = 0; fi < 80 && off + fi + 5 <= scan_sz;
                         fi++) {
                        if (code[off + fi] != 0xE8) continue;
                        int32_t fd;
                        memcpy(&fd, &code[off + fi + 1], 4);
                        uintptr_t ft = r.start + off + fi + 5 +
                                       static_cast<int64_t>(fd);
                        if (ft == active_lock) {
                            has_lock = true;
                            break;
                        }
                        if (!has_lock) {
                            uint8_t hb[30];
                            struct iovec hbl = {hb, 30};
                            struct iovec hbr = {
                                reinterpret_cast<void*>(ft), 30};
                            if (process_vm_readv(pid, &hbl, 1, &hbr, 1,
                                                 0) == 30) {
                                for (int hi = 0; hi < 25; hi++) {
                                    if (hb[hi] != 0xE8) continue;
                                    int32_t hd;
                                    memcpy(&hd, &hb[hi + 1], 4);
                                    uintptr_t ht = ft + hi + 5 +
                                        static_cast<int64_t>(hd);
                                    if (ht == active_lock) has_lock = true;
                                    break;
                                }
                            }
                        }
                        break;
                    }
                    if (!has_lock) continue;
                    bool sr_di = false, sr_si = false, sr_dx = false;
                    int calls = 0;
                    size_t fsz = 0;
                    for (size_t j = 0; j < 800 && off + j + 5 < scan_sz;
                         j++) {
                        size_t i = off + j;
                        if (code[i] == 0xE8) calls++;
                        if (j < 30 && i + 2 < scan_sz) {
                            if (code[i] == 0x89 &&
                                (code[i + 1] & 0x38) == 0x38)
                                sr_di = true;
                            if ((code[i] == 0x48 || code[i] == 0x49) &&
                                code[i + 1] == 0x89 &&
                                (code[i + 2] & 0x38) == 0x38)
                                sr_di = true;
                            if (code[i] == 0x89 &&
                                (code[i + 1] & 0x38) == 0x30)
                                sr_si = true;
                            if ((code[i] == 0x48 || code[i] == 0x49) &&
                                code[i + 1] == 0x89 &&
                                (code[i + 2] & 0x38) == 0x30)
                                sr_si = true;
                            if (code[i] == 0x89 &&
                                (code[i + 1] & 0x38) == 0x10)
                                sr_dx = true;
                            if ((code[i] == 0x48 || code[i] == 0x49) &&
                                code[i + 1] == 0x89 &&
                                (code[i + 2] & 0x38) == 0x10)
                                sr_dx = true;
                            if (code[i] == 0x48 && code[i + 1] == 0x63 &&
                                (code[i + 2] & 0xC7) == 0xC6)
                                sr_si = true;
                        }
                        if (code[i] == 0xC3 && j >= 300) {
                            fsz = j + 1;
                            break;
                        }
                    }
                    if (!sr_di || !sr_si) continue;
                    if (fsz < 300 || fsz > 900 || calls < 8) continue;
                    int score = 20;
                    if (sr_dx) score += 5;
                    if (calls >= 10) score += 3;
                    if (fsz >= 400 && fsz <= 700) score += 3;
                    if (out.settop) {
                        uint8_t stc[100];
                        struct iovec stl = {stc, 100};
                        struct iovec str_v = {
                            reinterpret_cast<void*>(out.settop), 100};
                        if (process_vm_readv(pid, &stl, 1, &str_v, 1,
                                             0) >= 50) {
                            for (size_t si = 0;
                                 si + 5 <= 100 && score < 40; si++) {
                                if (stc[si] != 0xE8) continue;
                                int32_t sd;
                                memcpy(&sd, &stc[si + 1], 4);
                                uintptr_t st2 = out.settop + si + 5 +
                                    static_cast<int64_t>(sd);
                                for (size_t cj = 0;
                                     cj < fsz && off + cj + 5 < scan_sz;
                                     cj++) {
                                    if (code[off + cj] != 0xE8) continue;
                                    int32_t cd;
                                    memcpy(&cd, &code[off + cj + 1], 4);
                                    uintptr_t ct = r.start + off + cj + 5
                                        + static_cast<int64_t>(cd);
                                    if (ct == st2) {
                                        score += 10;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if (score > best_rscore) {
                        best_rscore = score;
                        best_raddr = addr;
                        best_rfsz = fsz;
                    }
                }
            }
            if (best_raddr && best_rscore >= 25) {
                out.resume = best_raddr;
                LOG_INFO("[direct-hook] lock-anchored: lua_resume=0x{:X} "
                         "({}B, score={}, calls active_lock VERIFIED)",
                         best_raddr, best_rfsz, best_rscore);

                if (out.settop) {
                    bool st_ok = false;
                    int64_t st_dist = static_cast<int64_t>(out.settop) -
                                     static_cast<int64_t>(best_raddr);
                    if (st_dist < 0) st_dist = -st_dist;
                    if (static_cast<uint64_t>(st_dist) > 0x2800000ULL) {
                        LOG_WARN("[direct-hook] lua_settop 0x{:X} is {:.0f}MB "
                                 "from new lua_resume 0x{:X} — wrong copy",
                                 out.settop, st_dist / (1024.0 * 1024.0),
                                 best_raddr);
                    } else {
                        uint8_t st_chk[100];
                        struct iovec scl = {st_chk, 100};
                        struct iovec scr = {reinterpret_cast<void*>(out.settop), 100};
                        if (process_vm_readv(pid, &scl, 1, &scr, 1, 0) >= 50) {
                            for (size_t si = 0; si + 5 <= 100; si++) {
                                if (st_chk[si] != 0xE8) continue;
                                int32_t sd;
                                memcpy(&sd, &st_chk[si + 1], 4);
                                uintptr_t st_t = out.settop + si + 5 +
                                                 static_cast<int64_t>(sd);
                                if (st_t == active_lock) {
                                    st_ok = true;
                                    LOG_INFO("[direct-hook] lua_settop 0x{:X} "
                                             "calls active_lock — valid",
                                             out.settop);
                                    break;
                                }
                                uint8_t hb[25];
                                struct iovec hl = {hb, 25};
                                struct iovec hr = {reinterpret_cast<void*>(st_t), 25};
                                if (process_vm_readv(pid, &hl, 1, &hr, 1, 0) == 25) {
                                    for (int hi = 0; hi < 20; hi++) {
                                        if (hb[hi] != 0xE8) continue;
                                        int32_t hd;
                                        memcpy(&hd, &hb[hi + 1], 4);
                                        uintptr_t ht = st_t + hi + 5 +
                                                       static_cast<int64_t>(hd);
                                        if (ht == active_lock) {
                                            st_ok = true;
                                            LOG_INFO("[direct-hook] lua_settop "
                                                     "0x{:X} reaches active_lock "
                                                     "via one-hop", out.settop);
                                        }
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                        if (!st_ok) {
                            LOG_WARN("[direct-hook] lua_settop 0x{:X} does NOT "
                                     "call active_lock — wrong copy", out.settop);
                        }
                    }
                    if (!st_ok) {
                        LOG_INFO("[direct-hook] clearing stale lua_settop "
                                 "0x{:X}", out.settop);
                        out.settop = 0;
                    }
                }

                if (!out.settop) {
                    LOG_INFO("[direct-hook] lua_settop: lock-anchored re-scan "
                             "(active_lock=0x{:X}, near lua_resume=0x{:X})",
                             active_lock, best_raddr);
                    int best_st_score = -1;
                    uintptr_t best_st_addr = 0;
                    size_t best_st_fsz = 0;
                    for (const auto& r : regions) {
                        if (best_st_addr && best_st_score >= 20) break;
                        if (!r.readable() || !r.executable()) continue;
                        if (r.size() < 256) continue;
                        int64_t rd0 = static_cast<int64_t>(r.start) -
                                      static_cast<int64_t>(active_lock);
                        if (rd0 < -0x2800000LL || rd0 > 0x2800000LL) continue;
                        size_t scan_sz = std::min(r.size(),
                                                  static_cast<size_t>(0x4000000));
                        std::vector<uint8_t> code(scan_sz);
                        struct iovec sli = {code.data(), scan_sz};
                        struct iovec sri = {reinterpret_cast<void*>(r.start),
                                            scan_sz};
                        if (process_vm_readv(pid, &sli, 1, &sri, 1, 0) !=
                            static_cast<ssize_t>(scan_sz)) continue;
                        for (size_t off = 1; off + 260 < scan_sz; off++) {
                            if (code[off - 1] != 0xC3 &&
                                code[off - 1] != 0xCC &&
                                code[off - 1] != 0x90) continue;
                            uintptr_t addr = r.start + off;
                            if (addr == best_raddr || addr == out.newthread ||
                                addr == out.load) continue;
                            size_t p = off;
                            if (p + 3 < scan_sz && code[p] == 0xF3 &&
                                code[p + 1] == 0x0F && code[p + 2] == 0x1E &&
                                code[p + 3] == 0xFA) p += 4;
                            if (p >= scan_sz) continue;
                            if (!(code[p] == 0x55 || code[p] == 0x53 ||
                                  (code[p] == 0x41 && p + 1 < scan_sz &&
                                   code[p + 1] >= 0x54 &&
                                   code[p + 1] <= 0x57))) continue;
                            bool has_alock = false;
                            for (size_t fi = 0;
                                 fi < 60 && off + fi + 5 <= scan_sz; fi++) {
                                if (code[off + fi] != 0xE8) continue;
                                int32_t fd;
                                memcpy(&fd, &code[off + fi + 1], 4);
                                uintptr_t ft = r.start + off + fi + 5 +
                                               static_cast<int64_t>(fd);
                                if (ft == active_lock) {
                                    has_alock = true;
                                    break;
                                }
                                uint8_t hb[25];
                                struct iovec hbl = {hb, 25};
                                struct iovec hbr = {
                                    reinterpret_cast<void*>(ft), 25};
                                if (process_vm_readv(pid, &hbl, 1, &hbr, 1,
                                                     0) == 25) {
                                    for (int hi = 0; hi < 20; hi++) {
                                        if (hb[hi] != 0xE8) continue;
                                        int32_t hd;
                                        memcpy(&hd, &hb[hi + 1], 4);
                                        uintptr_t ht = ft + hi + 5 +
                                            static_cast<int64_t>(hd);
                                        if (ht == active_lock)
                                            has_alock = true;
                                        break;
                                    }
                                }
                                break;
                            }
                            if (!has_alock) continue;
                            bool sr_di = false, sr_si = false, sr_dx = false;
                            int calls = 0;
                            size_t fsz = 0;
                            for (size_t j = 0;
                                 j < 250 && off + j + 8 < scan_sz; j++) {
                                size_t i = off + j;
                                if (code[i] == 0xE8) calls++;
                                if (j < 20 && i + 2 < scan_sz) {
                                    if (code[i] == 0x89 &&
                                        (code[i + 1] & 0x38) == 0x38)
                                        sr_di = true;
                                    if ((code[i] == 0x48 ||
                                         code[i] == 0x49) &&
                                        code[i + 1] == 0x89 &&
                                        (code[i + 2] & 0x38) == 0x38)
                                        sr_di = true;
                                    if (code[i] == 0x89 &&
                                        (code[i + 1] & 0x38) == 0x30)
                                        sr_si = true;
                                    if ((code[i] == 0x48 ||
                                         code[i] == 0x49) &&
                                        code[i + 1] == 0x89 &&
                                        (code[i + 2] & 0x38) == 0x30)
                                        sr_si = true;
                                    if (code[i] == 0x48 &&
                                        code[i + 1] == 0x63 &&
                                        (code[i + 2] & 0xC7) == 0xC6)
                                        sr_si = true;
                                    if (code[i] == 0x89 &&
                                        (code[i + 1] & 0x38) == 0x10)
                                        sr_dx = true;
                                    if ((code[i] == 0x48 ||
                                         code[i] == 0x49) &&
                                        code[i + 1] == 0x89 &&
                                        (code[i + 2] & 0x38) == 0x10)
                                        sr_dx = true;
                                }
                                if (code[i] == 0xC3 && j >= 20) {
                                    fsz = j + 1;
                                    break;
                                }
                            }
                            if (!sr_di || !sr_si || sr_dx) continue;
                            if (fsz < 30 || fsz > 250 || calls < 1 ||
                                calls > 8) continue;
                            int score = 10;
                            if (calls >= 1 && calls <= 4) score += 2;
                            if (fsz >= 40 && fsz <= 150) score += 2;
                            {
                                uint8_t rc[1024];
                                struct iovec rcl = {rc, 1024};
                                struct iovec rcr = {
                                    reinterpret_cast<void*>(best_raddr),
                                    1024};
                                ssize_t rrd = process_vm_readv(
                                    pid, &rcl, 1, &rcr, 1, 0);
                                if (rrd >= 64) {
                                    for (size_t cj = 0;
                                         cj < fsz &&
                                         off + cj + 5 < scan_sz; cj++) {
                                        if (code[off + cj] != 0xE8)
                                            continue;
                                        int32_t cd;
                                        memcpy(&cd,
                                               &code[off + cj + 1], 4);
                                        uintptr_t ct = r.start + off +
                                            cj + 5 +
                                            static_cast<int64_t>(cd);
                                        for (size_t rj = 0;
                                             rj + 5 <=
                                             static_cast<size_t>(rrd);
                                             rj++) {
                                            if (rc[rj] != 0xE8) continue;
                                            int32_t rd2;
                                            memcpy(&rd2, &rc[rj + 1], 4);
                                            uintptr_t rt = best_raddr +
                                                rj + 5 +
                                                static_cast<int64_t>(rd2);
                                            if (ct == rt) {
                                                score += 10;
                                                goto st_rescan_xv_done;
                                            }
                                        }
                                    }
                                    st_rescan_xv_done:;
                                }
                            }
                            if (score > best_st_score) {
                                best_st_score = score;
                                best_st_addr = addr;
                                best_st_fsz = fsz;
                            }
                        }
                    }
                    if (best_st_addr && best_st_score >= 15) {
                        out.settop = best_st_addr;
                        int64_t sd2 = static_cast<int64_t>(best_st_addr) -
                                     static_cast<int64_t>(best_raddr);
                        if (sd2 < 0) sd2 = -sd2;
                        LOG_INFO("[direct-hook] lock-anchored: lua_settop="
                                 "0x{:X} ({}B, score={}, {:.1f}MB from "
                                 "lua_resume, VERIFIED)",
                                 best_st_addr, best_st_fsz,
                                 best_st_score, sd2 / (1024.0 * 1024.0));
                    } else if (best_st_addr) {
                        LOG_WARN("[direct-hook] lock-anchored settop "
                                 "candidate 0x{:X} rejected (score={})",
                                 best_st_addr, best_st_score);
                    } else {
                        LOG_WARN("[direct-hook] lock-anchored re-scan "
                                 "found no lua_settop calling active_lock");
                    }
                }

                if (out.settop) {
                    active_lock = 0;
                    uint8_t stbuf2[256];
                    struct iovec stl2 = {stbuf2, sizeof(stbuf2)};
                    struct iovec str2 = {reinterpret_cast<void*>(out.settop),
                                         sizeof(stbuf2)};
                    ssize_t strd2 = process_vm_readv(pid, &stl2, 1,
                                                      &str2, 1, 0);
                    if (strd2 >= 40) {
                        size_t st2_fend = 0;
                        {
                            size_t pos = 0;
                            size_t st2_read = static_cast<size_t>(strd2);
                            while (pos + 15 < st2_read && pos < 250) {
                                size_t il = dh_insn_len(stbuf2 + pos);
                                if (il == 0) break;
                                if (stbuf2[pos] == 0xC3) {
                                    st2_fend = pos + 1;
                                    break;
                                }
                                pos += il;
                            }
                        }
                        if (st2_fend > 0) {
                            for (size_t i = 0; i + 5 <= st2_fend; i++) {
                                if (stbuf2[i] != 0xE8) continue;
                                int32_t d;
                                memcpy(&d, &stbuf2[i + 1], 4);
                                uintptr_t t = out.settop + i + 5 +
                                              static_cast<int64_t>(d);
                                active_lock = t;
                                LOG_INFO("[direct-hook] re-extracted "
                                         "active_lock=0x{:X} from new "
                                         "lua_settop+{}", t, i);
                                break;
                            }
                        }
                    }
                    if (active_lock) {
                        out.lock_fn = active_lock;
                    }
                }
            } else if (best_raddr) {
                LOG_WARN("[direct-hook] lock-anchored lua_resume candidate "
                         "0x{:X} rejected (score={}, need >=25)",
                         best_raddr, best_rscore);
            } else {
                LOG_WARN("[direct-hook] lock-anchored re-scan found no "
                         "lua_resume calling active_lock 0x{:X}",
                         active_lock);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Validate luau_load calls active_lock.
    // ═══════════════════════════════════════════════════════════════
    if (out.load && active_lock) {
        uint8_t load_head[200];
        struct iovec lhl = {load_head, sizeof(load_head)};
        struct iovec lhr = {reinterpret_cast<void*>(out.load),
                            sizeof(load_head)};
        bool load_calls_active_lock = false;
        ssize_t lhrd = process_vm_readv(pid, &lhl, 1, &lhr, 1, 0);
        if (lhrd >= 50) {
            for (size_t li = 0; li + 5 <= static_cast<size_t>(lhrd); li++) {
                if (load_head[li] != 0xE8) continue;
                int32_t ld;
                memcpy(&ld, &load_head[li + 1], 4);
                uintptr_t lt = out.load + li + 5 + static_cast<int64_t>(ld);
                if (lt == active_lock) {
                    load_calls_active_lock = true;
                    LOG_INFO("[direct-hook] luau_load confirmed — calls "
                             "active_lock at +{}", li);
                    break;
                }
                if (!load_calls_active_lock && li < 80) {
                    uint8_t hop[30];
                    struct iovec hpl = {hop, 30};
                    struct iovec hpr = {reinterpret_cast<void*>(lt), 30};
                    if (process_vm_readv(pid, &hpl, 1, &hpr, 1, 0) == 30) {
                        for (int hi = 0; hi < 25; hi++) {
                            if (hop[hi] != 0xE8) continue;
                            int32_t hd;
                            memcpy(&hd, &hop[hi + 1], 4);
                            uintptr_t ht = lt + hi + 5 +
                                           static_cast<int64_t>(hd);
                            if (ht == active_lock) {
                                load_calls_active_lock = true;
                                LOG_INFO("[direct-hook] luau_load confirmed"
                                         " — reaches active_lock via "
                                         "one-hop through 0x{:X} at +{}",
                                         lt, li);
                            }
                            break;
                        }
                    }
                }
                if (load_calls_active_lock) break;
            }
        }
        if (!load_calls_active_lock) {
            int64_t load_dist = static_cast<int64_t>(out.load) -
                                static_cast<int64_t>(active_lock);
            if (load_dist < 0) load_dist = -load_dist;
            LOG_WARN("[direct-hook] luau_load at 0x{:X} does NOT call "
                     "active_lock 0x{:X} ({:.1f}MB away) — wrong Luau "
                     "copy, clearing for lock-anchored re-scan",
                     out.load, active_lock,
                     load_dist / (1024.0 * 1024.0));
            out.load = 0;

            LOG_INFO("[direct-hook] luau_load: lock-anchored re-scan "
                     "(active_lock=0x{:X})", active_lock);
            int best_lscore = -1;
            uintptr_t best_laddr = 0;
            size_t best_lfsz = 0;
            int best_lcalls = 0;
            for (const auto& r : regions) {
                if (out.load) break;
                if (!r.readable() || !r.executable()) continue;
                if (r.size() < 512) continue;
                int64_t rd0 = static_cast<int64_t>(r.start) -
                              static_cast<int64_t>(active_lock);
                if (rd0 < -0x2800000LL || rd0 > 0x2800000LL) continue;
                size_t scan_sz = std::min(r.size(),
                                          static_cast<size_t>(0x4000000));
                std::vector<uint8_t> code(scan_sz);
                struct iovec lli = {code.data(), scan_sz};
                struct iovec lri = {reinterpret_cast<void*>(r.start),
                                    scan_sz};
                if (process_vm_readv(pid, &lli, 1, &lri, 1, 0) !=
                    static_cast<ssize_t>(scan_sz)) continue;
                for (size_t off = 1; off + 500 < scan_sz; off++) {
                    if (code[off - 1] != 0xC3 && code[off - 1] != 0xCC &&
                        code[off - 1] != 0x90) continue;
                    uintptr_t addr = r.start + off;
                    if (addr == out.resume || addr == out.settop ||
                        addr == out.newthread || addr == out.sandbox)
                        continue;
                    size_t p = off;
                    if (p + 3 < scan_sz && code[p] == 0xF3 &&
                        code[p + 1] == 0x0F && code[p + 2] == 0x1E &&
                        code[p + 3] == 0xFA) p += 4;
                    if (p >= scan_sz) continue;
                    if (!(code[p] == 0x55 || code[p] == 0x53 ||
                          (code[p] == 0x41 && p + 1 < scan_sz &&
                           code[p + 1] >= 0x54 &&
                           code[p + 1] <= 0x57) ||
                          (code[p] == 0x48 && p + 2 < scan_sz &&
                           code[p + 1] == 0x83 &&
                           code[p + 2] == 0xEC)))
                        continue;
                    bool has_alock = false;
                    for (size_t fi = 0; fi < 100 && off + fi + 5 <= scan_sz;
                         fi++) {
                        if (code[off + fi] != 0xE8) continue;
                        int32_t fd;
                        memcpy(&fd, &code[off + fi + 1], 4);
                        uintptr_t ft = r.start + off + fi + 5 +
                                       static_cast<int64_t>(fd);
                        if (ft == active_lock) { has_alock = true; break; }
                        uint8_t hb[30];
                        struct iovec hbl = {hb, 30};
                        struct iovec hbr = {
                            reinterpret_cast<void*>(ft), 30};
                        if (process_vm_readv(pid, &hbl, 1, &hbr, 1,
                                             0) == 30) {
                            for (int hi = 0; hi < 25; hi++) {
                                if (hb[hi] != 0xE8) continue;
                                int32_t hd;
                                memcpy(&hd, &hb[hi + 1], 4);
                                uintptr_t ht = ft + hi + 5 +
                                    static_cast<int64_t>(hd);
                                if (ht == active_lock) has_alock = true;
                                break;
                            }
                        }
                        break;
                    }
                    if (!has_alock) continue;
                    bool sr_di = false, sr_si = false, sr_dx = false;
                    int calls = 0;
                    size_t fsz = 0;
                    for (size_t j = 0; j < 2000 && off + j + 5 < scan_sz;
                         j++) {
                        size_t i = off + j;
                        if (code[i] == 0xE8) calls++;
                        if (j < 30 && i + 2 < scan_sz) {
                            if (code[i] == 0x89 &&
                                (code[i + 1] & 0x38) == 0x38)
                                sr_di = true;
                            if ((code[i] == 0x48 || code[i] == 0x49) &&
                                code[i + 1] == 0x89 &&
                                (code[i + 2] & 0x38) == 0x38)
                                sr_di = true;
                            if (code[i] == 0x89 &&
                                (code[i + 1] & 0x38) == 0x30)
                                sr_si = true;
                            if ((code[i] == 0x48 || code[i] == 0x49) &&
                                code[i + 1] == 0x89 &&
                                (code[i + 2] & 0x38) == 0x30)
                                sr_si = true;
                            if (code[i] == 0x89 &&
                                (code[i + 1] & 0x38) == 0x10)
                                sr_dx = true;
                            if ((code[i] == 0x48 || code[i] == 0x49) &&
                                code[i + 1] == 0x89 &&
                                (code[i + 2] & 0x38) == 0x10)
                                sr_dx = true;
                        }
                        if (code[i] == 0xC3 && j >= 200) {
                            fsz = j + 1;
                            break;
                        }
                    }
                    if (!sr_di || !sr_si) continue;
                    if (!sr_dx && (fsz < 400 || calls < 8)) continue;
                    if (fsz < 200 || calls < 5) continue;
                    int shared = 0;
                    if (out.settop) {
                        uint8_t stbuf[100];
                        struct iovec stbl = {stbuf, 100};
                        struct iovec stbr = {
                            reinterpret_cast<void*>(out.settop), 100};
                        if (process_vm_readv(pid, &stbl, 1, &stbr, 1,
                                             0) >= 50) {
                            for (size_t si2 = 0; si2 + 5 <= 100; si2++) {
                                if (stbuf[si2] != 0xE8) continue;
                                int32_t sd;
                                memcpy(&sd, &stbuf[si2 + 1], 4);
                                uintptr_t stt = out.settop + si2 + 5 +
                                    static_cast<int64_t>(sd);
                                for (size_t cj = 0;
                                     cj < fsz && off + cj + 5 < scan_sz;
                                     cj++) {
                                    if (code[off + cj] != 0xE8) continue;
                                    int32_t cd;
                                    memcpy(&cd, &code[off + cj + 1], 4);
                                    uintptr_t ct = r.start + off + cj + 5
                                        + static_cast<int64_t>(cd);
                                    if (ct == stt) { shared++; break; }
                                }
                            }
                        }
                    }
                    int score = 20 + shared * 5 + (fsz >= 500 ? 3 : 0) +
                                (calls >= 8 ? 2 : 0);
                    if (score > best_lscore) {
                        best_lscore = score;
                        best_laddr = addr;
                        best_lfsz = fsz;
                        best_lcalls = calls;
                    }
                }
            }
            if (best_laddr && best_lscore >= 25) {
                out.load = best_laddr;
                int64_t fd = static_cast<int64_t>(best_laddr) -
                             static_cast<int64_t>(active_lock);
                if (fd < 0) fd = -fd;
                LOG_INFO("[direct-hook] lock-anchored: luau_load=0x{:X} "
                         "({}B, {} calls, score={}, {:.1f}MB from "
                         "active_lock, VERIFIED)",
                         best_laddr, best_lfsz, best_lcalls, best_lscore,
                         fd / (1024.0 * 1024.0));
            } else if (best_laddr) {
                LOG_WARN("[direct-hook] lock-anchored luau_load candidate "
                         "0x{:X} rejected (score={}, need >=25)",
                         best_laddr, best_lscore);
            } else {
                LOG_WARN("[direct-hook] lock-anchored re-scan found no "
                         "luau_load calling active_lock 0x{:X}",
                         active_lock);
            }
        }
    }


    // ═══════════════════════════════════════════════════════════════
    // FINAL GATE: validate lua_newthread reaches active_lock via its
    // FIRST call (direct) or first call's first call (one-hop).
    // Dead-copy functions have their first CALL targeting dead lua_lock
    // (different address) which hangs on a stale/corrupted mutex.
    // A later call may coincidentally resolve to active_lock, but the
    // function EXECUTES the first call FIRST, causing step-1 deadlock.
    // ═══════════════════════════════════════════════════════════════
    if (out.newthread && active_lock) {
        uint8_t ntfv[40];
        struct iovec nfl = {ntfv, 40};
        struct iovec nfr = {reinterpret_cast<void*>(out.newthread), 40};
        bool gate_pass = false;
        if (process_vm_readv(pid, &nfl, 1, &nfr, 1, 0) == 40) {
            for (int fi = 0; fi < 35; fi++) {
                if (ntfv[fi] != 0xE8) continue;
                int32_t fd; memcpy(&fd, &ntfv[fi+1], 4);
                uintptr_t t1 = out.newthread + fi + 5 + static_cast<int64_t>(fd);
                if (t1 == active_lock) {
                    gate_pass = true;
                    LOG_INFO("[direct-hook] FINAL GATE: lua_newthread 0x{:X} first CALL "
                             "directly targets active_lock — PASS", out.newthread);
                } else {
                    // One-hop: does t1 itself call active_lock as ITS first call?
                    uint8_t hop[25];
                    struct iovec hl = {hop, 25};
                    struct iovec hr = {reinterpret_cast<void*>(t1), 25};
                    if (process_vm_readv(pid, &hl, 1, &hr, 1, 0) == 25) {
                        for (int hi = 0; hi < 20; hi++) {
                            if (hop[hi] != 0xE8) continue;
                            int32_t hd; memcpy(&hd, &hop[hi+1], 4);
                            uintptr_t t2 = t1 + hi + 5 + static_cast<int64_t>(hd);
                            if (t2 == active_lock) {
                                gate_pass = true;
                                LOG_INFO("[direct-hook] FINAL GATE: lua_newthread 0x{:X} "
                                         "reaches active_lock via one-hop through 0x{:X} — PASS",
                                         out.newthread, t1);
                            } else {
                                LOG_WARN("[direct-hook] FINAL GATE: lua_newthread 0x{:X} "
                                         "first CALL→0x{:X}, whose first CALL→0x{:X} "
                                         "(neither is active_lock 0x{:X})",
                                         out.newthread, t1, t2, active_lock);
                            }
                            break;
                        }
                    }
                }
                break;  // MUST stop at first E8 — that's what executes first
            }
        }

        if (!gate_pass) {
            LOG_WARN("[direct-hook] FINAL GATE: lua_newthread 0x{:X} REJECTED — "
                     "dead copy (first call chain does not reach active_lock)",
                     out.newthread);
            out.newthread = 0;

            // Rescue scan: search ±80MB from lua_resume for functions with
            // the known lua_newthread prologue whose first CALL (or one-hop)
            // reaches active_lock. Prologue is consistent across all Luau
            // copies: push rbp; mov rbp,rsp; push rbx; push rax; mov rbx,rdi
            if (out.resume) {
                LOG_INFO("[direct-hook] rescue: prologue-pattern scan near lua_resume "
                         "for active lua_newthread");
                // Also accept ENDBR64 prefix variant
                const uint8_t pro9[] = {0x55,0x48,0x89,0xE5,0x53,0x50,0x48,0x89,0xFB};
                uintptr_t best_addr = 0;
                int64_t best_dist = INT64_MAX;
                for (const auto& r : regions) {
                    if (best_addr) break;
                    if (!r.readable() || !r.executable() || r.size() < 512) continue;
                    int64_t rd = static_cast<int64_t>(r.start) -
                                 static_cast<int64_t>(out.resume);
                    if (rd < -0x2800000LL || rd > 0x2800000LL) continue;
                    size_t scan_sz = std::min(r.size(),
                                              static_cast<size_t>(0x4000000));
                    std::vector<uint8_t> code(scan_sz);
                    struct iovec rsl = {code.data(), scan_sz};
                    struct iovec rsr = {reinterpret_cast<void*>(r.start), scan_sz};
                    if (process_vm_readv(pid, &rsl, 1, &rsr, 1, 0) !=
                        static_cast<ssize_t>(scan_sz)) continue;
                    for (size_t off = 1; off + sizeof(pro9) + 30 < scan_sz; off++) {
                        // Must be at a function boundary
                        uint8_t prev = code[off - 1];
                        if (prev != 0xC3 && prev != 0xCC && prev != 0x90) continue;
                        // Check for prologue (with optional ENDBR64 prefix)
                        size_t pro_off = off;
                        if (pro_off + 4 + sizeof(pro9) + 20 < scan_sz &&
                            code[pro_off]==0xF3 && code[pro_off+1]==0x0F &&
                            code[pro_off+2]==0x1E && code[pro_off+3]==0xFA)
                            pro_off += 4;
                        if (pro_off + sizeof(pro9) + 20 >= scan_sz) continue;
                        if (memcmp(&code[pro_off], pro9, sizeof(pro9)) != 0) continue;
                        uintptr_t cand = r.start + off;
                        if (cand == out.resume || cand == out.settop ||
                            cand == out.load) continue;
                        // Find first E8 after prologue
                        for (size_t ci = pro_off - off + sizeof(pro9);
                             ci < pro_off - off + sizeof(pro9) + 20 &&
                             off + ci + 5 < scan_sz; ci++) {
                            if (code[off + ci] != 0xE8) continue;
                            int32_t cd; memcpy(&cd, &code[off + ci + 1], 4);
                            uintptr_t ct = cand + ci + 5 + static_cast<int64_t>(cd);
                            if (ct == active_lock) {
                                int64_t d = static_cast<int64_t>(cand) -
                                            static_cast<int64_t>(out.resume);
                                if (d < 0) d = -d;
                                if (d < best_dist) {
                                    best_dist = d;
                                    best_addr = cand;
                                }
                            } else {
                                // One-hop check
                                uint8_t rh[25];
                                struct iovec rhl = {rh, 25};
                                struct iovec rhr = {reinterpret_cast<void*>(ct), 25};
                                if (process_vm_readv(pid, &rhl, 1, &rhr, 1, 0) == 25) {
                                    for (int rhi = 0; rhi < 20; rhi++) {
                                        if (rh[rhi] != 0xE8) continue;
                                        int32_t rhd; memcpy(&rhd, &rh[rhi+1], 4);
                                        uintptr_t rt2 = ct + rhi + 5 +
                                                         static_cast<int64_t>(rhd);
                                        if (rt2 == active_lock) {
                                            int64_t d = static_cast<int64_t>(cand) -
                                                        static_cast<int64_t>(out.resume);
                                            if (d < 0) d = -d;
                                            if (d < best_dist) {
                                                best_dist = d;
                                                best_addr = cand;
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                            break;  // only check first E8
                        }
                    }
                }
                if (best_addr) {
                    out.newthread = best_addr;
                    out.lock_fn = active_lock;
                                        // Unlock extraction deferred to authoritative cross-validation block.
                    // The rescue newthread is now validated (calls active_lock), so the
                    // cross-validation between it and lua_resume will find the correct unlock.
                    LOG_INFO("[direct-hook] rescue: lua_newthread=0x{:X} "
                             "({:.1f}MB from lua_resume, prologue+lock verified)",
                             best_addr, best_dist / (1024.0 * 1024.0));
                } else {
                    LOG_WARN("[direct-hook] rescue: no prologue-matching function "
                             "near lua_resume reaches active_lock");
                }
            }
        }
    }

        // ═══════════════════════════════════════════════════════════════
    // AUTHORITATIVE UNLOCK EXTRACTION via cross-validation.
    //
    // Previous approach (last CALL in lua_resume) FAILED because
    // lua_resume is 577 bytes with dozens of internal CALL instructions
    // — the last by offset is a helper function, not lua_unlock.
    //
    // New approach: find the CALL target that appears in MULTIPLE
    // validated Luau API functions (lua_resume, lua_newthread, etc.),
    // is NOT active_lock, and starts with a valid function prologue.
    // lua_unlock is the only function (besides lua_lock) that ALL
    // Luau API functions call — it's the universal pair.
    //
    // Strategy layers:
    // 1. Cross-validate between lua_newthread (small, simple) and
    //    lua_resume: shared target that isn't active_lock = unlock
    // 2. Instruction-decoded lua_newthread: last CALL before RET
    // 3. Instruction-decoded lua_settop (if CHUNK 1 found it)
    // ═══════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════
    // Unlock extraction removed — no longer needed.
    // The trampoline's guard path now executes the real lua_lock
    // for re-entrant calls. Each API function handles its own
    // lock/unlock pair correctly, whether lua_unlock is a function
    // call or compiler-inlined.
    // ═══════════════════════════════════════════════════════════════

    if (active_lock && !out.unlock_fn) {
        int32_t gs_off = 0, mx_off = 0;
        uintptr_t pml_addr = 0;
        bool internals_ok = extract_lock_internals(pid, active_lock, gs_off, mx_off, pml_addr);

        if (!internals_ok) {
            LOG_WARN("[direct-hook] structured extraction failed — trying "
                     "inlined unlock extraction from lua_settop body");
            if (out.settop) {
                uint8_t stcode[256];
                struct iovec sl = {stcode, sizeof(stcode)};
                struct iovec sr = {reinterpret_cast<void*>(out.settop), sizeof(stcode)};
                ssize_t srd = process_vm_readv(pid, &sl, 1, &sr, 1, 0);
                if (srd >= 40) {
                    size_t st_len = static_cast<size_t>(srd);
                    size_t st_fend = 0;
                    {
                        size_t p = 0;
                        while (p + 15 < st_len && p < 250) {
                            size_t il = dh_insn_len(stcode + p);
                            if (il == 0) break;
                            if (stcode[p] == 0xC3) { st_fend = p + 1; break; }
                            p += il;
                        }
                    }
                    if (st_fend > 10) {
                        size_t lock_call_end = 0;
                        for (size_t i = 0; i + 5 <= st_fend; i++) {
                            if (stcode[i] == 0xE8) {
                                int32_t d;
                                memcpy(&d, &stcode[i + 1], 4);
                                uintptr_t t = out.settop + i + 5 + static_cast<int64_t>(d);
                                if (t == active_lock) {
                                    lock_call_end = i + 5;
                                    break;
                                }
                            }
                        }
                        if (lock_call_end > 0 && lock_call_end + 10 < st_fend) {
                            size_t unlock_start = lock_call_end;
                            size_t unlock_end = st_fend - 1;
                            for (size_t i = unlock_start; i + 4 < unlock_end; i++) {
                                bool has_rw = (stcode[i] >= 0x48 && stcode[i] <= 0x4F);
                                size_t ri = has_rw ? i + 1 : i;
                                if (ri + 2 < unlock_end && stcode[ri] == 0x8B) {
                                    uint8_t modrm = stcode[ri + 1];
                                    uint8_t rm = modrm & 7;
                                    uint8_t mod = (modrm >> 6) & 3;
                                    if (rm == 3 && mod != 3) {
                                        if (mod == 1 && ri + 3 <= unlock_end) {
                                            gs_off = static_cast<int8_t>(stcode[ri + 2]);
                                            LOG_DEBUG("[direct-hook] inlined: global load "
                                                      "[rbx+{}] at settop+{}", gs_off, i);
                                        } else if (mod == 2 && ri + 6 <= unlock_end) {
                                            memcpy(&gs_off, &stcode[ri + 2], 4);
                                            LOG_DEBUG("[direct-hook] inlined: global load "
                                                      "[rbx+{}] at settop+{}", gs_off, i);
                                        } else if (mod == 0) {
                                            gs_off = 0;
                                            LOG_DEBUG("[direct-hook] inlined: global load "
                                                      "[rbx] at settop+{}", i);
                                        } else {
                                            continue;
                                        }
                                        for (size_t j = i + 3; j + 5 < unlock_end; j++) {
                                            if (stcode[j] == 0xE8) {
                                                int32_t d;
                                                memcpy(&d, &stcode[j + 1], 4);
                                                pml_addr = out.settop + j + 5 +
                                                           static_cast<int64_t>(d);
                                                if (pml_addr == active_lock) {
                                                    pml_addr = 0;
                                                    continue;
                                                }
                                                LOG_DEBUG("[direct-hook] inlined: found "
                                                          "call 0x{:X} at settop+{}",
                                                          pml_addr, j);
                                                break;
                                            }
                                        }
                                        if (pml_addr != 0 && pml_addr != active_lock) {
                                            for (size_t k = i + 3; k < unlock_end; k++) {
                                                bool krw = (stcode[k] >= 0x48 &&
                                                            stcode[k] <= 0x4F);
                                                size_t ki = krw ? k + 1 : k;
                                                if (ki + 2 < unlock_end && stcode[ki] == 0x8D) {
                                                    uint8_t km = stcode[ki + 1];
                                                    uint8_t kmod = (km >> 6) & 3;
                                                    if (kmod == 1 && ki + 3 <= unlock_end) {
                                                        mx_off = static_cast<int8_t>(stcode[ki + 2]);
                                                        break;
                                                    } else if (kmod == 2 && ki + 6 <= unlock_end) {
                                                        memcpy(&mx_off, &stcode[ki + 2], 4);
                                                        break;
                                                    }
                                                }
                                                if (ki + 3 < unlock_end && stcode[ki] == 0x83 &&
                                                    (stcode[ki + 1] & 0x38) == 0x00) {
                                                    mx_off = static_cast<int8_t>(stcode[ki + 2]);
                                                    break;
                                                }
                                                if (ki + 6 < unlock_end && stcode[ki] == 0x81 &&
                                                    (stcode[ki + 1] & 0x38) == 0x00) {
                                                    memcpy(&mx_off, &stcode[ki + 2], 4);
                                                    break;
                                                }
                                            }
                                            internals_ok = true;
                                            LOG_INFO("[direct-hook] inlined unlock analysis: "
                                                     "global=[rbx+{}] mutex_off={} "
                                                     "pthread_mutex_lock=0x{:X}",
                                                     gs_off, mx_off, pml_addr);
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (!internals_ok) {
            LOG_WARN("[direct-hook] both structured and inlined extraction failed — "
                     "trying brute-force: read first 30 bytes of lua_lock, find any "
                     "MOV from [rdi+X] followed by E8/E9 within 20 bytes");
            uint8_t lk[48];
            struct iovec lkl = {lk, sizeof(lk)};
            struct iovec lkr = {reinterpret_cast<void*>(active_lock), sizeof(lk)};
            ssize_t lkrd = process_vm_readv(pid, &lkl, 1, &lkr, 1, 0);
            if (lkrd >= 20) {
                size_t lk_len = static_cast<size_t>(lkrd);
                for (size_t i = 0; i + 7 < lk_len; i++) {
                    bool has_rw = (lk[i] == 0x48 || lk[i] == 0x4C);
                    if (!has_rw) continue;
                    size_t ri = i + 1;
                    if (ri >= lk_len) continue;
                    if (lk[ri] != 0x8B) continue;
                    if (ri + 1 >= lk_len) continue;
                    uint8_t modrm = lk[ri + 1];
                    uint8_t mod = (modrm >> 6) & 3;
                    uint8_t rm = modrm & 7;
                    if (rm != 7 || mod == 3 || rm == 4) continue;
                    int32_t disp_val = 0;
                    size_t insn_end = 0;
                    if (mod == 1 && ri + 3 <= lk_len) {
                        disp_val = static_cast<int8_t>(lk[ri + 2]);
                        insn_end = ri + 3;
                    } else if (mod == 2 && ri + 6 <= lk_len) {
                        memcpy(&disp_val, &lk[ri + 2], 4);
                        insn_end = ri + 6;
                    } else if (mod == 0) {
                        disp_val = 0;
                        insn_end = ri + 2;
                    } else {
                        continue;
                    }
                    for (size_t j = insn_end; j + 5 <= lk_len && j < insn_end + 25; j++) {
                        if (lk[j] == 0xE8 || lk[j] == 0xE9) {
                            int32_t cd;
                            memcpy(&cd, &lk[j + 1], 4);
                            uintptr_t ct = active_lock + j + 5 + static_cast<int64_t>(cd);
                            gs_off = disp_val;
                            mx_off = 0;
                            pml_addr = ct;
                            for (size_t k = insn_end; k < j; k++) {
                                if (k + 4 <= lk_len && (lk[k] == 0x48 || lk[k] == 0x49) &&
                                    lk[k + 1] == 0x83 && (lk[k + 2] & 0x38) == 0x00) {
                                    mx_off = static_cast<int8_t>(lk[k + 3]);
                                } else if (k + 7 <= lk_len && (lk[k] == 0x48 || lk[k] == 0x49) &&
                                           lk[k + 1] == 0x81 && (lk[k + 2] & 0x38) == 0x00) {
                                    memcpy(&mx_off, &lk[k + 3], 4);
                                } else if (k + 4 <= lk_len && (lk[k] == 0x48 || lk[k] == 0x4C) &&
                                           lk[k + 1] == 0x8D) {
                                    uint8_t lm = lk[k + 2];
                                    uint8_t lmod = (lm >> 6) & 3;
                                    uint8_t lreg = (lm >> 3) & 7;
                                    if (lreg == 7) {
                                        if (lmod == 1 && k + 4 <= lk_len)
                                            mx_off = static_cast<int8_t>(lk[k + 3]);
                                        else if (lmod == 2 && k + 7 <= lk_len)
                                            memcpy(&mx_off, &lk[k + 3], 4);
                                    }
                                }
                            }
                            internals_ok = true;
                            LOG_INFO("[direct-hook] brute-force: global=[rdi+{}] "
                                     "mutex_off={} target=0x{:X}",
                                     gs_off, mx_off, pml_addr);
                            goto brute_done;
                        }
                    }
                }
            }
        }
brute_done:

        if (internals_ok) {
            LOG_INFO("[direct-hook] lock internals extracted: "
                     "global_State offset={}, mutex offset={}, "
                     "pthread_mutex_lock=0x{:X}",
                     gs_off, mx_off, pml_addr);
            out.lock_global_state_offset = gs_off;
            out.lock_mutex_offset = mx_off;
            out.pthread_mutex_lock_addr = pml_addr;

            uintptr_t pmu_addr = 0;
            {
                std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
                std::string line;
                uintptr_t libc_base = 0;
                std::string libc_path;
                while (std::getline(maps, line)) {
                    if (line.find("libc") == std::string::npos &&
                        line.find("musl") == std::string::npos) continue;
                    unsigned long lo, file_off;
                    char perms[5]{};
                    if (sscanf(line.c_str(), "%lx-%*x %4s %lx", &lo, perms, &file_off) == 3 &&
                        file_off == 0 && libc_base == 0) {
                        libc_base = lo;
                        auto slash = line.find('/');
                        if (slash != std::string::npos) {
                            libc_path = line.substr(slash);
                            auto end = libc_path.find_last_not_of(" \n\r\t");
                            if (end != std::string::npos) libc_path = libc_path.substr(0, end + 1);
                        }
                    }
                }
                if (libc_base && !libc_path.empty()) {
                    std::string ns_path = "/proc/" + std::to_string(pid) + "/root" + libc_path;
                    struct stat st;
                    std::string elf_path;
                    if (::stat(ns_path.c_str(), &st) == 0) elf_path = ns_path;
                    else if (::stat(libc_path.c_str(), &st) == 0) elf_path = libc_path;
                    if (!elf_path.empty()) {
                        uintptr_t lock_sym = find_elf_symbol_impl(elf_path, "pthread_mutex_lock");
                        uintptr_t unlock_sym = find_elf_symbol_impl(elf_path, "pthread_mutex_unlock");
                        if (lock_sym && unlock_sym) {
                            int64_t delta = static_cast<int64_t>(pml_addr) -
                                            static_cast<int64_t>(libc_base + lock_sym);
                            if (delta >= -0x100000LL && delta <= 0x100000LL) {
                                pmu_addr = libc_base + unlock_sym + delta;
                            } else {
                                pmu_addr = libc_base + unlock_sym;
                                delta = 0;
                            }
                            LOG_DEBUG("[direct-hook] ELF: lock_sym=0x{:X} unlock_sym=0x{:X} "
                                      "delta={} → remote_unlock=0x{:X}",
                                      lock_sym, unlock_sym, delta, pmu_addr);
                        }
                    }
                }
            }

            if (!pmu_addr) {
                uintptr_t pml_sym = find_remote_symbol(pid, "c", "pthread_mutex_lock");
                if (!pml_sym) pml_sym = find_remote_symbol(pid, "pthread", "pthread_mutex_lock");
                uintptr_t pmu_sym = find_remote_symbol(pid, "c", "pthread_mutex_unlock");
                if (!pmu_sym) pmu_sym = find_remote_symbol(pid, "pthread", "pthread_mutex_unlock");
                if (pml_sym && pmu_sym && pml_addr) {
                    int64_t delta = static_cast<int64_t>(pml_addr) - static_cast<int64_t>(pml_sym);
                    if (delta >= -0x100000LL && delta <= 0x100000LL) {
                        pmu_addr = pmu_sym + delta;
                    } else {
                        pmu_addr = pmu_sym;
                        delta = 0;
                    }
                    LOG_DEBUG("[direct-hook] dlsym: lock_sym=0x{:X} unlock_sym=0x{:X} "
                              "delta={} → remote_unlock=0x{:X}",
                              pml_sym, pmu_sym, delta, pmu_addr);
                } else if (pmu_sym) {
                    pmu_addr = pmu_sym;
                }
            }

            if (!pmu_addr && pml_addr) {
                LOG_INFO("[direct-hook] attempting pthread_mutex_unlock via offset "
                         "heuristic from pthread_mutex_lock=0x{:X}", pml_addr);
                uint8_t lock_head[8];
                struct iovec ph_l = {lock_head, 8};
                struct iovec ph_r = {reinterpret_cast<void*>(pml_addr), 8};
                if (process_vm_readv(pid, &ph_l, 1, &ph_r, 1, 0) == 8) {
                    for (int64_t try_off : {static_cast<int64_t>(0x30), static_cast<int64_t>(0x40),
                                            static_cast<int64_t>(0x50), static_cast<int64_t>(0x60),
                                            static_cast<int64_t>(0x80), static_cast<int64_t>(0x20),
                                            static_cast<int64_t>(-0x30), static_cast<int64_t>(-0x40)}) {
                        uintptr_t cand = pml_addr + try_off;
                        uint8_t cand_head[4];
                        struct iovec cl = {cand_head, 4};
                        struct iovec cr = {reinterpret_cast<void*>(cand), 4};
                        if (process_vm_readv(pid, &cl, 1, &cr, 1, 0) != 4) continue;
                        bool looks_like_func = false;
                        if (cand_head[0] == 0xF3 && cand_head[1] == 0x0F &&
                            cand_head[2] == 0x1E && cand_head[3] == 0xFA)
                            looks_like_func = true;
                        if (cand_head[0] == 0x55) looks_like_func = true;
                        if (cand_head[0] == 0x48 && cand_head[1] == 0x83)
                            looks_like_func = true;
                        if (cand_head[0] == 0x31 || cand_head[0] == 0xB8)
                            looks_like_func = true;
                        if (looks_like_func) {
                            pmu_addr = cand;
                            LOG_INFO("[direct-hook] heuristic: pthread_mutex_unlock "
                                     "candidate at 0x{:X} (offset {} from lock)",
                                     cand, try_off);
                            break;
                        }
                    }
                }
            }

            if (pmu_addr) {
                out.pthread_mutex_unlock_addr = pmu_addr;
                out.lock_internals_valid = true;
                LOG_INFO("[direct-hook] pthread_mutex_unlock=0x{:X} — "
                         "inline unlock available for held-lock hooks",
                         pmu_addr);
            } else {
                LOG_WARN("[direct-hook] pthread_mutex_unlock not found — "
                         "inline unlock unavailable, held-lock hooks will "
                         "deadlock if unlock_fn is also missing");
            }
        } else {
            LOG_WARN("[direct-hook] all lock internals extraction methods failed "
                     "for active_lock 0x{:X}", active_lock);
        }
    }

    if (!out.resume || !out.load || !out.settop) {
        LOG_ERROR("[direct-hook] missing required functions: resume={:#x} load={:#x} settop={:#x}",
                  out.resume, out.load, out.settop);
        return false;
    }
    if (!out.newthread) {
        LOG_ERROR("[direct-hook] lua_newthread not found from active Luau copy — "
                  "cannot create execution threads (direct hook requires lua_newthread)");
        return false;
    }

    // ═══════════════════════════════════════════════════════════════
    // Extract lua_unlock from lua_settop.
    //
    // lua_settop(L, idx) always has the pattern:
    //   CALL lua_lock
    //   ... body (conditional stack manipulation) ...
    //   CALL lua_unlock
    //   RET
    //
    // The LAST E8 call before the first C3 (ret) in lua_settop is
    // lua_unlock. We already decoded lua_settop's boundary using
    // dh_insn_len, so we know exactly which CALL is last.
    // ═══════════════════════════════════════════════════════════════
    if (out.settop && active_lock) {
        uint8_t stbuf_ul[256];
        struct iovec ul_l = {stbuf_ul, sizeof(stbuf_ul)};
        struct iovec ul_r = {reinterpret_cast<void*>(out.settop),
                             sizeof(stbuf_ul)};
        ssize_t ul_rd = process_vm_readv(pid, &ul_l, 1, &ul_r, 1, 0);
        if (ul_rd >= 40) {
            size_t ul_read = static_cast<size_t>(ul_rd);
            size_t ul_fend = 0;
            {
                size_t pos = 0;
                while (pos + 15 < ul_read && pos < 250) {
                    size_t il = dh_insn_len(stbuf_ul + pos);
                    if (il == 0) break;
                    if (stbuf_ul[pos] == 0xC3) {
                        ul_fend = pos + 1;
                        break;
                    }
                    pos += il;
                }
            }
            if (ul_fend == 0) {
                for (size_t si = 20; si + 1 < ul_read; si++) {
                    if (stbuf_ul[si] != 0xC3) continue;
                    uint8_t nx = stbuf_ul[si + 1];
                    if (nx == 0xCC || nx == 0x90 || nx == 0x55 ||
                        nx == 0x53 || nx == 0xF3 || nx == 0x00 ||
                        (nx == 0x41 && si + 2 < ul_read &&
                         stbuf_ul[si + 2] >= 0x50 &&
                         stbuf_ul[si + 2] <= 0x57)) {
                        ul_fend = si + 1;
                        break;
                    }
                }
            }
            if (ul_fend > 10) {
                std::vector<std::pair<size_t, uintptr_t>> ul_calls;
                for (size_t i = 0; i + 5 <= ul_fend; i++) {
                    if (stbuf_ul[i] != 0xE8) continue;
                    int32_t d;
                    memcpy(&d, &stbuf_ul[i + 1], 4);
                    uintptr_t target = out.settop + i + 5 +
                                       static_cast<int64_t>(d);
                    ul_calls.push_back({i, target});
                }
                if (ul_calls.size() >= 2) {
                    uintptr_t last_call = ul_calls.back().second;
                    if (last_call != active_lock) {
                        out.unlock_fn = last_call;
                        LOG_INFO("[direct-hook] lua_unlock at 0x{:X} "
                                 "(last call in lua_settop at +{})",
                                 last_call, ul_calls.back().first);
                    } else if (ul_calls.size() >= 3) {
                        uintptr_t second_last =
                            ul_calls[ul_calls.size() - 2].second;
                        if (second_last != active_lock) {
                            out.unlock_fn = second_last;
                            LOG_INFO("[direct-hook] lua_unlock at "
                                     "0x{:X} (second-last call in "
                                     "lua_settop at +{})",
                                     second_last,
                                     ul_calls[ul_calls.size()-2].first);
                        }
                    }
                }
                if (!out.unlock_fn) {
                    LOG_WARN("[direct-hook] could not extract "
                             "lua_unlock from lua_settop");
                }
            }
        }
    }

    return true;
}

// ═══════════════════════════════════════════════════════════════════
// Phase 1: Fires inside lua_resume prologue (lua_lock HELD).
//          Only captures lua_State*, sets pending flag.  NO Lua calls.
// ═══════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════
// Epilogue Hook: Single lua_resume hook with return-address hijack.
//   ENTRY: Checks mailbox, saves state, swaps return addr → handler.
//   HANDLER: Fires AFTER lua_resume returns (lua_lock RELEASED).
//            Creates thread, loads bytecode, executes, cleans up.
// ═══════════════════════════════════════════════════════════════════
template<typename AddrsType>
static std::vector<uint8_t> gen_entry_trampoline(
    const AddrsType& a, uintptr_t mailbox_addr, uintptr_t cave_addr,
    uintptr_t hook_target, const uint8_t* stolen, size_t stolen_len,
    bool capture_rdi_to_mailbox = false,
    bool hook_held_lock = false,
    bool hook_target_is_settop = false)
{
    std::vector<uint8_t> c;
    c.reserve(640);
    auto e = [&](std::initializer_list<uint8_t> b){ c.insert(c.end(), b); };
    auto e8 = [&](uint8_t v){ c.push_back(v); };
    auto e32= [&](uint32_t v){ for(int i=0;i<4;i++) c.push_back((v>>(i*8))&0xFF); };
    auto e64= [&](uint64_t v){ for(int i=0;i<8;i++) c.push_back((v>>(i*8))&0xFF); };

    // ═══════════════════════════════════════════════════════════════
    // HELD-LOCK HOOK STRATEGY
    //
    // Problem: Hooking lua_lock fails because:
    //   - rdi is NOT lua_State* (it's global_State* or &mutex)
    //   - rbx is unreliable (19000+ callers from GC/scheduler/etc.)
    //   - Captured L from mailbox lets lua_newthread succeed, but
    //     luau_load hangs because the identified function at +32MB
    //     is not actually luau_load
    //
    // Solution: Hook the LIVE lua_settop (rdi=L, 20+ hits/200ms).
    // The live settop is called WITH the Lua global lock held.
    // Our payload calls lua_newthread, luau_load, lua_resume, which
    // each need to acquire/release the lock internally.
    //
    // Design:
    //   1. Capture rdi (= L) into r15
    //   2. Call lua_unlock(L) to release the lock
    //   3. Steps 1-4: lua_newthread, luau_load, lua_resume, settop
    //      (each acquires/releases the lock independently)
    //   4. Call lua_lock(L) to re-acquire for the original settop
    //   5. Execute stolen bytes → continue original settop body
    //
    // The unlock/lock bracketing ensures:
    //   - Our API calls don't deadlock on the already-held lock
    //   - The original settop caller gets the lock re-acquired
    //   - Thread safety is maintained (lock released only briefly)
    // ═══════════════════════════════════════════════════════════════

    // === SAVE ALL REGISTERS ===
    e8(0x9C); // pushfq
    e8(0x50); e8(0x51); e8(0x52); e8(0x56); e8(0x57); // push rax,rcx,rdx,rsi,rdi
    e({0x41,0x50}); e({0x41,0x51}); e({0x41,0x52}); e({0x41,0x53}); // push r8-r11
    e8(0x53); // push rbx
    e({0x41,0x56}); e({0x41,0x57}); // push r14, r15
    e8(0x55); // push rbp
    e({0x48,0x89,0xE5});           // mov rbp, rsp
    e({0x48,0x83,0xE4,0xF0});     // and rsp, -16 (align)

    // rbx = mailbox base address
    e({0x48,0xBB}); e64(mailbox_addr);

    // Phase 1 (capture probe): store rdi into mailbox+0x30
    if (capture_rdi_to_mailbox) {
        e({0x48,0x89,0x7B,0x30}); // mov [rbx+0x30], rdi
    }

    // --- Unconditional hit counter ---
    e({0x66,0xFF,0x43,0x2A});     // inc word [rbx+0x2A]

    // --- Guard check: if guard != 0, skip (re-entrant call) ---
    e({0x80,0x7B,0x28,0x00});     // cmp byte [rbx+0x28], 0
    size_t j_guard = c.size();
    e({0x0F,0x85}); e32(0);       // jnz -> skip_label

    // --- Sequence check: if seq <= ack, skip ---
    e({0x48,0x8B,0x43,0x10});     // mov rax, [rbx+0x10] (seq)
    e({0x48,0x3B,0x43,0x18});     // cmp rax, [rbx+0x18] (ack)
    size_t j_seq = c.size();
    e({0x0F,0x86}); e32(0);       // jbe -> skip_label

    // --- Set guard ---
    e({0xC6,0x43,0x28,0x01});     // mov byte [rbx+0x28], 1

    // --- Capture L into r15 ---
    // rdi IS lua_State* L for all hook targets (live settop, etc.)
    e({0x49,0x89,0xFF});           // mov r15, rdi

        // --- Release the Lua global lock before API calls ---
    // The hooked function was called with the lock held.
    // Release it so our nested API calls (lua_newthread, luau_load, etc.)
    // can acquire/release the lock independently without deadlocking.
    size_t j_no_captured_L = SIZE_MAX;
    if (hook_held_lock) {
        if (a.unlock_fn) {
            e({0x4C,0x89,0xFF});       // mov rdi, r15 (L)
            e({0x48,0xB8}); e64(a.unlock_fn);
            e({0xFF,0xD0});            // call lua_unlock
        } else if (a.lock_internals_valid && a.pthread_mutex_unlock_addr) {
            // Synthesized inline unlock: pthread_mutex_unlock(&(L->global + mutex_offset))
            // Equivalent to the compiler-inlined lua_unlock that exists in the binary.
            // r15 = L (lua_State*). Load L->global into rdi, add mutex offset, call unlock.
            e({0x4C,0x89,0xFF});       // mov rdi, r15 (L)
            if (a.lock_global_state_offset == 0) {
                e({0x48,0x8B,0x3F});   // mov rdi, [rdi]
            } else if (a.lock_global_state_offset >= -128 && a.lock_global_state_offset < 128) {
                e({0x48,0x8B,0x7F});   // mov rdi, [rdi + disp8]
                e8(static_cast<uint8_t>(static_cast<int8_t>(a.lock_global_state_offset)));
            } else {
                e({0x48,0x8B,0xBF});   // mov rdi, [rdi + disp32]
                e32(static_cast<uint32_t>(a.lock_global_state_offset));
            }
            if (a.lock_mutex_offset != 0) {
                if (a.lock_mutex_offset >= -128 && a.lock_mutex_offset < 128) {
                    e({0x48,0x83,0xC7}); // add rdi, disp8
                    e8(static_cast<uint8_t>(static_cast<int8_t>(a.lock_mutex_offset)));
                } else {
                    e({0x48,0x81,0xC7}); // add rdi, disp32
                    e32(static_cast<uint32_t>(a.lock_mutex_offset));
                }
            }
            e({0x48,0xB8}); e64(a.pthread_mutex_unlock_addr);
            e({0xFF,0xD0});            // call pthread_mutex_unlock
        }
    }
    // === STEP 1: lua_newthread(L) — create new thread ===
    size_t j_nt_fail = SIZE_MAX;
    if (a.newthread) {
        e({0xC7,0x43,0x2C,0x01,0x00,0x00,0x00}); // mov dword [rbx+0x2C], 1
        e({0x4C,0x89,0xFF});       // mov rdi, r15  (L)
        e({0x48,0xB8}); e64(a.newthread);
        e({0xFF,0xD0});            // call lua_newthread
        e({0x49,0x89,0xC6});       // mov r14, rax  (new thread)
        e({0x4D,0x85,0xF6});       // test r14, r14
        j_nt_fail = c.size();
        e({0x0F,0x84}); e32(0);   // jz -> ack_label (newthread failed)
    } else {
        e({0xC7,0x43,0x2C,0x01,0x00,0x00,0x00}); // step=1
        e({0x4D,0x89,0xFE});       // mov r14, r15 (use parent thread)
    }

    // === STEP 2: luau_load(thread, chunkname, data, size, env=0) ===
    e({0xC7,0x43,0x2C,0x02,0x00,0x00,0x00}); // mov dword [rbx+0x2C], 2
    e({0x4C,0x89,0xF7});           // mov rdi, r14 (thread)
    size_t chunk_movabs = c.size();
    e({0x48,0xBE}); e64(0);        // mov rsi, <chunk_name_addr> (patched below)
    e({0x48,0x8D,0x53,0x40});     // lea rdx, [rbx+0x40] (data)
    e({0x8B,0x4B,0x20});          // mov ecx, [rbx+0x20] (data_size)
    e({0x45,0x31,0xC0});          // xor r8d, r8d (env=0)
    e({0x48,0xB8}); e64(a.load);
    e({0xFF,0xD0});                // call luau_load
    e({0x85,0xC0});                // test eax, eax
    size_t j_load_fail = c.size();
    e({0x0F,0x85}); e32(0);       // jnz -> settop_label (load failed)

        // === STEP 3: lua_resume(thread, NULL, 0) ===
    e({0xC7,0x43,0x2C,0x03,0x00,0x00,0x00}); // mov dword [rbx+0x2C], 3
    e({0x4C,0x89,0xF7});           // mov rdi, r14 (thread)
    e({0x31,0xF6});                // xor esi, esi (from=NULL)
    e({0x31,0xD2});                // xor edx, edx (nresults=0)
    e({0x48,0xB8}); e64(a.resume); // lua_resume is NOT hooked, call directly
    e({0xFF,0xD0});                // call lua_resume

             // === STEP 4: cleanup — lua_settop(L, -2) to pop the new thread ===
    //
    // CRITICAL: Do NOT call addrs.settop (the dead, lock-validated settop).
    // Even though it calls the correct lua_lock, its INLINED lua_unlock uses
    // struct offsets from a stale Luau compilation — acquiring the mutex but
    // never releasing it, causing every subsequent lua_lock to deadlock.
    //
    // When hook_target IS a settop function, we embed a callable thunk that
    // executes the stolen prologue bytes and jumps into the live settop body
    // (past the hook JMP patch). The live settop's body has correct struct
    // offsets and properly unlocks the mutex.
    //
    // When hook_target is NOT settop (e.g., lua_resume fallback), we skip
    // step 4 entirely. The pushed thread is garbage-collected by Luau's GC.
    // Stack growth is bounded: Roblox creates fresh lua_States regularly,
    // and one extra slot per script execution is negligible vs LUAI_MAXSTACK.
    size_t settop_label = c.size();
    e({0xC7,0x43,0x2C,0x44,0x00,0x00,0x00});
  

       // === Re-acquire Lua global lock after API calls ===
    // The hooked function's caller expects the lock to be held.
    // lua_lock(L) re-acquires it before we execute the stolen bytes
    // and return to the original function body.
    // Note: lock_fn is NOT the hooked function here (we hook settop,
    // not lua_lock), so calling it directly is safe and non-recursive.
    if (hook_held_lock) {
        if (a.lock_fn) {
            e({0x4C,0x89,0xFF});       // mov rdi, r15 (L)
            e({0x48,0xB8}); e64(a.lock_fn);
            e({0xFF,0xD0});            // call lua_lock
        } else if (a.lock_internals_valid && a.pthread_mutex_lock_addr) {
            e({0x4C,0x89,0xFF});       // mov rdi, r15 (L)
            if (a.lock_global_state_offset == 0) {
                e({0x48,0x8B,0x3F});   // mov rdi, [rdi]
            } else if (a.lock_global_state_offset >= -128 && a.lock_global_state_offset < 128) {
                e({0x48,0x8B,0x7F});
                e8(static_cast<uint8_t>(static_cast<int8_t>(a.lock_global_state_offset)));
            } else {
                e({0x48,0x8B,0xBF});
                e32(static_cast<uint32_t>(a.lock_global_state_offset));
            }
            if (a.lock_mutex_offset != 0) {
                if (a.lock_mutex_offset >= -128 && a.lock_mutex_offset < 128) {
                    e({0x48,0x83,0xC7}); // add rdi, disp8
                    e8(static_cast<uint8_t>(static_cast<int8_t>(a.lock_mutex_offset)));
                } else {
                    e({0x48,0x81,0xC7}); // add rdi, disp32
                    e32(static_cast<uint32_t>(a.lock_mutex_offset));
                }
            }
            e({0x48,0xB8}); e64(a.pthread_mutex_lock_addr);
            e({0xFF,0xD0});
        }
    }

    // === STEP 5: acknowledge — set ack = seq, clear guard ===
    size_t ack_label = c.size();
    e({0x48,0x8B,0x43,0x10});     // mov rax, [rbx+0x10] (seq)
    e({0x48,0x89,0x43,0x18});     // mov [rbx+0x18], rax (ack = seq)
    e({0xC7,0x43,0x2C,0x05,0x00,0x00,0x00}); // mov dword [rbx+0x2C], 5
    e({0xC6,0x43,0x28,0x00});     // mov byte [rbx+0x28], 0 (clear guard)

    // === Skip label — restore registers and execute stolen bytes ===
    size_t skip_label = c.size();
    auto patch_j = [&](size_t off, size_t target) {
        int32_t r = static_cast<int32_t>(target - (off + 4));
        memcpy(&c[off], &r, 4);
    };
    // j_guard patched later (needs reentrant_label for lock hooks)
    patch_j(j_seq   + 2, skip_label);
    if (j_nt_fail != SIZE_MAX)
        patch_j(j_nt_fail + 2, ack_label);
    if (j_no_captured_L != SIZE_MAX)
        patch_j(j_no_captured_L + 2, ack_label);
    patch_j(j_load_fail + 2, settop_label);


    // Restore stack and all registers
    e({0x48,0x89,0xEC}); e8(0x5D); // mov rsp, rbp; pop rbp
    e({0x41,0x5F}); e({0x41,0x5E}); e8(0x5B);       // pop r15, r14, rbx
    e({0x41,0x5B}); e({0x41,0x5A}); e({0x41,0x59}); e({0x41,0x58}); // pop r11-r8
    e8(0x5F); e8(0x5E); e8(0x5A); e8(0x59); e8(0x58); // pop rdi,rsi,rdx,rcx,rax
    e8(0x9D); // popfq

        // Execute the stolen prologue bytes from lua_settop
    for (size_t i = 0; i < stolen_len; i++) e8(stolen[i]);

    // Jump back to lua_settop + stolen_len to continue original function
    uintptr_t settop_cont = hook_target + stolen_len;
    int64_t jd = (int64_t)settop_cont - (int64_t)(cave_addr + c.size() + 5);
    if (jd >= INT32_MIN && jd <= INT32_MAX) {
        e8(0xE9); e32((uint32_t)(int32_t)jd);
    } else {
        e({0xFF,0x25,0x00,0x00,0x00,0x00});
        e64(settop_cont);
    }

    // Chunk name string "=oss" embedded in cave
    size_t chunk_name_label = c.size();
    e({0x3D,0x6F,0x73,0x73,0x00}); // "=oss\0"

    // Patch the chunk name movabs to point here
    uintptr_t chunk_abs = cave_addr + chunk_name_label;
    memcpy(&c[chunk_movabs + 2], &chunk_abs, 8);

        // === Re-entrant path for ALL hooks (including lua_lock) ===
    //
    // Previous design: when hooked on lua_lock and guard != 0,
    // the re-entrant lua_lock call was made a no-op via RET.
    // This FAILS when lua_unlock is inlined by the compiler —
    // the inline unlock still executes, releasing a mutex that
    // was never acquired, causing deadlock at step 2.
    //
    // Fixed design: re-entrant lua_lock calls execute NORMALLY.
    // The trampoline intercepted lua_lock BEFORE the mutex was
    // acquired. Each internal API call (lua_newthread, luau_load,
    // lua_resume, lua_settop) acquires the lock via its own
    // lua_lock call, does work, then releases via inline unlock.
    // This works correctly even with non-recursive mutexes:
    //
    //   trampoline entry: lock NOT held (intercepted at prologue)
    //   lua_newthread → lua_lock(acquire) → work → unlock(release)
    //   luau_load     → lua_lock(acquire) → work → unlock(release)
    //   lua_resume    → lua_lock(acquire) → work → unlock(release)
    //   lua_settop    → lua_lock(acquire) → work → unlock(release)
    //   stolen bytes  → real lua_lock body → acquire for original caller
    //
    // No unlock bypass is needed AT ALL.
    patch_j(j_guard + 2, skip_label);

       // NOP stub — single RET used as CALL redirect target by
    // send_via_mailbox to no-op lua_unlock during payload execution.
    e8(0xC3);

    // ═══════════════════════════════════════════════════════════════
    // CLEANUP SETTOP THUNK — callable wrapper for the live hooked settop.
    //
    // This is a standalone function that can be CALL'd from step 4.
    // It reconstructs the original settop entry point by:
    //   1. Executing the stolen prologue bytes (push rbp; mov rbp,rsp; etc.)
    //   2. Jumping to hook_target + stolen_len (past the JMP patch)
    //
    // The live settop body runs normally: lua_lock → adjust stack →
    // lua_unlock (inlined with CORRECT struct offsets) → RET.
    // The RET returns to step 5 in the trampoline (after the CALL).
    //
    // This avoids calling the dead settop whose inlined lua_unlock has
    // stale struct offsets that fail to release the mutex.
    // ═══════════════════════════════════════════════════════════════
    size_t cleanup_thunk_label = 0;
    if (hook_target_is_settop && hook_target != 0 && stolen_len > 0) {
        cleanup_thunk_label = c.size();
        // Emit the stolen prologue bytes
        for (size_t i = 0; i < stolen_len; i++) e8(stolen[i]);
        // Jump to the original function body (past the hook JMP patch)
        uintptr_t thunk_cont = hook_target + stolen_len;
        int64_t thunk_jd = static_cast<int64_t>(thunk_cont) -
                           static_cast<int64_t>(cave_addr + c.size() + 5);
        if (thunk_jd >= INT32_MIN && thunk_jd <= INT32_MAX) {
            e8(0xE9);
            e32(static_cast<uint32_t>(static_cast<int32_t>(thunk_jd)));
        } else {
            e({0xFF,0x25,0x00,0x00,0x00,0x00});
            e64(thunk_cont);
        }
        // Patch step 4's movabs to point to this thunk
        if (step4_settop_movabs != 0) {
            uintptr_t thunk_addr = cave_addr + cleanup_thunk_label;
            memcpy(&c[step4_settop_movabs + 2], &thunk_addr, 8);
        }
    }

    return c;
}


bool Injection::inject_via_direct_hook(pid_t pid) {
    if (dhook_.active) {
        LOG_INFO("[direct-hook] already active, skipping re-hook for PID {}", pid);
        return true;
    }
    LOG_INFO("[direct-hook] starting for PID {}", pid);

    DirectHookAddrs addrs;
    if (!find_remote_luau_functions(pid, addrs)) {
        LOG_ERROR("[direct-hook] failed to find Luau functions");
        return false;
    }

    auto regions = memory_.get_regions();
    uintptr_t mb_addr = 0;
    {
        constexpr size_t MB_SIZE = 16384;
        constexpr size_t PROBE = MB_SIZE + 4096;
        for (auto it = regions.rbegin(); it != regions.rend(); ++it) {
            auto& r = *it;
            if (!r.writable() || !r.readable()) continue;
            if (r.size() < PROBE) continue;
            if (r.path.find("[stack") != std::string::npos) continue;
            if (r.path.find("[vvar") != std::string::npos) continue;
            if (r.path.find("[vdso") != std::string::npos) continue;
            if (!r.path.empty() && r.path[0] == '/') continue;
            uintptr_t check_start = r.end - PROBE;
            check_start &= ~static_cast<uintptr_t>(0xFFF);
            if (check_start < r.start) continue;
            std::vector<uint8_t> probe(MB_SIZE);
            if (!proc_mem_read(pid, check_start, probe.data(), MB_SIZE)) continue;
            bool all_zero = true;
            for (auto b : probe) if (b != 0) { all_zero = false; break; }
            if (all_zero) {
                mb_addr = check_start;
                LOG_INFO("[direct-hook] mailbox at 0x{:X} ({} KB region)", mb_addr, r.size()/1024);
                break;
            }
        }
    }
    if (!mb_addr) {
        LOG_ERROR("[direct-hook] no suitable writable memory for mailbox");
        return false;
    }

    {
        DirectMailbox mb{};
        memcpy(mb.magic, "OSS_DMBOX_V3\0\0\0\0", 16);
        if (!proc_mem_write(pid, mb_addr, &mb, sizeof(DirectMailbox))) {
            LOG_ERROR("[direct-hook] failed to write mailbox");
            return false;
        }
    }

       // Hook lua_settop instead of lua_resume — settop is called constantly
    // by every Lua operation, unlike lua_resume which Roblox may never call
    if (!addrs.settop) {
        LOG_ERROR("[direct-hook] lua_settop not found — cannot hook");
        return false;
    }

    uint8_t prologue[32];
    if (!proc_mem_read(pid, addrs.settop, prologue, sizeof(prologue))) {
        LOG_ERROR("[direct-hook] cannot read lua_settop prologue");
        return false;
    }

    size_t steal = 0;
    while (steal < 5) {
        size_t il = dh_insn_len(prologue + steal);
        if (il == 0 || steal + il > sizeof(prologue)) {
            LOG_ERROR("[direct-hook] cannot decode lua_settop prologue at offset {}", steal);
            return false;
        }
        steal += il;
    }
    LOG_INFO("[direct-hook] stealing {} bytes from lua_settop prologue", steal);

    {
        auto dump = [&](const char* name, uintptr_t addr) {
            uint8_t p[16];
            if (!proc_mem_read(pid, addr, p, sizeof(p))) return;
            LOG_INFO("[direct-hook] {} prologue: "
                     "{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} "
                     "{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
                     name,
                     p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                     p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15]);
        };
        dump("lua_settop", addrs.settop);
        dump("lua_resume", addrs.resume);
        dump("lua_newthread", addrs.newthread);
    }

    std::vector<MemoryRegion> nearby;
    for (const auto& r : regions) {
        int64_t d = (int64_t)r.start - (int64_t)addrs.settop;
        if (d > INT32_MIN && d < INT32_MAX) {
            nearby.push_back(r);
            continue;
        }
        d = (int64_t)r.end - (int64_t)addrs.settop;
        if (d > INT32_MIN && d < INT32_MAX)
            nearby.push_back(r);
    }

    constexpr size_t CAVE_SIZE = 640; // 512 base + cleanup thunk + margin
    ExeRegionInfo cave;
    if (!find_code_cave(pid, nearby, CAVE_SIZE, cave)) {
        LOG_ERROR("[direct-hook] no code cave within +/-2GB of lua_settop");
        return false;
    }
    LOG_INFO("[direct-hook] code cave at 0x{:X} ({} bytes)",
             cave.padding_start, cave.padding_size);

    uintptr_t hook_addr = addrs.settop;
    bool is_lock_hook = false;
    bool hook_needs_unlock = false;
    size_t patch_len = 0;
    uint8_t patch[16] = {};

    auto try_hook_target = [&](uintptr_t target, const char* name,
                                uint8_t* pro, size_t st,
                                bool target_is_settop = true) -> bool {
        auto t = gen_entry_trampoline(addrs, mb_addr, cave.padding_start,
                                       target, pro, st,
                                       false, false, target_is_settop);
        LOG_INFO("[direct-hook] {} trampoline: {} bytes", name, t.size());
        if (t.size() > CAVE_SIZE) return false;
        if (!proc_mem_write(pid, cave.padding_start, t.data(), t.size())) return false;

        uint8_t p[16]; size_t pl;
        int64_t hd = (int64_t)cave.padding_start - (int64_t)(target + 5);
        if (hd >= INT32_MIN && hd <= INT32_MAX && st >= 5) {
            p[0] = 0xE9;
            int32_t r32 = (int32_t)hd;
            memcpy(p + 1, &r32, 4);
            for (size_t i = 5; i < st; i++) p[i] = 0x90;
            pl = st;
        } else if (st >= 14) {
            p[0] = 0xFF; p[1] = 0x25;
            memset(p + 2, 0, 4);
            uintptr_t ca = cave.padding_start;
            memcpy(p + 6, &ca, 8);
            pl = 14;
        } else { return false; }

        if (!proc_mem_write(pid, target, p, pl)) return false;

        // Verify
        uint8_t vf[16] = {};
        if (proc_mem_read(pid, target, vf, pl) && memcmp(vf, p, pl) != 0) {
            LOG_ERROR("[direct-hook] {} patch did not persist", name);
            return false;
        }
        LOG_INFO("[direct-hook] {} patch verified at 0x{:X}", name, target);

                            // Probe: wait and check hit counter.
        // Require ≥10 hits in 1000ms to distinguish live functions
        // (~400+ hits/s for lua_resume) from stale/dead copies that
        // get sporadic hits (~3 in 500ms) then go completely silent.
        // Uses uint16_t at offset 42 to avoid overflow at high call rates.
        uint16_t zh = 0;
        proc_mem_write(pid, mb_addr + 42, &zh, 2);
        usleep(1000000);
        uint16_t hits = 0;
        proc_mem_read(pid, mb_addr + 42, &hits, 2);
        if (hits < 10) {
            LOG_WARN("[direct-hook] {} at 0x{:X} has only {} hits in 1000ms "
                     "(need ≥10) — likely dead/stale code", name, target, hits);
            proc_mem_write(pid, target, pro, st);  // restore prologue
            return false;
        }
        LOG_INFO("[direct-hook] {} probe: {} hits in 1000ms — LIVE!", name, hits);

        // Commit: store stolen bytes and patch for cleanup
        memcpy(prologue, pro, st);
        steal = st;
        patch_len = pl;
        memcpy(patch, p, pl);
        return true;
    };

         // === Attempt 1: lua_settop (lock-anchored, static validation) ===
    bool settop_probe_live = false;
    if (!try_hook_target(addrs.settop, "lua_settop", prologue, steal)) {
        LOG_WARN("[direct-hook] lua_settop at 0x{:X} is dead (0 hits) — "
                 "searching for live settop to hook with unlock/lock bracket",
                 addrs.settop);
        uintptr_t dead_settop_addr = addrs.settop;

        // ═══════════════════════════════════════════════════════════
        // LIVE SETTOP HOOK WITH UNLOCK/LOCK BRACKET
        //
        // The lock-anchored lua_settop (53B) was validated but gets 0
        // hits — it's structurally correct code that Roblox never
        // calls. The "live settop" (95B, 20+ hits) is a different
        // lua_settop variant that IS called. It holds the Lua global
        // lock when called (unlike top-level API functions).
        //
        // Strategy:
        //   1. Find the live settop via probing (same scan as before)
        //   2. Extract lua_unlock from its last CALL instruction
        //   3. Hook it with a trampoline that:
        //      a. Captures rdi (= L, guaranteed by settop signature)
        //      b. Calls lua_unlock(L) to release the held lock
        //      c. Executes steps 1-4 (each acquires/releases lock)
        //      d. Calls lua_lock(L) to re-acquire for caller
        //      e. Executes stolen bytes → continues into settop body
        //
        // This avoids the lua_lock hook entirely — no register
        // guessing, no mutex contention, no wrong-function issues.
        // ═══════════════════════════════════════════════════════════
        int total_probes = 0;
        constexpr int MAX_PROBES = 15;
        uintptr_t best_live_settop = 0;
        int best_live_hits [[maybe_unused]] = 0;

        for (const auto& r : regions) {
            if (best_live_settop) break;
            if (total_probes >= MAX_PROBES) {
                LOG_WARN("[direct-hook] hit probe limit ({}) — stopping "
                         "live-settop search", MAX_PROBES);
                break;
            }
            if (!r.readable() || !r.executable()) continue;
            if (r.size() < 256) continue;
            int64_t rd = static_cast<int64_t>(r.start) -
                         static_cast<int64_t>(addrs.resume);
            if (rd < -0x800000LL || rd > 0x800000LL) continue;
            size_t scan_sz = std::min(r.size(),
                                      static_cast<size_t>(0x800000));
            std::vector<uint8_t> code(scan_sz);
            struct iovec sli = {code.data(), scan_sz};
            struct iovec sri = {reinterpret_cast<void*>(r.start), scan_sz};
            if (process_vm_readv(pid, &sli, 1, &sri, 1, 0) !=
                static_cast<ssize_t>(scan_sz)) continue;

            for (size_t off = 1; off + 260 < scan_sz; off++) {
                if (best_live_settop) break;
                if (code[off - 1] != 0xC3 && code[off - 1] != 0xCC &&
                    code[off - 1] != 0x90) continue;
                uintptr_t cand = r.start + off;
                if (cand == addrs.resume || cand == addrs.newthread ||
                    cand == addrs.load || cand == addrs.lock_fn ||
                    cand == dead_settop_addr) continue;
                int64_t dead_dist = static_cast<int64_t>(cand) -
                                    static_cast<int64_t>(dead_settop_addr);
                if (dead_dist > -0x1000LL && dead_dist < 0x1000LL)
                    continue;
                size_t p = off;
                if (p + 3 < scan_sz && code[p] == 0xF3 &&
                    code[p + 1] == 0x0F && code[p + 2] == 0x1E &&
                    code[p + 3] == 0xFA) p += 4;
                if (p >= scan_sz) continue;
                if (!(code[p] == 0x55 || code[p] == 0x53 ||
                      (code[p] == 0x41 && p + 1 < scan_sz &&
                       code[p + 1] >= 0x54 && code[p + 1] <= 0x57)))
                    continue;
                bool sr_di = false, sr_si = false, sr_dx = false;
                bool has_alock = false;
                int calls = 0;
                size_t fsz = 0;
                for (size_t j = 0; j < 250 && off + j + 8 < scan_sz;
                     j++) {
                    size_t i = off + j;
                    if (code[i] == 0xE8) {
                        calls++;
                        if (!has_alock && j < 60) {
                            int32_t cd;
                            memcpy(&cd, &code[i + 1], 4);
                            uintptr_t ct = r.start + i + 5 +
                                           static_cast<int64_t>(cd);
                            if (ct == addrs.lock_fn) has_alock = true;
                            if (!has_alock) {
                                uint8_t hb[25];
                                struct iovec hbl = {hb, 25};
                                struct iovec hbr = {
                                    reinterpret_cast<void*>(ct), 25};
                                if (process_vm_readv(pid, &hbl, 1,
                                    &hbr, 1, 0) == 25) {
                                    for (int hi = 0; hi < 20; hi++) {
                                        if (hb[hi] != 0xE8) continue;
                                        int32_t hd;
                                        memcpy(&hd, &hb[hi + 1], 4);
                                        uintptr_t ht = ct + hi + 5 +
                                            static_cast<int64_t>(hd);
                                        if (ht == addrs.lock_fn)
                                            has_alock = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if (j < 20 && i + 2 < scan_sz) {
                        if (code[i] == 0x89 &&
                            (code[i+1] & 0x38) == 0x38) sr_di = true;
                        if ((code[i] == 0x48 || code[i] == 0x49) &&
                            code[i+1] == 0x89 &&
                            (code[i+2] & 0x38) == 0x38) sr_di = true;
                        if (code[i] == 0x89 &&
                            (code[i+1] & 0x38) == 0x30) sr_si = true;
                        if ((code[i] == 0x48 || code[i] == 0x49) &&
                            code[i+1] == 0x89 &&
                            (code[i+2] & 0x38) == 0x30) sr_si = true;
                        if (code[i] == 0x48 && code[i+1] == 0x63 &&
                            (code[i+2] & 0xC7) == 0xC6) sr_si = true;
                        if (code[i] == 0x89 &&
                            (code[i+1] & 0x38) == 0x10) sr_dx = true;
                        if ((code[i] == 0x48 || code[i] == 0x49) &&
                            code[i+1] == 0x89 &&
                            (code[i+2] & 0x38) == 0x10) sr_dx = true;
                    }
                    if (code[i] == 0xC3 && j >= 20) {
                        fsz = j + 1;
                        break;
                    }
                }
                if (!has_alock || !sr_di || !sr_si || sr_dx) continue;
                if (fsz < 30 || fsz > 250 || calls < 1 || calls > 8)
                    continue;

                total_probes++;
                if (total_probes > MAX_PROBES) {
                    LOG_WARN("[direct-hook] hit probe limit ({}) in "
                             "inner loop — stopping", MAX_PROBES);
                    break;
                }
                LOG_DEBUG("[direct-hook] live-settop candidate 0x{:X} "
                          "({}B, {} calls) — probing... [{}/{}]",
                          cand, fsz, calls, total_probes, MAX_PROBES);

                uint8_t cand_pro[32];
                if (!proc_mem_read(pid, cand, cand_pro, sizeof(cand_pro)))
                    continue;
                size_t cand_steal = 0;
                while (cand_steal < 5) {
                    size_t il = dh_insn_len(cand_pro + cand_steal);
                    if (il == 0 || cand_steal + il > sizeof(cand_pro))
                        break;
                    cand_steal += il;
                }
                if (cand_steal < 5) continue;

                int64_t cand_cave_dist = static_cast<int64_t>(
                    cave.padding_start) -
                    static_cast<int64_t>(cand + 5);
                if ((cand_cave_dist < INT32_MIN ||
                     cand_cave_dist > INT32_MAX) && cand_steal < 14)
                    continue;

                auto probe_tramp = gen_entry_trampoline(
                    addrs, mb_addr, cave.padding_start, cand,
                    cand_pro, cand_steal,
                    true, false, true);
                if (probe_tramp.size() > CAVE_SIZE) continue;
                if (!proc_mem_write(pid, cave.padding_start,
                                    probe_tramp.data(),
                                    probe_tramp.size())) continue;

                uint8_t probe_patch[16];
                size_t probe_pl;
                if (cand_cave_dist >= INT32_MIN &&
                    cand_cave_dist <= INT32_MAX && cand_steal >= 5) {
                    probe_patch[0] = 0xE9;
                    int32_t r32 = static_cast<int32_t>(cand_cave_dist);
                    memcpy(probe_patch + 1, &r32, 4);
                    for (size_t i = 5; i < cand_steal; i++)
                        probe_patch[i] = 0x90;
                    probe_pl = cand_steal;
                } else if (cand_steal >= 14) {
                    probe_patch[0] = 0xFF; probe_patch[1] = 0x25;
                    memset(probe_patch + 2, 0, 4);
                    uintptr_t ca = cave.padding_start;
                    memcpy(probe_patch + 6, &ca, 8);
                    probe_pl = 14;
                } else {
                    continue;
                }

                if (!proc_mem_write(pid, cand, probe_patch, probe_pl))
                    continue;

                uint16_t zh = 0;
                proc_mem_write(pid, mb_addr + 42, &zh, 2);
                usleep(200000);
                uint16_t probe_hits = 0;
                proc_mem_read(pid, mb_addr + 42, &probe_hits, 2);

                proc_mem_write(pid, cand, cand_pro, cand_steal);

                if (probe_hits >= 5) {
                    LOG_INFO("[direct-hook] LIVE settop at 0x{:X} "
                             "({} hits in 200ms, {}B, {} calls)",
                             cand, probe_hits, fsz, calls);
                    best_live_settop = cand;
                    best_live_hits = probe_hits;

                    uintptr_t captured_L = 0;
                    proc_mem_read(pid, mb_addr + 0x30, &captured_L, 8);
                    if (captured_L != 0 && captured_L > 0x10000 &&
                        captured_L < 0x7FFFFFFFFFFFULL) {
                        LOG_INFO("[direct-hook] captured L=0x{:X} from "
                                 "probe", captured_L);
                    }

                                        // Keep addrs.settop as the lock-anchored (dead) settop
                    // for step 4 cleanup — it's the VERIFIED real lua_settop.
                    // The live settop is only used as the hook target; it may
                    // not actually be lua_settop (just matches heuristics).
                    // Calling the dead settop directly avoids recursive hook
                    // re-entry and ensures correct settop(L, -2) behavior.
                    hook_addr = best_live_settop;
                    is_lock_hook = false;
                    memcpy(prologue, cand_pro, cand_steal);
                    steal = cand_steal;

                    if (!addrs.unlock_fn) {
                        uint8_t ls_buf[256];
                        struct iovec ls_l = {ls_buf, sizeof(ls_buf)};
                        struct iovec ls_r = {
                            reinterpret_cast<void*>(best_live_settop),
                            sizeof(ls_buf)};
                        ssize_t ls_rd = process_vm_readv(
                            pid, &ls_l, 1, &ls_r, 1, 0);
                        if (ls_rd >= 30) {
                            size_t ls_read =
                                static_cast<size_t>(ls_rd);
                            size_t ls_fend = 0;
                            {
                                size_t pos = 0;
                                while (pos + 15 < ls_read &&
                                       pos < 250) {
                                    size_t il = dh_insn_len(
                                        ls_buf + pos);
                                    if (il == 0) {
                                        LOG_DEBUG("[direct-hook] "
                                            "unlock-extract: decode "
                                            "failed at offset {} of "
                                            "live settop 0x{:X}",
                                            pos, best_live_settop);
                                        break;
                                    }
                                    if (ls_buf[pos] == 0xC3) {
                                        ls_fend = pos + 1;
                                        break;
                                    }
                                    if (pos + 1 < ls_read &&
                                        ls_buf[pos] == 0xF3 &&
                                        ls_buf[pos + 1] == 0xC3) {
                                        ls_fend = pos + 2;
                                        LOG_DEBUG("[direct-hook] "
                                            "unlock-extract: found "
                                            "REP RET at offset {}",
                                            pos);
                                        break;
                                    }
                                    pos += il;
                                }
                            }
                            if (ls_fend == 0) {
                                for (size_t si = 20;
                                     si + 1 < ls_read; si++) {
                                    if (ls_buf[si] == 0xC3 ||
                                        (ls_buf[si] == 0xF3 &&
                                         si + 1 < ls_read &&
                                         ls_buf[si + 1] == 0xC3)) {
                                        uint8_t nx = (ls_buf[si] == 0xF3)
                                            ? (si + 2 < ls_read ? ls_buf[si + 2] : 0)
                                            : ls_buf[si + 1];
                                        if (nx == 0xCC || nx == 0x90 ||
                                            nx == 0x55 || nx == 0x53 ||
                                            nx == 0x56 || nx == 0x57 ||
                                            nx == 0xF3 || nx == 0x00 ||
                                            (nx == 0x41 && si + 3 < ls_read &&
                                             ls_buf[si + (ls_buf[si]==0xF3?3:2)] >= 0x50 &&
                                             ls_buf[si + (ls_buf[si]==0xF3?3:2)] <= 0x57) ||
                                            (nx == 0x48 && si + 3 < ls_read &&
                                             ls_buf[si + (ls_buf[si]==0xF3?3:2)] == 0x83)) {
                                            ls_fend = si + (ls_buf[si] == 0xF3 ? 2 : 1);
                                            LOG_DEBUG("[direct-hook] "
                                                "unlock-extract: "
                                                "byte-pattern boundary "
                                                "at offset {} (decode "
                                                "fallback)", ls_fend);
                                            break;
                                        }
                                    }
                                }
                            }
                            if (ls_fend > 10) {
                                uintptr_t last_call_target = 0;
                                size_t last_call_off = 0;
                                for (size_t i = 0;
                                     i + 5 <= ls_fend; i++) {
                                    if (ls_buf[i] != 0xE8) continue;
                                    int32_t d;
                                    memcpy(&d, &ls_buf[i + 1], 4);
                                    uintptr_t t =
                                        best_live_settop + i + 5 +
                                        static_cast<int64_t>(d);
                                    last_call_target = t;
                                    last_call_off = i;
                                }
                                if (last_call_target &&
                                    last_call_target !=
                                        addrs.lock_fn) {
                                    addrs.unlock_fn = last_call_target;
                                    LOG_INFO("[direct-hook] lua_unlock"
                                             " at 0x{:X} (last E8 "
                                             "call in live settop at "
                                             "+{})", last_call_target,
                                             last_call_off);
                                }
                            }
                            if (!addrs.unlock_fn && ls_fend > 10) {
                                for (int ti = static_cast<int>(ls_fend) - 1;
                                     ti >= 5; ti--) {
                                    if (ls_buf[ti - 5] == 0xE9) {
                                        int32_t d;
                                        memcpy(&d, &ls_buf[ti - 4], 4);
                                        uintptr_t jt =
                                            best_live_settop + ti + 1 +
                                            static_cast<int64_t>(d);
                                        if (jt != addrs.lock_fn &&
                                            jt != best_live_settop) {
                                            addrs.unlock_fn = jt;
                                            LOG_INFO("[direct-hook] "
                                                "lua_unlock at 0x{:X}"
                                                " (tail-call JMP in "
                                                "live settop at +{})",
                                                jt, ti - 5);
                                            break;
                                        }
                                    }
                                    if (ti >= 14 &&
                                        ls_buf[ti - 14] == 0xFF &&
                                        ls_buf[ti - 13] == 0x25 &&
                                        ls_buf[ti - 12] == 0x00 &&
                                        ls_buf[ti - 11] == 0x00 &&
                                        ls_buf[ti - 10] == 0x00 &&
                                        ls_buf[ti - 9] == 0x00) {
                                        uintptr_t jt;
                                        memcpy(&jt, &ls_buf[ti - 8], 8);
                                        if (jt != addrs.lock_fn &&
                                            jt != best_live_settop &&
                                            jt > 0x10000) {
                                            addrs.unlock_fn = jt;
                                            LOG_INFO("[direct-hook] "
                                                "lua_unlock at 0x{:X}"
                                                " (indirect tail JMP "
                                                "in live settop)",
                                                jt);
                                            break;
                                        }
                                    }
                                }
                            }
                            if (!addrs.unlock_fn && addrs.resume) {
                                LOG_DEBUG("[direct-hook] unlock-extract"
                                    ": live settop extraction failed,"
                                    " trying lua_resume");
                                uint8_t rb[800];
                                struct iovec rbl = {rb, sizeof(rb)};
                                struct iovec rbr = {
                                    reinterpret_cast<void*>(addrs.resume),
                                    sizeof(rb)};
                                ssize_t rrd = process_vm_readv(
                                    pid, &rbl, 1, &rbr, 1, 0);
                                if (rrd >= 50) {
                                    size_t r_read =
                                        static_cast<size_t>(rrd);
                                    size_t r_fend = 0;
                                    {
                                        size_t pos = 0;
                                        while (pos + 15 < r_read &&
                                               pos < 700) {
                                            size_t il = dh_insn_len(
                                                rb + pos);
                                            if (il == 0) break;
                                            if (rb[pos] == 0xC3) {
                                                r_fend = pos + 1;
                                                break;
                                            }
                                            if (pos + 1 < r_read &&
                                                rb[pos] == 0xF3 &&
                                                rb[pos + 1] == 0xC3) {
                                                r_fend = pos + 2;
                                                break;
                                            }
                                            pos += il;
                                        }
                                    }
                                    if (r_fend == 0) {
                                        for (size_t si = 100;
                                             si + 1 < r_read; si++) {
                                            if (rb[si] != 0xC3) continue;
                                            uint8_t nx = rb[si + 1];
                                            if (nx==0xCC || nx==0x90 ||
                                                nx==0x55 || nx==0x53 ||
                                                nx==0xF3 || nx==0x00) {
                                                r_fend = si + 1;
                                                break;
                                            }
                                        }
                                    }
                                    if (r_fend > 50) {
                                        uintptr_t r_last = 0;
                                        size_t r_last_off = 0;
                                        for (size_t i = 0;
                                             i + 5 <= r_fend; i++) {
                                            if (rb[i] != 0xE8) continue;
                                            int32_t d;
                                            memcpy(&d, &rb[i+1], 4);
                                            uintptr_t t =
                                                addrs.resume + i + 5 +
                                                static_cast<int64_t>(d);
                                            if (t != addrs.lock_fn &&
                                                t != addrs.resume) {
                                                r_last = t;
                                                r_last_off = i;
                                            }
                                        }
                                        if (r_last) {
                                            bool is_lock_like = false;
                                            uint8_t ul_probe[16];
                                            struct iovec upl = {
                                                ul_probe, 16};
                                            struct iovec upr = {
                                                reinterpret_cast<void*>(
                                                    r_last), 16};
                                            if (process_vm_readv(
                                                pid, &upl, 1, &upr,
                                                1, 0) == 16) {
                                                for (int ui = 0;
                                                     ui + 5 <= 12;
                                                     ui++) {
                                                    if (ul_probe[ui] !=
                                                        0xE8) continue;
                                                    int32_t ud;
                                                    memcpy(&ud,
                                                        &ul_probe[ui+1],
                                                        4);
                                                    uintptr_t ut =
                                                        r_last + ui +
                                                        5 +
                                                        static_cast<
                                                            int64_t>(
                                                            ud);
                                                    if (ut ==
                                                        addrs.lock_fn)
                                                        is_lock_like =
                                                            true;
                                                    break;
                                                }
                                            }
                                            if (!is_lock_like) {
                                                int64_t ul_dist = static_cast<int64_t>(r_last) - static_cast<int64_t>(addrs.lock_fn);
                                                if (ul_dist < 0) ul_dist = -ul_dist;
                                                if (static_cast<uint64_t>(ul_dist) < 0x800000ULL) {
                                                    addrs.unlock_fn = r_last;
                                                    LOG_INFO("[direct-hook] lua_unlock at 0x{:X} (last non-lock call in lua_resume at +{}, {:.1f}MB from lock)", r_last, r_last_off, ul_dist / (1024.0 * 1024.0));
                                                } else {
                                                    LOG_WARN("[direct-hook] rejected lua_unlock candidate 0x{:X} from lua_resume — {:.1f}MB from active_lock 0x{:X} (likely inlined unlock)", r_last, ul_dist / (1024.0 * 1024.0), addrs.lock_fn);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (!addrs.unlock_fn && addrs.lock_internals_valid) {
                        LOG_INFO("[direct-hook] lua_unlock not found (compiler-inlined) — "
                                 "using synthesized inline unlock via pthread_mutex_unlock "
                                 "(global_offset={}, mutex_offset={}, unlock=0x{:X})",
                                 addrs.lock_global_state_offset,
                                 addrs.lock_mutex_offset,
                                 addrs.pthread_mutex_unlock_addr);
                    } else if (!addrs.unlock_fn) {
                        LOG_WARN("[direct-hook] lua_unlock not found and lock internals "
                                 "unavailable — held-lock hook will likely deadlock");
                    }

                    hook_needs_unlock = false;

                    auto held_tramp = gen_entry_trampoline(
                        addrs, mb_addr, cave.padding_start,
                        best_live_settop, prologue, steal,
                        false,
                        false, true);
                    if (held_tramp.size() <= CAVE_SIZE &&
                        proc_mem_write(pid, cave.padding_start,
                                       held_tramp.data(),
                                       held_tramp.size())) {
                        uint8_t hp[16];
                        size_t hpl;
                        int64_t hd = static_cast<int64_t>(
                            cave.padding_start) -
                            static_cast<int64_t>(
                                best_live_settop + 5);
                        if (hd >= INT32_MIN && hd <= INT32_MAX &&
                            steal >= 5) {
                            hp[0] = 0xE9;
                            int32_t r32 = static_cast<int32_t>(hd);
                            memcpy(hp + 1, &r32, 4);
                            for (size_t i = 5; i < steal; i++)
                                hp[i] = 0x90;
                            hpl = steal;
                        } else {
                            hp[0] = 0xFF; hp[1] = 0x25;
                            memset(hp + 2, 0, 4);
                            uintptr_t ca = cave.padding_start;
                            memcpy(hp + 6, &ca, 8);
                            hpl = 14;
                        }

                        if (proc_mem_write(pid, best_live_settop,
                                           hp, hpl)) {
                            patch_len = hpl;
                            memcpy(patch, hp, hpl);
                            settop_probe_live = true;
                            LOG_INFO("[direct-hook] live settop hooked "
                                     "at 0x{:X} with held-lock "
                                     "trampoline ({} bytes)",
                                     best_live_settop,
                                     held_tramp.size());
                        }
                    }
                    break;
                } else {
                    LOG_DEBUG("[direct-hook] candidate 0x{:X} dead "
                              "({} hits)", cand, probe_hits);
                }
            }
        }

        if (!settop_probe_live) {
            LOG_ERROR("[direct-hook] no live hook target found — "
                      "all settop variants are dead");

            LOG_INFO("[direct-hook] attempting lua_resume as alternative "
                     "hook target (called without lock held)");
            uint8_t resume_pro[32];
            if (addrs.resume &&
                proc_mem_read(pid, addrs.resume, resume_pro,
                              sizeof(resume_pro))) {
                size_t resume_steal = 0;
                while (resume_steal < 5) {
                    size_t il = dh_insn_len(resume_pro + resume_steal);
                    if (il == 0 || resume_steal + il > sizeof(resume_pro))
                        break;
                    resume_steal += il;
                }
                if (resume_steal >= 5) {
                    int64_t resume_cave_dist = static_cast<int64_t>(
                        cave.padding_start) -
                        static_cast<int64_t>(addrs.resume + 5);
                    if ((resume_cave_dist >= INT32_MIN &&
                         resume_cave_dist <= INT32_MAX) ||
                        resume_steal >= 14) {
                        if (try_hook_target(addrs.resume, "lua_resume",
                                            resume_pro, resume_steal, false)) {
                            hook_addr = addrs.resume;
                            is_lock_hook = false;
                            settop_probe_live = true;
                            LOG_INFO("[direct-hook] lua_resume hook "
                                     "succeeded as fallback (no "
                                     "unlock/lock bracket needed, "
                                     "step 4 cleanup skipped)");
                        }
                    }
                }
            }

            if (!settop_probe_live) {
                LOG_ERROR("[direct-hook] all hook targets exhausted");
                return false;
            }
        }
    } else {
        settop_probe_live = true;
        hook_needs_unlock = false;
    }
          // Re-generate trampoline with the final validated addrs
    // (lua_settop may have been re-scanned by lock-anchored validation)
    bool effective_held_lock = is_lock_hook || hook_needs_unlock;
    LOG_INFO("[direct-hook] final function addresses: resume=0x{:X} newthread=0x{:X} "
             "load=0x{:X} settop=0x{:X} lock=0x{:X} held_lock={} internals={}",
             addrs.resume, addrs.newthread, addrs.load, addrs.settop,
             addrs.lock_fn ? addrs.lock_fn : 0,
             effective_held_lock,
             addrs.lock_internals_valid);

    bool hook_is_settop = (hook_addr != addrs.resume);
    {
        auto t_final = gen_entry_trampoline(addrs, mb_addr, cave.padding_start,
                                             hook_addr, prologue, steal,
                                             false, effective_held_lock,
                                             hook_is_settop);
        if (!proc_mem_write(pid, cave.padding_start, t_final.data(), t_final.size())) {
            LOG_ERROR("[direct-hook] failed to write final trampoline");
            proc_mem_write(pid, hook_addr, prologue, steal);
            return false;
        }
        LOG_INFO("[direct-hook] final trampoline written: {} bytes at 0x{:X}",
                 t_final.size(), cave.padding_start);
    }

    dhook_.cave_addr = cave.padding_start;
    dhook_.mailbox_addr = mb_addr;
    dhook_.cave_size = CAVE_SIZE;
    dhook_.nop_stub_addr = 0;
    dhook_.stolen_len = steal;
    dhook_.resume_addr = addrs.resume;
    dhook_.newthread_addr = addrs.newthread;
    dhook_.load_addr = addrs.load;
    dhook_.settop_addr = hook_addr;
    memcpy(dhook_.stolen_bytes, prologue, steal);
    memcpy(dhook_.orig_patch, prologue, patch_len);
    dhook_.patch_len = patch_len;
    {
        auto t_measure = gen_entry_trampoline(addrs, mb_addr, cave.padding_start,
                                               hook_addr, prologue, steal,
                                               false, effective_held_lock,
                                               hook_is_settop);
        // NOP stub is the single RET (0xC3) emitted right before the optional
        // cleanup thunk. When hook_is_settop && steal > 0, the cleanup thunk
        // (stolen prologue bytes + JMP) is appended after the NOP stub.
        // The thunk's first byte equals prologue[0], so scan backward for
        // the 0xC3 immediately followed by that prologue byte.
        size_t nop_pos = t_measure.size() - 1;
        if (hook_is_settop && steal > 0) {
            for (size_t si = t_measure.size() - 1; si > 0; si--) {
                if (t_measure[si] == 0xC3 && si + 1 < t_measure.size() &&
                    t_measure[si + 1] == prologue[0]) {
                    nop_pos = si;
                    break;
                }
            }
        }
        dhook_.nop_stub_addr = cave.padding_start + nop_pos;
    }
    dhook_.active = true;
    dhook_.has_compile = (addrs.compile != 0);
    dhook_.hook_is_lock_fn = is_lock_hook;
    if (is_lock_hook) {
        dhook_.active_lock_addr = hook_addr;
        dhook_.real_settop_addr = addrs.settop;
        int64_t st_resume_dist = static_cast<int64_t>(addrs.settop) -
                                 static_cast<int64_t>(addrs.resume);
        if (st_resume_dist < 0) st_resume_dist = -st_resume_dist;
        LOG_INFO("[direct-hook] lock hook: active_lock=0x{:X} real_settop=0x{:X} "
                 "({:.1f}MB from lua_resume) "
                 "(re-entrant calls execute real lua_lock — no unlock bypass needed)",
                 hook_addr, addrs.settop,
                 st_resume_dist / (1024.0 * 1024.0));
        if (static_cast<uint64_t>(st_resume_dist) > 0x2800000ULL) {
            LOG_ERROR("[direct-hook] WARNING: lua_settop is {:.0f}MB from "
                      "lua_resume — likely dead copy! Step 4 cleanup may "
                      "deadlock or crash. The trampoline will still attempt "
                      "steps 1-3.", st_resume_dist / (1024.0 * 1024.0));
        }
    }

    LOG_INFO("[direct-hook] ENTRY HOOK ARMED — {} at 0x{:X}, cave at 0x{:X}, mailbox at 0x{:X}{}{}",
             is_lock_hook ? "lua_lock" : "lua_settop", hook_addr,
             cave.padding_start, mb_addr,
             is_lock_hook ? " (guard handles reentrancy, no lock bypass needed)" : "",
             addrs.settop == 0 ? " [step4-cleanup DISABLED: no live settop]" : "");

    // ═══════════════════════════════════════════════════════════════
    // DRY-RUN VALIDATION: Send minimal bytecode through the mailbox
    // and verify the trampoline completes all steps. This catches:
    // - lua_lock hook where rdi ≠ lua_State* (deadlock at step 1)
    // - Wrong lua_newthread/luau_load/lua_resume (crash/deadlock)
    // - Mutex corruption from hooking the wrong function
    //
    // The test bytecode is "return" compiled to Luau bytecode.
    // If step stalls at 1, the hook target is fundamentally broken
    // and we must fail immediately rather than let the user discover
    // it at script-execution time.
    // ═══════════════════════════════════════════════════════════════
    {
        LOG_INFO("[direct-hook] dry-run validation — sending test bytecode");

        size_t test_bc_len = 0;
        const char* test_src = "return";
        char* test_bc = luau_compile(test_src, strlen(test_src),
                                      nullptr, &test_bc_len);
        bool dryrun_pass = false;

        if (test_bc && test_bc_len > 0 &&
            static_cast<uint8_t>(test_bc[0]) != 0 &&
            test_bc_len <= 16320) {

            uint64_t test_seq = 0, test_ack = 0;
            proc_mem_read(pid, dhook_.mailbox_addr + 16, &test_seq, 8);
            proc_mem_read(pid, dhook_.mailbox_addr + 24, &test_ack, 8);

            if (test_seq <= test_ack) {
                proc_mem_write(pid, dhook_.mailbox_addr + 64,
                               test_bc, test_bc_len);
                uint32_t tsz = static_cast<uint32_t>(test_bc_len);
                uint32_t tflags = 1;
                proc_mem_write(pid, dhook_.mailbox_addr + 32, &tsz, 4);
                proc_mem_write(pid, dhook_.mailbox_addr + 36, &tflags, 4);
                uint32_t zero32 = 0;
                proc_mem_write(pid, dhook_.mailbox_addr + 44, &zero32, 4);
                uint8_t zero8 = 0;
                proc_mem_write(pid, dhook_.mailbox_addr + 40, &zero8, 1);
                uint16_t zero16 = 0;
                proc_mem_write(pid, dhook_.mailbox_addr + 42, &zero16, 2);

                uint64_t arm_seq = test_seq + 1;
                proc_mem_write(pid, dhook_.mailbox_addr + 16, &arm_seq, 8);

                LOG_DEBUG("[direct-hook] dry-run armed: seq={}", arm_seq);

                for (int di = 0; di < 100; di++) {
                    usleep(50000);
                    if (kill(pid, 0) != 0) {
                        LOG_ERROR("[direct-hook] dry-run: process died");
                        break;
                    }
                    uint64_t dr_ack = 0;
                    proc_mem_read(pid, dhook_.mailbox_addr + 24,
                                  &dr_ack, 8);
                    if (dr_ack >= arm_seq) {
                        dryrun_pass = true;
                        uint32_t dr_step = 0;
                        proc_mem_read(pid, dhook_.mailbox_addr + 44,
                                      &dr_step, 4);
                        LOG_INFO("[direct-hook] dry-run PASSED — "
                                 "trampoline completed in {}ms "
                                 "(final step={}{})",
                                 (di + 1) * 50, dr_step,
                                 is_lock_hook ? ", L from rbx" : "");
                        break;
                    }
                    if (di % 20 == 19) {
                        uint32_t dr_step = 0;
                        proc_mem_read(pid, dhook_.mailbox_addr + 44,
                                      &dr_step, 4);
                        uint8_t dr_guard = 0;
                        proc_mem_read(pid, dhook_.mailbox_addr + 40,
                                      &dr_guard, 1);
                        uint16_t dr_hits = 0;
                        proc_mem_read(pid, dhook_.mailbox_addr + 42,
                                      &dr_hits, 2);
                        LOG_DEBUG("[direct-hook] dry-run wait[{}]: "
                                  "step={} guard={} hits={}",
                                  di, dr_step, dr_guard, dr_hits);

                        if (dr_step == 1 && dr_guard == 1 && di >= 39) {
                            LOG_ERROR("[direct-hook] dry-run FAILED — "
                                      "deadlock at step 1 "
                                      "(lua_newthread). {}",
                                      is_lock_hook
                                          ? "lua_lock hook: rbx may "
                                            "not hold lua_State* in "
                                            "all callers. The calling "
                                            "API function may use a "
                                            "different register."
                                          : "Hook target may be called"
                                            " with Lua lock held.");
                            break;
                        }
                        if (dr_step == 0 && dr_guard == 0 &&
                            dr_hits > 50 && di >= 39) {
                            LOG_ERROR("[direct-hook] dry-run FAILED — "
                                      "hook is live ({} hits) but "
                                      "payload path never entered "
                                      "(seq/ack or guard check "
                                      "mismatch in trampoline)",
                                      dr_hits);
                            break;
                        }
                    }
                }
            } else {
                LOG_WARN("[direct-hook] dry-run skipped: mailbox busy "
                         "(seq={} ack={})", test_seq, test_ack);
                dryrun_pass = true;
            }
        } else {
            LOG_WARN("[direct-hook] dry-run skipped: test compile failed");
            dryrun_pass = true;
        }
        free(test_bc);

        if (!dryrun_pass) {
            uint32_t fail_step = 0;
            proc_mem_read(pid, mb_addr + 44, &fail_step, 4);

            LOG_ERROR("[direct-hook] dry-run validation FAILED — "
                      "cleaning up hook and reporting failure");

            proc_mem_write(pid, hook_addr, prologue, steal);
            usleep(50000);

            uint32_t reset_step = 0;
            uint8_t reset_guard = 0;
            proc_mem_write(pid, mb_addr + 44, &reset_step, 4);
            proc_mem_write(pid, mb_addr + 40, &reset_guard, 1);

            DirectMailbox empty_mb{};
            proc_mem_write(pid, mb_addr, &empty_mb,
                           sizeof(DirectMailbox));

            dhook_ = {};

            if (fail_step == 1 && addrs.resume != 0 &&
                hook_addr != addrs.resume) {
                LOG_INFO("[direct-hook] step-1 deadlock: live settop "
                         "called with Lua lock held. Retrying with "
                         "lua_resume (top-level API, never lock-held)");

                uint8_t resume_pro[32];
                if (proc_mem_read(pid, addrs.resume, resume_pro,
                                  sizeof(resume_pro))) {
                    size_t resume_steal = 0;
                    while (resume_steal < 5) {
                        size_t il = dh_insn_len(
                            resume_pro + resume_steal);
                        if (il == 0 ||
                            resume_steal + il > sizeof(resume_pro))
                            break;
                        resume_steal += il;
                    }

                    int64_t resume_cave_dist =
                        static_cast<int64_t>(cave.padding_start) -
                        static_cast<int64_t>(addrs.resume + 5);
                    bool cave_reachable =
                        (resume_cave_dist >= INT32_MIN &&
                         resume_cave_dist <= INT32_MAX) ||
                        resume_steal >= 14;

                    if (resume_steal >= 5 && cave_reachable) {
                        auto rt = gen_entry_trampoline(
                            addrs, mb_addr, cave.padding_start,
                            addrs.resume, resume_pro, resume_steal,
                            false, false, false);

                        if (rt.size() <= CAVE_SIZE &&
                            proc_mem_write(pid, cave.padding_start,
                                           rt.data(), rt.size())) {

                            uint8_t rp[16];
                            size_t rpl;
                            if (resume_cave_dist >= INT32_MIN &&
                                resume_cave_dist <= INT32_MAX &&
                                resume_steal >= 5) {
                                rp[0] = 0xE9;
                                int32_t r32 = static_cast<int32_t>(
                                    resume_cave_dist);
                                memcpy(rp + 1, &r32, 4);
                                for (size_t i = 5; i < resume_steal;
                                     i++)
                                    rp[i] = 0x90;
                                rpl = resume_steal;
                            } else {
                                rp[0] = 0xFF; rp[1] = 0x25;
                                memset(rp + 2, 0, 4);
                                uintptr_t ca = cave.padding_start;
                                memcpy(rp + 6, &ca, 8);
                                rpl = 14;
                            }

                            if (proc_mem_write(pid, addrs.resume,
                                               rp, rpl)) {
                                uint8_t vf[16] = {};
                                proc_mem_read(pid, addrs.resume,
                                              vf, rpl);
                                if (memcmp(vf, rp, rpl) != 0) {
                                    LOG_ERROR("[direct-hook] "
                                        "lua_resume patch did not "
                                        "persist");
                                } else {
                                    uint16_t zh = 0;
                                    proc_mem_write(pid, mb_addr + 42,
                                                   &zh, 2);
                                    usleep(1000000);
                                    uint16_t rh = 0;
                                    proc_mem_read(pid, mb_addr + 42,
                                                  &rh, 2);

                                    if (rh < 1) {
                                        LOG_WARN("[direct-hook] "
                                            "lua_resume at 0x{:X} "
                                            "has {} hits in 1s — "
                                            "may not be called "
                                            "frequently", addrs.resume,
                                            rh);
                                        proc_mem_write(pid,
                                            addrs.resume, resume_pro,
                                            resume_steal);
                                    } else {
                                        LOG_INFO("[direct-hook] "
                                            "lua_resume probe: {} "
                                            "hits in 1s — LIVE",
                                            rh);

                                        hook_addr = addrs.resume;
                                        memcpy(prologue, resume_pro,
                                               resume_steal);
                                        steal = resume_steal;
                                        patch_len = rpl;
                                        memcpy(patch, rp, rpl);
                                        is_lock_hook = false;

                                        auto rt_final =
                                            gen_entry_trampoline(
                                                addrs, mb_addr,
                                                cave.padding_start,
                                                addrs.resume,
                                                resume_pro,
                                                resume_steal,
                                                false, false, false);
                                        proc_mem_write(pid,
                                            cave.padding_start,
                                            rt_final.data(),
                                            rt_final.size());

                                        DirectMailbox mb2{};
                                        memcpy(mb2.magic,
                                            "OSS_DMBOX_V3\0\0\0\0",
                                            16);
                                        proc_mem_write(pid, mb_addr,
                                            &mb2, sizeof(mb2));

                                        size_t r_bc_len = 0;
                                        const char* r_src = "return";
                                        char* r_bc = luau_compile(
                                            r_src, strlen(r_src),
                                            nullptr, &r_bc_len);
                                        bool r_pass = false;

                                        if (r_bc && r_bc_len > 0 &&
                                            static_cast<uint8_t>(
                                                r_bc[0]) != 0 &&
                                            r_bc_len <= 16320) {

                                            proc_mem_write(pid,
                                                mb_addr + 64, r_bc,
                                                r_bc_len);
                                            uint32_t rsz =
                                                static_cast<uint32_t>(
                                                    r_bc_len);
                                            uint32_t rfl = 1;
                                            proc_mem_write(pid,
                                                mb_addr + 32, &rsz, 4);
                                            proc_mem_write(pid,
                                                mb_addr + 36, &rfl, 4);
                                            uint32_t z32 = 0;
                                            proc_mem_write(pid,
                                                mb_addr + 44, &z32, 4);
                                            uint8_t z8 = 0;
                                            proc_mem_write(pid,
                                                mb_addr + 40, &z8, 1);
                                            uint16_t z16 = 0;
                                            proc_mem_write(pid,
                                                mb_addr + 42, &z16, 2);
                                            uint64_t r_seq = 1;
                                            proc_mem_write(pid,
                                                mb_addr + 16, &r_seq,
                                                8);

                                            for (int ri = 0; ri < 100;
                                                 ri++) {
                                                usleep(50000);
                                                if (kill(pid, 0) != 0)
                                                    break;
                                                uint64_t r_ack = 0;
                                                proc_mem_read(pid,
                                                    mb_addr + 24,
                                                    &r_ack, 8);
                                                if (r_ack >= r_seq) {
                                                    r_pass = true;
                                                    uint32_t r_st = 0;
                                                    proc_mem_read(pid,
                                                        mb_addr + 44,
                                                        &r_st, 4);
                                                    LOG_INFO(
                                                        "[direct-hook]"
                                                        " lua_resume "
                                                        "dry-run "
                                                        "PASSED in "
                                                        "{}ms (step="
                                                        "{})",
                                                        (ri + 1) * 50,
                                                        r_st);
                                                    break;
                                                }
                                                if (ri % 20 == 19) {
                                                    uint32_t rs = 0;
                                                    uint8_t rg = 0;
                                                    proc_mem_read(pid,
                                                        mb_addr + 44,
                                                        &rs, 4);
                                                    proc_mem_read(pid,
                                                        mb_addr + 40,
                                                        &rg, 1);
                                                    LOG_DEBUG(
                                                        "[direct-hook]"
                                                        " resume "
                                                        "dry-run "
                                                        "wait[{}]: "
                                                        "step={} "
                                                        "guard={}",
                                                        ri, rs, rg);
                                                    if (rs == 1 &&
                                                        rg == 1 &&
                                                        ri >= 39) {
                                                        LOG_ERROR(
                                                            "[direct-"
                                                            "hook] "
                                                            "lua_resume"
                                                            " dry-run "
                                                            "also "
                                                            "deadlocked"
                                                            " at step 1"
                                                        );
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        free(r_bc);

                                        if (r_pass) {
                                            dhook_.cave_addr =
                                                cave.padding_start;
                                            dhook_.mailbox_addr =
                                                mb_addr;
                                            dhook_.cave_size = CAVE_SIZE;
                                            dhook_.nop_stub_addr = 0;
                                            dhook_.stolen_len =
                                                resume_steal;
                                            dhook_.resume_addr =
                                                addrs.resume;
                                            dhook_.newthread_addr =
                                                addrs.newthread;
                                            dhook_.load_addr =
                                                addrs.load;
                                            dhook_.settop_addr =
                                                addrs.resume;
                                            memcpy(
                                                dhook_.stolen_bytes,
                                                resume_pro,
                                                resume_steal);
                                            memcpy(
                                                dhook_.orig_patch,
                                                resume_pro,
                                                rpl);
                                            dhook_.patch_len = rpl;
                                            {
                                                auto tm =
                                                    gen_entry_trampoline(
                                                        addrs, mb_addr,
                                                        cave.padding_start,
                                                        addrs.resume,
                                                        resume_pro,
                                                        resume_steal,
                                                        false, false,
                                                        false);
                                                dhook_.nop_stub_addr =
                                                    cave.padding_start +
                                                    tm.size() - 1;
                                            }
                                            dhook_.active = true;
                                            dhook_.has_compile =
                                                (addrs.compile != 0);
                                            dhook_.hook_is_lock_fn =
                                                false;

                                            LOG_INFO("[direct-hook] "
                                                "ENTRY HOOK ARMED — "
                                                "lua_resume at "
                                                "0x{:X} (step-1 "
                                                "retry SUCCESS)",
                                                addrs.resume);
                                            set_state(
                                                InjectionState::Ready,
                                                "Direct hook active "
                                                "\u2014 ready for "
                                                "scripts");
                                            return true;
                                        }

                                        LOG_WARN("[direct-hook] "
                                            "lua_resume dry-run also "
                                            "failed — giving up");
                                        proc_mem_write(pid,
                                            addrs.resume, resume_pro,
                                            resume_steal);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            {
                const char* sn[] = {
                    "trampoline never entered payload path",
                    "lua_newthread", "luau_load",
                    "lua_resume", "lua_settop(-2) cleanup"
                };
                const char* step_name = (fail_step <= 4)
                    ? sn[fail_step] : "unknown";
                error_ = "Direct hook dry-run failed — trampoline "
                         "deadlocked at step " +
                         std::to_string(fail_step) + " (" +
                         step_name + ").";
                if (fail_step == 1)
                    error_ += " Hook target called with Lua lock "
                              "held — lua_resume retry also failed.";
            }
            set_state(InjectionState::Failed, error_);
            return false;
        }
    }

    set_state(InjectionState::Ready, "Direct hook active — ready for scripts");
    return true;
}

void Injection::cleanup_direct_hook() {
    if (!dhook_.active) return;
    pid_t pid = memory_.get_pid();
    if (pid > 0 && kill(pid, 0) == 0) {
        // dhook_.settop_addr stores whichever function was actually
        // patched with the JMP — this may be lua_settop, lua_lock,
        // lua_resume, or whichever target was selected by the hook
        // cascade. We must restore THAT function's prologue.
        uintptr_t hooked_addr = dhook_.settop_addr;
        if (!hooked_addr) {
            // Fallback: if settop_addr is 0 (shouldn't happen when
            // active), try the lock address or resume address.
            if (dhook_.hook_is_lock_fn && dhook_.active_lock_addr)
                hooked_addr = dhook_.active_lock_addr;
            else if (dhook_.resume_addr)
                hooked_addr = dhook_.resume_addr;
        }
        if (hooked_addr && dhook_.stolen_len > 0) {
            if (!proc_mem_write(pid, hooked_addr,
                                dhook_.stolen_bytes, dhook_.stolen_len)) {
                LOG_ERROR("[direct-hook] cleanup: failed to restore "
                          "prologue at 0x{:X} — target may crash",
                          hooked_addr);
            } else {
                LOG_DEBUG("[direct-hook] cleanup: restored {} bytes at "
                          "0x{:X}", dhook_.stolen_len, hooked_addr);
            }
        }
        // Clear the mailbox to prevent stale data from triggering
        // the trampoline if the cave memory is reused.
        DirectMailbox mb{};
        proc_mem_write(pid, dhook_.mailbox_addr, &mb, sizeof(DirectMailbox));

        // Zero out the code cave to prevent dangling shellcode.
        if (dhook_.cave_addr && dhook_.cave_size > 0) {
            std::vector<uint8_t> zeros(dhook_.cave_size, 0xCC);
            proc_mem_write(pid, dhook_.cave_addr, zeros.data(),
                           zeros.size());
        }
    }
    dhook_ = {};
    LOG_INFO("[direct-hook] cleaned up");
}

uint64_t Injection::send_via_mailbox(const void* data, size_t len, uint32_t flags) {
    if (!dhook_.active || !dhook_.mailbox_addr) return 0;
    pid_t pid = memory_.get_pid();
    if (pid <= 0) return 0;
    if (len > 16320) {
        LOG_ERROR("[direct-hook] script too large for mailbox: {} > 16320", len);
        return 0;
    }

    uint64_t seq = 0, ack = 0;
    if (!proc_mem_read(pid, dhook_.mailbox_addr + 16, &seq, 8)) return 0;
    if (!proc_mem_read(pid, dhook_.mailbox_addr + 24, &ack, 8)) return 0;

    for (int i = 0; i < 200 && seq > ack; i++) {
        usleep(10000);
        proc_mem_read(pid, dhook_.mailbox_addr + 24, &ack, 8);
    }
    if (seq > ack) {
        LOG_WARN("[direct-hook] mailbox not consumed after 2s (seq={} ack={})", seq, ack);
        return 0;
    }

    if (!proc_mem_write(pid, dhook_.mailbox_addr + 64, data, len)) return 0;
    uint32_t sz = static_cast<uint32_t>(len);
    if (!proc_mem_write(pid, dhook_.mailbox_addr + 32, &sz, 4)) return 0;
    if (!proc_mem_write(pid, dhook_.mailbox_addr + 36, &flags, 4)) return 0;
    uint32_t zero_step = 0;
    proc_mem_write(pid, dhook_.mailbox_addr + 44, &zero_step, 4);
    uint8_t zero_guard = 0;
    proc_mem_write(pid, dhook_.mailbox_addr + 40, &zero_guard, 1);
    uint16_t zero_hit = 0;
    proc_mem_write(pid, dhook_.mailbox_addr + 42, &zero_hit, 2);

    uint64_t new_seq = seq + 1;
    if (!proc_mem_write(pid, dhook_.mailbox_addr + 16, &new_seq, 8)) {
        LOG_ERROR("[direct-hook] failed to write seq={} — mailbox stuck", new_seq);
        return 0;
    }

    LOG_INFO("[direct-hook] mailbox armed: seq={} data={} bytes flags=0x{:X}",
             new_seq, len, flags);
    return new_seq;
}
bool Injection::wait_for_mailbox_ack(uint64_t armed_seq, size_t bc_len, uint8_t bc_ver) {
    if (!dhook_.active || !dhook_.mailbox_addr || armed_seq == 0) return false;
    pid_t mpid = memory_.get_pid();
    if (mpid <= 0) return false;

    uint16_t pre_hits = 0;
    proc_mem_read(mpid, dhook_.mailbox_addr + 42, &pre_hits, 2);
    LOG_INFO("[direct-hook] dispatch: armed_seq={} pre_hits={} "
             "— entering 5s wait loop", armed_seq, pre_hits);

    bool executed = false;
    for (int i = 0; i < 100; i++) {
        usleep(50000);
        if (kill(mpid, 0) != 0) {
            LOG_ERROR("[direct-hook] process died while waiting for ack");
            return false;
        }
        uint64_t cur_ack = 0;
        proc_mem_read(mpid, dhook_.mailbox_addr + 24, &cur_ack, 8);
        uint32_t step = 0;
        proc_mem_read(mpid, dhook_.mailbox_addr + 44, &step, 4);
        uint8_t guard = 0;
        proc_mem_read(mpid, dhook_.mailbox_addr + 40, &guard, 1);
        uint16_t hits = 0;
        proc_mem_read(mpid, dhook_.mailbox_addr + 42, &hits, 2);

        if (cur_ack >= armed_seq) {
            LOG_INFO("[direct-hook] execution confirmed: ack={} "
                     "seq={} step={} hits={} ({} bytes, v{})",
                     cur_ack, armed_seq, step, hits,
                     bc_len, static_cast<int>(bc_ver));
            executed = true;
            break;
        }
        if (i == 0 || i % 10 == 0) {
            LOG_DEBUG("[direct-hook] waiting[{}]: step={} guard={} "
                      "hits={} ack={} armed_seq={}",
                      i, step, guard, hits, cur_ack, armed_seq);
        }
        if (i == 20 && step == 0 && guard == 0 && hits > pre_hits + 10) {
            LOG_WARN("[direct-hook] hook is live ({} hits) but "
                     "payload path never entered after 1s — "
                     "seq may not be visible to target or "
                     "trampoline guard/seq check has a bug",
                     hits);
        }
    }

    if (executed) return true;

    uint32_t final_step = 0;
    uint8_t final_guard = 0;
    uint16_t final_hits = 0;
    uint64_t final_ack = 0;
    proc_mem_read(mpid, dhook_.mailbox_addr + 44, &final_step, 4);
    proc_mem_read(mpid, dhook_.mailbox_addr + 40, &final_guard, 1);
    proc_mem_read(mpid, dhook_.mailbox_addr + 42, &final_hits, 2);
    proc_mem_read(mpid, dhook_.mailbox_addr + 24, &final_ack, 8);

    uint64_t verify_seq = 0;
    proc_mem_read(mpid, dhook_.mailbox_addr + 16, &verify_seq, 8);

    if (verify_seq != armed_seq) {
        LOG_ERROR("[direct-hook] CRITICAL: seq in mailbox is {} but "
                  "we wrote {} — memory write did not persist or "
                  "target overwrote seq", verify_seq, armed_seq);
    }

    if (final_step == 0 && final_guard == 0) {
        LOG_ERROR("[direct-hook] trampoline never entered payload "
                  "path (step=0, guard=0, hits={}, ack={}, "
                  "armed_seq={}, verify_seq={}) — hook is {} "
                  "but seq/ack comparison in trampoline never "
                  "triggered",
                  final_hits, final_ack, armed_seq, verify_seq,
                  final_hits > pre_hits + 5 ? "LIVE" : "possibly dead");
    } else if (final_step > 0 && final_step < 5) {
        const char* step_names[] = {
            "?", "lua_newthread", "luau_load", "lua_resume",
            "lua_settop(-2)", "ack"
        };
        const char* sn = (final_step <= 5)
            ? step_names[final_step] : "?";
        LOG_ERROR("[direct-hook] execution stalled at step {} "
                  "({}) — likely deadlock or crash inside Luau "
                  "call (guard={}, hits={}, ack={}, armed_seq={})",
                  final_step, sn, final_guard, final_hits,
                  final_ack, armed_seq);
    } else {
        LOG_ERROR("[direct-hook] execution timeout: step={} "
                  "guard={} ack={} armed_seq={} verify_seq={} "
                  "hits={}",
                  final_step, final_guard, final_ack, armed_seq,
                  verify_seq, final_hits);
    }
    return false;
}

bool Injection::inject() {
    if (!attach()) return false;

    if (dhook_.active && payload_loaded_ && process_alive()) {
        LOG_INFO("[inject] direct hook already active for PID {}", memory_.get_pid());
        return true;
    }

    if (!process_alive()) {
        cleanup_direct_hook();
        set_state(InjectionState::Failed, "Process died during injection");
        memory_.set_pid(0);
        return false;
    }

    std::string payload = find_payload_path();
    if (!payload.empty()) {
        {
            std::ifstream scope_file("/proc/sys/kernel/yama/ptrace_scope");
            if (scope_file.is_open()) {
                int scope = -1;
                scope_file >> scope;
                scope_file.close();
                if (scope > 0) {
                    LOG_WARN("yama/ptrace_scope is {} (need 0 for ptrace path)", scope);
                    bool fixed = false;

                    {
                        std::ofstream fix("/proc/sys/kernel/yama/ptrace_scope",
                                         std::ios::trunc);
                        if (fix.is_open()) { fix << "0"; fix.close(); }
                    }
                    {
                        std::ifstream rc("/proc/sys/kernel/yama/ptrace_scope");
                        int v = -1;
                        if (rc.is_open()) rc >> v;
                        if (v == 0) { LOG_INFO("Auto-lowered ptrace_scope to 0"); fixed = true; }
                    }

                    if (!fixed) {
                        LOG_INFO("Requesting elevated privileges to lower ptrace_scope...");
                        pid_t pk = fork();
                        if (pk == 0) {
                            const char* argv[] = {
                                "pkexec", "sh", "-c",
                                "echo 0 > /proc/sys/kernel/yama/ptrace_scope",
                                nullptr
                            };
                            execvp("pkexec", const_cast<char* const*>(argv));
                            _exit(127);
                        } else if (pk > 0) {
                            int st = 0;
                            waitpid(pk, &st, 0);
                            std::ifstream rc("/proc/sys/kernel/yama/ptrace_scope");
                            int v = -1;
                            if (rc.is_open()) rc >> v;
                            if (v == 0) {
                                LOG_INFO("ptrace_scope lowered to 0 via pkexec");
                                fixed = true;
                            }
                        }
                    }

                    if (!fixed) {
                        LOG_WARN("Cannot lower ptrace_scope — will use /proc/pid/mem fallback");
                    }
                }
            }
        }

        set_state(InjectionState::Injecting,
                  "Injecting payload library into PID " +
                  std::to_string(memory_.get_pid()) + "...");

        if (inject_library(memory_.get_pid(), payload)) {
            set_state(InjectionState::Initializing,
                      "Payload loaded — waiting for init...");

            auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::seconds(5);
            bool handshake = false;
            while (std::chrono::steady_clock::now() < deadline) {
                if (verify_payload_alive()) {
                    handshake = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (handshake) {
                LOG_INFO("Payload handshake confirmed");
            } else {
                LOG_WARN("Payload handshake timeout — library may still be initializing");
            }
       
            payload_loaded_ = true;
        } else {
            // *** CHUNK 2 APPLIED: direct hook fallback after library injection failure ***
            LOG_WARN("Library injection failed ({}), continuing with VM-scan mode", error_);

            if (proc_info_.via_flatpak || proc_info_.via_sober) {
                std::string staged = "/proc/" + std::to_string(memory_.get_pid()) +
                                     "/root/tmp/liboss_payload.so";
                if (std::remove(staged.c_str()) == 0)
                    LOG_DEBUG("Cleaned up staged payload: {}", staged);
            }

            LOG_INFO("Attempting direct hook injection (bypass dlopen)...");
            set_state(InjectionState::Injecting, "Trying direct hook injection...");
            if (inject_via_direct_hook(memory_.get_pid())) {
                payload_loaded_ = true;
                LOG_INFO("Direct hook injection succeeded");
            } else {
                LOG_WARN("Direct hook injection failed: {}", error_);
            }
        }
    } else {
        // *** CHUNK 2 APPLIED: direct hook when no payload library found ***
        LOG_WARN("Payload library not found, trying direct hook injection...");
        set_state(InjectionState::Injecting, "Direct hook injection (no payload library)...");
        if (inject_via_direct_hook(memory_.get_pid())) {
            payload_loaded_ = true;
            LOG_INFO("Direct hook injection succeeded without payload library");
        } else {
            LOG_WARN("Direct hook injection failed: {}", error_);
        }
    }

    bool found = locate_luau_vm();

    // *** CHUNK 3 APPLIED: direct hook mode check ***
    if (payload_loaded_) {
        mode_ = InjectionMode::Full;
        if (dhook_.active) {
            set_state(InjectionState::Ready,
                      "Direct hook active \u2014 bypassed dlopen/seccomp");
            LOG_INFO("Mode: Full (direct hook) | mailbox=0x{:X} cave=0x{:X}",
                     dhook_.mailbox_addr, dhook_.cave_addr);
        } else if (found) {
            std::ostringstream hex;
            hex << "0x" << std::hex << vm_scan_.marker_addr;
            set_state(InjectionState::Ready,
                      "Injection complete \u2014 Luau VM at " + hex.str());
            LOG_INFO("Mode: Full | marker='{}' @ 0x{:X} | validated={} | "
                     "region='{}' base=0x{:X}",
                     vm_scan_.marker_name, vm_scan_.marker_addr,
                     vm_scan_.validated,
                     vm_scan_.region_path, vm_scan_.region_base);
        } else {
            set_state(InjectionState::Ready,
                      "Payload injected \u2014 hook active");
            LOG_INFO("Mode: Full (payload hook) | VM markers not found "
                     "({} regions, {:.1f}MB scanned)",
                     vm_scan_.regions_scanned,
                     vm_scan_.bytes_scanned / (1024.0 * 1024.0));
        }
    } else {
        mode_ = InjectionMode::LocalOnly;
        if (found) {
            set_state(InjectionState::Ready,
                      "Attached \u2014 VM located, no payload injected");
            LOG_WARN("VM markers found but payload injection failed");
        } else {
            set_state(InjectionState::Ready,
                      "Attached \u2014 local execution mode");
            LOG_WARN("No Luau markers in {} regions ({:.1f}MB). PID: {}",
                     vm_scan_.regions_scanned,
                     vm_scan_.bytes_scanned / (1024.0 * 1024.0),
                     memory_.get_pid());
        }
    }
    return true;
}

bool Injection::verify_payload_alive() {
    if (!payload_loaded_ || !process_alive()) return false;

    bool mapped = false;
    auto regions = memory_.get_regions();
    for (const auto& r : regions) {
        if (r.path.find("liboss_payload") != std::string::npos ||
            r.path.find("oss_payload") != std::string::npos ||
            r.path.find("liboss") != std::string::npos) {
            mapped = true;
            break;
        }
        if (!payload_mapped_name_.empty() &&
            r.path.find(payload_mapped_name_) != std::string::npos) {
            mapped = true;
            break;
        }
    }
    if (!mapped && (proc_info_.via_flatpak || proc_info_.via_sober)) {
        mapped = true;
        LOG_DEBUG("verify_payload_alive: skipping maps check for "
                  "Flatpak/Sober (library may be mapped under remapped name)");
    }
    if (!mapped) return false;

    std::string prefix;
    pid_t pid = memory_.get_pid();
    if ((proc_info_.via_flatpak || proc_info_.via_sober) && pid > 0)
        prefix = "/proc/" + std::to_string(pid) + "/root";

    struct stat st;
    if (::stat((prefix + "/tmp/oss_payload_ready").c_str(), &st) == 0)
        return true;

    int afd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (afd >= 0) {
        struct sockaddr_un abs_addr{};
        abs_addr.sun_family = AF_UNIX;
        abs_addr.sun_path[0] = '\0';
        static constexpr char ABS_SOCK[] = "oss_executor_v2";
        memcpy(abs_addr.sun_path + 1, ABS_SOCK, sizeof(ABS_SOCK) - 1);
        socklen_t abs_len = static_cast<socklen_t>(
            offsetof(struct sockaddr_un, sun_path) + 1 + sizeof(ABS_SOCK) - 1);
        struct timeval tv{}; tv.tv_usec = 500000;
        setsockopt(afd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        bool ok = (::connect(afd, reinterpret_cast<struct sockaddr*>(&abs_addr), abs_len) == 0);
        ::close(afd);
        if (ok) return true;
    }

    std::string sock_path = prefix + PAYLOAD_SOCK;
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0) {
        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
        struct timeval tv{}; tv.tv_usec = 500000;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        bool ok = (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);
        ::close(fd);
        if (ok) return true;
    }

    if (::stat((prefix + "/tmp/oss_payload_cmd").c_str(), &st) == 0)
        return true;

    LOG_WARN("Payload mapped but no IPC channel reachable");
    return mapped;
}

bool Injection::execute_script(const std::string& source) {
    if (state_ != InjectionState::Ready) {
        LOG_ERROR("execute_script: not in Ready state");
        return false;
    }

    if (!process_alive()) {
        set_state(InjectionState::Failed, "Target process exited");
        mode_ = InjectionMode::None;
        payload_loaded_ = false;
        memory_.set_pid(0);
        return false;
    }

    if (source.empty()) return true;

    // *** CHUNK 5 APPLIED: direct hook mailbox path ***
    if (!payload_loaded_) {
        set_state(InjectionState::Ready, "No payload \u2014 local execution only");
        return false;
    }

    set_state(InjectionState::Executing,
              "Executing (" + std::to_string(source.size()) + " bytes)...");

    if (dhook_.active) {
        size_t bc_len = 0;
        char* bc = luau_compile(source.c_str(), source.size(), nullptr, &bc_len);
        if (!bc || bc_len == 0 || static_cast<uint8_t>(bc[0]) == 0) {
            std::string ce = (bc && bc_len > 1) ? std::string(bc + 1, bc_len - 1) : "unknown";
            free(bc);
            set_state(InjectionState::Ready, "Compile error: " + ce);
            LOG_ERROR("Compile failed: {}", ce);
            return false;
        }
        uint8_t bc_ver = static_cast<uint8_t>(bc[0]);
        LOG_INFO("Compiled {} bytes -> {} bytes bytecode (v{})",
                 source.size(), bc_len, static_cast<int>(bc_ver));
        if (bc_ver < 3 || bc_ver > 6) {
            free(bc);
            set_state(InjectionState::Ready,
                "Bytecode version " + std::to_string(bc_ver) +
                " may not match Roblox VM — update Luau in CMakeLists.txt");
            LOG_WARN("Bytecode version {} outside expected range [3..6]", static_cast<int>(bc_ver));
            return false;
        }
        if (bc_len > 16320) {
            free(bc);
            set_state(InjectionState::Ready, "Bytecode too large for mailbox");
            LOG_ERROR("Bytecode {} bytes exceeds mailbox limit 16320", bc_len);
            return false;
        }
        uint64_t armed_seq = send_via_mailbox(bc, bc_len, 1);
        size_t sent_bc_len = bc_len;
        uint8_t sent_bc_ver = bc_ver;
        free(bc);
        if (armed_seq > 0) {
            bool executed = wait_for_mailbox_ack(armed_seq, sent_bc_len, sent_bc_ver);
            if (executed) {
                set_state(InjectionState::Ready, "Script executed in Roblox");
                return true;
            }
            uint32_t final_step = 0;
            proc_mem_read(memory_.get_pid(), dhook_.mailbox_addr + 44, &final_step, 4);
            set_state(InjectionState::Ready,
                      "Script dispatch timeout — step " +
                      std::to_string(final_step));
            return false;
        }
        LOG_WARN("Direct hook mailbox send failed, trying IPC fallback");
    }

    std::string data_to_send;
    {
        size_t bc_len = 0;
        char* bc = luau_compile(source.c_str(), source.size(), nullptr, &bc_len);
        if (!bc || bc_len == 0 || static_cast<uint8_t>(bc[0]) == 0) {
            std::string ce = (bc && bc_len > 1) ? std::string(bc + 1, bc_len - 1) : "unknown";
            free(bc);
            set_state(InjectionState::Ready, "Compile error: " + ce);
            LOG_ERROR("Compile failed: {}", ce);
            return false;
        }
        free(bc);
        data_to_send = source;
        LOG_INFO("Syntax verified, sending {} bytes source to payload for target-side compilation",
                 data_to_send.size());
    }

    {
        int afd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (afd >= 0) {
            struct timeval atv{};
            atv.tv_sec = 2;
            setsockopt(afd, SOL_SOCKET, SO_SNDTIMEO, &atv, sizeof(atv));

            struct sockaddr_un abs_addr{};
            abs_addr.sun_family = AF_UNIX;
            abs_addr.sun_path[0] = '\0';
            static constexpr char ABS_SOCK[] = "oss_executor_v2";
            memcpy(abs_addr.sun_path + 1, ABS_SOCK, sizeof(ABS_SOCK) - 1);
            socklen_t abs_len = static_cast<socklen_t>(
                offsetof(struct sockaddr_un, sun_path) + 1 + sizeof(ABS_SOCK) - 1);

            if (::connect(afd, reinterpret_cast<struct sockaddr*>(&abs_addr), abs_len) == 0) {
                const char* wd = data_to_send.data();
                size_t rem = data_to_send.size();
                bool wok = true;
                while (rem > 0) {
                    ssize_t n = ::write(afd, wd, rem);
                    if (n <= 0) { wok = false; break; }
                    wd += n;
                    rem -= static_cast<size_t>(n);
                }
                ::shutdown(afd, SHUT_WR);
                ::close(afd);
                if (wok) {
                    set_state(InjectionState::Ready, "Script dispatched to payload");
                    LOG_INFO("Sent {} bytes to payload via abstract socket @{}",
                             data_to_send.size(), ABS_SOCK);
                    return true;
                }
            } else {
                ::close(afd);
            }
        }
    }
  

    std::string sock_path = PAYLOAD_SOCK;
    if (proc_info_.via_flatpak || proc_info_.via_sober) {
        pid_t pid = memory_.get_pid();
        if (pid > 0)
            sock_path = "/proc/" + std::to_string(pid) + "/root" + PAYLOAD_SOCK;
    }

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        set_state(InjectionState::Ready, "Socket creation failed");
        LOG_ERROR("execute_script socket(): {}", strerror(errno));
        return false;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    struct timeval tv{};
    tv.tv_sec = 2;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_WARN("Socket connect failed ({}): {} — trying file IPC",
                 sock_path, strerror(errno));
        ::close(fd);

        
        std::string cmd_path = "/tmp/oss_payload_cmd";
        if (proc_info_.via_flatpak || proc_info_.via_sober) {
            pid_t pid = memory_.get_pid();
            if (pid > 0)
                cmd_path = "/proc/" + std::to_string(pid) +
                           "/root/tmp/oss_payload_cmd";
        }

        LOG_INFO("File IPC fallback: {}", cmd_path);

        std::string ack_path = cmd_path;
        {
            auto dot = ack_path.rfind("_cmd");
            if (dot != std::string::npos)
                ack_path.replace(dot, 4, "_ack");
            else
                ack_path += ".ack";
        }
        ::unlink(ack_path.c_str());

        std::string tmp_cmd = cmd_path + ".tmp";
        int cmd_fd = ::open(tmp_cmd.c_str(),
                            O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (cmd_fd >= 0) {
            const char* wd = data_to_send.data();
            size_t rem = data_to_send.size();
            bool fok = true;
            while (rem > 0) {
                ssize_t n = ::write(cmd_fd, wd, rem);
                if (n <= 0) { fok = false; break; }
                wd += n;
                rem -= static_cast<size_t>(n);
            }
            ::fsync(cmd_fd);
            ::close(cmd_fd);
            if (fok && ::rename(tmp_cmd.c_str(), cmd_path.c_str()) == 0) {
                LOG_INFO("Sent {} bytes via file IPC: {}",
                         data_to_send.size(), cmd_path);

                struct stat ack_st;
                bool ack_received = false;
                for (int ai = 0; ai < 40; ai++) {
                    usleep(50000);
                    if (::stat(ack_path.c_str(), &ack_st) == 0) {
                        ack_received = true;
                        ::unlink(ack_path.c_str());
                        break;
                    }
                    struct stat cmd_st;
                    if (::stat(cmd_path.c_str(), &cmd_st) != 0) {
                        ack_received = true;
                        LOG_DEBUG("File IPC: cmd file consumed by payload");
                        break;
                    }
                }
                if (ack_received) {
                    set_state(InjectionState::Ready,
                              "Script executed via file IPC");
                    LOG_INFO("File IPC confirmed: payload consumed command");
                } else {
                    set_state(InjectionState::Ready,
                              "Script dispatched via file IPC (unconfirmed)");
                    LOG_WARN("File IPC: no ack after 2s — payload may not "
                             "have consumed the command");
                }
                return true;
            }
            LOG_ERROR("File IPC write/rename error: {}", strerror(errno));
            ::unlink(tmp_cmd.c_str());
        } else {
            LOG_ERROR("Cannot create cmd file {}: {}", tmp_cmd, strerror(errno));
        }

        if (!dhook_.active) {
            LOG_INFO("All IPC channels failed — attempting direct hook "
                     "as secondary execution channel");
            pid_t cur_pid = memory_.get_pid();
            if (cur_pid > 0 && kill(cur_pid, 0) == 0) {
                if (inject_via_direct_hook(cur_pid)) {
                    LOG_INFO("Direct hook established as secondary "
                             "execution channel");
                    size_t bc_len = 0;
                    char* bc = luau_compile(source.c_str(), source.size(),
                                            nullptr, &bc_len);
                    if (bc && bc_len > 0 &&
                        static_cast<uint8_t>(bc[0]) != 0 &&
                        bc_len <= 16320) {
                        uint64_t armed_seq = send_via_mailbox(bc, bc_len, 1);
                        size_t sent_len = bc_len;
                        uint8_t sent_ver = static_cast<uint8_t>(bc[0]);
                        free(bc);
                        if (armed_seq > 0) {
                            bool exec_ok = wait_for_mailbox_ack(
                                armed_seq, sent_len, sent_ver);
                            if (exec_ok) {
                                set_state(InjectionState::Ready,
                                          "Script executed via direct "
                                          "hook (IPC bypass)");
                                return true;
                            }
                        }
                    } else {
                        free(bc);
                    }
                    set_state(InjectionState::Ready,
                              "Direct hook active but script execution "
                              "failed");
                    return false;
                }
            }
            payload_loaded_ = false;
            set_state(InjectionState::Ready,
                      "Payload unreachable (all channels failed)");
        } else {
            set_state(InjectionState::Ready,
                      "IPC channels unreachable but direct hook still "
                      "active");
        }
        return false;
    }

    const char* data = data_to_send.data();
    size_t remaining = data_to_send.size();
    bool write_ok = true;
    while (remaining > 0) {
        ssize_t n = ::write(fd, data, remaining);
        if (n <= 0) {
            LOG_ERROR("execute_script write(): {}", strerror(errno));
            write_ok = false;
            break;
        }
        data += n;
        remaining -= static_cast<size_t>(n);
    }

    ::shutdown(fd, SHUT_WR);
    ::close(fd);

    if (write_ok) {
        set_state(InjectionState::Ready, "Script dispatched to payload");
        LOG_INFO("Sent {} bytes to payload via @oss_executor", data_to_send.size());
        return true;
    }

    set_state(InjectionState::Ready, "Script dispatch failed");
    return false;
}

void Injection::start_auto_scan() {
    bool expected = false;
    if (!scanning_.compare_exchange_strong(expected, true)) return;

    scan_thread_ = std::thread([this]() {
        LOG_INFO("Auto-scan started");
        while (scanning_.load()) {
            if (memory_.is_valid() && !process_alive()) {
                LOG_WARN("Target process exited, resetting");
                cleanup_direct_hook();
                mode_            = InjectionMode::None;
                vm_marker_addr_  = 0;
                vm_scan_         = {};
                proc_info_       = {};
                payload_loaded_  = false;
                payload_mapped_name_.clear();
                memory_.set_pid(0);
                set_state(InjectionState::Idle, "Process exited \u2014 rescanning...");
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

}

















































































































