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

static pid_t get_tracer_pid(pid_t pid) {
    std::ifstream status("/proc/" + std::to_string(pid) + "/status");
    if (!status.is_open()) return -1;
    std::string line;
    while (std::getline(status, line)) {
        if (line.compare(0, 10, "TracerPid:") == 0) {
            pid_t tp = 0;
            sscanf(line.c_str() + 10, "%d", &tp);
            return tp;
        }
    }
    return 0;
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
    return w == static_cast<ssize_t>(len);
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

bool Injection::inject_via_procmem(pid_t pid, const std::string& lib_path,
                                    uintptr_t dlopen_addr) {
    LOG_INFO("Attempting /proc/pid/mem injection (ptrace-free) for PID {}", pid);

    pid_t tracer = get_tracer_pid(pid);
    if (tracer > 0) {
        LOG_WARN("PID {} is already traced by PID {} — may affect injection", pid, tracer);
    }

    std::string mem_path = "/proc/" + std::to_string(pid) + "/mem";
    int test_fd = open(mem_path.c_str(), O_RDWR);
    if (test_fd < 0) {
        LOG_ERROR("Cannot open {} for writing: {}", mem_path, strerror(errno));
        return false;
    }
    close(test_fd);
    LOG_DEBUG("Confirmed /proc/pid/mem is writable");

    auto regions = memory_.get_regions();
    if (regions.empty()) {
        LOG_ERROR("No memory regions available");
        return false;
    }

    uintptr_t data_addr = 0;
    for (const auto& r : regions) {
        if (!r.writable() || !r.readable()) continue;
        if (r.size() < 4096) continue;
        if (r.path.find("[stack") != std::string::npos) continue;
        if (r.path.find("[vvar") != std::string::npos) continue;
        if (r.path.find("[vdso") != std::string::npos) continue;
        data_addr = r.end - 4096;
        LOG_DEBUG("Using data region at 0x{:X} from '{}'", data_addr,
                  r.path.empty() ? "[anon]" : r.path);
        break;
    }
    if (data_addr == 0) {
        LOG_ERROR("No suitable writable region found");
        return false;
    }

    uint8_t orig_data[4096];
    if (!proc_mem_read(pid, data_addr, orig_data, sizeof(orig_data))) {
        LOG_ERROR("Failed to save original data region");
        return false;
    }

    size_t path_offset = 0;
    memset(orig_data + path_offset, 0, lib_path.size() + 1);

    uint8_t path_buf[512] = {};
    size_t path_len = std::min(lib_path.size(), sizeof(path_buf) - 1);
    memcpy(path_buf, lib_path.c_str(), path_len);
    if (!proc_mem_write(pid, data_addr, path_buf, path_len + 1)) {
        LOG_ERROR("Failed to write library path to data region");
        return false;
    }

    size_t flag_offset = 512;
    uintptr_t flag_addr = data_addr + flag_offset;
    uint64_t zero = 0;
    proc_mem_write(pid, flag_addr, &zero, sizeof(zero));

    size_t shellcode_needed = 256;
    ExeRegionInfo cave;
    if (!find_code_cave(pid, regions, shellcode_needed, cave)) {
        LOG_ERROR("No suitable code cave found for shellcode");
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }
    LOG_DEBUG("Code cave at 0x{:X} ({} bytes available)", cave.padding_start, cave.padding_size);

    uint8_t orig_cave[256];
    if (!proc_mem_read(pid, cave.padding_start, orig_cave, shellcode_needed)) {
        LOG_ERROR("Failed to save original code cave bytes");
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }

    uintptr_t path_addr = data_addr;

    uint8_t sc[256];
    int off = 0;

    sc[off++] = 0x50;
    sc[off++] = 0x51;
    sc[off++] = 0x52;
    sc[off++] = 0x53;
    sc[off++] = 0x56;
    sc[off++] = 0x57;
    sc[off++] = 0x41; sc[off++] = 0x50;
    sc[off++] = 0x41; sc[off++] = 0x51;
    sc[off++] = 0x41; sc[off++] = 0x52;
    sc[off++] = 0x41; sc[off++] = 0x53;
    sc[off++] = 0x41; sc[off++] = 0x54;
    sc[off++] = 0x41; sc[off++] = 0x55;
    sc[off++] = 0x41; sc[off++] = 0x56;
    sc[off++] = 0x41; sc[off++] = 0x57;

    sc[off++] = 0x48; sc[off++] = 0x83; sc[off++] = 0xE4; sc[off++] = 0xF0;

    sc[off++] = 0x48; sc[off++] = 0xBF;
    memcpy(sc + off, &path_addr, 8); off += 8;

    uint64_t dlopen_flags = 0x00000002ULL;
    sc[off++] = 0x48; sc[off++] = 0xBE;
    memcpy(sc + off, &dlopen_flags, 8); off += 8;

    sc[off++] = 0x48; sc[off++] = 0xB8;
    memcpy(sc + off, &dlopen_addr, 8); off += 8;

    sc[off++] = 0xFF; sc[off++] = 0xD0;

    sc[off++] = 0x48; sc[off++] = 0xB9;
    memcpy(sc + off, &flag_addr, 8); off += 8;
    sc[off++] = 0x48; sc[off++] = 0x89; sc[off++] = 0x01;

    int loop_top = off;
    sc[off++] = 0x48; sc[off++] = 0xB9;
    memcpy(sc + off, &flag_addr, 8); off += 8;
    sc[off++] = 0x48; sc[off++] = 0x8B; sc[off++] = 0x09;
    sc[off++] = 0x48; sc[off++] = 0x83; sc[off++] = 0xF9; sc[off++] = 0x01;
    sc[off++] = 0x74; sc[off++] = 0x06;
    sc[off++] = 0xF3; sc[off++] = 0x90;
    int8_t jmp_back = static_cast<int8_t>(loop_top - (off + 2));
    sc[off++] = 0xEB; sc[off++] = static_cast<uint8_t>(jmp_back);

    sc[off++] = 0x41; sc[off++] = 0x5F;
    sc[off++] = 0x41; sc[off++] = 0x5E;
    sc[off++] = 0x41; sc[off++] = 0x5D;
    sc[off++] = 0x41; sc[off++] = 0x5C;
    sc[off++] = 0x41; sc[off++] = 0x5B;
    sc[off++] = 0x41; sc[off++] = 0x5A;
    sc[off++] = 0x41; sc[off++] = 0x59;
    sc[off++] = 0x41; sc[off++] = 0x58;
    sc[off++] = 0x5F;
    sc[off++] = 0x5E;
    sc[off++] = 0x5B;
    sc[off++] = 0x5A;
    sc[off++] = 0x59;
    sc[off++] = 0x58;
    sc[off++] = 0xC3;

    if (static_cast<size_t>(off) > shellcode_needed) {
        LOG_ERROR("Shellcode too large: {} > {}", off, shellcode_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }

    if (!proc_mem_write(pid, cave.padding_start, sc, off)) {
        LOG_ERROR("Failed to write shellcode to code cave");
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }
    LOG_DEBUG("Shellcode written: {} bytes at 0x{:X}", off, cave.padding_start);

    if (kill(pid, SIGSTOP) != 0) {
        LOG_ERROR("SIGSTOP failed: {}", strerror(errno));
        proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }
    usleep(50000);

    std::string stat_path = "/proc/" + std::to_string(pid) + "/stat";
    bool stopped = false;
    for (int i = 0; i < 20; i++) {
        std::ifstream sf(stat_path);
        std::string sline;
        std::getline(sf, sline);
        auto ce = sline.rfind(')');
        if (ce != std::string::npos && ce + 2 < sline.size()) {
            char state = sline[ce + 2];
            if (state == 'T' || state == 't') { stopped = true; break; }
        }
        usleep(10000);
    }

    if (!stopped) {
        LOG_ERROR("Process did not stop after SIGSTOP");
        kill(pid, SIGCONT);
        proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }

    pid_t tid = pick_injectable_thread(pid);
    ThreadState ts;
    if (!get_thread_state(pid, tid, ts)) {
        LOG_ERROR("Cannot read thread state for TID {}", tid);
        kill(pid, SIGCONT);
        proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }
    LOG_DEBUG("Thread {} state: RIP=0x{:X} RSP=0x{:X}", tid, ts.rip, ts.rsp);

    uint8_t orig_rip_code[16];
    if (!proc_mem_read(pid, ts.rip, orig_rip_code, sizeof(orig_rip_code))) {
        LOG_ERROR("Failed to read original code at RIP 0x{:X}", ts.rip);
        kill(pid, SIGCONT);
        proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }

    uint8_t trampoline[16];
    int toff = 0;
    trampoline[toff++] = 0x48; trampoline[toff++] = 0xB8;
    memcpy(trampoline + toff, &cave.padding_start, 8); toff += 8;

    uintptr_t return_addr = ts.rip;
    uintptr_t new_rsp = ts.rsp - 128;

    uint8_t stack_setup[32];
    int soff = 0;
    stack_setup[soff++] = 0x48; stack_setup[soff++] = 0x81;
    stack_setup[soff++] = 0xEC;
    uint32_t sub_val = 128;
    memcpy(stack_setup + soff, &sub_val, 4); soff += 4;
    stack_setup[soff++] = 0x48; stack_setup[soff++] = 0xB9;
    memcpy(stack_setup + soff, &return_addr, 8); soff += 8;
    stack_setup[soff++] = 0x51;

    (void)new_rsp;
    (void)stack_setup;
    (void)soff;

    trampoline[toff++] = 0x50;

    trampoline[toff++] = 0x48; trampoline[toff++] = 0xB8;
    uintptr_t cave_addr = cave.padding_start;
    memcpy(trampoline + toff, &cave_addr, 8); toff += 8;

    toff = 0;

    trampoline[toff++] = 0x68;
    uint32_t ret_lo = static_cast<uint32_t>(return_addr & 0xFFFFFFFF);
    memcpy(trampoline + toff, &ret_lo, 4); toff += 4;

    if ((return_addr >> 32) != 0) {
        trampoline[toff++] = 0xC7; trampoline[toff++] = 0x44;
        trampoline[toff++] = 0x24; trampoline[toff++] = 0x04;
        uint32_t ret_hi = static_cast<uint32_t>(return_addr >> 32);
        memcpy(trampoline + toff, &ret_hi, 4); toff += 4;
    }

    trampoline[toff++] = 0xE9;
    int32_t rel32 = static_cast<int32_t>(
        static_cast<int64_t>(cave.padding_start) -
        static_cast<int64_t>(ts.rip + toff + 4));
    memcpy(trampoline + toff, &rel32, 4); toff += 4;

    bool use_rel_jmp = true;
    int64_t displacement = static_cast<int64_t>(cave.padding_start) -
                           static_cast<int64_t>(ts.rip + 5);
    if (displacement < INT32_MIN || displacement > INT32_MAX) {
        use_rel_jmp = false;
    }

    toff = 0;
    memset(trampoline, 0, sizeof(trampoline));

    if (use_rel_jmp) {
        trampoline[toff++] = 0x68;
        memcpy(trampoline + toff, &ret_lo, 4); toff += 4;
        if ((return_addr >> 32) != 0) {
            trampoline[toff++] = 0xC7; trampoline[toff++] = 0x44;
            trampoline[toff++] = 0x24; trampoline[toff++] = 0x04;
            uint32_t ret_hi = static_cast<uint32_t>(return_addr >> 32);
            memcpy(trampoline + toff, &ret_hi, 4); toff += 4;
        }
        trampoline[toff++] = 0xE9;
        rel32 = static_cast<int32_t>(
            static_cast<int64_t>(cave.padding_start) -
            static_cast<int64_t>(ts.rip + toff + 4));
        memcpy(trampoline + toff, &rel32, 4); toff += 4;
    } else {
        trampoline[toff++] = 0x68;
        memcpy(trampoline + toff, &ret_lo, 4); toff += 4;
        if ((return_addr >> 32) != 0) {
            trampoline[toff++] = 0xC7; trampoline[toff++] = 0x44;
            trampoline[toff++] = 0x24; trampoline[toff++] = 0x04;
            uint32_t ret_hi = static_cast<uint32_t>(return_addr >> 32);
            memcpy(trampoline + toff, &ret_hi, 4); toff += 4;
        }
        trampoline[toff++] = 0xFF; trampoline[toff++] = 0x25;
        uint32_t z = 0;
        memcpy(trampoline + toff, &z, 4); toff += 4;
        memcpy(trampoline + toff, &cave_addr, 8); toff += 8;
    }

    if (toff > static_cast<int>(sizeof(orig_rip_code))) {
        LOG_ERROR("Trampoline too large: {} bytes", toff);
        kill(pid, SIGCONT);
        proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }

    if (!proc_mem_write(pid, ts.rip, trampoline, toff)) {
        LOG_ERROR("Failed to write trampoline at RIP 0x{:X}", ts.rip);
        kill(pid, SIGCONT);
        proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        return false;
    }
    LOG_DEBUG("Trampoline written: {} bytes at 0x{:X}", toff, ts.rip);

    kill(pid, SIGCONT);
    LOG_DEBUG("Process resumed, waiting for dlopen completion...");

    bool completed = false;
    for (int i = 0; i < 100; i++) {
        usleep(50000);
        uint64_t flag_val = 0;
        if (proc_mem_read(pid, flag_addr, &flag_val, sizeof(flag_val)) && flag_val != 0) {
            LOG_INFO("dlopen completed, handle=0x{:X}", flag_val);
            completed = true;
            break;
        }
        if (kill(pid, 0) != 0) {
            LOG_ERROR("Process died during injection");
            return false;
        }
    }

    if (!completed) {
        LOG_ERROR("dlopen did not complete within timeout");
        kill(pid, SIGSTOP);
        usleep(50000);
        proc_mem_write(pid, ts.rip, orig_rip_code, sizeof(orig_rip_code));
        proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        kill(pid, SIGCONT);
        return false;
    }

    uint64_t signal_done = 1;
    proc_mem_write(pid, flag_addr, &signal_done, sizeof(signal_done));

    usleep(50000);

    kill(pid, SIGSTOP);
    usleep(50000);

    proc_mem_write(pid, ts.rip, orig_rip_code, sizeof(orig_rip_code));
    proc_mem_write(pid, cave.padding_start, orig_cave, shellcode_needed);

    uint8_t zero_region[4096] = {};
    proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));

    kill(pid, SIGCONT);
    LOG_INFO("Injection complete, process restored and resumed");

    payload_loaded_ = true;
    return true;
}

bool Injection::inject_library(pid_t pid, const std::string& lib_path) {
    LOG_INFO("Injecting {} into PID {}", lib_path, pid);

    if (!fs::exists(lib_path)) {
        error_ = "Payload library does not exist: " + lib_path;
        LOG_ERROR("inject_library: {}", error_);
        return false;
    }

    std::string target_path = prepare_payload_for_injection(pid, lib_path);

    bool libc_internal = false;
    uintptr_t dlopen_addr = find_remote_symbol(pid, "c", "__libc_dlopen_mode");
    if (dlopen_addr != 0) {
        libc_internal = true;
        LOG_DEBUG("Remote __libc_dlopen_mode at 0x{:x}", dlopen_addr);
    } else {
        dlopen_addr = find_remote_symbol(pid, "dl", "dlopen");
        if (dlopen_addr == 0)
            dlopen_addr = find_remote_symbol(pid, "c", "dlopen");
        if (dlopen_addr != 0)
            LOG_DEBUG("Remote dlopen at 0x{:x}", dlopen_addr);
    }

    if (dlopen_addr == 0) {
        error_ = "Could not find dlopen in target process";
        LOG_ERROR("inject_library: {}", error_);
        return false;
    }

    uint64_t flags = libc_internal ? 0x80000002ULL : 0x00000002ULL;

    pid_t tracer = get_tracer_pid(pid);
    if (tracer > 0)
        LOG_WARN("Target PID {} is already traced by PID {}", pid, tracer);

    bool ptrace_ok = false;
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

    if (ptrace_ok) {
        LOG_INFO("Using ptrace injection path");
        bool result = inject_shellcode_ptrace(pid, target_path, dlopen_addr, flags);
        if (result) return true;
        LOG_WARN("ptrace injection failed: {}", error_);
    }

    LOG_INFO("Falling back to /proc/pid/mem injection path");
    return inject_via_procmem(pid, target_path, dlopen_addr);
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
    uintptr_t path_addr = mem_addr + path_offset;
    memcpy(shellcode + sc_off, &path_addr, 8); sc_off += 8;

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

bool Injection::detach() {
    set_state(InjectionState::Detached, "Detached");
    memory_.set_pid(0);
    mode_            = InjectionMode::None;
    vm_marker_addr_  = 0;
    vm_scan_         = {};
    proc_info_       = {};
    payload_loaded_  = false;
    return true;
}

bool Injection::inject() {
    if (!attach()) return false;

    if (!process_alive()) {
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
        } else {
            LOG_WARN("Library injection failed ({}), continuing with VM-scan mode", error_);

            if (proc_info_.via_flatpak || proc_info_.via_sober) {
                std::string staged = "/proc/" + std::to_string(memory_.get_pid()) +
                                     "/root/tmp/liboss_payload.so";
                if (std::remove(staged.c_str()) == 0)
                    LOG_DEBUG("Cleaned up staged payload: {}", staged);
            }
        }
    } else {
        LOG_WARN("Payload library not found, using memory-scan mode");
    }

    bool found = locate_luau_vm();

    if (payload_loaded_) {
        mode_ = InjectionMode::Full;
        if (found) {
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
        if (r.path.find("liboss_payload") != std::string::npos) {
            mapped = true;
            break;
        }
    }
    if (!mapped) {
        payload_loaded_ = false;
        return false;
    }

    std::string sock = resolve_socket_path();
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return false;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock.c_str(), sizeof(addr.sun_path) - 1);
    struct timeval tv{};
    tv.tv_usec = 500000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    bool reachable = (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr),
                                sizeof(addr)) == 0);
    ::close(fd);

    if (!reachable) {
        LOG_WARN("Payload mapped but socket unreachable at {}", sock);
        payload_loaded_ = false;
    }
    return reachable;
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

    if (!payload_loaded_) {
        set_state(InjectionState::Ready, "No payload \u2014 local execution only");
        return false;
    }

    set_state(InjectionState::Executing,
              "Executing (" + std::to_string(source.size()) + " bytes)...");

    std::string data_to_send;
    size_t bc_size = 0;
    char* bc = luau_compile(source.c_str(), source.size(), nullptr, &bc_size);
    if (bc && bc_size > 0 && static_cast<uint8_t>(bc[0]) != 0) {
        data_to_send.assign(bc, bc_size);
        LOG_DEBUG("Pre-compiled {} bytes source to {} bytes bytecode",
                  source.size(), bc_size);
    } else {
        data_to_send = source;
        LOG_DEBUG("Pre-compilation skipped, sending {} bytes source", source.size());
    }
    free(bc);

    std::string sock = resolve_socket_path();

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        set_state(InjectionState::Ready, "Socket creation failed");
        LOG_ERROR("execute_script socket(): {}", strerror(errno));
        return false;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock.c_str(), sizeof(addr.sun_path) - 1);

    struct timeval tv{};
    tv.tv_sec = 2;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR("execute_script connect({}): {}", sock, strerror(errno));
        ::close(fd);
        payload_loaded_ = false;
        set_state(InjectionState::Ready, "Payload socket unreachable");
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
        LOG_INFO("Sent {} bytes to payload via {}", data_to_send.size(), sock);
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
                mode_            = InjectionMode::None;
                vm_marker_addr_  = 0;
                vm_scan_         = {};
                proc_info_       = {};
                payload_loaded_  = false;
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

}
