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
    int pos = 0;

    if (orig_prologue[0] == 0xF3 && orig_prologue[1] == 0x0F &&
        orig_prologue[2] == 0x1E && orig_prologue[3] == 0xFA) {
        pos = 4;
    }

    auto decode_modrm_len = [&](int base) -> int {
        uint8_t modrm = orig_prologue[base];
        int mod = (modrm >> 6) & 3;
        int rm = modrm & 7;
        int extra = 1;
        if (mod == 0 && rm == 5) extra += 4;
        else if (mod == 0 && rm == 4) { extra += 1; uint8_t sib = orig_prologue[base+1]; if ((sib & 7) == 5) extra += 4; }
        else if (mod == 1) { extra += (rm == 4) ? 2 : 1; }
        else if (mod == 2) { extra += (rm == 4) ? 5 : 4; }
        else if (mod == 3) { }
        else if (rm == 4) extra += 1;
        return extra;
    };

    while (pos < 5 && pos < 14) {
        uint8_t b = orig_prologue[pos];
        bool has_rex = (b >= 0x40 && b <= 0x4F);
        int rex_off = has_rex ? 1 : 0;
        uint8_t op = orig_prologue[pos + rex_off];

        if (!has_rex && b >= 0x50 && b <= 0x5F) { pos += 1; }
        else if (has_rex && op >= 0x50 && op <= 0x5F) { pos += rex_off + 1; }
        else if (b == 0x55) { pos += 1; }
        else if (b == 0x90 || b == 0xCC) { pos += 1; }
        else if (b == 0xC3) { break; }
        else if (b == 0x31 && orig_prologue[pos+1] == 0xC0) { pos += 2; }
        else if (b == 0x33 && orig_prologue[pos+1] == 0xC0) { pos += 2; }
        else if (has_rex && op == 0x89) { pos += rex_off + 1 + decode_modrm_len(pos + rex_off + 1); }
        else if (has_rex && op == 0x8B) { pos += rex_off + 1 + decode_modrm_len(pos + rex_off + 1); }
        else if (has_rex && op == 0x8D) {
            uint8_t modrm = orig_prologue[pos + rex_off + 1];
            int mod = (modrm >> 6) & 3;
            int rm = modrm & 7;
            if (mod == 0 && rm == 5) { LOG_WARN("RIP-relative LEA at offset {} — skipping function", pos); pos = 0; break; }
            pos += rex_off + 1 + decode_modrm_len(pos + rex_off + 1);
        }
        else if (has_rex && op == 0x83) { pos += rex_off + 1 + decode_modrm_len(pos + rex_off + 1) + 1; }
        else if (has_rex && op == 0x81) { pos += rex_off + 1 + decode_modrm_len(pos + rex_off + 1) + 4; }
        else if (!has_rex && op == 0x83) { pos += 1 + decode_modrm_len(pos + 1) + 1; }
        else if (!has_rex && op == 0x81) { pos += 1 + decode_modrm_len(pos + 1) + 4; }
        else if (b == 0x89) { pos += 1 + decode_modrm_len(pos + 1); }
        else if (b == 0x8B) { pos += 1 + decode_modrm_len(pos + 1); }
        else if (b == 0xB8 || b == 0xB9 || b == 0xBA || b == 0xBB ||
                 b == 0xBC || b == 0xBD || b == 0xBE || b == 0xBF) { pos += 5; }
        else if (has_rex && op >= 0xB8 && op <= 0xBF) { pos += rex_off + 1 + ((b & 0x08) ? 8 : 4); }
        else {
            LOG_WARN("Unknown opcode 0x{:02X} at offset {} — trying next function", b, pos);
            pos = 0;
            break;
        }
    }
    steal_size = pos;

    if (steal_size < 5) {
        LOG_WARN("Steal size {} too small for {} — trying next candidate", steal_size, hooked_name);
        hook_func_addr = 0;
        hooked_name = nullptr;
        for (size_t ci = 0; ci < sizeof(candidates)/sizeof(candidates[0]); ci++) {
            if (candidates[ci] == hooked_name) continue;
            uintptr_t a2 = find_remote_symbol(pid, "c", candidates[ci]);
            if (a2 == 0 || a2 == hook_func_addr) continue;
            hook_func_addr = a2;
            hooked_name = candidates[ci];
            if (!proc_mem_read(pid, hook_func_addr, orig_prologue, sizeof(orig_prologue))) continue;
            pos = 0;
            if (orig_prologue[0]==0xF3 && orig_prologue[1]==0x0F && orig_prologue[2]==0x1E && orig_prologue[3]==0xFA) pos=4;
            steal_size = 0;
            break;
        }
        if (steal_size < 5 && hook_func_addr == 0) {
            error_ = "No hookable function with sufficient prologue found";
            LOG_ERROR("{}", error_);
            return false;
        }
    }
    LOG_DEBUG("Stealing {} bytes from prologue of {}", steal_size, hooked_name);

    auto regions = memory_.get_regions();
    uintptr_t data_addr = 0;
    // Pass 1: prefer anonymous/heap regions — named binary segments contain live variables
    {
        size_t best_size = 0;
        for (const auto& r : regions) {
            if (!r.writable() || !r.readable()) continue;
            if (r.size() < 8192) continue;
            if (r.path.find("[stack") != std::string::npos) continue;
            if (r.path.find("[vvar") != std::string::npos) continue;
            if (r.path.find("[vdso") != std::string::npos) continue;
            // Skip file-backed mappings (binary/library data segments)
            if (!r.path.empty() && r.path[0] == '/') continue;
            if (r.size() > best_size) {
                best_size = r.size();
                data_addr = r.start + ((r.size() / 2) & ~static_cast<size_t>(0xFFF));
            }
        }
        if (data_addr != 0) {
            LOG_DEBUG("Data region (anonymous, {} KB) at 0x{:X}",
                      best_size / 1024, data_addr);
        }
    }
    // Pass 2: fall back to any writable region if no anonymous region found
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

    static constexpr uint64_t GUARD_MAGIC      = 0x4F53534755415244ULL; // "OSSGUARD"
    static constexpr uint64_t COMPLETION_MAGIC  = 0x4F5353444F4E4521ULL; // "OSSDONE!"
    uint64_t zero = 0;
    uint64_t magic = GUARD_MAGIC;
    proc_mem_write(pid, result_addr, &zero, 8);
    proc_mem_write(pid, guard_addr, &magic, 8);
    proc_mem_write(pid, completion_addr, &zero, 8);

        // Verify writes survived — detect if target threads are corrupting this region
    usleep(20000);  // Increased to 20ms for better detection
    uint64_t verify_guard = 0, verify_result = 0, verify_completion = 0;
    proc_mem_read(pid, guard_addr, &verify_guard, 8);
    proc_mem_read(pid, result_addr, &verify_result, 8);
    proc_mem_read(pid, completion_addr, &verify_completion, 8);
    if (verify_guard != GUARD_MAGIC || verify_result != 0 || verify_completion != 0) {
        LOG_ERROR("Data region at 0x{:X} is actively written by target threads "
                  "(guard: wrote 0x{:X}, read 0x{:X}; result: wrote 0, read 0x{:X}; "
                  "completion: wrote 0, read 0x{:X}) — aborting inline hook",
                  data_addr, GUARD_MAGIC, verify_guard, verify_result, verify_completion);
        proc_mem_write(pid, data_addr, orig_data, sizeof(orig_data));
        error_ = "Data region unstable — target process is actively using this memory";
        return false;
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


        // mov rdx, guard_addr
    sc[off++] = 0x48; sc[off++] = 0xBA;
    memcpy(sc + off, &guard_addr, 8); off += 8;

    // mov rax, GUARD_MAGIC (expected old value for cmpxchg)
    sc[off++] = 0x48; sc[off++] = 0xB8;
    memcpy(sc + off, &magic, 8); off += 8;

    // mov ecx, 1 (desired new value; zero-extends to rcx)
    sc[off++] = 0xB9; sc[off++] = 0x01; sc[off++] = 0x00; sc[off++] = 0x00; sc[off++] = 0x00;

    // lock cmpxchg [rdx], rcx — if [rdx]==rax then [rdx]=rcx, ZF=1; else rax=[rdx], ZF=0
    sc[off++] = 0xF0; sc[off++] = 0x48; sc[off++] = 0x0F; sc[off++] = 0xB1; sc[off++] = 0x0A;

    // jnz skip_dlopen (guard was corrupted or already consumed)
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

    // Write COMPLETION_MAGIC to completion_addr — proves shellcode actually ran
    {
        uint64_t comp_magic = COMPLETION_MAGIC;
        sc[off++] = 0x48; sc[off++] = 0xBA;                      // mov rdx, completion_addr
        memcpy(sc + off, &completion_addr, 8); off += 8;
        sc[off++] = 0x48; sc[off++] = 0xB8;                      // mov rax, COMPLETION_MAGIC
        memcpy(sc + off, &comp_magic, 8); off += 8;
        sc[off++] = 0x48; sc[off++] = 0x89; sc[off++] = 0x02;    // mov [rdx], rax
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

    // Build hook patch for function prologue
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
        
        // Check if process is still alive
        if (kill(pid, 0) != 0) {
            error_ = "Process died during inline hook injection";
            LOG_ERROR("{}", error_);
            return false;
        }
        
        // Read all status values
        proc_mem_read(pid, completion_addr, &completion, 8);
        proc_mem_read(pid, result_addr, &result, 8);
        proc_mem_read(pid, guard_addr, &guard_status, 8);
        
        // Check for completion marker (definitive success signal)
        if (completion == COMPLETION_MAGIC) {
            LOG_INFO("Inline hook dlopen completed, handle=0x{:X}", result);
            completed = true;
            break;
        }
        
        // Check if guard was corrupted (data region is unstable)
        if (guard_status != GUARD_MAGIC && guard_status != 1) {
            LOG_WARN("Guard value corrupted during wait (0x{:X}), data region unstable", 
                     guard_status);
            // Don't break — completion marker is authoritative
        }
    }


    
    // Read diagnostic values BEFORE cleanup overwrites the data region
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

    // Verify the library actually loaded by checking /proc/PID/maps
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
            std::ostringstream oss;
            oss << "dlopen returned handle 0x" << std::hex << result
                << " but library not found in /proc/maps — silent load failure";
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

    if (tracer > 0) {
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
    // Pass 1: prefer anonymous/heap regions — named binary segments contain live variables
    {
        size_t best_size = 0;
        for (const auto& r : regions) {
            if (!r.writable() || !r.readable()) continue;
            if (r.size() < 8192) continue;
            if (r.path.find("[stack") != std::string::npos) continue;
            if (r.path.find("[vvar")  != std::string::npos) continue;
            if (r.path.find("[vdso")  != std::string::npos) continue;
            if (!r.path.empty() && r.path[0] == '/') continue;
            if (r.size() > best_size) {
                best_size = r.size();
                // Use middle of region, page-aligned, to avoid allocation frontier
                data_addr = r.start + ((r.size() / 2) & ~static_cast<size_t>(0xFFF));
            }
        }
        if (data_addr != 0) {
            LOG_DEBUG("Data region (anonymous, {} KB) at 0x{:X}",
                      best_size / 1024, data_addr);
        }
    }
    // Pass 2: fall back to any writable region
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

    uintptr_t path_addr       = data_addr;
    uintptr_t result_addr     = data_addr + 512;
    uintptr_t guard_addr      = data_addr + 520;
    uintptr_t completion_addr = data_addr + 528;

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

    // Verify the library actually loaded by checking /proc/PID/maps
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
    if (inject_via_procmem(pid, target_path, dlopen_addr, flags))
        return true;

        // inject_via_procmem already tried inject_via_inline_hook as its internal
    // fallback when SIGSTOP failed. Don't retry with identical parameters.
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

bool Injection::detach() {
    if (state_ == InjectionState::Detached && !memory_.is_valid())
        return true;

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
       
            payload_loaded_ = true;
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

    if (!payload_loaded_) {
        set_state(InjectionState::Ready, "No payload \u2014 local execution only");
        return false;
    }

    set_state(InjectionState::Executing,
              "Executing (" + std::to_string(source.size()) + " bytes)...");

  
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
            ::close(cmd_fd);
            if (fok && ::rename(tmp_cmd.c_str(), cmd_path.c_str()) == 0) {
                set_state(InjectionState::Ready,
                          "Bytecode dispatched via file IPC");
                LOG_INFO("Sent {} bytes via file IPC: {}",
                         data_to_send.size(), cmd_path);
                return true;
            }
            LOG_ERROR("File IPC write/rename error: {}", strerror(errno));
            ::unlink(tmp_cmd.c_str());
        } else {
            LOG_ERROR("Cannot create cmd file {}: {}", tmp_cmd, strerror(errno));
        }

        payload_loaded_ = false;
        set_state(InjectionState::Ready, "Payload unreachable (socket + file IPC failed)");
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
                mode_            = InjectionMode::None;
                vm_marker_addr_  = 0;
                vm_scan_         = {};
                proc_info_       = {};
                payload_loaded_  = false;
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




















