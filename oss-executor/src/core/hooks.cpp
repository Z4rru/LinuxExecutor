#include "hooks.hpp"
#include "memory.hpp"
#include "utils/logger.hpp"

#include <sys/mman.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <unistd.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <stdexcept>

namespace oss {

HookManager& HookManager::instance() {
    static HookManager inst;
    return inst;
}

HookManager::HookManager() {
    long ps = sysconf(_SC_PAGESIZE);
    page_size_ = (ps > 0) ? static_cast<size_t>(ps) : 4096;
}

HookManager::~HookManager() {
    remove_all();
    remote_hooks_.clear();
}

std::vector<HookManager::MemRegionInfo> HookManager::parse_self_maps() {
    std::vector<MemRegionInfo> regions;
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return regions;

    std::string line;
    while (std::getline(maps, line)) {
        MemRegionInfo info{};
        std::istringstream iss(line);
        std::string addr_range, perms, offset, dev, inode;
        iss >> addr_range >> perms >> offset >> dev >> inode;
        std::getline(iss, info.path);

        size_t p = info.path.find_first_not_of(" \t");
        if (p != std::string::npos) info.path = info.path.substr(p);
        else info.path.clear();

        auto dash = addr_range.find('-');
        if (dash == std::string::npos) continue;

        try {
            info.start = std::stoull(addr_range.substr(0, dash), nullptr, 16);
            info.end   = std::stoull(addr_range.substr(dash + 1), nullptr, 16);
        } catch (...) {
            continue;
        }

        info.prot = 0;
        if (perms.size() >= 3) {
            if (perms[0] == 'r') info.prot |= PROT_READ;
            if (perms[1] == 'w') info.prot |= PROT_WRITE;
            if (perms[2] == 'x') info.prot |= PROT_EXEC;
        }

        regions.push_back(info);
    }
    return regions;
}

std::vector<HookManager::MemRegionInfo> HookManager::parse_proc_maps(pid_t pid) {
    std::vector<MemRegionInfo> regions;
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps.is_open()) return regions;

    std::string line;
    while (std::getline(maps, line)) {
        MemRegionInfo info{};
        std::istringstream iss(line);
        std::string addr_range, perms, offset, dev, inode;
        iss >> addr_range >> perms >> offset >> dev >> inode;
        std::getline(iss, info.path);

        size_t p = info.path.find_first_not_of(" \t");
        if (p != std::string::npos) info.path = info.path.substr(p);
        else info.path.clear();

        auto dash = addr_range.find('-');
        if (dash == std::string::npos) continue;

        try {
            info.start = std::stoull(addr_range.substr(0, dash), nullptr, 16);
            info.end   = std::stoull(addr_range.substr(dash + 1), nullptr, 16);
        } catch (...) {
            continue;
        }

        info.prot = 0;
        if (perms.size() >= 3) {
            if (perms[0] == 'r') info.prot |= PROT_READ;
            if (perms[1] == 'w') info.prot |= PROT_WRITE;
            if (perms[2] == 'x') info.prot |= PROT_EXEC;
        }

        regions.push_back(info);
    }
    return regions;
}

bool HookManager::is_address_in_own_process(uintptr_t addr) {
    auto regions = parse_self_maps();
    for (const auto& r : regions)
        if (addr >= r.start && addr < r.end) return true;
    return false;
}

int HookManager::get_region_protection(uintptr_t addr) {
    auto regions = parse_self_maps();
    for (const auto& r : regions)
        if (addr >= r.start && addr < r.end) return r.prot;
    return PROT_READ | PROT_EXEC;
}

bool HookManager::make_writable(uintptr_t addr, size_t size) {
    uintptr_t mask = ~(page_size_ - 1);
    uintptr_t page_start = addr & mask;
    size_t total = ((addr + size + page_size_ - 1) & mask) - page_start;
    return mprotect(reinterpret_cast<void*>(page_start), total,
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

bool HookManager::restore_protection(uintptr_t addr, size_t size, int old_prot) {
    uintptr_t mask = ~(page_size_ - 1);
    uintptr_t page_start = addr & mask;
    size_t total = ((addr + size + page_size_ - 1) & mask) - page_start;
    return mprotect(reinterpret_cast<void*>(page_start), total, old_prot) == 0;
}

bool HookManager::install_hook(uintptr_t target, uintptr_t detour,
                                uintptr_t* original, const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_address_in_own_process(target)) {
        LOG_ERROR("Hook target {:#x} not in own process", target);
        return false;
    }

    if (hooks_.count(target)) {
        LOG_WARN("Hook already installed at {:#x}", target);
        return false;
    }

    Hook hook;
    hook.target = target;
    hook.detour = detour;
    hook.name   = name.empty() ? ("hook_" + std::to_string(target)) : name;
    hook.active = false;
    hook.original_prot = get_region_protection(target);

#if defined(__x86_64__)
    constexpr size_t HOOK_SIZE = 14;

    hook.original_bytes.resize(HOOK_SIZE);
    std::memcpy(hook.original_bytes.data(),
                reinterpret_cast<const void*>(target), HOOK_SIZE);

    void* tramp = mmap(nullptr, page_size_,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) {
        LOG_ERROR("Failed to allocate trampoline for {}", hook.name);
        return false;
    }
    hook.trampoline = reinterpret_cast<uintptr_t>(tramp);

    std::memcpy(tramp, hook.original_bytes.data(), HOOK_SIZE);

    uint8_t* tramp_jmp = static_cast<uint8_t*>(tramp) + HOOK_SIZE;
    tramp_jmp[0] = 0xFF;
    tramp_jmp[1] = 0x25;
    std::memset(tramp_jmp + 2, 0, 4);
    uint64_t return_addr = target + HOOK_SIZE;
    std::memcpy(tramp_jmp + 6, &return_addr, 8);

    if (!make_writable(target, HOOK_SIZE)) {
        munmap(tramp, page_size_);
        LOG_ERROR("Failed to make target writable for {}", hook.name);
        return false;
    }

    uint8_t* target_ptr = reinterpret_cast<uint8_t*>(target);
    target_ptr[0] = 0xFF;
    target_ptr[1] = 0x25;
    std::memset(target_ptr + 2, 0, 4);
    std::memcpy(target_ptr + 6, &detour, 8);

    restore_protection(target, HOOK_SIZE, hook.original_prot);

#elif defined(__aarch64__)
    constexpr size_t HOOK_SIZE = 16;

    hook.original_bytes.resize(HOOK_SIZE);
    std::memcpy(hook.original_bytes.data(),
                reinterpret_cast<const void*>(target), HOOK_SIZE);

    void* tramp = mmap(nullptr, page_size_,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) {
        LOG_ERROR("Failed to allocate trampoline for {}", hook.name);
        return false;
    }
    hook.trampoline = reinterpret_cast<uintptr_t>(tramp);

    std::memcpy(tramp, hook.original_bytes.data(), HOOK_SIZE);

    uint32_t* tramp_code = reinterpret_cast<uint32_t*>(
        static_cast<uint8_t*>(tramp) + HOOK_SIZE);
    uintptr_t tramp_return = target + HOOK_SIZE;
    tramp_code[0] = 0x58000051;
    tramp_code[1] = 0xD61F0220;
    std::memcpy(&tramp_code[2], &tramp_return, 8);

    __builtin___clear_cache(static_cast<char*>(tramp),
                            static_cast<char*>(tramp) + page_size_);

    if (!make_writable(target, HOOK_SIZE)) {
        munmap(tramp, page_size_);
        LOG_ERROR("Failed to make target writable for {}", hook.name);
        return false;
    }

    uint32_t* target_code = reinterpret_cast<uint32_t*>(target);
    target_code[0] = 0x58000051;
    target_code[1] = 0xD61F0220;
    std::memcpy(&target_code[2], &detour, 8);

    __builtin___clear_cache(reinterpret_cast<char*>(target),
                            reinterpret_cast<char*>(target + HOOK_SIZE));

    restore_protection(target, HOOK_SIZE, hook.original_prot);
#else
    #error "Unsupported architecture"
#endif

    hook.active = true;
    if (original) *original = hook.trampoline;

    hooks_[target] = std::move(hook);
    LOG_INFO("Installed hook '{}' at {:#x} -> {:#x}",
             hooks_[target].name, target, detour);
    return true;
}

bool HookManager::remove_hook(uintptr_t target) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = hooks_.find(target);
    if (it == hooks_.end()) return false;

    auto& hook = it->second;
    if (hook.active && is_address_in_own_process(target)) {
        size_t sz = hook.original_bytes.size();
        if (make_writable(target, sz)) {
            std::memcpy(reinterpret_cast<void*>(target),
                        hook.original_bytes.data(), sz);
            restore_protection(target, sz, hook.original_prot);
#if defined(__aarch64__)
            __builtin___clear_cache(reinterpret_cast<char*>(target),
                                    reinterpret_cast<char*>(target + sz));
#endif
        }
    }

    if (hook.trampoline)
        munmap(reinterpret_cast<void*>(hook.trampoline), page_size_);

    LOG_INFO("Removed hook '{}' at {:#x}", hook.name, target);
    hooks_.erase(it);
    return true;
}

std::optional<HookManager::Hook> HookManager::find_hook(uintptr_t target) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = hooks_.find(target);
    if (it != hooks_.end()) return it->second;
    return std::nullopt;
}

std::optional<HookManager::Hook> HookManager::find_hook_by_name(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [addr, hook] : hooks_)
        if (hook.name == name) return hook;
    return std::nullopt;
}

uintptr_t HookManager::find_got_entry(const std::string& library,
                                       const std::string& symbol) {
    struct CallbackData {
        const std::string* lib;
        const std::string* sym;
        uintptr_t result;
    };

    CallbackData data{&library, &symbol, 0};

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* ctx) -> int {
        auto* d = static_cast<CallbackData*>(ctx);
        std::string name = info->dlpi_name ? info->dlpi_name : "";

        if (!d->lib->empty() && name.find(*d->lib) == std::string::npos)
            return 0;

        uintptr_t base = info->dlpi_addr;

        const ElfW(Dyn)* dyn = nullptr;
        for (int i = 0; i < info->dlpi_phnum; ++i) {
            if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
                dyn = reinterpret_cast<const ElfW(Dyn)*>(
                    base + info->dlpi_phdr[i].p_vaddr);
                break;
            }
        }
        if (!dyn) return 0;

        const ElfW(Sym)* symtab = nullptr;
        const char* strtab = nullptr;
        const ElfW(Rela)* rela_plt = nullptr;
        size_t rela_plt_size = 0;

        for (const ElfW(Dyn)* entry = dyn; entry->d_tag != DT_NULL; ++entry) {
            switch (entry->d_tag) {
                case DT_SYMTAB:  symtab = reinterpret_cast<const ElfW(Sym)*>(entry->d_un.d_ptr); break;
                case DT_STRTAB:  strtab = reinterpret_cast<const char*>(entry->d_un.d_ptr); break;
                case DT_JMPREL:  rela_plt = reinterpret_cast<const ElfW(Rela)*>(entry->d_un.d_ptr); break;
                case DT_PLTRELSZ: rela_plt_size = entry->d_un.d_val; break;
                default: break;
            }
        }

        if (!symtab || !strtab || !rela_plt || !rela_plt_size) return 0;

        size_t num_entries = rela_plt_size / sizeof(ElfW(Rela));
        for (size_t i = 0; i < num_entries; ++i) {
            size_t sym_idx = ELF64_R_SYM(rela_plt[i].r_info);
            const char* sym_name = strtab + symtab[sym_idx].st_name;
            if (*d->sym == sym_name) {
                d->result = base + rela_plt[i].r_offset;
                return 1;
            }
        }
        return 0;
    }, &data);

    return data.result;
}

uintptr_t HookManager::find_remote_got_entry(pid_t pid, const std::string& library,
                                              const std::string& symbol) {
    auto regions = parse_proc_maps(pid);

    uintptr_t lib_base = 0;
    std::string lib_path;
    for (const auto& r : regions) {
        if (!library.empty() && r.path.find(library) != std::string::npos) {
            if (!lib_base || r.start < lib_base) {
                lib_base = r.start;
                lib_path = r.path;
            }
        }
    }
    if (!lib_base) return 0;

    Memory mem(pid);
    if (!mem.attach()) return 0;

    ElfW(Ehdr) ehdr{};
    if (!mem.read(lib_base, &ehdr, sizeof(ehdr))) return 0;
    if (std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return 0;

    std::vector<ElfW(Phdr)> phdrs(ehdr.e_phnum);
    if (!mem.read(lib_base + ehdr.e_phoff, phdrs.data(),
                  ehdr.e_phnum * sizeof(ElfW(Phdr)))) return 0;

    uintptr_t dyn_addr = 0;
    size_t dyn_size = 0;
    for (const auto& ph : phdrs) {
        if (ph.p_type == PT_DYNAMIC) {
            dyn_addr = lib_base + ph.p_vaddr;
            dyn_size = ph.p_memsz;
            break;
        }
    }
    if (!dyn_addr) return 0;

    size_t dyn_count = dyn_size / sizeof(ElfW(Dyn));
    std::vector<ElfW(Dyn)> dyns(dyn_count);
    if (!mem.read(dyn_addr, dyns.data(), dyn_size)) return 0;

    uintptr_t symtab_addr = 0, strtab_addr = 0, jmprel_addr = 0;
    size_t pltrelsz = 0;

    for (const auto& d : dyns) {
        switch (d.d_tag) {
            case DT_SYMTAB:   symtab_addr = d.d_un.d_ptr; break;
            case DT_STRTAB:   strtab_addr = d.d_un.d_ptr; break;
            case DT_JMPREL:   jmprel_addr = d.d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz = d.d_un.d_val; break;
            default: break;
        }
    }

    if (!symtab_addr || !strtab_addr || !jmprel_addr || !pltrelsz) return 0;

    size_t num_rela = pltrelsz / sizeof(ElfW(Rela));
    for (size_t i = 0; i < num_rela; ++i) {
        ElfW(Rela) rela{};
        if (!mem.read(jmprel_addr + i * sizeof(ElfW(Rela)), &rela, sizeof(rela)))
            continue;

        size_t sym_idx = ELF64_R_SYM(rela.r_info);
        ElfW(Sym) sym{};
        if (!mem.read(symtab_addr + sym_idx * sizeof(ElfW(Sym)), &sym, sizeof(sym)))
            continue;

        char sym_name[256]{};
        if (!mem.read(strtab_addr + sym.st_name, sym_name, sizeof(sym_name) - 1))
            continue;
        sym_name[sizeof(sym_name) - 1] = '\0';

        if (symbol == sym_name)
            return lib_base + rela.r_offset;
    }

    return 0;
}

uintptr_t HookManager::find_remote_symbol(pid_t pid, const std::string& library,
                                           const std::string& symbol) {
    auto regions = parse_proc_maps(pid);

    uintptr_t lib_base = 0;
    for (const auto& r : regions) {
        if (!library.empty() && r.path.find(library) != std::string::npos &&
            (r.prot & PROT_EXEC)) {
            if (!lib_base || r.start < lib_base)
                lib_base = r.start;
        }
    }
    if (!lib_base) return 0;

    Memory mem(pid);
    if (!mem.attach()) return 0;

    ElfW(Ehdr) ehdr{};
    if (!mem.read(lib_base, &ehdr, sizeof(ehdr))) return 0;
    if (std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return 0;

    std::vector<ElfW(Phdr)> phdrs(ehdr.e_phnum);
    if (!mem.read(lib_base + ehdr.e_phoff, phdrs.data(),
                  ehdr.e_phnum * sizeof(ElfW(Phdr)))) return 0;

    uintptr_t dyn_addr = 0;
    size_t dyn_size = 0;
    for (const auto& ph : phdrs) {
        if (ph.p_type == PT_DYNAMIC) {
            dyn_addr = lib_base + ph.p_vaddr;
            dyn_size = ph.p_memsz;
            break;
        }
    }
    if (!dyn_addr) return 0;

    size_t dyn_count = dyn_size / sizeof(ElfW(Dyn));
    std::vector<ElfW(Dyn)> dyns(dyn_count);
    if (!mem.read(dyn_addr, dyns.data(), dyn_size)) return 0;

    uintptr_t symtab_addr = 0, strtab_addr = 0;
    size_t strtab_size = 0;
    uintptr_t hash_addr = 0, gnu_hash_addr = 0;

    for (const auto& d : dyns) {
        switch (d.d_tag) {
            case DT_SYMTAB:  symtab_addr = d.d_un.d_ptr; break;
            case DT_STRTAB:  strtab_addr = d.d_un.d_ptr; break;
            case DT_STRSZ:   strtab_size = d.d_un.d_val; break;
            case DT_HASH:    hash_addr = d.d_un.d_ptr; break;
            case DT_GNU_HASH: gnu_hash_addr = d.d_un.d_ptr; break;
            default: break;
        }
    }

    if (!symtab_addr || !strtab_addr) return 0;

    size_t num_syms = 0;
    if (hash_addr) {
        uint32_t hash_header[2]{};
        if (mem.read(hash_addr, hash_header, sizeof(hash_header)))
            num_syms = hash_header[1];
    } else if (gnu_hash_addr) {
        uint32_t gnu_header[4]{};
        if (mem.read(gnu_hash_addr, gnu_header, sizeof(gnu_header))) {
            uint32_t nbuckets = gnu_header[0];
            uint32_t symoffset = gnu_header[1];
            uint32_t bloom_size = gnu_header[2];
            uintptr_t buckets_addr = gnu_hash_addr + 16 + bloom_size * sizeof(uintptr_t);
            uint32_t max_bucket = 0;
            for (uint32_t i = 0; i < nbuckets; ++i) {
                uint32_t val = 0;
                mem.read(buckets_addr + i * 4, &val, 4);
                if (val > max_bucket) max_bucket = val;
            }
            if (max_bucket >= symoffset) {
                uintptr_t chains_addr = buckets_addr + nbuckets * 4;
                uint32_t chain_idx = max_bucket - symoffset;
                uint32_t chain_val = 0;
                do {
                    mem.read(chains_addr + chain_idx * 4, &chain_val, 4);
                    ++chain_idx;
                } while (!(chain_val & 1));
                num_syms = symoffset + chain_idx;
            }
        }
    }

    if (!num_syms) num_syms = 4096;

    for (size_t i = 0; i < num_syms; ++i) {
        ElfW(Sym) sym{};
        if (!mem.read(symtab_addr + i * sizeof(ElfW(Sym)), &sym, sizeof(sym)))
            continue;
        if (sym.st_name == 0 || sym.st_value == 0) continue;
        if (sym.st_name >= strtab_size && strtab_size > 0) continue;

        char name_buf[256]{};
        if (!mem.read(strtab_addr + sym.st_name, name_buf, sizeof(name_buf) - 1))
            continue;
        name_buf[sizeof(name_buf) - 1] = '\0';

        if (symbol == name_buf)
            return lib_base + sym.st_value;
    }

    return 0;
}

bool HookManager::install_plt_hook(const std::string& library,
                                    const std::string& symbol,
                                    uintptr_t detour, uintptr_t* original) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (plt_hooks_.count(symbol)) {
        LOG_WARN("PLT hook already installed for {}", symbol);
        return false;
    }

    uintptr_t got = find_got_entry(library, symbol);
    if (!got) {
        LOG_ERROR("Could not find GOT entry for {} in {}", symbol, library);
        return false;
    }

    PLTHook hook;
    hook.got_entry   = got;
    hook.symbol_name = symbol;
    hook.detour_func = detour;
    hook.original_prot = get_region_protection(got);
    hook.original_func = *reinterpret_cast<uintptr_t*>(got);
    if (original) *original = hook.original_func;

    if (!make_writable(got, sizeof(uintptr_t))) {
        LOG_ERROR("Cannot make GOT writable for {}", symbol);
        return false;
    }

    *reinterpret_cast<uintptr_t*>(got) = detour;

    hook.active = true;
    plt_hooks_[symbol] = hook;
    LOG_INFO("Installed PLT hook for {} at GOT {:#x}", symbol, got);
    return true;
}

bool HookManager::remove_plt_hook(const std::string& symbol) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = plt_hooks_.find(symbol);
    if (it == plt_hooks_.end()) return false;

    auto& hook = it->second;
    if (hook.active && hook.got_entry) {
        if (make_writable(hook.got_entry, sizeof(uintptr_t))) {
            *reinterpret_cast<uintptr_t*>(hook.got_entry) = hook.original_func;
            restore_protection(hook.got_entry, sizeof(uintptr_t), hook.original_prot);
        }
    }

    LOG_INFO("Removed PLT hook for {}", symbol);
    plt_hooks_.erase(it);
    return true;
}

bool HookManager::install_remote_hook(Memory& mem, uintptr_t target,
                                       const std::vector<uint8_t>& patch,
                                       const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string hook_name = name.empty()
        ? ("remote_" + std::to_string(target)) : name;

    if (remote_hooks_.count(hook_name)) {
        LOG_WARN("Remote hook '{}' already installed", hook_name);
        return false;
    }

    RemoteHook hook;
    hook.target = target;
    hook.pid    = mem.get_pid();
    hook.name   = hook_name;
    hook.patch_bytes = patch;

    hook.original_bytes = mem.read_bytes(target, patch.size());
    if (hook.original_bytes.empty()) {
        LOG_ERROR("Cannot read original bytes at {:#x} for '{}'", target, hook_name);
        return false;
    }

    if (!mem.write_bytes(target, patch)) {
        LOG_ERROR("Cannot write patch at {:#x} for '{}'", target, hook_name);
        return false;
    }

    hook.active = true;
    remote_hooks_[hook_name] = std::move(hook);
    LOG_INFO("Installed remote hook '{}' at {:#x} (pid {})",
             hook_name, target, remote_hooks_[hook_name].pid);
    return true;
}

bool HookManager::install_remote_got_hook(Memory& mem, pid_t pid,
                                           const std::string& library,
                                           const std::string& symbol,
                                           uintptr_t detour_addr,
                                           uintptr_t* original) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string hook_name = "rgot_" + symbol;
    if (remote_hooks_.count(hook_name)) {
        LOG_WARN("Remote GOT hook '{}' already installed", hook_name);
        return false;
    }

    uintptr_t got = find_remote_got_entry(pid, library, symbol);
    if (!got) {
        LOG_ERROR("Cannot find remote GOT for {} in {} (pid {})", symbol, library, pid);
        return false;
    }

    uintptr_t orig_val = 0;
    if (!mem.read(got, &orig_val, sizeof(orig_val))) {
        LOG_ERROR("Cannot read remote GOT at {:#x}", got);
        return false;
    }
    if (original) *original = orig_val;

    RemoteHook hook;
    hook.target = got;
    hook.pid = pid;
    hook.name = hook_name;
    hook.original_bytes.resize(sizeof(uintptr_t));
    std::memcpy(hook.original_bytes.data(), &orig_val, sizeof(orig_val));
    hook.patch_bytes.resize(sizeof(uintptr_t));
    std::memcpy(hook.patch_bytes.data(), &detour_addr, sizeof(detour_addr));

    if (!mem.write(got, &detour_addr, sizeof(detour_addr))) {
        LOG_ERROR("Cannot write remote GOT at {:#x}", got);
        return false;
    }

    hook.active = true;
    remote_hooks_[hook_name] = std::move(hook);
    LOG_INFO("Installed remote GOT hook for {} at {:#x} (pid {})", symbol, got, pid);
    return true;
}

bool HookManager::remove_remote_hook(Memory& mem, const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = remote_hooks_.find(name);
    if (it == remote_hooks_.end()) return false;

    auto& hook = it->second;
    if (hook.active && !hook.original_bytes.empty())
        mem.write_bytes(hook.target, hook.original_bytes);

    LOG_INFO("Removed remote hook '{}' at {:#x}", name, hook.target);
    remote_hooks_.erase(it);
    return true;
}

bool HookManager::remove_remote_hook(Memory& mem, uintptr_t target) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto it = remote_hooks_.begin(); it != remote_hooks_.end(); ++it) {
        if (it->second.target == target) {
            if (it->second.active && !it->second.original_bytes.empty())
                mem.write_bytes(target, it->second.original_bytes);
            LOG_INFO("Removed remote hook at {:#x}", target);
            remote_hooks_.erase(it);
            return true;
        }
    }
    return false;
}

void HookManager::set_namecall_handler(NamecallHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    namecall_handler_ = std::move(handler);
}

void HookManager::set_index_handler(IndexHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    index_handler_ = std::move(handler);
}

void HookManager::set_newindex_handler(NewindexHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    newindex_handler_ = std::move(handler);
}

int HookManager::dispatch_namecall(const std::string& method, void* state) {
    NamecallHandler handler;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        handler = namecall_handler_;
    }
    if (handler) return handler(method, state);
    return -1;
}

bool HookManager::dispatch_index(const std::string& key, void* state) {
    IndexHandler handler;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        handler = index_handler_;
    }
    if (handler) return handler(key, state);
    return false;
}

bool HookManager::dispatch_newindex(const std::string& key, void* state) {
    NewindexHandler handler;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        handler = newindex_handler_;
    }
    if (handler) return handler(key, state);
    return false;
}

void HookManager::remove_all() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [target, hook] : hooks_) {
        if (hook.active && is_address_in_own_process(target)) {
            size_t sz = hook.original_bytes.size();
            if (make_writable(target, sz)) {
                std::memcpy(reinterpret_cast<void*>(target),
                            hook.original_bytes.data(), sz);
                restore_protection(target, sz, hook.original_prot);
#if defined(__aarch64__)
                __builtin___clear_cache(reinterpret_cast<char*>(target),
                                        reinterpret_cast<char*>(target + sz));
#endif
            }
        }
        if (hook.trampoline)
            munmap(reinterpret_cast<void*>(hook.trampoline), page_size_);
    }
    hooks_.clear();

    for (auto& [sym, hook] : plt_hooks_) {
        if (hook.active && hook.got_entry) {
            if (make_writable(hook.got_entry, sizeof(uintptr_t))) {
                *reinterpret_cast<uintptr_t*>(hook.got_entry) = hook.original_func;
                restore_protection(hook.got_entry, sizeof(uintptr_t), hook.original_prot);
            }
        }
    }
    plt_hooks_.clear();

    namecall_handler_ = nullptr;
    index_handler_    = nullptr;
    newindex_handler_ = nullptr;

    LOG_INFO("All local hooks removed");
}

void HookManager::remove_all_remote(Memory& mem) {
    std::lock_guard<std::mutex> lock(mutex_);

    pid_t target_pid = mem.get_pid();

    for (auto& [name, hook] : remote_hooks_) {
        if (hook.active && hook.pid == target_pid && !hook.original_bytes.empty())
            mem.write_bytes(hook.target, hook.original_bytes);
    }

    for (auto it = remote_hooks_.begin(); it != remote_hooks_.end(); ) {
        if (it->second.pid == target_pid)
            it = remote_hooks_.erase(it);
        else
            ++it;
    }

    LOG_INFO("All remote hooks for pid {} removed", target_pid);
}

size_t HookManager::hook_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return hooks_.size() + plt_hooks_.size() + remote_hooks_.size();
}

std::vector<std::string> HookManager::list_hooks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> names;
    names.reserve(hooks_.size() + plt_hooks_.size() + remote_hooks_.size());

    for (const auto& [addr, hook] : hooks_)
        names.push_back("[inline] " + hook.name);
    for (const auto& [sym, hook] : plt_hooks_)
        names.push_back("[plt] " + hook.symbol_name);
    for (const auto& [name, hook] : remote_hooks_)
        names.push_back("[remote] " + hook.name);
    return names;
}

}
