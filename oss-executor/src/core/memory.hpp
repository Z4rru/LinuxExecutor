#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <optional>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dirent.h>
#include <cstring>
#include <algorithm>
#include <unistd.h>

namespace oss {

struct MemoryRegion {
    uintptr_t start;
    uintptr_t end;
    std::string perms;
    std::string path;
    
    size_t size() const { return end - start; }
    bool readable() const { return perms.size() > 0 && perms[0] == 'r'; }
    bool writable() const { return perms.size() > 1 && perms[1] == 'w'; }
    bool executable() const { return perms.size() > 2 && perms[2] == 'x'; }
};

class Memory {
public:
    explicit Memory(pid_t pid = 0) : pid_(pid) {}

    void set_pid(pid_t pid) { pid_ = pid; }
    pid_t get_pid() const { return pid_; }

    static std::optional<pid_t> find_process(const std::string& name) {
        DIR* dir = opendir("/proc");
        if (!dir) return std::nullopt;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type != DT_DIR) continue;
            
            pid_t pid = atoi(entry->d_name);
            if (pid <= 0) continue;

            std::string cmdline_path = "/proc/" + std::string(entry->d_name) + "/cmdline";
            std::ifstream cmdline(cmdline_path);
            std::string cmd;
            std::getline(cmdline, cmd, '\0');
            
            if (cmd.find(name) != std::string::npos) {
                closedir(dir);
                return pid;
            }
        }
        closedir(dir);
        return std::nullopt;
    }

    static std::vector<pid_t> find_all_processes(const std::string& name) {
        std::vector<pid_t> pids;
        DIR* dir = opendir("/proc");
        if (!dir) return pids;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type != DT_DIR) continue;
            pid_t pid = atoi(entry->d_name);
            if (pid <= 0) continue;

            std::string path = "/proc/" + std::string(entry->d_name) + "/cmdline";
            std::ifstream f(path);
            std::string cmd;
            std::getline(f, cmd, '\0');
            
            if (cmd.find(name) != std::string::npos) {
                pids.push_back(pid);
            }
        }
        closedir(dir);
        return pids;
    }

    std::vector<MemoryRegion> get_regions() const {
        std::vector<MemoryRegion> regions;
        std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
        std::ifstream maps(maps_path);
        
        if (!maps.is_open()) return regions;

        std::string line;
        while (std::getline(maps, line)) {
            MemoryRegion region{};
            char perms[5] = {};
            unsigned long start, end, offset, dev_major, dev_minor, inode;
            char path[512] = {};

            int parsed = sscanf(line.c_str(), "%lx-%lx %4s %lx %lx:%lx %lu %511[^\n]",
                               &start, &end, perms, &offset, 
                               &dev_major, &dev_minor, &inode, path);
            
            if (parsed >= 7) {
                region.start = start;
                region.end = end;
                region.perms = perms;
                if (parsed == 8) region.path = path;
                regions.push_back(region);
            }
        }
        return regions;
    }

    bool read(uintptr_t address, void* buffer, size_t size) const {
        struct iovec local{buffer, size};
        struct iovec remote{reinterpret_cast<void*>(address), size};
        
        ssize_t result = process_vm_readv(pid_, &local, 1, &remote, 1, 0);
        return result == static_cast<ssize_t>(size);
    }

    bool write(uintptr_t address, const void* data, size_t size) const {
        struct iovec local{const_cast<void*>(data), size};
        struct iovec remote{reinterpret_cast<void*>(address), size};
        
        ssize_t result = process_vm_writev(pid_, &local, 1, &remote, 1, 0);
        return result == static_cast<ssize_t>(size);
    }

    template<typename T>
    std::optional<T> read_value(uintptr_t address) const {
        T value{};
        if (read(address, &value, sizeof(T))) {
            return value;
        }
        return std::nullopt;
    }

    template<typename T>
    bool write_value(uintptr_t address, const T& value) const {
        return write(address, &value, sizeof(T));
    }

    std::optional<std::string> read_string(uintptr_t address, size_t max_len = 256) const {
        std::vector<char> buffer(max_len);
        if (!read(address, buffer.data(), max_len)) return std::nullopt;
        
        auto null_pos = std::find(buffer.begin(), buffer.end(), '\0');
        return std::string(buffer.begin(), null_pos);
    }

    std::optional<uintptr_t> pattern_scan(const std::vector<uint8_t>& pattern,
                                           const std::string& mask,
                                           uintptr_t start, size_t size) const {
        std::vector<uint8_t> buffer(size);
        if (!read(start, buffer.data(), size)) return std::nullopt;

        for (size_t i = 0; i <= buffer.size() - pattern.size(); i++) {
            bool found = true;
            for (size_t j = 0; j < pattern.size(); j++) {
                if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return start + i;
        }
        return std::nullopt;
    }

    std::optional<uintptr_t> find_module_base(const std::string& module_name) const {
        auto regions = get_regions();
        for (const auto& region : regions) {
            if (region.path.find(module_name) != std::string::npos) {
                return region.start;
            }
        }
        return std::nullopt;
    }

    bool attach() const {
        if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) == -1) return false;
        int status;
        waitpid(pid_, &status, 0);
        return true;
    }

    bool detach() const {
        return ptrace(PTRACE_DETACH, pid_, nullptr, nullptr) != -1;
    }

    bool is_valid() const {
        return pid_ > 0 && kill(pid_, 0) == 0;
    }

private:
    pid_t pid_;
};

} // namespace oss