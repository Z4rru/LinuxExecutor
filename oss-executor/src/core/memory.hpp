#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <sys/types.h>

namespace oss {

struct MemoryRegion {
    uintptr_t   start = 0;
    uintptr_t   end   = 0;
    std::string perms;
    std::string path;

    size_t size() const { return end - start; }
    bool readable()  const { return perms.size() > 0 && perms[0] == 'r'; }
    bool writable()  const { return perms.size() > 1 && perms[1] == 'w'; }
    bool executable()const { return perms.size() > 2 && perms[2] == 'x'; }
};

class Memory {
public:
    explicit Memory(pid_t pid = 0);

    void  set_pid(pid_t pid);
    pid_t get_pid() const;
    bool  is_valid() const;

    std::vector<MemoryRegion> get_regions();
    std::optional<uintptr_t>  pattern_scan(
        const std::vector<uint8_t>& pattern,
        const std::string& mask,
        uintptr_t start, size_t length);

    // Static process finders — check BOTH /proc/comm AND /proc/cmdline
    static std::optional<pid_t>  find_process(const std::string& name);
    static std::vector<pid_t>    find_all_processes(const std::string& name);

private:
    pid_t pid_ = 0;
};

} // namespace oss
