#include "memory.hpp"
#include "utils/logger.hpp"
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <sstream>

namespace oss {

std::optional<pid_t> Memory::find_process(const std::string& name) {
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;

        std::string dirname = entry.path().filename().string();
        if (!std::all_of(dirname.begin(), dirname.end(), ::isdigit))
            continue;

        pid_t pid = std::stoi(dirname);

        // ── Check /proc/PID/comm (short name, max 15 chars) ──
        try {
            std::ifstream comm_file(entry.path() / "comm");
            if (comm_file.is_open()) {
                std::string comm;
                std::getline(comm_file, comm);
                // Trim trailing whitespace/newline
                while (!comm.empty() && std::isspace(
                    static_cast<unsigned char>(comm.back()))) {
                    comm.pop_back();
                }
                if (comm.find(name) != std::string::npos) {
                    return pid;
                }
            }
        } catch (...) {}

        // ═══════════════════════════════════════════════════
        // FIX: ALSO check /proc/PID/cmdline
        //
        // WHY: Flatpak/Sober processes have truncated comm
        // (max 15 chars) but full path in cmdline.
        //
        // Example:
        //   comm    = "bwrap"
        //   cmdline = "bwrap --args 38 org.vinegarhq.Sober"
        //
        // Without this, find_process("Sober") would MISS it
        // because "bwrap" doesn't contain "Sober".
        // ═══════════════════════════════════════════════════
        try {
            std::ifstream cmdline_file(entry.path() / "cmdline",
                                       std::ios::binary);
            if (cmdline_file.is_open()) {
                std::string cmdline(
                    (std::istreambuf_iterator<char>(cmdline_file)),
                     std::istreambuf_iterator<char>());
                // Replace \0 separators with spaces for searching
                std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');
                if (cmdline.find(name) != std::string::npos) {
                    return pid;
                }
            }
        } catch (...) {}
    }
    return std::nullopt;
}

std::vector<pid_t> Memory::find_all_processes(const std::string& name) {
    std::vector<pid_t> results;

    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;

        std::string dirname = entry.path().filename().string();
        if (!std::all_of(dirname.begin(), dirname.end(), ::isdigit))
            continue;

        pid_t pid = std::stoi(dirname);

        try {
            // Check comm
            std::ifstream comm_file(entry.path() / "comm");
            if (comm_file.is_open()) {
                std::string comm;
                std::getline(comm_file, comm);
                while (!comm.empty() && std::isspace(
                    static_cast<unsigned char>(comm.back()))) {
                    comm.pop_back();
                }
                if (comm.find(name) != std::string::npos) {
                    results.push_back(pid);
                    continue;  // already matched, skip cmdline
                }
            }

            // Check cmdline
            std::ifstream cmdline_file(entry.path() / "cmdline",
                                       std::ios::binary);
            if (cmdline_file.is_open()) {
                std::string cmdline(
                    (std::istreambuf_iterator<char>(cmdline_file)),
                     std::istreambuf_iterator<char>());
                std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');
                if (cmdline.find(name) != std::string::npos) {
                    results.push_back(pid);
                }
            }
        } catch (...) {}
    }
    return results;
}

// ── Memory region reading ────────────────────────────────

Memory::Memory(pid_t pid) : pid_(pid) {}

void Memory::set_pid(pid_t pid) { pid_ = pid; }
pid_t Memory::get_pid() const { return pid_; }
bool Memory::is_valid() const { return pid_ > 0; }

std::vector<MemoryRegion> Memory::get_regions() {
    std::vector<MemoryRegion> regions;
    if (pid_ <= 0) return regions;

    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps(maps_path);
    if (!maps.is_open()) {
        LOG_ERROR("Cannot open {}", maps_path);
        return regions;
    }

    std::string line;
    while (std::getline(maps, line)) {
        MemoryRegion region;

        // Parse: "start-end perms offset dev inode path"
        std::istringstream iss(line);
        std::string addr_range, perms, offset, dev, inode;
        iss >> addr_range >> perms >> offset >> dev >> inode;

        // Rest of line is path (may contain spaces)
        std::getline(iss, region.path);
        // Trim leading whitespace
        size_t start_pos = region.path.find_first_not_of(" \t");
        if (start_pos != std::string::npos) {
            region.path = region.path.substr(start_pos);
        } else {
            region.path.clear();
        }

        // Parse address range
        auto dash = addr_range.find('-');
        if (dash == std::string::npos) continue;
        region.start = std::stoull(addr_range.substr(0, dash), nullptr, 16);
        region.end   = std::stoull(addr_range.substr(dash + 1), nullptr, 16);

        // Parse permissions
        region.perms = perms;

        regions.push_back(region);
    }

    return regions;
}

std::optional<uintptr_t> Memory::pattern_scan(
    const std::vector<uint8_t>& pattern,
    const std::string& mask,
    uintptr_t start, size_t length)
{
    if (pid_ <= 0 || pattern.empty()) return std::nullopt;

    std::string mem_path = "/proc/" + std::to_string(pid_) + "/mem";
    std::ifstream mem(mem_path, std::ios::binary);
    if (!mem.is_open()) return std::nullopt;

    std::vector<uint8_t> buffer(length);
    mem.seekg(static_cast<std::streamoff>(start));
    mem.read(reinterpret_cast<char*>(buffer.data()),
             static_cast<std::streamsize>(length));

    auto bytes_read = static_cast<size_t>(mem.gcount());
    if (bytes_read < pattern.size()) return std::nullopt;

    for (size_t i = 0; i <= bytes_read - pattern.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return start + i;
    }

    return std::nullopt;
}

} // namespace oss
