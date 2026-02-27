#include "memory.hpp"
#include "utils/logger.hpp"
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <cerrno>

namespace oss {

AOBPattern AOBPattern::from_ida(const std::string& pattern) {
    AOBPattern result;
    std::istringstream stream(pattern);
    std::string token;
    while (stream >> token) {
        if (token == "?" || token == "??") {
            result.bytes.push_back(0x00);
            result.mask.push_back(false);
        } else {
            result.bytes.push_back(
                static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
            result.mask.push_back(true);
        }
    }
    return result;
}

AOBPattern AOBPattern::from_code_style(const std::vector<uint8_t>& pattern,
                                        const std::string& mask) {
    AOBPattern result;
    result.bytes = pattern;
    result.mask.resize(mask.size());
    for (size_t i = 0; i < mask.size(); ++i)
        result.mask[i] = (mask[i] == 'x');
    return result;
}

std::optional<pid_t> Memory::find_process(const std::string& name) {
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;

        std::string dirname = entry.path().filename().string();
        if (!std::all_of(dirname.begin(), dirname.end(), ::isdigit))
            continue;

        pid_t pid = std::stoi(dirname);

        try {
            std::ifstream comm_file(entry.path() / "comm");
            if (comm_file.is_open()) {
                std::string comm;
                std::getline(comm_file, comm);
                while (!comm.empty() &&
                       std::isspace(static_cast<unsigned char>(comm.back())))
                    comm.pop_back();
                if (comm.find(name) != std::string::npos)
                    return pid;
            }
        } catch (...) {}

        try {
            std::ifstream cmdline_file(entry.path() / "cmdline",
                                        std::ios::binary);
            if (cmdline_file.is_open()) {
                std::string cmdline(
                    (std::istreambuf_iterator<char>(cmdline_file)),
                     std::istreambuf_iterator<char>());
                std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');
                if (cmdline.find(name) != std::string::npos)
                    return pid;
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
            std::ifstream comm_file(entry.path() / "comm");
            if (comm_file.is_open()) {
                std::string comm;
                std::getline(comm_file, comm);
                while (!comm.empty() &&
                       std::isspace(static_cast<unsigned char>(comm.back())))
                    comm.pop_back();
                if (comm.find(name) != std::string::npos) {
                    results.push_back(pid);
                    continue;
                }
            }

            std::ifstream cmdline_file(entry.path() / "cmdline",
                                        std::ios::binary);
            if (cmdline_file.is_open()) {
                std::string cmdline(
                    (std::istreambuf_iterator<char>(cmdline_file)),
                     std::istreambuf_iterator<char>());
                std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');
                if (cmdline.find(name) != std::string::npos)
                    results.push_back(pid);
            }
        } catch (...) {}
    }
    return results;
}

Memory::Memory(pid_t pid) : pid_(pid) {}

Memory::~Memory() {
    detach();
}

Memory::Memory(Memory&& other) noexcept
    : pid_(other.pid_), mem_fd_(other.mem_fd_),
      cached_regions_(std::move(other.cached_regions_)),
      regions_cached_(other.regions_cached_) {
    other.pid_ = 0;
    other.mem_fd_ = -1;
    other.regions_cached_ = false;
}

Memory& Memory::operator=(Memory&& other) noexcept {
    if (this != &other) {
        detach();
        pid_ = other.pid_;
        mem_fd_ = other.mem_fd_;
        cached_regions_ = std::move(other.cached_regions_);
        regions_cached_ = other.regions_cached_;
        other.pid_ = 0;
        other.mem_fd_ = -1;
        other.regions_cached_ = false;
    }
    return *this;
}

void Memory::set_pid(pid_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pid_ != pid) {
        close_mem();
        pid_ = pid;
        regions_cached_ = false;
        cached_regions_.clear();
    }
}

pid_t Memory::get_pid() const { return pid_; }
bool Memory::is_valid() const { return pid_ > 0; }

bool Memory::is_attached() const {
    return mem_fd_ >= 0;
}

int Memory::open_mem(int flags) {
    if (pid_ <= 0) return -1;
    std::string path = "/proc/" + std::to_string(pid_) + "/mem";
    return ::open(path.c_str(), flags);
}

void Memory::close_mem() {
    if (mem_fd_ >= 0) {
        ::close(mem_fd_);
        mem_fd_ = -1;
    }
}

bool Memory::attach() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pid_ <= 0) return false;
    close_mem();
    mem_fd_ = open_mem(O_RDWR);
    if (mem_fd_ < 0) {
        mem_fd_ = open_mem(O_RDONLY);
        if (mem_fd_ < 0) {
            LOG_ERROR("Failed to open /proc/{}/mem: {}", pid_, strerror(errno));
            return false;
        }
        LOG_WARN("Opened /proc/{}/mem read-only", pid_);
    }
    LOG_INFO("Attached to process {}", pid_);
    return true;
}

void Memory::detach() {
    std::lock_guard<std::mutex> lock(mutex_);
    close_mem();
    regions_cached_ = false;
    cached_regions_.clear();
}

std::vector<MemoryRegion> Memory::get_regions(bool refresh) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (regions_cached_ && !refresh)
        return cached_regions_;

    cached_regions_.clear();
    regions_cached_ = false;

    if (pid_ <= 0) return cached_regions_;

    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps(maps_path);
    if (!maps.is_open()) {
        LOG_ERROR("Cannot open {}", maps_path);
        return cached_regions_;
    }

    std::string line;
    while (std::getline(maps, line)) {
        MemoryRegion region;

        std::istringstream iss(line);
        std::string addr_range, perms, offset_str, dev, inode;
        iss >> addr_range >> perms >> offset_str >> dev >> inode;

        std::getline(iss, region.path);
        size_t start_pos = region.path.find_first_not_of(" \t");
        if (start_pos != std::string::npos)
            region.path = region.path.substr(start_pos);
        else
            region.path.clear();

        auto dash = addr_range.find('-');
        if (dash == std::string::npos) continue;
        region.start = std::stoull(addr_range.substr(0, dash), nullptr, 16);
        region.end = std::stoull(addr_range.substr(dash + 1), nullptr, 16);
        region.perms = perms;

        try {
            region.offset = std::stoull(offset_str, nullptr, 16);
        } catch (...) {
            region.offset = 0;
        }

        cached_regions_.push_back(region);
    }

    regions_cached_ = true;
    return cached_regions_;
}

std::vector<MemoryRegion> Memory::get_executable_regions() {
    auto all = get_regions();
    std::vector<MemoryRegion> result;
    for (auto& r : all) {
        if (r.executable() && r.readable())
            result.push_back(r);
    }
    return result;
}

std::vector<MemoryRegion> Memory::get_writable_regions() {
    auto all = get_regions();
    std::vector<MemoryRegion> result;
    for (auto& r : all) {
        if (r.writable())
            result.push_back(r);
    }
    return result;
}

std::optional<MemoryRegion> Memory::find_region(const std::string& name_contains) {
    auto regions = get_regions();
    for (auto& r : regions) {
        if (!r.path.empty() && r.path.find(name_contains) != std::string::npos)
            return r;
    }
    return std::nullopt;
}

std::optional<uintptr_t> Memory::get_module_base(const std::string& module_name) {
    auto r = find_region(module_name);
    if (r) return r->start;
    return std::nullopt;
}

std::optional<size_t> Memory::get_module_size(const std::string& module_name) {
    auto regions = get_regions();
    uintptr_t base = 0;
    uintptr_t end = 0;
    bool found = false;
    for (auto& r : regions) {
        if (!r.path.empty() && r.path.find(module_name) != std::string::npos) {
            if (!found) {
                base = r.start;
                found = true;
            }
            if (r.end > end) end = r.end;
        }
    }
    if (found) return end - base;
    return std::nullopt;
}

bool Memory::read_raw(uintptr_t address, void* buffer, size_t size) {
    if (pid_ <= 0 || !buffer || size == 0) return false;

    if (mem_fd_ >= 0) {
        ssize_t result = ::pread64(mem_fd_, buffer, size,
                                    static_cast<off64_t>(address));
        if (result == static_cast<ssize_t>(size))
            return true;
    }

    return read_raw_v(address, buffer, size);
}

bool Memory::write_raw(uintptr_t address, const void* buffer, size_t size) {
    if (pid_ <= 0 || !buffer || size == 0) return false;

    if (mem_fd_ >= 0) {
        ssize_t result = ::pwrite64(mem_fd_, buffer, size,
                                     static_cast<off64_t>(address));
        if (result == static_cast<ssize_t>(size))
            return true;
    }

    return write_raw_v(address, buffer, size);
}

bool Memory::read_raw_v(uintptr_t address, void* buffer, size_t size) {
    if (pid_ <= 0) return false;
    struct iovec local_iov;
    struct iovec remote_iov;
    local_iov.iov_base = buffer;
    local_iov.iov_len = size;
    remote_iov.iov_base = reinterpret_cast<void*>(address);
    remote_iov.iov_len = size;
    ssize_t result = process_vm_readv(pid_, &local_iov, 1, &remote_iov, 1, 0);
    return result == static_cast<ssize_t>(size);
}

bool Memory::write_raw_v(uintptr_t address, const void* buffer, size_t size) {
    if (pid_ <= 0) return false;
    struct iovec local_iov;
    struct iovec remote_iov;
    local_iov.iov_base = const_cast<void*>(buffer);
    local_iov.iov_len = size;
    remote_iov.iov_base = reinterpret_cast<void*>(address);
    remote_iov.iov_len = size;
    ssize_t result = process_vm_writev(pid_, &local_iov, 1, &remote_iov, 1, 0);
    return result == static_cast<ssize_t>(size);
}

std::vector<uint8_t> Memory::read_bytes(uintptr_t address, size_t size) {
    std::vector<uint8_t> result(size);
    if (!read_raw(address, result.data(), size))
        result.clear();
    return result;
}

bool Memory::write_bytes(uintptr_t address, const std::vector<uint8_t>& bytes) {
    return write_raw(address, bytes.data(), bytes.size());
}

std::optional<std::string> Memory::read_string(uintptr_t address, size_t max_len) {
    std::vector<char> buf(max_len + 1, 0);
    size_t chunk = std::min(max_len, static_cast<size_t>(256));
    size_t total_read = 0;

    while (total_read < max_len) {
        size_t to_read = std::min(chunk, max_len - total_read);
        if (!read_raw(address + total_read, buf.data() + total_read, to_read))
            break;

        for (size_t i = total_read; i < total_read + to_read; ++i) {
            if (buf[i] == '\0')
                return std::string(buf.data(), i);
        }
        total_read += to_read;
    }

    if (total_read > 0) {
        buf[total_read] = '\0';
        return std::string(buf.data());
    }
    return std::nullopt;
}

bool Memory::write_string(uintptr_t address, const std::string& str) {
    return write_raw(address, str.c_str(), str.size() + 1);
}

std::optional<uintptr_t> Memory::read_pointer(uintptr_t address) {
    return read<uintptr_t>(address);
}

std::optional<uintptr_t> Memory::resolve_pointer_chain(
    uintptr_t base, const std::vector<ptrdiff_t>& offsets) {
    uintptr_t current = base;
    for (size_t i = 0; i < offsets.size(); ++i) {
        if (i < offsets.size() - 1) {
            auto ptr = read<uintptr_t>(current + offsets[i]);
            if (!ptr) return std::nullopt;
            current = *ptr;
        } else {
            current = current + offsets[i];
        }
    }
    return current;
}

void Memory::batch_read(std::vector<BatchReadEntry>& entries) {
    if (pid_ <= 0 || entries.empty()) return;

    if (mem_fd_ >= 0) {
        for (auto& e : entries) {
            ssize_t r = ::pread64(mem_fd_, e.buffer, e.size,
                                   static_cast<off64_t>(e.address));
            e.success = (r == static_cast<ssize_t>(e.size));
        }
        return;
    }

    std::vector<struct iovec> local_iovs(entries.size());
    std::vector<struct iovec> remote_iovs(entries.size());

    for (size_t i = 0; i < entries.size(); ++i) {
        local_iovs[i].iov_base = entries[i].buffer;
        local_iovs[i].iov_len = entries[i].size;
        remote_iovs[i].iov_base = reinterpret_cast<void*>(entries[i].address);
        remote_iovs[i].iov_len = entries[i].size;
    }

    size_t total_expected = 0;
    for (auto& e : entries) total_expected += e.size;

    ssize_t result = process_vm_readv(pid_, local_iovs.data(), entries.size(),
                                       remote_iovs.data(), entries.size(), 0);

    if (result == static_cast<ssize_t>(total_expected)) {
        for (auto& e : entries) e.success = true;
    } else {
        for (auto& e : entries)
            e.success = read_raw(e.address, e.buffer, e.size);
    }
}

void Memory::batch_write(std::vector<BatchWriteEntry>& entries) {
    if (pid_ <= 0 || entries.empty()) return;

    if (mem_fd_ >= 0) {
        for (auto& e : entries) {
            ssize_t r = ::pwrite64(mem_fd_, e.buffer, e.size,
                                    static_cast<off64_t>(e.address));
            e.success = (r == static_cast<ssize_t>(e.size));
        }
        return;
    }

    std::vector<struct iovec> local_iovs(entries.size());
    std::vector<struct iovec> remote_iovs(entries.size());

    for (size_t i = 0; i < entries.size(); ++i) {
        local_iovs[i].iov_base = const_cast<void*>(entries[i].buffer);
        local_iovs[i].iov_len = entries[i].size;
        remote_iovs[i].iov_base = reinterpret_cast<void*>(entries[i].address);
        remote_iovs[i].iov_len = entries[i].size;
    }

    size_t total_expected = 0;
    for (auto& e : entries) total_expected += e.size;

    ssize_t result = process_vm_writev(pid_, local_iovs.data(), entries.size(),
                                        remote_iovs.data(), entries.size(), 0);

    if (result == static_cast<ssize_t>(total_expected)) {
        for (auto& e : entries) e.success = true;
    } else {
        for (auto& e : entries)
            e.success = write_raw(e.address, e.buffer, e.size);
    }
}

std::optional<uintptr_t> Memory::pattern_scan(
    const std::vector<uint8_t>& pattern,
    const std::string& mask,
    uintptr_t start, size_t length) {
    auto aob = AOBPattern::from_code_style(pattern, mask);
    return aob_scan(aob, start, length);
}

std::optional<uintptr_t> Memory::aob_scan(const AOBPattern& pattern,
                                            uintptr_t start, size_t length) {
    if (pid_ <= 0 || pattern.bytes.empty()) return std::nullopt;

    size_t pat_size = pattern.bytes.size();
    size_t overlap = pat_size - 1;
    std::vector<uint8_t> buffer(SCAN_CHUNK_SIZE + overlap);

    uintptr_t current = start;
    uintptr_t end_addr = start + length;

    while (current < end_addr) {
        size_t to_read = std::min(static_cast<size_t>(end_addr - current),
                                  buffer.size());
        size_t bytes_read = 0;

        if (read_raw(current, buffer.data(), to_read)) {
            bytes_read = to_read;
        } else {
            size_t partial = to_read;
            while (partial > 0) {
                if (read_raw(current, buffer.data(), partial)) {
                    bytes_read = partial;
                    break;
                }
                partial /= 2;
            }
        }

        if (bytes_read < pat_size) break;

        for (size_t i = 0; i <= bytes_read - pat_size; ++i) {
            bool found = true;
            for (size_t j = 0; j < pat_size; ++j) {
                if (pattern.mask[j] && buffer[i + j] != pattern.bytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return current + i;
        }

        if (bytes_read <= overlap) break;
        current += bytes_read - overlap;
    }

    return std::nullopt;
}

std::optional<uintptr_t> Memory::aob_scan_ida(const std::string& ida_pattern,
                                                uintptr_t start, size_t length) {
    return aob_scan(AOBPattern::from_ida(ida_pattern), start, length);
}

std::vector<uintptr_t> Memory::aob_scan_all(const AOBPattern& pattern,
                                              uintptr_t start, size_t length) {
    std::vector<uintptr_t> results;
    if (pid_ <= 0 || pattern.bytes.empty()) return results;

    size_t pat_size = pattern.bytes.size();
    size_t overlap = pat_size - 1;
    std::vector<uint8_t> buffer(SCAN_CHUNK_SIZE + overlap);

    uintptr_t current = start;
    uintptr_t end_addr = start + length;

    while (current < end_addr) {
        size_t to_read = std::min(static_cast<size_t>(end_addr - current),
                                  buffer.size());
        if (!read_raw(current, buffer.data(), to_read)) break;

        for (size_t i = 0; i <= to_read - pat_size; ++i) {
            bool found = true;
            for (size_t j = 0; j < pat_size; ++j) {
                if (pattern.mask[j] && buffer[i + j] != pattern.bytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) results.push_back(current + i);
        }

        if (to_read <= overlap) break;
        current += to_read - overlap;
    }

    return results;
}

std::optional<uintptr_t> Memory::aob_scan_regions(const std::string& ida_pattern,
                                                    bool executable_only) {
    auto pat = AOBPattern::from_ida(ida_pattern);
    auto regions = executable_only ? get_executable_regions() : get_regions();

    for (auto& r : regions) {
        if (!r.readable()) continue;
        auto result = aob_scan(pat, r.start, r.size());
        if (result) return result;
    }
    return std::nullopt;
}

std::vector<uintptr_t> Memory::aob_scan_all_regions(const std::string& ida_pattern,
                                                      bool executable_only) {
    std::vector<uintptr_t> results;
    auto pat = AOBPattern::from_ida(ida_pattern);
    auto regions = executable_only ? get_executable_regions() : get_regions();

    for (auto& r : regions) {
        if (!r.readable()) continue;
        auto partial = aob_scan_all(pat, r.start, r.size());
        results.insert(results.end(), partial.begin(), partial.end());
    }
    return results;
}

bool Memory::nop_bytes(uintptr_t address, size_t count) {
    std::vector<uint8_t> nops(count, 0x90);
    return write_bytes(address, nops);
}

bool Memory::patch_bytes(uintptr_t address, const std::vector<uint8_t>& bytes,
                          std::vector<uint8_t>* original_out) {
    if (original_out) {
        *original_out = read_bytes(address, bytes.size());
        if (original_out->empty()) return false;
    }
    return write_bytes(address, bytes);
}

size_t Memory::flush_write_buffer(WriteBuffer& buffer) {
    size_t success_count = 0;
    for (auto& entry : buffer.entries) {
        if (write_raw(entry.address, entry.data.data(), entry.data.size()))
            ++success_count;
    }
    buffer.clear();
    return success_count;
}

} // namespace oss
