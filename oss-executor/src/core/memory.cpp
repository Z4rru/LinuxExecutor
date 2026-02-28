
#include "memory.hpp"
#include "utils/logger.hpp"

#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <cerrno>

#if defined(__x86_64__)
#include <sys/user.h>
#endif

namespace oss {

// =============================================================================
//  AOBPattern
// =============================================================================

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

// =============================================================================
//  Static process discovery
// =============================================================================

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

// =============================================================================
//  Lifetime
// =============================================================================

Memory::Memory(pid_t pid) : pid_(pid) {}

Memory::~Memory() {
    detach();
}

Memory::Memory(Memory&& other) noexcept
    : pid_(other.pid_), mem_fd_(other.mem_fd_),
      cached_regions_(std::move(other.cached_regions_)),
      regions_cached_(other.regions_cached_),
      attached_(other.attached_),
      total_scanned_(other.total_scanned_),
      regions_scanned_(other.regions_scanned_) {
    other.pid_              = 0;
    other.mem_fd_           = -1;
    other.regions_cached_   = false;
    other.attached_         = false;
    other.total_scanned_    = 0;
    other.regions_scanned_  = 0;
}

Memory& Memory::operator=(Memory&& other) noexcept {
    if (this != &other) {
        detach();
        pid_              = other.pid_;
        mem_fd_           = other.mem_fd_;
        cached_regions_   = std::move(other.cached_regions_);
        regions_cached_   = other.regions_cached_;
        attached_         = other.attached_;
        total_scanned_    = other.total_scanned_;
        regions_scanned_  = other.regions_scanned_;
        other.pid_              = 0;
        other.mem_fd_           = -1;
        other.regions_cached_   = false;
        other.attached_         = false;
        other.total_scanned_    = 0;
        other.regions_scanned_  = 0;
    }
    return *this;
}

// =============================================================================
//  Accessors
// =============================================================================

void Memory::set_pid(pid_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pid_ != pid) {
        close_mem();
        pid_             = pid;
        attached_        = false;
        regions_cached_  = false;
        cached_regions_.clear();
        total_scanned_   = 0;
        regions_scanned_ = 0;
    }
}

pid_t Memory::get_pid()     const { return pid_;      }
pid_t Memory::target_pid()  const { return pid_;      }
bool  Memory::is_valid()    const { return pid_ > 0;  }
bool  Memory::is_attached() const { return attached_;  }

// =============================================================================
//  File descriptor helpers
// =============================================================================

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

// =============================================================================
//  Attach / detach
// =============================================================================

bool Memory::attach() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pid_ <= 0) return false;

    close_mem();

    // Try read-write first (needed for write_raw via pwrite64)
    mem_fd_ = open_mem(O_RDWR);
    if (mem_fd_ < 0) {
        mem_fd_ = open_mem(O_RDONLY);
        if (mem_fd_ < 0) {
            // Try ptrace attach to gain permissions, then retry
            if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) == 0) {
                int status;
                waitpid(pid_, &status, 0);
                mem_fd_ = open_mem(O_RDONLY);
                ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
            }
        }
        if (mem_fd_ >= 0) {
            LOG_WARN("Opened /proc/{}/mem read-only (writes will use "
                     "process_vm_writev / ptrace fallback)", pid_);
        }
    }

    if (mem_fd_ < 0) {
        LOG_WARN("Cannot open /proc/{}/mem: {} — using process_vm I/O only",
                 pid_, strerror(errno));
    }

    attached_ = true;
    LOG_INFO("Attached to process {}", pid_);
    return true;
}

bool Memory::attach(pid_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (attached_ && pid_ == pid) return true;

    // Inline detach (cannot call detach() — would deadlock on mutex_)
    close_mem();
    attached_        = false;
    regions_cached_  = false;
    cached_regions_.clear();
    total_scanned_   = 0;
    regions_scanned_ = 0;

    pid_ = pid;
    if (pid_ <= 0) return false;

    mem_fd_ = open_mem(O_RDWR);
    if (mem_fd_ < 0) {
        mem_fd_ = open_mem(O_RDONLY);
        if (mem_fd_ < 0) {
            if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) == 0) {
                int status;
                waitpid(pid_, &status, 0);
                mem_fd_ = open_mem(O_RDONLY);
                ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
            }
        }
        if (mem_fd_ >= 0) {
            LOG_WARN("Opened /proc/{}/mem read-only (writes will use "
                     "process_vm_writev / ptrace fallback)", pid_);
        }
    }

    if (mem_fd_ < 0) {
        LOG_WARN("Cannot open /proc/{}/mem: {} — using process_vm I/O only",
                 pid_, strerror(errno));
    }

    attached_ = true;
    LOG_INFO("Attached to process {}", pid_);
    return true;
}

void Memory::detach() {
    std::lock_guard<std::mutex> lock(mutex_);
    close_mem();
    attached_        = false;
    regions_cached_  = false;
    cached_regions_.clear();
    total_scanned_   = 0;
    regions_scanned_ = 0;
}

// =============================================================================
//  Region helpers
// =============================================================================

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

        try {
            region.start = std::stoull(addr_range.substr(0, dash), nullptr, 16);
            region.end   = std::stoull(addr_range.substr(dash + 1), nullptr, 16);
        } catch (...) {
            continue;
        }

        region.perms = perms;

        try {
            region.offset = std::stoull(offset_str, nullptr, 16);
        } catch (...) {
            region.offset = 0;
        }

        cached_regions_.push_back(std::move(region));
    }

    regions_cached_ = true;
    LOG_DEBUG("Found {} total regions for PID {}", cached_regions_.size(), pid_);
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

std::vector<MemoryRegion> Memory::get_readable_regions() {
    auto all = get_regions();
    std::vector<MemoryRegion> result;
    result.reserve(all.size());

    size_t total_size = 0;
    for (auto& r : all) {
        if (!r.readable()) continue;

        // Skip special kernel regions
        if (r.path == "[vvar]" || r.path == "[vsyscall]") continue;

        // Skip very small regions (< 4 KiB)
        if (r.size() < 4096) continue;

        result.push_back(r);
        total_size += r.size();
    }

    LOG_INFO("{} readable regions ({:.1f} MB) available for scanning",
             result.size(),
             static_cast<double>(total_size) / (1024.0 * 1024.0));
    return result;
}

std::optional<MemoryRegion>
Memory::find_region(const std::string& name_contains) {
    auto regions = get_regions();
    for (auto& r : regions) {
        if (!r.path.empty() &&
            r.path.find(name_contains) != std::string::npos)
            return r;
    }
    return std::nullopt;
}

std::optional<uintptr_t>
Memory::get_module_base(const std::string& module_name) {
    auto r = find_region(module_name);
    if (r) return r->start;
    return std::nullopt;
}

std::optional<size_t>
Memory::get_module_size(const std::string& module_name) {
    auto regions = get_regions();
    uintptr_t base = 0;
    uintptr_t end  = 0;
    bool found = false;
    for (auto& r : regions) {
        if (!r.path.empty() &&
            r.path.find(module_name) != std::string::npos) {
            if (!found) {
                base  = r.start;
                found = true;
            }
            if (r.end > end) end = r.end;
        }
    }
    if (found) return end - base;
    return std::nullopt;
}

// =============================================================================
//  Raw read / write
// =============================================================================

bool Memory::read_proc_mem(uintptr_t addr, void* buf, size_t len) {
    if (mem_fd_ < 0) return false;
    ssize_t result = ::pread64(mem_fd_, buf, len, static_cast<off64_t>(addr));
    return result == static_cast<ssize_t>(len);
}

bool Memory::read_process_vm(uintptr_t addr, void* buf, size_t len) {
    if (pid_ <= 0) return false;
    struct iovec local_iov  = { buf, len };
    struct iovec remote_iov = { reinterpret_cast<void*>(addr), len };
    ssize_t result = process_vm_readv(pid_, &local_iov, 1, &remote_iov, 1, 0);
    return result == static_cast<ssize_t>(len);
}

bool Memory::read_raw(uintptr_t address, void* buffer, size_t size) {
    if (pid_ <= 0 || !buffer || size == 0) return false;

    // Prefer /proc/pid/mem fd (fast, no context-switch per call)
    if (read_proc_mem(address, buffer, size))
        return true;

    // Fallback: process_vm_readv
    return read_process_vm(address, buffer, size);
}

bool Memory::write_raw(uintptr_t address, const void* buffer, size_t size) {
    if (pid_ <= 0 || !buffer || size == 0) return false;

    // Prefer /proc/pid/mem fd (needs O_RDWR)
    if (mem_fd_ >= 0) {
        ssize_t result = ::pwrite64(mem_fd_, buffer, size,
                                    static_cast<off64_t>(address));
        if (result == static_cast<ssize_t>(size))
            return true;
    }

    // Fallback: process_vm_writev
    {
        struct iovec local_iov  = { const_cast<void*>(buffer), size };
        struct iovec remote_iov = { reinterpret_cast<void*>(address), size };
        ssize_t result = process_vm_writev(pid_, &local_iov, 1,
                                           &remote_iov, 1, 0);
        if (result == static_cast<ssize_t>(size))
            return true;
    }

    // Last resort: ptrace word-by-word write
    if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) != 0)
        return false;
    int status;
    waitpid(pid_, &status, 0);

    const uint8_t* src = static_cast<const uint8_t*>(buffer);
    bool ok = true;
    for (size_t i = 0; i < size; i += sizeof(long)) {
        long word = 0;
        size_t chunk = std::min(size - i, sizeof(long));
        if (chunk < sizeof(long)) {
            word = ptrace(PTRACE_PEEKDATA, pid_,
                          reinterpret_cast<void*>(address + i), nullptr);
        }
        std::memcpy(&word, src + i, chunk);
        if (ptrace(PTRACE_POKEDATA, pid_,
                   reinterpret_cast<void*>(address + i),
                   reinterpret_cast<void*>(word)) != 0) {
            ok = false;
            break;
        }
    }

    ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
    return ok;
}

bool Memory::read_raw_v(uintptr_t address, void* buffer, size_t size) {
    return read_process_vm(address, buffer, size);
}

bool Memory::write_raw_v(uintptr_t address, const void* buffer, size_t size) {
    if (pid_ <= 0) return false;
    struct iovec local_iov  = { const_cast<void*>(buffer), size };
    struct iovec remote_iov = { reinterpret_cast<void*>(address), size };
    ssize_t result = process_vm_writev(pid_, &local_iov, 1, &remote_iov, 1, 0);
    return result == static_cast<ssize_t>(size);
}

// =============================================================================
//  Byte / string / pointer helpers
// =============================================================================

std::vector<uint8_t> Memory::read_bytes(uintptr_t address, size_t size) {
    std::vector<uint8_t> result(size);
    if (!read_raw(address, result.data(), size))
        result.clear();
    return result;
}

bool Memory::write_bytes(uintptr_t address,
                         const std::vector<uint8_t>& bytes) {
    return write_raw(address, bytes.data(), bytes.size());
}

std::optional<std::string>
Memory::read_string(uintptr_t address, size_t max_len) {
    std::vector<char> buf(max_len + 1, 0);
    size_t chunk      = std::min(max_len, static_cast<size_t>(256));
    size_t total_read = 0;

    while (total_read < max_len) {
        size_t to_read = std::min(chunk, max_len - total_read);
        if (!read_raw(address + total_read,
                      buf.data() + total_read, to_read))
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

// =============================================================================
//  Batch I/O
// =============================================================================

void Memory::batch_read(std::vector<BatchReadEntry>& entries) {
    if (pid_ <= 0 || entries.empty()) return;

    // Fast path: pread64 per entry
    if (mem_fd_ >= 0) {
        for (auto& e : entries) {
            ssize_t r = ::pread64(mem_fd_, e.buffer, e.size,
                                  static_cast<off64_t>(e.address));
            e.success = (r == static_cast<ssize_t>(e.size));
        }
        return;
    }

    // Vectorised path with IOV_MAX batching
    size_t offset = 0;
    while (offset < entries.size()) {
        size_t batch_count = std::min(entries.size() - offset, MAX_IOV_COUNT);

        std::vector<struct iovec> local_iovs(batch_count);
        std::vector<struct iovec> remote_iovs(batch_count);
        size_t total_expected = 0;

        for (size_t i = 0; i < batch_count; ++i) {
            auto& e = entries[offset + i];
            local_iovs[i]  = { e.buffer, e.size };
            remote_iovs[i] = { reinterpret_cast<void*>(e.address), e.size };
            total_expected += e.size;
        }

        ssize_t result = process_vm_readv(
            pid_, local_iovs.data(),
            static_cast<unsigned long>(batch_count),
            remote_iovs.data(),
            static_cast<unsigned long>(batch_count), 0);

        if (result == static_cast<ssize_t>(total_expected)) {
            for (size_t i = 0; i < batch_count; ++i)
                entries[offset + i].success = true;
        } else {
            for (size_t i = 0; i < batch_count; ++i) {
                auto& e = entries[offset + i];
                e.success = read_raw(e.address, e.buffer, e.size);
            }
        }
        offset += batch_count;
    }
}

void Memory::batch_write(std::vector<BatchWriteEntry>& entries) {
    if (pid_ <= 0 || entries.empty()) return;

    // Fast path: pwrite64 per entry
    if (mem_fd_ >= 0) {
        for (auto& e : entries) {
            ssize_t r = ::pwrite64(mem_fd_, e.buffer, e.size,
                                   static_cast<off64_t>(e.address));
            e.success = (r == static_cast<ssize_t>(e.size));
        }
        return;
    }

    // Vectorised path with IOV_MAX batching
    size_t offset = 0;
    while (offset < entries.size()) {
        size_t batch_count = std::min(entries.size() - offset, MAX_IOV_COUNT);

        std::vector<struct iovec> local_iovs(batch_count);
        std::vector<struct iovec> remote_iovs(batch_count);
        size_t total_expected = 0;

        for (size_t i = 0; i < batch_count; ++i) {
            auto& e = entries[offset + i];
            local_iovs[i]  = { const_cast<void*>(e.buffer), e.size };
            remote_iovs[i] = { reinterpret_cast<void*>(e.address), e.size };
            total_expected += e.size;
        }

        ssize_t result = process_vm_writev(
            pid_, local_iovs.data(),
            static_cast<unsigned long>(batch_count),
            remote_iovs.data(),
            static_cast<unsigned long>(batch_count), 0);

        if (result == static_cast<ssize_t>(total_expected)) {
            for (size_t i = 0; i < batch_count; ++i)
                entries[offset + i].success = true;
        } else {
            for (size_t i = 0; i < batch_count; ++i) {
                auto& e = entries[offset + i];
                e.success = write_raw(e.address, e.buffer, e.size);
            }
        }
        offset += batch_count;
    }
}

// =============================================================================
//  AOB / pattern scanning
// =============================================================================

std::optional<uintptr_t> Memory::pattern_scan(
    const std::vector<uint8_t>& pattern,
    const std::string& mask,
    uintptr_t start, size_t length) {
    auto aob = AOBPattern::from_code_style(pattern, mask);
    return aob_scan(aob, start, length);
}

std::optional<uintptr_t> Memory::aob_scan(const AOBPattern& pattern,
                                           uintptr_t start, size_t length) {
    if (pid_ <= 0 || pattern.empty()) return std::nullopt;

    const size_t pat_size = pattern.size();
    const size_t overlap  = pat_size - 1;
    std::vector<uint8_t> buffer(SCAN_CHUNK_SIZE + overlap);

    uintptr_t       current  = start;
    const uintptr_t end_addr = start + length;

    while (current < end_addr) {
        size_t to_read = std::min(static_cast<size_t>(end_addr - current),
                                  buffer.size());
        size_t bytes_read = 0;

        if (read_raw(current, buffer.data(), to_read)) {
            bytes_read = to_read;
        } else {
            size_t partial = to_read;
            while (partial >= pat_size) {
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
                if (pattern.mask[j] &&
                    buffer[i + j] != pattern.bytes[j]) {
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
    if (pid_ <= 0 || pattern.empty()) return results;

    const size_t pat_size = pattern.size();
    const size_t overlap  = pat_size - 1;
    std::vector<uint8_t> buffer(SCAN_CHUNK_SIZE + overlap);

    uintptr_t       current  = start;
    const uintptr_t end_addr = start + length;

    while (current < end_addr) {
        size_t to_read = std::min(static_cast<size_t>(end_addr - current),
                                  buffer.size());
        size_t bytes_read = 0;

        if (read_raw(current, buffer.data(), to_read)) {
            bytes_read = to_read;
        } else {
            size_t partial = to_read;
            while (partial >= pat_size) {
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
                if (pattern.mask[j] &&
                    buffer[i + j] != pattern.bytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) results.push_back(current + i);
        }

        if (bytes_read <= overlap) break;
        current += bytes_read - overlap;
    }

    return results;
}

std::optional<uintptr_t>
Memory::aob_scan_regions(const std::string& ida_pattern,
                         bool executable_only) {
    auto pat     = AOBPattern::from_ida(ida_pattern);
    auto regions = executable_only ? get_executable_regions() : get_regions();

    for (auto& r : regions) {
        if (!r.readable()) continue;
        auto result = aob_scan(pat, r.start, r.size());
        if (result) return result;
    }
    return std::nullopt;
}

std::vector<uintptr_t>
Memory::aob_scan_all_regions(const std::string& ida_pattern,
                             bool executable_only) {
    std::vector<uintptr_t> results;
    auto pat     = AOBPattern::from_ida(ida_pattern);
    auto regions = executable_only ? get_executable_regions() : get_regions();

    for (auto& r : regions) {
        if (!r.readable()) continue;
        auto partial = aob_scan_all(pat, r.start, r.size());
        results.insert(results.end(), partial.begin(), partial.end());
    }
    return results;
}

// =============================================================================
//  Classic pattern scanning (scored, multi-pattern)
// =============================================================================

std::vector<PatternResult> Memory::scan_pattern(
    const std::vector<MemoryRegion>& regions,
    const uint8_t* pattern,
    const char* mask,
    size_t pattern_len,
    int pattern_id)
{
    std::vector<PatternResult> results;
    if (!pattern || !mask || pattern_len == 0) return results;

    constexpr size_t CHUNK_SIZE = 4 * 1024 * 1024;
    std::vector<uint8_t> buffer(CHUNK_SIZE + pattern_len);

    for (const auto& region : regions) {
        if (!region.readable() || region.size() < pattern_len) continue;

        for (uintptr_t offset = 0; offset < region.size(); offset += CHUNK_SIZE) {
            size_t read_size = std::min(
                static_cast<size_t>(region.size() - offset),
                CHUNK_SIZE + pattern_len - 1);
            if (read_size < pattern_len) break;

            if (!read_raw(region.start + offset, buffer.data(), read_size))
                continue;

            total_scanned_ += read_size;

            for (size_t i = 0; i <= read_size - pattern_len; i++) {
                bool match = true;
                for (size_t j = 0; j < pattern_len; j++) {
                    if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    PatternResult pr;
                    pr.address    = region.start + offset + i;
                    pr.pattern_id = pattern_id;
                    pr.score      = 100;
                    results.push_back(pr);
                }
            }
        }
        regions_scanned_++;
    }

    return results;
}

std::vector<PatternResult> Memory::scan_string(
    const std::vector<MemoryRegion>& regions,
    const std::string& str)
{
    std::string mask(str.size(), 'x');
    return scan_pattern(regions,
                        reinterpret_cast<const uint8_t*>(str.data()),
                        mask.c_str(),
                        str.size(), 0);
}

uintptr_t Memory::find_pattern_first(
    const std::vector<MemoryRegion>& regions,
    const uint8_t* pattern,
    const char* mask,
    size_t pattern_len)
{
    auto results = scan_pattern(regions, pattern, mask, pattern_len);
    if (!results.empty()) return results[0].address;
    return 0;
}

// =============================================================================
//  Luau state discovery
// =============================================================================

LuauStateInfo Memory::find_luau_state() {
    if (!attached_) return {};

    auto regions = get_readable_regions();
    if (regions.empty()) {
        LOG_ERROR("No readable regions found for PID {}", pid_);
        return {};
    }

    LOG_INFO("Scanning {} regions for Luau state...", regions.size());

    // Strategy 1: Find task scheduler via known patterns
    auto result = scan_for_task_scheduler(regions);
    if (result.valid) {
        LOG_INFO("Found Luau state via TaskScheduler at 0x{:x} (confidence {}%)",
                 result.lua_state_addr, result.confidence);
        return result;
    }

    // Strategy 2: Direct lua_State scan
    result = scan_for_lua_state_direct(regions);
    if (result.valid) {
        LOG_INFO("Found Luau state via direct scan at 0x{:x} (confidence {}%)",
                 result.lua_state_addr, result.confidence);
        return result;
    }

    // Strategy 3: String table scan
    result = scan_for_string_table(regions);
    if (result.valid) {
        LOG_INFO("Found Luau state via string table at 0x{:x} (confidence {}%)",
                 result.lua_state_addr, result.confidence);
        return result;
    }

    LOG_WARN("Could not find Luau state in {} regions ({:.1f} MB scanned). "
             "Falling back to embedded VM.",
             regions_scanned_,
             static_cast<double>(total_scanned_) / (1024.0 * 1024.0));

    return {};
}

LuauStateInfo Memory::scan_for_task_scheduler(
    const std::vector<MemoryRegion>& regions)
{
    static const char ts_str[] = "TaskScheduler";

    auto str_results = scan_string(regions, ts_str);
    if (str_results.empty()) {
        LOG_DEBUG("TaskScheduler string not found");
        return {};
    }

    LOG_DEBUG("Found {} TaskScheduler string refs", str_results.size());

    for (const auto& sr : str_results) {
        uintptr_t str_addr = sr.address;

        uint8_t addr_bytes[8];
        std::memcpy(addr_bytes, &str_addr, 8);
        std::string addr_mask(8, 'x');

        auto ptr_results = scan_pattern(regions, addr_bytes,
                                        addr_mask.c_str(), 8, 1);
        for (const auto& pr : ptr_results) {
            for (int offset = -0x200; offset <= 0x400; offset += 8) {
                uintptr_t candidate = read_value<uintptr_t>(pr.address + offset);
                if (candidate > 0x10000 && candidate < 0x7fffffffffff) {
                    for (int ls_offset = 0x100; ls_offset < 0x300;
                         ls_offset += 8) {
                        uintptr_t ls_candidate =
                            read_value<uintptr_t>(candidate + ls_offset);
                        if (validate_lua_state(ls_candidate)) {
                            LuauStateInfo info;
                            info.lua_state_addr = ls_candidate;
                            info.script_context = candidate;
                            info.task_scheduler = pr.address;
                            info.valid          = true;
                            info.confidence     = 85;
                            return info;
                        }
                    }
                }
            }
        }
    }

    return {};
}

LuauStateInfo Memory::scan_for_lua_state_direct(
    const std::vector<MemoryRegion>& regions)
{
    std::vector<MemoryRegion> heap_regions;
    for (const auto& r : regions) {
        if (r.writable() && r.is_private() && r.size() >= 65536) {
            if (r.path.empty() || r.path == "[heap]" ||
                r.path.find("RobloxPlayer") != std::string::npos ||
                r.path.find("libroblox") != std::string::npos) {
                heap_regions.push_back(r);
            }
        }
    }

    // Also add all writable anonymous regions not already included
    for (const auto& r : regions) {
        if (r.writable() && r.is_private() && r.path.empty() &&
            r.size() >= 65536) {
            bool already = false;
            for (const auto& hr : heap_regions) {
                if (hr.start == r.start) { already = true; break; }
            }
            if (!already) heap_regions.push_back(r);
        }
    }

    LOG_DEBUG("Scanning {} heap regions for lua_State", heap_regions.size());

    constexpr size_t CHUNK = 2 * 1024 * 1024;
    std::vector<uint8_t> buf(CHUNK);

    for (const auto& region : heap_regions) {
        for (uintptr_t off = 0; off < region.size(); off += CHUNK - 256) {
            size_t rsize = std::min(
                static_cast<size_t>(region.size() - off), CHUNK);
            if (rsize < 256) break;

            if (!read_raw(region.start + off, buf.data(), rsize))
                continue;

            total_scanned_ += rsize;

            for (size_t i = 0; i + 128 <= rsize; i += 8) {
                uint8_t tt     = buf[i];
                uint8_t marked = buf[i + 1];
                uint8_t status = buf[i + 4];

                if (tt != 8 || marked >= 8 || status != 0) continue;

                uintptr_t candidate_addr = region.start + off + i;

                if (validate_lua_state(candidate_addr)) {
                    LuauStateInfo info;
                    info.lua_state_addr = candidate_addr;
                    info.valid          = true;
                    info.confidence     = 70;

                    for (int gs_off : {16, 24, 32}) {
                        uintptr_t gs = read_value<uintptr_t>(
                            candidate_addr + gs_off);
                        if (validate_global_state(gs)) {
                            info.global_state_addr = gs;
                            info.confidence = 80;
                            break;
                        }
                    }

                    return info;
                }
            }
        }
        regions_scanned_++;
    }

    return {};
}

LuauStateInfo Memory::scan_for_string_table(
    const std::vector<MemoryRegion>& regions)
{
    static const std::vector<std::string> marker_strings = {
        "getfenv",
        "coroutine",
        "Instance",
        "game",
        "workspace",
        "pcall",
        "spawn",
        "wait",
    };

    struct RegionScore {
        uintptr_t start;
        size_t    sz;
        int       score;
    };
    std::vector<RegionScore> scored;

    for (const auto& region : regions) {
        if (!region.readable() || region.size() < 4096) continue;

        int score = 0;
        for (const auto& marker : marker_strings) {
            constexpr size_t CHUNK = 4 * 1024 * 1024;
            size_t buf_size = std::min(region.size(), CHUNK);
            std::vector<uint8_t> buf(buf_size);

            for (uintptr_t off = 0; off < region.size(); off += CHUNK - 64) {
                size_t rsize = std::min(
                    static_cast<size_t>(region.size() - off), CHUNK);
                if (rsize < marker.size()) break;

                if (!read_raw(region.start + off, buf.data(), rsize))
                    continue;

                total_scanned_ += rsize;

                bool found_marker = false;
                for (size_t i = 0; i + marker.size() <= rsize; i++) {
                    if (std::memcmp(buf.data() + i, marker.data(),
                                    marker.size()) == 0) {
                        if (i + marker.size() < rsize &&
                            buf[i + marker.size()] == 0) {
                            score++;
                            found_marker = true;
                            break;
                        }
                    }
                }
                if (found_marker) break;
            }
        }

        if (score >= 3) {
            scored.push_back({region.start, region.size(),
                              score});
        }
        regions_scanned_++;
    }

    std::sort(scored.begin(), scored.end(),
              [](const RegionScore& a, const RegionScore& b) {
                  return a.score > b.score;
              });

    if (!scored.empty()) {
        LOG_INFO("Best string table region at 0x{:x} (score {}/{})",
                 scored[0].start, scored[0].score,
                 marker_strings.size());

        MemoryRegion hr;
        hr.start = scored[0].start;
        hr.end   = scored[0].start + scored[0].sz;
        hr.perms = "rw-p";

        auto high_region = std::vector<MemoryRegion>{ hr };

        auto sub = scan_for_lua_state_direct(high_region);
        if (sub.valid) {
            sub.confidence = std::min(95, scored[0].score * 12);
            return sub;
        }
    }

    return {};
}

bool Memory::validate_lua_state(uintptr_t addr) {
    if (addr < 0x10000 || addr > 0x7fffffffffff) return false;

    uint8_t header[64];
    if (!read_raw(addr, header, sizeof(header))) return false;

    if (header[0] != 8) return false;
    if (header[1] >= 8) return false;
    if (header[4] > 6) return false;

    uintptr_t* ptrs = reinterpret_cast<uintptr_t*>(header + 8);

    int valid_ptrs = 0;
    for (int i = 0; i < 6; i++) {
        uintptr_t p = ptrs[i];
        if (p >= 0x10000 && p <= 0x7fffffffffff)
            valid_ptrs++;
    }

    return valid_ptrs >= 3;
}

bool Memory::validate_global_state(uintptr_t addr) {
    if (addr < 0x10000 || addr > 0x7fffffffffff) return false;

    uint8_t data[128];
    if (!read_raw(addr, data, sizeof(data))) return false;

    uintptr_t* ptrs = reinterpret_cast<uintptr_t*>(data);
    int valid_ptrs = 0;
    for (int i = 0; i < 16; i++) {
        if (ptrs[i] >= 0x10000 && ptrs[i] <= 0x7fffffffffff)
            valid_ptrs++;
    }

    return valid_ptrs >= 5;
}

// =============================================================================
//  Remote memory allocation (syscall injection via ptrace)
// =============================================================================

uintptr_t Memory::remote_alloc(size_t size, int prot) {
#if defined(__x86_64__)
    if (pid_ <= 0) return 0;

    if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) != 0) {
        LOG_ERROR("ptrace attach failed for remote_alloc: {}", strerror(errno));
        return 0;
    }

    int status;
    waitpid(pid_, &status, 0);

    struct user_regs_struct orig_regs, regs;
    ptrace(PTRACE_GETREGS, pid_, nullptr, &orig_regs);
    regs = orig_regs;

    // mmap syscall (9 on x86_64)
    regs.rax = 9;
    regs.rdi = 0;
    regs.rsi = size;
    regs.rdx = prot;
    regs.r10 = 0x22;                   // MAP_PRIVATE | MAP_ANONYMOUS
    regs.r8  = static_cast<uintptr_t>(-1);  // fd = -1
    regs.r9  = 0;

    uintptr_t rip = orig_regs.rip;
    long orig_word = ptrace(PTRACE_PEEKTEXT, pid_,
                            reinterpret_cast<void*>(rip), nullptr);

    // Write syscall instruction (0x050F)
    long syscall_insn = (orig_word & ~0xFFFF) | 0x050F;
    ptrace(PTRACE_POKETEXT, pid_, reinterpret_cast<void*>(rip),
           reinterpret_cast<void*>(syscall_insn));

    ptrace(PTRACE_SETREGS, pid_, nullptr, &regs);
    ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
    waitpid(pid_, &status, 0);

    ptrace(PTRACE_GETREGS, pid_, nullptr, &regs);
    uintptr_t result = regs.rax;

    // Restore original instruction and registers
    ptrace(PTRACE_POKETEXT, pid_, reinterpret_cast<void*>(rip),
           reinterpret_cast<void*>(orig_word));
    ptrace(PTRACE_SETREGS, pid_, nullptr, &orig_regs);
    ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);

    if (result == static_cast<uintptr_t>(-1)) {
        LOG_ERROR("Remote mmap failed");
        return 0;
    }

    LOG_DEBUG("Allocated {} bytes at 0x{:x} in target", size, result);
    return result;
#else
    LOG_ERROR("remote_alloc not supported on this architecture");
    (void)size; (void)prot;
    return 0;
#endif
}

bool Memory::remote_free(uintptr_t addr, size_t size) {
#if defined(__x86_64__)
    if (pid_ <= 0) return false;

    if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) != 0) return false;
    int status;
    waitpid(pid_, &status, 0);

    struct user_regs_struct orig_regs, regs;
    ptrace(PTRACE_GETREGS, pid_, nullptr, &orig_regs);
    regs = orig_regs;

    // munmap syscall (11 on x86_64)
    regs.rax = 11;
    regs.rdi = addr;
    regs.rsi = size;

    uintptr_t rip = orig_regs.rip;
    long orig_word = ptrace(PTRACE_PEEKTEXT, pid_,
                            reinterpret_cast<void*>(rip), nullptr);
    long syscall_insn = (orig_word & ~0xFFFF) | 0x050F;
    ptrace(PTRACE_POKETEXT, pid_, reinterpret_cast<void*>(rip),
           reinterpret_cast<void*>(syscall_insn));

    ptrace(PTRACE_SETREGS, pid_, nullptr, &regs);
    ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
    waitpid(pid_, &status, 0);

    ptrace(PTRACE_POKETEXT, pid_, reinterpret_cast<void*>(rip),
           reinterpret_cast<void*>(orig_word));
    ptrace(PTRACE_SETREGS, pid_, nullptr, &orig_regs);
    ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);

    return true;
#else
    LOG_ERROR("remote_free not supported on this architecture");
    (void)addr; (void)size;
    return false;
#endif
}

// =============================================================================
//  Patching
// =============================================================================

bool Memory::nop_bytes(uintptr_t address, size_t count) {
#if defined(__aarch64__)
    if (count % 4 != 0) {
        LOG_WARN("nop_bytes: count {} not aligned to 4-byte ARM64 instruction "
                 "boundary", count);
        return false;
    }
    static constexpr uint8_t arm64_nop[4] = { 0x1F, 0x20, 0x03, 0xD5 };
    std::vector<uint8_t> nops(count);
    for (size_t i = 0; i < count; i += 4)
        std::memcpy(nops.data() + i, arm64_nop, 4);
    return write_bytes(address, nops);

#elif defined(__arm__)
    if (count % 4 != 0) {
        LOG_WARN("nop_bytes: count {} not aligned to 4-byte ARM instruction "
                 "boundary", count);
        return false;
    }
    static constexpr uint8_t arm_nop[4] = { 0x00, 0xF0, 0x20, 0xE3 };
    std::vector<uint8_t> nops(count);
    for (size_t i = 0; i < count; i += 4)
        std::memcpy(nops.data() + i, arm_nop, 4);
    return write_bytes(address, nops);

#else
    std::vector<uint8_t> nops(count, 0x90);
    return write_bytes(address, nops);
#endif
}

bool Memory::patch_bytes(uintptr_t address,
                         const std::vector<uint8_t>& bytes,
                         std::vector<uint8_t>* original_out) {
    if (original_out) {
        *original_out = read_bytes(address, bytes.size());
        if (original_out->empty()) return false;
    }
    return write_bytes(address, bytes);
}

// =============================================================================
//  Deferred buffers
// =============================================================================

size_t Memory::flush_write_buffer(WriteBuffer& buffer) {
    if (buffer.empty()) return 0;

    std::vector<BatchWriteEntry> batch;
    batch.reserve(buffer.count());
    for (auto& entry : buffer.entries) {
        batch.push_back({ entry.address,
                          entry.data.data(),
                          entry.data.size(),
                          false });
    }

    batch_write(batch);

    size_t success_count = 0;
    for (auto& e : batch) {
        if (e.success) ++success_count;
    }

    buffer.clear();
    return success_count;
}

size_t Memory::flush_read_buffer(ReadBuffer& buffer) {
    if (buffer.empty()) return 0;

    for (auto& entry : buffer.entries)
        entry.data.resize(entry.size);

    std::vector<BatchReadEntry> batch;
    batch.reserve(buffer.count());
    for (auto& entry : buffer.entries) {
        batch.push_back({ entry.address,
                          entry.data.data(),
                          entry.size,
                          false });
    }

    batch_read(batch);

    size_t success_count = 0;
    for (size_t i = 0; i < batch.size(); ++i) {
        buffer.entries[i].success = batch[i].success;
        if (!batch[i].success)
            buffer.entries[i].data.clear();
        else
            ++success_count;
    }

    return success_count;
}

} // namespace oss
