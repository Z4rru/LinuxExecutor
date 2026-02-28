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
      regions_cached_(other.regions_cached_) {
    other.pid_            = 0;
    other.mem_fd_         = -1;
    other.regions_cached_ = false;
}

Memory& Memory::operator=(Memory&& other) noexcept {
    if (this != &other) {
        detach();
        pid_            = other.pid_;
        mem_fd_         = other.mem_fd_;
        cached_regions_ = std::move(other.cached_regions_);
        regions_cached_ = other.regions_cached_;
        other.pid_            = 0;
        other.mem_fd_         = -1;
        other.regions_cached_ = false;
    }
    return *this;
}

// =============================================================================
//  Accessors / attach / detach
// =============================================================================

void Memory::set_pid(pid_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pid_ != pid) {
        close_mem();
        pid_            = pid;
        regions_cached_ = false;
        cached_regions_.clear();
    }
}

pid_t Memory::get_pid()     const { return pid_;          }
bool  Memory::is_valid()    const { return pid_ > 0;      }
bool  Memory::is_attached() const { return mem_fd_ >= 0;  }

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

    // Try read-write first (needed for write_raw via pwrite64)
    mem_fd_ = open_mem(O_RDWR);
    if (mem_fd_ < 0) {
        mem_fd_ = open_mem(O_RDONLY);
        if (mem_fd_ < 0) {
            LOG_ERROR("Failed to open /proc/{}/mem: {}", pid_, strerror(errno));
            return false;
        }
        LOG_WARN("Opened /proc/{}/mem read-only (writes will use "
                 "process_vm_writev fallback)", pid_);
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
            continue;   // malformed line
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

bool Memory::read_raw(uintptr_t address, void* buffer, size_t size) {
    if (pid_ <= 0 || !buffer || size == 0) return false;

    // Prefer /proc/pid/mem fd (fast, no context-switch per call)
    if (mem_fd_ >= 0) {
        ssize_t result = ::pread64(mem_fd_, buffer, size,
                                   static_cast<off64_t>(address));
        if (result == static_cast<ssize_t>(size))
            return true;
    }

    // Fallback: process_vm_readv (works even without an open fd)
    return read_raw_v(address, buffer, size);
}

bool Memory::write_raw(uintptr_t address, const void* buffer, size_t size) {
    if (pid_ <= 0 || !buffer || size == 0) return false;

    // Prefer /proc/pid/mem fd (needs O_RDWR)
    if (mem_fd_ >= 0) {
        ssize_t result = ::pwrite64(mem_fd_, buffer, size,
                                    static_cast<off64_t>(address));
        if (result == static_cast<ssize_t>(size))
            return true;
        // pwrite64 fails on read-only fd → fall through to writev
    }

    // Fallback: process_vm_writev
    return write_raw_v(address, buffer, size);
}

bool Memory::read_raw_v(uintptr_t address, void* buffer, size_t size) {
    if (pid_ <= 0) return false;
    struct iovec local_iov  = { buffer, size };
    struct iovec remote_iov = { reinterpret_cast<void*>(address), size };
    ssize_t result = process_vm_readv(pid_, &local_iov, 1, &remote_iov, 1, 0);
    return result == static_cast<ssize_t>(size);
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
    return write_raw(address, str.c_str(), str.size() + 1);   // include NUL
}

std::optional<uintptr_t> Memory::read_pointer(uintptr_t address) {
    return read<uintptr_t>(address);
}

std::optional<uintptr_t> Memory::resolve_pointer_chain(
    uintptr_t base, const std::vector<ptrdiff_t>& offsets) {
    uintptr_t current = base;
    for (size_t i = 0; i < offsets.size(); ++i) {
        if (i < offsets.size() - 1) {
            // Intermediate: dereference
            auto ptr = read<uintptr_t>(current + offsets[i]);
            if (!ptr) return std::nullopt;
            current = *ptr;
        } else {
            // Final offset: just add (caller reads from the result)
            current = current + offsets[i];
        }
    }
    return current;
}

// =============================================================================
//  Batch I/O
// =============================================================================

// FIX(3): IOV_MAX guard — split into sub-batches of MAX_IOV_COUNT

void Memory::batch_read(std::vector<BatchReadEntry>& entries) {
    if (pid_ <= 0 || entries.empty()) return;

    // Fast path: pread64 per entry (no iov limit)
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
            // Partial / failed — fall back per-entry
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
            // Partial-read fallback: halve until readable or too small
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

// FIX(1): CRITICAL — `to_read - pat_size` underflow on size_t
// FIX(2): Added partial-read fallback to match aob_scan robustness
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

        // ── FIX(2): partial-read fallback (was: immediate break) ────────
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

        // ── FIX(1): guard against size_t underflow ─────────────────────
        //    Old code:  for (i = 0; i <= to_read - pat_size; ...)
        //    If to_read < pat_size this wraps to ~0 → infinite OOB loop.
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
//  Patching
// =============================================================================

// FIX(4): Architecture-aware NOP encoding
bool Memory::nop_bytes(uintptr_t address, size_t count) {
#if defined(__aarch64__)
    // ARM64 NOP = 0xD503201F  (4-byte fixed-width instruction)
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
    // ARM32 NOP = 0xE320F000  (4-byte ARM-mode instruction)
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
    // x86 / x86_64 NOP = 0x90
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

// FIX(5): Use batch_write instead of one-at-a-time writes
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

// FIX(6): New ReadBuffer support
size_t Memory::flush_read_buffer(ReadBuffer& buffer) {
    if (buffer.empty()) return 0;

    // Allocate receive buffers
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
            buffer.entries[i].data.clear();   // don't expose garbage
        else
            ++success_count;
    }

    return success_count;
}

} // namespace oss
