#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <cstring>
#include <sys/types.h>
#include <sys/uio.h>
#include <unordered_map>
#include <mutex>
#include <functional>

namespace oss {

struct MemoryRegion {
    uintptr_t start = 0;
    uintptr_t end = 0;
    std::string perms;
    std::string path;
    uint64_t offset = 0;

    size_t size() const { return end - start; }
    bool readable() const { return perms.size() > 0 && perms[0] == 'r'; }
    bool writable() const { return perms.size() > 1 && perms[1] == 'w'; }
    bool executable() const { return perms.size() > 2 && perms[2] == 'x'; }
    bool is_private() const { return perms.size() > 3 && perms[3] == 'p'; }
};

struct AOBPattern {
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;

    static AOBPattern from_ida(const std::string& pattern);
    static AOBPattern from_code_style(const std::vector<uint8_t>& pattern,
                                       const std::string& mask);
};

class Memory {
public:
    explicit Memory(pid_t pid = 0);
    ~Memory();

    Memory(const Memory&) = delete;
    Memory& operator=(const Memory&) = delete;
    Memory(Memory&& other) noexcept;
    Memory& operator=(Memory&& other) noexcept;

    void set_pid(pid_t pid);
    pid_t get_pid() const;
    bool is_valid() const;
    bool is_attached() const;

    bool attach();
    void detach();

    std::vector<MemoryRegion> get_regions(bool refresh = false);
    std::vector<MemoryRegion> get_executable_regions();
    std::vector<MemoryRegion> get_writable_regions();
    std::optional<MemoryRegion> find_region(const std::string& name_contains);
    std::optional<uintptr_t> get_module_base(const std::string& module_name);
    std::optional<size_t> get_module_size(const std::string& module_name);

    bool read_raw(uintptr_t address, void* buffer, size_t size);
    bool write_raw(uintptr_t address, const void* buffer, size_t size);

    bool read_raw_v(uintptr_t address, void* buffer, size_t size);
    bool write_raw_v(uintptr_t address, const void* buffer, size_t size);

    std::vector<uint8_t> read_bytes(uintptr_t address, size_t size);
    bool write_bytes(uintptr_t address, const std::vector<uint8_t>& bytes);

    template<typename T>
    std::optional<T> read(uintptr_t address) {
        T value{};
        if (read_raw(address, &value, sizeof(T)))
            return value;
        return std::nullopt;
    }

    template<typename T>
    bool write(uintptr_t address, const T& value) {
        return write_raw(address, &value, sizeof(T));
    }

    std::optional<std::string> read_string(uintptr_t address, size_t max_len = 512);
    bool write_string(uintptr_t address, const std::string& str);

    std::optional<uintptr_t> read_pointer(uintptr_t address);
    std::optional<uintptr_t> resolve_pointer_chain(uintptr_t base,
                                                     const std::vector<ptrdiff_t>& offsets);

    struct BatchReadEntry {
        uintptr_t address;
        void* buffer;
        size_t size;
        bool success = false;
    };

    struct BatchWriteEntry {
        uintptr_t address;
        const void* buffer;
        size_t size;
        bool success = false;
    };

    void batch_read(std::vector<BatchReadEntry>& entries);
    void batch_write(std::vector<BatchWriteEntry>& entries);

    std::optional<uintptr_t> pattern_scan(
        const std::vector<uint8_t>& pattern,
        const std::string& mask,
        uintptr_t start, size_t length);

    std::optional<uintptr_t> aob_scan(const AOBPattern& pattern,
                                       uintptr_t start, size_t length);

    std::optional<uintptr_t> aob_scan_ida(const std::string& ida_pattern,
                                           uintptr_t start, size_t length);

    std::vector<uintptr_t> aob_scan_all(const AOBPattern& pattern,
                                         uintptr_t start, size_t length);

    std::optional<uintptr_t> aob_scan_regions(const std::string& ida_pattern,
                                               bool executable_only = true);

    std::vector<uintptr_t> aob_scan_all_regions(const std::string& ida_pattern,
                                                  bool executable_only = true);

    bool nop_bytes(uintptr_t address, size_t count);
    bool patch_bytes(uintptr_t address, const std::vector<uint8_t>& bytes,
                     std::vector<uint8_t>* original_out = nullptr);

    struct WriteBuffer {
        struct Entry {
            uintptr_t address;
            std::vector<uint8_t> data;
        };
        std::vector<Entry> entries;

        void add(uintptr_t address, const void* data, size_t size) {
            Entry e;
            e.address = address;
            e.data.assign(static_cast<const uint8_t*>(data),
                          static_cast<const uint8_t*>(data) + size);
            entries.push_back(std::move(e));
        }

        template<typename T>
        void add_value(uintptr_t address, const T& value) {
            add(address, &value, sizeof(T));
        }

        void add_bytes(uintptr_t address, const std::vector<uint8_t>& bytes) {
            Entry e;
            e.address = address;
            e.data = bytes;
            entries.push_back(std::move(e));
        }

        void clear() { entries.clear(); }
        size_t count() const { return entries.size(); }
    };

    size_t flush_write_buffer(WriteBuffer& buffer);

    static std::optional<pid_t> find_process(const std::string& name);
    static std::vector<pid_t> find_all_processes(const std::string& name);

private:
    pid_t pid_ = 0;
    int mem_fd_ = -1;
    std::vector<MemoryRegion> cached_regions_;
    bool regions_cached_ = false;
    mutable std::mutex mutex_;

    int open_mem(int flags);
    void close_mem();

    static constexpr size_t SCAN_CHUNK_SIZE = 1024 * 1024;
};

} // namespace oss
