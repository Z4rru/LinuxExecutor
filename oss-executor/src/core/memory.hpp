#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <functional>
#include <sys/types.h>
#include <sys/uio.h>
#include <mutex>

namespace oss {

struct MemoryRegion {
    uintptr_t   start  = 0;
    uintptr_t   end    = 0;
    std::string perms;
    std::string path;
    uint64_t    offset = 0;

    size_t size()       const { return end - start; }
    bool readable()     const { return perms.size() > 0 && perms[0] == 'r'; }
    bool writable()     const { return perms.size() > 1 && perms[1] == 'w'; }
    bool executable()   const { return perms.size() > 2 && perms[2] == 'x'; }
    bool is_private()   const { return perms.size() > 3 && perms[3] == 'p'; }
};

struct LuauStateInfo {
    uintptr_t  lua_state_addr    = 0;
    uintptr_t  global_state_addr = 0;
    uintptr_t  script_context    = 0;
    uintptr_t  task_scheduler    = 0;
    bool       valid             = false;
    int        confidence        = 0;
};

struct AOBPattern {
    std::vector<uint8_t> bytes;
    std::vector<bool>    mask;

    static AOBPattern from_ida(const std::string& pattern);
    static AOBPattern from_code_style(const std::vector<uint8_t>& pattern,
                                      const std::string& mask);

    bool   empty() const { return bytes.empty(); }
    size_t size()  const { return bytes.size();  }
};

struct PatternResult {
    uintptr_t address    = 0;
    int       pattern_id = -1;
    int       score      = 0;
};

class Memory {
public:
    explicit Memory(pid_t pid = 0);
    ~Memory();

    Memory(const Memory&)            = delete;
    Memory& operator=(const Memory&) = delete;
    Memory(Memory&& other) noexcept;
    Memory& operator=(Memory&& other) noexcept;

    void  set_pid(pid_t pid);
    pid_t get_pid()      const;
    pid_t target_pid()   const;
    bool  is_valid()     const;
    bool  is_attached()  const;
    bool  attach();
    bool  attach(pid_t pid);
    void  detach();

    std::vector<MemoryRegion>    get_regions(bool refresh = false);
    std::vector<MemoryRegion>    get_executable_regions();
    std::vector<MemoryRegion>    get_writable_regions();
    std::vector<MemoryRegion>    get_readable_regions();
    std::optional<MemoryRegion>  find_region(const std::string& name_contains);
    std::optional<uintptr_t>     get_module_base(const std::string& module_name);
    std::optional<size_t>        get_module_size(const std::string& module_name);

    bool read_raw (uintptr_t address, void*       buffer, size_t size);
    bool write_raw(uintptr_t address, const void* buffer, size_t size);

    bool read_raw_v (uintptr_t address, void*       buffer, size_t size);
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

    template<typename T>
    T read_value(uintptr_t addr) {
        T val{};
        read_raw(addr, &val, sizeof(T));
        return val;
    }

    template<typename T>
    bool write_value(uintptr_t addr, const T& val) {
        return write_raw(addr, &val, sizeof(T));
    }

    std::optional<std::string> read_string(uintptr_t address,
                                           size_t max_len = 512);
    bool write_string(uintptr_t address, const std::string& str);

    std::optional<uintptr_t> read_pointer(uintptr_t address);
    std::optional<uintptr_t> resolve_pointer_chain(
        uintptr_t base, const std::vector<ptrdiff_t>& offsets);

    struct BatchReadEntry {
        uintptr_t address;
        void*     buffer;
        size_t    size;
        bool      success = false;
    };

    struct BatchWriteEntry {
        uintptr_t   address;
        const void* buffer;
        size_t      size;
        bool        success = false;
    };

    void batch_read (std::vector<BatchReadEntry>&  entries);
    void batch_write(std::vector<BatchWriteEntry>& entries);

    std::optional<uintptr_t> pattern_scan(
        const std::vector<uint8_t>& pattern,
        const std::string& mask,
        uintptr_t start, size_t length);

    std::optional<uintptr_t> aob_scan(
        const AOBPattern& pattern, uintptr_t start, size_t length);

    std::optional<uintptr_t> aob_scan_ida(
        const std::string& ida_pattern, uintptr_t start, size_t length);

    std::vector<uintptr_t> aob_scan_all(
        const AOBPattern& pattern, uintptr_t start, size_t length);

    std::optional<uintptr_t> aob_scan_regions(
        const std::string& ida_pattern, bool executable_only = true);

    std::vector<uintptr_t> aob_scan_all_regions(
        const std::string& ida_pattern, bool executable_only = true);

    std::vector<PatternResult> scan_pattern(
        const std::vector<MemoryRegion>& regions,
        const uint8_t* pattern,
        const char* mask,
        size_t pattern_len,
        int pattern_id = 0);

    std::vector<PatternResult> scan_string(
        const std::vector<MemoryRegion>& regions,
        const std::string& str);

    uintptr_t find_pattern_first(
        const std::vector<MemoryRegion>& regions,
        const uint8_t* pattern,
        const char* mask,
        size_t pattern_len);

    LuauStateInfo find_luau_state();

    uintptr_t remote_alloc(size_t size, int prot = 7);
    bool      remote_free(uintptr_t addr, size_t size);

    bool nop_bytes(uintptr_t address, size_t count);
    bool patch_bytes(uintptr_t address, const std::vector<uint8_t>& bytes,
                     std::vector<uint8_t>* original_out = nullptr);

    struct WriteBuffer {
        struct Entry {
            uintptr_t            address;
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
            e.data    = bytes;
            entries.push_back(std::move(e));
        }

        void   clear() { entries.clear(); }
        size_t count() const { return entries.size(); }
        bool   empty() const { return entries.empty(); }
    };

    size_t flush_write_buffer(WriteBuffer& buffer);

    struct ReadBuffer {
        struct Entry {
            uintptr_t            address;
            size_t               size;
            std::vector<uint8_t> data;
            bool                 success = false;
        };
        std::vector<Entry> entries;

        void add(uintptr_t address, size_t size) {
            entries.push_back({address, size, {}, false});
        }

        template<typename T>
        void add_typed(uintptr_t address) {
            add(address, sizeof(T));
        }

        void   clear() { entries.clear(); }
        size_t count() const { return entries.size(); }
        bool   empty() const { return entries.empty(); }

        template<typename T>
        std::optional<T> get(size_t index) const {
            if (index >= entries.size() ||
                !entries[index].success  ||
                entries[index].data.size() < sizeof(T))
                return std::nullopt;
            T value{};
            std::memcpy(&value, entries[index].data.data(), sizeof(T));
            return value;
        }

        const std::vector<uint8_t>* get_bytes(size_t index) const {
            if (index >= entries.size() || !entries[index].success)
                return nullptr;
            return &entries[index].data;
        }
    };

    size_t flush_read_buffer(ReadBuffer& buffer);

    size_t total_scanned_bytes() const { return total_scanned_; }
    int    regions_scanned()     const { return regions_scanned_; }

    static std::optional<pid_t>  find_process(const std::string& name);
    static std::vector<pid_t>    find_all_processes(const std::string& name);

private:
    pid_t                      pid_             = 0;
    int                        mem_fd_          = -1;
    std::vector<MemoryRegion>  cached_regions_;
    bool                       regions_cached_  = false;
    bool                       attached_        = false;
    mutable std::mutex         mutex_;

    size_t                     total_scanned_   = 0;
    int                        regions_scanned_ = 0;

    int  open_mem(int flags);
    void close_mem();

    bool read_proc_mem(uintptr_t addr, void* buf, size_t len);
    bool read_process_vm(uintptr_t addr, void* buf, size_t len);

    LuauStateInfo scan_for_task_scheduler(const std::vector<MemoryRegion>& regions);
    LuauStateInfo scan_for_lua_state_direct(const std::vector<MemoryRegion>& regions);
    LuauStateInfo scan_for_string_table(const std::vector<MemoryRegion>& regions);
    bool validate_lua_state(uintptr_t candidate);
    bool validate_global_state(uintptr_t candidate);

    static constexpr size_t SCAN_CHUNK_SIZE = 1024 * 1024;
    static constexpr size_t MAX_IOV_COUNT   = 1024;
};

} // namespace oss
