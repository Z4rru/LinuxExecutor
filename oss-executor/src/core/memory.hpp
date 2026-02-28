#pragma once
// =============================================================================
//  memory.hpp — Process memory read/write, AOB scanning, batch I/O,
//               Luau state discovery, remote allocation
//
//  Threading model:
//    • attach()/detach()/set_pid() hold an exclusive lock.
//    • get_regions() holds an exclusive lock (updates cache).
//    • read_raw()/write_raw() and scan helpers do NOT lock; callers must
//      guarantee that attach/detach is not called concurrently with I/O.
// =============================================================================

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

// ─────────────────────────────────────────────────────────────────────────────
//  MemoryRegion — one line from /proc/<pid>/maps
// ─────────────────────────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────────────────────────
//  LuauStateInfo — result of Luau runtime discovery in target process
// ─────────────────────────────────────────────────────────────────────────────
struct LuauStateInfo {
    uintptr_t  lua_state_addr    = 0;
    uintptr_t  global_state_addr = 0;
    uintptr_t  script_context    = 0;
    uintptr_t  task_scheduler    = 0;
    bool       valid             = false;
    int        confidence        = 0;   // 0-100
};

// ─────────────────────────────────────────────────────────────────────────────
//  AOBPattern — Array-of-Bytes pattern with wildcard mask
// ─────────────────────────────────────────────────────────────────────────────
struct AOBPattern {
    std::vector<uint8_t> bytes;
    std::vector<bool>    mask;   // true = must match, false = wildcard

    /// Parse IDA-style: "48 8B ?? 0F 84 ?? ?? ?? ??"
    static AOBPattern from_ida(const std::string& pattern);

    /// Classic (pattern + "xx??x") style
    static AOBPattern from_code_style(const std::vector<uint8_t>& pattern,
                                      const std::string& mask);

    bool   empty() const { return bytes.empty(); }
    size_t size()  const { return bytes.size();  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  PatternResult — scored scan result with pattern identification
// ─────────────────────────────────────────────────────────────────────────────
struct PatternResult {
    uintptr_t address    = 0;
    int       pattern_id = -1;
    int       score      = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  Memory — main class
// ─────────────────────────────────────────────────────────────────────────────
class Memory {
public:
    explicit Memory(pid_t pid = 0);
    ~Memory();

    Memory(const Memory&)            = delete;
    Memory& operator=(const Memory&) = delete;
    Memory(Memory&& other) noexcept;
    Memory& operator=(Memory&& other) noexcept;

    // ── Process management ──────────────────────────────────────────────
    void  set_pid(pid_t pid);
    pid_t get_pid()      const;
    pid_t target_pid()   const;
    bool  is_valid()     const;
    bool  is_attached()  const;
    bool  attach();
    bool  attach(pid_t pid);
    void  detach();

    // ── Region queries ──────────────────────────────────────────────────
    std::vector<MemoryRegion>    get_regions(bool refresh = false);
    std::vector<MemoryRegion>    get_executable_regions();
    std::vector<MemoryRegion>    get_writable_regions();
    std::vector<MemoryRegion>    get_readable_regions();
    std::optional<MemoryRegion>  find_region(const std::string& name_contains);
    std::optional<uintptr_t>     get_module_base(const std::string& module_name);
    std::optional<size_t>        get_module_size(const std::string& module_name);

    // ── Raw I/O (prefers /proc/pid/mem fd, falls back to vm syscalls) ───
    bool read_raw (uintptr_t address, void*       buffer, size_t size);
    bool write_raw(uintptr_t address, const void* buffer, size_t size);

    // ── Explicit process_vm_{readv,writev} ──────────────────────────────
    bool read_raw_v (uintptr_t address, void*       buffer, size_t size);
    bool write_raw_v(uintptr_t address, const void* buffer, size_t size);

    // ── Byte-level helpers ──────────────────────────────────────────────
    std::vector<uint8_t> read_bytes(uintptr_t address, size_t size);
    bool write_bytes(uintptr_t address, const std::vector<uint8_t>& bytes);

    // ── Typed helpers (optional — safe) ─────────────────────────────────
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

    // ── Typed helpers (value — quick) ───────────────────────────────────
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

    // ── String helpers ──────────────────────────────────────────────────
    std::optional<std::string> read_string(uintptr_t address,
                                           size_t max_len = 512);
    bool write_string(uintptr_t address, const std::string& str);

    // ── Pointer helpers ─────────────────────────────────────────────────
    std::optional<uintptr_t> read_pointer(uintptr_t address);
    std::optional<uintptr_t> resolve_pointer_chain(
        uintptr_t base, const std::vector<ptrdiff_t>& offsets);

    // ── Batch I/O (vectorised) ──────────────────────────────────────────
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

    // ── AOB pattern scanning ────────────────────────────────────────────
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

    // ── Classic pattern scanning (scored, multi-pattern) ────────────────
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

    // ── Luau state discovery ────────────────────────────────────────────
    LuauStateInfo find_luau_state();

    // ── Remote memory allocation (syscall injection) ────────────────────
    uintptr_t remote_alloc(size_t size, int prot = 7 /* RWX */);
    bool      remote_free(uintptr_t addr, size_t size);

    // ── Patching helpers ────────────────────────────────────────────────
    bool nop_bytes(uintptr_t address, size_t count);
    bool patch_bytes(uintptr_t address, const std::vector<uint8_t>& bytes,
                     std::vector<uint8_t>* original_out = nullptr);

    // ── Deferred WriteBuffer ────────────────────────────────────────────
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

    // ── Deferred ReadBuffer ─────────────────────────────────────────────
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

    // ── Scan statistics ─────────────────────────────────────────────────
    size_t total_scanned_bytes() const { return total_scanned_; }
    int    regions_scanned()     const { return regions_scanned_; }

    // ── Static process utilities ────────────────────────────────────────
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
