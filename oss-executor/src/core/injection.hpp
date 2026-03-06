<<<<
    pid_t               elevated_pid_ = -1;
    int                 elevated_in_fd_ = -1;
    int                 elevated_out_fd_ = -1;
};

}
====
    pid_t               elevated_pid_ = -1;
    int                 elevated_in_fd_ = -1;
    int                 elevated_out_fd_ = -1;

    struct DirectMailbox {
        char magic[16];
        uint64_t seq;
        uint64_t ack;
        uint32_t data_size;
        uint32_t flags;
        uint8_t guard;
        uint8_t pad[7];
        char data[16336];
    };

    struct DirectHookAddrs {
        uintptr_t resume    = 0;
        uintptr_t newthread = 0;
        uintptr_t load      = 0;
        uintptr_t settop    = 0;
        uintptr_t sandbox   = 0;
    };

    struct DirectHookState {
        uintptr_t cave_addr    = 0;
        uintptr_t mailbox_addr = 0;
        size_t    cave_size    = 0;
        size_t    stolen_len   = 0;
        uint8_t   stolen_bytes[32] = {};
        uint8_t   orig_patch[16]   = {};
        size_t    patch_len    = 0;
        bool      active       = false;
    };

    bool inject_via_direct_hook(pid_t pid);
    bool find_remote_luau_functions(pid_t pid, DirectHookAddrs& out);
    bool send_via_mailbox(const void* data, size_t len, uint32_t flags);
    bool is_direct_hook() const { return dhook_.active; }
    void cleanup_direct_hook();

    DirectHookState dhook_;
};

}
>>>>
