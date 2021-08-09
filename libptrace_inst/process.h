#pragma once

#include <map>
#include <set>
#include <sys/types.h>

#include "defs.h"

class InstrumentedProcess;

struct process_handle {
    const pid_t pid;
    addr_t rip;
    InstrumentedProcess* process;

    process_handle(pid_t pid)
        : pid(pid)
        , process(nullptr) {}
};

int start_process(const char* pathname, char* const argv[], char* const envp[], process_handle*&);

class InstrumentedProcess {
public:
    explicit InstrumentedProcess(process_handle* h);

    InstrumentedProcess(InstrumentedProcess&&) = delete;
    InstrumentedProcess(const InstrumentedProcess&) = delete;

    InstrumentedProcess& operator=(const InstrumentedProcess&) = delete;

    int read_memory(addr_t, uint8_t* memory_out, size_t size);

    int run_until(addr_t);

    int find_next_basic_block(addr_t* next_branch);

    int hook_add(addr_t, hook_t, void* user_data);
    int hook_remove(addr_t);

private:
    struct Breakpoint {
        bool enabled { false };
        bool is_set { false };
        uint64_t original_instruction { 0 };
        addr_t addr { 0 };

        hook_t hook { nullptr };
        void* user_data { nullptr };

        Breakpoint() = default;
        Breakpoint& operator=(const Breakpoint&) = default;

        inline constexpr bool operator<(const Breakpoint& rhs) const { return addr < rhs.addr; }
    };

    inline pid_t pid() const { return handle_->pid; }
    inline addr_t inst_ptr() const { return handle_->rip; }

    [[nodiscard]] int hit_breakpoint(
        std::map<addr_t, InstrumentedProcess::Breakpoint>::iterator& hit);
    [[nodiscard]] bool set_breakpoint(Breakpoint&);
    [[nodiscard]] std::map<addr_t, Breakpoint>::iterator add_breakpoint(addr_t,
                                                                        hook_t,
                                                                        void* user_data);

    process_handle* handle_;
    size_t csh_;
    bool has_capstone_ { false };
    std::map<addr_t, Breakpoint> breakpoints_;
    std::map<addr_t, addr_t> known_bbs_;
};
