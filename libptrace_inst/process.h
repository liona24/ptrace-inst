#pragma once

#include <map>
#include <set>
#include <sys/types.h>

#include "defs.h"

class InstrumentedProcess;

struct process_handle {
    const pid_t pid;
    InstrumentedProcess* process;

    process_handle(pid_t pid)
        : pid(pid)
        , process(nullptr) {}
};

int start_process(const char* pathname, char* const argv[], char* const envp[], process_handle*&);

class InstrumentedProcess {
public:
    explicit InstrumentedProcess(pid_t pid)
        : pid_(pid) {}

    InstrumentedProcess(InstrumentedProcess&&) = delete;
    InstrumentedProcess(const InstrumentedProcess&) = delete;

    InstrumentedProcess& operator=(const InstrumentedProcess&) = delete;

    int read_memory(addr_t, uint8_t* memory_out, size_t size);

    int run_basic_block();
    int run_until(addr_t);

    int hook_add(addr_t, hook_t);
    int hook_remove(addr_t);

private:
    struct Breakpoint {
        bool enabled;
        uint64_t original_instruction;
        addr_t addr;

        hook_t hook;
        void* user_data;
    };

    const pid_t pid_;
    std::set<Breakpoint> breakpoints_;
    std::map<addr_t, addr_t> known_bbs_;
};
