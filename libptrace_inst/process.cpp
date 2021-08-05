#include "process.h"

#include <cstdio>
#include <cstdlib>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NDEBUG
#define LOG(x, ...)                                                                                \
    do {                                                                                           \
        fprintf(stderr, "DEBUG: %s:%d - " x "\n", __FILE__, __LINE__, ##__VA_ARGS__);              \
    } while (0)
#else
#define LOG(x)
#endif
#define WARN(x, ...)                                                                               \
    do {                                                                                           \
        fprintf(stderr, "WARN: %s:%d - " x "\n", __FILE__, __LINE__, ##__VA_ARGS__);               \
    } while (0)
#define PRINTERR() fprintf(stderr, "ERROR: %s:%d - %s\n", __FILE__, __LINE__, strerror(errno))
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if ((x) < 0) {                                                                             \
            PRINTERR();                                                                            \
            return -1;                                                                             \
        }                                                                                          \
    } while (0)
#define WAIT(pid, status)                                                                          \
    do {                                                                                           \
        if (waitpid(pid, &status, 0) < 0 || WIFSIGNALED(status)) {                                 \
            return 0;                                                                              \
        } else if (WIFEXITED(status)) {                                                            \
            return WEXITSTATUS(status);                                                            \
        }                                                                                          \
    } while (0)

int start_process(const char* pathname,
                  char* const argv[],
                  char* const envp[],
                  process_handle*& h) {
    int status;
    pid_t pid;

    LOG("start_process %s", pathname);

    pid = fork();

    if (pid == 0) {
        // child
        CHECK(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
        CHECK(execve(pathname, argv, envp));
    }

    h = new process_handle(pid);
    h->process = new InstrumentedProcess(pid);

    WAIT(pid, status);
    CHECK(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL));

    return 0;
}

bool InstrumentedProcess::set_breakpoint(InstrumentedProcess::Breakpoint& b) {
    constexpr uint64_t INSTR_TRAP = 0xCC;
    const uint64_t interrupt = (b.original_instruction & ~0xFFULL) | INSTR_TRAP;

    if (ptrace(PTRACE_POKETEXT, pid_, (void*)b.addr, interrupt) < 0) {
        PRINTERR();
        return false;
    } else {
        b.is_set = true;
        return true;
    }
}

int InstrumentedProcess::hit_breakpoint(
    std::map<addr_t, InstrumentedProcess::Breakpoint>::iterator& hit) {

    int status;

    CHECK(ptrace(PTRACE_CONT, pid_, NULL, NULL));
    WAIT(pid_, status);

    addr_t rip;
    CHECK(ptrace(PTRACE_PEEKUSER, pid_, REG_RIP * 4, &rip));
    rip -= 1;

    CHECK(ptrace(PTRACE_POKEUSER, pid_, REG_RIP * 4, rip));

    hit = breakpoints_.find(rip);
    if (hit == breakpoints_.end()) {
        // this is not recoverable.
        WARN("We lost a breakpoint @ %p. Panic mode.", (void*)rip);
        abort();
    }
    CHECK(ptrace(PTRACE_POKETEXT, pid_, rip, hit->second.original_instruction));
    hit->second.is_set = false;

    if (!hit->second.enabled) {
        return 0;
    }

    if (hit->second.hook != nullptr) {
        struct user_regs_struct regs;
        CHECK(ptrace(PTRACE_GETREGS, pid_, NULL, &regs));

        hit->second.hook(pid_, rip, &regs, hit->second.user_data);
    }

    CHECK(ptrace(PTRACE_SINGLESTEP, pid_, NULL, NULL));
    WAIT(pid_, status);

    if (!set_breakpoint(hit->second)) {
        return -1;
    } else {
        return 0;
    }
}

std::map<addr_t, InstrumentedProcess::Breakpoint>::iterator InstrumentedProcess::add_breakpoint(
    addr_t addr,
    hook_t hook,
    void* user_data) {

    LOG("Create breakpoint @ %p", (void*)addr);

    const auto it = breakpoints_.find(addr);
    if (it != breakpoints_.end()) {

        it->second.hook = hook;
        it->second.user_data = user_data;

        it->second.enabled = true;

        if (!set_breakpoint(it->second)) {
            WARN("Re-enable failed for breakpoint @ %p", (void*)addr);
            breakpoints_.erase(it);
            return breakpoints_.end();
        } else {
            return it;
        }
    }

    const uint64_t original_instr = ptrace(PTRACE_PEEKDATA, pid_, (void*)addr, NULL);

    Breakpoint b;
    b.addr = addr;
    b.enabled = true;
    b.is_set = false;
    b.hook = hook;
    b.user_data = user_data;
    b.original_instruction = original_instr;

    if (!set_breakpoint(b)) {
        return breakpoints_.end();
    }

    return breakpoints_.emplace(addr, std::move(b)).first;
}

int InstrumentedProcess::read_memory(addr_t, uint8_t* memory_out, size_t size) {
    (void)memory_out;
    (void)size;
    return -1;
}
int InstrumentedProcess::run_basic_block() { return -1; }
int InstrumentedProcess::run_until(addr_t addr) {
    bool is_temp = false;
    auto it = breakpoints_.find(addr);

    if (it == breakpoints_.end()) {
        is_temp = true;
        it = add_breakpoint(addr, nullptr, nullptr);

        // pre-emptively disable to not place it again.
        it->second.enabled = false;

        if (it == breakpoints_.end()) {
            WARN("Could not insert temporary breakpoint @ %p", (void*)addr);
            return -1;
        }
    } else if (it->second.is_set) {
        if (!set_breakpoint(it->second)) {
            return -2;
        }
    }

    std::map<addr_t, Breakpoint>::iterator hit;
    do {
        CHECK(hit_breakpoint(hit));
    } while (hit->second.addr != addr);

    if (is_temp) {
        breakpoints_.erase(addr);
    }

    return 0;
}
int InstrumentedProcess::hook_add(addr_t addr, hook_t hook, void* user_data) {
    const auto it = add_breakpoint(addr, hook, user_data);
    if (it == breakpoints_.end()) {
        WARN("Could not insert hook at %p", (void*)addr);
        return -1;
    } else {
        return 0;
    }
}

int InstrumentedProcess::hook_remove(addr_t addr) {
    auto it = breakpoints_.find(addr);
    if (it == breakpoints_.end()) {
        WARN("Tried to remove hook for un-hooked address %p", (void*)addr);
        return 0;
    }

    it->second.enabled = false;

    return 0;
}
