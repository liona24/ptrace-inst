#include "process.h"

#include <cstdio>
#include <cstdlib>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <capstone/capstone.h>

#ifndef NDEBUG
#define LOG(x, ...)                                                                                \
    do {                                                                                           \
        fprintf(stderr, "DEBUG: %s:%d - " x "\n", __FILE__, __LINE__, ##__VA_ARGS__);              \
    } while (0)
#else
#define LOG(x, ...)
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

int find_next_branch_instr(csh,
                           const uint8_t** code,
                           size_t* code_size,
                           uint64_t* rip,
                           uint32_t inst_mask);

int start_process(const char* pathname,
                  char* const argv[],
                  char* const envp[],
                  int fd_stdin,
                  int fd_stdout,
                  int fd_stderr,
                  process_handle*& h) {
    int status;
    pid_t pid;

    LOG("start_process %s", pathname);

    pid = fork();

    if (pid == 0) {
        if (fd_stdin >= 0) {
            CHECK(dup2(fd_stdin, STDIN_FILENO));
        }
        if (fd_stdout >= 0) {
            CHECK(dup2(fd_stdout, STDOUT_FILENO));
        }
        if (fd_stderr >= 0) {
            CHECK(dup2(fd_stderr, STDERR_FILENO));
        }
        close_range(3, ~0U, 0);

        // child
        CHECK(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
        CHECK(execve(pathname, argv, envp));
    }

    if (fd_stdin >= 0) {
        close(fd_stdin);
    }
    if (fd_stdout >= 0) {
        close(fd_stdout);
    }
    if (fd_stderr >= 0) {
        close(fd_stderr);
    }

    h = new process_handle(pid);
    h->process = new InstrumentedProcess(h);

    WAIT(pid, status);
    CHECK(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL));
    h->rip = ptrace(PTRACE_PEEKUSER, pid, REG_RIP * sizeof(size_t), NULL);

    return 0;
}

InstrumentedProcess::InstrumentedProcess(process_handle* h)
    : handle_(h) {

    cs_err err;

    if ((err = cs_open(CS_ARCH_X86, CS_MODE_64, &csh_)) != CS_ERR_OK ||
        (err = cs_option(csh_, CS_OPT_DETAIL, CS_OPT_ON)) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize capstone: %s\n", cs_strerror(err));
    } else {
        has_capstone_ = true;
    }
}

bool InstrumentedProcess::set_breakpoint(InstrumentedProcess::Breakpoint& b) {
    if (!b.enabled) {
        return true;
    }

    constexpr uint64_t INSTR_TRAP = 0xCC;
    const uint64_t interrupt = (b.original_instruction & ~0xFFULL) | INSTR_TRAP;

    if (ptrace(PTRACE_POKETEXT, pid(), (void*)b.addr, interrupt) < 0) {
        PRINTERR();
        return false;
    } else {
        b.is_set = true;
        return true;
    }
}

int InstrumentedProcess::single_step() {
    if (hit_plus_one_) {
        return 0;
    }

    int status;

    CHECK(ptrace(PTRACE_SINGLESTEP, pid(), NULL, NULL));
    WAIT(pid(), status);

    if (hit_ != breakpoints_.end() && !set_breakpoint(hit_->second)) {
        WARN("Could not restore breakpoint @ %p", (void*)hit_->second.addr);
        // we could also fail here, though nothing is in an unstable state yet.
    }

    hit_plus_one_ = true;
    return 0;
}

int InstrumentedProcess::hit_breakpoint() {

    int status;

    CHECK(single_step());

    CHECK(ptrace(PTRACE_CONT, pid(), NULL, NULL));
    WAIT(pid(), status);

    hit_plus_one_ = false;

    addr_t rip = ptrace(PTRACE_PEEKUSER, pid(), REG_RIP * sizeof(size_t), NULL);
    rip -= 1;

    handle_->rip = rip;

    CHECK(ptrace(PTRACE_POKEUSER, pid(), REG_RIP * sizeof(size_t), rip));

    hit_ = breakpoints_.find(rip);
    if (hit_ == breakpoints_.end()) {
        // this is not recoverable :(
        WARN("We lost a breakpoint @ %p. Panic mode.", (void*)rip);
        abort();
    }
    CHECK(ptrace(PTRACE_POKETEXT, pid(), rip, hit_->second.original_instruction));
    hit_->second.is_set = false;

    if (!hit_->second.enabled) {
        return 0;
    }

    if (hit_->second.hook != nullptr) {
        struct user_regs_struct regs;
        CHECK(ptrace(PTRACE_GETREGS, pid(), NULL, &regs));

        hit_->second.hook(handle_, rip, &regs, hit_->second.user_data);
    }

    return 0;
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

    const uint64_t original_instr = ptrace(PTRACE_PEEKDATA, pid(), (void*)addr, NULL);

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

int InstrumentedProcess::read_memory(addr_t addr, uint8_t* memory_out, size_t size) {
    long value;

    for (size_t i = 0; i < size / sizeof(long); ++i) {
        value = ptrace(PTRACE_PEEKDATA, pid(), addr + addr_t(i) * sizeof(long), NULL);
        ((long*)memory_out)[i] = value;
    }

    return 0;
}

int InstrumentedProcess::find_next_basic_block(addr_t* next_branch, uint32_t inst_mask) {
    int status;
    uint8_t code_buf[128] = { 0 };
    const uint8_t* inst = code_buf;
    size_t size = sizeof(code_buf);
    addr_t rip = inst_ptr();

    if (!has_capstone_) {
        WARN("Initialization of capstone failed. No basic block support available!");
        return -1;
    }

    auto it = known_bbs_.find(rip);
    if (it != known_bbs_.end()) {
        return it->second;
    }

    // Perform the "branch"
    CHECK(single_step());
    rip = ptrace(PTRACE_PEEKUSER, pid(), REG_RIP * sizeof(size_t), NULL);

    CHECK(read_memory(rip, code_buf, sizeof(code_buf)));

    while (true) {
        status = find_next_branch_instr(csh_, &inst, &size, &rip, inst_mask);

        if (status == -1) {
            WARN("Did not find a branching instruction!");
            return -2;
        } else if (status == 0) {
            // FIXME: This should only be done when the branch is unconditional
            //        Alternatively, we could also store more information and use that upon lookup?
            // known_bbs_.emplace(inst_ptr(), rip);
            *next_branch = rip;
            return 0;
        }

        memcpy(code_buf, inst, size);
        CHECK(read_memory(rip + sizeof(code_buf), code_buf + size, sizeof(code_buf) - size));
        rip += sizeof(code_buf) - size;
        size = sizeof(code_buf);
        inst = code_buf;
    }
}

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

    do {
        CHECK(hit_breakpoint());
    } while (hit_->second.addr != addr);

    if (is_temp) {
        breakpoints_.erase(addr);
    }

    return 0;
}

int InstrumentedProcess::run_continue() {
    CHECK(hit_breakpoint());

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

int find_next_branch_instr(csh h,
                           const uint8_t** code,
                           size_t* code_size,
                           uint64_t* rip,
                           uint32_t inst_mask) {
    cs_insn* insn;
    int status = -1;

    insn = cs_malloc(h);
    if (insn == nullptr) {
        WARN("Capstone error: %s\n", cs_strerror(cs_errno(h)));
        return status;
    }

    uint64_t current_instr;

    while (*code_size > 0) {
        current_instr = *rip;

        if (!cs_disasm_iter(h, code, code_size, rip, insn)) {
            WARN("Disassembler error: %s\n", cs_strerror(cs_errno(h)));
            goto END;
        }

        if (insn->id == X86_INS_INT3 ||
            ((inst_mask & BI_JUMP) && cs_insn_group(h, insn, CS_GRP_JUMP)) ||
            ((inst_mask & BI_CALL) && cs_insn_group(h, insn, CS_GRP_CALL)) ||
            ((inst_mask & BI_RET) && cs_insn_group(h, insn, CS_GRP_RET)) ||
            ((inst_mask & BI_IRET) && cs_insn_group(h, insn, CS_GRP_IRET)) ||
            ((inst_mask & BI_JUMP_REL) && cs_insn_group(h, insn, CS_GRP_BRANCH_RELATIVE))) {

            *rip = current_instr;
            status = 0;
            goto END;
        }

        // We use this to check if we ever reached a valid instruction
        status -= 1;
    }

END:
    cs_free(insn, 1);
    return status;
}
