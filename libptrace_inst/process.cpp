#include "process.h"

#include <cstdio>
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

int InstrumentedProcess::read_memory(addr_t, uint8_t* memory_out, size_t size) {
    (void)memory_out;
    (void)size;
    return -1;
}
int InstrumentedProcess::run_basic_block() { return -1; }
int InstrumentedProcess::run_until(addr_t) {
    LOG("%d", pid_);
    return -1;
}
int InstrumentedProcess::hook_add(addr_t, hook_t) { return -1; }
int InstrumentedProcess::hook_remove(addr_t) { return -1; }
