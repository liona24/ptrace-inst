#pragma once

#include <type_traits>

#include "defs.h"
#include "process.h"

#define EXPORT __attribute__((visibility("default")))

static_assert(std::is_standard_layout<process_handle>::value);

#ifdef __cplusplus
extern "C" {
#endif

EXPORT process_handle* pi_start_process(const char* pathname,
                                        char* const argv[],
                                        char* const envp[]);
// same as pi_start_process, except that the started processes stdio file descriptors are replaced
// with the provided. You may set anyone to -1 to not override it.
EXPORT process_handle* pi_start_process2(const char* pathname,
                                         char* const argv[],
                                         char* const envp[],
                                         int fd_stdin,
                                         int fd_stdout,
                                         int fd_stderr);

EXPORT int pi_run_until(process_handle*, addr_t);
EXPORT int pi_run_continue(process_handle*);

EXPORT int pi_find_next_basic_block(process_handle*,
                                    addr_t* next_branch,
                                    uint32_t instruction_mask);

EXPORT int pi_hook_add(process_handle*, addr_t, hook_t, void* user_data);
EXPORT int pi_hook_remove(process_handle*, addr_t);

EXPORT int pi_read_memory(process_handle*, addr_t, uint8_t* memory_out, size_t size);

EXPORT int pi_close_process(process_handle*);

#ifdef __cplusplus
}
#endif
