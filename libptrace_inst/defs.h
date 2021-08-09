#pragma once

#include <cstdint>
#include <sys/types.h>
#include <sys/user.h>

struct process_handle;

typedef uint64_t addr_t;
typedef int (*hook_t)(const process_handle*,
                      addr_t,
                      const struct user_regs_struct*,
                      void* user_data);
