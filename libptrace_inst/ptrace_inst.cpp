#include "ptrace_inst.h"

process_handle* pi_start_process(const char* pathname, char* const argv[], char* const envp[]) {
    process_handle* h = nullptr;
    if (start_process(pathname, argv, envp, h)) {
        pi_close_process(h);
        return NULL;
    } else {
        return h;
    }
}

int pi_run_until(process_handle* h, addr_t addr) { return h->process->run_until(addr); }
int pi_run_continue(process_handle* h) { return h->process->run_continue(); }

int pi_find_next_basic_block(process_handle* h, addr_t* next_branch, uint32_t instruction_mask) {
    return h->process->find_next_basic_block(next_branch, instruction_mask);
}

int pi_hook_add(process_handle* h, addr_t addr, hook_t hook, void* user_data) {
    return h->process->hook_add(addr, hook, user_data);
}
int pi_hook_remove(process_handle* h, addr_t addr) { return h->process->hook_remove(addr); }

int pi_read_memory(process_handle* h, addr_t addr, uint8_t* memory_out, size_t size) {
    return h->process->read_memory(addr, memory_out, size);
}

int pi_close_process(process_handle* h) {
    if (h == nullptr) {
        return 0;
    }

    if (h->process != nullptr) {
        delete h->process;
        h->process = nullptr;
    }

    delete h;

    return 0;
}
