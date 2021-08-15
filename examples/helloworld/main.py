import os
import ctypes

import ptrace_inst.libwrap as lib

def simple_status_printing_hook(proc: lib.Process, addr: int, user_regs: lib.UserRegsStructRef, _user_data) -> int:
    print(f"[+] Hit instrumentation at {hex(addr)} in process {proc.pid}")
    print(f"\trax = {hex(user_regs.contents.rax)}")
    instr = proc.read_memory(addr, 8).hex(" ")
    print(f"\tcurrent instruction = {instr}")

    return 0


if __name__ == '__main__':
    exe = os.path.join(os.path.dirname(__file__), "helloworld")

    args = [exe]
    proc = lib.Process()

    proc.start_process(exe, args, [])
    print(f"[+] Started process {exe} with pid {proc.pid} and rip @ {hex(proc.rip)}")

    main_addr = 0x401130
    proc.run_until(main_addr)
    print(f"[+] Hit initial breakpoint in main @ {hex(proc.rip)}")

    main_ret = 0x401174

    bbs = set()

    while proc.rip != main_ret:
        bb = proc.find_next_basic_block(lib.BranchInstruction.BI_JUMP | lib.BranchInstruction.BI_RET)
        print(f"[+] Current basic block : {hex(proc.rip)} - {hex(bb)}")
        if bb not in bbs:
            bbs.add(bb)
            proc.hook_add(bb, simple_status_printing_hook, ctypes.c_void_p())

        proc.run_until(bb)

    proc.run_continue()
    proc.close_process()
