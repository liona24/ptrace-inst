import os
import ctypes
from typing import Callable, Any, Type

SHARED_LIB_PATH = os.path.join(os.path.dirname(__file__), "..", "build", "libptrace_inst.so")
LIB = ctypes.cdll.LoadLibrary(SHARED_LIB_PATH)

class _ProcessHandle(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_int),
        ("rip", ctypes.c_uint64),
        ("_process", ctypes.c_void_p),
    ]

class UserRegsStruct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

UserRegsStructRef = ctypes.POINTER(UserRegsStruct)


_start_process = LIB.pi_start_process
_start_process.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.POINTER(ctypes.c_char_p),
]
_start_process.restype = ctypes.POINTER(_ProcessHandle)

_run_until = LIB.pi_run_until
_run_until.argtypes = [
    ctypes.POINTER(_ProcessHandle),
    ctypes.c_uint64
]
_run_until.restype = ctypes.c_int

_run_continue = LIB.pi_run_continue
_run_continue.argtypes = [
    ctypes.POINTER(_ProcessHandle),
]
_run_continue.restype = ctypes.c_int

_find_next_basic_block = LIB.pi_find_next_basic_block
_find_next_basic_block.argtypes = [
    ctypes.POINTER(_ProcessHandle),
    ctypes.POINTER(ctypes.c_uint64),
]
_find_next_basic_block.restype = ctypes.c_int

HOOK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(_ProcessHandle), ctypes.c_uint64, UserRegsStructRef, ctypes.c_void_p)
_hook_add = LIB.pi_hook_add
_hook_add.argtypes = [
    ctypes.POINTER(_ProcessHandle),
    ctypes.c_uint64,
    HOOK,
    ctypes.c_void_p
]
_hook_add.restype = ctypes.c_int

_hook_remove = LIB.pi_hook_remove
_hook_remove.argtypes = [
    ctypes.POINTER(_ProcessHandle),
    ctypes.c_uint64
]
_hook_remove.restype = ctypes.c_int


_read_memory = LIB.pi_read_memory
_read_memory.argtypes = [
    ctypes.POINTER(_ProcessHandle),
    ctypes.c_uint64,
    ctypes.c_void_p,
    ctypes.c_size_t
]
_read_memory.restype = ctypes.c_int


_close_process = LIB.pi_close_process
_close_process.argtypes = [
    ctypes.POINTER(_ProcessHandle),
]
_close_process.restype = ctypes.c_int


class Process():
    def __init__(self):
        self._handle = None
        self._hooks = {}

    @property
    def rip(self):
        return self._handle.contents.rip

    @property
    def pid(self):
        return self._handle.contents.pid

    def _check(self, code: int):
        if code != 0:
            raise RuntimeError(f"Return value {code} != 0!")

    def _wrap_hook(self, hook: Callable[["Process", int, UserRegsStructRef, Any], int], user_data_type: Type):

        @HOOK
        def wrapper(_handle, addr, regs, data):
            return hook(self, addr, regs, ctypes.cast(data, user_data_type))

        return wrapper

    def start_process(self, pathname: str, argv: list[str], envp: list[str]):
        c_argv = (ctypes.c_char_p * (len(argv) + 1))()
        c_argv[:-1] = list(map(str.encode, argv))
        c_argv[-1] = None

        c_envp = (ctypes.c_char_p * (len(envp) + 1))()
        c_envp[:-1] = list(map(str.encode, envp))
        c_envp[-1] = None

        pathname = pathname.encode()

        rv = _start_process(pathname, c_argv, c_envp)
        if rv is None:
            raise RuntimeError("Could not start process: " + pathname)

        self._handle = rv

    def run_until(self, addr: int):
        self._check(_run_until(self._handle, addr))

    def run_continue(self):
        self._check(_run_continue(self._handle))

    def find_next_basic_block(self) -> int:
        bb = ctypes.c_uint64()
        self._check(_find_next_basic_block(self._handle, ctypes.byref(bb)))
        return bb.value

    def hook_add(self, addr: int, hook: Callable[["Process", int, UserRegsStructRef, Any], int], user_data: Any):
        self._hooks[addr] = self._wrap_hook(hook, type(user_data))

        self._check(_hook_add(self._handle, addr, self._hooks[addr], ctypes.byref(user_data)))

    def hook_remove(self, addr: int):
        self._check(_hook_remove(self._handle, addr))

        del self._hooks[addr]

    def read_memory(self, addr: int, size: int) -> bytes:
        if size % ctypes.sizeof(ctypes.c_size_t) != 0:
            raise ValueError(f"Sorry, size needs to be aligned to {ctypes.sizeof(ctypes.c_size_t)} bytes")

        buf = ctypes.create_string_buffer(size)

        self._check(_read_memory(self._handle, addr, buf, size))
        return buf.raw

    def close_process(self):
        self._check(_close_process(self._handle))

        self._handle = None
        self._hooks.clear()
