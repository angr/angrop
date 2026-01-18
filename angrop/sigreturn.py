import logging

from .errors import RopException

l = logging.getLogger(__name__)

_REGISTERS = {
    # Reference: https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf
    "amd64": {
        0: "uc_flags",
        8: "&uc",
        16: "uc_stack.ss_sp",
        24: "uc_stack.ss_flags",
        32: "uc_stack.ss_size",
        40: "r8",
        48: "r9",
        56: "r10",
        64: "r11",
        72: "r12",
        80: "r13",
        88: "r14",
        96: "r15",
        104: "rdi",
        112: "rsi",
        120: "rbp",
        128: "rbx",
        136: "rdx",
        144: "rax",
        152: "rcx",
        160: "rsp",
        168: "rip",
        176: "eflags",
        184: "csgsfs",
        192: "err",
        200: "trapno",
        208: "oldmask",
        216: "cr2",
        224: "&fpstate",
        232: "__reserved",
        240: "sigmask",
    },
    # Reference: http://lxr.free-electrons.com/source/arch/x86/include/asm/sigcontext.h?v=2.6.28#L138
    "i386": {
        0: "gs",
        4: "fs",
        8: "es",
        12: "ds",
        16: "edi",
        20: "esi",
        24: "ebp",
        28: "esp",
        32: "ebx",
        36: "edx",
        40: "ecx",
        44: "eax",
        48: "trapno",
        52: "err",
        56: "eip",
        60: "cs",
        64: "eflags",
        68: "esp_at_signal",
        72: "ss",
        76: "fpstate",
    },
}

_DEFAULTS = {
    "amd64": {"csgsfs": 0x33},
    "i386": {"cs": 0x73, "ss": 0x7b},
}

_ARCH_NAME_MAP = {
    "AMD64": "amd64",
    "X86": "i386",
}


def _endness_to_str(endness):
    if endness == "Iend_BE":
        return "big"
    return "little"


class SigreturnFrame:
    """
    SigreturnFrame implementation for different architectures.
    """
    def __init__(self, arch_name, endness):
        if arch_name not in _REGISTERS:
            raise RopException(f"SigreturnFrame does not support arch {arch_name}")
        self.arch_name = arch_name
        self._registers = _REGISTERS[arch_name]
        self._values = {reg: 0 for reg in self._registers.values()}
        self._values.update(_DEFAULTS.get(arch_name, {}))
        self._word_size = 8 if arch_name == "amd64" else 4
        self._byteorder = _endness_to_str(endness)

    @classmethod
    def from_project(cls, project):
        arch_name = _ARCH_NAME_MAP.get(project.arch.name)
        if arch_name is None:
            raise RopException(f"SigreturnFrame does not support arch {project.arch.name}")
        return cls(arch_name, project.arch.memory_endness)

    def set_regvalue(self, reg, value):
        if reg not in self._values:
            raise RopException(f"Unknown sigreturn register: {reg}")
        self._values[reg] = value

    def update(self, **registers):
        for reg, value in registers.items():
            self.set_regvalue(reg, value)

    def to_bytes(self):
        frame = bytearray()
        for offset in sorted(self._registers.keys()):
            reg = self._registers[offset]
            if len(frame) < offset:
                frame.extend(b"\x00" * (offset - len(frame)))
            val = self._values[reg]
            frame.extend(int(val).to_bytes(self._word_size, self._byteorder, signed=False))
        return bytes(frame)

    def to_words(self):
        data = self.to_bytes()
        if len(data) % self._word_size != 0:
            pad = self._word_size - (len(data) % self._word_size)
            data += b"\x00" * pad
        words = []
        for i in range(0, len(data), self._word_size):
            words.append(int.from_bytes(data[i:i + self._word_size], self._byteorder, signed=False))
        return words

    def offset_of(self, reg):
        for offset, name in self._registers.items():
            if name == reg:
                return offset
        raise RopException(f"Unknown sigreturn register: {reg}")

    @property
    def word_size(self):
        return self._word_size
