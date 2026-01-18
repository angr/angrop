import logging
from typing import Literal

from .errors import RopException

l = logging.getLogger(__name__)

_REGISTERS = {
    # Reference : http://lxr.free-electrons.com/source/arch/x86/include/asm/sigcontext.h?v=2.6.28#L138
        'i386' : {0: 'gs', 4: 'fs', 8: 'es', 12: 'ds', 16: 'edi', 20: 'esi', 24: 'ebp', 28: 'esp',
                  32: 'ebx', 36: 'edx', 40: 'ecx', 44: 'eax', 48: 'trapno', 52: 'err', 56: 'eip',
                  60: 'cs', 64: 'eflags', 68: 'esp_at_signal', 72: 'ss', 76: 'fpstate'},
# Reference : https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf
        'amd64': {0: 'uc_flags', 8: '&uc', 16: 'uc_stack.ss_sp', 24: 'uc_stack.ss_flags',
                  32: 'uc_stack.ss_size', 40: 'r8', 48: 'r9', 56: 'r10', 64: 'r11', 72: 'r12',
                  80: 'r13', 88: 'r14', 96: 'r15', 104: 'rdi', 112: 'rsi', 120: 'rbp', 128: 'rbx',
                  136: 'rdx', 144: 'rax', 152: 'rcx', 160: 'rsp', 168: 'rip', 176: 'eflags',
                  184: 'csgsfs', 192: 'err', 200: 'trapno', 208: 'oldmask', 216: 'cr2',
                  224: '&fpstate', 232: '__reserved', 240: 'sigmask'},
# Reference : http://lxr.free-electrons.com/source/arch/arm/include/uapi/asm/sigcontext.h#L15
        'arm' : {0: 'uc_flags', 4: 'uc_link', 8: 'uc_stack.ss_sp', 12: 'uc_stack.ss_flags',
                 16: 'uc_stack.ss_size', 20: 'trap_no', 24: 'error_code', 28: 'oldmask', 32: 'r0',
                 36: 'r1', 40: 'r2', 44: 'r3', 48: 'r4', 52: 'r5', 56: 'r6', 60: 'r7', 64: 'r8',
                 68: 'r9', 72: 'r10', 76: 'fp', 80: 'ip', 84: 'sp', 88: 'lr', 92: 'pc', 96: 'cpsr',
                 100: 'fault_address', 104: 'uc_sigmask', 108: '__unused', 112: 'uc_regspace',
                 232: 'VFPU-magic', 236: 'VFPU-size'},
# Reference : http://lxr.free-electrons.com/source/arch/mips/include/uapi/asm/sigcontext.h#L15
        'mips': {0: 'sf_ass0', 4: 'sf_ass1', 8: 'sf_ass2', 12: 'sf_ass3', 16: 'sf_ass4', 20: 'sf_pad0',
                 24: 'sf_pad1', 28: 'sc_regmask', 32: 'sc_status', 36: 'pc', 44: 'padding', 52: 'at', 60: 'v0',
                 68: 'v1', 76: 'a0', 84: 'a1', 92: 'a2', 100: 'a3', 108: 't0', 116: 't1', 124: 't2',
                 132: 't3', 140: 't4', 148: 't5', 156: 't6', 164: 't7', 172: 's0', 180: 's1', 188: 's2',
                 196: 's3', 204: 's4', 212: 's5', 220: 's6', 228: 's7', 236: 't8', 244: 't9', 252: 'k0',
                 260: 'k1', 268: 'gp', 276: 'sp', 284: 's8', 292: 'ra'},
        'mipsel': {0: 'sf_ass0', 4: 'sf_ass1', 8: 'sf_ass2', 12: 'sf_ass3', 16: 'sf_ass4', 20: 'sc_regmask',
                   24: 'sc_status', 32: 'pc', 40: 'padding', 48: 'at', 56: 'v0', 64: 'v1', 72: 'a0',
                   80: 'a1', 88: 'a2', 96: 'a3', 104: 't0', 112: 't1', 120: 't2', 128: 't3', 136: 't4',
                   144: 't5', 152: 't6', 160: 't7', 168: 's0', 176: 's1', 184: 's2', 192: 's3', 200: 's4',
                   208: 's5', 216: 's6', 224: 's7', 232: 't8', 240: 't9', 248: 'k0', 256: 'k1', 264: 'gp',
                   272: 'sp', 280: 's8', 288: 'ra'},
        'aarch64': {312: 'x0', 320: 'x1', 328: 'x2', 336: 'x3',
                    344: 'x4',  352: 'x5', 360: 'x6', 368: 'x7',
                    376: 'x8', 384: 'x9', 392: 'x10', 400: 'x11',
                    408: 'x12', 416: 'x13', 424: 'x14', 432: 'x15',
                    440: 'x16', 448: 'x17', 456: 'x18', 464: 'x19',
                    472: 'x20', 480: 'x21', 488: 'x22', 496: 'x23',
                    504: 'x24', 512: 'x25', 520: 'x26', 528: 'x27',
                    536: 'x28', 544: 'x29', 552: 'x30', 560: 'sp',
                    568: 'pc', 592: 'magic'}
}
# TODO: default values are right?
_DEFAULTS = {
    "amd64": {"csgsfs": 0x33},
    "i386": {"cs": 0x73, "ss": 0x7b},
    "i386_on_amd64": {"cs": 0x23, "ss": 0x2b},
    "arm": {"trap_no": 0x6, "cpsr": 0x40000010, "VFPU-magic": 0x56465001, "VFPU-size": 0x120},
    "mips": {},
    "aarch64": {"magic": 0x0000021046508001},
}

_ARCH_NAME_MAP = {
    "AMD64": "amd64",
    "X86": "i386",
    "ARMEL": "arm",
    "MIPS32": "mips",
    "MIPSEL": "mipsel",
    "AARCH64": "aarch64",
}


def _endness_to_str(endness) -> Literal["little", "big"]:
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
        self._byteorder: Literal["little", "big"] = _endness_to_str(endness)

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
