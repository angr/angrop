"""
Architecture-dependent configurations
"""

class ROPArch:
    def __init__(self, project, kernel_mode=False):
        self.project = project
        self.kernel_mode = kernel_mode
        self.max_sym_mem_access = 4
        self.alignment = project.arch.instruction_alignment
        self.max_block_size = self.alignment * 8
        self.reg_set = self._get_reg_set()

        a = project.arch
        self.stack_pointer = a.register_names[a.sp_offset]
        self.base_pointer = a.register_names[a.bp_offset]
        self.syscall_insts = None
        self.ret_insts = None

    def _get_reg_set(self):
        """
        get the set of names of general-purpose registers
        """
        arch = self.project.arch
        _sp_reg = arch.register_names[arch.sp_offset]
        _ip_reg = arch.register_names[arch.ip_offset]

        # get list of general-purpose registers
        default_regs = arch.default_symbolic_registers
        # prune the register list of the instruction pointer and the stack pointer
        return {r for r in default_regs if r not in (_sp_reg, _ip_reg)}

    def block_make_sense(self, block):
        return True

class X86(ROPArch):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.max_block_size = 20 # X86 and AMD64 have alignment of 1, 8 bytes is certainly not good enough
        self.syscall_insts = {b"\xcd\x80"} # int 0x80
        self.ret_insts = {b"\xc2", b"\xc3", b"\xca", b"\xcb"}

    def block_make_sense(self, block):
        capstr = str(block.capstone).lower()
        if 'cli' in capstr or 'rex' in capstr:
            return False
        if not self.kernel_mode:
            if "fs:" in capstr or "gs:" in capstr or "iret" in capstr:
                return False
        if block.size < 1 or block.bytes[0] == 0x4f:
            return False
        return True

class AMD64(X86):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.syscall_insts = {b"\x0f\x05"} # syscall

arm_conditional_postfix = ['eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl',
                           'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al']
class ARM(ROPArch):

    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.is_thumb = False # by default, we don't use thumb mode
        self.alignment = self.project.arch.bytes

    def set_thumb(self):
        self.is_thumb = True
        self.alignment = 2

    def set_arm(self):
        self.is_thumb = False
        self.alignment = self.project.arch.bytes

    def block_make_sense(self, block):
        # disable conditional jumps, for now
        # FIXME: we should handle conditional jumps, they are useful
        for insn in block.capstone.insns:
            if insn.insn.mnemonic[-2:] in arm_conditional_postfix:
                return False
        return True
        
class MIPS(ROPArch):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.alignment = self.project.arch.bytes

def get_arch(project, kernel_mode=False):
    name = project.arch.name
    mode = kernel_mode
    if name == 'X86':
        return X86(project, kernel_mode=mode)
    elif name == 'AMD64':
        return AMD64(project, kernel_mode=mode)
    elif name.startswith('ARM'):
        return ARM(project, kernel_mode=mode)
    elif name.startswith('MIPS'):
        return MIPS(project, kernel_mode=mode)
    else:
        raise ValueError(f"Unknown arch: {name}")
