"""
Architecture-dependent configurations
"""

class ROPArch:
    def __init__(self, project, kernel_mode=False):
        self.project = project
        self.kernel_mode = kernel_mode
        self.max_sym_mem_access = 4
        self.alignment = project.arch.instruction_alignment
        self.reg_set = self._get_reg_set()
        self.max_block_size = None
        self.fast_mode_max_block_size = None

        a = project.arch
        self.stack_pointer = a.register_names[a.sp_offset]
        self.base_pointer = a.register_names[a.bp_offset]
        self.syscall_insts = None
        self.ret_insts = None
        self.execve_num = None

    def _get_reg_set(self):
        """
        get the set of names of general-purpose registers + bp
        because bp is usually considered as general-purpose these days
        """
        arch = self.project.arch
        _sp_reg = arch.register_names[arch.sp_offset]
        _ip_reg = arch.register_names[arch.ip_offset]
        _bp_reg = arch.register_names[arch.bp_offset]

        # get list of general-purpose registers
        default_regs = arch.default_symbolic_registers
        # prune the register list of the instruction pointer and the stack pointer
        return {r for r in default_regs if r not in (_sp_reg, _ip_reg)} | {_bp_reg}

    def block_make_sense(self, block):
        return True

class X86(ROPArch):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.max_block_size = 20
        self.fast_mode_max_block_size = 12
        self.syscall_insts = {b"\xcd\x80"} # int 0x80
        self.ret_insts = {b"\xc2", b"\xc3", b"\xca", b"\xcb"}
        self.segment_regs = {"cs", "ds", "es", "fs", "gs", "ss"}
        self.execve_num = 0xb

    def _x86_block_make_sense(self, block):
        capstr = str(block.capstone).lower()
        # currently, angrop does not handle "repz ret" correctly, we filter it
        if any(x in capstr for x in ('cli', 'rex', 'repz ret')):
            return False
        if not self.kernel_mode:
            if "fs:" in capstr or "gs:" in capstr or "iret" in capstr:
                return False
        if block.size < 1:
            return False
        return True

    def block_make_sense(self, block):
        if not self._x86_block_make_sense(block):
            return False
        for x in block.capstone.insns:
            if x.mnemonic == 'syscall':
                return False
        return True

class AMD64(X86):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.syscall_insts = {b"\x0f\x05"} # syscall
        self.segment_regs = {"cs_seg", "ds_seg", "es_seg", "fs_seg", "gs_seg", "ss_seg"}
        self.execve_num = 0x3b

    def block_make_sense(self, block):
        return self._x86_block_make_sense(block)

arm_conditional_postfix = ['eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl',
                           'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al']
class ARM(ROPArch):

    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.is_thumb = False # by default, we don't use thumb mode
        self.alignment = self.project.arch.bytes
        self.max_block_size = self.alignment * 8
        self.fast_mode_max_block_size = self.alignment * 6
        self.execve_num = 0xb

    def set_thumb(self):
        self.is_thumb = True
        self.alignment = 2
        self.max_block_size = self.alignment * 8
        self.fast_mode_max_block_size = self.alignment * 6

    def set_arm(self):
        self.is_thumb = False
        self.alignment = self.project.arch.bytes
        self.max_block_size = self.alignment * 8
        self.fast_mode_max_block_size = self.alignment * 6

    def block_make_sense(self, block):
        # disable conditional jumps, for now
        # FIXME: we should handle conditional jumps, they are useful
        for insn in block.capstone.insns:
            if insn.insn.mnemonic[-2:] in arm_conditional_postfix:
                return False
        return True

class AARCH64(ROPArch):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.ret_insts = {b'\xc0\x03_\xd6'}
        self.max_block_size = self.alignment * 10
        self.fast_mode_max_block_size = self.alignment * 6
        self.execve_num = 0xdd

class MIPS(ROPArch):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.alignment = self.project.arch.bytes
        self.max_block_size = self.alignment * 8
        self.fast_mode_max_block_size = self.alignment * 6
        self.execve_num = 0xfab

def get_arch(project, kernel_mode=False):
    name = project.arch.name
    mode = kernel_mode
    if name == 'X86':
        return X86(project, kernel_mode=mode)
    elif name == 'AMD64':
        return AMD64(project, kernel_mode=mode)
    elif name.startswith('ARM'):
        return ARM(project, kernel_mode=mode)
    elif name == 'AARCH64':
        return AARCH64(project, kernel_mode=mode)
    elif name.startswith('MIPS'):
        return MIPS(project, kernel_mode=mode)
    else:
        raise ValueError(f"Unknown arch: {name}")
