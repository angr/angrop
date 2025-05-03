from angr import Project
from .rop_utils import addr_to_asmstring
from .rop_effect import RopEffect

class RopGadget(RopEffect):
    """
    Gadget objects
    """
    def __init__(self, addr):
        super().__init__()
        self.project: Project = None # type: ignore
        self.addr = addr

        # gadget transition
        # we now support the following gadget transitions
        # 1. pop_pc:    ret, jmp [sp+X], pop pc,X,Y, retn), this type of gadgets are "self-contained"
        # 2. jmp_reg:   jmp reg <- requires reg setting before using it (call falls here as well)
        # 3. jmp_mem:   jmp [reg+X] <- requires mem setting before using it (call falls here as well)
        self.transit_type: str = None # type: ignore

        self.pc_offset = None # for pop_pc, ret is basically pc_offset == stack_change - arch.bytes
        self.pc_reg = None # for jmp_reg, which register it jumps to
        self.pc_target = None # for jmp_mem, where it jumps to

    @property
    def self_contained(self):
        """
        the gadget is useable by itself, doesn't rely on the existence of other gadgets
        e.g. 'jmp_reg' gadgets requires another one setting the registers
        (a gadget like mov rax, [rsp]; add rsp, 8; jmp rax will be considered pop_pc)
        """
        return (not self.has_conditional_branch) and self.transit_type == 'pop_pc' and not self.oop

    def dstr(self):
        return "; ".join(addr_to_asmstring(self.project, addr) for addr in self.bbl_addrs)

    def pp(self):
        print(self.dstr())

    def __str__(self):
        s = "Gadget %#x\n" % self.addr
        s += "Stack change: %#x\n" % self.stack_change
        s += "Changed registers: " + str(self.changed_regs) + "\n"
        s += "Popped registers: " + str(self.reg_pops) + "\n"
        for move in self.reg_moves:
            s += "Register move: [%s to %s, %d bits]\n" % (move.from_reg, move.to_reg, move.bits)
        s += "Register dependencies:\n"
        for reg, deps in self.reg_dependencies.items():
            controllers = self.reg_controllers.get(reg, [])
            dependencies = [x for x in deps if x not in controllers]
            s += "    " + reg + ": [" + " ".join(controllers) + " (" + " ".join(dependencies) + ")]" + "\n"
        for mem_access in self.mem_changes:
            if mem_access.op == "__add__":
                s += "Memory add:\n"
            elif mem_access.op == "__sub__":
                s += "Memory subtract:\n"
            elif mem_access.op == "__or__":
                s += "Memory or:\n"
            elif mem_access.op == "__and__":
                s += "Memory and:\n"
            else:
                s += "Memory change:\n"
            if mem_access.addr_constant is None:
                s += "    " + "address (%d bits) depends on: " % mem_access.addr_size
                s += str(list(mem_access.addr_dependencies)) + "\n"
            else:
                s += "    " + "address (%d bits): %#x\n" % (mem_access.addr_size, mem_access.addr_constant)
            s += "    " + "data (%d bits) depends on: " % mem_access.data_size
            s += str(list(mem_access.data_dependencies)) + "\n"
        for mem_access in self.mem_writes:
            s += "Memory write:\n"
            if mem_access.addr_constant is None:
                s += "    " + "address (%d bits) depends on: " % mem_access.addr_size
                s += str(list(mem_access.addr_dependencies)) + "\n"
            else:
                s += "    " + "address (%d bits): %#x\n" % (mem_access.addr_size, mem_access.addr_constant)
            if mem_access.data_constant is None:
                s += "    " + "data (%d bits) depends on: " % mem_access.data_size
                s += str(list(mem_access.data_dependencies)) + "\n"
            else:
                s += "    " + "data (%d bits): %#x\n" % (mem_access.data_size, mem_access.data_constant)
        for mem_access in self.mem_reads:
            s += "Memory read:\n"
            if mem_access.addr_constant is None:
                s += "    " + "address (%d bits) depends on: " % mem_access.addr_size
                s += str(list(mem_access.addr_dependencies)) + "\n"
            else:
                s += "    " + "address (%d bits): %#x" % (mem_access.addr_size, mem_access.addr_constant)
            s += "    " + "data (%d bits) stored in regs:" % mem_access.data_size
            s += str(list(mem_access.data_dependencies)) + "\n"
        return s

    def __repr__(self):
        return "<Gadget %#x>" % self.addr

    def copy(self):
        out = self.__class__(self.addr)
        self.copy_effect(out)
        out.project = self.project
        out.addr = self.addr
        out.transit_type = self.transit_type
        out.pc_offset = self.pc_offset
        out.pc_reg = self.pc_reg
        out.pc_target = self.pc_rtarget
        out.branch_dependencies = set(self.branch_dependencies)
        out.has_conditional_branch = self.has_conditional_branch
        return out

    def __getstate__(self):
        state = self.__dict__.copy()
        state['project'] = None
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)

class PivotGadget(RopGadget):
    """
    stack pivot gadget, the definition of a PivotGadget is that
    it can arbitrarily control the stack pointer register, and do the pivot exactly once
    """
    def __init__(self, addr):
        super().__init__(addr)
        self.stack_change_before_pivot = None
        self.stack_change_after_pivot = None
        # TODO: sp_controllers can be registers, payload on stack, and symbolic read data
        # but we do not handle symbolic read data, yet
        self.sp_reg_controllers = set()
        self.sp_stack_controllers = set()

    def __str__(self):
        s = f"PivotGadget {self.addr:#x}\n"
        s += f"  sp_controllers: {self.sp_controllers}\n"
        s += f"  stack change: {self.stack_change:#x}\n"
        s += f"  stack change after pivot: {self.stack_change_after_pivot:#x}\n"
        return s

    @property
    def sp_controllers(self):
        s = self.sp_reg_controllers.copy()
        return s.union(self.sp_stack_controllers)

    def __repr__(self):
        return f"<PivotGadget {self.addr:#x}>"

    def copy(self):

        new = super().copy()
        new.stack_change_after_pivot = self.stack_change_after_pivot
        new.sp_reg_controllers = set(self.sp_reg_controllers)
        new.sp_stack_controllers = set(self.sp_stack_controllers)
        return new

class SyscallGadget(RopGadget):
    """
    we collect two types of syscall gadgets:
    1. with return: syscall; ret
    2. without return: syscall; xxxx
    """
    def __init__(self, addr):
        super().__init__(addr)
        self.prologue: RopGadget = None # type: ignore

    def __str__(self):
        s = f"SyscallGadget {self.addr:#x}\n"
        s += f"  stack change: {self.stack_change:#x}\n"
        s += f"  can return: {self.can_return}\n"
        return s

    def __repr__(self):
        return f"<SyscallGadget {self.addr:#x}>"

    @property
    def can_return(self):
        return self.transit_type is not None

    def copy(self):
        new = super().copy()
        new.prologue = self.prologue
        return new

class FunctionGadget(RopGadget):
    """
    a function call
    """
    def __init__(self, addr, symbol):
        super().__init__(addr)
        self.symbol = symbol

    def dstr(self):
        if self.symbol:
            return f"<{self.symbol}>"
        return f"<func_{self.addr:#x}>"
