from angr import Project
from .rop_utils import addr_to_asmstring

class RopMemAccess:
    """Holds information about memory accesses
    Attributes:
        addr_dependencies (set): All the registers that affect the memory address.
        addr_controller (set): All the registers that can determine the symbolic memory access address by itself
        addr_offset (int): Constant offset in the memory address relative to register(s)
        addr_stack_controller (set): all the controlled gadgets on the stack that can determine the address by itself
        data_dependencies (set): All the registers that affect the data written.
        data_controller (set): All the registers that can determine the symbolic data by itself
        addr_constant (int): If the address is a constant it is stored here.
        data_constant (int): If the data is constant it is stored here.
        addr_size (int): Number of bits used for the address.
        data_size (int): Number of bits used for data
    """
    def __init__(self):
        self.addr_dependencies = set()
        self.addr_controllers = set()
        self.addr_offset: int | None = None
        self.addr_stack_controllers = set()
        self.data_dependencies = set()
        self.data_controllers = set()
        self.data_stack_controllers = set()
        self.addr_constant = None
        self.data_constant = None
        self.addr_size = None
        self.data_size = None
        self.op = None

    def is_valid(self):
        """
        the memory access address must be one of
        1. constant
        2. controlled by registers
        3. controlled by controlled stack
        """
        return self.addr_constant or self.addr_controllers or self.addr_stack_controllers

    def is_symbolic_access(self):
        return self.addr_controllable() or bool(self.addr_dependencies)

    def addr_controllable(self):
        return bool(self.addr_controllers or self.addr_stack_controllers)

    def data_controllable(self):
        return bool(self.data_controllers or self.data_stack_controllers)

    def addr_data_independent(self):
        return len(set(self.addr_controllers) & set(self.data_controllers)) == 0 and \
                len(set(self.addr_stack_controllers) & set(self.data_stack_controllers)) == 0

    def __hash__(self):
        to_hash = sorted(self.addr_dependencies) + sorted(self.data_dependencies) + [self.addr_constant] + \
            [self.data_constant] + [self.addr_size] + [self.data_size]
        return hash(tuple(to_hash))

    def __eq__(self, other):
        if type(other) != RopMemAccess:
            return False
        if self.addr_dependencies != other.addr_dependencies or self.data_dependencies != other.data_dependencies:
            return False
        if self.addr_controllers != other.addr_controllers or self.data_controllers != other.data_controllers:
            return False
        if self.addr_constant != other.addr_constant or self.data_constant != other.data_constant:
            return False
        if self.addr_size != other.addr_size or self.data_size != other.data_size:
            return False
        return True

class RopRegMove:
    """
    Holds information about Register moves
    Attributes:
        from_reg (string): register that started with the data
        to_reg (string): register that the data was moved to
        bits (int): number of bits that were moved
    """
    def __init__(self, from_reg, to_reg, bits):
        self.from_reg = from_reg
        self.to_reg = to_reg
        self.bits = bits

    def __hash__(self):
        return hash((self.from_reg, self.to_reg, self.bits))

    def __eq__(self, other):
        if type(other) != RopRegMove:
            return False
        return self.from_reg == other.from_reg and self.to_reg == other.to_reg and self.bits == other.bits

    def __repr__(self):
        return f"RegMove: {self.to_reg} <= {self.from_reg} ({self.bits} bits)"

class RopGadget:
    """
    Gadget objects
    """
    def __init__(self, addr):
        self.project: Project = None # type: ignore
        self.addr = addr
        self.stack_change: int = None # type: ignore

        # register effect information
        self.changed_regs = set()
        self.popped_regs = set()
        # Stores the stack variables that each register depends on.
        # Used to check for cases where two registers are popped from the same location.
        self.popped_reg_vars = {}
        self.concrete_regs = {}
        self.reg_dependencies = {}  # like rax might depend on rbx, rcx
        self.reg_controllers = {}  # like rax might be able to be controlled by rbx (for any value of rcx)
        self.reg_moves = []

        # memory effect information
        self.mem_reads = []
        self.mem_writes = []
        self.mem_changes = []

        # gadget transition
        # we now support the following gadget transitions
        # 1. pop_pc:    ret, jmp [sp+X], pop pc,X,Y, retn), this type of gadgets are "self-contained"
        # 2. jmp_reg:   jmp reg <- requires reg setting before using it (call falls here as well)
        # 3. jmp_mem:   jmp [reg+X] <- requires mem setting before using it (call is here as well)
        self.transit_type: str = None # type: ignore

        self.pc_offset = None # for pop_pc, ret is basically pc_offset == stack_change - arch.bytes
        self.pc_reg = None # for jmp_reg, which register it jumps to
        self.pc_target = None # for jmp_mem, where it jumps to

        # List of basic block addresses for gadgets with conditional branches
        self.bbl_addrs = []
        # Registers that affect path constraints
        self.constraint_regs = set()
        # Instruction count to estimate complexity
        self.isn_count: int = None # type: ignore
        self.has_conditional_branch: bool = None # type: ignore

    @property
    def num_mem_access(self):
        return len(self.mem_reads) + len(self.mem_writes) + len(self.mem_changes)

    def has_symbolic_access(self):
        accesses = set(self.mem_reads + self.mem_writes + self.mem_changes)
        return any(x.is_symbolic_access() for x in accesses)

    def dstr(self):
        return "; ".join(addr_to_asmstring(self.project, addr) for addr in self.bbl_addrs)

    def pp(self):
        print(self.dstr())

    def __str__(self):
        s = "Gadget %#x\n" % self.addr
        s += "Stack change: %#x\n" % self.stack_change
        s += "Changed registers: " + str(self.changed_regs) + "\n"
        s += "Popped registers: " + str(self.popped_regs) + "\n"
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
        out.project = self.project
        out.addr = self.addr
        out.changed_regs = set(self.changed_regs)
        out.popped_regs = set(self.popped_regs)
        out.concrete_regs = dict(self.concrete_regs)
        out.reg_dependencies = dict(self.reg_dependencies)
        out.reg_controllers = dict(self.reg_controllers)
        out.stack_change = self.stack_change
        out.mem_reads = list(self.mem_reads)
        out.mem_changes = list(self.mem_changes)
        out.mem_writes = list(self.mem_writes)
        out.reg_moves = list(self.reg_moves)
        out.transit_type = self.transit_type
        out.pc_reg = self.pc_reg
        return out


class PivotGadget(RopGadget):
    """
    stack pivot gadget, the definition of a PivotGadget is that
    it can arbitrarily control the stack pointer register, and do the pivot exactly once
    TODO: so currently, it cannot directly construct a `pop rbp; leave ret;`
    chain to pivot stack
    """
    def __init__(self, addr):
        super().__init__(addr)
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
        self.makes_syscall = False
        # TODO: starts_with_syscall should be removed, not useful at all
        self.starts_with_syscall = False

    def __str__(self):
        s = f"SyscallGadget {self.addr:#x}\n"
        s += f"  stack change: {self.stack_change:#x}\n"
        s += f"  transit type: {self.transit_type}\n"
        s += f"  can return: {self.can_return}\n"
        s += f"  starts_with_syscall: {self.starts_with_syscall}\n"
        return s

    def __repr__(self):
        return f"<SyscallGadget {self.addr:#x}>"

    @property
    def can_return(self):
        return self.transit_type != 'syscall'

    def copy(self):
        new = super().copy()
        new.makes_syscall = self.makes_syscall
        new.starts_with_syscall = self.starts_with_syscall
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
