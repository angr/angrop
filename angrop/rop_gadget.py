class RopMemAccess(object):
    """Holds information about memory accesses
    Attributes:
        addr_dependencies (set): All the registers that affect the memory address.
        data_dependencies (set): All the registers that affect the data written.
        addr_constant (int): If the address is a constant it is stored here.
        data_constant (int): If the data is constant it is stored here.
        addr_size (int): Number of bits used for the address.
        data_size (int): Number of bits used for data
    """
    def __init__(self):
        self.addr_dependencies = set()
        self.addr_controllers = set()
        self.data_dependencies = set()
        self.data_controllers = set()
        self.addr_constant = None
        self.data_constant = None
        self.addr_size = None
        self.data_size = None
        self.op = None

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


class RopRegMove(object):
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


class RopGadget(object):
    def __init__(self, addr):
        self.addr = addr
        self.changed_regs = set()
        self.popped_regs = set()
        self.reg_dependencies = dict()  # like rax might depend on rbx, rcx
        self.reg_controllers = dict()  # like rax might be able to be controlled by rbx (for any value of rcx)
        self.stack_change = None
        self.mem_reads = []
        self.mem_writes = []
        self.mem_changes = []
        self.reg_moves = []
        self.bp_moves_to_sp = None
        self.block_length = None
        self.makes_syscall = False
        self.starts_with_syscall = False

    def __str__(self):
        s = "Gadget %#x\n" % self.addr
        if self.bp_moves_to_sp:
            s += "Stack change: bp + %#x\n" % self.stack_change
        else:
            s += "Stack change: %#x\n" % self.stack_change
        s += "Changed registers: " + str(self.changed_regs) + "\n"
        s += "Popped registers: " + str(self.popped_regs) + "\n"
        for move in self.reg_moves:
            s += "Register move: [%s to %s, %d bits]\n" % (move.from_reg, move.to_reg, move.bits)
        s += "Register dependencies:\n"
        for reg in self.reg_dependencies:
            controllers = self.reg_controllers.get(reg, list())
            dependencies = [x for x in self.reg_dependencies[reg] if x not in controllers]
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
        if self.makes_syscall:
            s += "Makes a syscall\n"
        return s

    def __repr__(self):
        return "<Gadget %#x>" % self.addr

    def copy(self):
        out = RopGadget(self.addr)
        out.addr = self.addr
        out.changed_regs = set(self.changed_regs)
        out.popped_regs = set(self.popped_regs)
        out.reg_dependencies = dict(self.reg_dependencies)
        out.reg_controllers = dict(self.reg_controllers)
        out.stack_change = self.stack_change
        out.mem_reads = list(self.mem_reads)
        out.mem_changes = list(self.mem_changes)
        out.mem_writes = list(self.mem_writes)
        out.reg_moves = list(self.reg_moves)
        out.bp_moves_to_sp = self.bp_moves_to_sp
        out.block_length = self.block_length
        out.makes_syscall = self.makes_syscall
        out.starts_with_syscall = self.starts_with_syscall
        return out


class StackPivot(object):
    def __init__(self, addr):
        self.addr = addr
        self.sp_from_reg = None
        self.sp_popped_offset = None

    def __str__(self):
        s = "Pivot %#x\n" % self.addr
        if self.sp_from_reg is not None:
            s += "sp from reg: %s\n" % self.sp_from_reg
        elif self.sp_popped_offset is not None:
            s += "sp popped at %#x\n" % self.sp_popped_offset
        return s

    def __repr__(self):
        return "<Pivot %#x>" % self.addr
