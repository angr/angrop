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
        self.stack_offset = None # addr_constant - init_sp
        self.data_constant = None
        self.addr_size = None
        self.data_size = None
        self.out_of_patch = False
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

    def __lt__(self, other):
        if type(other) != RopRegMove:
            return False
        t1 = (self.from_reg, self.to_reg, self.bits)
        t2 = (other.from_reg, other.to_reg, other.bits)
        return t1 < t2

    def __repr__(self):
        return f"RegMove: {self.to_reg} <= {self.from_reg} ({self.bits} bits)"

class RopRegPop:
    def __init__(self, reg, bits):
        assert type(reg) is str
        self.reg = reg
        self.bits = bits

    def __hash__(self):
        return hash((self.reg, self.bits))

    def __eq__(self, other):
        if type(other) != RopRegPop:
            return False
        return self.reg == other.reg and self.bits == other.bits

    def __repr__(self):
        return f"<RegPop {self.reg}-{self.bits}bits>"

class RopEffect:
    def __init__(self):

        self.stack_change: int = None # type: ignore

        # register effect information
        self.changed_regs = set()
        # Stores the stack variables that each register depends on.
        # Used to check for cases where two registers are popped from the same location.
        self.concrete_regs = {}
        self.reg_dependencies = {}  # like rax might depend on rbx, rcx
        self.reg_controllers = {}  # like rax might be able to be controlled by rbx (for any value of rcx)
        self.reg_pops = set()
        self.reg_moves = []

        # memory effect information
        self.mem_reads = []
        self.mem_writes = []
        self.mem_changes = []

        # List of basic block addresses for gadgets with conditional branches
        self.bbl_addrs = []
        # Instruction count to estimate complexity
        self.isn_count: int = None # type: ignore

        self.pop_equal_set = set() # like pop rax; mov rbx, rax; they must be the same

        # Registers that affect path constraints
        self.branch_dependencies = set()
        self.has_conditional_branch: bool = None # type: ignore

    @property
    def oop(self):
        """
        whether the gadget contains out of patch access
        """
        return any(m.out_of_patch  for m in self.mem_reads + self.mem_writes + self.mem_changes)

    def has_symbolic_access(self):
        return self.num_sym_mem_access > 0

    @property
    def max_stack_offset(self):
        project = getattr(self, "project", None)
        if project is None:
            project = getattr(self, "_p", None)
        res = self.stack_change - project.arch.bytes
        for m in self.mem_reads + self.mem_writes + self.mem_changes:
            if m.out_of_patch and m.stack_offset > res:
                res = m.stack_offset
        return res

    @property
    def num_sym_mem_access(self):
        """
        by definition, jmp_mem gadgets have one symbolic memory access, which is its PC
        we take into account that
        """
        accesses = self.mem_reads + self.mem_writes + self.mem_changes
        res = len([x for x in accesses if x.is_symbolic_access()])
        if hasattr(self, "transit_type") and self.transit_type == 'jmp_mem' and self.pc_target.symbolic:
            assert res > 0
            res -= 1
        return res

    @property
    def popped_regs(self):
        return {x.reg for x in self.reg_pops}

    def get_pop(self, reg):
        for x in self.reg_pops:
            if x.reg == reg:
                return x
        return None

    def clear_effect(self):
        RopEffect.__init__(self)

    def import_effect(self, gadget):
        gadget.copy_effect(self)

    def copy_effect(self, cp):
        cp.stack_change = self.stack_change
        cp.changed_regs = set(self.changed_regs)
        cp.reg_pops = set(self.reg_pops)
        cp.concrete_regs = dict(self.concrete_regs)
        cp.reg_dependencies = dict(self.reg_dependencies)
        cp.reg_controllers = dict(self.reg_controllers)
        cp.reg_moves = list(self.reg_moves)
        cp.mem_reads = list(self.mem_reads)
        cp.mem_writes = list(self.mem_writes)
        cp.mem_changes = list(self.mem_changes)
        cp.bbl_addrs = list(self.bbl_addrs)
        cp.isn_count = self.isn_count
        return cp