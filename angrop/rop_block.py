from .rop_chain import RopChain
from .rop_value import RopValue
from . import rop_utils

class RopBlock(RopChain):
    """
    A mini-chain that satisfies the following conditions:
    1. positive stack_change
    2. no accesses outside the stack_change
    3. no conditional branches: the flag should be set so the execution flow is determined
    4. self-contained, in the sense that it does not require extra gadgets to maintain
       the contain-flow
    """

    gadget_analyzer = None
    sim_state = None

    def __init__(self, project, builder, state=None, badbytes=None):
        super().__init__(project, builder, state=state, badbytes=badbytes)

        self.stack_change = None

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

        self.isn_count: int = None # type: ignore

        if self.gadget_analyzer is None:
            self.__class__.gadget_analyzer = GadgetAnalyzer(project, True, kernel_mode=False, arch=builder.arch)

    @staticmethod
    def new_sim_state(builder):
        if RopBlock.sim_state:
            return RopBlock.sim_state.copy()
        arch = builder.arch
        project = builder.project
        state = rop_utils.make_symbolic_state(
            builder.project,
            arch.reg_set
        )
        rop_utils.make_reg_symbolic(state, arch.base_pointer)
        RopBlock.sim_state = state
        return state.copy()

    @property
    def num_mem_access(self):
        return len(self.mem_reads) + len(self.mem_writes) + len(self.mem_changes)

    def _chain_block(self, other):
        assert type(other) is RopBlock
        res = super().__add__(other)
        return res

    def __add__(self, other):
        res = self._chain_block(other)
        self._analyze_effect(res)
        return res

    @staticmethod
    def _analyze_effect(rb):
        init_state, final_state = rb.sim_exec()

        ga = RopBlock.gadget_analyzer

        # stack change
        ga._compute_sp_change(init_state, final_state, rb)

        # reg effect
        ga._check_reg_changes(final_state, init_state, rb)
        reg_reads = ga._get_reg_reads(final_state)
        ga._check_reg_change_dependencies(init_state, final_state, rb)
        ga._check_reg_movers(init_state, final_state, reg_reads, rb)

        # mem effect
        ga._check_reg_change_dependencies(init_state, final_state, rb)
        ga._check_reg_movers(init_state, final_state, reg_reads, rb)
        ga._analyze_concrete_regs(init_state, final_state, rb)
        ga._analyze_mem_access(final_state, init_state, rb)

        rb.bbl_addrs = list(final_state.history.bbl_addrs)
        project = init_state.project
        rb.isn_count = sum(project.factory.block(addr).instructions for addr in rb.bbl_addrs)

    def sim_exec(self):
        project = self._p
        # this is different RopChain.exec because the execution needs to be symbolic
        state = self._blank_state.copy()
        for idx, val in enumerate(self._values):
            offset = idx*project.arch.bytes
            state.memory.store(state.regs.sp+offset, val.data, project.arch.bytes, endness=project.arch.memory_endness)

        state.ip = state.stack_pop()

        simgr = self._p.factory.simgr(state, save_unconstrained=True)
        while simgr.active:
            simgr.step()
            assert len(simgr.active + simgr.unconstrained) == 1
        final_state = simgr.unconstrained[0]
        return state, final_state

    def import_gadget_effect(self, gadget):
        self.stack_change = gadget.stack_change
        self.changed_regs = gadget.changed_regs
        self.popped_regs = gadget.popped_regs
        self.popped_reg_vars = gadget.popped_reg_vars
        self.concrete_regs = gadget.concrete_regs
        self.reg_dependencies = gadget.reg_dependencies
        self.reg_controllers = gadget.reg_controllers
        self.reg_moves = gadget.reg_moves
        self.mem_reads = gadget.mem_reads
        self.mem_writes = gadget.mem_writes
        self.mem_changes = gadget.mem_changes
        self.isn_count = gadget.isn_count

    @staticmethod
    def from_gadget(gadget, builder):
        assert gadget.stack_change > 0
        assert not gadget.has_conditional_branch
        assert gadget.transit_type == 'pop_pc'

        # build the block(chain) state first
        project = builder.project
        bytes_per_pop = project.arch.bytes
        state = RopBlock.new_sim_state(builder)
        next_pc_val = rop_utils.cast_rop_value(
            state.solver.BVS("next_pc", project.arch.bits),
            project,
        )
        state.memory.store(state.regs.sp + gadget.pc_offset, next_pc_val.ast, endness=project.arch.memory_endness)
        state.stack_pop()
        state.ip = gadget.addr

        # now build the block(chain)
        rb = RopBlock(project, builder, state=state, badbytes=builder.badbytes)
        rb.import_gadget_effect(gadget)

        # fill in values and gadgets
        value = RopValue(gadget.addr, project)
        value.rebase_analysis(chain=rb)
        rb.add_value(value)
        for offset in range(0, gadget.stack_change, bytes_per_pop):
            sym_word = state.stack_read(offset, bytes_per_pop)
            sym_val = rop_utils.cast_rop_value(sym_word, project)
            if offset != gadget.pc_offset:
                rb.add_value(sym_val)
            else:
                rb.add_value(next_pc_val)

        rb.set_gadgets([gadget])
        return rb

    @staticmethod
    def from_gadget_list(gs, builder):
        assert gs
        rb = RopBlock.from_gadget(gs[0], builder)
        for g in gs[1:]:
            rb = rb._chain_block(RopBlock.from_gadget(g, builder))
        RopBlock._analyze_effect(rb)
        return rb

    def has_symbolic_access(self):
        accesses = set(self.mem_reads + self.mem_writes + self.mem_changes)
        return any(x.is_symbolic_access() for x in accesses)

    def copy(self):
        cp = super().copy()
        cp.changed_regs = set(self.changed_regs)
        cp.popped_regs = set(self.popped_regs)
        cp.popped_reg_vars = dict(self.popped_reg_vars)
        cp.concrete_regs = dict(self.concrete_regs)
        cp.reg_dependencies = dict(self.reg_dependencies)
        cp.reg_controllers = dict(self.reg_controllers)
        cp.stack_change = self.stack_change
        cp.reg_moves = list(self.reg_moves)
        cp.mem_reads = list(self.mem_reads)
        cp.mem_writes = list(self.mem_writes)
        cp.mem_changes = list(self.mem_changes)
        cp.isn_count = self.isn_count
        return cp

from .gadget_finder.gadget_analyzer import GadgetAnalyzer