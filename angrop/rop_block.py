import logging
from collections import defaultdict

from .rop_chain import RopChain
from .rop_value import RopValue
from .rop_gadget import RopGadget
from .rop_effect import RopEffect
from .errors import RopException
from . import rop_utils

l = logging.getLogger(__name__)

class RopBlock(RopChain, RopEffect):
    """
    A mini-chain that satisfies the following conditions:
    1. positive stack_change
    2. no accesses outside the stack_change
    3. no conditional branches: the flag should be set so the execution flow is determined
    4. self-contained, in the sense that it does not require extra gadgets to maintain
       the contain-flow
    """

    def __init__(self, project, builder, state=None, badbytes=None):
        RopChain.__init__(self, project, builder, state=state, badbytes=badbytes)
        RopEffect.__init__(self)

    def _chain_block(self, other):
        assert type(other) is RopBlock
        res = super().__add__(other)
        return res

    def __add__(self, other):
        res = self._chain_block(other)
        res._analyze_effect()
        return res

    def _analyze_effect(self):
        rb = self
        init_state, final_state = rb.sim_exec()

        ga = self._builder._gadget_analyzer

        # clear the effects
        rb.clear_effect()

        # stack change
        ga._compute_sp_change(init_state, final_state, rb)

        # reg effect
        ga._check_reg_changes(final_state, init_state, rb)
        ga._check_reg_change_dependencies(init_state, final_state, rb)
        ga._check_reg_movers(init_state, final_state, rb)
        ga._check_pop_equal_set(rb, final_state)

        # mem effect
        ga._analyze_concrete_regs(final_state, rb)
        ga._analyze_mem_access(final_state, init_state, rb)

        rb.bbl_addrs = list(final_state.history.bbl_addrs)
        project = init_state.project
        rb.isn_count = sum(project.factory.block(addr).instructions for addr in rb.bbl_addrs)

        # conditional branch analysis
        ga._cond_branch_analysis(rb, final_state)
        if rb.branch_dependencies:
            raise RopException("RopBlock should not have conditional branches")

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
            if len(simgr.active + simgr.unconstrained) != 1:
                l.warning("fail to sim_exec:\n%s", self.dstr())
                raise RopException("fail to sim_exec")
        final_state = simgr.unconstrained[0]
        return state, final_state

    @staticmethod
    def from_gadget(gadget, builder):
        assert isinstance(gadget, RopGadget)
        assert gadget.stack_change > 0
        assert not gadget.has_conditional_branch
        assert gadget.transit_type == 'pop_pc'

        # build the block(chain) state first
        project = builder.project
        bytes_per_pop = project.arch.bytes
        state = rop_utils.make_symbolic_state(
                                builder.project,
                                builder.arch.reg_list,
                                gadget.stack_change//bytes_per_pop)
        next_pc_val = rop_utils.cast_rop_value(
            state.solver.BVS("next_pc", project.arch.bits),
            project,
        )
        state.memory.store(state.regs.sp + gadget.pc_offset + bytes_per_pop, next_pc_val.ast,
                           endness=project.arch.memory_endness)
        state.stack_pop()
        state.ip = gadget.addr

        # now build the block(chain)
        rb = RopBlock(project, builder, state=state, badbytes=builder.badbytes)
        rb.import_effect(gadget)

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
        project = builder.project
        arch_bytes = project.arch.bytes
        for g in gs[1:]:
            if g.self_contained:
                rb = rb._chain_block(RopBlock.from_gadget(g, builder))
            elif g.stack_change >= 0 and g.transit_type == 'jmp_reg':
                init_state, final_state = rb.sim_exec()
                new_vals = []
                for offset in range(0, g.stack_change, arch_bytes):
                    tmp = final_state.memory.load(final_state.regs.sp+offset, arch_bytes, endness=project.arch.memory_endness)
                    new_vals.append(rop_utils.cast_rop_value(tmp, project))
                rb._values[rb.next_pc_idx()] = rop_utils.cast_rop_value(g.addr, project)

                final_state.solver.add(final_state.ip == g.addr)
                final_state = rop_utils.step_to_unconstrained_successor(project, final_state)
                rb._gadgets.append(g)
                rb._values += new_vals
                rb.payload_len += len(new_vals)*arch_bytes
                ip_hash = hash(final_state.ip)
                for idx, val in enumerate(rb._values):
                    if val.symbolic and hash(val.ast) == ip_hash:
                        next_pc_val = rop_utils.cast_rop_value(
                            init_state.solver.BVS("next_pc", project.arch.bits),
                            project,
                        )
                        rb._values[idx] = next_pc_val
            else:
                raise NotImplementedError("plz create an issue")
        rb._analyze_effect()
        return rb

    @staticmethod
    def from_chain(chain):
        state = chain._blank_state.copy()
        badbytes = chain._builder.badbytes
        rb = RopBlock(chain._p, chain._builder, state=state, badbytes=badbytes)
        rb._gadgets = chain._gadgets.copy()
        rb._values = chain._values.copy()
        rb.payload_len = chain.payload_len
        rb._analyze_effect()
        return rb

    def copy(self):
        cp = super().copy()
        cp = self.copy_effect(cp)
        return cp
