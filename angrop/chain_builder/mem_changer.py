import logging
from functools import cmp_to_key

import claripy
import angr

from .builder import Builder
from .. import rop_utils
from ..rop_block import RopBlock
from ..errors import RopException

l = logging.getLogger(__name__)

class MemChanger(Builder):
    """
    part of angrop's chainbuilder engine, responsible for adding values to a memory location
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)
        self._mem_change_gadgets = None
        self._mem_add_gadgets = None

    def bootstrap(self):
        self._mem_change_gadgets = self._get_all_mem_change_gadgets(self.chain_builder.gadgets)
        self._mem_add_gadgets = self._get_all_mem_add_gadgets()

    def verify(self, chain, addr, value, _):
        arch_bytes = self.project.arch.bytes
        endness = self.project.arch.memory_endness

        # verify the chain actually works
        chain2 = chain.copy()
        chain2._blank_state.memory.store(addr.data, 0x41424344, arch_bytes, endness=endness)
        state = chain2.exec()
        sim_data = state.memory.load(addr.data, arch_bytes, endness=endness)
        if not state.solver.eval(sim_data == 0x41424344 + value.data):
            raise RopException("memory add fails - 1")
        # the next pc must come from the stack
        if len(state.regs.pc.variables) != 1:
            raise RopException("memory add fails - 2")
        if not set(state.regs.pc.variables).pop().startswith("next_pc_"):
            raise RopException("memory add fails - 3")

    def _effect_tuple(self, g):
        change = g.mem_changes[0]
        v1 = change.op
        v2 = change.data_size
        v3 = change.data_constant
        v4 = tuple(sorted(change.addr_dependencies))
        v5 = tuple(sorted(change.data_dependencies))
        return (v1, v2, v3, v4, v5)

    def _comparison_tuple(self, g):
        return (len(g.changed_regs), g.stack_change, g.num_sym_mem_access,
                rop_utils.transit_num(g), g.isn_count)

    def _get_all_mem_change_gadgets(self, gadgets):
        possible_gadgets = set()
        for g in gadgets:
            if not g.self_contained:
                continue
            sym_rw = [m for m in g.mem_reads + g.mem_writes if m.is_symbolic_access()]
            if len(sym_rw) > 0 or len(g.mem_changes) != 1:
                continue
            for m_access in g.mem_changes:
                # assume we need intersection of addr_dependencies and data_dependencies to be 0
                if m_access.addr_controllable() and m_access.data_controllable() and m_access.addr_data_independent():
                    possible_gadgets.add(g)
        gadgets = self._filter_gadgets(possible_gadgets)
        return sorted(gadgets, key=lambda x: x.stack_change)

    def _get_all_mem_add_gadgets(self):
        return [x for x in self._mem_change_gadgets if x.mem_changes[0].op in ('__add__', '__sub__')]

    @staticmethod
    def _sort_gadgets(gadgets):
        def cmp_func(g1, g2):
            # prefer gadget with fewer memory accesses
            if g1.num_sym_mem_access > g2.num_sym_mem_access:
                return 1
            if g1.num_sym_mem_access < g2.num_sym_mem_access:
                return -1
            # prefer gadget taking less space
            if g1.stack_change > g2.stack_change:
                return 1
            elif g1.stack_change < g2.stack_change:
                return -1
            # prefer shorter gadget
            if g1.isn_count > g2.isn_count:
                return 1
            elif g1.isn_count < g2.isn_count:
                return -1
            return 0
        return sorted(gadgets, key=cmp_to_key(cmp_func))

    def add_to_mem(self, addr, value, data_size=None):
        # TODO could allow mem_reads as long as we control the address?

        if data_size is None:
            data_size = self.project.arch.bits

        possible_gadgets = [x for x in self._mem_add_gadgets if x.mem_changes[0].data_size == data_size]
        if not possible_gadgets:
            raise RopException("Fail to find any gadget that can perform memory adding...")

        # sort the gadgets with number of memory accesses and stack_change
        gadgets = self._sort_gadgets(possible_gadgets)

        if not gadgets:
            raise RopException("Couldnt set registers for any memory add gadget")

        l.debug("Now building the mem add chain")

        # try to build the chain
        for g in gadgets:
            try:
                chain = self._add_mem_with_gadget(g, addr, data_size, difference=value)
                self.verify(chain, addr, value, data_size)
                return chain
            except RopException:
                pass

        raise RopException("Fail to perform add_to_mem!")

    def _add_mem_with_gadget(self, gadget, addr, data_size, final_val=None, difference=None):
        # sanity check for simple gadget
        if len(gadget.mem_writes) + len(gadget.mem_changes) != 1 or len(gadget.mem_reads) != 0:
            raise RopException("too many memory accesses for my lazy implementation")

        if (final_val is not None and difference is not None) or (final_val is None and difference is None):
            raise RopException("must specify difference or final value and not both")

        arch_endness = self.project.arch.memory_endness

        # constrain the successor to be at the gadget
        # emulate 'pop pc'
        arch_bytes = self.project.arch.bytes
        test_state = self.make_sim_state(gadget.addr, gadget.stack_change//arch_bytes)

        if difference is not None:
            test_state.memory.store(addr.concreted, claripy.BVV(~(difference.concreted), data_size)) # pylint:disable=invalid-unary-operand-type
        if final_val is not None:
            test_state.memory.store(addr.concreted, claripy.BVV(~final_val, data_size)) # pylint:disable=invalid-unary-operand-type

        # step the gadget
        pre_gadget_state = test_state
        state = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)

        # constrain the change
        mem_change = gadget.mem_changes[0]
        the_action = None
        for a in state.history.actions.hardcopy:
            if a.type != "mem" or a.action != "write":
                continue
            if set(rop_utils.get_ast_dependency(a.addr.ast)) == set(mem_change.addr_dependencies):
                the_action = a
                break

        if the_action is None:
            raise RopException("Couldn't find the matching action")

        # constrain the addr
        test_state.add_constraints(the_action.addr.ast == addr.concreted)
        pre_gadget_state.add_constraints(the_action.addr.ast == addr.concreted)
        pre_gadget_state.options.discard(angr.options.AVOID_MULTIVALUED_WRITES)
        pre_gadget_state.options.discard(angr.options.AVOID_MULTIVALUED_READS)
        state = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)

        # constrain the data
        if final_val is not None:
            test_state.add_constraints(state.memory.load(addr.concreted, data_size//8, endness=arch_endness) ==
                                       claripy.BVV(final_val, data_size))
        if difference is not None:
            test_state.add_constraints(state.memory.load(addr.concreted, data_size//8, endness=arch_endness) -
                                       test_state.memory.load(addr.concreted, data_size//8, endness=arch_endness) ==
                                       claripy.BVV(difference.concreted, data_size))

        # get the actual register values
        all_deps = list(mem_change.addr_dependencies) + list(mem_change.data_dependencies)
        reg_vals = {}
        for reg in set(all_deps):
            reg_vals[reg] = test_state.solver.eval(test_state.registers.load(reg))

        chain = self.set_regs(**reg_vals)
        chain = RopBlock.from_chain(chain)
        chain = self._build_reg_setting_chain([chain, gadget], {})
        return chain
