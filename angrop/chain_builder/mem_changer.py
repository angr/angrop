import logging

import angr

from .builder import Builder
from .. import rop_utils
from ..rop_block import RopBlock
from ..rop_gadget import RopGadget
from ..errors import RopException

l = logging.getLogger(__name__)

class MemChanger(Builder):
    """
    part of angrop's chainbuilder engine, responsible for adding values to a memory location
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)
        self._mem_change_gadgets: list[RopGadget] = None # type: ignore
        self._mem_add_gadgets: list[RopGadget] = None # type: ignore
        self._mem_xor_gadgets: list[RopGadget] = None # type: ignore
        self._mem_or_gadgets: list[RopGadget] = None # type: ignore
        self._mem_and_gadgets: list[RopGadget] = None # type: ignore

    def bootstrap(self):
        self._mem_change_gadgets = self._get_all_mem_change_gadgets(self.chain_builder.gadgets)
        self._mem_add_gadgets = self._get_mem_change_gadgets(('__add__', '__sub__'))
        self._mem_xor_gadgets = self._get_mem_change_gadgets(('__xor__'))
        self._mem_or_gadgets = self._get_mem_change_gadgets(('__or__'))
        self._mem_and_gadgets = self._get_mem_change_gadgets(('__and__'))

    def verify(self, op, chain, addr, value, data_size):
        endness = self.project.arch.memory_endness
        data_bytes = data_size//8

        # make sure the chain actually works
        chain2 = chain.copy()
        init_val = 0x4142434445464748
        init_val &= (1 << data_size) - 1
        chain2._blank_state.memory.store(addr.data, init_val, data_bytes, endness=endness)
        init_bv = chain2._blank_state.memory.load(addr.data, data_bytes, endness=endness)
        state = chain2.exec()
        final_bv = state.memory.load(addr.data, data_bytes, endness=endness)

        init = init_bv.concrete_value
        final = final_bv.concrete_value
        value = value.concreted

        # check data effect correctness
        correct: int = 0
        match op:
            case 'add':
                correct = init + value
                mask = (1<<data_size)-1
                correct &= mask
            case 'xor':
                correct = init ^ value
            case 'or':
                correct = init | value
            case 'and':
                correct = init & value
            case _:
                raise RopException(f"unknown memory changing operation: {op}")
        if correct != final:
            raise RopException("memory change fails - 1")

        # the next pc must come from the stack
        if len(state.regs.pc.variables) != 1:
            raise RopException("memory change fails - 2")
        if not set(state.regs.pc.variables).pop().startswith("next_pc_"):
            raise RopException("memory change fails - 3")

    def _effect_tuple(self, g):
        change = g.mem_changes[0]
        # add and sub should be considered as the same class
        v1 = change.op if change.op not in ('__add__', '__sub__') else '__add__'
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
        gadgets = list(self._filter_gadgets(possible_gadgets))
        return gadgets

    def _get_mem_change_gadgets(self, ops):
        gadgets = [x for x in self._mem_change_gadgets if x.mem_changes[0].op in ops]
        return sorted(gadgets,
                      key=lambda g: (g.mem_changes[0].data_size, -len(g.changed_regs)),
                      reverse=True)

    def _change_mem_with_gadget(self, op, gadget, addr, value, data_size):
        arch_endness = self.project.arch.memory_endness
        arch_bytes = self.project.arch.bytes
        data_bytes = data_size // 8
        data_mask = (1 << data_size) - 1

        # create an initial state with a random initial value
        test_state = self.make_sim_state(gadget.addr, gadget.stack_change//arch_bytes)
        init_val = 0x4142434445464748
        match op:
            case 'or':
                init_val = 0
            case 'and':
                init_val = data_mask
        init_val &= data_mask
        test_state.memory.store(addr.concreted, init_val, data_bytes, endness=arch_endness)

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
        final_bv = state.memory.load(addr.concreted, data_bytes, endness=arch_endness)
        init_bv = test_state.memory.load(addr.concreted, data_bytes, endness=arch_endness)
        match op:
            case 'add':
                const = (init_bv + value.concreted) == final_bv
            case 'xor':
                const = (init_bv ^ value.concreted) == final_bv
            case 'and':
                const = (init_bv & value.concreted) == final_bv
            case 'or':
                const = (init_bv | value.concreted) == final_bv
            case _:
                raise RopException(f"unknown memory changing operation: {op}")

        test_state.add_constraints(const)

        # get the actual register values
        all_deps = list(mem_change.addr_dependencies) + list(mem_change.data_dependencies)
        reg_vals = {}
        for reg in set(all_deps):
            reg_vals[reg] = test_state.solver.eval(test_state.registers.load(reg))

        chain = self.set_regs(**reg_vals)
        chain = RopBlock.from_chain(chain)
        chain = self._build_reg_setting_chain([chain, gadget], {})
        return chain

    def _mem_change(self, op, addr, value, size=None):
        """
        size: number of bytes
        change memory with exactly the same data_size. It should be the user
        that handles different data_sizes
        # TODO could allow mem_reads as long as we control the address?
        """
        # sanity check the inputs
        if size is None:
            size = self.project.arch.bytes
        if size not in (1, 2, 4, 8):
            raise RopException(f"does not support finding raw chain that {op} {size} bytes of memory")
        data_size = 8*size
        if value.concreted >> data_size:
            raise RopException(f"{value.concreted:#x} cannot be represented by {size}-byte")

        # find the correct gadget list
        gadgets = getattr(self, f"_mem_{op}_gadgets")

        # find gadget matching the data_size
        gadgets = [x for x in gadgets if x.mem_changes[0].data_size == data_size]
        if not gadgets:
            raise RopException(f"Fail to find any gadget that can perform {data_size//8}-byte memory {op}")

        # sort the gadgets with number of memory accesses and stack_change
        gadgets = sorted(gadgets, key=self._comparison_tuple)

        l.debug("Now build the mem %s chain", op)

        # try to build the chain
        for g in gadgets:
            try:
                chain = self._change_mem_with_gadget(op, g, addr, value, data_size)
                self.verify(op, chain, addr, value, data_size)
                return chain
            except RopException:
                pass

        raise RopException(f"Fail to perform _mem_change for {op} operation!")

    def add_to_mem(self, addr, value, size=None):
        l.warning("add_to_mem is deprecated, please use mem_add!")
        return self._mem_change('add', addr, value, size=size)

    def mem_xor(self, addr, value, size=None):
        return self._mem_change('xor', addr, value, size=size)

    def mem_add(self, addr, value, size=None):
        return self._mem_change('add', addr, value, size=size)

    def mem_or(self, addr, value, size=None):
        return self._mem_change('or', addr, value, size=size)

    def mem_and(self, addr, value, size=None):
        return self._mem_change('and', addr, value, size=size)
