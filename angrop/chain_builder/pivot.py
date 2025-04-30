import logging
import functools

from .builder import Builder
from .. import rop_utils
from ..errors import RopException

l = logging.getLogger(__name__)

def cmp(g1, g2):
    if len(g1.sp_reg_controllers) < len(g2.sp_reg_controllers):
        return -1
    if len(g1.sp_reg_controllers) > len(g2.sp_reg_controllers):
        return 1

    if g1.stack_change + g1.stack_change_after_pivot < g2.stack_change + g2.stack_change_after_pivot:
        return -1
    if g1.stack_change + g1.stack_change_after_pivot > g2.stack_change + g2.stack_change_after_pivot:
        return 1

    if g1.isn_count < g2.isn_count:
        return -1
    if g1.isn_count > g2.isn_count:
        return 1
    return 0

class Pivot(Builder):
    """
    a chain_builder that builds stack pivoting rop chains
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)
        self._pivot_gadgets: list = None # type: ignore

    def bootstrap(self):
        self._pivot_gadgets = self.filter_gadgets(self.chain_builder.pivot_gadgets)

    def pivot(self, thing):
        if thing.is_register:
            return self.pivot_reg(thing)
        return self.pivot_addr(thing)

    def pivot_addr(self, addr):
        for gadget in self._pivot_gadgets:
            # constrain the successor to be at the gadget
            # emulate 'pop pc'
            init_state = self.make_sim_state(gadget.addr, gadget.stack_change_before_pivot//self.project.arch.bytes+1)

            # step the gadget
            final_state = rop_utils.step_to_unconstrained_successor(self.project, init_state)

            # constrain the final sp
            final_state.solver.add(final_state.regs.sp == addr.data)
            registers = {}
            for x in gadget.sp_reg_controllers:
                registers[x] = final_state.solver.eval(init_state.registers.load(x))
            chain = self.chain_builder.set_regs(**registers)

            try:
                chain.add_gadget(gadget)
                # iterate through the stack values that need to be in the chain
                sp = init_state.regs.sp
                arch_bytes = self.project.arch.bytes
                for i in range(gadget.stack_change_before_pivot // arch_bytes):
                    sym_word = init_state.memory.load(sp + arch_bytes*i, arch_bytes,
                                                      endness=self.project.arch.memory_endness)
                    val = final_state.solver.eval(sym_word)
                    chain.add_value(val)
                state = chain.exec(stop_at_pivot=True)
                if state.solver.eval(state.regs.sp == addr.data):
                    return chain
            except Exception: # pylint: disable=broad-exception-caught
                continue

        raise RopException(f"Fail to pivot the stack to {addr.data}!")

    def pivot_reg(self, reg_val):
        reg = reg_val.reg_name
        for gadget in self._pivot_gadgets:
            if reg not in gadget.sp_reg_controllers:
                continue

            init_state = self.make_sim_state(gadget.addr, gadget.stack_change_before_pivot//self.project.arch.bytes)
            final_state = rop_utils.step_to_unconstrained_successor(self.project, init_state)

            chain = self.chain_builder.set_regs()

            try:
                chain.add_gadget(gadget)
                # iterate through the stack values that need to be in the chain
                sp = init_state.regs.sp
                arch_bytes = self.project.arch.bytes
                for i in range(gadget.stack_change // arch_bytes):
                    sym_word = init_state.memory.load(sp + arch_bytes*i, arch_bytes,
                                                      endness=self.project.arch.memory_endness)

                    val = final_state.solver.eval(sym_word)
                    chain.add_value(val)
                state = chain.exec(stop_at_pivot=True)
                variables = set(state.regs.sp.variables)
                if len(variables) == 1 and variables.pop().startswith(f'sreg_{reg}'):
                    return chain
                else:
                    chain_str = chain.dstr()
                    l.exception("Somehow angrop thinks\n%s\ncan be use for stack pivoting", chain_str)
            except Exception: # pylint: disable=broad-exception-caught
                continue

        raise RopException(f"Fail to pivot the stack to {reg}!")

    def _effect_tuple(self, g):
        v1 = tuple(sorted(g.sp_controllers))
        return (v1, g.stack_change, g.stack_change_after_pivot)

    def _comparison_tuple(self, g):
        return (g.num_sym_mem_access, len(g.changed_regs), g.isn_count)

    def filter_gadgets(self, gadgets):
        gadgets = [x for x in gadgets if not x.has_conditional_branch and x.transit_type != 'jmp_reg' and not x.has_symbolic_access()]
        gadgets = self._filter_gadgets(gadgets)
        return sorted(gadgets, key=functools.cmp_to_key(cmp))
