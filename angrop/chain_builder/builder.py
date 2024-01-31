import struct
from functools import cmp_to_key

import claripy

from .. import rop_utils
from ..errors import RopException
from ..rop_value import RopValue
from ..rop_chain import RopChain

class Builder:
    """
    a generic class to bootstrap more complicated chain building functionality
    """
    def __init__(self, project, reg_list=None, badbytes=None, filler=None):
        self.project = project
        self._reg_set = set(reg_list)
        self._badbytes = badbytes
        self._roparg_filler = filler

    @staticmethod
    def _sort_chains(chains):
        def cmp_func(chain1, chain2):
            stack_change1 = sum(x.stack_change for x in chain1)
            stack_change2 = sum(x.stack_change for x in chain2)
            if stack_change1 > stack_change2:
                return 1
            elif stack_change1 < stack_change2:
                return -1

            num_mem_access1 = sum(x.num_mem_access for x in chain1)
            num_mem_access2 = sum(x.num_mem_access for x in chain2)
            if num_mem_access1 > num_mem_access2:
                return 1
            if num_mem_access1 < num_mem_access2:
                return -1
            return 0
        return sorted(chains, key=cmp_to_key(cmp_func))

    def _word_contain_badbyte(self, ptr):
        """
        check if a pointer contains any bad byte
        """
        if isinstance(ptr, RopValue):
            if ptr.symbolic:
                return False
            else:
                ptr = ptr.concreted
        raw_bytes = struct.pack(self.project.arch.struct_fmt(), ptr)
        if any(x in raw_bytes for x in self._badbytes):
            return True
        return False

    @rop_utils.timeout(2)
    def _build_reg_setting_chain(self, gadgets, modifiable_memory_range, register_dict, stack_change):
        """
        This function figures out the actual values needed in the chain
        for a particular set of gadgets and register values
        This is done by stepping a symbolic state through each gadget
        then constraining the final registers to the values that were requested
        FIXME: trim this disgusting function
        """

        # create a symbolic state
        test_symbolic_state = rop_utils.make_symbolic_state(self.project, self._reg_set)
        addrs = [g.addr for g in gadgets]
        addrs.append(test_symbolic_state.solver.BVS("next_addr", self.project.arch.bits))

        arch_bytes = self.project.arch.bytes
        arch_endness = self.project.arch.memory_endness

        # emulate a 'pop pc' of the first gadget
        state = test_symbolic_state
        state.regs.ip = addrs[0]
        # the stack pointer must begin pointing to our first gadget
        state.add_constraints(state.memory.load(state.regs.sp, arch_bytes, endness=arch_endness) == addrs[0])
        # push the stack pointer down, like a pop would do
        state.regs.sp += arch_bytes
        state.solver._solver.timeout = 5000

        # step through each gadget
        # for each gadget, constrain memory addresses and add constraints for the successor
        for addr in addrs[1:]:
            succ = rop_utils.step_to_unconstrained_successor(self.project, state)
            state.add_constraints(succ.regs.ip == addr)
            # constrain reads/writes
            for a in succ.log.actions:
                if a.type == "mem" and a.addr.ast.symbolic:
                    if modifiable_memory_range is None:
                        raise RopException("Symbolic memory address when there shouldnt have been")
                    test_symbolic_state.add_constraints(a.addr.ast >= modifiable_memory_range[0])
                    test_symbolic_state.add_constraints(a.addr.ast < modifiable_memory_range[1])
            test_symbolic_state.add_constraints(succ.regs.ip == addr)
            # get to the unconstrained successor
            state = rop_utils.step_to_unconstrained_successor(self.project, state)

        # re-adjuest the stack pointer
        sp = test_symbolic_state.regs.sp
        sp -= arch_bytes
        bytes_per_pop = arch_bytes

        # constrain the final registers
        rebase_state = test_symbolic_state.copy()
        var_dict = {}
        for r, v in register_dict.items():
            var = claripy.BVS(r, self.project.arch.bits)
            var_name = var._encoded_name.decode()
            var_dict[var_name] = v
            test_symbolic_state.add_constraints(state.registers.load(r) == var)
            test_symbolic_state.add_constraints(var == v.data)

        # constrain the "filler" values
        if self._roparg_filler is not None:
            for i in range(stack_change // bytes_per_pop):
                sym_word = test_symbolic_state.memory.load(sp + bytes_per_pop*i, bytes_per_pop,
                                                           endness=self.project.arch.memory_endness)
                # check if we can constrain val to be the roparg_filler
                if test_symbolic_state.solver.satisfiable((sym_word == self._roparg_filler,)) and \
                        rebase_state.solver.satisfiable((sym_word == self._roparg_filler,)):
                    # constrain the val to be the roparg_filler
                    test_symbolic_state.add_constraints(sym_word == self._roparg_filler)
                    rebase_state.add_constraints(sym_word == self._roparg_filler)

        # create the ropchain
        chain = RopChain(self.project, self, state=test_symbolic_state.copy(),
                       badbytes=self._badbytes)

        # iterate through the stack values that need to be in the chain
        for i in range(stack_change // bytes_per_pop):
            sym_word = test_symbolic_state.memory.load(sp + bytes_per_pop*i, bytes_per_pop,
                                                       endness=self.project.arch.memory_endness)

            val = test_symbolic_state.solver.eval(sym_word)
            if len(gadgets) > 0 and val == gadgets[0].addr:
                chain.add_gadget(gadgets[0])
                gadgets = gadgets[1:]
            else:
                # propagate the initial RopValue provided by users to preserve info like rebase
                var = sym_word
                for c in test_symbolic_state.solver.constraints:
                    if len(c.variables) != 2: # it is always xx == yy
                        continue
                    if not sym_word.variables.intersection(c.variables):
                        continue
                    var_name = set(c.variables - sym_word.variables).pop()
                    if var_name not in var_dict:
                        continue
                    var = var_dict[var_name]
                    break
                chain.add_value(var)

        if len(gadgets) > 0:
            raise RopException("Didnt find all gadget addresses, something must've broke")
        return chain
