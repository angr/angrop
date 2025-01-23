import struct
from abc import abstractmethod
from functools import cmp_to_key
from collections import defaultdict

import claripy

from .. import rop_utils
from ..errors import RopException
from ..rop_gadget import RopGadget
from ..rop_value import RopValue
from ..rop_chain import RopChain

class Builder:
    """
    a generic class to bootstrap more complicated chain building functionality
    """
    def __init__(self, chain_builder):
        self.chain_builder = chain_builder
        self.project = chain_builder.project
        self.arch = chain_builder.arch

    @property
    def badbytes(self):
        return self.chain_builder.badbytes

    @property
    def roparg_filler(self):
        return self.chain_builder.roparg_filler

    def make_sim_state(self, pc):
        """
        make a symbolic state with all general purpose register + base pointer symbolized
        and emulate a `pop pc` situation
        """
        arch_bytes = self.project.arch.bytes
        arch_endness = self.project.arch.memory_endness

        state = rop_utils.make_symbolic_state(self.project, self.arch.reg_set)
        rop_utils.make_reg_symbolic(state, self.arch.base_pointer)

        state.regs.ip = pc
        state.add_constraints(state.memory.load(state.regs.sp, arch_bytes, endness=arch_endness) == pc)
        state.regs.sp += arch_bytes
        state.solver._solver.timeout = 5000
        return state

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
        if any(x in raw_bytes for x in self.badbytes):
            return True
        return False

    def _get_ptr_to_writable(self, size):
        """
        get a pointer to writable region that can fit `size` bytes
        it shouldn't contain bad byte
        """
        # get all writable segments
        segs = [ s for s in self.project.loader.main_object.segments if s.is_writable ]
        # enumerate through all address to find a good address
        for seg in segs:
            for addr in range(seg.min_addr, seg.max_addr):
                if all(not self._word_contain_badbyte(x) for x in range(addr, addr+size, self.project.arch.bytes)):
                    return addr
        return None

    def _get_ptr_to_null(self):
        # get all non-writable segments
        segs = [ s for s in self.project.loader.main_object.segments if not s.is_writable ]
        # enumerate through all address to find a good address
        for seg in segs:
            null = b'\x00'*self.project.arch.bytes
            for addr in self.project.loader.memory.find(null, search_min=seg.min_addr, search_max=seg.max_addr):
                if not self._word_contain_badbyte(addr):
                    return addr
        return None

    @rop_utils.timeout(8)
    def _build_reg_setting_chain(
        self, gadgets, modifiable_memory_range, register_dict, stack_change
    ):
        """
        This function figures out the actual values needed in the chain
        for a particular set of gadgets and register values
        This is done by stepping a symbolic state through each gadget
        then constraining the final registers to the values that were requested
        """

        # emulate a 'pop pc' of the first gadget
        test_symbolic_state = rop_utils.make_symbolic_state(
            self.project,
            self.arch.reg_set,
            stack_gsize=stack_change // self.project.arch.bytes + 1,
        )
        rop_utils.make_reg_symbolic(test_symbolic_state, self.arch.base_pointer)
        test_symbolic_state.ip = test_symbolic_state.stack_pop()
        test_symbolic_state.solver._solver.timeout = 5000

        # Maps each stack variable to the RopValue or RopGadget that should be placed there.
        stack_var_to_value = {}

        def map_stack_var(ast, value):
            if len(ast.variables) != 1:
                raise RopException("Target value not controlled by a single variable")
            var = next(iter(ast.variables))
            if not var.startswith("symbolic_stack_"):
                raise RopException("Target value not controlled by the stack")
            stack_var_to_value[var] = value

        arch_bytes = self.project.arch.bytes

        state = test_symbolic_state.copy()

        # Step through each gadget and constrain the ip.
        for gadget in gadgets:
            map_stack_var(state.ip, gadget)
            state.solver.add(state.ip == gadget.addr)
            for addr in gadget.bbl_addrs[1:]:
                succ = state.step()
                succ_states = [
                    state
                    for state in succ.successors
                    if state.solver.is_true(state.ip == addr)
                ]
                if len(succ_states) != 1:
                    raise RopException(
                        "Zero or multiple states match address of next block"
                    )
                state = succ_states[0]
            succ = state.step()
            if succ.flat_successors or len(succ.unconstrained_successors) != 1:
                raise RopException(
                    "Executing gadget doesn't result in a single unconstrained state"
                )
            state = succ.unconstrained_successors[0]

        if len(state.solver.eval_upto(state.ip, 2)) < 2:
            raise RopException("The final pc is not unconstrained!")

        # Record the variable that controls the final ip.
        next_pc_val = rop_utils.cast_rop_value(
            test_symbolic_state.solver.BVS("next_pc", self.project.arch.bits),
            self.project,
        )
        map_stack_var(state.ip, next_pc_val)

        # Constrain final register values.
        for reg, val in register_dict.items():
            var = state.registers.load(reg)
            if val.is_register:
                if var.op != "BVS" or not next(iter(var.variables)).startswith(
                    f"sreg_{val.reg_name}-"
                ):
                    raise RopException("Register wasn't moved correctly")
            elif not var.symbolic and not val.symbolic:
                if var.concrete_value != val.concreted:
                    raise RopException("Register set to incorrect value")
            else:
                state.solver.add(var == val.data)

        # Constrain memory access addresses.
        for action in state.history.actions:
            if action.type == action.MEM and action.addr.symbolic:
                if modifiable_memory_range is None:
                    raise RopException(
                        "Symbolic memory address without modifiable memory range"
                    )
                state.solver.add(action.addr.ast >= modifiable_memory_range[0])
                state.solver.add(action.addr.ast < modifiable_memory_range[1])

        # now import the constraints from the state that has reached the end of the ropchain
        test_symbolic_state.solver.add(*state.solver.constraints)

        bytes_per_pop = arch_bytes

        # constrain the "filler" values
        if self.roparg_filler is not None:
            for offset in range(0, stack_change, bytes_per_pop):
                sym_word = test_symbolic_state.stack_read(offset, bytes_per_pop)
                # check if we can constrain val to be the roparg_filler
                if test_symbolic_state.solver.satisfiable([sym_word == self.roparg_filler]):
                    # constrain the val to be the roparg_filler
                    test_symbolic_state.add_constraints(sym_word == self.roparg_filler)

        # create the ropchain
        chain = RopChain(self.project,
                         self,
                         state=test_symbolic_state.copy(),
                         badbytes=self.badbytes)

        # iterate through the stack values that need to be in the chain
        for offset in range(-bytes_per_pop, stack_change, bytes_per_pop):
            sym_word = test_symbolic_state.stack_read(offset, bytes_per_pop)
            assert len(sym_word.variables) == 1
            sym_var = next(iter(sym_word.variables))
            if sym_var in stack_var_to_value:
                val = stack_var_to_value[sym_var]
                if isinstance(val, RopGadget):
                    # this is special, we know this won't be "next_pc", so don't try
                    # to take "next_pc"'s position
                    value = RopValue(val.addr, self.project)
                    value.rebase_analysis(chain=chain)
                    chain.add_value(value)
                else:
                    # HACK: Because angrop appears to have originally been written
                    # with assumptions around x86 ret gadgets, the target of the final jump
                    # is not included in the chain if it is the last value.
                    if offset == stack_change - bytes_per_pop and val is next_pc_val:
                        break
                    chain.add_value(val)
            else:
                chain.add_value(sym_word)

        chain.set_gadgets(gadgets)

        return chain

    def _get_fill_val(self):
        if self.roparg_filler is not None:
            return self.roparg_filler
        else:
            return claripy.BVS("filler", self.project.arch.bits)

    @abstractmethod
    def _same_effect(self, g1, g2):
        raise NotImplementedError("_same_effect is not implemented!")

    @abstractmethod
    def _better_than(self, g1, g2):
        raise NotImplementedError("_better_than is not implemented!")

    def same_effect(self, g1, g2):
        return self._same_effect(g1, g2)

    def better_than(self, g1, g2):
        if not self.same_effect(g1, g2):
            return False
        return self._better_than(g1, g2)

    def __filter_gadgets(self, gadgets):
        """
        remove any gadgets that are strictly worse than others
        FIXME: make all gadget filtering logic like what we do in reg_setter, which is correct and way more faster
        """
        gadgets = set(gadgets)
        bests = set()
        while gadgets:
            g1 = gadgets.pop()
            # check if nothing is better than g1
            for g2 in bests|gadgets:
                if self._better_than(g2, g1):
                    break
            else:
                bests.add(g1)
        return bests

    def _filter_gadgets(self, gadgets):
        bests = set()
        gadgets = set(gadgets)
        while gadgets:
            g0 = gadgets.pop()
            equal_class = {g for g in gadgets if self._same_effect(g0, g)}
            equal_class.add(g0)
            bests = bests.union(self.__filter_gadgets(equal_class))

            gadgets -= equal_class
        return bests

    @abstractmethod
    def update(self):
        raise NotImplementedError("each Builder class should have an `update` method!")
