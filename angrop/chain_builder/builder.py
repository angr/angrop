import struct
from abc import abstractmethod
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

    #@rop_utils.timeout(2)
    def _build_reg_setting_chain(self, gadgets, modifiable_memory_range, register_dict, stack_change):
        """
        This function figures out the actual values needed in the chain
        for a particular set of gadgets and register values
        This is done by stepping a symbolic state through each gadget
        then constraining the final registers to the values that were requested
        """
        print("\nStarting chain build with %d gadgets, stack_change: %#x" % (len(gadgets), stack_change))
        for i, g in enumerate(gadgets):
            print("Gadget[%d]: %#x type:%s stack_change:%#x" % (i, g.addr, g.transit_type, g.stack_change))

        # emulate a 'pop pc' of the first gadget
        test_symbolic_state = self.make_sim_state(gadgets[0].addr)

        # For memory control gadgets, add registers that control the memory access to dependencies
        for g in gadgets:
            if g.transit_type in ('jmp_reg_from_mem', 'call_reg_from_mem'):
                print("\nProcessing mem gadget %#x" % g.addr)
                # Add memory addressing registers to register_dict if not already there
                for reg in g.mem_target_regs:
                    if reg not in register_dict:
                        print("Adding mem target reg %s to register_dict" % reg)
                        rop_val = rop_utils.cast_rop_value(test_symbolic_state.registers.load(reg), self.project)
                        register_dict[reg] = rop_val

                # We need to preserve intermediate registers as-well
                if g.mem_load_reg and g.mem_load_reg not in register_dict:
                    print("Adding mem load reg %s to register_dict" % g.mem_load_reg)
                    rop_val = rop_utils.cast_rop_value(test_symbolic_state.registers.load(g.mem_load_reg), self.project)
                    register_dict[g.mem_load_reg] = rop_val

            print("\nCurrent register_dict: %s" % str(register_dict))

        addrs = [g.addr for g in gadgets]
        addrs.append(test_symbolic_state.solver.BVS("next_addr", self.project.arch.bits))
        print("\nGadget addresses to process: %s" % [hex(x) for x in addrs[:-1]])

        arch_bytes = self.project.arch.bytes
        state = test_symbolic_state

        # step through each gadget
        for addr in addrs[1:]:
            if not isinstance(addr, int):
                print("\nProcessing symbolic address")
            else:
                print("\nProcessing addr: %#x" % addr)

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

        print("\nReady to build chain. Stack change: %#x, bytes_per_pop: %#x" % (stack_change, bytes_per_pop))

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
        if self.roparg_filler is not None:
            print("\nUsing roparg_filler: %#x" % self.roparg_filler)
            for i in range(stack_change // bytes_per_pop):
                sym_word = test_symbolic_state.memory.load(sp + bytes_per_pop * i, bytes_per_pop,
                                                           endness=self.project.arch.memory_endness)
                # check if we can constrain val to be the roparg_filler
                if test_symbolic_state.solver.satisfiable((sym_word == self.roparg_filler,)) and \
                        rebase_state.solver.satisfiable((sym_word == self.roparg_filler,)):
                    # constrain the val to be the roparg_filler
                    test_symbolic_state.add_constraints(sym_word == self.roparg_filler)
                    rebase_state.add_constraints(sym_word == self.roparg_filler)

        # create the ropchain
        chain = RopChain(self.project, self, state=test_symbolic_state.copy(),
                         badbytes=self.badbytes)

        # iterate through the stack values that need to be in the chain
        if gadgets[-1].transit_type == 'jmp_reg' or \
                gadgets[-1].transit_type in ('jmp_reg_from_mem', 'call_reg_from_mem'):
            print("\nAdjusting stack_change for %s gadget" % gadgets[-1].transit_type)
            stack_change += arch_bytes

        print("\nProcessing %d stack values:" % (stack_change // bytes_per_pop))
        for i in range(stack_change // bytes_per_pop):
            sym_word = test_symbolic_state.memory.load(sp + bytes_per_pop * i, bytes_per_pop,
                                                       endness=self.project.arch.memory_endness)
            val = test_symbolic_state.solver.eval(sym_word)
            print("Stack value[%d]: %#x" % (i, val))

            if len(gadgets) > 0:
                print("Next gadget to match: %#x" % gadgets[0].addr)

            if len(gadgets) > 0 and val == gadgets[0].addr:
                print("Matched and added gadget %#x" % gadgets[0].addr)
                chain.add_gadget(gadgets[0])
                gadgets = gadgets[1:]
            else:
                print("Added value %#x to chain" % val)
                var = sym_word
                for c in test_symbolic_state.solver.constraints:
                    print("  ", c)
                    if len(c.variables) != 2:  # it is always xx == yy
                        continue
                    if not sym_word.variables.intersection(c.variables):
                        continue
                    var_name = set(c.variables - sym_word.variables).pop()
                    if var_name not in var_dict:
                        continue
                    var = var_dict[var_name]
                    break
                chain.add_value(var)

        print("\nRemaining unhandled gadgets: %d" % len(gadgets))
        if len(gadgets) > 0:
            print("Unhandled gadgets:")
            for g in gadgets:
                print("  %#x type:%s stack_change:%#x" % (g.addr, g.transit_type, g.stack_change))
            raise RopException("Didnt find all gadget addresses, something must've broke")
        return chain

    def _get_fill_val(self):
        if self.roparg_filler is not None:
            return self.roparg_filler
        else:
            return claripy.BVS("filler", self.project.arch.bits)

    @abstractmethod
    def update(self):
        raise NotImplementedError("each Builder class should have an `update` method!")
