import heapq
import logging
from collections import defaultdict
from functools import cmp_to_key

import angr


from .. import rop_utils
from ..rop_chain import RopChain
from ..errors import RopException

l = logging.getLogger("angrop.chain_builder.reg_setter")

class RegSetter:
    """
    TODO: get rid of Salls's code
    """
    def __init__(self, project, gadgets, reg_list=None, badbytes=None, rebase=False, filler=None):
        self.project = project
        self._reg_set = set(reg_list)
        self._badbytes = badbytes
        self._rebase = rebase

        self._reg_setting_gadgets = self._filter_gadgets(gadgets)
        self._roparg_filler = filler

    def run(self, modifiable_memory_range=None, use_partial_controllers=False, rebase_regs=None, **registers):
        # TODO: nuke or support rebase_regs
        if len(registers) == 0:
            return RopChain(self.project, None, rebase=self._rebase, badbytes=self._badbytes)

        # sanity check
        unknown_regs = set(registers.keys()) - self._reg_set
        if unknown_regs:
            raise RopException("unknown registers: %s" % unknown_regs)

        gadgets = self._find_relevant_gadgets(**registers)
        chains = self._find_all_candidate_chains(gadgets, **registers)

        if rebase_regs is None:
            rebase_regs = set()

        for chain in chains:
            chain_str = '\n-----\n'.join([str(self.project.factory.block(g.addr).capstone)for g in chain])
            l.debug("building reg_setting chain with chain:\n%s", chain_str)
            stack_change = sum(x.stack_change for x in chain)
            try:
                return self._build_reg_setting_chain(chain, modifiable_memory_range,
                                                     registers, stack_change, rebase_regs)
            except RopException:
                pass

        raise RopException("Couldn't set registers :(")

    def _find_relevant_gadgets(self, **registers):
        """
        find gadgets that may pop/load/change requested registers
        """
        gadgets = set({})
        for g in self._reg_setting_gadgets:
            if g.makes_syscall:
                continue
            for reg in registers:
                if reg in g.popped_regs:
                    gadgets.add(g)
                if reg in g.changed_regs:
                    gadgets.add(g)
                if reg in g.reg_dependencies.keys():
                    gadgets.add(g)
        return gadgets

    def _recursively_find_chains(self, gadgets, chain, preserve_regs, todo_regs):
        if not todo_regs:
            return [chain]

        todo_list = []
        for g in gadgets:
            set_regs = g.popped_regs.intersection(todo_regs)
            if not set_regs:
                continue
            destory_regs = g.changed_regs.intersection(preserve_regs)
            if destory_regs - set_regs:
                continue
            new_preserve = preserve_regs.copy()
            new_preserve.update(set_regs)
            new_chain = chain.copy()
            new_chain.append(g)
            todo_list.append((new_chain, new_preserve, todo_regs-set_regs))

        res = []
        for todo in todo_list:
            res += self._recursively_find_chains(gadgets, *todo)
        return res

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


    def _find_all_candidate_chains(self, gadgets, **registers):
        """
        find all pop only chains by BFS search
        TODO: handle moves
        """
        regs = set(registers.keys())
        chains = self._recursively_find_chains(gadgets, [], set({}), regs)
        return self._sort_chains(chains)

    def _same_reg_effects(self, g1, g2):
        if g1.popped_regs != g2.popped_regs:
            return False
        if g1.bp_moves_to_sp != g2.bp_moves_to_sp:
            return False
        if g1.reg_dependencies != g2.reg_dependencies:
            return False
        return True

    def _strictly_better(self, g1, g2):
        if not self._same_reg_effects(g1, g2):
            return False
        if len(g1.changed_regs) <= len(g2.changed_regs) and g1.block_length <= g2.block_length:
            return True
        return False

    def _filter_gadgets(self, gadgets):
        """
        filter gadgets having the same effect
        """
        gadgets = set(gadgets)
        skip = set({})
        while True:
            to_remove = set({})
            for g in gadgets-skip:
                to_remove.update({x for x in gadgets-{g} if self._strictly_better(g, x)})
                if to_remove:
                    break
                skip.add(g)
            if not to_remove:
                break
            gadgets -= to_remove
        return gadgets


    ################# Salls's Code Space ###################
    @rop_utils.timeout(2)
    def _build_reg_setting_chain(self, gadgets, modifiable_memory_range, register_dict, stack_change, rebase_regs):
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
        for r, v in register_dict.items():
            test_symbolic_state.add_constraints(state.registers.load(r) == v)

        # to handle register values that should depend on the binary base address
        if len(rebase_regs) > 0:
            for r, v in register_dict.items():
                if r in rebase_regs:
                    rebase_state.add_constraints(state.registers.load(r) == (v + 0x41414141))
                else:
                    rebase_state.add_constraints(state.registers.load(r) == v)

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
        res = RopChain(self.project, self, state=test_symbolic_state.copy(), rebase=self._rebase, badbytes=self._badbytes)
        for g in gadgets:
            res.add_gadget(g)

        # iterate through the stack values that need to be in the chain
        gadget_addrs = [g.addr for g in gadgets]
        for i in range(stack_change // bytes_per_pop):
            sym_word = test_symbolic_state.memory.load(sp + bytes_per_pop*i, bytes_per_pop,
                                                       endness=self.project.arch.memory_endness)

            val = test_symbolic_state.solver.eval(sym_word)

            if len(rebase_regs) > 0:
                val2 = rebase_state.solver.eval(rebase_state.memory.load(sp + bytes_per_pop*i, bytes_per_pop,
                                                                        endness=self.project.arch.memory_endness))
                if (val2 - val) & (2**self.project.arch.bits - 1) == 0x41414141:
                    res.add_value(val, needs_rebase=True)
                elif val == val2 and len(gadget_addrs) > 0 and val == gadget_addrs[0]:
                    res.add_value(val, needs_rebase=True)
                    gadget_addrs = gadget_addrs[1:]
                elif val == val2:
                    res.add_value(sym_word, needs_rebase=False)
                else:
                    raise RopException("Rebase Failed")
            else:
                if len(gadget_addrs) > 0 and val == gadget_addrs[0]:
                    res.add_value(val, needs_rebase=True)
                    gadget_addrs = gadget_addrs[1:]
                else:
                    res.add_value(sym_word, needs_rebase=False)

        if len(gadget_addrs) > 0:
            raise RopException("Didnt find all gadget addresses, something must've broke")
        return res
