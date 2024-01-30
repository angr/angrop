import heapq
import struct
import logging
from collections import defaultdict
from functools import cmp_to_key

from angr.errors import SimUnsatError


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

        self.hard_chain_cache = {}

    def _contain_badbyte(self, ptr):
        """
        check if a pointer contains any bad byte
        """
        raw_bytes = struct.pack(self.project.arch.struct_fmt(), ptr)
        if any(x in raw_bytes for x in self._badbytes):
            return True
        return False

    def verify(self, chain, registers):
        """
        given a potential chain, verify whether the chain can set the registers correctly by symbolically
        execute the chain
        """
        state = chain.exec()
        for reg, val in registers.items():
            chain_str = '\n-----\n'.join([str(self.project.factory.block(g.addr).capstone)for g in chain._gadgets])
            bv = getattr(state.regs, reg)
            if bv.symbolic or state.solver.eval(bv != val):
                l.exception("Somehow angrop thinks \n%s\n can be used for the chain generation.", chain_str)
                return False
        return True

    def run(self, modifiable_memory_range=None, use_partial_controllers=False,  **registers):
        if len(registers) == 0:
            return RopChain(self.project, None, badbytes=self._badbytes)

        # sanity check
        unknown_regs = set(registers.keys()) - self._reg_set
        if unknown_regs:
            raise RopException("unknown registers: %s" % unknown_regs)

        # load from cache
        #reg_tuple = tuple(sorted(registers.keys()))
        #chains = self._chain_cache[reg_tuple]
        chains = []

        gadgets = self._find_relevant_gadgets(**registers)

        # find the chain provided by the graph search algorithm
        best_chain, _, _ = self._find_reg_setting_gadgets(modifiable_memory_range,
                                                                       use_partial_controllers, **registers)
        if best_chain:
            chains += [best_chain]

        # find chains using BFS based on pops
        chains += self._find_all_candidate_chains(gadgets, **registers)

        for gadgets in chains:
            chain_str = '\n-----\n'.join([str(self.project.factory.block(g.addr).capstone)for g in gadgets])
            l.debug("building reg_setting chain with chain:\n%s", chain_str)
            stack_change = sum(x.stack_change for x in gadgets)
            try:
                chain = self._build_reg_setting_chain(gadgets, modifiable_memory_range,
                                                     registers, stack_change)
                chain._concretize_chain_values()
                if self.verify(chain, registers):
                    #self._chain_cache[reg_tuple].append(gadgets)
                    return chain
            except (RopException, SimUnsatError):
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
                if reg in g.concrete_regs.keys():
                    gadgets.add(g)
        return gadgets

    def _recursively_find_chains(self, gadgets, chain, preserve_regs, todo_regs, hard_preserve_regs):
        if not todo_regs:
            return [chain]

        todo_list = []
        for g in gadgets:
            set_regs = g.popped_regs.intersection(todo_regs)
            if not set_regs:
                continue
            if g.changed_regs.intersection(hard_preserve_regs):
                continue
            destory_regs = g.changed_regs.intersection(preserve_regs)
            if destory_regs - set_regs:
                continue
            new_preserve = preserve_regs.copy()
            new_preserve.update(set_regs)
            new_chain = chain.copy()
            new_chain.append(g)
            todo_list.append((new_chain, new_preserve, todo_regs-set_regs, hard_preserve_regs))

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

    @staticmethod
    def _find_concrete_chains(gadgets, registers):
        chains = []
        for g in gadgets:
            for reg, val in registers.items():
                if reg in g.concrete_regs and g.concrete_regs[reg] == val:
                    chains.append([g])
        return chains

    def _find_add_chain(self, gadgets, reg, val):
        """
        find one chain to set one single register to a specific value using concrete values only through add/dec
        """
        concrete_setter_gadgets = [ x for x in gadgets if reg in x.concrete_regs ]
        delta_gadgets = [ x for x in gadgets if len(x.reg_dependencies) == 1 and reg in x.reg_dependencies\
                            and len(x.reg_dependencies[reg]) == 1 and reg in x.reg_dependencies[reg]]
        for g1 in concrete_setter_gadgets:
            for g2 in delta_gadgets:
                try:
                    chain = self._build_reg_setting_chain([g1, g2], False, # pylint:disable=too-many-function-args
                                                         {reg: val}, g1.stack_change+g2.stack_change, [])
                    state = chain.exec()
                    bv = state.registers.load(reg)
                    if bv.symbolic:
                        continue
                    if state.solver.eval(bv == val):
                        return [g1, g2]
                except Exception:# pylint:disable=broad-except
                    pass
        return None

    def _find_all_candidate_chains(self, gadgets, **registers):
        """
        1. find gadgets that set concrete values to the target values, such as xor eax, eax to set eax to 0
        2. find all pop only chains by BFS search
        TODO: handle moves
        """
        # get the list of regs that cannot be popped (call it hard_regs)
        hard_regs = [reg for reg, val in registers.items() if type(val) == int and self._contain_badbyte(val)]
        if len(hard_regs) > 1:
            l.error("too many registers contain bad bytes! bail out! %s", registers)
            return []

        # if hard_regs exists, try to use concrete values to craft the value
        hard_chain = []
        if hard_regs:
            reg = hard_regs[0]
            val = registers[reg]
            key = (reg, val)
            if key in self.hard_chain_cache:
                hard_chain = self.hard_chain_cache[key]
            else:
                hard_chains = self._find_concrete_chains(gadgets, {reg: val})
                if hard_chains:
                    hard_chain = hard_chains[0]
                else:
                    hard_chain = self._find_add_chain(gadgets, reg, val)
                self.hard_chain_cache[key] = hard_chain # we cache the result even if it fails
            if not hard_chain:
                l.error("Fail to set register: %s to: %#x", reg, val)
                return []
            registers.pop(reg)

        # use the original pop techniques to set other registers
        chains = self._recursively_find_chains(gadgets, hard_chain, set(hard_regs),
                                               set(registers.keys()), set(hard_regs))
        return self._sort_chains(chains)

    @staticmethod
    def _filter_gadgets(gadgets):
        """
        filter gadgets having the same effect
        """
        gadgets = set(gadgets)
        skip = set({})
        while True:
            to_remove = set({})
            for g in gadgets-skip:
                to_remove.update({x for x in gadgets-{g} if g.reg_better_than(x)})
                if to_remove:
                    break
                skip.add(g)
            if not to_remove:
                break
            gadgets -= to_remove
        return gadgets


    ################# Salls's Code Space ###################
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
        for r, v in register_dict.items():
            test_symbolic_state.add_constraints(state.registers.load(r) == v)

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
                chain.add_value(sym_word, needs_rebase=False)

        if len(gadgets) > 0:
            raise RopException("Didnt find all gadget addresses, something must've broke")
        return chain

    @staticmethod
    def _tuple_to_gadgets(data, reg_tuple):
        """
        turn the entry tuple in the graph search to a list of gadgets
        """
        if reg_tuple in data:
            gadgets_reverse = []
            curr_tuple = reg_tuple
        else:
            gadgets_reverse = reg_tuple[2]
        while curr_tuple != ():
            gadgets_reverse.append(data[curr_tuple][2])
            curr_tuple = data[curr_tuple][0]
        return gadgets_reverse[::-1]

    @staticmethod
    def _verify_chain(chain, regs):
        """
        make sure the new chain can control the registers
        # TODO: maybe use symoblic execution to verify it?
        """
        g = chain[-1]
        if g.transit_type == 'jmp_reg':
            return g.pc_reg in regs

        # make sure all memory access can be forced to happen on valid addresses
        # don't need to consider constant addr or addr popped from stack
        for mem_access in g.mem_reads + g.mem_writes + g.mem_changes:
            if mem_access.addr_controllers and not mem_access.addr_controllers.intersection(regs):
                return False

        return True

    # todo allow user to specify rop chain location so that we can use read_mem gadgets to load values
    # todo allow specify initial regs or dont clobber regs
    # todo memcopy(from_addr, to_addr, len)
    # todo handle "leave" then try to do a mem write on chess from codegate-finals
    def _find_reg_setting_gadgets(self, modifiable_memory_range=None, use_partial_controllers=False,
                                  max_stack_change=None, **registers):
        """
        Finds a list of gadgets which set the desired registers
        This method currently only handles simple cases and will be improved later
        :param registers:
        :return:
        """
        search_regs = set(registers)

        if modifiable_memory_range is not None and len(modifiable_memory_range) != 2:
            raise RopException("modifiable_memory_range should be a tuple (low, high)")

        # find gadgets with sufficient partial control
        partial_controllers = {}
        for r in registers:
            partial_controllers[r] = set()
        if use_partial_controllers:
            partial_controllers = self._get_sufficient_partial_controllers(registers)

        # filter reg setting gadgets
        gadgets = set(self._reg_setting_gadgets)
        for s in partial_controllers.values():
            gadgets.update(s)
        gadgets = list(gadgets)
        if modifiable_memory_range is None:
            gadgets = [g for g in gadgets if
                       len(g.mem_changes) == 0 and len(g.mem_writes) == 0 and len(g.mem_reads) == 0]
        l.debug("finding best gadgets")


        # lets try doing a graph search to set registers, something like dijkstra's for minimum length

        # each key is tuple of sorted registers
        # use tuple (prev, total_stack_change, gadget, partial_controls)
        data = {}

        to_process = []
        to_process.append((0, ()))
        visited = set()
        data[()] = (None, 0, None, set())
        best_stack_change = 0xffffffff
        best_reg_tuple = None
        while to_process:
            regs = heapq.heappop(to_process)[1]

            if regs in visited:
                continue
            visited.add(regs)

            if data[regs][1] >= best_stack_change:
                continue
            if max_stack_change is not None and data[regs][1] > max_stack_change:
                continue

            for g in gadgets:
                # ignore gadgets which make a syscall when setting regs
                if g.makes_syscall:
                    continue
                # ignore gadgets which don't have a positive stack change
                if g.stack_change <= 0:
                    continue
                # ignore base pointer moves for now
                if g.bp_moves_to_sp:
                    continue

                stack_change = data[regs][1]
                new_stack_change = stack_change + g.stack_change
                # if its longer than the best ignore
                if new_stack_change >= best_stack_change:
                    continue
                # ignore if we only change controlled regs
                start_regs = set(regs)
                if g.changed_regs.issubset(start_regs - data[regs][3]):
                    continue

                end_regs, partial_regs = self._get_updated_controlled_regs(g, regs, data[regs], partial_controllers,
                                                                           modifiable_memory_range)

                # ignore the gadget if does not provide us new controlled registers
                end_reg_tuple = tuple(sorted(end_regs))
                npartial = len(partial_regs)
                if len(end_regs - start_regs) == 0:
                    continue

                # if we havent seen that tuple before, or payload is shorter or less partially controlled regs.
                if end_reg_tuple in data: # we have seen the tuple before
                    end_data = data.get(end_reg_tuple, None)
                    # payload is longer or contains more partially controlled regs
                    if not (new_stack_change < end_data[1] and npartial <= len(end_data[3])):
                        continue
                    if npartial >= len(end_data[3]):
                        continue

                # now make sure the chain does provide what it claims to provide
                chain = self._tuple_to_gadgets(data, regs) + [g]
                if not self._verify_chain(chain, end_regs):
                    continue

                # it improves the graph so add it
                data[end_reg_tuple] = (regs, new_stack_change, g, partial_regs)
                heapq.heappush(to_process, (new_stack_change, end_reg_tuple))

                # update the result if we find a better chain
                if search_regs.issubset(end_regs) and new_stack_change < best_stack_change:
                    best_stack_change = new_stack_change
                    best_reg_tuple = end_reg_tuple

        # if the best_reg_tuple is None then we failed to set the desired registers :(
        if best_reg_tuple is None:
            return None, None, data

        gadgets = self._tuple_to_gadgets(data, best_reg_tuple)
        return gadgets, best_stack_change, data

    def _get_sufficient_partial_controllers(self, registers):
        sufficient_partial_controllers = defaultdict(set)
        for g in self._reg_setting_gadgets:
            for reg in g.changed_regs:
                if reg in registers:
                    if self._check_if_sufficient_partial_control(g, reg, registers[reg]):
                        sufficient_partial_controllers[reg].add(g)
        return sufficient_partial_controllers

    @staticmethod
    def _get_updated_controlled_regs(gadget, regs, data_tuple, partial_controllers, modifiable_memory_range=None):
        g = gadget
        start_regs = set(regs)
        partial_regs = data_tuple[3]
        usable_regs = start_regs - partial_regs
        end_regs = set(start_regs)

        # skip ones that change memory if no modifiable_memory_addr
        if modifiable_memory_range is None and \
                (len(g.mem_reads) > 0 or len(g.mem_writes) > 0 or len(g.mem_changes) > 0):
            return set(), set()
        elif modifiable_memory_range is not None:
            # check if we control all the memory reads/writes/changes
            all_mem_accesses = g.mem_changes + g.mem_reads + g.mem_writes
            mem_accesses_controlled = True
            for m_access in all_mem_accesses:
                for reg in m_access.addr_dependencies:
                    if reg not in usable_regs:
                        mem_accesses_controlled = False
                    usable_regs -= m_access.addr_dependencies
            if not mem_accesses_controlled:
                return set(), set()

        # analyze  all registers that we control
        for reg in g.changed_regs:
            end_regs.discard(reg)
            partial_regs.discard(reg)

        # for any reg that can be fully controlled check if we control its dependencies
        for reg in g.reg_controllers.keys():
            has_deps = True
            for dep in g.reg_dependencies[reg]:
                if dep not in usable_regs:
                    has_deps = False
            if has_deps:
                for dep in g.reg_dependencies[reg]:
                    end_regs.discard(dep)
                    usable_regs.discard(dep)
                end_regs.add(reg)
            else:
                end_regs.discard(reg)

        # for all the changed regs that we dont fully control, we see if the partial control is good enough
        for reg in set(g.changed_regs) - set(g.reg_controllers.keys()):
            if reg in partial_controllers and g in partial_controllers[reg]:
                # partial control is good enough so now check if we control all the dependencies
                if reg not in g.reg_dependencies or set(g.reg_dependencies[reg]).issubset(usable_regs):
                    # we control all the dependencies add it and remove them from the usable regs
                    partial_regs.add(reg)
                    end_regs.add(reg)
                    if reg in g.reg_dependencies:
                        usable_regs -= set(g.reg_dependencies[reg])
                        end_regs -= set(g.reg_dependencies[reg])

        for reg in g.popped_regs:
            end_regs.add(reg)

        return end_regs, partial_regs

    def _get_single_ret(self):
        # start with a ret instruction
        ret_addr = None
        for g in self._reg_setting_gadgets:
            if len(g.changed_regs) == 0 and len(g.mem_writes) == 0 and \
                    len(g.mem_reads) == 0 and len(g.mem_changes) == 0 and \
                    g.stack_change == self.project.arch.bytes:
                ret_addr = g.addr
                break
        return ret_addr

    def _check_if_sufficient_partial_control(self, gadget, reg, value):
        # doesnt change it
        if reg not in gadget.changed_regs:
            return False
        # does syscall
        if gadget.makes_syscall:
            return False
        # can be controlled completely, not a partial control
        if reg in gadget.reg_controllers or reg in gadget.popped_regs:
            return False
        # make sure the register doesnt depend on itself
        if reg in gadget.reg_dependencies and reg in gadget.reg_dependencies[reg]:
            return False
        # make sure the gadget doesnt pop bp
        if gadget.bp_moves_to_sp:
            return False

        # set the register
        state = rop_utils.make_symbolic_state(self.project, self._reg_set)
        state.registers.store(reg, 0)
        state.regs.ip = gadget.addr
        # store A's past the end of the stack
        state.memory.store(state.regs.sp + gadget.stack_change, state.solver.BVV(b"A"*0x100))

        succ = rop_utils.step_to_unconstrained_successor(project=self.project, state=state)
        # successor
        if succ.ip is succ.registers.load(reg):
            return False

        if succ.solver.solution(succ.registers.load(reg), value):
            # make sure wasnt a symbolic read
            for var in succ.registers.load(reg).variables:
                if "symbolic_read" in var:
                    return False
            return True
        return False
