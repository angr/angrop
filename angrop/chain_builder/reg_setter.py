import heapq
import logging
from collections import defaultdict

from angr.errors import SimUnsatError

from .builder import Builder
from .. import rop_utils
from ..rop_chain import RopChain
from ..errors import RopException

l = logging.getLogger("angrop.chain_builder.reg_setter")

class RegSetter(Builder):
    """
    TODO: get rid of Salls's code
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)
        self._reg_setting_gadgets = None
        self.hard_chain_cache = None
        self.update()

    def update(self):
        self._reg_setting_gadgets = self._filter_gadgets(self.chain_builder.gadgets)
        self.hard_chain_cache = {}

    def verify(self, chain, preserve_regs, registers):
        """
        given a potential chain, verify whether the chain can set the registers correctly by symbolically
        execute the chain
        """
        state = chain.exec()
        for reg, val in registers.items():
            chain_str = '\n-----\n'.join([str(self.project.factory.block(g.addr).capstone)for g in chain._gadgets])
            bv = getattr(state.regs, reg)
            for act in state.history.actions.hardcopy:
                if act.type not in ("mem", "reg"):
                    continue
                if act.type == 'mem':
                    if act.addr.ast.variables:
                        l.exception("memory access outside stackframe\n%s\n", chain_str)
                        return False
                if act.type == 'reg' and act.action == 'write':
                    # get the full name of the register
                    offset = act.offset
                    offset -= act.offset % self.project.arch.bytes
                    reg_name = self.project.arch.register_size_names[offset, self.project.arch.bytes]
                    if reg_name in preserve_regs:
                        l.exception("Somehow angrop thinks \n%s\n can be used for the chain generation - 1.", chain_str)
                        return False
            if bv.symbolic or state.solver.eval(bv != val.data):
                l.exception("Somehow angrop thinks \n%s\n can be used for the chain generation - 2.", chain_str)
                return False
        # the next pc must come from the stack
        if len(state.regs.pc.variables) != 1:
            return False
        if not set(state.regs.pc.variables).pop().startswith("symbolic_stack"):
            return False
        return True

    def run(self, modifiable_memory_range=None, use_partial_controllers=False,  preserve_regs=None, **registers):
        if len(registers) == 0:
            return RopChain(self.project, None, badbytes=self.badbytes)

        # sanity check
        preserve_regs = set(preserve_regs) if preserve_regs else set()
        unknown_regs = set(registers.keys()).union(preserve_regs) - self.arch.reg_set
        if unknown_regs:
            raise RopException("unknown registers: %s" % unknown_regs)

        # cast values to RopValue
        for x in registers:
            registers[x] = rop_utils.cast_rop_value(registers[x], self.project)

        gadgets = self._find_relevant_gadgets(**registers)

        chains = []

        # find the chain provided by the graph search algorithm
        best_chain, _, _ = self._find_reg_setting_gadgets(modifiable_memory_range,
                                                          use_partial_controllers, **registers)
        if best_chain:
            chains += [best_chain]

        # find chains using BFS based on pops
        chains += self._find_all_candidate_chains(gadgets, preserve_regs.copy(), **registers)

        for gadgets in chains:
            chain_str = '\n-----\n'.join([str(self.project.factory.block(g.addr).capstone)for g in gadgets])
            l.debug("building reg_setting chain with chain:\n%s", chain_str)
            stack_change = sum(x.stack_change for x in gadgets)
            try:
                chain = self._build_reg_setting_chain(gadgets, modifiable_memory_range,
                                                     registers, stack_change)
                chain._concretize_chain_values()
                if self.verify(chain, preserve_regs, registers):
                    #self._chain_cache[reg_tuple].append(gadgets)
                    return chain
            except (RopException, SimUnsatError):
                pass

        raise RopException("Couldn't set registers :(")

    def _find_relevant_gadgets(self, **registers):
        """
        find gadgets that may pop/load/change requested registers
        exclude gadgets that do symbolic memory access
        """
        gadgets = set({})
        for g in self._reg_setting_gadgets:
            if g.makes_syscall:
                continue
            if g.has_symbolic_access():
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
        """
        preserve_regs: soft preservation, can be overwritten as long as it gets back to control
        hard_preserve_regs: cannot touch these regs at all
        """
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
        val = rop_utils.cast_rop_value(val, self.project)
        concrete_setter_gadgets = [ x for x in gadgets if reg in x.concrete_regs ]
        delta_gadgets = [ x for x in gadgets if len(x.reg_dependencies) == 1 and reg in x.reg_dependencies\
                            and len(x.reg_dependencies[reg]) == 1 and reg in x.reg_dependencies[reg]]
        for g1 in concrete_setter_gadgets:
            for g2 in delta_gadgets:
                try:
                    chain = self._build_reg_setting_chain([g1, g2], False, # pylint:disable=too-many-function-args
                                                         {reg: val}, g1.stack_change+g2.stack_change)
                    state = chain.exec()
                    bv = state.registers.load(reg)
                    if bv.symbolic:
                        continue
                    if state.solver.eval(bv == val.data):
                        return [g1, g2]
                except Exception:# pylint:disable=broad-except
                    pass
        return None

    def _find_all_candidate_chains(self, gadgets, preserve_regs, **registers):
        """
        1. find gadgets that set concrete values to the target values, such as xor eax, eax to set eax to 0
        2. find all pop only chains by BFS search
        TODO: handle moves
        """
        # get the list of regs that cannot be popped (call it hard_regs)
        hard_regs = [reg for reg, val in registers.items() if self._word_contain_badbyte(val)]
        if len(hard_regs) > 1:
            l.error("too many registers contain bad bytes! bail out! %s", registers)
            return []

        # if hard_regs exists, try to use concrete values to craft the value
        hard_chain = []
        if hard_regs and not registers[hard_regs[0]].symbolic:
            reg = hard_regs[0]
            val = registers[reg].concreted
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

        preserve_regs.update(hard_regs)
        # use the original pop techniques to set other registers
        chains = self._recursively_find_chains(gadgets, hard_chain, preserve_regs,
                                               set(registers.keys()), preserve_regs)
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
                to_remove.update({x for x in gadgets-{g} if g.reg_set_better_than(x)})
                if to_remove:
                    break
                skip.add(g)
            if not to_remove:
                break
            gadgets -= to_remove
        return gadgets

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

        # set the register
        state = rop_utils.make_symbolic_state(self.project, self.arch.reg_set)
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
