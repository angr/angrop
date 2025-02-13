import heapq
import logging
from collections import defaultdict, Counter
from typing import Iterable, Iterator

import claripy
from angr.errors import SimUnsatError

from .builder import Builder
from .. import rop_utils
from ..rop_chain import RopChain
from ..rop_block import RopBlock
from ..rop_gadget import RopGadget
from ..errors import RopException

l = logging.getLogger("angrop.chain_builder.reg_setter")

class RegSetter(Builder):
    """
    a chain builder that aims to set registers using different algorithms
    1. algo1: graph-search, fast, not reliable
    2. algo2: pop-only bfs search, fast, reliable, can generate chains to bypass bad-bytes
    3. algo3: riscy-rop inspired backward search, slow, can utilize gadgets containing conditional branches
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)
        self._reg_setting_gadgets = None # all the gadgets that can set registers
        self.hard_chain_cache = None
        # Estimate of how difficult it is to set each register.
        self._reg_weights = None
        self._reg_setting_dict = None

    def _insert_to_reg_dict(self, gs):
        for rb in gs:
            for reg in rb.popped_regs:
                self._reg_setting_dict[reg].append(rb)
        for reg in self._reg_setting_dict:
            lst = self._reg_setting_dict[reg]
            self._reg_setting_dict[reg] = sorted(lst, key=lambda x: x.stack_change)

    def bootstrap(self):
        self._reg_setting_gadgets = self.filter_gadgets(self.chain_builder.gadgets)

        # update reg_setting_dict
        self._reg_setting_dict = defaultdict(list)
        for g in self._reg_setting_gadgets:
            if not g.self_contained:
                continue
            for reg in g.popped_regs:
                self._reg_setting_dict[reg].append(g)
        self._insert_to_reg_dict([]) # sort reg dict

        reg_pops = Counter()
        for gadget in self._reg_setting_gadgets:
            reg_pops.update(gadget.popped_regs)
        self._reg_weights = {
            reg: 5 if reg_pops[reg] == 0 else 2 if reg_pops[reg] == 1 else 1
            for reg in self.arch.reg_set
        }

        self.hard_chain_cache = {}

    def optimize(self):
        # now we have a functional RegSetter, check whether we can do better

        # first, TODO: see whether we can use reg_mover to set hard-registers

        # second, see whether we can use non-self-contained gadgets to reduce stack-change requirements
        # TODO: currently, we only support jmp_reg gadgets
        bests = {}
        for gadget in self._reg_setting_gadgets:
            if gadget.self_contained:
                continue
            if gadget.has_conditional_branch:
                continue
            if gadget.transit_type != 'jmp_reg':
                continue
            stack_change = gadget.stack_change
            if gadget.pc_reg not in self._reg_setting_dict:
                continue

            # choose the best gadget to set the PC for this jmp_reg gadget
            pc_setter = None
            for g in self._reg_setting_dict[gadget.pc_reg]:
                if g.has_symbolic_access():
                    continue
                pc_setter = g
                break
            if pc_setter is None:
                continue
            pc_setter_sc = pc_setter.stack_change

            for reg in gadget.popped_regs:
                if gadget.pc_reg not in self._reg_setting_dict:
                    continue
                total_sc = stack_change + pc_setter_sc
                reg_sc = self._reg_setting_dict[reg][0].stack_change if reg in self._reg_setting_dict else 0xffffffff
                if total_sc > reg_sc:
                    continue

                assert isinstance(pc_setter, RopGadget)
                try:
                    chain = self._build_reg_setting_chain([pc_setter, gadget], None, {}, total_sc)
                    rb = RopBlock.from_chain(chain)
                    assert rb.stack_change == total_sc
                    if reg not in bests or rb.stack_change < bests[reg].stack_change:
                        bests[reg] = rb
                    elif rb.stack_change == bests[reg].stack_change and \
                            bests[reg].num_sym_mem_access > rb.num_sym_mem_access:
                        bests[reg] = rb
                except RopException:
                    pass
        self._insert_to_reg_dict(bests.values())

    def verify(self, chain, preserve_regs, registers):
        """
        given a potential chain, verify whether the chain can set the registers correctly by symbolically
        execute the chain
        """
        chain_str = chain.dstr()
        state = chain.exec()
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
                reg_name = self.project.arch.translate_register_name(offset)
                if reg_name in preserve_regs:
                    l.exception("Somehow angrop thinks\n%s\ncan be used for the chain generation-1.\nregisters: %s",
                                chain_str, registers)
                    return False
        for reg, val in registers.items():
            bv = getattr(state.regs, reg)
            if (val.symbolic != bv.symbolic) or state.solver.eval(bv != val.data):
                l.exception("Somehow angrop thinks\n%s\ncan be used for the chain generation-2.\nregisters: %s",
                            chain_str, registers)
                return False
        # the next pc must be marked as the next_pc
        if len(state.regs.pc.variables) != 1:
            return False
        pc_var = set(state.regs.pc.variables).pop()
        return pc_var.startswith("next_pc")

    @staticmethod
    def _mixins_to_gadgets(mixins):
        gadgets = []
        for mixin in mixins:
            if isinstance(mixin, RopGadget):
                gadgets.append(mixin)
            elif isinstance(mixin, RopBlock):
                gadgets += mixin._gadgets
            else:
                raise ValueError(f"cannot turn {mixin} into RopBlock!")
        return gadgets

    def run(self, modifiable_memory_range=None, preserve_regs=None, max_length=10, **registers):
        if len(registers) == 0:
            return RopChain(self.project, self, badbytes=self.badbytes)

        # sanity check
        preserve_regs = set(preserve_regs) if preserve_regs else set()
        unknown_regs = set(registers.keys()).union(preserve_regs) - self.arch.reg_set
        if unknown_regs:
            raise RopException("unknown registers: %s" % unknown_regs)

        # cast values to RopValue
        for x in registers:
            registers[x] = rop_utils.cast_rop_value(registers[x], self.project)

        for gadgets in self.iterate_candidate_chains(modifiable_memory_range, preserve_regs, max_length, registers):
            chain_str = "\n".join(g.dstr() for g in gadgets)
            l.debug("building reg_setting chain with chain:\n%s", chain_str)
            stack_change = sum(x.stack_change for x in gadgets)
            try:
                gadgets = self._mixins_to_gadgets(gadgets)
                chain = self._build_reg_setting_chain(gadgets, modifiable_memory_range,
                                                      registers, stack_change)
                chain._concretize_chain_values(timeout=len(chain._values)*3)
                if self.verify(chain, preserve_regs, registers):
                    #self._chain_cache[reg_tuple].append(gadgets)
                    return chain
            except (RopException, SimUnsatError):
                pass

        raise RopException("Couldn't set registers :(")

    def iterate_candidate_chains(self, modifiable_memory_range, preserve_regs, max_length, registers):
        # algorithm1
        gadgets, _, _ = self.find_candidate_chains_graph_search(modifiable_memory_range=modifiable_memory_range,
                                                                preserve_regs=preserve_regs.copy(),
                                                                **registers)
        if gadgets:
            yield gadgets

        # algorithm2
        yield from self.find_candidate_chains_pop_only_bfs_search(
                                    self._find_relevant_gadgets(allow_mem_access=False, **registers),
                                    preserve_regs.copy(),
                                    **registers)

        # algorithm3
        yield from self.find_candidate_chains_backwards_recursive_search(
                                    self._reg_setting_gadgets,
                                    set(registers),
                                    current_chain=[],
                                    preserve_regs=preserve_regs.copy(),
                                    modifiable_memory_range=modifiable_memory_range,
                                    visited={},
                                    max_length=max_length)

    #### Chain Building Algorithm 1: fast but unreliable graph-based search ####

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
            curr_tuple = ()
        while curr_tuple != ():
            gadgets_reverse.append(data[curr_tuple][2])
            curr_tuple = data[curr_tuple][0]
        return gadgets_reverse[::-1]

    @staticmethod
    def _verify_chain(chain, regs):
        """
        make sure the new chain does not do bad memory accesses
        """
        accesses = set()
        for g in chain:
            accesses.update(set(g.mem_reads + g.mem_writes + g.mem_changes))
        accesses = set(m for m in accesses if m.is_symbolic_access())
        for mem_access in accesses:
            if mem_access.addr_controllers and not mem_access.addr_controllers.intersection(regs):
                return False

        return True

    # todo allow user to specify rop chain location so that we can use read_mem gadgets to load values
    # todo allow specify initial regs
    # todo memcopy(from_addr, to_addr, len)
    # todo handle "leave" then try to do a mem write on chess from codegate-finals
    def find_candidate_chains_graph_search(self, modifiable_memory_range=None, use_partial_controllers=False,
                                  max_stack_change=None, preserve_regs=None, **registers):
        """
        Finds a list of gadgets which set the desired registers
        This method currently only handles simple cases and will be improved later
        :param registers:
        :return:
        """
        preserve_regs = set(preserve_regs) if preserve_regs else set()
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
        allow_mem_access = modifiable_memory_range is not None
        gadgets = self._find_relevant_gadgets(allow_mem_access=allow_mem_access, **registers)
        for s in partial_controllers.values():
            gadgets.update(s)
        gadgets = list(gadgets)
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
                # ignore gadgets which don't have a positive stack change
                if g.stack_change <= 0:
                    continue

                # ignore gadgets that set any of our preserved registers
                if g.changed_regs.intersection(preserve_regs):
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
        if modifiable_memory_range is None and g.has_symbolic_access():
            return set(), set()
        elif modifiable_memory_range is not None:
            # check if we control all the memory reads/writes/changes
            accesses =  g.mem_changes + g.mem_reads + g.mem_writes
            all_mem_accesses = [m for m in accesses if m.is_symbolic_access()]
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
        state.memory.store(state.regs.sp + gadget.stack_change, claripy.BVV(b"A"*0x100))

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

    #### Chain Building Algorithm 2: pop-only BFS search ####

    def _find_relevant_gadgets(self, allow_mem_access=True, **registers):
        """
        find gadgets that may pop/load/change requested registers
        """
        gadgets = set()

        # this step will add crafted rop_blocks as well
        for reg in registers:
            gadgets.update(self._reg_setting_dict[reg])

        for g in self._reg_setting_gadgets:
            if not g.self_contained:
                continue
            if g.has_symbolic_access():
                continue
            if not allow_mem_access and g.num_sym_mem_access:
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

    @staticmethod
    def _find_concrete_chains(gadgets, registers):
        chains = []
        for g in gadgets:
            for reg, val in registers.items():
                if reg in g.concrete_regs and g.concrete_regs[reg] == val:
                    chains.append([g])
        return chains

    def find_candidate_chains_pop_only_bfs_search(self, gadgets, preserve_regs, **registers):
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
            clobbered_regs = g.changed_regs.intersection(preserve_regs)
            if clobbered_regs - set_regs:
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

    #### Chain Building Algorithm 3: RiscyROP's backwards search ####

    def find_candidate_chains_backwards_recursive_search(
        self,
        gadgets: Iterable[RopGadget],
        registers: set[str],
        current_chain: list[RopGadget],
        preserve_regs: set[str],
        modifiable_memory_range: tuple[int, int] | None,
        visited: dict[tuple[str, ...], int],
        max_length: int,
    ) -> Iterator[list[RopGadget]]:
        """Recursively build ROP chains starting from the end using the RiscyROP algorithm."""
        # Base case.
        if not registers:
            yield current_chain[::-1]
            return

        if len(current_chain) >= max_length:
            return

        # Stop if we've seen the same set of registers before to prevent infinite recursion.
        reg_tuple = tuple(sorted(registers))
        if visited.get(reg_tuple, max_length) <= len(current_chain):
            return
        visited[reg_tuple] = len(current_chain)

        potential_next_gadgets = []

        for gadget in gadgets:
            if not gadget.changed_regs.isdisjoint(preserve_regs):
                continue
            # Skip gadgets with non-constant memory accesses if we don't have memory that can be safely accessed.
            if modifiable_memory_range is None and gadget.has_symbolic_access():
                continue
            remaining_regs = self._get_remaining_regs(gadget, registers)
            if remaining_regs is None:
                continue
            potential_next_gadgets.append((gadget, remaining_regs))

        # Sort gadgets by number of remaining registers, stack change, and instruction count
        potential_next_gadgets.sort(
            key=lambda g: (
                sum(self._reg_weights[reg] for reg in g[1]),
                g[0].stack_change,
                g[0].isn_count,
            )
        )

        for gadget, remaining_regs in potential_next_gadgets:
            current_chain.append(gadget)
            yield from self.find_candidate_chains_backwards_recursive_search(
                gadgets,
                remaining_regs,
                current_chain,
                preserve_regs,
                modifiable_memory_range,
                visited,
                max_length,
            )
            current_chain.pop()

    def _get_remaining_regs(self, gadget: RopGadget, registers: set[str]) -> set[str] | None:
        """
        Get the registers that still need to be controlled after prepending a gadget.

        Returns None if this gadget cannot be used.
        """
        # Check if the gadget sets any registers that we need.
        if gadget.popped_regs.isdisjoint(registers) and not any(
            reg_move.to_reg in registers and reg_move.bits == self.project.arch.bits
            for reg_move in gadget.reg_moves
         ):
            return None

        remaining_regs = set()
        stack_dependencies = set()

        for reg in registers:
            if reg in gadget.popped_regs:
                reg_vars = gadget.popped_reg_vars[reg] if reg in gadget.popped_reg_vars else set()
                if not reg_vars.isdisjoint(stack_dependencies):
                    # Two registers are popped from the same location on the stack.
                    return None
                stack_dependencies |= reg_vars
                continue
            new_reg = reg
            for reg_move in gadget.reg_moves:
                if reg_move.to_reg == reg:
                    if reg_move.bits != self.project.arch.bits:
                        # Register is only partially overwritten.
                        return None
                    new_reg = reg_move.from_reg
                    break
            else:
                # Check if the gadget changes the register in some other way.
                if reg in gadget.changed_regs:
                    return None
            if new_reg in remaining_regs:
                # Conflict, can't put two different values in the same register.
                return None
            remaining_regs.add(new_reg)

        if gadget.transit_type == 'jmp_reg':
            if gadget.pc_reg in remaining_regs:
                return None
            remaining_regs.add(gadget.pc_reg)

        if not gadget.constraint_regs.isdisjoint(remaining_regs):
            return None
        remaining_regs |= gadget.constraint_regs

        return remaining_regs

    #### Gadget Filtering ####

    def _filter_gadgets(self, gadgets):
        """
        group gadgets by features and drop lesser groups
        """
        # gadget grouping
        d = defaultdict(list)
        for g in gadgets:
            key = (len(g.changed_regs), g.stack_change, g.num_sym_mem_access, g.isn_count)
            d[key].append(g)
        if len(d) == 0:
            return set()
        if len(d) == 1:
            return {gadgets.pop()}

        # only keep the best groups
        keys = set(d.keys())
        bests = set()
        while keys:
            k1 = keys.pop()
            # check if nothing is better than k1
            for k2 in bests|keys:
                # if k2 is better than k1
                if all(k2[i] <= k1[i] for i in range(4)):
                    break
            else:
                bests.add(k1)

        # turn groups back to gadgets
        gadgets = set()
        for key, val in d.items():
            if key not in bests:
                continue
            gadgets = gadgets.union(val)
        return gadgets

    def _same_effect(self, g1, g2):
        if g1.popped_regs != g2.popped_regs:
            return False
        if g1.concrete_regs != g2.concrete_regs:
            return False
        if g1.reg_dependencies != g2.reg_dependencies:
            return False
        if g1.transit_type != g2.transit_type:
            return False
        if g1.has_conditional_branch != g2.has_conditional_branch:
            return False
        return True

    def filter_gadgets(self, gadgets):
        """
        process gadgets based on their effects
        exclude gadgets that do symbolic memory access
        """
        bests = set()
        gadgets = set(gadgets)
        while gadgets:
            g0 = gadgets.pop()
            equal_class = {g for g in gadgets if self._same_effect(g0, g)}
            equal_class.add(g0)
            bests = bests.union(self._filter_gadgets(equal_class))

            gadgets -= equal_class
        return bests
