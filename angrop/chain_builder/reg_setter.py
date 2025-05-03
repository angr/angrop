import itertools
import logging
from collections import defaultdict, Counter
from functools import cmp_to_key

import networkx as nx
from angr.errors import SimUnsatError

from .builder import Builder
from .. import rop_utils
from ..rop_chain import RopChain
from ..rop_block import RopBlock
from ..rop_gadget import RopGadget
from ..rop_effect import RopRegPop
from ..errors import RopException

l = logging.getLogger(__name__)

class RegSetter(Builder):
    """
    a chain builder that aims to set registers using different algorithms
    1. algo1: graph-search, fast, not reliable
    2. algo2: pop-only bfs search, fast, reliable, can generate chains to bypass bad-bytes
    3. algo3: riscy-rop inspired backward search, slow, can utilize gadgets containing conditional branches
    """

    #### Inits ####
    def __init__(self, chain_builder):
        super().__init__(chain_builder)
        # all the gadgets that can set registers
        self._reg_setting_gadgets: set[RopGadget]= None # type: ignore
        self.hard_chain_cache: dict[tuple, list] = None # type: ignore
        # Estimate of how difficult it is to set each register.
        # all self-contained and not symbolic access
        self._reg_setting_dict: dict[str, list] = None # type: ignore

    def bootstrap(self):
        self._reg_setting_gadgets = self.filter_gadgets(self.chain_builder.gadgets)

        # update reg_setting_dict
        self._reg_setting_dict = defaultdict(list)
        for g in self._reg_setting_gadgets:
            if not g.self_contained:
                continue
            if g.has_symbolic_access():
                continue
            for reg in g.popped_regs:
                self._reg_setting_dict[reg].append(g)
        self._insert_to_reg_dict([]) # sort reg dict

        reg_pops = Counter()
        for gadget in self._reg_setting_gadgets:
            reg_pops.update(gadget.popped_regs)

        self.hard_chain_cache = {}

    #### Utility Functions ####
    def _insert_to_reg_dict(self, gs):
        for rb in gs:
            for reg in rb.popped_regs:
                self._reg_setting_dict[reg].append(rb)
        for reg in self._reg_setting_dict:
            lst = self._reg_setting_dict[reg]
            self._reg_setting_dict[reg] = sorted(lst, key=lambda x: x.stack_change)

    def _expand_ropblocks(self, mixins):
        """
        expand simple ropblocks to gadgets so that we don't encounter solver conflicts
        when using the same ropblock multiple times
        """
        gadgets = []
        for mixin in mixins:
            if isinstance(mixin, RopGadget):
                gadgets.append(mixin)
            elif isinstance(mixin, RopBlock):
                if mixin._blank_state.solver.constraints:
                    try:
                        rb = self._build_reg_setting_chain(mixin._gadgets, {})
                        rb = RopBlock.from_chain(rb)
                        if mixin.popped_regs.issubset(rb.popped_regs):
                            rb.pop_equal_set = mixin.pop_equal_set.copy()
                            gadgets += mixin._gadgets
                            continue
                    except RopException:
                        pass
                    gadgets.append(mixin)
                else:
                    gadgets += mixin._gadgets
            else:
                raise ValueError(f"cannot turn {mixin} into RopBlock!")
        return gadgets

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
                if act.addr.ast.variables and any(not x.startswith('sym_addr') for x in act.addr.ast.variables):
                    l.exception("memory access outside stackframe\n%s\n", chain_str)
                    return False
            if act.type == 'reg' and act.action == 'write':
                # get the full name of the register
                offset = act.offset
                offset -= act.offset % self.project.arch.bytes
                reg_name = self.project.arch.translate_register_name(offset)
                if reg_name in preserve_regs:
                    l.exception("Somehow angrop thinks\n%s\ncan be used for the chain generation-1.\nregisters: %s\npreserve_regs: %s",
                                chain_str, registers, preserve_regs)
                    return False
        for reg, val in registers.items():
            bv = getattr(state.regs, reg)
            if (val.symbolic != bv.symbolic) or state.solver.eval(bv != val.data):
                l.exception("Somehow angrop thinks\n%s\ncan be used for the chain generation-2.\nregisters: %s\npreserve_regs: %s",
                            chain_str, registers, preserve_regs)
                return False
        # the next pc must be marked as the next_pc
        if len(state.regs.pc.variables) != 1:
            return False
        pc_var = set(state.regs.pc.variables).pop()
        return pc_var.startswith("next_pc")

    def can_set_reg(self, reg):
        return bool(self._reg_setting_dict[reg])

    #### Graph Optimization ####
    def _normalize_for_move(self, gadget, new_move):
        """
        two methods:
        1. normalize it and hope the from_reg to be set during normalization
        2. normalize it and make sure the from_reg won't be clobbered during normalization and then prepend it
        """
        rb = self.normalize_gadget(gadget, post_preserve={new_move.to_reg}, to_set_regs={new_move.from_reg})
        if rb is None: # if this does not exist, no need to try the more strict version
            return None
        if new_move.to_reg in rb.popped_regs:
            return rb

        rb = self.normalize_gadget(gadget, pre_preserve={new_move.from_reg}, post_preserve={new_move.to_reg})
        if rb is None:
            return None
        reg_setter = self._reg_setting_dict[new_move.from_reg][0]
        if isinstance(reg_setter, RopGadget):
            reg_setter = RopBlock.from_gadget(reg_setter, self)
        try:
            rb = reg_setter + rb
        except RopException:
            l.error("reg_setter + rb fail to execute, plz raise an issue")
            return None

        return rb

    def _should_normalize_reg_move(self, src, dst, shortest):
        # we can't set the source register, no point in normalizing it
        if src not in shortest:
            return False
        # situations we want to check
        # 1. this is a hard register and we can set the source
        # 2. the final chain is expected to be shorter than the best setter
        # for the second scenario, we only check whether the move can be done in one step
        mover_graph = self.chain_builder._reg_mover._graph
        if not self._reg_setting_dict[dst] and self._reg_setting_dict[src]:
            return True
        edge = (src, dst)
        if mover_graph.has_edge(edge[0], edge[1]):
            edge_blocks = mover_graph.get_edge_data(edge[0], edge[1])['block']
            if edge_blocks[0].stack_change + shortest[src] < shortest[dst]:
                return True
        return False

    def _can_set_reg_with_bits(self, reg, bits):
        blocks = self._reg_setting_dict[reg]
        for block in blocks:
            pop = block.get_pop(reg)
            if pop.bits >= bits:
                return True
        return False

    def _optimize_with_reg_moves(self):
        # basically, we are looking for situations like this:
        # 1) we can set register A to arbitrary value (in self._reg_setting_dict) AND
        # 2) we can move register A to another register, preferably an unseen one
        mover_graph = self.chain_builder._reg_mover._graph
        rop_blocks = []
        shortest = {x:y[0].stack_change for x,y in self._reg_setting_dict.items() if y}
        for src, dst in itertools.product(self._reg_setting_dict.keys(), self.arch.reg_list):
            if src == dst:
                continue

            if not self._should_normalize_reg_move(src, dst, shortest):
                continue

            paths = nx.all_simple_paths(mover_graph, src, dst, cutoff=3)
            all_chains = defaultdict(list)
            for path in paths:
                path_chain = []
                edges = zip(path, path[1:])
                path_bits = self.project.arch.bits
                for edge in edges:
                    edge_data = mover_graph.get_edge_data(edge[0], edge[1])
                    edge_blocks = edge_data['block']
                    edge_bits = edge_data['bits']
                    if edge_bits < path_bits:
                        path_bits = edge_bits
                    # for each edge, take the shortest 5 blocks
                    def block_with_max_bit_moves(blocks):
                        results = []
                        for block in blocks:
                            for m in block.reg_moves:
                                if m.from_reg == edge[0] and m.to_reg == edge[1]:
                                    break
                            else:
                                raise RuntimeError("????")
                            if m.bits == edge_bits:
                                results.append(block)
                        return results
                    edge_blocks = sorted(block_with_max_bit_moves(edge_blocks), key=lambda g: g.stack_change)[:5]
                    path_chain.append(edge_blocks)
                setter_chain = []
                for setter in self._reg_setting_dict[src]:
                    pop = setter.get_pop(src)
                    if pop.bits >= path_bits:
                        setter_chain.append(setter)
                if not setter_chain:
                    continue
                path_chains = list(itertools.product(*([setter_chain]+path_chain)))
                all_chains[path_bits] += path_chains

            if not all_chains:
                continue

            def chain_sc(gadgets):
                sc = 0
                for g in gadgets:
                    sc += g.stack_change
                return sc
            unique_chains = []
            max_bits = max(all_chains.keys())
            if not self._can_set_reg_with_bits(dst, max_bits):
                unique_chains = sorted(all_chains[max_bits], key=chain_sc)[:5]
            shorter_chains = []
            if dst in shortest:
                for bits in all_chains:
                    shorter_chains += sorted(all_chains[bits], key=chain_sc)[:5]
                shorter_chains = sorted(shorter_chains, key=chain_sc)[:5]
                shorter_chains = [c for c in shorter_chains if chain_sc(c) < shortest[dst]]

            # take the first normalized unique_chain
            for c in unique_chains:
                try:
                    gadgets = self._expand_ropblocks(c)
                    c = self._build_reg_setting_chain(gadgets, {})
                    c = RopBlock.from_chain(c)
                    rop_blocks.append(c)
                    break
                except RopException:
                    pass

            # take the first normalized shorter_chain
            for c in shorter_chains:
                try:
                    gadgets = self._expand_ropblocks(c)
                    c = self._build_reg_setting_chain(gadgets, {})
                    c = RopBlock.from_chain(c)
                    if dst not in shortest or c.stack_change < shortest[dst]:
                        shortest[dst] = c.stack_change
                        rop_blocks.append(c)
                        break
                except RopException:
                    pass
        return rop_blocks

    def _optimize_with_gadgets(self):
        new_blocks = set()
        shortest = {x:y[0] for x,y in self._reg_setting_dict.items() if y}
        arch_bytes = self.project.arch.bytes
        for gadget in itertools.chain(self._reg_setting_gadgets, self.chain_builder._reg_mover._reg_moving_gadgets):
            if gadget.self_contained and not gadget.has_symbolic_access():
                continue
            # check whether it introduces new capabilities
            rb = None
            new_pops = {x for x in gadget.popped_regs if not self._reg_setting_dict[x]}
            new_moves = {x for x in gadget.reg_moves if not self._reg_setting_dict[x.to_reg] and self._reg_setting_dict[x.from_reg]}
            if new_pops or new_moves:
                if new_moves:
                    for new_move in new_moves:
                        rb = self._normalize_for_move(gadget, new_move)
                        if rb is None:
                            continue
                        if new_move.to_reg in rb.popped_regs:
                            new_blocks.add(rb)
                            reg = new_move.to_reg
                            if reg not in shortest or rb.stack_change < shortest[reg].stack_change:
                                shortest[reg] = rb
                        else:
                            l.warning("normalizing \n%s does not yield any wanted new reg setting capability: %s", rb.dstr(), new_move.to_reg)
                else:
                    rb = self.normalize_gadget(gadget, post_preserve=new_pops)
                    if rb is None:
                        continue
                    if rb.popped_regs.intersection(new_pops):
                        new_blocks.add(rb)
                        for reg in new_pops:
                            if reg not in shortest or rb.stack_change < shortest[reg].stack_change:
                                shortest[reg] = rb
                    else:
                        l.warning("normalizing \n%s does not yield any wanted new reg setting capability: %s", rb.dstr(), new_pops)
                        continue

            # this means we tried to normalize the gadget but failed,
            # so don't try to do it again
            if any(reg not in shortest for reg in gadget.popped_regs):
                continue

            # check whether it shortens any chains
            better = False
            for reg in gadget.popped_regs:
                # it is unlikely we can use one more gadget to normalize it
                # usually it takes two (pop; ret), so account for it by - arch_ bytes
                if reg not in shortest or gadget.stack_change < shortest[reg].stack_change - arch_bytes:
                    # normalizing jmp_mem gadgets use a ton of gadgets, no need to even try
                    if gadget.transit_type == 'jmp_mem':
                        continue
                    elif gadget.transit_type == 'pop_pc':
                        better = True
                        break
                    elif gadget.transit_type == 'jmp_reg':
                        if gadget.pc_reg not in shortest:
                            continue
                        tmp = shortest[gadget.pc_reg]
                        if gadget.stack_change + tmp.stack_change < shortest[reg].stack_change:
                            better = True
                            break
            if better:
                if rb is None:
                    rb = self.normalize_gadget(gadget)
                if not rb:
                    continue
                for reg in rb.popped_regs:
                    if reg not in shortest or rb.stack_change < shortest[reg].stack_change:
                        shortest[reg] = rb
                        new_blocks.add(rb)
        return new_blocks

    def optimize(self, processes):
        # TODO: make it multiprocessing

        # now we have a functional RegSetter, check whether we can do better
        res = False

        # first, see whether we can use reg_mover to set registers
        rop_blocks = self._optimize_with_reg_moves()
        self._insert_to_reg_dict(rop_blocks)
        res |= bool(rop_blocks)

        # second, see whether we can use non-self-contained gadgets to set registers
        new_blocks = self._optimize_with_gadgets()
        self._insert_to_reg_dict(new_blocks)
        res |= bool(new_blocks)

        return res

    #### The Graph Search Algorithm ####
    def _reduce_graph(self, graph, regs):
        """
        TODO: maybe make the reduction smarter instead of just 5 gadgets each edge
        """
        regs = set(regs)
        def giga_graph_gadget_compare(g1, g2):
            if g1.stack_change < g2.stack_change:
                return -1
            if g1.stack_change > g2.stack_change:
                return 1
            side_effect1 = len(g1.changed_regs - regs)
            side_effect2 = len(g2.changed_regs - regs)
            if side_effect1 < side_effect2:
                return -1
            if side_effect1 > side_effect2:
                return 1
            return 0

        for edge in graph.edges:
            objects = graph.get_edge_data(*edge)['objects']
            objects = sorted(objects, key=cmp_to_key(giga_graph_gadget_compare))[:5]
            graph.get_edge_data(*edge)['objects'] = objects

    def find_candidate_chains_giga_graph_search(self, modifiable_memory_range, registers, preserve_regs, warn):
        if preserve_regs is None:
            preserve_regs = set()
        else:
            preserve_regs = preserve_regs.copy()

        registers = registers.copy()

        # handle hard registers
        gadgets = self._find_relevant_gadgets(allow_mem_access=modifiable_memory_range is not None, **registers)
        hard_chain = self._handle_hard_regs(gadgets, registers, preserve_regs)
        if not registers:
            return [hard_chain]

        # now do the giga graph search
        regs = sorted(list(registers.keys()))
        # build the target pops
        bit_map = {}
        for reg, val in registers.items():
            if self.project.arch.bits == 32 or val.symbolic:
                bits = self.project.arch.bits
            else:
                if (val.concreted >> 32) == 0:
                    bits = 32
                else:
                    bits = 64
            bit_map[reg] = bits

        graph = nx.DiGraph()

        # add all the nodes. here, each node represents a state where the corresponding register
        # is correctly set to the target value
        nodes = list(itertools.product((True, False), repeat=len(regs)))
        graph.add_nodes_from(nodes)

        def add_edge(src, dst, obj):
            assert type(obj) is not list
            if graph.has_edge(src, dst):
                objects = graph.get_edge_data(src, dst)['objects']
                if obj in objects:
                    return
                objects.add(obj)
            else:
                graph.add_edge(src, dst, objects={obj})

        def get_dst_node(src, reg_list, clobbered_regs):
            dst = list(src)
            for reg in reg_list:
                if reg not in regs:
                    continue
                idx = regs.index(reg)
                dst[idx] = True
            for reg in clobbered_regs:
                if reg not in regs:
                    continue
                idx = regs.index(reg)
                dst[idx] = False
            return tuple(dst)

        def can_set_regs(g):
            # ofc pops
            reg_set = set(pop.reg for pop in g.reg_pops if pop.reg not in bit_map or pop.bits >= bit_map[pop.reg])
            # if concrete values happen to match
            for reg in regs:
                if registers[reg].symbolic:
                    continue
                if reg in g.concrete_regs and g.concrete_regs[reg] == registers[reg].concreted:
                    reg_set.add(reg)
            return reg_set

        # add edges for pops and concrete values
        total_reg_set = set()
        for g in gadgets:
            if isinstance(g, RopGadget) and not g.self_contained:
                continue
            reg_set = can_set_regs(g)
            for unique_reg_set in list(itertools.product(*g.pop_equal_set)):
                unique_reg_set = set(unique_reg_set)
                unique_reg_set = unique_reg_set.intersection(reg_set)
                clobbered_regs = g.changed_regs - unique_reg_set
                # don't add the edge if changes registers that we want to preserve
                if g.changed_regs.intersection(preserve_regs):
                    continue
                total_reg_set.update(unique_reg_set)
                for n in nodes:
                    src_node = n
                    dst_node = get_dst_node(n, unique_reg_set, clobbered_regs)
                    if src_node == dst_node:
                        continue
                    # greedy algorithm: only add edges that transit to an at least equally good node
                    src_cnt = len([x for x in src_node if x is True])
                    dst_cnt = len([x for x in dst_node if x is True])
                    if dst_cnt >= src_cnt:
                        add_edge(src_node, dst_node, g)

        # bad, we can't set all registers, no need to try
        to_set_reg_set = set(registers.keys())
        if to_set_reg_set - total_reg_set:
            if warn:
                l.warning("fail to cover all registers using giga_graph_search!\nregister covered: %s, registers to set: %s", total_reg_set, to_set_reg_set)
            return []

        self._reduce_graph(graph, regs)

        # TODO: the ability to set a register using concrete_values and then move it to another
        # currently, we don't have a testcase that needs this

        # now find all paths between the src and dst node
        src = tuple([False] * len(regs))
        dst = tuple([True] * len(regs))

        chains = [] # here, each "chain" is a list of gadgets
        try:
            paths = nx.all_simple_paths(graph, source=src, target=dst, cutoff=min(len(registers)+2, 6))
            for path in paths:
                if hard_chain:
                    tmp = [[x] for x in hard_chain]
                else:
                    tmp = []
                edges = zip(path, path[1:])
                for edge in edges:
                    objects = graph.get_edge_data(edge[0], edge[1])['objects']
                    tmp.append(objects)
                # for each path, take the shortest 5 chains
                path_chains = itertools.product(*tmp)
                path_chains = sorted(path_chains, key=lambda c: sum(g.stack_change for g in c))[:5]
                chains += path_chains
            chains = list(chains)
        except nx.exception.NetworkXNoPath:
            return []

        # then sort them by stack_change
        chains = sorted(chains, key=lambda c: sum(g.stack_change for g in c))
        return chains

    def _find_relevant_gadgets(self, allow_mem_access=True, **registers):
        """
        find gadgets that may pop/load/change requested registers
        """
        gadgets = set()

        # this step will add crafted rop_blocks as well
        # notice that this step only include rop_blocks that can
        # POP the register
        for reg in registers:
            gadgets.update(self._reg_setting_dict[reg])

        # add all other gadgets that may be relevant,
        # including gadgets that set concrete values
        for g in self._reg_setting_gadgets:
            if not allow_mem_access and g.has_symbolic_access():
                continue
            # TODO: normalize these, use badbyte test as the testcase
            if g.oop:
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

    def _handle_hard_regs(self, gadgets, registers, preserve_regs):
        # handle register set that contains bad byte (so it can't be popped)
        # and cannot be directly set using concrete values
        hard_regs = [reg for reg, val in registers.items() if self._word_contain_badbyte(val)]
        if len(hard_regs) > 1:
            l.error("too many registers contain bad bytes! bail out! %s", registers)
            raise RopException("too many registers contain bad bytes")
        if not hard_regs:
            return
        if registers[hard_regs[0]].symbolic:
            return

        # if hard_regs exists, try to use concrete values to craft the value
        hard_chain = []
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
            if hard_chain:
                self.hard_chain_cache[key] = hard_chain # we cache the result even if it fails
        if not hard_chain:
            l.error("Fail to set register: %s to: %#x", reg, val)
            raise RopException("Fail to set hard registers")
        registers.pop(reg)
        return hard_chain

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
                    chain = self._build_reg_setting_chain([g1, g2], {reg: val})
                    state = chain.exec()
                    bv = state.registers.load(reg)
                    if bv.symbolic:
                        continue
                    if state.solver.eval(bv == val.data):
                        return [g1, g2]
                except Exception:# pylint:disable=broad-except
                    pass
        return None

    #### Gadget Filtering ####

    def _effect_tuple(self, g):
        v1 = tuple(sorted(g.popped_regs))
        v2 = tuple(sorted(g.concrete_regs.items()))
        v3 = []
        for x,y in g.reg_dependencies.items():
            v3.append((x, tuple(sorted(y))))
        v3 = tuple(sorted(v3))
        v4 = g.transit_type
        return (v1, v2, v3, v4)

    def _comparison_tuple(self, g):
        return (len(g.changed_regs-g.popped_regs), g.stack_change, g.num_sym_mem_access,
                   g.isn_count, int(g.has_conditional_branch is True))

    def _same_effect(self, g1, g2):
        if g1.popped_regs != g2.popped_regs:
            return False
        if g1.concrete_regs != g2.concrete_regs:
            return False
        if g1.reg_dependencies != g2.reg_dependencies:
            return False
        if g1.transit_type != g2.transit_type:
            return False
        return True

    def filter_gadgets(self, gadgets):
        """
        process gadgets based on their effects
        exclude gadgets that do symbolic memory access
        """
        gadgets = [g for g in gadgets if g.popped_regs or g.concrete_regs]
        results = self._filter_gadgets(gadgets)
        return results

    #### Main Entrance ####
    def run(self, modifiable_memory_range=None, preserve_regs=None, warn=True, **registers):
        if len(registers) == 0:
            return RopChain(self.project, self, badbytes=self.badbytes)

        # sanity check
        preserve_regs = set(preserve_regs) if preserve_regs else set()
        unknown_regs = set(registers.keys()).union(preserve_regs) - set(self.arch.reg_list)
        if unknown_regs:
            raise RopException("unknown registers: %s" % unknown_regs)

        # cast values to RopValue
        for x in registers:
            registers[x] = rop_utils.cast_rop_value(registers[x], self.project)

        for gadgets in self.find_candidate_chains_giga_graph_search(modifiable_memory_range, registers, preserve_regs, warn):
            chain_str = "\n".join(g.dstr() for g in gadgets)
            l.debug("building reg_setting chain with chain:\n%s", chain_str)
            try:
                gadgets = self._expand_ropblocks(gadgets)
                chain = self._build_reg_setting_chain(gadgets, registers)
                if self.verify(chain, preserve_regs, registers):
                    return chain
            except (RopException, SimUnsatError):
                pass

        raise RopException("Couldn't set registers :(")
