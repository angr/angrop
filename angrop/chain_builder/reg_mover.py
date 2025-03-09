import logging
import itertools
from collections import defaultdict

import networkx as nx
from angr.errors import SimUnsatError

from .builder import Builder
from .. import rop_utils
from ..rop_chain import RopChain
from ..rop_block import RopBlock
from ..errors import RopException
from ..rop_gadget import RopRegMove

l = logging.getLogger(__name__)

class RegMover(Builder):
    """
    handle register moves such as `mov rax, rcx`
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)
        self._reg_moving_gadgets = None
        self._reg_moving_blocks: set[RopBlock] = None # type: ignore
        self._graph: nx.Graph = None # type: ignore

    def bootstrap(self):
        self._reg_moving_gadgets = sorted(self.filter_gadgets(self.chain_builder.gadgets), key=lambda g:g.stack_change)
        self._reg_moving_blocks = {g for g in self._reg_moving_gadgets if g.self_contained}
        self._build_move_graph()

    def optimize(self):
        for gadget in self._reg_moving_gadgets:
            if gadget.self_contained:
                continue

            # check whether the gadget brings new_moves:
            # 1. the edge doesn't exist at all
            # 2. it moves more bits than all existing ones
            new_moves = []
            for m in gadget.reg_moves:
                edge = (m.from_reg, m.to_reg)
                if not self._graph.has_edge(*edge):
                    new_moves.append(m)
                    continue
                edge_data = self._graph.get_edge_data(*edge)
                if m.bits > edge_data['bits']:
                    new_moves.append(m)
                    continue

            if not new_moves:
                continue
            preserve_regs = {m.from_reg for m in new_moves}
            rb = self.normalize_gadget(gadget, pre_preserve=preserve_regs)
            if rb is None:
                continue
            for move in rb.reg_moves:
                edge = (move.from_reg, move.to_reg)
                if self._graph.has_edge(*edge):
                    edge_data = self._graph.get_edge_data(*edge)
                    edge_blocks = edge_data['block']
                    edge_blocks.add(rb)
                    if move.bits > edge_data['bits']:
                        edge_data['bits'] = move.bits
                else:
                    self._graph.add_edge(*edge, block={rb}, bits=move.bits)

    def _build_move_graph(self):
        self._graph = nx.DiGraph()
        graph = self._graph
        # each node is a register
        graph.add_nodes_from(self.arch.reg_set)
        # an edge means there is a move from the src register to the dst register
        objects = defaultdict(set)
        max_bits_dict = defaultdict(int)
        for block in self._reg_moving_blocks:
            for move in block.reg_moves:
                edge = (move.from_reg, move.to_reg)
                objects[edge].add(block)
                if move.bits > max_bits_dict[edge]:
                    max_bits_dict[edge] = move.bits
        for edge, val in objects.items():
            graph.add_edge(edge[0], edge[1], block=val, bits=max_bits_dict[edge])

    def verify(self, chain, preserve_regs, registers):
        """
        given a potential chain, verify whether the chain can move the registers correctly by symbolically
        execute the chain
        """
        chain_str = chain.dstr()
        state = chain.exec()
        for reg, val in registers.items():
            bv = getattr(state.regs, reg)
            if bv.depth != 1 or type(bv.args[0]) != str or val.reg_name not in bv._encoded_name.decode():
                l.exception("Somehow angrop thinks \n%s\n can be used for the chain generation.", chain_str)
                return False
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
                        l.exception("Somehow angrop thinks \n%s\n can be used for the chain generation.", chain_str)
                        return False
        # the next pc must be "next_pc"
        if len(state.regs.pc.variables) != 1:
            return False
        if not set(state.regs.pc.variables).pop().startswith("next_pc_"):
            return False
        return True

    def _recursively_find_chains(self, gadgets, chain, source_regs, hard_preserve_regs, todo_moves):
        """
        source_regs: registers that contain the original values of the source registers
        """
        # FIXME: what if the first gadget moves the second move.from_reg to another reg?
        if not todo_moves:
            return [chain]

        todo_list = []
        for g in gadgets:
            new_moves = set(g.reg_moves).intersection(todo_moves)
            if not new_moves:
                continue
            if g.changed_regs.intersection(hard_preserve_regs):
                continue
            new_source_regs = set()
            for move in new_moves:
                if move.from_reg in source_regs:
                    new_source_regs.add(move.to_reg)
            g_source_regs = source_regs.copy()
            g_source_regs -= g.changed_regs
            g_source_regs.update(new_source_regs)
            new_todo_moves = todo_moves - new_moves
            if any(m.from_reg not in g_source_regs for m in new_todo_moves):
                continue
            new_preserve = hard_preserve_regs.copy()
            new_preserve.update({x.to_reg for x in new_moves})
            new_chain = chain.copy()
            new_chain.append(g)
            todo_list.append((new_chain, g_source_regs, new_preserve, new_todo_moves))

        res = []
        for todo in todo_list:
            res += self._recursively_find_chains(gadgets, *todo)
        return res

    def run(self, preserve_regs=None, **registers):
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

        # find all blocks that are relevant to our moves
        assert all(val.is_register for _, val in registers.items())
        moves = {RopRegMove(val.reg_name, reg, self.project.arch.bits) for reg, val in registers.items()}
        rop_blocks = self._find_relevant_blocks(moves)

        # use greedy algorithm to find a chain that can do all the moves
        source_regs = {x.from_reg for x in moves}
        chains = self._recursively_find_chains(rop_blocks, [], source_regs, preserve_regs.copy(), moves)
        chains = self._sort_chains(chains)

        # now see whether any of the chain candidates can work
        for rop_blocks in chains:
            chain_str = "\n".join(g.dstr() for g in rop_blocks)
            l.debug("building reg_setting chain with chain:\n%s", chain_str)
            try:
                rb = rop_blocks[0]
                for x in rop_blocks[1:]:
                    rb += x
                if self.verify(rb, preserve_regs, registers):
                    return rb
            except (RopException, SimUnsatError):
                pass

        raise RopException("Couldn't move registers :(")

    def _find_relevant_blocks(self, target_moves):
        """
        find rop_blocks that may perform any of the requested moves
        """
        rop_blocks = set()

        # handle moves using graph search, this allows gadget chaining
        # to perform hard moves that requires multiple gadgets
        graph = self._graph
        for move in target_moves:
            # only consider the shortest path
            # TODO: we should use longer paths if the shortest one does work
            try:
                paths = nx.all_shortest_paths(graph, source=move.from_reg, target=move.to_reg)
                block_gadgets = []
                for path in paths:
                    edges = zip(path, path[1:])
                    edge_block_list = []
                    for edge in edges:
                        edge_blocks = graph.get_edge_data(edge[0], edge[1])['block']
                        edge_block_list.append(edge_blocks)
                    block_gadgets += list(itertools.product(*edge_block_list))

                # now turn them into blocks
                for gs in block_gadgets:
                    assert gs
                    # FIXME: we are using the _build_reg_setting_chain API to turn mixin lists to a RopBlock
                    # which is pretty wrong
                    chain = self._build_reg_setting_chain(gs, None, {})
                    rb = RopBlock.from_chain(chain)
                    rop_blocks.add(rb)
            except nx.exception.NetworkXNoPath:
                raise RopException(f"There is no chain can move {move.from_reg} to {move.to_reg}")
        return rop_blocks

    def filter_gadgets(self, gadgets):
        """
        filter gadgets having the same effect
        """
        # first: filter out gadgets that don't do register move
        gadgets = {g for g in gadgets if g.reg_moves and not g.has_conditional_branch and (not g.has_symbolic_access() or g.transit_type == 'jmp_mem')}
        gadgets = self._filter_gadgets(gadgets)
        new_gadgets = set(x for x in gadgets if any(y.from_reg != y.to_reg for y in x.reg_moves))
        return new_gadgets

    def _same_effect(self, g1, g2):
        """
        having the same register moving effect compared to the other gadget
        """
        if set(g1.reg_moves) != set(g2.reg_moves):
            return False
        if g1.reg_dependencies != g2.reg_dependencies:
            return False
        return True

    def _better_than(self, g1, g2):
        if g1.stack_change <= g2.stack_change and \
                g1.num_sym_mem_access <= g2.num_sym_mem_access and \
                g1.isn_count <= g2.isn_count:
            return True
        return False
