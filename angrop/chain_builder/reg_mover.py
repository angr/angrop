import logging
import itertools
import multiprocessing as mp
from collections import defaultdict

import networkx as nx
from angr.errors import SimUnsatError

from .builder import Builder
from .. import rop_utils
from ..rop_chain import RopChain
from ..rop_block import RopBlock
from ..errors import RopException
from ..rop_effect import RopRegMove

l = logging.getLogger(__name__)

_global_reg_mover = None
def _set_global_reg_mover(reg_mover, ptr_list):
    global _global_reg_mover# pylint: disable=global-statement
    _global_reg_mover = reg_mover
    Builder.used_writable_ptrs = ptr_list

def worker_func(t):
    new_move, gadget = t
    gadget.project = _global_reg_mover.project
    pre_preserve = {new_move.from_reg}
    post_preserve = {new_move.to_reg}
    rb = _global_reg_mover.normalize_gadget(gadget, pre_preserve=pre_preserve, post_preserve=post_preserve)
    solver = None
    if rb is not None:
        solver = rb._blank_state.solver
    return new_move, gadget.addr, solver, rb

class RegMover(Builder):
    """
    handle register moves such as `mov rax, rcx`
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)
        self._reg_moving_gadgets = None
        self._reg_moving_blocks: set[RopBlock] = None # type: ignore
        self._graph: nx.Graph = None # type: ignore
        self._normalize_todos = {}

    def bootstrap(self):
        self._reg_moving_gadgets = sorted(self.filter_gadgets(self.chain_builder.gadgets), key=lambda g:g.stack_change)
        self._reg_moving_blocks = {g for g in self._reg_moving_gadgets if g.self_contained}
        self._build_move_graph()

    def build_normalize_todos(self):
        """
        identify non-self-contained gadgets that can potentially improve
        our register move graph
        """
        self._normalize_todos = {}
        todos = {}
        for gadget in self._reg_moving_gadgets:
            if gadget.self_contained:
                continue
            # check whether the gadget brings new_moves:
            # 1. the edge doesn't exist at all
            # 2. it moves more bits than all existing ones
            # TODO: 3. fewer clobbered registers?
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
            for new_move in new_moves:
                if new_move in todos:
                    todos[new_move].append(gadget)
                else:
                    todos[new_move] = [gadget]

        # only normalize best ones
        to_remove = []
        for m1 in todos:
            for m2 in todos:
                if m1 == m2:
                    continue
                if m1.from_reg == m2.from_reg and m1.to_reg == m2.to_reg and m1.bits < m2.bits:
                    to_remove.append(m1)
        for m in to_remove:
            del todos[m]

        # we use address as key here instead of gadget because the gadget
        # returned by multiprocessing may be different from the original one
        for m, gadgets in todos.items():
            for g in gadgets:
                new_moves = [m for m in g.reg_moves if m in todos]
                self._normalize_todos[g.addr] = (g, new_moves)

    def normalize_todos(self):
        addrs = sorted(self._normalize_todos.keys())
        again = True
        while again:
            cnt = 0
            for addr in addrs:
                # take different gadgets to maximize performance
                g, new_moves = self._normalize_todos[addr]
                if new_moves:
                    new_move = new_moves.pop()
                    cnt += 1
                    yield new_move, g
            if cnt == 0:
                again = False

    def normalize_single_threaded(self):
        for new_move, gadget in self.normalize_todos():
            gadget.project = self.project
            pre_preserve = {new_move.from_reg}
            post_preserve = {new_move.to_reg}
            rb = self.normalize_gadget(gadget, pre_preserve=pre_preserve, post_preserve=post_preserve)
            if rb is not None:
                yield new_move, gadget.addr, rb

    def normalize_multiprocessing(self, processes):
        with mp.Manager() as manager:
            # HACK: ideally, used_ptrs should be a resource of each ropblock that can be reassigned when conflict happens
            # but currently, I'm being lazy and just make sure every pointer is different
            ptr_list = manager.list(Builder.used_writable_ptrs)
            initargs = (self, ptr_list)
            with mp.Pool(processes=processes, initializer=_set_global_reg_mover, initargs=initargs) as pool:
                for new_move, addr, solver, rb in pool.imap_unordered(worker_func, self.normalize_todos()):
                    if rb is None:
                        continue
                    state = rop_utils.make_symbolic_state(self.project, self.arch.reg_list, 0)
                    state.solver = solver
                    rb.set_project(self.project)
                    rb.set_builder(self)
                    rb._blank_state = state
                    yield new_move, addr, rb
            Builder.used_writable_ptrs = list(ptr_list)

    def optimize(self, processes):
        res = False
        self.build_normalize_todos()
        if processes == 1:
            iterable = self.normalize_single_threaded()
        else:
            iterable = self.normalize_multiprocessing(processes)
        for new_move, addr, rb in iterable:
            # if we happen to have normalized another move, don't do it again
            for m in rb.reg_moves:
                todo_new_moves = self._normalize_todos[addr][1]
                if m in todo_new_moves:
                    todo_new_moves.remove(m)
            # now we have this new_move, remove it from the todo list
            for m in rb.reg_moves:
                for addr in self._normalize_todos:
                    new_moves = self._normalize_todos[addr][1]
                    if m in new_moves:
                        new_moves.remove(m)
            # we already normalized it, just use it as much as we can
            if rb.popped_regs:
                self.chain_builder._reg_setter._insert_to_reg_dict([rb])
            if not any(m == new_move for m in rb.reg_moves):
                l.warning("normalizing \n%s does not yield any wanted new reg moving capability: %s", rb.dstr(), new_move)
                continue
            res = True
            for move in rb.reg_moves:
                edge = (move.from_reg, move.to_reg)
                if self._graph.has_edge(*edge):
                    edge_data = self._graph.get_edge_data(*edge)
                    edge_blocks = edge_data['block']
                    edge_blocks.append(rb)
                    edge_data['block'] = sorted(edge_blocks, key=lambda x: x.stack_change)
                    if move.bits > edge_data['bits']:
                        edge_data['bits'] = move.bits
                else:
                    self._graph.add_edge(*edge, block=[rb], bits=move.bits)
        return res

    def _build_move_graph(self):
        self._graph = nx.DiGraph()
        graph = self._graph
        # each node is a register
        graph.add_nodes_from(self.arch.reg_list)
        # an edge means there is a move from the src register to the dst register
        objects = defaultdict(list)
        max_bits_dict = defaultdict(int)
        for block in self._reg_moving_blocks:
            for move in block.reg_moves:
                edge = (move.from_reg, move.to_reg)
                objects[edge].append(block)
                if move.bits > max_bits_dict[edge]:
                    max_bits_dict[edge] = move.bits
        for edge, val in objects.items():
            val = sorted(val, key=lambda g:g.stack_change)
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
                    if act.addr.ast.variables and any(not x.startswith('sym_addr') for x in act.addr.ast.variables):
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
        unknown_regs = set(registers.keys()).union(preserve_regs) - set(self.arch.reg_list)
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
                    chain = self._build_reg_setting_chain(gs, {})
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
        gadgets = {g for g in gadgets if g.reg_moves and not g.has_conditional_branch and not g.has_symbolic_access()}
        gadgets = self._filter_gadgets(gadgets)
        new_gadgets = set(x for x in gadgets if any(y.from_reg != y.to_reg for y in x.reg_moves))
        return new_gadgets

    def _effect_tuple(self, g):
        v1 = tuple(sorted(g.reg_moves))
        v2 = []
        for x,y in g.reg_dependencies.items():
            v2.append((x, tuple(sorted(y))))
        v2 = tuple(sorted(v2))
        return (v1, v2)

    def _comparison_tuple(self, g):
        return (g.stack_change, g.num_sym_mem_access, rop_utils.transit_num(g), g.isn_count)