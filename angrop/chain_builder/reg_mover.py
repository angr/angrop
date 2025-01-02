import logging

from angr.errors import SimUnsatError

from .builder import Builder
from .. import rop_utils
from ..rop_chain import RopChain
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
        self.update()

    def update(self):
        self._reg_moving_gadgets = self._filter_gadgets(self.chain_builder.gadgets)

    def verify(self, chain, preserve_regs, registers):
        """
        given a potential chain, verify whether the chain can move the registers correctly by symbolically
        execute the chain
        """
        state = chain.exec()
        for reg, val in registers.items():
            bv = getattr(state.regs, reg)
            if bv.depth != 1 or val.reg_name not in bv._encoded_name.decode():
                chain_str = '\n-----\n'.join([str(self.project.factory.block(g.addr).capstone)for g in chain._gadgets])
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
        # the next pc must come from the stack
        if len(state.regs.pc.variables) != 1:
            return False
        if not set(state.regs.pc.variables).pop().startswith("symbolic_stack"):
            return False
        return True

    def _recursively_find_chains(self, gadgets, chain, hard_preserve_regs, todo_moves):
        if not todo_moves:
            return [chain]

        todo_list = []
        for g in gadgets:
            new_moves = set(g.reg_moves).intersection(todo_moves)
            if not new_moves:
                continue
            if g.changed_regs.intersection(hard_preserve_regs):
                continue
            new_preserve = hard_preserve_regs.copy()
            new_preserve.update({x.to_reg for x in new_moves})
            new_chain = chain.copy()
            new_chain.append(g)
            todo_list.append((new_chain, new_preserve, todo_moves-new_moves))

        res = []
        for todo in todo_list:
            res += self._recursively_find_chains(gadgets, *todo)
        return res

    def run(self, preserve_regs=None, **registers):
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

        # find all gadgets that are *directly* relevant to our moves
        # TODO: we currently do not support chaining moves like mov eax, ecx; mov esp, eax; to set esp to ecx
        assert all(val.is_register for _, val in registers.items())
        moves = {RopRegMove(val.reg_name, reg, self.project.arch.bits) for reg, val in registers.items()}
        gadgets = self._find_relevant_gadgets(moves)

        # use greedy algorithm to find a chain that can do all the moves
        chains = self._recursively_find_chains(gadgets, [], preserve_regs.copy(), moves)
        chains = self._sort_chains(chains)

        # now see whether any of the chain candidates can work
        for gadgets in chains:
            chain_str = '\n-----\n'.join([str(self.project.factory.block(g.addr).capstone)for g in gadgets])
            l.debug("building reg_setting chain with chain:\n%s", chain_str)
            stack_change = sum(x.stack_change for x in gadgets)
            try:
                chain = self._build_reg_setting_chain(gadgets, None, registers, stack_change)
                chain._concretize_chain_values()
                if self.verify(chain, preserve_regs, registers):
                    return chain
            except (RopException, SimUnsatError):
                pass

        raise RopException("Couldn't move registers :(")

    @staticmethod
    def _filter_gadgets(gadgets):
        """
        filter gadgets having the same effect
        """
        gadgets = {g for g in gadgets if not g.has_conditional_branch}
        # first: filter out gadgets that don't do register move
        gadgets = set(x for x in gadgets if x.reg_moves)
        # # second: remove gadgets that are strictly worse than some others
        # skip = set({})
        # while True:
        #     to_remove = set({})
        #     for g in gadgets-skip:
        #         to_remove.update({x for x in gadgets-{g} if g.reg_move_better_than(x)})
        #         if to_remove:
        #             break
        #         skip.add(g)
        #     if not to_remove:
        #         break
        #     gadgets -= to_remove
        # third: remove gadgets that only move from itself to itself, it is not helpful
        # for exploitation
        new_gadgets = set(x for x in gadgets if any(y.from_reg != y.to_reg for y in x.reg_moves))
        return new_gadgets

    def _find_relevant_gadgets(self, moves):
        """
        find gadgets that may directly perform any of the requested moves
        """
        gadgets = set()
        for g in self._reg_moving_gadgets:
            if g.has_symbolic_access():
                continue
            if moves.intersection(set(g.reg_moves)):
                gadgets.add(g)
        return gadgets
