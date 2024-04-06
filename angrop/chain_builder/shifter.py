import logging
from collections import defaultdict

from .builder import Builder
from ..rop_chain import RopChain
from ..errors import RopException

l = logging.getLogger(__name__)

class Shifter(Builder):
    """
    A class to find stack shifting gadgets, like add rsp; ret or pop chains
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)

        self.shift_gadgets = None
        self.update()

    def update(self):
        self.shift_gadgets = self._filter_gadgets(self.chain_builder.gadgets)

    def verify_shift(self, chain, length, preserve_regs):
        arch_bytes = self.project.arch.bytes
        init_sp = chain._blank_state.regs.sp.concrete_value - len(chain._values) * arch_bytes
        state = chain.exec()
        if state.regs.sp.concrete_value != init_sp + length + arch_bytes:
            return False
        for act in state.history.actions:
            if act.type != 'reg' or act.action != 'write':
                continue
            offset = act.offset
            offset -= act.offset % self.project.arch.bytes
            reg_name = self.project.arch.translate_register_name(offset)
            if reg_name in preserve_regs:
                chain_str = '\n-----\n'.join([str(self.project.factory.block(g.addr).capstone)for g in chain._gadgets])
                l.exception("Somehow angrop thinks \n%s\n can be used for the chain generation.", chain_str)
                return False
        return True

    def verify_retsled(self, chain, size, preserve_regs):
        if len(chain.payload_str()) != size:
            return False
        state = chain.exec()
        for act in state.history.actions:
            if act.type != 'reg' or act.action != 'write':
                continue
            offset = act.offset
            offset -= act.offset % self.project.arch.bytes
            reg_name = self.project.arch.translate_register_name(offset)
            if reg_name == self.arch.stack_pointer:
                continue
            if reg_name in preserve_regs:
                chain_str = '\n-----\n'.join([str(self.project.factory.block(g.addr).capstone)for g in chain._gadgets])
                l.exception("Somehow angrop thinks \n%s\n can be used for the chain generation.", chain_str)
                return False
        return True

    @staticmethod
    def same_effect(g1, g2):
        if g1.stack_change != g2.stack_change:
            return False
        if g1.transit_type != g2.transit_type:
            return False
        return True

    def shift(self, length, preserve_regs=None):
        preserve_regs = set(preserve_regs) if preserve_regs else set()
        arch_bytes = self.project.arch.bytes

        if length % arch_bytes != 0:
            raise RopException("Currently, we do not support shifting misaligned sp change")
        if length not in self.shift_gadgets or \
            all(preserve_regs.intersection(x.changed_regs) for x in self.shift_gadgets[length]):
            raise RopException("Encounter a shifting request that requires chaining multiple shifting gadgets " +
                               "together which is not support atm. Plz create an issue on GitHub " +
                               "so we can add the support!")
        for g in self.shift_gadgets[length]:
            if preserve_regs.intersection(g.changed_regs):
                continue
            try:
                chain = RopChain(self.project, self.chain_builder)
                chain.add_gadget(g)
                for _ in range(g.stack_change//arch_bytes-1):
                    chain.add_value(self._get_fill_val())
                if self.verify_shift(chain, length, preserve_regs):
                    return chain
            except RopException:
                continue

        raise RopException(f"Failed to shift sp for {length:#x} bytes while preserving {preserve_regs}")

    def retsled(self, size, preserve_regs=None):
        preserve_regs = set(preserve_regs) if preserve_regs else set()
        arch_bytes = self.project.arch.bytes

        if size % arch_bytes != 0:
            raise RopException("the size of a retsled must be word aligned")
        if not self.shift_gadgets[arch_bytes]:
            raise RopException("fail to find a ret-equivalent gadget in this binary!")
        for g in self.shift_gadgets[arch_bytes]:
            try:
                chain = RopChain(self.project, self.chain_builder)
                for _ in range(size//arch_bytes):
                    chain.add_gadget(g)
                if self.verify_retsled(chain, size, preserve_regs):
                    return chain
            except RopException:
                continue

        raise RopException(f"Failed to create a ret-sled sp for {size:#x} bytes while preserving {preserve_regs}")

    def better_than(self, g1, g2):
        if not self.same_effect(g1, g2):
            return False
        return g1.changed_regs.issubset(g2.changed_regs)

    def _filter_gadgets(self, gadgets):
        """
        filter gadgets having the same effect
        """
        # we don't like gadgets with any memory accesses or jump gadgets
        gadgets = [x for x in gadgets if x.num_mem_access == 0 and x.transit_type != 'jmp_reg']

        # now do the standard filtering
        gadgets = set(gadgets)
        skip = set({})
        while True:
            to_remove = set({})
            for g in gadgets-skip:
                to_remove.update({x for x in gadgets-{g} if self.better_than(g, x)})
                if to_remove:
                    break
                skip.add(g)
            if not to_remove:
                break
            gadgets -= to_remove

        d = defaultdict(list)
        for g in gadgets:
            d[g.stack_change].append(g)
        for x in d:
            d[x] = sorted(d[x], key=lambda g: len(g.changed_regs))
        return d
