import logging
from collections import defaultdict

from .. import rop_utils
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

    def update(self):
        self.shift_gadgets = self.filter_gadgets(self.chain_builder.gadgets)

    def verify_shift(self, chain, length, preserve_regs):
        arch_bytes = self.project.arch.bytes
        init_sp = chain._blank_state.regs.sp.concrete_value
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
                chain_str = chain.dstr()
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
                chain_str = chain.dstr()
                l.exception("Somehow angrop thinks \n%s\n can be used for the chain generation.", chain_str)
                return False
        return True

    def shift(self, length, preserve_regs=None, next_pc_idx=-1):
        """
        length:         how many bytes to shift
        preserve_regs:  what registers not to clobber
        next_pc_idx:    where is the next pc, e.g for ret, it is -1
        """
        preserve_regs = set(preserve_regs) if preserve_regs else set()
        arch_bytes = self.project.arch.bytes

        if length % arch_bytes != 0:
            raise RopException("Currently, we do not support shifting misaligned sp change")
        if length not in self.shift_gadgets or \
            all(preserve_regs.intersection(x.changed_regs) for x in self.shift_gadgets[length]):
            raise RopException("Encounter a shifting request that requires chaining multiple shifting gadgets " +
                               "together which is not support atm. Plz create an issue on GitHub " +
                               "so we can add the support!")
        g_cnt = length // arch_bytes
        next_pc_idx = (next_pc_idx % g_cnt + g_cnt) % g_cnt # support negative indexing
        for g in self.shift_gadgets[length]:
            if preserve_regs.intersection(g.changed_regs):
                continue
            if g.transit_type != 'pop_pc':
                continue
            if g.pc_offset != next_pc_idx*arch_bytes:
                continue
            try:
                chain = RopChain(self.project, self.chain_builder)
                chain.add_gadget(g)
                for idx in range(g_cnt):
                    if idx != next_pc_idx:
                        chain.add_value(self._get_fill_val())
                    else:
                        next_pc_val = rop_utils.cast_rop_value(
                            chain._blank_state.solver.BVS("next_pc", self.project.arch.bits),
                            self.project,
                        )
                        chain.add_value(next_pc_val)
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

    def _same_effect(self, g1, g2):
        if g1.stack_change != g2.stack_change:
            return False
        if g1.transit_type != g2.transit_type:
            return False
        if g1.pc_offset != g2.pc_offset:
            return False
        return True

    def _better_than(self, g1, g2):
        if g1.num_mem_access > g2.num_mem_access:
            return False
        if not g1.changed_regs.issubset(g2.changed_regs):
            return False
        if g1.isn_count > g2.isn_count:
            return False
        return True

    def filter_gadgets(self, gadgets):
        """
        filter gadgets having the same effect
        """
        # we don't like gadgets with any memory accesses
        gadgets = [
            x
            for x in gadgets
            if x.num_mem_access == 0
            and x.self_contained
        ]

        gadgets = self._filter_gadgets(gadgets)

        d = defaultdict(list)
        for g in gadgets:
            d[g.stack_change].append(g)
        for x in d:
            d[x] = sorted(d[x], key=lambda g: len(g.changed_regs))
        return d
