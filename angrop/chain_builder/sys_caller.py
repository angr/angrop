import logging
import functools

import angr

from .func_caller import FuncCaller
from ..errors import RopException
from ..import rop_utils

l = logging.getLogger(__name__)

def cmp(g1, g2):
    if g1.can_return and not g2.can_return:
        return -1
    if not g1.can_return and g2.can_return:
        return 1

    if g1.num_sym_mem_access < g2.num_sym_mem_access:
        return -1
    if g1.num_sym_mem_access > g2.num_sym_mem_access:
        return 1

    if g1.stack_change < g2.stack_change:
        return -1
    if g1.stack_change > g2.stack_change:
        return 1

    if g1.isn_count < g2.isn_count:
        return -1
    if g1.isn_count > g2.isn_count:
        return 1
    return 0

class SysCaller(FuncCaller):
    """
    handle linux system calls invocations
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)

        self.syscall_gadgets: list = None # type: ignore
        self.sysnum_reg = self.project.arch.register_names[self.project.arch.syscall_num_offset]

    @staticmethod
    def supported_os(os):
        return "unix" in os.lower()

    def bootstrap(self):
        self.syscall_gadgets = self.filter_gadgets(self.chain_builder.syscall_gadgets)

    @staticmethod
    def verify(chain, registers, preserve_regs):
        # these registers are marked as preserved, so they are set by the user
        # don't verify them here
        registers = dict(registers)
        for reg in preserve_regs:
            if reg in registers:
                del registers[reg]
        try:
            state = chain.sim_exec_til_syscall()
        except RuntimeError:
            chain_str = chain.dstr()
            l.exception("Somehow angrop thinks\n%s\ncan be used for syscall chain generation-1.\nregisters: %s",
                        chain_str, registers)
            return False

        if state is None:
            return False

        for reg, val in registers.items():
            bv = getattr(state.regs, reg)
            if (val.symbolic != bv.symbolic) or state.solver.eval(bv != val.data):
                chain_str = chain.dstr()
                l.exception("Somehow angrop thinks\n%s\ncan be used for syscall chain generation-2.\nregisters: %s",
                            chain_str, registers)
                return False

        return True

    def filter_gadgets(self, gadgets) -> list: # pylint: disable=no-self-use
        # currently, we don't support negative stack_change
        # syscall gadgets
        gadgets = list({g for g in gadgets if g.stack_change >= 0})
        return sorted(gadgets, key=functools.cmp_to_key(cmp))

    def _try_invoke_execve(self, path_addr):
        execve_syscall = self.chain_builder.arch.execve_num
        # next, try to invoke execve(path, ptr, ptr), where ptr points is either NULL or nullptr
        if 0 not in self.badbytes:
            ptr = 0
        else:
            nullptr = self._get_ptr_to_null()
            ptr = nullptr

        try:
            return self.do_syscall(execve_syscall, [path_addr, ptr, ptr], needs_return=False)
        except RopException:
            pass

        raise RopException("Fail to invoke execve!")

    def execve(self, path=None, path_addr=None):
        if self.project.simos.name != 'Linux':
            raise RopException(f"{self.project.simos.name} is not supported!")
        if not self.syscall_gadgets:
            raise RopException("target does not contain syscall gadget!")

        # determine the execution path
        if path is None:
            path = b"/bin/sh\x00"
        if path[-1] != 0:
            path += b"\x00"

        # look for a good buffer to store the payload
        if path_addr:
            if self._word_contain_badbyte(path_addr):
                raise RopException(f"{path_addr:#x} contains bad byte!")
        else:
            # reserve a little bit more bytes to fit pointers
            path_addr = self._get_ptr_to_writable(len(path)+self.project.arch.bytes)
            if path_addr is None:
                raise RopException("Fail to automatically find a good pointer to a writable region")
            l.warning("writing to %#x", path_addr)

        # now, write the path to memory
        chain = self.chain_builder.write_to_mem(path_addr, path)

        # finally, let's invoke execve!
        chain2 = self._try_invoke_execve(path_addr)

        return chain + chain2

    def _can_set_sysnum_reg(self, syscall_num):
        try:
            self.chain_builder.set_regs(**{self.sysnum_reg: syscall_num})
        except RopException:
            return False
        return True

    def _per_request_filtering(self, syscall_num, registers, preserve_regs, needs_return):
        """
        filter out gadgets that cannot be used at all for the chain
        """

        gadgets = self.syscall_gadgets
        if needs_return:
            gadgets = [x for x in gadgets if x.can_return]
        def concrete_val_ok(g):
            for key, val in g.prologue.concrete_regs.items():
                if key in registers and type(registers[key]) == int and registers[key] != val:
                    return False
                if key == self.sysnum_reg and val != syscall_num:
                    return False
            return True
        gadgets = [x for x in gadgets if concrete_val_ok(x)]
        target_regs = dict(registers)
        target_regs[self.sysnum_reg] = syscall_num

        # now try to set sysnum_reg, if we can't do it, that means we have to rely on concrete values
        def set_sysnum(g):
            if self.sysnum_reg not in g.prologue.concrete_regs:
                return False
            return g.prologue.concrete_regs[self.sysnum_reg] == syscall_num
        if self.sysnum_reg not in preserve_regs and not self._can_set_sysnum_reg(syscall_num):
            gadgets = [g for g in gadgets if set_sysnum(g)]

        # prioritize gadgets that can set more arguments
        def key_func(g):
            good_sets = set()
            for reg, val in g.prologue.concrete_regs.items():
                if reg in target_regs and target_regs[reg] == val:
                    good_sets.add(reg)
            return len(good_sets)
        gadgets = sorted(gadgets, reverse=True, key=key_func)
        return gadgets

    def do_syscall(self, syscall_num, args, needs_return=True, **kwargs):
        """
        build a rop chain which performs the requested system call with the arguments set to 'registers' before
        the call is made
        :param syscall_num: the syscall number to execute
        :param args: the register values to have set at system call time
        :param preserve_regs: list of registers which shouldn't be set
        :param needs_return: whether to continue the ROP after invoking the syscall
        :return: a RopChain which makes the system with the requested register contents
        """
        if not self.syscall_gadgets:
            raise RopException("target does not contain syscall gadget!")

        # set the system call number
        cc = angr.SYSCALL_CC[self.project.arch.name]["default"](self.project.arch)

        # find small stack change syscall gadget that also fits the stack arguments we want
        # FIXME: does any arch/OS take syscall arguments on stack? (windows? sysenter?)
        if len(args) > len(cc.ARG_REGS):
            raise NotImplementedError("Currently, we can't handle on stack system call arguments!")
        registers = {}
        for arg, reg in zip(args, cc.ARG_REGS):
            registers[reg] = rop_utils.cast_rop_value(arg, self.project)

        more = kwargs.pop('preserve_regs', set())

        # do per-request gadget filtering
        gadgets = self._per_request_filtering(syscall_num, registers, more, needs_return)
        orig_registers = registers
        for gadget in gadgets:
            registers = dict(orig_registers) # create a copy of it
            preserve_regs = set(more)
            extra_regs = {self.sysnum_reg: syscall_num}

            # at this point, we know all the concrete_regs are good, just remove the requirementes
            for reg in gadget.prologue.concrete_regs:
                if reg in extra_regs:
                    del extra_regs[reg]
                if reg in registers:
                    preserve_regs.add(reg)

            # now, check whether there are clobbered registers
            p = gadget.prologue
            clobbered_regs = p.changed_regs - p.popped_regs - set(p.concrete_regs.keys())
            tmp = set(preserve_regs)
            tmp = tmp.union(registers.keys())
            tmp = tmp.union(extra_regs.keys())
            if clobbered_regs.intersection(tmp):
                continue

            try:
                chain = self._func_call(gadget, cc, args, extra_regs=extra_regs,
                               needs_return=needs_return, preserve_regs=preserve_regs, **kwargs)
                if self.verify(chain, registers, more):
                    return chain
            except RopException:
                continue

        raise RopException(f"Fail to invoke syscall {syscall_num} with arguments: {args}!")
