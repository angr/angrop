import logging
import functools

import angr

from .func_caller import FuncCaller
from ..errors import RopException

l = logging.getLogger(__name__)

def cmp(g1, g2):
    if g1.can_return and not g2.can_return:
        return -1
    if not g1.can_return and g2.can_return:
        return 1

    if g1.num_mem_access < g2.num_mem_access:
        return -1
    if g1.num_mem_access > g2.num_mem_access:
        return 1

    if g1.stack_change < g2.stack_change:
        return -1
    if g1.stack_change > g2.stack_change:
        return 1

    if g1.block_length < g2.block_length:
        return -1
    if g1.block_length > g2.block_length:
        return 1
    return 0

class SysCaller(FuncCaller):
    """
    handle linux system calls invocations, only support i386 and x86_64 atm
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)

        self.syscall_gadgets = None
        self.update()

    @staticmethod
    def supported_os(os):
        return "unix" in os.lower()

    def update(self):
        self.syscall_gadgets = self._filter_gadgets(self.chain_builder.syscall_gadgets)

    @staticmethod
    def _filter_gadgets(gadgets):
        return sorted(gadgets, key=functools.cmp_to_key(cmp))

    def _try_invoke_execve(self, path_addr):
        execve_syscall = 0x3b if self.project.arch.bits == 64 else 0xb
        # next, try to invoke execve(path, ptr, ptr), where ptr points is either NULL or nullptr
        if 0 not in self.badbytes:
            ptr = 0
        else:
            nullptr = self._get_ptr_to_null()
            ptr = nullptr

        try:
            return self.do_syscall(execve_syscall, [path_addr, ptr, ptr],
                                 use_partial_controllers=False, needs_return=False)
        except RopException:
            pass

        # Try to use partial controllers
        l.warning("Trying to use partial controllers for syscall")
        try:
            return self.do_syscall(execve_syscall, [path_addr, 0, 0],
                                     use_partial_controllers=True, needs_return=False)
        except RopException:
            pass

        raise RopException("Fail to invoke execve!")

    def execve(self, path=None, path_addr=None):
        if "unix" not in self.project.loader.main_object.os.lower():
            raise RopException("unknown unix platform")
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
            registers[reg] = arg

        sysnum_reg = self.project.arch.register_names[self.project.arch.syscall_num_offset]
        registers[sysnum_reg] = syscall_num

        # do per-request gadget filtering
        gadgets = self.syscall_gadgets
        if needs_return:
            gadgets = [x for x in gadgets if x.can_return]
        gadgets = [x for x in gadgets if
                   all(y not in registers or x.concrete_regs[y] == registers[y] for y in x.concrete_regs)]
        key_func = lambda x: len(set(x.concrete_regs.keys()).intersection(registers.keys()))
        gadgets = sorted(gadgets, reverse=True, key=key_func)

        for gadget in gadgets:
            # separate registers to args and extra_regs
            to_set_regs = {x:y for x,y in registers.items() if x not in gadget.concrete_regs}
            if sysnum_reg in to_set_regs:
                extra_regs = {sysnum_reg: syscall_num}
                del to_set_regs[sysnum_reg]
            else:
                extra_regs = {}
            preserve_regs = set(registers.keys()) - set(to_set_regs.keys())
            if sysnum_reg in preserve_regs:
                preserve_regs.remove(sysnum_reg)
            self.project.factory.block(gadget.addr).pp()

            try:
                return self._func_call(gadget, cc, args, extra_regs=extra_regs,
                               needs_return=needs_return, preserve_regs=preserve_regs, **kwargs)
            except Exception: # pylint: disable=broad-exception-caught
                continue

        raise RopException(f"Fail to invoke syscall {syscall_num} with arguments: {args}!")
