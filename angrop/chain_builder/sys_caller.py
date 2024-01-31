import logging

import angr

from .func_caller import FuncCaller
from .. import common
from ..errors import RopException
from ..rop_gadget import RopGadget

l = logging.getLogger(__name__)

class SysCaller(FuncCaller):
    """
    handle linux system calls invocations, only support i386 and x86_64 atm
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)

        self._syscall_instruction = None
        if self.project.arch.linux_name == "x86_64":
            self._syscall_instructions = {b"\x0f\x05"}
        elif self.project.arch.linux_name == "i386":
            self._syscall_instructions = {b"\xcd\x80"}

        self._execve_syscall = None
        if "unix" in self.project.loader.main_object.os.lower():
            if self.project.arch.bits == 64:
                self._execve_syscall = 59
            elif self.project.arch.bits == 32:
                self._execve_syscall = 11
            else:
                raise RopException("unknown unix platform")

    def _get_syscall_locations(self):
        """
        :return: all the locations in the binary with a syscall instruction
        """
        addrs = []
        for segment in self.project.loader.main_object.segments:
            if segment.is_executable:
                num_bytes = segment.max_addr + 1 - segment.min_addr
                read_bytes = self.project.loader.memory.load(segment.min_addr, num_bytes)
                for syscall_instruction in self._syscall_instructions:
                    for loc in common.str_find_all(read_bytes, syscall_instruction):
                        addrs.append(loc + segment.min_addr)
        return sorted(addrs)

    def _try_invoke_execve(self, path_addr):
        # next, try to invoke execve(path, ptr, ptr), where ptr points is either NULL or nullptr
        if 0 not in self.badbytes:
            ptr = 0
        else:
            nullptr = self._get_ptr_to_null()
            ptr = nullptr

        try:
            return self.do_syscall(self._execve_syscall, [path_addr, ptr, ptr],
                                 use_partial_controllers=False, needs_return=False)
        except RopException:
            pass

        # Try to use partial controllers
        l.warning("Trying to use partial controllers for syscall")
        try:
            return self.do_syscall(self._execve_syscall, [path_addr, 0, 0],
                                     use_partial_controllers=True, needs_return=False)
        except RopException:
            pass

        raise RopException("Fail to invoke execve!")

    def execve(self, path=None, path_addr=None):
        # look for good syscall gadgets
        syscall_locs = self._get_syscall_locations()
        syscall_locs = [x for x in syscall_locs if not self._word_contain_badbyte(x)]
        if len(syscall_locs) == 0:
            raise RopException("No syscall instruction available")

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

    # TODO handle mess ups by _find_reg_setting_gadgets and see if we can set a register in a syscall preamble
    # or if a register value is explicitly set to just the right value
    def do_syscall(self, syscall_num, args, needs_return=True, **kwargs):
        """
        build a rop chain which performs the requested system call with the arguments set to 'registers' before
        the call is made
        :param syscall_num: the syscall number to execute
        :param args: the register values to have set at system call time
        :param ignore_registers: list of registers which shouldn't be set
        :param needs_return: whether to continue the ROP after invoking the syscall
        :return: a RopChain which makes the system with the requested register contents
        """

        # set the system call number
        extra_regs = {}
        extra_regs[self.project.arch.register_names[self.project.arch.syscall_num_offset]] = syscall_num
        cc = angr.SYSCALL_CC[self.project.arch.name]["default"](self.project.arch)

        # find small stack change syscall gadget that also fits the stack arguments we want
        # FIXME: does any arch/OS take syscall arguments on stack? (windows? sysenter?)
        smallest = None
        stack_arguments = args[len(cc.ARG_REGS):]
        for gadget in [x for x in self.chain_builder.gadgets if x.starts_with_syscall]:
            # adjust stack change for ret
            stack_change = gadget.stack_change - self.project.arch.bytes
            required_space = len(stack_arguments) * self.project.arch.bytes
            if stack_change >= required_space:
                if smallest is None or gadget.stack_change < smallest.stack_change:
                    smallest = gadget

        if smallest is None and not needs_return:
            syscall_locs = self._get_syscall_locations()
            if len(syscall_locs) > 0:
                smallest = RopGadget(syscall_locs[0])
                smallest.block_length = self.project.factory.block(syscall_locs[0]).size
                smallest.stack_change = self.project.arch.bits

        if smallest is None:
            raise RopException("No suitable syscall gadgets found")

        return self._func_call(smallest, cc, args, extra_regs=extra_regs,
                               needs_return=needs_return, **kwargs)
