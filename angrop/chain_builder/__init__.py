import types
import heapq
import struct
import logging
from collections import defaultdict

import angr
import claripy

from .reg_setter import RegSetter
from .mem_writer import MemWriter
from .. import rop_utils
from .. import common
from ..errors import RopException
from ..rop_chain import RopChain
from ..rop_gadget import RopGadget

l = logging.getLogger("angrop.chain_builder")


class ChainBuilder:
    """
    This class provides functions to generate common ropchains based on existing gadgets.
    """

    def __init__(self, project, gadgets, duplicates, reg_list, base_pointer, badbytes, roparg_filler, rebase=True):
        """
        Initializes the chain builder.

        :param project: Angr project
        :param gadgets: a list of RopGadget gadgets
        :param duplicates:
        :param reg_list: A list of multipurpose registers
        :param base_pointer: The name ("offset") for base pointer register
        :param badbytes: A list with badbytes, which we should avoid
        :param roparg_filler: An integer used when popping superfluous registers
        """
        self.project = project
        self._gadgets = gadgets
        # TODO get duplicates differently?
        self._duplicates = duplicates
        self._reg_list = reg_list
        self._base_pointer = base_pointer
        self.badbytes = badbytes
        self._roparg_filler = roparg_filler
        self._rebase = rebase

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

        # test state
        self._test_symbolic_state = rop_utils.make_symbolic_state(self.project, self._reg_list)

        # filtered gadget cache
        self._filtered_reg_gadgets = None

        self._reg_setter = RegSetter(project, gadgets, reg_list=reg_list, badbytes=badbytes,
                                     rebase=self._rebase, filler=self._roparg_filler)
        self._mem_writer = MemWriter(project, self._reg_setter, base_pointer, gadgets, badbytes=badbytes,
                                     rebase=self._rebase, filler=self._roparg_filler)

    def _contain_badbyte(self, ptr):
        """
        check if a pointer contains any bad byte
        """
        raw_bytes = struct.pack(self.project.arch.struct_fmt(), ptr)
        if any(x in raw_bytes for x in self.badbytes):
            return True
        return False

    def _get_ptr_to_writable(self, size):
        """
        get a pointer to writable region that can fit `size` bytes
        it shouldn't contain bad byte
        """
        # get all writable segments
        segs = [ s for s in self.project.loader.main_object.segments if s.is_writable ]
        # enumerate through all address to find a good address
        for seg in segs:
            for addr in range(seg.min_addr, seg.max_addr):
                if all(not self._contain_badbyte(x) for x in range(addr, addr+size, self.project.arch.bytes)):
                    return addr
        return None

    def _get_ptr_to_null(self):
        # get all non-writable segments
        segs = [ s for s in self.project.loader.main_object.segments if not s.is_writable ]
        # enumerate through all address to find a good address
        for seg in segs:
            null = b'\x00'*self.project.arch.bytes
            for addr in self.project.loader.memory.find(null, search_min=seg.min_addr, search_max=seg.max_addr):
                if not self._contain_badbyte(addr):
                    return addr
        return None

    def set_regs(self, *args, **kwargs):
        """
        :param registers: dict of registers to values
        :return: a chain which will set the registers to the requested values

        example:
        chain = rop.set_regs(rax=0x1234, rcx=0x41414141)
        """

        return self._reg_setter.run(*args, **kwargs)

    def _func_call(self, func_gadget, cc, args, extra_regs=None, modifiable_memory_range=None, ignore_registers=None,
                   use_partial_controllers=False, rebase_regs=None, needs_return=True):
        assert type(args) in [list, tuple], "function arguments must be a list or tuple!"
        arch_bytes = self.project.arch.bytes
        registers = {} if extra_regs is None else extra_regs
        if ignore_registers is None:
            ignore_registers = []

        # distinguish register and stack arguments
        register_arguments = args
        stack_arguments = []
        if len(args) > len(cc.ARG_REGS):
            register_arguments = args[:len(cc.ARG_REGS)]
            stack_arguments = args[len(cc.ARG_REGS):]

        # set register arguments
        for arg, reg in zip(register_arguments, cc.ARG_REGS):
            registers[reg] = arg
        for reg in ignore_registers:
            registers.pop(reg, None)
        chain = self.set_regs(modifiable_memory_range=modifiable_memory_range,
                              use_partial_controllers=use_partial_controllers,
                              rebase_regs=rebase_regs, **registers)

        # invoke the function
        chain.add_gadget(func_gadget)
        chain.add_value(func_gadget.addr, needs_rebase=True)
        for i in range(func_gadget.stack_change//arch_bytes-1):
            chain.add_value(self._get_fill_val(), needs_rebase=False)

        # we are done here if there is no stack arguments
        if not stack_arguments:
            return chain

        # handle stack arguments:
        # 1. we need to pop the arguments after use
        # 2. push the stack arguments

        # step 1: find a stack cleaner (a gadget that can pop all the stack args)
        #         with the smallest stack change
        stack_cleaner = None
        if needs_return:
            for g in self._gadgets:
                # just pop plz
                if g.mem_reads or g.mem_writes or g.mem_changes:
                    continue
                # at least can pop all the args
                if g.stack_change < arch_bytes * (len(stack_arguments)+1):
                    continue

                if stack_cleaner is None or g.stack_change < stack_cleaner.stack_change:
                    stack_cleaner = g

            if stack_cleaner is None:
                raise RopException(f"Fail to find a stack cleaner that can pop {len(stack_arguments)} words!")

        # in case we can't find a stack_cleaner and we don't need to return
        if stack_cleaner is None:
            stack_cleaner = RopGadget(self._get_fill_val())
            stack_cleaner.stack_change = arch_bytes * (len(stack_arguments)+1)

        chain.add_gadget(stack_cleaner)
        chain.add_value(stack_cleaner.addr, needs_rebase=True)
        stack_arguments += [self._get_fill_val()]*(stack_cleaner.stack_change//arch_bytes - len(stack_arguments)-1)
        for arg in stack_arguments:
            chain.add_value(arg, needs_rebase=False)

        return chain

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
        for gadget in [x for x in self._gadgets if x.starts_with_syscall]:
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

    def add_to_mem(self, addr, value, data_size=None):
        """
        :param addr: the address to add to
        :param value: the value to add
        :param data_size: the size of the data for the add (defaults to project.arch.bits)
        :return: A chain which will do [addr] += value

        Example:
        chain = rop.add_to_mem(0x8048f124, 0x41414141)
        """
        return self._mem_writer.add_to_mem(addr, value, data_size=data_size)

    def write_to_mem(self, addr, data, fill_byte=b"\xff"):
        return self._mem_writer.write_to_mem(addr, data, fill_byte=fill_byte)

    def _try_invoke_execve(self, path_addr):
        cc = angr.SYSCALL_CC[self.project.arch.name]["default"](self.project.arch)
        arg_regs = cc.ARG_REGS

        # next, try to invoke execve(path, ptr, ptr), where ptr points is either NULL or nullptr
        if 0 not in self.badbytes:
            ptr = 0
            rebase_regs = arg_regs[:1]
        else:
            nullptr = self._get_ptr_to_null()
            ptr = nullptr
            rebase_regs = arg_regs[:3]

        try:
            return self.do_syscall(self._execve_syscall, [path_addr, ptr, ptr],
                                 use_partial_controllers=False, needs_return=False, rebase_regs=rebase_regs)
        except RopException:
            pass

        # Try to use partial controllers
        l.warning("Trying to use partial controllers for syscall")
        try:
            return self.do_syscall(self._execve_syscall, [path_addr, 0, 0],
                                     use_partial_controllers=True, needs_return=False, rebase_regs=rebase_regs)
        except RopException:
            pass

        raise RopException("Fail to invoke execve!")

    def execve(self, path=None, path_addr=None):
        # look for good syscall gadgets
        syscall_locs = self._get_syscall_locations()
        syscall_locs = [x for x in syscall_locs if not self._contain_badbyte(x)]
        if len(syscall_locs) == 0:
            raise RopException("No syscall instruction available")

        # determine the execution path
        if path is None:
            path = b"/bin/sh\x00"
        if path[-1] != 0:
            path += b"\x00"

        # look for a good buffer to store the payload
        if path_addr:
            if self._contain_badbyte(path_addr):
                raise RopException(f"{path_addr:#x} contains bad byte!")
        else:
            # reserve a little bit more bytes to fit pointers
            path_addr = self._get_ptr_to_writable(len(path)+self.project.arch.bytes)
            if path_addr is None:
                raise RopException("Fail to automatically find a good pointer to a writable region")
            l.warning("writing to %#x", path_addr)

        # now, write the path to memory
        chain = self.write_to_mem(path_addr, path)

        # finally, let's invoke execve!
        chain2 = self._try_invoke_execve(path_addr)

        return chain + chain2

    def func_call(self, address, args, **kwargs):
        """
        :param address: address or name of function to call
        :param args: a list/tuple of arguments to the function
        :param ignore_registers: list of registers which shouldn't be set
        :param needs_return: whether to continue the ROP after invoking the function
        :return: a RopChain which inovkes the function with the arguments
        """
        # is it a symbol?
        if isinstance(address, str):
            symbol = address
            symobj = self.project.loader.main_object.get_symbol(symbol)
            if hasattr(self.project.loader.main_object, 'plt') and address in self.project.loader.main_object.plt:
                address = self.project.loader.main_object.plt[symbol]
            elif symobj is not None:
                address = symobj.rebased_addr
            else:
                raise RopException("Symbol passed to func_call does not exist in the binary")

        cc = angr.default_cc(
            self.project.arch.name,
            platform=self.project.simos.name if self.project.simos is not None else None,
        )(self.project.arch)
        func_gadget = RopGadget(address)
        func_gadget.stack_change = self.project.arch.bytes
        return self._func_call(func_gadget, cc, args, **kwargs)

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

    def _get_fill_val(self):
        if self._roparg_filler is not None:
            return self._roparg_filler
        else:
            return claripy.BVS("filler", self.project.arch.bits)

    def _set_badbytes(self, badbytes):
        self.badbytes = badbytes

    def _set_roparg_filler(self, roparg_filler):
        self._roparg_filler = roparg_filler
        self._reg_setter._roparg_filler = roparg_filler

    # should also be able to do execve by providing writable memory
    # todo pivot stack
    # todo pass values to setregs as symbolic variables
