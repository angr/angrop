import logging

from .reg_setter import RegSetter
from .reg_mover import RegMover
from .mem_writer import MemWriter
from .mem_changer import MemChanger
from .func_caller import FuncCaller
from .sys_caller import SysCaller
from .pivot import Pivot
from .shifter import Shifter
from .. import rop_utils
from ..errors import RopException

l = logging.getLogger("angrop.chain_builder")


class ChainBuilder:
    """
    This class provides functions to generate common ropchains based on existing gadgets.
    """

    def __init__(self, project, rop_gadgets, pivot_gadgets, syscall_gadgets, arch, badbytes, roparg_filler):
        """
        Initializes the chain builder.

        :param project: angr project
        :param gadgets: a list of RopGadget gadgets
        :param arch: a RopArch object
        :param badbytes: A list with badbytes, which we should avoid
        :param roparg_filler: An integer used when popping superfluous registers
        """
        self.project = project
        self.arch = arch
        self.badbytes = badbytes
        self.roparg_filler = roparg_filler

        self.gadgets = rop_gadgets
        self.pivot_gadgets = pivot_gadgets
        self.syscall_gadgets = syscall_gadgets

        self._reg_setter = RegSetter(self)
        self._reg_mover = RegMover(self)
        self._mem_writer = MemWriter(self)
        self._mem_changer = MemChanger(self)
        self._func_caller = FuncCaller(self)
        self._pivot = Pivot(self)
        self._sys_caller = SysCaller(self)
        if not SysCaller.supported_os(self.project.loader.main_object.os):
            l.warning("%s is not a fully supported OS, SysCaller may not work on this OS",
                      self.project.loader.main_object.os)
        self._shifter = Shifter(self)
        self._can_do_write = None

    def set_regs(self, *args, **kwargs):
        """
        :param preserve_regs: set of registers to preserve, e.g. ('eax', 'ebx')
        :param registers: dict of registers to values
        :return: a chain which will set the registers to the requested values

        example:
        chain = rop.set_regs(rax=0x1234, rcx=0x41414141)
        """
        return self._reg_setter.run(*args, **kwargs)

    def move_regs(self, **registers):
        """
        :param preserve_regs: set of registers to preserve, e.g. ('eax', 'ebx')
        :param registers: dict of registers, key is the destination register, value is the source register
        :return: a chain which will set the registers to the requested registers

        example:
        chain = rop.move_regs(rax='rcx', rcx='rbx')
        """
        return self._reg_mover.run(**registers)

    def add_to_mem(self, addr, value, data_size=None):
        """
        :param addr: the address to add to
        :param value: the value to add
        :param data_size: the size of the data for the add (defaults to project.arch.bits)
        :return: A chain which will do [addr] += value

        Example:
        chain = rop.add_to_mem(0x8048f124, 0x41414141)
        """
        addr = rop_utils.cast_rop_value(addr, self.project)
        value = rop_utils.cast_rop_value(value, self.project)
        return self._mem_changer.add_to_mem(addr, value, data_size=data_size)

    def write_to_mem(self, addr, data, fill_byte=b"\xff"):
        """
        :param addr: address to store the string
        :param data: string to store
        :param fill_byte: a byte to use to fill up the string if necessary
        :return: a rop chain
        """
        addr = rop_utils.cast_rop_value(addr, self.project)
        return self._mem_writer.write_to_mem(addr, data, fill_byte=fill_byte)

    def pivot(self, thing):
        thing = rop_utils.cast_rop_value(thing, self.project)
        return self._pivot.pivot(thing)

    def func_call(self, address, args, **kwargs):
        """
        :param address: address or name of function to call
        :param args: a list/tuple of arguments to the function
        :param preserve_regs: set of registers to preserve, e.g. ('eax', 'ebx')
        :param needs_return: whether to continue the ROP after invoking the function
        :return: a RopChain which invokes the function with the arguments
        """
        return self._func_caller.func_call(address, args, **kwargs)

    def do_syscall(self, syscall_num, args, needs_return=True, **kwargs):
        """
        build a rop chain which performs the requested system call with the arguments set to 'registers' before
        the call is made
        :param syscall_num: the syscall number to execute
        :param args: the register values to have set at system call time
        :param preserve_regs: set of registers to preserve, e.g. ('eax', 'ebx')
        :param needs_return: whether to continue the ROP after invoking the syscall
        :return: a RopChain which makes the system with the requested register contents
        """
        if not self._sys_caller:
            l.exception("SysCaller does not support OS: %s", self.project.loader.main_object.os)
            return None
        return self._sys_caller.do_syscall(syscall_num, args, needs_return=needs_return, **kwargs)

    def execve(self, path=None, path_addr=None):
        """
        build a rop chain that executes execve
        :param path: path of binary of execute, default to b"/bin/sh\x00"
        :param path_addr: where to store this path string
        """
        if not self._sys_caller:
            l.exception("SysCaller does not support OS: %s", self.project.loader.main_object.os)
            return None
        return self._sys_caller.execve(path=path, path_addr=path_addr)

    def shift(self, length, preserve_regs=None, next_pc_idx=-1):
        """
        build a rop chain to shift the stack to a specific value
        :param length: the length of sp you want to shift
        :param preserve_regs: set of registers to preserve, e.g. ('eax', 'ebx')
        """
        return self._shifter.shift(length, preserve_regs=preserve_regs, next_pc_idx=next_pc_idx)

    def retsled(self, size, preserve_regs=None):
        """
        create a ret-sled ROP chain where if the control flow falls into any point of the chain,
        the control flow will be captured and maintained.
        for example, a series of ret gadgets in x86/x86_64
        :param size: the size of the retsled chain
        :param preserve_regs: set of registers to preserve, e.g. ('eax', 'ebx')
        """
        return self._shifter.retsled(size, preserve_regs=preserve_regs)

    def set_badbytes(self, badbytes):
        self.badbytes = badbytes

    def set_roparg_filler(self, roparg_filler):
        self.roparg_filler = roparg_filler

    def bootstrap(self):
        # get a functional chain builder
        self._reg_mover.bootstrap()
        self._reg_setter.bootstrap()
        self._mem_writer.bootstrap()
        self._mem_changer.bootstrap()
        self._func_caller.bootstrap()
        if self._sys_caller:
            self._sys_caller.bootstrap()
        self._pivot.bootstrap()
        self._shifter.bootstrap()

    def check_can_do_write(self):
        bits = self.project.arch.bits
        if bits == 32:
            ptr = 0x31313131
        else:
            ptr = 0x313131313131
        try:
            self.write_to_mem(ptr, b'A'*4)
            self._can_do_write = True
        except RopException:
            self._can_do_write = False

    def optimize(self, processes=1):
        # optimize reg_mover and reg_setter
        again = True
        cnt = 0
        while again and cnt < 5:
            # check whether we can do memory write in the first place.
            # If we can't, then there is no way to normalize jmp_mem gadgets
            if not self._can_do_write:
                self.check_can_do_write()

            again = self._reg_mover.optimize(processes=processes)
            again |= self._reg_setter.optimize(processes=processes)
            cnt += 1