import heapq
import struct
import claripy
import simuvex

import rop_utils
import common

from errors import RopException
from rop_chain import RopChain
from rop_gadget import RopGadget

import types
import logging
from collections import defaultdict

l = logging.getLogger("angrop.chain_builder")


class ChainBuilder(object):
    """
    This class provides functions to generate common ropchains based on existing gadgets.
    """

    def __init__(self, project, gadgets, duplicates, reg_list, base_pointer, badbytes, roparg_filler):
        """
        Initializes the chain builder.

        :param project: Angr project
        :param gadgets: a list of RopGadget gadgets
        :param duplicates:
        :param reg_list: A list of multipurpose registers
        :param base_pointer: The name ("offset") for base pointer register
        :param badbytes: A list with badbytes, which we should avaoid
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

        self._syscall_instruction = None
        if self.project.arch.linux_name == "x86_64":
            self._syscall_instructions = {"\x0f\x05"}
        elif self.project.arch.linux_name == "i386":
            self._syscall_instructions = {"\xcd\x80"}

        self._execve_syscall = None
        if self.project.loader.main_bin.os == "unix":
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

    def set_regs(self, modifiable_memory_range=None, use_partial_controllers=False, rebase_regs=None, **registers):
        """
        :param registers: dict of registers to values
        :return: a chain which will set the registers to the requested values

        example:
        chain = rop.set_regs(rax=0x1234, rcx=0x41414141)
        """

        if len(registers) == 0:
            return RopChain(self.project, self)

        if rebase_regs is None:
            rebase_regs = set()

        gadgets, best_stack_change, _ = self._find_reg_setting_gadgets(modifiable_memory_range,
                                                                       use_partial_controllers, **registers)
        if gadgets is None:
            raise RopException("Couldn't set registers :(")

        return self._build_reg_setting_chain(gadgets, modifiable_memory_range,
                                             registers, best_stack_change, rebase_regs)

    # TODO handle mess ups by _find_reg_setting_gadgets and see if we can set a register in a syscall preamble
    # or if a register value is explicitly set to just the right value
    def do_syscall(self, syscall_num, arguments, ignore_registers=None, modifiable_memory_range=None,
                   use_partial_controllers=False, rebase_regs=None, needs_return=True):
        """
        build a rop chain which performs the requested system call with the arguments set to 'registers' before
        the call is made
        :param syscall_num: the syscall number to execute
        :param arguments: the register values to have set at system call time
        :param ignore_registers: list of registers which shouldn't be set
        :return: a RopChain which makes the system with the requested register contents
        """

        registers = {}

        if ignore_registers is None:
            ignore_registers = []

        # set the system call number
        registers[self.project.arch.register_names[self.project.arch.syscall_num_offset]] = syscall_num

        cc = simuvex.s_cc.SyscallCC[self.project.arch.name]["default"](self.project.arch)

        # distinguish register arguments from stack arguments
        register_arguments = arguments
        stack_arguments = []
        if len(arguments) > len(cc.ARG_REGS):
            register_arguments = arguments[:len(cc.ARG_REGS)]
            stack_arguments = arguments[len(cc.ARG_REGS):]

        for arg, reg in zip(register_arguments, cc.ARG_REGS):
            registers[reg] = arg

        # remove any registers which have been asked to be ignored
        for reg in ignore_registers:
            if reg in registers:
                del registers[reg]

        # first find gadgets to the set the registers
        chain = self.set_regs(modifiable_memory_range, use_partial_controllers, rebase_regs, **registers)

        # find small stack change syscall gadget that also fits the stack arguments we want
        smallest = None
        for gadget in filter(lambda g: g.starts_with_syscall, self._gadgets):
            # adjust stack change for ret
            stack_change = gadget.stack_change - (self.project.arch.bits / 8)
            required_space = len(stack_arguments) * (self.project.arch.bits / 8)
            if stack_change >= required_space:
                if smallest is None or gadget.stack_change < smallest.stack_change:
                    smallest = gadget

        if smallest is None and not needs_return:
            syscall_locs = self._get_syscall_locations()
            if len(syscall_locs) > 0:
                smallest = RopGadget(syscall_locs[0])
                smallest.stack_change = self.project.arch.bits

        if smallest is None:
            raise RopException("No suitable syscall gadgets found")

        chosen_gadget = smallest
        # add the gadget to the chain
        chain.add_gadget(chosen_gadget)

        # now we'll just pad it out with zeroes, in the future we'll probably want a way to be smart about
        # the next gadget in the chain

        # add the syscall gadget's address
        chain.add_value(chosen_gadget.addr, needs_rebase=True)

        # remove one word to account for the ret
        padding_bytes = chosen_gadget.stack_change - (self.project.arch.bits / 8)
        bytes_per_pop = self.project.arch.bits / 8
        # reverse stack_arguments list to make pushing them onto the stack easy
        stack_arguments = stack_arguments[::-1]
        for _ in range(max(padding_bytes / bytes_per_pop, len(stack_arguments))):
            try:
                val = stack_arguments.pop()
            except IndexError:
                val = self._get_fill_val()
            chain.add_value(val, needs_rebase=False)

        return chain

    def write_to_mem(self, addr, string_data, fill_byte="\xff"):
        """
        :param addr: address to store the string
        :param string_data: string to store
        :param fill_byte: a byte to use to fill up the string if necessary
        :return: a rop chain
        """

        if not (isinstance(fill_byte, basestring) and len(fill_byte) == 1):
            print "fill_byte is not a one byte string, aborting"
            return

        # create a dict of bytes per write to gadgets
        # assume we need intersection of addr_dependencies and data_dependencies to be 0
        # TODO could allow mem_reads as long as we control the address?
        possible_gadgets = set()
        for g in self._gadgets:
            if len(g.mem_reads) + len(g.mem_changes) > 0 or len(g.mem_writes) != 1:
                continue
            if g.bp_moves_to_sp:
                continue
            if g.stack_change <= 0:
                continue
            if self._containsbadbytes(g):
                continue
            for m_access in g.mem_writes:
                if len(m_access.addr_controllers) > 0 and len(m_access.data_controllers) > 0 and \
                        len(set(m_access.addr_controllers) & set(m_access.data_controllers)) == 0:
                    possible_gadgets.add(g)

        # get the data from trying to set all the registers
        registers = dict((reg, 0x41) for reg in self._reg_list)
        l.debug("getting reg data for mem writes")
        _, _, reg_data = self._find_reg_setting_gadgets(max_stack_change=0x50, **registers)
        l.debug("trying mem_write gadgets")

        # limit the maximum size of the chain
        best_stack_change = 0x400
        best_gadget = None
        for t, vals in reg_data.items():
            if vals[1] >= best_stack_change:
                continue
            for g in possible_gadgets:
                mem_write = g.mem_writes[0]
                if (set(mem_write.addr_dependencies) | set(mem_write.data_dependencies)).issubset(set(t)):
                    stack_change = g.stack_change + vals[1]
                    bytes_per_write = mem_write.data_size / 8
                    num_writes = (len(string_data) + bytes_per_write - 1)/bytes_per_write
                    stack_change *= num_writes
                    if stack_change < best_stack_change:
                        best_gadget = g
                        best_stack_change = stack_change

        # try again using partial_controllers
        use_partial_controllers = False
        best_stack_change = 0x400
        if best_gadget is None:
            use_partial_controllers = True
            l.warning("Trying to use partial controllers for memory write")
            l.debug("getting reg data for mem writes")
            _, _, reg_data = self._find_reg_setting_gadgets(max_stack_change=0x50, use_partial_controllers=True,
                                                            **registers)
            l.debug("trying mem_write gadgets")
            for t, vals in reg_data.items():
                if vals[1] >= best_stack_change:
                    continue
                for g in possible_gadgets:
                    mem_write = g.mem_writes[0]
                    # we need the addr to not be partially controlled
                    if (set(mem_write.addr_dependencies) | set(mem_write.data_dependencies)).issubset(set(t)) and \
                            len(set(mem_write.addr_dependencies) & vals[3]) == 0:
                        stack_change = g.stack_change + vals[1]
                        # only one byte at a time
                        bytes_per_write = 1
                        num_writes = (len(string_data) + bytes_per_write - 1)/bytes_per_write
                        stack_change *= num_writes
                        if stack_change < best_stack_change:
                            best_gadget = g
                            best_stack_change = stack_change

        if best_gadget is None:
            raise RopException("Couldnt set registers for any memory write gadget")

        mem_write = best_gadget.mem_writes[0]
        bytes_per_write = mem_write.data_size/8 if not use_partial_controllers else 1
        l.debug("Now building the mem write chain")

        # build the chain
        chain = RopChain(self.project, self)
        for i in range(0, len(string_data), bytes_per_write):
            to_write = string_data[i: i+bytes_per_write]
            # pad if needed
            if len(to_write) < bytes_per_write:
                to_write += fill_byte * (bytes_per_write-len(to_write))
            chain = chain + self._write_to_mem_with_gadget(best_gadget, addr + i, to_write, use_partial_controllers)

        return chain

    def add_to_mem(self, addr, value, data_size=None):
        """
        :param addr: the address to add to
        :param value: the value to add
        :param data_size: the size of the data for the add (defaults to project.arch.bits)
        :return: A chain which will do [addr] += value

        Example:
        chain = rop.add_to_mem(0x8048f124, 0x41414141)
        """
        # assume we need intersection of addr_dependencies and data_dependencies to be 0
        # TODO could allow mem_reads as long as we control the address?

        if data_size is None:
            data_size = self.project.arch.bits

        possible_gadgets = set()
        for g in self._gadgets:
            if len(g.mem_reads) + len(g.mem_writes) > 0 or len(g.mem_changes) != 1:
                continue
            if g.bp_moves_to_sp:
                continue
            if g.stack_change <= 0:
                continue
            if self._containsbadbytes(g):
                continue
            for m_access in g.mem_changes:
                if len(m_access.addr_controllers) > 0 and len(m_access.data_controllers) > 0 and \
                        len(set(m_access.addr_controllers) & set(m_access.data_controllers)) == 0 and \
                        (m_access.op == "__add__" or m_access.op == "__sub__") and m_access.data_size == data_size:
                    possible_gadgets.add(g)

        # get the data from trying to set all the registers
        registers = dict((reg, 0x41) for reg in self._reg_list)
        l.debug("getting reg data for mem adds")
        _, _, reg_data = self._find_reg_setting_gadgets(max_stack_change=0x50, **registers)
        l.debug("trying mem_add gadgets")

        best_stack_change = 0xffffffff
        best_gadget = None
        for t, vals in reg_data.items():
            if vals[1] >= best_stack_change:
                continue
            for g in possible_gadgets:
                mem_change = g.mem_changes[0]
                if (set(mem_change.addr_dependencies) | set(mem_change.data_dependencies)).issubset(set(t)):
                    stack_change = g.stack_change + vals[1]
                    if stack_change < best_stack_change:
                        best_gadget = g
                        best_stack_change = stack_change

        if best_gadget is None:
            raise RopException("Couldnt set registers for any memory add gadget")

        l.debug("Now building the mem add chain")

        # build the chain
        chain = self._change_mem_with_gadget(best_gadget, addr, data_size, difference=value)
        return chain

    def write_to_mem_v2(self, addr, data):
        """
        :param addr: address to store the string
        :param data: string to store
        :return: a rop chain
        """
        # assume we need intersection of addr_dependencies and data_dependencies to be 0
        # TODO could allow mem_reads as long as we control the address?
        # TODO implement better, allow adding a single byte repeatedly

        possible_gadgets = set()
        for g in self._gadgets:
            if len(g.mem_reads) + len(g.mem_writes) > 0 or len(g.mem_changes) != 1:
                continue
            if g.bp_moves_to_sp:
                continue
            if g.stack_change <= 0:
                continue
            if self._containsbadbytes(g):
                continue
            for m_access in g.mem_changes:
                if len(m_access.addr_controllers) > 0 and len(m_access.data_controllers) > 0 and \
                        len(set(m_access.addr_controllers) & set(m_access.data_controllers)) == 0 and \
                        (m_access.op == "__or__" or m_access.op == "__and__"):
                    possible_gadgets.add(g)

        # get the data from trying to set all the registers
        registers = dict((reg, 0x41) for reg in self._reg_list)
        l.debug("getting reg data for mem adds")
        _, _, reg_data = self._find_reg_setting_gadgets(max_stack_change=0x50, **registers)
        l.debug("trying mem_add gadgets")

        best_stack_change = 0xffffffff
        best_gadget = None
        for t, vals in reg_data.items():
            if vals[1] >= best_stack_change:
                continue
            for g in possible_gadgets:
                mem_change = g.mem_changes[0]
                if (set(mem_change.addr_dependencies) | set(mem_change.data_dependencies)).issubset(set(t)):
                    stack_change = g.stack_change + vals[1]
                    bytes_per_write = mem_change.data_size/8
                    stack_change *= bytes_per_write
                    if stack_change < best_stack_change:
                        best_gadget = g
                        best_stack_change = stack_change

        if best_gadget is None:
            raise RopException("Couldnt set registers for any memory add gadget")

        l.debug("Now building the mem const chain")
        mem_change = best_gadget.mem_changes[0]
        bytes_per_write = mem_change.data_size/8

        # build the chain
        if mem_change.op == "__or__":
            final_value = -1
        elif mem_change.op == "__and__":
            final_value = 0
        else:
            raise Exception("This shouldn't happen")
        chain = RopChain(self.project, self)
        for i in range(0, len(data), bytes_per_write):
            chain = chain + self._change_mem_with_gadget(best_gadget, addr + i,
                                                         mem_change.data_size, final_val=final_value)
        # FIXME for other adds
        for i in range(0, len(data), 4):
            to_write = data[i: i+4]
            # pad if needed
            if len(to_write) < 4:
                to_write += "\xff" * (4-len(to_write))
            to_add = struct.unpack("<I", to_write)[0] - final_value
            chain += self.add_to_mem(addr+i, to_add, 32)
        return chain

    def execve(self, target=None, addr_for_str=None):
        syscall_locs = self._get_syscall_locations()
        if len(syscall_locs) == 0:
            l.warning("No syscall instruction available, but I'll still try to make the rest of the payload for fun")

        if target is None:
            target = "/bin/sh\x00"
        if target[-1] != "\x00":
            target += "\x00"
        if addr_for_str is None:
            # get the max writable addr
            max_write_addr = 0
            for s in self.project.loader.main_bin.segments:
                if s.is_writable:
                    max_write_addr = max(max_write_addr, s.max_addr + self.project.loader.main_bin.rebase_addr)
            # page align up
            max_write_addr = (max_write_addr + 0x1000 - 1) / 0x1000 * 0x1000

            addr_for_str = max_write_addr - 0x40
            l.warning("writing to %#x", addr_for_str)

        chain = self.write_to_mem(addr_for_str, target)
        use_partial_controllers = False
        # TODO If this fails try using partial controllers
        chain2 = self.do_syscall(self._execve_syscall, [addr_for_str, 0, 0],
                                 use_partial_controllers=use_partial_controllers, needs_return=False)
        result = chain + chain2

        return result

    def func_call(self, address, args, use_partial_controllers=False):
        """
        :param address: address or name of function to call
        :param args: a list/tuple of arguments to the function
        :return: a rop chain
        """
        # is it a symbol?
        if isinstance(address, str):
            symbol = address
            symobj = self.project.loader.main_bin.get_symbol(symbol)
            if address in self.project.loader.main_bin.plt:
                address = self.project.loader.main_bin.plt[symbol]
            elif symobj is not None:
                address = symobj.addr + self.project.loader.main_bin.rebase_addr
            else:
                raise RopException("Symbol passed to func_call does not exist in the binary")

        cc = simuvex.s_cc.DefaultCC[self.project.arch.name](self.project.arch)
        # register arguments
        registers = {}

        register_arguments = args
        stack_arguments = []
        if len(args) > len(cc.ARG_REGS):
            register_arguments = args[:len(cc.ARG_REGS)]
            stack_arguments = args[len(cc.ARG_REGS):]

        for reg, arg in zip(cc.ARG_REGS, register_arguments):
            registers[reg] = arg

        if len(registers) > 0:
            chain = self.set_regs(use_partial_controllers=use_partial_controllers, **registers)
        else:
            chain = RopChain(self.project, self)

        # stack arguments
        bytes_per_arg = self.project.arch.bits / 8
        # find the smallest stack change
        stack_cleaner = None
        if len(stack_arguments) > 0:
            for g in self._gadgets:
                if self._containsbadbytes(g):
                    continue
                if len(g.mem_reads) > 0 or len(g.mem_writes) > 0 or len(g.mem_changes) > 0:
                    continue
                if g.stack_change >= bytes_per_arg * (len(stack_arguments) + 1):
                    if stack_cleaner is None or g.stack_change < stack_cleaner.stack_change:
                        stack_cleaner = g

        chain.add_value(address, needs_rebase=True)
        if stack_cleaner is not None:
            chain.add_value(stack_cleaner.addr, needs_rebase=True)
            chain.add_gadget(stack_cleaner)

        for arg in stack_arguments:
            chain.add_value(arg, needs_rebase=False)
        if stack_cleaner is not None:
            for _ in range(stack_cleaner.stack_change / bytes_per_arg - len(stack_arguments) - 1):
                chain.add_value(self._get_fill_val(), needs_rebase=False)

        return chain

    @staticmethod
    def _has_same_effects(g, g2):
        for attr in g.__dict__:
            # don't check property, or methods
            if hasattr(g.__class__, attr) and isinstance(getattr(g.__class__, attr), property):
                continue
            if isinstance(getattr(g, attr), types.MethodType):
                continue
            if attr == "addr":
                continue
            if attr == "stack_change":
                continue
            if getattr(g, attr) != getattr(g2, attr):
                return False
        return True

    @staticmethod
    def _filter_duplicates_helper(gadgets):
        gadgets_copy = list()
        for g in gadgets:
            good = True
            for g2 in gadgets:
                if g.stack_change > g2.stack_change and ChainBuilder._has_same_effects(g, g2):
                    good = False
                    break
                elif g.stack_change == g2.stack_change and g.addr > g2.addr and ChainBuilder._has_same_effects(g, g2):
                    good = False
                    break
            if good:
                gadgets_copy.append(g)
        return gadgets_copy

    @staticmethod
    def _filter_duplicates(gadgets):
        gadget_dict = defaultdict(set)
        for g in gadgets:
            t = (tuple(sorted(g.popped_regs)), tuple(sorted(g.changed_regs)))
            gadget_dict[t].add(g)
        gadgets = set()
        for v in gadget_dict.values():
            gadgets.update(ChainBuilder._filter_duplicates_helper(v))
        gadgets = ChainBuilder._filter_duplicates_helper(gadgets)
        return gadgets

    def _check_if_sufficient_partial_control(self, gadget, reg, value):
        # doesnt change it
        if reg not in gadget.changed_regs:
            return False
        # does syscall
        if gadget.makes_syscall:
            return False
        # can be controlled completely, not a partial control
        if reg in gadget.reg_controllers or reg in gadget.popped_regs:
            return False
        # make sure the register doesnt depend on itself
        if reg in gadget.reg_dependencies and reg in gadget.reg_dependencies[reg]:
            return False
        # make sure the gadget doesnt pop bp
        if gadget.bp_moves_to_sp:
            return False

        # set the register
        state = self._test_symbolic_state.copy()
        state.registers.store(reg, 0)
        state.regs.ip = gadget.addr
        # store A's past the end of the stack
        state.memory.store(state.regs.sp + gadget.stack_change, state.se.BVV("A"*0x100))

        succ = rop_utils.step_to_unconstrained_successor(project=self.project, state=state).state
        # successor
        if succ.ip is succ.registers.load(reg):
            return False

        if succ.se.solution(succ.registers.load(reg), value):
            # make sure wasnt a symbolic read
            for var in succ.registers.load(reg).variables:
                if "symbolic_read" in var:
                    return False
            return True
        return False

    def _get_sufficient_partial_controllers(self, registers):
        sufficient_partial_controllers = defaultdict(set)
        for g in self._gadgets:
            if self._containsbadbytes(g):
                continue
            for reg in g.changed_regs:
                if reg in registers:
                    if self._check_if_sufficient_partial_control(g, reg, registers[reg]):
                        sufficient_partial_controllers[reg].add(g)
        return sufficient_partial_controllers

    @staticmethod
    def _get_updated_controlled_regs(gadget, regs, data_tuple, partial_controllers, modifiable_memory_range=None):
        g = gadget
        start_regs = set(regs)
        partial_regs = data_tuple[3]
        usable_regs = start_regs - partial_regs
        end_regs = set(start_regs)

        # skip ones that change memory if no modifiable_memory_addr
        if modifiable_memory_range is None and \
                (len(g.mem_reads) > 0 or len(g.mem_writes) > 0 or len(g.mem_changes) > 0):
            return set(), set()
        elif modifiable_memory_range is not None:
            # check if we control all the memory reads/writes/changes
            all_mem_accesses = g.mem_changes + g.mem_reads + g.mem_writes
            mem_accesses_controlled = True
            for m_access in all_mem_accesses:
                for reg in m_access.addr_dependencies:
                    if reg not in usable_regs:
                        mem_accesses_controlled = False
                    usable_regs -= m_access.addr_dependencies
            if not mem_accesses_controlled:
                return set(), set()

        # analyze  all registers that we control
        for reg in g.changed_regs:
            end_regs.discard(reg)
            partial_regs.discard(reg)

        # for any reg that can be fully controlled check if we control its dependencies
        for reg in g.reg_controllers.keys():
            has_deps = True
            for dep in g.reg_dependencies[reg]:
                if dep not in usable_regs:
                    has_deps = False
            if has_deps:
                for dep in g.reg_dependencies[reg]:
                    end_regs.discard(dep)
                    usable_regs.discard(dep)
                end_regs.add(reg)
            else:
                end_regs.discard(reg)

        # for all the changed regs that we dont fully control, we see if the partial control is good enough
        for reg in set(g.changed_regs) - set(g.reg_controllers.keys()):
            if reg in partial_controllers and g in partial_controllers[reg]:
                # partial control is good enough so now check if we control all the dependencies
                if reg not in g.reg_dependencies or set(g.reg_dependencies[reg]).issubset(usable_regs):
                    # we control all the dependencies add it and remove them from the usable regs
                    partial_regs.add(reg)
                    end_regs.add(reg)
                    if reg in g.reg_dependencies:
                        usable_regs -= set(g.reg_dependencies[reg])
                        end_regs -= set(g.reg_dependencies[reg])

        for reg in g.popped_regs:
            end_regs.add(reg)

        return end_regs, partial_regs

    def _get_single_ret(self):
        # start with a ret instruction
        ret_addr = None
        for g in self._gadgets:
            if self._containsbadbytes(g):
                continue
            if len(g.changed_regs) == 0 and len(g.mem_writes) == 0 and \
                    len(g.mem_reads) == 0 and len(g.mem_changes) == 0 and \
                    g.stack_change == self.project.arch.bits/8:
                ret_addr = g.addr
                break
        return ret_addr

    @staticmethod
    def _filter_reg_setting_gadgets_helper(gadgets):
        good_gadgets = []
        for g in gadgets:
            is_good = True
            num_mem_changes = len(g.mem_writes) + len(g.mem_reads) + len(g.mem_changes)
            # make sure there are no strictly better gadgets
            for g2 in gadgets:
                num_mem_changes2 = len(g2.mem_writes) + len(g2.mem_reads) + len(g2.mem_changes)
                if len(g.reg_controllers) == 0 and len(g2.reg_controllers) == 0 and g.popped_regs == g2.popped_regs \
                        and g.reg_controllers == g2.reg_controllers and g.reg_dependencies == g2.reg_dependencies \
                        and g.changed_regs == g2.changed_regs and g.bp_moves_to_sp == g2.bp_moves_to_sp:
                    if num_mem_changes == 0 and num_mem_changes2 == 0:
                        if g.stack_change > g2.stack_change:
                            is_good = False
                    if num_mem_changes2 == 0 and num_mem_changes > 0 and g.stack_change >= g2.stack_change:
                        is_good = False
            if not is_good:
                continue
            # make sure we don't already have one that is as good
            for g2 in good_gadgets:
                num_mem_changes2 = len(g2.mem_writes) + len(g2.mem_reads) + len(g2.mem_changes)
                if g2.stack_change <= g.stack_change and g.reg_controllers == g2.reg_controllers \
                        and g.reg_dependencies == g2.reg_dependencies and g2.changed_regs.issubset(g.changed_regs) \
                        and g.popped_regs.issubset(g2.changed_regs) and num_mem_changes == 0 and num_mem_changes2 == 0 \
                        and g.bp_moves_to_sp == g2.bp_moves_to_sp:
                    is_good = False
            if is_good:
                good_gadgets.append(g)
        return good_gadgets

    def _filter_reg_setting_gadgets(self, gadgets):
        to_remove = set()
        for dups in self._duplicates:
            for i, addr in enumerate(dups):
                if i != 0:
                    to_remove.add(addr)
        gadgets = [g for g in gadgets if g.addr not in to_remove and not self._containsbadbytes(g)]
        gadgets = [g for g in gadgets if len(g.popped_regs) != 0 or len(g.reg_controllers) != 0]
        gadget_dict = defaultdict(set)
        for g in gadgets:
            t = (tuple(sorted(g.popped_regs)), tuple(sorted(g.changed_regs)))
            gadget_dict[t].add(g)
        gadgets = set()
        for v in gadget_dict.values():
            gadgets.update(self._filter_reg_setting_gadgets_helper(v))
        gadgets = self._filter_reg_setting_gadgets_helper(gadgets)
        return gadgets

    def _get_syscall_locations(self):
        """
        :return: all the locations in the binary with a syscall instruction
        """
        addrs = []
        for segment in self.project.loader.main_bin.segments:
            if segment.is_executable:
                min_addr = segment.min_addr + self.project.loader.main_bin.rebase_addr
                num_bytes = segment.max_addr-segment.min_addr
                read_bytes = "".join(self.project.loader.memory.read_bytes(min_addr, num_bytes))
                for syscall_instruction in self._syscall_instructions:
                    for loc in common.str_find_all(read_bytes, syscall_instruction):
                        addrs.append(loc + min_addr)
        return sorted(addrs)

    def _build_reg_setting_chain(self, gadgets, modifiable_memory_range, register_dict, stack_change, rebase_regs):
        """
        This function figures out the actual values needed in the chain
        for a particular set of gadgets and register values
        This is done by stepping a symbolic state through each gadget
        then constraining the final registers to the values that were requested
        """

        # create a symbolic state
        test_symbolic_state = rop_utils.make_symbolic_state(self.project, self._reg_list)
        addrs = [g.addr for g in gadgets]
        addrs.append(test_symbolic_state.se.BVS("next_addr", self.project.arch.bits))

        arch_bytes = self.project.arch.bits / 8
        arch_endness = self.project.arch.memory_endness

        # emulate a 'pop pc' of the first gadget
        state = test_symbolic_state
        state.regs.ip = addrs[0]
        # the stack pointer must begin pointing to our first gadget
        state.add_constraints(state.memory.load(state.regs.sp, arch_bytes, endness=arch_endness) == addrs[0])
        # push the stack pointer down, like a pop would do
        state.regs.sp += arch_bytes
        state.se._solver.timeout = 5000

        # step through each gadget
        # for each gadget, constrain memory addresses and add constraints for the successor
        for addr in addrs[1:]:
            succ = rop_utils.step_to_unconstrained_successor(self.project, state).state
            state.add_constraints(succ.regs.ip == addr)
            # constrain reads/writes
            for a in succ.log.actions:
                if a.type == "mem" and a.addr.ast.symbolic:
                    if modifiable_memory_range is None:
                        raise RopException("Symbolic memory address when there shouldnt have been")
                    test_symbolic_state.add_constraints(a.addr.ast >= modifiable_memory_range[0])
                    test_symbolic_state.add_constraints(a.addr.ast < modifiable_memory_range[1])
            test_symbolic_state.add_constraints(succ.regs.ip == addr)
            # get to the unconstrained successor
            state = rop_utils.step_to_unconstrained_successor(self.project, state).state

        # re-adjuest the stack pointer
        sp = test_symbolic_state.regs.sp
        sp -= arch_bytes
        bytes_per_pop = arch_bytes

        # constrain the final registers
        rebase_state = test_symbolic_state.copy()
        for r, v in register_dict.items():
            test_symbolic_state.add_constraints(state.registers.load(r) == v)

        # to handle register values that should depend on the binary base address
        if len(rebase_regs) > 0:
            for r, v in register_dict.items():
                if r in rebase_regs:
                    rebase_state.add_constraints(state.registers.load(r) == (v + 0x41414141))
                else:
                    rebase_state.add_constraints(state.registers.load(r) == v)

        # constrain the "filler" values
        if self._roparg_filler is not None:
            for i in range(stack_change / bytes_per_pop):
                sym_word = test_symbolic_state.memory.load(sp + bytes_per_pop*i, bytes_per_pop,
                                                           endness=self.project.arch.memory_endness)
                # check if we can constrain val to be the roparg_filler
                if test_symbolic_state.se.satisfiable((sym_word == self._roparg_filler,)) and \
                        rebase_state.se.satisfiable((sym_word == self._roparg_filler,)):
                    # constrain the val to be the roparg_filler
                    test_symbolic_state.add_constraints(sym_word == self._roparg_filler)
                    rebase_state.add_constraints(sym_word == self._roparg_filler)

        # create the ropchain
        res = RopChain(self.project, self, state=test_symbolic_state.copy())
        for g in gadgets:
            res.add_gadget(g)

        # iterate through the stack values that need to be in the chain
        gadget_addrs = [g.addr for g in gadgets]
        for i in range(stack_change / bytes_per_pop):
            sym_word = test_symbolic_state.memory.load(sp + bytes_per_pop*i, bytes_per_pop,
                                                       endness=self.project.arch.memory_endness)

            val = test_symbolic_state.se.any_int(sym_word)

            if len(rebase_regs) > 0:
                val2 = rebase_state.se.any_int(rebase_state.memory.load(sp + bytes_per_pop*i, bytes_per_pop,
                                                                        endness=self.project.arch.memory_endness))
                if (val2 - val) & (2**self.project.arch.bits - 1) == 0x41414141:
                    res.add_value(val, needs_rebase=True)
                elif val == val2 and len(gadget_addrs) > 0 and val == gadget_addrs[0]:
                    res.add_value(val, needs_rebase=True)
                    gadget_addrs = gadget_addrs[1:]
                elif val == val2:
                    res.add_value(sym_word, needs_rebase=False)
                else:
                    raise RopException("Rebase Failed")
            else:
                if len(gadget_addrs) > 0 and val == gadget_addrs[0]:
                    res.add_value(val, needs_rebase=True)
                    gadget_addrs = gadget_addrs[1:]
                else:
                    res.add_value(sym_word, needs_rebase=False)

        if len(gadget_addrs) > 0:
            raise RopException("Didnt find all gadget addresses, something must've broke")
        return res

    # todo allow user to specify rop chain location so that we can use read_mem gadgets to load values
    # todo allow specify initial regs or dont clobber regs
    # todo memcopy(from_addr, to_addr, len)
    # todo handle "leave" then try to do a mem write on chess from codegate-finals
    def _find_reg_setting_gadgets(self, modifiable_memory_range=None, use_partial_controllers=False,
                                  max_stack_change=None, **registers):
        """
        Finds a list of gadgets which set the desired registers
        This method currently only handles simple cases and will be improved later
        :param registers:
        :return:
        """
        if modifiable_memory_range is not None and len(modifiable_memory_range) != 2:
            raise Exception("modifiable_memory_range should be a tuple (low, high)")

        # check keys
        search_regs = set()
        for reg in registers.keys():
            search_regs.add(reg)
            if reg not in self._reg_list:
                raise RopException("Register %s not in reg list" % reg)

        # lets try doing a graph search to set registers, something like dijkstra's for minimum length

        # find gadgets with sufficient partial control
        partial_controllers = dict()
        for r in registers.keys():
            partial_controllers[r] = set()
        if use_partial_controllers:
            partial_controllers = self._get_sufficient_partial_controllers(registers)

        # filter reg setting gadgets
        if self._filtered_reg_gadgets is None or len(self._filtered_reg_gadgets) == 0:
            l.debug("filtering")
            self._filtered_reg_gadgets = self._filter_reg_setting_gadgets(set(self._gadgets))
        gadgets = set(self._filtered_reg_gadgets)
        for s in partial_controllers.values():
            gadgets.update(s)
        gadgets = list(gadgets)
        if modifiable_memory_range is None:
            gadgets = [g for g in gadgets if
                       len(g.mem_changes) == 0 and len(g.mem_writes) == 0 and len(g.mem_reads) == 0]
        l.debug("finding best gadgets")

        # each key is tuple of sorted registers
        # use tuple (prev, total_stack_change, gadget, partial_controls)
        data = dict()

        to_process = list()
        to_process.append((0, ()))
        visited = set()
        data[()] = (None, 0, None, set())
        best_stack_change = 0xffffffff
        best_reg_tuple = None
        while to_process:
            regs = heapq.heappop(to_process)[1]

            if regs in visited:
                continue
            visited.add(regs)

            if data[regs][1] >= best_stack_change:
                continue
            if max_stack_change is not None and data[regs][1] > max_stack_change:
                continue

            for g in gadgets:
                # ignore gadgets which make a syscall when setting regs
                if g.makes_syscall:
                    continue
                # ignore gadgets which don't have a positive stack change
                if g.stack_change <= 0:
                    continue
                if self._containsbadbytes(g):
                    continue

                stack_change = data[regs][1]
                new_stack_change = stack_change + g.stack_change
                # if its longer than the best ignore
                if new_stack_change >= best_stack_change:
                    continue
                # ignore base pointer moves for now
                if g.bp_moves_to_sp:
                    continue
                # ignore if we only change controlled regs
                start_regs = set(regs)
                if g.changed_regs.issubset(start_regs - data[regs][3]):
                    continue

                end_regs, partial_regs = self._get_updated_controlled_regs(g, regs, data[regs], partial_controllers,
                                                                           modifiable_memory_range)

                # if we control any new registers try adding it
                end_reg_tuple = tuple(sorted(end_regs))
                npartial = len(partial_regs)
                if len(end_regs - start_regs) > 0:
                    # if we havent seen that tuple before, or payload is shorter or less partially controlled regs.
                    end_data = data.get(end_reg_tuple, None)
                    if end_reg_tuple not in data or \
                            (new_stack_change < end_data[1] and npartial <= len(end_data[3])) or \
                            (npartial < len(end_data[3])):
                        # it improves the graph so add it
                        data[end_reg_tuple] = (regs, new_stack_change, g, partial_regs)
                        heapq.heappush(to_process, (new_stack_change, end_reg_tuple))

                        if search_regs.issubset(end_regs):
                            if new_stack_change < best_stack_change:
                                best_stack_change = new_stack_change
                                best_reg_tuple = end_reg_tuple

        # if the best_reg_tuple is None then we failed to set the desired registers :(
        if best_reg_tuple is None:
            return None, None, data

        # get the actual addresses
        gadgets_reverse = []
        curr_tuple = best_reg_tuple
        while curr_tuple != ():
            gadgets_reverse.append(data[curr_tuple][2])
            curr_tuple = data[curr_tuple][0]

        gadgets = gadgets_reverse[::-1]

        return gadgets, best_stack_change, data

    def _write_to_mem_with_gadget(self, gadget, addr, data, use_partial_controllers=False):
        # sanity check for simple gadget
        if len(gadget.mem_writes) != 1 or len(gadget.mem_reads) + len(gadget.mem_changes) > 0:
            raise RopException("too many memory accesses for my lazy implementation")

        if use_partial_controllers and len(data) < self.project.arch.bits / 8:
            data = data.ljust(self.project.arch.bits / 8, "\x00")

        arch_bytes = self.project.arch.bits / 8
        arch_endness = self.project.arch.memory_endness

        # constrain the successor to be at the gadget
        # emulate 'pop pc'
        test_state = self._test_symbolic_state.copy()
        rop_utils.make_reg_symbolic(test_state, self._base_pointer)

        test_state.regs.ip = gadget.addr
        test_state.add_constraints(
            test_state.memory.load(test_state.regs.sp, arch_bytes, endness=arch_endness) == gadget.addr)
        test_state.regs.sp += arch_bytes

        # step the gadget
        pre_gadget_state = test_state
        succ_p = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)

        # constrain the write
        mem_write = gadget.mem_writes[0]
        the_action = None
        for a in succ_p.actions.hardcopy:
            if a.type != "mem" or a.action != "write":
                continue
            if set(rop_utils.get_ast_dependency(a.addr.ast)) == set(mem_write.addr_dependencies) or \
                    set(rop_utils.get_ast_dependency(a.data.ast)) == set(mem_write.data_dependencies):
                the_action = a
                break

        if the_action is None:
            raise RopException("Couldn't find the matching action")

        # constrain the addr
        test_state.add_constraints(the_action.addr.ast == addr)
        pre_gadget_state.add_constraints(the_action.addr.ast == addr)
        pre_gadget_state.options.discard(simuvex.o.AVOID_MULTIVALUED_WRITES)
        succ_p = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)
        state = succ_p.state

        # constrain the data
        test_state.add_constraints(state.memory.load(addr, len(data)) == test_state.se.BVV(data))

        # get the actual register values
        all_deps = list(mem_write.addr_dependencies) + list(mem_write.data_dependencies)
        reg_vals = dict()
        for reg in set(all_deps):
            reg_vals[reg] = test_state.se.any_int(test_state.registers.load(reg))

        chain = self.set_regs(use_partial_controllers=use_partial_controllers, **reg_vals)
        chain.add_gadget(gadget)

        bytes_per_pop = self.project.arch.bits / 8
        chain.add_value(gadget.addr, needs_rebase=True)
        for _ in range(gadget.stack_change / bytes_per_pop - 1):
            chain.add_value(self._get_fill_val(), needs_rebase=False)
        return chain

    def _change_mem_with_gadget(self, gadget, addr, data_size, final_val=None, difference=None):
        # sanity check for simple gadget
        if len(gadget.mem_writes) + len(gadget.mem_changes) != 1 or len(gadget.mem_reads) != 0:
            raise RopException("too many memory accesses for my lazy implementation")

        if (final_val is not None and difference is not None) or (final_val is None and difference is None):
            raise RopException("must specify difference or final value and not both")

        arch_bytes = self.project.arch.bits / 8
        arch_endness = self.project.arch.memory_endness

        # constrain the successor to be at the gadget
        # emulate 'pop pc'
        test_state = self._test_symbolic_state.copy()
        rop_utils.make_reg_symbolic(test_state, self._base_pointer)

        if difference is not None:
            test_state.memory.store(addr, test_state.se.BVV(~difference, data_size))
        if final_val is not None:
            test_state.memory.store(addr, test_state.se.BVV(~final_val, data_size))

        test_state.regs.ip = gadget.addr
        test_state.add_constraints(
            test_state.memory.load(test_state.regs.sp, arch_bytes, endness=arch_endness) == gadget.addr)
        test_state.regs.sp += arch_bytes

        # step the gadget
        pre_gadget_state = test_state
        succ_p = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)

        # constrain the change
        mem_change = gadget.mem_changes[0]
        the_action = None
        for a in succ_p.actions.hardcopy:
            if a.type != "mem" or a.action != "write":
                continue
            if set(rop_utils.get_ast_dependency(a.addr.ast)) == set(mem_change.addr_dependencies):
                the_action = a
                break

        if the_action is None:
            raise RopException("Couldn't find the matching action")

        # constrain the addr
        test_state.add_constraints(the_action.addr.ast == addr)
        pre_gadget_state.add_constraints(the_action.addr.ast == addr)
        pre_gadget_state.options.discard(simuvex.o.AVOID_MULTIVALUED_WRITES)
        pre_gadget_state.options.discard(simuvex.o.AVOID_MULTIVALUED_READS)
        succ_p = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)
        state = succ_p.state

        # constrain the data
        if final_val is not None:
            test_state.add_constraints(state.memory.load(addr, data_size/8, endness=arch_endness) ==
                                       test_state.se.BVV(final_val, data_size))
        if difference is not None:
            test_state.add_constraints(state.memory.load(addr, data_size/8, endness=arch_endness) -
                                       test_state.memory.load(addr, data_size/8, endness=arch_endness) ==
                                       test_state.se.BVV(difference, data_size))

        # get the actual register values
        all_deps = list(mem_change.addr_dependencies) + list(mem_change.data_dependencies)
        reg_vals = dict()
        for reg in set(all_deps):
            reg_vals[reg] = test_state.se.any_int(test_state.registers.load(reg))

        chain = self.set_regs(**reg_vals)
        chain.add_gadget(gadget)

        bytes_per_pop = self.project.arch.bits / 8
        chain.add_value(gadget.addr, needs_rebase=True)
        for _ in range(gadget.stack_change / bytes_per_pop - 1):
            chain.add_value(self._get_fill_val(), needs_rebase=False)
        return chain

    def _get_fill_val(self):
        if self._roparg_filler is not None:
            return self._roparg_filler
        else:
            return claripy.BVS("filler", self.project.arch.bits)

    def _set_badbytes(self, badbytes):
        self.badbytes = badbytes

    def _set_roparg_filler(self, roparg_filler):
        self._roparg_filler = roparg_filler

    # inspired by ropper
    def _containsbadbytes(self, gadget):
        n_bytes = self.project.arch.bits/8
        addr = gadget.addr

        for b in self.badbytes:
            address = addr
            if type(b) == str:
                b = ord(b)

            for _ in range(n_bytes):
                if (address & 0xff) == b:
                    return True
                address >>= 8


    # should also be able to do execve by providing writable memory
    # todo pivot stack
    # todo pass values to setregs as symbolic variables
    # todo progress bar still sucky
