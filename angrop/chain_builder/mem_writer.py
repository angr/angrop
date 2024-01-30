import struct
import logging

import angr
import claripy

from .. import rop_utils
from ..errors import RopException
from ..rop_chain import RopChain
from ..rop_value import RopValue

l = logging.getLogger("angrop.chain_builder.mem_writer")

class MemWriter:
    """
    part of angrop's chainbuilder engine, responsible for writing data into memory
    using various techniques
    TODO: add a testcase for add_mem
    """
    def __init__(self, project, reg_setter, base_pointer, gadgets, badbytes=None, filler=None):
        self.project = project
        self.badbytes = badbytes

        self._reg_setter = reg_setter
        self._base_pointer = base_pointer
        self._mem_write_gadgets = self._get_all_mem_write_gadgets(gadgets)
        self._mem_change_gadgets = self._get_all_mem_change_gadgets(gadgets)
        self._test_symbolic_state = rop_utils.make_symbolic_state(self.project, self._reg_setter._reg_set)

        self._roparg_filler = filler

    def _set_regs(self, *args, **kwargs):
        return self._reg_setter.run(*args, **kwargs)

    @staticmethod
    def _get_all_mem_write_gadgets(gadgets):
        possible_gadgets = set()
        for g in gadgets:
            if len(g.mem_reads) + len(g.mem_changes) > 0 or len(g.mem_writes) != 1:
                continue
            if g.bp_moves_to_sp:
                continue
            if g.stack_change <= 0:
                continue
            for m_access in g.mem_writes:
                if m_access.addr_controllable() and m_access.data_controllable() and m_access.addr_data_independent():
                    possible_gadgets.add(g)
        return possible_gadgets

    @staticmethod
    def _get_all_mem_change_gadgets(gadgets):
        possible_gadgets = set()
        for g in gadgets:
            if len(g.mem_reads) + len(g.mem_writes) > 0 or len(g.mem_changes) != 1:
                continue
            if g.bp_moves_to_sp:
                continue
            if g.stack_change <= 0:
                continue
            for m_access in g.mem_changes:
                if m_access.addr_controllable() and m_access.data_controllable() and m_access.addr_data_independent():
                    possible_gadgets.add(g)
        return possible_gadgets

    def _contain_badbyte(self, ptr):
        """
        check if a pointer contains any bad byte
        """
        if isinstance(ptr, RopValue):
            if ptr.symbolic:
                return False
            else:
                ptr = ptr.concreted
        raw_bytes = struct.pack(self.project.arch.struct_fmt(), ptr)
        if any(x in raw_bytes for x in self.badbytes):
            return True
        return False

    def _gen_mem_write_gadgets(self, string_data):
        # create a dict of bytes per write to gadgets
        # assume we need intersection of addr_dependencies and data_dependencies to be 0
        # TODO could allow mem_reads as long as we control the address?
        possible_gadgets = self._mem_write_gadgets

        while possible_gadgets:
            # get the data from trying to set all the registers
            registers = dict((reg, 0x41) for reg in self._reg_setter._reg_set)
            l.debug("getting reg data for mem writes")
            _, _, reg_data = self._reg_setter._find_reg_setting_gadgets(max_stack_change=0x50, **registers)
            l.debug("trying mem_write gadgets")

            # limit the maximum size of the chain
            best_stack_change = 0x400
            best_gadget = None
            use_partial_controllers = False
            for t, vals in reg_data.items():
                if vals[1] >= best_stack_change:
                    continue
                for g in possible_gadgets:
                    mem_write = g.mem_writes[0]
                    if (set(mem_write.addr_dependencies) | set(mem_write.data_dependencies)).issubset(set(t)):
                        stack_change = g.stack_change + vals[1]
                        bytes_per_write = mem_write.data_size // 8
                        num_writes = (len(string_data) + bytes_per_write - 1)//bytes_per_write
                        stack_change *= num_writes
                        if stack_change < best_stack_change:
                            best_gadget = g
                            best_stack_change = stack_change

            # try again using partial_controllers
            best_stack_change = 0x400
            if best_gadget is None:
                use_partial_controllers = True
                l.warning("Trying to use partial controllers for memory write")
                l.debug("getting reg data for mem writes")
                _, _, reg_data = self._reg_setter._find_reg_setting_gadgets(max_stack_change=0x50,
                                                                use_partial_controllers=True,
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
                            num_writes = (len(string_data) + bytes_per_write - 1)//bytes_per_write
                            stack_change *= num_writes
                            if stack_change < best_stack_change:
                                best_gadget = g
                                best_stack_change = stack_change

            yield best_gadget, use_partial_controllers
            possible_gadgets.remove(best_gadget)

    @rop_utils.timeout(5)
    def _try_write_to_mem(self, gadget, use_partial_controllers, addr, string_data, fill_byte):
        gadget_code = str(self.project.factory.block(gadget.addr).capstone)
        l.debug("building mem_write chain with gadget:\n%s", gadget_code)
        mem_write = gadget.mem_writes[0]
        bytes_per_write = mem_write.data_size//8 if not use_partial_controllers else 1

        # build the chain
        chain = RopChain(self.project, self, badbytes=self.badbytes)
        for i in range(0, len(string_data), bytes_per_write):
            to_write = string_data[i: i+bytes_per_write]
            # pad if needed
            if len(to_write) < bytes_per_write:
                to_write += fill_byte * (bytes_per_write-len(to_write))
            chain = chain + self._write_to_mem_with_gadget(gadget, addr + i, to_write, use_partial_controllers)

        return chain

    def _write_to_mem(self, addr, string_data, fill_byte=b"\xff"):# pylint:disable=inconsistent-return-statements
        """
        :param addr: address to store the string
        :param string_data: string to store
        :param fill_byte: a byte to use to fill up the string if necessary
        :return: a rop chain
        """

        gen = self._gen_mem_write_gadgets(string_data)
        gadget, use_partial_controllers = next(gen, (None, None))
        while gadget:
            try:
                return self._try_write_to_mem(gadget, use_partial_controllers, addr, string_data, fill_byte)
            except (RopException, angr.errors.SimEngineError, angr.errors.SimUnsatError):
                pass
            gadget, use_partial_controllers  = next(gen, (None, None))

        try:
            return self._write_to_mem_v2(addr, string_data)
        except (RopException, angr.errors.SimEngineError, angr.errors.SimUnsatError):
            pass

        raise RopException("Fail to write data to memory :(")

    def _write_to_mem_v2(self, addr, data):
        """
        :param addr: address to store the string
        :param data: string to store
        :return: a rop chain
        """
        # assume we need intersection of addr_dependencies and data_dependencies to be 0
        # TODO could allow mem_reads as long as we control the address?
        # TODO implement better, allow adding a single byte repeatedly

        possible_gadgets = [x for x in self._mem_change_gadgets if x.mem_changes[0].op in ("__or__", "__and__")]

        # get the data from trying to set all the registers
        registers = dict((reg, 0x41) for reg in self._reg_setter._reg_set)
        l.debug("getting reg data for mem adds")
        _, _, reg_data = self._reg_setter._find_reg_setting_gadgets(max_stack_change=0x50, **registers)
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
                    bytes_per_write = mem_change.data_size//8
                    stack_change *= bytes_per_write
                    if stack_change < best_stack_change:
                        best_gadget = g
                        best_stack_change = stack_change

        if best_gadget is None:
            raise RopException("Couldnt set registers for any memory add gadget")

        l.debug("Now building the mem const chain")
        mem_change = best_gadget.mem_changes[0]
        bytes_per_write = mem_change.data_size//8

        # build the chain
        if mem_change.op == "__or__":
            final_value = -1
        elif mem_change.op == "__and__":
            final_value = 0
        else:
            raise RopException("This shouldn't happen")
        chain = RopChain(self.project, self, badbytes=self.badbytes)
        for i in range(0, len(data), bytes_per_write):
            chain = chain + self._change_mem_with_gadget(best_gadget, addr + i,
                                                         mem_change.data_size, final_val=final_value)
        # FIXME for other adds
        for i in range(0, len(data), 4):
            to_write = data[i: i+4]
            # pad if needed
            if len(to_write) < 4:
                to_write += b"\xff" * (4-len(to_write))
            to_add = struct.unpack("<I", to_write)[0] - final_value
            chain += self.add_to_mem(addr+i, to_add, 32)
        return chain

    def write_to_mem(self, addr, data, fill_byte=b"\xff"):

        # sanity check
        if not (isinstance(fill_byte, bytes) and len(fill_byte) == 1):
            raise RopException("fill_byte is not a one byte string, aborting")
        if not isinstance(data, bytes):
            raise RopException("data is not a byte string, aborting")
        if ord(fill_byte) in self.badbytes:
            raise RopException("fill_byte is a bad byte!")

        # split the string into smaller elements so that we can
        # handle bad bytes
        if all(x not in self.badbytes for x in data):
            elems = [data]
        else:
            elems = []
            e = b''
            for x in data:
                if x not in self.badbytes:
                    e += bytes([x])
                else:
                    elems.append(e)
                    elems.append(bytes([x]))
                    e = b''

        # do the write
        offset = 0
        chain = RopChain(self.project, self, badbytes=self.badbytes)
        for elem in elems:
            ptr = addr + offset
            if self._contain_badbyte(ptr):
                raise RopException(f"{ptr:#x} contains bad byte!")
            if elem not in self.badbytes:
                chain += self._write_to_mem(ptr, elem, fill_byte=fill_byte)
                offset += len(elem)
            else:
                chain += self._write_to_mem(ptr, elem, fill_byte=fill_byte)
                offset += 1
        return chain

    def add_to_mem(self, addr, value, data_size=None):
        # assume we need intersection of addr_dependencies and data_dependencies to be 0
        # TODO could allow mem_reads as long as we control the address?

        if data_size is None:
            data_size = self.project.arch.bits

        possible_gadgets = {x for x in self._mem_change_gadgets
                    if x.mem_changes[0].op in ('__add__', '__sub__') and x.mem_changes[0].data_size == data_size}

        # get the data from trying to set all the registers
        registers = dict((reg, 0x41) for reg in self._reg_setter._reg_set)
        l.debug("getting reg data for mem adds")
        _, _, reg_data = self._reg_setter._find_reg_setting_gadgets(max_stack_change=0x50, **registers)
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

    def _write_to_mem_with_gadget(self, gadget, addr_val, data, use_partial_controllers=False):
        """
        addr is a RopValue
        """
        addr_bvs = claripy.BVS("addr", self.project.arch.bits)

        # sanity check for simple gadget
        if len(gadget.mem_writes) != 1 or len(gadget.mem_reads) + len(gadget.mem_changes) > 0:
            raise RopException("too many memory accesses for my lazy implementation")

        if use_partial_controllers and len(data) < self.project.arch.bytes:
            data = data.ljust(self.project.arch.bytes, b"\x00")

        arch_bytes = self.project.arch.bytes
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
        state = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)

        # constrain the write
        mem_write = gadget.mem_writes[0]
        the_action = None
        for a in state.history.actions.hardcopy:
            if a.type != "mem" or a.action != "write":
                continue
            if set(rop_utils.get_ast_dependency(a.addr.ast)) == set(mem_write.addr_dependencies) or \
                    set(rop_utils.get_ast_dependency(a.data.ast)) == set(mem_write.data_dependencies):
                the_action = a
                break

        if the_action is None:
            raise RopException("Couldn't find the matching action")

        # constrain the addr
        test_state.add_constraints(the_action.addr.ast == addr_bvs, addr_bvs == addr_val.data)
        pre_gadget_state.add_constraints(the_action.addr.ast == addr_bvs, addr_bvs = addr_val.data)
        pre_gadget_state.options.discard(angr.options.AVOID_MULTIVALUED_WRITES)
        state = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)

        # constrain the data
        test_state.add_constraints(state.memory.load(addr_val.data, len(data)) == test_state.solver.BVV(data))

        # get the actual register values
        all_deps = list(mem_write.addr_dependencies) + list(mem_write.data_dependencies)
        reg_vals = {}
        name = addr_bvs._encoded_name.decode()
        for reg in set(all_deps):
            var = test_state.solver.eval(test_state.registers.load(reg))
            # check whether this reg will propagate to addr
            # if yes, propagate its rebase value
            for c in test_state.solver.constraints:
                if len(c.variables) != 2: # xx == yy
                    continue
                if name not in c.variables:
                    continue
                var_names = set(c.variables)
                var_names.remove(name)
                if reg in var_names.pop():
                    var = rop_utils.cast_rop_value(var, self.project)
                    if addr_val._rebase:
                        var.rebase_ptr()
                    break
            reg_vals[reg] = var

        chain = self._set_regs(use_partial_controllers=use_partial_controllers, **reg_vals)
        chain.add_gadget(gadget)

        bytes_per_pop = self.project.arch.bytes
        for _ in range(gadget.stack_change // bytes_per_pop - 1):
            chain.add_value(self._get_fill_val())

        # verify the write actually works
        state = chain.exec()
        sim_data = state.memory.load(addr_val.data, len(data))
        if not state.solver.eval(sim_data == data):
            raise RopException("memory write fails")
        return chain

    def _change_mem_with_gadget(self, gadget, addr, data_size, final_val=None, difference=None):
        # sanity check for simple gadget
        if len(gadget.mem_writes) + len(gadget.mem_changes) != 1 or len(gadget.mem_reads) != 0:
            raise RopException("too many memory accesses for my lazy implementation")

        if (final_val is not None and difference is not None) or (final_val is None and difference is None):
            raise RopException("must specify difference or final value and not both")

        arch_bytes = self.project.arch.bytes
        arch_endness = self.project.arch.memory_endness

        # constrain the successor to be at the gadget
        # emulate 'pop pc'
        test_state = self._test_symbolic_state.copy()
        rop_utils.make_reg_symbolic(test_state, self._base_pointer)

        if difference is not None:
            test_state.memory.store(addr, test_state.solver.BVV(~difference, data_size)) # pylint:disable=invalid-unary-operand-type
        if final_val is not None:
            test_state.memory.store(addr, test_state.solver.BVV(~final_val, data_size)) # pylint:disable=invalid-unary-operand-type

        test_state.regs.ip = gadget.addr
        test_state.add_constraints(
            test_state.memory.load(test_state.regs.sp, arch_bytes, endness=arch_endness) == gadget.addr)
        test_state.regs.sp += arch_bytes

        # step the gadget
        pre_gadget_state = test_state
        state = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)

        # constrain the change
        mem_change = gadget.mem_changes[0]
        the_action = None
        for a in state.history.actions.hardcopy:
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
        pre_gadget_state.options.discard(angr.options.AVOID_MULTIVALUED_WRITES)
        pre_gadget_state.options.discard(angr.options.AVOID_MULTIVALUED_READS)
        state = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)

        # constrain the data
        if final_val is not None:
            test_state.add_constraints(state.memory.load(addr, data_size//8, endness=arch_endness) ==
                                       test_state.solver.BVV(final_val, data_size))
        if difference is not None:
            test_state.add_constraints(state.memory.load(addr, data_size//8, endness=arch_endness) -
                                       test_state.memory.load(addr, data_size//8, endness=arch_endness) ==
                                       test_state.solver.BVV(difference, data_size))

        # get the actual register values
        all_deps = list(mem_change.addr_dependencies) + list(mem_change.data_dependencies)
        reg_vals = {}
        for reg in set(all_deps):
            reg_vals[reg] = test_state.solver.eval(test_state.registers.load(reg))

        chain = self._set_regs(**reg_vals)
        chain.add_gadget(gadget)

        bytes_per_pop = self.project.arch.bytes
        for _ in range(gadget.stack_change // bytes_per_pop - 1):
            chain.add_value(self._get_fill_val())
        return chain

    def _get_fill_val(self):
        if self._roparg_filler is not None:
            return self._roparg_filler
        else:
            return claripy.BVS("filler", self.project.arch.bits)
