import logging

import angr
import claripy

from .builder import Builder
from .. import rop_utils
from ..errors import RopException
from ..rop_chain import RopChain
from ..rop_value import RopValue

l = logging.getLogger("angrop.chain_builder.mem_writer")

class MemWriter(Builder):
    """
    part of angrop's chainbuilder engine, responsible for writing data into memory
    using various techniques
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)
        self._mem_write_gadgets: set = None # type: ignore
        self._good_mem_write_gadgets: set = None # type: ignore

    def bootstrap(self):
        self._mem_write_gadgets = self._get_all_mem_write_gadgets(self.chain_builder.gadgets)
        self._good_mem_write_gadgets = set()

    def _set_regs(self, *args, **kwargs):
        return self.chain_builder._reg_setter.run(*args, **kwargs)

    @staticmethod
    def _get_all_mem_write_gadgets(gadgets):
        possible_gadgets = set()
        for g in gadgets:
            if not g.self_contained:
                continue
            sym_rw = set(m for m in g.mem_reads + g.mem_changes if m.is_symbolic_access())
            if len(sym_rw) > 0 or len(g.mem_writes) != 1:
                continue
            if g.stack_change <= 0:
                continue
            for m_access in g.mem_writes:
                if m_access.addr_controllable() and m_access.data_controllable() and m_access.addr_data_independent():
                    possible_gadgets.add(g)
        return possible_gadgets

    def _better_than(self, g1, g2):
        if g1.stack_change > g2.stack_change:
            return False
        if g1.num_sym_mem_access > g2.num_sym_mem_access:
            return False
        if g1.isn_count > g2.isn_count:
            return False
        if not g1.changed_regs.issubset(g2.changed_regs):
            return False
        return True

    def _gen_mem_write_gadgets(self, string_data):
        # create a dict of bytes per write to gadgets
        # assume we need intersection of addr_dependencies and data_dependencies to be 0
        # TODO could allow mem_reads as long as we control the address?

        # generate from the cache first
        if self._good_mem_write_gadgets:
            yield from self._good_mem_write_gadgets

        possible_gadgets = {g for g in self._mem_write_gadgets.copy() if g.transit_type != 'jmp_reg'}
        possible_gadgets -= self._good_mem_write_gadgets # already yield these

        # use the graph-search to gain a rough idea about (stack_change, register setting)
        registers = dict((reg, 0x41) for reg in self.arch.reg_set)
        l.debug("getting reg data for mem writes")
        reg_setter = self.chain_builder._reg_setter
        _, _, reg_data = reg_setter.find_candidate_chains_graph_search(max_stack_change=0x50, **registers)
        l.debug("trying mem_write gadgets")

        # find a write gadget that induces the smallest stack_change
        while possible_gadgets:
            # limit the maximum size of the chain
            best_stack_change = 0x400
            best_gadget = None
            # regs: according to the graph search, what registers can be controlled
            # vals[1]: stack_change to set those registers
            for regs, vals in reg_data.items():
                reg_set_stack_change = vals[1]
                if reg_set_stack_change > best_stack_change:
                    continue
                for g in possible_gadgets:
                    mem_write = g.mem_writes[0]
                    if not (mem_write.addr_dependencies | mem_write.data_dependencies).issubset(regs):
                        continue
                    stack_change = g.stack_change + reg_set_stack_change
                    bytes_per_write = mem_write.data_size // 8
                    num_writes = (len(string_data) + bytes_per_write - 1)//bytes_per_write
                    stack_change *= num_writes
                    if stack_change < best_stack_change:
                        best_gadget = g
                        best_stack_change = stack_change
                    if stack_change == best_stack_change and self._better_than(g, best_gadget):
                        best_gadget = g

            if best_gadget:
                possible_gadgets.remove(best_gadget)
                yield best_gadget
            else:
                break

    @rop_utils.timeout(5)
    def _try_write_to_mem(self, gadget, use_partial_controllers, addr, string_data, fill_byte):
        gadget_code = str(self.project.factory.block(gadget.addr).capstone)
        l.debug("building mem_write chain with gadget:\n%s", gadget_code)
        mem_write = gadget.mem_writes[0]

        # build the chain
        # there should be only two cases. Either it is a string, or it is a single badbyte
        chain = RopChain(self.project, self, badbytes=self.badbytes)
        if len(string_data) == 1 and ord(string_data) in self.badbytes:
            chain += self._write_to_mem_with_gadget(gadget, addr, string_data, use_partial_controllers)
        else:
            bytes_per_write = mem_write.data_size//8 if not use_partial_controllers else 1
            for i in range(0, len(string_data), bytes_per_write):
                to_write = string_data[i: i+bytes_per_write]
                # pad if needed
                if len(to_write) < bytes_per_write and fill_byte:
                    to_write += fill_byte * (bytes_per_write-len(to_write))
                chain += self._write_to_mem_with_gadget(gadget, addr + i, to_write, use_partial_controllers)

        return chain

    def _write_to_mem(self, addr, string_data, fill_byte=b"\xff"):# pylint:disable=inconsistent-return-statements
        """
        :param addr: address to store the string
        :param string_data: string to store
        :param fill_byte: a byte to use to fill up the string if necessary
        :return: a rop chain
        """
        for gadget in self._gen_mem_write_gadgets(string_data):
            try:
                chain = self._try_write_to_mem(gadget, False, addr, string_data, fill_byte)
                self._good_mem_write_gadgets.add(gadget)
                return chain
            except (RopException, angr.errors.SimEngineError, angr.errors.SimUnsatError):
                pass

        raise RopException("Fail to write data to memory :(")

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
                    if e:
                        elems.append(e)
                    elems.append(bytes([x]))
                    e = b''
            if e:
                elems.append(e)

        # do the write
        offset = 0
        chain = RopChain(self.project, self, badbytes=self.badbytes)
        for elem in elems:
            ptr = addr + offset
            if self._word_contain_badbyte(ptr):
                raise RopException(f"{ptr} contains bad byte!")
            if len(elem) != 1 or ord(elem) not in self.badbytes:
                chain += self._write_to_mem(ptr, elem, fill_byte=fill_byte)
                offset += len(elem)
            else:
                chain += self._write_to_mem(ptr, elem, fill_byte=fill_byte)
                offset += 1
        return chain

    def _write_to_mem_with_gadget(self, gadget, addr_val, data, use_partial_controllers=False):
        """
        addr_val is a RopValue
        """
        addr_bvs = claripy.BVS("addr", self.project.arch.bits)

        # sanity check for simple gadget
        if len(gadget.mem_writes) != 1 or len(gadget.mem_reads) + len(gadget.mem_changes) > 0:
            raise RopException("too many memory accesses for my lazy implementation")

        if use_partial_controllers and len(data) < self.project.arch.bytes:
            data = data.ljust(self.project.arch.bytes, b"\x00")

        # constrain the successor to be at the gadget
        # emulate 'pop pc'
        test_state = self.make_sim_state(gadget.addr)

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
        pre_gadget_state.add_constraints(the_action.addr.ast == addr_bvs, addr_bvs == addr_val.data)
        pre_gadget_state.options.discard(angr.options.AVOID_MULTIVALUED_WRITES)
        state = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)

        # constrain the data
        test_state.add_constraints(state.memory.load(addr_val.data, len(data)) == claripy.BVV(data))

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
                    var = RopValue(var, self.project)
                    var._rebase = False
                    if addr_val._rebase:
                        var.rebase_ptr()
                        var._rebase = True
                    break
            reg_vals[reg] = var


        chain = self._set_regs(**reg_vals)
        chain.add_gadget(gadget)

        bytes_per_pop = self.project.arch.bytes
        pc_offset = None
        if gadget.transit_type == 'pop_pc':
            pc_offset = gadget.pc_offset
        else:
            raise ValueError(f"Unknown gadget transit_type: {gadget.transit_type}")

        for idx in range(gadget.stack_change // bytes_per_pop):
            if idx == pc_offset//bytes_per_pop:
                next_pc_val = rop_utils.cast_rop_value(
                    chain._blank_state.solver.BVS("next_pc", self.project.arch.bits),
                    self.project,
                )
                chain.add_value(next_pc_val)
                continue
            chain.add_value(self._get_fill_val())

        # verify the write actually works
        state = chain.exec()
        sim_data = state.memory.load(addr_val.data, len(data))
        if not state.solver.eval(sim_data == data):
            raise RopException("memory write fails")

        # the next pc must be in our control
        if len(state.regs.pc.variables) != 1:
            raise RopException("must have only one pc variable")
        if not set(state.regs.pc.variables).pop().startswith("next_pc_"):
            raise RopException("the next pc is not in our control!")
        return chain
