import struct
import logging
from collections import defaultdict

import angr
import claripy

from .builder import Builder
from .. import rop_utils
from ..errors import RopException
from ..rop_chain import RopChain
from ..rop_value import RopValue
from ..rop_block import RopBlock

l = logging.getLogger(__name__)

class MemWriteChain:
    def __init__(self, builder, gadget, preserve_regs):
        self.project = builder.project
        self.builder = builder
        self.gadget = gadget
        self.preserve_regs = preserve_regs
        mem_write = self.gadget.mem_writes[0]
        self.addr_bv = claripy.BVS("addr", mem_write.addr_size)
        self.data_bv = claripy.BVS("data", mem_write.data_size)
        self.state = builder.make_sim_state(gadget.addr, gadget.stack_change//self.project.arch.bytes+1)
        self.chain = self._build_chain()

    def _build_chain(self):
        mem_write = self.gadget.mem_writes[0]

        # step through the state once to identify the mem_write action
        state = self.state
        final_state = rop_utils.step_to_unconstrained_successor(self.project, state)
        the_action = None
        for a in final_state.history.actions.hardcopy:
            if a.type != "mem" or a.action != "write":
                continue
            if set(rop_utils.get_ast_dependency(a.addr.ast)) == set(mem_write.addr_dependencies) and \
                    set(rop_utils.get_ast_dependency(a.data.ast)) == set(mem_write.data_dependencies):
                the_action = a
                break
        else:
            raise RopException("Couldn't find the matching action")

        # they both need to contain one single variable
        addr_ast = the_action.addr.ast
        data_ast = the_action.data.ast
        assert len(addr_ast.variables) == 1 and len(data_ast.variables) == 1

        # check the register values
        reg_vals = {}
        constrained_addrs = None
        for ast, bv, t in [(addr_ast, self.addr_bv, 'addr'), (data_ast, self.data_bv, 'data')]:
            # in case of short write
            if bv.size() < ast.size():
                bv = claripy.ZeroExt(ast.size() - bv.size(), bv)
            variable = list(ast.variables)[0]
            if variable.startswith('sreg_'):
                reg_vals[variable.split('-', 1)[0][5:]] = self.builder._rebalance_ast(ast, bv, mode='reg')[1]
            elif variable.startswith('symbolic_stack_'):
                if t == 'addr':
                    assert constrained_addrs is None
                    constrained_addrs = [ast]
            else:
                raise RuntimeError("what variable this is?")

        chain = self.builder.set_regs(**reg_vals, preserve_regs=self.preserve_regs)
        chain = RopBlock.from_chain(chain)
        chain = self.builder._build_reg_setting_chain([chain, self.gadget], {}, constrained_addrs=constrained_addrs)

        if not constrained_addrs:
            return chain
        addr_ast = constrained_addrs[0]
        addr_ast_vars = addr_ast.variables
        for idx, val in enumerate(chain._values):
            if not val.symbolic:
                continue
            if not addr_ast_vars.intersection(val.ast.variables):
                continue
            ast = self.builder._rebalance_ast(addr_ast, self.addr_bv)[1]
            # FIXME: again endness issue
            if ast.op == 'Reverse':
                ast = ast.args[0]
            val._value = ast
            break
        return chain

    def concretize(self, addr_val, data):
        chain = self.chain.copy()
        fmt = self.project.arch.struct_fmt()
        # replace addr and data
        for idx, val in enumerate(chain._values):
            if not val.symbolic or not val.ast.variables:
                continue
            if list(val.ast.variables)[0].startswith('addr_'):
                test_ast = claripy.algorithm.replace(expr=val.ast,
                                          old=self.addr_bv,
                                          new=addr_val.data)
                new = addr_val.copy()
                new._value = test_ast
                if addr_val._rebase:
                    new.rebase_ptr()
                chain._values[idx] = new
                continue
            if list(val.ast.variables)[0].startswith('data_'):
                var = claripy.BVV(struct.unpack(fmt, data.ljust(self.project.arch.bytes, b'\x00'))[0], len(self.data_bv))
                test_ast = claripy.algorithm.replace(expr=val.ast,
                                          old=self.data_bv,
                                          new=var)
                arch_bits = self.project.arch.bits
                if len(test_ast) < arch_bits:
                    test_ast = claripy.ZeroExt(arch_bits-len(test_ast), test_ast)
                # since this is data, we assume it should not be rebased
                val = RopValue(test_ast, self.project)
                val._rebase = False
                chain._values[idx] = val
                continue
            if list(val.ast.variables)[0].startswith('symbolic_stack_'):
                # FIXME: my lazy implementation, the endness mess really needs to be rewritten
                tmp = claripy.BVS(f"symbolic_stack_{idx}", self.project.arch.bits)
                if self.project.arch.memory_endness == 'Iend_LE':
                    tmp = claripy.Reverse(tmp)
                chain._values[idx] = RopValue(tmp, self.project)
        return chain

    @property
    def changed_regs(self):
        s = set()
        for g in self.chain._gadgets:
            s |= g.changed_regs
        return s

class MemWriter(Builder):
    """
    part of angrop's chainbuilder engine, responsible for writing data into memory
    using various techniques
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)
        self._mem_write_gadgets: set = None # type: ignore
        self._good_mem_write_gadgets = None # type: ignore
        self._mem_write_chain_cache = defaultdict(list)

    def bootstrap(self):
        self._mem_write_gadgets = self._get_all_mem_write_gadgets(self.chain_builder.gadgets)
        self._good_mem_write_gadgets = defaultdict(set)

    @staticmethod
    def _get_all_mem_write_gadgets(gadgets):
        """
        we consider a gadget mem_write gadget if
        1. it is self-contained
        2. there is only one symbolic memory access and it is a memory write
        3. addr/data are independent
        """
        possible_gadgets = set()
        for g in gadgets:
            if not g.self_contained:
                continue
            sym_rw = [m for m in g.mem_reads + g.mem_changes if m.is_symbolic_access()]
            if len(sym_rw) > 0 or len(g.mem_writes) != 1:
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
        if rop_utils.transit_num(g1) > rop_utils.transit_num(g2):
            return False
        return True

    def _gen_mem_write_gadgets(self, string_data, cache_key):
        # create a dict of bytes per write to gadgets
        # assume we need intersection of addr_dependencies and data_dependencies to be 0
        # TODO could allow mem_reads as long as we control the address?

        # generate from the cache first
        if self._good_mem_write_gadgets[cache_key]:
            yield from self._good_mem_write_gadgets[cache_key]

        # now look for gadgets that require least stack change
        possible_gadgets = {g for g in self._mem_write_gadgets if g.self_contained}
        possible_gadgets -= self._good_mem_write_gadgets[cache_key] # already yield these

        reg_setter = self.chain_builder._reg_setter
        can_set_regs = {x for x in reg_setter._reg_setting_dict if reg_setter._reg_setting_dict[x]}
        while possible_gadgets:
            to_remove = set()
            # limit the maximum size of the chain
            best_stack_change = 0x400
            best_gadget = None

            for g in possible_gadgets:
                mem_write = g.mem_writes[0]
                dep_regs = mem_write.addr_dependencies | mem_write.data_dependencies
                if not dep_regs.issubset(can_set_regs):
                    to_remove.add(g)
                    continue

                # estimate the stack_change cost of the gadget
                stack_change = g.stack_change
                for reg in dep_regs:
                    stack_change += reg_setter._reg_setting_dict[reg][0].stack_change
                bytes_per_write = mem_write.data_size // 8
                num_writes = (len(string_data) + bytes_per_write - 1)//bytes_per_write
                stack_change *= num_writes

                if stack_change < best_stack_change:
                    best_gadget = g
                    best_stack_change = stack_change
                if stack_change == best_stack_change and (best_gadget is None or self._better_than(g, best_gadget)):
                    best_gadget = g

            if to_remove:
                possible_gadgets -= to_remove

            if best_gadget:
                possible_gadgets.remove(best_gadget)
                yield best_gadget
            else:
                break

    @rop_utils.timeout(5)
    def _try_write_to_mem(self, gadget, addr, string_data, preserve_regs, fill_byte):
        gadget_code = str(self.project.factory.block(gadget.addr).capstone)
        l.debug("building mem_write chain with gadget:\n%s", gadget_code)
        mem_write = gadget.mem_writes[0]

        # build the chain
        # there should be only two cases. Either it is a string, or it is a single badbyte
        chain = RopChain(self.project, self, badbytes=self.badbytes)
        if len(string_data) == 1 and ord(string_data) in self.badbytes:
            chain += self._write_to_mem_with_gadget_with_cache(gadget, addr, string_data, preserve_regs)
        else:
            bytes_per_write = mem_write.data_size//8
            for i in range(0, len(string_data), bytes_per_write):
                to_write = string_data[i: i+bytes_per_write]
                # pad if needed
                if len(to_write) < bytes_per_write and fill_byte:
                    to_write += fill_byte * (bytes_per_write-len(to_write))
                chain += self._write_to_mem_with_gadget_with_cache(gadget, addr + i, to_write, preserve_regs)

        return chain

    def _write_to_mem(self, addr, string_data, preserve_regs=None, fill_byte=b"\xff"):# pylint:disable=inconsistent-return-statements
        """
        :param addr: address to store the string
        :param string_data: string to store
        :param fill_byte: a byte to use to fill up the string if necessary
        :return: a rop chain
        """
        if preserve_regs is None:
            preserve_regs = set()

        key = (len(string_data), tuple(sorted(preserve_regs)))
        for gadget in self._gen_mem_write_gadgets(string_data, key):
            # sanity checks, make sure it doesn't clobber any preserved_regs
            if gadget.changed_regs.intersection(preserve_regs):
                continue
            mem_write = gadget.mem_writes[0]
            all_deps = mem_write.addr_dependencies | mem_write.data_dependencies
            if all_deps.intersection(preserve_regs):
                continue

            # actually trying each gadget and cache the good gadgets
            try:
                chain = self._try_write_to_mem(gadget, addr, string_data, preserve_regs, fill_byte)
                self._good_mem_write_gadgets[key].add(gadget)
                return chain
            except (RopException, angr.errors.SimEngineError, angr.errors.SimUnsatError):
                pass

        raise RopException("Fail to write data to memory :(")

    def _write_to_mem_with_gadget_with_cache(self, gadget, addr_val, data, preserve_regs):
        mem_write = gadget.mem_writes[0]
        if len(mem_write.addr_dependencies) <= 1 and len(mem_write.data_dependencies) <= 1 and mem_write.data_size in (32, 64):
            if not self._mem_write_chain_cache[gadget]:
                try:
                    cache_chain = MemWriteChain(self, gadget, preserve_regs)
                    self._mem_write_chain_cache[gadget].append(cache_chain)
                except RopException:
                    pass
            for cache_chain in self._mem_write_chain_cache[gadget]:
                if cache_chain.changed_regs.intersection(preserve_regs):
                    continue
                chain = cache_chain.concretize(addr_val, data)
                state = chain.exec()
                sim_data = state.memory.load(addr_val.data, len(data))
                if state.solver.eval(sim_data, cast_to=bytes) == data:
                    return chain
                l.error("write_to_mem_with_gadget_with_cache failed: %s %s %s\n%s\n%s", addr_val,
                        data, preserve_regs, gadget.dstr(), sim_data)
                continue
        return self._write_to_mem_with_gadget(gadget, addr_val, data, preserve_regs)

    def _write_to_mem_with_gadget(self, gadget, addr_val, data, preserve_regs):
        """
        addr_val is a RopValue
        """
        addr_bvs = claripy.BVS("addr", self.project.arch.bits)
        mem_write = gadget.mem_writes[0]
        all_deps = mem_write.addr_dependencies | mem_write.data_dependencies

        # constrain the successor to be at the gadget
        # emulate 'pop pc'
        test_state = self.make_sim_state(gadget.addr, gadget.stack_change//self.project.arch.bytes)

        # step the gadget
        pre_gadget_state = test_state
        state = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)

        # constrain the write
        the_action = None
        for a in state.history.actions.hardcopy:
            if a.type != "mem" or a.action != "write":
                continue
            if set(rop_utils.get_ast_dependency(a.addr.ast)) == set(mem_write.addr_dependencies) or \
                    set(rop_utils.get_ast_dependency(a.data.ast)) == set(mem_write.data_dependencies):
                the_action = a
                break
        else:
            raise RopException("Couldn't find the matching action")

        # constrain the addr
        test_state.add_constraints(the_action.addr.ast == addr_bvs, addr_bvs == addr_val.data)
        pre_gadget_state.add_constraints(the_action.addr.ast == addr_bvs, addr_bvs == addr_val.data)
        pre_gadget_state.options.discard(angr.options.AVOID_MULTIVALUED_WRITES)
        state = rop_utils.step_to_unconstrained_successor(self.project, pre_gadget_state)

        # constrain the data
        test_state.add_constraints(state.memory.load(addr_val.data, len(data)) == claripy.BVV(data))

        # get the actual register values
        reg_vals = {}
        new_addr_val = None
        constrained_addrs = None
        name = addr_bvs._encoded_name.decode()
        for reg in all_deps:
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
                    new_addr_val = var
                    break
            reg_vals[reg] = var

        # if this address is set by stack
        if new_addr_val is None:
            constrained_addrs = [addr_val.data]

        chain = self.set_regs(**reg_vals, preserve_regs=preserve_regs)
        chain = RopBlock.from_chain(chain)
        chain = self._build_reg_setting_chain([chain, gadget], {}, constrained_addrs=constrained_addrs)
        for idx, val in enumerate(chain._values):
            if not val.symbolic and new_addr_val is not None and not new_addr_val.symbolic and val.concreted == new_addr_val.concreted:
                chain._values[idx] = new_addr_val
                break

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

    ##### Main Entrance #####
    def write_to_mem(self, addr, data, preserve_regs=None, fill_byte=b"\xff"):
        """
        main function
        1. do parameter sanitization
        2. cutting the data to smaller pieces to handle bad bytes in the data
        """
        if preserve_regs is None:
            preserve_regs = set()

        # sanity check
        if not (isinstance(fill_byte, bytes) and len(fill_byte) == 1):
            raise RopException("fill_byte is not a one byte string, aborting")
        if not isinstance(data, bytes):
            raise RopException("data is not a byte string, aborting")
        if ord(fill_byte) in self.badbytes:
            raise RopException("fill_byte is a bad byte!")
        if isinstance(addr, RopValue) and addr.symbolic:
            raise RopException("cannot write to a symbolic address")

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
                chain += self._write_to_mem(ptr, elem, preserve_regs=preserve_regs, fill_byte=fill_byte)
                offset += len(elem)
            else:
                chain += self._write_to_mem(ptr, elem, preserve_regs=preserve_regs, fill_byte=fill_byte)
                offset += 1
        return chain
