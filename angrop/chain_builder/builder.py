import re
import math
import struct
import logging
import itertools
from abc import abstractmethod
from functools import cmp_to_key
from collections import defaultdict

import claripy

from .. import rop_utils
from ..errors import RopException
from ..rop_gadget import RopGadget
from ..rop_value import RopValue
from ..rop_chain import RopChain
from ..rop_block import RopBlock
from ..gadget_finder.gadget_analyzer import GadgetAnalyzer

l = logging.getLogger(__name__)

class Builder:
    """
    a generic class to bootstrap more complicated chain building functionality
    """
    used_writable_ptrs = []

    def __init__(self, chain_builder):
        self.chain_builder = chain_builder
        self.project = chain_builder.project
        self.arch = chain_builder.arch
        # used for effect analysis
        self._gadget_analyzer = GadgetAnalyzer(self.project,
                                               True,
                                               kernel_mode=False,
                                               arch=self.arch)

    @property
    def badbytes(self):
        return self.chain_builder.badbytes

    @property
    def roparg_filler(self):
        return self.chain_builder.roparg_filler

    def make_sim_state(self, pc, stack_gsize):
        """
        make a symbolic state with all general purpose register + base pointer symbolized
        and emulate a `pop pc` situation
        """
        state = rop_utils.make_symbolic_state(self.project, self.arch.reg_list, stack_gsize)
        state.stack_pop()
        state.regs.ip = pc
        return state

    def set_regs(self, *args, **kwargs):
        return self.chain_builder._reg_setter.run(*args, **kwargs)

    @staticmethod
    def _sort_chains(chains):
        def cmp_func(chain1, chain2):
            stack_change1 = sum(x.stack_change for x in chain1)
            stack_change2 = sum(x.stack_change for x in chain2)
            if stack_change1 > stack_change2:
                return 1
            elif stack_change1 < stack_change2:
                return -1

            num_mem_access1 = sum(x.num_sym_mem_access for x in chain1)
            num_mem_access2 = sum(x.num_sym_mem_access for x in chain2)
            if num_mem_access1 > num_mem_access2:
                return 1
            if num_mem_access1 < num_mem_access2:
                return -1
            return 0
        return sorted(chains, key=cmp_to_key(cmp_func))

    def _word_contain_badbyte(self, ptr):
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

    def _get_ptr_to_writable(self, size):
        """
        get a pointer to writable region that can fit `size` bytes
        currently, we force it to point to a NULL region
        it shouldn't contain bad byte
        """
        null = b'\x00'*size
        used_writable_ptrs = list(self.__class__.used_writable_ptrs)

        plt_sec = None
        # get all writable segments
        if self.arch.kernel_mode:
            segs = [x for x in self.project.loader.main_object.sections if x.name in ('.data', '.bss')]
        else:
            segs = [ s for s in self.project.loader.main_object.segments if s.is_writable ]
            for sec in self.project.loader.main_object.sections:
                if sec.name == '.got.plt':
                    plt_sec = sec
                    break

        def addr_is_used(addr):
            for a, s in used_writable_ptrs:
                if a <= addr < a+s or a < addr+size <= a+s:
                    return True
            return False

        # enumerate through all address to find a good address
        for seg in segs:
            # we should use project.loader.memory.find API, but it is currently broken as reported here:
            # https://github.com/angr/angr/issues/5330
            max_addr = math.ceil(seg.max_addr / 0x1000)*0x1000 # // round up to page size
            contains_plt = False
            # my lazy implementation of avoiding taking addresses from the GOT table
            # because they may not be zero during runtime even though they appear to be so in the binary
            if plt_sec:
                contains_plt = seg.min_addr <= plt_sec.min_addr and seg.max_addr >= plt_sec.max_addr
            for addr in range(seg.min_addr, max_addr):
                if plt_sec and contains_plt and plt_sec.contains_addr(addr):
                    continue
                if any(self._word_contain_badbyte(x) for x in range(addr, addr+size, self.project.arch.bytes)):
                    continue

                data_len = size
                if addr >= seg.max_addr and not addr_is_used(addr):
                    self.__class__.used_writable_ptrs.append((addr, size))
                    return addr
                if addr+size > seg.max_addr:
                    data_len = addr+size - seg.max_addr
                try:
                    data = self.project.loader.memory.load(addr, data_len)
                except KeyError:
                    continue
                if data == null[:data_len] and not addr_is_used(addr):
                    self.__class__.used_writable_ptrs.append((addr, size))
                    return addr

        l.error("used up all possible writable ptrs")
        raise RopException("used up all possible writable ptrs")

    def _get_ptr_to_null(self):
        # get all non-writable segments
        segs = [ s for s in self.project.loader.main_object.segments if not s.is_writable ]
        # enumerate through all address to find a good address
        null = b'\x00'*self.project.arch.bytes
        for seg in segs:
            for addr in self.project.loader.memory.find(null, search_min=seg.min_addr, search_max=seg.max_addr):
                if not self._word_contain_badbyte(addr):
                    return addr

        l.error("used up all possible ptrs to null")
        raise RopException("used up all possible ptrs to null")

    @staticmethod
    def _ast_contains_stack_data(ast):
        vs = ast.variables
        return len(vs) == 1 and list(vs)[0].startswith('symbolic_stack_')

    @staticmethod
    def _ast_contains_reg_data(ast):
        vs = ast.variables
        return len(vs) == 1 and list(vs)[0].startswith('sreg_')

    def _build_ast_constraints(self, ast):
        var_map = {}

        # well, if this ast is just a symbolic value, just record itself
        if ast.op == 'BVS':
            name = ast.args[0]
            bits = ast.args[1]
            reg = name[5:].split('-')[0]
            old_var = ast
            new_var = claripy.BVS("sreg_" + reg + "-", bits)
            var_map[reg] = (old_var, new_var)

        #  if this ast is a tree, record all the children_asts
        for x in ast.children_asts():
            if x.op != 'BVS':
                continue
            name = x.args[0]
            bits = x.args[1]
            if not name.startswith("sreg_"):
                raise NotImplementedError(f"cannot rebuild ast: {ast}")
            reg = name[5:].split('-')[0]
            old_var = x
            if reg not in var_map:
                reg = name[5:].split('-')[0]
                new_var = claripy.BVS("sreg_" + reg + "-", bits)
                var_map[reg] = (old_var, new_var)

        consts = []
        for old, new in var_map.values():
            consts.append(old == new)
        rop_values = {x:RopValue(y[1], self.project) for x,y in var_map.items()}
        return rop_values, consts

    def _solve_ast_constraint(self, ast, value):
        variables = set()
        if ast.op == 'BVS':
            variables.add(ast)
        else:
            for x in ast.children_asts():
                if x.op != 'BVS':
                    continue
                variables.add(x)
        solver = claripy.Solver()
        solver.add(ast == value)

        variables = list(variables)

        res = solver.batch_eval(variables, 1)
        assert res
        res = res[0]

        reg_d = dict()
        stack_d = dict()
        for idx, v in enumerate(variables):
            name = v.args[0]
            if name.startswith("sreg_"):
                reg = name.split('_')[1][:-1]
                reg_d[reg] = res[idx]
            elif name.startswith("symbolic_stack_"):
                re_res = re.match(r"symbolic_stack_(\d+)_", name)
                offset = int(re_res.group(1))
                val = res[idx]
                if self.project.arch.memory_endness == "Iend_LE":
                    val = claripy.Reverse(claripy.BVV(val, self.project.arch.bits))
                    val = val.concrete_value
                stack_d[offset] = val
            else:
                raise NotImplementedError("plz raise an issue")
        return reg_d, stack_d

    def _rebalance_ast(self, lhs, rhs, mode='stack'):
        """
        we know that lhs (stack content with modification) == rhs (user ropvalue)
        since user ropvalue may be symbolic, we need to present the stack content using the user ropvalue and store it
        on stack so that users can eval on their own ropvalue and get the correct solves
        TODO: currently, we only support add/sub, Extract/ZeroExt
        """
        # in some cases, we can just solve it
        if mode == 'stack' and lhs.symbolic and not rhs.symbolic and len(lhs.variables) == 1 and lhs.depth > 1:
            target_ast = None
            for ast in lhs.children_asts():
                if ast.op == 'BVS' and ast.args[0].startswith('symbolic_stack'):
                    target_ast = ast
                    break
            assert target_ast is not None

            solver = claripy.Solver()
            solver.add(lhs == rhs)
            return target_ast, claripy.BVV(solver.eval(target_ast, 1)[0], target_ast.size())

        if lhs.op == 'If':
            raise RopException("cannot handle conditional value atm")

        check_func = Builder._ast_contains_stack_data if mode == 'stack' else Builder._ast_contains_reg_data

        if not check_func(lhs):
            raise RopException(f"cannot rebalance the constraint {lhs} == {rhs}")
        while lhs.depth != 1:
            match lhs.op:
                case "__add__" | "__sub__":
                    arg0 = lhs.args[0]
                    arg1 = lhs.args[1]
                    flag = check_func(arg0)
                    op = lhs.op
                    if flag:
                        lhs = arg0
                        other = arg1
                    else:
                        lhs = arg1
                        other = arg0
                    if op == "__add__":
                        rhs -= other
                    elif flag:
                        rhs += other
                    else:
                        rhs = other - rhs
                case "__and__" | "__or__":
                    arg0 = lhs.args[0]
                    arg1 = lhs.args[1]
                    flag0 = check_func(arg0)
                    flag1 = check_func(arg1)
                    if flag0 and flag1:
                        raise RopException(f"cannot rebalance {lhs}")
                    op = lhs.op
                    if flag0:
                        lhs = arg0
                        other = arg1
                    else:
                        lhs = arg1
                        other = arg0
                    if op == "__and__":
                        rhs = rhs & other
                    else:
                        rhs = rhs
                case "Reverse":
                    lhs = lhs.args[0]
                    rhs = claripy.Reverse(rhs)
                case "ZeroExt":
                    rhs_leading = claripy.Extract(rhs.length-1, rhs.length-lhs.args[0], rhs)
                    if not rhs_leading.symbolic and rhs_leading.concrete_value != 0:
                        raise RopException("rebalance unsat")
                    rhs = claripy.Extract(rhs.length-lhs.args[0]-1, 0, rhs)
                    lhs = lhs.args[1]
                case "SignExt":
                    rhs_leading = claripy.Extract(rhs.length-1, rhs.length-lhs.args[0], rhs)
                    if not rhs_leading.symbolic and rhs_leading.concrete_value not in (0, (1<<rhs_leading.length)-1):
                        raise RopException("rebalance unsat")
                    rhs = claripy.Extract(rhs.length-lhs.args[0]-1, 0, rhs)
                    lhs = lhs.args[1]
                case "Extract":
                    assert lhs.length == rhs.length
                    ext_bits = self.project.arch.bits -1 - lhs.args[0]
                    padding_bits = lhs.args[1]
                    if padding_bits:
                        padding = claripy.BVV(0, padding_bits)
                        rhs = claripy.Concat(rhs, padding)
                    if ext_bits:
                        rhs = claripy.ZeroExt(ext_bits, rhs)
                    lhs = lhs.args[2]
                case "Concat":
                    raise RopException("cannot rebalance Concat")
                case "__rshift__" | "__lshift__":
                    bits = lhs.args[1]
                    if lhs.op == '__rshift__':
                        rhs = rhs << bits
                    else:
                        rhs = rhs >> bits
                    lhs = lhs.args[0]
                case "__xor__":
                    if check_func(lhs.args[0]):
                        other = lhs.args[1]
                        lhs = lhs.args[0]
                    else:
                        other = lhs.args[0]
                        lhs = lhs.args[1]
                    rhs = rhs ^ other
                case _:
                    raise ValueError(f"{lhs.op} cannot be rebalanced at the moment. plz create an issue!")
        assert check_func(lhs)
        assert lhs.length == rhs.length
        return lhs, rhs

    @rop_utils.timeout(3)
    def _build_reg_setting_chain(
        self, gadgets, register_dict, constrained_addrs=None):
        """
        This function figures out the actual values needed in the chain
        for a particular set of gadgets and register values
        This is done by stepping a symbolic state through each gadget
        then constraining the final registers to the values that were requested
        """

        total_sc = sum(max(g.stack_change, g.max_stack_offset + self.project.arch.bytes) for g in gadgets)
        arch_bytes = self.project.arch.bytes

        # emulate a 'pop pc' of the first gadget
        test_symbolic_state = rop_utils.make_symbolic_state(
            self.project,
            self.arch.reg_list,
            total_sc//arch_bytes+1, # compensate for the first gadget
        )
        test_symbolic_state.ip = test_symbolic_state.stack_pop()

        # Maps each stack variable to the RopValue or RopGadget that should be placed there.
        stack_var_to_value = {}

        def map_stack_var(ast, value):
            if len(ast.variables) != 1:
                raise RopException("Target value not controlled by a single variable")
            var = next(iter(ast.variables))
            if not var.startswith("symbolic_stack_") and not var.startswith("next_pc_"):
                raise RopException("Target value not controlled by the stack")
            stack_var_to_value[var] = value

        state = test_symbolic_state.copy()

        # Step through each gadget and constrain the ip.
        stack_patchs = []
        for gadget in gadgets:
            if isinstance(gadget, RopGadget):
                map_stack_var(state.ip, gadget)
                state.ip = gadget.addr
            elif isinstance(gadget, RopBlock):
                rb = gadget
                map_stack_var(state.ip, rb)
                state.ip = rb._values[0].concreted
                st = rb._blank_state
                for idx, val in enumerate(rb._values[1:]):
                    state.memory.store(state.regs.sp+idx*arch_bytes, val.data, endness=self.project.arch.memory_endness)
                    stack_patchs.append((state.regs.sp+idx*arch_bytes, val.data))
                state.solver.add(*st.solver.constraints)
                # when we import constraints, it is possible some of the constraints are associated with initial register value
                # now stitch them together, only the ones being used though
                used_regs = {x.split('-')[0].split('_')[-1] for x in st.solver._solver.variables if x.startswith('sreg_')}
                for reg in used_regs:
                    state.solver.add(state.registers.load(reg) == st.registers.load(reg))
            else:
                raise ValueError("huh?")

            # step following the trace
            for addr in gadget.bbl_addrs[1:]:
                succ = state.step()
                succ_states = [
                    state
                    for state in succ.successors
                    if state.solver.is_true(state.ip == addr)
                ]
                if len(succ_states) != 1:
                    raise RopException(
                        "Zero or multiple states match address of next block"
                    )
                state = succ_states[0]
            succ = state.step()
            if succ.flat_successors or len(succ.unconstrained_successors) != 1:
                raise RopException(
                    "Executing gadget doesn't result in a single unconstrained state"
                )
            state = succ.unconstrained_successors[0]

        if len(state.solver.eval_to_ast(state.ip, 2)) < 2:
            raise RopException("The final pc is not unconstrained!")

        # Record the variable that controls the final ip.
        next_pc_val = rop_utils.cast_rop_value(
            test_symbolic_state.solver.BVS("next_pc", self.project.arch.bits),
            self.project,
        )
        map_stack_var(state.ip, next_pc_val)

        # Constrain final register values.
        for reg, val in register_dict.items():
            var = state.registers.load(reg)
            if val.is_register:
                if var.op != "BVS" or not next(iter(var.variables)).startswith(
                    f"sreg_{val.reg_name}-"
                ):
                    raise RopException("Register wasn't moved correctly")
            elif not var.symbolic and not val.symbolic:
                if var.concrete_value != val.concreted:
                    raise RopException("Register set to incorrect value")
            else:
                state.solver.add(var == val.data)
                lhs, rhs = self._rebalance_ast(var, val.data)
                if self.project.arch.memory_endness == 'Iend_LE':
                    rhs = claripy.Reverse(rhs)
                ropvalue = val.copy()
                if val.rebase:
                    ropvalue._value = rhs - ropvalue._code_base
                else:
                    ropvalue._value = rhs
                map_stack_var(lhs, ropvalue)

        # Constrain memory access addresses.
        for action in state.history.actions:
            if action.type == action.MEM and action.addr.symbolic:
                if len(state.solver.eval_to_ast(action.addr, 2)) == 1:
                    continue
                if len(action.addr.ast.variables) == 1 and set(action.addr.ast.variables).pop().startswith("symbolic_stack"):
                    if constrained_addrs is not None:
                        ptr_bv = constrained_addrs[0]
                        constrained_addrs = constrained_addrs[1:]
                    else:
                        ptr_bv = claripy.BVV(self._get_ptr_to_writable(action.size.ast//8), action.addr.ast.size())
                    ropvalue = rop_utils.cast_rop_value(ptr_bv, self.project)
                    lhs, rhs = self._rebalance_ast(action.addr.ast, ptr_bv)
                    if self.project.arch.memory_endness == 'Iend_LE':
                        rhs = claripy.Reverse(rhs)
                    if ropvalue.rebase:
                        ropvalue._value = rhs - ropvalue._code_base
                    else:
                        ropvalue._value = rhs
                    map_stack_var(lhs, ropvalue)

        # now import the constraints from the state that has reached the end of the ropchain
        test_symbolic_state.solver.add(*state.solver.constraints)

        # now import the stack patchs
        for addr, data in stack_patchs:
            test_symbolic_state.memory.store(addr, data, endness=self.project.arch.memory_endness)

        bytes_per_pop = arch_bytes

        # constrain the "filler" values
        if self.roparg_filler is not None:
            for offset in range(0, total_sc, bytes_per_pop):
                sym_word = test_symbolic_state.stack_read(offset, bytes_per_pop)
                # check if we can constrain val to be the roparg_filler
                if test_symbolic_state.solver.satisfiable([sym_word == self.roparg_filler]):
                    # constrain the val to be the roparg_filler
                    test_symbolic_state.add_constraints(sym_word == self.roparg_filler)

        # create the ropchain
        chain = RopChain(self.project,
                         self,
                         state=test_symbolic_state.copy(),
                         badbytes=self.badbytes)

        # iterate through the stack values that need to be in the chain
        if not chain._blank_state.satisfiable():
            raise RopException("the chain is not feasible!")

        for offset in range(-bytes_per_pop, total_sc, bytes_per_pop):
            sym_word = test_symbolic_state.stack_read(offset, bytes_per_pop)
            assert len(sym_word.variables) <= 1
            if not sym_word.variables:
                chain.add_value(sym_word)
                continue

            sym_var = next(iter(sym_word.variables))
            if sym_var in stack_var_to_value:
                val = stack_var_to_value[sym_var]
                if isinstance(val, RopGadget):
                    # this is special, we know this won't be "next_pc", so don't try
                    # to take "next_pc"'s position
                    value = RopValue(val.addr, self.project)
                    value.rebase_analysis(chain=chain)
                    chain.add_value(value)
                elif isinstance(val, RopBlock):
                    chain.add_value(val._values[0])
                else:
                    chain.add_value(val)
            else:
                chain.add_value(sym_word)

        # expand mixins to plain gadgets
        plain_gadgets = []
        for g in gadgets:
            if isinstance(g, RopGadget):
                plain_gadgets.append(g)
            elif isinstance(g, RopBlock):
                plain_gadgets += g._gadgets
            else:
                raise RuntimeError("???")
        chain.set_gadgets(plain_gadgets)

        return chain

    def _get_fill_val(self):
        if self.roparg_filler is not None:
            return self.roparg_filler
        else:
            return claripy.BVS("filler", self.project.arch.bits)

    @abstractmethod
    def _effect_tuple(self, g):
        raise NotImplementedError("_effect_tuple is not implemented!")

    @abstractmethod
    def _comparison_tuple(self, g):
        raise NotImplementedError("_comparison_tuple is not implemented!")

    def __filter_gadgets(self, gadgets):
        """
        group gadgets by features and drop lesser groups
        """
        # gadget grouping
        d = defaultdict(list)
        for g in gadgets:
            key = self._comparison_tuple(g)
            d[key].append(g)
        if len(d) == 0:
            return set()
        if len(d) == 1:
            return {gadgets.pop()}

        # only keep the best groups
        keys = set(d.keys())
        bests = set()
        while keys:
            k1 = keys.pop()
            # check if nothing is better than k1
            for k2 in bests|keys:
                # if k2 is better than k1
                if all(k2[i] <= k1[i] for i in range(len(key))):
                    break
            else:
                bests.add(k1)

        # turn groups back to gadgets
        gadgets = set()
        for key, val in d.items():
            if key not in bests:
                continue
            gadgets = gadgets.union(val)
        return gadgets

    def _filter_gadgets(self, gadgets):
        """
        process gadgets based on their effects
        exclude gadgets that do symbolic memory access
        """
        bests = set()
        equal_classes = defaultdict(set)
        for g in gadgets:
            equal_classes[self._effect_tuple(g)].add(g)
        for _, equal_class in equal_classes.items():
            bests = bests.union(self.__filter_gadgets(equal_class))
        return bests

    @staticmethod
    def _mixins_to_gadgets(mixins):
        """
        simply expand all ropblocks to gadgets
        """
        gadgets = []
        for mixin in mixins:
            if isinstance(mixin, RopGadget):
                gadgets.append(mixin)
            elif isinstance(mixin, RopBlock):
                gadgets += mixin._gadgets
            else:
                raise ValueError(f"cannot turn {mixin} into RopBlock!")
        return gadgets

    @abstractmethod
    def bootstrap(self):
        """
        update the builder based on current gadgets to bootstrap a functional builder
        """
        raise NotImplementedError("each Builder class should have an `update` method!")

    @abstractmethod
    def optimize(self):
        """
        improve the capability of this builder using other builders
        """
        cls_name = self.__class__.__name__
        raise NotImplementedError(f"`advanced_update` is not implemented for {cls_name}!")

    def _normalize_conditional(self, gadget, preserve_regs=None):
        if preserve_regs is None:
            preserve_regs = set()

        registers = {}
        for reg in gadget.branch_dependencies:
            var = claripy.BVS(f"bvar_{reg}", self.project.arch.bits)
            registers[reg] = var
        try:
            chain = self.set_regs(preserve_regs=preserve_regs, **registers)
        except RopException:
            return None
        gadgets = chain._gadgets
        return gadgets

    def _normalize_jmp_reg(self, gadget, pre_preserve=None, to_set_regs=None):
        if pre_preserve is None:
            pre_preserve = set()
        if to_set_regs is None:
            to_set_regs = set()
        reg_setter = self.chain_builder._reg_setter
        if not reg_setter.can_set_reg(gadget.pc_reg):
            return None
        if gadget.pc_reg in pre_preserve or gadget.pc_reg in to_set_regs:
            return None

        # choose the best gadget to set the PC for this jmp_reg gadget
        for pc_setter in reg_setter._reg_setting_dict[gadget.pc_reg]:
            if pc_setter.has_symbolic_access():
                continue
            if pc_setter.changed_regs.intersection(pre_preserve):
                continue
            total_sc = gadget.stack_change + pc_setter.stack_change
            gadgets = reg_setter._mixins_to_gadgets([pc_setter, gadget])
            try:
                chain = reg_setter._build_reg_setting_chain(gadgets, {})
                rb = RopBlock.from_chain(chain)

                # TODO: technically, we should support chains like:
                # pop rax; add eax, 0x1000; ret + <useful stuff>; call rax;
                # but I'm too lazy to implement it atm
                init_state, final_state = rb.sim_exec()
                if final_state.ip.depth > 1:
                    continue
                assert rb.stack_change == total_sc
                return rb._gadgets[:-1]
            except RopException:
                pass
        return None

    def _normalize_jmp_mem(self, gadget, pre_preserve=None, post_preserve=None):
        if not self.chain_builder._can_do_write:
            return None
        if pre_preserve is None:
            pre_preserve = set()
        if post_preserve is None:
            post_preserve = set()

        # calculate the number of bytes we need to shift after jmp_mem
        # this handles out of patch access
        mem_writer = self.chain_builder._mem_writer
        stack_offsets = []
        for m in gadget.mem_reads + gadget.mem_writes + gadget.mem_changes:
            if m.stack_offset is not None:
                stack_offsets.append(m.stack_offset + self.project.arch.bytes)
        if stack_offsets:
            shift_size = max(stack_offsets) - gadget.stack_change
        else:
            shift_size = self.project.arch.bytes

        # make sure we can set the pc_target ast in the first place
        needed_regs = set(x[5:].split('-', 1)[0] for x in gadget.pc_target.variables if x.startswith('sreg_'))
        reg_setter = self.chain_builder._reg_setter
        for reg in needed_regs:
            if not reg_setter.can_set_reg(reg):
                return None

        # if the target is not symbolic, make sure the target location is writable
        if not gadget.pc_target.symbolic:
            seg = self.project.loader.find_segment_containing(gadget.pc_target.concrete_value)
            if not seg or not seg.is_writable:
                return None

        try:
            # step1: find a shifter that clean up the jmp_mem call
            sc = abs(gadget.stack_change) + self.project.arch.bytes
            shifter = None
            # find the smallest shifter
            shift_gadgets = self.chain_builder._shifter.shift_gadgets
            keys = sorted(shift_gadgets.keys())
            shifter_list = [shift_gadgets[x] for x in keys if x >= sc]
            if not shifter_list:
                return None
            shifter_list = itertools.chain.from_iterable(shifter_list)
            for shifter in shifter_list:
                if shifter.pc_offset < shift_size:
                    continue
                if not shifter.changed_regs.intersection(post_preserve):
                    break
            else:
                return None
            assert shifter.transit_type == 'pop_pc'

            # step2: write the shifter to a writable location
            data = struct.pack(self.project.arch.struct_fmt(), shifter.addr)
            if gadget.pc_target.symbolic:
                ptr = self._get_ptr_to_writable(self.project.arch.bytes)
                # we ensure the content it points to is zeroed out, so we don't need to write trailing 0s
                # but we can't do so for GOT because they may have leftovers there
                data = data.rstrip(b'\x00')
            else:
                ptr = gadget.pc_target.concrete_value
            ptr_val = rop_utils.cast_rop_value(ptr, self.project)
            chain = mem_writer.write_to_mem(ptr_val, data, fill_byte=b'\x00', preserve_regs=pre_preserve)
            rb = RopBlock.from_chain(chain)
            state = rb._blank_state

            # step3: identify the registers that we can't fully control yet in pc_target, then set them using RegSetter
            _, final_state = rb.sim_exec()
            try:
                reg_solves, stack_solves = self._solve_ast_constraint(gadget.pc_target, ptr)
            except claripy.errors.UnsatError:
                return None
            to_set_regs = {x:y for x,y in reg_solves.items() if x not in rb.popped_regs}
            preserve_regs = set(reg_solves.keys()) - set(to_set_regs.keys())
            if any(x for x in to_set_regs if not self.chain_builder._reg_setter.can_set_reg(x)):
                return None
            if preserve_regs:
                for reg in preserve_regs:
                    rb._blank_state.solver.add(final_state.registers.load(reg) == reg_solves[reg])
            if to_set_regs:
                chain = self.set_regs(**to_set_regs, preserve_regs=preserve_regs.union(pre_preserve))
                rb += RopBlock.from_chain(chain)

            # step4: chain it with the jmp_mem gadget
            # note that rb2 here is actually the gadget+shifter
            # but shifter is written into memory, so ignore it when building rb2
            rb2 = RopBlock(self.project, self)
            value = RopValue(gadget.addr, self.project)
            value.rebase_analysis(chain=chain)
            rb2.add_value(value)

            sc = shifter.stack_change + gadget.stack_change
            state = rb2._blank_state
            for offset in range(0, sc, self.project.arch.bytes):
                if offset == shifter.pc_offset + gadget.stack_change:
                    val = state.solver.BVS("next_pc", self.project.arch.bits)
                else:
                    # FIXME: currently, the endness handling is a mess. Need to rewrite this part in a uniformed way
                    # the following code is a compromise to the mess
                    idx = (rb.stack_change + offset)//self.project.arch.bytes
                    data = claripy.BVS(f"symbolic_stack_{idx}", self.project.arch.bits)
                    state.memory.store(state.regs.sp+rb.stack_change+offset, data)
                    val = state.memory.load(state.regs.sp+rb.stack_change+offset, self.project.arch.bytes, endness=self.project.arch.memory_endness)
                rb2.add_value(val)
            rb2.set_gadgets([gadget])
            for offset, val in stack_solves.items():
                # +1 because we insert a gadget before the stack patch
                rb2._values[offset+1] = rop_utils.cast_rop_value(val, self.project)

            rb += rb2
            return rb
        except (RopException, IndexError):
            return None

    def normalize_gadget(self, gadget, pre_preserve=None, post_preserve=None, to_set_regs=None):
        """
        pre_preserve: what registers to preserve before executing the gadget
        post_preserve: what registers to preserve after executing the gadget
        """
        try:
            gadgets = [gadget]

            if pre_preserve is None:
                pre_preserve = set()
            if post_preserve is None:
                post_preserve = set()
            m = None

            # filter out gadgets with too many symbolic access
            if gadget.num_sym_mem_access > 1:
                return None

            # TODO: don't support these yet
            if gadget.transit_type == 'jmp_mem':
                if gadget.has_conditional_branch or gadget.has_symbolic_access():
                    return None

            # at this point, we know for sure all gadget symbolic accesses should be normalized
            # because they can't be jmp_mem gadgets
            if gadget.has_symbolic_access():
                sim_accesses = [x for x in gadget.mem_reads + gadget.mem_writes + gadget.mem_changes if x.is_symbolic_access()]
                assert len(sim_accesses) == 1, hex(gadget.addr)
                m = sim_accesses[0]
                pre_preserve = pre_preserve.union(m.addr_controllers)

            # normalize conditional branches
            if gadget.has_conditional_branch:
                tmp = self._normalize_conditional(gadget, preserve_regs=pre_preserve)
                if tmp is None:
                    return None
                gadgets = tmp + gadgets

            # normalize transit_types
            if gadget.transit_type == 'jmp_reg':
                tmp = self._normalize_jmp_reg(gadget, pre_preserve=pre_preserve, to_set_regs=to_set_regs)
                if tmp is None:
                    return None
                gadgets = tmp + gadgets
            elif gadget.transit_type == 'jmp_mem':
                rb = self._normalize_jmp_mem(gadget, pre_preserve=pre_preserve, post_preserve=post_preserve)
                return rb
            elif gadget.transit_type == 'pop_pc':
                pass
            else:
                raise NotImplementedError()

            chain = self._build_reg_setting_chain(gadgets, {})
            rb = RopBlock.from_chain(chain)

            if rb is None:
                return None

            # normalize non-positive stack_change
            if gadget.stack_change <= 0:
                shift_gadgets = self.chain_builder._shifter.shift_gadgets
                sc = abs(gadget.stack_change) + self.project.arch.bytes
                keys = sorted(shift_gadgets.keys())
                shifter_list = [shift_gadgets[x] for x in keys if x >= sc]
                shifter_list = itertools.chain.from_iterable(shifter_list)
                max_stack_offset = gadget.max_stack_offset
                for shifter in shifter_list:
                    if shifter.pc_offset < abs(gadget.stack_change) + max_stack_offset + self.project.arch.bytes:
                        continue
                    if shifter.changed_regs.intersection(post_preserve):
                        continue
                    try:
                        chain = self._build_reg_setting_chain([rb, shifter], {})
                        rb = RopBlock.from_chain(chain)
                        break
                    except RopException:
                        pass
                else:
                    return None

            if rb is None:
                return None

            # handle cases where the ropblock has out_of_patch accesses
            # the solution is to shift the stack to contain the accesses
            # FIXME: currently, we allow bytes*2 more bytes in shifting because of the mismatch on how
            # stack_max_offset is calculated in ropblock and ropgadget
            if rb.oop:
                shift_gadgets = self.chain_builder._shifter.shift_gadgets
                keys = sorted(shift_gadgets.keys())
                shifter_list = itertools.chain.from_iterable([shift_gadgets[k] for k in keys])
                for shifter in shifter_list:
                    if shifter.stack_change + rb.stack_change <= rb.max_stack_offset:
                        continue
                    if shifter.pc_offset == rb.max_stack_offset - rb.stack_change:
                        continue
                    try:
                        chain = self._build_reg_setting_chain([rb, shifter], {})
                        rb = RopBlock.from_chain(chain)
                        rb._values = rb._values[:rb.stack_change//self.project.arch.bytes+1]
                        rb.payload_len = len(rb._values) * self.project.arch.bytes
                        break
                    except RopException:
                        pass
                else:
                    return None

            # constrain memory accesses
            if m is not None:
                request = {}
                for reg in m.addr_controllers:
                    data = claripy.BVS('sym_addr', self.project.arch.bits)
                    request[reg] = data
                if request:
                    tmp = self.set_regs(**request)
                    tmp = RopBlock.from_chain(tmp)
                    _, final_state = tmp.sim_exec()
                    st = rb._blank_state
                    for reg in m.addr_controllers:
                        tmp._blank_state.solver.add(final_state.registers.load(reg) == st.registers.load(reg))
                    rb = tmp + rb
                else: # TODO:we currently don't support symbolizing address popped from stack
                    return None
                return rb

            return rb
        except RopException:
            return None