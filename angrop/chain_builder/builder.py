import math
import struct
import itertools
from abc import abstractmethod
from functools import cmp_to_key

import claripy

from .. import rop_utils
from ..errors import RopException
from ..rop_gadget import RopGadget
from ..rop_value import RopValue
from ..rop_chain import RopChain
from ..rop_block import RopBlock
from ..gadget_finder.gadget_analyzer import GadgetAnalyzer

class Builder:
    """
    a generic class to bootstrap more complicated chain building functionality
    """
    def __init__(self, chain_builder):
        self.chain_builder = chain_builder
        self.project = chain_builder.project
        self.arch = chain_builder.arch
        self._gadget_analyzer = GadgetAnalyzer(self.project,
                                               True,
                                               kernel_mode=False,
                                               arch=self.arch)
        self._sim_state = rop_utils.make_symbolic_state(
                                self.project,
                                self.arch.reg_set,
                                stack_gsize=80*3
                                )
        self._used_writable_ptr = set()

    @property
    def badbytes(self):
        return self.chain_builder.badbytes

    @property
    def roparg_filler(self):
        return self.chain_builder.roparg_filler

    def make_sim_state(self, pc):
        """
        make a symbolic state with all general purpose register + base pointer symbolized
        and emulate a `pop pc` situation
        """
        arch_bytes = self.project.arch.bytes
        arch_endness = self.project.arch.memory_endness

        state = rop_utils.make_symbolic_state(self.project, self.arch.reg_set, stack_gsize=80*3)
        rop_utils.make_reg_symbolic(state, self.arch.base_pointer)

        state.regs.ip = pc
        state.add_constraints(state.memory.load(state.regs.sp, arch_bytes, endness=arch_endness) == pc)
        state.regs.sp += arch_bytes
        state.solver._solver.timeout = 5000
        return state

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
        # get all writable segments
        segs = [ s for s in self.project.loader.main_object.segments if s.is_writable ]
        null = b'\x00'*size
        # enumerate through all address to find a good address
        for seg in segs:
            # we should use project.loader.memory.find API, but it is currently broken as reported here:
            # https://github.com/angr/angr/issues/5330
            max_addr = math.ceil(seg.max_addr / 0x1000)*0x1000 # // round up to page size
            for addr in range(seg.min_addr, max_addr):
                # can't collide with used regions
                collide = False
                for a, s in self._used_writable_ptr:
                    if a <= addr < a+s or a < addr+size <= a+s:
                        collide = True
                        break
                if collide:
                    continue
                if all(not self._word_contain_badbyte(x) for x in range(addr, addr+size, self.project.arch.bytes)):
                    data_len = size
                    if addr >= seg.max_addr:
                        self._used_writable_ptr.add((addr, size))
                        return addr
                    if addr+size > seg.max_addr:
                        data_len = addr+size - seg.max_addr
                    data = self.project.loader.memory.load(addr, data_len)
                    if data == null[:data_len]:
                        self._used_writable_ptr.add((addr, size))
                        return addr
        return None

    def _get_ptr_to_null(self):
        # get all non-writable segments
        segs = [ s for s in self.project.loader.main_object.segments if not s.is_writable ]
        # enumerate through all address to find a good address
        null = b'\x00'*self.project.arch.bytes
        for seg in segs:
            for addr in self.project.loader.memory.find(null, search_min=seg.min_addr, search_max=seg.max_addr):
                if not self._word_contain_badbyte(addr):
                    return addr
        return None

    @staticmethod
    def _ast_contains_stack_data(ast):
        vs = ast.variables
        return len(vs) == 1 and list(vs)[0].startswith('symbolic_stack_')

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
        regs = []
        for v in variables:
            name = v.args[0]
            assert name.startswith("sreg_")
            reg = name.split('_')[1][:-1]
            regs.append(reg)
        d = dict(zip(regs, res))
        return d

    def _rebalance_ast(self, lhs, rhs):
        """
        we know that lhs (stack content with modification) == rhs (user ropvalue)
        since user ropvalue may be symbolic, we need to present the stack content using the user ropvalue and store it
        on stack so that users can eval on their own ropvalue and get the correct solves
        TODO: currently, we only support add/sub, Extract/ZeroExt
        """
        if lhs.op == 'If':
            raise RopException("cannot handle conditional value atm")

        assert self._ast_contains_stack_data(lhs)
        while lhs.depth != 1:
            match lhs.op:
                case "__add__" | "__sub__":
                    arg0 = lhs.args[0]
                    arg1 = lhs.args[1]
                    flag = self._ast_contains_stack_data(arg0)
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
                case "Reverse":
                    lhs = lhs.args[0]
                    rhs = claripy.Reverse(rhs)
                case "ZeroExt":
                    rhs_leading = claripy.Extract(rhs.length-1, rhs.length-lhs.args[0], rhs)
                    if rhs_leading.concrete_value != 0:
                        raise RopException("rebalance unsat")
                    rhs = claripy.Extract(rhs.length-lhs.args[0]-1, 0, rhs)
                    lhs = lhs.args[1]
                case "Extract":
                    assert lhs.length == rhs.length
                    full_size = lhs.args[2].length
                    ext_bits = self.project.arch.bits -1 - lhs.args[0]
                    padding_bits = lhs.args[1]
                    if padding_bits:
                        padding = claripy.BVV(0, padding_bits)
                        rhs = claripy.Concat(rhs, padding)
                    if ext_bits:
                        rhs = claripy.ZeroExt(ext_bits, rhs)
                    lhs = lhs.args[2]
                case _:
                    raise ValueError(f"{lhs.op} cannot be rebalanced at the moment. plz create an issue!")
        assert self._ast_contains_stack_data(lhs)
        assert lhs.length == rhs.length
        return lhs, rhs

    @rop_utils.timeout(8)
    def _build_reg_setting_chain(
        self, gadgets, modifiable_memory_range, register_dict):
        """
        This function figures out the actual values needed in the chain
        for a particular set of gadgets and register values
        This is done by stepping a symbolic state through each gadget
        then constraining the final registers to the values that were requested
        """

        total_sc = sum(g.stack_change for g in gadgets if g.stack_change >= 0)
        arch_bytes = self.project.arch.bytes

        # emulate a 'pop pc' of the first gadget
        test_symbolic_state = rop_utils.make_symbolic_state(
            self.project,
            self.arch.reg_set,
            stack_gsize=80*3,
        )
        rop_utils.make_reg_symbolic(test_symbolic_state, self.arch.base_pointer)
        test_symbolic_state.ip = test_symbolic_state.stack_pop()
        test_symbolic_state.solver._solver.timeout = 5000

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

        if len(state.solver.eval_upto(state.ip, 2)) < 2:
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
                if len(state.solver.eval_upto(action.addr, 2)) == 1:
                    continue
                if modifiable_memory_range is None:
                    raise RopException(
                        "Symbolic memory address without modifiable memory range"
                    )
                state.solver.add(action.addr.ast >= modifiable_memory_range[0])
                state.solver.add(action.addr.ast < modifiable_memory_range[1])

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
        plain_gadgets = []
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
                    plain_gadgets.append(val)
                elif isinstance(val, RopBlock):
                    chain.add_value(val._values[0])
                    plain_gadgets += val._gadgets
                else:
                    chain.add_value(val)
            else:
                chain.add_value(sym_word)

        chain.set_gadgets(plain_gadgets)

        return chain

    def _get_fill_val(self):
        if self.roparg_filler is not None:
            return self.roparg_filler
        else:
            return claripy.BVS("filler", self.project.arch.bits)

    @abstractmethod
    def _same_effect(self, g1, g2):
        raise NotImplementedError("_same_effect is not implemented!")

    @abstractmethod
    def _better_than(self, g1, g2):
        raise NotImplementedError("_better_than is not implemented!")

    def same_effect(self, g1, g2):
        return self._same_effect(g1, g2)

    def better_than(self, g1, g2):
        if not self.same_effect(g1, g2):
            return False
        return self._better_than(g1, g2)

    def __filter_gadgets(self, gadgets):
        """
        remove any gadgets that are strictly worse than others
        FIXME: make all gadget filtering logic like what we do in reg_setter, which is correct and way more faster
        """
        gadgets = set(gadgets)
        bests = set()
        while gadgets:
            g1 = gadgets.pop()
            # check if nothing is better than g1
            for g2 in bests|gadgets:
                if self._better_than(g2, g1): #pylint: disable=arguments-out-of-order
                    break
            else:
                bests.add(g1)
        return bests

    def _filter_gadgets(self, gadgets):
        bests = set()
        gadgets = set(gadgets)
        while gadgets:
            g0 = gadgets.pop()
            equal_class = {g for g in gadgets if self._same_effect(g0, g)}
            equal_class.add(g0)
            bests = bests.union(self.__filter_gadgets(equal_class))

            gadgets -= equal_class
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
            chain = self.chain_builder._reg_setter.run(preserve_regs=preserve_regs, **registers)
        except RopException:
            return None
        gadgets = chain._gadgets
        return gadgets

    def _normalize_jmp_reg(self, gadget, preserve_regs=None):
        if preserve_regs is None:
            preserve_regs = set()
        reg_setter = self.chain_builder._reg_setter
        if gadget.pc_reg not in reg_setter._reg_setting_dict:
            return None

        # choose the best gadget to set the PC for this jmp_reg gadget
        for pc_setter in reg_setter._reg_setting_dict[gadget.pc_reg]:
            if pc_setter.has_symbolic_access():
                continue
            if pc_setter.changed_regs.intersection(preserve_regs):
                continue
            total_sc = gadget.stack_change + pc_setter.stack_change
            gadgets = reg_setter._mixins_to_gadgets([pc_setter, gadget])
            try:
                chain = reg_setter._build_reg_setting_chain(gadgets, None, {})
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

    def _normalize_jmp_mem(self, gadget, preserve_regs=None):
        if preserve_regs is None:
            preserve_regs = set()

        mem_writer = self.chain_builder._mem_writer

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
                if shifter.pc_offset < abs(gadget.stack_change):
                    continue
                if not shifter.changed_regs.intersection(preserve_regs):
                    break
            else:
                return None
            assert shifter.transit_type == 'pop_pc'

            # step2: write the shifter to a writable location
            ptr = self._get_ptr_to_writable(self.project.arch.bytes)
            ptr_val = rop_utils.cast_rop_value(ptr, self.project)
            data = struct.pack(self.project.arch.struct_fmt(), shifter.addr)
            # we ensure the content it points to is zeroed out, so we don't need to write trailing 0s
            chain = mem_writer.write_to_mem(ptr_val, data.rstrip(b'\x00'), fill_byte=b'\x00')
            rb = RopBlock.from_chain(chain)
            st = chain._blank_state
            state = rb._blank_state

            # step3: identify the registers that we can't fully control yet in pc_target, then set them using RegSetter
            init_state, final_state = rb.sim_exec()
            rop_values = self._solve_ast_constraint(gadget.pc_target, ptr)
            to_set_regs = {x:y for x,y in rop_values.items() if x not in rb.popped_regs}
            preserve_regs = set(rop_values.keys()) - set(to_set_regs.keys())
            if any(x for x in to_set_regs if x not in self.chain_builder._reg_setter._reg_setting_dict):
                return None
            if preserve_regs:
                for reg in preserve_regs:
                    rb._blank_state.solver.add(final_state.registers.load(reg) == rop_values[reg])
            if to_set_regs:
                chain = self.chain_builder._reg_setter.run(**to_set_regs, preserve_regs=preserve_regs)
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
                    val = state.memory.load(state.regs.sp+rb.stack_change, self.project.arch.bytes, endness=self.project.arch.memory_endness)
                rb2.add_value(val)
            rb2.set_gadgets([gadget])

            rb += rb2
            return rb
        except RopException:
            return None
        return None

    def normalize_gadget(self, gadget, pre_preserve=None, post_preserve=None):
        """
        pre_preserve: what registers to preserve before executing the gadget
        post_preserve: what registers to preserve after executing the gadget
        """
        gadgets = [gadget]

        if pre_preserve is None:
            pre_preserve = set()
        if post_preserve is None:
            post_preserve = set()

        # HACK: technically, if we constrain the address, there will be no more
        # symbolic accesses
        # here, what we actually want to do is to filter out symbolic access other than
        # where the PC comes from. The following check will let through jmp_mem gadget that has
        # symbolic access, which is bad
        if gadget.has_symbolic_access() and gadget.transit_type != 'jmp_mem':
            return None

        # TODO: don't support this yet
        if gadget.has_conditional_branch and gadget.transit_type == 'jmp_mem':
            return None

        # normalize conditional branches
        if gadget.has_conditional_branch:
            tmp = self._normalize_conditional(gadget, preserve_regs=pre_preserve)
            if tmp is None:
                return None
            gadgets = tmp + gadgets

        # normalize transit_types
        if gadget.transit_type == 'jmp_reg':
            tmp = self._normalize_jmp_reg(gadget, preserve_regs=pre_preserve)
            if tmp is None:
                return None
            gadgets = tmp + gadgets
        elif gadget.transit_type == 'jmp_mem':
            rb = self._normalize_jmp_mem(gadget, preserve_regs=pre_preserve)
            return rb
        elif gadget.transit_type == 'pop_pc':
            pass
        else:
            raise NotImplementedError()

        chain = self._build_reg_setting_chain(gadgets, None, {})
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
            for shifter in shifter_list:
                if shifter.pc_offset < abs(gadget.stack_change):
                    continue
                if shifter.changed_regs.intersection(post_preserve):
                    continue
                try:
                    tmp = RopBlock.from_gadget(shifter, self)
                    rb += tmp
                    break
                except RopException:
                    pass
            else:
                return None

        if rb is None:
            return None

        # TODO
        if rb.oop:
            return None

        return rb