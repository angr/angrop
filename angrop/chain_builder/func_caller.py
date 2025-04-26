import struct
import logging

import angr
import claripy
from angr.calling_conventions import SimRegArg, SimStackArg

from .builder import Builder
from .. import rop_utils
from ..errors import RopException
from ..rop_gadget import FunctionGadget

l = logging.getLogger(__name__)

class FuncCaller(Builder):
    """
    handle function calls by automatically detecting the target binary's
    calling convention
    thanks to @tomgond for a great portion of this class
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)
        # invoke a function but cannot maintain the control flow afterwards (pop rdi; jmp rax)
        self._func_jmp_gadgets = None
        # invoke a function and still maintain the control flow afterwards (call rax; ret)
        # TODO: currently not supported
        self._func_call_gadgets = None
        # record the calling convention
        self._cc = angr.default_cc(
                            self.project.arch.name,
                            platform=self.project.simos.name if self.project.simos is not None else None,
                        )(self.project.arch)

    def bootstrap(self):
        cc = self._cc
        self._func_jmp_gadgets = set()
        for g in self.chain_builder.gadgets:
            if g.self_contained:
                continue
            if g.popped_regs.intersection(cc.ARG_REGS):
                self._func_jmp_gadgets.add(g)
                continue
            for move in g.reg_moves:
                if move.to_reg in cc.ARG_REGS:
                    self._func_jmp_gadgets.add(g)
                    break

    def _find_function_pointer_in_got_plt(self, func_addr):
        """
        Search if a func addr is in plt. If it's in plt, find func name and
        translate it to GOT so that we can directly call/jmp to the location pointed there.
        """
        # Search GOT and PLT across all loaded objects
        func_name = None
        for sym in self.project.loader.main_object.symbols:
            if sym.rebased_addr == func_addr:
                func_name = sym.name

        for sym, val in self.project.loader.main_object.plt.items():
            if val == func_addr:
                func_name = sym
        # addr is found in plt. we look for this symbol in got
        if func_name:
            func_got = self.project.loader.main_object.imports.get(func_name)
            if func_got:
                return func_got.rebased_addr
            else:
                # this is from plt but not in got somehow
                return None
        # not in plt. We can search in other ways
        else:
            return None

    def _find_function_pointer(self, func_addr):
        """Find pointer to function, allowing for potential memory locations"""
        # Existing GOT/PLT search logic first
        got_ptr = self._find_function_pointer_in_got_plt(func_addr)
        if got_ptr is not None:
            return got_ptr

        # Broader search strategy
        func_ptr_bytes = struct.pack(self.project.arch.struct_fmt(), func_addr)
        for seg in self.project.loader.main_object.segments:
            if not seg.is_readable:
                continue
            if not seg.memsize:
                continue

            # Scan segments for potential pointers
            sec_data = self.project.loader.memory.load(seg.min_addr, seg.memsize)
            offset = sec_data.find(func_ptr_bytes)
            if offset == -1:
                continue
            return seg.min_addr + offset
        return None

    def _func_call(self, func_gadget, cc, args, extra_regs=None, preserve_regs=None,
                   needs_return=True, jmp_mem_target=None, **kwargs):
        """
        func_gadget: the address of the function to invoke
        cc: calling convention
        args: the arguments to the function
        extra_regs: what extra registers to set besides the function arguments, useful for invoking system calls
        preserve_res: what registers preserve
        needs_return: whether we need to cleanup stack after the function invocation,
            setting this to False will result in a shorter chain
        """
        assert type(args) in [list, tuple], "function arguments must be a list or tuple!"
        if kwargs:
            l.warning("passing deprecated arguments %s to angrop.chain_builder.FuncCaller", kwargs)

        preserve_regs = set(preserve_regs) if preserve_regs else set()
        arch_bytes = self.project.arch.bytes

        # distinguish register and stack arguments
        register_arguments = args
        stack_arguments = []
        if len(args) > len(cc.ARG_REGS):
            register_arguments = args[:len(cc.ARG_REGS)]
            stack_arguments = args[len(cc.ARG_REGS):]

        # set register arguments
        if needs_return and isinstance(cc.RETURN_ADDR, SimRegArg) and cc.RETURN_ADDR.reg_name != 'ip_at_syscall':
            reg_name = cc.RETURN_ADDR.reg_name
            preserve_regs.add(reg_name)
        registers = {} if extra_regs is None else extra_regs
        for arg, reg in zip(register_arguments, cc.ARG_REGS):
            registers[reg] = arg
        for reg in preserve_regs:
            registers.pop(reg, None)

        # if this is a simple function call, just set the registers and invoke it
        if not jmp_mem_target:
            chain = self.chain_builder.set_regs(**registers, preserve_regs=preserve_regs)
        else:
            # this is a jmp_mem function call, we need to constrain the jmp_mem target
            rop_values, constraints = self._build_ast_constraints(func_gadget.pc_target)
            registers.update(rop_values)
            chain = self.chain_builder.set_regs(**registers, preserve_regs=preserve_regs)
            state = chain._blank_state
            state.solver.add(claripy.And(*constraints))
            state.solver.add(jmp_mem_target == func_gadget.pc_target)

        # invoke the function
        chain.add_gadget(func_gadget)
        for delta in range(func_gadget.stack_change//arch_bytes):
            if func_gadget.pc_offset is None or delta != func_gadget.pc_offset:
                chain.add_value(self._get_fill_val())
            else:
                chain.add_value(claripy.BVS("next_pc", self.project.arch.bits))

        # we are done here if we don't need to return
        if not needs_return:
            return chain

        # now we need to cleanly finish the calling convention
        # 1. handle stack arguments
        # 2. handle function return address to maintain the control flow
        if stack_arguments:
            shift_bytes = (len(stack_arguments)+1)*arch_bytes
            # TODO: currently, we only shift stack only for the minimal
            # but if this shift fails, we should try larger shifts
            cleaner = self.chain_builder.shift(shift_bytes, next_pc_idx=-1, preserve_regs=preserve_regs)
            chain.add_gadget(cleaner._gadgets[0])
            for arg in stack_arguments:
                chain.add_value(arg)
            next_pc = claripy.BVS("next_pc", self.project.arch.bits)
            chain.add_value(next_pc)

        # handle return address
        if not isinstance(cc.RETURN_ADDR, (SimStackArg, SimRegArg)):
            raise RopException(f"What is the calling convention {cc} I'm dealing with?")
        if isinstance(cc.RETURN_ADDR, SimRegArg) and cc.RETURN_ADDR.reg_name != 'ip_at_syscall':
            # now we know this function will return to a specific register
            # so we need to set the return address before invoking the function
            reg_name = cc.RETURN_ADDR.reg_name
            shifter = self.chain_builder._shifter.shift(self.project.arch.bytes)
            next_ip = rop_utils.cast_rop_value(shifter._gadgets[0].addr, self.project)
            pre_chain = self.chain_builder.set_regs(**{reg_name: next_ip})
            chain = pre_chain + chain
        return chain

    def func_call(self, address, args, **kwargs):
        """
        :param address: address or name of function to call
        :param args: a list/tuple of arguments to the function
        :param preserve_regs: list of registers which shouldn't be set
        :param needs_return: whether to continue the ROP after invoking the function
        :return: a RopChain which invokes the function with the arguments
        """
        symbol = None
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

        # try to invoke the function using all self-contained gadgets
        func_gadget = FunctionGadget(address, symbol)
        func_gadget.stack_change = self.project.arch.bytes
        func_gadget.pc_offset = 0
        try:
            return self._func_call(func_gadget, self._cc, args, **kwargs)
        except RopException:
            pass

        # well, let's try non-self-contained gadgets, but this time, we don't guarantee returns
        needs_return = kwargs.get("needs_return", None)
        if needs_return:
            raise RopException("fail to invoke function and return using all self-contained gadgets")
        if needs_return is None:
            s = symbol if symbol else hex(address)
            l.warning("function %s won't return!", s)
            kwargs['needs_return'] = False

        # try func_jmp_gadgets
        register_args = args[:len(self._cc.ARG_REGS)]
        registers = {self._cc.ARG_REGS[i]:register_args[i] for i in range(len(register_args))}
        reg_names = set(registers.keys())
        ptr_to_func = self._find_function_pointer(address)
        hard_regs = [x for x in registers if not self.chain_builder._reg_setter.can_set_reg(x)]
        if ptr_to_func is not None:
            for g in self._func_jmp_gadgets:
                if g.popped_regs.intersection(reg_names):
                    l.warning("do not support func_jmp_gadgets that have pops: %s", g.dstr())
                    continue

                # build the new target registers
                registers = registers.copy()
                skip = False
                for move in g.reg_moves:
                    if move.from_reg in hard_regs or move.to_reg not in hard_regs:
                        skip = True
                        break
                    if move.to_reg in registers.keys():
                        val = registers[move.to_reg]
                        if move.from_reg in registers:
                            l.warning("oops, overlapped moves not handled atm: %s", g.dstr())
                            skip = True
                            break
                        del registers[move.to_reg]
                        registers[move.from_reg] = val
                if skip:
                    continue

                if g.transit_type != 'jmp_mem':
                    raise NotImplementedError("currently only support jmp_mem type func_jmp_gadgets!")
                #func_gadget.stack_change = self.project.arch.bytes
                #func_gadget.pc_offset = 0
                # try to invoke the function using the new target registers
                try:
                    return self._func_call(g, self._cc, [], extra_regs=registers,
                                           jmp_mem_target=ptr_to_func, **kwargs)
                except RopException:
                    pass

        s = symbol if symbol else hex(address)
        raise RopException(f"fail to invoke function: {s}")
