import logging

import angr
import claripy
from angr.calling_conventions import SimRegArg, SimStackArg

from .builder import Builder
from .. import rop_utils
from ..errors import RopException
from ..rop_gadget import RopGadget
from ..rop_value import RopValue

l = logging.getLogger(__name__)

class FuncCaller(Builder):
    """
    handle function calls by automatically detecting the target binary's
    calling convention
    """

    def _is_valid_pointer(self, addr):
        """
        Validate if an address is a legitimate pointer in the binary

        Checks:
        1. Address is within memory ranges
        2. Address points to readable memory
        3. Address is aligned
        4. Address is not part of code or read-only sections
        """
        arch_bytes = self.project.arch.bytes

        # Check basic alignment
        if addr % arch_bytes != 0:
            return False

        # Check against memory ranges
        if (addr < self.project.loader.min_addr or
                addr >= self.project.loader.max_addr):
            return False

        # Check readable writable sections
        for section in self.project.loader.main_object.sections:
            if (section.is_readable and
                    section.min_addr <= addr < section.max_addr):
                return True

        return False

    def _find_function_pointer_in_got(self, func_addr):
        """
        Search if a func addr is in plt. If it's in plt, find func name and
        translate it to GOT so we can directly call/jmp to the memroy location pointed there.
        """
        # Search GOT and PLT across all loaded objects
        func_name = None
        for sym in self.project.loader.main_object.symbols:
            if sym.rebased_addr == func_addr:
                func_name = sym.name
        # addr is found in plt. we look for this symbol in got
        if func_name:
            func_got = self.project.loader.main_object.imports.get(func_name)
            if func_got:
                return func_got.rebased_addr
            else:
                # this is from plt but not in got? weird
                return None
        # not in plt. We can search in other ways
        else:
            return None


    def _find_function_pointer(self, func_addr):
        """Find pointer to function, allowing for potential memory locations"""
        # Existing GOT/PLT search logic first
        got_ptr = self._find_function_pointer_in_got(func_addr)
        if got_ptr is not None:
            return got_ptr

        # Broader search strategy
        for obj in self.project.loader.all_objects:
            for section in obj.sections:
                if not section.is_readable:
                    continue

                # Scan section for potential pointers
                for offset in range(0, section.max_addr - section.min_addr, self.project.arch.bytes):
                    potential_ptr = section.min_addr + offset
                    try:
                        ptr_value = self.project.loader.memory.unpack_word(potential_ptr)
                        if (ptr_value == func_addr and
                                self._is_valid_pointer(potential_ptr)):
                            return potential_ptr
                    except:
                        continue

        raise Exception("Could not find mem pointing to func in binary memory")

    def _solve_mem_target_formula(self, gadget_addr, mem_target_formula, func_addr):
        # Create initial state with symbolic registers
        init_state, final_state = self._reach_unconstrained_or_syscall(gadget_addr)

        # Step through gadget execution
        final_state = rop_utils.step_to_unconstrained_successor(
            self.project,
            init_state,
            max_steps=2  # Limit steps to handle just this gadget
        )

        # Add constraint on final memory access
        final_state.add_constraints(
            final_state.memory.load(mem_target_formula, self.project.arch.bytes,
                                    endness=final_state.arch.memory_endness) == func_addr
        )

        if not final_state.solver.satisfiable():
            raise ValueError("Cannot find register values that would access target function")

        # Get initial register values that lead to this state
        solved_regs = {}
        for var in mem_target_formula.variables:
            reg_name = var.split('_')[1].split('-')[0]
            val = init_state.solver.eval(init_state.registers.load(reg_name))
            solved_regs[reg_name] = val

        return solved_regs

    def _func_call(self, func_gadget, cc, args, extra_regs=None, preserve_regs=None,
                   needs_return=True, **kwargs):
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
        registers = {} if extra_regs is None else extra_regs
        for arg, reg in zip(register_arguments, cc.ARG_REGS):
            registers[reg] = arg
        for reg in preserve_regs:
            registers.pop(reg, None)
        chain = self.chain_builder.set_regs(**registers)

        # In case we have a call from mem gadget, we need to set the memory in the gadget itself
        last_gadget = chain._gadgets[-1]
        if last_gadget.transit_type in ('call_reg_from_mem', 'jmp_reg_from_mem'):
            # The address where we'll store func_gadget.addr
            func_addr_in_mem = self._find_function_pointer(func_gadget.addr)

            for i, val in enumerate(chain._values):
                if val.symbolic and rop_utils.get_ast_dependency(val.data).intersection(last_gadget.mem_target_regs):
                    # We need to change a value in the chain to control the call using mem access
                    controlled_register = rop_utils.get_ast_dependency(val.data)
                    if len(controlled_register) > 1:
                        raise RopException("Can't handle this case") # not sure when this could happen
                    controlled_register = list(controlled_register)[0]
                    if last_gadget.mem_target_regs[controlled_register] == 0: # this is a value we want to zero out
                        chain._values[i] = RopValue(0, self.project)
                    if last_gadget.mem_target_regs[controlled_register] == "controller":  # this will control the call
                        chain._values[i] = RopValue(func_addr_in_mem, self.project)
        else:
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
            cleaner = self.chain_builder.shift((len(stack_arguments)+1)*arch_bytes) # +1 for itself
            chain.add_gadget(cleaner._gadgets[0])
            for arg in stack_arguments:
                chain.add_value(arg)

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
        func_gadget.pc_offset = 0
        return self._func_call(func_gadget, cc, args, **kwargs)
