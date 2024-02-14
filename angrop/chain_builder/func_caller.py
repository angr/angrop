import logging

import angr
from angr.calling_conventions import SimRegArg, SimStackArg

from .builder import Builder
from .. import rop_utils
from ..errors import RopException
from ..rop_gadget import RopGadget

l = logging.getLogger(__name__)

class FuncCaller(Builder):
    """
    handle function calls by automatically detecting the target binary's
    calling convention
    """

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

        # invoke the function
        chain.add_gadget(func_gadget)
        for _ in range(func_gadget.stack_change//arch_bytes-1):
            chain.add_value(self._get_fill_val())

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
