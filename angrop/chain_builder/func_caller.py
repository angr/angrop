import logging

import angr

from .builder import Builder
from ..errors import RopException
from ..rop_gadget import RopGadget

l = logging.getLogger(__name__)

class FuncCaller(Builder):
    """
    handle function calls by automatically detecting the target binary's
    calling convention
    """
    def __init__(self, chain_builder):
        super().__init__(chain_builder)

    def _func_call(self, func_gadget, cc, args, extra_regs=None, modifiable_memory_range=None, ignore_registers=None,
                   use_partial_controllers=False, needs_return=True):
        assert type(args) in [list, tuple], "function arguments must be a list or tuple!"
        arch_bytes = self.project.arch.bytes
        registers = {} if extra_regs is None else extra_regs
        if ignore_registers is None:
            ignore_registers = []

        # distinguish register and stack arguments
        register_arguments = args
        stack_arguments = []
        if len(args) > len(cc.ARG_REGS):
            register_arguments = args[:len(cc.ARG_REGS)]
            stack_arguments = args[len(cc.ARG_REGS):]

        # set register arguments
        for arg, reg in zip(register_arguments, cc.ARG_REGS):
            registers[reg] = arg
        for reg in ignore_registers:
            registers.pop(reg, None)
        chain = self.chain_builder.set_regs(modifiable_memory_range=modifiable_memory_range,
                              use_partial_controllers=use_partial_controllers,
                              **registers)

        # invoke the function
        chain.add_gadget(func_gadget)
        for _ in range(func_gadget.stack_change//arch_bytes-1):
            chain.add_value(self._get_fill_val())

        # we are done here if there is no stack arguments
        if not stack_arguments:
            return chain

        # handle stack arguments:
        # 1. we need to pop the arguments after use
        # 2. push the stack arguments

        # step 1: find a stack cleaner (a gadget that can pop all the stack args)
        #         with the smallest stack change
        stack_cleaner = None
        if needs_return:
            for g in self.chain_builder.gadgets:
                # just pop plz
                if g.mem_reads or g.mem_writes or g.mem_changes:
                    continue
                # at least can pop all the args
                if g.stack_change < arch_bytes * (len(stack_arguments)+1):
                    continue

                if stack_cleaner is None or g.stack_change < stack_cleaner.stack_change:
                    stack_cleaner = g

            if stack_cleaner is None:
                raise RopException(f"Fail to find a stack cleaner that can pop {len(stack_arguments)} words!")

        # in case we can't find a stack_cleaner and we don't need to return
        if stack_cleaner is None:
            stack_cleaner = RopGadget(self._get_fill_val())
            stack_cleaner.stack_change = arch_bytes * (len(stack_arguments)+1)

        chain.add_gadget(stack_cleaner)
        stack_arguments += [self._get_fill_val()]*(stack_cleaner.stack_change//arch_bytes - len(stack_arguments)-1)
        for arg in stack_arguments:
            chain.add_value(arg)

        return chain

    def func_call(self, address, args, **kwargs):
        """
        :param address: address or name of function to call
        :param args: a list/tuple of arguments to the function
        :param ignore_registers: list of registers which shouldn't be set
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
