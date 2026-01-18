import logging

from ..errors import RopException
from ..sigreturn import SigreturnFrame

l = logging.getLogger(__name__)


class SigreturnBuilder:
    """
    Build srop chains
    """
    def __init__(self, chain_builder):
        self.chain_builder = chain_builder
        self.project = chain_builder.project
        self.arch = chain_builder.arch

    def _execute_sp_delta(self, chain):
        state = chain.sim_exec_til_syscall()
        if state is None:
            raise RopException("Fail to execute sigreturn chain until syscall")
        # but here @angrop/rop_chain.py#L213: we executed a stack pop here, so should consider that.
        init_state = chain._blank_state.copy()
        init_state.stack_pop()
        init_sp = init_state.solver.eval(init_state.regs.sp)
        sp_at_syscall = state.solver.eval(state.regs.sp) # pad sp change
        delta = sp_at_syscall - init_sp
        if delta % self.project.arch.bytes != 0:
            raise RopException("Unexpected stack alignment for sigreturn")
        offset_words = delta // self.project.arch.bytes
        return offset_words

    def sigreturn_syscall(self, syscall_num, args):
        """
        Build a sigreturn syscall chain with syscall gadget and ROP syscall registers => SigreturnFrame.
        :param syscall_num: syscall number for sigreturn
        :param args: syscall arguments for sigreturn
        :return: RopChain object
        """
        # TODO: auto set regs for syscall.

    def sigreturn(self, **registers):
        """
        Build a sigreturn chain with syscall gadget and SigreturnFrame.
        :param registers: registers to set in the SigreturnFrame
        :return: RopChain object
        """
        if self.project.simos.name != "Linux":
            raise RopException(f"{self.project.simos.name} is not supported!")
        if not self.chain_builder.syscall_gadgets:
            raise RopException("target does not contain syscall gadget!")
        if self.arch.sigreturn_num is None:
            raise RopException("sigreturn is not supported on this architecture")

        frame = SigreturnFrame.from_project(self.project)
        frame.update(**registers)

        syscall_num = self.arch.sigreturn_num # syscall(sigreturn)
        chain = self.chain_builder.do_syscall(syscall_num, [],stack_recover=False, needs_return=False) # dummy args
        if not chain or not chain._gadgets:
            raise RopException("Fail to build sigreturn syscall chain")
        frame_words = frame.to_words()

        offset_words = self._execute_sp_delta(chain)
        filler = self.chain_builder.roparg_filler
        if filler is None:
            filler = 0
        if 0 < offset_words < len(chain._values): # should pad to offset(rsp at syscall)
            chain._values = chain._values[:offset_words]
            chain.payload_len = offset_words * self.project.arch.bytes
        elif offset_words < 0: # drop values to fit offset.
            l.warning("Negative offset, some frame values would be dropped.")
            frame_words = frame_words[-offset_words:]
        elif offset_words > len(chain._values):
            for _ in range(offset_words - len(chain._values)):
                chain.add_value(filler)

        for word in frame_words:
            chain.add_value(word)
        return chain
