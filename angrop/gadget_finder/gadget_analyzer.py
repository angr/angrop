import logging
from collections import defaultdict

import angr
import pyvex
import claripy

from .. import rop_utils
from ..arch import get_arch, X86
from ..rop_gadget import RopGadget, RopMemAccess, RopRegMove, PivotGadget, SyscallGadget
from ..errors import RopException, RegNotFoundException

l = logging.getLogger("angrop.gadget_analyzer")


class GadgetAnalyzer:
    """
    find and analyze gadgets from binary code
    """
    def __init__(self, project, fast_mode, kernel_mode=False, arch=None, stack_gsize=80):
        """
        stack_gsize: number of controllable gadgets on the stack
        """
        # params
        self.project = project
        self.arch = get_arch(project, kernel_mode=kernel_mode) if arch is None else arch
        self._fast_mode = fast_mode

        # initial state that others are based off, all analysis should copy the state first and work on
        # the copied state
        self._stack_bsize = stack_gsize * self.project.arch.bytes # number of controllable bytes on stack
        sym_reg_set = self.arch.reg_set.union({self.arch.base_pointer})
        if isinstance(self.arch, X86):
            extra_reg_set = self.arch.segment_regs
        else:
            extra_reg_set = None
        self._state = rop_utils.make_symbolic_state(self.project, sym_reg_set,
                                                    extra_reg_set=extra_reg_set, stack_gsize=stack_gsize,
                                                    fast_mode=self._fast_mode)
        self._concrete_sp = self._state.solver.eval(self._state.regs.sp)

    @rop_utils.timeout(3)
    def analyze_gadget(self, addr):
        """
        :param addr: address to analyze for a gadget
        :return: a RopGadget instance
        """
        l.info("Analyzing 0x%x", addr)

        # Step 1: first check if the block makes sense
        if not self._block_make_sense(addr):
            return None

        try:
            # Step 2: make sure the gadget can lead to a *controlled* unconstrained state within 2 steps
            # TODO: shall we make the step number configurable?
            if not self._can_reach_unconstrained(addr):
                l.debug("... cannot get to unconstrained successor according to static analysis")
                return None

            init_state, final_state = self._reach_unconstrained_or_syscall(addr)

            if not self._valid_state(init_state, final_state):
                return None

            ctrl_type = self._check_for_control_type(init_state, final_state)
            if not ctrl_type:
                # for example, jump outside of the controllable region
                l.debug("... cannot maintain the control flow hijacking primitive after executing the gadget")
                return None

            # Step 3: gadget effect analysis
            l.debug("... analyzing rop potential of block")
            gadget = self._create_gadget(addr, init_state, final_state, ctrl_type)
            if not gadget:
                return None

            # Step 4: filter out bad gadgets
            # too many mem accesses, it can only be done after gadget creation
            # specifically, memory access analysis
            if gadget.num_mem_access > self.arch.max_sym_mem_access:
                l.debug("... too many symbolic memory accesses")
                return None

        except RopException as e:
            l.debug("... %s", e)
            return None
        except (claripy.errors.ClaripySolverInterruptError, claripy.errors.ClaripyZ3Error, ValueError):
            return None
        except (claripy.ClaripyFrontendError, angr.engines.vex.claripy.ccall.CCallMultivaluedException) as e:
            l.warning("... claripy error: %s", e)
            return None

        l.debug("... Appending gadget!")
        return gadget

    def _valid_state(self, init_state, final_state):
        if self._change_arch_state(init_state, final_state):
            return False
        for addr in final_state.history.bbl_addrs:
            b = final_state.project.factory.block(addr)
            if not self.arch.block_make_sense(b):
                return False
        return True

    def _change_arch_state(self, init_state, final_state):
        if isinstance(self.arch, X86):
            for reg in self.arch.segment_regs:
                init_reg= init_state.registers.load(reg)
                final_reg = final_state.registers.load(reg)
                # check whether there is any possibility that they can be different
                if final_state.solver.satisfiable([init_reg != final_reg]):
                    return True
        return False

    def _block_make_sense(self, addr):
        """
        Checks if a block at addr makes sense to analyze for rop gadgets
        :param addr: the address to check
        :return: True or False
        """
        try:
            l.debug("... checking if block makes sense")
            block = self.project.factory.block(addr)

            if not block.capstone.insns:
                return False

            if not self.arch.block_make_sense(block):
                return False

            if block.vex.jumpkind == 'Ijk_NoDecode':
                l.debug("... not decodable")
                return False

            if self._fast_mode:
                if block.vex.jumpkind != "Ijk_Ret" and not block.vex.jumpkind.startswith("Ijk_Sys"):
                    return False

            if any(isinstance(s, pyvex.IRStmt.Dirty) for s in block.vex.statements):
                l.debug("... has dirties that we probably can't handle")
                return False

            for op in block.vex.operations:
                if op.startswith("Iop_Div"):
                    return False

            if block.size > self.arch.max_block_size:
                l.debug("... too long")
                return False

            # we don't like floating point stuff
            if "Ity_F16" in block.vex.tyenv.types or "Ity_F32" in block.vex.tyenv.types \
                    or "Ity_F64" in block.vex.tyenv.types or "Ity_F128" in block.vex.tyenv.types:
                return False

        except angr.errors.SimEngineError:
            l.debug("... some simengine error")
            return False
        except pyvex.PyVEXError:
            l.debug("... some pyvex")
            return False
        except angr.SimCCallError:
            l.debug("... some other angr error")
            return False
        except angr.SimMemoryLimitError:
            l.debug("... angr memory limit error")
            return False
        except angr.UnsupportedIROpError:
            l.debug("... angr unsupported op error")
            return False
        except angr.AngrError:
            return False
        except AttributeError:
            return False

        return True

    def is_in_kernel(self, state):
        ip = state.ip
        if not ip.symbolic:
            obj = self.project.loader.find_object_containing(ip.concrete_value)
            if obj.binary == 'cle##kernel':
                return True
            return False
        return False

    def _can_reach_unconstrained(self, addr, max_steps=2):
        """
        Use static analysis to check whether the address can lead to unconstrained targets
        It is much faster than directly doing symbolic execution on the addr
        """
        b = self.project.factory.block(addr)
        constant_jump_targets = list(b.vex.constant_jump_targets)

        if not constant_jump_targets:
            return True

        # we drop block that have more than 1 jump targets
        # technically, this check make us miss some gadgets that have a branch that is never satisfiable
        # but it is what we need to pay for performance
        if len(constant_jump_targets) > 1:
            return False

        if max_steps == 0:
            return False

        target_block_addr = constant_jump_targets[0]
        if not self._block_make_sense(target_block_addr):
            return False

        return self._can_reach_unconstrained(target_block_addr, max_steps-1)

    def _reach_unconstrained_or_syscall(self, addr):
        init_state = self._state.copy()
        init_state.ip = addr

        # it will raise errors if angr fails to step the state
        final_state = rop_utils.step_to_unconstrained_successor(self.project, state=init_state, stop_at_syscall=True)

        if self.is_in_kernel(final_state):
            state = final_state.copy()
            succ = self.project.factory.successors(state)
            if len(succ.flat_successors) == 0:
                return init_state, final_state
            state = succ.flat_successors[0]
            state2 = rop_utils.step_to_unconstrained_successor(self.project, state=state)
            return init_state, state2
        return init_state, final_state

    def _identify_transit_type(self, final_state, ctrl_type):
        # FIXME: not always jump, could be call as well
        if ctrl_type == 'register':
            return "jmp_reg"
        if ctrl_type == 'syscall':
            return ctrl_type

        if ctrl_type == 'pivot':
            # FIXME: this logic feels wrong
            variables = list(final_state.ip.variables)
            if all(x.startswith("sreg_") for x in variables):
                return "jmp_reg"
            for act in final_state.history.actions:
                if act.type != 'mem':
                    continue
                if act.size != self.project.arch.bits:
                    continue
                if (act.data.ast == final_state.ip).symbolic or \
                    not final_state.solver.eval(act.data.ast == final_state.ip):
                    continue
                sols = final_state.solver.eval_upto(final_state.regs.sp-act.addr.ast, 2)
                if len(sols) != 1:
                    continue
                if sols[0] != final_state.arch.bytes:
                    continue
                return "ret"
            return "pop_pc"

        assert ctrl_type == 'stack'

        v = final_state.memory.load(final_state.regs.sp - final_state.arch.bytes,
                                    size=final_state.arch.bytes,
                                    endness=final_state.arch.memory_endness)
        if v is final_state.ip:
            return "ret"

        return "pop_pc"

    def _create_gadget(self, addr, init_state, final_state, ctrl_type):
        transit_type = self._identify_transit_type(final_state, ctrl_type)

        # create the gadget
        if ctrl_type == 'syscall' or self._does_syscall(final_state):
            gadget = SyscallGadget(addr=addr)
            gadget.makes_syscall = self._does_syscall(final_state)
            gadget.starts_with_syscall = self._starts_with_syscall(addr)
        elif ctrl_type == 'pivot' or self._does_pivot(final_state):
            gadget = PivotGadget(addr=addr)
        else:
            gadget = RopGadget(addr=addr)

        # FIXME this doesnt handle multiple steps
        gadget.block_length = self.project.factory.block(addr).size
        gadget.transit_type = transit_type

        # for jmp_reg gadget, record the jump target register
        if transit_type == "jmp_reg":
            state = self._state.copy()
            insns = self.project.factory.block(addr).capstone.insns
            if state.project.arch.name.startswith("MIPS"):
                idx = -2 # delayed slot
            else:
                idx = -1
            if len(insns) < abs(idx):
                return None
            jump_inst_addr = insns[idx].address
            state.ip = jump_inst_addr
            succ = rop_utils.step_to_unconstrained_successor(self.project, state=state)
            jump_reg = list(succ.ip.variables)[0].split('_', 1)[1].rsplit('-')[0]
            pc_reg = list(final_state.ip.variables)[0].split('_', 1)[1].rsplit('-')[0]
            gadget.pc_reg = pc_reg
            gadget.jump_reg = jump_reg

        # compute sp change
        l.debug("... computing sp change")
        self._compute_sp_change(init_state, final_state, gadget)
        if gadget.stack_change % (self.project.arch.bytes) != 0:
            l.debug("... uneven sp change")
            return None
        if gadget.stack_change < 0:
            l.debug("stack change is negative!!")
            #FIXME: technically, it can be negative, e.g. call instructions
            return None

        # record pc_offset
        if type(gadget) is not PivotGadget and transit_type in ['pop_pc', 'ret']:
            idx = list(final_state.ip.variables)[0].split('_')[2]
            gadget.pc_offset = int(idx) * self.project.arch.bytes

        l.info("... checking for controlled regs")
        self._check_reg_changes(final_state, init_state, gadget)

        # check for reg moves
        # get reg reads
        reg_reads = self._get_reg_reads(final_state)
        l.debug("... checking for reg moves")
        self._check_reg_change_dependencies(init_state, final_state, gadget)
        self._check_reg_movers(init_state, final_state, reg_reads, gadget)

        # check concretized registers
        self._analyze_concrete_regs(init_state, final_state, gadget)

        # check mem accesses
        l.debug("... analyzing mem accesses")
        self._analyze_mem_access(final_state, init_state, gadget)

        for m_access in gadget.mem_writes + gadget.mem_reads + gadget.mem_changes:
            if not m_access.is_valid():
                l.debug("... mem access with no addr dependencies")
                return None

        return gadget

    def _analyze_concrete_regs(self, init_state, final_state, gadget):
        """
        collect registers that are concretized after symbolically executing the block (for example, xor rax, rax)
        """
        if type(gadget) == SyscallGadget:
            state = self._windup_to_presyscall_state(final_state, init_state)
        else:
            state = final_state
        for reg in self.arch.reg_set:
            val = state.registers.load(reg)
            if val.symbolic:
                continue
            gadget.concrete_regs[reg] = state.solver.eval(val)

    def _check_reg_changes(self, final_state, init_state, gadget):
        """
        Checks which registers were changed and which ones were popped
        :param final_state: the stepped path, init_state is an ancestor of it.
        :param init_state: the input state for testing
        :param gadget: the gadget to store register change information
        """
        exit_action = final_state.history.actions[-1]
        if not isinstance(exit_action, angr.state_plugins.sim_action.SimActionExit):
            raise RopException("unexpected SimAction")

        exit_target = exit_action.target.ast

        stack_change = gadget.stack_change if type(gadget) == RopGadget else None

        for reg in self._get_reg_writes(final_state):
            # we assume any register in reg_writes changed
            # verify the stack controls it
            # we need to make sure they arent equal to the exit target otherwise they arent controlled
            # TODO what to do about moves to bp
            if final_state.registers.load(reg) is exit_target:
                gadget.changed_regs.add(reg)
            elif self._check_if_stack_controls_ast(final_state.registers.load(reg), init_state, stack_change):
                gadget.popped_regs.add(reg)
                gadget.changed_regs.add(reg)
            else:
                gadget.changed_regs.add(reg)

    def _check_reg_change_dependencies(self, symbolic_state, symbolic_p, gadget):
        """
        Checks which registers affect register changes
        :param symbolic_state: the input state for testing
        :param symbolic_p: the stepped path, symbolic_state is an ancestor of it.
        :param gadget: the gadget to store the reg change dependencies in
        """
        for reg in gadget.changed_regs:
            # skip popped regs
            if reg in gadget.popped_regs:
                continue
            # check its dependencies
            dependencies = self._get_reg_dependencies(symbolic_p, reg)
            if len(dependencies) != 0:
                gadget.reg_dependencies[reg] = set(dependencies)
            controllers = self._get_reg_controllers(symbolic_state, symbolic_p, reg, dependencies)
            if len(controllers) != 0:
                gadget.reg_controllers[reg] = set(controllers)

    def _check_reg_movers(self, symbolic_state, symbolic_p, reg_reads, gadget):
        """
        Checks if any data is directly copied from one register to another
        :param symbolic_state: the input state for testing
        :param symbolic_p: the stepped path, symbolic_state is an ancestor of it.
        :param reg_reads: all the registers which were read
        :param gadget: the gadget in which to store the reg movers
        :return:
        """
        for reg in gadget.changed_regs:
            regs_to_check = reg_reads
            # skip popped regs
            if reg in gadget.popped_regs:
                continue
            # skip regs that depend on more than 1 reg
            if reg in gadget.reg_dependencies:
                if len(gadget.reg_dependencies[reg]) != 1:
                    continue
                regs_to_check = gadget.reg_dependencies[reg]
            for from_reg in regs_to_check:
                ast_1 = symbolic_state.registers.load(from_reg)
                ast_2 = symbolic_p.registers.load(reg)
                if ast_1 is ast_2:
                    gadget.reg_moves.append(RopRegMove(from_reg, reg, self.project.arch.bits))
                # try lower 32 bits (this is intended for amd64)
                # todo do this for less bits too?
                else:
                    half_bits = self.project.arch.bits // 2
                    ast_1 = claripy.Extract(half_bits-1, 0, ast_1)
                    ast_2 = claripy.Extract(half_bits-1, 0, ast_2)
                    if ast_1 is ast_2:
                        gadget.reg_moves.append(RopRegMove(from_reg, reg, half_bits))

    # TODO: need to handle reg calls
    def _check_for_control_type(self, init_state, final_state):
        """
        :return: the data provenance of the controlled ip in the final state, either the stack or registers
        """

        ip = final_state.ip

        # this gadget arrives a syscall
        if self.is_in_kernel(final_state):
            return 'syscall'

        # the ip is controlled by stack
        if self._check_if_stack_controls_ast(ip, init_state):
            return "stack"

        # the ip is not controlled by regs
        if not ip.variables:
            return None

        # the ip is fully controlled by regs
        variables = list(ip.variables)
        if all(x.startswith("sreg_") for x in variables):
            return "register"

        # this is a stack pivoting gadget
        if all(x.startswith("symbolic_read_") for x in variables) and len(final_state.regs.sp.variables) == 1:
            # we don't fully control sp
            if not init_state.solver.satisfiable(extra_constraints=[final_state.regs.sp == 0x41414100]):
                return None
            # make sure the control after pivot is reasonable

            # find where the ip is read from
            saved_ip_addr = None
            for act in final_state.history.actions:
                if act.type == 'mem' and act.action == 'read':
                    if act.size == self.project.arch.bits and not (act.data.ast == ip).symbolic:
                        if init_state.solver.eval(act.data.ast == ip):
                            saved_ip_addr = act.addr.ast
                            break
            if saved_ip_addr is None:
                return None

            # if the saved ip is too far away from the final sp, that's a bad gadget
            sols = final_state.solver.eval_upto(final_state.regs.sp - saved_ip_addr, 2)
            if len(sols) != 1: # the saved ip has a symbolic distance from the final sp, bad
                return None
            offset = sols[0]
            if offset > self._stack_bsize: # filter out gadgets like mov rsp, rax; ret 0x1000
                return None
            if offset % self.project.arch.bytes != 0: # filter misaligned gadgets
                return None
            return "pivot"

        return None

    @staticmethod
    def _check_if_jump_gadget(final_state, init_state):
        """
        FIXME: this constraint is too strict, it can be less strict
        a gadget is a jump gadget if
            1. it does not modify sp
            2. ip is overwritten by a general purpose register
        """
        # constraint 1
        if not init_state.solver.eval(final_state.regs.sp == init_state.regs.sp):
            return False

        # constraint 2
        ip = final_state.ip
        if len(ip.variables) > 1 or len(ip.variables) == 0:
            return False
        var = list(ip.variables)[0]
        if not var.startswith('sreg_'):
            return False

        return True

    def _check_if_stack_controls_ast(self, ast, initial_state, gadget_stack_change=None):
        if gadget_stack_change is not None and gadget_stack_change <= 0:
            return False

        # if we had the lemma cache this might be already there!
        test_val = 0x4242424242424242 % (1 << self.project.arch.bits)

        # TODO add test where we recognize a value past the end of the stack frame isn't controlled
        # this is an annoying problem but this code should handle it

        # prefilter
        # FIXME: this check is kinda weird, what if it is rax+rbx?
        if len(ast.variables) != 1 or not list(ast.variables)[0].startswith("symbolic_stack"):
            return False

        stack_bytes_length = self._stack_bsize # number of controllable bytes
        if gadget_stack_change is not None:
            stack_bytes_length = min(max(gadget_stack_change, 0), stack_bytes_length)
        concrete_stack = claripy.BVV(b"B" * stack_bytes_length)
        concrete_stack_s = initial_state.copy()
        concrete_stack_s.add_constraints(
            initial_state.memory.load(initial_state.regs.sp, stack_bytes_length) == concrete_stack)
        test_constraint = ast != test_val
        # stack must have set the register and it must be able to set the register to all 1's or all 0's
        ans = not concrete_stack_s.solver.satisfiable(extra_constraints=(test_constraint,)) and \
                rop_utils.fast_unconstrained_check(initial_state, ast)

        return ans

    def _compute_sp_change(self, init_state, final_state, gadget):
        """
        Computes the change in the stack pointer for a gadget
        for a PivotGadget, it is the sp change right before pivoting
        :param symbolic_state: the input symbolic state
        :param gadget: the gadget in which to store the sp change
        """
        if type(gadget) in (RopGadget, SyscallGadget):
            dependencies = self._get_reg_dependencies(final_state, "sp")
            sp_change = final_state.regs.sp - init_state.regs.sp

            # analyze the results
            if len(dependencies) > 1:
                raise RopException("SP has multiple dependencies")
            if len(dependencies) == 0 and sp_change.symbolic:
                raise RopException("SP change is uncontrolled")

            assert self.arch.base_pointer not in dependencies
            if len(dependencies) == 0 and not sp_change.symbolic:
                stack_changes = [init_state.solver.eval(sp_change)]
            elif list(dependencies)[0] == self.arch.stack_pointer:
                stack_changes = init_state.solver.eval_upto(sp_change, 2)
            else:
                raise RopException("SP does not depend on SP or BP")

            if len(stack_changes) != 1:
                raise RopException("SP change is symbolic")

            gadget.stack_change = stack_changes[0]

        elif type(gadget) is PivotGadget:
            final_state = rop_utils.step_to_unconstrained_successor(self.project, state=init_state, precise_action=True)
            dependencies = self._get_reg_dependencies(final_state, "sp")
            last_sp = None
            init_sym_sp = None
            prev_act = None
            for act in final_state.history.actions:
                if act.type == 'reg' and act.action == 'write' and act.storage == self.arch.stack_pointer:
                    if not act.data.ast.symbolic:
                        last_sp = act.data.ast
                    else:
                        init_sym_sp = act.data.ast
                        break
                prev_act = act
            if last_sp is not None:
                gadget.stack_change = (last_sp - init_state.regs.sp).concrete_value
            else:
                gadget.stack_change = 0

            # if is popped from stack, we need to compensate for the popped sp value on the stack
            # if it is a pop, then sp comes from stack and the previous action must be a mem read
            # and the data is the new sp
            variables = init_sym_sp.variables
            if prev_act and variables and all(x.startswith('symbolic_stack_') for x in variables):
                if prev_act.type == 'mem' and prev_act.action == 'read' and prev_act.data.ast is init_sym_sp:
                    gadget.stack_change += self.project.arch.bytes

            assert init_sym_sp is not None
            sols = final_state.solver.eval_upto(final_state.regs.sp - init_sym_sp, 2)
            if len(sols) != 1:
                raise RopException("This gadget pivots more than once, which is currently not handled")
            gadget.stack_change_after_pivot = sols[0]
            gadget.sp_reg_controllers = set(self._get_reg_controllers(init_state, final_state, 'sp', dependencies))
            gadget.sp_stack_controllers = {x for x in final_state.regs.sp.variables if x.startswith("symbolic_stack_")}

    def _build_mem_access(self, a, gadget, init_state, final_state):
        """
        translate an angr symbolic action to angrop MemAccess
        """
        mem_access = RopMemAccess()

        # handle the memory access address
        # case 1: the address is not symbolic
        if not a.addr.ast.symbolic:
            mem_access.addr_constant = init_state.solver.eval(a.addr.ast)
        # case 2: the symbolic address comes from registers
        elif all(x.startswith("sreg_") for x in a.addr.ast.variables):
            mem_access.addr_dependencies = rop_utils.get_ast_dependency(a.addr.ast)
            mem_access.addr_controllers = rop_utils.get_ast_controllers(init_state, a.addr.ast,
                                                                        mem_access.addr_dependencies)
        # case 3: the symbolic address comes from controlled stack
        elif all(x.startswith("symbolic_stack") for x in a.addr.ast.variables):
            mem_access.addr_stack_controllers = set(a.addr.ast.variables)
        # case 4: both, we don't handle it now yet
        else:
            raise RopException("angrop does not handle symbolic address that depends on both regs and stack atm")

        if a.action == "write":
            # for writes we want what the data depends on
            if a.data.ast.symbolic:
                mem_access.data_dependencies = rop_utils.get_ast_dependency(a.data.ast)
                mem_access.data_controllers = rop_utils.get_ast_controllers(init_state, a.data.ast,
                                                                            mem_access.data_dependencies)
            else:
                mem_access.data_constant = init_state.solver.eval(a.data.ast)
        elif a.action == "read":
            # for reads we want to know if any register will have the data after
            succ_state = final_state
            bits_to_extend = self.project.arch.bits - a.data.ast.size()
            # if bits_to_extend is negative it breaks everything, and we probably dont care about it
            if bits_to_extend >= 0:
                for reg in gadget.changed_regs:
                    # skip popped regs
                    if reg in gadget.popped_regs:
                        continue
                    # skip registers which have known dependencies
                    if reg in gadget.reg_dependencies and len(gadget.reg_dependencies[reg]) > 0:
                        continue
                    test_constraint = claripy.And(
                        succ_state.registers.load(reg) != a.data.ast.zero_extend(bits_to_extend),
                        succ_state.registers.load(reg) != a.data.ast.sign_extend(bits_to_extend))

                    if not succ_state.solver.satisfiable(extra_constraints=(test_constraint,)):
                        mem_access.data_dependencies.add(reg)

        mem_access.data_size = a.data.ast.size()
        mem_access.addr_size = a.addr.ast.size()
        return mem_access

    def _build_mem_change(self, read_action, write_action, gadget, init_state, final_state):
        # to change memory, write data must have at least two arguments:
        # <sym_read> <op> <data>, such as `add [rax], rbx`
        if len(write_action.data.ast.args) <= 1:
            return None

        # to change memory, the read must be symbolic and the write data must be derived from
        # the symbolic read data
        read_variables = {x for x in read_action.data.ast.variables if x.startswith('symbolic_read_unconstrained')}
        if not read_variables:
            return None
        write_variables = {x for x in write_action.data.ast.variables if x.startswith('symbolic_read_unconstrained')}
        if not read_variables.intersection(write_variables):
            return None

        # identify the symbolic data controller
        sym_data = None
        for d in write_action.data.ast.args:
            # filter out concrete values
            if not isinstance(d, claripy.ast.bv.BV):
                continue
            # filter out the symbolic read itself
            # FIXME: technically, there could be cases where the controller also comes from a symbolic read
            # but we don't handle it atm
            vs = d.variables
            if any(x.startswith('symbolic_read_unconstrained_') for x in vs):
                continue
            # TODO: we don't handle the cases where there are multiple data dependencies
            if sym_data is not None:
                return None
            sym_data = d
        if sym_data is None:
            return None

        # FIXME: here, if the action does a constant increment
        # such as mov rax, [rbx]; inc rax; mov [rbx], rax,
        # this gadget will be ignored by us, which is not great
        data_dependencies = rop_utils.get_ast_dependency(sym_data)
        if len(data_dependencies) != 1:
            return None
        data_controllers = rop_utils.get_ast_controllers(init_state, sym_data, data_dependencies)
        if len(data_controllers) != 1:
            return None

        mem_change = self._build_mem_access(read_action, gadget, init_state, final_state)
        mem_change.op = write_action.data.ast.op
        mem_change.data_dependencies = data_dependencies
        mem_change.data_controllers = data_controllers
        mem_change.data_size = write_action.data.ast.size()
        mem_change.addr_size = write_action.addr.ast.size()
        return mem_change

    def _does_syscall(self, symbolic_p):
        """
        checks if the path does a system call at some point
        :param symbolic_p: input path of which to check history
        """
        for addr in symbolic_p.history.bbl_addrs:
            if self.project.simos.is_syscall_addr(addr):
                return True

        return False

    def _is_pivot_action(self, act):
        """
        check whether an sim_action is a stack pivoting action
        """
        if act.type != 'reg' or act.action != 'write':
            return False
        try:
            storage = act.storage
        except KeyError:
            return False
        if storage != self.arch.stack_pointer:
            return False
        # this gadget has done symbolic pivoting if there is a symbolic write to the stack pointer
        if act.data.symbolic:
            return True
        return False

    def _does_pivot(self, final_state):
        """
        checks if the path does a stack pivoting at some point
        :param final_state: the state that finishes the gadget execution
        """
        for act in final_state.history.actions:
            if self._is_pivot_action(act):
                return True
        return False

    def _analyze_mem_access(self, final_state, init_state, gadget):
        """
        analyzes memory accesses and stores their info in the gadget
        :param final_state: the stepped state, init_state is an ancestor of it.
        :param init_state: the input state for testing
        :param gadget: the gadget to store mem acccess in
        """
        all_mem_actions = []
        sp_vars = final_state.regs.sp.variables
        pivot_done = False

        # step 1: filter out irrelevant actions and irrelevant memory accesses
        for a in final_state.history.actions.hardcopy:
            if self._is_pivot_action(a):
                pivot_done = True
                continue

            if a.type != 'mem':
                continue

            # we don't like floating point stuff
            if isinstance(a.data.ast, (claripy.ast.FP)):
                continue

            # ignore read/write on stack after pivot
            if pivot_done and a.addr.ast.symbolic and not a.addr.ast.variables - sp_vars:
                continue

            # ignore read/write on stack
            if not a.addr.ast.symbolic:
                addr_constant = init_state.solver.eval(a.addr.ast)
                stack_min_addr = self._concrete_sp - 0x20
                # TODO should this be changed, so that we can more easily understand writes outside the frame
                stack_max_addr = max(stack_min_addr + self._stack_bsize, stack_min_addr + gadget.stack_change)
                if addr_constant is not None and \
                        stack_min_addr <= addr_constant < stack_max_addr:
                    continue
            all_mem_actions.append(a)

        # step 2: identify memory change accesses by indexing using the memory address as the key
        # specifically, if there is a read/write sequence on the same memory address,
        # and no subsequent memory actions on that same address, then the two actions will be
        # merged into a memory change action
        d = defaultdict(list)
        for a in all_mem_actions:
            d[a.addr.ast].append(a)
        to_del = set()
        for addr, actions in d.items():
            if len(actions) != 2:
                continue
            if actions[0].action != 'read' or actions[1].action != 'write':
                continue
            mem_change = self._build_mem_change(actions[0], actions[1], gadget, init_state, final_state)
            if mem_change:
                to_del.add(addr)
                gadget.mem_changes.append(mem_change)
        for addr in to_del:
            for m in d[addr]:
                all_mem_actions.remove(m)

        # step 3: add all left memory actions to either read/write memory accesses stashes
        for a in all_mem_actions:
            mem_access = self._build_mem_access(a, gadget, init_state, final_state)
            if a.action == "read":
                gadget.mem_reads.append(mem_access)
            if a.action == "write":
                gadget.mem_writes.append(mem_access)

    def _starts_with_syscall(self, addr):
        """
        checks if the path starts with a system call
        :param addr: input path to check history of
        """

        return self.project.factory.block(addr, num_inst=1).vex.jumpkind.startswith("Ijk_Sys")

    def _windup_to_presyscall_state(self, final_state, init_state):
        """
        Retrieve the state of a gadget just before the syscall is made
        :param symbolic_p: the stepped path, symbolic_state is an ancestor of it.
        :param symbolic_state: input state for testing
        """

        if self._does_syscall(final_state) or self.is_in_kernel(final_state):
            # step up until the syscall and save the possible syscall numbers into the gadget
            prev = cur = init_state.copy()
            while not self._does_syscall(cur) and not self.is_in_kernel(cur):
                tmp = rop_utils.step_one_inst(self.project, cur.copy(), stop_at_syscall=True)
                prev = cur
                cur = tmp
            return prev.copy()

        raise RopException("Gadget passed to _windup_to_presyscall_state does not make a syscall")

    # UTILITY FUNCTIONS

    @staticmethod
    def _get_reg_dependencies(symbolic_p, test_reg):
        """
        Gets all the registers which affect a test register
        :param symbolic_p: the stepped path, symbolic_state is an ancestor of it.
        :param test_reg: the register of which we are trying to analyze dependencies
        :return: A set of register names which affect the test_reg
        """
        dependencies = rop_utils.get_ast_dependency(symbolic_p.registers.load(test_reg))
        return dependencies

    @staticmethod
    def _get_reg_controllers(symbolic_state, symbolic_p, test_reg, reg_deps):
        """
        Gets all the registers which can completely control a test register
        :param symbolic_state: the input state for testing
        :param symbolic_p: the stepped path, symbolic_state is an ancestor of it.
        :param test_reg: the register which we are trying to analyze controllers
        :param reg_deps: All registers which it depends on
        :return: A set of register names which can control the test_reg
        """
        controllers = rop_utils.get_ast_controllers(symbolic_state, symbolic_p.registers.load(test_reg), reg_deps)
        return controllers

    def _get_reg_reads(self, path):
        """
        Finds all the registers read in a path
        :param path: The path to check
        :return: A set of register names which are read
        """
        all_reg_reads = set()
        for a in reversed(path.history.actions):
            if a.type == "reg" and a.action == "read":
                try:
                    reg_name = rop_utils.get_reg_name(self.project.arch, a.offset)
                    if reg_name in self.arch.reg_set:
                        all_reg_reads.add(reg_name)
                    elif reg_name != self.arch.stack_pointer:
                        l.info("reg read from register not in reg_set: %s", reg_name)
                except RegNotFoundException as e:
                    l.debug(e)
        return all_reg_reads

    def _get_reg_writes(self, path):
        """
        Finds all the registers written in a path
        :param path: The path to check
        :return: A set of register names which are read
        """
        all_reg_writes = set()
        for a in reversed(path.history.actions):
            if a.type == "reg" and a.action == "write":
                try:
                    reg_name = rop_utils.get_reg_name(self.project.arch, a.offset)
                    if reg_name in self.arch.reg_set:
                        all_reg_writes.add(reg_name)
                    elif reg_name != self.arch.stack_pointer:
                        l.info("reg write from register not in reg_set: %s", reg_name)
                except RegNotFoundException as e:
                    l.debug(e)
        return all_reg_writes


# TODO ip setters, ie call rax
