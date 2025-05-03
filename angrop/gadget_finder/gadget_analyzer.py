import math
import ctypes
import logging
import itertools
from collections import defaultdict

import angr
import pyvex
import claripy
from angr.analyses.bindiff import differing_constants
from angr.analyses.bindiff import UnmatchedStatementsException
from angr.errors import SimEngineError, SimMemoryError

from .. import rop_utils
from ..arch import get_arch, X86, RISCV64
from ..rop_gadget import RopGadget, PivotGadget, SyscallGadget
from ..rop_effect import RopMemAccess, RopRegMove, RopRegPop
from ..rop_block import RopBlock
from ..errors import RopException, RegNotFoundException, RopTimeoutException

l = logging.getLogger("angrop.gadget_analyzer")


class GadgetAnalyzer:
    """
    find and analyze gadgets from binary code
    """
    def __init__(self, project, fast_mode, kernel_mode=False, arch=None, stack_gsize=80, cond_br=False, max_bb_cnt=2):
        """
        stack_gsize: number of controllable gadgets on the stack
        """
        # params
        self.project = project
        self.arch = get_arch(project, kernel_mode=kernel_mode) if arch is None else arch
        self._fast_mode = fast_mode
        self._allow_conditional_branches = cond_br
        self._max_bb_cnt = max_bb_cnt

        # initial state that others are based off, all analysis should copy the state first and work on
        # the copied state
        self._stack_bsize = stack_gsize * self.project.arch.bytes # number of controllable bytes on stack
        if isinstance(self.arch, X86):
            extra_reg_set = self.arch.segment_regs
        else:
            extra_reg_set = None
        self._state = rop_utils.make_symbolic_state(self.project, self.arch.reg_list, stack_gsize,
                                                    extra_reg_set=extra_reg_set, symbolize_got=True)
        self._concrete_sp = self._state.solver.eval(self._state.regs.sp)

    def analyze_gadget(self, addr, allow_conditional_branches=None) -> list[RopGadget] | RopGadget | None:
        """
        Find gadgets at the given address.

        Support for gadgets with conditional branches can be enabled using the
        allow_conditional_branches option, which is False by default for
        compatibility with existing code that can't handle these gadgets.
        Returns a list of gadgets when allow_conditional_branches is enabled,
        and a single gadget or None when it is disabled.

        :param addr: address to analyze for gadgets
        :param allow_conditional_branches: whether to allow gadgets with conditional branches
        :return: a list of RopGadget instances or a single RopGadget instance
        """
        if allow_conditional_branches is None:
            allow_conditional_branches = self._allow_conditional_branches
        try:
            gadgets = self._analyze_gadget(addr, allow_conditional_branches)
        except RopTimeoutException:
            return [] if allow_conditional_branches else None
        if allow_conditional_branches:
            return gadgets
        else:
            assert len(gadgets) <= 1
            return (
                gadgets[0]
                if gadgets and not gadgets[0].has_conditional_branch
                else None
            )

    def _step_to_gadget_stopping_states(self, init_state):
        """
        Currently, the following scenarios are considered as stopping states:
        1. unconstrained (e.g. ret)
        2. invokes syscall (e.g. syscall)

        for gadgets invoking syscalls, we will try to step over it to find gadgets such as "syscall; ret"
        """
        try:
            simgr = self.project.factory.simulation_manager(init_state, save_unconstrained=True)

            def filter_func(state):
                if not state.ip.concrete:
                    return None
                if self.project.is_hooked(state.addr):
                    # We don't want to go into SimProcedures.
                    return simgr.DROP
                if rop_utils.is_in_kernel(self.project, state):
                    return "syscall"
                if not self._block_make_sense(state.addr):
                    return simgr.DROP
                return None

            simgr.run(n=self._max_bb_cnt, filter_func=filter_func)
            simgr.move(from_stash='active', to_stash='syscall',
                       filter_func=lambda s: rop_utils.is_in_kernel(self.project, s))

        except (claripy.ClaripySolverInterruptError, claripy.errors.ClaripyZ3Error, ValueError): # type: ignore
            return [], []
        except (claripy.ClaripyFrontendError,
                angr.engines.vex.claripy.ccall.CCallMultivaluedException) as e: # type: ignore
            l.warning("... claripy error: %s", e)
            return [], []
        except (angr.errors.AngrError, angr.errors.AngrRuntimeError, angr.errors.SimError):
            return [], []
        except RopTimeoutException:
            return [], []
        except (ctypes.ArgumentError, RecursionError):
            return [], []

        final_states = list(simgr.unconstrained)
        if "syscall" in simgr.stashes:
            final_states.extend(self._try_stepping_past_syscall(state) for state in simgr.syscall)

        bad_states = simgr.active + simgr.deadended

        return final_states, bad_states

    @rop_utils.timeout(3)
    def _analyze_gadget(self, addr, allow_conditional_branches):
        l.info("Analyzing 0x%x", addr)

        # Step 1: first statically check if the block can reach stopping states
        #         static analysis is much faster
        if not self._can_reach_stopping_states(addr, allow_conditional_branches, max_steps=self._max_bb_cnt):
            return []

        # Step 2: get all potential successor states
        init_state = self._state.copy()
        init_state.ip = addr
        final_states, bad_states = self._step_to_gadget_stopping_states(init_state)

        if not allow_conditional_branches and (bad_states or len(final_states) != 1):
            return []

        gadgets = []

        for final_state in final_states:
            try:
                if not self._valid_state(init_state, final_state):
                    continue

                ctrl_type = self._check_for_control_type(init_state, final_state)
                if not ctrl_type:
                    # for example, jump outside of the controllable region
                    l.debug("... cannot maintain the control flow hijacking primitive after executing the gadget")
                    continue

                # Step 3: gadget effect analysis
                l.debug("... analyzing rop potential of block")
                gadget = self._create_gadget(addr, init_state, final_state, ctrl_type, allow_conditional_branches)
                if not gadget:
                    continue

                l.debug("... Appending gadget!")
                gadgets.append(gadget)

            except RopTimeoutException:
                return gadgets
            except RopException as e:
                l.debug("... %s", e)
                continue
            except (claripy.ClaripySolverInterruptError, claripy.errors.ClaripyZ3Error, ValueError): # type: ignore
                continue
            except (claripy.ClaripyFrontendError,
                    angr.engines.vex.claripy.ccall.CCallMultivaluedException) as e: # type: ignore
                l.warning("... claripy error: %s", e)
                continue
            except (angr.errors.AngrError, angr.errors.AngrRuntimeError, angr.errors.SimError):
                continue
            except (ctypes.ArgumentError, RecursionError):
                continue

        return gadgets

    def _valid_state(self, init_state, final_state):
        if self._change_arch_state(init_state, final_state):
            return False
        # stack change is too large
        if not final_state.regs.sp.symbolic and final_state.regs.sp.concrete_value - self._concrete_sp > self._stack_bsize:
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

    def _block_make_sense_nostmt(self, block):
        if block.size > self.arch.max_block_size:
            l.debug("... too long")
            return False
        if block.vex.jumpkind in ('Ijk_SigTRAP', 'Ijk_NoDecode', 'Ijk_Privileged', 'Ijk_Yield'):
            l.debug("... not decodable")
            return False
        for target in block.vex.constant_jump_targets:
            if self.project.loader.find_segment_containing(target) is None:
                return False
        if self._fast_mode:
            if block.vex.jumpkind != "Ijk_Ret" and not block.vex.jumpkind.startswith("Ijk_Sys"):
                return False
        return True

    def _block_make_sense_vex(self, block):
        # we don't like floating point and SIMD stuff
        if any(t in block.vex.tyenv.types for t in ('Ity_F16', 'Ity_F32', 'Ity_F64', 'Ity_F128', 'Ity_V128')):
            return False

        if any(isinstance(s, pyvex.IRStmt.Dirty) for s in block.vex.statements):
            l.debug("... has dirties that we probably can't handle")
            return False

        # make sure all constant memory accesses are in-bound
        for expr in block.vex.expressions:
            if expr.tag in ('Iex_Load', 'Ist_Store'):
                if isinstance(expr.addr, pyvex.expr.Const):
                    if self.project.loader.find_segment_containing(expr.addr.con.value) is None:
                        return False

        for op in block.vex.operations:
            if op.startswith("Iop_Div"):
                return False

        return True

    def _block_make_sense_sym_access(self, block):
        # make sure there are not too many symbolic accesses
        # note that we can't actually distinguish between memory accesses on stack
        # and other memory accesses, we just assume all non-word access are symbolic memory accesses
        # consider at most one access each instruction

        # split statements by instructions
        accesses = set()
        word_ty = f'Ity_I{self.project.arch.bits}'
        insts = []
        inst = []
        for stmt in block.vex.statements:
            if isinstance(stmt, pyvex.stmt.IMark):
                insts.append(inst)
                inst = []
            else:
                inst.append(stmt)
        if inst:
            insts.append(inst)
        # count memory accesses
        for inst in insts:
            exprs = itertools.chain(*[x.expressions for x in inst])
            for expr in exprs:
                if expr.tag not in ('Iex_Load', 'Ist_Store'):
                    continue
                if isinstance(expr.addr, pyvex.expr.Const):
                    continue
                if expr.ty == word_ty:
                    continue
                accesses.add(str(expr.addr))
                break
        if len(accesses) > self.arch.max_sym_mem_access:
            return False
        return True

    def _block_make_sense(self, addr):
        """
        Checks if a block at addr makes sense to analyze for rop gadgets
        :param addr: the address to check
        :return: True or False
        """
        try:
            l.debug("... checking if block makes sense")
            block = self.project.factory.block(addr)
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
        except KeyError:
            return False

        if not self._block_make_sense_nostmt(block):
            return False
        if not self._block_make_sense_vex(block):
            return False
        if not self._block_make_sense_sym_access(block):
            return False

        if not self.arch.block_make_sense(block):
            return False

        if not block.capstone.insns and not isinstance(self.arch, RISCV64):
            return False


        return True

    def is_in_kernel(self, state):
        return rop_utils.is_in_kernel(self.project, state)

    def is_kernel_addr(self, addr):
        return rop_utils.is_kernel_addr(self.project, addr)

    def _can_reach_stopping_states(self, addr, allow_conditional_branches, max_steps=2):
        """
        Use static analysis to check whether the address can lead to unconstrained targets
        It is much faster than directly doing symbolic execution on the addr
        """
        if not self._block_make_sense(addr):
            return False

        b = self.project.factory.block(addr)

        if max_steps == self._max_bb_cnt: # this is the very first basic block
            # it doesn't make sense to have a gadget that starts with a conditional jump
            # this type of gadgets should be represented by two gadgets after the jump
            if b._instructions == 1 and len(b.vex.constant_jump_targets) > 1:
                return False

        constant_jump_targets = list(b.vex.constant_jump_targets)

        if not constant_jump_targets:
            return True

        if not allow_conditional_branches and len(constant_jump_targets) > 1:
            return False

        if max_steps == 0:
            return False

        for target_block_addr in constant_jump_targets:
            if self._can_reach_stopping_states(target_block_addr, allow_conditional_branches, max_steps-1):
                return True
        return False

    def _try_stepping_past_syscall(self, state):
        simgr = self.project.factory.simgr(state, save_unconstrained=True)
        def filter_func(state):
            if not state.ip.concrete:
                return None
            if self.project.is_hooked(state.addr):
                # We don't want to go into SimProcedures.
                return simgr.DROP
            if not self.is_in_kernel(state) and not self._block_make_sense(state.addr):
                return simgr.DROP
            return None
        try:
            simgr.run(n=2, filter_func=filter_func)
        except ValueError:
            return state
        if len(simgr.unconstrained) != 1:
            return state
        return simgr.unconstrained[0]

    @staticmethod
    def _control_to_transit_type(ctrl_type):
        match ctrl_type:
            case 'syscall':
                return None
            case 'pivot':
                return None
            case 'register':
                return "jmp_reg"
            case 'stack':
                return 'pop_pc'
            case 'memory':
                return "jmp_mem"
            case _:
                raise ValueError("Unknown control type")

    def _effect_analysis(self, gadget, init_state, final_state, ctrl_type, do_cond_branch):
        # compute sp change
        l.debug("... computing sp change")
        self._compute_sp_change(init_state, final_state, gadget)
        if (gadget.stack_change % self.project.arch.bytes) != 0:
            l.debug("... uneven sp change")
            return None

        # transit_type-based handling
        if ctrl_type is not None:
            transit_type = self._control_to_transit_type(ctrl_type)
            gadget.transit_type = transit_type
            arch_bits = self.project.arch.bits
            match transit_type:
                case 'pop_pc': # record pc_offset
                    idx = list(final_state.ip.variables)[0].split('_')[2]
                    gadget.pc_offset = int(idx) * self.project.arch.bytes
                    if gadget.pc_offset >= gadget.stack_change:
                        return None
                case 'jmp_reg': # record pc_reg
                    # TODO: we should support gadgets like `add rax, 0x1000; call rax`
                    # use test_chainbuilder.test_normalize_call as the testcase
                    if final_state.ip.depth > 1:
                        return None
                    gadget.pc_reg = list(final_state.ip.variables)[0].split('_', 1)[1].rsplit('-')[0]
                case 'jmp_mem': # record pc_target
                    # TODO: we currently don't support jmp_mem gadgets that look like
                    # pop rax; pop rbx; jmp [rax+rbx]
                    for a in reversed(final_state.history.actions):
                        if a.type == 'mem' and a.action == 'read' and a.size == arch_bits:
                            if (a.data.ast == final_state.ip).is_true():
                                gadget.pc_target = a.addr.ast
                                break
                    if gadget.pc_target is None:
                        return None

        # register effect analysis
        l.info("... checking for controlled regs")
        self._check_reg_changes(final_state, init_state, gadget)
        l.debug("... checking for reg moves")
        self._check_reg_change_dependencies(init_state, final_state, gadget)
        self._check_reg_movers(init_state, final_state, gadget)
        self._analyze_concrete_regs(final_state, gadget)
        self._check_pop_equal_set(gadget, final_state)

        # memory access analysis
        l.debug("... analyzing mem accesses")
        if not self._analyze_mem_access(final_state, init_state, gadget):
            l.debug("... too many symbolic memory accesses")
            return None

        for m_access in gadget.mem_writes + gadget.mem_reads + gadget.mem_changes:
            if not m_access.is_valid():
                l.debug("... mem access with no addr dependencies")
                return None

        gadget.bbl_addrs = list(x for x in final_state.history.bbl_addrs if not self.is_kernel_addr(x))
        gadget.isn_count = sum(self.project.factory.block(addr).instructions for addr in gadget.bbl_addrs)

        # conditional branch analysis
        if do_cond_branch:
            gadget = self._cond_branch_analysis(gadget, final_state)
        return gadget

    def _cond_branch_analysis(self, gadget, final_state):
        # list all conditional branch dependencies
        branch_guards = set()
        branch_guard_vars = set()
        for guard in final_state.history.jump_guards:
            if claripy.is_true(guard):
                continue
            branch_guards.add(guard)
            branch_guard_vars |= guard.variables

        # make sure all guards are controllable by us
        for var in branch_guard_vars:
            if var.startswith('sreg_') or var.startswith('symbolic_stack_'):
                continue
            return None

        # we do not consider a gadget having conditional branch if the branch guards can be set by itself
        gadget.has_conditional_branch = any(not v.startswith('symbolic_stack_') for v in branch_guard_vars)
        #gadget.has_conditional_branch = any(not v.startswith('symbolic_stack_') for v in branch_guard_vars)

        # if there is no conditional branch, good, we just finished the analysis
        if not branch_guards:
            return gadget

        # now analyze the branch dependencies and filter out gadgets that we do not support yet
        # TODO: support more guards such as existing flags
        def handle_constrained_var(var):
            if var.startswith("sreg_"):
                gadget.branch_dependencies.add(var.split('_', 1)[1].split('-', 1)[0])
            elif var.startswith("symbolic_stack_"):
                # we definitely can control this, but remove it from reg_pops
                to_remove = set()
                for pop in gadget.reg_pops:
                    reg = pop.reg
                    reg_val = final_state.registers.load(reg)
                    if var in reg_val.variables:
                        to_remove.add(pop)
                gadget.reg_pops -= to_remove

        for guard in branch_guards:
            if len(guard.variables) > 1:
                for var in guard.variables:
                    handle_constrained_var(var)
            else:
                var = list(guard.variables)[0]
                arg0 = guard.args[0]
                arg1 = guard.args[1]
                ast = arg0 if arg0.symbolic else arg1
                if rop_utils.loose_constrained_check(final_state, ast, extra_constraints=[guard]):
                    if var.startswith("sreg_"):
                        gadget.branch_dependencies.add(var.split('_', 1)[1].split('-', 1)[0])
                    continue
                handle_constrained_var(var)

        return gadget

    def _create_gadget(self, addr, init_state, final_state, ctrl_type, do_cond_branch):
        # create the gadget
        if ctrl_type == 'syscall' or self._does_syscall(final_state):
            # gadgets that do syscall and pivoting are too complicated
            if self._does_pivot(final_state):
                return None

            # FIXME: this try-except here is specifically for MIPS because angr
            # does not handle breakpoints in MIPS well
            try:
                prologue_state = rop_utils.step_to_syscall(init_state)
            except RuntimeError:
                return None
            g = RopGadget(addr=addr)
            if init_state.addr != prologue_state.addr:
                self._effect_analysis(g, init_state, prologue_state, None, do_cond_branch)
            gadget = SyscallGadget(addr=addr)
            gadget.prologue = g
        elif ctrl_type == 'pivot' or self._does_pivot(final_state):
            gadget = PivotGadget(addr=addr)
        else:
            gadget = RopGadget(addr=addr)

        gadget = self._effect_analysis(gadget, init_state, final_state, ctrl_type, do_cond_branch)
        return gadget

    def _analyze_concrete_regs(self, final_state, gadget):
        """
        collect registers that are concretized after symbolically executing the block (for example, xor rax, rax)
        """
        for reg in self.arch.reg_list:
            val = final_state.registers.load(reg)
            if val.symbolic:
                continue
            gadget.concrete_regs[reg] = final_state.solver.eval(val)

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
            ast = final_state.registers.load(reg)
            if ast is exit_target or ast.variables.intersection(exit_target.variables):
                gadget.changed_regs.add(reg)
            elif self._check_if_stack_controls_ast(ast, final_state, stack_change):
                if ast.op == 'Concat':
                    raise RopException("cannot handle Concat")
                bits = self.project.arch.bits
                extended = rop_utils.bits_extended(ast)
                if extended is not None and bits == 64:
                    if extended <= 32:
                        bits = 32
                pop = RopRegPop(reg, bits)
                gadget.reg_pops.add(pop)
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
            # check its dependencies and controllers
            dependencies = self._get_reg_dependencies(symbolic_p, reg)
            if len(dependencies) != 0:
                gadget.reg_dependencies[reg] = set(dependencies)
                controllers = self._get_reg_controllers(symbolic_state, symbolic_p, reg, dependencies)
                if controllers:
                    gadget.reg_controllers[reg] = set(controllers)

    def _check_pop_equal_set(self, gadget, final_state):
        """
        identify the situation where the final registers are dependent on each other
        e.g. in `pop rax; mov rbx, rax; add rbx, 1; ret;` rax and rbx are set by the same variable
        """

        d = defaultdict(list)
        for reg in self.arch.reg_list:
            ast = final_state.registers.load(reg)
            for v in ast.variables:
                d[v].append(reg)
        for v, regs in d.items():
            if not regs:
                continue
            if not v.startswith("symbolic_stack"):
                continue
            gadget.pop_equal_set.add(tuple(regs))

    @staticmethod
    def _is_add_int(final_val, init_val):
        if final_val.depth != 2 or final_val.op not in ("__add__", "__sub__"):
            return False
        arg0 = final_val.args[0]
        arg1 = final_val.args[1]
        if arg0 is init_val:
            return not arg1.symbolic
        if arg1 is init_val:
            return not arg0.symbolic
        return False

    def _check_reg_movers(self, init_state, final_state, gadget):
        """
        Checks if any data is directly copied from one register to another
        :param init_state: the input state for testing
        :param final_state: the stepped path, symbolic_state is an ancestor of it.
        :param gadget: the gadget in which to store the reg movers
        :return:
        """
        for reg in gadget.changed_regs - gadget.popped_regs:
            final_val = final_state.registers.load(reg)
            if len(final_val.variables) != 1:
                continue
            var_name = list(final_val.variables)[0]
            if not var_name.startswith("sreg_"):
                continue
            from_reg = var_name[5:].split('-')[0]
            # rax->rax (32bit) is not a move, it is a register change
            if from_reg == reg:
                continue
            init_val = init_state.registers.load(from_reg)
            if init_val is final_val:
                gadget.reg_moves.append(RopRegMove(from_reg, reg, self.project.arch.bits))
            elif self._is_add_int(final_val, init_val): # rax = rbx + <int> should be also considered as move
                gadget.reg_moves.append(RopRegMove(from_reg, reg, self.project.arch.bits))
            else:
                # try lower 32 bits (this is intended for amd64)
                # TODO: do this for less bits too?
                half_bits = self.project.arch.bits // 2
                init_val = claripy.Extract(half_bits-1, 0, init_val)
                final_val = claripy.Extract(half_bits-1, 0, final_val)
                if init_val is final_val:
                    gadget.reg_moves.append(RopRegMove(from_reg, reg, half_bits))

    def _check_for_control_type(self, init_state, final_state):
        """
        :return: the data provenance of the controlled ip in the final state
        """

        ip = final_state.ip

        # this gadget arrives at a syscall
        if self.is_in_kernel(final_state):
            return 'syscall'

        # the ip is controlled by stack (ret)
        if self._check_if_stack_controls_ast(ip, final_state):
            return "stack"

        # the ip is not controlled by regs/mem
        if not ip.variables:
            return None
        ip_variables = list(ip.variables)

        # the ip is fully controlled by regs (jmp rax)
        if all(x.startswith("sreg_") for x in ip_variables):
            return "register"

        # the ip is fully controlled by memory and sp is not symbolic (jmp [rax])
        if all(x.startswith("symbolic_read_") for x in ip_variables) and not final_state.regs.sp.symbolic:
            return "memory"

        # this is a stack pivoting gadget
        if self._check_if_stack_pivot(init_state, final_state):
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

    def _check_if_stack_controls_ast(self, ast, final_state, gadget_stack_change=None):
        if gadget_stack_change is not None and gadget_stack_change <= 0:
            return False

        # TODO add test where we recognize a value past the end of the stack frame isn't controlled
        # this is an annoying problem but this code should handle it

        # prefilter
        if len(ast.variables) != 1 or not list(ast.variables)[0].startswith("symbolic_stack"):
            return False

        # check whether it is loosely constrained if it is constrained
        if ast.variables.intersection(final_state.solver._solver.variables):
            return rop_utils.loose_constrained_check(final_state, ast)
        # if it is not constrained, check whether it is a decent ast
        # (symbolic_stack_0_0_32 >> 0x1f) is not because we only control 1 bit
        return rop_utils.fast_unconstrained_check(final_state, ast)

    def _check_if_stack_pivot(self, init_state, final_state):
        ip_variables = list(final_state.ip.variables)
        if any(not x.startswith("symbolic_read_") for x in ip_variables):
            return None
        if len(final_state.regs.sp.variables) != 1:
            return None

        # check if we fully control sp
        if not init_state.solver.satisfiable(extra_constraints=[final_state.regs.sp == 0x41414100]):
            return None

        # make sure the control after pivot is reasonable

        # find where the ip is read from
        ip = final_state.ip
        saved_ip_addr = None
        for act in final_state.history.actions:
            if act.type == 'mem' and act.action == 'read':
                if (
                    act.size == self.project.arch.bits
                    and isinstance(act.data.ast, claripy.ast.BV)
                    and not (act.data.ast == ip).symbolic
                ):
                    if init_state.solver.eval(act.data.ast == ip):
                        saved_ip_addr = act.addr.ast
                        break
        if saved_ip_addr is None:
            return None

        # if the saved ip is too far away from the final sp, that's a bad gadget
        sols = final_state.solver.eval_to_ast(final_state.regs.sp - saved_ip_addr, 2)
        sols = [x.concrete_value for x in sols]
        if len(sols) != 1: # the saved ip has a symbolic distance from the final sp, bad
            return None
        offset = sols[0]
        if offset > self._stack_bsize: # filter out gadgets like mov rsp, rax; ret 0x1000
            return None
        if offset % self.project.arch.bytes != 0: # filter misaligned gadgets
            return None
        return "pivot"

    def _to_signed(self, value):
        bits = self.project.arch.bits
        if value >> (bits-1): # if the MSB is 1, this value is negative
            value -= (1<<bits)
        return value

    def _compute_sp_change(self, init_state, final_state, gadget):
        """
        Computes the change in the stack pointer for a gadget
        for a PivotGadget, it is the sp change right before pivoting
        :param symbolic_state: the input symbolic state
        :param gadget: the gadget in which to store the sp change
        """
        if type(gadget) in (RopGadget, SyscallGadget, RopBlock):
            dependencies = self._get_reg_dependencies(final_state, "sp")
            sp_change = final_state.regs.sp - init_state.regs.sp

            # analyze the results
            if len(dependencies) > 1:
                raise RopException("SP has multiple dependencies")
            if len(dependencies) == 0 and sp_change.symbolic:
                raise RopException("SP change is uncontrolled")
            assert not dependencies
            if len(dependencies) == 0 and not sp_change.symbolic:
                stack_changes = [init_state.solver.eval(sp_change)]
            elif list(dependencies)[0] == self.arch.stack_pointer:
                stack_changes = init_state.solver.eval_to_ast(sp_change, 2)
                stack_changes = [x.concrete_values for x in stack_changes]
            else:
                raise RopException("SP does not depend on SP or BP")

            if len(stack_changes) != 1:
                raise RopException("SP change is symbolic")

            gadget.stack_change = self._to_signed(stack_changes[0])
            if gadget.stack_change % self.project.arch.bytes != 0 or abs(gadget.stack_change) > 0x1000:
                raise RopException("bad SP")

        elif type(gadget) is PivotGadget:
            dependencies = self._get_reg_dependencies(final_state, "sp")
            last_sp = None
            init_sym_sp = None # type: ignore
            prev_act = None
            bits = self.project.arch.bits
            max_prev_pivot_sc = 0
            for act in final_state.history.actions:
                if act.type == 'mem' and not act.addr.ast.symbolic:
                    end = act.addr.ast.concrete_value + act.size//8
                    sc = end - self._concrete_sp
                    if sc > max_prev_pivot_sc:
                        max_prev_pivot_sc = sc
                if act.type == 'reg' and act.action == 'write' and act.size == bits and \
                            act.storage == self.arch.stack_pointer:
                    if not act.data.ast.symbolic:
                        last_sp = act.data.ast
                    else:
                        init_sym_sp = act.data.ast
                        break
                prev_act = act
            if last_sp is not None:
                gadget.stack_change = self._to_signed((last_sp - init_state.regs.sp).concrete_value)
            else:
                gadget.stack_change = 0

            gadget.stack_change_before_pivot = max_prev_pivot_sc

            if init_sym_sp is None:
                raise RopException("PivotGadget does not work with conditional branches")

            # if is popped from stack, we need to compensate for the popped sp value on the stack
            # if it is a pop, then sp comes from stack and the previous action must be a mem read
            # and the data is the new sp
            variables = init_sym_sp.variables
            if prev_act and variables and all(x.startswith('symbolic_stack_') for x in variables):
                if prev_act.type == 'mem' and prev_act.action == 'read' and prev_act.data.ast is init_sym_sp:
                    gadget.stack_change += self.project.arch.bytes

            assert init_sym_sp is not None
            sols = final_state.solver.eval_to_ast(final_state.regs.sp - init_sym_sp, 2)
            sols = [x.concrete_value for x in sols]
            if len(sols) != 1:
                raise RopException("This gadget pivots more than once, which is currently not handled")
            gadget.stack_change_after_pivot = sols[0]
            gadget.sp_reg_controllers = set(self._get_reg_controllers(init_state, final_state, 'sp', dependencies))
            gadget.sp_stack_controllers = {x for x in final_state.regs.sp.variables if x.startswith("symbolic_stack_")}
            if gadget.stack_change_before_pivot % self.project.arch.bytes != 0 or abs(gadget.stack_change_before_pivot) > 0x1000:
                raise RopException("bad SP")
            if gadget.stack_change_after_pivot % self.project.arch.bytes != 0 or abs(gadget.stack_change_after_pivot) > 0x1000:
                raise RopException("bad SP")
        else:
            raise NotImplementedError(f"Unknown gadget type {type(gadget)}")

    def _build_mem_access(self, a, gadget, init_state, final_state):
        """
        translate an angr symbolic action to angrop MemAccess
        """
        mem_access = RopMemAccess()

        # handle the memory access address
        # case 1: the address is not symbolic
        if not a.addr.ast.symbolic or all(x.startswith('sym_addr_') for x in a.addr.ast.variables):
            if not a.addr.ast.symbolic:
                addr_constant = a.addr.ast.concrete_value
            else:
                addr_constant = final_state.solver.eval(a.addr.ast)
            mem_access.addr_constant = addr_constant
            mem_access.stack_offset = addr_constant - init_state.regs.sp.concrete_value
            if not final_state.regs.sp.symbolic:
                # check whether this is a pointer to a known mapping, these are not considered out-of-patch
                if self.project.loader.find_object_containing(addr_constant):
                    pass
                elif not (init_state.regs.sp.concrete_value <= addr_constant < final_state.regs.sp.concrete_value):
                    mem_access.out_of_patch = True
        # case 2: the symbolic address comes from registers
        elif all(x.startswith("sreg_") for x in a.addr.ast.variables):
            mem_access.addr_dependencies = rop_utils.get_ast_dependency(a.addr.ast)
            mem_access.addr_controllers = rop_utils.get_ast_controllers(init_state, a.addr.ast,
                                                                        mem_access.addr_dependencies)
            mem_access.addr_offset = rop_utils.get_ast_const_offset(init_state, a.addr.ast,
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

        data_ast = a.data.ast
        while data_ast.op in ('ZeroExt', 'SignExt'):
            data_ast = data_ast.args[1]
        mem_access.data_size = data_ast.size()
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
        data_controllers = set()
        data_stack_controllers = set()
        if len(data_dependencies):
            data_controllers = rop_utils.get_ast_controllers(init_state, sym_data, data_dependencies)
            if len(data_controllers) != 1:
                return None
        data_stack_controllers = {x for x in sym_data.variables if x.startswith('symbolic_stack')}


        mem_change = self._build_mem_access(read_action, gadget, init_state, final_state)
        mem_change.op = write_action.data.ast.op
        mem_change.data_dependencies = data_dependencies
        mem_change.data_stack_controllers = data_stack_controllers
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

            # ignore read/write within the stack patch
            if not a.addr.ast.symbolic:
                addr_constant = a.addr.ast.concrete_value

                # check whether the access is within the stack patch
                # we ignore pushes, which will lead to under patch write then load
                upper_bound = (1<<final_state.project.arch.bits)-1
                if not final_state.regs.sp.symbolic:
                    upper_bound = final_state.regs.sp.concrete_value
                if init_state.regs.sp.concrete_value-0x20 <= addr_constant < upper_bound:
                    continue
                if a.action == 'read' and any(x.startswith('uninitialized') for x in a.data.variables):
                    return False

            # ignore read/write in known segments
            if not a.addr.ast.symbolic:
                addr_constant = a.addr.ast.concrete_value
                found = False
                for seg in self.project.loader.main_object.segments:
                    min_addr = seg.min_addr
                    max_addr = math.ceil(seg.max_addr / 0x1000)*0x1000
                    if min_addr <= addr_constant < max_addr:
                        found = True
                        break
                if found is True:
                    continue

            # error out on invalid memory accesses
            if not a.addr.ast.symbolic:
                if abs(init_state.regs.sp.concrete_value - a.addr.ast.concrete_value) > 0x400:
                    return False

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

        sym_accesses = [ m for m in all_mem_actions if m.addr.ast.symbolic ]
        sym_accesses += [m for m in gadget.mem_changes if m.is_symbolic_access()]
        if len(sym_accesses) > self.arch.max_sym_mem_access:
            return False

        # step 3: add all left memory actions to either read/write memory accesses stashes
        for a in all_mem_actions:
            mem_access = self._build_mem_access(a, gadget, init_state, final_state)
            if a.action == "read":
                gadget.mem_reads.append(mem_access)
            if a.action == "write":
                gadget.mem_writes.append(mem_access)
        return True

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
                    if reg_name in self.arch.reg_list:
                        all_reg_writes.add(reg_name)
                    elif reg_name != self.arch.stack_pointer:
                        l.info("reg write from register not in reg_set: %s", reg_name)
                except RegNotFoundException as e:
                    l.debug(e)
        return all_reg_writes

    def _block_has_ip_relative(self, addr, bl):
        """
        Checks if a block has any ip relative instructions
        """
        # if thumb mode, the block needs to parsed very carefully
        if addr & 1 == 1 and self.project.arch.bits == 32 and self.project.arch.name.startswith('ARM'):
            # thumb mode has this conditional instruction thingy, which is terrible for vex statement
            # comparison. We inject a ton of fake statements into the program to ensure vex that this gadget
            # is not a conditional instruction
            MMAP_ADDR = 0x1000
            test_addr = MMAP_ADDR + 0x200+1
            if self.project.loader.memory.min_addr > MMAP_ADDR:
                # a ton of `pop {pc}`
                self.project.loader.memory.add_backer(MMAP_ADDR, b'\x00\xbd'*0x100+b'\x00'*0x200)

            # create the block without using the cache
            engine = self.project.factory.default_engine
            bk = engine._use_cache
            engine._use_cache = False
            self.project.loader.memory.store(test_addr-1, bl.bytes + b'\x00'*(0x200-len(bl.bytes)))
            bl2 = self.project.factory.block(test_addr)
            engine._use_cache = bk
        else:
            test_addr = 0x41414140 + addr % 0x10
            bl2 = self.project.factory.block(test_addr, insn_bytes=bl.bytes)

        # now diff the blocks to see whether anything constants changes
        try:
            diff_constants = differing_constants(bl, bl2)
        except UnmatchedStatementsException:
            return True
        # check if it changes if we move it
        bl_end = addr + bl.size
        bl2_end = test_addr + bl2.size
        filtered_diffs = []
        for d in diff_constants:
            if d.value_a < addr or d.value_a >= bl_end or \
                    d.value_b < test_addr or d.value_b >= bl2_end:
                filtered_diffs.append(d)
        return len(filtered_diffs) > 0

    def _is_simple_gadget(self, addr, block):
        """
        is the gadget a simple gadget like
        pop rax; ret
        """
        if block.vex.jumpkind not in {'Ijk_Boring', 'Ijk_Call', 'Ijk_Ret'}:
            return False
        if block.vex.jumpkind.startswith('Ijk_Sys_'):
            return False
        if block.vex.constant_jump_targets:
            return False
        if self._block_has_ip_relative(addr, block):
            return False
        return True

    def block_hash(self, block):
        """
        a hash to uniquely identify a simple block
        """
        if block.vex_nostmt.jumpkind.startswith('Ijk_Sys_'):
            next_addr = block.addr + block.size
            obj = self.project.loader.find_object_containing(next_addr)
            if not obj:
                return block.bytes
            next_block = self.project.factory.block(next_addr, skip_stmts=True)
            return block.bytes + next_block.bytes
        return block.bytes

    def _static_analyze_first_block(self, addr):
        try:
            bl = self.project.factory.block(addr, skip_stmts=True)
            if bl.size > self.arch.max_block_size:
                return None, None
            jumpkind = bl._vex_nostmt.jumpkind
            if jumpkind in ('Ijk_SigTRAP', 'Ijk_NoDecode', 'Ijk_Privileged', 'Ijk_Yield'):
                return None, None
            if not self._allow_conditional_branches and len(bl._vex_nostmt.constant_jump_targets) > 1:
                return None, None
            if self._fast_mode and jumpkind not in ("Ijk_Ret", "Ijk_Boring") and not jumpkind.startswith('Ijk_Sys_'):
                return None, None
            if bl._vex_nostmt.instructions == 1 and jumpkind in ('Ijk_Boring', 'Ijk_Call'):
                return None, None
            if not self._block_make_sense(addr):
                return None, None
        except (SimEngineError, SimMemoryError):
            return None, None
        if self._is_simple_gadget(addr, bl):
            h = self.block_hash(bl)
            return h, addr
        return None, addr