import angr
import pyvex
import claripy
import simuvex

import logging

from . import rop_utils
from .rop_gadget import RopGadget, RopMemAccess, RopRegMove, StackPivot
from .errors import RopException, RegNotFoundException

l = logging.getLogger("angrop.gadget_analyzer")


class GadgetAnalyzer(object):
    def __init__(self, project, reg_list, max_block_size, fast_mode, max_sym_mem_accesses):
        # params
        self.project = project
        self._reg_list = reg_list
        self._max_block_size = max_block_size
        self._fast_mode = fast_mode
        self._max_sym_mem_accesses = max_sym_mem_accesses

        # initial state that others are based off
        self._stack_length = 80
        self._stack_length_bytes = self._stack_length * self.project.arch.bits / 8
        self._test_symbolic_state = rop_utils.make_symbolic_state(self.project, reg_list)
        self._stack_pointer_value = self._test_symbolic_state.se.any_int(self._test_symbolic_state.regs.sp)

        # architecture stuff
        self._base_pointer = self.project.arch.register_names[self.project.arch.bp_offset]
        self._sp_reg = self.project.arch.register_names[self.project.arch.sp_offset]

        # solve cache
        self._solve_cache = dict()

    def analyze_gadget(self, addr):
        """
        :param addr: address to analyze for a gadget
        :return: a RopGadget instance
        """
        l.info("Analyzing 0x%x", addr)

        # first check if the block makes sense
        if not self._block_makes_sense(addr):
            return None

        try:
            # unconstrained check prefilter
            if self._does_not_get_to_unconstrained(addr):
                l.debug("... does not get to unconstrained successor")
                return None

            # create the symbolic state at the address
            symbolic_state = self._test_symbolic_state.copy()
            symbolic_state.ip = addr
            symbolic_p = rop_utils.step_to_unconstrained_successor(self.project, state=symbolic_state)

            l.debug("... analyzing rop potential of block")

            # filter out those that dont get to a controlled successor
            l.info("... check for controlled successor")
            if not self._check_for_controlled_successor(symbolic_p, symbolic_state):
                pivot = self._check_pivot(symbolic_p, symbolic_state, addr)
                return pivot

            # filter out if too many mem accesses
            if not self._satisfies_mem_access_limits(symbolic_p):
                l.debug("... too many symbolic memory accesses")
                return None

            # create the gadget
            this_gadget = RopGadget(addr=addr)
            # FIXME this doesnt handle multiple steps
            this_gadget.block_length = self.project.factory.block(addr).size

            # compute sp change
            l.debug("... computing sp change")
            self._compute_sp_change(symbolic_state, this_gadget)

            if this_gadget.stack_change % (self.project.arch.bits / 8) != 0:
                l.debug("... uneven sp change")
                return None

            if this_gadget.stack_change <= 0:
                l.debug("stack change isn't positive")
                return None

            # if the sp moves to the bp we have to handle it differently
            if not this_gadget.bp_moves_to_sp and self._base_pointer != self._sp_reg:
                rop_utils.make_reg_symbolic(symbolic_state, self._base_pointer)
                symbolic_p = rop_utils.step_to_unconstrained_successor(self.project, symbolic_state)

                if not self._satisfies_mem_access_limits(symbolic_p):
                    l.debug("... too many symbolic memory accesses")
                    return None

            l.info("... checking for syscall availability")
            this_gadget.makes_syscall = self._does_syscall(symbolic_p)
            this_gadget.starts_with_syscall = self._starts_with_syscall(addr)

            l.info("... checking for controlled regs")
            self._check_reg_changes(symbolic_p, symbolic_state, this_gadget)

            # check for reg moves
            # get reg reads
            reg_reads = self._get_reg_reads(symbolic_p)
            l.debug("... checking for reg moves")
            self._check_reg_change_dependencies(symbolic_state, symbolic_p, this_gadget)
            self._check_reg_movers(symbolic_state, symbolic_p, reg_reads, this_gadget)

            # check mem accesses
            l.debug("... analyzing mem accesses")
            self._analyze_mem_accesses(symbolic_p, symbolic_state, this_gadget)
            for m_access in this_gadget.mem_writes + this_gadget.mem_reads + this_gadget.mem_changes:
                if len(m_access.addr_dependencies) == 0 and m_access.addr_constant is None:
                    l.debug("... mem access with no addr dependencies")
                    return None

        except RopException as e:
            l.debug("... %s", e.message)
            return None
        except claripy.ClaripyFrontendError as e:
            l.warning("... claripy error: %s", e.message)
            return None

        l.debug("... Appending gadget!")
        return this_gadget

    def _block_makes_sense(self, addr):
        """
        Checks if a block at addr makes sense to analyze for rop gadgets
        :param addr: the address to check
        :return: True or False
        """
        try:
            l.debug("... checking if block makes sense")
            block = self.project.factory.block(addr)

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

            if block.size > self._max_block_size:
                l.debug("... too long")
                return False

            # we don't like floating point stuff
            if "Ity_F16" in block.vex.tyenv.types or "Ity_F32" in block.vex.tyenv.types \
                    or "Ity_F64" in block.vex.tyenv.types or "Ity_F128" in block.vex.tyenv.types:
                return False

        except pyvex.PyVEXError:
            l.debug("... some pyvex")
            return False
        except (angr.AngrError, pyvex.PyVEXError, simuvex.SimCCallError):
            l.debug("... some other angr error")
            return False
        except simuvex.SimMemoryLimitError:
            l.debug("... simuvex memory limit error")
            return False
        except simuvex.UnsupportedIROpError:
            l.debug("... simuvex unsupported op error")
            return False
        except simuvex.UnsupportedSyscallError:
            return False
        except AttributeError:
            return False

        return True

    # todo this one skips syscalls so it doesnt need to step as far?
    def _does_not_get_to_unconstrained(self, addr, max_steps=2):
        try:
            # might miss jumps where one side is never satisfiable
            bl = self.project.factory.block(addr)
            constant_jump_targets = list(bl.vex.constant_jump_targets)
            if len(constant_jump_targets) == 1 and max_steps == 0:
                return True
            elif len(constant_jump_targets) == 1:
                if not self._block_makes_sense(constant_jump_targets[0]):
                    return True
                return self._does_not_get_to_unconstrained(constant_jump_targets[0], max_steps-1)
            elif len(constant_jump_targets) > 1:
                return True
            # 0 constant jump targets is what we want to find
            return False
        except angr.AngrMemoryError:
            return True
        except angr.AngrTranslationError:
            return True

    def _satisfies_mem_access_limits(self, symbolic_path):
        """
        :param symbolic_path: the successor symbolic path
        :return: True/False indicating whether or not to keep the gadget
        """
        # get all the memory accesses
        symbolic_mem_accesses = []
        for a in reversed(symbolic_path.actions):
            if a.type == 'mem' and a.addr.ast.symbolic:
                symbolic_mem_accesses.append(a)
        if len(symbolic_mem_accesses) <= self._max_sym_mem_accesses:
            return True

        # allow mem changes (only add/subtract) to count as a single access
        if len(symbolic_mem_accesses) == 2 and self._max_sym_mem_accesses == 1:
            if symbolic_mem_accesses[0].action == "read" and symbolic_mem_accesses[1].action == "write" and \
                    (symbolic_mem_accesses[1].data.ast.op == "__sub__" or
                        symbolic_mem_accesses[1].data.ast.op == "__add__") and \
                    symbolic_mem_accesses[1].data.ast.size() == self.project.arch.bits and \
                    symbolic_mem_accesses[0].addr.ast is symbolic_mem_accesses[1].addr.ast:
                return True
        return False

    def _check_reg_changes(self, symbolic_p, symbolic_state, gadget):
        """
        Checks which registers were changed and which ones were popped
        :param symbolic_p: the stepped path, symbolic_state is an ancestor of it.
        :param symbolic_state: the input state for testing
        :param gadget: the gadget to store register change information
        """
        exit_target = symbolic_p.actions[-1].target.ast

        succ_state = symbolic_p.state
        stack_change = gadget.stack_change if not gadget.bp_moves_to_sp else None

        for reg in self._get_reg_writes(symbolic_p):
            # we assume any register in reg_writes changed
            # verify the stack controls it
            # we need to make sure they arent equal to the exit target otherwise they arent controlled
            # TODO what to do about moves to bp
            if symbolic_p.state.registers.load(reg) is exit_target:
                gadget.changed_regs.add(reg)
            elif self._check_if_stack_controls_ast(succ_state.registers.load(reg), symbolic_state, stack_change):
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
                ast_2 = symbolic_p.state.registers.load(reg)
                if ast_1 is ast_2:
                    gadget.reg_moves.append(RopRegMove(from_reg, reg, self.project.arch.bits))
                # try lower 32 bits (this is intended for amd64)
                # todo do this for less bits too?
                else:
                    half_bits = self.project.arch.bits / 2
                    ast_1 = claripy.Extract(half_bits-1, 0, ast_1)
                    ast_2 = claripy.Extract(half_bits-1, 0, ast_2)
                    if ast_1 is ast_2:
                        gadget.reg_moves.append(RopRegMove(from_reg, reg, half_bits))

    # todo need to handle reg calls/jumps
    def _check_for_controlled_successor(self, symbolic_p, symbolic_s):
        """
        :param symbolic_p: the symbolic successor path of symbolic_s
        :param symbolic_s: the symbolic state
        :return: True if the address of symbolic_p is controlled by the stack
        """
        return self._check_if_stack_controls_ast(symbolic_p.state.ip, symbolic_s)

    def _check_if_stack_controls_ast(self, ast, initial_state, gadget_stack_change=None):
        if gadget_stack_change is not None and gadget_stack_change <= 0:
            return False

        # if we had the lemma cache this might be already there!
        test_val = 0x4242424242424242 % (1 << self.project.arch.bits)

        # TODO add test where we recognize a value past the end of the stack frame isn't controlled
        # this is an annoying problem but this code should handle it

        # solve cache is used if it's already known to not work or
        # if we are using the whole stack (gadget_stack_change is None)
        if hash(ast) in self._solve_cache and \
                (gadget_stack_change is None or not self._solve_cache[hash(ast)]):
            return self._solve_cache[hash(ast)]

        # prefilter
        if len(ast.variables) != 1 or not list(ast.variables)[0].startswith("symbolic_stack"):
            self._solve_cache[hash(ast)] = False
            return False

        stack_bytes_length = self._stack_length * (self.project.arch.bits / 8)
        if gadget_stack_change is not None:
            stack_bytes_length = min(max(gadget_stack_change, 0), stack_bytes_length)
        concrete_stack = initial_state.se.BVV("B" * stack_bytes_length)
        concrete_stack_s = initial_state.copy()
        concrete_stack_s.add_constraints(
            initial_state.memory.load(initial_state.regs.sp, stack_bytes_length) == concrete_stack)
        test_constraint = (ast != test_val)
        # stack must have set the register and it must be able to set the register to all 1's or all 0's
        if not concrete_stack_s.se.satisfiable(extra_constraints=(test_constraint,)) and \
                rop_utils.fast_unconstrained_check(initial_state, ast):
            ans = True
        else:
            ans = False

        # only store the result if we were using the whole stack
        if gadget_stack_change is not None:
            self._solve_cache[hash(ast)] = ans
        return ans

    def _compute_sp_change(self, symbolic_state, gadget):
        """
        Computes the change in the stack pointer for a gadget, including whether or not it moves to the base pointer
        :param symbolic_state: the input symbolic state
        :param gadget: the gadget in which to store the sp change
        """
        # store symbolic sp and bp and check for dependencies
        ss_copy = symbolic_state.copy()
        ss_copy.regs.bp = ss_copy.se.BVS("sreg_" + self._base_pointer + "-", self.project.arch.bits)
        ss_copy.regs.sp = ss_copy.se.BVS("sreg_" + self._sp_reg + "-", self.project.arch.bits)
        symbolic_p = rop_utils.step_to_unconstrained_successor(self.project, ss_copy)
        dependencies = self._get_reg_dependencies(symbolic_p, "sp")
        sp_change = symbolic_p.state.regs.sp - ss_copy.regs.sp

        # analyze the results
        gadget.bp_moves_to_sp = False
        if len(dependencies) > 1:
            raise RopException("SP has multiple dependencies")
        elif len(dependencies) == 0 and sp_change.symbolic:
            raise RopException("SP change is uncontrolled")
        elif len(dependencies) == 0 and not sp_change.symbolic:
            stack_changes = [ss_copy.se.any_int(sp_change)]
        elif list(dependencies)[0] == self._sp_reg:
            stack_changes = ss_copy.se.any_n_int(sp_change, 2)
            gadget.stack_change = stack_changes[0]
        elif list(dependencies)[0] == self._base_pointer:
            sp_change = symbolic_p.state.regs.sp - ss_copy.regs.bp
            stack_changes = ss_copy.se.any_n_int(sp_change, 2)
            gadget.bp_moves_to_sp = True
        else:
            raise RopException("SP does not depend on SP or BP")

        if len(stack_changes) != 1:
            raise RopException("SP change is symbolic")

        gadget.stack_change = stack_changes[0]

    def _analyze_mem_accesses(self, symbolic_p, symbolic_state, gadget):
        """
        analyzes memory accesses and stores their info in the gadget
        :param symbolic_p: the stepped path, symbolic_state is an ancestor of it.
        :param symbolic_state: the input state for testing
        :param gadget: the gadget to store mem acccess in
        """
        last_action = None
        for a in symbolic_p.actions.hardcopy:
            if a.type == 'mem':
                mem_access = RopMemAccess()
                if a.addr.ast.symbolic:
                    mem_access.addr_dependencies = rop_utils.get_ast_dependency(a.addr.ast)
                    mem_access.addr_controllers = rop_utils.get_ast_controllers(symbolic_state, a.addr.ast,
                                                                                mem_access.addr_dependencies)
                else:
                    mem_access.addr_constant = symbolic_state.se.any_int(a.addr.ast)

                # don't need to inform user of stack reads/writes
                stack_min_addr = self._stack_pointer_value - 0x20
                # TODO should this be changed, so that we can more easily understand writes outside the frame
                stack_max_addr = max(stack_min_addr + self._stack_length_bytes, stack_min_addr + gadget.stack_change)
                if mem_access.addr_constant is not None and \
                        stack_min_addr <= mem_access.addr_constant < stack_max_addr:
                    continue

                if a.action == "write":
                    # special case for read than write form the same addr
                    if last_action is not None and last_action.action == "read" and \
                            last_action.addr.ast is a.addr.ast and \
                            last_action.ins_addr == a.ins_addr:
                        mem_change = gadget.mem_reads[-1]
                        gadget.mem_reads = gadget.mem_reads[:-1]
                        # get the actual change in certain cases
                        self._get_mem_change_op_and_data(mem_change, a, symbolic_state)
                        gadget.mem_changes.append(mem_change)
                        last_action = None
                        continue

                    # for writes we want what the data depends on
                    test_data = symbolic_state.se.any_n_int(a.data.ast, 2)
                    if len(test_data) > 1:
                        mem_access.data_dependencies = rop_utils.get_ast_dependency(a.data.ast)
                        mem_access.data_controllers = rop_utils.get_ast_controllers(symbolic_state, a.data.ast,
                                                                                    mem_access.data_dependencies)
                    elif len(test_data) == 1:
                        mem_access.data_constant = test_data[0]
                    else:
                        raise Exception("No data values, something went wrong")
                elif a.action == "read" and not isinstance(a.data.ast, claripy.fp.FPV) and \
                        not isinstance(a.data.ast, claripy.ast.FP):
                    # for reads we want to know if any register will have the data after
                    succ_state = symbolic_p.state
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

                            if not succ_state.se.satisfiable(extra_constraints=(test_constraint,)):
                                mem_access.data_dependencies.add(reg)

                mem_access.data_size = a.data.ast.size()
                mem_access.addr_size = a.addr.ast.size()

                last_action = a
                if a.action == "read":
                    gadget.mem_reads.append(mem_access)
                if a.action == "write":
                    gadget.mem_writes.append(mem_access)

    @staticmethod
    def _get_mem_change_op_and_data(mem_change, write_action, symbolic_state):
            if not write_action.data.ast.symbolic:
                return
            if len(write_action.data.ast.args) != 2:
                return
            if not write_action.data.ast.args[0].symbolic:
                return

            vars0 = list(write_action.data.ast.args[0].variables)
            if not len(vars0) == 1 and vars0[0].startswith("symbolic_read_sreg_"):
                return

            data_dependencies = rop_utils.get_ast_dependency(write_action.data.ast.args[1])
            if len(data_dependencies) != 1:
                return
            data_controllers = rop_utils.get_ast_controllers(symbolic_state, write_action.data.ast.args[1], data_dependencies)
            if len(data_controllers) != 1:
                return

            mem_change.op = write_action.data.ast.op
            mem_change.data_dependencies = data_dependencies
            mem_change.data_controllers = data_controllers

    @staticmethod
    def _does_syscall(symbolic_p):
        """
        checks if the path does a system call at some point
        :param symbolic_p: input path to check history of
        """

        for addr in symbolic_p.addr_trace:
            if not symbolic_p._project.is_hooked(addr):
                continue
            hooker = symbolic_p._project.hooked_by(addr)
            if hooker is not None and hooker.IS_SYSCALL:
                return True

        return False

    def _check_pivot(self, symbolic_p, symbolic_state, addr):
        """
        Super basic pivot analysis. Pivots are not really used by angrop right now
        :param symbolic_p: the stepped path, symbolic_state is an ancestor of it.
        :param symbolic_state: input state for testing
        :return: the pivot object
        """
        if len(symbolic_p.trace) > 1:
            return None
        pivot = None
        reg_deps = rop_utils.get_ast_dependency(symbolic_p.state.regs.sp)
        if len(reg_deps) == 1:
            pivot = StackPivot(addr)
            pivot.sp_from_reg = list(reg_deps)[0]
        elif len(symbolic_p.state.regs.sp.variables) == 1 and \
                list(symbolic_p.state.regs.sp.variables)[0].startswith("symbolic_stack"):
            offset = None
            for a in symbolic_p.state.regs.sp.recursive_children_asts:
                if a.op == "Extract" and a.depth == 2:
                    offset = a.args[2].size() - 1 - a.args[0]
            if offset is None or offset % 8 != 0:
                return None
            offset_bytes = offset/8
            pivot = StackPivot(addr)
            pivot.sp_popped_offset = offset_bytes

        if pivot is not None:
            # verify no weird mem accesses
            test_p = self.project.factory.path(symbolic_state.copy())
            # step until we find the pivot action
            for i in range(symbolic_p.previous_run.irsb.instructions):
                test_p.step(num_inst=1)
                if len(test_p.successors) != 1:
                    return None
                test_p = test_p.successors[0]
                if test_p.state.regs.sp.symbolic:
                    # found the pivot action
                    break
            # now iterate through the remaining instructions with a clean state
            test_p.step(num_inst=1)
            if len(test_p.successors) != 1:
                return None
            succ1 = test_p.successors[0]
            ss = symbolic_state.copy()
            ss.regs.ip = succ1.addr
            test_p = self.project.factory.path(ss)
            test_p.step()
            if len(test_p.successors + test_p.unconstrained_successors) == 0:
                return None
            succ2 = (test_p.successors + test_p.unconstrained_successors)[0]

            all_actions = [a for a in succ1.actions] + [a for a in succ2.actions]
            for a in all_actions:
                if a.type == "mem" and a.addr.ast.symbolic:
                    return None
            return pivot

        return None

    def _starts_with_syscall(self, addr):
        """
        checks if the path starts with a system call
        :param addr: input path to check history of
        """

        return self.project.factory.block(addr, num_inst=1).vex.jumpkind.startswith("Ijk_Sys")

    def _windup_to_presyscall_state(self, symbolic_p, symbolic_state):
        """
        Retrieve the state of a gadget just before the syscall is made
        :param symbolic_p: the stepped path, symbolic_state is an ancestor of it.
        :param symbolic_state: input state for testing
        """

        if self._does_syscall(symbolic_p):
            # step up until the syscall and save the possible syscall numbers into the gadget
            prev = cur = self.project.factory.path(state=symbolic_state)
            while not self._does_syscall(cur):
                cur.step()
                prev = cur
                cur = cur.successors[0]
            return prev.state.copy()

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
        dependencies = rop_utils.get_ast_dependency(symbolic_p.state.registers.load(test_reg))
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
        controllers = rop_utils.get_ast_controllers(symbolic_state, symbolic_p.state.registers.load(test_reg), reg_deps)
        return controllers

    def _get_reg_reads(self, path):
        """
        Finds all the registers read in a path
        :param path: The path to check
        :return: A set of register names which are read
        """
        all_reg_reads = set()
        for a in reversed(path.actions):
            if a.type == "reg" and a.action == "read":
                try:
                    reg_name = rop_utils.get_reg_name(self.project.arch, a.offset)
                    if reg_name in self._reg_list:
                        all_reg_reads.add(reg_name)
                    elif reg_name != self._sp_reg:
                        l.info("reg read from register not in reg_list: %s", reg_name)
                except RegNotFoundException as e:
                    l.debug(e.message)
        return all_reg_reads

    def _get_reg_writes(self, path):
        """
        Finds all the registers written in a path
        :param path: The path to check
        :return: A set of register names which are read
        """
        all_reg_writes = set()
        for a in reversed(path.actions):
            if a.type == "reg" and a.action == "write":
                try:
                    reg_name = rop_utils.get_reg_name(self.project.arch, a.offset)
                    if reg_name in self._reg_list:
                        all_reg_writes.add(reg_name)
                    elif reg_name != self._sp_reg:
                        l.info("reg read from register not in reg_list: %s", reg_name)
                except RegNotFoundException as e:
                    l.debug(e.message)
        return all_reg_writes

# TODO ip setters, ie call rax
