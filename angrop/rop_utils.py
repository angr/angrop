import angr

from .errors import RegNotFoundException, RopException


def gadget_to_asmstring(project, gadget):
    code = project.loader.memory.load(gadget.addr,gadget.block_length)
    md = project.arch.capstone
    return "; ".join(["%s %s" %(i.mnemonic, i.op_str) for i in md.disasm(code,gadget.addr)])


def get_ast_dependency(ast):
    """
    ast must be created from a symbolic state where registers values are named "sreg_REG-"
    looks for registers that if we make the register symbolic then the ast becomes symbolic
    :param ast: the ast of which we are trying to analyze dependencies
    :return: A set of register names which affect the ast
    """
    dependencies = set()

    for var in ast.variables:
        if var.startswith("sreg_"):
            dependencies.add(var[5:].split("-")[0])
        else:
            return set()
    return dependencies


def get_ast_controllers(test_state, ast, reg_deps):
    """
    looks for registers that we can make symbolic then the ast can be "anything"
    :param test_state: the input state
    :param ast: the ast of which we are trying to analyze controllers
    :param reg_deps: All registers which it depends on
    :return: A set of register names which can control the ast
    """

    test_val = 0x4141414141414141 % (2 << test_state.arch.bits)

    controllers = []
    if not ast.symbolic:
        return controllers

    # make sure it can't be symbolic if all the registers are constrained
    constrained_copy = test_state.copy()
    for reg in reg_deps:
        if not constrained_copy.registers.load(reg).symbolic:
            continue
        constrained_copy.add_constraints(constrained_copy.registers.load(reg) == test_val)
    if len(constrained_copy.solver.eval_upto(ast, 2)) > 1:
        return controllers

    for reg in reg_deps:
        constrained_copy = test_state.copy()
        for r in [a for a in reg_deps if a != reg]:
            # for bp and registers that might be set
            if not constrained_copy.registers.load(r).symbolic:
                continue
            constrained_copy.add_constraints(constrained_copy.registers.load(r) == test_val)

        if unconstrained_check(constrained_copy, ast):
            controllers.append(reg)

    return controllers


def unconstrained_check(state, ast):
    """
    Attempts to check if an ast is completely unconstrained
    :param state: the state to use
    :param ast: the ast to check
    :return: True if the ast is probably completely unconstrained
    """
    size = ast.size()
    test_val_0 = 0x0
    test_val_1 = (1 << size) - 1
    test_val_2 = int("1010"*16, 2) % (1 << size)
    test_val_3 = int("0101"*16, 2) % (1 << size)
    # chars need to be able to be different
    test_val_4 = int(("1001"*2 + "1010"*2 + "1011"*2 + "1100"*2 + "1101"*2 + "1110"*2 + "1110"*2 + "0001"*2), 2) \
        % (1 << size)
    if not state.solver.satisfiable(extra_constraints=(ast == test_val_0,)):
        return False
    if not state.solver.satisfiable(extra_constraints=(ast == test_val_1,)):
        return False
    if not state.solver.satisfiable(extra_constraints=(ast == test_val_2,)):
        return False
    if not state.solver.satisfiable(extra_constraints=(ast == test_val_3,)):
        return False
    if not state.solver.satisfiable(extra_constraints=(ast == test_val_4,)):
        return False
    return True


def fast_unconstrained_check(state, ast):
    """
    Attempts to check if an ast has any common unreversable operations mul, div
    :param state: the state to use
    :param ast: the ast to check
    :return: True if the ast is probably unconstrained
    """
    good_ops = {"Extract", "BVS", "__add__", "__sub__", "Reverse"}
    if len(ast.variables) != 1:
        return unconstrained_check(state, ast)

    passes_prefilter = True
    for a in ast.recursive_children_asts:
        if a.op not in good_ops:
            passes_prefilter = False
    if ast.op not in good_ops:
        passes_prefilter = False

    if passes_prefilter:
        return True

    return unconstrained_check(state, ast)


def get_reg_name(arch, reg_offset):
    """
    :param reg_offset: Tries to find the name of a register given the offset in the registers.
    :return: The register name
    """
    # todo does this make sense
    if reg_offset is None:
        raise RegNotFoundException("register offset is None")

    original_offset = reg_offset
    while reg_offset >= 0 and reg_offset >= original_offset - arch.bytes:
        if reg_offset in arch.register_names:
            return arch.register_names[reg_offset]
        else:
            reg_offset -= 1
    raise RegNotFoundException("register %s not found" % str(original_offset))


# todo this doesn't work if there is a timeout
def _asts_must_be_equal(state, ast1, ast2):
    """
    :param state: the state to use for solving
    :param ast1: first ast
    :param ast2: second ast
    :return: True if the ast's must be equal
    """
    if state.solver.satisfiable(extra_constraints=(ast1 != ast2,)):
        return False
    return True


def make_initial_state(project, stack_length):
    """
    :return: an initial state with a symbolic stack and good options for rop
    """
    initial_state = project.factory.blank_state(
        add_options={angr.options.AVOID_MULTIVALUED_READS, angr.options.AVOID_MULTIVALUED_WRITES,
                     angr.options.NO_SYMBOLIC_JUMP_RESOLUTION, angr.options.CGC_NO_SYMBOLIC_RECEIVE_LENGTH,
                     angr.options.NO_SYMBOLIC_SYSCALL_RESOLUTION, angr.options.TRACK_ACTION_HISTORY},
        remove_options=angr.options.resilience | angr.options.simplification)
    initial_state.options.discard(angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)
    initial_state.options.update({angr.options.TRACK_REGISTER_ACTIONS, angr.options.TRACK_MEMORY_ACTIONS,
                                  angr.options.TRACK_JMP_ACTIONS, angr.options.TRACK_CONSTRAINT_ACTIONS})
    symbolic_stack = initial_state.solver.BVS("symbolic_stack", project.arch.bits*stack_length)
    initial_state.memory.store(initial_state.regs.sp, symbolic_stack)
    if initial_state.arch.bp_offset != initial_state.arch.sp_offset:
        initial_state.regs.bp = initial_state.regs.sp + 20*initial_state.arch.bytes
    initial_state.solver._solver.timeout = 500  # only solve for half a second at most
    return initial_state


def make_symbolic_state(project, reg_list, stack_length=80):
    """
    converts an input state into a state with symbolic registers
    :return: the symbolic state
    """
    input_state = make_initial_state(project, stack_length)
    symbolic_state = input_state.copy()
    # overwrite all registers
    for reg in reg_list:
        symbolic_state.registers.store(reg, symbolic_state.solver.BVS("sreg_" + reg + "-", project.arch.bits))
    # restore sp
    symbolic_state.regs.sp = input_state.regs.sp
    # restore bp
    symbolic_state.regs.bp = input_state.regs.bp
    return symbolic_state


def make_reg_symbolic(state, reg):
    state.registers.store(reg,
    state.solver.BVS("sreg_" + reg + "-", state.arch.bits))


def step_to_unconstrained_successor(project, state, max_steps=2, allow_simprocedures=False):
    """
    steps up to two times to try to find an unconstrained successor
    :param state: the input state
    :param max_steps: maximum number of additional steps to try to get to an unconstrained state
    :return: a path at the unconstrained successor
    """
    try:
        # might only want to enable this option for arches / oses which don't care about bad syscall
        # nums
        state.options.add(angr.options.BYPASS_UNSUPPORTED_SYSCALL)

        succ = project.factory.successors(state)
        if len(succ.flat_successors) + len(succ.unconstrained_successors) != 1:
            raise RopException("Does not get to a single successor")
        if len(succ.flat_successors) == 1 and max_steps > 0:
            if not allow_simprocedures and project.is_hooked(succ.flat_successors[0].addr):
                # it cannot be a syscall as now syscalls are not explicitly hooked
                raise RopException("Skipping simprocedure")
            return step_to_unconstrained_successor(project, succ.flat_successors[0],
                                                   max_steps-1, allow_simprocedures)
        if len(succ.flat_successors) == 1 and max_steps == 0:
            raise RopException("Does not get to an unconstrained successor")
        return succ.unconstrained_successors[0]

    except (angr.errors.AngrError, angr.errors.SimError):
        raise RopException("Does not get to a single unconstrained successor")
