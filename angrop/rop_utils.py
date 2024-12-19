import time
import signal
import threading
import functools
import angr
import claripy
import angr

from .errors import RegNotFoundException, RopException
from .rop_value import RopValue

def addr_to_asmstring(project, addr):
    block = project.factory.block(addr)
    return "; ".join(["%s %s" %(i.mnemonic, i.op_str) for i in block.capstone.insns])

def gadget_to_asmstring(project, gadget):
    if not gadget.block_length:
        return ""
    return addr_to_asmstring(project, gadget.addr)


def print_gadget(gadget):
    """
    Print all available information about a ROP gadget
    """
    print(f"Gadget at {gadget.addr:#x}")
    print(f"Block length: {gadget.block_length}")
    print(f"Stack change: {gadget.stack_change:#x}")

    # Transit info
    print(f"\nTransit type: {gadget.transit_type}")
    if gadget.jump_reg:
        print(f"Jump register: {gadget.jump_reg}")
    if gadget.pc_reg:
        print(f"PC register: {gadget.pc_reg}")
    if gadget.pc_offset is not None:
        print(f"PC offset: {gadget.pc_offset:#x}")

    # Register effects
    print("\nRegister effects:")
    print(f"Changed registers: {gadget.changed_regs}")
    print(f"Popped registers: {gadget.popped_regs}")

    # Register concrete values
    if gadget.concrete_regs:
        print("\nConcrete register values:")
        for reg, val in gadget.concrete_regs.items():
            print(f"  {reg}: {val:#x}")

    # Register dependencies and controllers
    if gadget.reg_dependencies:
        print("\nRegister dependencies:")
        for reg, deps in gadget.reg_dependencies.items():
            controllers = gadget.reg_controllers.get(reg, [])
            print(f"  {reg}: controls={controllers} depends={deps}")

    # Register moves
    if gadget.reg_moves:
        print("\nRegister moves:")
        for move in gadget.reg_moves:
            print(f"  {move.from_reg} -> {move.to_reg} ({move.bits} bits)")

    # Memory operations
    if gadget.mem_reads:
        print("\nMemory reads:")
        for mem in gadget.mem_reads:
            print_mem_access(mem, "read")

    if gadget.mem_writes:
        print("\nMemory writes:")
        for mem in gadget.mem_writes:
            print_mem_access(mem, "write")

    if gadget.mem_changes:
        print("\nMemory changes:")
        for mem in gadget.mem_changes:
            print_mem_access(mem, "change")
            print(f"  Operation: {mem.op}")


def print_mem_access(access, type_str):
    """Print details about a memory access"""
    if access.addr_constant is not None:
        print(f"  Address: {access.addr_constant:#x}")
    else:
        print(f"  Address dependencies: {access.addr_dependencies}")
        print(f"  Address controllers: {access.addr_controllers}")

    if access.data_constant is not None:
        print(f"  Data: {access.data_constant:#x}")
    else:
        print(f"  Data dependencies: {access.data_dependencies}")
        print(f"  Data controllers: {access.data_controllers}")

    print(f"  Address size: {access.addr_size} bits")
    print(f"  Data size: {access.data_size} bits")


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
    for a in ast.children_asts():
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


# Move class definition outside any function
class SpecialMem(angr.storage.memory_mixins.SpecialFillerMixin, angr.storage.DefaultMemory):
    """
    Class to use angr's SpecialFillerMixin to replace uninitialized memory
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

def fast_uninitialized_filler(name, addr, size, state):
    return state.solver.BVS("uninitialized" + hex(addr), size, explicit_name=True)

def make_initial_state(project, stack_gsize, fast_mode=False):
    """
    :return: an initial state with a symbolic stack and good options for rop
    """
    # Register the special memory class
    angr.SimState.register_default("sym_memory", SpecialMem)

    remove_set = angr.options.resilience | angr.options.simplification
    if fast_mode:
        remove_set.add(angr.options.SUPPORT_FLOATING_POINT)
    add_set = {angr.options.AVOID_MULTIVALUED_READS, angr.options.AVOID_MULTIVALUED_WRITES,
               angr.options.NO_SYMBOLIC_JUMP_RESOLUTION, angr.options.CGC_NO_SYMBOLIC_RECEIVE_LENGTH,
               angr.options.NO_SYMBOLIC_SYSCALL_RESOLUTION, angr.options.TRACK_ACTION_HISTORY,
               angr.options.ADD_AUTO_REFS, angr.options.SPECIAL_MEMORY_FILL}

    initial_state = project.factory.blank_state(
        special_memory_filler=fast_uninitialized_filler,
        add_options=add_set, remove_options=remove_set)

    initial_state.options.discard(angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)
    initial_state.options.update({angr.options.TRACK_REGISTER_ACTIONS, angr.options.TRACK_MEMORY_ACTIONS,
                                angr.options.TRACK_JMP_ACTIONS, angr.options.TRACK_CONSTRAINT_ACTIONS})
    symbolic_stack = claripy.Concat(*[
        initial_state.solver.BVS(f"symbolic_stack_{i}", project.arch.bits) for i in range(stack_gsize)
    ])
    initial_state.memory.store(initial_state.regs.sp, symbolic_stack)
    if initial_state.arch.bp_offset != initial_state.arch.sp_offset:
        initial_state.regs.bp = initial_state.regs.sp + 20*initial_state.arch.bytes
    initial_state.solver._solver.timeout = 500  # only solve for half a second at most

    angr.SimState.register_default("sym_memory", angr.storage.DefaultMemory)

    return initial_state


def make_symbolic_state(project, reg_set, extra_reg_set=None, stack_gsize=80, fast_mode=False):
    """
    converts an input state into a state with symbolic registers
    :return: the symbolic state
    """
    if extra_reg_set is None:
        extra_reg_set = set()
    input_state = make_initial_state(project, stack_gsize, fast_mode)
    symbolic_state = input_state.copy()
    # overwrite all registers
    for reg in reg_set:
        symbolic_state.registers.store(reg, symbolic_state.solver.BVS("sreg_" + reg + "-", project.arch.bits))
    # extra regs have a different name so they aren't processed
    for reg in extra_reg_set:
        symbolic_state.registers.store(reg, symbolic_state.solver.BVS("esreg_" + reg + "-", project.arch.bits))

    # vex registers should be symbolic set once
    for reg in ("cc_ndep", "cc_dep1", "cc_dep2"):
        if reg in symbolic_state.arch.registers:
            symbolic_state.registers.store(reg, symbolic_state.solver.BVS("badreg_" + reg + "-", project.arch.bits))

    # restore sp
    symbolic_state.regs.sp = input_state.regs.sp
    return symbolic_state

def make_reg_symbolic(state, reg):
    state.registers.store(reg,
    state.solver.BVS("sreg_" + reg + "-", state.arch.bits))

def cast_rop_value(val, project):
    if not isinstance(val, RopValue):
        val = RopValue(val, project)
        val.rebase_analysis()
    return val

def is_in_kernel(project, state):
    ip = state.ip
    if not ip.symbolic:
        obj = project.loader.find_object_containing(ip.concrete_value)
        if obj is None:
            return False
        if obj.binary == 'cle##kernel':
            return True
        return False
    return False

def step_one_block(project, state, stop_at_syscall=False):
    block = state.block()
    num_insts = len(block.capstone.insns)

    if not num_insts:
        raise RopException("No instructions!")

    if project.is_hooked(state.addr):
        succ = project.factory.successors(state)
        return succ, None

    if is_in_kernel(project, state):
        succ = project.factory.successors(state)
        if stop_at_syscall:
            return None, succ.flat_successors[0]
        return succ, None

    if project.arch.linux_name.startswith("mips"):
        last_inst_addr = block.capstone.insns[-2].address
    else:
        last_inst_addr = block.capstone.insns[-1].address
    for _ in range(num_insts): # considering that it may get into kernel mode
        if state.addr != last_inst_addr:
            state = step_one_inst(project, state, stop_at_syscall=stop_at_syscall)
            if stop_at_syscall and is_in_kernel(project, state):
                return None, state
        else:
            succ = project.factory.successors(state, num_inst=1)
            if not succ.flat_successors:
                return succ, None
            if stop_at_syscall and is_in_kernel(project, succ.flat_successors[0]):
                return None, succ.flat_successors[0]
            return succ, None
    raise RopException("Fail to reach the last instruction!")

def step_one_inst(project, state, stop_at_syscall=False):
    if is_in_kernel(project, state):
        if stop_at_syscall:
            return state
        succ = project.factory.successors(state)
        return step_one_inst(project, succ.flat_successors[0])

    if project.is_hooked(state.addr):
        succ = project.factory.successors(state)
        return step_one_inst(project, succ.flat_successors[0])

    succ = project.factory.successors(state, num_inst=1)
    if not succ.flat_successors:
        raise RopException(f"fail to step state: {state}")
    return succ.flat_successors[0]

def step_to_unconstrained_successor(project, state, max_steps=2, allow_simprocedures=False,
                                    stop_at_syscall=False, precise_action=False):
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

        if not precise_action:
            succ = project.factory.successors(state)
            if stop_at_syscall and succ.flat_successors:
                next_state = succ.flat_successors[0]
                if is_in_kernel(project, next_state):
                    return next_state
        else:
            # FIXME: we step instruction by instruction because of an angr bug: xxxx
            # the bug makes angr may merge sim_actions from two instructions into one
            # making analysis based on sim_actions inaccurate
            succ, state = step_one_block(project, state, stop_at_syscall=stop_at_syscall)
            if state:
                return state

        if len(succ.flat_successors) + len(succ.unconstrained_successors) != 1:
            raise RopException("Does not get to a single successor")
        if len(succ.flat_successors) == 1 and max_steps > 0:
            if not allow_simprocedures and project.is_hooked(succ.flat_successors[0].addr):
                # it cannot be a syscall as now syscalls are not explicitly hooked
                raise RopException("Skipping simprocedure")
            return step_to_unconstrained_successor(project, succ.flat_successors[0], max_steps=max_steps-1,
                                                   allow_simprocedures=allow_simprocedures,
                                                   stop_at_syscall=stop_at_syscall,
                                                   precise_action=precise_action)
        if len(succ.flat_successors) == 1 and max_steps == 0:
            raise RopException("Does not get to an unconstrained successor")
        return succ.unconstrained_successors[0]

    except (angr.errors.AngrError, angr.errors.SimError) as e:
        raise RopException("Does not get to a single unconstrained successor") from e


def timeout(seconds_before_timeout):
    """
    A decorator that adds timeout functionality to a function.
    Works on both Windows and Linux platforms.

    :param seconds_before_timeout: Number of seconds to wait before timing out
    :return: The decorated function result or raises RopException on timeout
    """

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            result = None
            error = None
            is_finished = False

            def target():
                nonlocal result, error, is_finished
                try:
                    result = f(*args, **kwargs)
                except Exception as e:
                    error = e
                finally:
                    is_finished = True

            thread = threading.Thread(target=target)
            thread.daemon = True  # Allow program to exit if thread is still running

            thread.start()
            thread.join(seconds_before_timeout)

            if not is_finished:
                pass
                # raise RopException("[angrop] Timeout!")

            if error is not None:
                raise error

            return result

        return wrapper

    return decorator