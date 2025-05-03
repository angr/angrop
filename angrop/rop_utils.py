import sys
import time
import signal

import angr
import claripy
from angr.engines.successors import SimSuccessors

from .errors import RegNotFoundException, RopException, RopTimeoutException
from .rop_value import RopValue

def addr_to_asmstring(project, addr):
    block = project.factory.block(addr)
    return "; ".join(["%s %s" %(i.mnemonic, i.op_str) for i in block.capstone2.insns])


def get_ast_dependency(ast) -> set:
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


def get_ast_controllers(state, ast, reg_deps) -> set:
    """
    looks for registers that we can make symbolic then the ast can be "anything"
    :param state: the input state
    :param ast: the ast of which we are trying to analyze controllers
    :param reg_deps: All registers which it depends on
    :return: A set of register names which can control the ast
    """

    test_val = 0x4141414141414141 % (2 << state.arch.bits)

    controllers = set()
    if not ast.symbolic:
        return controllers

    # make sure only variables are registers
    var_names = {}
    for var in ast.variables:
        if not var.startswith("sreg_"):
            return controllers
        reg = (var[5:].split("-")[0])
        var_names[reg] = var

    # strip operations that dont affect control
    strip_ast = ast
    while True:
        if strip_ast.op == "Extract":
            strip_ast = strip_ast.args[2]
        elif strip_ast.op == "Reverse":
            strip_ast = strip_ast.args[0]
        elif strip_ast.op == "__add__" and len(strip_ast.args) == 2 and not strip_ast.args[1].symbolic:
            strip_ast = strip_ast.args[0]
        elif strip_ast.op in ('ZeroExt', 'SignExt'):
            strip_ast = strip_ast.args[1]
        else:
            break

    # fast path just a BVS of a register
    if len(strip_ast.variables) == 1 and strip_ast.op == "BVS":
        assert len(reg_deps) == 1
        # return that one register as the controller
        return list(reg_deps)

    for reg in reg_deps:
        test_ast = ast
        for r in [a for a in reg_deps if a != reg]:
            # for bp and registers that might be set
            if not state.registers.load(r).symbolic:
                 continue
            reg_sym_val = state.registers.load(r)
            test_ast = claripy.algorithm.replace(expr=test_ast,
                                      old=reg_sym_val,
                                      new=claripy.BVV(test_val, reg_sym_val.size()))
        # we consider 32-bit control on 64-bit system valid
        if state.project.arch.bits == 64 and test_ast.op in ('ZeroExt', 'SignExt') and test_ast.args[0] == 32:
            test_ast = test_ast.args[1]

        if fast_unconstrained_check(state, test_ast):
            controllers.add(reg)

    return controllers


def get_ast_const_offset(state, ast, reg_deps) -> int:
    """
    Gets the constant offset for a memory access
    :param state: the input state
    :param ast: the ast of which we are trying to analyze controllers
    :param reg_deps: All registers which it depends on
    :return: Constant value
    """
    size = ast.size()
    zero_val = claripy.BVV(0, size)

    # Replace symbolic values with zero to get the constant value
    # This is faster than eval with extra contraints
    for reg in reg_deps:
        reg_val = state.registers.load(reg)
        ast = claripy.algorithm.replace(
            expr=ast, old=reg_val, new=zero_val)

    assert not ast.symbolic
    return state.solver.eval(ast)


def loose_constrained_check(state, ast, extra_constraints=None):
    size = ast.size()
    # we are fine with partial control on 64bit system
    if size == 64:
        size = 32
    test_val_0 = 0x0
    test_val_1 = (1 << size) - 1
    test_val_2 = int("1010"*16, 2) % (1 << size)
    test_val_3 = int("0101"*16, 2) % (1 << size)
    # chars need to be able to be different
    test_val_4 = int(("1001"*2 + "1010"*2 + "1011"*2 + "1100"*2 + "1101"*2 + "1110"*2 + "1110"*2 + "0001"*2), 2) \
        % (1 << size)
    extra = extra_constraints if extra_constraints is not None else []

    cnt = 0
    if not state.solver.satisfiable(extra_constraints= extra + [ast == test_val_0]):
        cnt += 1
    if not state.solver.satisfiable(extra_constraints= extra + [ast == test_val_1]):
        cnt += 1
    if cnt > 1: return False
    if not state.solver.satisfiable(extra_constraints= extra + [ast == test_val_2]):
        cnt += 1
    if cnt > 1: return False
    if not state.solver.satisfiable(extra_constraints= extra + [ast == test_val_3]):
        cnt += 1
    if cnt > 1: return False
    if not state.solver.satisfiable(extra_constraints= extra + [ast == test_val_4]):
        cnt += 1
    if cnt > 1:
        return False
    return True

def unconstrained_check(state, ast, extra_constraints=None):
    """
    Attempts to check if an ast is completely unconstrained
    :param state: the state to use
    :param ast: the ast to check
    :return: True if the ast is probably completely unconstrained
    """
    if ast.variables.intersection(state.solver._solver.variables):
        return False
    return True

def fast_unconstrained_check(state, ast):
    """
    Attempts to check if an ast has any common unreversable operations mul, div
    :param state: the state to use
    :param ast: the ast to check
    :return: True if the ast is probably unconstrained
    """
    good_ops = {"Extract", "BVS", "__add__", "__sub__", "__xor__", "Reverse", "BVV"}

    if not ast.symbolic:
        return False

    passes_prefilter = True

    for a in ast.children_asts():
        if a.op not in good_ops:
            passes_prefilter = False
        # check for x __add__ x which is constrained
        seen_vars = set()
        for child in a.args:
            if isinstance(child, (int, str)) or child is None:
                continue
            if len(child.variables & seen_vars):
                passes_prefilter = False
            seen_vars |= child.variables

    if ast.op not in good_ops:
        passes_prefilter = False

    if passes_prefilter:
        return True

    def must_be_constrained(ast):
        if ast.op == "__and__":
            for arg in ast.args:
                if not arg.symbolic and arg.concrete_value != (1<<ast.size())-1:
                    return True
        if ast.op == "__or__":
            for arg in ast.args:
                if not arg.symbolic and arg.concrete_value != 0:
                    return True

        if ast.op in ("__rshift__", "__lshift__"):
            for arg in ast.args:
                if not arg.symbolic and arg.concrete_value != 0:
                    return True

        if ast.op in ["__add__", "__sub__", "__xor__"]:
            # recursively check symbolic part when there are 2 args and one is constant
            if len(ast.args) == 2 and (not ast.args[0].symbolic or not ast.args[1].symbolic):
                symbolic = ast.args[1]
                if ast.args[0].symbolic:
                    symbolic = ast.args[0]
                if must_be_constrained(symbolic):
                    return True
        return False

    if must_be_constrained(ast):
        return False

    # check that we don't have any obvious constrained parts
    ast2 = ast
    if state.project.arch.bits == 64 and ast.op in ('SignExt', 'ZeroExt') and ast.args[0] == 32:
        ast2 = ast.args[1]
    for i in range(ast2.length//8):
        b = ast2.get_byte(i)
        if not b.symbolic or must_be_constrained(b):
            return False

    return loose_constrained_check(state, ast)

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

def bits_extended(ast):
    if ast.op in ('ZeroExt', 'SignExt'):
        return ast.args[0]
    for c in ast.children_asts():
        if c.op in ('ZeroExt', 'SignExt'):
            return c.args[0]
    return None

def fast_uninitialized_filler(_, addr, size, state):
    return state.solver.BVS("uninitialized_" + hex(addr), size, explicit_name=True)


class SpecialMem(angr.storage.memory_mixins.SpecialFillerMixin, angr.storage.DefaultMemory):
    """
    class to use angr's SpecialFillerMixin to replace uninitialized memory
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

def make_initial_state(project, stack_gsize):
    """
    :return: an initial state with a symbolic stack and good options for rop
    """
    # create a new plugin for memory
    # the purpose of this plugin is to optimize away some slowness with the default uninitialized memory
    angr.SimState.register_default("sym_memory", SpecialMem)

    #angr.options.NO_SYMBOLIC_JUMP_RESOLUTION
    remove_set = angr.options.resilience | angr.options.simplification | {angr.options.AVOID_MULTIVALUED_READS, angr.options.SUPPORT_FLOATING_POINT}
    add_set = {angr.options.CONSERVATIVE_READ_STRATEGY, angr.options.AVOID_MULTIVALUED_WRITES,
               angr.options.NO_SYMBOLIC_JUMP_RESOLUTION, angr.options.CGC_NO_SYMBOLIC_RECEIVE_LENGTH,
               angr.options.NO_SYMBOLIC_SYSCALL_RESOLUTION, angr.options.TRACK_ACTION_HISTORY,
               angr.options.ADD_AUTO_REFS, angr.options.SPECIAL_MEMORY_FILL,
               angr.options.NO_CROSS_INSN_OPT, # for instruction-precise sim_action tracking
               }

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
    initial_state.solver._solver.timeout = 1000  # only solve for a second at most

    angr.SimState.register_default("sym_memory", angr.storage.DefaultMemory)

    return initial_state


def make_symbolic_state(project, reg_set, stack_gsize, extra_reg_set=None, symbolize_got=False):
    """
    converts an input state into a state with symbolic registers
    :return: the symbolic state
    """
    if extra_reg_set is None:
        extra_reg_set = set()
    input_state = make_initial_state(project, stack_gsize)
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

    # some arches have zero registers and they should be handle by pyvex.
    # but just to be extra safe, we set it here as well
    if hasattr(symbolic_state.regs, "zero"):
        symbolic_state.regs.zero = 0

    # restore sp
    symbolic_state.regs.sp = input_state.regs.sp

    # symbolic got table if it is not FULL RELRO, we only need this for gadget identification
    if symbolize_got:
        symbolize_got_table(project, symbolic_state)
    return symbolic_state

def symbolize_got_table(project, state):
    for s in project.loader.main_object.sections:
        if s.name == '.got.plt':
            break
    else:
        return
    # FULL RELRO
    if not s.is_writable:
        return
    endness = project.arch.memory_endness
    for i in range(0, s.memsize//project.arch.bytes):
        bv = claripy.BVS(f"symbolic_read_unconstrained_got_{i}", project.arch.bits)
        state.memory.store(s.vaddr + i*project.arch.bytes, bv, endness=endness)

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
        return is_kernel_addr(project, ip.concrete_value)
    return False

def is_kernel_addr(project, addr):
    obj = project.loader.find_object_containing(addr)
    if obj is None:
        return False
    if obj.binary == 'cle##kernel':
        return True
    return False

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
                                    stop_at_syscall=False):
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

        succ: SimSuccessors = None # type: ignore
        succ = project.factory.successors(state)
        if stop_at_syscall and succ.flat_successors:
            next_state = succ.flat_successors[0]
            if is_in_kernel(project, next_state):
                return next_state

        if len(succ.flat_successors) + len(succ.unconstrained_successors) != 1:
            raise RopException("Does not get to a single successor")
        if len(succ.flat_successors) == 1 and max_steps > 0:
            if not allow_simprocedures and project.is_hooked(succ.flat_successors[0].addr):
                # it cannot be a syscall as now syscalls are not explicitly hooked
                raise RopException("Skipping simprocedure")
            return step_to_unconstrained_successor(project, succ.flat_successors[0], max_steps=max_steps-1,
                                                   allow_simprocedures=allow_simprocedures,
                                                   stop_at_syscall=stop_at_syscall)
        if len(succ.flat_successors) == 1 and max_steps == 0:
            raise RopException("Does not get to an unconstrained successor")
        return succ.unconstrained_successors[0]

    except (angr.errors.AngrError, angr.errors.SimError) as e:
        raise RopException("Does not get to a single unconstrained successor") from e

def at_syscall(state):
    return state.project.factory.block(state.addr, num_inst=1).vex.jumpkind.startswith("Ijk_Sys") or is_kernel_addr(state.project, state.addr)

def step_to_syscall(state):
    """
    windup state to a state just about to make a syscall
    """
    if at_syscall(state):
        return state

    simgr = state.project.factory.simgr(state)
    while True:
        # FIXME: step(num_inst=1) does not with MIPS in angr
        # we currently work around it
        if state.project.arch.name.startswith("MIPS"):
            simgr.step()
        else:
            simgr.step(num_inst=1)
        if not simgr.active:
            raise RuntimeError("unable to reach syscall instruction")
        state = simgr.active[0]
        if at_syscall(state):
            return state
    return None

transit_arr = ["pop_pc", "jmp_reg", "jmp_mem", None]
def transit_num(g):
    return transit_arr.index(g.transit_type)

def handler(signum, frame):# pylint:disable=unused-argument
    # Exception during __del__ will be ignore
    # so if we happen to hit a __del__, retry the alarm
    # reference: https://docs.python.org/3/reference/datamodel.html#object.__del__
    while frame.f_back:
        filename = frame.f_code.co_filename
        if frame.f_code.co_name == '__del__':
            signal.setitimer(signal.ITIMER_REAL, 0.1, 0)
            return
        if filename.startswith(sys.base_prefix) and filename.endswith("/weakref.py"):
            print("Delaying for 0.1s because of weakref.py")
            signal.setitimer(signal.ITIMER_REAL, 0.1, 0)
            return
        frame = frame.f_back
    raise RopTimeoutException("[angrop] Timeout!")

def timeout(seconds_before_timeout):
    def decorate(f):
        def new_f(*args, **kwargs):
            old = signal.getsignal(signal.SIGALRM)
            if old == handler:
                old = signal.signal(signal.SIGALRM, handler)
                old_time_left = signal.alarm(seconds_before_timeout)
                if 0 < old_time_left < seconds_before_timeout: # never lengthen existing timer
                    signal.alarm(old_time_left)
            start_time = time.time()
            try:
                result = f(*args, **kwargs)
            finally:
                if old == handler:
                    if old_time_left > 0: # deduct f's run time from the saved timer
                        old_time_left -= int(time.time() - start_time)
                    signal.signal(signal.SIGALRM, old)
                    signal.alarm(old_time_left)
            return result
        return new_f
    return decorate
