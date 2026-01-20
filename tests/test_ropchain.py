import os

import angr
import angrop # pylint: disable=unused-import
from angrop.sigreturn import SigreturnFrame

BIN_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "binaries")
CACHE_DIR = os.path.join(BIN_DIR, 'tests_data', 'angrop_gadgets_cache')

def test_chain_exec():
    """
    Ensure the chain executor is correct
    """
    cache_path = os.path.join(CACHE_DIR, "1after909")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "1after909"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    # make sure the target gadget exist
    gadgets = [x for x in rop._all_gadgets if x.addr == 0x402503]
    assert len(gadgets) == 1
    gadget = gadgets[0]

    # build a ROP chain using the gadget
    chain = angrop.rop_chain.RopChain(proj, rop.chain_builder)
    chain.add_gadget(gadget)
    chain.add_value(0x41414141)

    # make sure the execution succeeds
    state = chain.exec()
    assert not state.regs.rdi.symbolic
    assert state.solver.eval(state.regs.rdi == 0x41414141)


def test_sigreturn_chain_i386():
    cache_path = os.path.join(CACHE_DIR, "bronze_ropchain")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets_single_threaded(show_progress=False)
        rop.save_gadgets(cache_path)

    rop.set_roparg_filler(0)
    assert rop.syscall_gadgets
    regs = {
        "eip": 0x41414141,
        "esp": 0xdeadbeef,
        "eax": 0x1337,
        "ebx": 0x11223344,
    }
    chain = rop.sigreturn(**regs)
    state = chain.sim_exec_til_syscall()
    assert state is not None
    cc = angr.SYSCALL_CC[proj.arch.name]["default"](proj.arch)
    assert state.solver.eval(cc.syscall_num(state)) == rop.arch.sigreturn_num

    frame = SigreturnFrame.from_project(proj)
    frame.update(**regs)
    sp = state.solver.eval(state.regs.sp)
    for reg, val in regs.items():
        offset = frame.offset_of(reg)
        mem = state.memory.load(sp + offset, frame.word_size, endness=proj.arch.memory_endness)
        assert state.solver.eval(mem) == val

def test_sigreturn_chain_amd64():
    # TODO: simulate the sigreturn syscall and verify the register again?
    cache_path = os.path.join(CACHE_DIR, "amd64_glibc_2.19")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets_single_threaded(show_progress=False)
        rop.save_gadgets(cache_path)

    rop.set_roparg_filler(0)
    assert rop.syscall_gadgets
    regs = {
        "rip": 0x4141414141414141,
        "rsp": 0x7fffffffdeadbeef,
        "rax": 0x1337,
        "rdi": 0x1122334455667788,
    }
    chain = rop.sigreturn(**regs)
    state = chain.sim_exec_til_syscall()
    assert state is not None
    cc = angr.SYSCALL_CC[proj.arch.name]["default"](proj.arch)
    assert state.solver.eval(cc.syscall_num(state)) == rop.arch.sigreturn_num

    frame = SigreturnFrame.from_project(proj)
    frame.update(**regs)
    sp = state.solver.eval(state.regs.sp)
    for reg, val in regs.items():
        offset = frame.offset_of(reg)
        mem = state.memory.load(sp + offset, frame.word_size, endness=proj.arch.memory_endness)
        assert state.solver.eval(mem) == val

def run_all():
    functions = globals()
    all_functions = {x:y for x, y in functions.items() if x.startswith('test_')}
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    import sys
    import logging

    logging.getLogger("angrop.rop").setLevel(logging.DEBUG)

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
