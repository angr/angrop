import os
import pickle
import logging

import claripy
import angr
import angrop  # pylint: disable=unused-import

l = logging.getLogger("angrop.tests.test_rop")

public_bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests')
test_data_location = os.path.join(public_bin_location, "..", "tests_data", "angrop_gadgets_cache")


"""
Suggestions on how to debug angr changes that break angrop.

If the gadget is completely missing after your changes. Pick the address that didn't work and run the following.
The logging should say why the gadget was discarded.

rop = p.analyses.ROP()
angrop.gadget_analyzer.l.setLevel("DEBUG")
rop._gadget_analyzer.analyze_gadget(addr)

If a gadget is missing memory reads / memory writes / memory changes, the actions are probably missing.
Memory changes require a read action followed by a write action to the same address.
"""


def assert_mem_access_equal(m1, m2):
    assert set(m1.addr_dependencies) ==set(m2.addr_dependencies)
    assert set(m1.addr_controllers) == set(m2.addr_controllers)
    assert set(m1.data_dependencies) == set(m2.data_dependencies)
    assert set(m1.data_controllers) == set(m2.data_controllers)
    assert m1.addr_constant == m2.addr_constant
    assert m1.data_constant == m2.data_constant
    assert m1.addr_size == m2.addr_size
    assert m1.data_size == m2.data_size


def assert_gadgets_equal(known_gadget, test_gadget):
    assert known_gadget.addr == test_gadget.addr
    assert known_gadget.changed_regs == test_gadget.changed_regs
    assert known_gadget.popped_regs == test_gadget.popped_regs
    assert known_gadget.reg_dependencies == test_gadget.reg_dependencies
    assert known_gadget.reg_controllers == test_gadget.reg_controllers
    assert known_gadget.stack_change == test_gadget.stack_change

    assert len(known_gadget.mem_reads) == len(test_gadget.mem_reads)
    for m1, m2 in zip(known_gadget.mem_reads, test_gadget.mem_reads):
        assert_mem_access_equal(m1, m2)
    assert len(known_gadget.mem_writes) == len(test_gadget.mem_writes)
    for m1, m2 in zip(known_gadget.mem_writes, test_gadget.mem_writes):
        assert_mem_access_equal(m1, m2)
    assert len(known_gadget.mem_changes) == len(test_gadget.mem_changes)
    for m1, m2 in zip(known_gadget.mem_changes, test_gadget.mem_changes):
        assert_mem_access_equal(m1, m2)

    assert known_gadget.addr == test_gadget.addr
    assert known_gadget.changed_regs == test_gadget.changed_regs


def compare_gadgets(test_gadgets, known_gadgets):
    test_gadgets = sorted(test_gadgets, key=lambda x: x.addr)
    known_gadgets = sorted(known_gadgets, key=lambda x: x.addr)

    # we allow new gadgets to be found, but only check the correctness of those that were there in the known_gadgets
    # so filter new gadgets found
    expected_addrs = set(g.addr for g in known_gadgets)
    test_gadgets = [g for g in test_gadgets if g.addr in expected_addrs]

    # check that each of the expected gadget addrs was found as a gadget
    # if it wasn't the best way to debug is to run:
    # angrop.gadget_analyzer.l.setLevel("DEBUG"); rop._gadget_analyzer.analyze_gadget(addr)
    test_gadget_dict = {}
    for g in test_gadgets:
        test_gadget_dict.setdefault(g.addr, []).append(g)

    found_addrs = set(g.addr for g in test_gadgets)
    for g in known_gadgets:
        assert g.addr in found_addrs

    # So now we should have
    assert len(test_gadgets) == len(known_gadgets)

    # check gadgets
    for g in known_gadgets:
        matching_gadgets = [
            test_gadget
            for test_gadget in test_gadget_dict[g.addr]
            if test_gadget.bbl_addrs == g.bbl_addrs
        ]
        assert len(matching_gadgets) == 1, matching_gadgets
        assert_gadgets_equal(g, matching_gadgets[0])

def execute_chain(project, chain):
    s = project.factory.blank_state()
    s.memory.store(s.regs.sp, chain.payload_str())
    goal_idx = chain.next_pc_idx()
    s.memory.store(
        s.regs.sp
        + (chain.payload_len if goal_idx is None else goal_idx * project.arch.bytes),
        b"A" * project.arch.bytes,
    )
    s.ip = s.stack_pop()
    p = project.factory.simulation_manager(s)
    goal_addr = 0x4141414141414141 % (1 << project.arch.bits)
    while p.one_active.addr != goal_addr:
        p.step()
        assert len(p.active) == 1

    return p.one_active

def verify_execve_chain(chain):
    state = chain._blank_state.copy()
    proj = state.project
    state.memory.store(state.regs.sp, chain.payload_str())
    state.ip = state.stack_pop()

    # step to the system call
    simgr = proj.factory.simgr(state)
    while simgr.active:
        assert len(simgr.active) == 1
        state = simgr.active[0]
        obj = proj.loader.find_object_containing(state.ip.concrete_value)
        if obj and obj.binary == 'cle##kernel':
            break
        simgr.step()

    # verify the syscall arguments
    state = simgr.active[0]
    cc = angr.SYSCALL_CC[proj.arch.name]["default"](proj.arch)
    assert cc.syscall_num(state).concrete_value == chain._builder.arch.execve_num
    ptr = state.registers.load(cc.ARG_REGS[0])
    assert state.solver.is_true(state.memory.load(ptr, 8) == b'/bin/sh\0')
    assert state.registers.load(cc.ARG_REGS[1]).concrete_value == 0
    assert state.registers.load(cc.ARG_REGS[2]).concrete_value == 0

def test_roptest_mips():
    proj = angr.Project(os.path.join(public_bin_location, "mipsel/darpa_ping"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=True)
    rop.find_gadgets_single_threaded(show_progress=False)

    chain = rop.set_regs(s0=0x41414142, s1=0x42424243, v0=0x43434344)
    result_state = execute_chain(proj, chain)
    assert result_state.solver.eval(result_state.regs.s0) == 0x41414142
    assert result_state.solver.eval(result_state.regs.s1) == 0x42424243
    assert result_state.solver.eval(result_state.regs.v0) == 0x43434344


def test_rop_x86_64():
    b = angr.Project(os.path.join(public_bin_location, "x86_64/datadep_test"), auto_load_libs=False)
    rop = b.analyses.ROP()
    rop.find_gadgets_single_threaded(show_progress=False)

    cache_path = os.path.join(test_data_location, "datadep_test_gadgets")
    if not os.path.exists(cache_path):
        rop.save_gadgets(cache_path)

    # check gadgets
    with open(cache_path, "rb") as f:
        tup = pickle.load(f)
        compare_gadgets(rop._all_gadgets, tup[0])

    # test creating a rop chain
    chain = rop.set_regs(rbp=0x1212, rbx=0x1234567890123456)
    # smallest possible chain
    assert chain.payload_len == 32
    # chain is correct
    result_state = execute_chain(b, chain)
    assert result_state.solver.eval(result_state.regs.rbp) == 0x1212
    assert result_state.solver.eval(result_state.regs.rbx) == 0x1234567890123456

    # test setting the filler value
    rop.set_roparg_filler(0x4141414141414141)
    chain = rop.set_regs(rbx=0x121212)
    assert chain._concretize_chain_values()[2][0] == 0x4141414141414141


def test_rop_i386_cgc():
    b = angr.Project(os.path.join(public_bin_location, "cgc/sc1_0b32aa01_01"), auto_load_libs=False)
    rop = b.analyses.ROP()
    rop.find_gadgets_single_threaded(show_progress=False)

    cache_path = os.path.join(test_data_location, "0b32aa01_01_gadgets")
    if not os.path.exists(cache_path):
        rop.save_gadgets(cache_path)

    # check gadgets
    with open(os.path.join(test_data_location, "0b32aa01_01_gadgets"), "rb") as f:
        tup = pickle.load(f)
        compare_gadgets(rop._all_gadgets, tup[0])

    # test creating a rop chain
    chain = rop.set_regs(ebx=0x98765432, ecx=0x12345678)
    # smallest possible chain
    assert chain.payload_len == 16
    # chain is correct
    result_state = execute_chain(b, chain)
    assert result_state.solver.eval(result_state.regs.ebx) == 0x98765432
    assert result_state.solver.eval(result_state.regs.ecx) == 0x12345678

    # test memwrite chain
    chain = rop.write_to_mem(0x41414141, b"ABCDEFGH")
    result_state = execute_chain(b, chain)
    assert result_state.solver.eval(result_state.memory.load(0x41414141, 8), cast_to=bytes) == b"ABCDEFGH"

def test_rop_arm():
    b = angr.Project(os.path.join(public_bin_location, "armel/manysum"), load_options={"auto_load_libs": False})
    rop = b.analyses.ROP()
    rop.find_gadgets_single_threaded(show_progress=False)

    cache_path = os.path.join(test_data_location, "arm_manysum_test_gadgets")
    if not os.path.exists(cache_path):
        rop.save_gadgets(cache_path)

    # check gadgets
    with open(os.path.join(test_data_location, "arm_manysum_test_gadgets"), "rb") as f:
        tup = pickle.load(f)
        compare_gadgets(rop._all_gadgets, tup[0])

    # test creating a rop chain
    chain = rop.set_regs(r11=0x99887766)
    # smallest possible chain
    assert chain.payload_len == 12
    # correct chains, using a more complicated chain here
    chain = rop.set_regs(r4=0x99887766, r9=0x44556677, r11=0x11223344)
    result_state = execute_chain(b, chain)
    assert result_state.solver.eval(result_state.regs.r4) == 0x99887766
    assert result_state.solver.eval(result_state.regs.r9) == 0x44556677
    assert result_state.solver.eval(result_state.regs.r11) == 0x11223344

    # test memwrite chain
    chain = rop.write_to_mem(0x41414141, b"ABCDEFGH")
    result_state = execute_chain(b, chain)
    assert result_state.solver.eval(result_state.memory.load(0x41414141, 8), cast_to=bytes) == b"ABCDEFGH"

def test_roptest_x86_64():
    p = angr.Project(os.path.join(public_bin_location, "x86_64/roptest"), auto_load_libs=False)
    r = p.analyses.ROP(only_check_near_rets=False)
    r.find_gadgets_single_threaded(show_progress=False)
    c = r.execve(path=b"/bin/sh")
    verify_execve_chain(c)

def test_roptest_aarch64():
    cache_path = os.path.join(test_data_location, "aarch64_glibc_2.19")
    proj = angr.Project(os.path.join(public_bin_location, "aarch64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=True, only_check_near_rets=False)

    """
    0x4b7ca8: ldp x19, x30, [sp]; add sp, sp, #0x20; ret
    0x4ebad4: add x0, x19, #0x260; ldr x19, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret
    """
    rop.analyze_gadget(0x4b7ca8)
    rop.analyze_gadget(0x4ebad4)
    rop.chain_builder.optimize()

    data = claripy.BVS("data", 64)
    chain = rop.set_regs(x0=data)
    assert chain is not None
    chain._blank_state.solver.add(data == 0x41414141)
    assert b'\xe1\x3eAA' in chain.payload_str()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.write_to_mem(0x41414140, b'AAAAAAA')
    assert chain is not None

    chain = rop.execve(path=b'/bin/sh')
    verify_execve_chain(chain)

def test_acct_sa():
    """
    just a system test
    """
    proj = angr.Project(os.path.join(public_bin_location, "x86_64", "ALLSTAR_acct_sa"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    cache_path = os.path.join(test_data_location, "ALLSTAR_acct_sa")

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.set_regs(rax=0x41414141)
    assert chain is not None
    state = chain.exec()
    assert state.regs.rax.concrete_value == 0x41414141

    chain = rop.func_call(0xdeadbeef, [0x41414141, 0x42424242, 0x43434343])
    assert chain is not None
    state = chain.concrete_exec_til_addr(0xdeadbeef)
    assert state.regs.rdi.concrete_value == 0x41414141
    assert state.regs.rsi.concrete_value == 0x42424242
    assert state.regs.rdx.concrete_value == 0x43434343

def test_liblog():
    """
    yet another system test
    the difficulty here is that it needs to be able to normalize a jmp_mem gadget that requries moves
    """
    proj = angr.Project(os.path.join(public_bin_location, "x86_64", "ALLSTAR_android-libzipfile-dev_liblog.so.0.21.0"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    cache_path = os.path.join(test_data_location, "ALLSTAR_liblog")

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.set_regs(rdx=0x41414141)
    assert chain is not None

    chain = rop.func_call(0xdeadbeef, [0x41414141, 0x42424242, 0x43434343])
    assert chain is not None

def run_all():
    functions = globals()
    all_functions = {x:y for x, y in functions.items() if x.startswith('test_')}
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            print(f)
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("angrop.rop").setLevel(logging.DEBUG)

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
