import os
import nose
import angr
import angrop  # pylint: disable=unused-import
import pickle

import logging
l = logging.getLogger("angrop.tests.test_rop")

public_bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))
test_data_location = str(os.path.dirname(os.path.realpath(__file__)))


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
    nose.tools.assert_equal(set(m1.addr_dependencies), set(m2.addr_dependencies))
    nose.tools.assert_equal(set(m1.addr_controllers), set(m2.addr_controllers))
    nose.tools.assert_equal(set(m1.data_dependencies), set(m2.data_dependencies))
    nose.tools.assert_equal(set(m1.data_controllers), set(m2.data_controllers))
    nose.tools.assert_equal(m1.addr_constant, m2.addr_constant)
    nose.tools.assert_equal(m1.data_constant, m2.data_constant)
    nose.tools.assert_equal(m1.addr_size, m2.addr_size)
    nose.tools.assert_equal(m1.data_size, m2.data_size)


def assert_gadgets_equal(known_gadget, test_gadget):
    nose.tools.assert_equal(known_gadget.addr, test_gadget.addr)
    nose.tools.assert_equal(known_gadget.changed_regs, test_gadget.changed_regs)
    nose.tools.assert_equal(known_gadget.popped_regs, test_gadget.popped_regs)
    nose.tools.assert_equal(known_gadget.reg_dependencies, test_gadget.reg_dependencies)
    nose.tools.assert_equal(known_gadget.reg_controllers, test_gadget.reg_controllers)
    nose.tools.assert_equal(known_gadget.stack_change, test_gadget.stack_change)
    nose.tools.assert_equal(known_gadget.makes_syscall, test_gadget.makes_syscall)

    nose.tools.assert_equal(len(known_gadget.mem_reads), len(test_gadget.mem_reads))
    for m1, m2 in zip(known_gadget.mem_reads, test_gadget.mem_reads):
        assert_mem_access_equal(m1, m2)
    nose.tools.assert_equal(len(known_gadget.mem_writes), len(test_gadget.mem_writes))
    for m1, m2 in zip(known_gadget.mem_writes, test_gadget.mem_writes):
        assert_mem_access_equal(m1, m2)
    nose.tools.assert_equal(len(known_gadget.mem_changes), len(test_gadget.mem_changes))
    for m1, m2 in zip(known_gadget.mem_changes, test_gadget.mem_changes):
        assert_mem_access_equal(m1, m2)

    nose.tools.assert_equal(known_gadget.addr, test_gadget.addr)
    nose.tools.assert_equal(known_gadget.changed_regs, test_gadget.changed_regs)


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
    test_gadget_dict = {g.addr: g for g in test_gadgets}

    found_addrs = set(g.addr for g in test_gadgets)
    for g in known_gadgets:
        nose.tools.assert_in(g.addr, found_addrs)

    # So now we should have
    nose.tools.assert_equal(len(test_gadgets), len(known_gadgets))

    # check gadgets
    for g in known_gadgets:
        assert_gadgets_equal(g, test_gadget_dict[g.addr])


def execute_chain(project, chain):
    s = project.factory.blank_state()
    s.memory.store(s.regs.sp, chain.payload_str() + "AAAAAAAAA")
    s.ip = s.stack_pop()
    p = project.factory.simgr(s)
    goal_addr = 0x4141414141414141 % (1 << project.arch.bits)
    while p.one_active.addr != goal_addr:
        p.step()
        nose.tools.assert_equal(len(p.active), 1)

    return p.one_active


def test_rop_x86_64():
    b = angr.Project(os.path.join(public_bin_location, "x86_64/datadep_test"))
    rop = b.analyses.ROP()
    rop.find_gadgets_single_threaded()

    # check gadgets
    test_gadgets, _ = pickle.load(open(os.path.join(test_data_location, "datadep_test_gadgets"), "rb"))
    compare_gadgets(rop.gadgets, test_gadgets)

    # test creating a rop chain
    chain = rop.set_regs(rbp=0x1212, rbx=0x1234567890123456)
    # smallest possible chain
    nose.tools.assert_equal(chain.payload_len, 24)
    # chain is correct
    result_state = execute_chain(b, chain)
    nose.tools.assert_equal(result_state.se.any_int(result_state.regs.rbp), 0x1212)
    nose.tools.assert_equal(result_state.se.any_int(result_state.regs.rbx), 0x1234567890123456)

    # test setting the filler value
    rop.set_roparg_filler(0x4141414141414141)
    chain = rop.set_regs(rbx=0x121212)
    nose.tools.assert_equal(chain._concretize_chain_values()[2][0], 0x4141414141414141)


def test_rop_i386_cgc():
    b = angr.Project(os.path.join(public_bin_location, "cgc/sc1_0b32aa01_01"))
    rop = b.analyses.ROP()
    rop.find_gadgets_single_threaded()

    # check gadgets
    test_gadgets, _, _ = pickle.load(open(os.path.join(test_data_location, "0b32aa01_01_gadgets"), "rb"))
    compare_gadgets(rop.gadgets, test_gadgets)

    # test creating a rop chain
    chain = rop.set_regs(ebx=0x98765432, ecx=0x12345678)
    # smallest possible chain
    nose.tools.assert_equal(chain.payload_len, 12)
    # chain is correct
    result_state = execute_chain(b, chain)
    nose.tools.assert_equal(result_state.se.any_int(result_state.regs.ebx), 0x98765432)
    nose.tools.assert_equal(result_state.se.any_int(result_state.regs.ecx), 0x12345678)

    # test memwrite chain
    chain = rop.write_to_mem(0x41414141, "ABCDEFGH")
    result_state = execute_chain(b, chain)
    nose.tools.assert_equal(result_state.se.any_str(result_state.memory.load(0x41414141, 8)), "ABCDEFGH")


def test_rop_arm():
    b = angr.Project(os.path.join(public_bin_location, "armel/manysum"), load_options={"auto_load_libs": False})
    rop = b.analyses.ROP()
    rop.find_gadgets_single_threaded()

    # check gadgets
    test_gadgets, _ = pickle.load(open(os.path.join(test_data_location, "arm_manysum_test_gadgets"), "rb"))
    compare_gadgets(rop.gadgets, test_gadgets)

    # test creating a rop chain
    chain = rop.set_regs(r11=0x99887766)
    # smallest possible chain
    nose.tools.assert_equal(chain.payload_len, 8)
    # correct chains, using a more complicated chain here
    chain = rop.set_regs(r4=0x99887766, r9=0x44556677, r11=0x11223344)
    result_state = execute_chain(b, chain)
    nose.tools.assert_equal(result_state.se.any_int(result_state.regs.r4), 0x99887766)
    nose.tools.assert_equal(result_state.se.any_int(result_state.regs.r9), 0x44556677)
    nose.tools.assert_equal(result_state.se.any_int(result_state.regs.r11), 0x11223344)

    # test memwrite chain
    chain = rop.write_to_mem(0x41414141, "ABCDEFGH")
    result_state = execute_chain(b, chain)
    nose.tools.assert_equal(result_state.se.any_str(result_state.memory.load(0x41414141, 8)), "ABCDEFGH")


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("angrop.rop").setLevel(logging.DEBUG)

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
