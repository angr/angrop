import os
import nose
import angr
import angrop
import pickle

import logging
l = logging.getLogger("angrop.tests.test_rop")

bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
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


def assert_gadgets_equal(g1, g2):
    nose.tools.assert_equal(g1.addr, g2.addr)
    nose.tools.assert_equal(g1.changed_regs, g2.changed_regs)
    nose.tools.assert_equal(g1.popped_regs, g2.popped_regs)
    nose.tools.assert_equal(g1.reg_dependencies, g2.reg_dependencies)
    nose.tools.assert_equal(g1.reg_controllers, g2.reg_controllers)
    nose.tools.assert_equal(g1.stack_change, g2.stack_change)

    nose.tools.assert_equal(len(g1.mem_reads), len(g2.mem_reads))
    for m1, m2 in zip(g1.mem_reads, g2.mem_reads):
        assert_mem_access_equal(m1, m2)
    nose.tools.assert_equal(len(g1.mem_writes), len(g2.mem_writes))
    for m1, m2 in zip(g1.mem_writes, g2.mem_writes):
        assert_mem_access_equal(m1, m2)
    nose.tools.assert_equal(len(g1.mem_changes), len(g2.mem_changes))
    for m1, m2 in zip(g1.mem_changes, g2.mem_changes):
        assert_mem_access_equal(m1, m2)

    nose.tools.assert_equal(g1.addr, g2.addr)
    nose.tools.assert_equal(g1.changed_regs, g2.changed_regs)


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
    found_addrs = set(g.addr for g in test_gadgets)
    for g in known_gadgets:
        nose.tools.assert_in(g.addr, found_addrs)

    # So now we should have
    nose.tools.assert_equal(len(test_gadgets), len(known_gadgets))

    # check gadgets
    for g1, g2, in zip(test_gadgets, known_gadgets):
        assert_gadgets_equal(g1, g2)


def execute_chain(project, chain):
    s = project.factory.blank_state()
    s.memory.store(s.regs.sp, chain.payload_str() + "AAAAAAAAA")
    s.ip = s.stack_pop()
    p = project.factory.path(s)
    goal_addr = 0x4141414141414141 % (1 << project.arch.bits)
    while p.addr != goal_addr:
        p.step()
        nose.tools.assert_equal(len(p.successors), 1)
        p = p.successors[0]

    return p.state


def test_rop_x86_64():
    b = angr.Project(os.path.join(bin_location, "tests/x86_64/datadep_test"))
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


def test_rop_i386_cgc():
    b = angr.Project(os.path.join(bin_location, "cgc_scored_event_1/cgc/0b32aa01_01"))
    rop = b.analyses.ROP()
    rop.find_gadgets_single_threaded()

    # check gadgets
    test_gadgets, _ = pickle.load(open(os.path.join(test_data_location, "0b32aa01_01_gadgets"), "rb"))
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
    b = angr.Project(os.path.join(bin_location, "tests/armel/manysum"))
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
