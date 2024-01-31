import os
import logging

import angr
import angrop  # pylint: disable=unused-import

l = logging.getLogger(__name__)

bin_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries'))
tests_dir = os.path.join(bin_path, 'tests')
data_dir = os.path.join(bin_path, 'tests_data', 'angrop_gadgets_cache')


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

def test_badbyte():
    cache_path = os.path.join(data_dir, "bronze_ropchain")
    proj = angr.Project(os.path.join(tests_dir, "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    rop.set_badbytes([0x0, 0x0a])

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    # make sure it can set 0 first
    chain = rop.set_regs(eax=0)
    state = chain.exec()
    assert not state.regs.eax.symbolic
    assert state.solver.eval(state.regs.eax == 0)
    assert all(x not in chain.payload_str() for x in [0, 0xa])

    # make sure it can set 0x16, which requires gadgets like `mov eax, 0x16`
    chain = rop.set_regs(eax=0x16)
    state = chain.exec()
    assert not state.regs.eax.symbolic
    assert state.solver.eval(state.regs.eax == 0x16)
    assert all(x not in chain.payload_str() for x in [0, 0xa])

    # make sure it can set 0xb
    # this binary does not have gadget that sets 0xb directly, it needs to do calculation
    # something like `mov eax, 8` and then `add eax, 3`
    chain = rop.set_regs(eax=0xb)
    state = chain.exec()
    assert not state.regs.eax.symbolic
    assert state.solver.eval(state.regs.eax == 0xb)
    assert all(x not in chain.payload_str() for x in [0, 0xa])

    # make sure it can write '/bin/sh\x00\n' into memory, notice that '\x00' and '\n' are bad bytes
    ptr = rop.chain_builder._mem_writer._get_ptr_to_writable(9+4)
    chain = rop.write_to_mem(ptr, b'/bin/sh\x00\n')
    state = chain.exec()
    assert state.solver.eval(state.memory.load(ptr, 9), cast_to=bytes)
    assert all(x not in chain.payload_str() for x in [0, 0xa])

    # finally, make sure setting multiple registers can work
    nullptr = rop.chain_builder._mem_writer._get_ptr_to_null()
    chain = rop.set_regs(eax=0xb, ebx=ptr, ecx=nullptr, edx=nullptr)
    state = chain.exec()
    assert not state.regs.eax.symbolic
    assert state.solver.eval(state.regs.eax == 0xb)
    assert not state.regs.ebx.symbolic
    assert state.solver.eval(state.regs.ebx == ptr)
    assert not state.regs.ecx.symbolic
    assert state.solver.eval(state.regs.ecx == nullptr)
    assert not state.regs.edx.symbolic
    assert state.solver.eval(state.regs.edx == nullptr)
    assert all(x not in chain.payload_str() for x in [0, 0xa])


def run_all():
    functions = globals()
    all_functions = {x:y for x, y in functions.items() if x.startswith('test_')}
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
