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

def gadget_exists(rop, addr):
    return rop._gadget_analyzer.analyze_gadget(addr) is not None

def test_badbyte():
    proj = angr.Project(os.path.join(tests_dir, "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    rop._initialize_gadget_analyzer()

    assert all(gadget_exists(rop, x) for x in [0x080a9773, 0x08091cf5, 0x08092d80, 0x080920d3])

def test_multiprocess_find_gadgets():
    proj = angr.Project(os.path.join(tests_dir, "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    rop.find_gadgets(show_progress=False)

    assert all(gadget_exists(rop, x) for x in [0x080a9773, 0x08091cf5, 0x08092d80, 0x080920d3])

def test_symbolic_memory_access_from_stack():
    proj = angr.Project(os.path.join(tests_dir, "armel", "test_angrop_arm_gadget"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    rop._initialize_gadget_analyzer()

    assert all(gadget_exists(rop, x) for x in [0x000103f4])

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
