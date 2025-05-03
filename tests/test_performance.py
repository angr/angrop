import os
import time
import logging

import angr
import angrop # pylint: disable=unused-import
from angrop.rop_gadget import RopGadget, PivotGadget, SyscallGadget

logging.getLogger("cle").setLevel("ERROR")

BIN_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "binaries")
CACHE_DIR = os.path.join(BIN_DIR, 'tests_data', 'angrop_gadgets_cache')

def local_gadget_finding():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel/libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    start = time.time()
    rop.find_gadgets(processes=16, optimize=False)
    assert time.time() - start < 20

    start = time.time()
    rop.optimize(processes=16)
    assert time.time() - start < 5

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64/libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    start = time.time()
    rop.find_gadgets(processes=16, optimize=False)
    assert time.time() - start < 35

    start = time.time()
    rop.optimize(processes=16)
    assert time.time() - start < 5

def local_graph_optimization_missing_write():
    """
    this binary does not contain enough gadgets to form a write chain
    """
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64/manywords"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    start = time.time()
    rop.find_gadgets(processes=16, optimize=False)
    assert time.time() - start < 5

    start = time.time()
    rop.optimize(processes=16)
    assert time.time() - start < 1

def local_graph_optimization():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64/ALLSTAR_389-dsgw_csearch"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False)

    start = time.time()
    rop.find_gadgets(processes=16, optimize=False)
    assert time.time() - start < 15

    # this is about 25-26s
    start = time.time()
    rop.optimize(processes=16)
    assert time.time() - start < 35

def local_write_optimize():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64/ALLSTAR_389-dsgw_csearch"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    cache = '/tmp/ALLSTAR_389-dsgw_csearch.cache'
    if os.path.exists(cache):
        rop.load_gadgets(cache, optimize=False)
    else:
        rop.find_gadgets(processes=16, show_progress=True, optimize=False)
        rop.save_gadgets(cache)

    start = time.time()
    for _ in range(20):
        rop.write_to_mem(0x41414141, b'AAAAAAA')
    print(time.time() - start)

def run_all():
    functions = globals()
    all_functions = {x:y for x, y in functions.items() if x.startswith('test_')}
    for f in sorted(all_functions.keys()):
        print(f)
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()
    print("local_gadget_finding")
    local_gadget_finding()
    print("local_graph_optimization_missing_write")
    local_graph_optimization_missing_write()
    print("local_graph_optimization")
    local_graph_optimization()
    print("local_write_optimize")
    local_write_optimize()

if __name__ == "__main__":
    import sys
    import logging

    logging.getLogger("angrop.rop").setLevel(logging.DEBUG)
    #logging.getLogger("angrop.gadget_analyzer").setLevel(logging.DEBUG)

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
