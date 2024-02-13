import os

import angr
import angrop # pylint: disable=unused-import

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
