import os

import angr
import angrop # pylint: disable=unused-import

BIN_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "binaries")
CACHE_DIR = os.path.join(BIN_DIR, 'tests_data', 'angrop_gadgets_cache')

def get_rop(path):
    cache_path = os.path.join(CACHE_DIR, os.path.basename(path))
    proj = angr.Project(path, auto_load_libs=False)
    rop = proj.analyses.ROP()
    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)
    return rop

def test_arm_conditional():
    """
    Currently, we don't model conditional execution in arm. So we don't allow
    conditional execution in arm at this moment.
    """
    rop = get_rop(os.path.join(BIN_DIR, "tests", "armel", "helloworld"))

    cond_gadget_addrs = [0x10368, 0x1036c, 0x10370, 0x10380, 0x10384, 0x1038c, 0x1039c,
                         0x103a0, 0x103b8, 0x103bc, 0x103c4, 0x104e8, 0x104ec]

    assert all(x.addr not in cond_gadget_addrs for x in rop._gadgets)

def test_jump_gadget():
    """
    Ensure it finds gadgets ending with jumps
    Ensure angrop can use jump gadgets to build ROP chains
    """
    rop = get_rop(os.path.join(BIN_DIR, "tests", "mipsel", "fauxware"))

    jump_gadgets = [x for x in rop._gadgets if x.transit_type == "jmp_reg"]
    assert len(jump_gadgets) > 0


    jump_regs = [x.jump_reg for x in jump_gadgets]
    assert 't9' in jump_regs
    assert 'ra' in jump_regs

def run_all():
    functions = globals()
    all_functions = dict([x for x in functions.items() if x[0].startswith('test_')])
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    import sys
    import logging

    logging.getLogger("angrop.rop").setLevel(logging.DEBUG)
    #logging.getLogger("angrop.gadget_analyzer").setLevel(logging.DEBUG)

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
