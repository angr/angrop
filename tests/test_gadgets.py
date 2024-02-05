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

def test_arm_mem_change_gadget():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)
    rop._initialize_gadget_analyzer()

    """
    4b1e30  ldr     r1, [r6]
    4b1e32  add     r4, r1
    4b1e34  str     r4, [r6]
    4b1e36  pop     {r3, r4, r5, r6, r7, pc}
    """
    gadget = rop._gadget_analyzer.analyze_gadget(0x4b1e30+1) # thumb mode
    assert gadget.mem_changes

    """
    4c1e78  ldr     r1, [r4,#0x14]
    4c1e7a  add     r1, r5
    4c1e7c  str     r1, [r4,#0x14]
    4c1e7e  pop     {r3, r4, r5, pc}
    """
    gadget = rop._gadget_analyzer.analyze_gadget(0x4c1e78+1) # thumb mode
    assert gadget.mem_changes

    """
    4c1ea4  ldr     r2, [r3,#0x14]
    4c1ea6  adds    r2, #0x4
    4c1ea8  str     r2, [r3,#0x14]
    4c1eaa  bx      lr
    """
    gadget = rop._gadget_analyzer.analyze_gadget(0x4c1ea4+1) # thumb mode
    assert not gadget.mem_changes

    """
    4c1e8e  ldr     r1, [r4,#0x14]
    4c1e90  str     r5, [r4,#0x10]
    4c1e92  add     r1, r5
    4c1e94  str     r1, [r4,#0x14]
    4c1e96  pop     {r3, r4, r5, pc}
    """
    gadget = rop._gadget_analyzer.analyze_gadget(0x4c1e8e+1) # thumb mode
    assert gadget.mem_changes

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
