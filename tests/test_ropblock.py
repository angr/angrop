import os

import angr
import angrop # pylint: disable=unused-import
from angrop.rop_block import RopBlock
from angrop.errors import RopException

BIN_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "binaries")
CACHE_DIR = os.path.join(BIN_DIR, 'tests_data', 'angrop_gadgets_cache')

def test_ropblock():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "mipsel", "darpa_ping"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    gadget = rop.analyze_gadget(0x404e98)
    rb = RopBlock.from_gadget(gadget, rop.chain_builder._reg_setter)
    assert rb.next_pc_idx() == 11

def test_reg_mover():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=True, only_check_near_rets=False)

    g1 = rop.analyze_gadget(0x46f562) # mov rax, rbp; pop rbp; pop r12; ret
    g2 = rop.analyze_gadget(0x524a50) # push rax; mov eax, 1; pop rbx; pop rbp; pop r12; ret
    assert g1 is not None and g2 is not None

    rb = RopBlock.from_gadget_list([g1, g2], rop.chain_builder._reg_mover)
    assert len(rb.reg_moves) == 1
    move = rb.reg_moves[0]
    assert move.from_reg == 'rbp'
    assert move.to_reg == 'rbx'
    assert move.bits == 64

    chain = rop.move_regs(rbx='rbp')
    chain._blank_state.regs.rbp = 0x41414141

    state = chain.exec()
    assert state.regs.rbx.concrete_value == 0x41414141

    # this should fail
    try:
        chain = rop.move_regs(rbx='rbp', rax='rbp')
        assert chain is None
    except RopException:
        pass

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
    #logging.getLogger("angrop.gadget_analyzer").setLevel(logging.DEBUG)

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
