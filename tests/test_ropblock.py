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

def test_expand_ropblock():
    proj = angr.load_shellcode(
        """
        pop rdi; ret
        mov eax, edi; ret
        pop rbx; ret
        add rsp, 8; ret
        mov rdx, rax; mov esi, 1; call rbx
        pop rsi; ret
        """,
        "amd64",
        load_address=0x400000,
        auto_load_libs=False,
    )
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    rop.find_gadgets_single_threaded(show_progress=False)

    chain = rop.set_regs(rsi=0x42424242, rdx=0x43434343)
    assert chain is not None

def test_block_effect():
    proj = angr.load_shellcode(
        """
        pop rax
        pop rbx
        ret
        """,
        "amd64",
        load_address=0x400000,
        auto_load_libs=False,
    )
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    rop.find_gadgets_single_threaded(show_progress=False)

    chain = rop.set_regs(rax=0x41414141)
    rb = RopBlock.from_chain(chain)
    data = rb._values[2].ast
    rb._blank_state.solver.add(data == 0x42424242)
    rb._analyze_effect()
    assert not rb.popped_regs

def test_normalized_block_effect():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    rop.analyze_gadget(0x536408) #: mov r8, r14; mov rsi, r15; call qword ptr [r12 + 0xf0]
    rop.analyze_gadget(0x41f668) #: pop r12; ret
    rop.analyze_gadget(0x0000000000401b96) # pop rdx; ret
    rop.analyze_gadget(0x0000000000422b5a) # pop rdi; ret
    rop.analyze_gadget(0x000000000043cdc9) # mov qword ptr [rdi + 8], rdx; ret
    rop.chain_builder.optimize()

    chain = rop.move_regs(r8='r14', rsi='r15')
    assert chain is not None

def test_stack_offset_infinite_loop():
    cache_path = os.path.join(CACHE_DIR, "libdevel-leak-perl-Leak.so")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "riscv", "libdevel-leak-perl-Leak.so"), auto_load_libs=False, load_options={'main_opts':{'base_addr': 0}})
    rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1, only_check_near_rets=False, cond_br=True, max_bb_cnt=5)

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path, optimize=False)
    else:
        rop.find_gadgets(optimize=False)
        rop.save_gadgets(cache_path)

    addrs = [g.addr for g in rop._all_gadgets]
    assert 0xf30 in addrs

    # if stack_offset is not properly calculated, it may lead to infinite loops
    # when handling 0xf30
    rop.optimize()

def test_normalized_block_effect2():
    cache_path = os.path.join(CACHE_DIR, "riscv_autotalent-autotalent.so")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "riscv", "autotalent-autotalent.so"), load_options={'main_opts':{'base_addr': 0}})
    rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1, only_check_near_rets=False, cond_br=True, max_bb_cnt=5)

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path, optimize=False)
    else:
        rop.find_gadgets(processes=16, optimize=False)
        rop.save_gadgets(cache_path)

    gs = rop.analyze_addr(0x4ae6)
    g = gs[0]
    rb = rop.chain_builder._reg_setter.normalize_gadget(g)
    assert 'a0' not in rb.popped_regs

def test_normalized_block_with_conditional_branch():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "aarch64", "libastring-ocaml-astring.cmxs"), load_options={'main_opts':{'base_addr': 0}})
    rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1, only_check_near_rets=False, cond_br=True, max_bb_cnt=5)

    rop.analyze_addr(0x0000000000023d28)
    rop.analyze_addr(0x00000000000189a4)
    rop.analyze_addr(0x0000000000020880)

    rop.chain_builder.optimize()
    chain = rop.set_regs(x0=0x41414141, x5=0x42424242)
    assert chain is not None

def test_jmp_reg_normalize_fast_path():
    cache_path = os.path.join(CACHE_DIR, "mipsel_btrfs-tools_btrfs-calc-size")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "mipsel", "btrfs-tools_btrfs-calc-size"), load_options={'main_opts':{'base_addr': 0}})
    rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1)

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path, optimize=False)
    else:
        rop.find_gadgets(processes=16, optimize=False)
        rop.save_gadgets(cache_path)

    rop.optimize(processes=1)

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
