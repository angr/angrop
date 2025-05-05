import os
import logging
from io import BytesIO

import angr
import angrop  # pylint: disable=unused-import
import archinfo

from angr_platforms import risc_v

l = logging.getLogger(__name__)

bin_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries'))
tests_dir = os.path.join(bin_path, 'tests')
data_dir = os.path.join(bin_path, 'tests_data', 'angrop_gadgets_cache')


"""
Suggestions on how to debug angr changes that break angrop.

If the gadget is completely missing after your changes. Pick the address that didn't work and run the following.
The logging should say why the gadget was discarded.

rop = p.analyses.ROP()
rop.analyze_gadget(addr)

If a gadget is missing memory reads / memory writes / memory changes, the actions are probably missing.
Memory changes require a read action followed by a write action to the same address.
"""

def gadget_exists(rop, addr):
    return rop.analyze_gadget(addr) is not None

def test_badbyte():
    proj = angr.Project(os.path.join(tests_dir, "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    assert all(gadget_exists(rop, x) for x in [0x080a9773, 0x08091cf5, 0x08092d80, 0x080920d3])

def local_multiprocess_find_gadgets():
    proj = angr.Project(os.path.join(tests_dir, "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    rop.find_gadgets(show_progress=True)

    assert all(gadget_exists(rop, x) for x in [0x080a9773, 0x08091cf5, 0x08092d80, 0x080920d3])

def test_symbolic_memory_access_from_stack():
    proj = angr.Project(os.path.join(tests_dir, "armel", "test_angrop_arm_gadget"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    assert all(gadget_exists(rop, x) for x in [0x000103f4])

def test_arm_thumb_mode():
    proj = angr.Project(os.path.join(bin_path, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)

    gadget = rop.analyze_gadget(0x4bf858+1)

    assert gadget
    assert gadget.isn_count == 2

def test_pivot_gadget():
    # pylint: disable=pointless-string-statement
    proj = angr.Project(os.path.join(tests_dir, "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    assert all(gadget_exists(rop, x) for x in [0x80488e8, 0x8048998, 0x8048fd6, 0x8052cac, 0x805658c, ])

    gadget = rop.analyze_gadget(0x8048592)
    assert not gadget

    proj = angr.Project(os.path.join(bin_path, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)

    """
    4c7b5a  mov     sp, r7
    4c7b5c  pop.w   {r4, r5, r6, r7, r8, sb, sl, fp, pc
    """

    gadget = rop.analyze_gadget(0x4c7b5a+1)
    assert gadget is not None

    proj = angr.Project(os.path.join(tests_dir, "i386", "i386_glibc_2.35"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    """
    439ad3  pop     esp
    439ad4  lea     esp, [ebp-0xc]
    439ad7  pop     ebx
    439ad8  pop     esi
    439ad9  pop     edi
    439ada  pop     ebp
    439adb  ret
    """
    gadget = rop.analyze_gadget(0x439ad3)
    assert gadget is None

    proj = angr.Project(os.path.join(tests_dir, "x86_64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    """
    402bc8  leave
    402bc9  clc
    402bca  repz ret
    """
    gadget = rop.analyze_gadget(0x402bc8)
    assert gadget is None

    # this is not a valid gadget because sal shifts the memory
    # and we don't fully control the shifted memory
    """
    50843e  sal     byte ptr [rbp-0x11], cl
    508441  leave
    508442  ret
    """
    gadget = rop.analyze_gadget(0x50843e)
    assert gadget is None

def test_syscall_gadget():
    proj = angr.Project(os.path.join(tests_dir, "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    assert all(gadget_exists(rop, x) for x in [0x0806f860, 0x0806f85e, 0x080939e3, 0x0806f2f1])

def test_shift_gadget():
    # pylint: disable=pointless-string-statement
    """
    438a91  pop     es
    438a92  add     esp, 0x9c
    438a98  ret

    454e75  push    cs
    454e76  add     esp, 0x5c
    454e79  pop     ebx
    454e7a  pop     esi
    454e7b  pop     edi
    454e7c  pop     ebp
    454e7d  ret

    5622d5  push    ss
    5622d6  add     esp, 0x74
    5622d9  pop     ebx
    5622da  pop     edi
    5622db  ret

    516fb2  clc
    516fb3  pop     ds
    516fb4  add     esp, 0x8
    516fb7  pop     ebx
    516fb8  ret

    490058  push    ds
    490059  add     esp, 0x2c
    49005c  ret
    """
    proj = angr.Project(os.path.join(tests_dir, "i386", "i386_glibc_2.35"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    assert all(not gadget_exists(rop, x) for x in [0x438a91, 0x516fb2])
    assert all(gadget_exists(rop, x) for x in [0x454e75, 0x5622d5, 0x490058])

def test_i386_syscall():
    """
    in 32-bit world, syscall instruction is only valid for AMD CPUs, we consider it invalid in angrop for
    better portability, see https://github.com/angr/angrop/issues/104
    """
    # pylint: disable=pointless-string-statement
    proj = angr.Project(os.path.join(tests_dir, "i386", "angrop_syscall_test"), auto_load_libs=False)

    rop = proj.analyses.ROP()
    """
    804918c  int     0x80
    """

    assert all(gadget_exists(rop, x) for x in [0x804918c])

    """
    8049189  syscall
    """
    assert all(not gadget_exists(rop, x) for x in [0x8049189])

def local_multiprocess_analyze_gadget_list():
    # pylint: disable=pointless-string-statement
    proj = angr.Project(os.path.join(tests_dir, "x86_64", "datadep_test"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    """
    0x4006d8, 0x400864  good gadgets
    0x4005d8            bad instruction
    """
    gadgets = rop.analyze_gadget_list([0x4006d8, 0x4005d8, 0x400864])
    assert len(gadgets) == 2
    assert gadgets[0].addr == 0x4006d8
    assert gadgets[1].addr == 0x400864

def test_gadget_filtering():
    proj = angr.Project(os.path.join(tests_dir, "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)
    g1 = rop.analyze_gadget(0x42bca5)
    g2 = rop.analyze_gadget(0x42c3c1)
    rop.chain_builder.bootstrap()
    values = list(rop.chain_builder._shifter.shift_gadgets.values())
    assert len(values) == 1 and len(values[0]) == 1

def test_aarch64_svc():
    proj = angr.Project(os.path.join(tests_dir, "aarch64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=True, only_check_near_rets=False)
    g = rop.analyze_gadget(0x0000000000463820)
    assert g is not None

def test_aarch64_reg_setter():
    proj = angr.Project(os.path.join(tests_dir, "aarch64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=True, only_check_near_rets=False)
    g = rop.analyze_gadget(0x00000000004c29a0)
    assert g is not None

def test_enter():
    proj = angr.Project(os.path.join(tests_dir, "x86_64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    g = rop.analyze_gadget(0x00000000004f83f3)
    assert g is not None

def test_jmp_mem_gadget():
    proj = angr.Project(os.path.join(tests_dir, "x86_64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    # 0x00000000001a2bd9 : xchg edx, esi ; jmp qword ptr [rax]
    # 0x00000000001905a1 : xor ebp, edx ; call qword ptr [rdx]
    g = rop.analyze_gadget(0x5a2bd9)
    assert g is not None
    assert g.transit_type == 'jmp_mem'
    g = rop.analyze_gadget(0x5905a1)
    assert g is not None
    assert g.transit_type == 'jmp_mem'

def test_syscall_next_block():
    proj = angr.Project(os.path.join(tests_dir, "cgc", "sc1_0b32aa01_01"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    g = rop.analyze_gadget(0x804843c)
    assert g
    assert g.isn_count < 20

    g = rop.analyze_gadget(0x8048441)
    assert g.can_return is True

    g = rop.analyze_gadget(0x080484d4)
    assert g.can_return is True

    rop.find_gadgets_single_threaded(show_progress=False)
    chain = rop.do_syscall(2, [1, 0x41414141, 0x42424242, 0], preserve_regs={'eax'}, needs_return=True)
    assert chain

def test_rex_pop_r10():
    f = BytesIO()
    f.write(b"OZ\xc3")
    proj = angr.Project(
        BytesIO(b"OZ\xc3"),
        main_opts={
            "backend": "blob",
            "arch": "amd64",
            "entry_point": 0,
            "base_addr": 0,
        })
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    g = rop.analyze_gadget(0)
    assert g is not None

def test_max_stack_change():
    proj = angr.load_shellcode("""
            xchg ebp, eax
            ret 0xd020
        """,
        "amd64",
    )

    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    g = rop.analyze_gadget(0)
    assert g is None

def test_symbolized_got():
    proj = angr.Project(os.path.join(tests_dir, "x86_64", "ALLSTAR_acct_sa"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    g = rop.analyze_gadget(0x40156A)
    assert g is not None

    # this will be considered pop, but it is not pop
    # pop rax; add al, 0; add al, al; ret
    g = rop.analyze_gadget(0x406850)
    assert g is None or 'rax' not in g.popped_regs

def test_syscall_when_ret_only():
    proj = angr.load_shellcode(
        """
        syscall
        """,
        "amd64",
        load_address=0x400000,
        simos='linux',
        auto_load_libs=False,
    )
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=True)
    rop.find_gadgets_single_threaded(show_progress=False)
    assert rop._all_gadgets

def test_riscv():
    proj = angr.Project(os.path.join(tests_dir, "riscv", "server_eapp.eapp_riscv"), load_options={'main_opts':{'base_addr': 0}})
    rop = proj.analyses.ROP(fast_mode=False)
    g = rop.analyze_gadget(0xA86C)
    assert g is not None

    proj = angr.Project(os.path.join(tests_dir, "riscv", "abgate-libabGateQt.so"),
                        load_options={'main_opts':{'base_addr': 0}},
                        )
    rop = proj.analyses.ROP(fast_mode=False, cond_br=True, max_bb_cnt=5)
    g = rop.analyze_addr(0x77da)
    assert g

def test_jmp_mem_num_mem_access():
    proj = angr.load_shellcode(
        """
        mov edx, ebp;
        mov rsi, r14;
        mov edi, r15d;
        call qword ptr [r12 + rbx*8]
        """,
        "amd64",
        load_address=0x400000,
        auto_load_libs=False,
    )
    rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1)
    g = rop.analyze_gadget(0x400000)
    assert g is not None

def test_exit_target():
    proj = angr.load_shellcode(
        """
        mov eax, dword ptr [rsp]; ret
        """,
        "amd64",
        load_address=0x400000,
        auto_load_libs=False,
    )
    rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1)
    g = rop.analyze_gadget(0x400000)
    assert not g.popped_regs

def test_syscall_block_hash():
    proj = angr.Project(os.path.join(tests_dir, "x86_64", "ALLSTAR_apcalc-dev_sample_many"), load_options={'main_opts':{'base_addr': 0}})
    rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1)
    rop.gadget_finder.gadget_analyzer
    tasks = list(rop.gadget_finder._addresses_to_check_with_caching(show_progress=False))
    for addr in [0x402de7, 0x425a00, 0x43e083, 0x4b146c]:
        assert addr in tasks

def run_all():
    functions = globals()
    all_functions = {x:y for x, y in functions.items() if x.startswith('test_')}
    for f in sorted(all_functions.keys()):
        print(f)
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()
    print("local_multiprocess_analyze_gadget_list")
    local_multiprocess_analyze_gadget_list()
    print("local_multiprocess_find_gadgets")
    local_multiprocess_find_gadgets()

if __name__ == "__main__":
    logging.getLogger("angrop.rop").setLevel(logging.DEBUG)

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
