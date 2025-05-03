import os

import angr
import angrop # pylint: disable=unused-import
from angrop.rop_gadget import RopGadget, PivotGadget, SyscallGadget

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

    assert all(x.addr not in cond_gadget_addrs for x in rop._all_gadgets)

def test_jump_gadget():
    """
    Ensure it finds gadgets ending with jumps
    Ensure angrop can use jump gadgets to build ROP chains
    """
    rop = get_rop(os.path.join(BIN_DIR, "tests", "mipsel", "fauxware"))

    jump_gadgets = [x for x in rop._all_gadgets if x.transit_type == "jmp_reg"]
    assert len(jump_gadgets) > 0

    jump_regs = [x.pc_reg for x in jump_gadgets]
    assert 't9' in jump_regs
    assert 'ra' in jump_regs

def test_arm_mem_change_gadget():
    # pylint: disable=pointless-string-statement

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True, max_sym_mem_access=4)

    """
    0x0004f08c <+28>:	ldr	r2, [r4, #48]	; 0x30
    0x0004f08e <+30>:	asrs	r3, r3, #2
    0x0004f090 <+32>:	str	r3, [r5, #8]
    0x0004f092 <+34>:	str	r2, [r5, #0]
    0x0004f094 <+36>:	str	r5, [r4, #48]	; 0x30
    0x0004f096 <+38>:	pop	{r3, r4, r5, pc}
    """
    gadget = rop.analyze_gadget(0x44f08c+1) # thumb mode
    assert gadget
    assert not gadget.mem_changes

    gadget = rop.analyze_gadget(0x459eea+1) # thumb mode
    assert gadget
    assert not gadget.mem_changes

    """
    4b1e30  ldr     r1, [r6]
    4b1e32  add     r4, r1
    4b1e34  str     r4, [r6]
    4b1e36  pop     {r3, r4, r5, r6, r7, pc}
    """
    gadget = rop.analyze_gadget(0x4b1e30+1) # thumb mode
    assert gadget.mem_changes

    """
    4c1e78  ldr     r1, [r4,#0x14]
    4c1e7a  add     r1, r5
    4c1e7c  str     r1, [r4,#0x14]
    4c1e7e  pop     {r3, r4, r5, pc}
    """
    gadget = rop.analyze_gadget(0x4c1e78+1) # thumb mode
    assert gadget.mem_changes

    """
    4c1ea4  ldr     r2, [r3,#0x14]
    4c1ea6  adds    r2, #0x4
    4c1ea8  str     r2, [r3,#0x14]
    4c1eaa  bx      lr
    """
    gadget = rop.analyze_gadget(0x4c1ea4+1) # thumb mode
    assert gadget.mem_changes

    """
    4c1e8e  ldr     r1, [r4,#0x14]
    4c1e90  str     r5, [r4,#0x10]
    4c1e92  add     r1, r5
    4c1e94  str     r1, [r4,#0x14]
    4c1e96  pop     {r3, r4, r5, pc}
    """
    gadget = rop.analyze_gadget(0x4c1e8e+1) # thumb mode
    assert gadget.mem_changes

def test_pivot_gadget():
    # pylint: disable=pointless-string-statement

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "i386_glibc_2.35"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    """
    5719da  pop     esp
    5719db  ret
    """
    gadget = rop.analyze_gadget(0x5719da)
    assert gadget.stack_change == 0x4
    assert gadget.stack_change_before_pivot == 0x4
    assert gadget.stack_change_after_pivot == 0x4
    assert len(gadget.sp_controllers) == 1
    assert len(gadget.sp_reg_controllers) == 0

    chain = rop.pivot(0x600000)
    assert chain

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    """
    80488e8  leave
    80488e9  ret
    """
    gadget = rop.analyze_gadget(0x80488e8)
    assert type(gadget) == PivotGadget
    assert gadget.stack_change == 0
    assert gadget.stack_change_before_pivot == 0
    assert gadget.stack_change_after_pivot == 0x8
    assert len(gadget.sp_controllers) == 1 and gadget.sp_controllers.pop() == 'ebp'


    """
    8048592  xchg    esp, eax
    8048593  ret     0xca21
    """
    gadget = rop.analyze_gadget(0x8048592)
    assert not gadget

    """
    8048998  pop     ecx
    8048999  pop     ebx
    804899a  pop     ebp
    804899b  lea     esp, [ecx-0x4]
    804899e  ret
    """
    gadget = rop.analyze_gadget(0x8048998)
    assert type(gadget) == PivotGadget
    assert gadget.stack_change == 0xc
    assert gadget.stack_change_before_pivot == 0xc
    assert gadget.stack_change_after_pivot == 0x4
    assert len(gadget.sp_controllers) == 1 and gadget.sp_controllers.pop().startswith('symbolic_stack_')

    """
    8048fd6  xchg    esp, eax
    8048fd7  ret
    """
    gadget = rop.analyze_gadget(0x8048fd6)
    assert type(gadget) == PivotGadget
    assert gadget.stack_change == 0
    assert gadget.stack_change_before_pivot == 0
    assert gadget.stack_change_after_pivot == 0x4
    assert len(gadget.sp_controllers) == 1 and gadget.sp_controllers.pop() == 'eax'

    """
    8052cac  lea     esp, [ebp-0xc]
    8052caf  pop     ebx
    8052cb0  pop     esi
    8052cb1  pop     edi
    8052cb2  pop     ebp
    8052cb3  ret
    """
    gadget = rop.analyze_gadget(0x8052cac)
    assert type(gadget) == PivotGadget
    assert gadget.stack_change == 0
    assert gadget.stack_change_before_pivot == 0
    assert gadget.stack_change_after_pivot == 0x14
    assert len(gadget.sp_controllers) == 1 and gadget.sp_controllers.pop() == 'ebp'

    """
    805658c  add    BYTE PTR [eax],al
    805658e  pop    ebx
    805658f  pop    esi
    8056590  pop    edi
    8056591  ret
    """
    gadget = rop.analyze_gadget(0x805658c)
    assert type(gadget) == RopGadget
    assert gadget.stack_change == 0x10 # 3 pops + 1 ret

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)

    """
    4c7b5a  mov     sp, r7
    4c7b5c  pop.w   {r4, r5, r6, r7, r8, sb, sl, fp, pc}
    """

    #rop.find_gadgets(show_progress=False)
    gadget = rop.analyze_gadget(0x4c7b5a+1)
    assert type(gadget) == PivotGadget
    assert gadget.stack_change == 0
    assert gadget.stack_change_before_pivot == 0
    assert gadget.stack_change_after_pivot == 0x24
    assert len(gadget.sp_controllers) == 1 and gadget.sp_controllers.pop() == 'r7'

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "manysum"), load_options={"auto_load_libs": False})
    rop = proj.analyses.ROP()

    """
    1040c  mov     r0, r3
    10410  sub     sp, fp, #0x0
    10414  pop     {fp}
    10418  bx      lr
    """
    gadget = rop.analyze_gadget(0x1040c)
    assert type(gadget) == PivotGadget
    assert gadget.stack_change == 0
    assert gadget.stack_change_before_pivot == 0
    assert gadget.stack_change_after_pivot == 0x4
    assert len(gadget.sp_controllers) == 1 and gadget.sp_controllers.pop() == 'r11'

def test_syscall_gadget():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "i386_glibc_2.35"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    gadget = rop.analyze_gadget(0x437765)
    assert type(gadget) == SyscallGadget
    assert gadget.stack_change == 0
    assert not gadget.can_return

    gadget = rop.analyze_gadget(0x5212f6)
    assert type(gadget) == SyscallGadget
    assert gadget.stack_change == 0
    assert not gadget.can_return

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    gadget = rop.analyze_gadget(0x0806f860)
    assert type(gadget) == SyscallGadget
    assert gadget.stack_change == 0x4
    assert gadget.can_return

    gadget = rop.analyze_gadget(0x0806f85e)
    assert type(gadget) == SyscallGadget
    assert gadget.stack_change == 0x4
    assert gadget.can_return

    gadget = rop.analyze_gadget(0x080939e3)
    assert type(gadget) == SyscallGadget
    assert gadget.stack_change == 0x0
    assert not gadget.can_return

    gadget = rop.analyze_gadget(0x0806f2f1)
    assert type(gadget) == SyscallGadget
    assert gadget.stack_change == 0x0
    assert not gadget.can_return

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "roptest"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    gadget = rop.analyze_gadget(0x4000c1)
    assert type(gadget) == SyscallGadget
    assert gadget.stack_change == 0
    assert not gadget.can_return

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False)

    gadget = rop.analyze_gadget(0x4c1330)
    assert type(gadget) == SyscallGadget
    assert gadget.stack_change == 0
    assert not gadget.can_return
    assert len(gadget.prologue.concrete_regs) == 1 and gadget.prologue.concrete_regs.pop('rax') == 0x3b

    gadget = rop.analyze_gadget(0x521cef)
    assert type(gadget) == RopGadget
    assert len(gadget.mem_writes) == 1
    mem_write = gadget.mem_writes[0]
    assert mem_write.addr_offset == 0x68
    assert len(mem_write.addr_controllers) == 1 and 'rdx' in mem_write.addr_controllers
    assert len(mem_write.data_controllers) == 1 and 'rcx' in mem_write.data_controllers

    gadget = rop.analyze_gadget(0x4c1437)
    assert type(gadget) == SyscallGadget
    assert gadget.stack_change == 0
    assert not gadget.can_return
    assert len(gadget.prologue.concrete_regs) == 1 and gadget.prologue.concrete_regs.pop('rax') == 0x3b

    gadget = rop.analyze_gadget(0x536715)
    assert type(gadget) == SyscallGadget
    assert gadget.stack_change == 0
    assert not gadget.can_return
    assert len(gadget.prologue.concrete_regs) == 1 and gadget.prologue.concrete_regs.pop('rsi') == 0x81

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "cgc", "sc1_0b32aa01_01"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    g = rop.analyze_gadget(0x0804843c)
    assert g.prologue and isinstance(g, RopGadget)

def test_pop_pc_gadget():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "mipsel", "darpa_ping"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    gadget = rop.analyze_gadget(0x404e98)
    assert gadget.transit_type == 'pop_pc'
    assert gadget.pc_offset == 0x28

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "angrop_retn_test"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    gadget = rop.analyze_gadget(0x40113a)
    assert gadget.transit_type == 'pop_pc'
    assert gadget.pc_offset == 0
    assert gadget.stack_change == 0x18

def test_reg_moves():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "arjsfxjr"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    gadget = rop.analyze_gadget(0x4027c4) # mov esi, esi; mov edi, r15d; call qword ptr [r12 + rbx*8]
    assert len(gadget.reg_moves) == 1

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "aarch64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=True, only_check_near_rets=False)
    g = rop.analyze_gadget(0x4ebad4)
    assert len(g.reg_moves) == 1

def test_oop_access():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    for addr in [0x0806b397, 0x0806b395, 0x08091dd2, 0x08091f5a]:
        g = rop.analyze_gadget(addr)
        assert g and g.oop

def test_negative_stack_change():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)

    # this is not a gadget because it is loading uninitialized memory
    """
    sub sp, #0x50
    add fp, pc
    b #0x4bf669
    ldr r3, [sp, #8]
    mov r2, r7
    mov r1, r6
    mov r0, r5
    str r3, [sp]
    mov r3, r8
    blx r4
    """
    g = rop.analyze_gadget(0x4bf661)
    assert g is None

def test_arm_jmp_mem():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)
    g = rop.analyze_gadget(0x456951)
    assert g is None

def test_num_mem_access():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "cgc", "sc1_0b32aa01_01"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, max_sym_mem_access=2)

    g = rop.analyze_gadget(0x8048500)
    assert g is not None
    assert g.has_symbolic_access() is True
    assert g.num_sym_mem_access == 2
    assert len(g.mem_changes) == 2

def test_pac():
    """
    add sp, sp, #0xc0
    autiasp
    ret
    """,
    proj = angr.load_shellcode(
        b'\xffC\x01\x91\xbf#\x03\xd5\xc0\x03_\xd6',
        "aarch64",
        load_address=0x400000,
        auto_load_libs=False,
    )
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    rop.find_gadgets_single_threaded(show_progress=False)

    assert len(rop._all_gadgets) == 1

def test_riscv():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "riscv", "abgate-libabGateQt.so"),
                        load_options={'main_opts':{'base_addr': 0}},
                        )
    rop = proj.analyses.ROP(fast_mode=False, cond_br=True, max_bb_cnt=5)
    gs = rop.analyze_addr(0x5f7a)
    g = gs[0]
    assert 's0' in g.popped_regs

def test_out_of_patch():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    # 0x000000000007c950 : mov rax, qword ptr [rip + 0x342849] ; ret
    g = rop.analyze_gadget(0x000000000047c950)
    assert g.oop is False

def test_controller():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64/datadep_test"), auto_load_libs=False)
    rop = proj.analyses.ROP()
    g = rop.analyze_gadget(0x400614)

    assert 'rax' in g.reg_controllers
    s = g.reg_controllers['rax']
    assert len(s) == 1 and 'rax' in s

    assert 'rbx' in g.reg_controllers
    s = g.reg_controllers['rbx']
    assert len(s) == 2 and 'rbx' in s and 'rsi' in s

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel/manysum"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    g = rop.analyze_gadget(0x10558)
    assert not g.reg_controllers

def test_cdq():
    proj = angr.load_shellcode(
        """
        pop rax
        cdq
        ret
        """,
        "amd64",
        load_address=0x400000,
        auto_load_libs=False,
    )
    rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1)
    g = rop.analyze_gadget(0x400000)
    assert g is not None
    assert 'rax' in g.popped_regs
    assert 'rdx' not in g.popped_regs

def test_invalid_ptr():
    proj = angr.load_shellcode(
        """
        pop rcx; xor al, 0x52; movabs byte ptr [0xc997d3941b683390], al; ret
        """,
        "amd64",
        load_address=0x400000,
        auto_load_libs=False,
    )
    rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1)
    g = rop.analyze_gadget(0x400000)
    assert g is None

def test_cond_br_guard_pop_conflict():
    proj = angr.load_shellcode(
        """
        ldr x3, [sp, #0x10];
        mov x15, x3;
        add x3, x3, #2;
        str x3, [sp, #0x10];
        ldr x24, [sp, #0x18];
        cmp x15, x24;
        b.eq #0x24;
        str x1, [x0];
        str x1, [x1];
        mov x0, #1;
        ldr x30, [sp, #0x28];
        add sp, sp, #0x30;
        ret
        """,
        "aarch64",
        load_address=0,
        auto_load_libs=False,
    )
    rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1)
    gs = rop.analyze_addr(0)
    assert len(gs) == 1
    g = gs[0]
    assert not g.reg_pops

def test_riscv_zero_register():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "riscv", "borgbackup2-chunker.cpython-312-riscv64-linux-gnu.so"), load_options={'main_opts':{'base_addr': 0}})
    rop = proj.analyses.ROP(fast_mode=False, max_bb_cnt=5, cond_br=True)

    gs = rop.analyze_addr(0x0000000000011f32)
    assert len(gs) == 1

def run_all():
    functions = globals()
    all_functions = {x:y for x, y in functions.items() if x.startswith('test_')}
    for f in sorted(all_functions.keys()):
        print(f)
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
