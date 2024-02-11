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
    # pylint: disable=pointless-string-statement

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)
    rop._initialize_gadget_analyzer()

    """
    0x0004f08c <+28>:	ldr	r2, [r4, #48]	; 0x30
    0x0004f08e <+30>:	asrs	r3, r3, #2
    0x0004f090 <+32>:	str	r3, [r5, #8]
    0x0004f092 <+34>:	str	r2, [r5, #0]
    0x0004f094 <+36>:	str	r5, [r4, #48]	; 0x30
    0x0004f096 <+38>:	pop	{r3, r4, r5, pc}
    """
    gadget = rop._gadget_analyzer.analyze_gadget(0x44f08c+1) # thumb mode
    assert gadget
    assert not gadget.mem_changes

    gadget = rop._gadget_analyzer.analyze_gadget(0x459eea+1) # thumb mode
    assert gadget
    assert not gadget.mem_changes

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
    assert gadget.stack_change_after_pivot == 0x4
    assert len(gadget.sp_controllers) == 1
    assert len(gadget.sp_reg_controllers) == 0

    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    """
    80488e8  leave
    80488e9  ret
    """
    gadget = rop.analyze_gadget(0x80488e8)
    assert type(gadget) == PivotGadget
    assert gadget.stack_change == 0
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
    assert gadget.stack_change_after_pivot == 0x4
    assert len(gadget.sp_controllers) == 1 and gadget.sp_controllers.pop().startswith('symbolic_stack_')

    """
    8048fd6  xchg    esp, eax
    8048fd7  ret
    """
    gadget = rop.analyze_gadget(0x8048fd6)
    assert type(gadget) == PivotGadget
    assert gadget.stack_change == 0
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
    assert gadget.stack_change_after_pivot == 0x24
    assert len(gadget.sp_controllers) == 1 and gadget.sp_controllers.pop() == 'r7'

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
