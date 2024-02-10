import os
import logging

import angr
import angrop  # pylint: disable=unused-import
from angrop.rop_gadget import RopGadget, PivotGadget

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

    rop.find_gadgets(show_progress=False)

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
    assert gadget.block_length == 6

def test_pivot_gadget():
    proj = angr.Project(os.path.join(tests_dir, "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    #rop.find_gadgets_single_threaded(show_progress=False)

    """
    80488e8  leave
    80488e9  ret
    """
    gadget = rop.analyze_gadget(0x80488e8)
    assert type(gadget) == PivotGadget
    assert gadget.stack_change == 0

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

    """
    8048fd6  xchg    esp, eax
    8048fd7  ret
    """
    gadget = rop.analyze_gadget(0x8048fd6)
    assert type(gadget) == PivotGadget
    assert gadget.stack_change == 0

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

    proj = angr.Project(os.path.join(bin_path, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)

    """
    4c7b5a  mov     sp, r7
    4c7b5c  pop.w   {r4, r5, r6, r7, r8, sb, sl, fp, pc
    """

    #rop.find_gadgets(show_progress=False)
    gadget = rop.analyze_gadget(0x4c7b5a+1)
    assert type(gadget) == PivotGadget
    assert gadget.stack_change == 0


def run_all():
    functions = globals()
    all_functions = {x:y for x, y in functions.items() if x.startswith('test_')}
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()
    local_multiprocess_find_gadgets()

if __name__ == "__main__":
    logging.getLogger("angrop.rop").setLevel(logging.DEBUG)

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
