import os
import logging

import angr
import angrop  # pylint: disable=unused-import

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
