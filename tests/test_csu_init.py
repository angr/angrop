import os
import angr
import test_rop
import angrop  # pylint: disable=unused-import


import logging
l = logging.getLogger("angrop.tests.test_csu_init")

bin_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries'))
tests_dir = os.path.join(bin_path, 'tests')
data_dir = os.path.join(bin_path, 'tests_data', 'angrop_gadgets_cache')


"""
MIPSTAKE
.text:00400E40 loc_400E40:                              # CODE XREF: __libc_csu_init+84↓j
.text:00400E40 lw      $t9, 0($s1)
.text:00400E44 addiu   $s0, 1
.text:00400E48 move    $a0, $s3
.text:00400E4C move    $a1, $s4
.text:00400E50 jalr    $t9
.text:00400E54 move    $a2, $s5
.text:00400E58 sltu    $v0, $s0, $s2
.text:00400E5C bnez    $v0, loc_400E40
.text:00400E60 addiu   $s1, 4
.text:00400E64
.text:00400E64 loc_400E64:                              # CODE XREF: __libc_csu_init+60↑j
.text:00400E64 lw      $ra, 0x34($sp)
.text:00400E68 lw      $s5, 0x30($sp)
.text:00400E68  # End of function __libc_csu_init
.text:00400E68
.text:00400E6C lw      $s4, 0x2C($sp)
.text:00400E70 lw      $s3, 0x28($sp)
.text:00400E74 lw      $s2, 0x24($sp)
.text:00400E78 lw      $s1, 0x20($sp)
.text:00400E7C lw      $s0, 0x1C($sp)
.text:00400E80 jr      $ra
.text:00400E84 addiu   $sp, 0x38
"""


def test_mipstake():
    cache_path = os.path.join(data_dir, "mipstake")
    proj = angr.Project(os.path.join(tests_dir, "mips", "mipstake"), auto_load_libs=True, arch="mips")
    rop = proj.analyses.ROP(max_block_size=40)

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets_single_threaded()
        rop.save_gadgets(cache_path)

    chain = rop.func_call("sleep", [1, 2], needs_return=False)
    sleep_addr = proj.loader.main_object.imports['sleep'].value
    result_state = test_rop.execute_chain(proj, chain, sleep_addr)
    assert result_state.solver.eval(result_state.registers.load('a0'), cast_to=int) == 1
    assert result_state.solver.eval(result_state.registers.load('a1'), cast_to=int) == 2
    assert chain._gadgets[-1].transit_type == 'call_reg_from_mem'


'''
UNEXPLOITABLE

.text:00000000004005D0 loc_4005D0:                             ; CODE XREF: .text:00000000004005E4↓j
.text:00000000004005D0                 mov     rdx, r15
.text:00000000004005D3                 mov     rsi, r14
.text:00000000004005D6                 mov     edi, r13d
.text:00000000004005D9                 call    qword ptr [r12+rbx*8]
.text:00000000004005DD                 add     rbx, 1
.text:00000000004005E1                 cmp     rbx, rbp
.text:00000000004005E1 __libc_csu_init endp ; sp-analysis failed
.text:00000000004005E1
.text:00000000004005E4                 jnz     short loc_4005D0
.text:00000000004005E6
.text:00000000004005E6 loc_4005E6:                             ; CODE XREF: __libc_csu_init+48↑j
.text:00000000004005E6                 mov     rbx, [rsp+8]
.text:00000000004005EB                 mov     rbp, [rsp+10h]
.text:00000000004005F0                 mov     r12, [rsp+18h]
.text:00000000004005F5                 mov     r13, [rsp+20h]
.text:00000000004005FA                 mov     r14, [rsp+28h]
.text:00000000004005FF                 mov     r15, [rsp+30h]
.text:0000000000400604                 add     rsp, 38h
.text:0000000000400608                 retn
.text:0000000000400608 ; } // starts at 400580
'''


def test_unexploitable():
    cache_path = os.path.join(data_dir, "unexploitable")
    proj = angr.Project(os.path.join(tests_dir, "x86_64", "unexploitable"), auto_load_libs=False, arch="x86_64")
    rop = proj.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False, )

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets_single_threaded()
        rop.save_gadgets(cache_path)

    chain = rop.func_call("sleep", [1, 0xdeadbeefdeadbeef], needs_return=True)
    sleep_addr = proj.loader.main_object.imports['sleep'].value
    result_state = test_rop.execute_chain(proj, chain, sleep_addr)
    assert result_state.solver.eval(result_state.registers.load('rsi'), cast_to=int) == 0xdeadbeefdeadbeef
    assert result_state.solver.eval(result_state.registers.load('rdi'), cast_to=int) == 0x1
    assert chain._gadgets[-1].transit_type == 'call_reg_from_mem'


def run_all():
    functions = globals()
    all_functions = dict([x for x in functions.items() if x[0].startswith('test_')])
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("angrop.rop").setLevel(logging.DEBUG)

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        test_mipstake()
        test_unexploitable()