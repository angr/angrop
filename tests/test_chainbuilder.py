import os

import angr
import test_rop
import angrop # pylint: disable=unused-import
from angrop.rop_value import RopValue

BIN_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "binaries")
CACHE_DIR = os.path.join(BIN_DIR, 'tests_data', 'angrop_gadgets_cache')

def test_x86_64_func_call():
    cache_path = os.path.join(CACHE_DIR, "1after909")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "1after909"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.func_call('puts', [0x402704]) + rop.func_call('puts', [0x402704])
    state = chain.exec()
    assert state.posix.dumps(1) == b'Enter username: \nEnter username: \n'

def test_i386_func_call():
    cache_path = os.path.join(CACHE_DIR, "bronze_ropchain")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.func_call('write', [1, 0x80AC5E8, 17]) + rop.func_call('write', [1, 0x80AC5E8, 17])
    state = chain.exec(max_steps=100)
    assert state.posix.dumps(1) == b'/usr/share/locale/usr/share/locale'

def test_arm_func_call():
    cache_path = os.path.join(CACHE_DIR, "armel_glibc_2.31")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)
    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    proj.hook_symbol('write', angr.SIM_PROCEDURES['posix']['write']())
    chain1 = rop.func_call("write", [1, 0x4E15F0, 9])
    state = chain1.exec()
    assert state.posix.dumps(1) == b'malloc.c\x00'

    proj.hook_symbol('puts', angr.SIM_PROCEDURES['libc']['puts']())
    chain2 = rop.func_call("puts", [0x4E15F0])
    state = chain2.exec()
    assert state.posix.dumps(1) == b'malloc.c\n'

    chain = chain1 + chain2
    state = chain.exec()
    assert state.posix.dumps(1) == b'malloc.c\x00malloc.c\n'

def test_i386_syscall():
    cache_path = os.path.join(CACHE_DIR, "bronze_ropchain")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.do_syscall(4, [1, 0x80AC5E8, 17])
    state = chain.exec()
    assert state.posix.dumps(1) == b'/usr/share/locale'

def test_x86_64_syscall():
    cache_path = os.path.join(CACHE_DIR, "amd64_glibc_2.19")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    gadget = rop.analyze_gadget(0x536715)
    rop.chain_builder._sys_caller.syscall_gadgets = [gadget]
    rop.do_syscall(0xca, [0, 0x81], needs_return=False)

def test_preserve_regs():
    cache_path = os.path.join(CACHE_DIR, "1after909")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "1after909"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain1 = rop.set_regs(rdi=0x402715)
    chain2 = rop.func_call('puts', [0x402704], preserve_regs=['rdi'])
    chain = chain1+chain2
    state = chain.exec()
    assert state.posix.dumps(1) == b'Failed to parse username.\n'

def test_i386_mem_write():
    cache_path = os.path.join(CACHE_DIR, "i386_glibc_2.35")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "i386_glibc_2.35"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.write_to_mem(0xdeadbeef, b"/bin/sh\x00")

    state = chain.exec()
    s = state.solver.eval(state.memory.load(0xdeadbeef, 8), cast_to=bytes)
    assert s == b"/bin/sh\x00"

def test_ropvalue():
    cache_path = os.path.join(CACHE_DIR, "i386_glibc_2.35")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "i386_glibc_2.35"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.write_to_mem(0x800000, b"/bin/sh\x00")
    assert sum(not x._rebase for x in chain._values) == 4 # 4 values

    value = RopValue(0x800000, proj)
    value._rebase = False
    chain = rop.write_to_mem(value, b"/bin/sh\x00")
    assert sum(not x._rebase for x in chain._values) == 4 # 4 values

    value = RopValue(0x800000, proj)
    value.rebase_ptr()
    chain = rop.write_to_mem(value, b"/bin/sh\x00")
    assert sum(not x._rebase for x in chain._values) == 2 # 2 values

def test_reg_move():
    cache_path = os.path.join(CACHE_DIR, "bronze_ropchain")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "bronze_ropchain"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    # test single register move
    chain = rop.set_regs(ecx=0x41414141)
    chain += rop.move_regs(eax="ecx")
    state = chain.exec()
    assert state.regs.eax.concrete_value == 0x41414141

    # test multiple register moves at the same time
    chain = rop.set_regs(ecx=0x42424242)
    chain += rop.set_regs(ebx=0x41414141, preserve_regs=['ecx'])
    chain += rop.move_regs(edx='ebx', eax='ecx')
    state = chain.exec()
    assert state.regs.eax.concrete_value == 0x42424242
    assert state.regs.edx.concrete_value == 0x41414141

def test_set_regs():
    cache_path = os.path.join(CACHE_DIR, "armel_glibc_2.31")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)
    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.set_regs(r4=0x4141412c, r5=0x42424242)
    state = chain.exec()
    assert state.regs.r4.concrete_value == 0x4141412c
    assert state.regs.r5.concrete_value == 0x42424242

def test_add_to_mem():
    cache_path = os.path.join(CACHE_DIR, "i386_glibc_2.35")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "i386_glibc_2.35"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.write_to_mem(0xdeadbeef, b'CCCC') # 0x43434343
    chain += rop.add_to_mem(0xdeadbeef, 0x62a000)
    state = chain.exec()
    assert state.mem[0xdeadbeef].long.unsigned.concrete == 0x43a5e343

    chain = rop.write_to_mem(0x41414140, b'CCCC') # 0x43434343
    chain += rop.add_to_mem(0x41414140, 0x42424242)

    state = chain.exec()
    assert state.memory.load(0x41414140, 4).concrete_value == 0x85858585

    cache_path = os.path.join(CACHE_DIR, "armel_glibc_2.31")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)
    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    rop.add_to_mem(0x41414140, 0x42424242)

    cache_path = os.path.join(CACHE_DIR, "amd64_glibc_2.19")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "libc.so.6"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    rop.add_to_mem(0x41414140, 0x42424242)

def test_pivot():
    cache_path = os.path.join(CACHE_DIR, "i386_glibc_2.35")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "i386_glibc_2.35"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.pivot(0x41414140)
    state = chain.exec()
    assert state.solver.eval(state.regs.sp == 0x41414140)

    chain = rop.set_regs(eax=0x41414140)
    chain += rop.pivot('eax')
    state = chain.exec()
    assert state.solver.eval(state.regs.sp == 0x41414140+4)

def test_shifter():
    # i386
    cache_path = os.path.join(CACHE_DIR, "i386_glibc_2.35")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "i386_glibc_2.35"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.shift(0x50, preserve_regs=['ebx'])
    init_sp = chain._blank_state.regs.sp.concrete_value - len(chain._values) * proj.arch.bytes
    state = chain.exec()
    assert state.regs.sp.concrete_value == init_sp + 0x50 + proj.arch.bytes

    chain = rop.set_regs(ebx=0x41414141)
    chain += rop.shift(0x50, preserve_regs=['ebx'])
    state = chain.exec()
    assert state.regs.ebx.concrete_value == 0x41414141

    chain = rop.set_regs(eax=0x41414141)
    chain += rop.shift(0x50, preserve_regs=['eax'])
    state = chain.exec()
    assert state.regs.eax.concrete_value == 0x41414141

    # x86_64
    cache_path = os.path.join(CACHE_DIR, "1after909")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "1after909"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.shift(0x40)
    init_sp = chain._blank_state.regs.sp.concrete_value - len(chain._values) * proj.arch.bytes
    state = chain.exec()
    assert state.regs.sp.concrete_value == init_sp + 0x40 + proj.arch.bytes

    # armel
    cache_path = os.path.join(CACHE_DIR, "armel_glibc_2.31")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)
    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.shift(0x40)
    init_sp = chain._blank_state.regs.sp.concrete_value - len(chain._values) * proj.arch.bytes
    state = chain.exec()
    assert state.regs.sp.concrete_value == init_sp + 0x40 + proj.arch.bytes

def test_retsled():
    # i386
    cache_path = os.path.join(CACHE_DIR, "i386_glibc_2.35")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "i386", "i386_glibc_2.35"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.retsled(0x40)
    assert len(chain.payload_str()) == 0x40

    # x86_64
    cache_path = os.path.join(CACHE_DIR, "1after909")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "1after909"), auto_load_libs=False)
    rop = proj.analyses.ROP()

    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.retsled(0x40)
    assert len(chain.payload_str()) == 0x40

    # armel
    cache_path = os.path.join(CACHE_DIR, "armel_glibc_2.31")
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "armel", "libc-2.31.so"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, is_thumb=True)
    if os.path.exists(cache_path):
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets()
        rop.save_gadgets(cache_path)

    chain = rop.retsled(0x40)
    assert len(chain.payload_str()) == 0x40

def test_pop_pc_syscall_chain():
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "angrop_retn_test"), auto_load_libs=False)
    rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False)
    rop.find_gadgets_single_threaded(show_progress=False)

    chain1 = rop.do_syscall(3, [0])
    chain2 = rop.do_syscall(0x27, [0])
    final_chain = chain1 + chain2
    state = final_chain.exec()
    assert state.regs.rax.concrete_value == 1337
    assert 0 not in state.posix.fd

    chain = rop.do_syscall(3, [0])
    gadget = rop.analyze_gadget(0x0000000000401138) # pop rdi; ret
    chain.add_gadget(gadget)
    chain.add_value(0x41414141)
    state = chain.exec()
    assert state.regs.rdi.concrete_value == 0x41414141
    assert 0 not in state.posix.fd


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
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "mips", "mipstake"), auto_load_libs=True, arch="mips")
    rop = proj.analyses.ROP(max_block_size=40)

    chain = rop.func_call("sleep", [1, 2], needs_return=False)
    sleep_addr = proj.loader.main_object.imports['sleep'].value
    result_state = test_rop.execute_chain(proj, chain, sleep_addr)
    assert result_state.solver.eval(result_state.registers.load('a0'), cast_to=int) == 1
    assert result_state.solver.eval(result_state.registers.load('a1'), cast_to=int) == 2
    assert chain._gadgets[-1].transit_type == 'call_from_mem'


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
    proj = angr.Project(os.path.join(BIN_DIR, "tests", "x86_64", "unexploitable"), auto_load_libs=False, arch="x86_64")
    rop = proj.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False, )
    chain = rop.func_call("sleep", [1, 0xdeadbeefdeadbeef], needs_return=True)
    sleep_addr = proj.loader.main_object.imports['sleep'].value
    result_state = test_rop.execute_chain(proj, chain, sleep_addr)
    assert result_state.solver.eval(result_state.registers.load('rsi'), cast_to=int) == 0xdeadbeefdeadbeef
    assert result_state.solver.eval(result_state.registers.load('rdi'), cast_to=int) == 0x1
    assert chain._gadgets[-1].transit_type == 'call_from_mem'


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

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
