import os

import angr
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
