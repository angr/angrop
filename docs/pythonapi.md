# Python API

## Configuration
```python
proj = angr.Project(<binary_path>)
rop = proj.analyses.ROP(<configs>)
```
common configs:
* `only_check_near_rets`: If true we skip blocks that are not near rets, default is true
* `max_block_size`: the maximum size of each basic block to consider, the default [varies by arch](https://github.com/angr/angrop/blob/master/angrop/arch.py#L41)
* `kernel_mode`: is the target linux kernel, default is false
* `fast_mode`: true/false, if set to None makes a decision based on the size of the binary (default is None). If True, skip gadgets with conditonal\_branches, floating point operations, jumps, and allow smaller gadget size

## Find Gadgets
```
# find gadgets using multiprocessing
rop.find_gadgets(<parameters>) 

# find gadgets using single thread, good for performance evaluation
rop.find_gadgets_single_threaded(<parameters>)
```
common parameters:
* `optimize`: whether to perform graph optimization after finishing finding gadgets. It can save time when you only want to find gadgets 
* `processes`: the number of processes for multiprocessing, the default is 4
* `show_progress`: whether to show the progress bar, default is true

## Basic Usage

```python
# angrop includes methods to create certain common chains

# setting registers
chain = rop.set_regs(rax=0x1337, rbx=0x56565656)

# moving registers
chain = rop.move_regs(rax='rdx')

# changing memory content
chain = rop.mem_add(0x804f124, 0x41414141)
chain = rop.mem_xor(0x804f124, 0x41414141)
chain = rop.mem_or(0x804f124, 0x41414141)
chain = rop.mem_and(0x804f124, 0x41414141)

# writing to memory 
# writes "/bin/sh\0" to address 0x61b100
chain = rop.write_to_mem(0x61b100, b"/bin/sh\0")

# find stack pivoting chain, the argument can be a register or an address
chain = rop.pivot('rax')
chain = rop.pivot(0x41414140)

# calling functions
chain = rop.func_call("read", [0, 0x804f000, 0x100])

# invoke syscall with arguments
chain = rop.do_syscall(0, [0, 0x41414141, 0x100], needs_return=False)

# sigreturn (SROP) chain
# example: set rip/rsp and registers via sigreturn frame
chain = rop.sigreturn(rip=0x401000, rsp=0x7fffffffe000, rax=59, rdi=0x41414141)

# generate an `execve("/bin/sh", NULL, NULL)` chain
chain = rop.execve()

# shifting stack pointer like add rsp, 0x8; ret (this gadget shifts rsp by 0x10)
chain = rop.shift(0x10)

# generating ret-sled chains like ret*0x10, but works for ARM/MIPS as well
chain = rop.retsled(0x40)

# bad bytes can be specified to generate chains with no bad bytes
rop.set_badbytes([0x0, 0x0a])
chain = rop.set_regs(eax=0)

# chains can be added together to chain operations
chain = rop.write_to_mem(0x61b100, b"/home/ctf/flag\x00") + rop.func_call("open", [0x61b100, os.O_RDONLY]) + ...

# chains can be printed for copy pasting into exploits
>>> chain.print_payload_code()
chain = b""
chain += p64(0x410b23)	# pop rax; ret
chain += p64(0x74632f656d6f682f)
chain += p64(0x404dc0)	# pop rbx; ret
chain += p64(0x61b0f8)
chain += p64(0x40ab63)	# mov qword ptr [rbx + 8], rax; add rsp, 0x10; pop rbx; ret
...

# chains can be pretty-printed for debugging
>>> chain.pp()
0x0000000000034573: pop rcx; ret 
                    0x61b0f8
0x000000000004a1dd: pop rdi; mov edx, 0x89480002; ret 
                    0x68732f6e69622f
0x00000000000d5a94: mov qword ptr [rcx + 8], rdi; ret 
                    <BV64 next_pc_1081_64>
```

## Advanced Usage

* register as an argument
If you want to directly use a register for an argument, you can do it like this:
~~~
[ins] In [3]: rop.func_call("prepare_kernel_cred", (0x41414141, 0x42424242), preserve_regs={'rdi'}).pp()
0xffffffff81489752: pop rsi; ret 
                    0x42424242
0xffffffff8114d660: <prepare_kernel_cred>
                    <BV64 next_pc_4280_64>
~~~
Here, since we tell it to preserve the `rdi` register, it will overrule the `0x41414141` argument and ignore it.
