angrop
======

angrop is a rop gadget finder and chain builder

## Overview
angrop is a tool to automatically generate rop chains.

It is built on top of angr's symbolic execution engine, and uses constraint solving for generating chains and understanding the effects of gadgets.

angrop should support all the architectures supported by angr, although more testing needs to be done.

Typically, it can generate rop chains (especially long chains) faster than humans.

It includes functions to generate chains which are commonly used in exploitation and CTF's, such as setting registers, and calling functions.

## Usage

The ROP analysis finds rop gadgets and can automatically build rop chains.

```python
>>> import angr, angrop
>>> p = angr.Project("/bin/ls")
>>> rop = p.analyses.ROP()
>>> rop.find_gadgets()
>>> chain = rop.set_regs(rax=0x1337, rbx=0x56565656)
>>> chain.payload_str()
b'\xb32@\x00\x00\x00\x00\x007\x13\x00\x00\x00\x00\x00\x00\xa1\x18@\x00\x00\x00\x00\x00VVVV\x00\x00\x00\x00'
>>> chain.print_payload_code()
chain = b""
chain += p64(0x410b23)	# pop rax; ret
chain += p64(0x1337)
chain += p64(0x404dc0)	# pop rbx; ret
chain += p64(0x56565656)
```

## Chains
```python
# angrop includes methods to create certain common chains

# setting registers
chain = rop.set_regs(rax=0x1337, rbx=0x56565656)

# writing to memory 
# writes "/bin/sh\0" to address 0x61b100
chain = rop.write_to_mem(0x61b100, b"/bin/sh\0")

# calling functions
chain = rop.func_call("read", [0, 0x804f000, 0x100])

# adding values to memory
chain = rop.add_to_mem(0x804f124, 0x41414141)

# chains can be added together to chain operations
chain = rop.write_to_mem(0x61b100, b"/home/ctf/flag\x00") + rop.func_call("open", [0x61b100,os.O_RDONLY]) + ...

# chains can be printed for copy pasting into exploits
>>> chain.print_payload_code()
chain = b""
chain += p64(0x410b23)	# pop rax; ret
chain += p64(0x74632f656d6f682f)
chain += p64(0x404dc0)	# pop rbx; ret
chain += p64(0x61b0f8)
chain += p64(0x40ab63)	# mov qword ptr [rbx + 8], rax; add rsp, 0x10; pop rbx; ret
...

```

## Gadgets

Gadgets contain a lot of information:

For example look at how the following code translates into a gadget

```asm
   0x403be4:	and    ebp,edi
   0x403be6:	mov    QWORD PTR [rbx+0x90],rax
   0x403bed:	xor    eax,eax
   0x403bef:	add    rsp,0x10
   0x403bf3:	pop    rbx
   0x403bf4:	ret    
```

```python
>>> print(rop.gadgets[0])
Gadget 0x403be4
Stack change: 0x20
Changed registers: set(['rbx', 'rax', 'rbp'])
Popped registers: set(['rbx'])
Register dependencies:
    rbp: [rdi, rbp]
Memory write:
    address (64 bits) depends on: ['rbx']
    data (64 bits) depends on: ['rax']
```


The dependencies describe what registers affect the final value of another register. 
In the example above, the final value of rbp depends on both rdi and rbp.
Dependencies are analyzed for registers and for memory actions.
All of the information is stored as properties in the gadgets, so it is easy to iterate over them and find gadgets which fit your needs.

```python
>>> for g in rop.gadgets:
    if "rax" in g.popped_regs and "rbx" not in g.changed_regs:
        print(g)
Gadget 0x4032b3
Stack change: 0x10
Changed registers: set(['rax'])
Popped registers: set(['rax'])
Register dependencies:
```

## TODO's
Allow strings to be passed as arguments to func_call(), which are then written to memory and referenced.

Add a function for open, read, write (for ctf's)

Allow using of angr objects such as BVV, BVS to make using symbolic values easy

The segment analysis for finding executable addresses seems to break on non-elf binaries often, such as PE files, kernel modules.

Allow setting constraints on the generated chain e.g. bytes that are valid.

## Common gotchas
Make sure to import angrop before calling proj.analyses.ROP()

Make sure to call find_gadets() before trying to make chains
