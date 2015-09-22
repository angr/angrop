angrop
======

angrop is a rop gadget finder and chain builder

## Usage

The ROP analysis finds rop gadgets and can automatically build rop chains.

```python
>>> import angr
>>> import angrop
>>> p = angr.Project("some_pwnable")
>>> rop = p.analyses.ROP()
>>> rop.find_gadgets()
>>> chain = rop.set_regs(rax=0x1337, rbx=0x56565656)
>>> chain.payload_str()
'\xb32@\x00\x00\x00\x00\x007\x13\x00\x00\x00\x00\x00\x00\xa1\x18@\x00\x00\x00\x00\x00VVVV\x00\x00\x00\x00'
>>> chain.print_payload_code()
chain = ""
chain += p64(0x4032b3)
chain += p64(0x1337)
chain += p64(0x4018a1)
chain += p64(0x56565656)
>>> chain = rop.write_to_mem(0x41414141, "/bin/sh\0")
```

## Gadgets

Gadgets contain a lot of information:

For example look at how the following code translates into a gadget

```
   0x403be4:	and    ebp,edi
   0x403be6:	mov    QWORD PTR [rbx+0x90],rax
   0x403bed:	xor    eax,eax
   0x403bef:	add    rsp,0x10
   0x403bf3:	pop    rbx
   0x403bf4:	ret    
```

```python
>>> print rop.gadgets[0]
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
        print g
Gadget 0x4032b3
Stack change: 0x10
Changed registers: set(['rax'])
Popped registers: set(['rax'])
Register dependencies:
```

