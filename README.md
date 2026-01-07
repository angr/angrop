angrop
======

angrop is a rop gadget finder and chain builder

## Overview
angrop is a tool to automatically generate rop chains.

It is built on top of angr's symbolic execution engine.
It uses symbolic execution to understand the effects of gadgets and uses constraint solving and graph search for generating chains.
Its design is architecture-agnostic so it supports multiple architectures.

Typically, it generate rop chains faster than humans.
In some cases, it can generate hard rop chains that may take humans hours to build within a few seconds.
Some examples can be found [here](examples).

It comes with a cli and a python api.
The command line `angrop-cli` offers some basic gadget finding/chaining capability such as finding an `system`/`execve` chain or invoking a specific function.
The `angrop` python api offers the full features.
Details can be found in [Usage](README.md#usage).

`angrop` does not just only works for userspace binaries, it works for the Linux kernel as well.

## Architectures
Supported architectures:
* x86/x64
* MIPS
* ARM
* AArch64
* RISC-V (64bit)

It should be relatively easy to support other architectures that are supported by `angr`.
If you'd like to use `angrop` on other architectures, please create an issue and we will look into it :)

## Usage

You can use either the CLI or the Python API.
The CLI only offers some basic functionalities while the Python API provides much more capabilities and is much more powerful.

## CLI
angrop comes with a command line tool for easy day-to-day usage
```bash
# dump command will find gadgets in the target binary, true/false marks whether the gadget is self-contained
$ angrop-cli dump /bin/ls
0x11735: true  : adc bl, byte ptr [rbx + 0x4c]; mov eax, esp; pop r12; pop r13; pop r14; pop rbp; ret 
0x10eaa: true  : adc eax, 0x12469; add rsp, 0x38; pop rbx; pop r12; pop r13; pop r14; pop r15; pop rbp; ret 
00xe026: true  : adc eax, 0xcec8; pop rbx; cmove rax, rdx; pop r12; pop rbp; ret 
00xdfd4: true  : adc eax, 0xcf18; pop rbx; cmove rax, rdx; pop r12; pop rbp; ret 
00xdfa5: true  : adc eax, 0xcf4d; pop rbx; cmove rax, rdx; pop r12; pop rbp; ret 
......

# chain command will find some predefined chains in the binary
$ angrop-cli chain -t execve /bin/bash
code_base = 0x0
chain = b""
chain += p64(code_base + 0x36083)	# pop rax; pop rbx; pop rbp; ret 
chain += p64(code_base + 0x30016)	# add rsp, 8; ret 
chain += p64(code_base + 0x34873)
chain += p64(code_base + 0x0)
chain += p64(code_base + 0x9616d)	# mov edx, ebp; mov rsi, r12; mov rdi, rbx; call rax
chain += p64(code_base + 0xe501e)	# pop rsi; ret 0
chain += p64(code_base + 0x0)
chain += p64(code_base + 0x31470)	# execve@plt
chain += p64(0x0)
chain += p64(code_base + 0x10d5bf)
```

## Python API
```python
>>> import angr, angrop
>>> p = angr.Project("/bin/ls")
>>> rop = p.analyses.ROP()
>>> rop.find_gadgets()
>>> chain = rop.set_regs(rax=0x41414141, rbx=0x42424242)
>>> chain.print_payload_code()
code_base = 0x0
chain = b""
chain += p64(code_base + 0xf5e2)	# pop rbx; pop r12; test eax, eax; pop rbp; cmovs eax, edx; ret 
chain += p64(0x42424242)
chain += p64(0x0)
chain += p64(0x0)
chain += p64(code_base + 0x812f)	# pop rsi; pop rbp; ret 
chain += p64(0x41414141)
chain += p64(0x0)
chain += p64(code_base + 0x169dd)	# mov rax, rsi; ret 
chain += p64(code_base + 0x10a55)
```
More detailed docs on the Python API can be found [here](docs/pythonapi.md).

## Demo

### gadget finding
![gadget](gifs/find_gadget.gif?raw=true)

### find execve chain
![execve](gifs/execve.gif?raw=true)

### container escape chain for the kernel
![kernel](gifs/kernel.gif?raw=true)

## Paper
We describe our design and findings in this paper

[__ropbot: Reimaging Code Reuse Attack Synthesis__](https://kylebot.net/papers/ropbot.pdf)

Kyle Zeng, Moritz Schloegel, Christopher Salls, Adam Doupé, Ruoyu Wang, Yan Shoshitaishvili, Tiffany Bao

*In Proceedings of the Network and Distributed System Security Symposium (NDSS), February 2026*,
