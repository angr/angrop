# RiscyROP Usage

## z3 Memory Usage

Unfortunately there appears to be some kind of memory leak issue involving z3 that causes the memory usage to keep increasing during gadget finding.
With the latest z3 version the memory usage will increase to several GB per thread very quickly, but with older versions like 4.12.6.0 it's not as bad and the workaround I implemented that periodically restarts the worker processes is enough to keep the memory usage below 1.5 GB per thread.

## Finding Gadgets

Disable angrop's `fast_mode` setting when initializing the project, otherwise you will get very few gadgets.
The new gadget analyzer is a lot slower than angrop's original implementation.
You'll probably want to increase the number of processes from the default of 4, but make sure you have enough memory.
On my machine, it takes around 30 minutes to an hour to find gadgets in nginx and glibc with 16 processes.

```python
import angr, angrop
p = angr.Project("some_binary", auto_load_libs=False)
rop = p.analyses.ROP(fast_mode=False)
rop.find_gadgets(16)
```

Since gadget finding takes a while, you can save the gadgets and load them later so that you don't have to run the gadget finder again.

```python
rop.save_gadgets("gadgets")
rop.load_gadgets("gadgets")
```

## Chain Building

Building register setting chains should work well, but building other types of chains might not work since integration of the new algorithms with the existing angrop features isn't fully complete.
On large binaries like glibc the new algorithm can set most if not all of the argument registers.
You can set the `modifiable_memory_range` argument to a range of addresses that can be safely accessed.
This will allow the chain builder to use gadgets that access memory outside of the stack, and it will ensure that the addresses are within the given range.
The maximum chain length defaults to 10 gadgets, which might not be enough if the number of registers is large.

```python
chain = rop.set_regs(x0=1, x1=2, x2=3, x3=4, x4=5, x5=6, x6=7, x7=8, x30=42, modifiable_memory_range=(0x1000, 0x2000), max_length=15)
chain.print_gadget_asm()
chain.print_payload_code()
```

The address of the first gadget is placed at the beginning of the chain since all of the existing code assumes this is the case, but you might have to put it somewhere else depending on how you enter the chain.
For example, the initial gadget address would probably have to be placed further up the stack if return addresses are stored at the beginning of the stack frame instead of the end.
Similarly, the address that you want the last gadget to jump to might have to be placed somewhere in the middle of the chain instead of right after the chain.
`chain.next_pc_idx()` tells you which value in the chain should be replaced with the desired address if this is the case.

If things aren't working, you might want to enable debug logging:

```python
import logging
logging.getLogger('angrop.chain_builder.reg_setter').setLevel('DEBUG')
```

If the chain builder finds a sequence of gadgets that should work but it encounters an error when concretizing the chain, it will try a different sequence of gadgets.
However, this should rarely happen with the new algorithm.
