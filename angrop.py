import logging
l = logging.getLogger('angrop')
l.setLevel(logging.INFO)

import angr
import pyvex
import simuvex
import archinfo
import progressbar

b = angr.Project("/bin/false")
initial_state = b.state_generator.blank_state(initial_prefix='start', add_options={simuvex.o.AVOID_MULTIVALUED_READS, simuvex.o.AVOID_MULTIVALUED_WRITES}, remove_options=simuvex.o.resilience_options | simuvex.o.simplification)
initial_state.regs.sp = 0xffff0000
initial_state.mem[initial_state.regs.sp:] = initial_state.se.BV("symbolic_stack", initial_state.arch.bits*20)

b_pystr = open("/lib/x86_64-linux-gnu/libc.so.6").read()
ffi = pyvex.ffi
b = ffi.new('char []', b_pystr)

arch = archinfo.ArchAMD64()
widgets = ['ROP: ', progressbar.Percentage(), ' ', progressbar.Bar(marker=progressbar.RotatingMarker()), ' ', progressbar.ETA(), ' ', progressbar.FileTransferSpeed()]
progress = progressbar.ProgressBar(widgets=widgets)

#total=1
for addr in xrange(b.ld.min_addr(), b.ld.max_addr()):
#for addr in progress(range(0, len(b) - 400)):
    l.debug("Analyzing 0x%x", addr)

    # first check if the block makes sense
    try:
        l.debug("... checking if block makes sense")
        block = b.block(addr)
        #block = pyvex.IRSB(b[addr:addr+400], 0x400000 + addr, arch)
        #block = pyvex.IRSB(bytes=b+addr, num_bytes=400, mem_addr=0x400000 + addr, arch=arch)
        #block.pp()
        if block.jumpkind == 'Ijk_NoDecode':
            l.debug("... not decodable")
            continue
        if any(isinstance(s, pyvex.IRStmt.Dirty) for s in block.statements):
            l.debug("... has dirties that we probably can't handle")
            continue
    except pyvex.PyVEXError:
        l.debug("... some pyvex")
        continue
    except (angr.AngrError, pyvex.PyVEXError):
        l.debug("... some other angr error")
        continue

    #total += 1
    #if total%100 == 0:
    #   print "A"
    #continue

    ss = initial_state.copy()
    ss.regs.ip = addr

    l.debug("... analyzing block")
    p = b.path_generator.blank_path(state=ss)
    if p.errored:
        l.debug("... error from simuvex")
        continue

    all_actions = sum([ s.actions for s in p.successors], [ ])
    regs_written = { p.state.arch.register_names[a.offset] for a in all_actions if a.type == 'reg' and a.action == 'write' and a.offset in p.state.arch.register_names }
    regs_used = { p.state.arch.register_names[a.offset] for a in all_actions if a.type == 'reg' and a.action == 'read' and a.offset in p.state.arch.register_names }

    l.info("... written: %s", regs_written)
    l.info("... used: %s", regs_written)
