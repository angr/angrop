import os
import re
import time
import signal
import logging
import multiprocessing as mp
from functools import partial

import tqdm
import psutil

from angr.errors import SimEngineError, SimMemoryError
from angr.misc.loggers import CuteFormatter

from . import gadget_analyzer
from ..arch import get_arch, RISCV64
from ..arch import ARM, X86, AMD64, AARCH64

l = logging.getLogger(__name__)

logging.getLogger('pyvex.lifting').setLevel("ERROR")

ANALYZE_GADGET_TIMEOUT = 3
_global_gadget_analyzer = None
_global_skip_cache = None
_global_cache = None
_global_init_rss = None

# disable loggers in each worker
def _disable_loggers():
    for handler in logging.root.handlers:
        if type(handler.formatter) == CuteFormatter:
            logging.root.removeHandler(handler)
            return

# global initializer for multiprocessing
def _set_global_gadget_analyzer(rop_gadget_analyzer):
    global _global_gadget_analyzer, _global_skip_cache, _global_cache, _global_init_rss # pylint: disable=global-statement
    _global_gadget_analyzer = rop_gadget_analyzer
    _global_skip_cache = set()
    _global_cache = {}
    _disable_loggers()
    process = psutil.Process()
    _global_init_rss = process.memory_info().rss

def handler(signum, frame):
    l.warning("[angrop] worker_func2 times out, exit the worker process!")
    os._exit(0)

def worker_func1(slice):
    analyzer = _global_gadget_analyzer
    res = list(GadgetFinder._addresses_from_slice(analyzer, slice, _global_skip_cache, _global_cache, None))
    return (slice[1]-slice[0]+1, res)

def worker_func2(addr, cond_br=None):
    analyzer = _global_gadget_analyzer
    signal.signal(signal.SIGALRM, handler)

    signal.alarm(ANALYZE_GADGET_TIMEOUT)
    if cond_br is None:
        res = analyzer.analyze_gadget(addr)
    else:
        res = analyzer.analyze_gadget(addr, allow_conditional_branches=cond_br)
    signal.alarm(0)

    if not res:
        # HACK: we are seeing some very bad memory leak situation, restart the worker
        process = psutil.Process()
        rss = process.memory_info().rss
        if rss - _global_init_rss > 500*1024*1024:
            l.warning("[angrop] worker_func2 encounters memory leak, exit the worker process!")
            os._exit(0)

    if res is None:
        return []
    if isinstance(res, list):
        return res
    return [res]

class GadgetFinder:
    """
    a class to find ROP gadgets
    """
    def __init__(self, project, fast_mode=None, only_check_near_rets=True, max_block_size=None,
                 max_sym_mem_access=None, is_thumb=False, kernel_mode=False, stack_gsize=80,
                 cond_br=False, max_bb_cnt=2):
        # configurations
        self.project = project
        self.fast_mode = fast_mode
        self.arch = get_arch(self.project, kernel_mode=kernel_mode)
        self.only_check_near_rets = only_check_near_rets
        self.kernel_mode = kernel_mode
        self.stack_gsize = stack_gsize
        self.cond_br = cond_br
        self.max_bb_cnt = max_bb_cnt

        if only_check_near_rets and not isinstance(self.arch, (X86, AMD64, AARCH64)):
            l.warning("only_check_near_rets only makes sense for i386/amd64/aarch64, setting it to False")
            self.only_check_near_rets = False

        # override parameters
        if max_block_size:
            self.arch.max_block_size = max_block_size
        if max_sym_mem_access:
            self.arch.max_sym_mem_access = max_sym_mem_access
        if is_thumb:
            assert isinstance(self.arch, ARM), "is_thumb is only compatible with ARM binaries!"
            arch: ARM = self.arch
            arch.set_thumb()

        # internal stuff
        self._ret_locations: list = None # type: ignore
        self._syscall_locations: list = None # type: ignore
        # cache seen blocks, dict(block_hash => sets of addresses)
        self._cache: dict = None # type: ignore
        self._gadget_analyzer: gadget_analyzer.GadgetAnalyzer = None # type: ignore
        self._executable_ranges = None

        # silence annoying loggers
        logging.getLogger('angr.engines.vex.ccall').setLevel(logging.CRITICAL)
        logging.getLogger('angr.engines.vex.expressions.ccall').setLevel(logging.CRITICAL)
        logging.getLogger('angr.engines.vex.irop').setLevel(logging.CRITICAL)
        logging.getLogger('pyvex.lifting.libvex').setLevel(logging.CRITICAL)
        logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.CRITICAL)
        logging.getLogger('angr.state_plugins.posix').setLevel(logging.CRITICAL)
        logging.getLogger('angr.procedures').setLevel(logging.CRITICAL)

    @property
    def gadget_analyzer(self):
        if self._gadget_analyzer is not None:
            return self._gadget_analyzer
        self._initialize_gadget_analyzer()
        return self._gadget_analyzer

    def _initialize_gadget_analyzer(self):

        if self.kernel_mode or not self.only_check_near_rets:
            self._syscall_locations = []
        else:
            self._syscall_locations = self._get_syscall_locations()

        # find locations to analyze
        if self.only_check_near_rets and not self._ret_locations:
            self._ret_locations = self._get_ret_locations()
        num_to_check = self._num_addresses_to_check()

        # fast mode
        if self.fast_mode is None:
            if num_to_check > 20000:
                self.fast_mode = True
                l.warning("Enabling fast mode for large binary")
            else:
                self.fast_mode = False
        if self.fast_mode:
            self.arch.max_block_size = self.arch.fast_mode_max_block_size
            self.arch.max_sym_mem_access = 1
            # Recalculate num addresses to check based on fast_mode settings
            num_to_check = self._num_addresses_to_check()

        l.info("There are %d addresses within %d bytes of a ret",
               num_to_check, self.arch.max_block_size)

        self._gadget_analyzer = gadget_analyzer.GadgetAnalyzer(self.project, self.fast_mode, arch=self.arch,
                                                               kernel_mode=self.kernel_mode, stack_gsize=self.stack_gsize,
                                                               cond_br=self.cond_br, max_bb_cnt=self.max_bb_cnt)

    def analyze_gadget(self, addr, allow_conditional_branches=None):
        g = self.gadget_analyzer.analyze_gadget(addr, allow_conditional_branches=allow_conditional_branches)
        if isinstance(g, list):
            for x in g:
                x.project = self.project
        elif g:
            g.project = self.project
        return g

    def _truncated_slices(self):
        for slice in self._slices_to_check():
            size = slice[1] - slice[0] + 1
            if size <= 0x100:
                yield slice
                continue
            while slice[1] - slice[0] + 1 > 0x100:
                new = (slice[0], slice[0]+0xff)
                slice = (slice[0]+0x100, slice[1])
                yield new
            yield slice

    def _multiprocess_static_analysis(self, processes, show_progress, timeout):
        """
        use multiprocessing to build the cache
        """
        start = time.time()
        task_len = self._num_addresses_to_check()
        todos = []

        t = None
        if show_progress:
            t = tqdm.tqdm(smoothing=0, total=task_len, desc="ROP", maxinterval=0.5, dynamic_ncols=True)

        initargs = (self.gadget_analyzer,)
        with mp.Pool(processes=processes, initializer=_set_global_gadget_analyzer, initargs=initargs) as pool:
            for n, results in pool.imap_unordered(worker_func1, self._truncated_slices(), chunksize=40):
                if t:
                    t.update(n)
                for addr, h in results:
                    if addr is None:
                        continue
                    if h:
                        if h in self._cache:
                            self._cache[h].add(addr)
                        else:
                            self._cache[h] = {addr}
                            todos.append(addr)
                    else:
                        todos.append(addr)
                if timeout is not None and time.time() - start > timeout:
                    break

        remaining = None
        if timeout is not None:
            remaining = timeout - (time.time() - start)
        return todos, remaining

    def _analyze_gadgets_multiprocess(self, processes, tasks, show_progress, timeout, cond_br):
        gadgets = []
        start = time.time()

        # select the target function
        if cond_br is not None:
            func = partial(worker_func2, cond_br=cond_br)
        else:
            func = worker_func2

        # the progress bar
        t = None
        if show_progress:
            t = tqdm.tqdm(smoothing=0, total=len(tasks), desc="ROP", maxinterval=0.5, dynamic_ncols=True)

        # prep for the main loop
        sync_data = [time.time(), 0]
        def on_success(gs):
            gadgets.extend(gs)
            if t:
                t.update(1)
            sync_data[0] = time.time()
            sync_data[1] += 1

        # the main loop
        initargs = (self.gadget_analyzer,)
        with mp.Pool(processes=processes, initializer=_set_global_gadget_analyzer, initargs=initargs) as pool:
            for addr in tasks:
                pool.apply_async(func, args=(addr,), callback=on_success)
            pool.close()

            def should_continue():
                if sync_data[1] == len(tasks):
                    return False
                if sync_data[1] > len(tasks)*0.8:
                    return time.time() - sync_data[0] < ANALYZE_GADGET_TIMEOUT
                return time.time() - sync_data[0] < ANALYZE_GADGET_TIMEOUT*5

            while should_continue():
                if timeout and time.time() - start > timeout:
                    break
                time.sleep(0.1)

            pool.terminate()
        if t is not None:
            t.close()

        for g in gadgets:
            g.project = self.project

        return sorted(gadgets, key=lambda x: x.addr)

    def analyze_gadget_list(self, addr_list, processes=4, show_progress=True):
        return self._analyze_gadgets_multiprocess(processes, addr_list, show_progress, None, False)

    def get_duplicates(self):
        """
        return duplicates that have been seen at least twice
        """
        cache = self._cache
        return {k:v for k,v in cache.items() if len(v) >= 2}

    def find_gadgets(self, processes=4, show_progress=True, timeout=None):
        assert self.gadget_analyzer is not None
        self._cache = {}
        timeout1 = timeout/2 if timeout is not None else None
        tasks, remaining = self._multiprocess_static_analysis(processes, show_progress, timeout1)
        timeout = remaining+timeout/2 if timeout is not None else None
        return self._analyze_gadgets_multiprocess(processes, tasks, show_progress, timeout, None), self.get_duplicates()

    def find_gadgets_single_threaded(self, show_progress=True):
        gadgets = []
        self._cache = {}

        assert self.gadget_analyzer is not None

        for addr in self._addresses_to_check_with_caching(show_progress):
            res = self.gadget_analyzer.analyze_gadget(addr)
            if res is None:
                continue
            if isinstance(res, list):
                gadgets.extend(res)
                continue
            gadgets.append(res)

        for g in gadgets:
            g.project = self.project

        return sorted(gadgets, key=lambda x: x.addr), self.get_duplicates()

    #### generate addresses from slices ####
    @staticmethod
    def _addr_block_in_cache(analyzer, loc, skip_cache, cache):
        """
        To avoid loading the block, we first check if the data that we would
        disassemble is already in the cache first
        """
        data = analyzer.project.loader.memory.load(loc, analyzer.arch.max_block_size)
        align = analyzer.arch.alignment
        for i in range(align, len(data)+1, align):
            h = data[0:i]
            if h in skip_cache or h in cache:
                return True
        return False

    @staticmethod
    def _addresses_from_slice(analyzer, slice, skip_cache, cache, it):
        offset = 1 if isinstance(analyzer.arch, ARM) and analyzer.arch.is_thumb else 0
        alignment = analyzer.arch.alignment
        max_block_size = analyzer.arch.max_block_size

        def do_update():
            if it is not None:
                it.update(1)

        skip_addrs = set()
        simple_cache = set()
        for addr in range(slice[0], slice[1]+1, alignment):
            # when loading from memory, use loc
            # when calling block, use addr
            loc = addr
            addr += offset # this is the actual address

            if addr in skip_addrs:
                do_update()
                continue

            if GadgetFinder._addr_block_in_cache(analyzer, loc, skip_cache, cache):
                do_update()
                continue

            try:
                bl = analyzer.project.factory.block(addr, skip_stmts=True, max_size=analyzer.arch.max_block_size+0x10)
            except (SimEngineError, SimMemoryError):
                do_update()
                continue
            # check size
            if bl.size > max_block_size:
                for ins_addr in bl.instruction_addrs:
                     size = bl.size-(ins_addr-addr)
                     if size > max_block_size:
                         skip_addrs.add(ins_addr)
                do_update()
                continue
            # check jumpkind
            jumpkind = bl.vex_nostmt.jumpkind
            if jumpkind == 'Ijk_NoDecode':
                do_update()
                continue
            if jumpkind in ('Ijk_SigTRAP', 'Ijk_Privileged', 'Ijk_Yield'):
                for ins_addr in bl.instruction_addrs:
                    bad = bl.bytes[ins_addr-addr:]
                    skip_cache.add(bad)
                    skip_addrs.add(ins_addr)
                do_update()
                continue
            if analyzer._fast_mode and jumpkind not in ("Ijk_Ret", "Ijk_Boring") and not jumpkind.startswith('Ijk_Sys_'):
                for ins_addr in bl.instruction_addrs:
                    bad = bl.bytes[ins_addr-addr:]
                    skip_cache.add(bad)
                    skip_addrs.add(ins_addr)
                do_update()
                continue
            # check conditional jumps
            if not analyzer._allow_conditional_branches and len(bl.vex_nostmt.constant_jump_targets) > 1:
                for ins_addr in bl.instruction_addrs:
                    bad = bl.bytes[ins_addr-addr:]
                    skip_cache.add(bad)
                    skip_addrs.add(ins_addr)
                do_update()
                continue
            # make sure all the jump targets are valid
            valid = True
            for target in bl.vex_nostmt.constant_jump_targets:
                if analyzer.project.loader.find_segment_containing(target) is None:
                    valid = False
            if not valid:
                for ins_addr in bl.instruction_addrs:
                    skip_addrs.add(ins_addr)
                do_update()
                continue

            # it doesn't make sense to include a gadget that starts with a jump or call
            # the jump target itself will be the gadget
            if bl.vex_nostmt.instructions == 1 and jumpkind in ('Ijk_Boring', 'Ijk_Call'):
                do_update()
                continue

            ####### use vex ########
            if not analyzer._block_make_sense_vex(bl) or not analyzer._block_make_sense_sym_access(bl) or not analyzer.arch.block_make_sense(bl):
                do_update()
                continue
            if not bl.capstone.insns and not isinstance(analyzer.arch, RISCV64):
                do_update()
                continue

            # we only analyze simple gadgets once
            h = None
            if addr in simple_cache or analyzer._is_simple_gadget(addr, bl):
                # if a block is simple, all aligned sub blocks are simple
                for ins_addr in bl.instruction_addrs:
                    simple_cache.add(ins_addr)
                h = analyzer.block_hash(bl)
                if h not in cache:
                    cache[h] = {addr}
                else:
                    cache[h].add(addr)
            elif jumpkind.startswith("Ijk_Sys_"):
                h = analyzer.block_hash(bl)
            else:
                s = ''
                for insn in bl.capstone2.insns:
                    s += insn.mnemonic + '\t' + insn.op_str + '\n'
                h = hash(s)
            do_update()
            yield addr, h

    def _addresses_to_check_with_caching(self, show_progress=True):
        """
        The goal of this function is to do a fast check of the block
        only jumpkind, jump targets check and cache the result to avoid the need of symbolically
        analyzing a ton of gadget candidates
        """
        num_addrs = self._num_addresses_to_check()

        it = None
        if show_progress:
            it = tqdm.tqdm(smoothing=0, total=num_addrs,
                           desc="ROP", maxinterval=0.5, dynamic_ncols=True)
        self._cache = {}
        skip_cache = set() # bytes to skip
        for slice in self._slices_to_check():
            for addr, _ in self._addresses_from_slice(self.gadget_analyzer, slice, skip_cache, self._cache, it):
                yield addr

    def block_hash(self, block):
        """
        a hash to uniquely identify a simple block
        """
        if block.vex.jumpkind.startswith('Ijk_Sys_'):
            next_addr = block.addr + block.size
            obj = self.project.loader.find_object_containing(next_addr)
            if not obj:
                return block.bytes
            next_block = self.project.factory.block(next_addr)
            return block.bytes + next_block.bytes
        return block.bytes

    #### generate slices to analyze ####
    def _get_executable_ranges(self):
        """
        returns the ranges which are executable
        """
        if self._executable_ranges is not None:
            return self._executable_ranges

        # For kernel_mode we use .text if we can find it
        if self.kernel_mode:
            for section in self.project.loader.main_object.sections:
                if section.name == ".text":
                    self._executable_ranges = [section]
                    return self._executable_ranges

        # use segments otherwise
        executable_segments = []
        for segment in self.project.loader.main_object.segments:
            if segment.is_executable:
                executable_segments.append(segment)
        self._executable_ranges = executable_segments
        return self._executable_ranges

    def _addr_in_executable_memory(self, addr):
        """
        :return: is the address in executable memory
        """
        executable_ranges = self._get_executable_ranges()
        for r in executable_ranges:
            if r.contains_addr(addr):
                return True
        return False

    def _find_executable_range(self, addr):
        for r in self._get_executable_ranges():
            if r.contains_addr(addr):
                return r
        return None

    def _get_slice_by_addr(self, addr, blocksize):
        start = addr - blocksize
        end = addr
        seg = self._find_executable_range(addr)
        assert seg is not None
        start = max(start, seg.min_addr)
        return (start, end)

    @staticmethod
    def merge_slices(slices):
        """
        generate a list of slices that don't overlap
        """
        if not slices:
            return []

        # sort by start of each slice
        slices.sort(key=lambda x: x[0])

        merged = [slices[0]]
        for current in slices[1:]:
            last = merged[-1]
            if current[0] <= last[1]: # overlapping
                merged[-1] = (last[0], max(last[1], current[1])) # merge
            else:
                merged.append(current)
        return merged

    def _slices_to_check(self, do_sort=True):
        """
        :return: all the slices to check, slice is inclusive: [start, end]
        """
        alignment = self.arch.alignment
        blocksize = (self.arch.max_block_size & ((1 << self.project.arch.bits) - alignment)) + alignment

        if self.only_check_near_rets:
            slices = []
            if not self.arch.kernel_mode and self._syscall_locations:
                slices += [self._get_slice_by_addr(addr, blocksize) for addr in self._syscall_locations]
            if self._ret_locations:
                slices += [self._get_slice_by_addr(addr, blocksize) for addr in self._ret_locations]

            # avoid decoding one address multiple times
            slices = self.merge_slices(slices)
            if not do_sort:
                yield from slices
                return

            # prioritize syscalls, so we still have syscall gadgets even if we timeout during gadget analysis
            start = time.time()
            syscall_locations = sorted(list(self._syscall_locations))
            slices1 = []
            for s in slices:
                if not syscall_locations:
                    break
                loc = syscall_locations[0]
                if s[0] <= loc <= s[1]:
                    slices1.append(s)
                    for idx in range(1, len(syscall_locations)):
                        if s[0] <= syscall_locations[idx] <= s[1]:
                            continue
                        break
                    else:
                        break
                    syscall_locations = syscall_locations[idx:]
            slices2 = [s for s in slices if s not in slices1]

            yield from slices1 + slices2
        else:
            for segment in self._get_executable_ranges():
                start = alignment * ((segment.min_addr + alignment - 1) // alignment)
                end = segment.min_addr + segment.memsize
                end -= end % alignment
                end -= alignment # a slice is inclusive
                yield (start, end)

    def _num_addresses_to_check(self):
        cnt = 0
        for slice in self._slices_to_check(do_sort=False):
            cnt += slice[1] - slice[0] + 1
        return cnt

    #### identify ret/syscall locations ####
    def _get_ret_locations(self):
        """
        :return: all the locations in the binary with a ret instruction
        """

        if self.arch.ret_insts:
            return self._get_locations_by_strings(self.arch.ret_insts)

        l.warning("Only have ret strings for i386/amd64/aarch64/riscv, now start the slow path for identifying gadgets end with 'ret'")

        addrs = []
        seen = set()
        for segment in self._get_executable_ranges():
            alignment = self.arch.alignment
            min_addr = segment.min_addr + (alignment - segment.min_addr % alignment)

            # iterate through the code looking for rets
            for addr in range(min_addr, segment.max_addr, alignment):
                # dont recheck addresses we've seen before
                if addr in seen:
                    continue
                try:
                    block = self.project.factory.block(addr)
                    # if it has a ret get the return address
                    if block.vex.jumpkind.startswith("Ijk_Ret"):
                        ret_addr = block.instruction_addrs[-1]
                        # hack for mips pipelining
                        if self.project.arch.linux_name.startswith("mips"):
                            ret_addr = block.instruction_addrs[-2]
                        if ret_addr not in seen:
                            addrs.append(ret_addr)
                    # save the addresses in the block
                    seen.update(block.instruction_addrs)
                except (SimEngineError, SimMemoryError):
                    pass

        return sorted(addrs)

    def _get_syscall_locations(self):
        """
        uses a string filter to find all the system calls instructions
        :return: all the locations in the binary with a system call instruction
        """
        if not self.arch.syscall_insts:
            l.warning("Only have syscall strings for i386/amd64/mips, fail to identify syscall strings")
            return []
        return self._get_locations_by_strings(self.arch.syscall_insts)

    def _get_locations_by_strings(self, strings):
        fmt = b'(' + b')|('.join(strings) + b')'

        addrs = []
        for segment in self._get_executable_ranges():
            read_bytes = self.project.loader.memory.load(segment.min_addr, segment.memsize)
            # find all occurrences of the ret_instructions
            addrs += [segment.min_addr + m.start() for m in re.finditer(fmt, read_bytes)]
        return sorted(addrs)
