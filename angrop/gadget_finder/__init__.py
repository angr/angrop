import re
import time
import signal
import logging
from functools import partial
import multiprocessing as mp

import tqdm

from angr.errors import SimEngineError, SimMemoryError
from angr.misc.loggers import CuteFormatter

from . import gadget_analyzer
from ..arch import get_arch
from ..errors import RopException
from ..arch import ARM, X86, AMD64, AARCH64

l = logging.getLogger(__name__)

logging.getLogger('pyvex.lifting').setLevel("ERROR")

ANALYZE_GADGET_TIMEOUT = 3

_global_gadget_analyzer: gadget_analyzer.GadgetAnalyzer = None # type: ignore

# disable loggers in each worker
def _disable_loggers():
    for handler in logging.root.handlers:
        if type(handler.formatter) == CuteFormatter:
            logging.root.removeHandler(handler)
            return

# global initializer for multiprocessing
def _set_global_gadget_analyzer(rop_gadget_analyzer):
    global _global_gadget_analyzer # pylint: disable=global-statement
    _global_gadget_analyzer = rop_gadget_analyzer
    _disable_loggers()

def run_worker(addr, allow_cond_branch=None):
    if allow_cond_branch is None:
        res = _global_gadget_analyzer.analyze_gadget(addr)
    else:
        res = _global_gadget_analyzer.analyze_gadget(addr, allow_conditional_branches=allow_cond_branch)
    if res is None:
        return []
    if isinstance(res, list):
        return res
    return [res]

def handler(signum):
    print("triggered!!!!")
    print("exit!!!")
    exit()

def worker_func(analyzer, task_queue, result_queue, cond_br=None):
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(ANALYZE_GADGET_TIMEOUT)
    cnt = 0
    while not task_queue.empty() and cnt < 200:
        addr = task_queue.get()
        cnt += 1

        signal.alarm(ANALYZE_GADGET_TIMEOUT)
        if cond_br is None:
            res = analyzer.analyze_gadget(addr)
        else:
            res = analyzer.analyze_gadget(addr, allow_conditional_branches=cond_br)
        signal.alarm(0)
        if res is None:
            res = []
        if not isinstance(res, list):
            res = [res]

        h = None
        bl = analyzer.project.factory.block(addr)
        if analyzer._is_simple_gadget(addr, bl):
            h = analyzer.block_hash(bl)
        result_queue.put((res, h))

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

        if self.kernel_mode:
            self._syscall_locations = []
        else:
            self._syscall_locations = self._get_syscall_locations_by_string()

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

    def _collect_results(self, t, result_queue):
        gadgets = []
        cnt = 0
        while not result_queue.empty() and cnt < 200:
            new_gadgets, h = result_queue.get()
            if t:
                t.update(1)
            cnt += 1
            gadgets += new_gadgets
        return gadgets

    def _analyze_gadgets_multiprocess(self, processes, tasks, show_progress, timeout, cond_br):
        gadgets = []
        self._cache = {}

        # prepare queues
        task_queue = mp.Queue()
        result_queue = mp.Queue()

        # select the target function
        if cond_br is not None:
            func = partial(worker_func, cond_br=cond_br)
        else:
            func = worker_func

        # launch the subprocesses
        procs = []
        for _ in range(processes):
            proc = mp.Process(target=func, args=(self.gadget_analyzer, task_queue, result_queue))
            procs.append(proc)

        # put in all the tasks
        for addr in tasks:
            task_queue.put(addr)

        t = None
        if show_progress:
            t = tqdm.tqdm(smoothing=0, total=task_queue.qsize(), desc="ROP", maxinterval=0.5, dynamic_ncols=True)

        # launch all subprocesses
        for proc in procs:
            proc.start()

        # now do the main loop
        while not task_queue.empty() or not result_queue.empty():
            # check worker status
            for idx, p in enumerate(procs):
                if p.is_alive():
                    continue
                procs[idx] = mp.Process(target=func, args=(self.gadget_analyzer, task_queue, result_queue))
                procs[idx].start()

            gadgets += self._collect_results(t, result_queue)

        # now wait for all the tasks to finish
        for proc in procs:
            if proc.is_alive():
                proc.join(timeout=0.5)
                proc.terminate()
                if proc.is_alive():
                    proc.kill()

        # harvest whatever is still in there
        gadgets += self._collect_results(t, result_queue)

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
        iterable = self._addresses_to_check()
        return self._analyze_gadgets_multiprocess(processes, iterable, show_progress, timeout, None), self.get_duplicates()

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

    def _addresses_to_check_with_caching(self, show_progress=True):
        num_addrs = self._num_addresses_to_check()

        iterable = self._addresses_to_check()
        if show_progress:
            iterable = tqdm.tqdm(iterable=iterable, smoothing=0, total=num_addrs,
                                 desc="ROP", maxinterval=0.5, dynamic_ncols=True)

        for a in iterable:
            try:
                bl = self.project.factory.block(a)
                if bl.size > self.arch.max_block_size:
                    continue
            except (SimEngineError, SimMemoryError):
                continue
            if self._gadget_analyzer._is_simple_gadget(a, bl):
                h = self.block_hash(bl)
                if h not in self._cache:
                    self._cache[h] = {a}
                else:
                    # we only return the first unique gadget
                    # so skip duplicates
                    self._cache[h].add(a)
                    continue
            yield a

    def block_hash(self, block):
        """
        a hash to uniquely identify a simple block
        """
        if block.vex.jumpkind == 'Ijk_Sys_syscall':
            next_addr = block.addr + block.size
            obj = self.project.loader.find_object_containing(next_addr)
            if not obj:
                return block.bytes
            next_block = self.project.factory.block(next_addr)
            return block.bytes + next_block.bytes
        return block.bytes

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

    def _addresses_to_check(self):
        """
        :return: all the addresses to check
        """
        # align block size
        seen_addrs = set()
        alignment = self.arch.alignment
        offset = 1 if isinstance(self.arch, ARM) and self.arch.is_thumb else 0

        # step 1: check syscall locations
        if not self.arch.kernel_mode and self._syscall_locations:
            for addr in self._syscall_locations:
                seen_addrs.add(addr+offset)
                yield addr+offset

        # step 2: check gadgets near rets
        if self._ret_locations:
            block_size = (self.arch.max_block_size & ((1 << self.project.arch.bits) - alignment)) + alignment
            slices = [(addr-block_size, addr) for addr in self._ret_locations]
            current_addr = 0
            for st, _ in slices:
                current_addr = max(current_addr, st)
                end_addr = st + block_size + alignment
                for i in range(current_addr, end_addr, alignment):
                    if i+offset in seen_addrs:
                        continue
                    if self._addr_in_executable_memory(i):
                        yield i+offset
                current_addr = max(current_addr, end_addr)

        # step 3: check every possible addresses
        if not self.only_check_near_rets:
            for segment in self._get_executable_ranges():
                l.debug("Analyzing segment with address range: 0x%x, 0x%x", segment.min_addr, segment.max_addr)
                start = alignment * ((segment.min_addr + alignment - 1) // alignment)
                for addr in range(start, start+segment.memsize, alignment):
                    if addr+offset in seen_addrs:
                        continue
                    yield addr+offset

    def _num_addresses_to_check(self):
        if self.only_check_near_rets:
            # TODO: This could probably be optimized further by fewer segments checks (i.e. iterating for segments and
            #  adding ranges instead of incrementing, instead of calling _addressses_to_check) although this is still a
            # significant improvement.
            return sum(1 for _ in self._addresses_to_check())

        cnt = 0
        if self._syscall_locations:
            cnt += len(self._syscall_locations)

        alignment = self.arch.alignment
        for segment in self._get_executable_ranges():
            cnt += segment.memsize // alignment
        return cnt

    def _get_ret_locations(self):
        """
        :return: all the locations in the binary with a ret instruction
        """

        try:
            return self._get_ret_locations_by_string()
        except RopException:
            pass

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

    def _get_ret_locations_by_string(self):
        """
        uses a string filter to find the return instructions
        :return: all the locations in the binary with a ret instruction
        """
        if not self.arch.ret_insts:
            raise RopException("Only have ret strings for i386/x86_64/aarch64")
        return self._get_locations_by_strings(self.arch.ret_insts)

    def _get_syscall_locations_by_string(self):
        """
        uses a string filter to find all the system calls instructions
        :return: all the locations in the binary with a system call instruction
        """
        if not self.arch.syscall_insts:
            l.warning("Only have syscall strings for i386 and x86_64")
            return []
        return self._get_locations_by_strings(self.arch.syscall_insts)

    def _get_locations_by_strings(self, strings):
        fmt = b'(' + b')|('.join(strings) + b')'

        addrs = []
        state = self.project.factory.entry_state()
        for segment in self._get_executable_ranges():
            # angr is slow to read huge chunks
            read_bytes = []
            for i in range(segment.min_addr, segment.min_addr+segment.memsize, 0x100):
                read_size = min(0x100, segment.min_addr+segment.memsize-i)
                read_bytes.append(state.solver.eval(state.memory.load(i, read_size), cast_to=bytes))
            read_bytes = b"".join(read_bytes)
            # find all occurrences of the ret_instructions
            addrs += [segment.min_addr + m.start() for m in re.finditer(fmt, read_bytes)]
        return sorted(addrs)
