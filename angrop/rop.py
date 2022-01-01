from angr.errors import SimEngineError, SimMemoryError
from angr.analyses.bindiff import differing_constants
from angr.analyses.bindiff import UnmatchedStatementsException
from angr.misc.loggers import CuteHandler
from angr import Analysis, register_analysis

from . import chain_builder
from . import gadget_analyzer
from . import common
from .arch import get_arch

import pickle
import inspect
import logging
import tqdm

from .errors import RopException
from .rop_gadget import RopGadget, StackPivot

from multiprocessing import Pool

l = logging.getLogger('angrop.rop')


_global_gadget_analyzer = None

# disable loggers in each worker
def _disable_loggers():
    for handler in logging.root.handlers:
        if type(handler) == CuteHandler:
            logging.root.removeHandler(handler)
            return

# global initializer for multiprocessing
def _set_global_gadget_analyzer(rop_gadget_analyzer):
    global _global_gadget_analyzer
    _global_gadget_analyzer = rop_gadget_analyzer
    _disable_loggers()

def run_worker(addr):
    return _global_gadget_analyzer.analyze_gadget(addr)


# todo what if we have mov eax, [rsp+0x20]; ret (cache would need to know where it is or at least a min/max)
# todo what if we have pop eax; mov ebx, eax; need to encode that we cannot set them to different values
class ROP(Analysis):
    """
    This class is a semantic aware rop gadget finder
    It is a work in progress, so don't be surprised if something doesn't quite work

    After calling find_gadgets(), find_gadgets_single_threaded() or load_gadgets(),
    self.gadgets, self.stack_pivots, and self._duplicates is populated.
    Additionally, all public methods from ChainBuilder are copied into ROP.
    """

    def __init__(self, only_check_near_rets=True, max_block_size=None, max_sym_mem_access=None, fast_mode=None, rebase=True, is_thumb=False):
        """
        Initializes the rop gadget finder
        :param only_check_near_rets: If true we skip blocks that are not near rets
        :param max_block_size: limits the size of blocks considered, longer blocks are less likely to be good rop
                               gadgets so we limit the size we consider
        :param fast_mode: if set to True sets options to run fast, if set to False sets options to find more gadgets
                          if set to None makes a decision based on the size of the binary
        :param rebase:    if set to True, angrop will try to rebase the gadgets with its best effort
                          if set to False, angrop will use the memory mapping in angr in the ropchain
        :param is_thumb:  execute ROP chain in thumb mode. Only makes difference on ARM architecture.
                          angrop does not switch mode within a rop chain
        :return:
        """

        # params
        self.arch = get_arch(self.project)
        self._only_check_near_rets = only_check_near_rets
        self._rebase = rebase

        # override parameters
        if max_block_size:
            self.arch.max_block_size = max_block_size
        if max_sym_mem_access:
            self.arch.max_sym_mem_access = max_sym_mem_access
        if is_thumb:
            self.arch.is_thumb = is_thumb

        # get ret locations
        self._ret_locations = None

        # list of RopGadget's
        self._gadgets = []
        self.stack_pivots = []
        self._duplicates = []

        # RopChain settings
        self.badbytes = []
        self.roparg_filler = None

        self._fast_mode = fast_mode

        # gadget analyzer
        self._gadget_analyzer = None

        # chain builder
        self._chain_builder = None

        # silence annoying loggers
        logging.getLogger('angr.engines.vex.ccall').setLevel(logging.CRITICAL)
        logging.getLogger('angr.engines.vex.expressions.ccall').setLevel(logging.CRITICAL)
        logging.getLogger('angr.engines.vex.irop').setLevel(logging.CRITICAL)
        logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.CRITICAL)
        logging.getLogger('pyvex.lifting.libvex').setLevel(logging.CRITICAL)
        logging.getLogger('angr.procedures.cgc.deallocate').setLevel(logging.CRITICAL)

    @property
    def gadgets(self):
        return [x for x in self._gadgets if not self._contain_badbytes(x.addr)]

    def _initialize_gadget_analyzer(self):

        # find locations to analyze
        self._ret_locations = self._get_ret_locations()
        num_to_check = self._num_addresses_to_check()

        # fast mode
        if self._fast_mode is None:
            if num_to_check > 20000:
                self._fast_mode = True
                l.warning("Enabling fast mode for large binary")
            else:
                self._fast_mode = False
        if self._fast_mode:
            self.arch.max_block_size = 12
            self.arch.max_sym_mem_access = 1
            # Recalculate num addresses to check based on fast_mode settings
            num_to_check = self._num_addresses_to_check()

        l.info("There are %d addresses within %d bytes of a ret",
               num_to_check, self.arch.max_block_size)

        self._gadget_analyzer = gadget_analyzer.GadgetAnalyzer(self.project, self._fast_mode, arch=self.arch)

    def find_gadgets(self, processes=4, show_progress=True):
        """
        Finds all the gadgets in the binary by calling analyze_gadget on every address near a ret.
        Saves gadgets in self._gadgets
        Saves stack pivots in self.stack_pivots
        :param processes: number of processes to use
        """
        self._initialize_gadget_analyzer()
        self._gadgets = []

        pool = Pool(processes=processes, initializer=_set_global_gadget_analyzer, initargs=(self._gadget_analyzer,))

        it = pool.imap_unordered(run_worker, self._addresses_to_check_with_caching(show_progress), chunksize=5)
        for gadget in it:
            if gadget is not None:
                if isinstance(gadget, RopGadget):
                    self._gadgets.append(gadget)
                elif isinstance(gadget, StackPivot):
                    self.stack_pivots.append(gadget)

        pool.close()

        # fix up gadgets from cache
        for g in self._gadgets:
            if g.addr in self._cache:
                dups = {g.addr}
                for addr in self._cache[g.addr]:
                    dups.add(addr)
                    g_copy = g.copy()
                    g_copy.addr = addr
                    self._gadgets.append(g_copy)
                self._duplicates.append(dups)
        self._gadgets = sorted(self._gadgets, key=lambda x: x.addr)
        self._reload_chain_funcs()

    def find_gadgets_single_threaded(self, show_progress=True):
        """
        Finds all the gadgets in the binary by calling analyze_gadget on every address near a ret
        Saves gadgets in self.gadgets
        Saves stack pivots in self.stack_pivots
        """
        self._initialize_gadget_analyzer()
        self._gadgets = []

        _set_global_gadget_analyzer(self._gadget_analyzer)
        for _, addr in enumerate(self._addresses_to_check_with_caching(show_progress)):
            gadget = _global_gadget_analyzer.analyze_gadget(addr)
            if gadget is not None:
                if isinstance(gadget, RopGadget):
                    self._gadgets.append(gadget)
                elif isinstance(gadget, StackPivot):
                    self.stack_pivots.append(gadget)

        # fix up gadgets from cache
        for g in self._gadgets:
            if g.addr in self._cache:
                dups = {g.addr}
                for addr in self._cache[g.addr]:
                    dups.add(addr)
                    g_copy = g.copy()
                    g_copy.addr = addr
                    self._gadgets.append(g_copy)
                self._duplicates.append(dups)
        self._gadgets = sorted(self._gadgets, key=lambda x: x.addr)
        self._reload_chain_funcs()

    def save_gadgets(self, path):
        """
        Saves gadgets in a file.
        :param path: A path for a file where the gadgets are stored
        """
        with open(path, "wb") as f:
            pickle.dump(self._get_cache_tuple(), f)

    def load_gadgets(self, path):
        """
        Loads gadgets from a file.
        :param path: A path for a file where the gadgets are loaded
        """
        cache_tuple = pickle.load(open(path, "rb"))
        self._load_cache_tuple(cache_tuple)

    def set_badbytes(self, badbytes):
        """
        Define badbytes which should not appear in the generated ropchain.
        :param badbytes: a list of 8 bit integers
        """
        if not isinstance(badbytes, list):
            print("Require a list, e.g: [0x00, 0x09]")
            return
        badbytes = [x if type(x) == int else ord(x) for x in badbytes]
        self.badbytes = badbytes
        if len(self._gadgets) > 0:
            self.chain_builder._set_badbytes(self.badbytes)

    def set_roparg_filler(self, roparg_filler):
        """
        Define rop gadget filler argument. These will be used if the rop chain needs to pop
        useless registers.
        If roparg_filler is None, symbolic values will be used and the concrete values will
        be whatever the constraint solver chooses (usually 0).
        :param roparg_filler: A integer which is used when popping useless register or None.
        """
        if not isinstance(roparg_filler, (int, type(None))):
            print("Require an integer, e.g: 0x41414141 or None")
            return

        self.roparg_filler = roparg_filler
        if len(self._gadgets) > 0:
            self.chain_builder._set_roparg_filler(self.roparg_filler)

    def get_badbytes(self):
        """
        Returns list of badbytes.
        :returns the list of badbytes
        """
        return self.badbytes

    def _get_cache_tuple(self):
        return self._gadgets, self.stack_pivots, self._duplicates, self._ret_locations, self._fast_mode, \
                self.arch, self._gadget_analyzer

    def _load_cache_tuple(self, cache_tuple):
        self._gadgets, self.stack_pivots, self._duplicates, self._ret_locations, self._fast_mode, \
        self.arch, self._gadget_analyzer = cache_tuple
        self._reload_chain_funcs()

    def _reload_chain_funcs(self):
        for f_name, f in inspect.getmembers(self.chain_builder, predicate=inspect.ismethod):
            if f_name.startswith("_"):
                continue
            setattr(self, f_name, f)

    @property
    def chain_builder(self):
        if self._chain_builder is not None:
            return self._chain_builder
        if len(self._gadgets) == 0:
            l.warning("Could not find gadgets for %s, check your badbytes and make sure find_gadgets() or load_gadgets() was called.", self.project)
        self._chain_builder = chain_builder.ChainBuilder(self.project, self.gadgets, self._duplicates,
                                                         self.arch.reg_list, self.arch.base_pointer, self.badbytes,
                                                         self.roparg_filler, rebase=self._rebase)
        return self._chain_builder

    def _block_has_ip_relative(self, addr, bl):
        """
        Checks if a block has any ip relative instructions
        """
        string = bl.bytes
        test_addr = 0x41414140 + addr % 0x10
        bl2 = self.project.factory.block(test_addr, byte_string=string)
        try:
            diff_constants = differing_constants(bl, bl2)
        except UnmatchedStatementsException:
            return True
        # check if it changes if we move it
        bl_end = addr + bl.size
        bl2_end = test_addr + bl2.size
        filtered_diffs = []
        for d in diff_constants:
            if d.value_a < addr or d.value_a >= bl_end or \
                    d.value_b < test_addr or d.value_b >= bl2_end:
                filtered_diffs.append(d)
        return len(filtered_diffs) > 0

    def _addresses_to_check_with_caching(self, show_progress=True):
        num_addrs = self._num_addresses_to_check()
        self._cache = dict()
        seen = dict()

        iterable = self._addresses_to_check()
        if show_progress:
            iterable = tqdm.tqdm(iterable=iterable, smoothing=0, total=num_addrs,
                                 desc="ROP", maxinterval=0.5, dynamic_ncols=True)

        for a in iterable:
            try:
                bl = self.project.factory.block(a)
                if bl.size > self.arch.max_block_size:
                    continue
                block_data = bl.bytes
            except (SimEngineError, SimMemoryError):
                continue
            if block_data in seen:
                self._cache[seen[block_data]].add(a)
                continue
            else:
                if self._is_jumpkind_valid(bl.vex.jumpkind) and \
                        len(bl.vex.constant_jump_targets) == 0 and \
                        not self._block_has_ip_relative(a, bl):
                    seen[block_data] = a
                    self._cache[a] = set()
                yield a

    def _addresses_to_check(self):
        """
        :return: all the addresses to check
        """
        if self._only_check_near_rets:
            # align block size
            alignment = self.arch.alignment
            block_size = (self.arch.max_block_size & ((1 << self.project.arch.bits) - alignment)) + alignment
            slices = [(addr-block_size, addr) for addr in self._ret_locations]
            current_addr = 0
            for st, _ in slices:
                current_addr = max(current_addr, st)
                end_addr = st + block_size + alignment
                for i in range(current_addr, end_addr, alignment):
                    segment = self.project.loader.main_object.find_segment_containing(i)
                    if segment is not None and segment.is_executable:
                        yield i
                current_addr = max(current_addr, end_addr)
        else:
            for segment in self.project.loader.main_object.segments:
                if segment.is_executable:
                    l.debug("Analyzing segment with address range: 0x%x, 0x%x" % (segment.min_addr, segment.max_addr))
                    for addr in range(segment.min_addr, segment.max_addr):
                        yield addr

    def _num_addresses_to_check(self):
        if self._only_check_near_rets:
            # TODO: This could probably be optimized further by fewer segments checks (i.e. iterating for segments and
            #  adding ranges instead of incrementing, instead of calling _addressses_to_check) although this is still a
            # significant improvement.
            return sum(1 for _ in self._addresses_to_check())
        else:
            num = 0
            for segment in self.project.loader.main_object.segments:
                if segment.is_executable:
                    num += (segment.max_addr - segment.min_addr)
            return num
                        
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
        for segment in self.project.loader.main_object.segments:
            if segment.is_executable:
                num_bytes = segment.max_addr-segment.min_addr

                alignment = self.arch.alignment

                # iterate through the code looking for rets
                for addr in range(segment.min_addr, segment.min_addr + num_bytes, alignment):
                    # dont recheck addresses we've seen before
                    if addr in seen:
                        continue
                    try:
                        block = self.project.factory.block(addr)
                        # it it has a ret get the return address
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
        if self.project.arch.linux_name == "x86_64" or self.project.arch.linux_name == "i386":
            ret_instructions = {b"\xc2", b"\xc3", b"\xca", b"\xcb"}
        else:
            raise RopException("Only have ret strings for i386 and x86_64")

        addrs = []
        try:
            for segment in self.project.loader.main_object.segments:
                if segment.is_executable:
                    num_bytes = segment.max_addr-segment.min_addr
                    read_bytes = self.project.loader.memory.load(segment.min_addr, num_bytes)
                    for ret_instruction in ret_instructions:
                        for loc in common.str_find_all(read_bytes, ret_instruction):
                            addrs.append(loc + segment.min_addr)
        except KeyError:
            l.warning("Key error with segment analysis")
            # try reading from state
            state = self.project.factory.entry_state()
            for segment in self.project.loader.main_object.segments:
                if segment.is_executable:
                    num_bytes = segment.max_addr - segment.min_addr

                    read_bytes = state.solver.eval(state.memory.load(segment.min_addr, num_bytes), cast_to=bytes)
                    for ret_instruction in ret_instructions:
                        for loc in common.str_find_all(read_bytes, ret_instruction):
                            addrs.append(loc + segment.min_addr)

        return sorted(addrs)

    @staticmethod
    def _is_jumpkind_valid(jk):

        if jk in {'Ijk_Boring', 'Ijk_Call', 'Ijk_Ret'}:
            return True
        return False

    # inspired by ropper
    def _contain_badbytes(self, addr):
        n_bytes = self.project.arch.bytes

        for b in self.badbytes:
            tmp_addr = addr
            for _ in range(n_bytes):
                if (tmp_addr & 0xff) == b:
                    return True
                tmp_addr >>= 8
        return False

register_analysis(ROP, 'ROP')
