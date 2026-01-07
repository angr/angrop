import pickle
import inspect
import logging
from typing import cast

from angr import Analysis, register_analysis

from . import chain_builder
from .gadget_finder import GadgetFinder
from .rop_gadget import RopGadget, PivotGadget, SyscallGadget

l = logging.getLogger('angrop.rop')

class ROP(Analysis):
    """
    This class is a semantic aware rop gadget finder
    It is a work in progress, so don't be surprised if something doesn't quite work

    After calling find_gadgets(), find_gadgets_single_threaded() or load_gadgets(),
    self.rop_gadgets, self.pivot_gadgets, self.syscall_gadgets are populated.
    Additionally, all public methods from ChainBuilder are copied into ROP.
    """

    def __init__(self, only_check_near_rets=True, max_block_size=None, max_sym_mem_access=None,
                 fast_mode=None, rebase=None, is_thumb=False, kernel_mode=False, stack_gsize=80,
                 cond_br=False, max_bb_cnt=2
                 ):
        """
        Initializes the rop gadget finder
        :param only_check_near_rets: If true we skip blocks that are not near rets
        :param max_block_size: limits the size of blocks considered, longer blocks are less likely to be good rop
                               gadgets so we limit the size we consider
        :param fast_mode: True/False, if set to None makes a decision based on the size of the binary
                          if True, skip gadgets with conditonal_branches, floating point operations, jumps
                          allow smaller gadget size
        :param is_thumb:  execute ROP chain in thumb mode. Only makes difference on ARM architecture.
                          angrop does not switch mode within a rop chain
        :param kernel_mode: find kernel mode gadgets
        :param stack_gsize: change the maximum allowable stack change for gadgets, where
                            the max stack_change = stack_gsize * arch.bytes
        :param cond_br: whether to support conditional branches, this option impacts gadget finding speed significantly
        :return:
        """

        # private list of RopGadget's
        self._all_gadgets: list[RopGadget] = [] # all types of gadgets
        # all equivalent gadgets (with the same instructions)
        self._duplicates: dict = None # type: ignore

        # public list of RopGadget's
        self.rop_gadgets = [] # gadgets used for ROP, like pop rax; ret
        self.pivot_gadgets = [] # gadgets used for stack pivoting, like mov rsp, rbp; ret
        self.syscall_gadgets = [] # gadgets used for invoking system calls, such as syscall; ret or int 0x80; ret

        # RopChain settings
        self.badbytes = []
        self.roparg_filler = None

        # gadget finder configurations
        self.gadget_finder = GadgetFinder(self.project, fast_mode=fast_mode, only_check_near_rets=only_check_near_rets,
                                          max_block_size=max_block_size, max_sym_mem_access=max_sym_mem_access,
                                          is_thumb=is_thumb, kernel_mode=kernel_mode, stack_gsize=stack_gsize,
                                          cond_br=cond_br, max_bb_cnt=max_bb_cnt)
        self.arch = self.gadget_finder.arch

        # chain builder
        self._chain_builder = None

        if rebase is not None:
            l.warning("rebase is deprecated in angrop!")

    def _screen_gadgets(self):
        # screen gadgets based on badbytes and gadget types
        self.rop_gadgets = []
        self.pivot_gadgets = []
        self.syscall_gadgets = []
        for g in self._all_gadgets:
            if self._contain_badbytes(g.addr):
                # in case the gadget contains bad byte, try to take an equivalent one from
                # the duplicates (other gadgets with the same instructions)
                block = self.project.factory.block(g.addr)
                h = self.gadget_finder.block_hash(block)
                addr = None
                if h not in self._duplicates:
                    continue
                for addr in self._duplicates[h]:
                    if not self._contain_badbytes(addr):
                        break
                if not addr:
                    continue
                g = self.gadget_finder.analyze_gadget(addr)
            if type(g) is RopGadget:
                self.rop_gadgets.append(g)
            if type(g) is PivotGadget:
                self.pivot_gadgets.append(g)
            if type(g) is SyscallGadget:
                self.syscall_gadgets.append(g)

        self.chain_builder.gadgets = self.rop_gadgets
        self.chain_builder.pivot_gadgets = self.pivot_gadgets
        self.chain_builder.syscall_gadgets = self.syscall_gadgets
        self.chain_builder.bootstrap()

    def analyze_addr(self, addr):
        """
        return a list of gadgets that starts from addr
        this is possible because of conditional branches
        """
        res = self.gadget_finder.analyze_gadget(addr, allow_conditional_branches=True)
        gs:list[RopGadget]|None = cast(list[RopGadget]|None, res)
        if not gs:
            return gs
        self._all_gadgets += gs
        self._screen_gadgets()
        return gs

    def analyze_gadget(self, addr):
        """
        return a gadget or None, it filters out gadgets containing conditional_branches
        if you'd like those, use analyze_addr
        """
        res = self.gadget_finder.analyze_gadget(addr, allow_conditional_branches=False)
        g = cast(RopGadget|None, res)
        if g is None:
            return g
        self._all_gadgets.append(g)
        self._screen_gadgets()
        return g

    def analyze_gadget_list(self, addr_list, processes=4, show_progress=True, optimize=True):
        """
        Analyzes a list of addresses to identify ROP gadgets.
        Saves rop gadgets in self.rop_gadgets
        Saves syscall gadgets in self.syscall_gadgets
        Saves stack pivots in self.stack_pivots
        :param processes: number of processes to use
        :param show_progress: whether or not to show progress bar
        """

        self._all_gadgets = self.gadget_finder.analyze_gadget_list(
            addr_list, processes=processes, show_progress=show_progress)
        self._screen_gadgets()
        if optimize:
            self.chain_builder.optimize(processes=processes)
        return self.rop_gadgets

    def find_gadgets(self, optimize=True, **kwargs):
        """
        Finds all the gadgets in the binary by calling analyze_gadget on every address near a ret.
        Saves rop gadgets in self.rop_gadgets
        Saves syscall gadgets in self.syscall_gadgets
        Saves stack pivots in self.stack_pivots
        :param processes: number of processes to use
        :param optimize: whether to run chain_builder.optimize(), this may take some time,
                         but makes the chain builder more powerful
        """
        self._all_gadgets, self._duplicates = self.gadget_finder.find_gadgets(**kwargs)
        self._screen_gadgets()
        if optimize:
            processes = kwargs.get('processes', 4)
            self.chain_builder.optimize(processes=processes)
        return self.rop_gadgets

    def find_gadgets_single_threaded(self, show_progress=True, optimize=True):
        """
        Finds all the gadgets in the binary by calling analyze_gadget on every address near a ret
        Saves rop gadgets in self.rop_gadgets
        Saves syscall gadgets in self.syscall_gadgets
        Saves stack pivots in self.stack_pivots
        """
        self._all_gadgets, self._duplicates = self.gadget_finder.find_gadgets_single_threaded(
                                                                 show_progress=show_progress)
        self._screen_gadgets()
        if optimize:
            self.chain_builder.optimize(processes=1)
        return self.rop_gadgets

    def _get_cache_tuple(self):
        all_gadgets = self._all_gadgets
        for g in all_gadgets:
            g.project = None
        return (all_gadgets, self._duplicates)

    def _load_cache_tuple(self, tup):
        self._all_gadgets = tup[0]
        self._duplicates = tup[1]
        for g in self._all_gadgets:
            g.project = self.project
        self._screen_gadgets()

    def save_gadgets(self, path):
        """
        Saves gadgets in a file.
        :param path: A path for a file where the gadgets are stored
        """
        with open(path, "wb") as f:
            pickle.dump(self._get_cache_tuple(), f)
        for g in self._all_gadgets:
            g.project = self.project

    def load_gadgets(self, path, optimize=True):
        """
        Loads gadgets from a file.
        :param path: A path for a file where the gadgets are loaded
        """
        with open(path, "rb") as f:
            cache_tuple = pickle.load(f)
            self._load_cache_tuple(cache_tuple)
        if optimize:
            self.chain_builder.optimize()

    def set_badbytes(self, badbytes):
        """
        Define badbytes which should not appear in the generated ropchain.
        :param badbytes: a list of 8 bit integers
        """
        if not isinstance(badbytes, list):
            l.error("Require a list, e.g: [0x00, 0x09]")
            return
        badbytes = [x if type(x) == int else ord(x) for x in badbytes]
        self.badbytes = badbytes
        if self._chain_builder:
            self._chain_builder.set_badbytes(self.badbytes)
        self._screen_gadgets()

    def set_roparg_filler(self, roparg_filler):
        """
        Define rop gadget filler argument. These will be used if the rop chain needs to pop
        useless registers.
        If roparg_filler is None, symbolic values will be used and the concrete values will
        be whatever the constraint solver chooses (usually 0).
        :param roparg_filler: A integer which is used when popping useless register or None.
        """
        if not isinstance(roparg_filler, (int, type(None))):
            l.error("Require an integer, e.g: 0x41414141 or None")
            return

        self.roparg_filler = roparg_filler
        self.chain_builder.set_roparg_filler(self.roparg_filler)

    def get_badbytes(self):
        """
        Returns list of badbytes.
        :returns the list of badbytes
        """
        return self.badbytes

    @property
    def chain_builder(self):
        if self._chain_builder is not None:
            return self._chain_builder

        if len(self._all_gadgets) == 0:
            l.warning("Could not find gadgets for %s", self.project)
            l.warning("check your badbytes and make sure find_gadgets() or load_gadgets() was called.")
        self._chain_builder = chain_builder.ChainBuilder(self.project, self.rop_gadgets, self.pivot_gadgets,
                                                         self.syscall_gadgets, self.arch, self.badbytes,
                                                         self.roparg_filler)
        for f_name, f in inspect.getmembers(self._chain_builder, predicate=inspect.ismethod):
            if f_name.startswith("_"):
                continue
            setattr(self, f_name, f)
        return self._chain_builder

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
