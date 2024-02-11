import pickle
import inspect
import logging
import multiprocessing

from angr import Analysis, register_analysis

from . import chain_builder
from .gadget_finder import GadgetFinder
from .rop_gadget import RopGadget, PivotGadget

l = logging.getLogger('angrop.rop')

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

    def __init__(self, only_check_near_rets=True, max_block_size=None, max_sym_mem_access=None,
                 fast_mode=None, rebase=None, is_thumb=False, kernel_mode=False):
        """
        Initializes the rop gadget finder
        :param only_check_near_rets: If true we skip blocks that are not near rets
        :param max_block_size: limits the size of blocks considered, longer blocks are less likely to be good rop
                               gadgets so we limit the size we consider
        :param fast_mode: if set to True sets options to run fast, if set to False sets options to find more gadgets
                          if set to None makes a decision based on the size of the binary
        :param is_thumb:  execute ROP chain in thumb mode. Only makes difference on ARM architecture.
                          angrop does not switch mode within a rop chain
        :return:
        """

        # private list of RopGadget's
        self._all_gadgets = [] # all types of gadgets
        self._duplicates = None # all equivalent gadgets (with the same instructions)

        # public list of RopGadget's
        self.rop_gadgets = [] # gadgets used for ROP, like pop rax; ret
        self.pivot_gadgets = [] # gadgets used for stack pivoting, like mov rsp, rbp; ret

        # RopChain settings
        self.badbytes = []
        self.roparg_filler = None

        # gadget finder configurations
        self.gadget_finder = GadgetFinder(self.project, fast_mode=fast_mode, only_check_near_rets=only_check_near_rets, max_block_size=max_block_size, max_sym_mem_access=max_sym_mem_access, is_thumb=is_thumb, kernel_mode=kernel_mode)
        self.arch = self.gadget_finder.arch

        # chain builder
        self._chain_builder = None

        if rebase is not None:
            l.warning("rebase is deprecated in angrop!")

    def _screen_gadgets(self):
        # screen gadgets based on badbytes and gadget types
        self.rop_gadgets = []
        self.pivot_gadgets = []
        for g in self._all_gadgets:
            if self._contain_badbytes(g.addr):
                # in case the gadget contains bad byte, try to take an equivalent one from
                # the duplicates (other gadgets with the same instructions)
                block = self.project.factory.block(g.addr)
                h = self.gadget_finder.block_hash(block)
                if h not in self._duplicates:
                    continue
                for addr in self._duplicates[h]:
                    if not self._contain_badbytes(addr):
                        break
                else:
                    continue
                g = self.analyze_gadget(addr)
            if type(g) is RopGadget:
                self.rop_gadgets.append(g)
            if type(g) is PivotGadget:
                self.pivot_gadgets.append(g)

    def analyze_gadget(self, addr):
        g = self.gadget_finder.analyze_gadget(addr)
        self._reload_chain_funcs()
        return g

    def find_gadgets(self, processes=None, show_progress=True):
        """
        Finds all the gadgets in the binary by calling analyze_gadget on every address near a ret.
        Saves gadgets in self._gadgets
        Saves stack pivots in self.stack_pivots
        :param processes: number of processes to use
        """
        if processes is None:
            processes = multiprocessing.cpu_count()
        self._all_gadgets, self._duplicates = self.gadget_finder.find_gadgets(processes=processes, show_progress=show_progress)
        self._screen_gadgets()
        self._reload_chain_funcs()
        return self.rop_gadgets

    def find_gadgets_single_threaded(self, show_progress=True):
        """
        Finds all the gadgets in the binary by calling analyze_gadget on every address near a ret
        Saves gadgets in self.gadgets
        Saves stack pivots in self.stack_pivots
        """
        self._all_gadgets, self._duplicates = self.gadget_finder.find_gadgets_single_threaded(show_progress=show_progress)
        self._screen_gadgets()
        self._reload_chain_funcs()
        return self.rop_gadgets

    def save_gadgets(self, path):
        """
        Saves gadgets in a file.
        :param path: A path for a file where the gadgets are stored
        """
        with open(path, "wb") as f:
            pickle.dump((self._all_gadgets, self._duplicates), f)

    def load_gadgets(self, path):
        """
        Loads gadgets from a file.
        :param path: A path for a file where the gadgets are loaded
        """
        with open(path, "rb") as f:
            cache_tuple = pickle.load(f)
            self._all_gadgets = cache_tuple[0]
            self._duplicates = cache_tuple[1]
        self._screen_gadgets()
        self._reload_chain_funcs()

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
        self.chain_builder.set_badbytes(self.badbytes)
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
                                                         self.arch, self.badbytes,
                                                         self.roparg_filler)
        return self._chain_builder

    def _reload_chain_funcs(self):
        for f_name, f in inspect.getmembers(self.chain_builder, predicate=inspect.ismethod):
            if f_name.startswith("_"):
                continue
            setattr(self, f_name, f)

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