import io

import angr
import angrop # pylint: disable=unused-import

from angrop.rop_gadget import SyscallGadget

#BIN_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "binaries")
#CACHE_DIR = os.path.join(BIN_DIR, 'tests_data', 'angrop_gadgets_cache')

def test_blob():
    """
    make sure angrop works well with the blob backend
    """
    bio = io.BytesIO(b"\x58\xC3\x0F\x05") # pop rax; ret; syscall
    proj = angr.Project(bio, main_opts={'backend': 'blob', 'arch': 'amd64'}, simos='linux')
    rop = proj.analyses.ROP(only_check_near_rets=False)

    gadget = rop.analyze_gadget(2)
    assert gadget
    assert isinstance(gadget, SyscallGadget)

def run_all():
    functions = globals()
    all_functions = {x:y for x, y in functions.items() if x.startswith('test_')}
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    import sys
    import logging

    logging.getLogger("angrop.rop").setLevel(logging.DEBUG)

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
