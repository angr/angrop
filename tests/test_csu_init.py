import os
import angr
import angrop  # pylint: disable=unused-import
import pickle

import logging
l = logging.getLogger("angrop.tests.test_csu_init")

bin_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries'))
tests_dir = os.path.join(bin_path, 'tests')
data_dir = os.path.join(bin_path, 'tests_data', 'angrop_gadgets_cache')


def print_rop_gadgets(gadgets, project=None):
    """
    Print detailed information about ROP gadgets in a one-line format per gadget.

    Args:
        gadgets: List of ROP gadgets to display
        project: Optional angr project object for resolving addresses to symbols

    Format:
    [addr] (len) type="transit_type" stack_Δ=N | changed={regs} popped={regs} concrete={reg:val} |
    deps={reg:[deps]} controllers={reg:[controllers]} | moves=[reg->reg] | mem_access=[type:addr->data]
    """
    for g in gadgets:
        # Basic gadget info
        parts = []
        addr_str = f"[{g.addr:#x}]"
        if project and project.loader.find_symbol(g.addr):
            addr_str += f"({project.loader.find_symbol(g.addr).name})"
        parts.append(f"{addr_str} ({g.block_length}) type={g.transit_type}")

        # Stack info
        parts.append(f"stack_Δ={g.stack_change:#x}")

        # Register operations
        reg_parts = []
        if g.changed_regs:
            reg_parts.append(f"changed={{{','.join(sorted(g.changed_regs))}}}")
        if g.popped_regs:
            reg_parts.append(f"popped={{{','.join(sorted(g.popped_regs))}}}")
        if g.concrete_regs:
            concrete = [f"{r}:{v:#x}" for r, v in sorted(g.concrete_regs.items())]
            reg_parts.append(f"concrete={{{','.join(concrete)}}}")
        if reg_parts:
            parts.append(" | " + " ".join(reg_parts))

        # Register dependencies and controllers
        dep_parts = []
        if g.reg_dependencies:
            deps = [f"{r}:[{','.join(sorted(d))}]" for r, d in sorted(g.reg_dependencies.items())]
            dep_parts.append(f"deps={{{','.join(deps)}}}")
        if g.reg_controllers:
            controllers = [f"{r}:[{','.join(sorted(c))}]" for r, c in sorted(g.reg_controllers.items())]
            dep_parts.append(f"controllers={{{','.join(controllers)}}}")
        if dep_parts:
            parts.append(" | " + " ".join(dep_parts))

        # Register moves
        if g.reg_moves:
            moves = [f"{m.from_reg}->{m.to_reg}({m.bits}b)" for m in g.reg_moves]
            parts.append(f" | moves=[{','.join(moves)}]")

        # Memory operations
        mem_parts = []
        for access in g.mem_reads:
            addr = f"{access.addr_constant:#x}" if access.addr_constant is not None else "{" + ",".join(
                access.addr_dependencies) + "}"
            data = "{" + ",".join(access.data_dependencies) + "}"
            mem_parts.append(f"read:{addr}->{data}")
        for access in g.mem_writes:
            addr = f"{access.addr_constant:#x}" if access.addr_constant is not None else "{" + ",".join(
                access.addr_dependencies) + "}"
            data = f"{access.data_constant:#x}" if access.data_constant is not None else "{" + ",".join(
                access.data_dependencies) + "}"
            mem_parts.append(f"write:{addr}->{data}")
        for access in g.mem_changes:
            addr = f"{access.addr_constant:#x}" if access.addr_constant is not None else "{" + ",".join(
                access.addr_dependencies) + "}"
            data = "{" + ",".join(access.data_dependencies) + "}"
            mem_parts.append(f"change({access.op}):{addr}->{data}")
        if mem_parts:
            parts.append(f" | mem=[{','.join(mem_parts)}]")

        print(" ".join(parts))

def test_mipstake():
    cache_path = os.path.join(data_dir, "mipstake")
    proj = angr.Project(os.path.join(tests_dir, "mips", "mipstake"), auto_load_libs=False, )
    rop = proj.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False, )

    if os.path.exists(cache_path) and False:
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets_single_threaded()
        rop.save_gadgets(cache_path)

    print_rop_gadgets(rop.rop_gadgets)


def test_unexploitable():
    cache_path = os.path.join(data_dir, "unexploitable")
    proj = angr.Project(os.path.join(tests_dir, "x86_64", "unexploitable"), auto_load_libs=False, )
    rop = proj.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False, )

    if os.path.exists(cache_path) and False:
        rop.load_gadgets(cache_path)
    else:
        rop.find_gadgets_single_threaded()
        rop.save_gadgets(cache_path)

    print_rop_gadgets(rop.rop_gadgets)


def run_all():
    functions = globals()
    all_functions = dict([x for x in functions.items() if x[0].startswith('test_')])
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()



if __name__ == "__main__":
    logging.getLogger("angrop.rop").setLevel(logging.DEBUG)

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        test_unexploitable()
