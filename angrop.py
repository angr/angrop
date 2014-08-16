import angr

p = angr.Project("false", load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=True)
initial_state = p.initial_state(mode='symbolic', initial_prefix='start')
initial_state.store_mem(initial_state.reg_expr('rsp'), initial_state.BV("symbolic_stack", initial_state.arch.bits*20))

for addr in range(min(p.mem.keys()), ....):
    sirsb = p.sim_run(p.exit_to(addr, state=initial_state))

