import logging

from . import rop_utils
from .errors import RopException
from .rop_gadget import RopGadget
from .rop_value import RopValue

CHAIN_TIMEOUT_DEFAULT = 3

l = logging.getLogger("angrop.chain_builder.reg_setter")

class RopChain:
    """
    This class holds rop chains returned by the rop chain building methods such as rop.set_regs()
    """
    cls_timeout = CHAIN_TIMEOUT_DEFAULT

    def __init__(self, project, builder, state=None, badbytes=None):
        """
        """
        self._p = project
        self._pie = self._p.loader.main_object.pic
        self._builder = builder

        self._gadgets = []
        self._values = []
        self.payload_len = 0

        # blank state used for solving
        self._blank_state = self._p.factory.blank_state() if state is None else state
        self.badbytes = badbytes if badbytes else []

        self._timeout = self.cls_timeout

    def __add__(self, other):
        # need to add the values from the other's stack and the constraints to the result state
        result = self.copy()
        o_state = other._blank_state
        o_stack = o_state.memory.load(o_state.regs.sp, other.payload_len)
        result._blank_state.memory.store(result._blank_state.regs.sp + self.payload_len, o_stack)
        result._blank_state.add_constraints(*o_state.solver.constraints)
        if not other._values:
            return result
        # add the other values and gadgets
        result._gadgets.extend(other._gadgets)
        idx = self.next_pc_idx()
        result.payload_len = self.payload_len + other.payload_len
        if idx is None:
            result._values.extend(other._values)
        else:
            result._values[idx] = other._values[0]
            result._values.extend(other._values[1:])
            result.payload_len -= self._p.arch.bytes
        return result

    def set_timeout(self, timeout):
        self._timeout = timeout

    @classmethod
    def set_cls_timeout(cls, timeout):
        cls.cls_timeout = timeout
        print(cls, cls.cls_timeout)

    def add_value(self, value):
        if type(value) is not RopValue:
            value = RopValue(value, self._p)
            value.rebase_analysis(chain=self)
        self._values.append(value)
        self.payload_len += self._p.arch.bytes

    def add_gadget(self, gadget):
        value = gadget.addr
        if self._pie:
            value -= self._p.loader.main_object.mapped_base
        value = RopValue(value, self._p)
        value._rebase = self._pie is True

        if (idx := self.next_pc_idx()) is None:
            self.add_value(value)
        else:
            self._values[idx] = value

        self._gadgets.append(gadget)

    def set_gadgets(self, gadgets: list[RopGadget]):
        self._gadgets = gadgets

    def add_constraint(self, cons):
        """
        helpful if the chain contains variables
        """
        self._blank_state.add_constraints(cons)

    def next_pc_idx(self):
        """
        in some gadgets, we have this situation:
        pop pc,r1, which means pc is not the last popped value like ret (retn is another example)
        in these case, the value will be presented as symbolic "next_pc" in _values.
        it will be concretized when adding new gadgets or doing chain concatenation
        """
        for idx, x in enumerate(self._values):
            if x.symbolic and any(y.startswith("next_pc_") for y in x.ast.variables):
                return idx
        return None

    def __concretize_chain_values(self, constraints=None):
        """
        with the flexibilty of chains to have symbolic values, this helper function
        makes the chain into a list of concrete ints before printing
        :param constraints: constraints to use when concretizing values
        :return: a list of tuples of type (int, needs_rebase)
        """
        solver_state = self._blank_state.copy()
        if constraints is not None:
            if isinstance(constraints, (list, tuple)):
                for c in constraints:
                    solver_state.add_constraints(c)
            else:
                solver_state.add_constraints(constraints)

        concrete_vals = []
        for value in self._values:
            # make sure it does not have badbytes in it
            ast = value.data
            constraints = []
            # for each byte, it should not be equal to any bad bytes
            # TODO: we should do the badbyte verification when adding values
            # not when concretizing them
            for idx in range(ast.length//8):
                b = ast.get_byte(idx)
                constraints += [ b != c for c in self.badbytes]
            # apply the constraints
            for expr in constraints:
                solver_state.solver.add(expr)
                if not solver_state.solver.satisfiable():
                    raise RopException("bad chain!")
            concrete_vals.append((solver_state.solver.eval(ast), value.rebase))

        return concrete_vals

    def _concretize_chain_values(self, constraints=None, timeout=None, preserve_next_pc=False, append_shift=False):
        """
        concretize chain values with a timeout
        """
        if self.next_pc_idx() is not None and append_shift:
            try:
                # the following line is the final touch for chains ending with retn-style
                # gadget to make sure that the next_pc is at the end of the chain
                chain = self + self._builder.chain_builder.shift(self._p.arch.bytes)
                values = chain._concretize_chain_values(
                                    constraints=constraints,
                                    timeout=timeout,
                                    preserve_next_pc=preserve_next_pc,
                                    append_shift=False,
                                )
                return values
            except RopException:
                pass
        if timeout is None:
            timeout = self._timeout
        values = rop_utils.timeout(timeout)(self.__concretize_chain_values)(constraints=constraints)
        if not preserve_next_pc:
            return values
        idx = self.next_pc_idx()
        if idx is None:
            return values
        values[idx] = (self._values[idx].ast, None)
        return values

    def payload_str(self, constraints=None, base_addr=None, timeout=None):
        """
        :param base_addr: the base address of the binary
        :return: a string that does the rop payload
        """
        if base_addr is None:
            base_addr = self._p.loader.main_object.mapped_base
        test_state = self._blank_state.copy()
        concrete_vals = self._concretize_chain_values(constraints, timeout=timeout, append_shift=True)
        for value, rebased in reversed(concrete_vals):
            if rebased:
                test_state.stack_push(value - self._p.loader.main_object.mapped_base + base_addr)
            else:
                test_state.stack_push(value)
        sp = test_state.regs.sp
        rop_str = test_state.solver.eval(test_state.memory.load(sp, self.payload_len), cast_to=bytes)
        if any(bytes([c]) in rop_str for c in self.badbytes):
            raise RopException()
        return rop_str

    def payload_bv(self):

        test_state = self._blank_state.copy()

        for value in reversed(self._values):
            test_state.stack_push(value.data)

        sp = test_state.regs.sp
        return test_state.memory.load(sp, self.payload_len)

    def addr_to_asmstring(self, addr):
        for g in self._gadgets:
            if g.addr == addr:
                return g.dstr()
        return ""

    def find_symbol(self, addr):
        plt = self._p.loader.find_plt_stub_name(addr)
        if plt:
            return plt + '@plt'
        symbol = self._p.loader.find_symbol(addr)
        if symbol:
            return symbol.name
        return None

    def payload_code(self, constraints=None, print_instructions=True, timeout=None):
        """
        :param print_instructions: prints the instructions that the rop gadgets use
        :return: prints the code for the rop payload
        """
        if self._p.arch.bits == 32:
            pack = "p32(%#x)"
            pack_rebase = "p32(code_base + %#x)"
        else:
            pack = "p64(%#x)"
            pack_rebase = "p64(code_base + %#x)"

        if self._pie:
            payload = "code_base = 0x0\n"
        else:
            payload = ""
        payload += 'chain = b""\n'

        concrete_vals = self._concretize_chain_values(constraints, timeout=timeout, append_shift=True)
        for value, rebased in concrete_vals:

            instruction_code = ""
            if print_instructions :
                sec = self._p.loader.find_section_containing(value)
                if sec and sec.is_executable:
                    symbol = self.find_symbol(value)
                    if symbol:
                        instruction_code = f"\t# {symbol}"
                    else:
                        asmstring = self.addr_to_asmstring(value)
                        if asmstring != "":
                            instruction_code = "\t# " + asmstring

            if rebased:
                value -= self._p.loader.main_object.mapped_base
                payload += "chain += " + pack_rebase % value + instruction_code
            else:
                payload += "chain += " + pack % value + instruction_code
            payload += "\n"
        return payload

    def print_payload_code(self, constraints=None, print_instructions=True):
        print(self.payload_code(constraints=constraints, print_instructions=print_instructions))

    def exec(self, max_steps=None, timeout=None):
        """
        symbolically execute the ROP chain and return the final state
        """
        state = self._blank_state.copy()
        state.solver.reload_solver([]) # remove constraints
        state.regs.pc = self._values[0].concreted
        concrete_vals = self._concretize_chain_values(timeout=timeout, preserve_next_pc=True, append_shift=False)

        # when the chain data includes symbolic values, we need to replace the concrete values
        # with the user's symbolic data
        values = concrete_vals
        for idx, val in enumerate(self._values):
            if not val.symbolic:
                continue
            if all(var.startswith("symbolic_stack") for var in val.ast.variables):
                continue
            values[idx] = (val.data, val.rebase)

        # the assumption is that the first value in the chain is a code address
        # it sounds like a reasonable assumption to me. But I can be wrong.
        for value, _ in reversed(values[1:]):
            state.stack_push(value)
        if max_steps is None:
            max_steps = sum(len(gadget.bbl_addrs) for gadget in self._gadgets)
        try:
            state = rop_utils.step_to_unconstrained_successor(self._p, state, max_steps=max_steps,
                                                              allow_simprocedures=True)
        except RopException as e:
            code = self.payload_code(print_instructions=True)
            l.error("The following chain fails to execute!")
            l.error(code)
            raise e
        return state

    def copy(self):
        cp = RopChain(self._p, self._builder)
        cp._gadgets = list(self._gadgets)
        cp._values = list(self._values)
        cp.payload_len = self.payload_len
        cp._blank_state = self._blank_state.copy()
        cp.badbytes = self.badbytes.copy()

        return cp

    def __str__(self):
        return self.payload_code()

    def dstr(self):
        res = ''
        bs = self._p.arch.bytes
        prefix_len = bs*2+2
        prefix = " "*prefix_len
        for v in self._values:
            if v.symbolic:
                res += prefix + f"  {v.ast}\n"
                continue
            for g in self._gadgets:
                if g.addr == v.concreted:
                    fmt = f"%#0{prefix_len}x"
                    res += fmt % g.addr + f": {g.dstr()}\n"
                    break
            else:
                res += prefix + f"  {v.concreted:#x}\n"
        return res

    def pp(self):
        print(self.dstr())