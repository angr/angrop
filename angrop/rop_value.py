import claripy

class RopValue:
    """
    This class represents a value that needs to be concretized in a ROP chain
    Automatically handles rebase
    """
    def __init__(self, value, project):
        if not isinstance(value, (int, claripy.ast.bv.BV)):
            raise ValueError("bad value type!")
        self._value = value # when rebase is needed, value here holds the offset
        self._project = project
        self._rebase = None # rebase needs to be either specified or inferred
        self._code_base = None

        self._project_update()

    def _project_update(self):
        if type(self._value) is int:
            self._value = claripy.BVV(self._value, self._project.arch.bits)
        pie = self._project.loader.main_object.pic
        self._code_base = self._project.loader.main_object.mapped_base if pie else 0
        if not pie:
            self._rebase = False

    def __add__(self, other):
        cp = self.copy()
        if type(other) is int:
            cp._value += other
        elif isinstance(other, RopValue):
            cp._value += other._value
            cp._rebase |= other._rebase
        else:
            raise ValueError(f"Can't add {other} to RopValue!")
        return cp

    def determined(self, chain):
        res = chain._blank_state.solver.eval_upto(self._value, 2)
        return len(res) <= 1

    def rebase_ptr(self):
        pie = self._project.loader.main_object.pic
        if pie:
            self._value -= self._code_base
            self._rebase = True

    def rebase_analysis(self, chain=None):
        """
        use our best effort to infer whether we should rebase this RopValue or not
        """
        # if not pie, great, we are done
        pie = self._project.loader.main_object.pic
        if not pie:
            self._rebase = False
            return
        # if fully symbolic, we don't know whether it should be rebased or not
        if self.symbolic:
            if chain is None or not self.determined(chain):
                self._rebase = None
                return
            concreted = chain._blank_state.solver.eval(self._value)
        else:
            concreted = self.concreted

        # if concrete, check whether it is a pointer that needs rebase:
        # it is an address within a PIC object
        if concreted < self._project.loader.min_addr or concreted >= self._project.loader.max_addr:
            self._rebase = False
            return
        for obj in self._project.loader.all_elf_objects:
            if obj.pic and obj.min_addr <= concreted < obj.max_addr:
                self._value -= obj.min_addr
                self._rebase = True
                if obj != self._project.loader.main_object:
                    raise NotImplementedError("Currently, angrop does not support rebase library address!")
                return
        self._rebase = False
        return

    @property
    def symbolic(self):
        return self._value.symbolic

    @property
    def ast(self):
        assert self._value.symbolic
        return self.data

    @property
    def concreted(self):
        assert not self._value.symbolic
        if self.rebase:
            return self._code_base + self._value.concrete_value
        return self._value.concrete_value

    @property
    def data(self):
        if self.rebase:
            return self._code_base + self._value
        return self._value

    @property
    def rebase(self):
        #if self._rebase is None:
        #    raise RuntimeError("Somehow rebase is not specified in this RopValue")
        return self._rebase

    def __repr__(self):
        return f"RopValue({self.data}, {self._rebase})"

    def copy(self):
        cp = RopValue(self._value, self._project)
        cp._value = self._value
        cp._project = self._project
        cp._rebase = self._rebase
        cp._code_base = self._code_base
        return cp
