import claripy

class ROPValue:
    """
    This class represents a value that needs to be concretized in a ROP chain
    Automatically handles rebase
    """
    def __init__(self, value, project=None):
        if not isinstance(value, (int, claripy.ast.bv.BV)):
            raise ValueError("bad value type!")
        self._value = value # when rebase is needed, value here holds the offset
        self._project = project
        self._rebase = None # rebase needs to be either specified or inferred
        self._code_base = None

    def set_rebase(self, rebase):
        self._rebase = rebase

    def set_project(self, project):
        self._project = project
        if type(self._value) is int:
            self._value = claripy.BVV(self._value, self._project.arch.bits)
        pie = self._project.loader.main_object.pic
        self._code_base = self._project.loader.main_object.mapped_base if pie else 0

    def rebase_analysis(self):
        """
        use our best effort to infer whether we should rebase this ROPValue or not
        """
        # if not pie, great, we are done
        pie = self._project.loader.main_object.pic
        if not pie:
            self._rebase = False
            return
        # if symbolic, we don't know whether it should be rebased or not
        if self.symbolic:
            self._rebase = None
            return
        # if concrete, check whether it is a pointer that needs rebase:
        # it is an address within a PIC object
        concreted = self.concreted
        if concreted < self._project.loader.min_addr or concreted >= self._project.loader.max_addr:
            self._rebase = False
            return
        for obj in self._project.loader.all_elf_objects:
            if obj.pic and obj.min_addr <= concreted and obj.max_addr:
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
        #    raise RuntimeError("Somehow rebase is not specified in this ROPValue")
        return self._rebase