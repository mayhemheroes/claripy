"""
Load the clari module in ./lib and install operators / sugar
Warning: This requires hooking clari, it modifies the module
"""
import logging
import sys
import os

# TODO: find a better way, pybind11 doesn't seem to play well with relative imports
old = sys.path
sys.path = [ os.path.join(os.path.dirname(__file__), "lib") ]
import clari
sys.path = old
del old


config_log = logging.getLogger(__file__)


# TODO: remove clari.Create.foo from method calls (dict lookups are costly)
class Load:
    """
    A class used to load claricpp into claripy
    """
    def __init__(self, *, debug_mode: bool = False):
        self._debug_mode = debug_mode

    def config(self, *, src_root: str = None):
        """
        Configure claricpp to work with claripy
        """
        self._fix_operators()
        if src_root:
            clari.API.add_source_root(src_root)

    def establish_link(self, *, logger):
        """
        Link claricpp and claripy's logging and exception systems
        """
        self._link_logging(logger, debug_mode=self._debug_mode)
        clari.Util.Err.Claricpp.toggle_backtrace(self._debug_mode)
        if self._debug_mode:
            clari.API.enable_signal_traces()
        enabled = ("en" if self._debug_mode else "dis") + "abled"
        config_log.info(f"Native backtraces {enabled}")
        self._link_exceptions(logger)

    def define_members(self):
        """
        Define's various functions for clari to make it far easier to use
        """
        Create = clari.Create
        rm = clari.Mode.FP.Rounding
        rm.default = rm.NearestTiesEven
        Create.pos = lambda x: x
        self._py_obj_ctors()
        self._def_magic_ops()

    @staticmethod
    def _py_obj_ctors():
        clari.PyObj.VS.factory = clari.API.py_obj_ctor.vs
        del clari.API.py_obj_ctor

    @staticmethod
    def _fix_operators():
        Create = clari.Create
        # Equality (bindings default to pointer equality)
        clari.Expr.Base.__eq__ = lambda a, b: Create.eq(a, b)
        clari.Expr.Base.__ne__ = lambda a, b: Create.neq(a, b)
        # Hashing
        # clari.Annotation.Base.__hash__ = lambda x: x.hash
        # clari.Annotation.Vec.__hash__ = lambda x: x.hash
        # clari.Expr.Base.__hash__ = lambda x: x.hash
        # clari.Op.PyObj.__hash__ = lambda x: x.hash
        # clari.Op.Base.__hash__ = lambda x: x.hash TODO: consolidate
        config_log.info("Claricpp uses unsigned 64-bit integers to store hashes; "
            "python uses signed 64-bit integers. The unsigned variant "
            "is available via x.hash; the signed variant is returned by hash(x)")
        clari.Mode.FP.Width.__hash__ = lambda x: hash(x.exp, + (x.mantissa << 32))
        # TODO: make make C++ hashes signed?
        clari.Hash.Hashed.__hash__ = clari.PyObj.Base.py_hash
        # repr (ignore pybind11 defaults)
        # TODO: consolidate? HasRepr.__repr__ ?
        clari.Annotation.Base.__repr__ = clari.Annotation.Base.repr
        clari.Annotation.Vec.__repr__ = clari.Annotation.Vec.repr
        clari.PyObj.Base.__repr__ = clari.PyObj.Base.repr
        clari.Expr.Base.__repr__ = clari.Expr.Base.repr
        clari.Op.Base.__repr__ = clari.Op.Base.repr

    @staticmethod
    def _link_logging(logger, *, debug_mode: bool):
        # Allow level synchronization if Claricpp supports it
        if hasattr(clari.API, "set_log_level"):
            # Hook setLevel to call the C++ version as well
            if not hasattr(logger, "_original_setLevel"):  # Don't overwrite
                logger._original_setLevel = logger.setLevel

            def _set_level(lvl):
                logger._original_setLevel(lvl)
                clari.API.set_log_level(lvl)

            logger.setLevel = _set_level
            msg = "Synchrnoizing Claripy/Claricpp log levels: hooking log.setLevel"
            logger.info(msg)
        else:
            lvl = logging.getLevelName(clari.API.get_log_level())
            logger.info("Claricpp's log level is fixed at: " + lvl)
        # Update log level (also synchronizes log levels if applicable)
        logger.setLevel(logging.DEBUG if debug_mode else logger.getEffectiveLevel())
        # Install logger
        # TODO: don't bother having C++ send name, incoporate as needed instead
        f = lambda name, lvl, msg: logger.log(level=lvl, msg=(name + " : " + msg))
        clari.API.install_logger(f)

    @staticmethod
    def _link_exceptions(logger):
        def native_trace(self):
            if not hasattr(self, "_native_trace"):
                lazy = self._lazy_bt
                # Free the lazy object since we cache the evaluation
                del self._lazy_bt
                if lazy is not None:
                    try:
                        lazy = lazy.str()  # Evaluate lazy
                    except Exception as e:
                        msg = f"Failed to extract native backtrace because: {e}"
                        logger.error(msg)
                self._native_trace = lazy
            return self._native_trace

        def _cls_init(self, *args, **kwargs):
            self.native_trace = lambda: native_trace(self)
            self._lazy_bt = clari.Util.Err.Claricpp.lazy_backtrace()
            self._original_init(*args, **kwargs)

        # Override builtin inits with our new init
        Base = clari.py_err._internal.Base
        if not hasattr(Base, "_original_init"):  # In case we called this before
            Base._original_init = Base.__init__
        Base.__init__ = _cls_init

    @staticmethod
    def _def_magic_ops():
        # TODO: reverse operators __radd__ etc
        # TODO: support for things like "x + 3" instead of needing "x + BV(3, 32)"
        # TODO: ask fish __sizeof__ for base # z3 backend uses getsizeof
        # TODO: ask fish __reduce__ for base
        # TODO: VS?
        check = hasattr(clari.Mode.FP.Rounding, "default")
        assert check, "Define a default FP rounding mode first"
        Create = clari.Create
        ### Base / Bits / String
        clari.Expr.Base.__pos__ = Create.pos
        clari.Expr.Bits.__len__ = lambda x: x.bit_length
        clari.Expr.String.__add__ = lambda x, y: Create.concat(x, y)

        ### Bool
        clari.Expr.Bool.__invert__ = lambda x: Create.invert(x)
        clari.Expr.Bool.__not__ = lambda x: Create.invert(x)
        clari.Expr.Bool.__and__ = lambda x: Create.and_(x)
        clari.Expr.Bool.__xor__ = lambda x: Create.xor_(x)
        clari.Expr.Bool.__or__ = lambda x: Create.or_(x)

        ### FP
        # Comparisons
        clari.Expr.FP.__le__ = lambda x, y: Create.sle(x, y)
        clari.Expr.FP.__lt__ = lambda x, y: Create.slt(x, y)
        clari.Expr.FP.__ge__ = lambda x, y: Create.sge(x, y)
        clari.Expr.FP.__gt__ = lambda x, y: Create.sgt(x, y)
        # Math
        rm = clari.Mode.FP.Rounding.default
        clari.Expr.FP.__neg__ = lambda x: Create.neg(x)
        clari.Expr.FP.__add__ = lambda x, y: Create.FP.add(x, y, rm)
        clari.Expr.FP.__sub__ = lambda x, y: Create.FP.sub(x, y, rm)
        clari.Expr.FP.__mul__ = lambda x, y: Create.FP.mul(x, y, rm)
        clari.Expr.FP.__truediv__ = lambda x, y: Create.FP.div(x, y, rm)
        clari.Expr.FP.__abs__ = lambda x: Create.abs(x)

        ### BV
        # Comparisons
        clari.Expr.BV.__le__ = lambda x, y: Create.ule(x, y)
        clari.Expr.BV.__lt__ = lambda x, y: Create.ult(x, y)
        clari.Expr.BV.__ge__ = lambda x, y: Create.uge(x, y)
        clari.Expr.BV.__gt__ = lambda x, y: Create.ugt(x, y)
        # Logical
        clari.Expr.BV.__invert__ = lambda x: Create.invert(x)
        clari.Expr.BV.__and__ = lambda x: Create.and_(x)
        clari.Expr.BV.__xor__ = lambda x: Create.xor_(x)
        clari.Expr.BV.__or__ = lambda x: Create.or_(x)
        # Math
        clari.Expr.BV.__neg__ = lambda x: Create.neg(x)
        clari.Expr.BV.__add__ = lambda *args: Create.add(args)
        clari.Expr.BV.__mul__ = lambda *args: Create.mul(args)
        clari.Expr.BV.__sub__ = lambda x, y: Create.sub(x, y)
        clari.Expr.BV.__floordiv__ = lambda x, y: Create.div(x, y)
        clari.Expr.BV.__abs__ = lambda x: Create.abs(x)
        clari.Expr.BV.__pow__ = lambda a, b: Create.pow(a, b)
        clari.Expr.BV.__mod__ = lambda a, b: Create.mod(a, b)
        clari.Expr.BV.__lshift__ = lambda a, b: Create.shift_l(a, b)
        clari.Expr.BV.__rshift__ = lambda a, b: Create.shift_arithmetic_right(a, b)


__all__ = ("Load", "clari")