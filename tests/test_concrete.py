import claripy
import nose

def test_concrete():
    a = claripy.BVV(10, 32)
    b = claripy.BoolVal(True)
    c = claripy.BVS('x', 32)

    nose.tools.assert_is(type(claripy.backend_concrete.convert(a)), claripy.bv.BVV)
    nose.tools.assert_is(type(claripy.backend_concrete.convert(b)), bool)

if __name__ == '__main__':
    test_concrete()
