#!/usr/bin/python3
import pdb

import atheris
from io import BytesIO
from contextlib import contextmanager
import logging
import sys

with atheris.instrument_imports():
    import claripy

# No logging
logging.disable(logging.CRITICAL)


# Disable stdout
@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = BytesIO()
    sys.stdout.encoding = 'latin-1'  # For eval to not freak out
    sys.stderr = BytesIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr


def test_solver(fdp):
    s = claripy.Solver()
    bw = fdp.ConsumeIntInRange(1, 128)
    var = claripy.BVS(f'var', bw)

    # Add random constraints
    s.add(var <= fdp.ConsumeIntInRange(0, 2**bw))
    s.add(var >= fdp.ConsumeIntInRange(0, 2**bw))
    s.add(var != fdp.ConsumeIntInRange(0, 2**bw))
    s.add(var % 2 == fdp.ConsumeIntInRange(0, 2))

    s.eval(var, 20)

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    with nostdout():
        try:
            byte_count = fdp.ConsumeIntInRange(0, 100)
            bv_1 = claripy.BVV(fdp.ConsumeBytes(byte_count))
            bv_2 = claripy.BVV(fdp.ConsumeBytes(byte_count))

            # Perform math on the bitvectors
            bv_3 = bv_1 + bv_2
            bv_4 = bv_1 - bv_2
            bv_5 = bv_1 * bv_2
            bv_6 = bv_1 / bv_2
            bv_7 = bv_1 % bv_2
            bv_8 = bv_1 << bv_2
            bv_9 = bv_1 >> bv_2
            bv_10 = bv_1 & bv_2
            bv_11 = bv_1 | bv_2
            bv_12 = bv_1 ^ bv_2
            bv_13 = ~bv_1
            bv_14 = -bv_1
            bv_15 = abs(bv_1)
            bv_19 = bv_1.concat(bv_2)

            test_solver(fdp)
        except claripy.ClaripyError:
            pass  # Don't want to report handled exceptions as crashes


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
