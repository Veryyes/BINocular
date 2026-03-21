import json

from binocular import Binary, Ghidra, Rizin


def test_instr_serial():
    with Rizin("example") as r:
        r.analyze()
        binary = r.binary

        f = binary.function_sym("fib")
        bb = list(f.basic_blocks)[0]
        instr = bb.instructions[0]
        instr.model_dump_json()

    assert True


def test_bb_serial():
    with Rizin("example") as r:
        r.analyze()
        binary = r.binary

        f = binary.function_sym("fib")
        bb = list(f.basic_blocks)[0]
        bb.model_dump_json()

    assert True


def test_func_serial():
    with Rizin("example") as r:
        r.analyze()
        binary = r.binary

        f = binary.function_sym("fib")
        f.model_dump_json()

    assert True


def test_bin_serial():
    with Rizin("example") as r:
        r.analyze()
        b = r.binary
        b.model_dump_json()

    assert True


def test_serial_and_back(make):
    assert Ghidra.is_installed()

    serialized = None
    with Ghidra("example") as g:
        g.analyze()
        b = g.binary
        serialized = json.loads(b.model_dump_json())
        b_prime = Binary.model_validate(serialized)

        assert b.names[0] == b_prime.names[0]
        assert len(b.functions) > 0
        assert len(b.functions) == len(b_prime.functions)
