from binocular import Rizin, Binary

def test_instr_serial():
    with Rizin() as g:
        g.load("example")
        f = g.function_sym('fib')
        bb = list(f.basic_blocks)[0]
        instr = bb.instructions[0]
        instr.model_dump_json()

    assert True

def test_bb_serial():
    with Rizin() as g:
        g.load("example")
        f = g.function_sym('fib')
        bb = list(f.basic_blocks)[0]
        bb.model_dump_json()

    assert True

def test_func_serial():
    with Rizin() as g:
        g.load("example")
        f = g.function_sym('fib')
        f.model_dump_json()

    assert True

def test_bin_serial():
    with Rizin() as g:
        g.load("example")
        b = g.binary
        b.model_dump_json()

    assert True