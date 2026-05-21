import json

from binocular import Binary, Ghidra, NativeFunction, Rizin


def _make_func(*names) -> NativeFunction:
    return NativeFunction(address=0x1000, names=list(names) if names else None)


def _make_binary(*funcs) -> Binary:
    return Binary(functions=set(funcs))


# --- add_name ---


def test_add_name_no_binary():
    f = _make_func("foo")
    f.add_name("bar")
    assert "bar" in f.names
    assert f.name == "foo"  # primary unchanged


def test_add_name_updates_func_names():
    f = _make_func("foo")
    b = _make_binary(f)
    f.add_name("bar")
    assert b.function_sym("bar") is f


def test_add_name_duplicate_is_noop():
    f = _make_func("foo")
    _make_binary(f)
    f.add_name("foo")
    assert f.names.count("foo") == 1


def test_add_name_when_names_is_none():
    f = _make_func()
    assert f.names is None
    f.add_name("foo")
    assert f.names == ["foo"]
    assert f.name == "foo"


def test_add_name_when_names_is_none_updates_func_names():
    f = _make_func()
    b = _make_binary(f)
    f.add_name("foo")
    assert b.function_sym("foo") is f


# --- remove_name ---


def test_remove_name_no_binary():
    f = _make_func("foo", "bar")
    f.remove_name("bar")
    assert "bar" not in f.names


def test_remove_name_alias_removed_from_func_names():
    f = _make_func("foo")
    b = _make_binary(f)
    f.add_name("bar")
    f.remove_name("bar")
    assert b.function_sym("bar") is None
    assert b.function_sym("foo") is f  # primary intact


def test_remove_name_primary_reindexes_new_primary():
    f = _make_func("foo", "bar")
    b = _make_binary(f)
    f.remove_name("foo")
    assert f.name == "bar"
    assert b.function_sym("foo") is None
    assert b.function_sym("bar") is f


def test_remove_name_not_present_is_noop():
    f = _make_func("foo")
    b = _make_binary(f)
    f.remove_name("nonexistent")
    assert f.names == ["foo"]
    assert b.function_sym("foo") is f


def test_remove_name_last_clears_index():
    f = _make_func("foo")
    b = _make_binary(f)
    f.remove_name("foo")
    assert f.names == []
    assert b.function_sym("foo") is None


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
