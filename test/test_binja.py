import itertools
import json
import os
import tempfile

from binocular import IL, Binary, BinaryNinja, Endian


def test_is_installed():
    assert BinaryNinja.is_installed()


def test_disassm(make):
    assert BinaryNinja.is_installed()
    with BinaryNinja("example") as g:
        g.analyze()
        b = g.binary

        assert "example" in b.names

        strings = ["Need at least 1 cmd arg", "i use arch btw"]
        assert set(strings) <= b.strings

        fs = set(g.functions)
        fnames = [f.names for f in fs]
        assert "main" in itertools.chain(*fnames)
        assert "foo" in itertools.chain(*fnames)
        assert "bar" in itertools.chain(*fnames)

        a = sorted(list(b.functions), key=lambda x: x.address)
        b = sorted(list(fs), key=lambda x: x.address)

        for f0, f1 in zip(a, b):
            assert f0 == f1


def test_function(make):
    assert BinaryNinja.is_installed()
    with BinaryNinja("example") as g:
        g.analyze()
        binary = g.binary
        f = binary.function_sym("foo")

        f = binary.function_sym("main")
        assert binary.function_sym("foo") in [x for x in f.calls]
        assert binary.function_sym("fib") in [x for x in f.calls]

        # Recursive, so itself should be a caller and calls
        f = binary.function_sym("fib")
        assert f in [x for x in f.callers]
        assert f in [x for x in f.calls]


def test_architecture(make):
    with BinaryNinja("example") as g:
        g.analyze()
        b = g.binary

        assert b.architecture is not None
        assert b.bitness == 64
        assert b.endianness == Endian.LITTLE


def test_entry_point(make):
    with BinaryNinja("example") as g:
        g.analyze()
        b = g.binary

        assert b.entrypoint is not None
        assert b.entrypoint > 0


def test_base_address(make):
    with BinaryNinja("example") as g:
        g.analyze()
        b = g.binary

        assert b.base_addr >= 0


def test_dynamic_libs(make):
    with BinaryNinja("example") as g:
        g.analyze()
        b = g.binary

        assert len(b.dynamic_libs) > 0


def test_basic_blocks(make):
    with BinaryNinja("example") as g:
        g.analyze()
        binary = g.binary

        f = binary.function_sym("bar")
        assert len(f.basic_blocks) > 1

        for bb in f.basic_blocks:
            assert bb.address is not None
            assert len(bb.instructions) > 0

            for instr in bb.instructions:
                assert instr.address is not None
                assert instr.data is not None
                assert len(instr.data) > 0
                assert instr.asm is not None


def test_decompilation(make):
    with BinaryNinja("example") as g:
        g.analyze()
        binary = g.binary

        f = binary.function_sym("main")
        assert len(f.sources) > 0

        src = list(f.sources)[0]
        assert src.decompiled
        assert len(src.source) > 0


def test_variables(make):
    with BinaryNinja("example") as g:
        g.analyze()
        binary = g.binary

        f = binary.function_sym("main")
        assert len(f.variables) > 0

        has_stack = any(v.is_stack for v in f.variables)
        assert has_stack


def test_ir(make):
    with BinaryNinja("example") as g:
        g.analyze()
        binary = g.binary

        f = binary.function_sym("main")
        found_bnil = False
        for bb in f.basic_blocks:
            for instr in bb.instructions:
                if instr.ir is not None and instr.ir.lang_name == IL.BNIL:
                    found_bnil = True
                    assert len(instr.ir.data) > 0
                    break
            if found_bnil:
                break

        assert found_bnil


def test_thunk_detection(make):
    with BinaryNinja("example") as g:
        g.analyze()
        binary = g.binary

        thunks = [f for f in binary.functions if f.thunk]
        assert len(thunks) > 0


def test_xrefs(make):
    with BinaryNinja("example") as g:
        g.analyze()
        binary = g.binary

        f = binary.function_sym("main")
        total_xrefs = sum(len(bb.xrefs) for bb in f.basic_blocks)
        assert total_xrefs > 0


def test_binary_not_in_cwd(make):
    assert BinaryNinja.is_installed()
    with tempfile.TemporaryDirectory() as tmpdir:
        symlink = os.path.join(tmpdir, "example")
        os.symlink(os.path.abspath("example"), symlink)

        with BinaryNinja(symlink) as g:
            g.analyze()
            assert g.binary is not None


def test_serialization(make):
    with BinaryNinja("example") as g:
        g.analyze()
        b = g.binary
        serialized = json.loads(b.model_dump_json())
        b_prime = Binary.model_validate(serialized)

        assert b.names[0] == b_prime.names[0]
        assert len(b.functions) > 0
        assert len(b.functions) == len(b_prime.functions)


def test_stack_frame_size(make):
    with BinaryNinja("example") as g:
        g.analyze()
        binary = g.binary

        f = binary.function_sym("main")
        assert f.stack_frame_size > 0


def test_func_args(make):
    with BinaryNinja("example") as g:
        g.analyze()
        binary = g.binary

        main = binary.function_sym("main")
        assert len(main.argv) >= 2

        bar = binary.function_sym("bar")
        assert len(bar.argv) >= 3


def test_func_return_type(make):
    with BinaryNinja("example") as g:
        g.analyze()
        binary = g.binary

        main = binary.function_sym("main")
        assert main.return_type is not None
        assert len(main.return_type) > 0


def test_cfg(make):
    with BinaryNinja("example") as g:
        g.analyze()
        binary = g.binary

        # bar has branches so CFG should have multiple nodes
        bar = binary.function_sym("bar")
        assert len(bar.cfg.nodes) > 1
        assert len(bar.cfg.edges) > 0

        # fib is recursive with branches
        fib = binary.function_sym("fib")
        assert len(fib.cfg.nodes) > 1
