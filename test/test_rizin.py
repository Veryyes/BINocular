import itertools
import tempfile

from binocular import Binary, Rizin


def test_install_release():
    with tempfile.TemporaryDirectory() as tmpdirname:
        assert not Rizin.is_installed(install_dir=tmpdirname)
        Rizin.install(version="v0.7.3", install_dir=tmpdirname)
        assert Rizin.is_installed(install_dir=tmpdirname)


def test_build_commit():
    with tempfile.TemporaryDirectory() as tmpdirname:
        assert not Rizin.is_installed(install_dir=tmpdirname)
        Rizin.install(version="87add99", build=True, install_dir=tmpdirname)
        assert Rizin.is_installed(install_dir=tmpdirname)


def test_disassm(make):
    with Rizin() as g:
        assert g.is_installed()

        g.load("example")
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


def test_binary(make):
    with Rizin() as g:
        assert g.is_installed()

        g.load("example")
        b = g.binary

        borm = b.orm()
        assert b.architecture == borm.architecture
        assert b.endianness == borm.endianness
        assert b.bitness == borm.bitness
        assert b.entrypoint == borm.entrypoint
        assert b.os == borm.os
        assert b.sha256 == borm.sha256

        b1 = Binary.from_orm(borm)
        assert b1.architecture == borm.architecture
        assert b1.endianness == borm.endianness
        assert b1.bitness == borm.bitness
        assert b1.entrypoint == borm.entrypoint
        assert b1.os == borm.os
        assert b1.sha256 == borm.sha256

        assert b1.architecture == b.architecture
        assert b1.endianness == b.endianness
        assert b1.bitness == b.bitness
        assert b1.entrypoint == b.entrypoint
        assert b1.os == b.os
        assert b1.sha256 == b.sha256


def test_function(make):
    with Rizin() as g:
        assert g.is_installed()

        g.load("example")
        f = g.function_sym("foo")

        form = f.orm()
        assert f.architecture == form.architecture
        assert f.endianness == form.endianness
        assert f.bitness == form.bitness
        assert f.return_type == form.return_type
        assert ", ".join([str(x) for x in f.argv]) == form.argv

        f = g.function_sym("main")
        assert g.function_sym("foo") in [x for x in f.calls]
        assert g.function_sym("fib") in [x for x in f.calls]

        # Recursive, so itself should be a caller and calls
        f = g.function_sym("fib")
        assert f in [x for x in f.callers]
        assert f in [x for x in f.calls]
