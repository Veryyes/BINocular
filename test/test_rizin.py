import itertools
import tempfile

from binocular import Rizin


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
    with Rizin("example") as g:
        assert g.is_installed()

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
    with Rizin("example") as g:
        assert g.is_installed()

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
