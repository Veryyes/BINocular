import itertools
import os
import pathlib
import tempfile
from urllib.request import urlopen

from binocular import Ghidra
from binocular.ghidra_impl.core import gzf_project_name


def test_install_release_12():
    with tempfile.TemporaryDirectory() as tmpdirname:
        assert not Ghidra.is_installed(install_dir=tmpdirname)
        Ghidra.install(version="12.0", install_dir=tmpdirname)
        assert Ghidra.is_installed(install_dir=tmpdirname)


def test_install_release_11():
    with tempfile.TemporaryDirectory() as tmpdirname:
        assert not Ghidra.is_installed(install_dir=tmpdirname)
        Ghidra.install(version="11.1.1", install_dir=tmpdirname)
        assert Ghidra.is_installed(install_dir=tmpdirname)


def test_install_local():
    url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20240926.zip"
    tmp_file = "/tmp/binocular_temp_test_file.bin"
    with open(tmp_file, "wb") as f:
        f.write(urlopen(url).read())

    with tempfile.TemporaryDirectory() as tmpdirname:
        assert not Ghidra.is_installed(install_dir=tmpdirname)
        Ghidra.install(install_dir=tmpdirname, local_install_file=tmp_file)
        assert Ghidra.is_installed(install_dir=tmpdirname)

    os.unlink(tmp_file)


def test_build_commit():
    with tempfile.TemporaryDirectory() as tmpdirname:
        assert not Ghidra.is_installed(install_dir=tmpdirname)
        Ghidra.install(version="1e4882d", build=True, install_dir=tmpdirname)
        assert Ghidra.is_installed(install_dir=tmpdirname)


def test_build_commit_2():
    with tempfile.TemporaryDirectory() as tmpdirname:
        assert not Ghidra.is_installed(install_dir=tmpdirname)
        Ghidra.install(
            version="7e6daf45e1c6a541bddeb8733eb21c4baa354c08",
            build=True,
            install_dir=tmpdirname,
        )
        assert Ghidra.is_installed(install_dir=tmpdirname)


def test_binary_not_in_cwd(make):
    assert Ghidra.is_installed()
    with tempfile.TemporaryDirectory() as tmpdir:
        symlink = os.path.join(tmpdir, "example")
        os.symlink(os.path.abspath("example"), symlink)

        with Ghidra(symlink) as g:
            g.analyze()
            assert g.binary is not None


def test_disassm(make):
    assert Ghidra.is_installed()
    with Ghidra("example") as g:
        g.analyze()
        b = g.binary

        assert "example" in b.names

        strings = ["Need at least 1 cmd arg", "i use arch btw"]
        assert set(strings) <= b.strings

        fs = g.functions
        fnames = [f.names for f in fs]
        assert "main" in itertools.chain(*fnames)
        assert "foo" in itertools.chain(*fnames)
        assert "bar" in itertools.chain(*fnames)

        a = sorted(list(b.functions), key=lambda x: x.address)
        b = sorted(list(fs), key=lambda x: x.address)

        for f0, f1 in zip(a, b):
            assert f0 == f1


def test_function(make):
    assert Ghidra.is_installed()
    with Ghidra("example") as g:
        g.analyze()
        binary = g.binary
        f = binary.function_sym("foo")

        f = binary.function_sym("main")
        # print(f.calls_addrs)
        assert binary.function_sym("foo") in [x for x in f.calls]
        assert binary.function_sym("fib") in [x for x in f.calls]

        # Recursive, so itself should be a caller and calls
        f = binary.function_sym("fib")
        assert f in [x for x in f.callers]
        assert f in [x for x in f.calls]


def test_is_stripped(make):
    assert Ghidra.is_installed()
    with Ghidra("example") as g:
        g.analyze()
        assert g.is_stripped() is False


def test_is_stripped_true(make):
    assert Ghidra.is_installed()
    with Ghidra("example_stripped") as g:
        g.analyze()
        assert g.is_stripped() is True


def test_has_debug_info(make):
    assert Ghidra.is_installed()
    with Ghidra("example") as g:
        g.analyze()
        assert g.has_debug_info() is True


def test_has_debug_info_false(make):
    assert Ghidra.is_installed()
    with Ghidra("example_stripped") as g:
        g.analyze()
        assert g.has_debug_info() is False


def test_script(make):
    assert Ghidra.is_installed()
    with Ghidra("example") as g:
        g.analyze()
        stdout = g.run_script("./ghidra_script.py", 10)

    assert stdout is not None
    assert "Ghidra Version:" in stdout


def test_script_args(make):
    assert Ghidra.is_installed()
    with Ghidra("example") as g:
        g.analyze()
        script_args = ["ARRRGH", "BLEHH", "BIN OCULAR", '"X"']
        stdout = g.run_script("./ghidra_script_args.py", 10, script_args=script_args)
        assert stdout is not None
        for a in script_args:
            assert a in stdout


def test_script_java(make):
    assert Ghidra.is_installed()
    with Ghidra("example") as g:
        g.analyze()
        stdout = g.run_script("HelloWorld.java", 10)
    assert "Hello, World!" in stdout


def test_export_gzf(make):
    assert Ghidra.is_installed()
    with tempfile.TemporaryDirectory() as tmpdir:
        out = pathlib.Path(tmpdir) / "example.gzf"
        with Ghidra("example") as g:
            g.analyze()
            result = g.export_gzf(out)

        assert result == out
        assert result.exists()
        assert result.suffix == ".gzf"
        assert gzf_project_name(result) == "example"


def test_export_gzf_adds_suffix(make):
    assert Ghidra.is_installed()
    with tempfile.TemporaryDirectory() as tmpdir:
        out = pathlib.Path(tmpdir) / "example"
        with Ghidra("example") as g:
            g.analyze()
            result = g.export_gzf(out)

        assert result.suffix == ".gzf"
        assert result.exists()
