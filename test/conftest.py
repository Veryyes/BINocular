import os
import subprocess

import pytest


@pytest.fixture(scope="module")
def make():
    p = subprocess.Popen(["make"])
    p.communicate(timeout=2)

    assert os.path.exists("example")
    assert os.path.exists("example_stripped")


@pytest.fixture(scope="module")
def make_cpp():
    p = subprocess.Popen(["make", "cpp_rtti"])
    p.communicate(timeout=60)
    assert p.returncode == 0, "make cpp_rtti failed"

    for name in ("rtti_simple", "rtti_inherit", "rtti_diamond"):
        assert os.path.exists(name), f"C++ test binary '{name}' was not built"
