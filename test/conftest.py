import os
import subprocess

import pytest


@pytest.fixture(scope="module")
def make():
    p = subprocess.Popen(["make"])
    p.communicate(timeout=2)

    assert os.path.exists("example")
