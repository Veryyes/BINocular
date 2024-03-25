
from __future__ import annotations

from typing import List, Tuple
import subprocess


def run_proc(cmd:List[str], timeout:int=15, stdin=False, cwd=".") -> Tuple[str, str]:
    if stdin:
        stdin = subprocess.PIPE
    else:
        stdin = None

    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=stdin)
    try:
        out, err = p.communicate(timeout=timeout)
        return str(out, 'utf8'), str(err, 'utf8')
    except TimeoutError:
        p.kill()
        raise TimeoutError
        