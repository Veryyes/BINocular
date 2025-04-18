from __future__ import annotations

import posixpath
import subprocess
from collections import defaultdict
from typing import Dict, List, Tuple, Type, Optional
from urllib.parse import unquote, urlsplit

from archinfo import (
    ArchAArch64,
    ArchAMD64,
    ArchARM,
    ArchARMCortexM,
    ArchARMEL,
    ArchARMHF,
    ArchAVR8,
    ArchMIPS32,
    ArchMIPS64,
    ArchNotFound,
    ArchPPC32,
    ArchPPC64,
    ArchRISCV64,
    ArchS390X,
    ArchSoot,
    ArchX86,
)

arches: List[Type] = [
    ArchAArch64,
    ArchAMD64,
    ArchARM,
    ArchARMCortexM,
    ArchARMEL,
    ArchARMEL,
    ArchARMHF,
    ArchAVR8,
    ArchMIPS32,
    ArchMIPS64,
    ArchPPC32,
    ArchPPC64,
    ArchRISCV64,
    ArchS390X,
    ArchSoot,
    ArchX86,
]
archinfo_lookup: Dict[str, Type] = defaultdict(lambda: ArchNotFound)

for a in arches:
    archinfo_lookup[a.name] = a
    archinfo_lookup[a.name.upper()] = a
    archinfo_lookup[a.name.lower()] = a
    if hasattr(a, "qemu_name"):
        archinfo_lookup[a.qemu_name] = a
    if hasattr(a, "linux_name"):
        archinfo_lookup[a.linux_name] = a
    if hasattr(a, "triplet"):
        archinfo_lookup[a.triplet] = a


def run_proc(
    cmd: List[str], timeout: Optional[int] = 15, stdin=False, cwd="."
) -> Tuple[str, str]:
    if stdin:
        stdin = subprocess.PIPE
    else:
        stdin = None

    p = subprocess.Popen(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=stdin
    )
    try:
        out, err = p.communicate(timeout=timeout)
        return str(out, "utf8"), str(err, "utf8")
    except TimeoutError:
        p.kill()
        raise TimeoutError


def url_filename(url: str):
    path = urlsplit(url).path
    return posixpath.basename(unquote(path))


def str2archinfo(a: str):
    return archinfo_lookup[a]()
