from __future__ import annotations
from collections.abc import Iterable
import pkgutil
import os
import tempfile
import zipfile
from urllib.request import urlopen

import pyhidra
from pyhidra.launcher import PyhidraLauncher, HeadlessPyhidraLauncher
from pyhidra.core import _setup_project, _analyze_program

from .disassembler import Disassembler
from .primitives import Binary, Section, Function, BasicBlock, Instruction, IR

class Ghidra(Disassembler):
    DEFAULT_INSTALL = os.path.join(os.path.dirname(pkgutil.get_loader('binocular').path), 'data', 'ghidra')
    RELEASE_URL = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.2_build/ghidra_11.0.2_PUBLIC_20240326.zip"
    DEFAULT_PROJECT_PATH = os.path.join(os.path.dirname(pkgutil.get_loader('binocular').path), 'data', 'ghidra_proj')

    def __init__(self, project_path:str=None, ghidra_home=None, save_on_close=False):
        self.project = None
        self.program = None

        if project_path is None:
            project_path = Ghidra.DEFAULT_PROJECT_PATH
        self.project_location = os.path.dirname(project_path)
        self.project_name = os.path.basename(project_path)

        if ghidra_home is None:
            self.ghidra_home = os.path.join(Ghidra.DEFAULT_INSTALL, os.listdir(Ghidra.DEFAULT_INSTALL)[0])
        else:
            self.ghidra_home = ghidra_home

        self.save_on_close = save_on_close

    def __enter__(self):
        if not PyhidraLauncher.has_launched():
            print(self.ghidra_home)
            HeadlessPyhidraLauncher(install_dir=self.ghidra_home).start()
        return self

    def __exit__(self, type, value, tb):
        self.close()

    def close(self):
        from ghidra.app.script import GhidraScriptUtil
        GhidraScriptUtil.releaseBundleHostReference()
        if self.project is not None:
            if self.save_on_close:        
                self.project.save(self.program)
            self.project.close()

    def is_installed(self) -> bool:
        if self.ghidra_home is None:
            self.ghidra_home = os.path.join(Ghidra.DEFAULT_INSTALL, os.listdir(Ghidra.DEFAULT_INSTALL)[0])
        
        return os.path.exists(os.path.join(self.ghidra_home, "support", "launch.sh"))
        
    def install(self, install_dir=None):
        if install_dir is None:
            install_dir = Ghidra.DEFAULT_INSTALL

        print("Downloading Ghidra")
        with tempfile.TemporaryFile() as fp:
            fp.write(urlopen(Ghidra.RELEASE_URL).read())
            fp.seek(0)
            print("Extracting Ghidra")
            with zipfile.ZipFile(fp, 'r') as zf:
                zf.extractall(install_dir)

        self.ghidra_home = os.path.join(install_dir, os.listdir(install_dir)[0])
        assert os.path.exists(self.ghidra_home)
        
        pyhidra.DeferredPyhidraLauncher(install_dir=self.ghidra_home).start()

    def load(self, path):
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.flatapi import FlatProgramAPI

        self.project, self.program = _setup_project(
            path,
            self.project_location,
            self.project_name,
            None,
            None
        )
        GhidraScriptUtil.acquireBundleHostReference()

        flat_api = FlatProgramAPI(self.program)
        _analyze_program(flat_api, self.program)

    def binary(self) -> Binary:
        return super().binary()

    def function(self, address: int) -> Function:
        return super().function(address)

    def function_sym(self, symbol: str) -> Function:
        return super().function_sym(symbol)

    def functions(self) -> Iterable[Function]:
        return super().functions()