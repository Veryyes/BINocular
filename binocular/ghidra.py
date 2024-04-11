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
from .consts import Endian

class Ghidra(Disassembler):
    DEFAULT_INSTALL = os.path.join(os.path.dirname(pkgutil.get_loader('binocular').path), 'data', 'ghidra')
    RELEASE_URL = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.2_build/ghidra_11.0.2_PUBLIC_20240326.zip"
    DEFAULT_PROJECT_PATH = os.path.join(os.path.dirname(pkgutil.get_loader('binocular').path), 'data', 'ghidra_proj')

    def __init__(self, project_path:str=None, ghidra_home=None, save_on_close=False):
        self.project = None
        self.program = None
        self.flat_api = None

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

    def _get_entrypoint(self):
        from ghidra.program.model.symbol import SymbolType

        for ep_addr in self.st.getExternalEntryPointIterator():
            sym = self.flat_api.getSymbolAt(ep_addr)
            if sym.getSymbolType().equals(SymbolType.FUNCTION):
                entry = self.fm.getFunctionAt(ep_addr)
                if entry.callingConventionName == 'processEntry':
                    return ep_addr.getOffset()
        return None

    def load(self, path):
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.util import DefinedDataIterator
        
        self.project, self.program = _setup_project(
            path,
            self.project_location,
            self.project_name,
            None,
            None
        )
        GhidraScriptUtil.acquireBundleHostReference()

        self.flat_api = FlatProgramAPI(self.program)
        _analyze_program(self.flat_api, self.program)

        props = dict()
        sections = list()

        blocks = self.program.getMemory().getBlocks()
        for block in blocks:
            sections.append(Section(
                name=block.getName(),
                type=str(block.getType()),
                start=block.getStart().getOffset(),
                offset=0,
                size=block.getSize(),
                entsize=0,
                link=0,
                info=0,
                align=0,
                write=block.isWrite(),
                alloc=block.isRead(),
                execute=block.isExecute()
            ))

        self.base_addr = self.program.getImageBase()
        self.fm = self.program.getFunctionManager()
        self.st = self.program.getSymbolTable()
        self.lang = self.program.getLanguage()

        lang_data = self.lang.getLanguageDescription()
        
        endian = str(lang_data.getEndian())
        if endian == 'little':
            props['endianness'] = Endian.LITTLE
        elif endian == 'big':
            props['endianness'] = Endian.BIG

        props['filename'] = self.program.getName()
        props['entrypoint'] = self._get_entrypoint()
        props['architecture'] = str(lang_data.getProcessor())
        props['bitness'] = lang_data.getSize()

        self._bin = Binary(**props)
        self._bin.sections = sections
        self._bin.set_path(self.program.getExecutablePath())
        self._bin.set_disassembler(self)

        # strings
        for s in DefinedDataIterator.definedStrings(self.program):
            self._bin.strings.add(s.value)

        # dyn libs
        em = self.program.getExternalManager()
        self._bin.dynamic_libs = list(em.getExternalLibraryNames())
        if "<EXTERNAL>" in self._bin.dynamic_libs:
            self._bin.dynamic_libs.pop(self._bin.dynamic_libs.index("<EXTERNAL>"))

    def binary(self) -> Binary:
        return self._bin

    def _mk_addr(self, offset:int):
        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    def _convert_func(self, f):
        # import IPython
        # IPython.embed()
        return Function(
            endianness=self._bin.endianness,
            architecture=self._bin.architecture,
            bitness=self._bin.bitness,
            pie=self._bin.pie,
            canary=self._bin.canary,
            address=f.getEntryPoint().getOffset(),
            name=f.getName(),
            return_type=str(f.getReturnType())
            
        )

    def function(self, address: int) -> Function:
        addr = self._mk_addr(address)
        return self._convert_func(self.fm.getFunctionAt(addr))

    def function_sym(self, symbol: str) -> Function:
        pass

    def functions(self) -> Iterable[Function]:
        for f in self.fm.getFunctions(True):
            yield self._convert_func(f)