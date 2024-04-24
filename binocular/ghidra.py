from __future__ import annotations
from collections.abc import Iterable
from typing import Union
import pkgutil
import os
import tempfile
import zipfile
from urllib.request import urlopen

import pyhidra
from pyhidra.launcher import PyhidraLauncher, HeadlessPyhidraLauncher
from pyhidra.core import _setup_project, _analyze_program

from .disassembler import Disassembler
from .primitives import Binary, Section, Function, BasicBlock, Instruction, IR, FunctionSource
from .consts import Endian, IL, BranchType

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
        self.decomp_timeout = 60
        
    def open(self):
        if not PyhidraLauncher.has_launched():
            HeadlessPyhidraLauncher(install_dir=self.ghidra_home,verbose=False).start()
        return self

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
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra.program.model.block import BasicBlockModel

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
        self.bb_model = BasicBlockModel(self.program)
        self.listing = self.program.getListing()
        self.monitor = ConsoleTaskMonitor()
        self.decomp = DecompInterface()
        self.decomp.setOptions(DecompileOptions())
        self.decomp.openProgram(self.program)

        lang_data = self.lang.getLanguageDescription()
        
        endian = str(lang_data.getEndian())
        if endian == 'little':
            props['endianness'] = Endian.LITTLE
        elif endian == 'big':
            props['endianness'] = Endian.BIG

        props['filename'] = self.program.getName()
        props['names'] = [os.path.basename(props['filename'])]
        props['entrypoint'] = self._get_entrypoint()
        props['architecture'] = str(lang_data.getProcessor())
        props['bitness'] = lang_data.getSize()
        props['base_addr'] = self.program.getImageBase()

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
        from ghidra.program.model.symbol import FlowType

        res = self.decomp.decompileFunction(f, self.decomp_timeout, self.monitor)
        high_func = res.getHighFunction()
        proto = high_func.getFunctionPrototype()
        
        decomp = res.getDecompiledFunction().getC()
        dsrc = FunctionSource(
            decompiled=True,
            source = decomp
        )

        func = Function(
            endianness=self._bin.endianness,
            architecture=self._bin.architecture,
            bitness=self._bin.bitness,
            pie=self._bin.pie,
            canary=self._bin.canary,
            address=f.getEntryPoint().getOffset(),
            names=[f.getName()],
            return_type=str(proto.getReturnType()),
            argv = [(str(proto.getParam(i).getDataType()), str(proto.getParam(i).getName())) for i in range(proto.getNumParams())],
            thunk=f.isThunk()
        )
        func.sources.add(dsrc)

        blocks = self.bb_model.getCodeBlocksContaining(f.getBody(), self.monitor)
        history = set()
        while(blocks.hasNext()):
            bb = blocks.next()
            bb_addr = bb.getFirstStartAddress().getOffset()
            
            if bb_addr in history:
                continue

            history.add(bb_addr)
            basicblock = BasicBlock(
                endianness=self._bin.endianness,
                architecture=self._bin.architecture,
                bitness=self._bin.bitness,
                pie=self._bin.pie,
                address=bb_addr,
            )

            if bb_addr == func.address:
                func.start = basicblock

            dest_refs = bb.getDestinations(self.monitor)
            while(dest_refs.hasNext()):
                dest = dest_refs.next()
                if not self.fm.getFunctionAt(dest.getDestinationAddress()):
                    dest_addr = dest.getDestinationAddress().getOffset()
                    flow_type = dest.getFlowType()
                    if flow_type.hasFallthrough():
                        basicblock.branches.add((BranchType.FalseBranch, dest_addr))
                    elif flow_type.isConditional():
                        basicblock.branches.add((BranchType.TrueBranch, dest_addr))
                    elif flow_type.isUnConditional():
                        basicblock.branches.add((BranchType.UnconditionalBranch, dest_addr))
                    elif flow_type.isComputed():
                        basicblock.branches.add((BranchType.IndirectBranch, None))

            curr_instr = self.listing.getInstructionAt(bb.getFirstStartAddress())
            while (curr_instr is not None and bb.contains(curr_instr.getAddress())):
                pcodes = [str(p) for p in curr_instr.getPcode()]
                ir = IR(lang_name=IL.PCODE, data=";".join([p for p in pcodes]))
                instr = Instruction(
                    endianness=self._bin.endianness,
                    architecture=self._bin.architecture,
                    bitness=self._bin.bitness,
                    address=curr_instr.getAddress().getOffset(), 
                    data=bytes(curr_instr.getBytes()),
                    asm=curr_instr.getMnemonicString(),
                    ir=ir,
                )
                basicblock.instructions.append(instr)
                
                curr_instr = curr_instr.getNext()

            func.basic_blocks.add(basicblock)
            basicblock.set_function(func)

        return func

    def function(self, address: int) -> Function:
        addr = self._mk_addr(address)
        return self._convert_func(self.fm.getFunctionAt(addr))

    def function_sym(self, symbol: str) -> Function:
        # TODO add error handling
        return self._convert_func(self.flat_api.getGlobalFunctions(symbol)[0])

    def functions(self) -> Iterable[Function]:
        for f in self.fm.getFunctions(True):
            yield self._convert_func(f)

    def basic_block(self, address: int) -> BasicBlock:
        if isinstance(address, int):
            addr = self._mk_addr(address)
            
        bb = self.bb_model.getFirstCodeBlockContaining(addr)
        basicblock = BasicBlock(
            endianness=self._bin.endianness,
            architecture=self._bin.architecture,
            bitness=self._bin.bitness,
            pie=self._bin.pie,
            address=address.getOffset(),
        )

        curr_instr = self.listing.getInstructionAt(self._mk_addr(address))
        while (bb.contains(curr_instr.getAddress())):
            pcodes = list(curr_instr.getPCode())
            ir = IR(lang_name=IL.PCODE, data=";".join([p for p in pcodes]))
            instr = Instruction(
                endianness=self._bin.endianness,
                architecture=self._bin.architecture,
                bitness=self._bin.bitness,
                address=curr_instr.getAddress().getOffset(), 
                data=bytes(curr_instr.getBytes()),
                asm=curr_instr.getMnemonicString(),
                ir=ir,
            )
            basicblock.instructions.append(instr)
            
            curr_instr = curr_instr.getNext()

    def instruction(self, address: int) -> Instruction:
        if isinstance(address, int):
            addr = self._mk_addr(address)
        
        curr_instr = self.listing.getInstructionAt(addr)
        pcodes = list(curr_instr.getPCode())
        ir = IR(lang_name=IL.PCODE, data=";".join([p for p in pcodes]))
        instr = Instruction(
            endianness=self._bin.endianness,
            architecture=self._bin.architecture,
            bitness=self._bin.bitness,
            address=curr_instr.getAddress().getOffset(), 
            data=bytes(curr_instr.getBytes()),
            asm=curr_instr.getMnemonicString(),
            ir=ir,
        )
        
        return instr