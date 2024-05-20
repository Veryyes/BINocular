from __future__ import annotations
from collections.abc import Iterable
from typing import Any, Optional, Tuple, List, IO
import pkgutil
import os
import tempfile
import zipfile
from urllib.request import urlopen
from functools import lru_cache

import pyhidra
from pyhidra.launcher import PyhidraLauncher, HeadlessPyhidraLauncher
from pyhidra.core import _setup_project, _analyze_program

from .disassembler import Disassembler
from .primitives import Section,Instruction, IR, Argument, Branch, Reference, Variable
from .consts import Endian, IL, BranchType, RefType

class Ghidra(Disassembler):
    
    DEFAULT_INSTALL = os.path.join(os.path.dirname(pkgutil.get_loader('binocular').path), 'data', 'ghidra')
    RELEASE_URL = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.2_build/ghidra_11.0.2_PUBLIC_20240326.zip"
    DEFAULT_PROJECT_PATH = os.path.join(os.path.dirname(pkgutil.get_loader('binocular').path), 'data', 'ghidra_proj')

    def __init__(self, verbose=True, project_path:str=None, ghidra_home=None, save_on_close=False):
        super().__init__(verbose=verbose)

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

    def clear(self):
        super().clear()
        self.project.close()
        
        self.project = None
        self.program = None
        self.flat_api = None


    def get_sections(self) -> Iterable[Section]:
        '''
        Returns a list of the sections within the binary.
        Currently only supports sections within an ELF file.
        '''
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

        return sections

    def _mk_addr(self, offset:int):
        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


    def analyze(self, path) -> bool:
        '''
        Loads the binary specified by `path` into the disassembler.
        Implement all diaassembler specific setup and trigger analysis here.
        :returns: True on success, false otherwise
        '''
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.flatapi import FlatProgramAPI
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

        # Create refs to all the managers that ghidra has lol
        self.base_addr = self.program.getImageBase()
        self.fm = self.program.getFunctionManager()
        self.st = self.program.getSymbolTable()
        self.ref_m = self.program.getReferenceManager()
        self.lang_description = self.program.getLanguage().getLanguageDescription()
        self.bb_model = BasicBlockModel(self.program)
        self.listing = self.program.getListing()
        self.monitor = ConsoleTaskMonitor()
        self.decomp = DecompInterface()
        self.decomp.setOptions(DecompileOptions())
        self.decomp.openProgram(self.program)

        return True

    def is_installed(self) -> bool:
        '''Returns Boolean on whether or not the dissassembler is installed'''
        if self.ghidra_home is None:
            self.ghidra_home = os.path.join(Ghidra.DEFAULT_INSTALL, os.listdir(Ghidra.DEFAULT_INSTALL)[0])
        
        return os.path.exists(os.path.join(self.ghidra_home, "support", "launch.sh"))

    def install(self, install_dir=None):
        '''Installs the disassembler to a user specified directory or within the python module if none is specified'''
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

    def get_binary_name(self) -> str:
        '''Returns the name of the binary loaded'''
        return self.program.getName()

    def get_entry_point(self) -> int:
        '''Returns the address of the entry point to the function'''
        from ghidra.program.model.symbol import SymbolType

        for ep_addr in self.st.getExternalEntryPointIterator():
            sym = self.flat_api.getSymbolAt(ep_addr)
            if sym.getSymbolType().equals(SymbolType.FUNCTION):
                entry = self.fm.getFunctionAt(ep_addr)
                if entry.callingConventionName == 'processEntry':
                    return ep_addr.getOffset()

        return None
    
    def get_architecture(self) -> str:
        '''
        Returns the architecture of the binary.
        For best results use either archinfo, qemu, or compilation triplet naming conventions.
        https://github.com/angr/archinfo
        '''
        return str(self.lang_description.getProcessor())
    
    def get_endianness(self) -> Endian:
        '''Returns an Enum representing the Endianness'''
        endian = str(self.lang_description.getEndian())
        if endian == 'little':
            return Endian.LITTLE
        elif endian == 'big':
            return Endian.BIG
        return Endian.OTHER

    def get_bitness(self) -> int:
        '''Returns the word size of the architecture (e.g., 16, 32, 64)'''
        return self.lang_description.getSize()

    def get_base_address(self) -> int:
        '''Returns the base address the binary is based at'''
        return self.program.getImageBase().getOffset()
    
    def get_strings(self, binary_io:IO, file_size:int) -> Iterable[str]:
        '''Returns the list of defined strings in the binary'''
        from ghidra.program.util import DefinedDataIterator

        return [s.value for s in DefinedDataIterator.definedStrings(self.program)]

    def get_dynamic_libs(self) -> Iterable[str]:
        '''Returns the list of names of the dynamic libraries used in this binary'''
        em = self.program.getExternalManager()
        dyn_libs = list(em.getExternalLibraryNames())
        if "<EXTERNAL>" in dyn_libs:
            dyn_libs.pop(dyn_libs.index("<EXTERNAL>"))

        return dyn_libs

    def get_func_iterator(self) -> Iterable["ghidra.program.database.function.FunctionDB"]:
        '''
        Returns an iterable of `Any` data type (e.g., address, interal func obj, dict of data) 
        needed to construct a `Function` object for all functions in the binary.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        for f in self.fm.getFunctions(True):            
            yield f

    def get_func_addr(self, func_ctxt:Any) -> int:
        '''Returns the address of the function corresponding to the function information returned from `get_func_iterator()`'''
        return func_ctxt.getEntryPoint().getOffset()

    def get_func_name(self, addr:int, func_ctxt:Any) -> str:
        '''Returns the name of the function corresponding to the function information returned from `get_func_iterator()`'''
        return func_ctxt.getName()

    @lru_cache
    def _decompile(self, func_ctxt:Any):
        '''Return DecompileResult object. lru_cache'd because it's a little expensive'''
        return self.decomp.decompileFunction(func_ctxt, self.decomp_timeout, self.monitor)
    
    def get_func_args(self, addr:int, func_ctxt:Any) -> List[Argument]:
        '''Returns the arguments in the function corresponding to the function information returned from `get_func_iterator()`'''
        decomp_res = self._decompile(func_ctxt)
        high_func = decomp_res.getHighFunction()
        proto = high_func.getFunctionPrototype()

        # TODO handle var args
        # if func_ctxt.hasVarArgs() ...

        return [
            Argument(
                data_type = str(proto.getParam(i).getDataType()),
                var_name = str(proto.getParam(i).getName())
            ) for i in range(proto.getNumParams())
        ]
    
    def get_func_return_type(self, addr:int, func_ctxt:Any) -> int:
        '''Returns the return type of the function corresponding to the function information returned from `get_func_iterator()`'''
        decomp_res = self._decompile(func_ctxt)
        high_func = decomp_res.getHighFunction()
        proto = high_func.getFunctionPrototype()

        return str(proto.getReturnType())

    def get_func_stack_frame_size(self, addr:int, func_ctxt:Any) -> int:
        '''Returns the size of the stack frame in the function corresponding to the function information returned from `get_func_iterator()`'''
        sf = func_ctxt.getStackFrame()
        return sf.getFrameSize()

    def get_func_vars(self, addr:int, func_ctxt:Any) -> Iterable[Variable]:
        '''Return variables within the function corresponding to the function information returned from `get_func_iterator()`'''
        vars = list()
        for var in func_ctxt.getLocalVariables():
            v = Variable(
                data_type=var.getDataType().getName(),
                name=var.getName(),
                is_register=var.isRegisterVariable(),
                is_stack=var.isStackVariable(),
                stack_offset=var.getStackOffset()
            )
            vars.append(v)
        return vars

    def is_func_thunk(self, addr:int, func_ctxt:Any) -> bool:
        '''Returns True if the function corresponding to the function information returned from `get_func_iterator()` is a thunk'''
        return func_ctxt.isThunk()
    
    def get_func_decomp(self, addr:int, func_ctxt:Any) -> Optional[str]:
        '''Returns the decomplication of the function corresponding to the function information returned from `get_func_iterator()`'''
        decomp_res = self._decompile(func_ctxt)
        return decomp_res.getDecompiledFunction().getC()
    
    def get_func_callers(self, addr:int, func_ctxt:Any) -> Iterable[int]:
        refs = self.ref_m.getReferencesTo(self._mk_addr(addr))
        for ref in refs:
            if ref.getReferenceType().isCall():
                call_addr = ref.getFromAddress()
                caller = self.fm.getFunctionContaining(call_addr)
                if caller is not None:
                    yield caller.getEntryPoint().getOffset()
        
    def get_func_callees(self, addr:int, func_ctxt:Any) -> Iterable[int]:
        for addr in func_ctxt.getBody().getAddresses(True):
            refs = self.ref_m.getReferencesFrom(addr)
            for ref in refs:
                if ref.getReferenceType().isCall():
                    yield ref.getToAddress().getOffset()

    def _parse_ref_type(self, type):
        if type.isCall():
            return RefType.CALL
        if type.isJump():
            return RefType.JUMP
        if type.isRead():
            return RefType.READ
        if type.isWrite():
            return RefType.WRITE
        
        return RefType.UNKNOWN

    def get_func_xrefs(self, addr:int, func_ctxt:Any) -> Iterable[Reference]:
        for addr in func_ctxt.getBody().getAddresses(True):
            from_refs = self.ref_m.getReferencesFrom(addr)
            for ref in from_refs:
                ref_type = ref.getReferenceType()
                yield Reference(
                    from_ = ref.getFromAddress().getOffset(),
                    to = ref.getToAddress().getOffset(),
                    type = self._parse_ref_type(ref_type)
                )

            to_refs = self.ref_m.getReferencesTo(addr)
            for ref in to_refs:
                ref_type = ref.getReferenceType()
                yield Reference(
                    from_ = ref.getFromAddress().getOffset(),
                    to = ref.getToAddress().getOffset(),
                    type = self._parse_ref_type(ref_type)
                )

    def get_func_bb_iterator(self, addr:int, func_ctxt:Any) -> Iterable[Any]:
        '''
        Returns an iterator of `Any` data type (e.g., address, implementation specific basic block information, dict of data)
        needed to construct a `BasicBlock` object for all basic blocks in the function based on function information returned from `get_func_iterator()`.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        blocks = self.bb_model.getCodeBlocksContaining(func_ctxt.getBody(), self.monitor)
        history = set()
        
        while(blocks.hasNext()):
            bb = blocks.next()
            bb_addr = bb.getFirstStartAddress().getOffset()
            
            if bb_addr in history:
                continue

            history.add(bb_addr)
            yield bb
        

    def get_bb_addr(self, bb_ctxt:Any, func_ctxt:Any) -> int:
        '''
        Returns the address of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        return bb_ctxt.getFirstStartAddress().getOffset()

    def get_next_bbs(self, bb_addr:int, bb_ctxt:Any, func_addr:int, func_ctxt:Any) -> Iterable[Branch]:
        '''
        Returns the Branching information of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        dest_refs = bb_ctxt.getDestinations(self.monitor)
        while(dest_refs.hasNext()):
            dest = dest_refs.next()
            if not self.fm.getFunctionAt(dest.getDestinationAddress()):
                dest_addr = dest.getDestinationAddress().getOffset()
                flow_type = dest.getFlowType()
                if flow_type.hasFallthrough():
                    yield Branch(btype=BranchType.FalseBranch, target=dest_addr)
                elif flow_type.isConditional():
                    yield Branch(btype=BranchType.TrueBranch, target=dest_addr)
                elif flow_type.isUnConditional():
                    yield Branch(btype=BranchType.UnconditionalBranch, target=dest_addr)
                elif flow_type.isComputed():
                    yield Branch(btype=BranchType.IndirectBranch, target=None)


    def get_bb_instructions(self, bb_addr:int, bb_ctxt:Any, func_ctxt:Any) -> List[Tuple(bytes, str)]:
        '''
        Returns a iterable of tuples of raw instruction bytes and corresponding mnemonic from the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        instr = list()

        curr_instr = self.listing.getInstructionAt(bb_ctxt.getFirstStartAddress())
        while (curr_instr is not None and bb_ctxt.contains(curr_instr.getAddress())):
            instr.append((bytes(curr_instr.getBytes()), curr_instr.getMnemonicString()))
            curr_instr = curr_instr.getNext()

        return instr
    
    def get_ir_from_instruction(self, instr_addr:int, instr:Instruction) -> Optional[IR]:
        '''
        Returns the Intermediate Representation data based on the instruction given
        '''
        curr_instr = self.listing.getInstructionAt(self._mk_addr(instr_addr))
        pcodes = [str(p) for p in curr_instr.getPcode()]
        return IR(lang_name=IL.PCODE, data=";".join([p for p in pcodes]))

    def get_instruction_comment(self, instr_addr:int) -> Optional[str]:
        '''Return comments at the instruction'''
        # TODO need to implement
        return ""
