from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any, Optional, Tuple, List

from .primitives import (BasicBlock, Binary, Function, FunctionSource,
                         Instruction, Section, Argument, Branch, IR)

from .consts import Endian

class Disassembler(ABC):
    class FailedToLoadBinary(Exception):
        pass
    class ArchitectureNotSupported(Exception):
        pass

    def __init__(self):
        self._func_names = dict()
        self._func_addrs = dict()
        self._bbs = dict()
        self._instrs = dict()

    def __enter__(self):
        return self.open()

    def __exit__(self, type, value, tb):
        self.close()

    def load(self, path):
        '''Load a binary into the disassembler and trigger any default analysis'''
        self._binary_filepath = path
        if not self.analyze(self._binary_filepath):
            raise Disassembler.FailedToLoadBinary
        self._create_binary()
        self._create_functions()

    def _create_binary(self):
        sections = self.get_sections()
        self.binary = Binary(
            sections=sections,
            filename=os.path.basename(self._binary_filepath),
            names=[self.get_binary_name()],
            entrypoint=self.get_entry_point(),
            architecture=self.get_architecture(),
            endianness=self.get_endianness(),
            bitness=self.get_bitness(),
            base_addr=self.get_base_address(),
            strings=self.get_strings(),
            dynamic_libs=self.get_dynamic_libs()
        )
        self.binary.set_path(self._binary_filepath)
        self.binary.set_disassembler(self)

        self.functions = set()

    def _create_functions(self):
        for func_ctxt in self.get_func_iterator():
            addr = self.get_func_addr(func_ctxt)
            func_name = self.get_func_name(addr, func_ctxt)
           
            f = Function(
                endianness=self.binary.endianness,
                architecture=self.binary.architecture,
                bitness=self.binary.bitness,
                pie=self.binary.pie,
                canary=self.binary.canary,
                address=addr,
                names=[func_name],
                return_type=self.get_func_return_type(addr, func_ctxt),
                argv=self.get_func_args(addr, func_ctxt),
                thunk=self.is_func_thunk(addr, func_ctxt)
            )

            decompiled_code = self.get_func_decomp(addr, func_ctxt)
            dsrc = None
            if decompiled_code is not None:
                dsrc = FunctionSource(
                    decompiled=True,
                    name=func_name,
                    source=decompiled_code
                )
                f.sources.add(dsrc)

            self._create_basicblocks(addr, func_ctxt, f)
        
            self.functions.add(f)

            self._func_addrs[addr] = f
            self._func_names[func_name] = f

    def _create_basicblocks(self, addr:int, func_ctxt:Any, f:Function):
        for bb_ctxt in self.get_func_bb_iterator(addr, func_ctxt):
            bb_addr = self.get_bb_addr(bb_ctxt, func_ctxt)
                
            bb = BasicBlock(
                endianness=self.binary.endianness,
                architecture=self.binary.architecture,
                bitness=self.binary.bitness,
                pie=self.binary.pie,
                address = bb_addr
            )

            if bb_addr == f.address:
                f.start = bb

            for branch_data in self.get_next_bbs(bb_addr, bb_ctxt, addr, func_ctxt):
                bb.branches.add(branch_data)

            self._create_instructions(bb_addr, bb_ctxt, bb, func_ctxt)

            f.basic_blocks.add(bb)
            bb.set_function(f)

            self._bbs[bb_addr] = bb

    def _create_instructions(self, bb_addr:int, bb_ctxt:Any, bb:BasicBlock, func_ctxt:Any):
        cur_addr = bb_addr
        for data, asm in self.get_bb_instructions(bb_addr, bb_ctxt, func_ctxt):
            instr = Instruction(
                endianness=self.binary.endianness,
                architecture=self.binary.architecture,
                bitness=self.binary.bitness,
                address=cur_addr,
                data=data,
                asm=asm,
                comment=self.get_instruction_comment(cur_addr)
            )
            ir=self.get_ir_from_instruction(cur_addr, instr)
            instr.ir = ir
            bb.instructions.append(instr)
            self._instrs[cur_addr] = instr

            cur_addr += len(data)

    def function_at(self, address:int) -> Function:
        '''Returns a Function at the address specified'''
        return self._func_addrs.get(address, None)

    def function_sym(self, symbol:str) -> Function:
        '''Returns a Function with the given symbol names'''
        return self._func_names.get(symbol, None)

    def basic_block(self, address:int) -> BasicBlock:
        '''Returns a basic block at the given address'''
        return self._bbs.get(address, None)

    def instruction(self, address:int) -> Instruction:
        '''Returns the instruction at the given address'''
        return self._instrs.get(address, None)

    #######################################################
    # REQUIRED & OPTIONAL DISASSEMBLER DEFINED OPERATIONS #
    #######################################################

    def open(self):
        '''Open up any resources'''
        return self

    def close(self):
        '''Release/Free up any resources'''
        pass

    @abstractmethod
    def analyze(self, path) -> bool:
        '''
        Loads the binary specified by `path` into the disassembler.
        Implement all diaassembler specific setup and trigger analysis here.
        :returns: True on success, false otherwise
        '''
        raise NotImplementedError

    @abstractmethod
    def is_installed(self) -> bool:
        '''Returns Boolean on whether or not the dissassembler is installed'''
        raise NotImplementedError

    @abstractmethod
    def install(self, install_dir=None):
        '''Installs the disassembler to a user specified directory or within the python module if none is specified'''
        raise NotImplementedError
       
    def get_sections(self) -> Iterable[Section]:
        '''
        Returns a list of the sections within the binary.
        Currently only supports sections within an ELF file.
        '''
        return list()

    def get_binary_name(self) -> str:
        '''Returns the name of the binary loaded'''
        return os.path.basename(self._binary_filepath)

    @abstractmethod
    def get_entry_point(self) -> int:
        '''Returns the address of the entry point to the function'''
        raise NotImplementedError

    @abstractmethod
    def get_architecture(self) -> str:
        '''
        Returns the architecture of the binary.
        For best results use either archinfo, qemu, or compilation triplet naming conventions.
        https://github.com/angr/archinfo
        '''
        raise NotImplementedError

    @abstractmethod
    def get_endianness(self) -> Endian:
        '''Returns an Enum representing the Endianness'''
        raise NotImplementedError

    @abstractmethod
    def get_bitness(self) -> int:
        '''Returns the word size of the architecture (e.g., 16, 32, 64)'''
        raise NotImplementedError

    @abstractmethod
    def get_base_address(self) -> int:
        '''Returns the base address the binary is based at'''
        raise NotImplementedError

    @abstractmethod
    def get_strings(self) -> Iterable[str]:
        '''Returns the list of defined strings in the binary'''
        raise NotImplementedError

    @abstractmethod
    def get_dynamic_libs(self) -> Iterable[str]:
        '''Returns the list of names of the dynamic libraries used in this binary'''
        raise NotImplementedError

    @abstractmethod
    def get_func_iterator(self) -> Iterable[Any]:
        '''
        Returns an iterable of `Any` data type (e.g., address, interal func obj, dict of data) 
        needed to construct a `Function` object for all functions in the binary.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        raise NotImplementedError

    @abstractmethod
    def get_func_addr(self, func_ctxt:Any) -> int:
        '''Returns the address of the function corresponding to the function information returned from `get_func_iterator()`'''
        raise NotImplementedError

    @abstractmethod
    def get_func_name(self, addr:int, func_ctxt:Any) -> str:
        '''Returns the name of the function corresponding to the function information returned from `get_func_iterator()`'''
        raise NotImplementedError

    @abstractmethod
    def get_func_args(self, addr:int, func_ctxt:Any) -> List[Argument]:
        '''Returns the arguments in the function corresponding to the function information returned from `get_func_iterator()`'''
        raise NotImplementedError
    
    @abstractmethod
    def get_func_return_type(self, addr:int, func_ctxt:Any) -> int:
        '''Returns the return type of the function corresponding to the function information returned from `get_func_iterator()`'''
        raise NotImplementedError

    @abstractmethod
    def is_func_thunk(self, addr:int, func_ctxt:Any) -> bool:
        '''Returns True if the function corresponding to the function information returned from `get_func_iterator()` is a thunk'''
        raise NotImplementedError

    @abstractmethod
    def get_func_decomp(self, addr:int, func_ctxt:Any) -> Optional[str]:
        '''Returns the decomplication of the function corresponding to the function information returned from `get_func_iterator()`'''
        raise NotImplementedError
    
    @abstractmethod
    def get_func_bb_iterator(self, addr:int, func_ctxt:Any) -> Iterable[Any]:
        '''
        Returns an iterator of `Any` data type (e.g., address, implementation specific basic block information, dict of data)
        needed to construct a `BasicBlock` object for all basic blocks in the function based on function information returned from `get_func_iterator()`.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        raise NotImplementedError

    @abstractmethod
    def get_bb_addr(self, bb_ctxt:Any, func_ctxt:Any) -> int:
        '''
        Returns the address of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        raise NotImplementedError

    @abstractmethod
    def get_next_bbs(self, bb_addr:int, bb_ctxt:Any, func_addr:int, func_ctxt:Any) -> Iterable[Branch]:
        '''
        Returns the Branching information of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        raise NotImplementedError

    @abstractmethod
    def get_bb_instructions(self, bb_addr:int, bb_ctxt:Any, func_ctxt:Any) -> List[Tuple(bytes, str)]:
        '''
        Returns a iterable of tuples of raw instruction bytes and corresponding mnemonic from the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        raise NotImplementedError

    @abstractmethod
    def get_ir_from_instruction(self, instr_addr:int, instr:Instruction) -> Optional[IR]:
        '''
        Returns a list of Intermediate Representation data based on the instruction given
        '''
        raise NotImplementedError

    @abstractmethod
    def get_instruction_comment(self, instr_addr:int) -> Optional[str]:
        '''Return comments at the instruction'''
        raise NotImplementedError
