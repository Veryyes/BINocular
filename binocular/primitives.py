from __future__ import annotations
from typing import List, Union, Set, IO, Optional
from functools import cached_property
from pathlib import Path
import tempfile

import networkx as nx
from pydantic import BaseModel, computed_field
from checksec.elf import ELFSecurity, ELFChecksecData

from .consts import Endian

class NativeCode(BaseModel):
    _context:NativeCode = None

    def context(self):
        '''
        Provides Flexibilty for objects to have either 
            - inheritable properties from containering objects
            - properties as a standalong object that has no container

        e.g., An Instruction has endianness, but if we know the basic block containing
        the instruction, then we dont need to store the endianness to each instruction and
        just query the containing basic block. Yes the variable space is already allocated
        but it avoids having to set the endianess of each instruction in a bb
        '''
        if self._context is None:
            return self
        return self._context.context()

    _endianness: Optional[Endian] = None
    _architecture: Optional[str] = None
    _bitness: Optional[int] = None

    @computed_field(repr=False)
    @property
    def endianness(self) -> Endian:
        if self.context() == self:
            return self._endianness
        return self.context().endianness

    @endianness.setter
    def endianness(self, value:Union[str, Endian]) -> None:
        if isinstance(value, str):
            if value.lower() == 'little':
                value = Endian.LITTLE
            elif value.lower() == 'big':
                value = Endian.BIG
            else:
                value = Endian.OTHER

        self._endianness = value
    

    @computed_field(repr=False)
    @property
    def architecture(self) -> str:
        if self.context() == self:
            return self._architecture
        return self.context().architecture

    @architecture.setter
    def architecture(self, value:str) -> None:
        self._architecture = value

    @computed_field(repr=False)
    @property
    def bitness(self) -> int:
        if self.context() == self:
            return self._bitness
        return self.context().bitness

    @bitness.setter
    def bitness(self, value:int) -> None:
        self._bitness = value

class Instruction(NativeCode):
    '''Represents a single instruction'''

    _context:BasicBlock = None

    address: Optional[int]
    data: bytes
    opcode: str
    operands: List[str]

    xref_to: List[int]
    xref_from: List[int]

    def __repr__(self):
        raise NotImplementedError

    def __len__(self):
        return len(self.data)
    
    def __eq__(self, other:Instruction):
        return self.data == other.data
    
    def __hash__(self):
        return hash(self.data)
    
    def __contains__(self, x:bytes):
        return x in self.data


class BasicBlock(NativeCode):
    _context:Function = None

    instructions: List[Instruction]
    is_prologue: bool
    is_epilogue: bool

    xref_to: List[int]
    xref_from: List[int]

    _size_bytes: int = None
    _pie:str = None

    # TODO Consider
    # next() -> return subsequent blocks

    def __repr__(self):
        raise NotImplementedError

    def __hash__(self):
        raise hash(self.bytes)

    def __len__(self):
        if self._size_bytes is None:
            self._size_bytes = sum([len(i) for i in self.instructions])            
        return self._size_bytes

    def __contains__(self, x:Union[Instruction, bytes]):
        if isinstance(x, Instruction):
            return x in self.instructions
        elif isinstance(x, bytes):
            return x in self.bytes
        raise TypeError

    @cached_property
    def bytes(self) -> bytes:
        b = b''
        for instr in self.instructions:
            b += instr.data
        return b

    @computed_field(repr=False)
    @property
    def pie(self) -> str:
        if self.context() == self:
            return self._pie
        return self.context().pie

    @pie.setter
    def pie(self, value) -> None:
        self._pie = value

    def num_instructions(self):
        return len(self.instructions)

class Function(NativeCode):
    _context:Binary = None

    name:str
    basic_blocks: Set[BasicBlock]
    prologue: BasicBlock
    epilogue: BasicBlock # does this need to be a list?
    
    xref_to: List[int]
    xref_from: List[int]

    _pie:str = None
    _canary:bool = None

    # TODO CONSIDER:
    # get call args
    # get return type

    def __repr__(self):
        raise NotImplementedError

    def __hash__(self):
        raise NotImplementedError
    
    def __contains__(self, x:Union[BasicBlock, Instruction, bytes]):
        if isinstance(x, BasicBlock):
            return x in self.basic_blocks
        elif isinstance(x, Instruction) or isinstance(x, bytes):
            return any([x in bb for bb in self.basic_blocks])
        raise TypeError

    @computed_field(repr=False)
    @property
    def pie(self):
        if self._context == self:
            return self._pie
        return self.context().pie

    @pie.setter
    def pie(self, value) -> None:
        self._pie = value

    @computed_field(repr=False)
    @property
    def canary(self):
        if self._context == self:
            return self._canary
        return self.context().canary

    @canary.setter
    def canary(self, value) -> None:
        self._canary = value

    # Note: Better to just recalculate this after deserialization
    # We don't have to do any hard analysis of figuring out where jumps/xrefs go
    # because that is assuming already done and stored in this object
    #
    # Should just we reconstructing the Graph Obj and not extra analysis
    @cached_property
    def cfg(self) -> nx.MultiDiGraph:
        raise NotImplementedError

class Section(BaseModel):
    name: str
    start: int
    end: int

class Binary(NativeCode):
    '''
    This maps 1 to 1 of what you'd load into a disassembler (e.g., ELF, PE, MACH-O, Firmware Dump, Binary Blob)
    '''

    class NoDataException(Exception):
        pass

    _context = None

    # Path to where the binary is stored
    _path: Path = None
    # The file contents of the binary
    _bytes: bytes = None

    entrypoint: int = None
    os: str = None
    abi: str = None

    sections: List[Section] = []
    dynamic_libs: Set[Binary] = set([])
    
    functions: Set[Function] = set([])

    # Strings from String table
    # maybe use `$ strings` if not such structure exists in the binary?
    strings: Set[str] = set([])

    @classmethod
    def from_path(cls, path:Union[Path, str], **kwargs):
        obj = cls(**kwargs)
        obj._path = path
        return obj

    @classmethod
    def from_bytes(cls, b:bytes, **kwargs):
        obj = cls(**kwargs)
        obj._bytes = b
        return obj

    # def __repr__(self):
    #     raise NotImplementedError
    
    def __hash__(self):
        return int(self.sha256, 16)
    
    def __contains__(self, x:Union[Function, BasicBlock, Instruction, bytes]):
        if isinstance(x, Function):
            return x in self.functions
        elif isinstance(x, BasicBlock) or isinstance(x, Instruction) or isinstance(x, bytes):
            return any([x in f for f in self.functions])
 
    @computed_field(repr=False)
    @cached_property
    def sha256(self) -> str:
        '''sha256 hex digest of the file'''
        raise NotImplementedError

    @computed_field(repr=False)
    @property
    def nx(self) -> bool:
        return self._checksec.nx

    @computed_field(repr=False)
    @property
    def pie(self) -> str:
        return self._checksec.pie.name

    @computed_field(repr=False)
    @property
    def canary(self) -> bool:
        return self._checksec.canary

    @computed_field(repr=False)
    @property
    def relro(self) -> str:
        return self._checksec.relro.name

    @computed_field(repr=False)
    @property
    def rpath(self) -> bool:
        return self._checksec.rpath

    @computed_field(repr=False)
    @property
    def runpath(self) -> bool:
        return self._checksec.runpath

    @computed_field(repr=False)
    @property
    def stripped(self) -> bool:
        return not self._checksec.symbols

    @computed_field(repr=False)
    @property
    def fortify(self) -> bool:
        return self._checksec.fortify_source

    @computed_field(repr=False)
    @property
    def fortified(self) -> int:
        return self._checksec.fortified

    @computed_field(repr=False)
    @property
    def fortifiable(self) -> int:
        return self._checksec.fortifiable

    @computed_field(repr=False)
    @property
    def fortify_score(self) -> int:
        return self._checksec.fortify_score

    def bytes(self) -> bytes:
        '''return the raw bytes of the binary'''
        if self._bytes is not None:
            return self._bytes

        if self._path is not None:
            with self._path.open("rb") as f:
                self._bytes = f.read()
            return self._bytes

        raise Binary.NoDataException("Binary Object has no Path or data")

    def io(self) -> IO:
        '''returns a stream/IO handle to the bytes of the binary. This function does not self close the stream'''
        if self._path is not None:
            return self._path.open("rb")

        if self._bytes is not None:
            tp = tempfile.NamedTemporaryFile(delete=False)
            tp.write(self._bytes)
            return tp

        raise Binary.NoDataException("Binary Object has no Path or data")

    # def entrypoint(self) -> int:
    #     return None

    # def os(self) -> str:
    #     return None

    # def abi(self) -> str:
    #     return None

    @computed_field(repr=False)
    @cached_property
    def _checksec(self) -> ELFChecksecData:
        fp = None
        path = self._path

        if self._path is None:
            fp = self.io()
            path = fp.name

        # TODO
        # This only works on ELFs. See PESecurity
        elf = ELFSecurity(path)
        cs = elf.checksec_state
 
        if fp is not None:
            fp.close()

        return cs

