from __future__ import annotations
from typing import List, Union, Set, IO, Optional
from functools import cached_property
from pathlib import Path
import tempfile
import hashlib

import networkx as nx
from pydantic import BaseModel, computed_field
from checksec.elf import ELFSecurity, ELFChecksecData, PIEType, RelroType

from .consts import Endian

class Instruction(BaseModel):
    '''Represents a single instruction'''

    endianness: Optional[Endian] = None
    architecture: Optional[str] = None
    bitness: Optional[int] = None

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

class BasicBlock(BaseModel): 
    endianness: Optional[Endian] = None
    architecture: Optional[str] = None
    bitness: Optional[int] = None

    instructions: List[Instruction]
    is_prologue: bool
    is_epilogue: bool

    xref_to: List[int]
    xref_from: List[int]

    _size_bytes: int = None
    pie:PIEType = None

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

    def num_instructions(self):
        return len(self.instructions)

class Function(BaseModel):
    endianness: Optional[Endian] = None
    architecture: Optional[str] = None
    bitness: Optional[int] = None
    pie:PIEType = None
    canary:bool = None

    name:str
    basic_blocks: Set[BasicBlock]
    prologue: BasicBlock
    epilogue: BasicBlock # does this need to be a list?
    
    xref_to: List[int]
    xref_from: List[int]

    

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
    stype: str
    start: int
    offset: int
    size: int
    entsize: int
    link: int
    info: int
    align: int

    # flags
    write: bool = False
    alloc: bool = False
    execute: bool = False
    merge: bool = False
    strings: bool = False
    info_flag: bool = False
    link_order:bool = False
    extra_processing:bool = False
    group: bool = False
    tls:bool = False
    compressed:bool = False
    unknown: bool = False
    os_specific:bool = False
    exclude:bool = False
    mbind:bool = False
    large:bool = False
    processor_specific:bool = False


class Binary(BaseModel):
    '''
    This maps 1 to 1 of what you'd load into a disassembler (e.g., ELF, PE, MACH-O, Firmware Dump, Binary Blob)
    '''

    class NoDataException(Exception):
        pass

    # Path to where the binary is stored
    _path: Path = None
    # The file contents of the binary
    _bytes: bytes = None

    endianness: Optional[Endian] = None
    architecture: Optional[str] = None
    bitness: Optional[int] = None
    entrypoint: int = None
    os: str = None
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
        return hashlib.sha256(self.bytes()).hexdigest()

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

