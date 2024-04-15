from __future__ import annotations

from typing import List, Union, Set, IO, Optional, Tuple
from functools import cached_property
from pathlib import Path
import tempfile
import hashlib
import pyvex

import networkx as nx
from pydantic import BaseModel, computed_field
from pydantic.dataclasses import dataclass
from checksec.elf import ELFSecurity, ELFChecksecData, PIEType, RelroType

from .consts import Endian, BranchType, IL
from .utils import str2archinfo

@dataclass
class IR:
    lang_name: IL
    data: str

class NativeCode(BaseModel):
    endianness: Optional[Endian] = None
    architecture: Optional[str] = None
    bitness: Optional[int] = None

    def __repr__(self) -> str:
        fields = []
        for f in self.model_fields.keys():
            field = getattr(self, f)
            if field is None:
                continue

            if isinstance(field, str):
                fields.append(f"{f}={field}")
            elif isinstance(field, bytes):
                fields.append(f"{f}=0x{field.hex()}")
            elif getattr(field, '__len__', None) is not None:
                fields.append(f"len({f})={len(field)}")
            else:
                fields.append(f"{f}={field}")

        return f"{self.__class__.__name__}({', '.join(fields)})"
        

class Instruction(NativeCode):
    '''Represents a single instruction'''
    address: Optional[int] = None

    data: bytes
    asm: Optional[str] = ""
    operands: Optional[List[str]] = list()
    comment: Optional[str] = ""
    ir: Optional[IR] = None
    

    xref_to: List[int] = list()
    xref_from: List[int] = list()

    def __len__(self):
        return len(self.data)
    
    def __eq__(self, other:Instruction):
        return self.data == other.data
    
    def __hash__(self):
        return hash(self.data)
    
    def __contains__(self, x:bytes):
        return x in self.data

    def vex(self):
        address = self.address
        if address is None:
            address = 0

        il = pyvex.lift(self.data, address, str2archinfo(self.architecture))
        return IR(lang_name=IL.VEX, data=";".join([stmt.pp() for stmt in il.statements]))

class BasicBlock(NativeCode): 
    address: Optional[int] = None
    pie:PIEType = None

    instructions: List[Instruction] = list()
    branches: Set[Tuple[BranchType, int]] = set([])
    is_prologue: Optional[bool] = False
    is_epilogue: Optional[bool] = False

    xref_to: List[int] = list()
    xref_from: List[int] = list()

    _size_bytes: int = None
    

    # TODO Consider
    # next() -> return subsequent blocks

    def __hash__(self):
        return hash(self.bytes)

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

    def vex(self):
        bb_ir = []
        for instr in self.instructions:
            bb_ir.append(instr.vex().data)
        return IR(lang_name=IL, data=";".join(bb_ir))

class Function(NativeCode):
    address: Optional[int]
    pie:Optional[PIEType] = None
    canary:Optional[bool] = None
    name:str = None
    return_type:str = None
    argv: List[Tuple[str, str]] = None
    source: List[FunctionSource] = list()

    basic_blocks: Set[BasicBlock] = set([])
    prologue: Optional[BasicBlock] = None
    epilogue: Optional[BasicBlock] = None # does this need to be a list?
    
    calls: Optional[Set[Function]] = set([])
    callers: Optional[Set[Function]] = set([])

    xref_to: Optional[List[int]] = list()
    xref_from: Optional[List[int]] = list()

    def __hash__(self):
        return hash(frozenset(self.basic_blocks))
    
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

    def decompile(self):
        pass

class FunctionSource:
    language:str = "C"
    decompiled:bool
    source: str

class Section(BaseModel):
    name: str
    type: str
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

class Binary(NativeCode):
    '''
    This maps 1 to 1 of what you'd load into a disassembler (e.g., ELF, PE, MACH-O, Firmware Dump, Binary Blob)
    '''

    class NoDataException(Exception):
        pass

    # Path to where the binary is stored
    _path: Path = None
    # The file contents of the binary
    _bytes: bytes = None

    _functions: Set[Function] = None

    # A disassembler associated with this binary
    # Properties like `functions` is lazy loaded and requires a disassember
    # to pull that information out 
    _disassembler: 'Disassembler'

    filename: Optional[str] = None
    entrypoint: int = None
    os: str = None
    # TODO base_addr:int = None
    sections: List[Section] = []
    dynamic_libs: Set[str] = set([])
    
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

    def __hash__(self):
        return int(self.sha256, 16)
    
    def __contains__(self, x:Union[Function, BasicBlock, Instruction, bytes]):
        if isinstance(x, Function):
            return x in self.functions
        elif isinstance(x, BasicBlock) or isinstance(x, Instruction) or isinstance(x, bytes):
            return any([x in f for f in self.functions])
 
    def set_path(self, path:Union[Path, str]):
        if isinstance(path, str):
            path = Path(path)
        self._path = path

    def set_disassembler(self, d:'Disassembler'):
        self._disassembler = d

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
    def pie(self) -> PIEType:
        return self._checksec.pie

    @computed_field(repr=False)
    @property
    def canary(self) -> bool:
        return self._checksec.canary

    @computed_field(repr=False)
    @property
    def relro(self) -> RelroType:
        return self._checksec.relro

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

    @computed_field(repr=True)
    @property
    def functions(self) -> Set[Function]:
        if self._functions is None:
            if self._disassembler is None:
                # log warning?
                return None
            else:
                self._functions = set(self._disassembler.functions())

        return self._functions
    
    
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

