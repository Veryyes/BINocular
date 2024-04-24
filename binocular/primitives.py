from __future__ import annotations

from typing import List, Union, Set, IO, Optional, Tuple, Iterable
from functools import cached_property
from pathlib import Path
import os
import tempfile
import hashlib

import networkx as nx
from pydantic import BaseModel, computed_field
from pydantic.dataclasses import dataclass
from checksec.elf import ELFSecurity, ELFChecksecData, PIEType, RelroType
from sqlalchemy.engine.base import Engine
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
import pyvex


from .db import Base, NameORM, StringsORM, BinaryORM, NativeFunctionORM, BasicBlockORM, InstructionORM, IR_ORM, SourceFunctionORM
from .consts import Endian, BranchType, IL, IndirectToken
from .utils import str2archinfo

@dataclass
class IR:
    lang_name: IL
    data: str

class NoDBException(Exception):
    pass

class Backend:
    engine:Engine = None

    @classmethod
    def set_engine(cls, db_uri:str) -> Engine:
        if Backend.engine is None:
            Backend.engine = create_engine(db_uri)
            Base.metadata.create_all(Backend.engine)
        
        return Backend.engine

    def __init__(self, disassembler: 'Disassembler'=None): #, db_uri:str=None):
        self.disassembler = disassembler
        
    @property
    def db(self) -> Engine:
        return Backend.engine

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
    _backend: Backend = Backend()

    address: Optional[int] = None
    data: bytes
    asm: Optional[str] = ""
    comment: Optional[str] = ""
    ir: Optional[IR] = None

    xref_to: List[int] = list()
    xref_from: List[int] = list()

    @classmethod
    def from_orm(cls, orm):
        instruction = cls(
            endianness=orm.endianness,
            architecture=orm.architecture,
            bitness=orm.bitness,
            address = orm.address,
            data=orm.bytes,
            asm=orm.asm,
            comment=orm.comment
        )
        
        if len(orm.ir) > 0:
            # TODO for now, just pick the first one
            ir_data = orm.ir[0]
            ir = IR(
                lang_name=ir_data.lang,
                data=ir_data.data
            )
            instruction.ir = ir
        
        return instruction

    def __len__(self):
        return len(self.data)
    
    def __eq__(self, other:Instruction):
        return self.data == other.data
    
    def __hash__(self):
        return hash(self.data)
    
    def __contains__(self, x:bytes):
        return x in self.data

    def orm(self):
        i = InstructionORM(
            endianness=self.endianness,
            architecture=self.architecture,
            bitness=self.bitness,
            address=self.address,
            bytes = self.data,
            asm=self.asm,
            comment=self.comment,
        )

        ir = None
        if self.ir is not None:
            ir = IR_ORM(
                lang=self.ir.lang_name,
                data=self.ir.data,
                instruction=i
            )
            i.ir.append(ir)

        return i, ir

    def db_add(self, session:Session):
        instr, ir = self.orm()
        session.add(instr)
        session.add(ir)

    def vex(self):
        address = self.address
        if address is None:
            address = 0

        il = pyvex.lift(self.data, address, str2archinfo(self.architecture))
        return IR(lang_name=IL.VEX, data=";".join([stmt.pp() for stmt in il.statements]))

class BasicBlock(NativeCode): 
    _backend: Backend = Backend()

    address: Optional[int] = None
    pie:PIEType = None

    instructions: List[Instruction] = list()
    branches: Set[Tuple[BranchType, int]] = set([])
    is_prologue: Optional[bool] = False
    is_epilogue: Optional[bool] = False

    xref_to: List[int] = list()
    xref_from: List[int] = list()

    _size_bytes: int = None
    
    @classmethod
    def from_orm(cls, orm):
        bb = cls(
            architecture=orm.architecture,
            endianness=orm.endianness,
            bitness=orm.bitness,
            pie=orm.pie,
        )

        for instr_orm in orm.instructions:
            instr = Instruction.from_orm(instr_orm)
            bb.instructions.append(instr)

        return bb


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

    def set_disassembler(self, disassembler:"Disassembler"):
        self._backend.disassembler=disassembler

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

    # TODO ask disassembler first, otherwise default to vex
    def ir(self):
        return self.vex()

    def orm(self):
        bb = BasicBlockORM(
            address=self.address,
            endianness=self.endianness,
            architecture=self.architecture,
            bitness=self.bitness,
            pie=self.pie,
            size=len(self),
        )

        for instr in self.instructions:
            instr_orm, _ = instr.orm()
            bb.instructions.append(instr_orm)
            instr_orm.basic_block=bb
        
        return bb

    def db_add(self, session:Session):
        bb = self.orm()
        session.add(bb)
        for instr in bb.instructions:
            session.add(instr)
            if instr.ir is not None:
                # session.add(instr.ir)
                [session.add(ir) for ir in instr.ir]

class Function(NativeCode):
    _backend: Backend = Backend()

    address: Optional[int] = None
    pie:Optional[PIEType] = None
    canary:Optional[bool] = None
    names:Optional[List[str]] = None
    return_type:Optional[str] = None
    argv: List[Tuple[str, str]] = None
    sources: Set[FunctionSource] = set([])
    thunk:bool = False

    basic_blocks: Optional[Set[BasicBlock]] = set([])
    start: BasicBlock = None
    end: Set[BasicBlock] = set([])
    
    calls: Optional[Set[Function]] = set([])
    callers: Optional[Set[Function]] = set([])

    xref_to: Optional[List[int]] = list()
    xref_from: Optional[List[int]] = list()

    @classmethod
    def from_orm(cls, orm):
        f = cls(
            names=[n.name for n in orm.names],
            architecture=orm.architecture,
            endianness=orm.endianness,
            bitness=orm.bitness,
            pie=orm.pie,
            canary=orm.canary,
            return_type=orm.return_type,
            thunk=orm.thunk,
            argv=[tuple(arg.strip().rsplit(" ", 1)) for arg in orm.argv.split(",")],
        )

        for bb in orm.basic_blocks:
            f.basic_blocks.add(BasicBlock.from_orm(bb))

        for src_f in orm.sources:
            f.sources.add(FunctionSource.from_orm(src_f))

        return f

    def __hash__(self):
        return hash(frozenset(self.basic_blocks))

    def __eq__(self, other:Function) -> bool:
        return hash(self) == hash(other)
    
    def __ne__(self, other:Function) -> bool:
        return hash(self) != hash(other)

    def __contains__(self, x:Union[BasicBlock, Instruction, bytes]):
        if isinstance(x, BasicBlock):
            return x in self.basic_blocks
        elif isinstance(x, Instruction) or isinstance(x, bytes):
            return any([x in bb for bb in self.basic_blocks])
        raise TypeError

    @cached_property
    def cfg(self) -> nx.MultiDiGraph:
        # setup cache
        blocks = dict()
        for bb in self.basic_blocks:
            blocks[bb.address] = bb

        cfg = nx.MultiDiGraph()
        self._cfg(set(), blocks, cfg, self.start)

        return cfg

    def _cfg(self, history, block_cache, g, bb):
        if bb in history:
            return

        history.add(bb)
        g.add_node(bb)
        for btype, addr in bb.branches:
            next_bb = block_cache.get(addr, None)

            if addr is None:
                # Statically Unknown Branch Location (e.g. indirect jump)
                dest = IndirectToken()
            elif next_bb is None:
                # Branch goes to an address that doesnt match a bb we have
                dest = addr
            else:
                dest = next_bb

            g.add_node(dest)
            g.add_edge(bb, dest, branch=btype)

            if isinstance(dest, BasicBlock):
                self._cfg(history, block_cache, g, dest)

    def set_disassembler(self, disassembler:"Disassembler"):
        self._backend.disassembler=disassembler

    def orm(self):
        names = self.names
        if names is None:
            names = list()

        func = NativeFunctionORM(
            names=[NameORM(name=n) for n in names],
            endianness=self.endianness,
            architecture=self.architecture,
            bitness=self.bitness,
            pie=self.pie,
            canary=self.canary,
            return_type=self.return_type,
            thunk=self.thunk,
            argv=", ".join([f"{arg[0]} {arg[1]}" for arg in self.argv]),
            
        )
        for bb in self.basic_blocks:
            block_orm = bb.orm()
            func.basic_blocks.append(block_orm)
            block_orm.function = func

        for src in self.sources:
            src_orm = src.orm()
            func.sources.append(src_orm)
            src_orm.function = func
        
        return func
        
    def db_add(self, session:Session):
        f = self.orm()
        session.add(f)
        for bb in f.basic_blocks:
            session.add(bb)
            for instr in bb.instructions:
                session.add(instr)
                if instr.ir is not None:
                    [session.add(ir) for ir in instr.ir]
       

class FunctionSource(BaseModel):
    _backend: Backend = Backend()

    lang:str = "C"
    decompiled:bool
    source: str

    @classmethod
    def from_orm(cls, orm):
        return cls(
            lang=orm.lang,
            decompiled=orm.decompiled,
            source=orm.source
        )

    def orm(self):
        return SourceFunctionORM(
            sha256=self.sha256,
            lang=self.lang,
            decompiled=self.decompiled,
            source=self.source
        )

    def __hash__(self):
        return int(self.sha256, 16)

    @computed_field(repr=False)
    @cached_property
    def sha256(self) -> str:
        '''sha256 hex digest of the file'''
        return hashlib.sha256(bytes(self.source, 'utf8')).hexdigest()

    def set_disassembler(self, disassembler:"Disassembler"):
        self._backend.disassembler=disassembler

    def orm(self, compiled_func:Function=None):
        src = SourceFunctionORM(
            sha256=self.sha256,
            lang=self.lang,
            decompiled=self.decompiled,
            source=self.source
        )
        if compiled_func is not None:
            src.compiled = compiled_func.orm()

        return src

    def commit(self):
        if self._backend.db is None:
            raise NoDBException()

        with Session(self._backend.db) as s:
            s.add(self.orm())
            s.commit()
    
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

    _backend: Backend = Backend()

    # Path to where the binary is stored
    _path: Path = None
    # The file contents of the binary
    _bytes: bytes = None

    _functions: Set[Function] = None   

    filename: Optional[Union[str, List[str]]] = None
    names: List[str] = []
    entrypoint: int = None
    os: Optional[str] = None
    base_addr:int = 0
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

    @classmethod
    def from_orm(cls, orm):
        b = cls(
            filename=os.path.basename(orm.path),
            architecture=orm.architecture,
            endianness=orm.endianness,
            bitness=orm.bitness,
            entrypoint=orm.entrypoint,
            path=orm.path,
            names=[n.name for n in orm.names],
            strings=set([s.value for s in orm.strings]),
            os=orm.os,
            base_addr=orm.base_addr,
            sha256=orm.sha256,
            nx=orm.nx,
            pie=orm.pie,
            canary=orm.canary,
            relro=orm.relro,
            rpath=orm.rpath,
            runpath=orm.runpath,
            stripped=orm.stripped,
            fortify=orm.fortify,
            fortified=orm.fortified,
            fortifiable=orm.fortifiable,
            fortify_score=orm.fortify_score
        )
        b.set_path(orm.path)

        for f in orm.functions:
            func = Function.from_orm(f)
            # TODO func.address = 
            b.functions.add(func)

        return b

    def __hash__(self):
        return int(self.sha256, 16)
    
    def __contains__(self, x:Union[Function, BasicBlock, Instruction, bytes]):
        if isinstance(x, Function):
            return x in self.functions
        elif isinstance(x, BasicBlock) or isinstance(x, Instruction) or isinstance(x, bytes):
            return any([x in f for f in self.functions])
    
    
    def orm(self):
        name = NameORM(name=self.filename)
        strings = [StringsORM(value=s) for s in self.strings]
    
        b = BinaryORM(
            path=str(self._path), 
            names=[name] + [NameORM(name=n) for n in self.names],
            strings=strings,
            endianness = self.endianness,
            architecture = self.architecture,
            bitness = self.bitness,
            entrypoint = self.entrypoint,
            base_addr = self.base_addr,
            os = self.os,
            sha256=self.sha256,
            nx=self.nx,
            pie=self.pie,
            canary=self.canary,
            relro=self.relro,
            rpath=self.rpath,
            runpath=self.runpath,
            stripped=self.stripped,
            fortify=self.fortify,
            fortified=self.fortified,
            fortifiable=self.fortifiable,
            fortify_score=self.fortify_score
        )

        return b

    def db_add(self, session:Session):
        b = self.orm()
        session.add(b)
        for f in self.functions:
            f.db_add(session)
            

    def set_path(self, path:Union[Path, str]):
        if isinstance(path, str):
            path = Path(path)
        self._path = path

    def set_disassembler(self, disassembler:"Disassembler"):
        self._backend.disassembler=disassembler

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
    def functions(self) -> Iterable[Function]:
        if self._backend.db is not None:
            with Session(self._backend.db) as s:
                # Weirdness w/ query building & cached property
                # warm cache up before building query or else it breaks
                self.sha256

                stmt = select(BinaryORM).where(BinaryORM.sha256 == self.sha256)
                bin_orm = s.execute(stmt).first()
                if bin_orm is not None:
                    # TODO need to recover address :(
                    return [Function.from_orm(f) for f in bin_orm[0].functions]
        
        if self._backend.disassembler is not None:
            return set(self._backend.disassembler.functions())

        return set()
    
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

