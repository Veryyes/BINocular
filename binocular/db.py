from __future__ import annotations

from typing import Optional, List

from .consts import Endian, IL

from sqlalchemy import create_engine, select
from sqlalchemy import Table, Column, ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped,  mapped_column, relationship
from checksec.elf import PIEType, RelroType

class Base(DeclarativeBase):
    pass

string_pivot = Table(
    "string_pivot",
    Base.metadata,
    Column("bin_id", ForeignKey("binaries.id")),
    Column("string_id", ForeignKey("strings.id")),
)

bin_name_pivot = Table(
    "bin_name_pivot",
    Base.metadata, 
    Column("bin_id", ForeignKey("binaries.id")),
    Column("name_id", ForeignKey("names.id"))
)

func_name_pivot = Table(
    "func_name_pivot",
    Base.metadata, 
    Column("native_func_id", ForeignKey("native_functions.id")),
    Column("name_id", ForeignKey("names.id"))
)


native_func_pivot = Table(
    "native_func_pivot",
    Base.metadata,
    Column("bin_id", ForeignKey("binaries.id")),
    Column("native_func_id", ForeignKey("native_functions.id")),
)

class NameORM(Base):
    __tablename__ = "names"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))

class StringsORM(Base):
    __tablename__ = "strings"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(String(512))

class BinaryORM(Base):
    __tablename__ = "binaries"

    id: Mapped[int] = mapped_column(primary_key=True)
    path: Mapped[str]
    names: Mapped[List[NameORM]] = relationship(secondary=bin_name_pivot)
    endianness: Mapped[Endian]
    architecture: Mapped[str]
    bitness:Mapped[int]
    entrypoint: Mapped[Optional[int]]
    os:Mapped[Optional[str]]
    # TODO dynamic libs
    strings: Mapped[List[StringsORM]] = relationship(secondary=string_pivot)
    
    sha256:Mapped[str] = mapped_column(String(32))
    nx:Mapped[bool]
    pie:Mapped[PIEType]
    canary:Mapped[bool]
    relro:Mapped[RelroType]
    rpath:Mapped[bool]
    runpath:Mapped[bool]
    stripped:Mapped[bool]
    fortify:Mapped[bool]
    fortified:Mapped[int]
    fortifiable:Mapped[int]
    fortify_score:Mapped[int]

    functions: Mapped[List[NativeFunctionORM]] = relationship(
        secondary=native_func_pivot,
        back_populates='binaries'
    )


class NativeFunctionORM(Base):
    __tablename__ = "native_functions"

    id: Mapped[int] = mapped_column(primary_key=True)
    names: Mapped[List[NameORM]] = relationship(secondary=func_name_pivot)
    binaries: Mapped[List[BinaryORM]] = relationship(
        secondary=native_func_pivot,
        back_populates='functions'
    )
    
    basic_blocks: Mapped[List[BasicBlockORM]] = relationship(back_populates='function')
    # TODO hash

    endianness: Mapped[Endian]
    architecture: Mapped[str]
    bitness:Mapped[int]
    pie:Mapped[PIEType]
    canary:Mapped[bool]
    return_type:Mapped[str]
    argv:Mapped[str]
    thunk:Mapped[bool]
    # calls:Mapped[List[NativeFunction]] =  relationship("NativeFunction", back_populates='callers') 
    # callers:Mapped[List[NativeFunction]] =  relationship("NativeFunction", back_populates="calls")

    sources: Mapped[List[SourceFunctionORM]] = relationship(back_populates='compiled')

class BasicBlockORM(Base):
    __tablename__ = "basic_blocks"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    address: Mapped[int]
    endianness: Mapped[Endian]
    architecture: Mapped[str]
    bitness:Mapped[int]
    pie:Mapped[PIEType]
    size:Mapped[int]
    function_id:Mapped[int] = mapped_column(ForeignKey('native_functions.id'))
    function:Mapped[NativeFunctionORM] = relationship(back_populates='basic_blocks')
    instructions:Mapped[List[InstructionORM]] = relationship(back_populates='basic_block')

class InstructionORM(Base):
    __tablename__ = "instructions"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    endianness: Mapped[Endian]
    architecture: Mapped[str]
    bitness:Mapped[int]
    basic_block_id:Mapped[int] = mapped_column(ForeignKey("basic_blocks.id"))
    basic_block:Mapped[BasicBlockORM] = relationship(back_populates='instructions')
    address: Mapped[int]
    bytes:Mapped[bytes]
    asm:Mapped[str]
    comment:Mapped[str]
    ir: Mapped[Optional[List[IR_ORM]]] = relationship(back_populates='instruction')

class IR_ORM(Base):
    __tablename__ = "ir"

    id: Mapped[int] = mapped_column(primary_key=True)
    lang: Mapped[IL]
    data: Mapped[str]

    instr_id: Mapped[int] = mapped_column(ForeignKey("instructions.id"))
    instruction: Mapped[InstructionORM] = relationship(back_populates='ir')

class SourceFunctionORM(Base):
    __tablename__ = "source"

    id: Mapped[int] = mapped_column(primary_key=True)
    sha256:Mapped[str] = mapped_column(String(32))
    lang: Mapped[str]
    decompiled:Mapped[bool]
    compiled_id: Mapped[int] = mapped_column(ForeignKey('native_functions.id'))
    compiled: Mapped[NativeFunctionORM] = relationship(back_populates='sources')
    source:Mapped[str]