from __future__ import annotations

from typing import Optional, Set, List
from sqlalchemy import Table, Column, ForeignKey, String, BigInteger
from sqlalchemy.orm import DeclarativeBase, Mapped,  mapped_column, relationship
from checksec.elf import PIEType, RelroType

from .consts import Endian, IL

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

class Name(Base):
    __tablename__ = "names"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    
class Strings(Base):
    __tablename__ = "strings"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(String(512))

# Not really that important to keep
# also easily reacalculated
# class Section(Base):
#     __tablename__ = "bin_sections"
#     id: Mapped[int] = mapped_column(primary_key=True)
#     binary: Mapped[int] = mapped_column(ForeignKey('binaries.id'))
#     name: Mapped[str]
#     type: Mapped[str]
#     start: Mapped[int]
#     offset: Mapped[int]
#     entsize: Mapped[int]
#     link: Mapped[int]
#     info: Mapped[int]
#     align: Mapped[int]

#     # Flags
#     write: Mapped[bool]
#     alloc: Mapped[bool]
#     execute: Mapped[bool]
#     merge: Mapped[bool]
#     strings: Mapped[bool]
#     info_flag: Mapped[bool]
#     link_order: Mapped[bool]
#     extra_processing: Mapped[bool]
#     group: Mapped[bool]
#     tls: Mapped[bool]
#     compressed: Mapped[bool]
#     unknown: Mapped[bool]
#     os_specific: Mapped[bool]
#     exclude: Mapped[bool]
#     mbind: Mapped[bool]
#     large: Mapped[bool]
#     processor_specific: Mapped[bool]




class Binary(Base):
    __tablename__ = "binaries"

    id: Mapped[int] = mapped_column(primary_key=True)
    path: Mapped[str]
    names: Mapped[List[Name]] = relationship(secondary=bin_name_pivot)
    endianness: Mapped[Endian]
    architecture: Mapped[str]
    bitness:Mapped[int]
    entrypoint: Mapped[Optional[int]]
    os:Mapped[Optional[str]]
    # TODO dynamic libs
    strings: Mapped[List[Strings]] = relationship(secondary=string_pivot)
    
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
    fortifyScore:Mapped[int]

    functions: Mapped[List[NativeFunction]] = relationship(
        secondary=native_func_pivot,
        back_populates='binaries'
    )

class NativeFunction(Base):
    __tablename__ = "native_functions"

    id: Mapped[int] = mapped_column(primary_key=True)
    names: Mapped[List[Name]] = relationship(secondary=func_name_pivot)
    binaries: Mapped[List[Binary]] = relationship(
        secondary=native_func_pivot,
        back_populates='functions'
    )
    
    basic_blocks: Mapped[List[BasicBlock]] = relationship(back_populates='function')
    # TODO hash

    endianness: Mapped[Endian]
    architecture: Mapped[str]
    bitness:Mapped[int]
    pie:Mapped[PIEType]
    canary:Mapped[bool]
    return_type:Mapped[str]
    argv:Mapped[str]
    # calls:Mapped[List[NativeFunction]] =  relationship("NativeFunction", back_populates='callers') 
    # callers:Mapped[List[NativeFunction]] =  relationship("NativeFunction", back_populates="calls")

class BasicBlock(Base):
    __tablename__ = "basic_blocks"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    address: Mapped[int]
    endianness: Mapped[Endian]
    architecture: Mapped[str]
    bitness:Mapped[int]
    pie:Mapped[PIEType]
    
    bytes:Mapped[bytes]
    size:Mapped[int]
    function_id:Mapped[int] = mapped_column(ForeignKey('native_functions.id'))
    function:Mapped[NativeFunction] = relationship(back_populates='basic_blocks')

    ir: Mapped[Optional[List[IR]]] = relationship(back_populates='basic_block')

class IR(Base):
    __tablename__ = "ir"

    id: Mapped[int] = mapped_column(primary_key=True)
    lang: Mapped[IL]
    data: Mapped[str]

    bb_id: Mapped[int] = mapped_column(ForeignKey("basic_blocks.id"))
    basic_block: Mapped[BasicBlock] = relationship(back_populates='ir')