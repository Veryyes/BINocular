from __future__ import annotations

from typing import Optional, List

from .consts import Endian, IL, RefType, BranchType

from sqlalchemy import Table, Column, ForeignKey, String, select, Integer, BigInteger
from sqlalchemy.orm import DeclarativeBase, Mapped,  mapped_column, relationship
from checksec.elf import PIEType, RelroType

MAX_STR_SIZE = 512


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

source_compile_pivot = Table(
    "source_compiled_pivot",
    Base.metadata,
    Column("source_id", ForeignKey("source_functions.id")),
    Column("compiled_id", ForeignKey("native_functions.id")),
)

calls_pivot = Table(
    "calls_func_pivot",
    Base.metadata,
    Column("native_func_caller", ForeignKey("native_functions.id")),
    Column("native_func_callee", ForeignKey("native_functions.id"))
)


class NameORM(Base):
    __tablename__ = "names"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))


class StringsORM(Base):
    __tablename__ = "strings"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(String(MAX_STR_SIZE))


class MetaInfo(Base):
    __tablename__ = "metainfo"

    id: Mapped[int] = mapped_column(primary_key=True)
    bin: Mapped[BinaryORM] = relationship(back_populates="metainfo")

    path: Mapped[str]
    compressed: Mapped[bool]


class BinaryORM(Base):
    __tablename__ = "binaries"

    id: Mapped[int] = mapped_column(primary_key=True)
    metainfo_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey('metainfo.id'))
    metainfo: Mapped[Optional[MetaInfo]] = relationship(back_populates="bin")

    names: Mapped[List[NameORM]] = relationship(secondary=bin_name_pivot)
    endianness: Mapped[Endian]
    architecture: Mapped[str]
    bitness: Mapped[int]
    entrypoint: Mapped[Optional[int]]
    os: Mapped[Optional[str]]
    base_addr: Mapped[int] = mapped_column(BigInteger())
    dynamic_libs: Mapped[Optional[str]]
    strings: Mapped[List[StringsORM]] = relationship(secondary=string_pivot)

    compiler: Mapped[Optional[str]]
    compilation_flags: Mapped[Optional[str]]

    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    nx: Mapped[bool]
    pie: Mapped[PIEType]
    canary: Mapped[bool]
    relro: Mapped[RelroType]
    rpath: Mapped[bool]
    runpath: Mapped[bool]
    stripped: Mapped[bool]
    fortify: Mapped[bool]
    fortified: Mapped[int]
    fortifiable: Mapped[int]
    fortify_score: Mapped[int]

    tags: Mapped[str]

    functions: Mapped[List[NativeFunctionORM]
                      ] = relationship(back_populates='binary')

    @classmethod
    def select_hash(cls, session, hash: str):
        row = session.execute(select(BinaryORM).where(
            BinaryORM.sha256 == hash)).one_or_none()
        return row


class NativeFunctionORM(Base):
    __tablename__ = "native_functions"

    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    names: Mapped[List[NameORM]] = relationship(secondary=func_name_pivot)
    address: Mapped[int] = mapped_column(BigInteger())
    binary_id: Mapped[int] = mapped_column(ForeignKey('binaries.id'))
    binary: Mapped[BinaryORM] = relationship(back_populates='functions')

    basic_blocks: Mapped[List[BasicBlockORM]
                         ] = relationship(back_populates='function')
    variables: Mapped[List[VariableORM]] = relationship(
        back_populates='function')
    stack_frame_size: Mapped[int] = mapped_column(Integer, default=0)
    endianness: Mapped[Endian]
    architecture: Mapped[str]
    bitness: Mapped[int]
    pie: Mapped[PIEType]
    canary: Mapped[bool]
    return_type: Mapped[str]
    argv: Mapped[str]
    thunk: Mapped[bool]

    sources: Mapped[List[SourceFunctionORM]] = relationship(
        secondary=source_compile_pivot, back_populates='compiled')

    calls = relationship(
        "NativeFunctionORM",
        secondary=calls_pivot,
        primaryjoin=id == calls_pivot.c.native_func_caller,
        secondaryjoin=id == calls_pivot.c.native_func_callee,
    )

    callers = relationship(
        "NativeFunctionORM",
        secondary=calls_pivot,
        primaryjoin=id == calls_pivot.c.native_func_callee,
        secondaryjoin=id == calls_pivot.c.native_func_caller,
        back_populates='calls'
    )

    @classmethod
    def select_hash_by_binary(cls, session, bin_hash: str, func_hash: str):
        stmt = select(NativeFunctionORM)\
            .join(NativeFunctionORM.binary)\
            .where((NativeFunctionORM.sha256 == func_hash) & (BinaryORM.sha256 == bin_hash))

        row = session.execute(stmt).one_or_none()
        if row is not None:
            return row[0]
        return row

    @classmethod
    def exists_in_binary(cls, session, bin_hash: str, func_hash: str):
        stmt = select(NativeFunctionORM.id) \
            .join(NativeFunctionORM.binary) \
            .where((NativeFunctionORM.sha256 == func_hash) & (BinaryORM.sha256 == bin_hash))
        id_ = session.execute(stmt).one_or_none()
        if id_ is None:
            return False
        return id_

    @classmethod
    def select_hash(cls, session, hash: str):
        row = session.execute(select(NativeFunctionORM).where(
            NativeFunctionORM.sha256 == hash)).one_or_none()
        return row

    @classmethod
    def exists_hash(cls, session, hash: str):
        id_ = session.query(NativeFunctionORM.id).filter_by(
            sha256=hash).scalar()
        if id_ is None:
            return False
        return id_


class VariableORM(Base):
    __tablename__ = "variables"

    id: Mapped[int] = mapped_column(primary_key=True)
    data_type: Mapped[str]
    name: Mapped[str]
    is_register: Mapped[bool]
    is_stack: Mapped[bool]
    stack_offset: Mapped[Optional[int]]
    function_id: Mapped[int] = mapped_column(ForeignKey('native_functions.id'))
    function: Mapped[NativeFunctionORM] = relationship(
        back_populates='variables')


class BasicBlockORM(Base):
    __tablename__ = "basic_blocks"

    id: Mapped[int] = mapped_column(primary_key=True)
    address: Mapped[int] = mapped_column(BigInteger())
    endianness: Mapped[Endian]
    architecture: Mapped[str]
    bitness: Mapped[int]
    pie: Mapped[PIEType]
    size: Mapped[int]
    function_id: Mapped[int] = mapped_column(ForeignKey('native_functions.id'))
    function: Mapped[NativeFunctionORM] = relationship(
        back_populates='basic_blocks')
    instructions: Mapped[List[InstructionORM]] = relationship(
        back_populates='basic_block')
    xrefs: Mapped[List[ReferenceORM]] = relationship(
        back_populates='basic_block')
    branches: Mapped[List[BranchORM]] = relationship(
        back_populates='basic_block')


class BranchORM(Base):
    __tablename__ = "branches"
    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[BranchType]
    target: Mapped[int]
    basic_block_id: Mapped[int] = mapped_column(ForeignKey("basic_blocks.id"))
    basic_block: Mapped[BasicBlockORM] = relationship(back_populates='branches')


class ReferenceORM(Base):
    __tablename__ = "references"

    id: Mapped[int] = mapped_column(primary_key=True)
    from_addr: Mapped[int] = mapped_column(BigInteger())
    to_addr: Mapped[int] = mapped_column(BigInteger())
    type: Mapped[RefType]
    basic_block_id: Mapped[int] = mapped_column(ForeignKey("basic_blocks.id"))
    basic_block: Mapped[BasicBlockORM] = relationship(back_populates='xrefs')


class InstructionORM(Base):
    __tablename__ = "instructions"

    id: Mapped[int] = mapped_column(primary_key=True)
    endianness: Mapped[Endian]
    architecture: Mapped[str]
    bitness: Mapped[int]
    basic_block_id: Mapped[int] = mapped_column(ForeignKey("basic_blocks.id"))
    basic_block: Mapped[BasicBlockORM] = relationship(
        back_populates='instructions')
    address: Mapped[int]
    bytes: Mapped[bytes]
    asm: Mapped[str]
    comment: Mapped[Optional[str]]
    ir: Mapped[Optional[List[IR_ORM]]] = relationship(
        back_populates='instruction')


class IR_ORM(Base):
    __tablename__ = "ir"

    id: Mapped[int] = mapped_column(primary_key=True)
    lang: Mapped[IL]
    data: Mapped[str]

    instr_id: Mapped[int] = mapped_column(ForeignKey("instructions.id"))
    instruction: Mapped[InstructionORM] = relationship(back_populates='ir')


class SourceFunctionORM(Base):
    __tablename__ = "source_functions"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), index=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    lang: Mapped[str]
    decompiled: Mapped[bool]
    perfect_decomp: Mapped[bool]  # Decompilation matches Source 100%
    compiled: Mapped[List[NativeFunctionORM]] = relationship(
        secondary=source_compile_pivot, back_populates='sources')
    source: Mapped[str]
    return_type: Mapped[str]
    argv: Mapped[str]
    qualifiers: Mapped[str]

    @classmethod
    def select_hash(cls, session, hash: str):
        row = session.execute(select(SourceFunctionORM).where(
            SourceFunctionORM.sha256 == hash)).one_or_none()
        if row is not None:
            return row[0]
        return row

    @classmethod
    def exists_hash(cls, session, hash: str):
        id_ = session.query(SourceFunctionORM.id).filter_by(
            sha256=hash).scalar()
        if id_ is None:
            return False
        return id_
