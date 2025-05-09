from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from collections import defaultdict
from functools import cached_property
from pathlib import Path
from typing import IO, Any, Dict, List, Optional, Set, Type, Union

import networkx as nx
import pyvex
from pydantic import BaseModel, computed_field, model_validator
from pydantic.functional_serializers import PlainSerializer
from pydantic.functional_validators import PlainValidator
from sqlalchemy.orm import Session
from typing_extensions import Annotated

from .consts import IL, BranchType, Endian, IndirectToken, RefType
from .db import (
    IR_ORM,
    MAX_STR_SIZE,
    BasicBlockORM,
    BinaryORM,
    BranchORM,
    InstructionORM,
    MetaInfo,
    NameORM,
    NativeFunctionORM,
    ReferenceORM,
    SourceFunctionORM,
    StringsORM,
    VariableORM,
)
from .source import C_Code
from .utils import str2archinfo

logger = logging.getLogger(__file__)


parsers: Dict[str, Optional[Type]] = defaultdict(lambda: None)
parsers["C"] = C_Code


def bytes_validator(x: Union[bytes, bytearray, str]) -> bytes:
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    if isinstance(x, str):
        return bytes.fromhex(x)
    raise ValueError(f"Does not appear to be bytes or hexstring: {x}")


Bytes = Annotated[
    bytes, PlainValidator(bytes_validator), PlainSerializer(lambda x: x.hex())
]


class NoDBException(Exception):
    pass


class NoContextException(Exception):
    pass


class Branch(BaseModel):
    """
    Describes a branch in control flow
    """

    type: BranchType
    """Type of Jump"""
    target: Optional[int]
    """Address to Jump to"""

    @classmethod
    def orm_type(cls) -> Type:
        return BranchORM

    @classmethod
    def from_orm(cls, orm):
        return cls(type=orm.type, target=orm.target)

    def __hash__(self):
        return hash((self.type, self.target))

    def orm(self):
        return BranchORM(type=self.type, target=self.target)


class IR(BaseModel):
    """
    Represents a series of intermediate instruction(s) that correspond to a single assembly instruction
    """

    lang_name: IL
    data: str


class Variable(BaseModel):
    """Represents a Variable recovered from compiled code"""

    data_type: str
    name: str
    is_register: bool
    is_stack: bool
    stack_offset: Optional[int] = 0

    @classmethod
    def orm_type(cls) -> Type:
        return VariableORM

    @classmethod
    def from_orm(cls, orm):
        return cls(
            data_type=orm.data_type,
            name=orm.name,
            is_register=orm.is_register,
            is_stack=orm.is_stack,
            stack_offset=orm.stack_offset,
        )

    def orm(self):
        return VariableORM(
            data_type=self.data_type,
            name=self.name,
            is_register=self.is_register,
            is_stack=self.is_stack,
            stack_offset=self.stack_offset,
        )


class Reference(BaseModel):
    """Represents a single Reference at a given address pointing to another address"""

    from_: int
    to: int
    type: RefType

    @classmethod
    def orm_type(cls) -> Type:
        return ReferenceORM

    @classmethod
    def from_orm(cls, orm):
        return cls(from_=orm.from_addr, to=orm.to_addr, type=orm.type)

    def __hash__(self):
        return hash((self.from_, self.to, self.type.value))

    def __repr__(self):
        return f"{hex(self.from_)} -{self.type.name}-> {hex(self.to)}"

    def orm(self):
        return ReferenceORM(from_addr=self.from_, to_addr=self.to, type=self.type)


class Argument(BaseModel):
    """Represents a single argument in a function"""

    data_type: Optional[str] = None
    """Argument data type (e.g., char, int, short*, struct socket, long(*)(char*))"""

    var_name: Optional[str] = None
    """Argument Variable Name"""

    var_args: bool = False
    """True when the argument is Variadic (i.e. more than one argument, like printf)"""

    # TODO pydantic alias fields
    # so we can represent args in multiple langs?

    # TODO add parsers and serializers for diff langs?

    @model_validator(mode="before")
    @classmethod
    def from_literal(cls, data: Any) -> Any:
        if isinstance(data, str):
            data = data.strip()

            if data == "...":
                return Argument(data_type=None, var_name=None, var_args=True)
            data_type, var_name = data.rsplit(" ", 1)

            # move pointer to the data type
            while var_name.startswith("*"):
                data_type += "*"
                var_name = var_name[1:]

            return Argument(
                data_type=data_type,
                var_name=var_name,
            )
        return data

    def __str__(self):
        if self.var_args:
            return "..."

        return f"{self.data_type} {self.var_name}"


class NativeCode(BaseModel):
    """A Base class to represent attributes of compiled code generally"""

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
            elif getattr(field, "__len__", None) is not None:
                fields.append(f"len({f})={len(field)}")
            else:
                fields.append(f"{f}={field}")

        return f"{self.__class__.__name__}({', '.join(fields)})"


class Instruction(NativeCode):
    """Represents a single instruction"""

    address: Optional[int] = None
    data: Bytes
    asm: Optional[str] = ""
    comment: Optional[str] = ""
    ir: Optional[IR] = None

    @classmethod
    def orm_type(cls) -> Type:
        return InstructionORM

    @classmethod
    def from_orm(cls, orm, ir_type: Optional[IL] = None):
        instruction = cls(
            endianness=orm.endianness,
            architecture=orm.architecture,
            bitness=orm.bitness,
            address=orm.address,
            data=orm.bytes,
            asm=orm.asm,
            comment=orm.comment,
        )

        if len(orm.ir) > 0:
            # If multiple IRs for this instruction has been loaded
            # into the database (i.e. we ran more than one diassembler)
            # then orm.ir would have more than one entry
            # We will just pick one arbitrarily unless, specified
            if ir_type is None:
                ir_data = orm.ir[0]
            else:
                for ir_data in orm.ir:
                    if ir_data.lang == ir_type:
                        break

            ir = IR(lang_name=ir_data.lang, data=ir_data.data)
            instruction.ir = ir

        return instruction

    def __len__(self):
        return len(self.data)

    def __eq__(self, other: object):
        if not isinstance(other, Instruction):
            return False

        return self.data == other.data

    def __hash__(self):
        return hash(self.data)

    def __contains__(self, x: bytes):
        return x in self.data

    def __bytes__(self):
        return self.data

    def orm(self):
        i = InstructionORM(
            endianness=self.endianness,
            architecture=self.architecture,
            bitness=self.bitness,
            address=self.address,
            bytes=self.data,
            asm=self.asm,
            comment=self.comment,
        )

        ir = None
        if self.ir is not None:
            ir = IR_ORM(lang=self.ir.lang_name, data=self.ir.data, instruction=i)
            i.ir.append(ir)

        return i, ir

    def db_add(self, session: Session):
        instr, ir = self.orm()
        session.add(instr)
        session.add(ir)

    def vex(self):
        address = self.address
        if address is None:
            address = 0

        il = pyvex.lift(self.data, address, str2archinfo(self.architecture))
        return IR(
            lang_name=IL.VEX, data=";".join([stmt.pp_str() for stmt in il.statements])
        )


class BasicBlock(NativeCode):
    """Represents a Basic Block"""

    _function: Optional[NativeFunction] = None

    address: Optional[int] = None

    instructions: List[Instruction] = list()
    branches: Set[Branch] = set()
    is_prologue: Optional[bool] = False
    is_epilogue: Optional[bool] = False
    xrefs: Set[Reference] = set([])

    _size_bytes: Optional[int] = None

    @classmethod
    def orm_type(cls) -> Type:
        return BasicBlockORM

    @classmethod
    def from_orm(cls, orm):
        bb = cls(
            address=orm.address,
            architecture=orm.architecture,
            endianness=orm.endianness,
            bitness=orm.bitness,
            xrefs=set(Reference.from_orm(ref) for ref in orm.xrefs),
            branches=set(Branch.from_orm(b) for b in orm.branches),
        )

        for instr_orm in orm.instructions:
            instr = Instruction.from_orm(instr_orm)
            bb.instructions.append(instr)

        return bb

    class BasicBlockIterator:
        def __init__(self, block: BasicBlock):
            self.blocks = list(block.branches)
            self.idx = 0

            self.block_cache = dict()
            if block._function is None:
                raise RuntimeError(
                    f"BasicBlock {block.address} has no function associated with it"
                )
            for bb in block._function.basic_blocks:
                self.block_cache[bb.address] = bb

        def __iter__(self):
            return self

        def __next__(self):
            if self.idx >= len(self.blocks):
                raise StopIteration

            branch_data = self.blocks[self.idx]
            btype = branch_data.type
            addr = branch_data.target

            target_bb = self.block_cache.get(addr, None)
            if addr is None:
                # Statically Unknown Branch Location (e.g. indirect jump)
                dest = IndirectToken()
            elif target_bb is None:
                # Branch goes to an address that doesnt match a bb we have
                dest = addr
            else:
                dest = target_bb

            self.idx += 1
            return btype, dest

    def __iter__(self):
        return BasicBlock.BasicBlockIterator(self)

    def __hash__(self):
        return hash(bytes(self))

    def __len__(self):
        if self._size_bytes is None:
            self._size_bytes = sum([len(i) for i in self.instructions])
        return self._size_bytes

    def __contains__(self, x: Union[Instruction, bytes, int]):
        if isinstance(x, Instruction):
            return x in self.instructions
        elif isinstance(x, bytes):
            return x in bytes(self)
        elif isinstance(x, int):
            if self.address is None:
                raise RuntimeError("BasicBlock has no address")
            return x >= self.address and x <= (self.address + len(self))
        raise TypeError

    def __bytes__(self):
        b = b""
        for instr in self.instructions:
            b += instr.data
        return b

    def set_function(self, func: NativeFunction):
        self._function = func

    def num_instructions(self):
        return len(self.instructions)

    def vex(self):
        bb_ir = []
        for instr in self.instructions:
            bb_ir.append(instr.vex().data)
        return IR(lang_name=IL.VEX, data="\n".join(bb_ir))

    def ir(self):
        bb_ir = []
        for instr in self.instructions:
            if instr.ir is None:
                bb_ir.append(instr.vex().data)
            else:
                bb_ir.append(instr.ir.data)
        return IR(lang_name=instr.ir.lang_name, data="\n".join(bb_ir))

    def orm(self):
        bb = BasicBlockORM(
            address=self.address,
            endianness=self.endianness,
            architecture=self.architecture,
            bitness=self.bitness,
            size=len(self),
            xrefs=[xref.orm() for xref in self.xrefs],
            branches=[branch.orm() for branch in self.branches],
        )

        for instr in self.instructions:
            instr_orm, _ = instr.orm()
            bb.instructions.append(instr_orm)
            instr_orm.basic_block = bb

        return bb

    def db_add(self, session: Session):
        bb = self.orm()
        session.add(bb)
        for instr in bb.instructions:
            session.add(instr)
            if instr.ir is not None:
                for ir in instr.ir:
                    session.add(ir)


class NativeFunction(NativeCode):
    """
    Represents a natively compiled function
    """

    _block_lookup: Dict[int, BasicBlock] = dict()
    _binary: Optional[Binary] = None

    address: Optional[int] = None
    canary: Optional[bool] = None
    names: Optional[List[str]] = None
    return_type: Optional[str] = None
    argv: List[Argument] = list()
    variables: List[Variable] = list()
    stack_frame_size: int = 0
    sources: Set[SourceFunction] = set([])
    thunk: bool = False

    calls_addrs: Set[int] = set([])
    called_by: Set[int] = set([])
    basic_blocks: Set[BasicBlock] = set([])
    end_block_addrs: Set[int] = set([])

    @model_validator(mode="after")
    def _populate_cache(self):
        for bb in self.basic_blocks:
            self._block_lookup[bb.address] = bb
            bb._function = self
        return self

    @classmethod
    def orm_type(cls) -> Type:
        return NativeFunctionORM

    @classmethod
    def from_orm(cls, orm):
        f = cls(
            names=[n.name for n in orm.names],
            address=orm.address,
            architecture=orm.architecture,
            endianness=orm.endianness,
            bitness=orm.bitness,
            sha256=orm.sha256,
            stack_frame_size=orm.stack_frame_size,
            return_type=orm.return_type,
            thunk=orm.thunk,
            argv=[
                Argument.from_literal(arg)
                for arg in orm.argv.split(",")
                if len(orm.argv) > 0
            ],
        )
        for var in orm.variables:
            f.variables.append(Variable.from_orm(var))

        for bb in orm.basic_blocks:
            f.basic_blocks.add(BasicBlock.from_orm(bb))

        for src_f in orm.sources:
            f.sources.add(SourceFunction.from_orm(src_f))

        return f

    def __hash__(self):
        return int(self.sha256, 16)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NativeFunction):
            return False

        return hash(self) == hash(other)

    def __ne__(self, other: object) -> bool:
        return hash(self) != hash(other)

    def __contains__(self, x: Union[BasicBlock, Instruction, bytes]):
        if isinstance(x, BasicBlock):
            return x in self.basic_blocks
        elif isinstance(x, Instruction) or isinstance(x, bytes):
            return any([x in bb for bb in self.basic_blocks])
        raise TypeError

    def __bytes__(self):
        """Returns the bytes from the lowest addressed basic block to the end of the largest addressed basic block"""
        bbs = [bb for bb in self.basic_blocks]
        bbs = sorted(bbs, key=lambda b: b.address)

        if self._binary is not None:
            start = bbs[0].address - self._binary.base_addr
            end = bbs[-1].address + len(bbs[-1]) - self._binary.base_addr
            return bytes(self._binary)[start:end]

        return None

    def start(self):
        return self._block_lookup[self.address]

    def end(self):
        return [self._block_lookup[e] for e in self.end_block_addrs]

    @property
    def calls(self):
        """Functions that this Function Calls"""
        if self._binary is None:
            raise NoContextException("Function is not associated with Binary")

        for addr in self.calls_addrs:
            f = self._binary._function_lookup.get(addr, None)
            if f is not None:
                yield f

    @property
    def callers(self):
        """Functions that call this Function"""
        if self._binary is None:
            raise NoContextException("Function is not associated with Binary")

        for addr in self.called_by:
            f = self._binary._function_lookup.get(addr, None)
            if f is not None:
                yield f

    @cached_property
    def cfg(self) -> nx.MultiDiGraph:
        """Control Flow Graph of the Function"""

        cfg: nx.MultiDiGraph = nx.MultiDiGraph()
        self._cfg(set(), cfg, self.start())

        return cfg

    def _cfg(self, history, g, bb: BasicBlock):
        if bb in history:
            return

        history.add(bb)
        g.add_node(bb)

        for btype, dest in bb:
            if dest not in self._block_lookup:
                continue

            g.add_node(dest)
            g.add_edge(bb, dest, branch=btype)

            if isinstance(dest, BasicBlock):
                self._cfg(history, g, dest)

    @cached_property
    def xrefs(self) -> Set[Reference]:
        """Cross References Within the Function"""
        xrefs = set()
        for bb in self.basic_blocks:
            xrefs |= bb.xrefs
        return xrefs

    @computed_field(repr=False)  # type: ignore[misc]
    @cached_property
    def sha256(self) -> str:
        bbs = sorted(
            self.basic_blocks, key=lambda b: 0 if b.address is None else b.address
        )
        func_bytes = b"".join([bytes(bb) for bb in bbs])
        return hashlib.sha256(func_bytes).hexdigest()

    def disasm(self) -> str:
        """Returns disassembled instructions from the lowest addressed basic block to the end of the largest addressed basic block"""
        bbs = [bb for bb in self.basic_blocks]
        bbs = sorted(bbs, key=lambda b: 0 if b.address is None else b.address)

        asm = []
        for bb in bbs:
            for instr in bb.instructions:
                if instr.asm is not None:
                    asm.append(instr.asm)

        return "\n".join(asm)

    def ir(self) -> str:
        """Returns lifed intermediate representation of instructions from the lowest addressed basic block to the end of the largest addressed basic block"""
        bbs = [bb for bb in self.basic_blocks]
        bbs = sorted(bbs, key=lambda b: 0 if b.address is None else b.address)

        ir = []
        for bb in bbs:
            ir.append(bb.ir().data)

        return "\n".join(ir)

    def orm(self):
        names = self.names
        if names is None:
            names = list()

        func = NativeFunctionORM(
            names=[NameORM(name=n) for n in names],
            endianness=self.endianness,
            architecture=self.architecture,
            bitness=self.bitness,
            address=self.address,
            sha256=self.sha256,
            return_type=self.return_type,
            thunk=self.thunk,
            argv=", ".join(str(arg) for arg in self.argv),
        )

        return func

    def db_add(self, session: Session, binary: BinaryORM):
        f_orm = None
        with session.no_autoflush:
            if NativeFunctionORM.exists_in_binary(session, binary.sha256, self.sha256):
                f_orm = NativeFunctionORM.select_hash_by_binary(
                    session, binary.sha256, self.sha256
                )
            else:
                f_orm = self.orm()
                f_orm.binary = binary
                session.add(f_orm)

            if not self.thunk:
                sources: List[SourceFunction] = list()
                for src in self.sources:
                    for src_other in sources:
                        if src.sha256 == src_other.sha256:
                            if src.decompiled and not src_other.decompiled:
                                src_other.perfect_decomp = True
                                sources.append(src_other)
                            elif not src.decompiled and src_other.decompiled:
                                src.perfect_decomp = True
                                sources.append(src)

                for src in sources:
                    if src is None:
                        continue

                    if not SourceFunctionORM.exists_hash(session, src.sha256):
                        src_orm = src.orm()
                        src_orm.compiled.append(f_orm)
                        session.add(src_orm)
                    else:
                        src_orm = SourceFunctionORM.select_hash(session, src.sha256)
                        src_orm.compiled.append(f_orm)

            for called in self.calls:
                if called == self:
                    c = f_orm
                elif NativeFunctionORM.exists_in_binary(
                    session, binary.sha256, called.sha256
                ):
                    c = NativeFunctionORM.select_hash_by_binary(
                        session, binary.sha256, called.sha256
                    )
                else:
                    c = called.orm()
                    c.binary = binary
                    session.add(c)

                f_orm.calls.append(c)

            for caller in self.callers:
                if caller == self:
                    c = f_orm
                elif NativeFunctionORM.exists_in_binary(
                    session, binary.sha256, caller.sha256
                ):
                    c = NativeFunctionORM.select_hash_by_binary(
                        session, binary.sha256, caller.sha256
                    )
                else:
                    c = caller.orm()
                    c.binary = binary
                    session.add(c)

                f_orm.callers.append(c)

        assert f_orm is not None

        for bb in self.basic_blocks:
            block_orm = bb.orm()
            f_orm.basic_blocks.append(block_orm)
            block_orm.function = f_orm

            for instr in block_orm.instructions:
                if instr is not None:
                    for ir in instr.ir:
                        session.add(ir)
                session.add(instr)
            session.add(block_orm)

        for var in self.variables:
            var_orm = var.orm()
            f_orm.variables.append(var_orm)
            session.add(var_orm)


class SourceFunction(BaseModel):
    """
    Representation of the source code of a function.
    Currently tailored around C functions
    """

    _tree_sitter_root = None

    lang: str = "C"
    name: str
    decompiled: bool
    perfect_decomp: Optional[bool] = False
    """True if the decompilation is exactly the true source code"""

    source: str
    argv: Optional[List[Argument]] = list()
    return_type: Optional[str] = ""
    qualifiers: Set[str] = set()
    """Function Qualifiers such as `const`, `volatile`, or `static`"""

    @classmethod
    def orm_type(cls) -> Type:
        return SourceFunctionORM

    @classmethod
    def from_orm(cls, orm):
        return cls(
            lang=orm.lang,
            decompiled=orm.decompiled,
            perfect_decomp=orm.perfect_decomp,
            source=orm.source,
            name=orm.name,
            return_type=orm.return_type,
            argv=[
                Argument.from_literal(arg)
                for arg in orm.argv.split(",")
                if len(orm.argv) > 0
            ],
            qualifiers=set(orm.qualifiers.split(" ")),
        )

    @classmethod
    def from_file(
        cls,
        fname: str,
        filepath: str,
        encoding: str = "utf8",
        lang: str = "C",
        is_decompiled=False,
    ):
        """
        Parse a function from the given file and create a SourceFunction object
        :param fname: the function name
        :param filepath: the path to the source function
        :param encoding: the encoding to use
        :param lang: the programming language the source code is in
        :param is_decompiled: True if the file is decompiled
        :returns: a SourceFunction object representing function `fname`; None if no such function exists in the file
        """
        with open(filepath, "rb") as f:
            return cls.from_code(
                fname,
                f.read(),
                lang=lang,
                encoding=encoding,
                is_decompiled=is_decompiled,
            )

    @classmethod
    def from_code(
        cls,
        fname: str,
        source: Union[str, bytes],
        encoding: str = "utf8",
        lang: str = "C",
        is_decompiled=False,
    ):
        """
        Parse a function from the source code and create a SourceFunction object
        :param fname: the function name
        :param source: the source code containing the function
        :param encoding: the encoding to use
        :param lang: the programming language the source code is in
        :param is_decompiled: True if the file is decompiled
        :returns: a SourceFunction object representing function `fname`; None if no such function exists in the source
        """
        if isinstance(source, str):
            source = bytes(source, encoding)

        parser = parsers[lang]
        if parser is None:
            raise NotImplementedError(f"No support for {lang}")

        f_root = parser.find_func(fname, source, encoding=encoding)
        if f_root is None:
            return None

        try:
            src_func_dict = parser.normalize(f_root, encoding=encoding)
        except Exception as e:
            logger.error(f"Tried to parse C Source and Failed: {str(e)}")
            return None

        src_func_dict["decompiled"] = is_decompiled

        function_source = cls.model_validate(src_func_dict)
        function_source._tree_sitter_root = f_root
        return function_source

    def orm(self):
        return SourceFunctionORM(
            name=self.name,
            sha256=self.sha256,
            lang=self.lang,
            decompiled=self.decompiled,
            perfect_decomp=self.perfect_decomp,
            source=self.source,
            return_type=self.return_type,
            argv=", ".join(str(arg) for arg in self.argv),
            qualifiers=" ".join(self.qualifiers),
        )

    def __hash__(self):
        return int(self.sha256, 16)

    @computed_field(repr=False)  # type: ignore[misc]
    @cached_property
    def sha256(self) -> str:
        """sha256 hex digest of the file"""
        return hashlib.sha256(bytes(self.source, "utf8")).hexdigest()


class Binary(NativeCode):
    """
    Represents a Binary Blob or executable format. This maps 1 to 1 of what you'd load into a disassembler (e.g., ELF, PE, MACH-O, Firmware Dump, Binary Blob)
    """

    class NoDataException(Exception):
        pass

    # Path to where the binary is stored
    _path: Optional[Path] = None
    # Whether or not the binary at self._path is gz compressed
    _compressed: bool = False
    # The file contents of the binary
    _bytes: Optional[bytes] = None
    _size: Optional[int] = None
    _function_lookup: Dict[int, NativeFunction] = dict()

    functions: Set[NativeFunction] = set()

    filename: Optional[Union[str, List[str]]] = None

    names: List[str] = []
    """names this binary has gone by (multiple are possbile when loading data from a database)"""

    entrypoint: Optional[int] = None
    os: Optional[str] = None
    base_addr: int = 0
    dynamic_libs: Set[str] = set([])
    compiler: Optional[str] = None
    compilation_flags: Optional[str] = None

    # Strings from String table if they exists, otherwise strings detected in the binary (like unix `strings`` command)
    strings: Set[str] = set([])

    # User defined tags
    tags: Set[str] = set([])

    @model_validator(mode="after")
    def _populate_cache(self):
        for f in self.functions:
            self._function_lookup[f.address] = f
            f._binary = self
        return self

    @classmethod
    def orm_type(cls) -> Type:
        return BinaryORM

    @classmethod
    def from_path(cls, path: Union[Path, str], **kwargs):
        obj = cls(**kwargs)
        obj._path = Path(path)
        return obj

    @classmethod
    def from_bytes(cls, b: bytes, **kwargs):
        obj = cls(**kwargs)
        obj._bytes = b
        return obj

    @classmethod
    def from_orm(cls, orm):
        b = cls(
            filename=os.path.basename(orm.metainfo.path),
            architecture=orm.architecture,
            endianness=orm.endianness,
            bitness=orm.bitness,
            entrypoint=orm.entrypoint,
            names=[n.name for n in orm.names],
            strings=set([s.value for s in orm.strings]),
            compiler=orm.compiler,
            compilation_flags=orm.compilation_flags,
            dynamic_libs=orm.dynamic_libs.split(","),
            os=orm.os,
            base_addr=orm.base_addr,
            sha256=orm.sha256,
            tags=orm.tags.split(","),
        )
        b.set_path(orm.metainfo.path)

        if b.functions is None:
            b.functions = set()

        for f in orm.functions:
            func = NativeFunction.from_orm(f)
            b.functions.add(func)
            b._function_lookup[f.address] = f

        return b

    def __len__(self):
        if self._size is None:
            if self._path is not None:
                self._size = os.path.getsize(self._path)
            else:
                self._size = len(bytes(self))

        return self._size

    def __hash__(self):
        return int(self.sha256, 16)

    def __contains__(self, x: Union[NativeFunction, BasicBlock, Instruction, bytes]):
        if isinstance(x, NativeFunction):
            return x in self.functions
        elif isinstance(x, BasicBlock) or isinstance(x, Instruction):
            return any([x in f for f in self.functions])
        elif isinstance(x, bytes):
            return x in bytes(self)

    def __bytes__(self):
        """return the raw bytes of the binary"""
        if self._bytes is not None:
            return self._bytes

        if self._path is not None:
            with self._path.open("rb") as f:
                self._bytes = f.read()
            return self._bytes

        raise Binary.NoDataException("Binary Object has no Path or data")

    def orm(self):
        name = NameORM(name=self.filename)
        strings = [StringsORM(value=s[:MAX_STR_SIZE]) for s in self.strings]

        metainfo = MetaInfo(path=str(self._path), compressed=False)

        b = BinaryORM(
            metainfo=metainfo,
            names=[name] + [NameORM(name=n) for n in self.names],
            strings=strings,
            endianness=self.endianness,
            architecture=self.architecture,
            bitness=self.bitness,
            entrypoint=self.entrypoint,
            base_addr=self.base_addr,
            os=self.os,
            compiler=self.compiler,
            compilation_flags=self.compilation_flags,
            dynamic_libs=",".join(list(self.dynamic_libs)),
            sha256=self.sha256,
            tags=",".join(self.tags),
        )

        return b

    def db_add(self, session: Session):
        b = self.orm()
        session.add(b)
        for f in self.functions:
            f.db_add(session, binary=b)
            session.commit()

    def set_path(self, path: Union[Path, str]):
        if isinstance(path, str):
            path = Path(path)
        self._path = path

    @cached_property
    def call_graph(self) -> nx.MultiDiGraph:
        """Function Call Graph"""
        g: nx.MultiDiGraph = nx.MultiDiGraph()
        for f in self.functions:
            g.add_node(f)
            for child_f in f.calls:
                g.add_node(child_f)
                g.add_edge(f, child_f)
            for parent_f in f.callers:
                g.add_node(parent_f)
                g.add_edge(f, parent_f)
        return g

    @computed_field(repr=False)  # type: ignore[misc]
    @cached_property
    def sha256(self) -> str:
        """sha256 hex digest of the file"""
        return hashlib.sha256(bytes(self)).hexdigest()

    def io(self) -> IO:
        """returns a stream/IO handle to the bytes of the binary. This function does not self close the stream"""
        if self._path is not None:
            return self._path.open("rb")

        if self._bytes is not None:
            tp = tempfile.NamedTemporaryFile(delete=False)
            tp.write(self._bytes)
            return tp

        raise Binary.NoDataException("Binary Object has no Path or data")
