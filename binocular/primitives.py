from __future__ import annotations

import os
import bisect
import hashlib
import logging
import tempfile
from pathlib import Path
from collections import defaultdict
from functools import cached_property
from typing import (
    IO,
    Any,
    Set,
    Dict,
    List,
    Type,
    Tuple,
    Union,
    Generator,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from .disassembler import Disassembler

import pyvex
import networkx as nx
from typing_extensions import Annotated, Self
from pydantic.functional_validators import PlainValidator
from pydantic.functional_serializers import PlainSerializer
from pydantic import BaseModel, computed_field, model_validator

from .source import C_Code
from .utils import str2archinfo
from .consts import IL, Endian, RefType, BranchType, IndirectToken

logger = logging.getLogger(__file__)


parsers: Dict[str, Type | None] = defaultdict(lambda: None)
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
    target: int | None
    """Address to Jump to"""

    def __hash__(self):
        return hash((self.type, self.target))


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
    stack_offset: int | None = 0


class Reference(BaseModel):
    """Represents a single Reference at a given address pointing to another address"""

    from_: int
    to: int
    type: RefType

    def __hash__(self) -> int:
        return hash((self.from_, self.to, self.type.value))

    def __repr__(self) -> str:
        return f"{hex(self.from_)} -{self.type.name}-> {hex(self.to)}"


class Argument(BaseModel):
    """Represents a single argument in a function"""

    data_type: str | None = None
    """Argument data type (e.g., char, int, short*, struct socket, long(*)(char*))"""

    var_name: str | None = None
    """Argument Variable Name"""

    var_args: bool = False
    """True when the argument is Variadic (i.e. more than one argument, like printf)"""

    # TODO pydantic alias fields
    # so we can represent args in multiple langs?

    # TODO add parsers and serializers for diff langs?

    @model_validator(mode="before")
    @classmethod
    def from_literal(cls, data: Any) -> Self:
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

    def __str__(self) -> str:
        if self.var_args:
            return "..."

        return f"{self.data_type} {self.var_name}"


class NativeCode(BaseModel):
    """A Base class to represent attributes of compiled code generally"""

    endianness: Endian | None = None
    architecture: str | None = None
    bitness: int | None = None

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

    address: int | None = None
    data: Bytes
    asm: str | None = ""
    comment: str | None = ""
    ir: IR | None = None

    def __len__(self) -> int:
        return len(self.data)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Instruction):
            return False

        return self.data == other.data

    def __hash__(self) -> int:
        return hash(self.data)

    def __contains__(self, x: bytes) -> bool:
        return x in self.data

    def __bytes__(self) -> bytes:
        return self.data

    def vex(self) -> IR:
        address = self.address
        if address is None:
            address = 0

        if self.architecture is None:
            raise ValueError("Cannot lift VEX IR: architecture is unknown")
        il = pyvex.lift(self.data, address, str2archinfo(self.architecture))
        return IR(
            lang_name=IL.VEX, data=";".join([stmt.pp_str() for stmt in il.statements])
        )


class BasicBlock(NativeCode):
    """Represents a Basic Block"""

    _function: NativeFunction | None = None

    address: int | None = None

    instructions: List[Instruction] = list()
    branches: Set[Branch] = set()
    is_prologue: bool | None = False
    is_epilogue: bool | None = False
    xrefs: Set[Reference] = set([])

    _size_bytes: int | None = None

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

        def __iter__(self) -> Self:
            return self

        def __next__(self) -> Tuple[BranchType, Union[IndirectToken, int, BasicBlock]]:
            if self.idx >= len(self.blocks):
                raise StopIteration

            branch_data = self.blocks[self.idx]
            btype = branch_data.type
            addr = branch_data.target

            target_bb = self.block_cache.get(addr, None)
            dest: Union[IndirectToken, int, BasicBlock]
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

    def __iter__(self) -> BasicBlock.BasicBlockIterator:
        return BasicBlock.BasicBlockIterator(self)

    def __hash__(self) -> int:
        return hash(bytes(self))

    def __len__(self) -> int:
        if self._size_bytes is None:
            self._size_bytes = sum([len(i) for i in self.instructions])
        return self._size_bytes

    def __contains__(self, x: Union[Instruction, bytes, int]) -> bool:
        if isinstance(x, Instruction):
            return x in self.instructions
        elif isinstance(x, bytes):
            return x in bytes(self)
        elif isinstance(x, int):
            if self.address is None:
                raise RuntimeError("BasicBlock has no address")
            end = self.end()
            if end is None:
                raise RuntimeError("Unreachable Code")
            return x >= self.address and x < end
        raise TypeError

    def __bytes__(self) -> bytes:
        b = b""
        for instr in self.instructions:
            b += instr.data
        return b

    def __str__(self) -> str:
        addr = "N/A" if self.address is None else hex(self.address)
        return f"<BasicBlock addr={addr}>"

    def __repr__(self) -> str:
        return str(self)

    def end(self) -> int | None:
        if self.address is None:
            return None
        return self.address + len(self)

    def set_function(self, func: NativeFunction) -> None:
        self._function = func

    def num_instructions(self) -> int:
        return len(self.instructions)

    def vex(self) -> IR | None:
        bb_ir = []
        for instr in self.instructions:
            bb_ir.append(instr.vex().data)
        return IR(lang_name=IL.VEX, data="\n".join(bb_ir))

    def ir(self) -> IR | None:
        lang = IL.UNK
        bb_ir = []

        if len(self.instructions) == 0:
            return None

        # We can assume no one is mixing IL. That would be hella weird otherwise
        instr = self.instructions[0]
        if instr.ir is not None:
            lang = instr.ir.lang_name

        for instr in self.instructions:
            if instr.ir is None:
                bb_ir.append(instr.vex().data)
            else:
                bb_ir.append(instr.ir.data)
        return IR(lang_name=lang, data="\n".join(bb_ir))


class NativeFunction(NativeCode):
    """
    Represents a natively compiled function
    """

    _ctxt: Any = None  # Reference to backing disassebler function context object
    _block_lookup: Dict[int, BasicBlock] = dict()
    _binary: Binary | None = None

    address: int | None = None
    canary: bool | None = None
    names: List[str] | None = None
    return_type: str | None = None
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
    def _populate_cache(self) -> Self:
        for bb in self.basic_blocks:
            if bb.address is not None:
                self._block_lookup[bb.address] = bb
            bb._function = self
        return self

    def __hash__(self) -> int:
        return int(self.sha256, 16)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NativeFunction):
            return False

        return hash(self) == hash(other)

    def __ne__(self, other: object) -> bool:
        return hash(self) != hash(other)

    def __contains__(self, x: Union[BasicBlock, Instruction, bytes]) -> bool:
        if isinstance(x, BasicBlock):
            return x in self.basic_blocks
        elif isinstance(x, Instruction) or isinstance(x, bytes):
            return any([x in bb for bb in self.basic_blocks])
        raise TypeError

    def __str__(self) -> str:
        addr = "N/A" if self.address is None else hex(self.address)
        return f"<Function {self.name}({','.join([str(arg) for arg in self.argv])}) address={addr}>"

    def __repr__(self) -> str:
        return str(self)

    def __bytes__(self) -> bytes:
        """Returns the bytes from the lowest addressed basic block to the end of the largest addressed basic block"""
        bbs = [bb for bb in self.basic_blocks]
        bbs = sorted(bbs, key=lambda b: b.address if b.address is not None else 0)

        if self._binary is not None:
            start_addr = bbs[0].address
            end_addr = bbs[-1].address
            if start_addr is None or end_addr is None:
                return b""
            start = start_addr - self._binary.base_addr
            end = end_addr + len(bbs[-1]) - self._binary.base_addr
            return bytes(self._binary)[start:end]

        return b""

    def start(self) -> BasicBlock:
        if self.address is None:
            # No function address defined — fall back to the basic block with the smallest address
            if any(addr is None for addr in self._block_lookup):
                raise ValueError(
                    "No start defined: one or more basic blocks have no address"
                )
            if not self._block_lookup:
                raise ValueError("No start defined: function has no basic blocks")
            return self._block_lookup[min(self._block_lookup)]

        bb = self._block_lookup.get(self.address, None)
        if bb is not None:
            return bb

        # Edge case, but saw this with the debug info where a frame descriptor entry's PcBegin pointed
        # two bytes into the the first basic block of a thunk function and a function was defined there,
        # nested within the thunk. Technically by the debug info, that is where the function starts,
        # but this breaks the assumption that the address of the first basic block is the address of the function
        # so we just clap to the function start
        candidates = [addr for addr in self._block_lookup if addr < self.address]
        if not candidates:
            raise ValueError(
                f"No basic block found at or before function address {self.address:#x}"
            )
        return self._block_lookup[max(candidates)]

    def end(self) -> List[BasicBlock]:
        return [self._block_lookup[e] for e in self.end_block_addrs]

    @property
    def name(self) -> str:
        if self.names is None:
            return "N/A"
        return self.names[0]

    def add_name(self, name: str) -> None:
        if self.names is None:
            self.names = []
        if name in self.names:
            return
        becomes_primary = len(self.names) == 0
        self.names.append(name)
        if self._binary is not None:
            self._binary._func_names[name] = self
            if (
                becomes_primary
                and self._binary._disassembler is not None
                and self.address is not None
            ):
                self._binary._disassembler.rename_function(self.address, name)

    def remove_name(self, name: str) -> None:
        if self.names is None or name not in self.names:
            return
        was_primary = self.names[0] == name
        self.names.remove(name)
        if self._binary is not None:
            self._binary._func_names.pop(name, None)
            if was_primary and self.names:
                self._binary._func_names[self.names[0]] = self
                if self._binary._disassembler is not None and self.address is not None:
                    self._binary._disassembler.rename_function(
                        self.address, self.names[0]
                    )

    @property
    def calls(self) -> Generator[NativeFunction, None, None]:
        """Functions that this Function Calls"""
        if self._binary is None:
            raise NoContextException("Function is not associated with Binary")

        for addr in self.calls_addrs:
            f = self._binary._func_addrs.get(addr, None)
            if f is not None:
                yield f

    @property
    def callers(self) -> Generator[NativeFunction, None, None]:
        """Functions that call this Function"""
        if self._binary is None:
            raise NoContextException("Function is not associated with Binary")

        for addr in self.called_by:
            f = self._binary._func_addrs.get(addr, None)
            if f is not None:
                yield f

    @cached_property
    def cfg(self) -> nx.DiGraph:
        """Control Flow Graph of the Function"""

        cfg: nx.DiGraph = nx.DiGraph()
        history: Set[BasicBlock] = set()
        bbs_to_explore: List[BasicBlock] = [self.start()]

        while len(bbs_to_explore) > 0:
            curr = bbs_to_explore.pop()
            if curr in history:
                continue

            history.add(curr)
            cfg.add_node(curr)

            for btype, dest in curr:
                if isinstance(dest, IndirectToken):
                    continue

                if isinstance(dest, BasicBlock):
                    branch_addr = dest.address
                else:
                    branch_addr = dest

                if branch_addr not in self._block_lookup:
                    continue

                cfg.add_node(dest)
                cfg.add_edge(curr, dest, branch=btype)

                if isinstance(dest, BasicBlock):
                    bbs_to_explore.append(dest)

        return cfg

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
            ir_obj = bb.ir()

            # ir_obj would only be None if the basic block had no instructions
            if ir_obj is not None:
                ir.append(ir_obj.data)

        return "\n".join(ir)


class SourceFunction(BaseModel):
    """
    Representation of the source code of a function.
    Currently tailored around C functions
    """

    _tree_sitter_root = None

    lang: str = "C"
    name: str
    decompiled: bool
    perfect_decomp: bool | None = False
    """True if the decompilation is exactly the true source code"""

    source: str
    argv: List[Argument] | None = list()
    return_type: str | None = ""
    qualifiers: Set[str] = set()
    """Function Qualifiers such as `const`, `volatile`, or `static`"""

    @classmethod
    def from_file(
        cls,
        fname: str,
        filepath: str,
        encoding: str = "utf8",
        lang: str = "C",
        is_decompiled=False,
    ) -> Self | None:
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
    ) -> Self | None:
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

    def __hash__(self) -> int:
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

    _path: Path | None = None
    _bytes: bytes | None = None
    _size: int | None = None
    _disassembler: Disassembler | None = None

    functions: Set[NativeFunction] = set()
    _func_sorted: List[int] = list()
    _func_names: Dict[str, NativeFunction] = dict()
    _func_addrs: Dict[int, NativeFunction] = dict()
    _bbs: Dict[int, BasicBlock] = dict()
    _bbs_sorted: List[int] = list()
    _instrs: Dict[int, Instruction] = dict()

    filename: str | List[str] | None = None

    names: List[str] = []
    """names this binary has gone by (multiple are possbile when loading data from a database)"""

    entrypoint: int | None = None
    os: str | None = None
    base_addr: int = 0
    dynamic_libs: Set[str] = set([])
    compiler: str | None = None
    compilation_flags: str | None = None
    is_stripped: bool | None = None
    has_debug_info: bool | None = None

    # Strings from String table if they exists, otherwise strings detected in the binary (like unix `strings`` command)
    strings: Set[str] = set([])

    def __len__(self) -> int:
        """returns the size of the binary in bytes"""
        if self._size is None:
            if self._path is not None:
                self._size = os.path.getsize(self._path)
            else:
                self._size = len(bytes(self))

        return self._size

    def __hash__(self) -> int:
        return int(self.sha256, 16)

    def __contains__(
        self, x: Union[NativeFunction, BasicBlock, Instruction, bytes]
    ) -> bool:
        if isinstance(x, NativeFunction):
            return x in self.functions
        elif isinstance(x, BasicBlock) or isinstance(x, Instruction):
            return any([x in f for f in self.functions])
        elif isinstance(x, bytes):
            return x in bytes(self)
        return False

    def __bytes__(self) -> bytes:
        """return the raw bytes of the binary"""
        if self._bytes is not None:
            return self._bytes

        if self._path is not None:
            with self._path.open("rb") as f:
                self._bytes = f.read()
            return self._bytes

        raise Binary.NoDataException("Binary Object has no Path or data")

    def model_post_init(self, context: Any, /) -> None:
        self.build_indexes()

    def set_path(self, path: Union[Path, str]) -> None:
        if isinstance(path, str):
            path = Path(path)
        self._path = path

    @cached_property
    def call_graph(self) -> nx.DiGraph:
        """Function Call Graph"""
        g: nx.DiGraph = nx.DiGraph()
        for f in self.functions:
            g.add_node(f)
            for child_f in f.calls:
                g.add_node(child_f)
                g.add_edge(f, child_f)

            for parent_f in f.callers:
                g.add_node(parent_f)
                g.add_edge(parent_f, f)
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

    def function_at(self, address: int) -> NativeFunction | None:
        """Returns a Function at the address specified"""
        return self._func_addrs.get(address, None)

    def function_sym(self, symbol: str) -> NativeFunction | None:
        """Returns a Function with the given symbol names"""
        return self._func_names.get(symbol, None)

    def basic_block(self, address: int) -> BasicBlock | None:
        """Returns a basic block at the given address"""
        return self._bbs.get(address, None)

    def instruction(self, address: int) -> Instruction | None:
        """Returns the instruction at the given address"""
        return self._instrs.get(address, None)

    def function_containing(self, address: int) -> NativeFunction | None:
        """Return the function which contains the given address"""
        idx = bisect.bisect_left(self._func_sorted, address)
        if idx >= len(self._func_sorted):
            return self._func_addrs[self._func_sorted[-1]]
        if self._func_sorted[idx] == address:
            return self._func_addrs[self._func_sorted[idx]]

        idx -= 1
        if idx < 0:
            return None

        return self._func_addrs[self._func_sorted[idx]]

    def bb_containing(self, address: int) -> BasicBlock | None:
        """Return the basicblock containing the given address"""
        idx = bisect.bisect_left(self._bbs_sorted, address)

        if idx >= len(self._bbs_sorted):
            bb = self._bbs[self._bbs_sorted[-1]]
        elif self._bbs_sorted[idx] == address:
            bb = self._bbs[self._bbs_sorted[idx]]
        else:
            idx -= 1
            if idx < 0:
                return None

            bb = self._bbs[self._bbs_sorted[idx]]

        if address in bb:
            return bb

        return None

    def build_indexes(self) -> None:
        self._func_sorted.clear()
        self._func_names.clear()
        self._func_addrs.clear()
        self._bbs.clear()
        self._bbs_sorted.clear()
        self._instrs.clear()

        for f in self.functions:
            f._binary = self

            # Generally functions will have a default name and address,
            # but our model has the flexibility for these two be None if you wish to manipulate these outside the context of a program
            if f.names is not None and len(f.names) > 0:
                self._func_names[f.names[0]] = f
            if f.address is not None:
                self._func_addrs[f.address] = f

            for bb in f.basic_blocks:
                if bb.address is not None:
                    self._bbs[bb.address] = bb
                    self._bbs_sorted.append(bb.address)

                for instr in bb.instructions:
                    if instr.address is not None:
                        self._instrs[instr.address] = instr

        self._func_sorted = list(self._func_addrs)
        self._func_sorted.sort()
        self._bbs_sorted.sort()
