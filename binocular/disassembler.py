from __future__ import annotations

import logging
import os
import types
import string
import pathlib
import functools
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any, Set, List, Type, Tuple

import typing_extensions

from .consts import Endian
from .primitives import (
    IR,
    IL,
    Binary,
    Branch,
    Argument,
    Variable,
    Reference,
    BasicBlock,
    Instruction,
    NativeFunction,
    SourceFunction,
)

logger = logging.getLogger("BINocular")


class Disassembler(ABC):
    """
    Abstract Class for a Disassembler.
    """

    class FailedToLoadBinaryError(Exception):
        """Raise when a Disassembler fails to load a binary"""

        pass

    class ArchitectureNotSupportedError(Exception):
        """Raise when a disassembler receives a binary of an architecture that it does not support"""

        pass

    class NotOpenedError(RuntimeError):
        """Raised when Diassembler.analyze() needs to be called first in order for the function to work properly"""

        def __init__(self):
            super().__init__(
                "Disassembler has not been opened with a binary yet. Call open() or use a Context Manager"
            )

    class AnalyzeNotRunError(NotOpenedError):
        """Raised when Diassembler.analyze() needs to be called first in order for the function to work properly"""

        def __init__(self):
            super().__init__("analyzer() must be run first")

    def __init__(self, filepath: pathlib.Path | str, verbose: bool = True):
        self.verbose: bool = verbose
        self.opened: bool = False
        self.is_loaded: bool = False
        self.binary_filepath: pathlib.Path = pathlib.Path(filepath)

        self._binary: Binary | None = None
        self._functions: Set[NativeFunction] | None = None

    def __enter__(self):
        return self.open()

    def __exit__(
        self,
        type: Type[BaseException] | None,
        value: BaseException | None,
        tb: types.TracebackType | None,
    ) -> bool | None:
        return self.close()

    @property
    def name(self):
        """Returns the Name of the Disassembler"""
        return self.__class__.__name__

    @property
    def binary(self) -> Binary:
        if self._binary is None:
            self._load()
            assert self._binary is not None

        return self._binary

    @property
    def functions(self) -> Set[NativeFunction]:
        if self._functions is None:
            self._load()
            assert self._functions is not None

        return self._functions

    ############################################
    # OPTIONAL DISASSEMBLER DEFINED OPERATIONS #
    ############################################

    @classmethod
    def list_versions(cls) -> List[str]:
        """List installable verions of this disassembler"""
        return list()

    @classmethod
    def IL(cls) -> IL:
        return IL.UNK

    def open(self) -> typing_extensions.Self:
        """Open up any resources"""
        self.opened = True
        return self

    def close(self):
        """Release/Free up any resources"""
        self.opened = False

    def get_strings(self) -> Iterable[str]:
        """
        Returns the list of defined strings in the binary
        :param binary_io: a file-like object to the binary ingested
        :returns: list of strings in the file (similar to the strings unix utility)
        """
        return self._strings()

    def get_binary_name(self) -> str:
        """Returns the name of the binary loaded"""
        return self.binary_filepath.name

    def get_func_decomp(self, addr: int, func_ctxt: Any) -> str | None:
        """Returns the decomplication of the function corresponding to the function information returned from `get_func_iterator()`"""
        return None

    def get_func_vars(self, addr: int, func_ctxt: Any) -> Iterable[Variable]:
        """Return variables within the function corresponding to the function information returned from `get_func_iterator()`"""
        return list()

    def get_ir_from_instruction(self, instr_addr: int, instr: Instruction) -> IR | None:
        """
        Returns a list of Intermediate Representation data based on the instruction given
        """
        return instr.vex()

    def get_instruction_comment(self, instr_addr: int) -> str | None:
        """Return comments at the instruction"""
        return None

    def run_script(
        self, script: str, timeout: int, script_args: List[str] | None = None
    ) -> str | None:
        """Run a custom script"""
        return None

    ############################################
    # REQUIRED DISASSEMBLER DEFINED OPERATIONS #
    ############################################

    @classmethod
    @abstractmethod
    def is_installed(cls) -> bool:
        """Returns Boolean on whether or not the dissassembler is installed"""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def install(
        cls,
        version: str | None = None,
        install_dir: str | None = None,
        build: bool | None = False,
        local_install_file: str | None = None,
    ) -> str | None:
        """
        Installs the disassembler to a user specified directory or within the python module if none is specified
        :param version: The release version or commit hash. If commit hash is provided build must be set True. Ignored if local_install_file is provided
        :param install_dir: The directory to install the disassembler too
        :param build: True if the disassembler should be built from source
        :param local_install_file: Path to the release file of the disassembler
        :returns: the directory the disassembler is installed to
        """
        raise NotImplementedError

    def analyze(self) -> None:
        """
        Starts analysis of the binary loaded from open or with a context manager
        Implement all diaassembler specific setup and trigger analysis here.
        """
        if not self.opened:
            raise Disassembler.NotOpenedError()

    @abstractmethod
    def get_entry_point(self) -> int:
        """Returns the address of the entry point to the function"""
        raise NotImplementedError

    @abstractmethod
    def get_architecture(self) -> str:
        """
        Returns the architecture of the binary.
        For best results use either archinfo, qemu, or compilation triplet naming conventions.
        https://github.com/angr/archinfo
        """
        raise NotImplementedError

    @abstractmethod
    def get_endianness(self) -> Endian:
        """Returns an Enum representing the Endianness"""
        raise NotImplementedError

    @abstractmethod
    def get_bitness(self) -> int:
        """Returns the word size of the architecture (e.g., 16, 32, 64)"""
        raise NotImplementedError

    @abstractmethod
    def get_base_address(self) -> int:
        """Returns the base address the binary is based at"""
        raise NotImplementedError

    @abstractmethod
    def get_dynamic_libs(self) -> Iterable[str]:
        """Returns the list of names of the dynamic libraries used in this binary"""
        raise NotImplementedError

    @abstractmethod
    def is_stripped(self) -> bool:
        """Returns whether the binary has been stripped of debug symbols"""
        raise NotImplementedError

    @abstractmethod
    def has_debug_info(self) -> bool:
        """Returns whether the binary contains debug information"""
        raise NotImplementedError

    @abstractmethod
    def rename_function(self, addr: int, name: str) -> None:
        """Rename the function at `addr` to `name` in the disassembler's internal state."""
        raise NotImplementedError

    @abstractmethod
    def get_func_iterator(self) -> Iterable[Any]:
        """
        Returns an iterable of `Any` data type (e.g., address, interal func obj, dict of data)
        needed to construct a `Function` object for all functions in the binary.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        """
        raise NotImplementedError

    @abstractmethod
    def get_func_addr(self, func_ctxt: Any) -> int:
        """Returns the address of the function corresponding to the function information returned from `get_func_iterator()`"""
        raise NotImplementedError

    @abstractmethod
    def get_func_name(self, addr: int, func_ctxt: Any) -> str:
        """Returns the name of the function corresponding to the function information returned from `get_func_iterator()`"""
        raise NotImplementedError

    @abstractmethod
    def get_func_args(self, addr: int, func_ctxt: Any) -> List[Argument]:
        """Returns the arguments in the function corresponding to the function information returned from `get_func_iterator()`"""
        raise NotImplementedError

    @abstractmethod
    def get_func_return_type(self, addr: int, func_ctxt: Any) -> str:
        """Returns the return type of the function corresponding to the function information returned from `get_func_iterator()`"""
        raise NotImplementedError

    @abstractmethod
    def get_func_stack_frame_size(self, addr: int, func_ctxt: Any) -> int:
        """Returns the size of the stack frame in the function corresponding to the function information returned from `get_func_iterator()`"""
        raise NotImplementedError

    @abstractmethod
    def is_func_thunk(self, addr: int, func_ctxt: Any) -> bool:
        """Returns True if the function corresponding to the function information returned from `get_func_iterator()` is a thunk"""
        raise NotImplementedError

    @abstractmethod
    def get_func_callers(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        """Return the address to functions that call func_ctxt"""
        raise NotImplementedError

    @abstractmethod
    def get_func_callees(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        """Return the address to functions that are called in func_ctxt"""
        raise NotImplementedError

    @abstractmethod
    def get_func_xrefs(self, addr: int, func_ctxt: Any) -> Iterable[Reference]:
        """Returns an iterable of references within a function"""
        raise NotImplementedError

    @abstractmethod
    def get_func_bb_iterator(self, addr: int, func_ctxt: Any) -> Iterable[Any]:
        """
        Returns an iterator of `Any` data type (e.g., address, implementation specific basic block information, dict of data)
        needed to construct a `BasicBlock` object for all basic blocks in the function based on function information returned from `get_func_iterator()`.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        """
        raise NotImplementedError

    @abstractmethod
    def get_bb_addr(self, bb_ctxt: Any, func_ctxt: Any) -> int:
        """
        Returns the address of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        raise NotImplementedError

    @abstractmethod
    def get_next_bbs(
        self, bb_addr: int, bb_ctxt: Any, func_addr: int, func_ctxt: Any
    ) -> Iterable[Branch]:
        """
        Returns the Branching information of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        raise NotImplementedError

    @abstractmethod
    def get_bb_instructions(
        self, bb_addr: int, bb_ctxt: Any, func_ctxt: Any
    ) -> List[Tuple[bytes, str]]:
        """
        Returns a iterable of tuples of raw instruction bytes and corresponding mnemonic from the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        raise NotImplementedError

    ###################
    # Private Helpers #
    ###################

    def _load(self) -> None:
        # Only need to fire this function off once to populate all the member variables
        if self.is_loaded:
            return

        self.is_loaded = True
        try:
            self._binary = self._load_binary()
            self._functions = self._load_functions()
            self._binary.functions = self._functions
            self._binary.build_indexes()
            self._binary._disassembler = self
        except Exception as e:
            logger.critical(f"Failed to load binary: {e}")
            self.is_loaded = False
            raise

    def _load_binary(self) -> Binary:
        b = Binary(
            filename=os.path.basename(self.binary_filepath),
            names=[self.get_binary_name()],
            entrypoint=self.get_entry_point(),
            architecture=self.get_architecture(),
            endianness=self.get_endianness(),
            bitness=self.get_bitness(),
            base_addr=self.get_base_address(),
            dynamic_libs=self.get_dynamic_libs(),
            is_stripped=self.is_stripped(),
            has_debug_info=self.has_debug_info(),
        )
        b.set_path(self.binary_filepath)
        b.strings |= set(self.get_strings())

        return b

    def _load_functions(self) -> Set[NativeFunction]:
        funcs: Set[NativeFunction] = set()
        for func_ctxt in self.get_func_iterator():
            addr = self.get_func_addr(func_ctxt)
            func_name = self.get_func_name(addr, func_ctxt)
            logger.debug(f"Processing Function: {func_name}")
            f = NativeFunction(
                endianness=self.binary.endianness,
                architecture=self.binary.architecture,
                bitness=self.binary.bitness,
                address=addr,
                names=[func_name],
                return_type=self.get_func_return_type(addr, func_ctxt),
                argv=self.get_func_args(addr, func_ctxt),
                thunk=self.is_func_thunk(addr, func_ctxt),
                stack_frame_size=self.get_func_stack_frame_size(addr, func_ctxt),
                variables=[v for v in self.get_func_vars(addr, func_ctxt)],
            )
            f._ctxt = func_ctxt
            decompiled_code = self.get_func_decomp(addr, func_ctxt)

            dsrc = None
            if decompiled_code is not None:
                dsrc = SourceFunction.from_code(
                    fname=func_name, source=decompiled_code, is_decompiled=True
                )
                if dsrc is None:
                    # Failed to parse source with tree sitter :(
                    # Random notes: some disassemblers like to inject extra things into the decompiled source
                    # i.e. it's not true C code.
                    # e.g., adding annotations like 'processEntry': `void processEntry _start(undefined8 param_1,undefined8 param_2)``
                    dsrc = SourceFunction(
                        name=func_name,
                        decompiled=True,
                        source=decompiled_code,
                    )

                f.sources.add(dsrc)

            xrefs = set(self.get_func_xrefs(addr, func_ctxt))
            self._load_basic_blocks(addr, func_ctxt, f, xrefs.copy())

            if len(f.basic_blocks) > 0:
                f.end_block_addrs = set(
                    (
                        bb.address
                        for bb, out_degree in f.cfg.out_degree()
                        if out_degree == 0
                    )
                )
            elif not f.thunk:
                logger.warning(f"[{self.name}] {func_name} @ {addr} has 0 Basic Blocks")

            funcs.add(f)

        # 2nd pass to do callee/callers
        for f in funcs:
            f.called_by = set()
            assert f.address is not None  # We just set it above
            for caller_addr in self.get_func_callers(f.address, f._ctxt):
                f.called_by.add(caller_addr)

            f.calls_addrs = set()
            for callee_addr in self.get_func_callees(f.address, f._ctxt):
                f.calls_addrs.add(callee_addr)

        return funcs

    def _load_basic_blocks(
        self, addr: int, func_ctxt: Any, f: NativeFunction, xrefs: Set[Reference]
    ) -> None:
        for bb_ctxt in self.get_func_bb_iterator(addr, func_ctxt):
            bb_addr = self.get_bb_addr(bb_ctxt, func_ctxt)

            bb = BasicBlock(
                endianness=self.binary.endianness,
                architecture=self.binary.architecture,
                bitness=self.binary.bitness,
                address=bb_addr,
            )

            for branch_data in self.get_next_bbs(bb_addr, bb_ctxt, addr, func_ctxt):
                bb.branches.add(branch_data)

            self._load_instructions(bb_addr, bb_ctxt, bb, func_ctxt)

            for xref in xrefs:
                if xref.from_ in bb or xref.to in bb:
                    bb.xrefs.add(xref)
            xrefs -= bb.xrefs

            f.basic_blocks.add(bb)

            if bb.address is None:
                raise RuntimeError("No address associated with basic block")
            f._block_lookup[bb.address] = bb
            bb.set_function(f)

        if len(xrefs) > 0 and len(f.basic_blocks) > 0:
            logger.warning(f"[{self.name}] {len(xrefs)} XRefs not in function: {xrefs}")

    def _load_instructions(
        self, bb_addr: int, bb_ctxt: Any, bb: BasicBlock, func_ctxt: Any
    ) -> None:
        cur_addr = bb_addr
        for data, asm in self.get_bb_instructions(bb_addr, bb_ctxt, func_ctxt):
            instr = Instruction(
                endianness=self.binary.endianness,
                architecture=self.binary.architecture,
                bitness=self.binary.bitness,
                address=cur_addr,
                data=data,
                asm=asm,
                comment=self.get_instruction_comment(cur_addr),
            )
            ir = self.get_ir_from_instruction(cur_addr, instr)
            instr.ir = ir
            bb.instructions.append(instr)

            cur_addr += len(data)

    @functools.cache
    def _strings(self, min_size: int = 4) -> Iterable[str]:
        CHUNK_SIZE = 4096
        MIN_BUFFER_SIZE = min_size + 1  # +1 to account for null terminator
        strings = list()
        printables = bytes(string.printable, "ascii")

        buff = b""
        with open(self.binary_filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                buff += chunk

                i = 0
                while len(buff) >= MIN_BUFFER_SIZE:
                    while buff[i] in printables:
                        i += 1

                    if buff[i] == 0 and i > (min_size - 1):
                        strings.append(str(buff[:i], "ascii"))
                        buff = buff[i + 1 :]
                    else:
                        buff = buff[1:]
                    i = 0

        return strings
