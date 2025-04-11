from __future__ import annotations

from collections.abc import Iterable
from typing import IO, Any, List, Optional, Tuple

from binocular import (
    IR,
    Argument,
    Branch,
    Disassembler,
    Endian,
    Instruction,
    Reference,
    Variable,
)


class TemplateDisassm(Disassembler):

    ##################################
    # Optional to Implement/Redefine #
    ##################################

    def __init__(self) -> None:
        super().__init__()

    @classmethod
    def list_versions(cls) -> List[str]:
        """List installable verions of this disassembler"""
        return list()

    def open(self):
        """Open up any resources"""
        return self

    def close(self):
        """Release/Free up any resources"""
        pass

    def clear(self):
        """Reset any state within this object"""
        return super().clear()

    def get_strings(self, binary_io: IO, file_size: int) -> Iterable[str]:
        return super().get_strings(binary_io, file_size)

    def get_ir_from_instruction(
        self, instr_addr: int, instr: Instruction
    ) -> Optional[IR]:
        """
        Returns a list of Intermediate Representation data based on the instruction given
        """
        return super().get_ir_from_instruction(instr_addr, instr)

    def get_binary_name(self) -> str:
        """Returns the name of the binary loaded"""
        return super().get_binary_name()

    def get_func_decomp(self, addr: int, func_ctxt: Any) -> Optional[str]:
        """Returns the decomplication of the function corresponding to the function information returned from `get_func_iterator()`"""
        return None

    def get_func_vars(self, addr: int, func_ctxt: Any) -> Iterable[Variable]:
        """Return variables within the function corresponding to the function information returned from `get_func_iterator()`"""
        return list()

    def get_instruction_comment(self, instr_addr: int) -> Optional[str]:
        """Return comments at the instruction"""
        return None

    ####################
    # Please Implement #
    ####################

    def analyze(self, path) -> Tuple[bool, Optional[str]]:
        """
        Loads the binary specified by `path` into the disassembler.
        Implement all diaassembler specific setup and trigger analysis here.
        :returns: (True, optional message) on success, (False, failure reason) otherwise
        """
        raise NotImplementedError

    @classmethod
    def is_installed(cls) -> bool:
        """Returns Boolean on whether or not the dissassembler is installed"""
        raise NotImplementedError

    @classmethod
    def install(cls, install_dir=None):
        """Installs the disassembler to a user specified directory or within the python module if none is specified"""
        raise NotImplementedError

    def get_entry_point(self) -> int:
        """Returns the address of the entry point to the function"""
        raise NotImplementedError

    def get_architecture(self) -> str:
        """
        Returns the architecture of the binary.
        For best results use either archinfo, qemu, or compilation triplet naming conventions.
        https://github.com/angr/archinfo
        """
        raise NotImplementedError

    def get_endianness(self) -> Endian:
        """Returns an Enum representing the Endianness"""
        raise NotImplementedError

    def get_bitness(self) -> int:
        """Returns the word size of the architecture (e.g., 16, 32, 64)"""
        raise NotImplementedError

    def get_base_address(self) -> int:
        """Returns the base address the binary is based at"""
        raise NotImplementedError

    def get_dynamic_libs(self) -> Iterable[str]:
        """Returns the list of names of the dynamic libraries used in this binary"""
        raise NotImplementedError

    def get_func_iterator(self) -> Iterable[Any]:
        """
        Returns an iterable of `Any` data type (e.g., address, interal func obj, dict of data)
        needed to construct a `Function` object for all functions in the binary.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        """
        raise NotImplementedError

    def get_func_addr(self, func_ctxt: Any) -> int:
        """Returns the address of the function corresponding to the function information returned from `get_func_iterator()`"""
        raise NotImplementedError

    def get_func_name(self, addr: int, func_ctxt: Any) -> str:
        """Returns the name of the function corresponding to the function information returned from `get_func_iterator()`"""
        raise NotImplementedError

    def get_func_args(self, addr: int, func_ctxt: Any) -> List[Argument]:
        """Returns the arguments in the function corresponding to the function information returned from `get_func_iterator()`"""
        raise NotImplementedError

    def get_func_return_type(self, addr: int, func_ctxt: Any) -> str:
        """Returns the return type of the function corresponding to the function information returned from `get_func_iterator()`"""
        raise NotImplementedError

    def get_func_stack_frame_size(self, addr: int, func_ctxt: Any) -> int:
        """Returns the size of the stack frame in the function corresponding to the function information returned from `get_func_iterator()`"""
        raise NotImplementedError

    def is_func_thunk(self, addr: int, func_ctxt: Any) -> bool:
        """Returns True if the function corresponding to the function information returned from `get_func_iterator()` is a thunk"""
        raise NotImplementedError

    def get_func_callers(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        """Return the address to functions that call func_ctxt"""
        raise NotImplementedError

    def get_func_callees(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        """Return the address to functions that are called in func_ctxt"""
        raise NotImplementedError

    def get_func_xrefs(self, addr: int, func_ctxt: Any) -> Iterable[Reference]:
        """Returns an iterable of references within a function"""
        raise NotImplementedError

    def get_func_bb_iterator(self, addr: int, func_ctxt: Any) -> Iterable[Any]:
        """
        Returns an iterator of `Any` data type (e.g., address, implementation specific basic block information, dict of data)
        needed to construct a `BasicBlock` object for all basic blocks in the function based on function information returned from `get_func_iterator()`.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        """
        raise NotImplementedError

    def get_bb_addr(self, bb_ctxt: Any, func_ctxt: Any) -> int:
        """
        Returns the address of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        raise NotImplementedError

    def get_next_bbs(
        self, bb_addr: int, bb_ctxt: Any, func_addr: int, func_ctxt: Any
    ) -> Iterable[Branch]:
        """
        Returns the Branching information of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        raise NotImplementedError

    def get_bb_instructions(
        self, bb_addr: int, bb_ctxt: Any, func_ctxt: Any
    ) -> List[Tuple[bytes, str]]:
        """
        Returns a iterable of tuples of raw instruction bytes and corresponding mnemonic from the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        raise NotImplementedError
