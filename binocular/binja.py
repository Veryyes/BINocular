from __future__ import annotations

import os
import sys
import pathlib
import typing
from collections.abc import Iterable
from typing import Any, List, Tuple

import typing_extensions
from typing_extensions import override

from . import logger
from .disassembler import Disassembler
from .consts import IL, Endian, BranchType, RefType
from .primitives import IR, Branch, Argument, Variable, Reference, Instruction
import typing
if typing.TYPE_CHECKING:
    import binaryninja
# Lazy import: binaryninja is only imported when actually used
_bn = None


def _import_binja():
    """Lazily import the binaryninja module.

    Tries a direct import first (works if the user ran Binary Ninja's
    install_api.py or otherwise has the module on sys.path). Falls back
    to the BN_INSTALL_DIR environment variable.
    """
    global _bn
    if _bn is not None:
        return _bn

    # Try direct import first (already on sys.path or pip-installed)
    try:
        import binaryninja

        _bn = binaryninja
        return _bn
    except ImportError:
        pass

    # Fall back to BN_INSTALL_DIR environment variable
    bn_dir = os.environ.get("BN_INSTALL_DIR")
    if bn_dir:
        py_path = os.path.join(bn_dir, "python")
        if os.path.isdir(py_path) and py_path not in sys.path:
            sys.path.insert(0, py_path)
            try:
                import binaryninja

                _bn = binaryninja
                return _bn
            except ImportError:
                pass

    raise ImportError(
        "Cannot import binaryninja. Either run Binary Ninja's install_api.py "
        "to install the Python module, or set the BN_INSTALL_DIR environment "
        "variable to your Binary Ninja installation directory."
    )


class BinaryNinja(Disassembler):
    """Binary Ninja disassembler backend for BINocular."""

    @classmethod
    def is_installed(cls, install_dir: str | None = None) -> bool:
        """Returns True if Binary Ninja is importable."""
        try:
            _import_binja()
            return True
        except ImportError:
            return False

    @classmethod
    def install(
        cls,
        version: str | None = None,
        install_dir: str | None = None,
        build: bool | None = False,
        local_install_file: str | None = None,
    ) -> str | None:
        """Binary Ninja is commercial software and cannot be auto-installed."""
        logger.warning(
            "Binary Ninja is commercial software. "
            "Please install from https://binary.ninja/ "
            "and ensure the Python module is available on sys.path."
        )
        return None

    @classmethod
    def IL(cls) -> IL:
        return IL.LLIL # BinaryNinja implementation returns low level IL

    def __init__(
        self,
        filepath: pathlib.Path | str,
        verbose: bool = True,
    ) -> None:
        super().__init__(filepath=filepath, verbose=verbose)
        self._bv: binaryninja.BinaryView | None = None

    @property
    def bv(self) -> binaryninja.BinaryView:
        if self._bv is not None:
            return self._bv
        raise self.NotOpenedError()

    def open(self) -> typing_extensions.Self:
        super().open()

        if not self.binary_filepath.exists() or self.binary_filepath.is_dir():
            raise OSError(f"File not found: {self.binary_filepath}")

        bn = _import_binja()
        self._bv = bn.load(str(self.binary_filepath.resolve()))
        if self._bv is None:
            raise self.FailedToLoadBinaryError(
                f"Binary Ninja failed to load: {self.binary_filepath}"
            )

        return self

    def close(self):
        """Release Binary Ninja resources."""
        if self._bv is not None:
            self._bv.file.close()
            self._bv = None
        super().close()

    def analyze(self) -> None:
        """Binary Ninja auto-analyzes on load, so this is a lightweight call."""
        super().analyze()

    # -------------------------------------------------------
    # Binary-level metadata
    # -------------------------------------------------------

    @override
    def get_entry_point(self) -> int:
        return self.bv.entry_point

    @override
    def get_architecture(self) -> str:
        arch = self.bv.arch
        if arch is None: # Only happens when no architecture is associated with the BinaryView. 
            return "Unknown"
        if arch.name is None:
            return "Unnamed Architecture"
        return arch.name

    @override
    def get_endianness(self) -> Endian:
        bn = _import_binja()
        if self.bv.endianness == bn.Endianness.LittleEndian:
            return Endian.LITTLE
        elif self.bv.endianness == bn.Endianness.BigEndian:
            return Endian.BIG
        return Endian.OTHER

    @override
    def get_bitness(self) -> int:
        return self.bv.address_size * 8

    @override
    def get_base_address(self) -> int:
        return self.bv.start

    @override
    def get_strings(self) -> Iterable[str]:
        return [s.value for s in self.bv.strings]

    @override
    def get_dynamic_libs(self) -> Iterable[str]:
        return [lib.name for lib in self.bv.get_external_libraries()]

    # -------------------------------------------------------
    # Function iteration
    # -------------------------------------------------------

    @override
    def get_func_iterator(self) -> Iterable[binaryninja.Function]:
        for func in self.bv.functions:
            yield func

    @override
    def get_func_addr(self, func_ctxt: binaryninja.Function) -> int:
        return func_ctxt.start

    @override
    def get_func_name(self, addr: int, func_ctxt: binaryninja.Function) -> str:
        return func_ctxt.name

    @override
    def get_func_args(self, addr: int, func_ctxt: binaryninja.Function) -> List[Argument]:
        args = []
        for param in func_ctxt.parameter_vars:
            args.append(
                Argument(
                    data_type=str(param.type) if param.type is not None else None,
                    var_name=param.name,
                )
            )

        has_varargs = func_ctxt.has_variable_arguments
        if has_varargs.value:
            args.append(Argument(data_type=None, var_name=None, var_args=True))

        return args

    @override
    def get_func_return_type(self, addr: int, func_ctxt: binaryninja.Function) -> str:
        return str(func_ctxt.return_type)

    @override
    def get_func_stack_frame_size(self, addr: int, func_ctxt: binaryninja.Function) -> int:
        total = 0
        for var in func_ctxt.stack_layout:
            if var.type is not None:
                total += var.type.width
        return total

    @override
    def is_func_thunk(self, addr: int, func_ctxt: binaryninja.Function) -> bool:
        return func_ctxt.is_thunk
        return func_ctxt.is_thunk

    @override
    def get_func_decomp(self, addr: int, func_ctxt: binaryninja.Function) -> str | None:
        try:
            hlil = func_ctxt.hlil
            if hlil is not None:
                return str(hlil)
        except Exception:
            pass
        return None

    @override
    def get_func_vars(self, addr: int, func_ctxt: binaryninja.Function) -> Iterable[Variable]:
        bn = _import_binja()
        variables: List[Variable] = []
        for var in func_ctxt.vars:
            is_stack = var.source_type == bn.VariableSourceType.StackVariableSourceType
            is_register = (
                var.source_type == bn.VariableSourceType.RegisterVariableSourceType
            )

            v = Variable(
                data_type=str(var.type) if var.type is not None else "unknown",
                name=var.name,
                is_register=is_register,
                is_stack=is_stack,
            )
            if is_stack:
                v.stack_offset = var.storage
            variables.append(v)

        return variables

    @override
    def get_func_callers(self, addr: int, func_ctxt: binaryninja.Function) -> Iterable[int]:
        for caller in func_ctxt.callers:
            yield caller.start

    @override
    def get_func_callees(self, addr: int, func_ctxt: binaryninja.Function) -> Iterable[int]:
        for callee in func_ctxt.callees:
            yield callee.start

    def _classify_code_ref(self, target_addr: int) -> RefType:
        """Classify a code reference as CALL or JUMP based on whether target is a function entry."""
        if self.bv.get_function_at(target_addr) is not None:
            return RefType.CALL
        return RefType.JUMP

    @override
    def get_func_xrefs(self, addr: int, func_ctxt: binaryninja.Function) -> Iterable[Reference]:
        for bb in func_ctxt.basic_blocks:
            cur_addr = bb.start
            for _tokens, size in bb:
                # Outgoing code references (jumps/calls)
                code_refs = self.bv.get_code_refs_from(cur_addr)
                for target in code_refs:
                    yield Reference(
                        from_=cur_addr,
                        to=target,
                        type=self._classify_code_ref(target),
                    )

                # Outgoing data references
                for target in self.bv.get_data_refs_from(cur_addr):
                    yield Reference(
                        from_=cur_addr,
                        to=target,
                        type=RefType.DATA,
                    )

                cur_addr += size

    # -------------------------------------------------------
    # Basic block iteration
    # -------------------------------------------------------

    @override
    def get_func_bb_iterator(self, addr: int, func_ctxt: binaryninja.Function) -> Iterable[binaryninja.BasicBlock]:
        for bb in func_ctxt.basic_blocks:
            yield bb

    @override
    def get_bb_addr(self, bb_ctxt: binaryninja.BasicBlock, func_ctxt: binaryninja.Function) -> int:
        return bb_ctxt.start

    @override
    def get_next_bbs(
        self,
        bb_addr: int,
        bb_ctxt: binaryninja.BasicBlock,
        func_addr: int,
        func_ctxt: binaryninja.Function,
    ) -> Iterable[Branch]:
        bn = _import_binja()
        for edge in bb_ctxt.outgoing_edges:
            if edge.type == bn.BranchType.TrueBranch:
                yield Branch(type=BranchType.TrueBranch, target=edge.target.start)
            elif edge.type == bn.BranchType.FalseBranch:
                yield Branch(type=BranchType.FalseBranch, target=edge.target.start)
            elif edge.type == bn.BranchType.UnconditionalBranch:
                yield Branch(
                    type=BranchType.UnconditionalBranch, target=edge.target.start
                )
            elif edge.type == bn.BranchType.IndirectBranch:
                yield Branch(type=BranchType.IndirectBranch, target=None)
            # Skip CallDestination, FunctionReturn, SystemCall, etc.

    @override
    def get_bb_instructions(
        self, bb_addr: int, bb_ctxt: binaryninja.BasicBlock, func_ctxt: binaryninja.Function
    ) -> List[Tuple[bytes, str]]:
        instructions = []
        cur_addr = bb_ctxt.start
        for tokens, size in bb_ctxt:
            raw_bytes = self.bv.read(cur_addr, size)
            asm_text = "".join(str(t) for t in tokens).strip()
            instructions.append((raw_bytes, asm_text))
            cur_addr += size
        return instructions

    @override
    def get_ir_from_instruction(
        self, instr_addr: int, instr: Instruction
    ) -> IR | None:
        funcs = self.bv.get_functions_containing(instr_addr)
        if not funcs:
            return instr.vex()

        func = funcs[0]
        try:
            llils = func.get_llils_at(instr_addr)
            if llils:
                data = ";".join(str(il) for il in llils)
                return IR(lang_name=IL.BNIL, data=data)
        except Exception:
            pass

        return instr.vex()

    @override
    def get_instruction_comment(self, instr_addr: int) -> str | None:
        funcs = self.bv.get_functions_containing(instr_addr)
        if not funcs:
            return None

        comment = funcs[0].get_comment_at(instr_addr)
        if comment:
            return comment
        return None
