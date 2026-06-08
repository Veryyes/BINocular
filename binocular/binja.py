from __future__ import annotations

import logging
import os
import sys
import pathlib
import typing
from collections.abc import Iterable
from typing import List, Tuple

import typing_extensions
from typing_extensions import override

from .disassembler import Disassembler
from .consts import IL, Endian, BranchType, RefType
from .primitives import IR, Branch, Argument, Variable, Reference, Instruction

if typing.TYPE_CHECKING:
    import binaryninja

logger = logging.getLogger("BINocular")

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
        return IL.LLIL  # BinaryNinja implementation returns low level IL

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
        if (
            arch is None
        ):  # Only happens when no architecture is associated with the BinaryView.
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

    @override
    def is_stripped(self) -> bool:
        # Non-allocated ELF sections (.symtab) live in parent_view, not bv.sections.
        parent = self.bv.parent_view
        if parent is not None and ".symtab" in parent.sections:
            return False
        # PE: CodeView sections are allocated and appear in bv.sections.
        if ".debug$S" in self.bv.sections or ".debug$T" in self.bv.sections:
            return False
        return True

    @override
    def has_debug_info(self) -> bool:
        # Non-allocated ELF sections (.debug_*) are added to parent_view by BN's ELF
        # loader, not to the analysis view. Check both to handle ELF and PE/MachO.
        for view in (v for v in [self.bv, self.bv.parent_view] if v is not None):
            for name in view.sections:
                if name.startswith((".debug", ".zdebug", "__debug")):
                    return True
        return False

    @override
    def rename_function(self, addr: int, name: str) -> None:
        func = self.bv.get_function_at(addr)
        if func is not None:
            func.name = name

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
    def get_func_args(
        self, addr: int, func_ctxt: binaryninja.Function
    ) -> List[Argument]:
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
    def get_func_stack_frame_size(
        self, addr: int, func_ctxt: binaryninja.Function
    ) -> int:
        total = 0
        for var in func_ctxt.stack_layout:
            if var.type is not None:
                total += var.type.width
        return total

    @override
    def is_func_thunk(self, addr: int, func_ctxt: binaryninja.Function) -> bool:
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
    def get_func_vars(
        self, addr: int, func_ctxt: binaryninja.Function
    ) -> Iterable[Variable]:
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
    def get_func_callers(
        self, addr: int, func_ctxt: binaryninja.Function
    ) -> Iterable[int]:
        for caller in func_ctxt.callers:
            yield caller.start

    @override
    def get_func_callees(
        self, addr: int, func_ctxt: binaryninja.Function
    ) -> Iterable[int]:
        for callee in func_ctxt.callees:
            yield callee.start

    def _classify_code_ref(self, target_addr: int) -> RefType:
        """Classify a code reference as CALL or JUMP based on whether target is a function entry."""
        if self.bv.get_function_at(target_addr) is not None:
            return RefType.CALL
        return RefType.JUMP

    @override
    def get_func_xrefs(
        self, addr: int, func_ctxt: binaryninja.Function
    ) -> Iterable[Reference]:
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
    def get_func_bb_iterator(
        self, addr: int, func_ctxt: binaryninja.Function
    ) -> Iterable[binaryninja.BasicBlock]:
        for bb in func_ctxt.basic_blocks:
            yield bb

    @override
    def get_bb_addr(
        self, bb_ctxt: binaryninja.BasicBlock, func_ctxt: binaryninja.Function
    ) -> int:
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
        self,
        bb_addr: int,
        bb_ctxt: binaryninja.BasicBlock,
        func_ctxt: binaryninja.Function,
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
    def get_ir_from_instruction(self, instr_addr: int, instr: Instruction) -> IR | None:
        funcs = self.bv.get_functions_containing(instr_addr)
        if not funcs:
            return instr.vex()

        func = funcs[0]
        try:
            llils = func.get_llils_at(instr_addr)
            if llils:
                data = ";".join(str(il) for il in llils)
                return IR(lang_name=IL.LLIL, data=data)
        except Exception:
            pass

        return instr.vex()

    @override
    def get_classes(self) -> Iterable[typing.Any]:
        from .primitives import ClassInfo

        bn = _import_binja()
        ptr_size = self.get_bitness() // 8
        is_big_endian = self.bv.endianness == bn.Endianness.BigEndian

        for name, sym_list in self.bv.symbols.items():
            is_gcc = name.startswith("_ZTV")
            is_msvc = not is_gcc and (
                "vftable" in name.lower()
                or (name.startswith("??_7") and name.endswith("@@6B@"))
            )
            if not (is_gcc or is_msvc):
                continue

            for sym in sym_list:
                class_name = self._bn_demangle(name, is_gcc)
                if not class_name:
                    continue

                vtable_addr = sym.address
                entries = self._bn_read_vtable(
                    vtable_addr, ptr_size, is_big_endian, is_gcc
                )

                if is_gcc:
                    zti_name = "_ZTI" + name[4:]
                    base_classes, has_multi, has_virtual = self._bn_parse_gcc_rtti(
                        zti_name, ptr_size, is_big_endian
                    )
                else:
                    base_classes, has_multi, has_virtual = [], False, False

                yield ClassInfo(
                    name=class_name,
                    vtable_addr=vtable_addr,
                    vtable=entries,
                    base_classes=base_classes,
                    has_multiple_inheritance=has_multi,
                    has_virtual_inheritance=has_virtual,
                )

    def _bn_read_ptr(self, addr: int, ptr_size: int, is_big_endian: bool) -> int | None:
        import struct

        raw = self.bv.read(addr, ptr_size)
        if not raw or len(raw) < ptr_size:
            return None
        endian = ">" if is_big_endian else "<"
        fmt = f"{endian}{'Q' if ptr_size == 8 else 'I'}"
        return struct.unpack(fmt, raw)[0]

    def _bn_is_exec(self, addr_val: int) -> bool:
        if not addr_val:
            return False
        seg = self.bv.get_segment_at(addr_val)
        return seg is not None and seg.executable

    def _bn_is_pure_virtual(self, addr_val: int) -> bool:
        syms = self.bv.get_symbols_at(addr_val)
        for sym in syms:
            if any(
                kw in sym.name for kw in ("__cxa_pure_virtual", "_purecall", "purevirt")
            ):
                return True
        return False

    def _bn_demangle(self, mangled: str, is_gcc: bool) -> str | None:
        bn = _import_binja()
        try:
            if is_gcc:
                _type, parts = bn.demangle_gnu3(self.bv.arch, mangled, simplify=True)
                if parts:
                    full = "::".join(parts) if isinstance(parts, list) else str(parts)
                    if "vtable for " in full:
                        return full.split("vtable for ", 1)[1].strip()
                    # parts may already be [class_name] without the "vtable for" prefix
                    return full
            else:
                _type, parts = bn.demangle_ms(self.bv.arch, mangled, simplify=True)
                if parts:
                    full = "::".join(parts) if isinstance(parts, list) else str(parts)
                    if "::`vftable'" in full:
                        name = full.split("::`vftable'")[0].strip()
                        if name.startswith("const "):
                            name = name[6:]
                        return name
        except Exception:
            pass
        if is_gcc and mangled.startswith("_ZTV"):
            from .rtti_util import itanium_name

            return itanium_name(mangled[4:])
        return None

    def _bn_read_vtable(
        self, vtable_addr: int, ptr_size: int, is_big_endian: bool, is_gcc: bool
    ) -> list:
        from .primitives import VTableEntry

        start_slot = 0
        if is_gcc:
            for i in range(4):
                val = self._bn_read_ptr(
                    vtable_addr + i * ptr_size, ptr_size, is_big_endian
                )
                if val is not None and self._bn_is_exec(val):
                    start_slot = i
                    break
            else:
                start_slot = 2

        # Cap slots using BN's data-variable width to avoid over-reading into the VTT.
        try:
            dv = self.bv.get_data_var_at(vtable_addr)
            max_slots = (
                (dv.type.width // ptr_size) if dv and dv.type and dv.type.width else 512
            )
        except Exception:
            max_slots = 512

        entries: list = []
        slot = 0
        addr = vtable_addr + start_slot * ptr_size
        consecutive_bad = 0

        while consecutive_bad < 3 and slot < max_slots:
            val = self._bn_read_ptr(addr, ptr_size, is_big_endian)
            if val is None:
                break
            is_pure = self._bn_is_pure_virtual(val)
            if not is_pure and not self._bn_is_exec(val):
                consecutive_bad += 1
                addr += ptr_size
                slot += 1
                continue
            consecutive_bad = 0
            entries.append(
                VTableEntry(
                    slot=slot,
                    byte_offset=(start_slot + slot) * ptr_size,
                    func_addr=None if is_pure else val,
                )
            )
            slot += 1
            addr += ptr_size

        return entries

    def _bn_resolve_zti(self, zti_ptr: int) -> str | None:
        syms = self.bv.get_symbols_at(zti_ptr)
        for sym in syms:
            if sym.name.startswith("_ZTI"):
                return self._bn_demangle("_ZTV" + sym.name[4:], is_gcc=True)
        return None

    def _bn_parse_gcc_rtti(
        self, zti_name: str, ptr_size: int, is_big_endian: bool
    ) -> tuple[list[str], bool, bool]:
        import struct

        zti_syms = self.bv.symbols.get(zti_name, [])
        if not zti_syms:
            return [], False, False

        ti_addr = zti_syms[0].address
        vptr_val = self._bn_read_ptr(ti_addr, ptr_size, is_big_endian)
        if vptr_val is None:
            return [], False, False

        is_si = is_vmi = False
        for sym in self.bv.get_symbols_at(vptr_val):
            if "vmi_class_type_info" in sym.name:
                is_vmi = True
            elif "si_class_type_info" in sym.name:
                is_si = True

        if not is_si and not is_vmi:
            return [], False, False

        if is_si:
            base_ptr = self._bn_read_ptr(
                ti_addr + 2 * ptr_size, ptr_size, is_big_endian
            )
            if not base_ptr:
                return [], False, False
            base = self._bn_resolve_zti(base_ptr)
            return ([base] if base else []), False, False

        endian = ">" if is_big_endian else "<"
        flags_off = ti_addr + 2 * ptr_size
        raw4 = self.bv.read(flags_off, 4)
        raw4b = self.bv.read(flags_off + 4, 4)
        if not raw4 or not raw4b:
            return [], False, False

        flags = struct.unpack(f"{endian}I", raw4)[0]
        base_count = struct.unpack(f"{endian}I", raw4b)[0]
        if base_count > 64:
            return [], False, False

        has_virtual = bool(flags & 1)
        base_names: list[str] = []
        pair_start = flags_off + 8
        pair_stride = ptr_size + 8

        for i in range(base_count):
            base_ptr = self._bn_read_ptr(
                pair_start + i * pair_stride, ptr_size, is_big_endian
            )
            if not base_ptr:
                continue
            base = self._bn_resolve_zti(base_ptr)
            if base:
                base_names.append(base)

        return base_names, len(base_names) > 1, has_virtual

    @override
    def get_instruction_comment(self, instr_addr: int) -> str | None:
        funcs = self.bv.get_functions_containing(instr_addr)
        if not funcs:
            return None

        comment = funcs[0].get_comment_at(instr_addr)
        if comment:
            return comment
        return None
