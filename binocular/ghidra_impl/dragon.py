from __future__ import annotations

import logging
import os
import typing
import functools
import pathlib
import typing_extensions

# https://github.com/NationalSecurityAgency/ghidra/pull/9030
import pyghidra  # type: ignore[import-untyped]

if typing.TYPE_CHECKING:
    import ghidra.framework.model
    import ghidra.program.flatapi
    import ghidra.program.model.symbol
    import ghidra.program.model.address
    import ghidra.program.model.listing
    import ghidra.program.model.block
    import ghidra.program.model.lang
    import ghidra.app.decompiler
    import ghidra.util.task

from .core import GhidraBase
from ..consts import IL, BranchType, Endian, RefType
from ..disassembler import Disassembler
from ..primitives import (
    IR,
    Argument,
    Branch,
    ClassInfo,
    Instruction,
    Reference,
    Variable,
    VTableEntry,
)
from ..rtti_util import itanium_name as _itanium_name

logger = logging.getLogger("BINocular")

DEFAULT_DECOMP_TIMEOUT_S = 60 * 10


class Ghidra(GhidraBase):
    def __init__(
        self,
        filepath: pathlib.Path | str,
        verbose: bool = True,
        project_path: str | None = None,
        home: str | None = None,
        decomp_timeout: int = DEFAULT_DECOMP_TIMEOUT_S,
    ):
        super().__init__(
            filepath=filepath, verbose=verbose, project_path=project_path, home=home
        )
        self.project_ctxt: ghidra.framework.model.Project | None = None
        self._program: ghidra.program.model.listing.Program | None = None
        self._consumer: typing.Any = None

        self._monitor: ghidra.util.task.ConsoleTaskMonitor | None = None
        self._decomp: ghidra.app.decompiler.DecompInterface | None = None
        self.decomp_timeout = decomp_timeout

        self.analysis_log: str = ""

    @classmethod
    def install(
        cls,
        version: str | None = None,
        install_dir: str | None = None,
        build: bool | None = False,
        local_install_file: str | None = None,
    ) -> str | None:
        # TODO change the commit hash to see if its before 12.0.0's commit
        if not build and version:
            major_ver, _ = version.split(".", 1)
            if int(major_ver) < 12:
                logger.error(
                    f"Cannot use {cls.__name__} with Ghidra Version < 12.0.0 because this class uses pyghidra. Use GhidraLegacy class instead"
                )
                return None
        return super().install(version, install_dir, build, local_install_file)

    def _mk_addr(self, offset: int, addr_space: int | None = None):
        factory = self.program.getAddressFactory()
        if addr_space is None:
            return factory.getDefaultAddressSpace().getAddress(offset)
        return factory.getAddressSpace(addr_space).getAddress(offset)

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        if self._program is None:
            raise Disassembler.NotOpenedError()
        return self._program

    @program.setter
    def program(self, prog: ghidra.program.model.listing.Program):
        if self._program is not None and (
            not self._program.isClosed() or self._consumer is not None
        ):
            raise ResourceWarning("Unclosed ghidra program. Call close()")
        self._program = prog

    @functools.cached_property
    def flat_api(self) -> ghidra.program.flatapi.FlatProgramAPI:
        import ghidra.program.flatapi

        return ghidra.program.flatapi.FlatProgramAPI(self.program)

    @functools.cached_property
    def bb_model(self) -> ghidra.program.model.block.BasicBlockModel:
        import ghidra.program.model.block

        return ghidra.program.model.block.BasicBlockModel(self.program)

    @property
    def decomp(self) -> ghidra.app.decompiler.DecompInterface:
        if self.opened:
            if self._decomp is None:
                import ghidra.app.decompiler

                self._decomp = ghidra.app.decompiler.DecompInterface()
            return self._decomp

        raise self.NotOpenedError

    @property
    def func_manager(self) -> ghidra.program.model.listing.FunctionManager:
        return self.program.getFunctionManager()

    @property
    def ref_manager(self) -> ghidra.program.model.symbol.ReferenceManager:
        return self.program.getReferenceManager()

    @property
    def lang_description(self) -> ghidra.program.model.lang.LanguageDescription:
        return self.program.getLanguage().getLanguageDescription()

    @property
    def listing(self) -> ghidra.program.model.listing.Listing:
        return self.program.getListing()

    @property
    def monitor(self) -> ghidra.util.task.ConsoleTaskMonitor:
        import ghidra.util.task

        if self._monitor is None:
            self._monitor = ghidra.util.task.ConsoleTaskMonitor()
        return self._monitor

    def open(self) -> typing_extensions.Self:
        super().open()
        if not pyghidra.started():
            pyghidra.start(install_dir=self.ghidra_home)

        if not os.path.exists(self.project_location):
            os.makedirs(self.project_location, exist_ok=True)

        self.project_ctxt = pyghidra.open_project(
            self.project_location, self.project_name, create=True
        )
        loader = (
            pyghidra.program_loader()
            .project(self.project_ctxt)
            .source(str(self.binary_filepath))
        )
        with loader.load() as load_results:
            load_results.save(pyghidra.task_monitor())

        self.program, self._consumer = pyghidra.consume_program(
            self.project_ctxt, f"/{self.bin_name}"
        )

        import ghidra.app.decompiler

        self.decomp.setOptions(ghidra.app.decompiler.DecompileOptions())
        self.decomp.openProgram(self.program)

        return self

    def close(self):
        self.decomp.closeProgram()

        if self.program is not None:
            self.program.release(self._consumer)
            self._consumer = None

        if self.project_ctxt is not None:
            self.project_ctxt.close()
        super().close()

    def analyze(self) -> None:
        super().analyze()
        self.analysis_log = pyghidra.analyze(self.program)

    def export_gzf(self, output_path: pathlib.Path | str) -> pathlib.Path:
        """Export the loaded program to a Ghidra Zip File (.gzf)."""
        from ghidra.app.util.exporter import GzfExporter  # type: ignore[import-untyped]
        from java.io import File as JFile  # type: ignore[import-untyped]

        output_path = pathlib.Path(output_path)
        if output_path.suffix != ".gzf":
            output_path = output_path.with_suffix(".gzf")

        exporter = GzfExporter()
        exporter.export(
            JFile(str(output_path.resolve())), self.program, None, self.monitor
        )
        return output_path

    def get_binary_name(self) -> str:
        """Returns the name of the binary loaded"""
        return self.program.getName()

    def get_entry_point(self) -> int:
        """Returns the address of the entry point to the function"""
        from ghidra.program.model.symbol import SymbolType

        symtab = self.program.getSymbolTable()
        for ep_addr in symtab.getExternalEntryPointIterator():
            sym = self.flat_api.getSymbolAt(ep_addr)
            if sym.getSymbolType().equals(SymbolType.FUNCTION):
                entry = self.func_manager.getFunctionAt(ep_addr)
                if entry.callingConventionName == "processEntry":
                    return ep_addr.getOffset()

        return -1

    def get_architecture(self) -> str:
        """
        Returns the architecture of the binary.
        For best results use either archinfo, qemu, or compilation triplet naming conventions.
        https://github.com/angr/archinfo
        """
        return str(self.lang_description.getProcessor())

    def get_endianness(self) -> Endian:
        """Returns an Enum representing the Endianness"""
        endian = str(self.lang_description.getEndian())
        if endian == "little":
            return Endian.LITTLE
        elif endian == "big":
            return Endian.BIG
        return Endian.OTHER

    def get_bitness(self) -> int:
        """Returns the word size of the architecture (e.g., 16, 32, 64)"""
        return self.lang_description.getSize()

    def get_base_address(self) -> int:
        """Returns the base address the binary is based at"""
        return self.program.getImageBase().getOffset()

    def get_strings(self) -> typing.Iterable[str]:
        """Returns the list of defined strings in the binary"""
        return [
            d.getValue()
            for d in self.listing.getDefinedData(True)
            if d.hasStringValue()
        ]

    def get_dynamic_libs(self) -> typing.Iterable[str]:
        """Returns the list of names of the dynamic libraries used in this binary"""
        em = self.program.getExternalManager()
        dyn_libs = list(em.getExternalLibraryNames())
        if "<EXTERNAL>" in dyn_libs:
            dyn_libs.pop(dyn_libs.index("<EXTERNAL>"))

        return dyn_libs

    @typing_extensions.override
    def is_stripped(self) -> bool:
        from ghidra.program.model.symbol import SourceType, SymbolType

        memory = self.program.getMemory()

        # ELF: .symtab is definitively absent when stripped — no fallback needed.
        # (Ghidra also creates IMPORTED symbols from ELF dynamic metadata like e_entry and
        # DT_INIT that would produce false negatives if the iterator ran on ELF binaries.)
        if "ELF" in self.program.getExecutableFormat():
            return memory.getBlock(".symtab") is None

        # PE: embedded CodeView debug sections (.debug$S / .debug$T) indicate not stripped
        if (
            memory.getBlock(".debug$S") is not None
            or memory.getBlock(".debug$T") is not None
        ):
            return False

        # MachO / PE fallback: any IMPORTED function symbol that is not an external import
        # or an import stub indicates the binary has its own symbol table.
        _STUB_BLOCKS = {"__TEXT.__stubs", "__TEXT.__stub_helper"}
        sym_table = self.program.getSymbolTable()
        for sym in sym_table.getSymbolIterator():
            if sym.getSymbolType() != SymbolType.FUNCTION:
                continue
            if sym.getSource() != SourceType.IMPORTED:
                continue
            if sym.isExternal():
                continue
            addr = sym.getAddress()
            block = memory.getBlock(addr)
            block_name = block.getName() if block is not None else ""
            if block_name in _STUB_BLOCKS:
                continue
            func = self.func_manager.getFunctionAt(addr)
            if func is not None and func.isThunk():
                continue
            return False

        return True

    @typing_extensions.override
    def has_debug_info(self) -> bool:
        memory = self.program.getMemory()
        for block in memory.getBlocks():
            name = block.getName()
            if (
                name.startswith(".debug")
                or name.startswith(".zdebug")
                or name.startswith("__debug")
            ):
                return True
        return False

    @typing_extensions.override
    def rename_function(self, addr: int, name: str) -> None:
        from ghidra.program.model.symbol import SourceType

        func = self.func_manager.getFunctionAt(self._mk_addr(addr))
        if func is None:
            return
        tx = self.program.startTransaction(f"rename {func.getName()} -> {name}")
        try:
            func.setName(name, SourceType.USER_DEFINED)
        finally:
            self.program.endTransaction(tx, True)

    @typing_extensions.override
    def get_func_iterator(
        self,
    ) -> typing.Iterable[ghidra.program.model.listing.Function]:
        """
        Returns an iterable of `Any` data type (e.g., address, interal func obj, dict of data)
        needed to construct a `Function` object for all functions in the binary.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        """
        for f in self.func_manager.getFunctions(True):
            yield f

    @typing_extensions.override
    def get_func_addr(self, func_ctxt: ghidra.program.model.listing.Function) -> int:
        """Returns the address of the function corresponding to the function information returned from `get_func_iterator()`"""
        return func_ctxt.getEntryPoint().getOffset()

    @typing_extensions.override
    def get_func_name(
        self, addr: int, func_ctxt: ghidra.program.model.listing.Function
    ) -> str:
        """Returns the name of the function corresponding to the function information returned from `get_func_iterator()`"""
        return func_ctxt.getName()

    @functools.lru_cache
    def _decompile(
        self, func_ctxt: ghidra.program.model.listing.Function
    ) -> ghidra.app.decompiler.DecompileResults:
        """Return DecompileResult object. lru_cache'd because it's a little expensive"""
        res = self.decomp.decompileFunction(
            func_ctxt, self.decomp_timeout, self.monitor
        )
        if not res.decompileCompleted():
            logger.warning(
                f"[{self.name}] Unable to Decompile {func_ctxt.getName()}() {res.getErrorMessage()}"
            )

        return res

    @typing_extensions.override
    def get_func_args(
        self, addr: int, func_ctxt: ghidra.program.model.listing.Function
    ) -> typing.List[Argument]:
        """Returns the arguments in the function corresponding to the function information returned from `get_func_iterator()`"""
        decomp_res = self._decompile(func_ctxt)
        high_func = decomp_res.getHighFunction()
        if high_func is None:
            return list()

        proto = high_func.getFunctionPrototype()

        args = [
            Argument(
                data_type=str(proto.getParam(i).getDataType()),
                var_name=str(proto.getParam(i).getName()),
            )
            for i in range(proto.getNumParams())
        ]

        if func_ctxt.hasVarArgs():
            args.append(Argument(data_type=None, var_name=None, var_args=True))

        return args

    @typing_extensions.override
    def get_func_return_type(
        self, addr: int, func_ctxt: ghidra.program.model.listing.Function
    ) -> str:
        """Returns the return type of the function corresponding to the function information returned from `get_func_iterator()`"""
        decomp_res = self._decompile(func_ctxt)
        high_func = decomp_res.getHighFunction()
        if high_func is None:
            return ""
        proto = high_func.getFunctionPrototype()

        return str(proto.getReturnType())

    @typing_extensions.override
    def get_func_stack_frame_size(
        self, addr: int, func_ctxt: ghidra.program.model.listing.Function
    ) -> int:
        """Returns the size of the stack frame in the function corresponding to the function information returned from `get_func_iterator()`"""
        sf = func_ctxt.getStackFrame()
        return sf.getFrameSize()

    @typing_extensions.override
    def get_func_vars(
        self, addr: int, func_ctxt: ghidra.program.model.listing.Function
    ) -> typing.Iterable[Variable]:
        """Return variables within the function corresponding to the function information returned from `get_func_iterator()`"""
        vars = list()
        for var in func_ctxt.getLocalVariables():
            v = Variable(
                data_type=var.getDataType().getName(),
                name=var.getName(),
                is_register=var.isRegisterVariable(),
                is_stack=var.isStackVariable(),
            )
            if v.is_stack:
                v.stack_offset = var.getStackOffset()
            vars.append(v)
        return vars

    @typing_extensions.override
    def is_func_thunk(
        self, addr: int, func_ctxt: ghidra.program.model.listing.Function
    ) -> bool:
        """Returns True if the function corresponding to the function information returned from `get_func_iterator()` is a thunk"""
        return func_ctxt.isThunk()

    @typing_extensions.override
    def get_func_decomp(
        self, addr: int, func_ctxt: ghidra.program.model.listing.Function
    ) -> str | None:
        """Returns the decomplication of the function corresponding to the function information returned from `get_func_iterator()`"""
        decomp_res = self._decompile(func_ctxt)
        dfunc = decomp_res.getDecompiledFunction()
        if dfunc is None:
            return None

        return dfunc.getC()

    @typing_extensions.override
    def get_func_callers(
        self, addr: int, func_ctxt: ghidra.program.model.listing.Function
    ) -> typing.Iterable[int]:
        refs = self.ref_manager.getReferencesTo(self._mk_addr(addr))
        for ref in refs:
            if ref.getReferenceType().isCall():
                call_addr = ref.getFromAddress()
                caller = self.func_manager.getFunctionContaining(call_addr)
                if caller is not None:
                    yield caller.getEntryPoint().getOffset()

    @typing_extensions.override
    def get_func_callees(
        self, addr: int, func_ctxt: ghidra.program.model.listing.Function
    ) -> typing.Iterable[int]:
        for addr in func_ctxt.getBody().getAddresses(True):
            refs = self.ref_manager.getReferencesFrom(addr)
            for ref in refs:
                if ref.getReferenceType().isCall():
                    yield ref.getToAddress().getOffset()

    def _parse_ref_type(self, type: ghidra.program.model.symbol.RefType) -> RefType:
        if type.isCall():
            return RefType.CALL
        if type.isJump():
            return RefType.JUMP
        if type.isRead():
            return RefType.READ
        if type.isWrite():
            return RefType.WRITE

        return RefType.UNKNOWN

    @typing_extensions.override
    def get_func_xrefs(
        self, addr: int, func_ctxt: ghidra.program.model.listing.Function
    ) -> typing.Iterable[Reference]:
        import ghidra.program.model.symbol

        for addr in func_ctxt.getBody().getAddresses(True):
            from_refs = self.ref_manager.getReferencesFrom(addr)
            for ref in from_refs:
                # mypy unable to infer the item type in a java iterator; manually casting type

                ref_type = ref.getReferenceType()
                yield Reference(
                    from_=ref.getFromAddress().getOffset(),
                    to=ref.getToAddress().getOffset(),
                    type=self._parse_ref_type(ref_type),
                )

            # NOTE: VSCode's python plugin cant seem to infer the type here, but mypy can. Manually typing
            to_refs: ghidra.program.model.symbol.ReferenceIterator = (
                self.ref_manager.getReferencesTo(addr)
            )
            for ref in to_refs:
                # NOTE same deal as the note above
                ref = typing.cast(ghidra.program.model.symbol.Reference, ref)
                ref_type = ref.getReferenceType()
                yield Reference(
                    from_=ref.getFromAddress().getOffset(),
                    to=ref.getToAddress().getOffset(),
                    type=self._parse_ref_type(ref_type),
                )

    @typing_extensions.override
    def get_func_bb_iterator(
        self, addr: int, func_ctxt: ghidra.program.model.listing.Function
    ) -> typing.Iterable[ghidra.program.model.block.CodeBlock]:
        """
        Returns an iterator of `Any` data type (e.g., address, implementation specific basic block information, dict of data)
        needed to construct a `BasicBlock` object for all basic blocks in the function based on function information returned from `get_func_iterator()`.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        """
        import ghidra.program.model.block

        blocks = self.bb_model.getCodeBlocksContaining(
            func_ctxt.getBody(), self.monitor
        )
        history = set()

        while blocks.hasNext():
            # NOTE: VSCode's python plugin can't seem to figure out the typing for jpype hasNext() and next() functions
            # mypy is cool with it though
            bb = typing.cast(ghidra.program.model.block.CodeBlock, blocks.next())
            bb_addr = bb.getFirstStartAddress().getOffset()

            if bb_addr in history:
                continue

            history.add(bb_addr)
            yield bb

    @typing_extensions.override
    def get_bb_addr(
        self,
        bb_ctxt: ghidra.program.model.block.CodeBlock,
        func_ctxt: ghidra.program.model.listing.Function,
    ) -> int:
        """
        Returns the address of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        return bb_ctxt.getFirstStartAddress().getOffset()

    @typing_extensions.override
    def get_next_bbs(
        self,
        bb_addr: int,
        bb_ctxt: ghidra.program.model.block.CodeBlock,
        func_addr: int,
        func_ctxt: ghidra.program.model.listing.Function,
    ) -> typing.Iterable[Branch]:
        """
        Returns the Branching information of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        dest_refs = bb_ctxt.getDestinations(self.monitor)
        while dest_refs.hasNext():
            dest = dest_refs.next()
            if not self.func_manager.getFunctionAt(dest.getDestinationAddress()):
                dest_addr = dest.getDestinationAddress().getOffset()
                flow_type = dest.getFlowType()
                if flow_type.hasFallthrough():
                    yield Branch(type=BranchType.FalseBranch, target=dest_addr)
                elif flow_type.isConditional():
                    yield Branch(type=BranchType.TrueBranch, target=dest_addr)
                elif flow_type.isUnConditional():
                    yield Branch(type=BranchType.UnconditionalBranch, target=dest_addr)
                elif flow_type.isComputed():
                    yield Branch(type=BranchType.IndirectBranch, target=None)

    @typing_extensions.override
    def get_bb_instructions(
        self,
        bb_addr: int,
        bb_ctxt: ghidra.program.model.block.CodeBlock,
        func_ctxt: ghidra.program.model.listing.Function,
    ) -> typing.List[typing.Tuple[bytes, str]]:
        """
        Returns a iterable of tuples of raw instruction bytes and corresponding mnemonic from the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        instr = list()

        curr_instr = self.listing.getInstructionAt(bb_ctxt.getFirstStartAddress())
        while curr_instr is not None and bb_ctxt.contains(curr_instr.getAddress()):
            instr.append((bytes(curr_instr.getBytes()), curr_instr.getMnemonicString()))
            curr_instr = curr_instr.getNext()

        return instr

    def get_ir_from_instruction(self, instr_addr: int, instr: Instruction) -> IR | None:
        """
        Returns the Intermediate Representation data based on the instruction given
        """
        curr_instr = self.listing.getInstructionAt(self._mk_addr(instr_addr))
        pcodes = [str(p) for p in curr_instr.getPcode()]
        return IR(lang_name=IL.PCODE, data=";".join([p for p in pcodes]))

    def get_instruction_comment(self, instr_addr: int) -> str | None:
        """Return comments at the instruction"""
        from ghidra.program.model.listing import CodeUnit

        curr_instr = self.listing.getInstructionAt(self._mk_addr(instr_addr))
        comments = list()
        comments.append(curr_instr.getComment(CodeUnit.PLATE_COMMENT))
        comments.append(curr_instr.getComment(CodeUnit.PRE_COMMENT))
        comments.append(curr_instr.getComment(CodeUnit.EOL_COMMENT))
        comments.append(curr_instr.getComment(CodeUnit.POST_COMMENT))

        return "\n".join([c for c in comments if c is not None])

    def _register_java_bundle(self, script: str, bundle_host):
        from generic.jar import ResourceFile  # type: ignore[import-untyped]
        from java.io import File, PrintWriter, StringWriter  # type: ignore[import-untyped]

        script_dir = os.path.abspath(os.path.dirname(script))
        bundle_file = ResourceFile(File(script_dir))
        bundle_host.enable(bundle_file)
        bundle = bundle_host.getGhidraBundle(bundle_file)
        bundle_host.activateAll([bundle], self.monitor, PrintWriter(StringWriter()))

    @typing_extensions.override
    def get_classes(self) -> typing.Iterable[ClassInfo]:
        ptr_size = self.get_bitness() // 8
        symtab = self.program.getSymbolTable()

        for sym in symtab.getSymbolIterator():
            name = str(sym.getName())
            is_gcc = name.startswith("_ZTV")
            is_msvc = not is_gcc and (
                "vftable" in name.lower()
                or (name.startswith("??_7") and name.endswith("@@6B@"))
            )
            if not (is_gcc or is_msvc):
                continue

            class_name = self._rtti_demangle(name)
            if not class_name:
                continue

            vtable_addr = sym.getAddress()
            entries = self._rtti_read_vtable(vtable_addr, ptr_size, is_gcc)

            if is_gcc:
                zti_name = "_ZTI" + name[4:]
                base_classes, has_multi, has_virtual = self._rtti_parse_gcc(
                    zti_name, ptr_size
                )
            else:
                base_classes, has_multi, has_virtual = [], False, False

            yield ClassInfo(
                name=class_name,
                vtable_addr=vtable_addr.getOffset(),
                vtable=entries,
                base_classes=base_classes,
                has_multiple_inheritance=has_multi,
                has_virtual_inheritance=has_virtual,
            )

    def _rtti_read_ptr(self, addr, ptr_size: int) -> int | None:
        """Read a native-width pointer from addr; returns unsigned value or None."""
        memory = self.program.getMemory()
        try:
            if ptr_size == 8:
                return int(memory.getLong(addr)) & 0xFFFFFFFFFFFFFFFF
            else:
                return int(memory.getInt(addr)) & 0xFFFFFFFF
        except Exception:
            return None

    def _rtti_is_exec(self, addr_val: int) -> bool:
        if not addr_val:
            return False
        try:
            block = self.program.getMemory().getBlock(self._mk_addr(addr_val))
            return block is not None and block.isExecute()
        except Exception:
            return False

    def _rtti_is_pure_virtual(self, addr_val: int) -> bool:
        try:
            for sym in self.program.getSymbolTable().getSymbols(
                self._mk_addr(addr_val)
            ):
                n = str(sym.getName())
                if "__cxa_pure_virtual" in n or "_purecall" in n or "purevirt" in n:
                    return True
        except Exception:
            pass
        return False

    def _rtti_demangle(self, mangled: str) -> str | None:
        """Return the demangled class name from a vtable symbol name."""
        try:
            from ghidra.app.util import DemanglerUtil

            result = DemanglerUtil.demangle(self.program, mangled)
            if result is not None:
                sig = str(result.getSignature(False))
                if "vtable for " in sig:
                    return sig.split("vtable for ", 1)[1].strip()
                if "::`vftable'" in sig:
                    name = sig.split("::`vftable'")[0].strip()
                    if name.startswith("const "):
                        name = name[6:]
                    return name
        except Exception:
            pass
        if mangled.startswith("_ZTV"):
            return _itanium_name(mangled[4:])
        return None

    def _rtti_read_vtable(self, vtable_addr, ptr_size: int, is_gcc: bool) -> list:
        # Find the first slot that points to executable code.
        start_slot = 0
        if is_gcc:
            for i in range(4):
                val = self._rtti_read_ptr(vtable_addr.add(i * ptr_size), ptr_size)
                if val is not None and self._rtti_is_exec(val):
                    start_slot = i
                    break
            else:
                start_slot = 2  # default: skip offset-to-top + typeinfo ptr

        # Use Ghidra's data-type length as a hard slot cap to avoid over-reading
        # into the VTT (Virtual Table Table) that follows in multiple-inheritance layouts.
        try:
            data = self.program.getListing().getDataAt(vtable_addr)
            max_slots = (data.getLength() // ptr_size) if data else 512
        except Exception:
            max_slots = 512

        entries: list = []
        slot = 0
        addr = vtable_addr.add(start_slot * ptr_size)
        consecutive_bad = 0

        while consecutive_bad < 3 and slot < max_slots:
            val = self._rtti_read_ptr(addr, ptr_size)
            if val is None:
                break
            is_pure = self._rtti_is_pure_virtual(val)
            if not is_pure and not self._rtti_is_exec(val):
                consecutive_bad += 1
                addr = addr.add(ptr_size)
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
            addr = addr.add(ptr_size)

        return entries

    def _rtti_resolve_zti(self, zti_ptr_val: int) -> str | None:
        """Given a pointer to a _ZTI structure, return the demangled class name."""
        try:
            addr = self._mk_addr(zti_ptr_val)
            for sym in self.program.getSymbolTable().getSymbols(addr):
                sname = str(sym.getName())
                if sname.startswith("_ZTI"):
                    return self._rtti_demangle("_ZTV" + sname[4:])
        except Exception:
            pass
        return None

    def _rtti_parse_gcc(
        self, zti_name: str, ptr_size: int
    ) -> tuple[list[str], bool, bool]:
        """
        Parse a GCC __class_type_info to extract base class names and flags.
        Returns (base_classes, has_multiple_inheritance, has_virtual_inheritance).

        Detection strategy (avoids resolving the vptr, which points into external
        libstdc++ symbols that Ghidra can't look up by address):

          - __class_type_info    (no bases): struct ends at slot 1; slot 2 read returns None.
          - __si_class_type_info (1 base):   slot 2 holds a pointer to the base _ZTI*.
          - __vmi_class_type_info (N bases): slot 2 holds flags(u32) || base_count(u32).

        A vmi flags value (0–7) is too small to collide with any valid _ZTI address.
        Uses memory.getInt/getLong (not getBytes) since JPype doesn't update Python
        bytearrays in-place when passed to Java byte[] parameters.
        """
        symtab = self.program.getSymbolTable()
        syms = list(symtab.getGlobalSymbols(zti_name))
        if not syms:
            return [], False, False

        ti_addr = syms[0].getAddress()
        memory = self.program.getMemory()

        slot2_addr = ti_addr.add(2 * ptr_size)
        slot2_val = self._rtti_read_ptr(slot2_addr, ptr_size)
        if slot2_val is None:
            return [], False, False  # __class_type_info: no bases

        # Si check: does slot 2 hold a valid _ZTI* address?
        base = self._rtti_resolve_zti(slot2_val)
        if base is not None:
            return [base], False, False

        # Vmi: slot 2 encodes flags(u32) + base_count(u32).
        # getInt reads in program endianness, so the first u32 is always flags.
        try:
            flags = int(memory.getInt(slot2_addr)) & 0xFFFFFFFF
            base_count = int(memory.getInt(slot2_addr.add(4))) & 0xFFFFFFFF
        except Exception:
            return [], False, False

        if base_count == 0 or base_count > 64 or flags > 3:
            return [], False, False

        has_virtual = False
        base_names: list[str] = []
        pair_start = slot2_addr.add(8)
        pair_stride = ptr_size + 8  # base_ti_ptr + offset_flags (8-byte long)

        for i in range(base_count):
            base_ptr = self._rtti_read_ptr(pair_start.add(i * pair_stride), ptr_size)
            if not base_ptr:
                continue
            # Bit 0 of the per-base offset_flags signals virtual inheritance for this base.
            off_flags_addr = pair_start.add(i * pair_stride + ptr_size)
            try:
                per_flags = int(memory.getLong(off_flags_addr)) & 0xFFFFFFFFFFFFFFFF
                if per_flags & 1:
                    has_virtual = True
            except Exception:
                pass
            base_name = self._rtti_resolve_zti(base_ptr)
            if base_name:
                base_names.append(base_name)

        return base_names, len(base_names) > 1, has_virtual

    def run_script(
        self, script: str, timeout: int, script_args: typing.List[str] | None = None
    ) -> str | None:
        if script_args is None:
            script_args = list()

        from ghidra.app.script import GhidraScriptUtil  # type: ignore[import-untyped]
        from java.io import PrintStream, ByteArrayOutputStream  # type: ignore[import-untyped]
        from java.lang import System  # type: ignore[import-untyped]

        GhidraScriptUtil.acquireBundleHostReference()
        try:
            if script.endswith(".java"):
                self._register_java_bundle(script, GhidraScriptUtil.getBundleHost())

            baos = ByteArrayOutputStream()
            original_out = System.out
            System.setOut(PrintStream(baos))
            try:
                controls_stdout, _ = pyghidra.ghidra_script(
                    script, self.project_ctxt, self.program, script_args, False, False
                )
            finally:
                System.out.flush()
                System.setOut(original_out)
        finally:
            GhidraScriptUtil.releaseBundleHostReference()

        return controls_stdout + str(baos.toString())
