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
from ..primitives import IR, Argument, Branch, Instruction, Reference, Variable

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
