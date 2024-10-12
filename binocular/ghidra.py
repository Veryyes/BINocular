from __future__ import annotations
from collections.abc import Iterable
from collections import OrderedDict
from typing import Any, Optional, Tuple, List, IO
import pkgutil
import os
import tempfile
import zipfile
from urllib.request import urlopen
from functools import lru_cache
import logging
import hashlib
import json
import shutil

import pyhidra
from pyhidra.launcher import PyhidraLauncher, HeadlessPyhidraLauncher
from pyhidra.core import _setup_project, _analyze_program
import requests
import jpype
import coloredlogs
from git import Repo
import git

from .disassembler import Disassembler
from .primitives import Section, Instruction, IR, Argument, Branch, Reference, Variable
from .consts import Endian, IL, BranchType, RefType
from .utils import run_proc

logger = logging.getLogger(__name__)
coloredlogs.install(
    fmt="%(asctime)s %(name)s[%(process)d] %(levelname)s %(message)s")


class Ghidra(Disassembler):
    _DONT_SHUTDOWN_JVM = False

    GIT_REPO = "https://github.com/NationalSecurityAgency/ghidra.git"
    GITHUB_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases"

    @staticmethod
    def DEFAULT_INSTALL():
        '''Default Install Location for Ghidra (Within Python Package Installation)'''
        return os.path.join(os.path.dirname(pkgutil.get_loader('binocular').path), 'data', 'ghidra')

    @staticmethod
    def DEFAULT_PROJECT_PATH():
        '''Default Ghidra Project Path (Within Python Package Installation)'''
        return os.path.join(os.path.dirname(pkgutil.get_loader('binocular').path), 'data', 'ghidra_proj')

    @classmethod
    def list_versions(cls):
        r = requests.get(cls.GITHUB_API)
        if r.status_code != 200:
            raise Exception(f"Cannot reach {cls.GITHUB_API}")

        release_data = json.loads(r.text)
        versions = list()
        for release in release_data:
            ver = release['name'].rsplit(" ", 1)[1]
            versions.append(ver.strip())

        return versions

    @classmethod
    def _install_prebuilt(cls, version, install_dir):
        # Ask Github API for Ghidra Release versions and the
        # prebuilt download link
        r = requests.get(Ghidra.GITHUB_API)
        if r.status_code != 200:
            logger.critical(f"Cannot reach {Ghidra.GITHUB_API}")
            raise Exception(f"Cannot reach {Ghidra.GITHUB_API}")

        release_data = json.loads(r.text)
        links = OrderedDict()
        for release in release_data:
            ver = release['name'].rsplit(" ", 1)[1].strip()
            dl_link = release['assets'][0]['browser_download_url']
            links[ver] = dl_link

        if version is None:
            # Version not specified. getting latest
            version = next(iter(links.keys()))
        elif version not in links:
            logger.critical(f"Ghidra version {version} not found")
            raise Exception(f"Ghidra version {version} not found")

        dl_link = links[version]

        logger.info(f"Installing Ghidra {version} to {install_dir}")
        logger.info(f"Downloading {dl_link}...")
        with tempfile.TemporaryFile() as fp:
            fp.write(urlopen(dl_link).read())
            fp.seek(0)
            logger.info("Extracting Ghidra")
            with zipfile.ZipFile(fp, 'r') as zf:
                zf.extractall(install_dir)

        return os.path.join(install_dir, os.listdir(install_dir)[0])

    @classmethod
    def _build(cls, version, install_dir):
        if version is None:
            raise ValueError("No commit version supplied")

        logger.info(f"Building Ghidra @ commit {version}")

        # dependency check
        if shutil.which('java') is None:
            logger.critical(
                "Can't find java. Is JDK 21 installed? Download here: https://adoptium.net/temurin/releases/")
            exit(1)

        if shutil.which('gradle') is None:
            logger.critical(
                "Can't find gradle. Gradle 8.5+ required. Download here: https://gradle.org/releases/")
            exit(1)

        logger.info(f"Cloning Ghidra {version} to: {install_dir}")
        try:
            repo = Repo.clone_from(Ghidra.GIT_REPO, install_dir)
        except git.GitCommandError:
            logger.info("Ghidra Already Cloned")
            repo = Repo(install_dir)

        repo.git.checkout(version)

        cmds = [
            ["gradle", "-I", "gradle/support/fetchDependencies.gradle", "init"],
            ["gradle", "buildGhidra"]
        ]

        no_init_gradle_commit = repo.commit("30628db2d09d7b4ce46368b7522dc315e7b245c5")
        target_commit = repo.commit(version)

        common_ancestor = repo.merge_base(no_init_gradle_commit, target_commit)
        if target_commit in common_ancestor:
            # do nothing
            pass
        elif no_init_gradle_commit in common_ancestor:
            # remove init in gradle command
            del cmds[0][-1]
        else:
            raise Exception("Is {version} a valid commit hash?")

        for cmd in cmds:
            logger.info(f"$ {' '.join(cmd)}")
            out, err = run_proc(cmd=cmd, timeout=None, cwd=install_dir)
            if len(out) > 0:
                logger.info(f"[STDOUT] {out}")
            if len(err) > 0:
                logger.info(f"[STDERR] {err}")

        dist = os.path.join(install_dir, 'build', 'dist')
        zip_file = os.path.join(dist, os.listdir(dist)[0])
        with open(zip_file, 'rb') as f:
            with zipfile.ZipFile(f, 'r') as zf:
                zf.extractall(dist)

        return os.path.join(dist, "_".join(os.path.basename(zip_file).split('_')[:3]))

    @classmethod
    def install(cls, version: str = None, install_dir=None, build=False) -> str:
        '''
        Installs the disassembler to a user specified directory or within the python module if none is specified
        :param version: Release Version Number or Commit Hash
        :param install_dir: the directory to install Ghidra to
        :param build: True if version is a Commit Hash.
        '''
        if install_dir is None:
            install_dir = Ghidra.DEFAULT_INSTALL()

        os.makedirs(install_dir, exist_ok=True)

        if build:
            ghidra_home = Ghidra._build(version, install_dir)
        else:
            ghidra_home = Ghidra._install_prebuilt(version, install_dir)

        logger.info("Ghidra Install Completed")
        assert os.path.exists(ghidra_home)

        # Permission to execute stuff in Ghidra Home
        os.chmod(os.path.join(ghidra_home, "support", "launch.sh"), 0o775)
        for root, _, files in os.walk(ghidra_home):
            for fname in files:
                fpath = os.path.join(root, fname)
                os.chmod(fpath, 0o775)

        try:
            launcher = pyhidra.HeadlessPyhidraLauncher(install_dir=ghidra_home)
            launcher.start()
        except ValueError:
            logger.warn(
                f"Unable to install Pyhidra Plugin. Minimum Ghidra version required is 10.3.\nTL;DR Ghidra {version} is installed, but won't be useable for Binocular")

        return ghidra_home

    @classmethod
    def is_installed(cls, install_dir=None) -> bool:
        '''Returns Boolean on whether or not the dissassembler is installed'''
        os.makedirs(Ghidra.DEFAULT_INSTALL(), exist_ok=True)

        if install_dir is None:
            install_dir = Ghidra.DEFAULT_INSTALL()

        if len(os.listdir(install_dir)) == 0:
            return False

        release_install = os.path.join(install_dir, os.listdir(install_dir)[0])
        release_install = os.path.join(release_install, "support", "launch.sh")

        build_install = os.path.join(install_dir, 'build', 'dist')
                
        return os.path.exists(release_install) or os.path.exists(build_install)

    def __init__(self, verbose=True, project_path: str = None, home=None, save_on_close=False, jvm_args: Iterable[str] = None):
        super().__init__(verbose=verbose)

        self.project = None
        self.program = None
        self.flat_api = None
        self.decomp = None
        self.jvm_args = jvm_args
        if self.jvm_args is None:
            self.jvm_args = list()

        if project_path is None:
            project_path = Ghidra.DEFAULT_PROJECT_PATH()
        self.base_project_path = project_path

        if home is None:
            self.ghidra_home = os.path.join(
                Ghidra.DEFAULT_INSTALL(), os.listdir(Ghidra.DEFAULT_INSTALL())[0])
        else:
            self.ghidra_home = home

        self.save_on_close = save_on_close
        self.decomp_timeout = 60

    def open(self):
        if not PyhidraLauncher.has_launched():
            launcher = HeadlessPyhidraLauncher(
                install_dir=self.ghidra_home, verbose=False)
            launcher.add_vmargs(*self.jvm_args)
            launcher.start()
        return self

    def close(self):
        from ghidra.app.script import GhidraScriptUtil
        GhidraScriptUtil.releaseBundleHostReference()

        if self.decomp is not None:
            self.decomp.closeProgram()

        if self.project is not None:
            if self.save_on_close:
                self.project.save(self.program)
            self.project.close()

        if jpype.isJVMStarted() and not self.__class__._DONT_SHUTDOWN_JVM:
            jpype.shutdownJVM()

    def clear(self):
        from ghidra.app.script import GhidraScriptUtil
        super().clear()
        GhidraScriptUtil.releaseBundleHostReference()
        if self.decomp is not None:
            self.decomp.closeProgram()
        if self.save_on_close:
            self.project.save(self.program)

        self.project.close()
        self.project = None
        self.program = None
        self.flat_api = None

    def get_sections(self) -> Iterable[Section]:
        '''
        Returns a list of the sections within the binary.
        Currently only supports sections within an ELF file.
        '''
        sections = list()

        blocks = self.program.getMemory().getBlocks()
        for block in blocks:
            sections.append(Section(
                name=block.getName(),
                type=str(block.getType()),
                start=block.getStart().getOffset(),
                offset=0,
                size=block.getSize(),
                entsize=0,
                link=0,
                info=0,
                align=0,
                write=block.isWrite(),
                alloc=block.isRead(),
                execute=block.isExecute()
            ))

        return sections

    def _mk_addr(self, offset: int):
        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    def analyze(self, path) -> bool:
        '''
        Loads the binary specified by `path` into the disassembler.
        Implement all diaassembler specific setup and trigger analysis here.
        :returns: True on success, false otherwise
        '''
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra.program.model.block import BasicBlockModel

        with open(path, 'rb') as f:
            project_path = os.path.join(
                self.base_project_path, hashlib.md5(f.read()).hexdigest())

        self.project_location = os.path.dirname(project_path)
        self.project_name = os.path.basename(project_path)

        import java
        try:
            self.project, self.program = _setup_project(
                path,
                self.project_location,
                self.project_name,
                None,
                None
            )
            GhidraScriptUtil.acquireBundleHostReference()

            self.flat_api = FlatProgramAPI(self.program)
            _analyze_program(self.flat_api, self.program)

            # Create refs to all the managers that ghidra has lol
            self.base_addr = self.program.getImageBase()
            self.fm = self.program.getFunctionManager()
            self.st = self.program.getSymbolTable()
            self.ref_m = self.program.getReferenceManager()
            self.lang_description = self.program.getLanguage().getLanguageDescription()
            self.bb_model = BasicBlockModel(self.program)
            self.listing = self.program.getListing()
            self.monitor = ConsoleTaskMonitor()
            self.decomp = DecompInterface()
            self.decomp.setOptions(DecompileOptions())
            self.decomp.openProgram(self.program)
        except java.lang.OutOfMemoryError as ex:
            logger.critical(ex.stacktrace())
            return False, "java.lang.OutOfMemoryError"

        return True, None

    def get_binary_name(self) -> str:
        '''Returns the name of the binary loaded'''
        return self.program.getName()

    def get_entry_point(self) -> int:
        '''Returns the address of the entry point to the function'''
        from ghidra.program.model.symbol import SymbolType

        for ep_addr in self.st.getExternalEntryPointIterator():
            sym = self.flat_api.getSymbolAt(ep_addr)
            if sym.getSymbolType().equals(SymbolType.FUNCTION):
                entry = self.fm.getFunctionAt(ep_addr)
                if entry.callingConventionName == 'processEntry':
                    return ep_addr.getOffset()

        return None

    def get_architecture(self) -> str:
        '''
        Returns the architecture of the binary.
        For best results use either archinfo, qemu, or compilation triplet naming conventions.
        https://github.com/angr/archinfo
        '''
        return str(self.lang_description.getProcessor())

    def get_endianness(self) -> Endian:
        '''Returns an Enum representing the Endianness'''
        endian = str(self.lang_description.getEndian())
        if endian == 'little':
            return Endian.LITTLE
        elif endian == 'big':
            return Endian.BIG
        return Endian.OTHER

    def get_bitness(self) -> int:
        '''Returns the word size of the architecture (e.g., 16, 32, 64)'''
        return self.lang_description.getSize()

    def get_base_address(self) -> int:
        '''Returns the base address the binary is based at'''
        return self.program.getImageBase().getOffset()

    def get_strings(self, binary_io: IO, file_size: int) -> Iterable[str]:
        '''Returns the list of defined strings in the binary'''
        from ghidra.program.util import DefinedDataIterator

        return [s.value for s in DefinedDataIterator.definedStrings(self.program)]

    def get_dynamic_libs(self) -> Iterable[str]:
        '''Returns the list of names of the dynamic libraries used in this binary'''
        em = self.program.getExternalManager()
        dyn_libs = list(em.getExternalLibraryNames())
        if "<EXTERNAL>" in dyn_libs:
            dyn_libs.pop(dyn_libs.index("<EXTERNAL>"))

        return dyn_libs

    def get_func_iterator(self) -> Iterable["ghidra.program.database.function.FunctionDB"]:
        '''
        Returns an iterable of `Any` data type (e.g., address, interal func obj, dict of data) 
        needed to construct a `Function` object for all functions in the binary.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        for f in self.fm.getFunctions(True):
            yield f

    def get_func_addr(self, func_ctxt: Any) -> int:
        '''Returns the address of the function corresponding to the function information returned from `get_func_iterator()`'''
        return func_ctxt.getEntryPoint().getOffset()

    def get_func_name(self, addr: int, func_ctxt: Any) -> str:
        '''Returns the name of the function corresponding to the function information returned from `get_func_iterator()`'''
        return func_ctxt.getName()

    @lru_cache
    def _decompile(self, func_ctxt: Any):
        '''Return DecompileResult object. lru_cache'd because it's a little expensive'''
        res = self.decomp.decompileFunction(
            func_ctxt, self.decomp_timeout, self.monitor)
        if not res.decompileCompleted():
            logger.warn(
                f"[{self.name()}] Unable to Decompile {func_ctxt.getName()}() {res.getErrorMessage()}")

        return res

    def get_func_args(self, addr: int, func_ctxt: Any) -> List[Argument]:
        '''Returns the arguments in the function corresponding to the function information returned from `get_func_iterator()`'''
        decomp_res = self._decompile(func_ctxt)
        high_func = decomp_res.getHighFunction()
        if high_func is None:
            return list()

        proto = high_func.getFunctionPrototype()

        args = [
            Argument(
                data_type=str(proto.getParam(i).getDataType()),
                var_name=str(proto.getParam(i).getName())
            ) for i in range(proto.getNumParams())
        ]

        if func_ctxt.hasVarArgs():
            args.append(Argument(data_type=None, var_name=None, var_args=True))

        return args

    def get_func_return_type(self, addr: int, func_ctxt: Any) -> int:
        '''Returns the return type of the function corresponding to the function information returned from `get_func_iterator()`'''
        decomp_res = self._decompile(func_ctxt)
        high_func = decomp_res.getHighFunction()
        if high_func is None:
            return ""
        proto = high_func.getFunctionPrototype()

        return str(proto.getReturnType())

    def get_func_stack_frame_size(self, addr: int, func_ctxt: Any) -> int:
        '''Returns the size of the stack frame in the function corresponding to the function information returned from `get_func_iterator()`'''
        sf = func_ctxt.getStackFrame()
        return sf.getFrameSize()

    def get_func_vars(self, addr: int, func_ctxt: Any) -> Iterable[Variable]:
        '''Return variables within the function corresponding to the function information returned from `get_func_iterator()`'''
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

    def is_func_thunk(self, addr: int, func_ctxt: Any) -> bool:
        '''Returns True if the function corresponding to the function information returned from `get_func_iterator()` is a thunk'''
        return func_ctxt.isThunk()

    def get_func_decomp(self, addr: int, func_ctxt: Any) -> Optional[str]:
        '''Returns the decomplication of the function corresponding to the function information returned from `get_func_iterator()`'''
        decomp_res = self._decompile(func_ctxt)
        dfunc = decomp_res.getDecompiledFunction()
        if dfunc is None:
            return None

        return dfunc.getC()

    def get_func_callers(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        refs = self.ref_m.getReferencesTo(self._mk_addr(addr))
        for ref in refs:
            if ref.getReferenceType().isCall():
                call_addr = ref.getFromAddress()
                caller = self.fm.getFunctionContaining(call_addr)
                if caller is not None:
                    yield caller.getEntryPoint().getOffset()

    def get_func_callees(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        for addr in func_ctxt.getBody().getAddresses(True):
            refs = self.ref_m.getReferencesFrom(addr)
            for ref in refs:
                if ref.getReferenceType().isCall():
                    yield ref.getToAddress().getOffset()

    def _parse_ref_type(self, type):
        if type.isCall():
            return RefType.CALL
        if type.isJump():
            return RefType.JUMP
        if type.isRead():
            return RefType.READ
        if type.isWrite():
            return RefType.WRITE

        return RefType.UNKNOWN

    def get_func_xrefs(self, addr: int, func_ctxt: Any) -> Iterable[Reference]:
        for addr in func_ctxt.getBody().getAddresses(True):
            from_refs = self.ref_m.getReferencesFrom(addr)
            for ref in from_refs:
                ref_type = ref.getReferenceType()
                yield Reference(
                    from_=ref.getFromAddress().getOffset(),
                    to=ref.getToAddress().getOffset(),
                    type=self._parse_ref_type(ref_type)
                )

            to_refs = self.ref_m.getReferencesTo(addr)
            for ref in to_refs:
                ref_type = ref.getReferenceType()
                yield Reference(
                    from_=ref.getFromAddress().getOffset(),
                    to=ref.getToAddress().getOffset(),
                    type=self._parse_ref_type(ref_type)
                )

    def get_func_bb_iterator(self, addr: int, func_ctxt: Any) -> Iterable[Any]:
        '''
        Returns an iterator of `Any` data type (e.g., address, implementation specific basic block information, dict of data)
        needed to construct a `BasicBlock` object for all basic blocks in the function based on function information returned from `get_func_iterator()`.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        blocks = self.bb_model.getCodeBlocksContaining(
            func_ctxt.getBody(), self.monitor)
        history = set()

        while (blocks.hasNext()):
            bb = blocks.next()
            bb_addr = bb.getFirstStartAddress().getOffset()

            if bb_addr in history:
                continue

            history.add(bb_addr)
            yield bb

    def get_bb_addr(self, bb_ctxt: Any, func_ctxt: Any) -> int:
        '''
        Returns the address of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        return bb_ctxt.getFirstStartAddress().getOffset()

    def get_next_bbs(self, bb_addr: int, bb_ctxt: Any, func_addr: int, func_ctxt: Any) -> Iterable[Branch]:
        '''
        Returns the Branching information of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        dest_refs = bb_ctxt.getDestinations(self.monitor)
        while (dest_refs.hasNext()):
            dest = dest_refs.next()
            if not self.fm.getFunctionAt(dest.getDestinationAddress()):
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

    def get_bb_instructions(self, bb_addr: int, bb_ctxt: Any, func_ctxt: Any) -> List[Tuple(bytes, str)]:
        '''
        Returns a iterable of tuples of raw instruction bytes and corresponding mnemonic from the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        instr = list()

        curr_instr = self.listing.getInstructionAt(
            bb_ctxt.getFirstStartAddress())
        while (curr_instr is not None and bb_ctxt.contains(curr_instr.getAddress())):
            instr.append((bytes(curr_instr.getBytes()),
                         curr_instr.getMnemonicString()))
            curr_instr = curr_instr.getNext()

        return instr

    def get_ir_from_instruction(self, instr_addr: int, instr: Instruction) -> Optional[IR]:
        '''
        Returns the Intermediate Representation data based on the instruction given
        '''
        curr_instr = self.listing.getInstructionAt(self._mk_addr(instr_addr))
        pcodes = [str(p) for p in curr_instr.getPcode()]
        return IR(lang_name=IL.PCODE, data=";".join([p for p in pcodes]))

    def get_instruction_comment(self, instr_addr: int) -> Optional[str]:
        '''Return comments at the instruction'''
        from ghidra.program.model.listing import CodeUnit
        curr_instr = self.listing.getInstructionAt(self._mk_addr(instr_addr))
        comments = list()
        comments.append(curr_instr.getComment(CodeUnit.PLATE_COMMENT))
        comments.append(curr_instr.getComment(CodeUnit.PRE_COMMENT))
        comments.append(curr_instr.getComment(CodeUnit.EOL_COMMENT))
        comments.append(curr_instr.getComment(CodeUnit.POST_COMMENT))

        return "\n".join([c for c in comments if c is not None])
