
from __future__ import annotations
from collections.abc import Iterable
from collections import defaultdict, OrderedDict
from typing import Any, Optional, Tuple, List, IO
from pathlib import Path
import os
import shutil
import pkgutil
import binascii
import requests
import json
import logging
import tempfile
import lzma
import tarfile
from urllib.request import urlopen

from .disassembler import Disassembler
from .primitives import Section, Instruction, IR, Branch, Argument, Reference, RefType, Variable
from .consts import Endian, BranchType, IL
from .utils import run_proc

from git import Repo
import git
import rzpipe
import coloredlogs

logger = logging.getLogger(__name__)
coloredlogs.install(
    fmt="%(asctime)s %(name)s[%(process)d] %(levelname)s %(message)s")


class Rizin(Disassembler):

    GIT_REPO = "https://github.com/rizinorg/rizin.git"
    GITHUB_API = "https://api.github.com/repos/rizinorg/rizin/releases"

    @staticmethod
    def DEFAULT_INSTALL():
        return os.path.join(os.path.dirname(pkgutil.get_loader('binocular').path), 'data', 'rizin')

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
    def is_installed(cls, install_dir=None) -> bool:
        '''Returns Boolean on whether or not the dissassembler is installed'''
        if install_dir is not None:
            pre_built_loc = os.path.join(install_dir, "bin")
            build_loc = os.path.join(install_dir, "build", "binrz")
            return os.path.exists(pre_built_loc) or os.path.exists(build_loc)

        sys_install = shutil.which('rizin') is not None
        local_install_pre_built = os.path.exists(
            os.path.join(Rizin.DEFAULT_INSTALL(), "bin"))
        local_install_build = os.path.exists(os.path.join(
            Rizin.DEFAULT_INSTALL(), "build", "binrz", "rizin"))

        return sys_install or local_install_pre_built or local_install_build

    @classmethod
    def install(cls, version: str = None, install_dir=None, build=False) -> str:
        '''Installs the disassembler to a user specified directory or within the python module if none is specified'''
        logger.info("Installing Rizin")

        if install_dir is None:
            install_dir = Rizin.DEFAULT_INSTALL()

        os.makedirs(install_dir, exist_ok=True)

        if build:
            if version is None:
                raise ValueError("No commit version supplied")
                
            logger.info(f"Cloning Rizin to: {install_dir}")
            try:
                repo = Repo.clone_from(Rizin.GIT_REPO, install_dir)
            except git.GitCommandError:
                logger.warn("Rizin Already Cloned")
                repo = Repo(install_dir)

            repo.git.checkout(version)

            cmds = [
                ["meson", "setup", "build"],
                ["meson", "compile", "-C", "build"],
            ]

            for cmd in cmds:
                logger.info(f"$ {' '.join(cmd)}")
                out, err = run_proc(cmd=cmd, timeout=None, cwd=install_dir)
                if len(out) > 0:
                    logger.info(f"[STDOUT] {out}")
                if len(err) > 0:
                    logger.info(f"[STDERR] {err}")
        else:
            r = requests.get(cls.GITHUB_API)
            if r.status_code != 200:
                raise Exception(f"Cannot reach {cls.GITHUB_API}")

            release_data = json.loads(r.text)
            links = OrderedDict()
            for release in release_data:
                ver = release['name'].rsplit(" ", 1)[1]

                for asset in release['assets']:
                    # Only supporting linux x86 as of now
                    if 'static-x86_64' in asset['name']:
                        dl_link = asset['browser_download_url']
                        links[ver] = dl_link
                        break

            if version is None:
                version = next(iter(links.keys()))
            elif version not in links:
                logger.critical(f"Rizin version {version} not found")
                raise Exception(f"Rizin version {version} not found")

            dl_link = links[version]
            logger.info(f"Installing Rizin {version} to {install_dir}")
            logger.info(f"Downloading {dl_link}...")
            with tempfile.TemporaryFile() as fp:
                fp.write(urlopen(dl_link).read())
                fp.seek(0)
                with lzma.open(fp) as xz:
                    with tarfile.open(fileobj=xz) as tar:
                        tar.extractall(install_dir)

        logger.info("Rizin Install Completed")
        return install_dir

    def __init__(self, verbose=True, home: str = None) -> None:
        super().__init__(verbose=verbose)
        self.rizin_home = home
        self._pipe = None

        self._bin_info = None
        self._thunk_dict = dict()
        self._caller_cache = defaultdict(lambda: set())
        self._calls_cache = defaultdict(lambda: set())

    def close(self):
        '''Release/Free up any resources'''
        if self._pipe is not None:
            self._pipe.quit()

    def clear(self):
        super().clear()
        self._pipe.quit()
        self._pipe = None

        self._bin_info = None
        self._thunk_dict = dict()
        self._caller_cache = defaultdict(lambda: set())
        self._calls_cache = defaultdict(lambda: set())

    def get_sections(self) -> Iterable[Section]:
        '''
        Returns a list of the sections within the binary.
        Currently only supports sections within an ELF file.
        '''
        return list()

    def analyze(self, path) -> bool:
        '''
        Loads the binary specified by `path` into the disassembler.
        Implement all diaassembler specific setup and trigger analysis here.
        :returns: True on success, false otherwise
        '''
        if isinstance(path, Path):
            path = str(path)

        if not os.path.exists(path) or os.path.isdir(path):
            return False, f"File not Found: {path}"

        try:
            self._pipe = rzpipe.open(path)
        except Exception:
            if self.rizin_home is None:
                self.rizin_home = Rizin.DEFAULT_INSTALL()

            pre_built_loc = os.path.join(self.rizin_home, "bin")
            build_loc = os.path.join(
                self.rizin_home, "build", "binrz", "rizin")
            if os.path.exists(pre_built_loc):
                self._pipe = rzpipe.open(path, rizin_home=pre_built_loc)
            elif os.path.exists(build_loc):
                self._pipe = rzpipe.open(path, rizin_home=build_loc)
            else:
                raise FileNotFoundError("Can't find rizin binary")

        self._pipe.cmd('aaaa')
        self._bin_info = self._pipe.cmdj('ij')['bin']

        return True, None

    def _post_normalize(self):
        del self._caller_cache
        del self._calls_cache
        del self._thunk_dict

    def get_entry_point(self) -> int:
        '''Returns the address of the entry point to the function'''
        return self._pipe.cmdj('iej')[0]['vaddr']

    def get_architecture(self) -> str:
        '''
        Returns the architecture of the binary.
        For best results use either archinfo, qemu, or compilation triplet naming conventions.
        https://github.com/angr/archinfo
        '''
        return self._bin_info['arch']

    def get_endianness(self) -> Endian:
        '''Returns an Enum representing the Endianness'''
        if self._bin_info['endian'] == "LE":
            return Endian.LITTLE
        elif self._bin_info['endian'] == "BE":
            return Endian.BIG

        return Endian.OTHER

    def get_bitness(self) -> int:
        '''Returns the word size of the architecture (e.g., 16, 32, 64)'''
        return self._bin_info['bits']

    def get_base_address(self) -> int:
        '''Returns the base address the binary is based at'''
        return int(self._pipe.cmd("echo $B"), 16)

    def get_strings(self, binary_io: IO, file_size: int) -> Iterable[str]:
        '''Returns the list of defined strings in the binary'''
        return [s['string'] for s in self._pipe.cmdj('izj')]

    def get_dynamic_libs(self) -> Iterable[str]:
        '''Returns the list of names of the dynamic libraries used in this binary'''
        return [l for l in self._pipe.cmdj("ilj")]

    def get_func_iterator(self) -> Iterable[Any]:
        '''
        Returns an iterable of `Any` data type (e.g., address, interal func obj, dict of data) 
        needed to construct a `Function` object for all functions in the binary.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        for f in self._pipe.cmdj("aflj"):
            yield f

    def get_func_addr(self, func_ctxt: Any) -> int:
        '''Returns the address of the function corresponding to the function information returned from `get_func_iterator()`'''
        return func_ctxt['offset']

    def get_func_name(self, addr: int, func_ctxt: Any) -> str:
        '''Returns the name of the function corresponding to the function information returned from `get_func_iterator()`'''
        self._pipe.cmd(f"s {addr}")
        signature = self._pipe.cmdj('afsj')
        name = signature['name']

        if name.startswith("dbg."):
            name = name[len("dbg."):]

        if name.startswith("sym."):
            name = name[len("sym."):]

        if name.startswith("imp."):
            name = name[len("imp."):]
            self._thunk_dict[addr] = True

        return name

    def get_func_args(self, addr: int, func_ctxt: Any) -> List[Argument]:
        '''Returns the arguments in the function corresponding to the function information returned from `get_func_iterator()`'''
        self._pipe.cmd(f"s {addr}")
        signature = self._pipe.cmdj('afsj')
        return [
            Argument(
                data_type=arg['type'],
                var_name=arg['name']
            ) for arg in signature['args'] if arg.get('type', None) and arg.get('name', None)
        ]

    def get_func_callers(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        '''Return the address to functions that call func_ctxt'''
        for call_addr in self._caller_cache[addr]:
            yield call_addr

    def get_func_callees(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        '''Return the address to functions that are called in func_ctxt'''
        for callee_addr in self._calls_cache[addr]:
            yield callee_addr

    def _parse_xref_type(self, type):
        if type == 'CODE':
            return RefType.JUMP
        if type == 'CALL':
            return RefType.CALL
        if type == 'DATA' or type == 'STRING':
            return RefType.DATA

        return RefType.UNKNOWN

    def get_func_xrefs(self, addr: int, func_ctxt: Any) -> Iterable[Reference]:
        self._pipe.cmd(f"s {addr}")
        xref_data = self._pipe.cmdj("afxj")
        for xref in xref_data:
            if xref['type'] == 'CALL':
                self._calls_cache[addr].add(xref['to'])
                self._caller_cache[xref['to']].add(addr)

            yield Reference(
                to=xref['to'],
                from_=xref['from'],
                type=self._parse_xref_type(xref['type'])
            )

    def get_func_return_type(self, addr: int, func_ctxt: Any) -> int:
        '''Returns the return type of the function corresponding to the function information returned from `get_func_iterator()`'''
        self._pipe.cmd(f"s {addr}")
        signature = self._pipe.cmdj('afsj')

        return signature['ret']

    def get_func_stack_frame_size(self, addr: int, func_ctxt: Any) -> int:
        '''Returns the size of the stack frame in the function corresponding to the function information returned from `get_func_iterator()`'''
        self._pipe.cmd(f"s {addr}")

        return self._pipe.cmdj('afij')[0]['stackframe']

    def get_func_vars(self, addr: int, func_ctxt: Any) -> Iterable[Variable]:
        '''Return variables within the function corresponding to the function information returned from `get_func_iterator()`'''
        self._pipe.cmd(f"s {addr}")
        vars = list()
        if 'stack' not in self._pipe.cmdj('afvlj'):
            return vars

        for var in self._pipe.cmdj('afvlj')['stack']:
            if not var['arg']:
                v = Variable(
                    data_type=var['type'],
                    name=var['name'],
                    is_register=var['storage']['type'] != "stack",
                    is_stack=var['storage']['type'] == "stack",
                )

                if v.is_stack:
                    v.stack_offset = var['storage']['stack']

                vars.append(v)

        return vars

    def is_func_thunk(self, addr: int, func_ctxt: Any) -> bool:
        '''Returns True if the function corresponding to the function information returned from `get_func_iterator()` is a thunk'''
        return self._thunk_dict.get(addr, False)

    def get_func_decomp(self, addr: int, func_ctxt: Any) -> Optional[str]:
        '''Returns the decomplication of the function corresponding to the function information returned from `get_func_iterator()`'''
        return None

    def get_func_bb_iterator(self, addr: int, func_ctxt: Any) -> Iterable[Any]:
        '''
        Returns an iterator of `Any` data type (e.g., address, implementation specific basic block information, dict of data)
        needed to construct a `BasicBlock` object for all basic blocks in the function based on function information returned from `get_func_iterator()`.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        self._pipe.cmd(f"s {addr}")
        for bb in self._pipe.cmdj('afbj'):
            yield bb

    def get_bb_addr(self, bb_ctxt: Any, func_ctxt: Any) -> int:
        '''
        Returns the address of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        return bb_ctxt['addr']

    def get_next_bbs(self, bb_addr: int, bb_ctxt: Any, func_addr: int, func_ctxt: Any) -> Iterable[Branch]:
        '''
        Returns the Branching information of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        branches = list()
        if bb_ctxt.get('fail', None) is not None:
            branches.append(
                Branch(type=BranchType.FalseBranch, target=bb_ctxt['fail']))
            if bb_ctxt.get('jump', None) is not None:
                branches.append(
                    Branch(type=BranchType.TrueBranch, target=bb_ctxt['jump']))
        elif bb_ctxt.get('jump', None) is not None:
            branches.append(
                Branch(type=BranchType.UnconditionalBranch, target=bb_ctxt['jump']))

        return branches

    def get_bb_instructions(self, bb_addr: int, bb_ctxt: Any, func_ctxt: Any) -> List[Tuple(bytes, str)]:
        '''
        Returns a iterable of tuples of raw instruction bytes and corresponding mnemonic from the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        instrs = list()

        self._pipe.cmd(f"s {bb_addr}")
        for i in self._pipe.cmdj("pdbj"):
            addr = i['offset']

            self._pipe.cmd(f"s {addr}")
            instr_data = self._pipe.cmdj(f"pdj 1")[0]

            instrs.append(
                (bytes.fromhex(instr_data['bytes']), instr_data['disasm']))

        return instrs

    def get_ir_from_instruction(self, instr_addr: int, instr: Instruction) -> Optional[IR]:
        '''
        Returns the Intermediate Representation data based on the instruction given
        '''
        self._pipe.cmd(f"s {instr_addr}")
        instr_data = self._pipe.cmdj(f"pdj 1")[0]
        ir = instr_data.get('esil', None)
        if ir is not None and len(ir) > 0:
            return IR(IL.ESIL, ir)

        return None

    def get_instruction_comment(self, instr_addr: int) -> Optional[str]:
        '''Return comments at the instruction'''
        self._pipe.cmd(f"s {instr_addr}")
        instr_data = self._pipe.cmdj(f"pdj 1")[0]

        if instr_data.get('comment', None) is not None:
            return str(binascii.a2b_base64(instr_data['comment']), 'utf8')
        return None