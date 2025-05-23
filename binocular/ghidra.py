from __future__ import annotations

import hashlib
import json
import os
import pkgutil
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import zipfile
from collections import OrderedDict
from collections.abc import Iterable
from enum import Enum
from typing import IO, Any, List, Optional, Tuple
from urllib.request import urlopen

import git
import requests  # type: ignore[import-untyped]
from git import Repo

from . import logger
from .consts import IL, BranchType, Endian, RefType
from .disassembler import Disassembler
from .primitives import IR, Argument, Branch, Instruction, Reference, Variable
from .utils import run_proc


class PipeRPCNotOpened(Exception):
    """Exception raise when an object is trying to use PipeRPC when it hasnt been created yet"""

    pass


class PipeRPC:
    """
    A TCP Socket based RPC from the python Ghidra class to a Ghidra Script
    Type-Length-Value Style Protocol
    **NOT** Thread or Multiprocess Safe *LMAO!!*
    """

    class Command(Enum):
        QUIT = 0
        TEST = 2
        BINARY_NAME = 4
        ENTRY_POINT = 6
        ARCHITECTURE = 8
        ENDIANNESS = 10
        BITNESS = 12
        BASE_ADDR = 14
        DYN_LIBS = 16
        FUNCS = 18
        # FUNC_ADDR = 20
        FUNC_NAME = 22
        FUNC_ARGS = 24
        FUNC_RETURN = 26
        FUNC_STACK_FRAME = 28
        FUNC_CALLERS = 30
        FUNC_CALLEES = 32
        FUNC_XREFS = 34
        FUNC_BB = 36
        # BB_ADDR = 38
        BB_BRANCHES = 40
        BB_INSTR = 42
        SECTIONS = 44
        DECOMP = 46
        FUNC_VARS = 48
        INSTR_PCODE = 50
        INSTR_COMMENT = 52
        STRINGS = 54
        FUNC_IS_THUNK = 56
        FUNC_BATCH = 58

    # Requests will have no length. Size is known
    # Procedure ID | BasicBlock Address | Function Address
    REQFMT = "!BQQQ"

    # Procedure ID | Total Length | Data...
    RESFMT = "!BI"
    RESFMT_SIZE = struct.calcsize(RESFMT)

    def __init__(
        self, gscript_ip: str = "127.0.0.1", port: int = 7331, timeout: int = 30
    ):
        self.gscript_ip: str = gscript_ip
        self.port: int = port
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_connected: bool = False
        self.timeout: int = timeout
        self.proc: Optional[subprocess.Popen] = None

    def connect(self) -> bool:
        if self.proc is None or self.proc.poll() is not None:
            self.is_connected = False
            return False

        assert self.proc.poll() == None
        logger.info(f"Attempting to Connect to: {self.gscript_ip}:{self.port}")
        waited = 0.0
        while not self.is_connected:
            try:
                self.sock.connect((self.gscript_ip, self.port))
                self.is_connected = True
                logger.info(
                    f"Socket Connect to BINocular Ghidra Script {self.gscript_ip}:{self.port}"
                )
                return True
            except ConnectionRefusedError:
                time.sleep(0.25)
                waited += 0.25

            if waited > self.timeout:
                raise ConnectionRefusedError(
                    "Unable to Connect to BINocular Ghidra Script"
                )

        self.is_connected = False
        return True

    def close(self):
        self.sock.close()
        self.is_connected = False

    def request(
        self,
        cmd: Command,
        bb_addr: int = 0,
        f_addr: int = 0,
        instr_addr: int = 0,
    ) -> bytes:
        if not self.is_connected:
            if cmd == PipeRPC.Command.QUIT:
                return b""

            self.connect()
        if self.proc is None:
            raise RuntimeError(
                "Ghidra AnalyzeHeadless process was never set to RPC Pipe"
            )

        # Its ok if it dies if we are telling it to quit, otherwise not ok
        if self.proc.poll() is not None and not cmd == PipeRPC.Command.QUIT:
            raise RuntimeError("Ghidra AnalyzeHeadless process is dead")

        id = cmd.value
        msg = struct.pack(PipeRPC.REQFMT, id, bb_addr, f_addr, instr_addr)
        self.sock.sendall(msg)
        start = time.time()
        header = b""
        header = self._recv_bytes(self.sock, PipeRPC.RESFMT_SIZE, timeout=self.timeout)
        res_id, size = struct.unpack(PipeRPC.RESFMT, header)
        if res_id != id + 1:
            raise Exception(
                f"Recieved unexpected response id: {res_id}, Expected: {id+1}"
            )

        if size < 0:
            raise Exception(f"Recieved negative lengthed response")

        if size > 0:
            res = self._recv_bytes(self.sock, size, timeout=self.timeout)
            logger.debug(
                f"Recieved {PipeRPC.Command(res_id-1).name} Response in {time.time()-start:2f}s"
            )
            return res

        return b""

    def _recv_bytes(self, sock: socket.socket, size: int, timeout: int):
        data = b""
        start = time.time()
        while len(data) < size:
            data += sock.recv(min(size - len(data), 4096))
            if time.time() - start > timeout:
                raise TimeoutError

        return data


class ProcMon(threading.Thread):
    def __init__(self, chunk_len: int = 2048, verbose: bool = False):
        super().__init__()
        self.proc: Optional[subprocess.Popen] = None
        self.verbose: bool = verbose
        self.running: bool = False
        self.stdout: str = ""
        self.stderr: str = ""
        self.chunk_len: int = chunk_len

    def __contains__(self, x: str):
        return x in self.stdout

    def run(self):
        if self.proc is None:
            return

        self.running = True
        while self.running and self.proc.poll() is None:
            out = self.proc.stdout.read1(self.chunk_len)
            # err = self.proc.stderr.read1(self.chunk_len)
            # print('err')
            if out is None:  # and err is None:
                time.sleep(1)
            else:
                if out:
                    self.stdout += str(out, "utf8")
                # if err:
                #     self.stderr += str(err, "utf8")

            time.sleep(0.250)
        # self.stderr = str(self.proc.stderr.read(), 'utf8')

        out = self.proc.stdout.read()
        if out:
            self.stdout += str(out, "utf8")

    def stop(self) -> None:
        self.running = False


class Ghidra(Disassembler):
    GIT_REPO = "https://github.com/NationalSecurityAgency/ghidra.git"
    GITHUB_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases"

    @staticmethod
    def DEFAULT_INSTALL():
        """Default Install Location for Ghidra (Within Python Package Installation)"""
        return os.path.join(
            os.path.dirname(pkgutil.get_loader("binocular").path), "data", "ghidra"
        )

    @staticmethod
    def DEFAULT_PROJECT_PATH():
        """Default Ghidra Project Path (Within Python Package Installation)"""
        return os.path.join(
            os.path.dirname(pkgutil.get_loader("binocular").path), "data", "ghidra_proj"
        )

    @staticmethod
    def SCRIPT_PATH():
        return os.path.join(
            os.path.join(os.path.dirname(pkgutil.get_loader("binocular").path)),
            "scripts",
        )

    @classmethod
    def list_versions(cls):
        r = requests.get(cls.GITHUB_API)
        if r.status_code != 200:
            raise Exception(f"Cannot reach {cls.GITHUB_API}")

        release_data = json.loads(r.text)
        versions = list()
        for release in release_data:
            ver = release["name"].rsplit(" ", 1)[1]
            versions.append(ver.strip())

        return versions

    @classmethod
    def _install_prebuilt(
        cls,
        version: Optional[str],
        install_dir: str,
        local_install_file: Optional[str] = None,
    ):
        if local_install_file is None:
            # Ask Github API for Ghidra Release versions and the
            # prebuilt download link
            r = requests.get(Ghidra.GITHUB_API)
            if r.status_code != 200:
                logger.critical(f"Cannot reach {Ghidra.GITHUB_API}")
                raise Exception(f"Cannot reach {Ghidra.GITHUB_API}")

            release_data = json.loads(r.text)
            links = OrderedDict()
            for release in release_data:
                ver = release["name"].rsplit(" ", 1)[1].strip()
                dl_link = release["assets"][0]["browser_download_url"]
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
                with zipfile.ZipFile(fp, "r") as zf:
                    zf.extractall(install_dir)
        else:
            if not os.path.exists(local_install_file):
                raise Exception(f"File Does not Exist: {local_install_file}")

            # Assume this is a zip of a Ghidra Release
            with open(local_install_file, "rb") as fp:
                with zipfile.ZipFile(fp, "r") as zf:
                    zf.extractall(install_dir)

        return os.path.join(install_dir, os.listdir(install_dir)[0])

    @classmethod
    def _build(cls, version: Optional[str], install_dir: str):
        if version is None:
            raise ValueError("No commit version supplied")

        logger.info(f"Building Ghidra @ commit {version}")

        # dependency check
        if shutil.which("java") is None:
            logger.critical(
                "Can't find java. Is JDK 21 installed? Download here: https://adoptium.net/temurin/releases/"
            )
            exit(1)

        if shutil.which("gradle") is None:
            logger.critical(
                "Can't find gradle. Gradle 8.5+ required. Download here: https://gradle.org/releases/"
            )
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
            ["gradle", "buildGhidra"],
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

        dist = os.path.join(install_dir, "build", "dist")
        zip_file = os.path.join(dist, os.listdir(dist)[0])
        with open(zip_file, "rb") as f:
            with zipfile.ZipFile(f, "r") as zf:
                zf.extractall(dist)

        return os.path.join(dist, "_".join(os.path.basename(zip_file).split("_")[:3]))

    @classmethod
    def install(
        cls,
        version: Optional[str] = None,
        install_dir: Optional[str] = None,
        build: Optional[bool] = False,
        local_install_file: Optional[str] = None,
    ) -> str:
        """
        Installs the disassembler to a user specified directory or within the python module if none is specified
        :param version: Release Version Number or Commit Hash
        :param install_dir: the directory to install Ghidra to
        :param build: True if version is a Commit Hash.
        """
        if install_dir is None:
            install_dir = Ghidra.DEFAULT_INSTALL()

        os.makedirs(install_dir, exist_ok=True)

        if build:
            ghidra_home = Ghidra._build(version, install_dir)
        else:
            ghidra_home = Ghidra._install_prebuilt(
                version, install_dir, local_install_file=local_install_file
            )

        logger.info("Ghidra Install Completed")
        assert os.path.exists(ghidra_home)

        # Permission to execute stuff in Ghidra Home
        os.chmod(os.path.join(ghidra_home, "support", "launch.sh"), 0o775)
        for root, _, files in os.walk(ghidra_home):
            for fname in files:
                fpath = os.path.join(root, fname)
                os.chmod(fpath, 0o775)

        return ghidra_home

    @classmethod
    def is_installed(cls, install_dir: Optional[str] = None) -> bool:
        """Returns Boolean on whether or not the dissassembler is installed"""
        os.makedirs(Ghidra.DEFAULT_INSTALL(), exist_ok=True)

        if install_dir is None:
            install_dir = Ghidra.DEFAULT_INSTALL()

        if len(os.listdir(install_dir)) == 0:
            return False

        release_install = os.path.join(install_dir, os.listdir(install_dir)[0])
        release_install = os.path.join(release_install, "support", "launch.sh")

        build_install = os.path.join(install_dir, "build", "dist")

        return os.path.exists(release_install) or os.path.exists(build_install)

    def __init__(
        self,
        verbose: bool = True,
        project_path: Optional[str] = None,
        home: Optional[str] = None,
        cpus: int = 1,
    ):
        super().__init__(verbose=verbose)

        if project_path is None:
            project_path = Ghidra.DEFAULT_PROJECT_PATH()
        self.base_project_path = project_path

        self.ghidra_home: str
        if home is None:
            ghidra_release_patttern = re.compile(r"ghidra_(\d+(\.\d+)*)_PUBLIC")
            ghidra_dir = None
            for dir in os.listdir(Ghidra.DEFAULT_INSTALL()):
                if ghidra_release_patttern.match(dir):
                    ghidra_dir = dir
                    break

            if ghidra_dir is None:
                raise Exception(
                    f"Unable to find Ghidra install directory inside of {self.ghidra_home}"
                )

            self.ghidra_home = os.path.join(Ghidra.DEFAULT_INSTALL(), ghidra_dir)
        else:
            self.ghidra_home = home

        self.cpus: int = cpus
        self.ghidra_proc: Optional[subprocess.Popen] = None
        self.rpc_pipe: Optional[PipeRPC] = None
        self.proc_monitor: Optional[ProcMon] = None
        self.bin_name: Optional[str] = None

    def _analyze_headless_path(self) -> str:
        return os.path.join(self.ghidra_home, "support", "analyzeHeadless")

    def open(self):
        return self

    # TODO type hint
    def close(self):
        self.clear()

    def clear(self):
        super().clear()
        self.bin_name = None
        self._close_rpc()

    def analysis_timeout(self, bin_size) -> int:
        # 30s +
        # 1 minutes per 500KB
        return round(30 + 60 * (bin_size / (1024)) ** 2)

    def analyze(self, path) -> Tuple[bool, Optional[str]]:
        """
        Loads the binary specified by `path` into the disassembler.
        Implement all diaassembler specific setup and trigger analysis here.
        :returns: (True, optional message) on success, (False, failure reason) otherwise
        """

        # CHECK IN
        bin_size = 0
        m = hashlib.md5()
        with open(path, "rb") as f:
            chunk = f.read(4096)
            while chunk:
                m.update(chunk)
                bin_size += len(chunk)
                chunk = f.read(4096)

        md5hash = m.hexdigest()

        imported = False

        # PROJECT SETUP
        cmd = [self._analyze_headless_path()]
        # Containing folder of the project is the same name of the project
        # A little cleaner to handle when you can just rm the <md5sum>/ to
        # delete a whole project if need be
        self.project_location = os.path.join(self.base_project_path, md5hash)
        self.project_name = md5hash
        imported = os.path.exists(self.project_location)
        os.makedirs(self.project_location, exist_ok=True)
        cmd += [self.project_location, self.project_name]

        self.rpc_pipe = PipeRPC(timeout=self.analysis_timeout(bin_size))

        # Run the BinocularPipe Script
        cmd += [
            "-scriptPath",
            Ghidra.SCRIPT_PATH(),
            "-postScript",
            "BinocularPipe.java",
            self.rpc_pipe.gscript_ip,
            str(self.rpc_pipe.port),
            "-max-cpu",
            str(self.cpus),
        ]

        self.bin_name = os.path.basename(path)
        if self.bin_name is None:
            return False, f"Failed to resolve input binary from path: {path}"

        if not imported:
            cmd += ["-import", str(path)]
        else:
            cmd += ["-process", self.bin_name]

        if self.verbose:
            logger.info("$ " + " ".join(cmd))

        self.ghidra_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        self.rpc_pipe.proc = self.ghidra_proc

        self.proc_monitor = ProcMon(verbose=self.verbose)
        self.proc_monitor.proc = self.ghidra_proc
        self.proc_monitor.start()

        start = time.time()
        timedout = False

        if self.ghidra_proc.poll() is not None:
            raise RuntimeError("Ghidra Analyzeheadless is not running")

        timeout = self.analysis_timeout(bin_size)
        logger.debug(f"Waiting at least {timeout}s for Analysis to finish")
        while (
            timedout := (time.time() - start < timeout)
            and self.ghidra_proc.poll() is None
        ):
            if "Analysis succeeded for file" in self.proc_monitor:
                return True, None
            time.sleep(0.01)

        if self.ghidra_proc.poll() is not None:
            logger.debug("Ghidra Analyzeheadless died")
            logger.debug(self.proc_monitor.stdout)

        if "Unable to lock project" in self.proc_monitor:
            logger.error(
                f"Unable to lock project: {os.path.join(self.project_location, self.project_name + '.lock')}. Exiting"
            )

        # Timed out. Kill self.ghidra_proc
        self.proc_monitor.stop()
        self.proc_monitor.join()
        self._kill_headless()
        return False, "Analyze Headless Timedout"

    def _kill_headless(self):
        if self.ghidra_proc is None:
            return True

        self.ghidra_proc.terminate()
        count = 0
        if count < 5 and self.ghidra_proc.poll() is None:
            time.sleep(1)
            count += 1

        return self.ghidra_proc.poll() is not None

    def _post_normalize(self):
        self._close_rpc()

    def _close_rpc(self):
        # Analysis Done. Close AnalyzeHeadless Process

        if self.ghidra_proc is None:
            return

        if self.proc_monitor is None:
            return

        if "ERROR REPORT SCRIPT ERROR" in self.proc_monitor:
            logger.info("Ghidra Analyze Headless Errored")

        self.proc_monitor.stop()
        self.proc_monitor.join(timeout=1)
        self.proc_monitor = None

        logger.info("Closing RPC Pipe...")
        try:
            self.rpc_pipe.request(PipeRPC.Command.QUIT)
        except TimeoutError:
            logger.warn("Encountered Timeout on PipeRPC graceful quit")

        self.rpc_pipe.close()
        logger.info("Waiting on Ghidra to exit...")
        try:
            self.ghidra_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("Timeout. Killing Ghidra Process")
            self._kill_headless()

        exit_code = self.ghidra_proc.poll()
        if exit_code is not None:
            logger.info(f"Ghidra Process has exited: {exit_code}")
            self.ghidra_proc = None
        else:
            raise RuntimeError("Unable to Close Ghidra Analyze Headless")

    @staticmethod
    def _unpack_str_list(raw: bytes) -> List[str]:
        # Null terminated C Strings
        strs = list()
        start = 0
        for i in range(len(raw)):
            if raw[i] == 0:
                strs.append(raw[start:i])
                start = i + 1

        return [str(s, "utf8") for s in strs]

    def get_binary_name(self) -> str:
        """Returns the name of the binary loaded"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return str(self.rpc_pipe.request(PipeRPC.Command.BINARY_NAME), "utf8")

    def get_entry_point(self) -> int:
        """Returns the address of the entry point to the function"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return struct.unpack("!Q", self.rpc_pipe.request(PipeRPC.Command.ENTRY_POINT))[
            0
        ]

    def get_architecture(self) -> str:
        """
        Returns the architecture of the binary.
        For best compatibility use either archinfo, qemu, or compilation triplet naming conventions.
        https://github.com/angr/archinfo
        """
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return str(self.rpc_pipe.request(PipeRPC.Command.ARCHITECTURE), "utf8")

    def get_endianness(self) -> Endian:
        """Returns an Enum representing the Endianness"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        endian = str(self.rpc_pipe.request(PipeRPC.Command.ENDIANNESS), "utf8").lower()
        if endian == "little":
            return Endian.LITTLE
        elif endian == "big":
            return Endian.BIG
        return Endian.OTHER

    def get_bitness(self) -> int:
        """Returns the word size of the architecture (e.g., 16, 32, 64)"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return struct.unpack("!I", self.rpc_pipe.request(PipeRPC.Command.BITNESS))[0]

    def get_base_address(self) -> int:
        """Returns the base address the binary is based at"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return struct.unpack("!Q", self.rpc_pipe.request(PipeRPC.Command.BASE_ADDR))[0]

    def get_strings(self, binary_io: IO, file_size: int) -> Iterable[str]:
        """Returns the list of defined strings in the binary"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return self._unpack_str_list(self.rpc_pipe.request(PipeRPC.Command.STRINGS))

    def get_dynamic_libs(self) -> Iterable[str]:
        """Returns the list of names of the dynamic libraries used in this binary"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        raw = self.rpc_pipe.request(PipeRPC.Command.DYN_LIBS)
        return [str(lib, "utf8") for lib in raw.split(b"\x00")]

    def get_func_iterator(self) -> Iterable[int]:
        """
        Returns an iterable of `Any` data type (e.g., address, interal func obj, dict of data)
        needed to construct a `Function` object for all functions in the binary.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        """
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        # RPC returns back the address of each function
        # We will use the address to index/address/key each function
        raw = self.rpc_pipe.request(PipeRPC.Command.FUNCS)
        n_funcs = len(raw) // 8

        for i in range(n_funcs):
            f = struct.unpack("!Q", raw[i * 8 : (i + 1) * 8])[0]

            yield f

    def get_func_addr(self, func_ctxt: int) -> int:
        """Returns the address of the function corresponding to the function information returned from `get_func_iterator()`"""
        # Here, func_ctxt is the address
        return func_ctxt

    def get_func_name(self, addr: int, func_ctxt: Any) -> str:
        """Returns the name of the function corresponding to the function information returned from `get_func_iterator()`"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return str(
            self.rpc_pipe.request(PipeRPC.Command.FUNC_NAME, f_addr=addr), "utf8"
        )

    def get_func_args(self, addr: int, func_ctxt: Any) -> List[Argument]:
        """Returns the arguments in the function corresponding to the function information returned from `get_func_iterator()`"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        args_str = self._unpack_str_list(
            self.rpc_pipe.request(PipeRPC.Command.FUNC_ARGS, f_addr=addr)
        )
        return [Argument.from_literal(s) for s in args_str]

    def get_func_return_type(self, addr: int, func_ctxt: Any) -> str:
        """Returns the return type of the function corresponding to the function information returned from `get_func_iterator()`"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return str(
            self.rpc_pipe.request(PipeRPC.Command.FUNC_RETURN, f_addr=addr), "utf8"
        )

    def get_func_stack_frame_size(self, addr: int, func_ctxt: Any) -> int:
        """Returns the size of the stack frame in the function corresponding to the function information returned from `get_func_iterator()`"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return struct.unpack(
            "!I", self.rpc_pipe.request(PipeRPC.Command.FUNC_STACK_FRAME, f_addr=addr)
        )[0]

    def get_func_vars(self, addr: int, func_ctxt: Any) -> Iterable[Variable]:
        """Return variables within the function corresponding to the function information returned from `get_func_iterator()`"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        raw = self.rpc_pipe.request(PipeRPC.Command.FUNC_VARS, f_addr=addr)
        curr = 0
        while curr < len(raw):
            size = struct.unpack("!I", raw[curr : curr + 4])[0]
            data = raw[curr + 4 : curr + 4 + size]
            dtype, name = self._unpack_str_list(data[:-6])
            v = Variable(
                data_type=dtype,
                name=name,
                is_register=bool(data[-6]),
                is_stack=bool(data[-5]),
            )
            if v.is_stack:
                v.stack_offset = struct.unpack("!I", data[-4:])[0]

            yield v

            curr = curr + 4 + size

    def is_func_thunk(self, addr: int, func_ctxt: Any) -> bool:
        """Returns True if the function corresponding to the function information returned from `get_func_iterator()` is a thunk"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return bool(
            self.rpc_pipe.request(PipeRPC.Command.FUNC_IS_THUNK, f_addr=addr)[0]
        )

    def get_func_decomp(self, addr: int, func_ctxt: Any) -> Optional[str]:
        """Returns the decomplication of the function corresponding to the function information returned from `get_func_iterator()`"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return str(self.rpc_pipe.request(PipeRPC.Command.DECOMP, f_addr=addr), "utf8")

    def get_func_callers(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        raw = self.rpc_pipe.request(PipeRPC.Command.FUNC_CALLERS, f_addr=addr)
        num_funcs = len(raw) // 8
        fmt = f"!{num_funcs}Q"
        return struct.unpack(fmt, raw)

    def get_func_callees(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        raw = self.rpc_pipe.request(PipeRPC.Command.FUNC_CALLEES, f_addr=addr)
        num_funcs = len(raw) // 8
        fmt = f"!{num_funcs}Q"
        return struct.unpack(fmt, raw)

    def get_func_xrefs(self, addr: int, func_ctxt: Any) -> Iterable[Reference]:
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        raw = self.rpc_pipe.request(PipeRPC.Command.FUNC_XREFS, f_addr=addr)
        struct_size = 17
        num_refs = len(raw) // struct_size
        for i in range(num_refs):
            type_, to, from_ = struct.unpack(
                "!BQQ", raw[i * struct_size : (i + 1) * struct_size]
            )
            yield Reference(from_=from_, type=RefType(type_), to=to)

    def get_func_bb_iterator(self, addr: int, func_ctxt: Any) -> Iterable[Any]:
        """
        Returns an iterator of `Any` data type (e.g., address, implementation specific basic block information, dict of data)
        needed to construct a `BasicBlock` object for all basic blocks in the function based on function information returned from `get_func_iterator()`.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        """
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        raw = self.rpc_pipe.request(PipeRPC.Command.FUNC_BB, f_addr=addr)
        num_funcs = len(raw) // 8
        fmt = f"!{num_funcs}Q"
        return struct.unpack(fmt, raw)

    def get_bb_addr(self, bb_ctxt: Any, func_ctxt: Any) -> int:
        """
        Returns the address of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        return bb_ctxt

    def get_next_bbs(
        self, bb_addr: int, bb_ctxt: Any, func_addr: int, func_ctxt: Any
    ) -> Iterable[Branch]:
        """
        Returns the Branching information of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        raw = self.rpc_pipe.request(PipeRPC.Command.BB_BRANCHES, bb_addr=bb_addr)
        struct_size = 9
        n = len(raw) // struct_size
        for i in range(n):
            flow, addr = struct.unpack(
                "!BQ", raw[i * struct_size : (i + 1) * struct_size]
            )
            yield Branch(type=BranchType(flow), target=addr)

    def get_bb_instructions(
        self, bb_addr: int, bb_ctxt: Any, func_ctxt: Any
    ) -> List[Tuple[bytes, str]]:
        """
        Returns a iterable of tuples of raw instruction bytes and corresponding mnemonic from the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        raw = self.rpc_pipe.request(PipeRPC.Command.BB_INSTR, bb_addr=bb_addr)

        instr: List[Tuple[bytes, str]] = list()
        i = 0
        while i < len(raw):
            instr_size = raw[i]
            i += 1

            if instr_size > 0:
                instr_bytes = raw[i : i + instr_size]
            else:
                instr_bytes = b""
            i += instr_size

            mnemonic_size = raw[i]
            i += 1
            mnemonic = raw[i : i + mnemonic_size]

            instr.append((instr_bytes, str(mnemonic, "utf8")))
            i += mnemonic_size

        return instr

    def get_ir_from_instruction(
        self, instr_addr: int, instr: Instruction
    ) -> Optional[IR]:
        """
        Returns the Intermediate Representation data based on the instruction given
        """
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        pcode = str(
            self.rpc_pipe.request(PipeRPC.Command.INSTR_PCODE, instr_addr=instr_addr),
            "utf8",
        )
        return IR(lang_name=IL.PCODE, data=pcode)

    def get_instruction_comment(self, instr_addr: int) -> Optional[str]:
        """Return comments at the instruction"""
        if self.rpc_pipe is None:
            raise PipeRPCNotOpened

        return str(
            self.rpc_pipe.request(PipeRPC.Command.INSTR_COMMENT, instr_addr=instr_addr),
            "utf8",
        )

    def run_script(
        self, script: str, timeout: int, script_args: Optional[List[str]] = None
    ) -> Optional[str]:
        """Run a custom script"""
        script_path = os.path.join(Ghidra.SCRIPT_PATH(), script)
        if not os.path.exists(script_path):
            script = os.path.realpath(script)
            logger.info(f"Creating Symlink: {script} -> {script_path}")
            os.symlink(script, script_path)

        if os.path.isdir(script_path):
            return None

        cmd = [
            self._analyze_headless_path(),
            self.project_location,
            self.project_name,
            "-scriptPath",
            Ghidra.SCRIPT_PATH(),
            "-max-cpu",
            str(self.cpus),
            "-process",
            self.bin_name,
            "-postScript",
            script,
        ]

        if script_args is not None:
            cmd += script_args

        if self.verbose:
            logger.info("$ " + " ".join(cmd))

        # script proc
        script_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        script_monitor = ProcMon(verbose=self.verbose)
        script_monitor.proc = script_proc
        script_monitor.start()

        try:
            start = time.time()

            while time.time() - start < timeout and script_proc.poll() is None:
                if "Unable to lock project" in script_monitor:
                    logger.error(
                        f"Unable to lock project: {os.path.join(self.project_location, self.project_name + '.lock')}"
                    )
                    script_proc.terminate()
                    script_monitor.stop()
                    script_monitor.join()
                    return script_monitor.stdout

                # TODO if we want a early exit or something
                # if Sentinal in self.stdout_monitor:
                #     return True, None
                time.sleep(0.1)

        finally:
            # Ensure we clean up processes

            if script_proc.poll() is None:
                logger.debug("Analyze Headless has timed out and will be killed")
                script_proc.terminate()
                logger.debug(script_monitor.stdout)

            script_monitor.stop()
            script_monitor.join(5)
            stdout = script_monitor.stdout

        return stdout
