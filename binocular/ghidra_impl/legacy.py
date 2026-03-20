from __future__ import annotations

import os
import socket
import struct
import subprocess
import threading
import time
import pathlib
import typing_extensions
from collections.abc import Iterable
from enum import Enum
from typing import IO, Any, List, Optional, Tuple


from .core import GhidraBase

from .. import logger
from ..consts import IL, BranchType, Endian, RefType
from ..primitives import IR, Argument, Branch, Instruction, Reference, Variable


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

    def __init__(self, unix_socket: str, timeout: int = 30):
        self.unix_socket: str = unix_socket
        self.sock: socket.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.is_connected: bool = False
        self.timeout: int = timeout
        self.proc: Optional[subprocess.Popen] = None

    def connect(self) -> bool:
        if self.proc is None or self.proc.poll() is not None:
            self.is_connected = False
            return False

        assert self.proc.poll() == None
        logger.info(f"Attempting to Connect to: {self.unix_socket}")
        waited = 0.0
        while not self.is_connected:
            try:
                self.sock.connect(self.unix_socket)
                self.is_connected = True
                logger.info(
                    f"Socket Connect to BINocular Ghidra Script: {self.unix_socket}"
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

        logger.debug(f"Sending Request: {cmd.name}")

        id = cmd.value
        msg = struct.pack(PipeRPC.REQFMT, id, bb_addr, f_addr, instr_addr)
        self.sock.sendall(msg)
        start = time.time()
        header = b""
        header = self._recv_bytes(self.sock, PipeRPC.RESFMT_SIZE, timeout=self.timeout)

        res_id, size = struct.unpack(PipeRPC.RESFMT, header)
        if res_id != id + 1:
            raise Exception(
                f"Receive unexpected response id: {res_id}, Expected: {id+1}"
            )

        if size < 0:
            raise Exception(f"Receive negative lengthed response")

        if size > 0:
            res = self._recv_bytes(self.sock, size, timeout=self.timeout)
            logger.debug(
                f"Receive {PipeRPC.Command(res_id-1).name} Response in {time.time()-start:2f}s"
            )
            return res

        logger.debug(f"Empty Response to: {cmd.name}")

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
            if out is None:
                time.sleep(1)
            else:
                if out:
                    self.stdout += str(out, "utf8")

            time.sleep(0.250)
        out = self.proc.stdout.read()
        if out:
            self.stdout += str(out, "utf8")

    def stop(self) -> None:
        self.running = False


class GhidraLegacy(GhidraBase):
    def __init__(
        self,
        verbose: bool = True,
        project_path: Optional[str] = None,
        home: Optional[str] = None,
        cpus: int = 1,
        analysis_timeout: Optional[int] = None,
    ):
        super().__init__(verbose=verbose, project_path=project_path, home=home)
        self.cpus: int = cpus
        self.ghidra_proc: Optional[subprocess.Popen] = None
        self.unix_socket: str = os.path.join("/tmp", f"binocular_ghidra_{os.getpid()}")
        self.rpc_pipe: Optional[PipeRPC] = None
        self.proc_monitor: Optional[ProcMon] = None
        self.anal_time: Optional[int] = analysis_timeout

    def analysis_timeout(self, bin_size) -> int:
        # 30s +
        # 1 minutes per 100KB
        return round(30 + 60 * (bin_size / (1024)))

    def analyze(self) -> None:
        """
        Loads the binary specified by `path` into the disassembler.
        Implement all diaassembler specific setup and trigger analysis here.
        :returns: (True, optional message) on success, (False, failure reason) otherwise
        """
        super().analyze()

        cmd = [self._analyze_headless_path()]
        imported = os.path.exists(self.project_location)
        os.makedirs(self.project_location, exist_ok=True)
        cmd += [self.project_location, self.project_name]

        self.rpc_pipe = PipeRPC(
            self.unix_socket, timeout=self.analysis_timeout(self.bin_size)
        )

        # Run the BinocularPipe Script
        cmd += [
            "-scriptPath",
            self.SCRIPT_PATH(),
            "-postScript",
            "BinocularPipe.java",
            self.unix_socket,
            "-max-cpu",
            str(self.cpus),
        ]

        logger.info(f"Loading: {self.bin_name}")
        if not imported:
            cmd += ["-import", str(self.binary_filepath)]
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
        if self.ghidra_proc.poll() is not None:
            raise RuntimeError("Ghidra Analyzeheadless is not running")

        if self.anal_time is None:
            timeout = self.analysis_timeout(self.bin_size)
        elif self.anal_time <= 0:
            timeout = None
        else:
            timeout = self.anal_time

        logger.debug(f"Waiting at least {timeout}s for Analysis to finish")
        while (
            timeout is None or time.time() - start < timeout
        ) and self.ghidra_proc.poll() is None:
            if "BINocularPipe Ready" in self.proc_monitor:
                return
            time.sleep(0.01)

        if self.ghidra_proc.poll() is not None:
            logger.debug("Ghidra Analyzeheadless died")
            logger.debug(self.proc_monitor.stdout)

        if "Unable to lock project" in self.proc_monitor:
            raise RuntimeError(
                f"Unable to lock project: {os.path.join(self.project_location, self.project_name + '.lock')}. Exiting"
            )

        # Timed out. Kill self.ghidra_proc
        self.proc_monitor.stop()
        self.proc_monitor.join()
        self._kill_headless()
        raise RuntimeError("Analyze Headless Timeout")

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
        self,
        script: str,
        timeout: int,
        script_args: Optional[List[str]] = None,
        script_path: Optional[str] = None,
    ) -> Optional[str]:
        """Run a custom script"""
        curr_script_path = (
            os.path.join(self.SCRIPT_PATH(), script)
            if script_path is None
            else os.path.join(os.path.realpath(script_path), script)
        )
        if not os.path.exists(curr_script_path):
            script = os.path.realpath(script)
            logger.info(f"Creating Symlink: {script} -> {curr_script_path}")
            os.symlink(script, curr_script_path)

        if os.path.isdir(curr_script_path):
            return None

        if self.bin_name is None:
            raise RuntimeError("Binary Name is Unknown")

        cmd = [
            self._analyze_headless_path(),
            self.project_location,
            self.project_name,
            "-scriptPath",
            self.SCRIPT_PATH() if script_path is None else script_path,
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
        idx = 0
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

                # log out stdout as it runs
                nl_idx = script_monitor.stdout[idx:].rfind("\n")
                if nl_idx >= 0:
                    idx = nl_idx

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
