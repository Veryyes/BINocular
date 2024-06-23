from __future__ import annotations

import os
import logging
import time
import string
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any, Optional, Tuple, List, Dict, Set, IO

import coloredlogs

from .primitives import (BasicBlock, Binary, NativeFunction, SourceFunction,
                         Instruction, Section, Argument, Branch, IR, Reference, Variable)

from .consts import Endian

logger = logging.getLogger(__name__)
coloredlogs.install(
    fmt="%(asctime)s %(name)s[%(process)d] %(levelname)s %(message)s")


class Disassembler(ABC):
    '''
    Abstract Class for a Disassembler.
    '''

    class FailedToLoadBinary(Exception):
        '''Raise when a Disassembler fails to load a binary'''
        pass

    class ArchitectureNotSupported(Exception):
        '''Raise when a disassembler receives a binary of an architecture that it does not support'''
        pass

    def __init__(self, verbose=True):
        self.verbose = verbose

        self._bb_count = 0
        self._func_names: Dict[str, NativeFunction] = dict()
        self._func_addrs: Dict[int, NativeFunction] = dict()
        self._bbs: Dict[int, BasicBlock] = dict()
        self._instrs: Dict[int, Instruction] = dict()

    def __enter__(self):
        return self.open()

    def __exit__(self, type, value, tb):
        self.close()

    def name(self):
        '''Returns the Name of the Disassembler'''
        return self.__class__.__name__

    def load(self, path):
        '''
        Load a binary into the disassembler and trigger any default analysis
        :param path: The file path to binary to analyze
        '''
        logger.info(f"[{self.name()}] Analyzing {path}")
        self._binary_filepath = path

        start = time.time()
        success, err_msg = self.analyze(self._binary_filepath)
        if not success:
            raise Disassembler.FailedToLoadBinary(err_msg)
        logger.info(
            f"[{self.name()}] Analysis Complete: {time.time() - start:.2f}s")

        start = time.time()
        self._pre_normalize(path)
        self._create_binary()
        self._create_functions()
        self._post_normalize()
        logger.info(
            f"[{self.name()}] Parsing Complete: {time.time() - start:.2f}s")

    def _create_binary(self):
        start = time.time()

        sections = self.get_sections()
        self.binary = Binary(
            sections=sections,
            filename=os.path.basename(self._binary_filepath),
            names=[self.get_binary_name()],
            entrypoint=self.get_entry_point(),
            architecture=self.get_architecture(),
            endianness=self.get_endianness(),
            bitness=self.get_bitness(),
            base_addr=self.get_base_address(),
            dynamic_libs=self.get_dynamic_libs()
        )
        self.binary.set_path(self._binary_filepath)
        self.binary.set_disassembler(self)

        io_stream = self.binary.io()
        self.binary.strings |= set(
            self.get_strings(io_stream, len(self.binary)))
        io_stream.close()

        self.functions = set()

        logger.info(
            f"[{self.name()}] Binary Data Loaded: {time.time() - start:.2f}s")

    def _create_functions(self):
        start = time.time()

        count = 0
        for func_ctxt in self.get_func_iterator():
            addr = self.get_func_addr(func_ctxt)
            func_name = self.get_func_name(addr, func_ctxt)

            f = NativeFunction(
                endianness=self.binary.endianness,
                architecture=self.binary.architecture,
                bitness=self.binary.bitness,
                pie=self.binary.pie,
                canary=self.binary.canary,
                address=addr,
                names=[func_name],
                return_type=self.get_func_return_type(addr, func_ctxt),
                argv=self.get_func_args(addr, func_ctxt),
                thunk=self.is_func_thunk(addr, func_ctxt),
                stack_frame_size=self.get_func_stack_frame_size(
                    addr, func_ctxt),
                variables=[v for v in self.get_func_vars(addr, func_ctxt)]
            )
            f._binary = self.binary
            f._context = func_ctxt

            count += 1

            decompiled_code = self.get_func_decomp(addr, func_ctxt)

            dsrc = None
            if decompiled_code is not None:
                dsrc = SourceFunction.from_code(
                    fname=func_name,
                    source=decompiled_code,
                    is_decompiled=True
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
            self._create_basicblocks(addr, func_ctxt, f, xrefs.copy())
            self.functions.add(f)

            self._func_addrs[addr] = f
            self._func_names[func_name] = f

            if len(f.basic_blocks) > 0:
                f.end = set(
                    (bb for bb, out_degree in f.cfg.out_degree() if out_degree == 0))
            elif not f.thunk:
                logger.warn(
                    f"[{self.name()}] {func_name} @ {addr} has 0 Basic Blocks")

        # 2nd pass to do callee/callers
        for func_ctxt in self.get_func_iterator():
            addr = self.get_func_addr(func_ctxt)
            func_name = self.get_func_name(addr, func_ctxt)
            f = self._func_addrs[addr]

            f._callers = set()
            for caller_addr in self.get_func_callers(addr, func_ctxt):
                caller = self._func_addrs.get(caller_addr, None)
                if caller is not None:
                    f._callers.add(caller)

            f._calls = set()
            for callee_addr in self.get_func_callees(addr, func_ctxt):
                callee = self._func_addrs.get(callee_addr, None)
                if callee is not None:
                    f.calls.add(callee)

        run_time = time.time() - start
        logger.info(f"[{self.name()}] {self._bb_count} Basic Blocks Loaded")

        logger.info(f"[{self.name()}] {count} Functions Loaded")
        logger.info(f"[{self.name()}] Function Data Loaded: {run_time:.2f}s")
        logger.info(
            f"[{self.name()}] Ave Function Load Time: {run_time/count:.2f}s")

    def _create_basicblocks(self, addr: int, func_ctxt: Any, f: NativeFunction, xrefs: Set[Reference]):
        for bb_ctxt in self.get_func_bb_iterator(addr, func_ctxt):
            bb_addr = self.get_bb_addr(bb_ctxt, func_ctxt)

            self._bb_count += 1
            bb = BasicBlock(
                endianness=self.binary.endianness,
                architecture=self.binary.architecture,
                bitness=self.binary.bitness,
                pie=self.binary.pie,
                address=bb_addr
            )

            if bb_addr == f.address:
                f.start = bb

            for branch_data in self.get_next_bbs(bb_addr, bb_ctxt, addr, func_ctxt):
                bb.branches.add(branch_data)

            self._create_instructions(bb_addr, bb_ctxt, bb, func_ctxt)

            for xref in xrefs:
                if xref.from_ in bb or xref.to in bb:
                    bb.xrefs.add(xref)
            xrefs -= bb.xrefs

            f.basic_blocks.add(bb)
            bb.set_function(f)

            self._bbs[bb_addr] = bb

        if len(xrefs) > 0 and len(f.basic_blocks) > 0:
            logger.warn(
                f"[{self.name()}] {len(xrefs)} XRefs not in function: {xrefs}")

    def _create_instructions(self, bb_addr: int, bb_ctxt: Any, bb: BasicBlock, func_ctxt: Any):
        cur_addr = bb_addr
        for data, asm in self.get_bb_instructions(bb_addr, bb_ctxt, func_ctxt):
            instr = Instruction(
                endianness=self.binary.endianness,
                architecture=self.binary.architecture,
                bitness=self.binary.bitness,
                address=cur_addr,
                data=data,
                asm=asm,
                comment=self.get_instruction_comment(cur_addr)
            )
            ir = self.get_ir_from_instruction(cur_addr, instr)
            instr.ir = ir
            bb.instructions.append(instr)
            self._instrs[cur_addr] = instr

            cur_addr += len(data)

    def function_at(self, address: int) -> NativeFunction:
        '''Returns a Function at the address specified'''
        return self._func_addrs.get(address, None)

    def function_sym(self, symbol: str) -> NativeFunction:
        '''Returns a Function with the given symbol names'''
        return self._func_names.get(symbol, None)

    def basic_block(self, address: int) -> BasicBlock:
        '''Returns a basic block at the given address'''
        return self._bbs.get(address, None)

    def instruction(self, address: int) -> Instruction:
        '''Returns the instruction at the given address'''
        return self._instrs.get(address, None)

    ############################################
    # OPTIONAL DISASSEMBLER DEFINED OPERATIONS #
    ############################################

    @classmethod
    def list_versions(cls) -> List[str]:
        '''List installable verions of this disassembler'''
        return list()

    def _pre_normalize(self, path):
        '''
        Optional Function to Override. _pre_normalize is called before the the binary
        at `path` is loaded into the underlying disassembler. This function provides
        a way to add a custom preprocessing step.
        :param path: path to the binary that is about to be analyzed
        '''
        pass

    def _post_normalize(self):
        '''
        Optional Function to Override. _post_normalize is called after the the binary
        at `path` is loaded into the underlying disassembler. This function provides
        a way to add a custom postprocessing step.
        '''
        pass

    def open(self):
        '''Open up any resources'''
        return self

    def close(self):
        '''Release/Free up any resources'''
        pass

    def clear(self):
        '''Reset any state within this object'''
        self._bb_count = 0
        self._func_names.clear()
        self._func_addrs.clear()
        self._bbs.clear()
        self._instrs.clear()
        self.binary = None
        self.functions.clear()

    def get_strings(self, binary_io: IO) -> Iterable[str]:
        '''
        Returns the list of defined strings in the binary
        :param binary_io: a file-like object to the binary ingested
        :returns: list of strings in the file (similar to the strings unix utility)
        '''
        strings = list()
        printables = bytes(string.printable, 'ascii')

        buff = b""
        while True:
            chunk = binary_io.read(4096)
            if not chunk:
                break
            buff += chunk

            i = 0
            while len(buff) >= 5:
                while (buff[i] in printables):
                    i += 1

                if buff[i] == 0 and i > 3:
                    strings.append(buff[:i])
                    buff = buff[i+1:]
                else:
                    buff = buff[1:]
                i = 0

        return strings

    def get_sections(self) -> Iterable[Section]:
        '''
        Returns a list of the sections within the binary.
        Currently only supports sections within an ELF file.
        '''
        return list()

    def get_binary_name(self) -> str:
        '''Returns the name of the binary loaded'''
        return os.path.basename(self._binary_filepath)

    def get_func_decomp(self, addr: int, func_ctxt: Any) -> Optional[str]:
        '''Returns the decomplication of the function corresponding to the function information returned from `get_func_iterator()`'''
        return None

    def get_func_vars(self, addr: int, func_ctxt: Any) -> Iterable[Variable]:
        '''Return variables within the function corresponding to the function information returned from `get_func_iterator()`'''
        return list()

    def get_ir_from_instruction(self, instr_addr: int, instr: Instruction) -> Optional[IR]:
        '''
        Returns a list of Intermediate Representation data based on the instruction given
        '''
        return instr.vex()

    def get_instruction_comment(self, instr_addr: int) -> Optional[str]:
        '''Return comments at the instruction'''
        return None

    ############################################
    # REQUIRED DISASSEMBLER DEFINED OPERATIONS #
    ############################################

    @classmethod
    @abstractmethod
    def is_installed(cls) -> bool:
        '''Returns Boolean on whether or not the dissassembler is installed'''
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def install(cls, version: str = None, install_dir=None, build=False) -> str:
        '''
        Installs the disassembler to a user specified directory or within the python module if none is specified
        :returns: the directory the disassembler is installed to
        '''
        raise NotImplementedError

    @abstractmethod
    def analyze(self, path) -> bool:
        '''
        Loads the binary specified by `path` into the disassembler.
        Implement all diaassembler specific setup and trigger analysis here.
        :returns: True on success, false otherwise
        '''
        raise NotImplementedError

    @abstractmethod
    def get_entry_point(self) -> int:
        '''Returns the address of the entry point to the function'''
        raise NotImplementedError

    @abstractmethod
    def get_architecture(self) -> str:
        '''
        Returns the architecture of the binary.
        For best results use either archinfo, qemu, or compilation triplet naming conventions.
        https://github.com/angr/archinfo
        '''
        raise NotImplementedError

    @abstractmethod
    def get_endianness(self) -> Endian:
        '''Returns an Enum representing the Endianness'''
        raise NotImplementedError

    @abstractmethod
    def get_bitness(self) -> int:
        '''Returns the word size of the architecture (e.g., 16, 32, 64)'''
        raise NotImplementedError

    @abstractmethod
    def get_base_address(self) -> int:
        '''Returns the base address the binary is based at'''
        raise NotImplementedError

    @abstractmethod
    def get_dynamic_libs(self) -> Iterable[str]:
        '''Returns the list of names of the dynamic libraries used in this binary'''
        raise NotImplementedError

    @abstractmethod
    def get_func_iterator(self) -> Iterable[Any]:
        '''
        Returns an iterable of `Any` data type (e.g., address, interal func obj, dict of data) 
        needed to construct a `Function` object for all functions in the binary.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        raise NotImplementedError

    @abstractmethod
    def get_func_addr(self, func_ctxt: Any) -> int:
        '''Returns the address of the function corresponding to the function information returned from `get_func_iterator()`'''
        raise NotImplementedError

    @abstractmethod
    def get_func_name(self, addr: int, func_ctxt: Any) -> str:
        '''Returns the name of the function corresponding to the function information returned from `get_func_iterator()`'''
        raise NotImplementedError

    @abstractmethod
    def get_func_args(self, addr: int, func_ctxt: Any) -> List[Argument]:
        '''Returns the arguments in the function corresponding to the function information returned from `get_func_iterator()`'''
        raise NotImplementedError

    @abstractmethod
    def get_func_return_type(self, addr: int, func_ctxt: Any) -> int:
        '''Returns the return type of the function corresponding to the function information returned from `get_func_iterator()`'''
        raise NotImplementedError

    @abstractmethod
    def get_func_stack_frame_size(self, addr: int, func_ctxt: Any) -> int:
        '''Returns the size of the stack frame in the function corresponding to the function information returned from `get_func_iterator()`'''
        raise NotImplementedError

    @abstractmethod
    def is_func_thunk(self, addr: int, func_ctxt: Any) -> bool:
        '''Returns True if the function corresponding to the function information returned from `get_func_iterator()` is a thunk'''
        raise NotImplementedError

    @abstractmethod
    def get_func_callers(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        '''Return the address to functions that call func_ctxt'''
        raise NotImplementedError

    @abstractmethod
    def get_func_callees(self, addr: int, func_ctxt: Any) -> Iterable[int]:
        '''Return the address to functions that are called in func_ctxt'''
        raise NotImplementedError

    @abstractmethod
    def get_func_xrefs(self, addr: int, func_ctxt: Any) -> Iterable[Reference]:
        '''Returns an iterable of references within a function'''
        raise NotImplementedError

    @abstractmethod
    def get_func_bb_iterator(self, addr: int, func_ctxt: Any) -> Iterable[Any]:
        '''
        Returns an iterator of `Any` data type (e.g., address, implementation specific basic block information, dict of data)
        needed to construct a `BasicBlock` object for all basic blocks in the function based on function information returned from `get_func_iterator()`.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        raise NotImplementedError

    @abstractmethod
    def get_bb_addr(self, bb_ctxt: Any, func_ctxt: Any) -> int:
        '''
        Returns the address of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        raise NotImplementedError

    @abstractmethod
    def get_next_bbs(self, bb_addr: int, bb_ctxt: Any, func_addr: int, func_ctxt: Any) -> Iterable[Branch]:
        '''
        Returns the Branching information of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        raise NotImplementedError

    @abstractmethod
    def get_bb_instructions(self, bb_addr: int, bb_ctxt: Any, func_ctxt: Any) -> List[Tuple(bytes, str)]:
        '''
        Returns a iterable of tuples of raw instruction bytes and corresponding mnemonic from the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        raise NotImplementedError
