from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from .primitives import Function, Binary, BasicBlock, Instruction

# This will be constantly changing until we have a few examples in
class Disassembler(ABC):
    class FailedToLoadBinary(Exception):
        pass
    class ArchitectureNotSupported(Exception):
        pass

    def __enter__(self):
        return self.open()

    def __exit__(self, type, value, tb):
        self.close()

    def open(self):
        return self

    def close(self):
        pass

    @abstractmethod
    def is_installed(self) -> bool:
        '''Returns Boolean on whether or not the dissassembler is installed'''
        raise NotImplementedError

    @abstractmethod
    def install(self, install_dir=None):
        '''Installs the disassembler to a user specified directory or within the python module if none is specified'''
        raise NotImplementedError

    @abstractmethod
    def load(self, path):
        '''Load a binary into the disassembler and trigger any default analysis'''
        raise NotImplementedError

    @abstractmethod
    def binary(self) -> Binary:
        '''Returns a Binary object of the loaded binary'''
        raise NotImplementedError


    ############
    # FUNCTIONS #
    ############

    @abstractmethod
    def function(self, address:int) -> Function:
        '''Returns a Function at the address specified'''
        raise NotImplementedError

    @abstractmethod
    def function_sym(self, symbol:str) -> Function:
        '''Returns a Function with the given symbol names'''
        raise NotImplementedError

    @abstractmethod
    def functions(self) -> Iterable[Function]:
        '''Returns an iterator of all Functions'''
        raise NotImplementedError

    ################
    # Basic Blocks #
    ################

    @abstractmethod
    def basic_block(self, address:int) -> BasicBlock:
        '''Returns a basic block at the given address'''
        raise NotImplementedError

    ################
    # Instructions #
    ################

    @abstractmethod
    def instruction(self, address:int) -> Instruction:
        '''Returns the instruction at the given address'''
        raise NotImplementedError