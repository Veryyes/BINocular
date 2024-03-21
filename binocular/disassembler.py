from __future__ import annotations

from abc import ABC, abstractmethod

from .primitives import Binary

# This will be constantly changing until we have a few examples in
class Disassembler(ABC):
    class FailedToLoadBinary(Exception):
        pass
    class ArchitectureNotSupported(Exception):
        pass

    @abstractmethod
    def is_installed(self) -> bool:
        '''Returns Boolean on whether or not the dissassembler is installed'''
        raise NotImplementedError

    @abstractmethod
    def install(self, install_dir=None):
        '''Installs the disassembler to a user specified directory or within the python module if none is specified'''
        raise NotImplementedError

    # @abstractmethod
    # def launch(self):
    #     raise NotImplementedError

    @abstractmethod
    def load_binary(self, path) -> Binary:
        '''Load a binary into the disassembler and trigger any default analysis'''
        raise NotImplementedError


    ############
    # FUNCTIONS #
    ############

    @abstractmethod
    def function(self, address:int):
        raise NotImplementedError

    @abstractmethod
    def function_sym(self, symbol:str):
        raise NotImplementedError

    @abstractmethod
    def functions(self):
        raise NotImplementedError

