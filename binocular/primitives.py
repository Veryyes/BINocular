from __future__ import annotations
from typing import List, Union, Dict, Set
from functools import cached_property

import networkx as nx
from pydantic import BaseModel, computed_field
from pydantic.dataclasses import dataclass

from .consts import Endian

# TODO is there a better way represent contextual information
# This sort of data in a database is usually represented as mappings/pivot tables
# But We want to be able to represent these things as standalone or in context to other things

# Could just make all these properties
@dataclass
class Context(BaseModel):
    # Functions #

    # The address of an instruction/basic block/function are relative to the binary it's in
    address: int

    # Binary #

    # These attributes depend on the hw architecture running the code
    # Generally they are tied to the binary
    endianness: Endian
    architecture: str
    bitness: int

class Contextable(BaseModel):
    _context:Context

    def context(self):
        if isinstance(self._context, Context):
            return self._context
        return self._context.context()

class Instruction(Contextable):
    _context:Union[Context, BasicBlock] = None

    data: bytes
    opcode: str
    operands: List[str]

    def __repr__(self):
        raise NotImplementedError

    def __len__(self):
        return len(self.data)
    
    def __eq__(self, other:Instruction):
        return self.data == other.data
    
    def __hash__(self):
        return hash(self.data)
    
    def __contains__(self, x:bytes):
        return x in self.data


class BasicBlock(Contextable):
    _context:Union[Context, Function] = None

    instructions: List[Instruction]
    is_prologue: bool
    is_epilogue: bool
    _size_bytes: int = None

    def __repr__(self):
        raise NotImplementedError

    def __hash__(self):
        raise hash(self.bytes)

    def __len__(self):
        if self._size_bytes is None:
            self._size_bytes = sum([len(i) for i in self.instructions])            
        return self._size_bytes

    def __contains__(self, x:Union[Instruction, bytes]):
        if isinstance(x, Instruction):
            return x in self.instructions
        elif isinstance(x, bytes):
            return x in self.bytes
        raise TypeError

    @cached_property
    def bytes(self) -> bytes:
        b = b''
        for instr in self.instructions:
            b += instr.data
        return b

    def num_instructions(self):
        return len(self.instructions)

class Function(Contextable):
    _context:Union[Context, Binary] = None

    basic_blocks: Set[BasicBlock]

    def __repr__(self):
        raise NotImplementedError

    def __hash__(self):
        raise NotImplementedError
    
    def __contains__(self, x:Union[BasicBlock, Instruction, bytes]):
        raise NotImplementedError

    # Note: Better to just recalculate this after deserialization
    # We don't have to do any hard analysis of figuring out where jumps/xrefs go
    # because that is assuming already done and stored in this object
    #
    # Should just we reconstructing the Graph Obj and not extra analysis
    @cached_property
    def cfg(self) -> nx.MultiDiGraph:
        raise NotImplementedError

class Binary(Contextable):
    '''
    This maps 1 to 1 of what you'd load into a disassembler (e.g., ELF, PE, MACH-O, Firmware Dump, Binary Blob)
    '''
    dynamic_libs:Set[Binary]

    def __repr__(self):
        raise NotImplementedError
    
    def __hash__(self):
        return int(self.sha256, 16)
    
    def __contains__(self, x:Union[Function, BasicBlock, Instruction, bytes]):
        raise NotImplementedError

    @computed_field(repr=False)
    @cached_property
    def sha256(self) -> str:
        '''sha256 hex digest of the file'''
        raise NotImplementedError
