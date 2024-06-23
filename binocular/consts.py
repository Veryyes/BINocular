from enum import Enum


class Endian(Enum):
    '''Enumeration of Endianness'''
    LITTLE = 0
    BIG = 1
    OTHER = 2


class BranchType(Enum):
    '''Enumeration of different types of Code Branching'''
    TrueBranch = 0
    FalseBranch = 1
    UnconditionalBranch = 2
    IndirectBranch = 3


class IL(Enum):
    '''Enumeration of supported Intermediate Languages'''
    VEX = 0
    ESIL = 1
    PCODE = 2


class RefType(Enum):
    '''Enumeration of different types of references'''

    UNKNOWN = 0
    '''Unknown type of Reference'''

    JUMP = 1
    '''Reference to a normal Branch'''

    CALL = 2
    '''Reference to a Function Call'''

    READ = 3
    '''Reference to a Memory Read'''

    WRITE = 4
    '''Reference to a Memory Write'''

    DATA = 5
    '''Reference to either a Memory Read or Write'''


class IndirectToken:
    '''A Token to represent a Dynamically Determined Value'''
    pass


# Not an ENUM; Just Macros
X86 = "x86"
ARM = "ARM"
MIPS = "MIPS"
PPC = "PowerPC"
