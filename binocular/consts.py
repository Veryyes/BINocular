from enum import Enum

class Endian(Enum):
    LITTLE = 0
    BIG = 1
    OTHER = 2

class BranchType(Enum):
    TrueBranch = 0
    FalseBranch = 1
    UnconditionalBranch = 2
    IndirectBranch = 3

class IL(Enum):
    VEX = 0
    ESIL = 1
    PCODE = 2

class RefType(Enum):
    UNKNOWN = 0
    # Normal Branch
    JUMP = 1 
    # Function Call
    CALL = 2
    # Read Data
    READ = 3
    # Write Data
    WRITE = 4
    # Read or Write (Disassembler doesn't say which) 
    DATA = 5
    

class IndirectToken:
    '''A Token to represent a Dynamically Determined Value'''
    pass

# Not an ENUM; Just Macros
X86 = "x86"
ARM = "ARM"
MIPS = "MIPS"
PPC = "PowerPC"