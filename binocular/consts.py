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
    ESIL = 0

# Not an ENUM; Just Macros
X86 = "x86"
ARM = "ARM"
MIPS = "MIPS"
PPC = "PowerPC"