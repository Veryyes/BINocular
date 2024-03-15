from enum import Enum

class Endian(Enum):
    LITTLE = 0
    BIG = 1

# Not an ENUM; Just Macros
X86 = "x86"
ARM = "ARM"
MIPS = "MIPS"
PPC = "PowerPC"