import coloredlogs
import logging
logger = logging.getLogger("BINocular")
logger.addHandler(logging.FileHandler("logs.txt"))
coloredlogs.install(
    fmt="%(asctime)s %(name)s[%(process)d] %(levelname)s %(message)s")

from .primitives import (
    Argument,
    Branch,
    IR,
    Instruction,
    BasicBlock,
    NativeFunction,
    SourceFunction,
    Binary,
    Variable
)

from .consts import (
    Endian,
    BranchType,
    IL,
    IndirectToken
)

from .ghidra import Ghidra
from .rizin import Rizin
from .disassembler import Disassembler, Backend

__all__ = [
    "Argument",
    "Branch",
    "IR",
    "Backend",
    "Instruction",
    "BasicBlock",
    "NativeFunction",
    "SourceFunction",
    "Binary",
    "Ghidra",
    "Rizin",
    "Disassembler",
    "Endian",
    "BranchType",
    "IL",
    "Variable",
    "IndirectToken",
]
