import logging

import coloredlogs  # type: ignore[import-untyped]

logger = logging.getLogger("BINocular")
logger.addHandler(logging.FileHandler("logs.txt"))
coloredlogs.install(fmt="%(asctime)s %(name)s[%(process)d] %(levelname)s %(message)s")

from .consts import IL, BranchType, Endian, IndirectToken
from .disassembler import Backend, Disassembler
from .ghidra import Ghidra
from .primitives import (
    IR,
    Argument,
    BasicBlock,
    Binary,
    Branch,
    Instruction,
    NativeFunction,
    Reference,
    SourceFunction,
    Variable,
)
from .rizin import Rizin

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
    "Reference",
]
