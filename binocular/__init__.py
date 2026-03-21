import logging

import coloredlogs  # type: ignore[import-untyped]

logger = logging.getLogger("BINocular")
coloredlogs.install(
    logger=logger,
    fmt="%(asctime)s %(name)s[%(process)d] %(levelname)s %(message)s",
    level=logging.DEBUG,
)

from .consts import IL, BranchType, Endian, IndirectToken
from .disassembler import Disassembler
from .ghidra_impl.legacy import GhidraLegacy  # Ghidra < 12.0.0
from .ghidra_impl.dragon import Ghidra  # Ghidra >= 12.0.0
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
    "Instruction",
    "BasicBlock",
    "NativeFunction",
    "SourceFunction",
    "Binary",
    "GhidraLegacy",
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
