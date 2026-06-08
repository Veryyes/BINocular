import logging

import coloredlogs  # type: ignore[import-untyped]

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
    ClassInfo,
    Instruction,
    NativeFunction,
    Reference,
    SourceFunction,
    Variable,
    VTableEntry,
)
from .rizin import Rizin
from .binja import BinaryNinja

logger = logging.getLogger("BINocular")
coloredlogs.install(
    logger=logger,
    fmt="%(asctime)s %(name)s[%(process)d] %(levelname)s %(message)s",
    level=logging.DEBUG,
)

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
    "BinaryNinja",
    "Disassembler",
    "Endian",
    "BranchType",
    "IL",
    "Variable",
    "IndirectToken",
    "Reference",
    "ClassInfo",
    "VTableEntry",
]
