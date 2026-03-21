<p align="center">
	<img src="./imgs/BINocular-logo-background.svg" width=30% height=30%>
</p>

# BINocular - Common Binary Analysis Framework

![Static Badge](https://img.shields.io/badge/Version-1.1-navy) 
![Static Badge](https://img.shields.io/badge/license-GPLv3-green) 
![Static Badge](https://img.shields.io/badge/Python-3.10-blue)

![Static Badge](https://img.shields.io/badge/Disassembler-Rizin-yellow)
![Static Badge](https://img.shields.io/badge/Disassembler-Ghidra-red)

BINocular is a disassembler agnostic binary analysis framework written in python. It provides an common abstraction layer between different disassemblers.

Features Include: 
- Disassembler Agnostic Representation of Common Binary Analysis Primitives and Concepts
  * Assembly Instructions
  * Intermediate Representations (e.g., pcode)
  * Functions
    - Compiled
    - Source
  * Control Flow Graph
- CLI and API to install supported disassemblers
- Serialization/Deserialization of concepts (e.g., Functions, Basic Blocks, Instructions)

## Disassembler Backend Support
### [Ghidra](https://www.ghidra-sre.org/)
### [Rizin](https://rizin.re/)

## Installation
`pip install BINocular`

## Example CLI Usage
**List Avaliable Ghidra Versions to Install**
```shell
$ binocular install ghidra -l 
12.0.4
12.0.3
12.0.2
12.0.1
12.0
11.4.3
11.4.2
11.4.1
11.4
11.3.2
11.3.1
11.3
11.2.1
11.2
11.1.2
11.1.1
11.1
11.0.3
11.0.2
11.0.1
11.0
10.4
10.3.3
10.3.2
10.3.1
10.3
10.2.3
10.2.2
10.2.1
10.2
```

**Install Ghidra from Command Line**
```shell
$ binocular install ghidra -v 12.0.1
2026-03-21 01:53:04 BINocular[336690] INFO Installing Ghidra 12.0.1 to /home/brandon/Documents/DaSH/compiler_wiz/angha/BINocular/binocular/data/ghidra
2026-03-21 01:53:04 BINocular[336690] INFO Downloading https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.1_build/ghidra_12.0.1_PUBLIC_20260114.zip...
2026-03-21 01:53:24 BINocular[336690] INFO Extracting Ghidra
2026-03-21 01:54:21 BINocular[336690] INFO Ghidra Install Completed
```

**Install Rizin from Command Line**
```shell
$ binocular install rizin
2026-03-21 01:53:25 BINocular[337174] INFO Installing Rizin
2026-03-21 01:53:25 BINocular[337174] INFO Installing Rizin v0.8.2 to /home/brandon/Documents/DaSH/compiler_wiz/angha/BINocular/binocular/data/rizin
2026-03-21 01:53:25 BINocular[337174] INFO Downloading https://github.com/rizinorg/rizin/releases/download/v0.8.2/rizin-v0.8.2-static-x86_64.tar.xz...
2026-03-21 01:54:33 BINocular[337174] INFO Rizin Install Completed
```

## Example Python Usage

### Installing Ghidra at commit `dee48e9`

This makes the assumption you already have all the build dependencies to build Ghidra (same goes for other disassemblers).
```python
from binocular import Ghidra

install_dir = "./test_install"
if not Ghidra.is_installed(install_dir=install_dir):
    # Install Ghidra @ commit dee48e9 if Ghidra isn't installed already
    # This make take a while since it does build Ghidra from scratch
    Ghidra.install(version='dee48e9', install_dir=install_dir, build=True)
```

### Serializing Objects
All the basic primitives such as `Instruction`, `Basic Block`, and `NativeFunction` are all built on top of [Pydantic](https://docs.pydantic.dev/latest/) with python type hinting. This means we get all the benefits of pydantic like type validation and json serialization.


```python
from binocular import Ghidra

with Ghidra("./test/example") as g:
    g.analyze()
    b = g.binary
    
    f = b.function_sym("fib")
    bb = list(f.basic_blocks)[0]
    print(bb.model_dump_json())
```

**Output (After piped to jq)**
```json
{
  "endianness": 0,
  "architecture": "x86",
  "bitness": 64,
  "address": 1053246,
  "instructions": [
    {
      "endianness": 0,
      "architecture": "x86",
      "bitness": 64,
      "address": 1053246,
      "data": "f30f1efa",
      "asm": "ENDBR64",
      "comment": "",
      "ir": {
        "lang_name": 2,
        "data": ""
      }
    },
    {
      "endianness": 0,
      "architecture": "x86",
      "bitness": 64,
      "address": 1053250,
      "data": "55",
      "asm": "PUSH",
      "comment": "",
      "ir": {
        "lang_name": 2,
        "data": "(unique, 0x4f900, 8) COPY (register, 0x28, 8);(register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x8, 8); ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (unique, 0x4f900, 8)"
      }
    },
    {
      "endianness": 0,
      "architecture": "x86",
      "bitness": 64,
      "address": 1053251,
      "data": "4889e5",
      "asm": "MOV",
      "comment": "",
      "ir": {
        "lang_name": 2,
        "data": "(register, 0x28, 8) COPY (register, 0x20, 8)"
      }
    },
    {
      "endianness": 0,
      "architecture": "x86",
      "bitness": 64,
      "address": 1053254,
      "data": "53",
      "asm": "PUSH",
      "comment": "",
      "ir": {
        "lang_name": 2,
        "data": "(unique, 0x4f900, 8) COPY (register, 0x18, 8);(register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x8, 8); ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (unique, 0x4f900, 8)"
      }
    },
    {
      "endianness": 0,
      "architecture": "x86",
      "bitness": 64,
      "address": 1053255,
      "data": "4883ec18",
      "asm": "SUB",
      "comment": "",
      "ir": {
        "lang_name": 2,
        "data": "(register, 0x200, 1) INT_LESS (register, 0x20, 8) , (const, 0x18, 8);(register, 0x20b, 1) INT_SBORROW (register, 0x20, 8) , (const, 0x18, 8);(register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x18, 8);(register, 0x207, 1) INT_SLESS (register, 0x20, 8) , (const, 0x0, 8);(register, 0x206, 1) INT_EQUAL (register, 0x20, 8) , (const, 0x0, 8);(unique, 0x58300, 8) INT_AND (register, 0x20, 8) , (const, 0xff, 8);(unique, 0x58400, 1) POPCOUNT (unique, 0x58300, 8);(unique, 0x58500, 1) INT_AND (unique, 0x58400, 1) , (const, 0x1, 1);(register, 0x202, 1) INT_EQUAL (unique, 0x58500, 1) , (const, 0x0, 1)"
      }
    },
    {
      "endianness": 0,
      "architecture": "x86",
      "bitness": 64,
      "address": 1053259,
      "data": "897dec",
      "asm": "MOV",
      "comment": "",
      "ir": {
        "lang_name": 2,
        "data": "(unique, 0x8f00, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffec, 8);(unique, 0xd400, 4) COPY (register, 0x38, 4); ---  STORE (const, 0x1b1, 4) , (unique, 0x8f00, 8) , (unique, 0xd400, 4)"
      }
    },
    {
      "endianness": 0,
      "architecture": "x86",
      "bitness": 64,
      "address": 1053262,
      "data": "837dec00",
      "asm": "CMP",
      "comment": "",
      "ir": {
        "lang_name": 2,
        "data": "(unique, 0x8f00, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffec, 8);(unique, 0x23d00, 4) LOAD (const, 0x1b1, 4) , (unique, 0x8f00, 8);(unique, 0x7d100, 4) COPY (unique, 0x23d00, 4);(register, 0x200, 1) INT_LESS (unique, 0x7d100, 4) , (const, 0x0, 4);(register, 0x20b, 1) INT_SBORROW (unique, 0x7d100, 4) , (const, 0x0, 4);(unique, 0x7d300, 4) INT_SUB (unique, 0x7d100, 4) , (const, 0x0, 4);(register, 0x207, 1) INT_SLESS (unique, 0x7d300, 4) , (const, 0x0, 4);(register, 0x206, 1) INT_EQUAL (unique, 0x7d300, 4) , (const, 0x0, 4);(unique, 0x58300, 4) INT_AND (unique, 0x7d300, 4) , (const, 0xff, 4);(unique, 0x58400, 1) POPCOUNT (unique, 0x58300, 4);(unique, 0x58500, 1) INT_AND (unique, 0x58400, 1) , (const, 0x1, 1);(register, 0x202, 1) INT_EQUAL (unique, 0x58500, 1) , (const, 0x0, 1)"
      }
    },
    {
      "endianness": 0,
      "architecture": "x86",
      "bitness": 64,
      "address": 1053266,
      "data": "7507",
      "asm": "JNZ",
      "comment": "",
      "ir": {
        "lang_name": 2,
        "data": "(unique, 0x24f00, 1) BOOL_NEGATE (register, 0x206, 1); ---  CBRANCH (ram, 0x10125b, 8) , (unique, 0x24f00, 1)"
      }
    }
  ],
  "branches": [
    {
      "type": 1,
      "target": 1053268
    },
    {
      "type": 1,
      "target": 1053275
    }
  ],
  "is_prologue": false,
  "is_epilogue": false,
  "xrefs": [
    {
      "from_": 1053266,
      "to": 1053275,
      "type": 1
    },
    {
      "from_": 1053447,
      "to": 1053246,
      "type": 2
    },
    {
      "from_": 1057112,
      "to": 1053246,
      "type": 0
    },
    {
      "from_": 0,
      "to": 1053246,
      "type": 0
    },
    {
      "from_": 1053296,
      "to": 1053246,
      "type": 2
    },
    {
      "from_": 1053259,
      "to": -28,
      "type": 4
    },
    {
      "from_": 1056888,
      "to": 1053246,
      "type": 0
    },
    {
      "from_": 1053262,
      "to": -28,
      "type": 3
    },
    {
      "from_": 1053311,
      "to": 1053246,
      "type": 2
    }
  ]
}

```