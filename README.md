<p align="center">
	<img src="./imgs/BINocular-logo-background.svg" width=30% height=30%>
</p>

# BINocular - Common Binary Analysis Framework

![Static Badge](https://img.shields.io/badge/Version-1.1-navy) 
![Static Badge](https://img.shields.io/badge/license-GPLv3-green) 
![Static Badge](https://img.shields.io/badge/Python-3.10-blue)

![Static Badge](https://img.shields.io/badge/Disassembler-Rizin-yellow)
![Static Badge](https://img.shields.io/badge/Disassembler-Ghidra-red)

BINocular is an python package for static analysis of compiled binaries 
through a common API layer. It is an abstraction layer between different
disassemblers and provides:

- Disassembler Agnostic Representation of Common Binary Analysis Primitives and Concepts
  * Assembly Instructions
  * Intermediate Representations (e.g., pcode)
  * Functions
    - Compiled
    - Source
  * Control Flow Graph
- CLI and API to install supported disassemblers
- Serialization/Deserialization of concepts (e.g., Functions, Basic Blocks, Instructions)
- Persistent storage of objects to SQL databases

## Disassembler Backend Support
### [Ghidra](https://www.ghidra-sre.org/)
### [Rizin](https://rizin.re/)

## Installation
`pip install BINocular`

## Example CLI Usage
**List Avaliable Ghidra Versions to Install**
```shell
$ binocular install ghidra -l 
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
```

**Install Ghidra from Command Line**
```shell
$ binocular install ghidra -v 11.1 -p ~/Documents/ghidra_install_location
2024-06-15 13:41:04 binocular.ghidra[472653] INFO Installing Ghidra 11.1 to /home/brandon/Documents/ghidra_install_location
2024-06-15 13:41:27 binocular.ghidra[472653] INFO Extracting Ghidra
2024-06-15 13:41:31 pyhidra.javac[472653] INFO WARNING
2024-06-15 13:41:32 pyhidra.launcher[472653] INFO Installed plugin: pyhidra 1.1.0
```

**Parse a Binary and load it to a SQLite Database**
```shell
$ binocular parse ./test/example rizin --uri sqlite:///$(pwd)/example.db
2024-06-15 13:46:23 binocular.disassembler[473064] INFO [Rizin] Analyzing test/example
2024-06-15 13:46:23 binocular.disassembler[473064] INFO [Rizin] Analysis Complete: 0.03s
2024-06-15 13:46:23 binocular.disassembler[473064] INFO [Rizin] Binary Data Loaded: 0.00s
2024-06-15 13:46:25 binocular.disassembler[473064] INFO [Rizin] 49 Basic Blocks Loaded
2024-06-15 13:46:25 binocular.disassembler[473064] INFO [Rizin] 18 Functions Loaded
2024-06-15 13:46:25 binocular.disassembler[473064] INFO [Rizin] Function Data Loaded: 2.26s
2024-06-15 13:46:25 binocular.disassembler[473064] INFO [Rizin] Ave Function Load Time: 0.13s
2024-06-15 13:46:25 binocular.disassembler[473064] INFO [Rizin] Parsing Complete: 2.26s
Binary:
	Name: example
	Arch: x86
	Bits: 64
	Endian: Endian.LITTLE
	SHA256: a7f9141c1781c20d13b8442f24fcddba4b75b4b73ae04e734a92a79fcf0869c3
	Size: 18088
	Num Functions: 18
Inserting to DB
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

with Ghidra() as g:
    g.load("./test/example")
    b = g.binary
    
    f = g.function_sym("fib")
    bb = list(f.basic_blocks)[0]
    print(bb.model_dump_json())
```

**Output (After piped to jq)**
```json
{
  "endianness": 0,
  "architecture": "x86",
  "bitness": 64,
  "address": 1053275,
  "pie": 3,
  "instructions": [
    {
      "endianness": 0,
      "architecture": "x86",
      "bitness": 64,
      "address": 1053275,
      "data": "837dec01",
      "asm": "CMP",
      "comment": "",
      "ir": {
        "lang_name": 2,
        "data": "(unique, 0x4400, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffec, 8);(unique, 0xdb00, 4) LOAD (const, 0x1b1, 4) , (unique, 0x4400, 8);(unique, 0x27600, 4) COPY (unique, 0xdb00, 4);(register, 0x200, 1) INT_LESS (unique, 0x27600, 4) , (const, 0x1, 4);(register, 0x20b, 1) INT_SBORROW (unique, 0x27600, 4) , (const, 0x1, 4);(unique, 0x27700, 4) INT_SUB (unique, 0x27600, 4) , (const, 0x1, 4);(register, 0x207, 1) INT_SLESS (unique, 0x27700, 4) , (const, 0x0, 4);(register, 0x206, 1) INT_EQUAL (unique, 0x27700, 4) , (const, 0x0, 4);(unique, 0x15080, 4) INT_AND (unique, 0x27700, 4) , (const, 0xff, 4);(unique, 0x15100, 1) POPCOUNT (unique, 0x15080, 4);(unique, 0x15180, 1) INT_AND (unique, 0x15100, 1) , (const, 0x1, 1);(register, 0x202, 1) INT_EQUAL (unique, 0x15180, 1) , (const, 0x0, 1)"
      }
    },
    {
      "endianness": 0,
      "architecture": "x86",
      "bitness": 64,
      "address": 1053279,
      "data": "7507",
      "asm": "JNZ",
      "comment": "",
      "ir": {
        "lang_name": 2,
        "data": "(unique, 0xe480, 1) BOOL_NEGATE (register, 0x206, 1); ---  CBRANCH (ram, 0x101268, 8) , (unique, 0xe480, 1)"
      }
    }
  ],
  "branches": [
    {
      "btype": 1,
      "target": 1053288
    },
    {
      "btype": 1,
      "target": 1053281
    }
  ],
  "is_prologue": false,
  "is_epilogue": false,
  "xrefs": [
    {
      "from_": 1053279,
      "to": 1053288,
      "type": 1
    }
  ]
}
```

### Loading a Binary In and Upload to a Database
Each primitive has a corresponding [SQLAlchemy](https://www.sqlalchemy.org/) ORM class that is suffixed with "ORM". (e.g. `NativeFunctionORM`, `BinaryORM`). 

```python
from sqlalchemy.orm import Session
from binocular import Ghidra, Backend, FunctionSource

Backend.set_engine('sqlite:////home/brandon/Documents/BINocular/example.db')

# If no install_dir parameter is specified, it will use the baked in default path (inside the python package itself)
with Ghidra() as g:
    g.load("./test/example")
    b = g.binary
    
    for f in b.functions:
        name = f.names[0]

        # Auto parse the source code and associate the functions within 
        # the source to the parsed functions that Ghidra has found
        src = FunctionSource.from_file(name, './test/example.c')
        if src is not None:
            f.sources.add(src)

    # Load the entire binary to the database set in line 4
    with Session(Backend.engine) as s:
        b.db_add(s)
        s.commit()

```

### Querying Data from a Database
This is an example of querying a binary by name. This is all SQL/SQLAlchemy so make whatever queries you want.

Use the `.from_orm()` function to lift the ORM object back to a Pydantic BaseModel object
```python
from sqlalchemy import select
from sqlalchemy.orm import Session
from binocular import Backend, Binary
from binocular.db import BinaryORM, NameORM

Backend.set_engine('sqlite:////home/brandon/Documents/BINocular/example.db')

with Session(Backend.engine) as session:
    # Select a binary whoes file name has been "example"
    binary = session.execute(
        select(BinaryORM).join(NameORM, BinaryORM.names).where(NameORM.name == 'example')
    ).all()
    binary = [b[0] for b in binary][0]

    # Convert the BinaryORM object to a Binary Object
    # and get all its functions
    funcs = Binary.from_orm(binary).functions
    print(f"example has {len(funcs)} functions")
```
