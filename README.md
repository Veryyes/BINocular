# BINocular - Common Binary Framework

## Features
 - Abstraction Layer between Disassemblers (e.g., Ghidra, Binary Ninja, Radare2/Rizin, IDA)
 - Programatically Install Disassemblers or throught command line
 - Common Language and Representation of Binary Analysis Concepts
   - [ ] Common Executable Formats
     * [ ] ELF
     * [ ] PE
     * [ ] Mach-O
   - [x] Instructions
   - [x] Intermediate Representations (e.g., pcode)
   - [ ] Binary Blobs (e.g., flash dump)
   - [x] Functions
     * [x] Compiled (Native) Functions
     * [x] Source Code
   - [ ] Traces & Execution Paths
   - [x] Control Flow Graphs
   - [ ] Data Flow Graphs
   
### Treat Binary Analysis Concepts as data (In relation to other objects or standalone)  
 - Serialization/Deserialization
 - Persistent Storage to a Database
 - Common API to query information (e.g., Get all Functions in a Binary)
   - "Hot Swappable" Disassembler Backends (e.g., Ask Ghidra and Binja for the same data w/ minimal code)
 - Common API for analysis (instruction frequency count, cyclomatic complexity of CFG, string table)

## Installation
Install the python package using `setup.py`

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


```python
from sqlalchemy.orm import Session
from binocular import Ghidra, Backend, FunctionSource

Backend.set_engine('sqlite:////home/brandon/Documents/BINocular/example.db')

install_dir = "./test_install"
if not Ghidra.is_installed(install_dir=install_dir):
    # Install Ghidra @ commit dee48e9 if Ghidra isn't installed already
    # This make take a while since it does build Ghidra from scratch
    Ghidra.install(version='dee48e9', install_dir=install_dir, build=True)

with Ghidra(home=install_dir) as g:
    g.load("./test/example")
    b = g.binary
    
    for f in b.functions:
        name = f.names[0]

        # Auto parse the source code and associate the functions within 
        # the source to the parsed functions that Ghidra has found
        src = FunctionSource.from_file(name, './test/example.c')
        if src is not None:
            f.sources.add(src)

        # If f calls itself (i.e. f is recursive) then print the function name
        if f in f.calls:
            print(f.names[0])

    # Load the entire binary to the database set in line 4
    with Session(Backend.engine) as s:
        b.db_add(s)
        s.commit()

```
