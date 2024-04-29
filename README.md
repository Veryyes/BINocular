# BINocular - Common Binary Framework

## Features
 - Abstraction Layer between Disassemblers (e.g., Ghidra, Binary Ninja, Radare2/Rizin, IDA, and even objdump)
 - Common Language and Representation of Binary Analysis Concepts
   - Instructions
   - Binary Blobs
   - Functions
   - Traces & Execution Paths
   - Control Flow Graphs
   - Entire Programs
   
### Treat Binary Analysis Concepts as data (In relation to other objects or standalone)  
 - Serialization/Deserialization
 - Persistent Storage to a Database
 - Common API to query information (e.g., Get all Functions in a Binary)
   - "Hot Swappable" Disassembler Backends (e.g., Ask Ghidra and Binja for the same data w/ minimal code)
 - Common API for analysis (instruction frequency count, cyclomatic complexity of CFG, string table)

### Compare Results across Disassemblers 
- Assess which IL is best for a specific task (e.g., Pcode or Binja-IL for Function Diffing?)

# Example Usage

```python
from sqlalchemy.orm import Session

from binocular import Ghidra, Backend

Backend.set_engine('sqlite:////home/brandon/Documents/BINocular/example.db')

with Ghidra() as g:
    assert g.is_installed()
    g.load("/bin/ls")
    
    b = g.binary
    print(b.architecture)

    with Session(Backend.engine) as s:
        b.db_add(s)
        s.commit()
```