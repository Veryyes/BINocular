import os
from enum import Enum
from pathlib import Path
from typing_extensions import Annotated
import string

import typer
from sqlalchemy.orm import Session
from binocular import Backend, Ghidra, Rizin

app = typer.Typer()

class DisassemblerChoice(Enum):
    rizin = "rizin"
    ghidra = "ghidra"

@app.command()
def parse(
    p: Annotated[Path, typer.Argument(help="Path to Binary")],
    d: Annotated[DisassemblerChoice, typer.Argument(help="Disassembler")],
    uri: Annotated[str, typer.Option('-u', '--uri', help="SQL database URI")] = None,
    quiet: Annotated[bool, typer.Option('-q', '--quiet', help="")] = False
):
    disasm_type = None
    if d == DisassemblerChoice.rizin:
        disasm_type = Rizin
    elif d == DisassemblerChoice.ghidra:
        disasm_type = Ghidra
    else:
        raise ValueError("Not a supported Disassembler")

    if not os.path.exists(p) or os.path.isdir(p):
        raise ValueError(f"Invalid File: {p}")

    if uri is not None:
        Backend.set_engine(uri)

    if not disasm_type.is_installed():
        disasm_type.install()

    with disasm_type() as disasm:
        disasm.load(p)
        b = disasm.binary
        if not quiet:
            print("Binary:")
            print(f"\tName: {b.names[0]}")
            print(f"\tArch: {b.architecture}")
            print(f"\tBits: {b.bitness}")
            print(f"\tEndian: {b.endianness}")
            print(f"\tSHA256: {b.sha256}")
            print(f"\tSize: {len(b.bytes())}")
            print(f"\tNum Functions: {len(b.functions)}")

        if uri is not None:
            with Session(Backend.engine) as s:
                if not quiet:
                    print("Inserting to DB")
                b.db_add(s)
                s.commit()

@app.command()
def install(
    disassm: Annotated[DisassemblerChoice, typer.Argument(help="Disassembler")],
    version: Annotated[str, typer.Option('-v', '--version', help="Version Number or Commit Hash (if applicable) to download, (build), and install ")] = None,
    path: Annotated[str, typer.Option('-p', '--path', help="Path to install disassembler to")] = None,
    l: Annotated[bool, typer.Option('-l', '--list', help="List available verions to download and install")] = False,
):
    disasm_type = None
    if disassm == DisassemblerChoice.rizin:
        disasm_type = Rizin
    elif disassm == DisassemblerChoice.ghidra:
        disasm_type = Ghidra
    else:
        raise ValueError("Not a supported Disassembler")

    if l:
        for ver in disasm_type.list_versions():
            print(ver)
        return

    build = False
    if (len(version) == 7 or len(version) == 40) and all(c in string.hexdigits for c in version):
        build = True

    disasm_type.install(
        version=version,
        install_dir=path,
        build = build
    )

    


def main():
    app()

if __name__ == "__main__":
    main()