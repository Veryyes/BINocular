import logging
import os
import string
from enum import Enum
from pathlib import Path
from typing import Optional, Type

import IPython
import typer
from sqlalchemy.orm import Session
from typing_extensions import Annotated

from binocular import Backend, Disassembler, Ghidra, Rizin

app = typer.Typer()


class DisassemblerChoice(Enum):
    rizin = "rizin"
    ghidra = "ghidra"


@app.command()
def parse(
    path: Annotated[Path, typer.Argument(help="Path to Binary")],
    disassm: Annotated[DisassemblerChoice, typer.Argument(help="Disassembler")],
    uri: Annotated[
        Optional[str], typer.Option("-u", "--uri", help="SQL database URI")
    ] = None,
    quiet: Annotated[
        bool, typer.Option("-q", "--quiet", help="Supress Analysis Output")
    ] = False,
    interactive: Annotated[
        bool,
        typer.Option("-i", "--ipython", help="Launch an IPython shell after loading"),
    ] = False,
    json: Annotated[
        bool, typer.Option("-j", "--json", help="Output parsed binary as json data")
    ] = False,
):
    disasm_type: Optional[Type[Disassembler]] = None
    if disassm == DisassemblerChoice.rizin:
        disasm_type = Rizin
    elif disassm == DisassemblerChoice.ghidra:
        disasm_type = Ghidra
    else:
        raise ValueError("Not a supported Disassembler")

    if not os.path.exists(path) or os.path.isdir(path):
        raise ValueError(f"Invalid File: {path}")

    if uri is not None:
        Backend.set_engine(uri)

    if not disasm_type.is_installed():
        disasm_type.install()

    if quiet:
        logging.disable(logging.INFO)
        logging.disable(logging.WARN)

    with disasm_type(verbose=not quiet) as disasm:
        disasm.load(path)
        b = disasm.binary
        if json:
            print(b.model_dump_json())
        elif not quiet:
            print("Binary:")
            print(f"\tName: {b.names[0]}")
            print(f"\tArch: {b.architecture}")
            print(f"\tBits: {b.bitness}")
            print(f"\tEndian: {b.endianness}")
            print(f"\tSHA256: {b.sha256}")
            print(f"\tSize: {len(b)}")
            print(f"\tNum Functions: {len(b.functions)}")

        if uri is not None:
            with Session(Backend.engine) as s:
                b.db_add(s)
                s.commit()

        if interactive:
            print("Binary stored in variable 'b'")
            IPython.embed()


@app.command()
def install(
    disassm: Annotated[DisassemblerChoice, typer.Argument(help="Disassembler")],
    version: Annotated[
        Optional[str],
        typer.Option(
            "-v",
            "--version",
            help="Version Number or Commit Hash (if applicable) to download, (build), and install ",
        ),
    ] = None,
    path: Annotated[
        Optional[str],
        typer.Option("-p", "--path", help="Path to install disassembler to"),
    ] = None,
    l: Annotated[
        bool,
        typer.Option(
            "-l", "--list", help="List available verions to download and install"
        ),
    ] = False,
):
    disasm_type: Optional[Type[Disassembler]] = None
    if disassm == DisassemblerChoice.rizin:
        disasm_type = Rizin
    elif disassm == DisassemblerChoice.ghidra:
        disasm_type = Ghidra
    else:
        raise ValueError("Not a supported Disassembler")

    if disasm_type is None:
        raise ValueError("Not a supported Disassembler")

    if l:
        for ver in disasm_type.list_versions():
            print(ver)
        return

    build = False
    if (
        version is not None
        and (len(version) == 7 or len(version) == 40)
        and all(c in string.hexdigits for c in version)
    ):
        build = True

    disasm_type.install(version=version, install_dir=path, build=build)


def main():
    app()


if __name__ == "__main__":
    main()
