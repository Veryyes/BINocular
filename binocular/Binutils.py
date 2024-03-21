from __future__ import annotations
from typing import Union, List, Tuple
from pathlib import Path
import subprocess
import shutil
import string
import re

from .disassembler import Disassembler
from .primitives import Binary, Section, Function, BasicBlock, Instruction
from .consts import Endian

class Binutils(Disassembler):
    '''Parse all the data of a blob using Binutil Binaries'''
    FUNC_PAT = re.compile(r'([0-9a-fA-F]+) <(\S+)>:')


    @classmethod
    def _readelf_parse_flag(cls, flag:str):
        flag_key = {
            "W": "write",
            "A": "alloc",
            "X": "execute",
            "M": "merge",
            "S": "strings",
            "I": "info_flag",
            "L": "link_order",
            "O": "extra_processing",
            "G": "group",
            "T": "tls",
            "C": "compressed",
            "x": "unknown",
            "o": "os_specific",
            "E": "exclude",
            "D": "mbind",
            "l": "large",
            "p": "processor_specific"
        }

        props = dict()
        for f in flag:
            p = flag_key.get(f, None)
            if p is not None:
                props[p] = True

        return props

    def __init__(self, timeout=15):
        self._raw_output = ""
        self._loaded_bin = False
        self._bin = None

        self._funcs_by_name = dict()
        self._funcs_by_addr = dict()

        self.timeout = timeout

        if not self.is_installed():
            self.install()

    def is_installed(self) -> bool:
        tools = ["objdump", "readelf"]
        return all([shutil.which(x) is not None for x in tools])

    def install(self):
        # TODO install binutils...
        raise NotImplementedError("Go install Binutils")

    def load_binary(self, binary:Union[Path, str]) -> Binary:
        if isinstance(binary, str):
            binary = Path(binary)
        if isinstance(binary, Path):
            if not binary.exists() or binary.is_dir():
                raise FileNotFoundError

        header_data = self._readelf_header(binary)
        sections = self._readelf_sections(binary)
        self._bin = Binary(sections=sections, **header_data)
        self._bin._path=binary

        self._bin.functions = self._objdump(binary)
        for f in self._bin.functions:
            self._funcs_by_addr[f.address] = f
            self._funcs_by_name[f.name] = f

        return self._bin
    
    def _run_proc(self, cmd:List[str]) -> Tuple[str, str]:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, err = p.communicate(timeout=self.timeout)
            return str(out, 'utf8'), str(err, 'utf8')
        except TimeoutError:
            p.kill()
            raise Disassembler.FailedToLoadBinary

    def _readelf_header(self, bin_path:Path):
        props = {
            "endianness": None,
            "os": None,
            "architecture": None,
            "entrypoint": None,
        }

        out, _ = self._run_proc(["readelf", "-h", str(bin_path)])
        lines = out.split('\n')
        for l in lines:
            info = l.strip().split(":", 1)
            if info[0] == "Data":
                if "little" in info[1]:
                    props['endianness'] = Endian.LITTLE
                elif "big" in info[1]:
                    props['endianness'] = Endian.BIG
            
            if "OS/ABI" == info[0]:
                props['os'] = info[1].strip()

            if "Machine" == info[0]:
                props['architecture'] = info[1].strip()
            
            # print(info[0])
            if "Entry point address" == info[0]:
                props['entrypoint'] = int(info[1].strip(), 16)
        
        return props

    def _readelf_sections(self, bin_path:Path):
        sections = list()

        out, _ = self._run_proc(["readelf", "--sections", "-W", str(bin_path)])
        lines = out.split("\n")
        lines = lines[5:-6]
        for l in lines:
            l = l.split("]", 1)[1].strip()
            name, stype, address, offset, size, entsize, info = l.split(maxsplit=6)
            info = info.split()
            if info[0][0] not in string.digits:
                flags = self.__class__._readelf_parse_flag(info.pop(0))
            
            link, info, align = info

            s = Section(
                name=name,
                stype=stype,
                start=int(address, 16),
                offset=int(offset, 16),
                size=int(size, 16),
                entsize=int(entsize, 16),
                link=int(link),
                info=int(info),
                align=int(align),
                **flags
            )
            sections.append(s)
                
        return sections
    
    def _objdump(self, bin_path:Path):
        funcs = set()
        curr_func = None
        curr_bb = None

        cmd = ["objdump", "-w", "-d", "-Mintel", str(bin_path)]
        out, _ = self._run_proc(cmd)
        lines = out.split("\n")[4:]
        for l in lines:
            if "Disassembly of section" in l:
                continue
  
            # TODO FIX
            # FOR NOW ASSUME FUNCTION IS 1 BIG BB

            # Start of a function
            if l.endswith(":"):
                m = re.match(Binutils.FUNC_PAT, l)
                addr = int(m.group(1), 16)
                fname = m.group(2)

                curr_func = Function(
                    name=fname, 
                    address=addr,

                    endianness=self._bin.endianness,
                    architecture=self._bin.architecture,
                    bitness=self._bin.bitness,
                    pie=self._bin.pie
                )
                
                curr_bb = BasicBlock(
                    address=addr,
                    endianness=self._bin.endianness,
                    architecture=self._bin.architecture,
                    bitness=self._bin.bitness,
                    pie=self._bin.pie
                )
                continue

            # nothing or End of a function
            if len(l) == 0:
                if curr_bb is not None:
                    curr_func.basic_blocks.add(curr_bb)
                    curr_bb = None

                if curr_func is not None:
                    funcs.add(curr_func)
                    curr_func = None
                continue

            # code in a function
            if l[0] == ' ':
                comment = None
                addr, data, asm = l.strip().split('\t')
                if "#" in asm:
                    asm, comment = asm.split("#", 1)
                    comment = comment.strip()

                i = Instruction(
                    address=int(addr[:-1], 16),
                    data=bytes.fromhex(re.sub(r'\s+', "", data)),
                    asm=asm.strip(),
                    comment=comment,

                    endianness=self._bin.endianness,
                    architecture=self._bin.architecture,
                    bitness=self._bin.bitness
                )
                curr_bb.instructions.append(i)

                # TODO determine if we are at the end of the bb
                # if jump or ret:
                    # curr_fnuc.basic_blocks.add(curr_bb)
                    # curr_bb = BasicBlock(
                    #     endianness=self._bin.endianness,
                    #     architecture=self._bin.architecture,
                    #     bitness=self._bin.bitness,
                    #     pie=self._bin.pie
                    # )
                    # curr_bb = None
        return funcs

            
    def function(self, address:int, exact=True) -> Function:
        if exact:
            return self._funcs_by_addr.get(address, None)

        if address in self._funcs_by_addr:
            return self.self._funcs_by_addr[address]

        addrs = [(abs(a - address), f) for a, f in self._funcs_by_addr.items()]
        return min(addrs, key=lambda x: x[0])[1]
            

    def function_sym(self, symbol:str) -> Function:
        return self._funcs_by_name.get(symbol, None)

    def functions(self) -> List[Function]:
        return self._bin.functions