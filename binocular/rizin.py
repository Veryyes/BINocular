from __future__ import annotations
from typing import List, Union
from collections.abc import Iterable
from pathlib import Path
from functools import lru_cache
import os
import shutil
import pkgutil
import binascii

from .disassembler import Disassembler
from .primitives import Binary, Section, Function, BasicBlock, Instruction, IR
from .consts import Endian, BranchType, IL
from .utils import run_proc

from git import Repo
import git
import rzpipe

class Rizin(Disassembler):
    GIT_REPO = "https://github.com/rizinorg/rizin.git"
    DEFAULT_INSTALL = os.path.join(os.path.dirname(pkgutil.get_loader('binocular').path), 'data', 'rizin')

    def __init__(self, rizin_home=None):
        self.rizin_home = rizin_home

        self._pipe = None
        self._bin = None

        self._funcs_by_name = dict()
        self._funcs_by_addr = dict()

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.close()

    def close(self):
        self._pipe.quit()

    def is_installed(self) -> bool:
        if self.rizin_home is not None:
            bin_loc = os.path.join(self.rizin_home, "build", "binrz", "rizin")
            return os.path.exists(bin_loc)

        sys_install = shutil.which('rizin') is not None
        local_install = os.path.exists(os.path.join(Rizin.DEFAULT_INSTALL, "build", "binrz", "rizin"))
        
        return sys_install or local_install

    def install(self, install_dir=None):
        print("Installing Rizin")

        if install_dir is None:
            install_dir = Rizin.DEFAULT_INSTALL

        os.makedirs(install_dir, exist_ok=True)
        print(f"Cloning Rizin to: {install_dir}")
        try:
            repo = Repo.clone_from(Rizin.GIT_REPO, install_dir)
        except git.GitCommandError:
            print("Rizin Already Cloned")
            repo = Repo(install_dir)

        # Lock in to Version 0.7.2 for now
        repo.git.checkout("87add99")

        cmds = [
            ["meson", "setup", "build"],
            ["meson", "compile", "-C", "build"],
        ]

        for cmd in cmds:
            print(f"$ {' '.join(cmd)}")
            out, err = run_proc(cmd=cmd, timeout=None, cwd=install_dir)
            print(out)
            print(err)

        assert self.is_installed()

    def _section_flags(self, flags:List[str]):
        prop_names = {
            'info': 'info_flag',
            'extra_os_processing_reqd': 'extra_processing',
            'TLS': 'tls',
        }
        section_flags = dict()

        for f in flags:
            section_flags[prop_names.get(f, f)] = True
        return section_flags

    def load(self, path:Union[Path, str]):
        if isinstance(path, Path):
            path = str(path)

        if not os.path.exists(path) or os.path.isdir(path):
            raise FileNotFoundError

        if self.rizin_home is not None:
            self._pipe = rzpipe.open(path, rizin_home=self.rizin_home)
        else:
            try:
                self._pipe = rzpipe.open(path)
            except Exception:
                self._pipe = rzpipe.open(path, rizin_home=os.path.join(Rizin.DEFAULT_INSTALL, "build", "binrz", "rizin"))

        self._pipe.cmd('aaaa')

        props = dict()

        bin_info = self._pipe.cmdj('ij')['bin']
        props['architecture'] = bin_info['arch']
        if bin_info['endian'] == "LE":
            props['endianness'] = Endian.LITTLE
        elif bin_info['endian'] == "BE":
            props['endianness'] = Endian.BIG
        props['bitness'] = bin_info['bits']
        props['os'] = bin_info['os']
        
        props['entrypoint'] = self._pipe.cmdj('iej')[0]['vaddr']

        self._bin = Binary(filename=os.path.basename(path), **props)
        self._bin.set_path(path)
        self._bin.set_disassembler(self)

        # Sections
        for s in self._pipe.cmdj('iSj'):
            if len(s['name']) > 0:
                
                # Invalid offset sizes being set to 0xf * 16
                offset = s['vaddr']
                if offset == 18446744073709551615:
                    offset = -1

                sec = Section(
                    name = s['name'],
                    type = s['type'],
                    start = s['paddr'],
                    offset = offset,
                    size = s['size'],
                    entsize = 0,
                    link = 0,
                    info = 0,
                    align = 0,
                    **self._section_flags(s.get("flags", list()))
                )
                self._bin.sections.append(sec)

        # Strings
        for s in self._pipe.cmdj('izj'):
            self._bin.strings.add(s['string'])
        
        # Libs
        for l in self._pipe.cmdj("ilj"):
            self._bin.dynamic_libs.add(l)

    def binary(self):
        return self._bin

    @lru_cache
    def function(self, address:int) -> Function:
        self._pipe.cmd(f"s {address}")
        addr = self._pipe.cmdj("afoj")['address']
        signature = self._pipe.cmdj('afsj')
        argv = [(arg['type'], arg['name']) for arg in  signature['args']]
        func = Function(
            endianness=self._bin.endianness,
            architecture=self._bin.architecture,
            bitness=self._bin.bitness,
            pie=self._bin.pie,
            canary=self._bin.canary,
            address=addr,
            name=signature['name'],
            argv=argv,
            return_type=signature["ret"]
        )

        # For each basic block in the function
        for b in self._pipe.cmdj('afbj'):
            bb = BasicBlock(
                endianness=self._bin.endianness,
                architecture=self._bin.architecture,
                bitness=self._bin.bitness,
                pie=self._bin.pie,
                address=b['addr']
            )

            if b.get('fail', None) is not None:
                bb.branches.add((BranchType.FalseBranch, b['fail']))
                if b.get('jump', None) is not None:
                    bb.branches.add((BranchType.TrueBranch, b['jump']))

            elif b.get('jump', None) is not None:
                bb.branches.add((BranchType.UnconditionalBranch, b['jump']))

            # Seek to basic block
            self._pipe.cmd(f"s {b['addr']}")

            # For each Instruction in the basic block
            for i in self._pipe.cmdj("pdbj"):
                instr = Instruction(
                    endianness=self._bin.endianness,
                    architecture=self._bin.architecture,
                    bitness=self._bin.bitness,
                    address=i['offset'],
                    data=bytes.fromhex(i['bytes'])
                )
                
                if i.get('disasm', None) is not None:
                    instr.asm = i['disasm']

                if i.get('comment', None) is not None:
                    instr.comment = str(binascii.a2b_base64(i['comment']), 'utf8')

                ir = i.get('esil', None)
                if ir is not None and len(ir) > 0:
                    instr.ir = IR(IL.ESIL, ir)
            
                bb.instructions.append(instr)
            
            func.basic_blocks.add(bb)
        return func
            
    @lru_cache
    def function_sym(self, symbol:str) -> Function:
        for f in self._pipe.cmdj("aflj"):
            name = f['name']
            if symbol == name:
                return self.function(f['offset'])

    def functions(self) -> Iterable[Function]:
        # Functions
        for f in self._pipe.cmdj("aflj"):
            func = self.function(f['offset'])
            yield func