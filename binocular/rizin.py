
from __future__ import annotations
from collections.abc import Iterable
from collections import defaultdict
from typing import Any, Optional, Tuple, List, IO
from pathlib import Path
import os
import shutil
import pkgutil
import binascii

from .disassembler import Disassembler
from .primitives import Section, Instruction, IR, Branch, Argument, Reference, RefType, Variable
from .consts import Endian, BranchType, IL
from .utils import run_proc

from git import Repo
import git
import rzpipe

class Rizin(Disassembler):

    GIT_REPO = "https://github.com/rizinorg/rizin.git"
    DEFAULT_INSTALL = os.path.join(os.path.dirname(pkgutil.get_loader('binocular').path), 'data', 'rizin')

    @classmethod
    def is_installed(cls, install_dir=None) -> bool:
        '''Returns Boolean on whether or not the dissassembler is installed'''
        if install_dir is not None:
            bin_loc = os.path.join(install_dir, "build", "binrz", "rizin")
            return os.path.exists(bin_loc)

        sys_install = shutil.which('rizin') is not None
        local_install = os.path.exists(os.path.join(Rizin.DEFAULT_INSTALL, "build", "binrz", "rizin"))
        
        return sys_install or local_install

    @classmethod
    def install(cls, install_dir=None) -> str:
        '''Installs the disassembler to a user specified directory or within the python module if none is specified'''
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

        return install_dir


    def __init__(self, verbose=True, rizin_home:str=None) -> None:
        super().__init__(verbose=verbose)
        self.rizin_home = rizin_home
        self._pipe = None

        self._bin_info = None
        self._thunk_dict = dict()
        self._caller_cache = defaultdict(lambda: set())
        self._calls_cache = defaultdict(lambda: set())

    def close(self):
        '''Release/Free up any resources'''
        self._pipe.quit()

    def clear(self):
        super().clear()
        self._pipe.quit()
        self._pipe = None

        self._bin_info = None
        self._thunk_dict = dict()
        self._caller_cache = defaultdict(lambda: set())
        self._calls_cache = defaultdict(lambda: set())

    def get_sections(self) -> Iterable[Section]:
        '''
        Returns a list of the sections within the binary.
        Currently only supports sections within an ELF file.
        '''
        return list()

    def analyze(self, path) -> bool:
        '''
        Loads the binary specified by `path` into the disassembler.
        Implement all diaassembler specific setup and trigger analysis here.
        :returns: True on success, false otherwise
        '''
        if isinstance(path, Path):
            path = str(path)

        if not os.path.exists(path) or os.path.isdir(path):
            return False, f"File not Found: {path}"

        if self.rizin_home is not None:
            self._pipe = rzpipe.open(path, rizin_home=self.rizin_home)
        else:
            try:
                self._pipe = rzpipe.open(path)
            except Exception:
                self._pipe = rzpipe.open(path, rizin_home=os.path.join(Rizin.DEFAULT_INSTALL, "build", "binrz", "rizin"))

        self._pipe.cmd('aaaa')
        self._bin_info = self._pipe.cmdj('ij')['bin']
        
        return True, None

    def _post_normalize(self):
        del self._caller_cache
        del self._calls_cache
        del self._thunk_dict


    def get_entry_point(self) -> int:
        '''Returns the address of the entry point to the function'''
        return self._pipe.cmdj('iej')[0]['vaddr']
    
    def get_architecture(self) -> str:
        '''
        Returns the architecture of the binary.
        For best results use either archinfo, qemu, or compilation triplet naming conventions.
        https://github.com/angr/archinfo
        '''
        return self._bin_info['arch']
    
    def get_endianness(self) -> Endian:
        '''Returns an Enum representing the Endianness'''
        if self._bin_info['endian'] == "LE":
            return Endian.LITTLE
        elif self._bin_info['endian'] == "BE":
            return Endian.BIG
        
        return Endian.OTHER

    def get_bitness(self) -> int:
        '''Returns the word size of the architecture (e.g., 16, 32, 64)'''
        return self._bin_info['bits']

    def get_base_address(self) -> int:
        '''Returns the base address the binary is based at'''
        return int(self._pipe.cmd("echo $B"), 16)
    
    def get_strings(self, binary_io:IO, file_size:int) -> Iterable[str]:
        '''Returns the list of defined strings in the binary'''
        return [s['string'] for s in self._pipe.cmdj('izj')]

    def get_dynamic_libs(self) -> Iterable[str]:
        '''Returns the list of names of the dynamic libraries used in this binary'''
        return [l for l in self._pipe.cmdj("ilj")]

    def get_func_iterator(self) -> Iterable[Any]:
        '''
        Returns an iterable of `Any` data type (e.g., address, interal func obj, dict of data) 
        needed to construct a `Function` object for all functions in the binary.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        for f in self._pipe.cmdj("aflj"):
            yield f

    def get_func_addr(self, func_ctxt:Any) -> int:
        '''Returns the address of the function corresponding to the function information returned from `get_func_iterator()`'''
        return func_ctxt['offset']

    def get_func_name(self, addr:int, func_ctxt:Any) -> str:
        '''Returns the name of the function corresponding to the function information returned from `get_func_iterator()`'''
        self._pipe.cmd(f"s {addr}")
        signature = self._pipe.cmdj('afsj')
        name = signature['name']
        if name.startswith("sym."):
            name = name[len("sym."):]

        if name.startswith("imp."):
            name = name[len("imp."):]
            self._thunk_dict[addr] = True

        return name         
    
    def get_func_args(self, addr:int, func_ctxt:Any) -> List[Argument]:
        '''Returns the arguments in the function corresponding to the function information returned from `get_func_iterator()`'''
        self._pipe.cmd(f"s {addr}")
        signature = self._pipe.cmdj('afsj')
        return [
            Argument(
                data_type=arg['type'],
                var_name=arg['name']
            ) for arg in signature['args']
        ]

    def get_func_callers(self, addr:int, func_ctxt:Any) -> Iterable[int]:        
        '''Return the address to functions that call func_ctxt'''
        for call_addr in self._caller_cache[addr]:
            yield call_addr

    def get_func_callees(self, addr:int, func_ctxt:Any) -> Iterable[int]:
        '''Return the address to functions that are called in func_ctxt'''
        for callee_addr in self._calls_cache[addr]:
            yield callee_addr

    def _parse_xref_type(self, type):
        if type == 'CODE':
            return RefType.JUMP
        if type == 'CALL':
            return RefType.CALL
        if type == 'DATA' or type == 'STRING':
            return RefType.DATA

        return RefType.UNKNOWN

    def get_func_xrefs(self, addr:int, func_ctxt:Any) -> Iterable[Reference]:
        self._pipe.cmd(f"s {addr}")
        xref_data = self._pipe.cmdj("afxj")
        for xref in xref_data:
            if xref['type'] == 'CALL':
                self._calls_cache[addr].add(xref['to'])
                self._caller_cache[xref['to']].add(addr)

            yield Reference(
                to=xref['to'],
                from_=xref['from'],
                type=self._parse_xref_type(xref['type'])
            )
    
    def get_func_return_type(self, addr:int, func_ctxt:Any) -> int:
        '''Returns the return type of the function corresponding to the function information returned from `get_func_iterator()`'''
        self._pipe.cmd(f"s {addr}")
        signature = self._pipe.cmdj('afsj')

        return signature['ret']

    def get_func_stack_frame_size(self, addr:int, func_ctxt:Any) -> int:
        '''Returns the size of the stack frame in the function corresponding to the function information returned from `get_func_iterator()`'''
        self._pipe.cmd(f"s {addr}")

        return self._pipe.cmdj('afij')[0]['stackframe']

    def get_func_vars(self, addr:int, func_ctxt:Any) -> Iterable[Variable]:
        '''Return variables within the function corresponding to the function information returned from `get_func_iterator()`'''
        self._pipe.cmd(f"s {addr}")
        vars = list()
        if 'stack' not in self._pipe.cmdj('afvlj'):
            return vars

        for var in self._pipe.cmdj('afvlj')['stack']:
            if not var['arg']:
                v = Variable(
                    data_type=var['type'],
                    name=var['name'],
                    is_register=var['storage']['type'] != "stack",
                    is_stack=var['storage']['type'] == "stack",
                )

                if v.is_stack:
                    v.stack_offset = var['storage']['stack']

                vars.append(v)

        return vars


    def is_func_thunk(self, addr:int, func_ctxt:Any) -> bool:
        '''Returns True if the function corresponding to the function information returned from `get_func_iterator()` is a thunk'''
        return self._thunk_dict.get(addr, False)
    
    def get_func_decomp(self, addr:int, func_ctxt:Any) -> Optional[str]:
        '''Returns the decomplication of the function corresponding to the function information returned from `get_func_iterator()`'''
        return None
    
    def get_func_bb_iterator(self, addr:int, func_ctxt:Any) -> Iterable[Any]:
        '''
        Returns an iterator of `Any` data type (e.g., address, implementation specific basic block information, dict of data)
        needed to construct a `BasicBlock` object for all basic blocks in the function based on function information returned from `get_func_iterator()`.
        The return type is left up to implementation to avoid any weird redundant analysis or
        any weirdness with how a disassembler's API may work.
        '''
        self._pipe.cmd(f"s {addr}")
        for bb in self._pipe.cmdj('afbj'):
            yield bb

    def get_bb_addr(self, bb_ctxt:Any, func_ctxt:Any) -> int:
        '''
        Returns the address of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        return bb_ctxt['addr']

    def get_next_bbs(self, bb_addr:int, bb_ctxt:Any, func_addr:int, func_ctxt:Any) -> Iterable[Branch]:
        '''
        Returns the Branching information of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        branches = list()
        if bb_ctxt.get('fail', None) is not None:
            branches.append(Branch(btype=BranchType.FalseBranch, target=bb_ctxt['fail']))
            if bb_ctxt.get('jump', None) is not None:
                branches.append(Branch(btype=BranchType.TrueBranch, target=bb_ctxt['jump']))
        elif bb_ctxt.get('jump', None) is not None:
            branches.append(Branch(btype=BranchType.UnconditionalBranch, target=bb_ctxt['jump']))

        return branches

    def get_bb_instructions(self, bb_addr:int, bb_ctxt:Any, func_ctxt:Any) -> List[Tuple(bytes, str)]:
        '''
        Returns a iterable of tuples of raw instruction bytes and corresponding mnemonic from the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        '''
        instrs = list()

        self._pipe.cmd(f"s {bb_addr}")
        for i in self._pipe.cmdj("pdbj"):
            addr = i['offset']

            self._pipe.cmd(f"s {addr}")
            instr_data = self._pipe.cmdj(f"pdj 1")[0]

            instrs.append((bytes.fromhex(instr_data['bytes']), instr_data['disasm']))
            
        return instrs

    
    def get_ir_from_instruction(self, instr_addr:int, instr:Instruction) -> Optional[IR]:
        '''
        Returns the Intermediate Representation data based on the instruction given
        '''
        self._pipe.cmd(f"s {instr_addr}")
        instr_data = self._pipe.cmdj(f"pdj 1")[0]
        ir = instr_data.get('esil', None)
        if ir is not None and len(ir) > 0:
            return IR(IL.ESIL, ir)
            
        return None

    def get_instruction_comment(self, instr_addr:int) -> Optional[str]:
        '''Return comments at the instruction'''
        self._pipe.cmd(f"s {instr_addr}")
        instr_data = self._pipe.cmdj(f"pdj 1")[0]

        if instr_data.get('comment', None) is not None:
            return str(binascii.a2b_base64(instr_data['comment']), 'utf8')
        return None