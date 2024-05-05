"""Collection of finding of eBPF primitives, i.e. symbols such as uprobes or offsets"""
from __future__ import annotations

import os.path

# Standard Imports
from typing import Literal, Iterable, Collection, Optional
from pathlib import Path
import re
import subprocess

# Third-Party Imports
from elftools.elf.elffile import ELFFile
from distorm3 import Decode, Decode64Bits

# Perun Imports
from perun.utils import log
from perun.utils.external import commands

def get_symbols(traced_file: Path, packages: List[str]) -> tuple[dict[int, str], dict[str, list[str]]]:
    f = open(traced_file, 'rb')
    e = ELFFile(f)

    functions = []
    morestack_noctxt_addr = ""
    morestack_addr = ""


    # find user declared functions
    sec = e.get_section_by_name('.symtab')
    for sym in sec.iter_symbols():
        if sym["st_info"].type == "STT_FUNC":
            if sym.name.startswith("type:"):
                continue
            if sym.name == "runtime.morestack_noctxt.abi0":
                morestack_noctxt_addr = sym["st_value"]
            if sym.name == "runtime.morestack.abi0":
                morestack_addr = sym["st_value"]
            # find functions to profile in given packages
            for package in packages:
                if sym.name.startswith(package):
                    if "[" in sym.name or "{" in sym.name:
                        continue
                    functions.append((sym.name, sym["st_value"], sym["st_size"]))

    if not functions:
        log.error(f"no functions in executable in packages {packages}")
    
    symbol_map = {}

    # find all returns of each function
    for func in functions:
        sec = e.get_section_by_name('.text')

        sec_offset = sec['sh_offset']
        sec_size = sec['sh_size']
        sec_addr = sec['sh_addr']

        if func[1] < sec_addr or func[1] + func[2] > sec_addr + sec_size:
            log.error(f"Symbol {func[1]} not in section, Should not happen")
        
        f.seek(sec_offset + func[1] - sec_addr)

        offsets = []
        morestack_offset = ""
        instructions = Decode(func[1], f.read(func[2]), type=Decode64Bits)
        for addr, _, asm, _ in instructions:
            if asm == 'RET':
                offsets.append(hex(addr - func[1]))
            if asm == f"CALL {hex(morestack_addr)}" or asm == f"CALL {hex(morestack_noctxt_addr)}":
                morestack_offset = hex(addr - func[1])

        if morestack_offset == '':
            morestack_offset = None

        symbol_map[func[0]] = (offsets, morestack_offset)

    idx_name_map = {i: name for i, (name, _) in enumerate(symbol_map.items())}

    return idx_name_map, symbol_map