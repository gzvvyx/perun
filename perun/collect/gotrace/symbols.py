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

def get_symbols(traced_file: Path) -> tuple[dict[int, str], dict[str, list[str]]]:
    f = open(traced_file, 'rb')
    e = ELFFile(f)

    functions = []

    # find user declared functions
    for sec in e.iter_sections():
        if sec.name == '.symtab':
            for sym in sec.iter_symbols():
                # "main" signals package -- should add param for all packages
                # "main.." added in go 1.22 as comments
                if sym.name.startswith('main.') and not sym.name.startswith('main..'):
                    # found user declared function
                    functions.append((sym.name, sym['st_value'], sym['st_size']))

    if not functions:
        raise ValueError('No main functions found in .symtab')
    
    symbol_map = {}

    # find all returns of each function
    for func in functions:
        sec = e.get_section_by_name('.text')

        sec_offset = sec['sh_offset']
        sec_size = sec['sh_size']
        sec_addr = sec['sh_addr']

        if func[1] < sec_addr or func[1] + func[2] > sec_addr + sec_size:
            raise ValueError('Symbol not in section')
        
        f.seek(sec_offset + func[1] - sec_addr)

        offsets = []
        instructions = Decode(func[1], f.read(func[2]), type=Decode64Bits)
        for addr, _, asm, _ in instructions:
            if asm == 'RET':
                offsets.append(hex(addr - func[1]))

        symbol_map[func[0]] = offsets

    idx_name_map = {i: name for i, (name, _) in enumerate(symbol_map.items())}

    return idx_name_map, symbol_map