"""Main module of the ktrace, which specifies its phases"""
import subprocess

# Standard Imports
from typing import Any
from pathlib import Path
import time

# Third-Party Imports
# import click
import sys

# Perun Imports
# from perun.collect.ktrace import symbols, bpfgen, interpret
# from perun.logic import runner
# from perun.utils import log
# from perun.utils.common import script_kit
# from perun.utils.external import commands, processes
# from perun.utils.structs import CollectStatus
import bpfgen
import interpret
import symbols


BUSY_WAIT: int = 5


def before(prog):
    """In before function we collect available symbols, filter them and prepare the eBPF program"""
    # log.major_info("Creating the profiling program")

    # log.minor_info("Discovering available and attachable symbols")

    symbol_map, idx_name_map = symbols.get_symbols(prog)
    # kwargs["func_to_idx"], kwargs["idx_to_func"] = symbols.create_symbol_maps(attachable_symbols)
    # log.minor_success("Generating the source of the eBPF program")

    bpfgen.generate_bpf_c(prog, symbol_map, 1024)
    build_dir = Path(Path(__file__).resolve().parent, "bpf_build")
    # commands.run_safely_external_command(f"make -C {build_dir}")
    # log.minor_success("Building the eBPF program")

    return idx_name_map
    

NS_TO_MS = 1000000

def after(file_path, func_map: dict[str, list[str]]):

    flat_parsed_traces = interpret.parse_traces(file_path, func_map, interpret.FuncDataFlat)
    trace_data = interpret.traces_flat_to_pandas(flat_parsed_traces)
    print(trace_data)

def main(args):
    if args.path is None:
          print('Missing go exec path\n', file=sys.stderr)
          return

    idx_name_map = before(args.path)
    after(args.raw, idx_name_map)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Time function time\n')
    parser.add_argument(
        '--path',
        help='go exec path\n')
    parser.add_argument(
        '--raw',
        help='go raw data path\n')
    args = parser.parse_args()
    main(args)