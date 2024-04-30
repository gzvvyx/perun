"""Main module of the ktrace, which specifies its phases"""
import subprocess

# Standard Imports
from typing import Any
from pathlib import Path
import time

# Third-Party Imports
import click
import sys
import os
import re

# Perun Imports
from perun.collect.gotrace import symbols, bpfgen, interpret
from perun.logic import runner
from perun.utils import log
from perun.utils.common import script_kit
from perun.utils.external import commands, processes
from perun.utils.structs import CollectStatus


BUSY_WAIT: int = 5


def before(**kwargs: Any) -> tuple[CollectStatus, str, dict[str, Any]]:
    """In before function we collect available symbols, filter them and prepare the eBPF program"""
    log.major_info("Creating the profiling program")

    if kwargs["executable"] is None:
            log.error(
                "cannot collect perf events without executable. Run collection again with `-c cmd`."
            )
    if not kwargs["packages"]:
        kwargs["packages"] = ("main",)
        log.minor_info("No packages given, defaulting to only main package")
    log.minor_info(f"Discovering available and attachable symbols for {kwargs['packages']} packages")

    kwargs["idx_to_func"], kwargs["symbol_map"] = symbols.get_symbols(str(kwargs["executable"]), kwargs["packages"])

    if kwargs["verbose"]:
        log.minor_info(f"Found these functions {list(kwargs['symbol_map'].keys())}")

    log.minor_info(f"Number of functions: {len(kwargs['symbol_map'])}")

    log.minor_success("Generating the source of the eBPF program")

    executable_dir = str(Path.cwd()) + str(kwargs["executable"])[1:]
    bpfgen.generate_bpf_c(executable_dir, kwargs["symbol_map"], kwargs["bpfring_size"])
    build_dir = Path(Path(__file__).resolve().parent, "bpf_build")
    commands.run_safely_external_command(f"make -C {build_dir}")
    log.minor_success("Building the eBPF program")

    return CollectStatus.OK, "", dict(kwargs)

def collect(**kwargs: Any) -> tuple[CollectStatus.OK, str, dict[str, Any]]:
    """In collect, we run the eBPF program

    Note, that currently we wait for user to run the results manually

    :param kwargs: stash of shared values between the phases
    :return: collection status (error or OK), error message (if error happened) and shared parameters
    """
    log.major_info("Collecting performance data")

    # First we wait for starting the gotrace
    log.minor_info(f"waiting for {log.highlight('gotrace')} to start", end="")
    while True:
        log.tick()

        if processes.is_process_running("gotrace"):
            log.newline()
            break
        time.sleep(BUSY_WAIT)

    log.minor_info(f"waiting for {log.highlight('gotrace')} to attach", end="")
    time.sleep(BUSY_WAIT)

    log.minor_success(f"{log.highlight('gotrace')}", "running")

    failed_reason = ""
    profiled_time = ""
    if kwargs["executable"]:
        if script_kit.may_contains_script_with_sudo(str(kwargs["executable"])):
            failed_reason = "the command might require sudo"
            log.minor_fail("Running the workload")
        else:
            try:
                if kwargs["verbose"]:
                    if kwargs["get_overhead"]:
                        _, cmderr = commands.run_safely_external_command("time " + str(kwargs["executable"]), quiet=False)

                        profiled_time = interpret.get_elapsed_time(cmderr)

                        log.minor_success(f"real time of {str(kwargs['executable'])} with {log.highlight('gotrace')} in [s]", profiled_time)
                    else:
                        commands.run_safely_external_command(str(kwargs["executable"]), quiet=False)
                else:
                    commands.run_safely_external_command(str(kwargs["executable"]))
                log.minor_success("Running the workload", "finished")
            except (subprocess.CalledProcessError, FileNotFoundError) as exc:
                failed_reason = f"the called process failed: {exc}"
                log.minor_fail("Running the workload")
    else:
        log.minor_fail("Running the workload", "skipped")
        failed_reason = "command was not provided on CLI"
    if failed_reason:
        log.minor_info(f"The workload has to be run manually, since {failed_reason}", end="\n")

    log.minor_info(
        f"waiting for {log.highlight('gotrace')} to finish profiling {str(kwargs['executable'])}",
        end="",
    )

    while True:
        log.tick()

        if not processes.is_process_running("gotrace"):
            log.newline()
            break
        time.sleep(BUSY_WAIT)

    log.minor_success(f"collecting data for {str(kwargs['executable'])}")

    non_profiled_time = ''
    if kwargs["verbose"]:
        if kwargs["get_overhead"]:
            log.minor_info(f"running {str(kwargs['executable'])} second time, without {log.highlight('gotrace')}")

            _, cmderr = commands.run_safely_external_command("time " + str(kwargs["executable"]))
            non_profiled_time = interpret.get_elapsed_time(cmderr)

            log.minor_success(f"real time of {str(kwargs['executable'])} alonein in [s]", non_profiled_time)
            overhead = ((profiled_time - non_profiled_time) / non_profiled_time) * 100
            log.minor_info(f"overhead {'{:.2f}'.format(overhead)}%")

    return CollectStatus.OK, "", dict(kwargs)


def after(**kwargs: Any) -> tuple[CollectStatus, str, dict[str, Any]]:
    """Creates performance profile based on the results"""
    log.major_info("Creating performance profile")

    raw_data_file = Path(Path(__file__).resolve().parent, "bpf_build", "output.txt")
    output_file = Path(Path(__file__).resolve().parent, "bpf_build", "profile.csv")

    save_intermediate = kwargs["save_intermediate_to_csv"]

    parsed_traces = interpret.parse_traces(
        raw_data_file, kwargs["idx_to_func"], interpret.FuncDataFlat
    )
    trace_data = interpret.traces_to_pandas(parsed_traces)

    if save_intermediate:
        trace_data.to_csv(output_file, index=False)
    resources = interpret.pandas_to_resources(trace_data)
    total_runtime = parsed_traces.total_runtime

    log.minor_info(f"time {total_runtime}ns")
    log.minor_success("generating profile")

    if not resources:
        log.warn("no resources were generated (probably due to empty file?)")
    if save_intermediate:
        log.minor_status(f"intermediate data saved", f"{log.cmd_style(str(output_file))}")
    kwargs["profile"] = {"global": {"time": total_runtime, "resources": resources}}
    return CollectStatus.OK, "", dict(kwargs)

# delete .output?, output file?, gotrace.bpf.c?
# def teardown():
#     pass


@click.command()
@click.argument("packages", required=False, nargs=-1)
@click.option(
    "--bpfring-size",
    "-s",
    type=int,
    default=4096 * 4096 * 10,
    help="Size of the ring buffer used in eBPF program. Increasing the size will lead to lesser number of lost events.",
)
@click.option(
    "--save-intermediate-to-csv",
    "-c",
    is_flag=True,
    type=bool,
    default=False,
    help="Saves the intermediate results into some file.",
)
@click.option(
    "--get-overhead",
    "-o",
    is_flag=True,
    type=bool,
    default=False,
    help="Calculates overhead of `gotrace`. Only usable together with `--verbose`. ! will run the program twice !",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    type=bool,
    default=False,
    help="Shows all functions `gotrace` will monitor. ! might clutter perun output !",
)
@click.pass_context
def gotrace(ctx, **kwargs):
    """Generates go user defined function traces."""
    runner.run_collector_from_cli_context(ctx, "gotrace", kwargs)