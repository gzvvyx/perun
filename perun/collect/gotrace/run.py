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

    log.minor_info(f"Found these functions {list(kwargs['symbol_map'].keys())}")

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
    if kwargs["executable"]:
        if script_kit.may_contains_script_with_sudo(str(kwargs["executable"])):
            failed_reason = "the command might require sudo"
            log.minor_fail("Running the workload")
        else:
            try:
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

    return CollectStatus.OK, "", dict(kwargs)


def after(**kwargs: Any) -> tuple[CollectStatus, str, dict[str, Any]]:
    """Creates performance profile based on the results"""
    log.major_info("Creating performance profile")

    raw_data_file = Path(Path(__file__).resolve().parent, "bpf_build", "output.txt")
    output_file = Path(Path(__file__).resolve().parent, "bpf_build", "profile.csv")

    profile_output_type = kwargs["output_profile_type"]
    save_intermediate = kwargs["save_intermediate_to_csv"]

    if profile_output_type == "flat":
        flat_parsed_traces = interpret.parse_traces(
            raw_data_file, kwargs["idx_to_func"], interpret.FuncDataFlat
        )
        trace_data = interpret.traces_flat_to_pandas(flat_parsed_traces)

        if save_intermediate:
            trace_data.to_csv(output_file, index=False)
        resources = interpret.pandas_to_resources(trace_data)
        total_runtime = flat_parsed_traces.total_runtime
    elif profile_output_type == "details":
        detailed_parsed_traces = interpret.parse_traces(
            raw_data_file, kwargs["idx_to_func"], interpret.FuncDataDetails
        )
        trace_data = interpret.traces_details_to_pandas(detailed_parsed_traces)
        resources = interpret.pandas_to_resources(trace_data)
        total_runtime = detailed_parsed_traces.total_runtime
        if save_intermediate:
            trace_data.to_csv(output_file, index=False)
    else:
        assert profile_output_type == "clustered"
        detailed_parsed_traces = interpret.parse_traces(
            raw_data_file, kwargs["idx_to_func"], interpret.FuncDataDetails
        )
        resources = interpret.trace_details_to_resources(detailed_parsed_traces)
        total_runtime = detailed_parsed_traces.total_runtime
    log.minor_success("generating profile")

    if not resources:
        log.warn("no resources were generated (probably due to empty file?)")
    if save_intermediate and profile_output_type != "clustered":
        log.minor_status(f"intermediate data saved", f"{log.cmd_style(str(output_file))}")
    kwargs["profile"] = {"global": {"time": total_runtime, "resources": resources}}
    return CollectStatus.OK, "", dict(kwargs)

# delete .output?, output file?, gotrace.bpf.c?
# def teardown():
#     pass


@click.command()
@click.argument("packages", required=False, nargs=-1)
@click.option(
    "--with-sudo",
    "-ws",
    default=False,
    is_flag=True,
    help="Whether some commands should be run with sudo or not",
)
@click.option(
    "--bpfring-size",
    "-s",
    type=int,
    default=4096 * 4096 * 10,
    help="Size of the ring buffer used in eBPF program. Increasing the size will lead to lesser number of lost events.",
)  # add checks
@click.option(
    "--output-profile-type",
    "-t",
    type=click.Choice(["clustered", "details", "flat"]),
    default="flat",
    help="type of the resulting profile; clustered has highest granularity, flat has lowest granularity.",
)
@click.option(
    "--save-intermediate-to-csv",
    "-c",
    is_flag=True,
    type=bool,
    default=False,
    help="Saves the intermediate results into some file",
)
@click.pass_context
def gotrace(ctx, **kwargs):
    """Generates go user defined function traces."""
    runner.run_collector_from_cli_context(ctx, "gotrace", kwargs)