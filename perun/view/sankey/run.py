"""Sankey visualisation of traces"""
from __future__ import annotations

# Standard Imports
from dataclasses import dataclass
from typing import Any

# Third-Party Imports
import click
import os
import pandas as pd
import jinja2
import holoviews as hv
from holoviews import opts, dim
hv.extension('bokeh')

# Perun Imports
from perun.utils import log
from perun.utils.common import cli_kit, common_kit, view_kit
from perun.profile.factory import Profile
from perun.profile import convert



PRECISION: int = 2


@dataclass
class SankeyRecord:
    """Represents single record on top of the consumption

    :ivar uid: uid of the records
    :ivar trace: trace of the record
    :ivar caller: uid of the caller
    :ivar trace_list: trace as list of formatted strings
    :ivar total_excl_t: total exclusive time
    :ivar total_morestack_t: total morestack time
    """

    uid: str
    trace: str
    caller: str
    trace_list: list[str]
    total_excl_t: float
    total_morestack_t: float


def generate_trace_list(trace: str, uid: str) -> list[str]:
    """Generates list of traces

    :param trace: trace to uid
    :param uid: called uid
    """
    if trace.strip() == "":
        return [uid]
    data = []
    lhs_trace = trace.split(",") + [uid]
    for i, lhs in enumerate(lhs_trace):
        if i == 0:
            data.append(lhs)
            continue
        indent = " " * i
        data.append(lhs)
    return data

def generate_caller(trace: str) -> str:
    """Generates list of traces

    :param trace: trace to uid
    :param uid: called uid
    """
    if trace.strip() == "":
        return ""
    lhs_trace = trace.split(",")
    return lhs_trace[-1]



def profile_to_data(profile: Profile) -> list[SankeyRecord]:
    """Converts profile to list of columns and list of list of values

    :param profile: converted profile
    :return: list of columns and list of rows
    """
    df = convert.resources_to_pandas_dataframe(profile)

    pivoted_df = df.pivot(index=['uid', 'trace', 'ncalls'], columns='subtype', values='amount').reset_index()

    data = []
    for _, row in pivoted_df.iterrows():
        data.append(
            SankeyRecord(
                row["uid"],
                row["trace"],
                generate_caller(row["trace"]),
                generate_trace_list(row["trace"], row["uid"]),
                row["Total Inclusive T [ms]"],
                row["Total Morestack T [ms]"]
            )
        )
    return data
    

def generate_sankey(profile: Profile, **kwargs: Any) -> None:
    data = profile_to_data(profile)
    
    pairs = []
    for record in data:
        if record.caller == '':
            split_record = record.uid.split('.')
            if len(split_record) == 3:
                pairs.append([split_record[0] + '.' + split_record[1], record.uid, record.total_excl_t])
                continue
            # pairs.append(['Total Time', record.uid, record.total_excl_t])
            continue
        if record.total_morestack_t != 0.0:
            pairs.append([record.uid, record.uid + ' Morestack', record.total_morestack_t])
            continue
        pairs.append([record.caller, record.uid, record.total_excl_t])

    print(pairs)

    sankey = hv.Sankey(pairs)
    sankey.opts(width=1200, height=800)

    view_kit.save_view_graph(sankey, '/home/gzvv/Desktop/bp/sankey.html', True)





@click.command()
@click.option("-o", "--output-file", help="Sets the output file (default=automatically generated).")
@click.pass_context
def sankey(ctx: click.Context, *_: Any, **kwargs: Any) -> None:
    assert ctx.parent is not None and f"impossible happened: {ctx} has no parent"
    generate_sankey(ctx.parent.params["profile"], **kwargs)
