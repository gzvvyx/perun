"""Sankey visualisation of traces"""
from __future__ import annotations

# Standard Imports
from dataclasses import dataclass
from typing import Any

# Third-Party Imports
import click
import os
import pandas as pd
import numpy as np
import jinja2
import matplotlib.colors as mcolors

import plotly.graph_objects as go
import plotly.express as pex

# Perun Imports
from perun.profile import helpers
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
    :ivar total_incl_t: total inclusive time
    :ivar total_excl_t: total exclusive time
    :ivar total_morestack_t: total morestack time
    """

    uid: str
    trace: str
    caller: str
    trace_list: list[str]
    total_incl_t: float
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
                row["Total Exclusive T [ms]"],
                row["Total Morestack T [ms]"]
            )
        )
    return data

def generate_pairs(data: List[SankeyRecord]) -> Tuple[List[str], List[List[str, str, float]], List[List[str, str, float]]]:
    labels = []
    label_map = {}
    pairs_excl = []
    pairs_incl = []

    for record in data:
        # here add check if record.uid is in map
        if record.uid not in labels:
            labels.append(record.uid)
            label_map[record.uid] = len(labels) - 1

        # no caller
        if record.caller == '':
            split_record = record.uid.split('.')
            if len(split_record) == 3:
                # is goroutine, create caller
                record.caller = split_record[0] + '.' + split_record[1]
            # maybe create unknown caller
            if record.uid.endswith(".main"):
                continue

        # here add check if record.caller is in map
        if record.caller not in labels:
            labels.append(record.caller)
            label_map[record.caller] = len(labels) - 1

        if record.total_morestack_t != 0.0:
            # add morestack pair
            morestack_uid = record.uid + "__morestack"
            if morestack_uid not in labels:
                labels.append(morestack_uid)
                label_map[morestack_uid] = len(labels) - 1
            pairs_excl.append([label_map[record.uid], label_map[morestack_uid], record.total_morestack_t])                
            pairs_incl.append([label_map[record.uid], label_map[morestack_uid], record.total_morestack_t])

        # add pairs
        pairs_excl.append([label_map[record.caller], label_map[record.uid], record.total_excl_t])
        pairs_incl.append([label_map[record.caller], label_map[record.uid], record.total_incl_t])

    return labels, pairs_excl, pairs_incl


def pairs_to_links(pairs: List[List[int, int, float]]) -> dict:
    links = {
        "source": [],
        "target": [],
        "value": []
    }
    
    for pair in pairs:
        links["source"].append(pair[0])
        links["target"].append(pair[1])
        links["value"].append(pair[2])

    return links
    

def generate_sankey(profile: Profile, **kwargs: Any) -> None:
    log.minor_info("Starting generating")

    data = profile_to_data(profile)

    log.minor_info("Generating pairs and labels")
    
    labels, pairs_excl, pairs_incl = generate_pairs(data)

    links_excl = pairs_to_links(pairs_excl)
    links_incl = pairs_to_links(pairs_incl)

    colors = pex.colors.qualitative.D3
    node_colors_mappings = dict([(node,np.random.choice(colors)) for node in labels])
    node_colors = [node_colors_mappings[node] for node in labels]

    
    fig_excl = go.Figure(go.Sankey(
        valueformat = ".000f",
        valuesuffix = " ms",
        node = dict(
            pad = 50,
            thickness = 15,
            line = dict(color = "black", width = 0.5),
            label = labels,
            color = node_colors
        ),
        link = dict(
            source = links_excl["source"],
            target = links_excl["target"],
            value = links_excl["value"]
        )
    ))

    fig_incl = go.Figure(go.Sankey(
        valueformat = ".000f",
        valuesuffix = " ms",
        node = dict(
            pad = 50,
            thickness = 15,
            line = dict(color = "black", width = 0.5),
            label = labels,
            color = node_colors
        ),
        link = dict(
            source = links_incl["source"],
            target = links_incl["target"],
            value = links_incl["value"],
        )
    ))

    # TODO: add this to view_kit.save_view_graph
    output_file = kwargs["output_file"]
    if output_file is None:
        prof_name = os.path.splitext(helpers.generate_profile_name(profile))[0]
        output_file = f"sankey-of-{prof_name}" + ".html"

    if not output_file.endswith(".html"):
        output_file += ".html"

    env = jinja2.Environment(loader=jinja2.PackageLoader("perun", "templates"))
    template = env.get_template("view_sankey.html.jinja2")
    content = template.render(
        main_title="Sankey representation of Go program traces",
        title1="Exclusive Time [ms]",
        figure1=fig_excl.to_html(full_html=False),
        title2="Inclusive Time [ms]",
        figure2=fig_incl.to_html(full_html=False),
    )

    log.minor_success(f"Sankey", "generated")
    
    with open(output_file, "w", encoding="utf-8") as template_out:
        template_out.write(content)

    log.minor_success("Output saved", log.path_style(output_file))


@click.command()
@click.option("-o", "--output-file", help="Sets the output file (default=automatically generated).")
@click.pass_context
def sankey(ctx: click.Context, *_: Any, **kwargs: Any) -> None:
    assert ctx.parent is not None and f"impossible happened: {ctx} has no parent"
    generate_sankey(ctx.parent.params["profile"], **kwargs)
