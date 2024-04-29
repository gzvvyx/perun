from __future__ import annotations

# Standard Imports
from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any, Generic, TypeVar, Type, Literal
import itertools
import os
import pathlib
import struct

# Third-Party Imports
import pandas as pd

# Perun Imports
from perun.utils import log



NS_TO_MS = 1000000




DataT = TypeVar("DataT", bound="FuncData")



class FuncData(ABC):
    @abstractmethod
    def update(self, inclusive_t: int, exclusive_t: int, callees_cnt: int, morestack_t: int) -> None:
        ...


class FuncDataFlat(FuncData):
    __slots__ = [
        "inclusive_time",
        "exclusive_time",
        "morestack_time",
        "incl_t_min",
        "incl_t_max",
        "excl_t_min",
        "excl_t_max",
        "call_count",
        "callees_count",
    ]

    def __init__(self) -> None:
        self.inclusive_time: int = 0
        self.exclusive_time: int = 0
        self.morestack_time: int = 0
        self.incl_t_min: int = -1
        self.incl_t_max: int = 0
        self.excl_t_min: int = -1
        self.excl_t_max: int = 0
        self.call_count: int = 0
        self.callees_count: int = 0

    def update(self, inclusive_t: int, exclusive_t: int, callees_cnt: int, morestack_t: int) -> None:
        self.inclusive_time += inclusive_t
        self.exclusive_time += exclusive_t
        self.morestack_time += morestack_t
        self.call_count += 1
        self.callees_count += callees_cnt
        # Update the max and min values
        if self.incl_t_min == -1:
            self.incl_t_min = inclusive_t
            self.excl_t_min = exclusive_t
        else:
            self.incl_t_min = min(self.incl_t_min, inclusive_t)
            self.excl_t_min = min(self.excl_t_min, exclusive_t)
        self.incl_t_max = max(self.incl_t_max, inclusive_t)
        self.excl_t_max = max(self.excl_t_max, exclusive_t)




class TraceContextsMap(Generic[DataT]):
    __slots__ = "idx_name_map", "data_t", "trace_map", "durations", "total_runtime"

    def __init__(self, idx_name_map: dict[int, str], data_type: Type[DataT]) -> None:
        self.idx_name_map: dict[int, str] = idx_name_map
        self.data_t: Type[DataT] = data_type
        # Trace (sequence of function IDs) -> Trace ID
        self.trace_map: dict[tuple[int, ...], int] = {}
        # Function ID, Trace ID -> Inclusive, Exclusive durations, callees count
        self.durations: dict[int, DataT] = {}
        self.total_runtime: int = 0

    def add(
        self, func_id: int, trace: tuple[int, ...], inclusive_t: int, exclusive_t: int, callees: int, morestack_t: int
    ) -> None:
        trace_id = self.trace_map.setdefault(trace, len(self.trace_map))
        func_times = self.durations.setdefault((func_id, trace_id), self.data_t())
        func_times.update(inclusive_t, exclusive_t, callees, morestack_t)

    def __iter__(self) -> Iterator[tuple[str, tuple[str, ...], DataT]]:
        # Reverse the trace map for fast retrieval of Trace ID -> Trace
        trace_map_rev: dict[int, tuple[int, ...]] = {
            trace_id: trace for trace, trace_id in self.trace_map.items()
        }
        for (func_id, trace_id), func_times in self.durations.items():
            # Func name, Trace (sequence of func names), inclusive times, exclusive times
            yield (
                self.idx_name_map.get(func_id, str(func_id)),
                # Translate the function indices to names
                tuple(
                    self.idx_name_map.get(trace_func, str(trace_func))
                    for trace_func in trace_map_rev[trace_id]
                ),
                func_times,
            )




class TraceRecord:
    __slots__ = "func_id", "timestamp", "callees", "callees_time", "morestack", "morestack_time"

    def __init__(self, func_id: int, timestamp: int, morestack: bool) -> None:
        self.func_id: int = func_id
        self.timestamp: int = timestamp
        self.morestack: bool = morestack
        self.callees: int = 0
        self.callees_time: int = 0
        self.morestack_time: int = 0




def parse_traces(raw_data: pathlib.Path, func_map: dict[int, str], data_type: Type[DataT]) -> TraceContextsMap[DataT]:
    # Dummy TraceRecord for measuring exclusive time of the top-most function call
    record_stacks: dict[int, List[TraceRecord]] = {}
    trace_contexts = TraceContextsMap(func_map, data_type)
    first_record = True

    with open(raw_data, 'r') as data_handle:
        for record in data_handle:
            parts = record.strip().split(';')

            func_id = int(parts[0])
            event_type = int(parts[1])
            morestack = int(parts[2])
            goid = int(parts[3])
            ts = int(parts[4])

            # get first timestamp
            if first_record:
                trace_contexts.total_runtime = ts
                first_record = False

            if goid not in record_stacks:
                record_stacks[goid] = [TraceRecord(-1, 0, 0)]

            if event_type == 0:
                record_stacks[goid].append(TraceRecord(func_id, ts, morestack))
                continue
            
            found_matching_record = True
            while True:
                if not record_stacks[goid]:
                    found_matching_record = False
                    break
                top_record = record_stacks[goid].pop()

                if top_record.func_id != func_id:
                    log.warn(
                            f"stack mismatch: expected {func_map.get(top_record.func_id, top_record.func_id)} (skipping),"
                            f" but got {func_map.get(func_id, func_id)}."
                        )
                    continue

                # look for morestack
                while True:
                    if not record_stacks[goid]:
                        # there is nothing
                        break
                    if record_stacks[goid][-1].func_id != func_id:
                        # there is no morestack
                        break
                    if record_stacks[goid][-1].morestack == 0:
                        # recursion
                        break
                    # calculate morestack
                    record_stacks[goid].pop()
                    morestack_record = record_stacks[goid].pop()
                    top_record.morestack_time = top_record.timestamp - morestack_record.timestamp
                break
            
            if not found_matching_record:
                log.warn(f"no calling event for {func_map.get(func_id, func_id)} (skipping)")
                continue
            
            if (duration := ts - top_record.timestamp) < 0:
                log.error(
                        f"corrupted log: invalid timestamps for {func_map.get(func_id, func_id)}:"
                        f" duration {duration} is negative."
                    )
            # Obtain the trace from the stack
            trace_list = []
            for record in record_stacks[goid]:
                if record.morestack == 1:
                    trace_list.pop()
                if record.func_id != -1:
                    trace_list.append(record.func_id)
            trace = tuple(trace_list)
            # print(goid, trace)
            # Update the exclusive time of the parent call
            record_stacks[goid][-1].callees += 1
            record_stacks[goid][-1].callees_time += duration
            # Register the new function duration record
            trace_contexts.add(
                top_record.func_id,
                trace,
                duration,
                duration - top_record.callees_time,
                top_record.callees,
                top_record.morestack_time
            )

        trace_contexts.total_runtime = ts - trace_contexts.total_runtime
    return trace_contexts




def traces_to_pandas(trace_contexts: TraceContextsMap[FuncDataFlat]) -> pd.DataFrame:
    pandas_rows: list[tuple[Any, ...]] = []
    for func_name, trace, func_times in trace_contexts:
        pandas_rows.append(
            (
                func_name,
                " -> ".join(trace),
                func_times.call_count,
                func_times.callees_count,
                func_times.callees_count / func_times.inclusive_time,
                func_times.inclusive_time / NS_TO_MS,
                func_times.inclusive_time / trace_contexts.total_runtime,
                func_times.exclusive_time / NS_TO_MS,
                func_times.exclusive_time / trace_contexts.total_runtime,
                func_times.morestack_time / NS_TO_MS,
                func_times.morestack_time / trace_contexts.total_runtime,
                func_times.inclusive_time / func_times.call_count / NS_TO_MS,
                func_times.exclusive_time / func_times.call_count / NS_TO_MS,
                func_times.incl_t_min,
                func_times.excl_t_min,
                func_times.incl_t_max,
                func_times.excl_t_max,
            )
        )
    df = pd.DataFrame(
        pandas_rows,
        columns=[
            "Function",
            "Trace",
            "Calls [#]",
            "Callees [#]",
            "Callees Mean [#]",
            "Total Inclusive T [ms]",
            "Total Inclusive T [%]",
            "Total Exclusive T [ms]",
            "Total Exclusive T [%]",
            "Total Morestack T [ms]",
            "Total Morestack T [%]",
            "I Mean",
            "E Mean",
            "I Min",
            "E Min",
            "I Max",
            "E Max",
        ],
    )
    df.sort_values(by=["Total Exclusive T [%]"], inplace=True, ascending=False)
    return df




def pandas_to_resources(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Transforms pandas dataframe to list of resources

    :param df: pandas dataframe
    :return: list of resources
    """
    resources = []
    for _, row in df.iterrows():
        function = row["Function"]
        trace = row["Trace"].split(" -> ") if row["Trace"] else []
        ncalls = row["Calls [#]"]

        for col in df.columns:
            if col in ("Function", "Trace", "Calls [#]"):
                continue
            resources.append(
                {
                    "amount": row[col],
                    "uid": function,
                    "ncalls": ncalls,
                    "type": "time",
                    "subtype": col,
                    "trace": [{"func": f} for f in trace],
                }
            )
    return resources