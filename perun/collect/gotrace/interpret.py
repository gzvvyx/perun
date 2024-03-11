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
# from perun.utils import log



NS_TO_MS = 1000000




DataT = TypeVar("DataT", bound="FuncData")


class FuncData(ABC):
    @abstractmethod
    def update(self, inclusive_t: int, exclusive_t: int, callees_cnt: int) -> None:
        ...

class FuncDataFlat(FuncData):
    __slots__ = [
        "inclusive_time",
        "exclusive_time",
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
        self.incl_t_min: int = -1
        self.incl_t_max: int = 0
        self.excl_t_min: int = -1
        self.excl_t_max: int = 0
        self.call_count: int = 0
        self.callees_count: int = 0

    def update(self, inclusive_t: int, exclusive_t: int, callees_cnt: int) -> None:
        self.inclusive_time += inclusive_t
        self.exclusive_time += exclusive_t
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
    __slots__ = "idx_name_map", "data_t", "durations", "total_runtime"

    def __init__(self, idx_name_map: dict[int, str], data_type: Type[DataT]) -> None:
        self.idx_name_map: dict[int, str] = idx_name_map
        self.data_t: Type[DataT] = data_type
        # Function ID, Trace ID -> Inclusive, Exclusive durations, callees count
        self.durations: dict[int, DataT] = {}
        self.total_runtime: int = 0

    def add(
        self, func_id: int, inclusive_t: int, exclusive_t: int, callees: int
    ) -> None:
        func_times = self.durations.setdefault(func_id, self.data_t())
        func_times.update(inclusive_t, exclusive_t, callees)

    def __iter__(self) -> Iterator[tuple[str, tuple[str, ...], DataT]]:
        # Reverse the trace map for fast retrieval of Trace ID -> Trace
        for func_id, func_times in self.durations.items():
            # Func name, Trace (sequence of func names), inclusive times, exclusive times
            yield (
                self.idx_name_map.get(func_id, str(func_id)),
                # Translate the function indices to names
                func_times,
            )


class TraceRecord:
    __slots__ = "func_id", "timestamp", "callees", "callees_time"

    def __init__(self, func_id: int, timestamp: int) -> None:
        self.func_id: int = func_id
        self.timestamp: int = timestamp
        self.callees: int = 0
        self.callees_time: int = 0



def parse_traces(raw_data: pathlib.Path, func_map: dict[int, str], data_type: Type[DataT]) -> TraceContextsMap[DataT]:
    # Dummy TraceRecord for measuring exclusive time of the top-most function call
    record_stack: list[TraceRecord] = [TraceRecord(-1, 0)]
    trace_contexts = TraceContextsMap(func_map, data_type)

    with open(raw_data, 'r') as data_handle:
        for record in data_handle:
            parts = record.strip().split(';')

            func_id = int(parts[0])
            event_type = int(parts[1])
            # pid = int(parts[2])
            # tgid = int(parts[3])
            # goid = int(parts[4])
            ts = int(parts[5])

            if event_type == 0:
                record_stack.append(TraceRecord(func_id, ts))
                continue
            found_matching_record = True
            while True:
                if not record_stack:
                    found_matching_record = False
                    break
                top_record = record_stack.pop()

                if top_record.func_id != func_id:
                    print("Mismatched function IDs:", func_map[top_record.func_id], func_map[func_id], "(skipping)")
                    continue
                break
            if not found_matching_record:
                print("No matching record found for func_id:", func_id)
                continue
            
            if (duration := ts - top_record.timestamp) < 0:
                print("corrupted log")
            # Obtain the trace from the stack
            # trace = tuple(record.func_id for record in record_stack if record.func_id != -1)
            # Update the exclusive time of the parent call
            record_stack[-1].callees += 1
            record_stack[-1].callees_time += duration
            # Register the new function duration record
            trace_contexts.add(
                top_record.func_id,
                duration,
                duration - top_record.callees_time,
                top_record.callees
            )
            # print(func_map[top_record.func_id], "inc:", duration / NS_TO_MS, "ms", "excl", duration - top_record.callees_time / NS_TO_MS, "ms", "callees:", top_record.callees)
        trace_contexts.total_runtime = ts - trace_contexts.total_runtime
    return trace_contexts


def traces_flat_to_pandas(trace_contexts: TraceContextsMap[FuncDataFlat]) -> pd.DataFrame:
    pandas_rows: list[tuple[Any, ...]] = []
    for func_name, func_times in trace_contexts:
        pandas_rows.append(
            (
                func_name,
                func_times.call_count,
                func_times.callees_count,
                func_times.callees_count / func_times.inclusive_time,
                func_times.inclusive_time / NS_TO_MS,
                func_times.inclusive_time / trace_contexts.total_runtime,
                func_times.exclusive_time / NS_TO_MS,
                func_times.exclusive_time / trace_contexts.total_runtime,
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
            "Calls [#]",
            "Callees [#]",
            "Callees Mean [#]",
            "Total Inclusive T [ms]",
            "Total Inclusive T [%]",
            "Total Exclusive T [ms]",
            "Total Exclusive T [%]",
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