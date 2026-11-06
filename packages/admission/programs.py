"""Bounded built-in programs. Program digest = sha256(name + exact source)."""
from __future__ import annotations

import csv
import inspect
import io

from packages.contracts.models import Program


def row_count_v1(data: bytes) -> dict:
    rows = list(csv.reader(io.StringIO(data.decode("utf-8"))))
    return {"program": "row_count_v1", "rows_total": len(rows),
            "data_rows": max(len(rows) - 1, 0), "header": rows[0] if rows else []}


BUILTIN_PROGRAMS = {"row_count_v1": row_count_v1}


def builtin_program(name: str) -> Program:
    return Program(name=name, source=inspect.getsource(BUILTIN_PROGRAMS[name]))
