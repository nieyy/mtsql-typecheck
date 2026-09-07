"""Bounded read-side access for reduction/trace.py (design 6.5, Phase 2).

Every over-limit expectation is hand-written: the traces are built by the
test-side ``Script`` helper (or the real sink via ``drive_run``) from
test_trace.py, and each test pins BOTH outcomes — the cap fires with a
``TraceBudgetError`` naming the cap, and the same input without the cap (or
with ``limits=None``) keeps the historical verdict.  A limit hit must never
be misreported as trace corruption.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.oracle import EVIDENCE_APPEND_BUDGET
from mtsql_typecheck.reduction.trace import (
    TRACE_STATUS_COMPLETE,
    TRACE_STATUS_CORRUPT,
    JsonlTraceSink,
    TraceBudgetError,
    TraceReadLimits,
    read_trace,
)

import test_trace as tt

# --------------------------------------------------------------------------
# TraceReadLimits construction
# --------------------------------------------------------------------------


def test_all_none_limits_means_unlimited_and_is_constructible() -> None:
    limits = TraceReadLimits()
    assert limits.max_records is None
    assert limits.max_line_bytes is None
    assert limits.max_dependency_bytes is None
    assert limits.max_dependencies is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_records": -1},
        {"max_records": True},
        {"max_records": "10"},
        {"max_line_bytes": -1},
        {"max_line_bytes": False},
        {"max_dependency_bytes": -3},
        {"max_dependency_bytes": 1.5},
        {"max_dependencies": True},
    ],
)
def test_invalid_limit_values_are_rejected(kwargs: dict) -> None:
    with pytest.raises(TraceBudgetError):
        TraceReadLimits(**kwargs)


def test_zero_is_a_valid_immediate_cap() -> None:
    limits = TraceReadLimits(max_records=0, max_line_bytes=0)
    assert limits.max_records == 0
    assert limits.max_line_bytes == 0


def test_limits_are_frozen() -> None:
    limits = TraceReadLimits(max_records=1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.max_records = 2  # type: ignore[misc]


# --------------------------------------------------------------------------
# limits=None keeps the historical behaviour byte-for-byte
# --------------------------------------------------------------------------


def test_limits_none_and_all_none_give_identical_results(tmp_path: Path) -> None:
    sink = tt.new_sink(tmp_path)
    tt.drive_run(sink, tt.Chain())
    sink.close()
    root = tmp_path / "out"
    assert read_trace(root) == read_trace(root, limits=TraceReadLimits())


# --------------------------------------------------------------------------
# max_records
# --------------------------------------------------------------------------


def _sink_run(root: Path):
    sink = JsonlTraceSink(root, EVIDENCE_APPEND_BUDGET)
    tt.drive_run(sink, tt.Chain())
    sink.close()
    return root


def test_max_records_cap_fires_naming_the_cap(tmp_path: Path) -> None:
    root = _sink_run(tmp_path / "out")
    unlimited = read_trace(root)
    assert unlimited.trace_status == TRACE_STATUS_COMPLETE
    assert unlimited.records_verified == 35

    with pytest.raises(TraceBudgetError) as excinfo:
        read_trace(root, limits=TraceReadLimits(max_records=10))
    assert "max_records=10" in str(excinfo.value)


def test_max_records_cap_is_inclusive(tmp_path: Path) -> None:
    root = _sink_run(tmp_path / "out")
    # Exactly the record count is fine; one less is not.
    assert read_trace(root, limits=TraceReadLimits(max_records=35)).trace_status == (
        TRACE_STATUS_COMPLETE
    )
    with pytest.raises(TraceBudgetError):
        read_trace(root, limits=TraceReadLimits(max_records=34))


def test_max_records_is_checked_before_decoding_a_corrupt_line(
    tmp_path: Path,
) -> None:
    """A cap hit must surface as TraceBudgetError even when the NEXT line is
    undecodable garbage; without the cap the same line is CORRUPT."""
    script = tt.Script()
    tt.add_head(script, tt.START_COMPLEXITY)
    script.raw(b"this is not json\n")
    root = script.write(tmp_path / "corrupt")

    unlimited = read_trace(root)
    assert unlimited.trace_status == TRACE_STATUS_CORRUPT

    with pytest.raises(TraceBudgetError) as excinfo:
        read_trace(root, limits=TraceReadLimits(max_records=2))
    assert "max_records=2" in str(excinfo.value)


# --------------------------------------------------------------------------
# max_line_bytes
# --------------------------------------------------------------------------


def test_max_line_bytes_cap_fires_naming_the_cap(tmp_path: Path) -> None:
    root = _sink_run(tmp_path / "out")
    with pytest.raises(TraceBudgetError) as excinfo:
        read_trace(root, limits=TraceReadLimits(max_line_bytes=32))
    assert "max_line_bytes=32" in str(excinfo.value)
    # The same trace passes with a generous line cap.
    assert read_trace(
        root, limits=TraceReadLimits(max_line_bytes=1_000_000)
    ).trace_status == TRACE_STATUS_COMPLETE


def test_max_line_bytes_is_checked_before_decoding(tmp_path: Path) -> None:
    """The over-long line is rejected on its raw bytes even though it is also
    invalid JSON (so decoding it would report corruption instead)."""
    script = tt.Script()
    tt.add_head(script, tt.START_COMPLEXITY)
    script.raw(b"x" * 5000 + b"\n")
    root = script.write(tmp_path / "longline")

    unlimited = read_trace(root)
    assert unlimited.trace_status == TRACE_STATUS_CORRUPT

    with pytest.raises(TraceBudgetError) as excinfo:
        read_trace(root, limits=TraceReadLimits(max_line_bytes=1024))
    assert "max_line_bytes=1024" in str(excinfo.value)


# --------------------------------------------------------------------------
# max_dependency_bytes
# --------------------------------------------------------------------------


def test_max_dependency_bytes_cap_fires_naming_the_cap(tmp_path: Path) -> None:
    script = tt.Script()
    # The SNAPSHOT dependency's content is opaque to the audit (only layout,
    # size and hash are verified), so a 64 KiB payload is a legal trace.
    big_payload = b"A" * (64 * 1024)
    original = script.payload(big_payload)
    script.add("SNAPSHOT", payload_ref=original, inline={"case_id": tt.CASE_ID})
    script.add(
        "START",
        inline={
            "complexity": tt.START_COMPLEXITY,
            "payload_ref": original,
            "case_id": tt.CASE_ID,
        },
    )
    script.add("FINISHED", inline={"outcome": "UNCHANGED"})
    root = script.write(tmp_path / "bigdep")

    unlimited = read_trace(root)
    assert unlimited.trace_status == TRACE_STATUS_COMPLETE

    with pytest.raises(TraceBudgetError) as excinfo:
        read_trace(root, limits=TraceReadLimits(max_dependency_bytes=1024))
    assert "max_dependency_bytes=1024" in str(excinfo.value)


# --------------------------------------------------------------------------
# max_dependencies
# --------------------------------------------------------------------------


def test_max_dependencies_cap_fires_naming_the_cap(tmp_path: Path) -> None:
    script = tt.Script()
    tt.add_head(script, tt.START_COMPLEXITY)
    tt.add_group(script, "g")
    script.add("FINISHED", inline={"outcome": "UNCHANGED"})
    root = script.write(tmp_path / "deps")

    unlimited = read_trace(root)
    assert unlimited.trace_status == TRACE_STATUS_COMPLETE

    with pytest.raises(TraceBudgetError) as excinfo:
        read_trace(root, limits=TraceReadLimits(max_dependencies=3))
    assert "max_dependencies=3" in str(excinfo.value)
    # The head plus one group publishes exactly 7 distinct dependency files.
    assert read_trace(
        root, limits=TraceReadLimits(max_dependencies=7)
    ).trace_status == TRACE_STATUS_COMPLETE


def test_max_dependencies_counts_distinct_files_not_references(
    tmp_path: Path,
) -> None:
    """Many records may reference the SAME dependency file; the cap counts
    distinct files, so one shared file passes a cap of 1."""
    script = tt.Script()
    script.add("SNAPSHOT", inline={"case_id": tt.CASE_ID})
    script.add(
        "START",
        inline={"complexity": tt.START_COMPLEXITY, "payload_ref": None, "case_id": tt.CASE_ID},
    )
    shared = script.payload(tt.canonical({"evidence": "shared"}))
    for group in range(2):
        for attempt in range(3):
            label = f"s{group}{attempt}"
            script.add("REQUESTED", inline={"attempt_id": label})
            script.add("EXPECTATION", inline={"request_hash": tt.HASH1})
            script.add("EVIDENCE", payload_ref=shared, inline={"attempt_id": label})
            script.add("RESULT", inline={"attempt_id": label})
            script.add("COMPARISON", payload_ref=shared, inline={"attempt_id": label})
        script.add("REPLAY", inline={})
    script.add("FINISHED", inline={"outcome": "UNCHANGED"})
    root = script.write(tmp_path / "shared")

    audit = read_trace(root, limits=TraceReadLimits(max_dependencies=1))
    assert audit.trace_status == TRACE_STATUS_COMPLETE
    assert audit.records_verified == 2 + 2 * (3 * 5 + 1) + 1
