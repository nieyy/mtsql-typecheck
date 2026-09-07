"""Per-attempt detailed audit (audit_trace_detailed, design 6.5, Phase 2).

The honest traces come from the real engine run against the real
``JsonlTraceSink`` (helpers reused from test_audit.py); the multi-group
traces are re-chained by the test side.  Each test pins the contrast with
``audit_trace``: the detailed audit reports EVERY attempt instead of
stopping at the first problem, unaudited attempts are never reported as
verified, and a limit hit is ``limit_exhausted``, never a verdict.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.oracle import ComparisonBudget
from mtsql_typecheck.reduction import audit as audit_mod
from mtsql_typecheck.reduction.audit import (
    EVIDENCE_PROFILE_FULL_MARKED,
    EVIDENCE_PROFILE_LEGACY,
    EVIDENCE_PROFILE_NONE,
    SEMANTIC_FULL_VERIFIED,
    SEMANTIC_MISMATCH,
    SEMANTIC_NOT_AUDITED,
    AttemptOutcome,
    audit_trace,
    audit_trace_detailed,
)
from mtsql_typecheck.reduction.trace import (
    TRACE_STATUS_COMPLETE,
    TRACE_STATUS_PARTIAL,
    TraceReadLimits,
    read_trace,
)

import test_audit as ta
import test_trace as tt

_BUDGET = ComparisonBudget()

# group 1 / 2 / 3 attempt ids of the honest engine trace (one attempt per
# original-replay group; group 4 holds the three reduce attempts).
_ATTEMPT_KINDS = ("REQUESTED", "EXPECTATION", "EVIDENCE", "COMPARISON")


def _honest_root(tmp_path: Path) -> Path:
    root = tmp_path / "honest"
    ta._run_engine_trace(root)
    return root


def _outcome_keys(outcomes) -> list[tuple[int, str, str]]:
    return [(o.group_index, o.attempt_id, o.status) for o in outcomes]


# --------------------------------------------------------------------------
# Honest trace: every attempt of every group is reported
# --------------------------------------------------------------------------


def test_honest_trace_reports_every_attempt_full_verified(tmp_path: Path) -> None:
    root = _honest_root(tmp_path)
    structural = read_trace(root)
    assert structural.trace_status == TRACE_STATUS_COMPLETE

    detailed = audit_trace_detailed(root, _BUDGET)
    assert detailed.structural_status == TRACE_STATUS_COMPLETE
    assert detailed.evidence_profile == EVIDENCE_PROFILE_FULL_MARKED
    assert detailed.records_verified == structural.records_verified
    assert detailed.best_payload_ref == structural.best_payload_ref
    assert detailed.limit_exhausted is False
    # 4 groups: three one-attempt replay groups and the three reduce attempts.
    assert len(detailed.attempt_outcomes) == 6
    assert all(
        outcome.status == SEMANTIC_FULL_VERIFIED
        for outcome in detailed.attempt_outcomes
    )
    assert [key[0] for key in _outcome_keys(detailed.attempt_outcomes)] == [
        1, 2, 3, 4, 4, 4,
    ]


def test_all_none_limits_give_identical_detailed_results(tmp_path: Path) -> None:
    root = _honest_root(tmp_path)
    assert audit_trace_detailed(root, _BUDGET) == audit_trace_detailed(
        root, _BUDGET, limits=TraceReadLimits()
    )


# --------------------------------------------------------------------------
# Mismatch and unverifiable attempts do not stop the detailed audit
# --------------------------------------------------------------------------


def _three_group_trace_with_forgery_and_gap(root: Path) -> None:
    """Rewrite the honest trace into exactly three groups: group 1 honest,
    group 2 with a forged comparison hash, group 3 without an EXPECTATION
    record (grammar-legal failure branch)."""
    ta._run_engine_trace(root)
    records = ta._load_records(root)
    kinds = [record["kind"] for record in records]
    replays = [index for index, kind in enumerate(kinds) if kind == "REPLAY"]
    kept = records[: replays[2] + 1]
    comparisons = [
        index for index, record in enumerate(kept) if record["kind"] == "COMPARISON"
    ]
    assert len(comparisons) == 3
    # Group 2: forge the recorded comparison hash (the record chain is
    # rebuilt afterwards, so this is structurally valid).
    kept[comparisons[1]]["inline"]["comparison_hash"] = "e" * 64
    # Group 3: drop the EXPECTATION record -> no full document set.
    expectation_index = next(
        index
        for index, record in enumerate(kept)
        if record["kind"] == "EXPECTATION" and comparisons[1] < index < comparisons[2]
    )
    del kept[expectation_index]
    # Close the trace with FINISHED and renumber the seq of every kept
    # record (the deletion leaves a gap otherwise).
    kept.append(
        {
            "kind": "FINISHED",
            "payload_ref": None,
            "inline": {"outcome": "UNCHANGED"},
            "prev_hash": "",
            "hash": "",
            "seq": 0,
        }
    )
    for index, record in enumerate(kept, start=1):
        record["seq"] = index
    ta._write_records(root, kept)


def test_detailed_audit_reports_all_groups_while_audit_trace_stops(
    tmp_path: Path,
) -> None:
    root = tmp_path / "mixed"
    _three_group_trace_with_forgery_and_gap(root)
    assert read_trace(root).trace_status == TRACE_STATUS_COMPLETE

    # The plain audit still stops at the first problem (group 2).
    plain = audit_trace(root, _BUDGET)
    assert plain.semantic_status == SEMANTIC_MISMATCH
    assert "group 2" in plain.detail

    # The detailed audit continues: group 1 verified, group 2 mismatch,
    # group 3 honestly unverifiable.
    detailed = audit_trace_detailed(root, _BUDGET)
    assert detailed.structural_status == TRACE_STATUS_COMPLETE
    assert detailed.evidence_profile == EVIDENCE_PROFILE_FULL_MARKED
    assert detailed.limit_exhausted is False
    assert len(detailed.attempt_outcomes) == 3
    by_group = {
        outcome.group_index: outcome for outcome in detailed.attempt_outcomes
    }
    assert by_group[1].status == SEMANTIC_FULL_VERIFIED
    assert by_group[2].status == SEMANTIC_MISMATCH
    assert "comparison_hash" in by_group[2].detail
    assert by_group[3].status == SEMANTIC_NOT_AUDITED
    assert "lacks the full document set" in by_group[3].detail
    assert "EXPECTATION" in by_group[3].detail


def test_legacy_trace_yields_no_attempt_outcomes(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    ta._run_engine_trace(root)
    records = ta._load_records(root)
    for obj in records:
        if obj["kind"] == "START":
            del obj["inline"]["evidence_profile"]
    ta._write_records(root, records)
    assert read_trace(root).trace_status == TRACE_STATUS_COMPLETE

    detailed = audit_trace_detailed(root, _BUDGET)
    assert detailed.structural_status == TRACE_STATUS_COMPLETE
    assert detailed.evidence_profile == EVIDENCE_PROFILE_LEGACY
    assert detailed.attempt_outcomes == ()
    assert detailed.limit_exhausted is False


def test_partial_trace_yields_no_attempt_outcomes(tmp_path: Path) -> None:
    root = tmp_path / "partial"
    ta._run_engine_trace(root)
    records = [obj for obj in ta._load_records(root) if obj["kind"] != "FINISHED"]
    ta._write_records(root, records)
    assert read_trace(root).trace_status == TRACE_STATUS_PARTIAL

    detailed = audit_trace_detailed(root, _BUDGET)
    assert detailed.structural_status == TRACE_STATUS_PARTIAL
    assert detailed.evidence_profile == EVIDENCE_PROFILE_NONE
    assert detailed.attempt_outcomes == ()
    assert detailed.limit_exhausted is False


# --------------------------------------------------------------------------
# Limit exhaustion
# --------------------------------------------------------------------------


def test_structural_limit_exhaustion_is_reported_not_raised(tmp_path: Path) -> None:
    root = tmp_path / "out"
    sink = tt.new_sink(tmp_path)
    tt.drive_run(sink, tt.Chain())
    sink.close()

    detailed = audit_trace_detailed(
        root, _BUDGET, limits=TraceReadLimits(max_records=10)
    )
    assert detailed.limit_exhausted is True
    assert detailed.structural_status == "UNKNOWN"
    assert detailed.records_verified == 0
    assert detailed.best_payload_ref is None
    # No attempt could be grouped: one group-level outcome, empty attempt_id.
    assert detailed.attempt_outcomes == (
        AttemptOutcome(
            group_index=1,
            attempt_id="",
            status=SEMANTIC_NOT_AUDITED,
            detail=detailed.attempt_outcomes[0].detail,
        ),
    )
    assert detailed.attempt_outcomes[0].detail.startswith("budget_exhausted:")


def test_per_attempt_limit_abort_keeps_prior_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A budget hit while loading an attempt's documents marks THAT attempt
    NOT_AUDITED and stops; already-audited attempts keep their verdicts."""
    root = _honest_root(tmp_path)
    original = audit_mod._payload_bytes
    calls = {"count": 0}

    def aborting_payload_bytes(root_path, ref, what, limits=None):
        calls["count"] += 1
        if calls["count"] == 9:  # first document read of the 3rd attempt
            from mtsql_typecheck.reduction.trace import TraceBudgetError

            raise TraceBudgetError(
                "trace read limit exceeded: max_dependency_bytes=1: injected"
            )
        return original(root_path, ref, what, limits)

    monkeypatch.setattr(audit_mod, "_payload_bytes", aborting_payload_bytes)

    detailed = audit_trace_detailed(root, _BUDGET)
    assert detailed.limit_exhausted is True
    assert detailed.structural_status == TRACE_STATUS_COMPLETE
    assert [outcome.status for outcome in detailed.attempt_outcomes] == [
        SEMANTIC_FULL_VERIFIED,
        SEMANTIC_FULL_VERIFIED,
        SEMANTIC_NOT_AUDITED,
    ]
    aborted = detailed.attempt_outcomes[2]
    assert aborted.group_index == 3
    assert aborted.detail.startswith("budget_exhausted:")
    # Later attempts are absent (never reported as verified).
    assert len(detailed.attempt_outcomes) == 3


# --------------------------------------------------------------------------
# Streaming: long traces do not retain attempt payloads
# --------------------------------------------------------------------------


def _long_trace(base: Path, root: Path, groups: int) -> int:
    """Re-chain the honest run's first attempt into ``groups`` replay groups
    of three attempts each; payload files are reused (content-addressed).

    Returns the byte size of one attempt's four published documents."""
    ta._run_engine_trace(base)
    records = ta._load_records(base)
    kinds = [record["kind"] for record in records]
    first_request = kinds.index("REQUESTED")
    first_comparison = kinds.index("COMPARISON")
    attempt_records = records[first_request : first_comparison + 1]
    assert [record["kind"] for record in attempt_records] == [
        "REQUESTED",
        "EXPECTATION",
        "EVIDENCE",
        "RESULT",
        "COMPARISON",
    ]
    attempt_payload_total = sum(
        record["payload_ref"]["size_bytes"]
        for record in attempt_records
        if record["payload_ref"] is not None
    )

    script = tt.Script()
    for payload_file in (base / "files").iterdir():
        script.files[f"files/{payload_file.name}"] = payload_file.read_bytes()
    snapshot, start = records[0], records[1]
    script.add("SNAPSHOT", payload_ref=snapshot["payload_ref"], inline=snapshot["inline"])
    script.add("START", inline=start["inline"])
    for group in range(1, groups + 1):
        for attempt in range(3):
            for record in attempt_records:
                inline = copy.deepcopy(record["inline"])
                inline["attempt_id"] = f"g{group}-a{attempt}"
                script.add(
                    record["kind"],
                    payload_ref=record["payload_ref"],
                    inline=inline,
                )
        script.add("REPLAY", inline={})
    script.add("FINISHED", inline={"outcome": "UNCHANGED"})
    script.write(root)
    return attempt_payload_total


def test_long_trace_is_fully_processed_without_retaining_payloads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "base"
    root = tmp_path / "long"
    attempt_payload_total = _long_trace(base, root, groups=200)

    original = audit_mod._payload_bytes
    accounting = {"outstanding": 0, "peak": 0}

    def counting_payload_bytes(root_path, ref, what, limits=None):
        accounting["outstanding"] += ref.size_bytes
        accounting["peak"] = max(accounting["peak"], accounting["outstanding"])
        try:
            return original(root_path, ref, what, limits)
        finally:
            accounting["outstanding"] -= ref.size_bytes

    monkeypatch.setattr(audit_mod, "_payload_bytes", counting_payload_bytes)

    detailed = audit_trace_detailed(root, _BUDGET)
    assert detailed.limit_exhausted is False
    assert detailed.structural_status == TRACE_STATUS_COMPLETE
    # 200 groups x 3 attempts, every one audited (no early stop).
    assert len(detailed.attempt_outcomes) == 600
    assert all(
        outcome.status == SEMANTIC_FULL_VERIFIED
        for outcome in detailed.attempt_outcomes
    )
    # Payload memory rule: at most one attempt's documents are alive at a
    # time (600 attempts re-read the same content-addressed payloads).
    assert accounting["outstanding"] == 0
    assert 0 < accounting["peak"] <= attempt_payload_total
