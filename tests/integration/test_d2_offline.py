"""T01/P01 offline integration: import closed loop, fixture-to-gate closed
loop, and a full replay -> reduce -> trace-audit run over the real JSONL
trace sink.

Everything here runs without a database connection and without network
access: execution facts enter only through hand-written ``ExecutionPort``
fakes and synthetic (``synthetic=True``) evidence fixtures, and the trace
is written to a temporary output root.  Expected statuses and case ids are
hand-written or recomputed independently through D1 primitives (``codec``,
``apply_transform``), never read back from the code paths under test.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.codec import case_id_of, load_payload
from mtsql_typecheck.contracts.oracle import (
    EVIDENCE_APPEND_BUDGET,
    ComparisonStatus,
    ReductionOutcome,
    StopReason,
)
from mtsql_typecheck.generation.transforms import apply_transform
from mtsql_typecheck.generation.validation import validate_case
from mtsql_typecheck.reduction.trace import JsonlTraceSink, read_trace

FIXTURES = Path(__file__).parents[1] / "contract" / "fixtures" / "d2"

_ALL_D2_MODULES = (
    "mtsql_typecheck.contracts.case",
    "mtsql_typecheck.contracts.codec",
    "mtsql_typecheck.contracts.execution",
    "mtsql_typecheck.contracts.oracle",
    "mtsql_typecheck.oracle.exact",
    "mtsql_typecheck.oracle.fingerprint",
    "mtsql_typecheck.oracle.gates",
    "mtsql_typecheck.reduction.replay",
    "mtsql_typecheck.reduction.strategy",
    "mtsql_typecheck.reduction.trace",
    "mtsql_typecheck.reduction.engine",
)

# Fixture name -> the hand-written gate verdict this closed loop expects
# (mirroring the per-fixture unit expectations, not re-deriving them).
# Every fixture in the directory must flow through the gates to an explicit
# verdict; none may crash or fake a result.
# name -> (expected status, expected comparable)
_FIXTURE_VERDICTS = {
    "evidence_success_match": (ComparisonStatus.MATCH, True),
    "evidence_success_candidate": (ComparisonStatus.MISMATCH_CANDIDATE, True),
    # cleanup != DONE does not block an otherwise complete comparison.
    "evidence_cleanup_failed": (ComparisonStatus.MATCH, True),
    # A structured preflight rejection is an explicit NOT_APPLICABLE.
    "evidence_preflight_rejection": (ComparisonStatus.NOT_APPLICABLE, False),
}


def test_all_d2_modules_import_in_a_fresh_offline_process() -> None:
    """No I/O at import time: a fresh interpreter imports every D2 module
    (plus the D1 core they sit on) and exits cleanly and silently."""
    program = "; ".join(f"import {module}" for module in _ALL_D2_MODULES)
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""


@pytest.mark.parametrize("name", sorted(p.stem for p in FIXTURES.glob("*.json")))
def test_every_d2_fixture_reduces_to_an_explicit_verdict(name: str) -> None:
    """Each synthetic execution-evidence fixture flows through the frozen
    codec into ``compare_case_document`` and yields an explicit verdict."""
    from mtsql_typecheck.oracle.gates import compare_case_document
    from mtsql_typecheck.contracts.oracle import ComparisonBudget

    doc = json.loads(FIXTURES.joinpath(f"{name}.json").read_text(encoding="utf-8"))
    outcome = compare_case_document(
        doc["request"], doc.get("expectation"), doc["evidence"], ComparisonBudget()
    )
    assert outcome is not None
    if name in _FIXTURE_VERDICTS:
        expected_status, expected_comparable = _FIXTURE_VERDICTS[name]
        assert outcome.status is expected_status, name
        assert outcome.comparable is expected_comparable
    else:
        # Failure-path fixtures must never fake a comparable result.
        assert outcome.comparable is False
        assert outcome.status is ComparisonStatus.INCONCLUSIVE


def test_replay_reduce_trace_closed_loop(tmp_path: Path) -> None:
    """End-to-end: verified synthetic candidate -> 3-attempt replay ->
    bounded reduction with real JSONL tracing -> read-only audit rebuilds
    the accepted best."""
    sys.path.insert(0, str(Path(__file__).parents[1] / "unit" / "reduction"))
    from engine_fakes import ReductionExecutor, run_reduction
    from replay_fakes import CANDIDATE_A_ROWS, CANDIDATE_B_ROWS, CandidateBundle, run_replay

    from mtsql_typecheck.contracts.case import RemoveRows

    bundle = CandidateBundle()

    # Original replay: three unscripted attempts return the candidate's own
    # mismatch observation, so the group must come back REPRODUCED before
    # any reduction may dispatch.  A dedicated executor instance keeps the
    # dispatch log separate from the reduction run below (the engine always
    # re-runs the original replay itself, from dispatch index 0).
    replay_executor = ReductionExecutor(bundle)
    replay = run_replay(bundle, replay_executor)
    assert replay.outcome.value == "REPRODUCED"
    assert replay.requested == 3
    assert replay.comparable == 3
    assert replay.matching_signature == 3

    # Reduction, scripted per dispatch index (the deterministic proposal
    # order is frozen in the strategy contract): the original replay used
    # dispatches 0-2, so proposal 1 (delete-all child) starts at index 3
    # and matches; proposal 2 (RemoveRows of the last two rids) runs its
    # own three-attempt group at indexes 4-6 and is accepted; every later
    # child keeps matching, so nothing else can be accepted and the search
    # completes with the accepted one-row best.
    executor = ReductionExecutor(bundle)
    executor.script[3] = (CANDIDATE_A_ROWS, CANDIDATE_A_ROWS)
    for index in (4, 5, 6):
        executor.script[index] = (CANDIDATE_A_ROWS[:1], CANDIDATE_B_ROWS[:1])
    for index in range(7, 20):
        executor.script[index] = (CANDIDATE_A_ROWS, CANDIDATE_A_ROWS)

    sink_root = tmp_path / "d2-trace"
    with JsonlTraceSink(sink_root, EVIDENCE_APPEND_BUDGET) as sink:
        result = run_reduction(bundle, executor, sink)

    assert result.outcome is ReductionOutcome.REDUCED
    assert result.stop_reason is StopReason.SEARCH_EXHAUSTED
    assert result.search_complete is True
    assert result.accepted >= 1
    assert result.has_reduction is True

    # The reported best is the accepted child, recomputed independently
    # through D1 apply_transform + case id derivation.
    expected_child = apply_transform(
        bundle.candidate.request.payload, RemoveRows((2, 3))
    ).child.payload
    assert validate_case(expected_child).status.value == "VALID_STATIC"
    assert result.best_case_id == case_id_of(expected_child)

    # The on-disk trace is a COMPLETE audit whose best is the same child:
    # the last verified ACCEPTED record is the only persistent authority.
    audit = read_trace(sink_root)
    assert audit.trace_status == "COMPLETE", audit.detail
    assert audit.best_source == "ACCEPTED"
    assert audit.best_payload_ref is not None
    artifact = sink_root / audit.best_payload_ref.path
    best_payload = load_payload(artifact.read_bytes())
    assert case_id_of(best_payload) == result.best_case_id
