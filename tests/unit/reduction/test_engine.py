"""Reduction engine behaviour tests (oracle-d2-contract section 9).

Every expected counter, outcome and trace shape below is hand-written from
the frozen contract and the deterministic proposal order of the fixture
payload -- none is derived from the engine under test.  The fixture is the
same reviewed three-row signed-widen candidate as the replay tests; its
proposal order (verified against the strategy's frozen order, design 6.4.4)
is:

  1 RemoveRows((1,2,3))   6 ReplaceValue(1,NULL)  11 ReplaceValue(2,0)   *
  2 RemoveRows((2,3))     7 ReplaceValue(1,0)     12 ReplaceValue(2,1)   *
  3 RemoveRows((1,))      8 ReplaceValue(1,1)     13 ReplaceValue(2,-1)  *
  4 RemoveRows((2,))      9 ReplaceValue(1,-1)    14 ReplaceValue(3,NULL)
  5 RemoveRows((3,))     10 ReplaceValue(1,-64)   ... (same-or-worse: *)

Proposals 11-13 replace the NULL row value with a non-NULL candidate and are
rejected before execution (complexity never decreases); proposals 14-18 are
only reachable when the best has a third row.  Dispatch indices in the
executor scripts are 0-based across the whole run: 0-2 are the original
replay group.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from mtsql_typecheck.contracts.case import (
    IntegerValue,
    NullValue,
    RemoveRows,
    ReplaceValue,
)
from mtsql_typecheck.contracts.execution import (
    AttemptFailure,
    AttemptStage,
    CleanupState,
    TerminalReceipt,
    TerminationState,
)
from mtsql_typecheck.contracts.codec import canonical_json, case_id_of, sha256_hex
from mtsql_typecheck.contracts.oracle import (
    EVIDENCE_APPEND_BUDGET,
    CandidateInput,
    ComparisonBudget,
    ComparisonStatus,
    ReductionOutcome,
    ReductionPolicy,
    StopReason,
)
from mtsql_typecheck.generation.transforms import apply_transform
from mtsql_typecheck.generation.validation import validate_case
from mtsql_typecheck.oracle.gates import compare_case
from mtsql_typecheck.reduction.engine import reduce_candidate
from mtsql_typecheck.reduction.trace import (
    BEST_SOURCE_ACCEPTED,
    BEST_SOURCE_ORIGINAL,
    TRACE_STATUS_COMPLETE,
    JsonlTraceSink,
    read_trace,
)

from engine_fakes import (
    RecordingTraceSink,
    ReductionExecutor,
    run_reduction,
)
from replay_fakes import (
    CANDIDATE_A_ROWS,
    CANDIDATE_B_ROWS,
    CancelToken,
    CandidateBundle,
    StubClock,
    build_attempt,
    make_control,
)

# One replay group attempt in the trace grammar (design 6.4.6).
_ATTEMPT = ["REQUESTED", "EXPECTATION", "EVIDENCE", "RESULT", "COMPARISON"]

# Hand-derived fixture facts (independent of the code under test):
# 3 rows, 0 predicate nodes, 2 non-NULL values, |v| sum 255.
_ORIG_COMPLEXITY_HEAD = [3, 0, 2, 255]
# Accepted child (proposal 2, RemoveRows((2,3))): 1 row, 1 non-NULL, |v| 128.
_CHILD_COMPLEXITY_HEAD = [1, 0, 1, 128]

# Scripted result rows.
_MATCH = (CANDIDATE_A_ROWS, CANDIDATE_A_ROWS)
_MISMATCH_1ROW = ((IntegerValue(-128),), (IntegerValue(-127),))
_MISMATCH_2ROW = ((NullValue(), IntegerValue(127)), (NullValue(), IntegerValue(126)))


def accepted_group_comparisons(records):
    """The COMPARISON records of the group closed right before an ACCEPTED.

    Each attempt contributes [REQUESTED, EXPECTATION, EVIDENCE, RESULT,
    COMPARISON], so the walk skips the interleaved non-COMPARISON records of
    the group's attempts and stops at the preceding group boundary.
    """
    index = next(i for i, record in enumerate(records) if record.kind == "ACCEPTED")
    assert records[index - 1].kind == "REPLAY"
    cursor = index - 2
    comparisons = []
    while cursor >= 0 and records[cursor].kind not in (
        "REPLAY",
        "ACCEPTED",
        "SNAPSHOT",
        "START",
    ):
        if records[cursor].kind == "COMPARISON":
            comparisons.append(records[cursor])
        cursor -= 1
    return list(reversed(comparisons))


def single_row_bundle():
    """A verified one-row mismatch candidate (delete-all is its only proposal)."""
    request, expectation, evidence = build_attempt(
        run_id="run-reduce-1",
        attempt_id="attempt-orig",
        row_values=(IntegerValue(-128),),
    )
    comparison = compare_case(request, expectation, evidence, ComparisonBudget())
    assert comparison.status is ComparisonStatus.MISMATCH_CANDIDATE
    candidate = CandidateInput(
        payload=request.payload,
        request=request,
        expectation=expectation,
        evidence=evidence,
        comparison_hash=comparison.hash,
        source="test",
    )
    return candidate, comparison


# --------------------------------------------------------------------------
# Entry validation (zero dispatches, no trace frame)
# --------------------------------------------------------------------------


def test_missing_executor_fails_without_dispatch():
    bundle = CandidateBundle()
    result = run_reduction(bundle, None, None)
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.NO_EXECUTOR
    assert result.executions == 0
    assert result.proposals == 0
    assert result.accepted == 0
    assert result.has_reduction is False
    assert result.search_complete is False
    assert result.best_case_id == result.original_case_id


def test_none_candidate_fails_without_dispatch():
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    result = reduce_candidate(
        None, executor, None, ReductionPolicy(), make_control(StubClock())
    )
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.INVALID_CANDIDATE
    assert result.executions == 0
    assert result.proposals == 0
    assert executor.calls == []


def test_invalid_candidate_recompare_fails_before_any_dispatch():
    """A candidate whose stored evidence is a prepare-failure envelope (never
    a comparable mismatch observation) re-compares INCONCLUSIVE and is
    refused before the original replay, with zero dispatches."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    request, expectation, evidence = (
        bundle.candidate.request,
        bundle.candidate.expectation,
        bundle.candidate.evidence,
    )
    failure_evidence = dataclasses.replace(
        evidence,
        expectation=None,
        runtime_facts=None,
        a_context=None,
        b_context=None,
        a_query=None,
        b_query=None,
        isolation_receipt=None,
        setup_diagnostics=(),
        terminal=TerminalReceipt(
            attempt_id=request.attempt_id,
            termination=TerminationState.UNKNOWN,
            cleanup=CleanupState.PENDING,
            owned_objects=(),
        ),
        failure=AttemptFailure(
            stage=AttemptStage.PREPARE,
            code="EXECUTOR_EXCEPTION",
            side=None,
            diagnostics_ref=None,
        ),
        evidence_hash="",
    )
    # The recomputed comparison is INCONCLUSIVE, not a mismatch observation.
    recomputed = compare_case(
        request, expectation, failure_evidence, ComparisonBudget()
    )
    assert recomputed.status is ComparisonStatus.INCONCLUSIVE
    candidate = CandidateInput(
        payload=request.payload,
        request=request,
        expectation=expectation,
        evidence=failure_evidence,
        comparison_hash=recomputed.hash,
        source="test",
    )
    result = reduce_candidate(
        candidate, executor, None, ReductionPolicy(), make_control(StubClock())
    )
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.INVALID_CANDIDATE
    assert result.executions == 0
    assert result.proposals == 0
    assert executor.calls == []


# --------------------------------------------------------------------------
# Original replay gate
# --------------------------------------------------------------------------


def test_original_not_reproduced_fails_without_proposals():
    """The second replay attempt matches: the run stops after two dispatches
    and never reaches the proposal loop."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    executor.script[1] = _MATCH
    result = run_reduction(bundle, executor, None)
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.ORIGINAL_NOT_REPRODUCED
    assert result.executions == 2
    assert result.proposals == 0
    assert executor.prepares == 2
    assert result.has_reduction is False
    assert result.best_case_id == result.original_case_id


def test_original_reported_hashes_come_from_the_recompare():
    """original_comparison_hash/fingerprint are re-derived, never the
    candidate's recorded comparison hash."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    executor.script[3] = _MATCH
    result = run_reduction(bundle, executor, None)
    assert result.original_comparison_hash == bundle.comparison.hash
    assert result.original_fingerprint == bundle.fingerprint


# --------------------------------------------------------------------------
# Search outcomes
# --------------------------------------------------------------------------


def test_single_row_candidate_unchanged_after_matches():
    """The one-row candidate has six proposals (delete-all plus five value
    replacements on the single row); each child is strictly smaller, so each
    is executed once, matches, and the search ends UNCHANGED with the
    original as best."""
    candidate, _comparison = single_row_bundle()
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    for index in range(3, 9):
        executor.script[index] = _MATCH
    result = reduce_candidate(
        candidate, executor, None, ReductionPolicy(), make_control(StubClock())
    )
    assert result.outcome is ReductionOutcome.UNCHANGED
    assert result.stop_reason is StopReason.SEARCH_EXHAUSTED
    assert result.search_complete is True
    assert result.proposals == 6
    assert result.executions == 9  # 3 original attempts + 6 one-attempt groups
    assert result.accepted == 0
    assert result.unstable_candidates == 6
    assert result.rejected_static == 0
    assert result.inconclusive_candidates == 0
    assert result.has_reduction is False
    assert result.best_case_id == result.original_case_id


def test_happy_reduction_reduced_with_exact_counters():
    """Delete-all matches (unstable); proposal 2 (RemoveRows((2,3))) is
    accepted after three matching attempts; the search restarts from the
    one-row best, its delete-all child is already visited, one value proposal
    fails plain execution (inconclusive), the remaining four match, and the
    search completes REDUCED.

    Hand-derived counters: proposals 8 (2 + visited 1 + 5 values),
    executions 12 (3 + 1 + 3 + 1 + 4), unstable 5, inconclusive 1,
    rejected_static 1.
    """
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    executor.script[3] = _MATCH  # proposal 1: delete-all, 0-row child -> MATCH
    for index in (4, 5, 6):  # proposal 2: 1-row child -> accepted group
        executor.script[index] = _MISMATCH_1ROW
    executor.script[7] = "sql_error"  # restart: ReplaceValue(1,NULL) fails
    for index in (8, 9, 10, 11):  # ReplaceValue(1, 0/1/-1/-64): MATCH
        executor.script[index] = _MATCH
    sink = RecordingTraceSink()
    result = run_reduction(bundle, executor, sink)

    assert result.outcome is ReductionOutcome.REDUCED
    assert result.stop_reason is StopReason.SEARCH_EXHAUSTED
    assert result.search_complete is True
    assert result.proposals == 8
    assert result.executions == 12
    assert result.accepted == 1
    assert result.unstable_candidates == 5
    assert result.inconclusive_candidates == 1
    assert result.rejected_static == 1
    assert result.has_reduction is True

    # The best is proposal 2's child, recomputed independently via D1.
    expected_child = apply_transform(
        bundle.candidate.request.payload, RemoveRows((2, 3))
    ).child.payload
    assert validate_case(expected_child).status.value == "VALID_STATIC"
    assert result.best_case_id == case_id_of(expected_child)
    assert len(result.best_comparison_hashes) == 3

    # Restart from the new best: dispatched payload row counts are
    # 3,3,3 (original), 0 (delete-all), 1,1,1 (accepted group),
    # then 1,1,1,1,1 (value children of the one-row best).
    assert executor.dispatched_row_counts == [3, 3, 3, 0, 1, 1, 1, 1, 1, 1, 1, 1]
    assert executor.prepares == 12

    # The ACCEPTED record is the persistent authority for the child.
    accepted = sink.records_of_kind("ACCEPTED")
    assert len(accepted) == 1
    inline = accepted[0].inline
    assert inline["parent_complexity"] == _ORIG_COMPLEXITY_HEAD + [
        len(canonical_json(bundle.candidate.request.payload.to_obj()))
    ]
    assert inline["child_complexity"] == _CHILD_COMPLEXITY_HEAD + [
        len(canonical_json(expected_child.to_obj()))
    ]
    comparisons = accepted_group_comparisons(sink.records)
    assert inline["comparison_hashes"] == [record.hash for record in comparisons]
    child_attempt_hashes = [
        executor.evidence_by_dispatch[index].evidence_hash for index in (4, 5, 6)
    ]
    assert inline["attempt_hashes"] == child_attempt_hashes
    assert accepted[0].payload_ref.sha256 == sha256_hex(
        canonical_json(expected_child.to_obj())
    )
    assert list(result.best_comparison_hashes) == inline["comparison_hashes"]


def test_same_or_worse_child_rejected_before_execution():
    """Every strictly-smaller proposal is executed once and matches; the
    first same-or-worse children (proposals 11 and 12, ReplaceValue(2, 0/1):
    replacing the NULL row with a value raises the non-NULL count 2 -> 3) are
    rejected statically, so no dispatch ever carries a child whose rid-2 row
    holds a value."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    for index in (0, 1, 2):  # the original group keeps its mismatch rows
        executor.script[index] = (CANDIDATE_A_ROWS, CANDIDATE_B_ROWS)
    executor.default = _MATCH  # proposals 1-10 all match on the first attempt
    policy = ReductionPolicy(max_proposals=12)
    result = run_reduction(bundle, executor, None, policy=policy)

    assert result.outcome is ReductionOutcome.BUDGET_EXHAUSTED
    assert result.stop_reason is StopReason.PROPOSAL_BUDGET
    assert result.search_complete is False
    # Proposals 1-10 executed (10 one-attempt groups), then proposals 11 and
    # 12 (the first same-or-worse children) are rejected statically,
    # consuming the budget of 12.
    assert result.proposals == 12
    assert result.executions == 13  # 3 original + 10 one-attempt child groups
    assert result.unstable_candidates == 10
    assert result.rejected_static == 2
    assert result.accepted == 0
    assert executor.prepares == 13

    # Neither rejected child was ever executed: no dispatched child payload
    # holds a non-NULL value in its rid-2 row.
    worse = apply_transform(
        bundle.candidate.request.payload, ReplaceValue(2, IntegerValue(0))
    ).child.payload
    dispatched = {case_id_of(p) for p in executor.payloads_by_dispatch.values()}
    assert case_id_of(worse) not in dispatched
    for payload in executor.payloads_by_dispatch.values():
        for row in payload.rows.rows:
            if row.rid == 2:
                assert isinstance(row.value, NullValue)
    assert result.best_case_id == result.original_case_id


def test_visited_child_executed_once():
    """After the acceptance, the restart re-walks the new best's proposals:
    its delete-all child is case-identical to the already executed 0-row
    child, so it is rejected as visited and never dispatched again; the two
    fresh single-row deletions are executed once each (MATCH), and the
    proposal budget then stops the search."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    executor.script[3] = _MATCH  # p1 delete-all: 0-row child, MATCH
    executor.script[4] = _MATCH  # p2 RemoveRows((2,3)): 1-row child, MATCH
    for index in (5, 6, 7):  # p3 RemoveRows((1,)): 2-row child, accepted
        executor.script[index] = _MISMATCH_2ROW
    executor.script[8] = _MATCH  # restart RemoveRows((2,)): 1-row, MATCH
    executor.script[9] = _MATCH  # restart RemoveRows((3,)): 1-row, MATCH
    policy = ReductionPolicy(max_proposals=6)
    result = run_reduction(bundle, executor, None, policy=policy)

    assert result.outcome is ReductionOutcome.BUDGET_EXHAUSTED
    assert result.stop_reason is StopReason.PROPOSAL_BUDGET
    assert result.proposals == 6
    assert result.executions == 10  # 3 original + 1 + 1 + 3 + 1 + 1
    assert result.accepted == 1
    assert result.unstable_candidates == 4
    assert result.rejected_static == 1  # the visited delete-all child
    assert result.inconclusive_candidates == 0
    # Dispatched payload row counts: no 0-row child beyond dispatch index 3.
    assert executor.dispatched_row_counts == [3, 3, 3, 0, 1, 2, 2, 2, 1, 1]

    expected_child = apply_transform(
        bundle.candidate.request.payload, RemoveRows((1,))
    ).child.payload
    assert result.best_case_id == case_id_of(expected_child)
    assert len(result.best_comparison_hashes) == 3


# --------------------------------------------------------------------------
# Budgets and cancellation
# --------------------------------------------------------------------------


def test_execution_budget_stops_before_a_new_group():
    """With one execution slot left after the original replay, a new
    three-round group cannot start: EXECUTION_BUDGET with the proposal
    consumed but the child never executed."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    policy = ReductionPolicy(max_executions=4)
    result = run_reduction(bundle, executor, None, policy=policy)
    assert result.outcome is ReductionOutcome.BUDGET_EXHAUSTED
    assert result.stop_reason is StopReason.EXECUTION_BUDGET
    assert result.search_complete is False
    assert result.proposals == 1
    assert result.executions == 3
    assert result.accepted == 0
    assert result.rejected_static == 0
    assert executor.prepares == 3
    assert result.best_case_id == result.original_case_id


def test_time_budget_stops_before_proposals():
    """The injected clock advances 10 s per execution; a 25 s total budget is
    gone after the original replay, so no proposal is evaluated."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    clock = StubClock()

    def advance(_index: int) -> None:
        clock.advance_ms(10_000)

    executor.on_execute = advance
    policy = ReductionPolicy(total_budget_ms=25_000)
    result = run_reduction(
        bundle, executor, None, policy=policy, control=make_control(clock)
    )
    assert result.outcome is ReductionOutcome.BUDGET_EXHAUSTED
    assert result.stop_reason is StopReason.TIME_BUDGET
    assert result.search_complete is False
    assert result.executions == 3
    assert result.proposals == 0
    assert result.accepted == 0
    assert result.best_case_id == result.original_case_id


def test_cancellation_mid_original_group_stops_with_zero_proposals():
    """The cancel token flips after the second execution; the third attempt
    is never dispatched and the run reports CANCELLED."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    token = CancelToken()

    def cancel_soon(index: int) -> None:
        if index >= 1:
            token.cancelled_flag = True

    executor.on_execute = cancel_soon
    clock = StubClock()
    result = run_reduction(
        bundle,
        executor,
        None,
        control=make_control(clock, cancelled=token),
    )
    assert result.outcome is ReductionOutcome.BUDGET_EXHAUSTED
    assert result.stop_reason is StopReason.CANCELLED
    assert result.search_complete is False
    assert result.executions == 2
    assert result.proposals == 0
    assert executor.prepares == 2
    assert result.best_case_id == result.original_case_id


def test_cancellation_before_dispatch_zero_executions():
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    token = CancelToken()
    token.cancelled_flag = True
    clock = StubClock()
    result = run_reduction(
        bundle,
        executor,
        None,
        control=make_control(clock, cancelled=token),
    )
    assert result.outcome is ReductionOutcome.BUDGET_EXHAUSTED
    assert result.stop_reason is StopReason.CANCELLED
    assert result.executions == 0
    assert result.proposals == 0
    assert executor.calls == []


# --------------------------------------------------------------------------
# Faults
# --------------------------------------------------------------------------


def test_executor_fault_outranks_exhausted_proposal_budget():
    """The first child prepare fails while the proposal budget is already
    exhausted: the safety fault wins, the run reports FAILED."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    executor.prepare_errors[3] = RuntimeError("boom")
    policy = ReductionPolicy(max_proposals=1)
    result = run_reduction(bundle, executor, None, policy=policy)
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.EXECUTOR_EXCEPTION
    assert result.search_complete is False
    assert result.proposals == 1
    assert result.executions == 4
    assert result.accepted == 0
    assert result.best_case_id == result.original_case_id


def test_environment_drift_is_a_whole_run_fault():
    """A child attempt whose side B reports a different session time zone
    fails the fingerprint gate: the run stops dispatching with FAILED."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    executor.script[3] = "drift"
    result = run_reduction(bundle, executor, None)
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.ENVIRONMENT_DRIFT
    assert result.executions == 4
    assert executor.prepares == 4  # no further dispatch after the drift
    assert result.accepted == 0
    assert result.best_case_id == result.original_case_id


def test_plain_child_sql_error_rejects_child_and_continues():
    """A child whose first attempt ends in a confirmed, cleaned-up SQL error
    is inconclusive: the child is rejected and the search continues to the
    next proposal, which is accepted.  The restart's next proposal
    (ReplaceValue(1, NULL) on the one-row best) then matches, and the
    proposal budget stops the run."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    executor.script[3] = "sql_error"  # proposal 1 child fails
    for index in (4, 5, 6):  # proposal 2 child is accepted
        executor.script[index] = _MISMATCH_1ROW
    executor.script[7] = _MATCH  # restart: ReplaceValue(1, NULL) matches
    policy = ReductionPolicy(max_proposals=4)
    result = run_reduction(bundle, executor, None, policy=policy)
    assert result.outcome is ReductionOutcome.BUDGET_EXHAUSTED
    assert result.stop_reason is StopReason.PROPOSAL_BUDGET
    assert result.inconclusive_candidates == 1
    assert result.accepted == 1
    assert result.unstable_candidates == 1
    assert result.rejected_static == 1  # the visited delete-all child
    assert result.proposals == 4
    assert result.executions == 3 + 1 + 3 + 1


def test_sink_failure_at_accepted_keeps_best_and_reports_failed():
    """A persistence fault at the ACCEPTED record must not advance the best
    pointer: the run reports FAILED with the original as best."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    for index in (4, 5, 6):
        executor.script[index] = _MISMATCH_1ROW
    sink = RecordingTraceSink(fail_on={"ACCEPTED"})
    result = run_reduction(bundle, executor, sink)
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.EVIDENCE_WRITE_FAILED
    assert result.search_complete is False
    assert result.accepted == 0
    assert result.has_reduction is False
    assert result.best_case_id == result.original_case_id
    kinds = sink.kinds
    assert "ACCEPTED" not in kinds
    assert kinds[-1] == "FINISHED"  # the termination record still persisted


def test_keyboard_interrupt_from_child_prepare_propagates():
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    executor.prepare_errors[3] = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        run_reduction(bundle, executor, None)
    assert executor.prepares == 4


# --------------------------------------------------------------------------
# Trace integration (grammar + read-side audit)
# --------------------------------------------------------------------------


def _expected_kinds_for_happy_run() -> list[str]:
    """Hand-written grammar for the happy reduction: SNAPSHOT, START, the
    original replay (replay_candidate closes each of its three attempts with
    a REPLAY record), one match group, the accepted group, five
    single-attempt groups, FINISHED.  Child groups are closed by exactly one
    REPLAY record after their attempts."""
    kinds = ["SNAPSHOT", "START"]
    kinds += (_ATTEMPT + ["REPLAY"]) * 3  # original replay
    kinds += _ATTEMPT + ["REPLAY"]  # proposal 1: match
    kinds += _ATTEMPT * 3 + ["REPLAY", "ACCEPTED"]  # proposal 2: accepted
    kinds += (_ATTEMPT + ["REPLAY"]) * 5  # restart: 1 inconclusive + 4 match
    kinds += ["FINISHED"]
    return kinds


def test_trace_grammar_and_audit_reconstruct_best(tmp_path):
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    executor.script[3] = _MATCH
    for index in (4, 5, 6):
        executor.script[index] = _MISMATCH_1ROW
    executor.script[7] = "sql_error"
    for index in (8, 9, 10, 11):
        executor.script[index] = _MATCH
    root = tmp_path / "trace-run"
    with JsonlTraceSink(root, EVIDENCE_APPEND_BUDGET) as sink:
        result = run_reduction(bundle, executor, sink)

    assert result.outcome is ReductionOutcome.REDUCED
    expected = _expected_kinds_for_happy_run()
    # The sink itself enforces the grammar; re-read the file and verify the
    # full recorded order independently.
    with open(root / "trace.jsonl", "rb") as handle:
        lines = [line for line in handle.read().split(b"\n") if line]
    kinds = [
        json.loads(line)["kind"] for line in lines
    ]
    assert kinds == expected

    audit = read_trace(root)
    assert audit.trace_status == TRACE_STATUS_COMPLETE
    assert audit.best_source == BEST_SOURCE_ACCEPTED
    assert audit.records_verified == len(expected)
    expected_child = apply_transform(
        bundle.candidate.request.payload, RemoveRows((2, 3))
    ).child.payload
    assert audit.best_payload_ref.sha256 == sha256_hex(
        canonical_json(expected_child.to_obj())
    )


def test_trace_audit_falls_back_to_original_without_acceptance(tmp_path):
    """Without any ACCEPTED record the audit's best is the original snapshot."""
    bundle = CandidateBundle()
    executor = ReductionExecutor(bundle)
    executor.default = _MATCH  # every child matches: nothing is accepted
    for index in (0, 1, 2):  # the original group keeps its mismatch rows
        executor.script[index] = (CANDIDATE_A_ROWS, CANDIDATE_B_ROWS)
    root = tmp_path / "trace-noreduce"
    with JsonlTraceSink(root, EVIDENCE_APPEND_BUDGET) as sink:
        result = run_reduction(
            bundle, executor, sink, policy=ReductionPolicy(max_proposals=6)
        )
    assert result.accepted == 0
    audit = read_trace(root)
    assert audit.trace_status == TRACE_STATUS_COMPLETE
    assert audit.best_source == BEST_SOURCE_ORIGINAL
    assert audit.best_payload_ref.sha256 == sha256_hex(
        canonical_json(bundle.candidate.request.payload.to_obj())
    )
