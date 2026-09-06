"""R01: replay_candidate order, counters, early exits and budgets.

Every expectation below is hand-written: the candidate is verified through the
independent oracle gates, the executor is a scripted stub whose behaviour each
test states explicitly, and no expected hash/counter is derived from the
replay implementation itself.
"""

from __future__ import annotations

import dataclasses

from mtsql_typecheck.contracts.execution import ExecutionOrder, Side
from mtsql_typecheck.contracts.oracle import (
    ComparisonStatus,
    ReplayOutcome,
    ReplayPolicy,
    StopReason,
)
from mtsql_typecheck.oracle.gates import compare_case
from mtsql_typecheck.reduction import replay as replay_module

import replay_fakes as f

_POLICY = ReplayPolicy()


def _hex64(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def test_no_executor_returns_not_replayed_with_zero_dispatch():
    bundle = f.CandidateBundle()
    result = f.run_replay(bundle, None)
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.stop_reason is StopReason.NO_EXECUTOR
    assert result.requested == 0
    assert result.attempt_hashes == ()
    assert result.operational_failure is False
    assert result.comparison_hash == bundle.comparison.hash
    f.assert_counter_invariants(result)


def test_none_candidate_is_invalid_with_sentinel_comparison_hash():
    result = f.replay_candidate(
        None, f.ScriptedExecutor(f.CandidateBundle()), None, _POLICY, f.make_control(f.StubClock())
    )
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.stop_reason is StopReason.INVALID_CANDIDATE
    assert result.requested == 0
    assert result.comparison_hash == "0" * 64
    f.assert_counter_invariants(result)


def test_cancelled_control_before_any_dispatch_stops_without_dispatching():
    bundle = f.CandidateBundle()
    token = f.CancelToken()
    token.cancelled_flag = True
    executor = f.ScriptedExecutor(bundle)
    result = f.run_replay(bundle, executor, control=f.make_control(f.StubClock(), token))
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.stop_reason is StopReason.CANCELLED
    assert result.requested == 0
    assert executor.calls == []
    f.assert_counter_invariants(result)


def test_candidate_that_recompares_to_match_is_not_replayed():
    # A candidate whose own evidence no longer mismatches (here: a fresh MATCH
    # bundle handed in as a candidate) must never reach the executor.
    request, expectation, evidence = f.build_attempt(
        a_result_rows=f.CANDIDATE_A_ROWS, b_result_rows=f.MATCH_B_ROWS
    )
    comparison = compare_case(request, expectation, evidence, f._BUDGET)
    assert comparison.status is ComparisonStatus.MATCH
    candidate = f.CandidateInput(
        payload=request.payload,
        request=request,
        expectation=expectation,
        evidence=evidence,
        comparison_hash=comparison.hash,
        source="test",
    )
    executor = f.ScriptedExecutor(f.CandidateBundle())
    result = f.replay_candidate(candidate, executor, None, _POLICY, f.make_control(f.StubClock()))
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.stop_reason is StopReason.INVALID_CANDIDATE
    assert result.requested == 0
    assert executor.calls == []
    f.assert_counter_invariants(result)


def test_full_replay_dispatches_three_fresh_attempts_in_ab_ba_ab_order():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    result = f.run_replay(bundle, executor)
    assert result.outcome is ReplayOutcome.REPRODUCED
    assert result.stop_reason is StopReason.REPLAY_COMPLETE
    assert (result.requested, result.completed, result.comparable, result.matching_signature) == (
        3,
        3,
        3,
        3,
    )
    assert f.prepare_dispatches(executor) == [
        ("run-replay-1-replay-1", "AB"),
        ("run-replay-1-replay-2", "BA"),
        ("run-replay-1-replay-3", "AB"),
    ]
    assert len(set(result.attempt_hashes)) == 3
    assert all(_hex64(h) for h in result.attempt_hashes)
    assert result.exact_signatures == (bundle.exact_signature,) * 3
    assert result.operational_failure is False
    assert result.synthetic is True
    f.assert_counter_invariants(result)


def test_logical_labels_follow_schema_never_dispatch_order():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    f.run_replay(bundle, executor)
    for index, order in enumerate((ExecutionOrder.AB, ExecutionOrder.BA, ExecutionOrder.AB)):
        attempt_id = f"run-replay-1-replay-{index + 1}"
        evidence = executor.evidence_by_attempt[attempt_id]
        name_map = evidence.expectation.name_map
        assert evidence.actual_execution_order is order
        # Side A always maps to this attempt's database_a, side B to
        # database_b, regardless of the dispatch order.
        assert evidence.a_context.current_database == name_map.database_a
        assert evidence.b_context.current_database == name_map.database_b
        assert evidence.a_query.side is Side.A
        assert evidence.b_query.side is Side.B
        assert evidence.a_query.actual_database == name_map.database_a
        assert evidence.b_query.actual_database == name_map.database_b


def test_every_attempt_gets_fresh_name_map_connections_and_sessions():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    f.run_replay(bundle, executor)
    evidences = [executor.evidence_by_attempt[f"run-replay-1-replay-{n}"] for n in (1, 2, 3)]
    assert len({id(e.expectation.name_map) for e in evidences}) == 3
    assert len({e.expectation.name_map.database_a for e in evidences}) == 3
    conn_ids = [
        (e.a_context.setup_connection_id, e.b_context.setup_connection_id) for e in evidences
    ]
    assert len({cid for pair in conn_ids for cid in pair}) == 6
    session_ids = [
        (e.a_query.session_start_id, e.b_query.session_start_id) for e in evidences
    ]
    assert len({sid for pair in session_ids for sid in pair}) == 6


def test_first_match_stops_the_group_after_exactly_one_attempt():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    executor.result_overrides[0] = (f.CANDIDATE_A_ROWS, f.MATCH_B_ROWS)
    result = f.run_replay(bundle, executor)
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.MATCH_OBSERVED
    assert result.requested == 1
    assert result.completed == 1
    assert result.comparable == 1
    assert result.matching_signature == 0
    assert len(result.exact_signatures) == 1 and _hex64(result.exact_signatures[0])
    assert f.prepare_dispatches(executor) == [("run-replay-1-replay-1", "AB")]
    assert executor.cancel_calls == []
    assert result.operational_failure is False
    f.assert_counter_invariants(result)


def test_signature_change_on_second_attempt_stops_with_drift_recorded():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    executor.result_overrides[1] = (f.CANDIDATE_A_ROWS, f.DRIFT_B_ROWS)
    result = f.run_replay(bundle, executor)
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.SIGNATURE_CHANGED
    assert result.requested == 2
    assert result.comparable == 2
    assert result.matching_signature == 1
    assert result.exact_signatures[0] == bundle.exact_signature
    assert result.exact_signatures[1] != bundle.exact_signature
    assert len(f.prepare_dispatches(executor)) == 2
    f.assert_counter_invariants(result)


def test_environment_drift_stops_the_group():
    # Fingerprint drift is structurally unreachable through a faithful
    # executor (every attempt shares the candidate's environment/profile), so
    # the defensive branch is exercised by injecting a drifted fingerprint at
    # the compare boundary — the same fault-injection style as the stub
    # executor, never by weakening the code under test.
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    real_compare = replay_module.compare_case

    def drifted_compare(request, expectation, evidence, budget, control=None):
        comparison = real_compare(request, expectation, evidence, budget, control)
        if (
            comparison.status is ComparisonStatus.MISMATCH_CANDIDATE
            and request.attempt_id == "run-replay-1-replay-1"
        ):
            comparison = dataclasses.replace(comparison, fingerprint="e" * 64, hash="")
        return comparison

    original = replay_module.compare_case
    replay_module.compare_case = drifted_compare
    try:
        result = f.run_replay(bundle, executor)
    finally:
        replay_module.compare_case = original
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.ENVIRONMENT_DRIFT
    assert result.requested == 1
    assert result.comparable == 1
    assert result.matching_signature == 0
    f.assert_counter_invariants(result)


def test_replay_is_deterministic_and_sinkless_runs_are_identical():
    bundle = f.CandidateBundle()
    first = f.run_replay(bundle, f.ScriptedExecutor(bundle))
    second = f.run_replay(bundle, f.ScriptedExecutor(bundle), sink=f.SpyTraceSink())
    assert first.hash == second.hash
    assert first.exact_signatures == second.exact_signatures
    assert first.attempt_hashes == second.attempt_hashes


def test_synthetic_flag_propagates_from_candidate():
    request, expectation, evidence = f.build_attempt(synthetic=False)
    comparison = compare_case(request, expectation, evidence, f._BUDGET)
    assert comparison.status is ComparisonStatus.MISMATCH_CANDIDATE
    candidate = f.CandidateInput(
        payload=request.payload,
        request=request,
        expectation=expectation,
        evidence=evidence,
        comparison_hash=comparison.hash,
        source="test",
    )
    result = f.replay_candidate(candidate, f.ScriptedExecutor(f.CandidateBundle()), None, _POLICY, f.make_control(f.StubClock()))
    assert result.synthetic is False


def test_trace_group_ordering_and_hash_chain():
    bundle = f.CandidateBundle()
    sink = f.SpyTraceSink()
    f.run_replay(bundle, f.ScriptedExecutor(bundle), sink)
    per_attempt = [sink.kinds[i : i + 6] for i in range(0, len(sink.kinds), 6)]
    assert per_attempt == [
        ["REQUESTED", "EXPECTATION", "EVIDENCE", "RESULT", "COMPARISON", "REPLAY"]
    ] * 3
    previous = "0" * 64
    for position, record in enumerate(sink.records, start=1):
        assert record.seq == position
        assert record.prev_hash == previous
        assert _hex64(record.hash)
        previous = record.hash
    # Every append was preceded by an exact reserve call.
    assert len(sink.reserved) == len(sink.records)
    assert all(size > 0 for size in sink.reserved)


def test_attempt_budget_is_clamped_to_remaining_total_budget():
    # Total budget 1000ms, attempt budget 1000ms, each execute consumes
    # 600ms of the stub clock: the third attempt must never be dispatched.
    bundle = f.CandidateBundle()
    clock = f.StubClock()
    executor = f.ScriptedExecutor(bundle)
    executor.on_execute = lambda index: clock.advance_ms(600)
    policy = ReplayPolicy(total_budget_ms=1000, attempt_budget_ms=1000)
    result = f.run_replay(bundle, executor, policy=policy, control=f.make_control(clock))
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.EXECUTION_INCOMPLETE
    assert result.requested == 2
    assert result.comparable == 1
    assert result.matching_signature == 1
    assert len(f.prepare_dispatches(executor)) == 2
    assert result.operational_failure is False
    f.assert_counter_invariants(result)


def test_spent_total_budget_stops_before_the_first_dispatch():
    bundle = f.CandidateBundle()
    clock = f.StubClock()
    executor = f.ScriptedExecutor(bundle)
    control = f.make_control(clock, deadline_ms=0)
    result = f.run_replay(bundle, executor, control=control)
    # The re-comparison hits the already-spent deadline; nothing is dispatched.
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.stop_reason is StopReason.TIME_BUDGET
    assert result.requested == 0
    assert executor.calls == []
    f.assert_counter_invariants(result)
