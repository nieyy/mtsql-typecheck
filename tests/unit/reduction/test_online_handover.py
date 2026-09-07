"""D3 Phase-1 online-handover tests (design 6.2/6.3/6.4.6, items G01/G02/G04,
R02, A04/A05/A06).

Every expected verdict here is stated from the design, not derived from the
code under test: executors are scripted per dispatch, the budgeted sink
re-implements the frozen reserve semantics (remaining - hint >=
EVIDENCE_RESERVE_BYTES), and the minimal sink implements exactly the
TraceSink protocol to prove the writer depends on nothing more.
"""

from __future__ import annotations

import dataclasses

import pytest

from mtsql_typecheck.contracts.case import NameMap, TypeFamily
from mtsql_typecheck.contracts.codec import canonical_json, sha256_hex
from mtsql_typecheck.contracts.execution import (
    dump_attempt_request,
    dump_execution_evidence,
    load_attempt_request,
)
from mtsql_typecheck.contracts.oracle import (
    ArtifactRef,
    ComparisonStatus,
    EVIDENCE_RESERVE_BYTES,
    PersistedReceipt,
    ReplayOutcome,
    ReplayPolicy,
    ReductionOutcome,
    ReductionPolicy,
    StopReason,
    TRACE_SCHEMA_VERSION,
)
from mtsql_typecheck.oracle.gates import (
    ResultContractViolation,
    compare_case,
    compare_case_document,
)
from mtsql_typecheck.reduction.engine import reduce_candidate
from mtsql_typecheck.reduction.replay import attempt_reserve_hint, replay_candidate
from mtsql_typecheck.reduction.trace import TraceBudgetError

import engine_fakes as ef
import replay_fakes as f

_POLICY = ReplayPolicy()


def _control():
    return f.make_control(f.StubClock())


# --------------------------------------------------------------------------
# G01: fresh-objects handover (per-run name-map ledger, replaced bindings)
# --------------------------------------------------------------------------


class _ReusingNameMapExecutor(f.ScriptedExecutor):
    """prepare() returns an internally consistent expectation that reuses the
    original candidate's name map: a cross-round object reuse that is only
    detectable through the per-run content-hash ledger."""

    def __init__(self, base: f.CandidateBundle) -> None:
        super().__init__(base)
        self._reused = base.candidate.expectation.name_map

    def prepare(self, request, control):
        expectation = super().prepare(request, control)
        binding = dataclasses.replace(
            expectation.binding,
            name_map_hash=sha256_hex(canonical_json(self._reused.to_obj())),
        )
        return dataclasses.replace(expectation, name_map=self._reused, binding=binding)


class _RebindingExecutor(f.ScriptedExecutor):
    """execute() returns evidence bound to a DIFFERENT expectation than the
    one this executor prepared and handed to the caller (replaced binding)."""

    def execute(self, request, expectation, control):
        swapped = dataclasses.replace(
            expectation, name_map=NameMap("swap_a", "swap_b", "swap_ta", "swap_tb")
        )
        return super().execute(request, swapped, control)


def test_reused_name_map_is_a_protocol_error_when_fresh_maps_required():
    bundle = f.CandidateBundle()
    executor = _ReusingNameMapExecutor(bundle)
    sink = f.SpyTraceSink()
    result = f.replay_candidate(
        bundle.candidate,
        executor,
        sink,
        _POLICY,
        _control(),
        require_fresh_name_maps=True,
    )
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.EXECUTION_PROTOCOL_ERROR
    assert result.operational_failure is True
    # The reuse is detected right after prepare: one attempt requested,
    # zero executes, and the attempt is cancelled before anything else.
    assert result.requested == 1
    assert [kind for kind, _aid, _order in executor.calls if kind == "execute"] == []
    assert executor.cancel_calls == ["run-replay-1-replay-1"]
    # Failure branch: REQUESTED, EVIDENCE, RESULT, REPLAY — no EXPECTATION or
    # COMPARISON record for the refused attempt.
    assert sink.kinds == ["REQUESTED", "EVIDENCE", "RESULT", "REPLAY"]
    f.assert_counter_invariants(result)


def test_reused_name_map_is_record_only_by_default():
    bundle = f.CandidateBundle()
    executor = _ReusingNameMapExecutor(bundle)
    result = f.run_replay(bundle, executor)
    # Without require_fresh_name_maps the ledger records the hash and the
    # internally consistent run replays normally.
    assert result.outcome is ReplayOutcome.REPRODUCED
    assert result.stop_reason is StopReason.REPLAY_COMPLETE
    f.assert_counter_invariants(result)


def test_fresh_name_maps_pass_the_required_freshness_gate():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    result = f.run_replay(bundle, executor, require_fresh_name_maps=True)
    assert result.outcome is ReplayOutcome.REPRODUCED
    f.assert_counter_invariants(result)


def test_replaced_binding_evidence_is_refused_and_cancelled():
    bundle = f.CandidateBundle()
    executor = _RebindingExecutor(bundle)
    sink = f.SpyTraceSink()
    result = f.replay_candidate(bundle.candidate, executor, sink, _POLICY, _control())
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.EXECUTION_PROTOCOL_ERROR
    assert result.operational_failure is True
    # The executed attempt is cancelled BEFORE the stop is reported.
    assert executor.cancel_calls, "the replaced-binding attempt must be cancelled"
    f.assert_counter_invariants(result)


class _RebindingReductionExecutor(ef.ReductionExecutor):
    def execute(self, request, expectation, control):
        swapped = dataclasses.replace(
            expectation, name_map=NameMap("swap_a", "swap_b", "swap_ta", "swap_tb")
        )
        return super().execute(request, swapped, control)


def test_engine_refuses_replaced_binding_evidence():
    bundle = f.CandidateBundle()
    executor = _RebindingReductionExecutor(bundle)
    result = ef.run_reduction(bundle, executor)
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.EXECUTION_PROTOCOL_ERROR
    assert result.executions == 1
    assert result.accepted == 0


class _ReusingChildNameMapExecutor(ef.ReductionExecutor):
    """Child attempts (dispatch index >= 3) reuse the ORIGINAL CANDIDATE's
    name map: internally consistent per attempt, but a cross-round object
    reuse caught only because the run ledger is seeded with the candidate."""

    def __init__(self, base: f.CandidateBundle) -> None:
        super().__init__(base)
        self._reused = base.candidate.expectation.name_map

    def prepare(self, request, control):
        expectation = super().prepare(request, control)
        index = self._index_by_attempt[request.attempt_id]
        if index >= 3:
            binding = dataclasses.replace(
                expectation.binding,
                name_map_hash=sha256_hex(canonical_json(self._reused.to_obj())),
            )
            expectation = dataclasses.replace(
                expectation, name_map=self._reused, binding=binding
            )
        return expectation


def test_engine_catches_child_name_map_reuse_when_fresh_maps_required():
    bundle = f.CandidateBundle()
    executor = _ReusingChildNameMapExecutor(bundle)
    # The original replay (dispatch 0..2) is clean; the run ledger is seeded
    # with the candidate's map, so the first child attempt (dispatch 3) hits
    # the duplicate immediately.
    executor.script[3] = (f.CANDIDATE_A_ROWS, f.CANDIDATE_B_ROWS)
    result = ef.run_reduction(bundle, executor, require_fresh_name_maps=True)
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.EXECUTION_PROTOCOL_ERROR
    # 3 original replay attempts + 1 refused child attempt.
    assert result.executions == 4
    assert result.accepted == 0


def test_engine_fresh_name_maps_complete_normally():
    bundle = f.CandidateBundle()
    executor = ef.ReductionExecutor(bundle)
    for index in (0, 1, 2):  # the original group keeps its mismatch rows
        executor.script[index] = (f.CANDIDATE_A_ROWS, f.CANDIDATE_B_ROWS)
    executor.default = "sql_error"  # every child fails plainly: no protocol error
    result = ef.run_reduction(bundle, executor, require_fresh_name_maps=True)
    assert result.outcome is ReductionOutcome.UNCHANGED
    assert result.accepted == 0
    assert result.stop_reason is StopReason.SEARCH_EXHAUSTED


# --------------------------------------------------------------------------
# G04: comparison deadline binding and max-receipt reservation
# --------------------------------------------------------------------------


class _BudgetedSink(f.SpyTraceSink):
    """Spy sink with the frozen reserve semantics: a reserve is refused with
    TraceBudgetError unless remaining - size_hint >= EVIDENCE_RESERVE_BYTES
    (the reserve is a non-consuming pre-flight check)."""

    def __init__(self, budget: int, **kwargs) -> None:
        super().__init__(**kwargs)
        self._remaining = budget

    def reserve(self, size_hint: int) -> None:
        super().reserve(size_hint)
        if self._remaining - size_hint < EVIDENCE_RESERVE_BYTES:
            raise TraceBudgetError(
                f"reserve of {size_hint} does not fit the remaining budget"
            )


def _first_attempt_hint(bundle: f.CandidateBundle, policy: ReplayPolicy) -> int:
    from mtsql_typecheck.reduction import replay as replay_module

    attempt_ms = min(policy.attempt_budget_ms, policy.total_budget_ms)
    request = replay_module._attempt_request(bundle.candidate, 0, attempt_ms, True)
    return attempt_reserve_hint(len(dump_attempt_request(request)))


def test_insufficient_pre_dispatch_reserve_never_dispatches():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    hint = _first_attempt_hint(bundle, _POLICY)
    sink = _BudgetedSink(hint + EVIDENCE_RESERVE_BYTES - 1)
    result = replay_candidate(
        bundle.candidate, executor, sink, _POLICY, _control()
    )
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.stop_reason is StopReason.EVIDENCE_BUDGET
    # Zero execution: not even one prepare, and the attempt was never counted.
    assert result.requested == 0
    assert executor.calls == []
    assert result.operational_failure is False
    f.assert_counter_invariants(result)


def test_exactly_fitting_reservation_replays_fully():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    hint = _first_attempt_hint(bundle, _POLICY)
    sink = _BudgetedSink(hint + EVIDENCE_RESERVE_BYTES)
    result = replay_candidate(bundle.candidate, executor, sink, _POLICY, _control())
    assert result.outcome is ReplayOutcome.REPRODUCED
    assert result.requested == 3
    f.assert_counter_invariants(result)


def test_non_budget_reserve_failure_is_an_operational_write_failure():
    class _BrokenReserveSink(f.SpyTraceSink):
        def reserve(self, size_hint: int) -> None:
            raise RuntimeError("simulated sink reserve failure")

    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    result = replay_candidate(
        bundle.candidate, executor, _BrokenReserveSink(), _POLICY, _control()
    )
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.stop_reason is StopReason.EVIDENCE_WRITE_FAILED
    assert result.operational_failure is True
    assert result.requested == 0
    assert executor.calls == []


# --------------------------------------------------------------------------
# R02 / A05: NO_SINK semantics, unpersisted opt-out, cancel-on-sink-failure
# --------------------------------------------------------------------------


def test_replay_without_sink_is_a_zero_dispatch_no_sink_stop():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    result = replay_candidate(bundle.candidate, executor, None, _POLICY, _control())
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.stop_reason is StopReason.NO_SINK
    assert result.operational_failure is True
    assert result.requested == 0
    assert executor.calls == []
    f.assert_counter_invariants(result)


def test_replay_unpersisted_opt_out_preserves_in_memory_behaviour():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    result = replay_candidate(
        bundle.candidate, executor, None, _POLICY, _control(), unpersisted=True
    )
    assert result.outcome is ReplayOutcome.REPRODUCED
    assert result.requested == 3


def test_reduction_without_sink_is_a_zero_dispatch_no_sink_stop():
    bundle = f.CandidateBundle()
    executor = ef.ReductionExecutor(bundle)
    result = reduce_candidate(
        bundle.candidate, executor, None, ReductionPolicy(), _control()
    )
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.NO_SINK
    assert result.executions == 0
    assert result.proposals == 0
    assert executor.calls == []


def test_reduction_unpersisted_opt_out_preserves_in_memory_behaviour():
    bundle = f.CandidateBundle()
    executor = ef.ReductionExecutor(bundle)
    for index in (0, 1, 2):  # the original group keeps its mismatch rows
        executor.script[index] = (f.CANDIDATE_A_ROWS, f.CANDIDATE_B_ROWS)
    executor.default = "sql_error"
    result = reduce_candidate(
        bundle.candidate,
        executor,
        None,
        ReductionPolicy(),
        _control(),
        unpersisted=True,
    )
    assert result.outcome is ReductionOutcome.UNCHANGED
    assert result.executions > 0


def test_replay_sink_failure_after_execution_cancels_the_attempt():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    sink = f.SpyTraceSink(fail_on={"EVIDENCE"})
    result = replay_candidate(bundle.candidate, executor, sink, _POLICY, _control())
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.EVIDENCE_WRITE_FAILED
    assert result.operational_failure is True
    # One attempt executed (prepare + execute); the sink failed persisting its
    # evidence, and the attempt must be cancelled before reporting the stop.
    assert [kind for kind, _a, _o in executor.calls if kind == "execute"] != []
    assert executor.cancel_calls == ["run-replay-1-replay-1"]


def test_engine_sink_failure_after_execution_cancels_the_attempt():
    bundle = f.CandidateBundle()
    executor = ef.ReductionExecutor(bundle)
    sink = ef.RecordingTraceSink(fail_on={"EVIDENCE"})
    result = ef.run_reduction(bundle, executor, sink)
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.EVIDENCE_WRITE_FAILED
    assert any(kind == "cancel" for kind, _i, _r in executor.calls)


def test_engine_frame_publication_failure_stops_before_any_dispatch():
    bundle = f.CandidateBundle()
    executor = ef.ReductionExecutor(bundle)
    sink = ef.RecordingTraceSink(fail_publish=True)
    result = ef.run_reduction(bundle, executor, sink)
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.EVIDENCE_WRITE_FAILED
    assert result.executions == 0
    assert executor.calls == []


def test_replay_publication_failure_never_dispatches():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    sink = f.SpyTraceSink(fail_publish=True)
    result = replay_candidate(bundle.candidate, executor, sink, _POLICY, _control())
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.stop_reason is StopReason.EVIDENCE_WRITE_FAILED
    assert result.requested == 0
    assert executor.calls == []


# --------------------------------------------------------------------------
# A06: TraceSink protocol minimality and the two comparison calling
# conventions
# --------------------------------------------------------------------------


class _MinimalProtocolSink:
    """Implements EXACTLY the TraceSink protocol — reserve, publish_payload,
    append — and nothing else.  If the writer needed more, this test could
    not drive a full replay."""

    def __init__(self) -> None:
        self.records = []
        self.payloads: dict[str, bytes] = {}

    def reserve(self, size_hint: int) -> None:
        return None

    def publish_payload(self, data: bytes) -> ArtifactRef:
        payload = bytes(data)
        digest = sha256_hex(payload)
        self.payloads[digest] = payload
        return ArtifactRef(
            path=f"files/{digest}.json",
            size_bytes=len(payload),
            sha256=digest,
            schema_version=TRACE_SCHEMA_VERSION,
        )

    def append(self, record) -> PersistedReceipt:
        self.records.append(record)
        return PersistedReceipt(seq=record.seq, kind=record.kind, record_hash=record.hash)


def test_minimal_protocol_sink_drives_a_full_replay():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    sink = _MinimalProtocolSink()
    result = replay_candidate(bundle.candidate, executor, sink, _POLICY, _control())
    assert result.outcome is ReplayOutcome.REPRODUCED
    requested = [record for record in sink.records if record.kind == "REQUESTED"]
    assert len(requested) == 3
    assert all(record.payload_ref is not None for record in requested)
    # The published payload IS the full canonical request document.
    document = sink.payloads[requested[0].payload_ref.sha256]
    assert load_attempt_request(document).request_hash == requested[0].inline["request_hash"]


def test_result_contract_violation_has_two_calling_conventions():
    """compare_case raises ResultContractViolation (carrying the honest
    INCONCLUSIVE comparison); compare_case_document returns that carried
    comparison with the RESULT_CONTRACT_VIOLATION reason.  Writers catch the
    exception, auditors may use either entry point."""
    bundle = f.CandidateBundle()
    bad_column = dataclasses.replace(
        bundle.evidence.b_query.result.columns[0], family=TypeFamily.DECIMAL
    )
    bad_result = dataclasses.replace(
        bundle.evidence.b_query.result, columns=(bad_column,), payload_hash=""
    )
    bad_query = dataclasses.replace(bundle.evidence.b_query, result=bad_result)
    evidence = dataclasses.replace(bundle.evidence, b_query=bad_query, evidence_hash="")

    with pytest.raises(ResultContractViolation) as excinfo:
        compare_case(bundle.request, bundle.expectation, evidence, f._BUDGET)
    assert excinfo.value.comparison.status is ComparisonStatus.INCONCLUSIVE
    assert excinfo.value.comparison.reasons == ("RESULT_CONTRACT_VIOLATION",)

    carried = compare_case_document(
        bundle.request.to_obj(),
        bundle.expectation.to_obj(),
        dump_execution_evidence(evidence),
        f._BUDGET,
    )
    assert carried.status is ComparisonStatus.INCONCLUSIVE
    assert carried.reasons == ("RESULT_CONTRACT_VIOLATION",)
    assert carried.hash == excinfo.value.comparison.hash
