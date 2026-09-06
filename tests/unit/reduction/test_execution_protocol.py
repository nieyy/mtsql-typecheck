"""B01: fault-injection matrix for replay_candidate against a stub
ExecutionPort (contract section 7, design 6.4.5).

Each fault is its own test.  Faults are injected only at the executor and
trace-sink boundaries; the comparison itself always runs through the real
gates.  Match/signature-change/cleanup/budget early exits live in
test_replay.py; this file covers protocol and operational failures.  Every
test re-asserts the frozen counter invariants.
"""

from __future__ import annotations

import pytest

from mtsql_typecheck.contracts.execution import (
    AttemptFailure,
    AttemptStage,
    CleanupState,
    ExecutionPortError,
    TerminalReceipt,
    TerminationState,
)
from mtsql_typecheck.contracts.oracle import ReplayOutcome, StopReason

import replay_fakes as f


def test_cancel_before_prepare_zero_dispatch_and_zero_trace():
    bundle = f.CandidateBundle()
    token = f.CancelToken()
    token.cancelled_flag = True
    sink = f.SpyTraceSink()
    executor = f.ScriptedExecutor(bundle)
    result = f.run_replay(bundle, executor, sink, control=f.make_control(f.StubClock(), token))
    assert result.stop_reason is StopReason.CANCELLED
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.requested == 0
    assert executor.calls == []
    assert sink.records == []
    f.assert_counter_invariants(result)


def test_prepare_execution_port_error_is_operational_failure():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    executor.prepare_errors[0] = ExecutionPortError(
        "prepare refused",
        failure=AttemptFailure(AttemptStage.PREPARE, "PREPARE_REFUSED", None, None),
    )
    sink = f.SpyTraceSink()
    result = f.run_replay(bundle, executor, sink)
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.EXECUTOR_EXCEPTION
    assert result.operational_failure is True
    assert result.requested == 1
    assert result.completed == 0
    assert result.comparable == 0
    assert result.matching_signature == 0
    assert len(result.attempt_hashes) == 1
    # The attempt is cancelled safely even though prepare failed.
    assert [call[0] for call in executor.calls] == ["prepare", "cancel"]
    # Failure branch: no EXPECTATION, no COMPARISON.
    assert sink.kinds == ["REQUESTED", "EVIDENCE", "RESULT", "REPLAY"]
    f.assert_counter_invariants(result)


def test_prepare_generic_exception_is_operational_failure():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    executor.prepare_errors[0] = RuntimeError("driver exploded")
    result = f.run_replay(bundle, executor)
    assert result.stop_reason is StopReason.EXECUTOR_EXCEPTION
    assert result.operational_failure is True
    assert result.requested == 1
    assert len(result.attempt_hashes) == 1
    assert [call[0] for call in executor.calls] == ["prepare", "cancel"]
    f.assert_counter_invariants(result)


def test_sink_failure_on_requested_record_prevents_any_dispatch():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    sink = f.SpyTraceSink(fail_on={"REQUESTED"})
    result = f.run_replay(bundle, executor, sink)
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.stop_reason is StopReason.EVIDENCE_WRITE_FAILED
    assert result.operational_failure is True
    assert result.requested == 0
    assert executor.calls == []
    f.assert_counter_invariants(result)


def test_sink_failure_on_expectation_record_keeps_attempt_and_cancels():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    sink = f.SpyTraceSink(fail_on={"EXPECTATION"})
    result = f.run_replay(bundle, executor, sink)
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.EVIDENCE_WRITE_FAILED
    assert result.operational_failure is True
    # The prepare dispatch happened, so the attempt stays requested.
    assert result.requested == 1
    assert result.completed == 0
    assert len(result.attempt_hashes) == 1
    assert [call[0] for call in executor.calls] == ["prepare", "cancel"]
    f.assert_counter_invariants(result)


def test_execute_generic_exception_is_operational_failure():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    executor.execute_errors[0] = RuntimeError("connection reset")
    sink = f.SpyTraceSink()
    result = f.run_replay(bundle, executor, sink)
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.EXECUTOR_EXCEPTION
    assert result.operational_failure is True
    assert result.requested == 1
    assert result.completed == 0
    assert [call[0] for call in executor.calls] == ["prepare", "execute", "cancel"]
    assert sink.kinds == ["REQUESTED", "EXPECTATION", "EVIDENCE", "RESULT", "REPLAY"]
    f.assert_counter_invariants(result)


def test_execute_port_error_salvages_carried_evidence():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    executor.execute_errors[0] = lambda evidence: ExecutionPortError(
        "query failed after partial fetch",
        failure=AttemptFailure(AttemptStage.QUERY, "QUERY_FAILED", None, None),
        evidence=evidence,
    )
    result = f.run_replay(bundle, executor)
    assert result.stop_reason is StopReason.EXECUTOR_EXCEPTION
    assert result.operational_failure is True
    salvaged = executor.evidence_by_attempt["run-replay-1-replay-1"]
    # The executor-carried evidence is kept as the attempt's evidence.
    assert result.attempt_hashes[0] == salvaged.evidence_hash
    assert result.requested == 1
    f.assert_counter_invariants(result)


def test_cancel_and_wait_failure_after_unconfirmed_termination():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    executor.terminal_overrides[0] = TerminalReceipt(
        attempt_id="placeholder",
        termination=TerminationState.UNKNOWN,
        cleanup=CleanupState.PENDING,
        owned_objects=(),
    )
    executor.cancel_error = RuntimeError("cancel channel broken")
    result = f.run_replay(bundle, executor)
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.TERMINATION_UNCONFIRMED
    assert result.operational_failure is True
    assert result.requested == 1
    assert result.comparable == 0
    assert executor.cancel_calls == ["run-replay-1-replay-1"]
    f.assert_counter_invariants(result)


def test_cancel_grace_timeout_leaves_termination_unconfirmed():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    executor.terminal_overrides[0] = TerminalReceipt(
        attempt_id="placeholder",
        termination=TerminationState.UNKNOWN,
        cleanup=CleanupState.PENDING,
        owned_objects=(),
    )
    executor.cancel_receipt = TerminalReceipt(
        attempt_id="placeholder",
        termination=TerminationState.UNKNOWN,
        cleanup=CleanupState.PENDING,
        owned_objects=(),
    )
    result = f.run_replay(bundle, executor)
    assert result.stop_reason is StopReason.TERMINATION_UNCONFIRMED
    assert result.operational_failure is True
    assert result.requested == 1
    f.assert_counter_invariants(result)


def test_late_cancel_confirmation_is_incomplete_but_not_operational():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    executor.terminal_overrides[0] = TerminalReceipt(
        attempt_id="placeholder",
        termination=TerminationState.UNKNOWN,
        cleanup=CleanupState.PENDING,
        owned_objects=(),
    )
    # The safety cancel itself confirms termination: the evidence stays
    # incomplete, but the group is not left in an unknown state.
    result = f.run_replay(bundle, executor)
    assert result.stop_reason is StopReason.EXECUTION_INCOMPLETE
    assert result.operational_failure is False
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.requested == 1
    assert result.comparable == 0
    f.assert_counter_invariants(result)


def test_control_cancelled_mid_run_is_unstable_with_confirmed_termination():
    bundle = f.CandidateBundle()
    token = f.CancelToken()
    executor = f.ScriptedExecutor(bundle)

    class CancelAfterFirstReplay(f.SpyTraceSink):
        """Flip the cancel flag once attempt 1's group record is persisted:
        the cancellation happens after a confirmed, fully processed attempt,
        before the next dispatch."""

        def __init__(self) -> None:
            super().__init__()
            self._token = token

        def append(self, record):
            receipt = super().append(record)
            if record.kind == "REPLAY":
                self._token.cancelled_flag = True
            return receipt

    sink = CancelAfterFirstReplay()
    result = f.run_replay(bundle, executor, sink, control=f.make_control(f.StubClock(), token))
    # Attempt 1 ran to confirmed termination and matched; the group then
    # stops before dispatching attempt 2 and is reported as unstable.
    assert result.outcome is ReplayOutcome.UNSTABLE
    assert result.stop_reason is StopReason.CANCELLED
    assert result.operational_failure is False
    assert result.requested == 1
    assert result.completed == 1
    assert result.comparable == 1
    assert result.matching_signature == 1
    assert len(f.prepare_dispatches(executor)) == 1
    assert executor.cancel_calls == []
    f.assert_counter_invariants(result)


def test_keyboard_interrupt_from_executor_is_never_swallowed():
    bundle = f.CandidateBundle()
    executor = f.ScriptedExecutor(bundle)
    executor.execute_errors[0] = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        f.run_replay(bundle, executor)
    # The safety-cancel flow still ran before the interrupt propagated.
    assert [call[0] for call in executor.calls] == ["prepare", "execute", "cancel"]
