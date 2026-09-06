"""Serial reduction driver for one verified mismatch candidate
(oracle-d2-contract section 9; design 6.4.4/6.4.5/6.4.6).

``reduce_candidate`` walks the deterministic proposal iterator over the
current best payload, rejects same-or-worse children before execution, and
verifies every executed child with its own fresh three-attempt group in the
frozen AB/BA/AB order.  The original candidate is always re-compared through
the oracle gates first (its recorded comparison hash is never trusted) and
then re-replayed from scratch through :func:`reduction.replay.replay_candidate`
-- no prior REPRODUCED label is ever substituted.

Safety boundaries implemented here:

- Generation and comparison stay independent of database connections: all
  side effects live behind the injected ``ExecutionPort``.
- A mismatch is a candidate finding, not a confirmed bug: a child is accepted
  only when all three fresh attempts are valid comparable MISMATCH_CANDIDATE
  comparisons with one stable in-group exact_signature, a fingerprint equal
  to the original observation, and confirmed termination with DONE cleanup.
- Binding conflicts, environment drift, protocol violations, unconfirmed
  termination and trace persistence failures are whole-run faults: dispatch
  stops and the run reports FAILED with the last persisted best.
- The trace is the only persistent authority for an acceptance: the child
  payload artifact is published and the ACCEPTED record is appended BEFORE
  the in-memory best pointer commits, so a persistence fault can never
  promote a child the trace cannot prove.
- The best pointer is preserved across budget exhaustion, cancellation and
  faults; the original ``CandidateInput`` is never mutated.

Time comes exclusively from the injected ``Control`` clock (monotonic
seconds); every budget in this module is an integer millisecond value and no
wall-clock read happens here.  ``KeyboardInterrupt`` is never swallowed.
"""

from __future__ import annotations

from typing import Optional

from ..contracts.case import (
    CasePayload,
    ContractError,
    StaticCheckStatus,
    TransformStatus,
)
from ..contracts.codec import canonical_json, case_id_of
from ..contracts.execution import (
    AttemptFailure,
    AttemptRequest,
    AttemptStage,
    CleanupState,
    Control,
    ControlCancelled,
    ExecutionEvidence,
    ExecutionOrder,
    ExecutionPort,
    QueryStatus,
    TerminalReceipt,
    TerminationState,
)
from ..contracts.oracle import (
    REPLAY_ATTEMPTS,
    ArtifactRef,
    CandidateInput,
    Comparison,
    ComparisonBudget,
    ComparisonReason,
    ComparisonStatus,
    PersistedReceipt,
    ReductionOutcome,
    ReductionPolicy,
    ReductionResult,
    ReplayOutcome,
    StopReason,
    TraceRecord,
    TraceSink,
)
from ..generation.transforms import apply_transform
from ..generation.validation import validate_case
from ..oracle.gates import ResultContractViolation, compare_case
from .replay import replay_candidate
from .strategy import complexity, iter_proposals
from .trace import TraceBudgetError

__all__ = ["reduce_candidate"]

# Sentinel for "no trusted original comparison exists" (unreached re-compare);
# ReductionResult.original_comparison_hash is a frozen hex64 field.
_NO_COMPARISON_HASH = "0" * 64

# Frozen dispatch order (design 6.4.3), shared with the original replay.
_DISPATCH_ORDERS = (ExecutionOrder.AB, ExecutionOrder.BA, ExecutionOrder.AB)

# Keeps "-reduce-<n>" inside the 128-char AttemptRequest.attempt_id limit.
_ATTEMPT_ID_RUN_MAX = 100

# Pre-dispatch reserve: must cover a full attempt's records (REQUESTED,
# EXPECTATION, EVIDENCE, RESULT, COMPARISON) plus the group's REPLAY close.
_ATTEMPT_RESERVE_HINT = 4096


# --------------------------------------------------------------------------
# Result assembly
# --------------------------------------------------------------------------


class _RunState:
    """Mutable reduction state; the frozen ReductionResult seals it at exit."""

    def __init__(self, candidate: Optional[CandidateInput], policy: ReductionPolicy) -> None:
        self.policy = policy
        self.synthetic = candidate.evidence.synthetic if candidate is not None else False
        self.original_case_id = (
            candidate.request.case_id if candidate is not None else _NO_COMPARISON_HASH
        )
        self.reduction_id = f"reduce-{self.original_case_id}"
        self.original_comparison_hash = _NO_COMPARISON_HASH
        self.original_fingerprint: Optional[str] = None
        self.best_payload: Optional[CasePayload] = (
            candidate.request.payload if candidate is not None else None
        )
        self.best_case_id = self.original_case_id
        self.best_comparison_hashes: tuple[str, ...] = ()
        self.proposals = 0
        self.executions = 0
        self.accepted = 0
        self.rejected_static = 0
        self.inconclusive_candidates = 0
        self.unstable_candidates = 0
        self.visited: set[str] = set()
        self.attempt_seq = 0

    def commit_best(self, child_payload: CasePayload, comparison_hashes: tuple[str, ...]) -> None:
        """Commit the in-memory best pointer; called only after the ACCEPTED
        record is durably persisted (design 6.4.6: trace first, then commit)."""
        self.best_payload = child_payload
        self.best_case_id = case_id_of(child_payload)
        self.best_comparison_hashes = comparison_hashes
        self.accepted += 1

    def result(
        self,
        outcome: ReductionOutcome,
        stop_reason: Optional[StopReason],
        search_complete: bool,
    ) -> ReductionResult:
        has_reduction = self.best_case_id != self.original_case_id
        if outcome is ReductionOutcome.REDUCED:
            assert has_reduction
        if outcome not in (ReductionOutcome.REDUCED, ReductionOutcome.UNCHANGED):
            search_complete = False
        return ReductionResult(
            reduction_id=self.reduction_id,
            outcome=outcome,
            stop_reason=stop_reason,
            original_case_id=self.original_case_id,
            original_comparison_hash=self.original_comparison_hash,
            original_fingerprint=self.original_fingerprint,
            best_case_id=self.best_case_id,
            best_comparison_hashes=self.best_comparison_hashes,
            has_reduction=has_reduction,
            search_complete=search_complete,
            proposals=self.proposals,
            executions=self.executions,
            accepted=self.accepted,
            rejected_static=self.rejected_static,
            inconclusive_candidates=self.inconclusive_candidates,
            unstable_candidates=self.unstable_candidates,
            synthetic=self.synthetic,
        )


# --------------------------------------------------------------------------
# Trace chain ownership (engine frame + re-based replay records)
# --------------------------------------------------------------------------


class _Chain:
    """Owns the run's hash chain: seq/prev_hash advance only on successful
    appends, so a failed emit leaves the chain exactly where it was."""

    def __init__(self, sink: TraceSink) -> None:
        self._sink = sink
        self._seq = 0
        self._prev_hash = "0" * 64

    @property
    def sink(self) -> TraceSink:
        return self._sink

    def publish(self, data: bytes) -> ArtifactRef:
        """Publish one dependency payload artifact (raises on failure)."""
        return self._sink.publish_payload(data)

    def emit(
        self,
        kind: str,
        inline: Optional[dict] = None,
        payload_ref: Optional[ArtifactRef] = None,
        reserve_hint: Optional[int] = None,
    ) -> PersistedReceipt:
        """Build, reserve and append one record; raises on sink failure."""
        record = TraceRecord(
            seq=self._seq + 1,
            kind=kind,
            payload_ref=payload_ref,
            inline=inline,
            prev_hash=self._prev_hash,
        )
        size = len(canonical_json(record.to_obj())) + 1
        self._sink.reserve(size if reserve_hint is None else max(size, reserve_hint))
        receipt = self._sink.append(record)
        self._seq = receipt.seq
        self._prev_hash = receipt.record_hash
        return receipt


class _ReplayView:
    """Sink view for :func:`replay_candidate` that re-bases replay-local
    records onto the run chain (replay's tracer starts its own chain)."""

    def __init__(self, chain: _Chain) -> None:
        self._chain = chain

    def reserve(self, size_hint: int) -> None:
        self._chain.sink.reserve(size_hint)

    def append(self, record: TraceRecord) -> PersistedReceipt:
        chain = self._chain
        rebased = TraceRecord(
            seq=chain._seq + 1,
            kind=record.kind,
            payload_ref=record.payload_ref,
            inline=record.inline,
            prev_hash=chain._prev_hash,
        )
        size = len(canonical_json(rebased.to_obj())) + 1
        chain.sink.reserve(size)
        receipt = chain.sink.append(rebased)
        chain._seq = receipt.seq
        chain._prev_hash = receipt.record_hash
        return receipt


# --------------------------------------------------------------------------
# Entry frame
# --------------------------------------------------------------------------


def _emit_engine_frame(
    chain: _Chain, state: _RunState
) -> Optional[tuple[ReductionOutcome, StopReason]]:
    """Emit SNAPSHOT (+ original payload artifact) and START; returns a
    terminal (outcome, stop) pair when the run cannot be traced, else None."""
    payload_ref: Optional[ArtifactRef] = None
    try:
        payload_ref = chain.publish(canonical_json(state.best_payload.to_obj()))
    except TraceBudgetError:
        return (ReductionOutcome.BUDGET_EXHAUSTED, StopReason.EVIDENCE_BUDGET)
    except Exception:
        payload_ref = None  # START.payload_ref is null when publication failed
    try:
        chain.emit(
            "SNAPSHOT",
            inline={"case_id": state.original_case_id},
            payload_ref=payload_ref,
        )
        chain.emit(
            "START",
            inline={
                "complexity": list(complexity(state.best_payload)),
                "payload_ref": None if payload_ref is None else payload_ref.to_obj(),
                "case_id": state.original_case_id,
            },
        )
    except TraceBudgetError:
        return (ReductionOutcome.BUDGET_EXHAUSTED, StopReason.EVIDENCE_BUDGET)
    except Exception:
        return (ReductionOutcome.FAILED, StopReason.EVIDENCE_WRITE_FAILED)
    return None


# --------------------------------------------------------------------------
# Shared attempt helpers (mirror reduction.replay; the child protocol needs
# them against a group baseline established by its first comparable attempt)
# --------------------------------------------------------------------------


def _compare_evidence(
    request: AttemptRequest, evidence: ExecutionEvidence, control: Control
) -> tuple[Optional[Comparison], Optional[StopReason]]:
    """Gate walk over one attempt's evidence; mirrors replay's mapping."""
    try:
        return (
            compare_case(
                request, evidence.expectation, evidence, ComparisonBudget(), control
            ),
            None,
        )
    except ResultContractViolation as exc:
        return exc.comparison, None
    except ControlCancelled:
        return None, StopReason.EXECUTION_INCOMPLETE
    except ContractError:
        return None, StopReason.EXECUTION_PROTOCOL_ERROR


def _both_sides_complete(evidence: ExecutionEvidence) -> bool:
    for query in (evidence.a_query, evidence.b_query):
        if query is None or query.status is not QueryStatus.COMPLETE:
            return False
        if query.result is None or not query.result.fetch_complete or query.result.truncated:
            return False
    return True


def _safe_cancel(
    executor: ExecutionPort, attempt_id: str, grace_ms: int
) -> Optional[TerminalReceipt]:
    """Best-effort cooperative cancel; never raises, never fabricates."""
    try:
        return executor.cancel_and_wait(attempt_id, grace_ms / 1000)
    except Exception:
        return None


def _failure_evidence(
    request: AttemptRequest,
    expectation,
    stage: AttemptStage,
    exc: Optional[BaseException],
    terminal: Optional[TerminalReceipt],
) -> ExecutionEvidence:
    """Salvage executor-carried evidence or record an honest failure envelope
    bound to the dispatched request (no fabricated success facts)."""
    salvaged = getattr(exc, "evidence", None)
    if isinstance(salvaged, ExecutionEvidence) and salvaged.request_hash == request.request_hash:
        return salvaged
    failure = getattr(exc, "failure", None)
    failure_code = (
        failure.code if isinstance(failure, AttemptFailure) else "EXECUTOR_EXCEPTION"
    )
    receipt = terminal
    if receipt is None:
        receipt = TerminalReceipt(
            attempt_id=request.attempt_id,
            termination=TerminationState.UNKNOWN,
            cleanup=CleanupState.PENDING,
            owned_objects=(),
        )
    return ExecutionEvidence(
        request_hash=request.request_hash,
        expectation=expectation,
        runtime_facts=None,
        setup_diagnostics=(),
        actual_execution_order=None,
        a_context=None,
        b_context=None,
        a_query=None,
        b_query=None,
        isolation_receipt=None,
        terminal=receipt,
        failure=AttemptFailure(stage=stage, code=failure_code, side=None, diagnostics_ref=None),
        preflight_rejection=None,
        synthetic=request.synthetic,
    )


def _evidence_inline(attempt_id: str, evidence: ExecutionEvidence) -> dict:
    terminal = evidence.terminal
    return {
        "attempt_id": attempt_id,
        "evidence_hash": evidence.evidence_hash,
        "failure": (
            str(evidence.failure.code) if evidence.failure is not None else None
        ),
        "termination": (
            str(terminal.termination.value) if terminal is not None else None
        ),
        "cleanup": str(terminal.cleanup.value) if terminal is not None else None,
    }


def _result_inline(attempt_id: str, evidence: ExecutionEvidence) -> dict:
    def _side(query) -> tuple[Optional[str], Optional[int]]:
        if query is None:
            return None, None
        rows = len(query.result.rows) if query.result is not None else None
        return str(query.status.value), rows

    a_status, a_rows = _side(evidence.a_query)
    b_status, b_rows = _side(evidence.b_query)
    return {
        "attempt_id": attempt_id,
        "a_status": a_status,
        "a_rows": a_rows,
        "b_status": b_status,
        "b_rows": b_rows,
    }


def _comparison_inline(attempt_id: str, comparison: Comparison) -> dict:
    return {
        "attempt_id": attempt_id,
        "status": str(comparison.status.value),
        "comparison_hash": comparison.hash,
        "exact_signature": comparison.exact_signature,
        "fingerprint": comparison.fingerprint,
        "reasons": [str(reason.value) for reason in comparison.reasons],
    }


# --------------------------------------------------------------------------
# Child attempt protocol
# --------------------------------------------------------------------------


class _GroupState:
    """One child group's counters and its in-group baseline signature."""

    def __init__(self) -> None:
        self.requested = 0
        self.completed = 0
        self.comparable = 0
        self.matching = 0
        self.baseline: Optional[str] = None
        self.comparison_hashes: list[str] = []
        self.attempt_hashes: list[str] = []


class _GroupOutcome:
    """Verdict for one child group (design 6.4.5).

    ``status`` is one of ``accept`` (three matching attempts), ``unstable``
    (MATCH or in-group signature change: the child is rejected, the run
    continues), ``inconclusive`` (plain execution failure: the child is
    rejected, the run continues), ``fault`` (whole-run FAILED) or ``budget``
    (whole-run BUDGET_EXHAUSTED stop)."""

    __slots__ = ("status", "stop", "comparison_hashes", "attempt_hashes")

    def __init__(
        self,
        status: str,
        stop: Optional[StopReason] = None,
        comparison_hashes: tuple[str, ...] = (),
        attempt_hashes: tuple[str, ...] = (),
    ) -> None:
        self.status = status
        self.stop = stop
        self.comparison_hashes = comparison_hashes
        self.attempt_hashes = attempt_hashes


def _child_request(
    state: _RunState,
    parent_request: AttemptRequest,
    child_payload: CasePayload,
    index: int,
    attempt_ms: int,
) -> AttemptRequest:
    """Fresh caller-generated child request: new attempt_id, frozen dispatch
    order, the parent's frozen environment/profile and the attempt budget."""
    state.attempt_seq += 1
    run_id = parent_request.run_id
    return AttemptRequest(
        run_id=run_id,
        attempt_id=f"{run_id[:_ATTEMPT_ID_RUN_MAX]}-reduce-{state.attempt_seq}",
        payload=child_payload,
        target_environment=parent_request.target_environment,
        session_profile=parent_request.session_profile,
        execution_order=_DISPATCH_ORDERS[index],
        result_row_budget=parent_request.result_row_budget,
        result_byte_budget=parent_request.result_byte_budget,
        time_budget_ms=attempt_ms,
        synthetic=parent_request.synthetic,
    )


def _emit_attempt_records(
    chain: Optional[_Chain],
    request: AttemptRequest,
    evidence: ExecutionEvidence,
    comparison: Optional[Comparison],
) -> None:
    """Best-effort EVIDENCE/RESULT/(COMPARISON) failure branch for one child
    attempt (design 6.4.6); the stop decision stands regardless.  The
    comparison is emitted whenever the gate walk produced an honest verdict,
    so the group stays closable by a REPLAY record."""
    if chain is None:
        return
    try:
        chain.emit("EVIDENCE", _evidence_inline(request.attempt_id, evidence))
        chain.emit("RESULT", _result_inline(request.attempt_id, evidence))
        if comparison is not None:
            chain.emit("COMPARISON", _comparison_inline(request.attempt_id, comparison))
    except Exception:
        return


def _close_group(
    chain: Optional[_Chain],
    attempts: int,
    group: _GroupState,
    stop_value: Optional[str],
) -> bool:
    """Emit the REPLAY close for one group; True when the record persisted."""
    if chain is None:
        return True
    try:
        chain.emit(
            "REPLAY",
            inline={
                "attempt_index": attempts,
                "requested": group.requested,
                "completed": group.completed,
                "comparable": group.comparable,
                "matching_signature": group.matching,
                "stop_reason": stop_value,
            },
        )
    except Exception:
        return False
    return True


def _run_child_attempt(
    state: _RunState,
    chain: Optional[_Chain],
    executor: ExecutionPort,
    run_control: Control,
    child_payload: CasePayload,
    parent_request: AttemptRequest,
    index: int,
    group: _GroupState,
    original_fingerprint: str,
) -> Optional[_GroupOutcome]:
    """Dispatch one child attempt and classify it (design 6.4.5).

    Returns None when the attempt matched the in-group baseline and the group
    may continue; otherwise the group verdict.  ``state.executions`` counts
    every prepare dispatch, prepare failures included.
    """
    remaining_ms = run_control.remaining_ms()
    attempt_ms = min(state.policy.attempt_budget_ms, remaining_ms)
    if attempt_ms < 1:
        attempt_ms = 1
    attempt_control = run_control.child(attempt_ms / 1000)
    request = _child_request(state, parent_request, child_payload, index, attempt_ms)

    if chain is not None:
        try:
            chain.emit(
                "REQUESTED",
                inline={
                    "attempt_id": request.attempt_id,
                    "execution_order": str(request.execution_order.value),
                    "request_hash": request.request_hash,
                },
                reserve_hint=_ATTEMPT_RESERVE_HINT,
            )
        except TraceBudgetError:
            return _GroupOutcome("budget", StopReason.EVIDENCE_BUDGET)
        except Exception:
            return _GroupOutcome("fault", StopReason.EVIDENCE_WRITE_FAILED)
    state.executions += 1
    group.requested += 1

    try:
        expectation = executor.prepare(request, attempt_control)
    except BaseException as exc:  # KeyboardInterrupt re-raised below
        terminal = _safe_cancel(executor, request.attempt_id, state.policy.cancel_grace_ms)
        evidence = _failure_evidence(request, None, AttemptStage.PREPARE, exc, terminal)
        group.attempt_hashes.append(evidence.evidence_hash)
        comparison, _ = _compare_evidence(request, evidence, run_control)
        _emit_attempt_records(chain, request, evidence, comparison)
        if not isinstance(exc, Exception):
            raise  # KeyboardInterrupt is never swallowed
        return _GroupOutcome("fault", StopReason.EXECUTOR_EXCEPTION)
    if chain is not None:
        try:
            chain.emit(
                "EXPECTATION",
                inline={
                    "attempt_id": request.attempt_id,
                    "expectation_hash": expectation.expectation_hash,
                },
            )
        except TraceBudgetError:
            _safe_cancel(executor, request.attempt_id, state.policy.cancel_grace_ms)
            return _GroupOutcome("budget", StopReason.EVIDENCE_BUDGET)
        except Exception:
            _safe_cancel(executor, request.attempt_id, state.policy.cancel_grace_ms)
            return _GroupOutcome("fault", StopReason.EVIDENCE_WRITE_FAILED)

    try:
        evidence = executor.execute(request, expectation, attempt_control)
    except BaseException as exc:  # KeyboardInterrupt re-raised below
        terminal = _safe_cancel(executor, request.attempt_id, state.policy.cancel_grace_ms)
        salvaged = _failure_evidence(request, expectation, AttemptStage.QUERY, exc, terminal)
        group.attempt_hashes.append(salvaged.evidence_hash)
        comparison, _ = _compare_evidence(request, salvaged, run_control)
        _emit_attempt_records(chain, request, salvaged, comparison)
        if not isinstance(exc, Exception):
            raise
        return _GroupOutcome("fault", StopReason.EXECUTOR_EXCEPTION)

    group.attempt_hashes.append(evidence.evidence_hash)
    if evidence.request_hash != request.request_hash:
        # Evidence bound to another request is refused, never treated as
        # verdict evidence (design 6.5); the gate walk still records an honest
        # INCONCLUSIVE comparison so the trace group stays closable.
        comparison, _ = _compare_evidence(request, evidence, run_control)
        _emit_attempt_records(chain, request, evidence, comparison)
        return _GroupOutcome("fault", StopReason.EXECUTION_PROTOCOL_ERROR)

    if _both_sides_complete(evidence):
        group.completed += 1
    if chain is not None:
        try:
            chain.emit("EVIDENCE", _evidence_inline(request.attempt_id, evidence))
            chain.emit("RESULT", _result_inline(request.attempt_id, evidence))
        except TraceBudgetError:
            return _GroupOutcome("budget", StopReason.EVIDENCE_BUDGET)
        except Exception:
            return _GroupOutcome("fault", StopReason.EVIDENCE_WRITE_FAILED)

    # Unconfirmed termination blocks the comparison (design 6.4.1); request a
    # cancellation proof before deciding the group's fate.
    terminal = evidence.terminal
    if terminal is None or terminal.termination is not TerminationState.CONFIRMED:
        cancel_receipt = _safe_cancel(
            executor, request.attempt_id, state.policy.cancel_grace_ms
        )
        if (
            cancel_receipt is not None
            and cancel_receipt.termination is TerminationState.CONFIRMED
        ):
            if run_control.cancelled():
                return _GroupOutcome("budget", StopReason.CANCELLED)
            if run_control.expired() or run_control.remaining_ms() <= 0:
                return _GroupOutcome("budget", StopReason.TIME_BUDGET)
            return _GroupOutcome("inconclusive")
        return _GroupOutcome("fault", StopReason.TERMINATION_UNCONFIRMED)

    comparison, comparison_stop = _compare_evidence(request, evidence, run_control)
    if comparison is None:
        if comparison_stop is StopReason.EXECUTION_PROTOCOL_ERROR:
            return _GroupOutcome("fault", StopReason.EXECUTION_PROTOCOL_ERROR)
        # Comparison cancelled or out of budget: disambiguate honestly.
        if run_control.cancelled():
            return _GroupOutcome("budget", StopReason.CANCELLED)
        if run_control.expired() or run_control.remaining_ms() <= 0:
            return _GroupOutcome("budget", StopReason.TIME_BUDGET)
        return _GroupOutcome("fault", StopReason.EXECUTION_PROTOCOL_ERROR)
    if chain is not None:
        try:
            # The ACCEPTED inline carries the COMPARISON *trace record* hashes
            # (trace.py contract); the receipt hash is authoritative.
            receipt = chain.emit(
                "COMPARISON", _comparison_inline(request.attempt_id, comparison)
            )
        except TraceBudgetError:
            return _GroupOutcome("budget", StopReason.EVIDENCE_BUDGET)
        except Exception:
            return _GroupOutcome("fault", StopReason.EVIDENCE_WRITE_FAILED)
        group.comparison_hashes.append(receipt.record_hash)
    else:
        group.comparison_hashes.append(comparison.hash)

    # Cleanup failure does not retract a complete comparison but is an
    # operational fault that stops the whole run (design 6.4.1/6.4.5).
    if evidence.terminal is None or evidence.terminal.cleanup is not CleanupState.DONE:
        return _GroupOutcome("fault", StopReason.CLEANUP_FAILED)

    if not comparison.comparable:
        if ComparisonReason.CANCELLED in comparison.reasons:
            return _GroupOutcome("budget", StopReason.CANCELLED)
        if ComparisonReason.BINDING_MISMATCH in comparison.reasons:
            return _GroupOutcome("fault", StopReason.EXECUTION_PROTOCOL_ERROR)
        if ComparisonReason.DATABASE_BINDING_MISMATCH in comparison.reasons:
            return _GroupOutcome("fault", StopReason.EXECUTION_PROTOCOL_ERROR)
        if ComparisonReason.ENVIRONMENT_DRIFT in comparison.reasons:
            return _GroupOutcome("fault", StopReason.ENVIRONMENT_DRIFT)
        if ComparisonReason.RESULT_CONTRACT_VIOLATION in comparison.reasons:
            return _GroupOutcome("fault", StopReason.EXECUTION_PROTOCOL_ERROR)
        # Plain execution failure: inconclusive about this child, the run
        # continues (design 6.4.5).
        return _GroupOutcome("inconclusive")

    group.comparable += 1
    if comparison.status is ComparisonStatus.MATCH:
        # A fresh child matching the parent's mismatch means the proposed
        # change destroyed the behaviour under test; the child is rejected
        # and the group stops (design 6.4.5).
        return _GroupOutcome("unstable", StopReason.MATCH_OBSERVED)
    if comparison.fingerprint != original_fingerprint:
        return _GroupOutcome("fault", StopReason.ENVIRONMENT_DRIFT)
    assert comparison.exact_signature is not None  # comparable MISMATCH invariant
    if group.baseline is None:
        # The first comparable attempt establishes the group baseline
        # (design 6.4.4: fresh children carry no prior evidence).
        group.baseline = comparison.exact_signature
    elif comparison.exact_signature != group.baseline:
        return _GroupOutcome("unstable", StopReason.SIGNATURE_CHANGED)
    group.matching += 1
    return None


# --------------------------------------------------------------------------
# Original replay outcome mapping
# --------------------------------------------------------------------------


def _classify_original_replay(
    replay, run_control: Control
) -> Optional[tuple[ReductionOutcome, StopReason]]:
    """Map the original replay's outcome; None means REPRODUCED and the
    search may start (contract 9: safety > budget > ordinary non-replay)."""
    if replay.outcome is ReplayOutcome.REPRODUCED:
        return None
    stop = replay.stop_reason
    if replay.operational_failure:
        return (ReductionOutcome.FAILED, stop)
    if stop is StopReason.NO_EXECUTOR:
        return (ReductionOutcome.FAILED, StopReason.NO_EXECUTOR)
    if stop is StopReason.INVALID_CANDIDATE:
        return (ReductionOutcome.FAILED, StopReason.INVALID_CANDIDATE)
    if stop is StopReason.CANCELLED:
        return (ReductionOutcome.BUDGET_EXHAUSTED, StopReason.CANCELLED)
    if stop is StopReason.TIME_BUDGET:
        return (ReductionOutcome.BUDGET_EXHAUSTED, StopReason.TIME_BUDGET)
    if stop is StopReason.EXECUTION_INCOMPLETE:
        # Non-operational incompleteness: a budget stop when the run's own
        # budget is gone, otherwise an ordinary non-reproduction.
        if run_control.cancelled():
            return (ReductionOutcome.BUDGET_EXHAUSTED, StopReason.CANCELLED)
        if run_control.expired() or run_control.remaining_ms() <= 0:
            return (ReductionOutcome.BUDGET_EXHAUSTED, StopReason.TIME_BUDGET)
        return (ReductionOutcome.FAILED, StopReason.ORIGINAL_NOT_REPRODUCED)
    return (ReductionOutcome.FAILED, StopReason.ORIGINAL_NOT_REPRODUCED)


# --------------------------------------------------------------------------
# Proposal loop
# --------------------------------------------------------------------------


def _identity_preserved(child: CasePayload, parent: CasePayload) -> bool:
    """Transforms must never change the rule, type pair, template or index
    variant (design 6.4.4); verified again before execution."""
    return (
        child.rule == parent.rule
        and child.a_type == parent.a_type
        and child.b_type == parent.b_type
        and child.query.template_id == parent.query.template_id
        and child.table.index_variant == parent.table.index_variant
    )


def _persist_acceptance(
    state: _RunState,
    chain: Optional[_Chain],
    child_payload: CasePayload,
    outcome: _GroupOutcome,
) -> Optional[tuple[ReductionOutcome, StopReason]]:
    """Publish the child payload artifact and append ACCEPTED BEFORE the
    in-memory best commits (design 6.4.6).  Returns a terminal (outcome,
    stop) pair on persistence failure, else None."""
    if chain is None:
        return None
    try:
        ref = chain.publish(canonical_json(child_payload.to_obj()))
    except TraceBudgetError:
        return (ReductionOutcome.BUDGET_EXHAUSTED, StopReason.EVIDENCE_BUDGET)
    except Exception:
        return (ReductionOutcome.FAILED, StopReason.EVIDENCE_WRITE_FAILED)
    try:
        chain.emit(
            "ACCEPTED",
            inline={
                "child_payload_ref": ref.to_obj(),
                "parent_complexity": list(complexity(state.best_payload)),
                "child_complexity": list(complexity(child_payload)),
                "comparison_hashes": list(outcome.comparison_hashes),
                "attempt_hashes": list(outcome.attempt_hashes),
            },
            payload_ref=ref,
        )
    except TraceBudgetError:
        return (ReductionOutcome.BUDGET_EXHAUSTED, StopReason.EVIDENCE_BUDGET)
    except Exception:
        return (ReductionOutcome.FAILED, StopReason.EVIDENCE_WRITE_FAILED)
    return None


def _run_proposals(
    state: _RunState,
    chain: Optional[_Chain],
    executor: ExecutionPort,
    run_control: Control,
    parent_request: AttemptRequest,
    original_fingerprint: str,
) -> tuple[Optional[tuple[ReductionOutcome, StopReason]], bool]:
    """Serial proposal loop over the current best payload (design 6.4.4).

    Returns (terminal, search_complete): terminal is None when every ordered
    proposal of the final best was exhausted, else an (outcome, stop) pair.
    """
    while True:
        restart = False
        fault: Optional[StopReason] = None
        budget_stop: Optional[StopReason] = None
        for transform in iter_proposals(state.best_payload):
            if run_control.cancelled():
                budget_stop = StopReason.CANCELLED
                break
            if run_control.expired() or run_control.remaining_ms() <= 0:
                budget_stop = StopReason.TIME_BUDGET
                break
            if state.proposals >= state.policy.max_proposals:
                budget_stop = StopReason.PROPOSAL_BUDGET
                break
            state.proposals += 1
            try:
                applied = apply_transform(state.best_payload, transform)
            except ContractError:
                state.rejected_static += 1
                continue
            if applied.status is not TransformStatus.APPLIED or applied.child is None:
                state.rejected_static += 1
                continue
            child_payload = applied.child.payload
            check = validate_case(child_payload)
            if (
                check.status is not StaticCheckStatus.VALID_STATIC
                or not _identity_preserved(child_payload, state.best_payload)
            ):
                state.rejected_static += 1
                continue
            if not complexity(child_payload) < complexity(state.best_payload):
                # Same-or-worse candidates are rejected before any execution.
                state.rejected_static += 1
                continue
            child_case_id = case_id_of(child_payload)
            if child_case_id in state.visited:
                state.rejected_static += 1
                continue
            state.visited.add(child_case_id)

            # A new three-round group needs at least three execution slots.
            if run_control.cancelled():
                budget_stop = StopReason.CANCELLED
                break
            if run_control.expired() or run_control.remaining_ms() <= 0:
                budget_stop = StopReason.TIME_BUDGET
                break
            if state.policy.max_executions - state.executions < REPLAY_ATTEMPTS:
                budget_stop = StopReason.EXECUTION_BUDGET
                break

            group = _GroupState()
            outcome: Optional[_GroupOutcome] = None
            for index in range(REPLAY_ATTEMPTS):
                if run_control.cancelled():
                    outcome = _GroupOutcome("budget", StopReason.CANCELLED)
                    break
                if run_control.expired() or run_control.remaining_ms() <= 0:
                    outcome = _GroupOutcome("budget", StopReason.TIME_BUDGET)
                    break
                outcome = _run_child_attempt(
                    state,
                    chain,
                    executor,
                    run_control,
                    child_payload,
                    parent_request,
                    index,
                    group,
                    original_fingerprint,
                )
                if outcome is not None:
                    break
            if outcome is None:
                outcome = _GroupOutcome(
                    "accept",
                    comparison_hashes=tuple(group.comparison_hashes),
                    attempt_hashes=tuple(group.attempt_hashes),
                )
            authoritative_close = outcome.status != "fault" and outcome.status != "budget"
            if not _close_group(
                chain,
                group.requested,
                group,
                None
                if outcome.status == "accept"
                else (
                    str(outcome.stop.value)
                    if outcome.stop is not None
                    else outcome.status
                ),
            ) and authoritative_close:
                outcome = _GroupOutcome("fault", StopReason.EVIDENCE_WRITE_FAILED)

            if outcome.status == "accept":
                terminal = _persist_acceptance(state, chain, child_payload, outcome)
                if terminal is not None:
                    # The pointer is not committed: the trace, not memory, is
                    # the only persistent authority for an acceptance.
                    if terminal[0] is ReductionOutcome.FAILED:
                        fault = terminal[1]
                    else:
                        budget_stop = terminal[1]
                    break
                state.commit_best(child_payload, outcome.comparison_hashes)
                restart = True
                break
            if outcome.status == "fault":
                fault = outcome.stop
                break
            if outcome.status == "budget":
                budget_stop = outcome.stop
                break
            if outcome.status == "unstable":
                state.unstable_candidates += 1
                continue
            state.inconclusive_candidates += 1
            continue
        if restart:
            continue  # restart from the new best's payload (design 6.4.4)
        if fault is not None:
            return (ReductionOutcome.FAILED, fault), False
        if budget_stop is not None:
            return (ReductionOutcome.BUDGET_EXHAUSTED, budget_stop), False
        return None, True


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def reduce_candidate(
    candidate: CandidateInput | None,
    executor: ExecutionPort | None,
    trace_sink: TraceSink | None,
    policy: ReductionPolicy,
    control: Control,
) -> ReductionResult:
    """Reduce one verified mismatch candidate through safe transforms
    (oracle-d2-contract section 9)."""
    state = _RunState(candidate, policy)

    # Zero-dispatch exits before any trace frame exists.
    if executor is None:
        return state.result(ReductionOutcome.FAILED, StopReason.NO_EXECUTOR, False)
    if candidate is None:
        return state.result(ReductionOutcome.FAILED, StopReason.INVALID_CANDIDATE, False)

    chain = None if trace_sink is None else _Chain(trace_sink)
    if chain is not None:
        terminal = _emit_engine_frame(chain, state)
        if terminal is not None:
            return state.result(terminal[0], terminal[1], False)

    # The total budget covers re-comparison, the original replay, dispatch,
    # comparison and tracing (design 6.4.5); the run control takes the min
    # with the caller's deadline and shares its token and injected clock.
    run_control = control.child(policy.total_budget_ms / 1000)

    if control.cancelled() or run_control.cancelled():
        outcome, stop = _emit_finished(
            chain, state, ReductionOutcome.BUDGET_EXHAUSTED, StopReason.CANCELLED
        )
        return state.result(outcome, stop, False)

    # Re-compare the original observation first; the recorded comparison hash
    # is never trusted (contract 9).  This costs no execution and no proposal.
    try:
        original = compare_case(
            candidate.request,
            candidate.expectation,
            candidate.evidence,
            ComparisonBudget(),
            run_control,
        )
    except ResultContractViolation as exc:
        original = exc.comparison
    except ControlCancelled:
        outcome, stop = _emit_finished(
            chain, state, ReductionOutcome.BUDGET_EXHAUSTED, StopReason.CANCELLED
        )
        return state.result(outcome, stop, False)
    except ContractError:
        outcome, stop = _emit_finished(
            chain, state, ReductionOutcome.FAILED, StopReason.INVALID_CANDIDATE
        )
        return state.result(outcome, stop, False)
    state.original_comparison_hash = original.hash
    if ComparisonReason.CANCELLED in original.reasons:
        outcome, stop = _emit_finished(
            chain, state, ReductionOutcome.BUDGET_EXHAUSTED, StopReason.CANCELLED
        )
        return state.result(outcome, stop, False)
    if ComparisonReason.COMPARISON_DEADLINE in original.reasons:
        outcome, stop = _emit_finished(
            chain, state, ReductionOutcome.BUDGET_EXHAUSTED, StopReason.TIME_BUDGET
        )
        return state.result(outcome, stop, False)
    if original.status is not ComparisonStatus.MISMATCH_CANDIDATE:
        outcome, stop = _emit_finished(
            chain, state, ReductionOutcome.FAILED, StopReason.INVALID_CANDIDATE
        )
        return state.result(outcome, stop, False)
    state.original_fingerprint = original.fingerprint

    # The original observation is always re-replayed fresh (contract 9): no
    # prior REPRODUCED label is ever cached or substituted.
    replay = replay_candidate(
        candidate,
        executor,
        None if chain is None else _ReplayView(chain),
        policy.replay_policy(),
        run_control,
    )
    state.executions += replay.requested
    terminal = _classify_original_replay(replay, run_control)
    if terminal is not None:
        outcome, stop = _emit_finished(chain, state, terminal[0], terminal[1])
        return state.result(outcome, stop, False)

    proposal_terminal, search_complete = _run_proposals(
        state,
        chain,
        executor,
        run_control,
        candidate.request,
        state.original_fingerprint,
    )
    if proposal_terminal is not None:
        outcome, stop = _emit_finished(chain, state, proposal_terminal[0], proposal_terminal[1])
        return state.result(outcome, stop, False)

    final_outcome = (
        ReductionOutcome.REDUCED
        if state.best_case_id != state.original_case_id
        else ReductionOutcome.UNCHANGED
    )
    outcome, stop = _emit_finished(chain, state, final_outcome, StopReason.SEARCH_EXHAUSTED)
    return state.result(outcome, stop, True)


def _emit_finished(
    chain: Optional[_Chain],
    state: _RunState,
    outcome: ReductionOutcome,
    stop: Optional[StopReason],
) -> tuple[ReductionOutcome, Optional[StopReason]]:
    """Emit the FINISHED record.  A budget refusal keeps the computed outcome
    (FINISHED may consume the reserve; a refusal means nothing fits).  Any
    other FINISHED failure is a persistence fault: the run reports FAILED
    with the last persisted best (design 6.4.6)."""
    if chain is None:
        return outcome, stop
    try:
        chain.emit(
            "FINISHED",
            inline={
                "outcome": str(outcome.value),
                "stop_reason": None if stop is None else str(stop.value),
                "best_case_id": state.best_case_id,
                "has_reduction": state.best_case_id != state.original_case_id,
            },
        )
    except TraceBudgetError:
        return outcome, stop
    except Exception:
        return ReductionOutcome.FAILED, StopReason.EVIDENCE_WRITE_FAILED
    return outcome, stop
