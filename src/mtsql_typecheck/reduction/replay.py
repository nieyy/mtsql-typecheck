"""Fixed three-attempt replay of a mismatch candidate (oracle-d2-contract
section 7; design 6.4.3/6.4.5).

``replay_candidate`` never trusts the candidate's recorded comparison: the
original input is first re-compared through :func:`oracle.gates.compare_case`
(the same gate walk as any attempt), then exactly ``REPLAY_ATTEMPTS`` fresh
attempts are dispatched in the frozen order AB, BA, AB.  Every attempt gets a
fresh caller-generated attempt_id and the executor allocates fresh objects
(fresh NameMap/connections are modeled inside the ExecutionPort); logical A/B
labels always follow the AttemptRequest schema, never the dispatch order.

Early exit is terminal for the group: the first MATCH, any
exact_signature/fingerprint drift against the original observation, missing or
errored evidence, and operational failures (execution protocol violation,
cleanup != DONE, unconfirmed termination, trace write failure, executor
exception) stop the group; remaining rounds are neither dispatched nor
retried.  Counters always satisfy matching_signature <= comparable <=
completed <= requested (enforced again by the frozen ReplayResult model).

Time comes exclusively from the injected ``Control`` clock (monotonic
seconds; ``contracts.execution.default_control`` wires ``time.monotonic`` as
the default), so every budget in this module is an integer millisecond value
and no wall-clock read happens here.  All database side effects stay behind
the injected ``ExecutionPort``; this module performs no I/O of its own and
never imports a driver.

D3 online handover: a run without a sink is a zero-dispatch NO_SINK stop
unless the caller passes ``unpersisted=True`` (in-memory, non-certifiable);
each attempt reserves its max-receipt envelope before REQUESTED; full
canonical documents are published as dependency payloads (evidence profile
``typecheck-full-evidence-v1``); and the per-run name-map ledger guards the
fresh-objects handover.
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

from mtsql_typecheck.contracts.case import ContractError
from mtsql_typecheck.contracts.codec import canonical_json
from mtsql_typecheck.contracts.execution import (
    AttemptExpectation,
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
    dump_attempt_expectation,
    dump_attempt_request,
    dump_execution_evidence,
)
from mtsql_typecheck.contracts.oracle import (
    EVIDENCE_RESERVE_BYTES,
    MAX_EVIDENCE_BYTES,
    ORACLE_VERSION,
    REPLAY_ATTEMPTS,
    CandidateInput,
    Comparison,
    ComparisonBudget,
    ComparisonReason,
    ComparisonStatus,
    ReplayOutcome,
    ReplayPolicy,
    ReplayResult,
    StopReason,
    TraceRecord,
    TraceSink,
    dump_comparison,
)
from mtsql_typecheck.generation.validation import name_map_content_hash
from mtsql_typecheck.oracle.exact import row_key
from mtsql_typecheck.oracle.fingerprint import exact_signature
from mtsql_typecheck.oracle.gates import ResultContractViolation, compare_case

from .trace import TraceBudgetError

__all__ = ["replay_candidate", "attempt_reserve_hint"]

# Sentinel reference for "no original comparison exists" (None candidate);
# ReplayResult.comparison_hash is a frozen hex64 field.
_NO_COMPARISON_HASH = "0" * 64

# Frozen dispatch order (design 6.4.3); logical A/B labels follow the schema,
# never this sequence.
_DISPATCH_ORDERS = (ExecutionOrder.AB, ExecutionOrder.BA, ExecutionOrder.AB)

# Keeps "-replay-<n>" inside the 128-char AttemptRequest.attempt_id limit.
_ATTEMPT_ID_RUN_MAX = 100

# Slack for the remaining attempt records (EXPECTATION/EVIDENCE/RESULT/
# COMPARISON lines plus their published documents) on top of the worst-case
# evidence envelope (design 6.4.6 max-receipt reservation).
_ATTEMPT_RECORD_SLACK_BYTES = 1024 * 1024


def attempt_reserve_hint(request_doc_bytes: int) -> int:
    """Max-receipt pre-dispatch reserve for one attempt (design 6.4.6).

    Covers the attempt's REQUESTED document, the largest evidence envelope
    the executor may return (``MAX_EVIDENCE_BYTES``), one slack MiB for the
    remaining attempt records and the sink's termination reserve floor.
    Shared with the reduction engine so both writers reserve before they
    dispatch.
    """
    return (
        request_doc_bytes
        + MAX_EVIDENCE_BYTES
        + _ATTEMPT_RECORD_SLACK_BYTES
        + EVIDENCE_RESERVE_BYTES
    )


def replay_candidate(
    candidate: CandidateInput | None,
    executor: ExecutionPort | None,
    trace_sink: TraceSink | None,
    policy: ReplayPolicy,
    control: Control,
    *,
    require_fresh_name_maps: bool = False,
    unpersisted: bool = False,
) -> ReplayResult:
    """Replay one mismatch candidate with three fresh attempts (contract 7).

    ``require_fresh_name_maps=True`` additionally treats a repeated name-map
    content hash across the seeded original candidate and the replay attempts
    as an execution protocol violation (design 6.2 G01: cross-round object
    reuse) instead of a record-only ledger entry.  ``unpersisted=True``
    preserves the pre-D3 in-memory behaviour of running without a sink; such
    runs carry no trace and are never certifiable evidence.
    """
    synthetic = candidate.evidence.synthetic if candidate is not None else False
    comparison_hash = (
        candidate.comparison_hash if candidate is not None else _NO_COMPARISON_HASH
    )

    # Zero-dispatch exits: no executor, cooperative cancellation before any
    # dispatch, a candidate that does not re-compare to a mismatch, and —
    # since D3 — a missing sink without the explicit unpersisted opt-out
    # (a run with nowhere to persist its evidence is never dispatched).
    if executor is None:
        return _result(
            comparison_hash,
            policy,
            (),
            0,
            0,
            0,
            0,
            (),
            ReplayOutcome.NOT_REPLAYED,
            StopReason.NO_EXECUTOR,
            False,
            synthetic,
        )
    if control.cancelled():
        return _result(
            comparison_hash,
            policy,
            (),
            0,
            0,
            0,
            0,
            (),
            ReplayOutcome.NOT_REPLAYED,
            StopReason.CANCELLED,
            False,
            synthetic,
        )
    if candidate is None:
        return _result(
            comparison_hash,
            policy,
            (),
            0,
            0,
            0,
            0,
            (),
            ReplayOutcome.NOT_REPLAYED,
            StopReason.INVALID_CANDIDATE,
            False,
            synthetic,
        )
    if trace_sink is None and not unpersisted:
        return _result(
            comparison_hash,
            policy,
            (),
            0,
            0,
            0,
            0,
            (),
            ReplayOutcome.NOT_REPLAYED,
            StopReason.NO_SINK,
            True,
            synthetic,
        )

    # The total budget covers re-comparison, dispatch, comparison and tracing
    # (design 6.4.5); the group control takes the min with the caller's
    # deadline and shares its cancellation token and injected clock.
    group = control.child(policy.total_budget_ms / 1000)
    original, stop = _recompare(candidate, group)
    if original is None:
        return _result(
            comparison_hash,
            policy,
            (),
            0,
            0,
            0,
            0,
            (),
            ReplayOutcome.NOT_REPLAYED,
            stop,
            False,
            synthetic,
        )
    if ComparisonReason.CANCELLED in original.reasons:
        return _result(
            comparison_hash,
            policy,
            (),
            0,
            0,
            0,
            0,
            (),
            ReplayOutcome.NOT_REPLAYED,
            StopReason.CANCELLED,
            False,
            synthetic,
        )
    if ComparisonReason.COMPARISON_DEADLINE in original.reasons:
        return _result(
            comparison_hash,
            policy,
            (),
            0,
            0,
            0,
            0,
            (),
            ReplayOutcome.NOT_REPLAYED,
            StopReason.TIME_BUDGET,
            False,
            synthetic,
        )
    if original.status is not ComparisonStatus.MISMATCH_CANDIDATE:
        return _result(
            comparison_hash,
            policy,
            (),
            0,
            0,
            0,
            0,
            (),
            ReplayOutcome.NOT_REPLAYED,
            StopReason.INVALID_CANDIDATE,
            False,
            synthetic,
        )

    baseline_signature = original.exact_signature
    assert baseline_signature is not None  # MISMATCH_CANDIDATE model invariant
    baseline_fingerprint = original.fingerprint
    assert baseline_fingerprint is not None

    comparison_hash = original.hash
    tracer = _Tracer(trace_sink)
    counters = _Counters()

    # Per-run name-map content-hash ledger (design 6.2 G01): the original
    # candidate's name map seeds it, so an executor reusing the candidate's
    # objects for a "fresh" attempt is detected even on the first dispatch.
    name_map_ledger: set[str] = set()
    if candidate.expectation is not None:
        name_map_ledger.add(name_map_content_hash(candidate.expectation.name_map))

    for index in range(REPLAY_ATTEMPTS):
        # Pre-dispatch gates: cancellation is never retried past, and a
        # group whose total budget is spent never starts another attempt.
        if group.cancelled():
            stop = StopReason.CANCELLED
            break
        remaining_ms = group.remaining_ms()
        if remaining_ms <= 0 or group.expired():
            stop = StopReason.EXECUTION_INCOMPLETE
            break
        attempt_ms = min(policy.attempt_budget_ms, remaining_ms)
        if attempt_ms < 1:
            attempt_ms = 1
        attempt_control = group.child(attempt_ms / 1000)
        request = _attempt_request(candidate, index, attempt_ms, synthetic)

        # Max-receipt reservation BEFORE the REQUESTED record and before any
        # dispatch (design 6.4.6): an attempt that cannot reserve its full
        # evidence envelope up front is never started, so a budget refusal
        # leaves zero execution for it.
        try:
            tracer.reserve(attempt_reserve_hint(len(dump_attempt_request(request))))
        except TraceBudgetError:
            stop = StopReason.EVIDENCE_BUDGET
            break
        except Exception:
            stop, counters.operational = StopReason.EVIDENCE_WRITE_FAILED, True
            break
        if not tracer.emit_full(
            "REQUESTED",
            {
                "attempt_id": request.attempt_id,
                "execution_order": str(request.execution_order.value),
                "request_hash": request.request_hash,
            },
            dump_attempt_request(request),
        ):
            # Never dispatch an attempt that cannot be traced first
            # (design 6.4.5: no "run first, save later").
            stop, counters.operational = StopReason.EVIDENCE_WRITE_FAILED, True
            break
        counters.requested += 1

        stop, operational = _run_attempt(
            candidate,
            request,
            executor,
            attempt_control,
            group,
            policy,
            tracer,
            counters,
            baseline_signature,
            baseline_fingerprint,
            name_map_ledger,
            require_fresh_name_maps,
        )
        if operational:
            counters.operational = True

        replay_inline = {
            "attempt_index": index + 1,
            "requested": counters.requested,
            "completed": counters.completed,
            "comparable": counters.comparable,
            "matching_signature": counters.matching,
            "stop_reason": None if stop is None else str(stop.value),
        }
        if not tracer.emit("REPLAY", replay_inline) and stop is None:
            stop, counters.operational = StopReason.EVIDENCE_WRITE_FAILED, True
        if stop is not None:
            break

    if stop is None:
        # The loop only exhausts when every attempt matched the baseline;
        # the frozen model re-asserts matching == requested == 3.
        return _result(
            comparison_hash,
            policy,
            tuple(counters.attempt_hashes),
            counters.requested,
            counters.completed,
            counters.comparable,
            counters.matching,
            tuple(counters.signatures),
            ReplayOutcome.REPRODUCED,
            StopReason.REPLAY_COMPLETE,
            False,
            synthetic,
        )
    outcome = ReplayOutcome.UNSTABLE if counters.requested > 0 else ReplayOutcome.NOT_REPLAYED
    return _result(
        comparison_hash,
        policy,
        tuple(counters.attempt_hashes),
        counters.requested,
        counters.completed,
        counters.comparable,
        counters.matching,
        tuple(counters.signatures),
        outcome,
        stop,
        counters.operational,
        synthetic,
    )


# --------------------------------------------------------------------------
# Per-attempt driver
# --------------------------------------------------------------------------


class _Counters:
    """Mutable replay counters; the frozen ReplayResult seals them at exit."""

    def __init__(self) -> None:
        self.requested = 0
        self.completed = 0
        self.comparable = 0
        self.matching = 0
        self.operational = False
        self.attempt_hashes: list[str] = []
        self.signatures: list[str] = []


def _run_attempt(
    candidate: CandidateInput,
    request: AttemptRequest,
    executor: ExecutionPort,
    attempt_control: Control,
    group: Control,
    policy: ReplayPolicy,
    tracer: "_Tracer",
    counters: _Counters,
    baseline_signature: str,
    baseline_fingerprint: str,
    name_map_ledger: set[str],
    require_fresh_name_maps: bool,
) -> tuple[Optional[StopReason], bool]:
    """Dispatch prepare/execute for one attempt and evaluate the early-exit
    contract.  Returns (stop_reason, operational); None means the attempt
    matched the baseline and the group may continue."""
    expectation = None
    try:
        expectation = executor.prepare(request, attempt_control)
    except BaseException as exc:  # KeyboardInterrupt re-raised below
        terminal = _safe_cancel(executor, request.attempt_id, policy.cancel_grace_ms)
        evidence = _failure_evidence(request, None, AttemptStage.PREPARE, exc, terminal)
        counters.attempt_hashes.append(evidence.evidence_hash)
        _emit_failure_branch(tracer, request, evidence)
        if not isinstance(exc, Exception):
            raise  # KeyboardInterrupt is never swallowed
        return StopReason.EXECUTOR_EXCEPTION, True

    # Fresh-objects handover (design 6.2 G01): the executor allocates its own
    # NameMap per attempt; a content hash already in the run ledger means a
    # cross-round object reuse.  Record-only unless require_fresh_name_maps.
    name_map_hash = name_map_content_hash(expectation.name_map)
    if require_fresh_name_maps and name_map_hash in name_map_ledger:
        terminal = _safe_cancel(executor, request.attempt_id, policy.cancel_grace_ms)
        evidence = _failure_evidence(
            request, expectation, AttemptStage.SETUP, None, terminal,
            code="EXECUTION_PROTOCOL_ERROR",
        )
        counters.attempt_hashes.append(evidence.evidence_hash)
        _emit_failure_branch(tracer, request, evidence)
        return StopReason.EXECUTION_PROTOCOL_ERROR, True
    name_map_ledger.add(name_map_hash)

    if not tracer.emit_full(
        "EXPECTATION",
        {
            "attempt_id": request.attempt_id,
            "expectation_hash": expectation.expectation_hash,
        },
        dump_attempt_expectation(expectation),
    ):
        # Prepare ran; the attempt stays requested and is cancelled safely.
        terminal = _safe_cancel(executor, request.attempt_id, policy.cancel_grace_ms)
        evidence = _failure_evidence(
            request,
            expectation,
            AttemptStage.SETUP,
            None,
            terminal,
            code="EVIDENCE_WRITE_FAILED",
        )
        counters.attempt_hashes.append(evidence.evidence_hash)
        _emit_failure_branch(tracer, request, evidence)
        return StopReason.EVIDENCE_WRITE_FAILED, True
    try:
        evidence = executor.execute(request, expectation, attempt_control)
    except BaseException as exc:  # KeyboardInterrupt re-raised below
        terminal = _safe_cancel(executor, request.attempt_id, policy.cancel_grace_ms)
        salvaged = _failure_evidence(request, expectation, AttemptStage.QUERY, exc, terminal)
        counters.attempt_hashes.append(salvaged.evidence_hash)
        _emit_failure_branch(tracer, request, salvaged)
        if not isinstance(exc, Exception):
            raise
        return StopReason.EXECUTOR_EXCEPTION, True

    counters.attempt_hashes.append(evidence.evidence_hash)
    if evidence.request_hash != request.request_hash:
        # Evidence bound to another request is refused, never compared
        # (design 6.5: mismatched executor responses stop dispatching).
        _emit_failure_branch(tracer, request, evidence)
        return StopReason.EXECUTION_PROTOCOL_ERROR, True
    if (
        evidence.expectation is not None
        and evidence.expectation.expectation_hash != expectation.expectation_hash
    ):
        # Replaced binding/facts (design 6.2 G01): the executor returned
        # evidence bound to a different expectation than the one it prepared;
        # it is refused, never compared, and the attempt is cancelled first.
        _safe_cancel(executor, request.attempt_id, policy.cancel_grace_ms)
        _emit_failure_branch(tracer, request, evidence)
        return StopReason.EXECUTION_PROTOCOL_ERROR, True
    if _both_sides_complete(evidence):
        counters.completed += 1
    if not tracer.emit_full(
        "EVIDENCE",
        _evidence_inline(request.attempt_id, evidence),
        dump_execution_evidence(evidence),
    ):
        # The attempt ran; cancel it before reporting the write failure.
        _safe_cancel(executor, request.attempt_id, policy.cancel_grace_ms)
        return StopReason.EVIDENCE_WRITE_FAILED, True
    if not tracer.emit("RESULT", _result_inline(request.attempt_id, evidence)):
        _safe_cancel(executor, request.attempt_id, policy.cancel_grace_ms)
        return StopReason.EVIDENCE_WRITE_FAILED, True

    # Unconfirmed termination blocks the comparison (design 6.4.1); D2
    # requests cancellation to obtain a proof before giving up on the group.
    terminal = evidence.terminal
    if terminal is None or terminal.termination is not TerminationState.CONFIRMED:
        cancel_receipt = _safe_cancel(executor, request.attempt_id, policy.cancel_grace_ms)
        if cancel_receipt is not None and cancel_receipt.termination is TerminationState.CONFIRMED:
            return StopReason.EXECUTION_INCOMPLETE, False
        return StopReason.TERMINATION_UNCONFIRMED, True

    comparison, comparison_stop = _compare_attempt(
        request, expectation, evidence, group
    )
    if comparison is None:
        return comparison_stop, comparison_stop is StopReason.EXECUTION_PROTOCOL_ERROR
    if not tracer.emit_full(
        "COMPARISON",
        _comparison_inline(request.attempt_id, comparison),
        dump_comparison(comparison),
    ):
        _safe_cancel(executor, request.attempt_id, policy.cancel_grace_ms)
        return StopReason.EVIDENCE_WRITE_FAILED, True

    if comparison.comparable:
        counters.comparable += 1
        if comparison.status is ComparisonStatus.MATCH:
            # The frozen ReplayResult model requires one signature per
            # comparable attempt; a MATCH carries the signature of the
            # observed equal multisets (computed, never the candidate's hash).
            signature = _observed_signature(candidate.request.payload, evidence)
        else:
            signature = comparison.exact_signature
        assert signature is not None
        counters.signatures.append(signature)
    else:
        # A non-comparable attempt (gate refusal / inconclusive comparison)
        # is never treated as evidence about the mismatch; the group stops.
        if ComparisonReason.CANCELLED in comparison.reasons:
            return StopReason.CANCELLED, False
        return StopReason.EXECUTION_INCOMPLETE, False

    # Cleanup failure does not retract an already-complete comparison but is
    # an operational failure that stops the group (design 6.4.1/6.4.5).
    if evidence.terminal is None or evidence.terminal.cleanup is not CleanupState.DONE:
        return StopReason.CLEANUP_FAILED, True
    if comparison.status is ComparisonStatus.MATCH:
        return StopReason.MATCH_OBSERVED, False
    if comparison.fingerprint != baseline_fingerprint:
        return StopReason.ENVIRONMENT_DRIFT, False
    if comparison.exact_signature != baseline_signature:
        return StopReason.SIGNATURE_CHANGED, False
    counters.matching += 1
    return None, False


def _attempt_request(
    candidate: CandidateInput, index: int, attempt_ms: int, synthetic: bool
) -> AttemptRequest:
    """Fresh caller-generated request: new attempt_id, frozen dispatch order,
    the candidate's frozen payload/environment/profile and the attempt budget."""
    run_id = candidate.request.run_id
    return AttemptRequest(
        run_id=run_id,
        attempt_id=f"{run_id[:_ATTEMPT_ID_RUN_MAX]}-replay-{index + 1}",
        payload=candidate.request.payload,
        target_environment=candidate.request.target_environment,
        session_profile=candidate.request.session_profile,
        execution_order=_DISPATCH_ORDERS[index],
        result_row_budget=candidate.request.result_row_budget,
        result_byte_budget=candidate.request.result_byte_budget,
        time_budget_ms=attempt_ms,
        synthetic=synthetic,
    )


# --------------------------------------------------------------------------
# Baseline accessors (established by the initial re-comparison)
# --------------------------------------------------------------------------


def _recompare(
    candidate: CandidateInput, control: Control
) -> tuple[Optional[Comparison], Optional[StopReason]]:
    """Re-run the full gate walk on the candidate's own evidence; the recorded
    comparison hash/status are never trusted (contract 7)."""
    try:
        return (
            compare_case(
                candidate.request,
                candidate.expectation,
                candidate.evidence,
                ComparisonBudget(),
                control,
            ),
            None,
        )
    except ResultContractViolation as exc:
        return exc.comparison, None
    except ControlCancelled:
        return None, StopReason.CANCELLED
    except ContractError:
        return None, StopReason.INVALID_CANDIDATE


def _compare_attempt(
    request: AttemptRequest,
    expectation: AttemptExpectation,
    evidence: ExecutionEvidence,
    control: Control,
) -> tuple[Optional[Comparison], Optional[StopReason]]:
    """Compare against the prepare-RETURNED expectation (design 6.2 G01),
    never the expectation the evidence may be carrying itself."""
    try:
        return (
            compare_case(
                request, expectation, evidence, ComparisonBudget(), control
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
    """completed counter condition: both sides COMPLETE with a full,
    untruncated fetch (the model already ties COMPLETE to full fetch)."""
    for query in (evidence.a_query, evidence.b_query):
        if query is None or query.status is not QueryStatus.COMPLETE:
            return False
        if query.result is None or not query.result.fetch_complete or query.result.truncated:
            return False
    return True


def _observed_signature(payload, evidence: ExecutionEvidence) -> str:
    """exact_signature over the observed multisets, also for MATCH attempts."""
    a_rows = evidence.a_query.result.rows if evidence.a_query is not None else ()
    b_rows = evidence.b_query.result.rows if evidence.b_query is not None else ()
    return exact_signature(payload, ORACLE_VERSION, _key_counts(a_rows), _key_counts(b_rows))


def _key_counts(rows) -> dict:
    counter: Counter = Counter()
    for row in rows:
        counter[row_key(row)] += 1
    return dict(counter)


def _safe_cancel(
    executor: ExecutionPort, attempt_id: str, grace_ms: int
) -> Optional[TerminalReceipt]:
    """Best-effort cooperative cancel; never raises and never fabricates a
    confirmation (None means the attempt could not be confirmed)."""
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
    code: Optional[str] = None,
) -> ExecutionEvidence:
    """Salvage executor-carried evidence or record an honest failure envelope
    bound to the dispatched request (no fabricated success facts)."""
    salvaged = getattr(exc, "evidence", None)
    if isinstance(salvaged, ExecutionEvidence) and salvaged.request_hash == request.request_hash:
        return salvaged
    failure = getattr(exc, "failure", None)
    failure_code = code
    if failure_code is None:
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


# --------------------------------------------------------------------------
# Trace emission (chain-tracked; a None sink disables tracing entirely)
# --------------------------------------------------------------------------


class _Tracer:
    """Emits hash-chained TraceRecords through the injected sink and follows
    the PersistedReceipt chain so a shared sink stays consistent.

    Full-evidence profile (design 6.3): every REQUESTED/EXPECTATION/EVIDENCE/
    COMPARISON record publishes its complete canonical document through the
    sink's ``publish_payload`` first and references it via ``payload_ref``
    (``emit_full``); the engine's replay view implements that publication so
    the chain keeps a single owner.  ``emit`` writes inline-only records.
    """

    def __init__(self, sink: TraceSink | None) -> None:
        self._sink = sink
        self._seq = 0
        self._prev_hash = "0" * 64

    def reserve(self, size_hint: int) -> None:
        """Pre-flight budget check; TraceBudgetError propagates to the caller
        so it can distinguish a budget refusal from a write failure."""
        if self._sink is None:
            return
        self._sink.reserve(size_hint)

    def emit(self, kind: str, inline: dict) -> bool:
        """Persist one record; False on sink failure (caller stops dispatch)."""
        return self.emit_full(kind, inline, None)

    def emit_full(self, kind: str, inline: dict, doc: Optional[bytes]) -> bool:
        """Persist one record, publishing ``doc`` as a dependency payload and
        referencing it; False on sink failure (caller stops dispatch)."""
        if self._sink is None:
            return True
        try:
            payload_ref = None if doc is None else self._sink.publish_payload(doc)
            record = TraceRecord(
                seq=self._seq + 1,
                kind=kind,
                payload_ref=payload_ref,
                inline=inline,
                prev_hash=self._prev_hash,
            )
            self._sink.reserve(len(canonical_json(record.to_obj())))
            receipt = self._sink.append(record)
        except Exception:
            return False
        self._seq = receipt.seq
        self._prev_hash = receipt.record_hash
        return True


def _emit_failure_branch(
    tracer: _Tracer, request: AttemptRequest, evidence: ExecutionEvidence
) -> None:
    """EVIDENCE/RESULT failure branch without EXPECTATION/COMPARISON
    (design 6.4.6); failures are best-effort, the stop decision stands."""
    tracer.emit_full(
        "EVIDENCE", _evidence_inline(request.attempt_id, evidence),
        dump_execution_evidence(evidence),
    )
    tracer.emit("RESULT", _result_inline(request.attempt_id, evidence))


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


def _result(
    comparison_hash: str,
    policy: ReplayPolicy,
    attempt_hashes: tuple[str, ...],
    requested: int,
    completed: int,
    comparable: int,
    matching: int,
    signatures: tuple[str, ...],
    outcome: ReplayOutcome,
    stop: StopReason,
    operational: bool,
    synthetic: bool,
) -> ReplayResult:
    """Seal the frozen ReplayResult; the model re-asserts every invariant."""
    return ReplayResult(
        comparison_hash=comparison_hash,
        policy_hash=policy.policy_hash(),
        attempt_hashes=attempt_hashes,
        requested=requested,
        completed=completed,
        comparable=comparable,
        matching_signature=matching,
        exact_signatures=signatures,
        outcome=outcome,
        stop_reason=stop,
        operational_failure=operational,
        synthetic=synthetic,
    )
