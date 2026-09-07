"""Hand-written fakes and helpers for the reduction-engine tests.

No expected value here is derived from the engine under test: results are
scripted per dispatch index by each test, readbacks are derived from the
dispatched request's own payload (the executor's fresh-objects obligation),
and every expectation in the test files is stated explicitly.  This module is
uniquely named suite-wide so tests can import it directly without a conftest
(pytest prepend import mode), exactly like ``replay_fakes``.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Callable, Optional

from mtsql_typecheck.contracts.case import NameMap
from mtsql_typecheck.contracts.codec import canonical_json, sha256_hex
from mtsql_typecheck.contracts.execution import (
    AttemptExpectation,
    AttemptRequest,
    Control,
    ExpectedBinding,
    ExecutionEvidence,
    QueryStatus,
    ResultTerminal,
    TerminalReceipt,
    TerminationState,
    CleanupState,
)
from mtsql_typecheck.contracts.oracle import (
    ArtifactRef,
    PersistedReceipt,
    ReductionPolicy,
    ReductionResult,
    TRACE_SCHEMA_VERSION,
    TraceRecord,
)
from mtsql_typecheck.reduction.engine import reduce_candidate

from replay_fakes import (
    CANDIDATE_A_ROWS,
    CANDIDATE_B_ROWS,
    CandidateBundle,
    StubClock,
    evidence_for,
    make_control,
)

from mtsql_typecheck.contracts.case import NullValue

# A NULL-only "mismatch" pair: A and B observe the same single NULL.  Used to
# reject one-row children whose shared value is NULL via MATCH (the observed
# multisets are independent of the payload rows).
NULL_ONLY_ROWS = (NullValue(),)


class ReductionExecutor:
    """ExecutionPort stub with per-dispatch scripting and adaptive readback.

    ``script`` maps the dispatch index (0-based, one index per dispatched
    attempt) either to an ``(a_rows, b_rows)`` pair of ExactValue items
    (default: the candidate fixture's mismatch rows) or to the string
    ``"sql_error"`` (side A ends SQL_ERROR with UNKNOWN result terminal).
    ``prepare_errors``/``execute_errors`` raise per dispatch index.
    ``tampered_bindings`` makes prepare return an expectation bound to a
    different case (binding drift).  The readback always mirrors the
    dispatched payload's shared rows, so child payloads produce consistent
    runtime facts.
    """

    def __init__(self, base: CandidateBundle) -> None:
        self.base = base
        self.script: dict[int, object] = {}
        # Rows used for dispatches without an explicit script entry (the
        # candidate fixture's mismatch observation).
        self.default: object = (CANDIDATE_A_ROWS, CANDIDATE_B_ROWS)
        self.prepare_errors: dict[int, BaseException] = {}
        self.execute_errors: dict[int, BaseException] = {}
        self.tampered_bindings: set[int] = set()
        self.on_execute: Optional[Callable[[int], None]] = None
        self.cancel_receipt: Optional[TerminalReceipt] = None
        self.calls: list[tuple[str, int, int]] = []
        self.evidence_by_dispatch: dict[int, ExecutionEvidence] = {}
        self.payloads_by_dispatch: dict[int, object] = {}
        self._dispatch = 0
        self._index_by_attempt: dict[str, int] = {}

    # -- dispatch log accessors --------------------------------------------

    @property
    def prepares(self) -> int:
        return sum(1 for kind, _index, _rows in self.calls if kind == "prepare")

    @property
    def dispatched_row_counts(self) -> list[int]:
        return [rows for kind, _index, rows in self.calls if kind == "prepare"]

    def payload_row_counts(self) -> list[int]:
        return self.dispatched_row_counts

    # -- ExecutionPort -------------------------------------------------------

    def prepare(self, request: AttemptRequest, control: Control) -> AttemptExpectation:
        index = self._dispatch
        self._dispatch += 1
        self._index_by_attempt[request.attempt_id] = index
        self.calls.append(("prepare", index, len(request.payload.rows.rows)))
        self.payloads_by_dispatch[index] = request.payload
        nm = NameMap(f"e_a_{index + 1}", f"e_b_{index + 1}", f"e_ta_{index + 1}", f"e_tb_{index + 1}")
        binding = ExpectedBinding(
            run_id=request.run_id,
            case_id=request.case_id,
            attempt_id=request.attempt_id,
            environment_hash=sha256_hex(canonical_json(request.target_environment.to_obj())),
            name_map_hash=sha256_hex(canonical_json(nm.to_obj())),
        )
        if index in self.tampered_bindings:
            binding = replace(binding, case_id="f" * 64)
        expectation = AttemptExpectation(
            binding=binding,
            request_hash=request.request_hash,
            codec_version="mysql-text-1",
            execution_order=request.execution_order,
            name_map=nm,
        )
        error = self.prepare_errors.get(index)
        if error is not None:
            raise error
        return expectation

    def execute(
        self, request: AttemptRequest, expectation: AttemptExpectation, control: Control
    ) -> ExecutionEvidence:
        index = self._index_by_attempt[request.attempt_id]
        self.calls.append(("execute", index, len(request.payload.rows.rows)))
        if self.on_execute is not None:
            self.on_execute(index)
        readback = tuple(row.value for row in request.payload.rows.rows)
        readback_rids = tuple(row.rid for row in request.payload.rows.rows)
        scripted = self.script.get(index, self.default)
        if scripted == "sql_error":
            evidence = _sql_error_evidence(
                request,
                expectation,
                readback,
                readback_rids,
                (CANDIDATE_B_ROWS),
            )
        elif scripted == "drift":
            evidence = drifted_evidence(
                evidence_for(
                    request,
                    expectation,
                    a_readback=readback,
                    b_readback=readback,
                    a_result_rows=CANDIDATE_A_ROWS,
                    b_result_rows=CANDIDATE_B_ROWS,
                    readback_rids=readback_rids,
                )
            )
        else:
            a_rows, b_rows = scripted
            evidence = evidence_for(
                request,
                expectation,
                a_readback=readback,
                b_readback=readback,
                a_result_rows=a_rows,
                b_result_rows=b_rows,
                readback_rids=readback_rids,
            )
        self.evidence_by_dispatch[index] = evidence
        error = self.execute_errors.get(index)
        if error is not None:
            raise error
        return evidence

    def cancel_and_wait(self, attempt_id: str, grace_seconds: float) -> TerminalReceipt:
        self.calls.append(("cancel", -1, 0))
        if self.cancel_receipt is not None:
            return replace(self.cancel_receipt, attempt_id=attempt_id)
        return TerminalReceipt(
            attempt_id=attempt_id,
            termination=TerminationState.CONFIRMED,
            cleanup=CleanupState.DONE,
            owned_objects=(),
        )


def _sql_error_evidence(
    request: AttemptRequest,
    expectation: AttemptExpectation,
    readback: tuple,
    readback_rids: tuple,
    b_result_rows: tuple,
) -> ExecutionEvidence:
    """Full evidence whose side A query ends SQL_ERROR with UNKNOWN terminal
    (a plain, terminal-confirmed execution failure)."""
    evidence = evidence_for(
        request,
        expectation,
        a_readback=readback,
        b_readback=readback,
        a_result_rows=(),
        b_result_rows=b_result_rows,
        readback_rids=readback_rids,
    )
    failed = replace(
        evidence.a_query,
        status=QueryStatus.SQL_ERROR,
        result=None,
        result_terminal=ResultTerminal.UNKNOWN,
    )
    return replace(evidence, a_query=failed, evidence_hash="")


def drifted_evidence(evidence: ExecutionEvidence) -> ExecutionEvidence:
    """Resealed evidence whose side B reports a different session time zone
    (environment drift against the declared requirements)."""
    drifted = replace(evidence.b_query.environment_after, time_zone="+08:00")
    b_query = replace(evidence.b_query, environment_after=drifted)
    b_context = replace(evidence.b_context, environment_after=drifted)
    return replace(evidence, b_query=b_query, b_context=b_context, evidence_hash="")


class RecordingTraceSink:
    """In-memory TraceSink spy with payload publication and per-kind failure.

    ``publish_payload`` records payload bytes under their sha256 (the same
    layout the real sink uses) so ACCEPTED/SNAPSHOT artifacts can be
    asserted; ``fail_on`` kinds raise ``RuntimeError`` before any state
    change, modelling a persistence fault; ``fail_publish`` makes every
    dependency publication raise instead.
    """

    def __init__(self, fail_on=(), fail_publish: bool = False) -> None:
        self.records: list[TraceRecord] = []
        self.reserved: list[int] = []
        self.payloads: dict[str, bytes] = {}
        self.fail_on = frozenset(fail_on)
        self.fail_publish = fail_publish

    def reserve(self, size_hint: int) -> None:
        self.reserved.append(size_hint)

    def publish_payload(self, data: bytes) -> ArtifactRef:
        if self.fail_publish:
            raise RuntimeError("simulated payload publication failure")
        payload = bytes(data)
        digest = sha256_hex(payload)
        self.payloads[digest] = payload
        return ArtifactRef(
            path=f"files/{digest}.json",
            size_bytes=len(payload),
            sha256=digest,
            schema_version=TRACE_SCHEMA_VERSION,
        )

    def append(self, record: TraceRecord) -> PersistedReceipt:
        if record.kind in self.fail_on:
            raise RuntimeError(f"simulated sink failure at {record.kind}")
        self.records.append(record)
        return PersistedReceipt(seq=record.seq, kind=record.kind, record_hash=record.hash)

    @property
    def kinds(self) -> list[str]:
        return [record.kind for record in self.records]

    def records_of_kind(self, kind: str) -> list[TraceRecord]:
        return [record for record in self.records if record.kind == kind]


def run_reduction(
    bundle: CandidateBundle,
    executor: ReductionExecutor,
    sink=None,
    *,
    policy: Optional[ReductionPolicy] = None,
    control=None,
    require_fresh_name_maps: bool = False,
) -> ReductionResult:
    return reduce_candidate(
        bundle.candidate,
        executor,
        sink,
        policy if policy is not None else ReductionPolicy(),
        control if control is not None else make_control(StubClock()),
        require_fresh_name_maps=require_fresh_name_maps,
        # In-memory test runs without a sink keep the pre-D3 unpersisted
        # behaviour; sink-less NO_SINK semantics are tested explicitly.
        unpersisted=(sink is None),
    )


def candidate_snapshot(bundle: CandidateBundle) -> dict[str, object]:
    """Byte/hash fingerprint of the original candidate's frozen objects, used
    to prove the engine never mutates its input."""
    candidate = bundle.candidate
    return {
        "payload": sha256_hex(canonical_json(candidate.request.payload.to_obj())),
        "request_hash": candidate.request.request_hash,
        "expectation_hash": candidate.expectation.expectation_hash,
        "evidence_hash": candidate.evidence.evidence_hash,
        "comparison_hash": candidate.comparison_hash,
    }


def assert_candidate_unchanged(bundle: CandidateBundle, before: dict[str, object]) -> None:
    after = candidate_snapshot(bundle)
    assert after == before
