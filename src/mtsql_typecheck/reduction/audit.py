"""Semantic audit over one persisted reduction trace (design 6.3, G03).

``read_trace`` (reduction.trace) verifies the structural layer: the JSONL
grammar, the hash chain, the dependency files' content hashes and the
ACCEPTED bookkeeping.  That layer proves the trace was written by
hash-chaining code; it does NOT prove the recorded verdicts follow from the
recorded evidence.

``audit_trace`` closes that gap for traces written on the full-evidence
profile (``START.inline.evidence_profile == typecheck-full-evidence-v1``):
every REQUESTED/EXPECTATION/EVIDENCE/COMPARISON record of such a trace also
publishes its complete canonical document, so the auditor can, per attempt,

1. reload the published request/expectation/evidence/comparison documents
   through the strict contract loaders,
2. verify the recorded inline hashes bind them together (request hash,
   expectation hash, evidence hash) and that the evidence carries the
   prepared expectation,
3. re-run the full oracle gate walk (:func:`oracle.gates.compare_case`) over
   the reloaded documents, and
4. require the recomputed comparison's content hash to equal the recorded
   comparison hash.

Any contradiction is a SEMANTIC_MISMATCH and trust stops there: the audit
never reports FULL_VERIFIED past the first forged group.  Attempts whose
failure branch legitimately lacks a full document set (no EXPECTATION/
COMPARISON document after a failed prepare/execute) make the trace honestly
unverifiable and are reported NOT_AUDITED, never as a mismatch.  Legacy D2
traces (no full-evidence marker) are NOT_AUDITED by construction: they do
not publish the documents needed to re-derive anything.

This module is read-only: it never writes to the trace root and never
imports a driver.

Bounded reads (design 6.5): ``audit_trace`` and ``audit_trace_detailed``
accept an optional :class:`~reduction.trace.TraceReadLimits`.  The structural
pass (:func:`reduction.trace.read_trace`) enforces the caps and raises
``TraceBudgetError`` at the first exceeded one.  The detailed audit consumes
the trace as a stream of replay groups: every attempt's documents are loaded,
verified and released before the next attempt is read, so neither the whole
record list nor more than one attempt's payloads is ever held in memory.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..contracts.case import ContractError
from ..contracts.codec import parse_strict_json
from ..contracts.execution import (
    Control,
    load_attempt_expectation,
    load_attempt_request,
    load_execution_evidence,
)
from ..contracts.oracle import (
    EVIDENCE_PROFILE_FULL,
    ArtifactRef,
    ComparisonBudget,
    TraceRecord,
    decode_trace_record,
    load_comparison,
)
from ..oracle.gates import ResultContractViolation, compare_case
from .trace import (
    TRACE_FILE_NAME,
    TRACE_STATUS_COMPLETE,
    TraceBudgetError,
    TraceReadLimits,
    read_trace,
)

__all__ = [
    "EVIDENCE_PROFILE_NONE",
    "EVIDENCE_PROFILE_LEGACY",
    "EVIDENCE_PROFILE_FULL_MARKED",
    "SEMANTIC_NOT_AUDITED",
    "SEMANTIC_FULL_VERIFIED",
    "SEMANTIC_MISMATCH",
    "STRUCTURAL_STATUS_UNKNOWN",
    "AttemptOutcome",
    "TraceSemanticAudit",
    "TraceDetailedAudit",
    "audit_trace",
    "audit_trace_detailed",
]

# Audit-level evidence profile labels (distinct from the START marker value,
# which is contracts.oracle.EVIDENCE_PROFILE_FULL).
EVIDENCE_PROFILE_NONE = "NONE"
EVIDENCE_PROFILE_LEGACY = "LEGACY"
EVIDENCE_PROFILE_FULL_MARKED = "FULL"

# Semantic pass verdicts.
SEMANTIC_NOT_AUDITED = "NOT_AUDITED"
SEMANTIC_FULL_VERIFIED = "FULL_VERIFIED"
SEMANTIC_MISMATCH = "SEMANTIC_MISMATCH"

# TraceDetailedAudit.structural_status when a read limit stopped the
# structural read itself, so no structural verdict could be reached.
STRUCTURAL_STATUS_UNKNOWN = "UNKNOWN"

_ATTEMPT_KINDS = ("REQUESTED", "EXPECTATION", "EVIDENCE", "COMPARISON")


@dataclass(frozen=True)
class TraceSemanticAudit:
    """Result of one semantic audit over a trace root.

    ``evidence_profile`` is FULL / LEGACY / NONE; ``semantic_status`` is
    NOT_AUDITED / FULL_VERIFIED / SEMANTIC_MISMATCH.  ``detail`` carries the
    human-readable reason, including the exact group and attempt at which
    trust stopped.  ``best_payload_ref`` mirrors the structural audit's
    reconstructed best-case artifact.
    """

    records_verified: int
    structural_status: str
    evidence_profile: str
    semantic_status: str
    detail: str
    best_payload_ref: Optional[ArtifactRef]


def audit_trace(
    root: Path,
    budget: ComparisonBudget,
    control: Optional[Control] = None,
    *,
    limits: Optional[TraceReadLimits] = None,
) -> TraceSemanticAudit:
    """Structurally and semantically audit one trace root (read-only).

    The structural pass is :func:`reduction.trace.read_trace`; only a
    structurally COMPLETE trace on the full-evidence profile receives the
    semantic pass.  With ``limits``, the caps are enforced by the structural
    pass and by every document read; the first exceeded cap raises
    ``TraceBudgetError`` out of this call.
    """
    structural = read_trace(Path(root), limits=limits)
    if structural.trace_status != TRACE_STATUS_COMPLETE:
        return TraceSemanticAudit(
            records_verified=structural.records_verified,
            structural_status=structural.trace_status,
            evidence_profile=EVIDENCE_PROFILE_NONE,
            semantic_status=SEMANTIC_NOT_AUDITED,
            detail=(
                "semantic audit requires a structurally COMPLETE trace; "
                f"structural status is {structural.trace_status}"
                + (f" ({structural.detail})" if structural.detail else "")
            ),
            best_payload_ref=structural.best_payload_ref,
        )

    records = _read_records(Path(root), limits)
    profile = _profile_of_records(records)
    if profile != EVIDENCE_PROFILE_FULL_MARKED:
        if profile is EVIDENCE_PROFILE_NONE:
            detail = "trace carries no records"
        else:
            detail = (
                "trace is a legacy D2 trace (START without the "
                f"{EVIDENCE_PROFILE_FULL!r} marker); its records do not "
                "publish the documents needed to re-derive the verdicts"
            )
        return TraceSemanticAudit(
            records_verified=structural.records_verified,
            structural_status=structural.trace_status,
            evidence_profile=profile,
            semantic_status=SEMANTIC_NOT_AUDITED,
            detail=detail,
            best_payload_ref=structural.best_payload_ref,
        )

    return _semantic_pass(
        Path(root),
        records,
        budget,
        control,
        structural.records_verified,
        structural.best_payload_ref,
        limits,
    )


# --------------------------------------------------------------------------
# Record access
# --------------------------------------------------------------------------


def _iter_records(
    root: Path, limits: Optional[TraceReadLimits] = None
) -> Iterator[TraceRecord]:
    """Stream the decoded records of a structurally COMPLETE trace.

    Mirrors the historical :func:`_read_records` line handling (``\\r\\n``
    stripped, empty lines skipped).  With limits, ``max_line_bytes`` and
    ``max_records`` are enforced before a line is decoded; exceeding one
    raises ``TraceBudgetError`` naming the cap.
    """
    line_cap = limits.max_line_bytes if limits is not None else None
    record_cap = limits.max_records if limits is not None else None
    count = 0
    with open(root / TRACE_FILE_NAME, "rb") as fh:
        for raw in fh:
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            if line_cap is not None and len(line) > line_cap:
                raise TraceBudgetError(
                    f"trace read limit exceeded: max_line_bytes={line_cap}: "
                    f"a trace line is {len(line)} bytes"
                )
            if record_cap is not None and count >= record_cap:
                raise TraceBudgetError(
                    f"trace read limit exceeded: max_records={record_cap}: "
                    f"the trace continues beyond {record_cap} records"
                )
            count += 1
            yield decode_trace_record(parse_strict_json(line))


def _read_records(
    root: Path, limits: Optional[TraceReadLimits] = None
) -> list[TraceRecord]:
    """Decode every complete JSONL line of a structurally COMPLETE trace."""
    return list(_iter_records(root, limits))


def _profile_of_records(records: Iterator[TraceRecord]) -> str:
    """FULL / LEGACY / NONE from the trace's START marker (streaming: the
    scan stops at the START record instead of materialising all records)."""
    seen_any = False
    for record in records:
        seen_any = True
        if record.kind == "START":
            inline = record.inline if isinstance(record.inline, dict) else {}
            if inline.get("evidence_profile") == EVIDENCE_PROFILE_FULL:
                return EVIDENCE_PROFILE_FULL_MARKED
            return EVIDENCE_PROFILE_LEGACY
    return EVIDENCE_PROFILE_NONE if not seen_any else EVIDENCE_PROFILE_LEGACY


def _payload_bytes(
    root: Path,
    ref: ArtifactRef,
    what: str,
    limits: Optional[TraceReadLimits] = None,
) -> bytes:
    target = root / ref.path
    if limits is not None and limits.max_dependency_bytes is not None:
        cap = limits.max_dependency_bytes
        try:
            st = os.lstat(target)
        except OSError as exc:
            raise ContractError(f"cannot read {what} document: {exc}") from exc
        if st.st_size > cap:
            raise TraceBudgetError(
                f"trace read limit exceeded: max_dependency_bytes={cap}: "
                f"dependency file {ref.path!r} is {st.st_size} bytes"
            )
    try:
        return target.read_bytes()
    except OSError as exc:
        raise ContractError(f"cannot read {what} document: {exc}") from exc


# --------------------------------------------------------------------------
# Semantic pass
# --------------------------------------------------------------------------


def _semantic_pass(
    root: Path,
    records: list[TraceRecord],
    budget: ComparisonBudget,
    control: Optional[Control],
    records_verified: int,
    best_payload_ref: Optional[ArtifactRef],
    limits: Optional[TraceReadLimits] = None,
) -> TraceSemanticAudit:
    """Re-derive every attempt verdict from the published documents.

    Returns FULL_VERIFIED only when every attempt of every group re-verifies;
    the first contradiction stops trust (SEMANTIC_MISMATCH) and the first
    honest unverifiable attempt stops the audit (NOT_AUDITED).
    """
    groups = list(_group_attempts(records))
    for group_index, group in groups:
        for attempt_id in group:
            docs = group[attempt_id]
            missing = [
                kind
                for kind in _ATTEMPT_KINDS
                if docs.get(kind) is None or docs[kind].payload_ref is None
            ]
            if missing:
                return TraceSemanticAudit(
                    records_verified=records_verified,
                    structural_status=TRACE_STATUS_COMPLETE,
                    evidence_profile=EVIDENCE_PROFILE_FULL_MARKED,
                    semantic_status=SEMANTIC_NOT_AUDITED,
                    detail=(
                        f"group {group_index} attempt {attempt_id!r} lacks the "
                        f"full document set (no {', '.join(missing)} payload); "
                        "the trace is honestly unverifiable, not forged"
                    ),
                    best_payload_ref=best_payload_ref,
                )
            detail = _verify_attempt(
                root, group_index, attempt_id, docs, budget, control, limits
            )
            if detail is not None:
                return TraceSemanticAudit(
                    records_verified=records_verified,
                    structural_status=TRACE_STATUS_COMPLETE,
                    evidence_profile=EVIDENCE_PROFILE_FULL_MARKED,
                    semantic_status=SEMANTIC_MISMATCH,
                    detail=detail,
                    best_payload_ref=best_payload_ref,
                )
    return TraceSemanticAudit(
        records_verified=records_verified,
        structural_status=TRACE_STATUS_COMPLETE,
        evidence_profile=EVIDENCE_PROFILE_FULL_MARKED,
        semantic_status=SEMANTIC_FULL_VERIFIED,
        detail=(
            f"all {len(groups)} replay group(s) re-verified from their "
            "published documents: recorded comparison hashes equal the "
            "recomputed gate-walk verdicts"
        ),
        best_payload_ref=best_payload_ref,
    )


def _group_attempts(
    records: Iterator[TraceRecord],
) -> Iterator[tuple[int, dict[str, dict[str, TraceRecord]]]]:
    """Group attempt records the way read_trace scopes replay groups: a
    REQUESTED that follows REPLAY/ACCEPTED/START opens a new group; within a
    group, records are keyed by their inline attempt_id.

    Streaming form: a group is yielded (1-based index, dict) the moment the
    next group opens or the record stream ends, so a consumer can process and
    release one group at a time over a long trace.  The grouping logic —
    including the group numbering and the treatment of records without a
    string ``attempt_id`` — is the historical :func:`_attempt_groups` logic,
    unchanged.
    """
    current: Optional[dict[str, dict[str, TraceRecord]]] = None
    last_kind: Optional[str] = None
    group_index = 0
    for record in records:
        if record.kind == "REQUESTED" and last_kind != "COMPARISON":
            if current is not None:
                group_index += 1
                yield group_index, current
            current = {}
        if record.kind in _ATTEMPT_KINDS:
            if current is None:
                continue  # no REQUESTED seen yet (e.g. a bare SNAPSHOT/START)
            attempt_id = (record.inline or {}).get("attempt_id")
            if not isinstance(attempt_id, str):
                continue
            current.setdefault(attempt_id, {})[record.kind] = record
        if record.kind in ("REPLAY", "ACCEPTED"):
            last_kind = record.kind
            continue
        last_kind = record.kind
    if current is not None:
        group_index += 1
        yield group_index, current


def _attempt_groups(
    records: list[TraceRecord],
) -> list[dict[str, dict[str, TraceRecord]]]:
    """Materialised form of :func:`_group_attempts` (historical shape)."""
    return [group for _index, group in _group_attempts(iter(records))]


def _verify_attempt(
    root: Path,
    group_index: int,
    attempt_id: str,
    docs: dict[str, TraceRecord],
    budget: ComparisonBudget,
    control: Optional[Control],
    limits: Optional[TraceReadLimits] = None,
) -> Optional[str]:
    """Re-derive one attempt's verdict; None when it re-verifies, else the
    mismatch detail."""
    where = f"group {group_index} attempt {attempt_id!r}"
    try:
        request = load_attempt_request(
            _payload_bytes(root, docs["REQUESTED"].payload_ref, "REQUESTED", limits)
        )
        expectation = load_attempt_expectation(
            _payload_bytes(root, docs["EXPECTATION"].payload_ref, "EXPECTATION", limits)
        )
        evidence = load_execution_evidence(
            _payload_bytes(root, docs["EVIDENCE"].payload_ref, "EVIDENCE", limits)
        )
        recorded = load_comparison(
            _payload_bytes(root, docs["COMPARISON"].payload_ref, "COMPARISON", limits)
        )
    except TraceBudgetError:
        raise  # a read-limit hit is a budget signal, not a loader failure
    except ContractError as exc:
        return f"{where}: a published document fails its strict loader: {exc}"

    def _inline(kind: str) -> dict:
        inline = docs[kind].inline
        return inline if isinstance(inline, dict) else {}

    checks = (
        (
            request.request_hash == _inline("REQUESTED").get("request_hash"),
            "REQUESTED document does not hash to the recorded request_hash",
        ),
        (
            request.request_hash == expectation.request_hash,
            "EXPECTATION document is bound to a different request_hash",
        ),
        (
            expectation.expectation_hash
            == _inline("EXPECTATION").get("expectation_hash"),
            "EXPECTATION document does not hash to the recorded expectation_hash",
        ),
        (
            evidence.request_hash == request.request_hash,
            "EVIDENCE document is bound to a different request_hash",
        ),
        (
            evidence.expectation is not None
            and evidence.expectation.expectation_hash == expectation.expectation_hash,
            "EVIDENCE document does not carry the prepared expectation",
        ),
        (
            evidence.evidence_hash == _inline("EVIDENCE").get("evidence_hash"),
            "EVIDENCE document does not hash to the recorded evidence_hash",
        ),
        (
            recorded.hash == _inline("COMPARISON").get("comparison_hash"),
            "COMPARISON document does not hash to the recorded comparison_hash",
        ),
    )
    for holds, reason in checks:
        if not holds:
            return f"{where}: {reason}"

    try:
        recomputed = compare_case(request, expectation, evidence, budget, control)
    except ResultContractViolation as exc:
        recomputed = exc.comparison
    except ContractError as exc:
        return f"{where}: recomputed gate walk refuses the documents: {exc}"
    if recomputed.hash != recorded.hash:
        return (
            f"{where}: recomputed comparison hash {recomputed.hash} does not "
            f"match the recorded comparison hash {recorded.hash} "
            f"(recorded status {str(recorded.status.value)}, recomputed "
            f"{str(recomputed.status.value)}); trust stops at this group"
        )
    return None


# --------------------------------------------------------------------------
# Detailed per-attempt audit (D4 read-side entry, design 6.5)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AttemptOutcome:
    """One attempt's semantic-audit outcome inside :class:`TraceDetailedAudit`.

    ``group_index`` is the 1-based replay-group number (same numbering as
    ``audit_trace``'s detail strings).  ``status`` is one of the module's
    semantic verdict constants (FULL_VERIFIED / NOT_AUDITED /
    SEMANTIC_MISMATCH).  ``detail`` carries the human-readable reason; a
    group-level outcome (see :class:`TraceDetailedAudit`) is marked by an
    empty ``attempt_id``.
    """

    group_index: int
    attempt_id: str
    status: str
    detail: str


@dataclass(frozen=True)
class TraceDetailedAudit:
    """Per-attempt result of :func:`audit_trace_detailed`.

    Unlike :func:`audit_trace`, the detailed audit does not stop at the first
    contradiction: every attempt of every group receives an
    :class:`AttemptOutcome` (in group order, then first-seen attempt order).

    Conventions:

    - ``structural_status`` mirrors the structural audit's trace status; when
      a read limit stopped the structural read itself, no structural verdict
      exists and the value is ``STRUCTURAL_STATUS_UNKNOWN`` ("UNKNOWN").
    - Legacy traces and structurally incomplete traces yield an EMPTY
      ``attempt_outcomes`` tuple (the same early returns ``audit_trace``
      takes); no attempt of such a trace is ever reported as verified.
    - ``limit_exhausted`` is True when a ``TraceBudgetError`` (structural or
      per-attempt) stopped the audit early.  Attempts after the stop point do
      not appear at all; the attempt or group that could not be completed is
      reported NOT_AUDITED with a ``budget_exhausted: ...`` detail.  When the
      stop happened while grouping (before any attempt of the group had an
      outcome), the group is recorded as ONE group-level ``AttemptOutcome``
      with the group's 1-based index and an empty ``attempt_id``.
    """

    structural_status: str
    evidence_profile: str
    attempt_outcomes: tuple[AttemptOutcome, ...]
    records_verified: int
    best_payload_ref: Optional[ArtifactRef]
    limit_exhausted: bool


def audit_trace_detailed(
    root: Path,
    budget: ComparisonBudget,
    control: Optional[Control] = None,
    *,
    limits: Optional[TraceReadLimits] = None,
) -> TraceDetailedAudit:
    """Audit every attempt of every group of one trace root (read-only).

    The comparison logic per attempt is exactly :func:`audit_trace`'s (the
    shared ``_verify_attempt`` helper); the difference is that a mismatch or
    an unverifiable attempt is recorded and the audit CONTINUES with the next
    attempt, so the result names every good and every bad attempt instead of
    only the first problem.  Records are consumed as a stream of replay
    groups: one attempt's documents are loaded, verified and released before
    the next attempt is read.

    With ``limits``, the caps are enforced by the structural pass and by
    every document read; a exceeded cap stops the audit with
    ``limit_exhausted=True`` (see :class:`TraceDetailedAudit` for the
    outcome conventions) instead of raising.
    """
    root_path = Path(root)
    try:
        structural = read_trace(root_path, limits=limits)
    except TraceBudgetError as exc:
        # The structural read itself stopped at a cap: no attempt could be
        # grouped, so the whole trace is recorded as one group-level outcome.
        return TraceDetailedAudit(
            structural_status=STRUCTURAL_STATUS_UNKNOWN,
            evidence_profile=EVIDENCE_PROFILE_NONE,
            attempt_outcomes=(
                AttemptOutcome(
                    group_index=1,
                    attempt_id="",
                    status=SEMANTIC_NOT_AUDITED,
                    detail=(
                        "budget_exhausted: the structural trace read stopped "
                        f"at a read limit: {exc}"
                    ),
                ),
            ),
            records_verified=0,
            best_payload_ref=None,
            limit_exhausted=True,
        )

    if structural.trace_status != TRACE_STATUS_COMPLETE:
        return TraceDetailedAudit(
            structural_status=structural.trace_status,
            evidence_profile=EVIDENCE_PROFILE_NONE,
            attempt_outcomes=(),
            records_verified=structural.records_verified,
            best_payload_ref=structural.best_payload_ref,
            limit_exhausted=False,
        )

    try:
        profile = _profile_of_records(_iter_records(root_path, limits))
    except FileNotFoundError:
        if structural.records_verified != 0:
            raise
        # A zero-record COMPLETE audit already reported the absent/empty
        # trace.jsonl; there is nothing to audit per attempt.
        profile = EVIDENCE_PROFILE_NONE
    if profile != EVIDENCE_PROFILE_FULL_MARKED:
        return TraceDetailedAudit(
            structural_status=structural.trace_status,
            evidence_profile=profile,
            attempt_outcomes=(),
            records_verified=structural.records_verified,
            best_payload_ref=structural.best_payload_ref,
            limit_exhausted=False,
        )

    outcomes: list[AttemptOutcome] = []
    limit_exhausted = False
    group_index = 0
    try:
        stopped = False
        for index, group in _group_attempts(_iter_records(root_path, limits)):
            group_index = index
            for attempt_id in group:
                docs = group[attempt_id]
                missing = [
                    kind
                    for kind in _ATTEMPT_KINDS
                    if docs.get(kind) is None or docs[kind].payload_ref is None
                ]
                if missing:
                    outcomes.append(
                        AttemptOutcome(
                            group_index=index,
                            attempt_id=attempt_id,
                            status=SEMANTIC_NOT_AUDITED,
                            detail=(
                                f"lacks the full document set (no "
                                f"{', '.join(missing)} payload); the trace is "
                                "honestly unverifiable, not forged"
                            ),
                        )
                    )
                    continue
                try:
                    detail = _verify_attempt(
                        root_path, index, attempt_id, docs, budget, control, limits
                    )
                except TraceBudgetError as exc:
                    outcomes.append(
                        AttemptOutcome(
                            group_index=index,
                            attempt_id=attempt_id,
                            status=SEMANTIC_NOT_AUDITED,
                            detail=f"budget_exhausted: {exc}",
                        )
                    )
                    limit_exhausted = True
                    stopped = True
                    break
                if detail is not None:
                    outcomes.append(
                        AttemptOutcome(
                            group_index=index,
                            attempt_id=attempt_id,
                            status=SEMANTIC_MISMATCH,
                            detail=detail,
                        )
                    )
                else:
                    outcomes.append(
                        AttemptOutcome(
                            group_index=index,
                            attempt_id=attempt_id,
                            status=SEMANTIC_FULL_VERIFIED,
                            detail="re-verified from the published documents",
                        )
                    )
            if stopped:
                break
    except TraceBudgetError as exc:
        # The stop happened while streaming/grouping records, before the
        # group being read could receive attempt outcomes: record it as one
        # group-level outcome (empty attempt_id convention).
        limit_exhausted = True
        outcomes.append(
            AttemptOutcome(
                group_index=group_index + 1,
                attempt_id="",
                status=SEMANTIC_NOT_AUDITED,
                detail=f"budget_exhausted: {exc}",
            )
        )

    return TraceDetailedAudit(
        structural_status=structural.trace_status,
        evidence_profile=EVIDENCE_PROFILE_FULL_MARKED,
        attempt_outcomes=tuple(outcomes),
        records_verified=structural.records_verified,
        best_payload_ref=structural.best_payload_ref,
        limit_exhausted=limit_exhausted,
    )
