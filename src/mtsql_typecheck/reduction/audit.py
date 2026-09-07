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
"""

from __future__ import annotations

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
from .trace import TRACE_FILE_NAME, TRACE_STATUS_COMPLETE, read_trace

__all__ = [
    "EVIDENCE_PROFILE_NONE",
    "EVIDENCE_PROFILE_LEGACY",
    "EVIDENCE_PROFILE_FULL_MARKED",
    "SEMANTIC_NOT_AUDITED",
    "SEMANTIC_FULL_VERIFIED",
    "SEMANTIC_MISMATCH",
    "TraceSemanticAudit",
    "audit_trace",
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
) -> TraceSemanticAudit:
    """Structurally and semantically audit one trace root (read-only).

    The structural pass is :func:`reduction.trace.read_trace`; only a
    structurally COMPLETE trace on the full-evidence profile receives the
    semantic pass.
    """
    structural = read_trace(Path(root))
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

    records = _read_records(Path(root))
    profile = _evidence_profile(records)
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
    )


# --------------------------------------------------------------------------
# Record access
# --------------------------------------------------------------------------


def _read_records(root: Path) -> list[TraceRecord]:
    """Decode every complete JSONL line of a structurally COMPLETE trace."""
    records: list[TraceRecord] = []
    with open(root / TRACE_FILE_NAME, "rb") as fh:
        for raw in fh:
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            records.append(decode_trace_record(parse_strict_json(line)))
    return records


def _evidence_profile(records: list[TraceRecord]) -> str:
    if not records:
        return EVIDENCE_PROFILE_NONE
    for record in records:
        if record.kind == "START":
            inline = record.inline if isinstance(record.inline, dict) else {}
            if inline.get("evidence_profile") == EVIDENCE_PROFILE_FULL:
                return EVIDENCE_PROFILE_FULL_MARKED
            return EVIDENCE_PROFILE_LEGACY
    return EVIDENCE_PROFILE_LEGACY


def _payload_bytes(root: Path, ref: ArtifactRef, what: str) -> bytes:
    try:
        return (root / ref.path).read_bytes()
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
) -> TraceSemanticAudit:
    """Re-derive every attempt verdict from the published documents.

    Returns FULL_VERIFIED only when every attempt of every group re-verifies;
    the first contradiction stops trust (SEMANTIC_MISMATCH) and the first
    honest unverifiable attempt stops the audit (NOT_AUDITED).
    """
    groups = _attempt_groups(records)
    for group_index, group in enumerate(groups, start=1):
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
            detail = _verify_attempt(root, group_index, attempt_id, docs, budget, control)
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


def _attempt_groups(
    records: list[TraceRecord],
) -> list[dict[str, dict[str, TraceRecord]]]:
    """Group attempt records the way read_trace scopes replay groups: a
    REQUESTED that follows REPLAY/ACCEPTED/START opens a new group; within a
    group, records are keyed by their inline attempt_id."""
    groups: list[dict[str, dict[str, TraceRecord]]] = []
    current: Optional[dict[str, dict[str, TraceRecord]]] = None
    last_kind: Optional[str] = None
    for record in records:
        if record.kind == "REQUESTED" and last_kind != "COMPARISON":
            current = {}
            groups.append(current)
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
    return groups


def _verify_attempt(
    root: Path,
    group_index: int,
    attempt_id: str,
    docs: dict[str, TraceRecord],
    budget: ComparisonBudget,
    control: Optional[Control],
) -> Optional[str]:
    """Re-derive one attempt's verdict; None when it re-verifies, else the
    mismatch detail."""
    where = f"group {group_index} attempt {attempt_id!r}"
    try:
        request = load_attempt_request(
            _payload_bytes(root, docs["REQUESTED"].payload_ref, "REQUESTED")
        )
        expectation = load_attempt_expectation(
            _payload_bytes(root, docs["EXPECTATION"].payload_ref, "EXPECTATION")
        )
        evidence = load_execution_evidence(
            _payload_bytes(root, docs["EVIDENCE"].payload_ref, "EVIDENCE")
        )
        recorded = load_comparison(
            _payload_bytes(root, docs["COMPARISON"].payload_ref, "COMPARISON")
        )
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
