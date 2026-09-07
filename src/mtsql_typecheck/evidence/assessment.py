"""Layered source assessment over one snapshot copy (design 6.2.2, 6.4.2, 6.4.3, 6.5).

For one native source (its bytes already copied to the private snapshot
``<output_root>/raw/<source-id>/``), this module derives the four assessment
dimensions of design 6.2.2:

- structural (design 6.4.2 per-kind integrity gates),
- semantic (per-attempt independent recompute through the D1 static
  revalidation and the D2 oracle, never trusting a recorded verdict),
- provenance and execution safety (delegated to :mod:`.provenance`).

House rules (design 6.4.1 item 5, 6.4.3, 6.5):

- Every read touches the snapshot copy only; the original tree is never read
  and never modified.  A recorded comparison document is never rewritten; a
  contradiction is reported, not repaired.
- A recompute mismatch is a CONFLICT with the original preserved; missing or
  unreadable inputs are NOT_RECOMPUTED, never silently "verified"; attempts
  that could not be audited are never reported as verified.
- Traces reuse the D2 read/audit engines (:func:`reduction.trace.read_trace`,
  :func:`reduction.audit.audit_trace_detailed`); D4 does not re-implement
  comparison or reduction algorithms (design 6.4.3).
- Every stage is bounded by :class:`~contracts.delivery.Limits` and the
  injected :class:`~contracts.execution.Control` deadline; the oracle budget
  is the minimum of the remaining total budget and the per-attempt cap
  (design 6.5).

Phase 2 boundary: a DELIVERY-kind source is re-validated at package level
only; each ``raw/<source-id>`` member is assessed as its own source by the
Phase 3 assembly, so the delivery source itself reports semantic/provenance
as not applicable rather than pretending a nested re-audit happened.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from ..contracts.case import ContractError, ReasonCode, StaticCheckStatus
from ..contracts.codec import case_id_of, decode_case_payload, parse_strict_json
from ..contracts.delivery import (
    AssessmentDimension,
    DimensionObservation,
    DimensionResult,
    Limits,
    NativeKind,
    SemanticStatus,
    StructuralStatus,
    SyntheticKind,
    aggregate_semantic,
    aggregate_structural,
)
from ..contracts.execution import (
    Control,
    load_attempt_expectation,
    load_attempt_request,
    load_execution_evidence,
)
from ..contracts.oracle import (
    COMPARISON_DEADLINE_MS,
    ComparisonBudget,
    decode_comparison,
)
from ..generation.bundle import (
    BundleBudgetError,
    BundleReadLimits,
    ValidationProblem,
    validate_output_dir,
)
from ..generation.validation import validate_case
from ..oracle.gates import ResultContractViolation, compare_case
from ..reduction.audit import (
    EVIDENCE_PROFILE_LEGACY,
    SEMANTIC_FULL_VERIFIED,
    SEMANTIC_MISMATCH,
    audit_trace_detailed,
)
from ..reduction.trace import (
    BEST_SOURCE_ACCEPTED,
    TRACE_FILE_NAME,
    TRACE_STATUS_CORRUPT,
    TRACE_STATUS_PARTIAL,
    TraceBudgetError,
    TraceError,
    TraceReadLimits,
    read_trace,
)
from .manifest import (
    P_DUPLICATE,
    P_HASH_MISMATCH,
    P_MANIFEST_CORRUPT,
    P_NOT_REGULAR_FILE,
    P_SOURCE_ID_MISMATCH,
    P_SYMLINK_ENTRY,
    validate_delivery_dir,
)
from .native import SourcePlan
from .provenance import assess_execution_safety, assess_provenance, iter_attempt_ids
from .reader import (
    BudgetExhaustedError,
    MissingEntryError,
    ReadLimitExceededError,
    SourceChangedError,
    SourceReader,
    UnsafePathError,
)
from .snapshot import SnapshotResult

__all__ = [
    "AttemptSemanticResult",
    "SelectionProof",
    "SourceAssessment",
    "assess_snapshot",
]

# Attempt documents that must be present for a recompute to be possible at
# all (runner/evidence.py ATTEMPT_FILE_NAMES minus the optional journals).
_ATTEMPT_REQUIRED_DOC_NAMES = (
    "request.json",
    "expectation.json",
    "execution-evidence.json",
    "comparison.json",
)


# --------------------------------------------------------------------------
# Pinned assessment models
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AttemptSemanticResult:
    """Per-attempt semantic outcome (design 6.4.3).

    ``recompute`` is RECOMPUTED only when the recorded comparison hash equals
    the hash of a comparison recomputed here from the published documents
    through the real oracle; CONFLICT keeps both hashes (the original is
    never modified); NOT_RECOMPUTED carries no recomputed hash.
    """

    source_id: str
    attempt_id: Optional[str]
    case_id: Optional[str]
    original_comparison_hash: Optional[str]
    static_check_status: Optional[str]  # "PASS"/"FAIL"/None
    recompute: SemanticStatus
    recomputed_comparison_hash: Optional[str]
    exact_signature: Optional[str]
    fingerprint: Optional[str]
    synthetic: SyntheticKind
    reason_codes: tuple[str, ...]
    limit_reasons: tuple[str, ...]


@dataclass(frozen=True)
class SelectionProof:
    """Best-case selectability proof for a trace source (design 6.4.3).

    ``chain_verified`` is true only when every ACCEPTED step of the best
    chain (parent/child linkage, complexity descent, D1 legality of the child
    payload via the semantic audit, best-source derivation) was re-verified by
    the D2 engines; D4 never re-implements the reduction itself.
    """

    best_payload_ref: Optional[str]
    best_case_id: Optional[str]
    chain_verified: bool
    chain_status: str  # "VERIFIED"|"UNVERIFIED"|"CONFLICT"|"MISSING"|"LEGACY"
    constraints: tuple[str, ...]


@dataclass(frozen=True)
class SourceAssessment:
    """Four-dimension assessment of one native source (design 6.2.2)."""

    source_id: str
    native_kind: NativeKind
    structural: DimensionResult
    semantic: DimensionResult
    provenance: DimensionResult
    execution_safety: DimensionResult
    attempts: tuple[AttemptSemanticResult, ...]
    selection: Optional[SelectionProof]
    reason_codes: tuple[str, ...]


# --------------------------------------------------------------------------
# Bounded read helpers
# --------------------------------------------------------------------------


def _read_doc(
    reader: SourceReader, relpath: str, max_bytes: int
) -> tuple[Optional[bytes], Optional[str], Optional[str]]:
    """Read one bounded document from the snapshot copy.

    Returns ``(data, reason_code, limit_code)``; ``data`` is None whenever a
    reason code is set.  Missing, oversized and unreadable are distinct,
    stable outcomes — none of them ever becomes a successful match.
    """
    try:
        return reader.read_bytes(relpath, max_bytes=max_bytes), None, None
    except MissingEntryError:
        return None, "document_missing", None
    except ReadLimitExceededError:
        return None, "document_oversize", "limit_exceeded"
    except BudgetExhaustedError:
        return None, "document_unreadable", "budget_exhausted"
    except (UnsafePathError, SourceChangedError):
        return None, "document_unreadable", None


def _parse_json(data: bytes) -> Optional[object]:
    try:
        return parse_strict_json(data)
    except ContractError:
        return None


def _ref_of(relpath: str) -> str:
    """Bounded object reference (DimensionObservation caps the length)."""
    return relpath[:256]


def _oracle_budget(control: Optional[Control]) -> Optional[ComparisonBudget]:
    """Oracle budget per design 6.5: the minimum of the remaining total wall
    clock and the per-attempt comparison cap.  None means the budget is
    already exhausted (the caller reports NOT_RECOMPUTED/budget_exhausted)."""
    if control is None:
        return ComparisonBudget()
    remaining_ms = control.remaining_ms()
    if remaining_ms <= 0:
        return None
    return ComparisonBudget(deadline_ms=min(remaining_ms, COMPARISON_DEADLINE_MS))


def _limit_reasons(limit_code: Optional[str]) -> tuple[str, ...]:
    return (limit_code,) if limit_code else ()


# --------------------------------------------------------------------------
# Attempt document helpers
# --------------------------------------------------------------------------


def _read_attempt_document(
    reader: SourceReader, relpath: str, limits: Limits
) -> tuple[Optional[object], Optional[str], Optional[str]]:
    """Strictly decode one attempt document; missing/oversize/corrupt are
    distinguished reason codes, never folded into one verdict."""
    data, reason, limit_code = _read_doc(reader, relpath, limits.max_json_document_bytes)
    if data is None:
        return None, reason, limit_code
    parsed = _parse_json(data)
    if parsed is None:
        return None, "document_invalid", None
    return parsed, None, None


def _structural_status_for_attempt_docs(
    reader: SourceReader, prefix: str, limits: Limits
) -> tuple[StructuralStatus, tuple[str, ...]]:
    """Design 6.4.2 attempt row: ordinary missing docs are PARTIAL, present
    but undecodable documents are CORRUPT."""
    status = StructuralStatus.COMPLETE
    reasons: set[str] = set()
    for name in _ATTEMPT_REQUIRED_DOC_NAMES:
        parsed, reason, _limit = _read_attempt_document(reader, prefix + name, limits)
        if parsed is None:
            if reason == "document_missing":
                status = StructuralStatus.PARTIAL
                reasons.add("missing_attempt_documents")
            elif reason == "document_oversize":
                status = StructuralStatus.PARTIAL
                reasons.add("limit_exceeded")
            else:
                status = StructuralStatus.CORRUPT
                reasons.add("attempt_document_corrupt")
    return status, tuple(sorted(reasons))


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def assess_snapshot(
    snapshot: SnapshotResult,
    reader: SourceReader,
    plan: SourcePlan,
    limits: Limits,
    control: Optional[Control] = None,
    *,
    snapshot_root: Path,
) -> SourceAssessment:
    """Assess one native source over its private snapshot copy.

    ``snapshot_root`` is the D4 output root; the snapshot copy of this source
    lives at ``<snapshot_root>/raw/<source-id>/`` (design 6.4.1).  It is an
    explicit keyword (not part of the pinned positional interface) because
    :class:`SnapshotResult` deliberately carries no output root.

    ``reader`` is the original-source reader from the Phase 1 flow.  Per
    design 6.4.1 item 5 all validators and auditors here read ONLY the
    snapshot copy, so ``reader`` is required by the pinned call signature but
    never read through; a separate bounded :class:`SourceReader` is opened on
    the copy with the caller's clock and deadline.
    """
    del reader  # pinned interface position; reads never touch the original tree
    source_id = snapshot.source_id
    snapshot_dir = Path(snapshot_root) / "raw" / source_id
    clock = control.clock if control is not None else time.monotonic
    deadline = control.deadline if control is not None else None
    with SourceReader(snapshot_dir, limits=limits, clock=clock, deadline=deadline) as snap:
        structural = _structural_dimension(snap, snapshot, plan, limits, control, snapshot_dir)
        semantic, attempts, selection = _semantic_dimension(
            snap, source_id, plan, limits, control
        )
        provenance = assess_provenance(snap, plan, limits, control, snapshot_root=snapshot_dir)
        safety = assess_execution_safety(
            snap, plan, limits, control, snapshot_root=snapshot_dir
        )

    reason_codes: set[str] = set()
    for dimension in (structural, semantic, provenance, safety):
        reason_codes.update(dimension.reason_codes)
    if selection is not None:
        reason_codes.update(selection.constraints)
    return SourceAssessment(
        source_id=source_id,
        native_kind=plan.kind,
        structural=structural,
        semantic=semantic,
        provenance=provenance,
        execution_safety=safety,
        attempts=attempts,
        selection=selection,
        reason_codes=tuple(sorted(reason_codes)),
    )


# --------------------------------------------------------------------------
# Structural dimension (design 6.4.2)
# --------------------------------------------------------------------------


def _structural_dimension(
    snap: SourceReader,
    snapshot: SnapshotResult,
    plan: SourcePlan,
    limits: Limits,
    control: Optional[Control],
    snapshot_dir: Path,
) -> DimensionResult:
    observations: list[DimensionObservation] = []
    reasons: set[str] = set()
    unchecked = 0

    # Closure vs existence: every declared file that could not be snapshotted
    # is a PARTIAL observation, never silently dropped (design 6.4.2).
    for relpath in snapshot.missing_paths:
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL,
                True,
                StructuralStatus.PARTIAL,
                object_ref=_ref_of(relpath),
            )
        )
        reasons.add("missing_snapshot_file")
    if snapshot.orphan_files:
        # Orphans are recorded, not copied (design 6.6); the closure itself
        # is still judged by the per-kind gates below.
        reasons.add("orphan_files_present")

    if plan.kind is NativeKind.GENERATION:
        _structural_generation(snapshot_dir, limits, control, observations, reasons)
    elif plan.kind is NativeKind.DELIVERY:
        _structural_delivery(snapshot_dir, limits, observations, reasons)
    elif plan.kind is NativeKind.TRACE:
        _structural_trace(snap, limits, observations, reasons)
    elif plan.kind is NativeKind.RUN:
        unchecked += _structural_run(snap, plan, limits, control, observations, reasons)
    elif plan.kind is NativeKind.ATTEMPT:
        unchecked += _structural_attempt(snap, limits, control, observations, reasons)
    else:  # NativeKind.UNKNOWN: no native format could be identified.
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL,
                True,
                StructuralStatus.UNSUPPORTED,
                object_ref=_ref_of(plan.root_document or "/"),
            )
        )
        reasons.add("unknown_native_kind")

    checked = sum(1 for obs in observations if obs.applicable)
    return DimensionResult(
        dimension=AssessmentDimension.STRUCTURAL,
        applicable=True,
        status=aggregate_structural(observations),
        reason_codes=tuple(sorted(reasons)),
        checked_objects=checked,
        unchecked_objects=unchecked,
        detail=None,
    )


def _structural_generation(
    snapshot_dir: Path,
    limits: Limits,
    control: Optional[Control],
    observations: list[DimensionObservation],
    reasons: set[str],
) -> None:
    """Generation bundle gate: full re-derivation via the D1 validator
    (design 6.4.2 generation row), bounded per design 6.5 — an over-cap
    traversal is a limit signal (PARTIAL, ``limit_exceeded``), never a
    bundle verdict."""
    bundle_limits = BundleReadLimits(
        max_files=limits.max_files,
        max_file_bytes=limits.max_json_document_bytes,
        max_total_bytes=limits.max_total_source_bytes,
    )
    try:
        report = validate_output_dir(snapshot_dir, limits=bundle_limits, control=control)
    except BundleBudgetError:
        reasons.add("limit_exceeded")
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL,
                True,
                StructuralStatus.PARTIAL,
                object_ref=_ref_of("generation-manifest.json"),
            )
        )
        return
    if not report.problems:
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL,
                True,
                StructuralStatus.COMPLETE,
                object_ref=_ref_of("generation-manifest.json"),
            )
        )
        return
    for problem in report.problems:
        assert isinstance(problem, ValidationProblem)
        if problem.severity == "corrupt":
            status = StructuralStatus.CORRUPT
            reasons.add("generation_bundle_corrupt")
        else:
            status = StructuralStatus.PARTIAL
            reasons.add("generation_bundle_incomplete")
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL,
                True,
                status,
                object_ref=_ref_of(problem.path or "generation-manifest.json"),
            )
        )


def _structural_delivery(
    snapshot_dir: Path,
    limits: Limits,
    observations: list[DimensionObservation],
    reasons: set[str],
) -> None:
    """Delivery package gate (design 6.4.2): re-validate against the sealed
    manifest; the old assessment.json is never trusted, only the raw bytes."""
    validation = validate_delivery_dir(snapshot_dir, limits)
    if not validation.problems:
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL,
                True,
                StructuralStatus.COMPLETE,
                object_ref=_ref_of("evidence-manifest.json"),
            )
        )
        return
    corrupt_codes = {
        P_MANIFEST_CORRUPT,
        P_DUPLICATE,
        P_HASH_MISMATCH,
        P_NOT_REGULAR_FILE,
        P_SYMLINK_ENTRY,
        P_SOURCE_ID_MISMATCH,
    }
    for problem in validation.problems:
        if problem.code in corrupt_codes:
            status = StructuralStatus.CORRUPT
            reasons.add("delivery_package_corrupt")
        else:
            status = StructuralStatus.PARTIAL
            reasons.add("delivery_package_incomplete")
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL,
                True,
                status,
                object_ref=_ref_of(problem.path or "evidence-manifest.json"),
            )
        )


def _structural_trace(
    snap: SourceReader,
    limits: Limits,
    observations: list[DimensionObservation],
    reasons: set[str],
) -> None:
    """Trace gates (design 6.4.2): reuse read_trace statuses, then apply the
    D4 run-level gates — an empty trace can never make a run complete."""
    if not snap.exists(TRACE_FILE_NAME):
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL,
                True,
                StructuralStatus.PARTIAL,
                object_ref=_ref_of(TRACE_FILE_NAME),
            )
        )
        reasons.add("trace_file_missing")
        return
    try:
        audit = read_trace(Path(str(snap.root)), limits=_trace_read_limits(limits))
    except TraceBudgetError:
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL,
                True,
                StructuralStatus.PARTIAL,
                object_ref=_ref_of(TRACE_FILE_NAME),
            )
        )
        reasons.add("limit_exceeded")
        return
    except TraceError:
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL,
                True,
                StructuralStatus.CORRUPT,
                object_ref=_ref_of(TRACE_FILE_NAME),
            )
        )
        reasons.add("trace_unreadable")
        return

    object_ref = _ref_of(TRACE_FILE_NAME)
    if audit.trace_status == TRACE_STATUS_CORRUPT:
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL, True, StructuralStatus.CORRUPT, object_ref
            )
        )
        reasons.add("trace_corrupt")
    elif audit.trace_status == TRACE_STATUS_PARTIAL:
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL, True, StructuralStatus.PARTIAL, object_ref
            )
        )
        reasons.add("trace_incomplete")
    elif audit.records_verified == 0:
        # Zero records but a structurally "complete" read: no SNAPSHOT/START
        # exists, so no work can be shown — always PARTIAL (design 6.4.2).
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL, True, StructuralStatus.PARTIAL, object_ref
            )
        )
        reasons.add("trace_zero_records")
    else:
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL, True, StructuralStatus.COMPLETE, object_ref
            )
        )


def _structural_run(
    snap: SourceReader,
    plan: SourcePlan,
    limits: Limits,
    control: Optional[Control],
    observations: list[DimensionObservation],
    reasons: set[str],
) -> int:
    """Run gates (design 6.4.2 run row): manifest presence, then one
    observation per attempt file group.  Without the manifest only a limited
    scan happened (the plan carries the diagnostic); requested counts are
    never inferred from directory sizes.  Returns the unchecked-attempt
    count (deadline exhausted before the attempt could be examined)."""
    if "missing_root_manifest" in plan.diagnostics:
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL,
                True,
                StructuralStatus.PARTIAL,
                object_ref=_ref_of("runner-manifest.json"),
            )
        )
        reasons.add("missing_root_manifest")

    unchecked = 0
    for attempt_id in sorted(iter_attempt_ids(plan)):
        if control is not None and control.expired():
            unchecked += 1
            continue
        prefix = f"attempts/{attempt_id}/"
        status, doc_reasons = _structural_status_for_attempt_docs(snap, prefix, limits)
        reasons.update(doc_reasons)
        observations.append(
            DimensionObservation(
                AssessmentDimension.STRUCTURAL, True, status, object_ref=_ref_of(prefix)
            )
        )
    return unchecked


def _structural_attempt(
    snap: SourceReader,
    limits: Limits,
    control: Optional[Control],
    observations: list[DimensionObservation],
    reasons: set[str],
) -> int:
    if control is not None and control.expired():
        reasons.add("budget_exhausted")
        return 1
    status, doc_reasons = _structural_status_for_attempt_docs(snap, "", limits)
    reasons.update(doc_reasons)
    observations.append(
        DimensionObservation(
            AssessmentDimension.STRUCTURAL, True, status, object_ref=_ref_of("request.json")
        )
    )
    return 0


# --------------------------------------------------------------------------
# Semantic dimension (design 6.4.3)
# --------------------------------------------------------------------------


def _semantic_dimension(
    snap: SourceReader,
    source_id: str,
    plan: SourcePlan,
    limits: Limits,
    control: Optional[Control],
) -> tuple[DimensionResult, tuple[AttemptSemanticResult, ...], Optional[SelectionProof]]:
    if plan.kind is NativeKind.GENERATION:
        return (
            DimensionResult(
                dimension=AssessmentDimension.SEMANTIC,
                applicable=False,
                status=SemanticStatus.NOT_RECOMPUTED,
                reason_codes=("generation_has_no_comparison",),
            ),
            (),
            None,
        )
    if plan.kind is NativeKind.DELIVERY:
        return (
            DimensionResult(
                dimension=AssessmentDimension.SEMANTIC,
                applicable=False,
                status=SemanticStatus.NOT_RECOMPUTED,
                reason_codes=("delivery_raw_not_reaudited",),
            ),
            (),
            None,
        )
    if plan.kind is NativeKind.TRACE:
        return _semantic_trace(snap, source_id, limits, control)
    if plan.kind in (NativeKind.RUN, NativeKind.ATTEMPT):
        return _semantic_attempts(snap, source_id, plan, limits, control)
    return (
        DimensionResult(
            dimension=AssessmentDimension.SEMANTIC,
            applicable=False,
            status=SemanticStatus.NOT_RECOMPUTED,
            reason_codes=("unknown_native_kind",),
        ),
        (),
        None,
    )


def _semantic_attempts(
    snap: SourceReader,
    source_id: str,
    plan: SourcePlan,
    limits: Limits,
    control: Optional[Control],
) -> tuple[DimensionResult, tuple[AttemptSemanticResult, ...], None]:
    if plan.kind is NativeKind.ATTEMPT:
        # Standalone attempt root: one attempt, id resolved from the request.
        attempt_ids: list[str] = [""]
    else:
        attempt_ids = sorted(iter_attempt_ids(plan))
    if not attempt_ids:
        return (
            DimensionResult(
                dimension=AssessmentDimension.SEMANTIC,
                applicable=False,
                status=SemanticStatus.NOT_RECOMPUTED,
                reason_codes=("no_attempts",),
            ),
            (),
            None,
        )

    results: list[AttemptSemanticResult] = []
    skipped: list[AttemptSemanticResult] = []
    for attempt_id in attempt_ids:
        if control is not None and control.expired():
            # Deadline exhausted: the remaining attempts stay unaudited and
            # are never counted as checked or verified (design 6.5).
            skipped.append(
                AttemptSemanticResult(
                    source_id=source_id,
                    attempt_id=attempt_id or None,
                    case_id=None,
                    original_comparison_hash=None,
                    static_check_status=None,
                    recompute=SemanticStatus.NOT_RECOMPUTED,
                    recomputed_comparison_hash=None,
                    exact_signature=None,
                    fingerprint=None,
                    synthetic=SyntheticKind.UNKNOWN,
                    reason_codes=("budget_exhausted",),
                    limit_reasons=("budget_exhausted",),
                )
            )
            continue
        prefix = f"attempts/{attempt_id}/" if attempt_id else ""
        results.append(_assess_attempt(snap, source_id, attempt_id or None, prefix, limits, control))

    observations = [
        DimensionObservation(
            AssessmentDimension.SEMANTIC,
            True,
            result.recompute,
            object_ref=_ref_of(
                f"attempts/{result.attempt_id}/" if result.attempt_id else "attempt/"
            ),
        )
        for result in results
    ]

    reasons: set[str] = set()
    for result in results + skipped:
        reasons.update(result.reason_codes)
        reasons.update(result.limit_reasons)
    if skipped:
        reasons.add("budget_exhausted")
    return (
        DimensionResult(
            dimension=AssessmentDimension.SEMANTIC,
            applicable=True,
            status=aggregate_semantic(observations),
            reason_codes=tuple(sorted(reasons)),
            checked_objects=len(observations),
            unchecked_objects=len(skipped),
            detail=None,
        ),
        tuple(results + skipped),
        None,
    )


def _assess_attempt(
    snap: SourceReader,
    source_id: str,
    attempt_id: Optional[str],
    prefix: str,
    limits: Limits,
    control: Optional[Control],
) -> AttemptSemanticResult:
    """Independent recompute for one attempt (design 6.4.3 pipeline):

    D1 static revalidation first, then strict loaders, then the real oracle
    (:func:`oracle.gates.compare_case`); the recorded comparison is compared
    by hash and never modified.  Missing/invalid/unknown-rule/budget cases
    are NOT_RECOMPUTED, never "verified" by default.
    """

    def _not_recomputed(
        reason_codes: tuple[str, ...],
        limit_reasons: tuple[str, ...] = (),
        *,
        case_id: Optional[str] = None,
        original_hash: Optional[str] = None,
        static_status: Optional[str] = None,
    ) -> AttemptSemanticResult:
        return AttemptSemanticResult(
            source_id=source_id,
            attempt_id=attempt_id,
            case_id=case_id,
            original_comparison_hash=original_hash,
            static_check_status=static_status,
            recompute=SemanticStatus.NOT_RECOMPUTED,
            recomputed_comparison_hash=None,
            exact_signature=None,
            fingerprint=None,
            synthetic=SyntheticKind.UNKNOWN,
            reason_codes=reason_codes,
            limit_reasons=limit_reasons,
        )

    request_obj, reason, limit_code = _read_attempt_document(snap, prefix + "request.json", limits)
    if request_obj is None:
        return _not_recomputed((reason or "document_unreadable",), _limit_reasons(limit_code))
    try:
        request = load_attempt_request(request_obj)
    except ContractError:
        return _not_recomputed(("document_invalid",))

    # D1 static revalidation against the CURRENT registry (design 6.4.3):
    # unknown or disabled rules are version data, never recomputed.
    try:
        static = validate_case(request.payload)
    except ContractError:
        return _not_recomputed(("static_check_invalid",), case_id=request.case_id)
    if static.status is StaticCheckStatus.VALID_STATIC:
        static_status = "PASS"
    else:
        static_status = "FAIL"
        code = "static_check_invalid"
        for condition in static.conditions:
            if condition.reason is ReasonCode.UNKNOWN_VERSION:
                code = "unknown_rule"
            elif condition.reason is ReasonCode.RULE_DISABLED and code != "unknown_rule":
                code = "rule_disabled"
        return _not_recomputed((code,), case_id=request.case_id, static_status=static_status)

    documents: dict[str, object] = {}
    for name in ("expectation.json", "execution-evidence.json", "comparison.json"):
        parsed, doc_reason, doc_limit = _read_attempt_document(snap, prefix + name, limits)
        if parsed is None:
            return _not_recomputed(
                (doc_reason or "document_unreadable",),
                _limit_reasons(doc_limit),
                case_id=request.case_id,
                static_status=static_status,
            )
        documents[name] = parsed

    try:
        expectation = load_attempt_expectation(documents["expectation.json"])
        evidence = load_execution_evidence(documents["execution-evidence.json"])
        recorded = decode_comparison(documents["comparison.json"])
    except ContractError:
        return _not_recomputed(
            ("document_invalid",), case_id=request.case_id, static_status=static_status
        )

    budget = _oracle_budget(control)
    if budget is None:
        return _not_recomputed(
            ("budget_exhausted",),
            ("budget_exhausted",),
            case_id=request.case_id,
            original_hash=recorded.hash,
            static_status=static_status,
        )
    try:
        recomputed = compare_case(request, expectation, evidence, budget, control=control)
    except ResultContractViolation as violation:
        # The oracle's INCONCLUSIVE verdict is a valid recompute result: its
        # hash is compared like any other (a reproduced inconclusive original
        # stays RECOMPUTED; a contradictory one becomes CONFLICT).
        recomputed = violation.comparison

    if recomputed.hash == recorded.hash:
        recompute_status = SemanticStatus.RECOMPUTED
        reason_codes: tuple[str, ...] = ()
    else:
        # Contradiction with the published comparison: CONFLICT, original
        # preserved verbatim (design 6.4.3 "SEMANTIC_CONFLICT").
        recompute_status = SemanticStatus.CONFLICT
        reason_codes = ("semantic_conflict",)
    return AttemptSemanticResult(
        source_id=source_id,
        attempt_id=attempt_id,
        case_id=request.case_id,
        original_comparison_hash=recorded.hash,
        static_check_status=static_status,
        recompute=recompute_status,
        recomputed_comparison_hash=recomputed.hash,
        exact_signature=recorded.exact_signature,
        fingerprint=recorded.fingerprint,
        synthetic=SyntheticKind.SYNTHETIC if request.synthetic else SyntheticKind.REAL,
        reason_codes=reason_codes,
        limit_reasons=(),
    )


# --------------------------------------------------------------------------
# Trace semantic + selection proof (design 6.4.3)
# --------------------------------------------------------------------------


def _trace_read_limits(limits: Limits) -> TraceReadLimits:
    return TraceReadLimits(
        max_records=limits.max_files,
        max_line_bytes=limits.max_jsonl_line_bytes,
        max_dependency_bytes=limits.max_json_document_bytes,
        max_dependencies=limits.max_files,
    )


def _semantic_trace(
    snap: SourceReader,
    source_id: str,
    limits: Limits,
    control: Optional[Control],
) -> tuple[DimensionResult, tuple[AttemptSemanticResult, ...], Optional[SelectionProof]]:
    trace_limits = _trace_read_limits(limits)
    try:
        structural = read_trace(Path(str(snap.root)), limits=trace_limits)
    except (TraceBudgetError, TraceError):
        structural = None

    if control is not None and control.expired():
        return (
            DimensionResult(
                dimension=AssessmentDimension.SEMANTIC,
                applicable=True,
                status=SemanticStatus.NOT_RECOMPUTED,
                reason_codes=("budget_exhausted",),
                checked_objects=0,
                unchecked_objects=1,
                detail=None,
            ),
            (),
            SelectionProof(
                best_payload_ref=None,
                best_case_id=None,
                chain_verified=False,
                chain_status="UNVERIFIED",
                constraints=("budget_exhausted",),
            ),
        )

    budget = _oracle_budget(control) or ComparisonBudget()
    detailed = audit_trace_detailed(
        Path(str(snap.root)), budget, control, limits=trace_limits
    )

    results: list[AttemptSemanticResult] = []
    observations: list[DimensionObservation] = []
    reasons: set[str] = set()

    if detailed.evidence_profile == EVIDENCE_PROFILE_LEGACY:
        # Legacy traces carry no full-evidence semantics: every attempt is
        # honestly NOT_AUDITED (design 6.4.3) and the best case is not
        # exportable as a verified chain.
        reasons.add("legacy_trace")
        return (
            DimensionResult(
                dimension=AssessmentDimension.SEMANTIC,
                applicable=False,
                status=SemanticStatus.NOT_RECOMPUTED,
                reason_codes=tuple(sorted(reasons)),
            ),
            (),
            _trace_selection(structural, detailed, (), snap, limits),
        )

    for outcome in detailed.attempt_outcomes:
        if not outcome.attempt_id:
            # Group-level outcome: the audit stopped before any attempt of
            # the group could be judged; it is never counted as verified.
            reasons.add("attempt_not_audited")
            if "budget_exhausted" in outcome.detail:
                reasons.add("budget_exhausted")
            continue
        if outcome.status == SEMANTIC_FULL_VERIFIED:
            recompute_status = SemanticStatus.RECOMPUTED
            outcome_reasons: tuple[str, ...] = ()
            outcome_limits: tuple[str, ...] = ()
        elif outcome.status == SEMANTIC_MISMATCH:
            recompute_status = SemanticStatus.CONFLICT
            outcome_reasons = ("semantic_conflict",)
            outcome_limits = ()
        else:
            recompute_status = SemanticStatus.NOT_RECOMPUTED
            outcome_reasons = ("attempt_not_audited",)
            outcome_limits = ("budget_exhausted",) if "budget_exhausted" in outcome.detail else ()
        reasons.update(outcome_reasons)
        reasons.update(outcome_limits)
        results.append(
            AttemptSemanticResult(
                source_id=source_id,
                attempt_id=outcome.attempt_id,
                case_id=None,
                original_comparison_hash=None,
                static_check_status=None,
                recompute=recompute_status,
                recomputed_comparison_hash=None,
                exact_signature=None,
                fingerprint=None,
                synthetic=SyntheticKind.UNKNOWN,
                reason_codes=outcome_reasons,
                limit_reasons=outcome_limits,
            )
        )
        observations.append(
            DimensionObservation(
                AssessmentDimension.SEMANTIC,
                True,
                recompute_status,
                object_ref=_ref_of(
                    f"trace group {outcome.group_index} attempt {outcome.attempt_id}"
                ),
            )
        )
    if detailed.limit_exhausted:
        reasons.add("budget_exhausted")

    dimension = DimensionResult(
        dimension=AssessmentDimension.SEMANTIC,
        applicable=bool(results),
        status=aggregate_semantic(observations),
        reason_codes=tuple(sorted(reasons)),
        checked_objects=len(observations),
        unchecked_objects=0,
        detail=structural.detail if structural is not None else None,
    )
    return dimension, tuple(results), _trace_selection(structural, detailed, results, snap, limits)


def _trace_selection(
    structural,  # Optional[reduction.trace.TraceAudit]
    detailed,  # reduction.audit.TraceDetailedAudit
    results: Sequence[AttemptSemanticResult],
    snap: SourceReader,
    limits: Limits,
) -> SelectionProof:
    """Derive the best-case selection proof from the D2 engines' verdicts
    (design 6.4.3): no reduction algorithm is re-implemented here."""
    best_ref = (
        structural.best_payload_ref.path
        if structural is not None and structural.best_payload_ref is not None
        else None
    )
    best_case_id = _best_case_id(snap, best_ref, limits)

    if detailed.evidence_profile == EVIDENCE_PROFILE_LEGACY:
        return SelectionProof(
            best_payload_ref=best_ref,
            best_case_id=None,
            chain_verified=False,
            chain_status="LEGACY",
            constraints=("legacy_trace_no_best_export",),
        )
    if structural is None or structural.trace_status == TRACE_STATUS_CORRUPT:
        return SelectionProof(
            best_payload_ref=best_ref,
            best_case_id=best_case_id,
            chain_verified=False,
            chain_status="CONFLICT",
            constraints=("trace_corrupt",),
        )
    if structural.trace_status == TRACE_STATUS_PARTIAL:
        return SelectionProof(
            best_payload_ref=best_ref,
            best_case_id=best_case_id,
            chain_verified=False,
            chain_status="UNVERIFIED",
            constraints=("trace_incomplete",),
        )

    statuses = [result.recompute for result in results]
    if SemanticStatus.CONFLICT in statuses:
        return SelectionProof(
            best_payload_ref=best_ref,
            best_case_id=best_case_id,
            chain_verified=False,
            chain_status="CONFLICT",
            constraints=("best_chain_not_verified",),
        )
    if detailed.limit_exhausted or SemanticStatus.NOT_RECOMPUTED in statuses:
        return SelectionProof(
            best_payload_ref=best_ref,
            best_case_id=best_case_id,
            chain_verified=False,
            chain_status="UNVERIFIED",
            constraints=("best_chain_not_verified",),
        )
    if structural.best_source == BEST_SOURCE_ACCEPTED:
        return SelectionProof(
            best_payload_ref=best_ref,
            best_case_id=best_case_id,
            chain_verified=True,
            chain_status="VERIFIED",
            constraints=(),
        )
    # Complete, fully verified, but no verified ACCEPTED chain: the best case
    # is the original candidate; nothing accepted was proven.
    return SelectionProof(
        best_payload_ref=best_ref,
        best_case_id=best_case_id,
        chain_verified=False,
        chain_status="MISSING",
        constraints=("best_is_original_no_accepted_chain",),
    )


def _best_case_id(
    snap: SourceReader, best_payload_ref: Optional[str], limits: Limits
) -> Optional[str]:
    """Best-effort case id of the best payload artifact; unreadable payloads
    stay None (never inferred)."""
    if best_payload_ref is None:
        return None
    data, _reason, _limit = _read_doc(snap, best_payload_ref, limits.max_json_document_bytes)
    if data is None:
        return None
    parsed = _parse_json(data)
    if parsed is None:
        return None
    try:
        payload = decode_case_payload(parsed)
    except ContractError:
        return None
    return case_id_of(payload)
