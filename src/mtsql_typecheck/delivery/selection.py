"""Case selection from an assessed evidence snapshot (design 6.4.6, phase 4b).

Pure offline module: reads only the local snapshot copy through a bounded
:class:`~mtsql_typecheck.evidence.reader.SourceReader`; no database, network,
or clock access.  ``select_case`` resolves one :class:`CaseSelector` against a
:class:`~mtsql_typecheck.evidence.assessment.SourceAssessment` and returns a
:class:`SelectedCase` holding the decoded payload and the attempt-backed
occurrence row that justifies it.

Stable error codes (:class:`SelectionError`, subclass of ``ValueError``):

- ``UNKNOWN_CASE``          no attempt-backed row / payload matches the
                            requested case id (or occurrence id).
- ``AMBIGUOUS_SELECTION``   several attempts carry the case id and the
                            selector names no occurrence id.
- ``BEST_UNAVAILABLE``      a selection proof exists but the verified-ACCEPTED
                            chain is absent (``chain_status`` named in the
                            message) or the best payload is missing.
- ``IDENTITY_BROKEN``       snapshot copy disagrees with the assessment
                            (payload hashes to another case id, attempt doc
                            names another attempt, missing closure file).
- ``SELECTION_PROOF_MISSING`` ``select="best"`` without a selection proof.
- ``RECOMPUTE_NOT_AVAILABLE`` the only stored row carries no static-check
                            status at all (nothing to resolve legality from).
- ``UNSUPPORTED_NATIVE_KIND`` source kind is not a snapshot-able native kind.
- ``STATIC_CHECK_UNAVAILABLE`` (added, documented) the static-check document
                            backing the selected case is absent.
- ``STATIC_CHECK_FAILED``   (added, documented) the static-check document
                            exists but records the case as not statically
                            legal.
- ``CORRUPT_CASE``          (added, documented) a selected document exists in
                            the snapshot but is not strict, contract-valid
                            JSON for the pinned schema.
- ``INVALID_SELECTOR``      (added, documented) the selector itself names an
                            unsupported ``select`` mode or malformed ids.

Documented decisions (this project's interpretation of design 6.4.6):

- Only attempt-backed rows (``attempt_id is not None``) are selectable.
  Standalone ATTEMPT sources therefore never match; trace rows carry
  ``case_id=None`` in the current assessment, so best selection from trace
  sources names no attempt-backed occurrence (``SelectedCase.occurrence`` is
  ``None``) and is refused by the regression gates later.
- Generation sources have no attempt rows; selecting their cases is allowed
  for SQL-debug purposes with ``occurrence=None``.  The regression gates in
  ``delivery.export`` refuse such material.
- Payloads are read exclusively from the snapshot copy under
  ``<snapshot_root>/raw/<source_id>/``.  The ``reader`` argument is accepted
  for signature compatibility and intentionally unused (same shape as
  ``evidence.assessment.assess_snapshot``); a fresh internal reader is opened
  so selection can never be pointed at the original tree.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mtsql_typecheck.contracts.case import (
    CheckStage,
    StaticCheckStatus,
)
from mtsql_typecheck.contracts.codec import (
    canonical_json,
    decode_case_payload,
    decode_compatibility_check,
    parse_strict_json,
    sha256_hex,
)
from mtsql_typecheck.contracts.delivery import (
    Limits,
    NativeKind,
    SemanticStatus,
    compute_occurrence_id,
)
from mtsql_typecheck.contracts.execution import Control, load_attempt_request
from mtsql_typecheck.evidence.assessment import (
    AttemptSemanticResult,
    SelectionProof,
    SourceAssessment,
)
from mtsql_typecheck.evidence.native import SourcePlan
from mtsql_typecheck.evidence.reader import (
    MissingEntryError,
    SourceReader,
)

__all__ = [
    "SelectionError",
    "CaseSelector",
    "SelectedCase",
    "select_case",
]

# Stable refusal codes.
UNKNOWN_CASE = "UNKNOWN_CASE"
AMBIGUOUS_SELECTION = "AMBIGUOUS_SELECTION"
BEST_UNAVAILABLE = "BEST_UNAVAILABLE"
IDENTITY_BROKEN = "IDENTITY_BROKEN"
SELECTION_PROOF_MISSING = "SELECTION_PROOF_MISSING"
RECOMPUTE_NOT_AVAILABLE = "RECOMPUTE_NOT_AVAILABLE"
UNSUPPORTED_NATIVE_KIND = "UNSUPPORTED_NATIVE_KIND"
STATIC_CHECK_UNAVAILABLE = "STATIC_CHECK_UNAVAILABLE"
STATIC_CHECK_FAILED = "STATIC_CHECK_FAILED"
CORRUPT_CASE = "CORRUPT_CASE"
INVALID_SELECTOR = "INVALID_SELECTOR"

_SELECT_MODES = ("original", "best")
_SNAPSHOT_RAW_DIRNAME = "raw"


class SelectionError(ValueError):
    """Refusal to select a case; ``code`` is one of the stable module codes."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class CaseSelector:
    """Which case to pull out of one assessed source.

    ``select`` is ``"original"`` (the snapshot copy of the case the row was
    recorded against) or ``"best"`` (the reduction-produced best payload,
    requires a verified selection proof).  ``occurrence_id`` disambiguates
    several attempts carrying the same case id.
    """

    case_id: str
    select: str  # "original" | "best"
    occurrence_id: Optional[str] = None


@dataclass(frozen=True)
class SelectedCase:
    """One case resolved from the snapshot copy, ready for export.

    ``occurrence`` is the matching attempt-backed assessment row, or ``None``
    when the source carries no attempt rows bound to a case id (generation
    sources, trace-derived best selection).  ``case_payload`` is the raw
    payload object from the snapshot copy; ``static_check`` is the parsed
    generation static-check document when one exists.  ``payload_ref`` is the
    snapshot-relative path the payload was read from and ``basis`` echoes the
    selector mode that produced it.
    """

    source_id: str
    case_id: str
    occurrence: Optional[AttemptSemanticResult]
    case_payload: dict
    static_check: Optional[dict]
    payload_ref: str
    basis: str

    @property
    def occurrence_id(self) -> Optional[str]:
        """Occurrence id of the backed row, or ``None`` without one."""
        occurrence = self.occurrence
        if (
            occurrence is None
            or occurrence.attempt_id is None
            or occurrence.case_id is None
        ):
            return None
        return compute_occurrence_id(
            self.source_id, occurrence.attempt_id, occurrence.case_id
        )

    @property
    def recompute_eligible(self) -> bool:
        """True only for an attempt-backed row recomputed to RECOMPUTED."""
        occurrence = self.occurrence
        if occurrence is None or occurrence.attempt_id is None:
            return False
        return occurrence.recompute is SemanticStatus.RECOMPUTED


# --------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------


def _check_hex64(value: object, what: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise SelectionError(
            INVALID_SELECTOR, f"{what} must be a 64-hex sha256 id, got {value!r}"
        )
    for char in value:
        if char not in "0123456789abcdef":
            raise SelectionError(
                INVALID_SELECTOR, f"{what} must be lowercase hex, got {value!r}"
            )
    return value


def _planned_max_bytes(plan: SourcePlan, relpath: str) -> Optional[int]:
    for planned in plan.files:
        if planned.relpath == relpath:
            return planned.max_bytes
    return None


def _open_snapshot_reader(
    snapshot_root: Path, source_id: str, limits: Limits, control: Optional[Control]
) -> SourceReader:
    root = Path(snapshot_root) / _SNAPSHOT_RAW_DIRNAME / source_id
    clock = time.monotonic
    deadline = None
    if control is not None:
        clock = control.clock
        deadline = control.deadline
    return SourceReader(root, limits=limits, clock=clock, deadline=deadline)


def _read_snapshot_document(
    reader: SourceReader,
    plan: SourcePlan,
    control: Optional[Control],
    relpath: str,
) -> object:
    """Read and strict-parse one snapshot document, or raise SelectionError."""
    max_bytes = _planned_max_bytes(plan, relpath)
    if max_bytes is None:
        raise SelectionError(
            IDENTITY_BROKEN,
            f"snapshot closure does not contain {relpath!r} for this source",
        )
    if control is not None:
        control.raise_if_cancelled()
    try:
        raw = reader.read_bytes(relpath, max_bytes=max_bytes)
    except MissingEntryError as error:
        raise SelectionError(
            IDENTITY_BROKEN, f"snapshot copy is missing {relpath!r}"
        ) from error
    try:
        return parse_strict_json(raw)
    except ValueError as error:
        raise SelectionError(
            CORRUPT_CASE, f"snapshot document {relpath!r} is not strict JSON: {error}"
        ) from error


def _decode_payload(obj: object, what: str) -> dict:
    if not isinstance(obj, dict):
        raise SelectionError(CORRUPT_CASE, f"{what} must hold a JSON object")
    try:
        decode_case_payload(obj, what=what)
    except ValueError as error:
        raise SelectionError(
            CORRUPT_CASE, f"{what} does not satisfy the case contract: {error}"
        ) from error
    return obj


def _payload_hash(payload: dict) -> str:
    """case_id of a contract-valid raw payload object (canonical bytes)."""
    return sha256_hex(canonical_json(payload))


def _require_payload_case_id(obj: dict, expected_case_id: str, what: str) -> None:
    payload = obj.get("payload")
    if not isinstance(payload, dict):
        raise SelectionError(CORRUPT_CASE, f"{what} has no payload object")
    actual = _payload_hash(payload)
    if actual != expected_case_id:
        raise SelectionError(
            IDENTITY_BROKEN,
            f"{what} hashes to case id {actual}, expected {expected_case_id}",
        )


def _load_generation_static_check(
    reader: SourceReader,
    plan: SourcePlan,
    control: Optional[Control],
    case_id: str,
) -> dict:
    relpath = f"cases/{case_id}/static-check.json"
    doc = _read_snapshot_document(reader, plan, control, relpath)
    if not isinstance(doc, dict):
        raise SelectionError(
            CORRUPT_CASE, f"snapshot document {relpath!r} must hold a JSON object"
        )
    try:
        check = decode_compatibility_check(doc, what=f"snapshot document {relpath!r}")
    except ValueError as error:
        raise SelectionError(
            CORRUPT_CASE,
            f"snapshot document {relpath!r} is not a compatibility check: {error}",
        ) from error
    if check.stage is not CheckStage.STATIC:
        raise SelectionError(
            STATIC_CHECK_UNAVAILABLE,
            f"{relpath!r} is a {str(check.stage.value)} check, not a static one",
        )
    if check.status is not StaticCheckStatus.VALID_STATIC:
        raise SelectionError(
            STATIC_CHECK_FAILED,
            f"{relpath!r} records the case as {str(check.status.value)}; "
            "statically illegal cases must not be exported",
        )
    return doc


def _load_request_static_status(
    row: AttemptSemanticResult,
) -> None:
    """Refuse attempts whose stored static status is unusable."""
    if row.static_check_status is None:
        raise SelectionError(
            RECOMPUTE_NOT_AVAILABLE,
            f"attempt {row.attempt_id!r} carries no static-check status; "
            "static legality cannot be resolved",
        )
    if row.static_check_status != "PASS":
        raise SelectionError(
            STATIC_CHECK_FAILED,
            f"attempt {row.attempt_id!r} records static_check_status "
            f"{row.static_check_status!r}; statically illegal cases must not "
            "be exported",
        )


def _match_occurrence(
    assessment: SourceAssessment, selector: CaseSelector
) -> Optional[AttemptSemanticResult]:
    """Resolve the attempt-backed row for the selector.

    Returns ``None`` when no row matches and the selector names no
    occurrence id: generation sources legitimately have no attempt rows,
    and best selection from trace sources names no case-bound occurrence.
    Whether that is acceptable is decided by the caller per select mode.
    """
    rows = [
        row
        for row in assessment.attempts
        if row.attempt_id is not None and row.case_id == selector.case_id
    ]
    if selector.occurrence_id is not None:
        keyed = {
            compute_occurrence_id(assessment.source_id, row.attempt_id, row.case_id): row
            for row in rows
        }
        row = keyed.get(selector.occurrence_id)
        if row is None:
            raise SelectionError(
                UNKNOWN_CASE,
                f"no attempt-backed occurrence {selector.occurrence_id} for case "
                f"{selector.case_id} in source {assessment.source_id}",
            )
        return row
    if len(rows) > 1:
        candidates = sorted(
            compute_occurrence_id(assessment.source_id, row.attempt_id, row.case_id)
            for row in rows
        )
        raise SelectionError(
            AMBIGUOUS_SELECTION,
            f"case {selector.case_id} is backed by {len(rows)} attempts; pass "
            "occurrence_id, candidates: " + ", ".join(candidates),
        )
    return rows[0] if rows else None


def _select_generation(
    assessment: SourceAssessment,
    selector: CaseSelector,
    occurrence: Optional[AttemptSemanticResult],
    plan: SourcePlan,
    reader: SourceReader,
    control: Optional[Control],
) -> SelectedCase:
    relpath = f"cases/{selector.case_id}/case.json"
    doc = _read_snapshot_document(reader, plan, control, relpath)
    if not isinstance(doc, dict) or set(doc.keys()) != {"case_id", "payload"}:
        raise SelectionError(
            CORRUPT_CASE,
            f"snapshot document {relpath!r} must hold exactly the keys "
            "'case_id' and 'payload'",
        )
    if doc.get("case_id") != selector.case_id:
        raise SelectionError(
            IDENTITY_BROKEN,
            f"snapshot document {relpath!r} names case_id {doc.get('case_id')!r}, "
            f"expected {selector.case_id!r}",
        )
    payload = doc.get("payload")
    if not isinstance(payload, dict):
        raise SelectionError(CORRUPT_CASE, f"snapshot document {relpath!r} has no payload object")
    _decode_payload(payload, what=f"snapshot document {relpath!r}")
    _require_payload_case_id(doc, selector.case_id, what=f"snapshot document {relpath!r}")
    static_check = _load_generation_static_check(reader, plan, control, selector.case_id)
    return SelectedCase(
        source_id=assessment.source_id,
        case_id=selector.case_id,
        occurrence=occurrence,
        case_payload=payload,
        static_check=static_check,
        payload_ref=relpath,
        basis=selector.select,
    )


def _select_attempt(
    assessment: SourceAssessment,
    selector: CaseSelector,
    occurrence: AttemptSemanticResult,
    plan: SourcePlan,
    reader: SourceReader,
    control: Optional[Control],
) -> SelectedCase:
    if occurrence.attempt_id is None or occurrence.case_id is None:
        raise SelectionError(
            IDENTITY_BROKEN, "selected occurrence row is not attempt-backed"
        )
    relpath = f"attempts/{occurrence.attempt_id}/request.json"
    doc = _read_snapshot_document(reader, plan, control, relpath)
    if not isinstance(doc, dict):
        raise SelectionError(
            CORRUPT_CASE, f"snapshot document {relpath!r} must hold a JSON object"
        )
    try:
        request = load_attempt_request(doc)
    except ValueError as error:
        raise SelectionError(
            CORRUPT_CASE,
            f"snapshot document {relpath!r} is not a valid attempt request: {error}",
        ) from error
    if request.attempt_id != occurrence.attempt_id:
        raise SelectionError(
            IDENTITY_BROKEN,
            f"snapshot document {relpath!r} names attempt_id "
            f"{request.attempt_id!r}, expected {occurrence.attempt_id!r}",
        )
    payload = doc.get("payload")
    if not isinstance(payload, dict):
        raise SelectionError(CORRUPT_CASE, f"snapshot document {relpath!r} has no payload object")
    _decode_payload(payload, what=f"snapshot document {relpath!r}")
    payload_case_id = _payload_hash(payload)
    if payload_case_id != occurrence.case_id:
        raise SelectionError(
            IDENTITY_BROKEN,
            f"snapshot request payload hashes to case id {payload_case_id}, "
            f"expected {occurrence.case_id}",
        )
    _load_request_static_status(occurrence)
    return SelectedCase(
        source_id=assessment.source_id,
        case_id=occurrence.case_id,
        occurrence=occurrence,
        case_payload=payload,
        static_check=None,
        payload_ref=relpath,
        basis=selector.select,
    )


def _select_best(
    assessment: SourceAssessment,
    selector: CaseSelector,
    occurrence: Optional[AttemptSemanticResult],
    plan: SourcePlan,
    reader: SourceReader,
    control: Optional[Control],
) -> SelectedCase:
    proof: Optional[SelectionProof] = assessment.selection
    if proof is None:
        raise SelectionError(
            SELECTION_PROOF_MISSING,
            f"source {assessment.source_id} carries no selection proof; best "
            "selection requires a verified ACCEPTED reduction chain",
        )
    if not proof.chain_verified or proof.chain_status != "VERIFIED":
        raise SelectionError(
            BEST_UNAVAILABLE,
            f"selection chain is not verified: chain_verified="
            f"{proof.chain_verified!r}, chain_status={proof.chain_status!r}; "
            "best selection requires chain_status VERIFIED",
        )
    if not isinstance(proof.best_case_id, str) or not isinstance(
        proof.best_payload_ref, str
    ):
        raise SelectionError(
            BEST_UNAVAILABLE,
            "selection proof names no best_case_id/best_payload_ref",
        )
    relpath = proof.best_payload_ref
    doc = _read_snapshot_document(reader, plan, control, relpath)
    if not isinstance(doc, dict):
        raise SelectionError(CORRUPT_CASE, f"snapshot document {relpath!r} must hold a JSON object")
    if set(doc.keys()) == {"case_id", "payload"}:
        if doc.get("case_id") != proof.best_case_id:
            raise SelectionError(
                IDENTITY_BROKEN,
                f"snapshot document {relpath!r} names case_id "
                f"{doc.get('case_id')!r}, expected {proof.best_case_id!r}",
            )
        payload_obj = doc.get("payload")
        what = f"snapshot document {relpath!r}"
    else:
        payload_obj = doc
        what = f"snapshot payload {relpath!r}"
    if not isinstance(payload_obj, dict):
        raise SelectionError(CORRUPT_CASE, f"{what} has no payload object")
    _decode_payload(payload_obj, what=what)
    payload_case_id = _payload_hash(payload_obj)
    if payload_case_id != proof.best_case_id:
        raise SelectionError(
            IDENTITY_BROKEN,
            f"{what} hashes to case id {payload_case_id}, expected "
            f"{proof.best_case_id}",
        )
    # Best payloads come from the reduction chain; a generation-layout
    # sibling static check, when present, must still be legal.
    static_check: Optional[dict] = None
    head, _, tail = relpath.rpartition("/")
    sibling = f"{head}/static-check.json" if head else "static-check.json"
    if tail and _planned_max_bytes(plan, sibling) is not None:
        static_check = _load_generation_static_check(
            reader, plan, control, proof.best_case_id
        )
    return SelectedCase(
        source_id=assessment.source_id,
        case_id=proof.best_case_id,
        occurrence=occurrence,
        case_payload=payload_obj,
        static_check=static_check,
        payload_ref=relpath,
        basis=selector.select,
    )


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def select_case(
    assessment: SourceAssessment,
    selector: CaseSelector,
    *,
    plan: SourcePlan,
    reader: SourceReader,
    snapshot_root: Path,
    limits: Limits,
    control: Optional[Control] = None,
) -> SelectedCase:
    """Resolve ``selector`` against ``assessment`` using the snapshot copy.

    ``reader`` is accepted for signature parity with
    ``evidence.assessment.assess_snapshot`` but is deliberately unused: a
    dedicated reader over ``<snapshot_root>/raw/<source_id>/`` is opened
    here so selection can never touch the original tree.  Budget and
    cancellation errors from the underlying reader propagate unchanged.
    """
    del reader  # snapshot-copy-only reads; see module docstring
    if not isinstance(assessment, SourceAssessment):
        raise ValueError("assessment must be a SourceAssessment")
    if not isinstance(selector, CaseSelector):
        raise ValueError("selector must be a CaseSelector")
    if not isinstance(plan, SourcePlan):
        raise ValueError("plan must be a SourcePlan")
    if not isinstance(limits, Limits):
        raise ValueError("limits must be a Limits")
    if selector.select not in _SELECT_MODES:
        raise SelectionError(
            INVALID_SELECTOR,
            f"select must be one of {_SELECT_MODES}, got {selector.select!r}",
        )
    _check_hex64(selector.case_id, "CaseSelector.case_id")
    if selector.occurrence_id is not None:
        _check_hex64(selector.occurrence_id, "CaseSelector.occurrence_id")
    if plan.kind not in (
        NativeKind.GENERATION,
        NativeKind.RUN,
        NativeKind.TRACE,
        NativeKind.ATTEMPT,
    ):
        raise SelectionError(
            UNSUPPORTED_NATIVE_KIND,
            f"source kind {str(plan.kind.value)!r} is not a selectable native "
            "evidence kind",
        )
    if control is not None:
        control.raise_if_cancelled()

    occurrence = _match_occurrence(assessment, selector)
    with _open_snapshot_reader(
        snapshot_root, assessment.source_id, limits, control
    ) as snapshot_reader:
        if selector.select == "best":
            return _select_best(
                assessment, selector, occurrence, plan, snapshot_reader, control
            )
        if plan.kind is NativeKind.GENERATION:
            return _select_generation(
                assessment, selector, occurrence, plan, snapshot_reader, control
            )
        if occurrence is not None:
            return _select_attempt(
                assessment, selector, occurrence, plan, snapshot_reader, control
            )
        raise SelectionError(
            UNKNOWN_CASE,
            f"no attempt-backed occurrence for case {selector.case_id} in source "
            f"{assessment.source_id}",
        )
