"""Finding occurrence collection and aggregation for D4 reporting (6.4.4).

Candidates are counted per (source, attempt): every attempt-level semantic
result that carries a native attempt identifier and a case identifier becomes
one :class:`~mtsql_typecheck.contracts.delivery.FindingOccurrence`.  Rows
without an attempt identifier never become execution occurrences (design
6.2.1: 缺失 attempt 标识时不伪造 execution occurrence) and rows without a
case identifier are skipped as well.  Duplicate (source, attempt, case) triples
are rejected: occurrences are per-execution, not per-evidence-source.

Aggregation keeps the three dedup surfaces separate -- exact signatures for
reproduction, coarse fingerprints for browsing groups, ``case_id`` for logical
input dedup -- and none of them is a root-cause identity or a bug count
(design 6.4.4).  ``reviewed_confirmed`` is derived only from
:class:`~mtsql_typecheck.contracts.delivery.FindingReview` records whose
``evidence_digest`` matches the aggregation's evidence digest and whose
occurrence ids bind occurrences in this delivery; unmatched or historical
reviews are ignored here and are surfaced by the report layer instead.  No
``confirmed_bug`` boolean is ever produced (design 6.2.1).

The :class:`~mtsql_typecheck.evidence.assessment.AttemptSemanticResult` input
is imported from the Phase 2 assessment module when available; the collection
logic itself only reads the pinned attributes, so tests may construct
structurally equivalent fakes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Sequence

from ..contracts.delivery import (
    FindingOccurrence,
    FindingReview,
    ReviewDecision,
    SemanticStatus,
    SyntheticKind,
)
from .model import FindingsSummary

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..evidence.assessment import AttemptSemanticResult
else:  # pragma: no cover - exercised only while Phase 2 assessment lands
    try:
        from ..evidence.assessment import AttemptSemanticResult
    except ImportError:  # assessment module not present yet; duck-typed inputs
        AttemptSemanticResult = Any  # type: ignore[assignment, misc]

__all__ = ["DuplicateOccurrenceError", "aggregate_findings", "collect_occurrences"]


class DuplicateOccurrenceError(ValueError):
    """Raised when two attempt rows map to one (source, attempt, case) triple.

    Occurrences are per-execution observations; the same native attempt
    yielding the same case twice is a structural inconsistency of the input,
    not something to dedupe silently (design 6.4.4).
    """


def collect_occurrences(
    attempts: Sequence["AttemptSemanticResult"],
    source_id: str,
) -> tuple[FindingOccurrence, ...]:
    """Convert attempt semantic results into delivery finding occurrences.

    Rows lacking ``attempt_id`` (generation-only or legacy rows) and rows
    lacking ``case_id`` are skipped -- they carry no execution occurrence to
    fabricate.  The original exact signature and fingerprint are passed
    through unchanged; ``recompute`` becomes the occurrence's
    ``recompute_status`` and ``recomputed_comparison_hash`` is set exactly
    when the recompute status is ``RECOMPUTED`` or ``CONFLICT`` (the
    ``FindingOccurrence`` contract enforces the same invariant).

    Raises :class:`DuplicateOccurrenceError` on a repeated
    (source_id, attempt_id, case_id) triple.
    """
    occurrences: list[FindingOccurrence] = []
    seen: set[tuple[str, str, str]] = set()
    for row in attempts:
        attempt_id = getattr(row, "attempt_id", None)
        case_id = getattr(row, "case_id", None)
        if attempt_id is None or case_id is None:
            # No native attempt identifier / no case: never fabricate an
            # execution occurrence (design 6.2.1).
            continue
        key = (source_id, attempt_id, case_id)
        if key in seen:
            raise DuplicateOccurrenceError(
                f"duplicate finding occurrence for source {source_id!r}, attempt "
                f"{attempt_id!r}, case {case_id!r}; occurrences are per-execution"
            )
        seen.add(key)
        recompute = row.recompute
        if recompute not in (SemanticStatus.RECOMPUTED, SemanticStatus.CONFLICT):
            recomputed_hash = None
        else:
            recomputed_hash = row.recomputed_comparison_hash
        occurrences.append(
            FindingOccurrence(
                source_id=source_id,
                attempt_id=attempt_id,
                case_id=case_id,
                recompute_status=recompute,
                comparison_hash=row.original_comparison_hash,
                original_exact_signature=row.exact_signature,
                fingerprint=row.fingerprint,
                recomputed_comparison_hash=recomputed_hash,
                synthetic=row.synthetic,
            )
        )
    return tuple(occurrences)


def aggregate_findings(
    occurrences: Sequence[FindingOccurrence],
    reviews: Sequence[FindingReview] = (),
    *,
    evidence_digest: str = "",
) -> FindingsSummary:
    """Aggregate occurrences into the findings-layer summary (design 6.4.4).

    REAL / SYNTHETIC / UNKNOWN candidates are counted in separate columns;
    UNKNOWN is never folded into the real column.  ``conflicts`` counts
    occurrences whose recompute status is ``CONFLICT``.  Unique case ids,
    distinct exact signatures and distinct coarse fingerprints are three
    independent surfaces; a fingerprint grouping never produces a bug count.

    ``reviewed_confirmed`` counts occurrences bound by at least one supplied
    review whose ``evidence_digest`` equals ``evidence_digest`` and whose
    decision is ``CONFIRMED_DB_BUG``.  Reviews with a different digest
    (historical evidence), unmatched occurrence ids, or other decisions are
    ignored for counting; the report layer displays them.  With an empty
    ``evidence_digest`` no review is applied.
    """
    occs = tuple(occurrences)
    real = sum(1 for o in occs if o.synthetic is SyntheticKind.REAL)
    synthetic = sum(1 for o in occs if o.synthetic is SyntheticKind.SYNTHETIC)
    unknown = sum(1 for o in occs if o.synthetic is SyntheticKind.UNKNOWN)
    conflicts = sum(1 for o in occs if o.recompute_status is SemanticStatus.CONFLICT)
    unique_case_ids = len({o.case_id for o in occs})
    distinct_signatures = len(
        {o.original_exact_signature for o in occs if o.original_exact_signature is not None}
    )
    distinct_fingerprints = len({o.fingerprint for o in occs if o.fingerprint is not None})

    confirmed_ids: set[str] = set()
    if evidence_digest:
        known_ids = {o.occurrence_id for o in occs}
        for review in reviews:
            if review.evidence_digest != evidence_digest:
                continue
            if review.decision is not ReviewDecision.CONFIRMED_DB_BUG:
                continue
            confirmed_ids.update(oid for oid in review.occurrence_ids if oid in known_ids)
    return FindingsSummary(
        real_candidates=real,
        synthetic_candidates=synthetic,
        unknown_synthetic_candidates=unknown,
        conflicts=conflicts,
        unique_case_ids=unique_case_ids,
        distinct_signatures=distinct_signatures,
        distinct_fingerprints=distinct_fingerprints,
        reviewed_confirmed=len(confirmed_ids),
    )
