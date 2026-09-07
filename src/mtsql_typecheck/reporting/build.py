"""Pure ``build_report`` constructor for the D4 report document (6.4.5).

``build_report`` is the only sanctioned way to assemble a
:class:`~mtsql_typecheck.reporting.model.ReportDocument`: it applies the
display budgets of design 6.5 (diff summaries bounded to 100 lines / 1KiB per
cell with an explicit truncation marker), the stable candidate ordering of
design 6.4.5 item 3 (risk rank, then ``occurrence_id`` — never the random
order of the run), deterministic inventory ordering, and the binding checks
that keep case details and review references tied to known occurrences and
known reviews.  The function is pure: no file I/O, no database access, no
clock; ``generated_at`` is a display-only fact supplied by the caller.

The report never emits a single aggregated PASS status and never lets the
review section modify the observed comparisons (design 6.2.2, 6.4.5).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Sequence

from ..contracts.delivery import EvidenceFile, FindingOccurrence, ProducerInfo, SyntheticKind
from ..evidence.manifest import Problem
from .model import (
    DIFF_SUMMARY_MAX_CELL_BYTES,
    DIFF_SUMMARY_MAX_LINES,
    DIFF_SUMMARY_TRUNCATION_MARKER,
    CaseDetail,
    CaseDetailInput,
    CoverageSummary,
    ExecutionCounts,
    FindingsSummary,
    GenerationCounts,
    ReportDocument,
    ReportHeader,
    ReportInventory,
    ReviewSet,
    occurrence_risk_rank,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..evidence.assessment import SourceAssessment
else:  # pragma: no cover - exercised only while Phase 2 assessment lands
    try:
        from ..evidence.assessment import SourceAssessment
    except ImportError:  # assessment module not present yet; duck-typed input
        SourceAssessment = Any  # type: ignore[assignment, misc]

__all__ = ["bound_diff_summary", "build_report"]


def bound_diff_summary(text: str | None) -> str | None:
    """Bound a diff summary to the design 6.5 display caps.

    Keeps at most :data:`DIFF_SUMMARY_MAX_LINES` lines and at most
    :data:`DIFF_SUMMARY_MAX_CELL_BYTES` bytes of content, then appends the
    explicit :data:`DIFF_SUMMARY_TRUNCATION_MARKER` whenever anything was
    dropped — an omission is never silent.  The byte cut never splits a
    multi-byte UTF-8 character.  Text already within the caps is returned
    unchanged; a pre-existing trailing marker is stripped before re-bounding
    so repeated application is idempotent.
    """
    if text is None:
        return None
    lines = text.count("\n") + 1
    if (
        lines <= DIFF_SUMMARY_MAX_LINES
        and len(text.encode("utf-8")) <= DIFF_SUMMARY_MAX_CELL_BYTES
    ):
        return text
    marker = DIFF_SUMMARY_TRUNCATION_MARKER
    if text.endswith(marker):
        text = text[: -len(marker)]
    text_lines = text.split("\n")
    too_many_lines = len(text_lines) > DIFF_SUMMARY_MAX_LINES
    kept = text_lines[:DIFF_SUMMARY_MAX_LINES]
    body = "\n".join(kept)
    data = body.encode("utf-8")
    too_many_bytes = False
    if len(data) > DIFF_SUMMARY_MAX_CELL_BYTES:
        too_many_bytes = True
    if too_many_lines or too_many_bytes:
        budget = DIFF_SUMMARY_MAX_CELL_BYTES - len(marker.encode("utf-8")) - 1
        if len(data) > budget:
            data = data[:budget]
            while data and (data[-1] & 0xC0) == 0x80:
                data = data[:-1]
            body = data.decode("utf-8", errors="ignore")
        return body + "\n" + marker
    return text


def build_report(
    *,
    assessment: "SourceAssessment",
    tool_name: str,
    writer_version: str,
    delivery_id: str,
    synthetic: SyntheticKind,
    findings: FindingsSummary,
    reviews: ReviewSet,
    occurrences: Sequence[FindingOccurrence] = (),
    case_details: Sequence[CaseDetailInput] = (),
    original_run_status: str | None = None,
    producer: ProducerInfo | None = None,
    source_commit: str | None = None,
    generated_at: str | None = None,
    known_limitations: Sequence[str] = (),
    generation_counts: GenerationCounts | None = None,
    execution_counts: ExecutionCounts | None = None,
    coverage: CoverageSummary | None = None,
    files: Sequence[EvidenceFile] = (),
    problems: Sequence[Problem] = (),
    reproduction_notes: Sequence[str] = (),
) -> ReportDocument:
    """Assemble the typed report document from typed inputs (design 6.4.5).

    Ordering and binding rules enforced here:

    - occurrences are re-ordered by (risk rank, ``occurrence_id``); every
      occurrence must belong to the assessed source;
    - every case detail must bind a known occurrence and follow the same
      risk order; every ``review_ids`` entry must reference a review that is
      present in the review section (accepted or historical);
    - the file inventory is sorted by path and audit problems by
      ``(code, path, detail)`` so report.json is byte-stable for identical
      inputs;
    - ``known_limitations`` is sorted and de-duplicated;
    - diff summaries are bounded by :func:`bound_diff_summary` (the
      renderers only display what this builder already bounded).

    ``synthetic`` is an explicit input, not inferred here: design 6.2.2
    requires an undetermined classification to stay UNKNOWN, and the caller
    (the delivery assembly) owns that decision from the source plan and the
    per-attempt kinds.  ``producer``/``source_commit`` come from the native
    snapshot plan; D4 never fills a commit from its own HEAD.
    """
    if not hasattr(assessment, "source_id") or not hasattr(assessment, "structural"):
        raise TypeError("build_report assessment must be a SourceAssessment")
    if not isinstance(synthetic, SyntheticKind):
        raise TypeError("build_report synthetic must be a SyntheticKind")
    source_id = assessment.source_id
    ordered_occurrences = tuple(
        sorted(occurrences, key=lambda item: (occurrence_risk_rank(item), item.occurrence_id))
    )
    for occurrence in ordered_occurrences:
        if occurrence.source_id != source_id:
            raise ValueError(
                f"occurrence {occurrence.occurrence_id!r} binds source "
                f"{occurrence.source_id!r}, not the assessed source {source_id!r}"
            )
    rank_of = {
        occurrence.occurrence_id: occurrence_risk_rank(occurrence)
        for occurrence in ordered_occurrences
    }
    known_review_ids = {review.review_id for review in reviews.accepted}
    known_review_ids.update(item.review.review_id for item in reviews.historical)

    bounded_details: list[CaseDetail] = []
    for row in case_details:
        if row.occurrence_id not in rank_of:
            raise ValueError(
                f"case detail binds unknown occurrence {row.occurrence_id!r}"
            )
        unknown_reviews = [rid for rid in row.review_ids if rid not in known_review_ids]
        if unknown_reviews:
            raise ValueError(
                f"case detail for occurrence {row.occurrence_id!r} references "
                f"unknown review ids {unknown_reviews!r}"
            )
        bounded_details.append(
            CaseDetail(
                occurrence_id=row.occurrence_id,
                case_id=row.case_id,
                rule_id=row.rule_id,
                rule_version=row.rule_version,
                type_pair=row.type_pair,
                select_text=row.select_text,
                diff_summary=bound_diff_summary(row.diff_summary),
                original_ref=row.original_ref,
                best_ref=row.best_ref,
                round_outcomes=row.round_outcomes,
                review_ids=row.review_ids,
            )
        )
    bounded_details.sort(key=lambda row: (rank_of[row.occurrence_id], row.occurrence_id))

    header = ReportHeader(
        tool_name=tool_name,
        writer_version=writer_version,
        native_kind=assessment.native_kind,
        synthetic=synthetic,
        structural=assessment.structural,
        semantic=assessment.semantic,
        provenance=assessment.provenance,
        execution_safety=assessment.execution_safety,
        source_id=source_id,
        delivery_id=delivery_id,
        original_run_status=original_run_status,
        producer=producer,
        source_commit=source_commit,
        generated_at=generated_at,
        known_limitations=tuple(sorted(set(known_limitations))),
    )
    inventory = ReportInventory(
        files=tuple(sorted(files, key=lambda item: item.path)),
        problems=tuple(
            sorted(problems, key=lambda item: (item.code, item.path or "", item.detail))
        ),
        reproduction_notes=tuple(reproduction_notes),
    )
    return ReportDocument(
        header=header,
        findings=findings,
        occurrences=ordered_occurrences,
        case_details=tuple(bounded_details),
        reviews=reviews,
        inventory=inventory,
        generation_counts=generation_counts,
        execution_counts=execution_counts,
        coverage=coverage,
    )

