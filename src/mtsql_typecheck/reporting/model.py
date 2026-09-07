"""Typed count, coverage and finding models for D4 reporting (design 6.4.4).

Three statistic layers, each only asserting numbers its source actually
provides:

- generation (:class:`GenerationCounts`): ordinal receipts re-checked for
  conservation;
- execution (:class:`ExecutionCounts` with :class:`AttemptSummary` inputs):
  dispatch/completion splits, preflight failures kept separate, undispatched
  cases never presented as attempts;
- coverage (:class:`CoverageEntry`/:class:`CoverageSummary` over
  :class:`CaseCoverageRow` inputs): unique comparable cases per rule
  definition / type pair / template / index variant, with the Profile +
  registry static legal combinations as denominator.

Identity transforms and empty-result cases are counted separately and never
act as non-trivial coverage.  Findings (:class:`FindingsSummary`) split
REAL / SYNTHETIC / UNKNOWN candidates and keep exact signatures, coarse
fingerprints and logical ``case_id`` dedup as three separate surfaces; none of
them is a root-cause identity (design 6.4.4).

All models are frozen dataclasses over plain data.  No percentage field may
exist anywhere in this module by design.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..contracts.case import (
    ContractError,
    _check_enum,
    _check_hex64,
    _check_int,
    _check_str,
)
from ..contracts.codec import (
    _as_bool,
    _as_enum,
    _as_int,
    _as_list,
    _as_str,
    _expect_dict,
    _field,
    _no_extra,
)
from ..contracts.delivery import (
    DELIVERY_SCHEMA_VERSION,
    AssessmentDimension,
    DimensionResult,
    EvidenceFile,
    FindingOccurrence,
    FindingReview,
    NativeKind,
    ProducerInfo,
    SemanticStatus,
    SyntheticKind,
    check_package_path,
    decode_dimension_result,
    decode_evidence_file,
    decode_finding_occurrence,
    decode_finding_review,
    decode_producer_info,
)
from ..evidence.manifest import Problem

__all__ = [
    "RECEIPT_RECHECK_CONSERVED",
    "RECEIPT_RECHECK_MISMATCH",
    "RECEIPT_RECHECK_NOT_CHECKED",
    "ATTEMPT_STATUSES",
    "AttemptSummary",
    "CaseCoverageRow",
    "CoverageEntry",
    "CoverageSummary",
    "ExecutionCounts",
    "FindingsSummary",
    "GenerationCounts",
]

# --------------------------------------------------------------------------
# Receipt re-check vocabulary (design 6.4.4: counts are re-checked against the
# manifest's own ordinal receipts).
# --------------------------------------------------------------------------

RECEIPT_RECHECK_CONSERVED = "CONSERVED"
RECEIPT_RECHECK_MISMATCH = "MISMATCH"
RECEIPT_RECHECK_NOT_CHECKED = "NOT_CHECKED"
RECEIPT_RECHECK_VALUES = (
    RECEIPT_RECHECK_CONSERVED,
    RECEIPT_RECHECK_MISMATCH,
    RECEIPT_RECHECK_NOT_CHECKED,
)


# --------------------------------------------------------------------------
# Generation layer
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class GenerationCounts:
    """Generation-layer counters re-checked against ordinal receipts (6.4.4).

    The numeric fields mirror the ``GenerationManifest`` statistics; ``None``
    is reserved for a source that cannot provide the number (the D1 manifest
    always can, so they are ``int`` in practice but typed ``int | None`` so
    callers cannot silently treat a missing number as zero).

    ``receipt_recheck`` is ``CONSERVED`` when the manifest's own receipts
    independently reproduce the counters, ``MISMATCH`` when they disagree (the
    numbers keep the manifest's values and ``receipt_mismatch_reason`` carries
    the disagreement), and ``NOT_CHECKED`` when the manifest carries no
    receipts to re-check against.

    ``denominator_known`` is only true when the requested set is final and the
    receipts did not contradict it: a ``RUNNING`` manifest may still grow and
    a mismatching receipt set means the counters cannot be trusted as a
    denominator.  No percentage may be computed from ``False``.
    """

    requested_ordinals: int | None
    attempted_candidates: int | None
    emitted_occurrences: int | None
    unique_cases: int | None
    rejected_ordinals: int | None
    interrupted_ordinals: int | None
    not_attempted: int | None
    receipt_recheck: str
    receipt_mismatch_reason: str | None = None
    denominator_known: bool = False

    def __post_init__(self) -> None:
        for name in (
            "requested_ordinals",
            "attempted_candidates",
            "emitted_occurrences",
            "unique_cases",
            "rejected_ordinals",
            "interrupted_ordinals",
            "not_attempted",
        ):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                raise TypeError(f"GenerationCounts.{name} must be int or None")
            if isinstance(value, int) and not isinstance(value, bool) and value < 0:
                raise ValueError(f"GenerationCounts.{name} must be >= 0")
        if self.receipt_recheck not in RECEIPT_RECHECK_VALUES:
            raise ValueError(
                f"GenerationCounts.receipt_recheck must be one of "
                f"{RECEIPT_RECHECK_VALUES}, got {self.receipt_recheck!r}"
            )
        if self.receipt_recheck == RECEIPT_RECHECK_MISMATCH and (
            self.receipt_mismatch_reason is None
        ):
            raise ValueError(
                "GenerationCounts with a MISMATCH receipt re-check must carry "
                "receipt_mismatch_reason"
            )
        if not isinstance(self.denominator_known, bool):
            raise TypeError("GenerationCounts.denominator_known must be bool")


# --------------------------------------------------------------------------
# Execution layer
# --------------------------------------------------------------------------

ATTEMPT_STATUSES = (
    "MATCH_CANDIDATE",
    "NOT_APPLICABLE",
    "UNDECIDABLE",
    "PREFLIGHT_FAILURE",
    "COMPLETED",
)


@dataclass(frozen=True)
class AttemptSummary:
    """Caller-supplied per-attempt execution outcome (design 6.4.4).

    A restricted typed view over one native attempt document; D4 reporting
    never parses attempt files itself.  ``status`` comes from
    :data:`ATTEMPT_STATUSES`; ``both_selects`` is ``None`` when the attempt
    documents do not record whether both sides completed.
    """

    attempt_id: str
    both_selects: bool | None
    status: str

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, str) or not self.attempt_id:
            raise ValueError("AttemptSummary.attempt_id must be a non-empty string")
        if self.both_selects is not None and not isinstance(self.both_selects, bool):
            raise TypeError("AttemptSummary.both_selects must be bool or None")
        if self.status not in ATTEMPT_STATUSES:
            raise ValueError(
                f"AttemptSummary.status must be one of {ATTEMPT_STATUSES}, "
                f"got {self.status!r}"
            )


@dataclass(frozen=True)
class ExecutionCounts:
    """Execution-layer counters (design 6.4.4 execution row).

    ``requested_attempts`` counts dispatches only; undispatched cases are
    never presented as attempts and are reported through ``undispatched``.
    ``preflight_failures`` are kept as their own counter, never folded into
    completed or undecidable work.  ``None`` means the source cannot provide
    the number; it is never fabricated as zero.

    ``match_candidates`` counts attempts whose comparison produced a match
    candidate (``RunnerManifest.candidate``); expected matches
    (``RunnerManifest.match``) are completed comparable work but are not
    candidates and do not enter the findings layer.
    """

    requested_attempts: int | None
    completed_both_selects: int | None
    match_candidates: int | None
    not_applicable: int | None
    undecidable: int | None
    preflight_failures: int | None
    undispatched: int | None

    def __post_init__(self) -> None:
        for name in (
            "requested_attempts",
            "completed_both_selects",
            "match_candidates",
            "not_applicable",
            "undecidable",
            "preflight_failures",
            "undispatched",
        ):
            value = getattr(self, name)
            if value is None:
                continue
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"ExecutionCounts.{name} must be int or None")
            if value < 0:
                raise ValueError(f"ExecutionCounts.{name} must be >= 0")


# --------------------------------------------------------------------------
# Coverage layer
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseCoverageRow:
    """Caller-supplied per-case coverage observation (design 6.4.4).

    One row per (case, rule, type pair, template, index variant) observation;
    the same ``case_id`` may appear in several rows (e.g. one per attempt).
    Coverage counts unique cases, while the number of rows remains the work
    count -- that split is the core design point of 6.4.4.

    ``type_pair`` must be the canonical ASCII encoding produced by
    :func:`mtsql_typecheck.rules.registry.canonical_type_pair` for the case's
    ``(A, B)`` type pair so rows and registry combinations compare exactly.
    ``build_key`` identifies the environment/build/profile a case was
    generated for; rows with different build keys never merge into one
    coverage denominator (design: 不同环境/build/profile 不合并覆盖分母).
    """

    case_id: str
    rule_id: str
    rule_version: int
    type_pair: str
    template: str
    index_variant: str
    comparable: bool
    identity_only: bool
    empty_result: bool
    build_key: str

    def __post_init__(self) -> None:
        for name in ("case_id", "rule_id", "type_pair", "template", "index_variant", "build_key"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"CaseCoverageRow.{name} must be a non-empty string")
        if not isinstance(self.rule_version, int) or isinstance(self.rule_version, bool):
            raise TypeError("CaseCoverageRow.rule_version must be int")
        if self.rule_version < 1:
            raise ValueError("CaseCoverageRow.rule_version must be >= 1")
        for name in ("comparable", "identity_only", "empty_result"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"CaseCoverageRow.{name} must be bool")


@dataclass(frozen=True)
class CoverageEntry:
    """One observed (rule, type pair, template, index variant) coverage slot.

    ``comparable_unique_cases`` counts distinct ``case_id`` values classified
    comparable in this slot; identity-only and empty-result cases never
    contribute (design 6.4.4).  ``denominator`` is the number of static legal
    combinations for the rule under the profile's templates and index
    variants, or ``None`` when the denominator is unknown (no profile, no
    matching legal combination, or build keys that must not be merged).

    ``build_key`` is ``None`` when all case rows share one build key (the
    single-group case); it is set per entry when rows span several build keys,
    in which case denominators stay ``None`` because per-build profiles are
    not available to the pure computation and cross-build merging is
    forbidden.
    """

    rule_id: str
    rule_version: int
    type_pair: str
    template: str
    index_variant: str
    comparable_unique_cases: int
    denominator: int | None
    build_key: str | None = None

    def __post_init__(self) -> None:
        for name in ("rule_id", "type_pair", "template", "index_variant"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"CoverageEntry.{name} must be a non-empty string")
        if not isinstance(self.rule_version, int) or isinstance(self.rule_version, bool):
            raise TypeError("CoverageEntry.rule_version must be int")
        if not isinstance(self.comparable_unique_cases, int) or isinstance(
            self.comparable_unique_cases, bool
        ):
            raise TypeError("CoverageEntry.comparable_unique_cases must be int")
        if self.comparable_unique_cases < 0:
            raise ValueError("CoverageEntry.comparable_unique_cases must be >= 0")
        if self.denominator is not None:
            if not isinstance(self.denominator, int) or isinstance(self.denominator, bool):
                raise TypeError("CoverageEntry.denominator must be int or None")
            if self.denominator < 1:
                raise ValueError("CoverageEntry.denominator must be >= 1 when known")
        if self.build_key is not None and (not isinstance(self.build_key, str) or not self.build_key):
            raise ValueError("CoverageEntry.build_key must be a non-empty string or None")


@dataclass(frozen=True)
class CoverageSummary:
    """Coverage-layer result (design 6.4.4).

    ``denominator_known=False`` always comes with a non-empty
    ``unknown_reason`` (no profile, unrestorable requested set, or multiple
    build keys) and every entry denominator is ``None``; no percentage may be
    computed in that state.  ``identity_only_cases`` and
    ``empty_result_cases`` count unique cases held out as controls; they are
    separate counters and never part of non-trivial coverage.
    """

    entries: tuple[CoverageEntry, ...]
    denominator_known: bool
    unknown_reason: str | None
    identity_only_cases: int
    empty_result_cases: int

    def __post_init__(self) -> None:
        if not isinstance(self.entries, tuple) or any(
            not isinstance(entry, CoverageEntry) for entry in self.entries
        ):
            raise TypeError("CoverageSummary.entries must be a tuple of CoverageEntry")
        if not isinstance(self.denominator_known, bool):
            raise TypeError("CoverageSummary.denominator_known must be bool")
        if self.denominator_known:
            if self.unknown_reason is not None:
                raise ValueError(
                    "CoverageSummary with a known denominator must not carry an "
                    "unknown_reason"
                )
            if any(entry.denominator is None for entry in self.entries):
                raise ValueError(
                    "CoverageSummary with a known denominator must not carry "
                    "entries without one"
                )
        else:
            if not self.unknown_reason:
                raise ValueError(
                    "CoverageSummary with an unknown denominator must carry an "
                    "unknown_reason"
                )
        for name in ("identity_only_cases", "empty_result_cases"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"CoverageSummary.{name} must be int")
            if value < 0:
                raise ValueError(f"CoverageSummary.{name} must be >= 0")


# --------------------------------------------------------------------------
# Findings layer
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingsSummary:
    """Finding-layer aggregation over occurrences (design 6.4.4).

    Candidates are counted per (source, attempt); REAL / SYNTHETIC / UNKNOWN
    stay in separate columns and UNKNOWN is never folded into the real
    column.  ``unique_case_ids``, ``distinct_signatures`` and
    ``distinct_fingerprints`` are three separate dedup surfaces -- exact
    signatures serve reproduction, coarse fingerprints serve browsing groups,
    ``case_id`` dedups logical inputs -- and none of them is a bug count; a
    fingerprint group is never aggregated into a "number of bugs".

    ``reviewed_confirmed`` counts only occurrences bound by a supplied
    :class:`~mtsql_typecheck.contracts.delivery.FindingReview` whose
    ``evidence_digest`` matches the aggregation's evidence digest and whose
    decision is ``CONFIRMED_DB_BUG``; it is never auto-derived.  No
    ``confirmed_bug`` boolean exists anywhere (design 6.2.1).
    """

    real_candidates: int
    synthetic_candidates: int
    unknown_synthetic_candidates: int
    conflicts: int
    unique_case_ids: int
    distinct_signatures: int
    distinct_fingerprints: int
    reviewed_confirmed: int

    def __post_init__(self) -> None:
        for name in (
            "real_candidates",
            "synthetic_candidates",
            "unknown_synthetic_candidates",
            "conflicts",
            "unique_case_ids",
            "distinct_signatures",
            "distinct_fingerprints",
            "reviewed_confirmed",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"FindingsSummary.{name} must be int")
            if value < 0:
                raise ValueError(f"FindingsSummary.{name} must be >= 0")


# ==========================================================================
# Report document (design 6.4.5 first screen, 6.5 budgets, Phase 3)
#
# ``ReportDocument`` is the single display-fact source shared by report.json
# and both renderers (report.md / report.html).  It groups exactly the facts
# of design 6.4.5's ordered first screen:
#
#   1. source/tool/contract version, real or synthetic, original run status,
#      the four dimension audit statuses and their limits;
#   2. generation/execution/unique-coverage counts with denominators and
#      missing reasons;
#   3. candidates, execution anomalies, UNKNOWN terminations/leftovers,
#      ordered by risk and stable id (never run-random order);
#   4. per-case rule/type/SELECT, exact bounded diff summary, original/best
#      references, per-round outcomes and human review bindings;
#   5. full file inventory, audit problems and reproduction notes.
#
# There is deliberately no aggregate PASS/FAIL field anywhere: the four
# dimension results stay authoritative and the renderers derive their
# headline from them (design 6.2.2: 聚合不生成一个总 PASS).
# ==========================================================================

__all__.extend(
    [
        "DIFF_SUMMARY_MAX_LINES",
        "DIFF_SUMMARY_MAX_CELL_BYTES",
        "DIFF_SUMMARY_TRUNCATION_MARKER",
        "REPORT_SCHEMA_VERSION",
        "DEFAULT_MAX_RENDER_BYTES",
        "CaseDetail",
        "CaseDetailInput",
        "HistoricalReview",
        "LimitExceeded",
        "ReportDocument",
        "ReportHeader",
        "ReportInventory",
        "ReviewConflict",
        "ReviewSet",
        "UnsafeLinkError",
        "check_linkable_ref",
        "decode_report_document",
        "occurrence_risk_rank",
    ]
)

REPORT_SCHEMA_VERSION = DELIVERY_SCHEMA_VERSION

# Design 6.5: 差异展示最多 100 行 / 每单元 1KiB，省略部分明确标展示截断。
DIFF_SUMMARY_MAX_LINES = 100
DIFF_SUMMARY_MAX_CELL_BYTES = 1024
DIFF_SUMMARY_TRUNCATION_MARKER = "……（展示截断：超过 100 行 / 1KiB 显示上限）"

# Design 6.5: HTML/MD 各 8MiB 默认上限。
DEFAULT_MAX_RENDER_BYTES = 8 * 1024 * 1024

_VERSION_TEXT_RE = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
_DELIVERY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_ID_RE = re.compile(r"^s-[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
# Linkable object reference: package-relative plus no colon anywhere (a
# colon can turn the reference into a URL scheme such as javascript:), no
# whitespace or quote characters.
_LINKABLE_REF_RE = re.compile(r"^[A-Za-z0-9._/@~+-]{1,256}$")


class LimitExceeded(ValueError):
    """A rendered report exceeded its byte budget (design 6.5: MD/HTML 各 8MiB)."""


class UnsafeLinkError(ValueError):
    """A renderer refused to build a link from a non-package-relative path.

    Design 6.4.5: 链接由受控路径生成并 URL 编码，不接受 javascript/data/file
    URL。  The renderers only ever emit ``href`` values produced by the
    shared link builder, which re-validates every target.
    """


def _fail(msg: str) -> None:
    raise ContractError(msg)


def check_linkable_ref(value: object, name: str) -> str:
    """Validate a package-relative reference that renderers may link.

    Stricter than :func:`~mtsql_typecheck.contracts.delivery.check_package_path`
    on purpose: colons are rejected outright so no reference can ever look
    like a URL scheme (``javascript:``, ``data:``, ``file:``), and whitespace
    or quote characters are rejected so the value cannot break out of an
    attribute or a Markdown link target.
    """
    check_package_path(value, name)
    value = _check_str(value, name)
    if not _LINKABLE_REF_RE.match(value):
        _fail(f"{name} is not a linkable package reference: {value!r}")
    return value


def occurrence_risk_rank(occurrence: FindingOccurrence) -> int:
    """Risk class used for stable candidate ordering (design 6.4.5 item 3).

    ``0`` for a semantic CONFLICT (an observed self-contradiction of the
    evidence) — this is also where a per-occurrence UNSAFE verdict would
    rank, but the occurrence contract has no per-occurrence safety field, so
    a source-level UNSAFE/UNKNOWN execution-safety status is surfaced through
    the dimension table and the renderers' headline instead of being
    fabricated onto individual occurrences.  ``1`` for an occurrence whose
    synthetic kind is UNKNOWN (never counted as a real finding).  ``2`` for
    everything else.  Ties break by ``occurrence_id``, never by run order.
    """
    if occurrence.recompute_status is SemanticStatus.CONFLICT:
        return 0
    if occurrence.synthetic is SyntheticKind.UNKNOWN:
        return 1
    return 2


# --------------------------------------------------------------------------
# Review section types (guarded import of the pinned reporting/review.py API)
# --------------------------------------------------------------------------

try:  # pragma: no cover - sibling Phase 3 module; exercised when it lands
    from .review import HistoricalReview, ReviewConflict, ReviewSet
except ImportError:  # pragma: no cover - structural fallback, pinned interface

    @dataclass(frozen=True)
    class HistoricalReview:
        """Fallback shape of ``reporting.review.HistoricalReview`` (pin).

        Used only while the sibling review module is absent; a review bound
        to a different evidence digest is displayed as history, never
        applied (design 6.4.5).
        """

        review: FindingReview
        detail: str

    @dataclass(frozen=True)
    class ReviewConflict:
        """Fallback shape of ``reporting.review.ReviewConflict`` (pin)."""

        occurrence_ids: tuple[str, ...]
        review_ids: tuple[str, ...]
        detail: str

    @dataclass(frozen=True)
    class ReviewSet:
        """Fallback shape of ``reporting.review.ReviewSet`` (pin)."""

        accepted: tuple[FindingReview, ...]
        duplicates_ignored: tuple[str, ...]
        historical: tuple[HistoricalReview, ...]
        conflicts: tuple[ReviewConflict, ...]
        has_conflict: bool


# --------------------------------------------------------------------------
# Per-case display rows
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseDetail:
    """Bounded per-case display row (design 6.4.5 item 4).

    ``diff_summary`` is already display-bounded (max 100 lines / 1KiB per
    cell, explicit truncation marker) — the bound is enforced by the report
    builder, not by the renderers.  ``original_ref``/``best_ref`` are
    linkable package references validated by :func:`check_linkable_ref`.
    """

    occurrence_id: str
    case_id: str
    rule_id: str
    rule_version: int
    type_pair: str
    select_text: Optional[str] = None
    diff_summary: Optional[str] = None
    original_ref: Optional[str] = None
    best_ref: Optional[str] = None
    round_outcomes: tuple[str, ...] = ()
    review_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _check_hex64(self.occurrence_id, "CaseDetail.occurrence_id")
        _check_hex64(self.case_id, "CaseDetail.case_id")
        rule_id = _check_str(self.rule_id, "CaseDetail.rule_id")
        if not rule_id or len(rule_id) > 128:
            _fail("CaseDetail.rule_id must be 1..128 chars")
        if not isinstance(self.rule_version, int) or isinstance(self.rule_version, bool):
            _fail("CaseDetail.rule_version must be int")
        if self.rule_version < 1:
            _fail("CaseDetail.rule_version must be >= 1")
        type_pair = _check_str(self.type_pair, "CaseDetail.type_pair")
        if not type_pair or len(type_pair) > 256:
            _fail("CaseDetail.type_pair must be 1..256 chars")
        if self.select_text is not None:
            _check_str(self.select_text, "CaseDetail.select_text")
        self._check_diff_summary()
        for name in ("original_ref", "best_ref"):
            value = getattr(self, name)
            if value is not None:
                check_linkable_ref(value, f"CaseDetail.{name}")
        for name in ("round_outcomes", "review_ids"):
            previous: Optional[str] = None
            for item in getattr(self, name):
                value = _check_str(item, f"CaseDetail.{name} item")
                if not value or len(value) > 128:
                    _fail(f"CaseDetail.{name} items must be 1..128 chars")
                if previous is not None and value <= previous:
                    _fail(f"CaseDetail.{name} must be sorted and unique")
                previous = value

    def _check_diff_summary(self) -> None:
        value = self.diff_summary
        if value is None:
            return
        _check_str(value, "CaseDetail.diff_summary")
        lines = value.count("\n") + 1
        size = len(value.encode("utf-8"))
        if DIFF_SUMMARY_TRUNCATION_MARKER in value:
            marker_bytes = len(DIFF_SUMMARY_TRUNCATION_MARKER.encode("utf-8"))
            if lines > DIFF_SUMMARY_MAX_LINES + 1:
                _fail("CaseDetail.diff_summary exceeds the 100-line display cap")
            if size > DIFF_SUMMARY_MAX_CELL_BYTES + marker_bytes + 1:
                _fail("CaseDetail.diff_summary exceeds the 1KiB display cap")
        else:
            if lines > DIFF_SUMMARY_MAX_LINES:
                _fail("CaseDetail.diff_summary exceeds the 100-line display cap")
            if size > DIFF_SUMMARY_MAX_CELL_BYTES:
                _fail("CaseDetail.diff_summary exceeds the 1KiB display cap")

    def to_obj(self) -> dict[str, object]:
        return {
            "occurrence_id": self.occurrence_id,
            "case_id": self.case_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "type_pair": self.type_pair,
            "select_text": self.select_text,
            "diff_summary": self.diff_summary,
            "original_ref": self.original_ref,
            "best_ref": self.best_ref,
            "round_outcomes": list(self.round_outcomes),
            "review_ids": list(self.review_ids),
        }


@dataclass(frozen=True)
class CaseDetailInput:
    """Unbounded caller-supplied case detail; :func:`build_report` bounds it.

    Identical to :class:`CaseDetail` except ``diff_summary`` may exceed the
    display caps; the builder trims it to 100 lines / 1KiB and appends the
    explicit truncation marker (design 6.5).  Reference fields are validated
    immediately so non-linkable values never enter a report.
    """

    occurrence_id: str
    case_id: str
    rule_id: str
    rule_version: int
    type_pair: str
    select_text: Optional[str] = None
    diff_summary: Optional[str] = None
    original_ref: Optional[str] = None
    best_ref: Optional[str] = None
    round_outcomes: tuple[str, ...] = ()
    review_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _check_hex64(self.occurrence_id, "CaseDetailInput.occurrence_id")
        _check_hex64(self.case_id, "CaseDetailInput.case_id")
        if not isinstance(self.rule_id, str) or not self.rule_id:
            _fail("CaseDetailInput.rule_id must be a non-empty string")
        if not isinstance(self.rule_version, int) or isinstance(self.rule_version, bool):
            _fail("CaseDetailInput.rule_version must be int")
        if not isinstance(self.type_pair, str) or not self.type_pair:
            _fail("CaseDetailInput.type_pair must be a non-empty string")
        if self.diff_summary is not None and not isinstance(self.diff_summary, str):
            _fail("CaseDetailInput.diff_summary must be str or None")
        for name in ("original_ref", "best_ref"):
            value = getattr(self, name)
            if value is not None:
                check_linkable_ref(value, f"CaseDetailInput.{name}")
        for name in ("select_text",):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                _fail(f"CaseDetailInput.{name} must be str or None")


# --------------------------------------------------------------------------
# Header and inventory
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ReportHeader:
    """First-screen identity and dimension facts (design 6.4.5 item 1).

    ``generated_at`` is a display-only timestamp and never part of any
    identity (the delivery/occurrence ids hash content only).  The four
    dimension results are kept verbatim; nothing here aggregates them into a
    total PASS (design 6.2.2).
    """

    tool_name: str
    writer_version: str
    native_kind: NativeKind
    synthetic: SyntheticKind
    structural: DimensionResult
    semantic: DimensionResult
    provenance: DimensionResult
    execution_safety: DimensionResult
    source_id: str
    delivery_id: str
    original_run_status: Optional[str] = None
    producer: Optional[ProducerInfo] = None
    source_commit: Optional[str] = None
    generated_at: Optional[str] = None
    known_limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        tool_name = _check_str(self.tool_name, "ReportHeader.tool_name")
        if not tool_name or len(tool_name) > 128:
            _fail("ReportHeader.tool_name must be 1..128 chars")
        version = _check_str(self.writer_version, "ReportHeader.writer_version")
        if not _VERSION_TEXT_RE.match(version):
            _fail(f"ReportHeader.writer_version has unsupported form: {version!r}")
        _check_enum(self.native_kind, NativeKind, "ReportHeader.native_kind")
        _check_enum(self.synthetic, SyntheticKind, "ReportHeader.synthetic")
        for name, dimension in (
            ("structural", AssessmentDimension.STRUCTURAL),
            ("semantic", AssessmentDimension.SEMANTIC),
            ("provenance", AssessmentDimension.PROVENANCE),
            ("execution_safety", AssessmentDimension.EXECUTION_SAFETY),
        ):
            result = getattr(self, name)
            if not isinstance(result, DimensionResult):
                _fail(f"ReportHeader.{name} must be a DimensionResult")
            if result.dimension is not dimension:
                _fail(f"ReportHeader.{name} must carry the {dimension.value} dimension")
        if self.original_run_status is not None:
            value = _check_str(self.original_run_status, "ReportHeader.original_run_status")
            if not value or len(value) > 128:
                _fail("ReportHeader.original_run_status must be 1..128 chars or None")
        if self.producer is not None and not isinstance(self.producer, ProducerInfo):
            _fail("ReportHeader.producer must be a ProducerInfo or None")
        if self.source_commit is not None:
            commit = _check_str(self.source_commit, "ReportHeader.source_commit")
            if not _COMMIT_RE.match(commit):
                _fail(f"ReportHeader.source_commit must be 40-hex, got {commit!r}")
        source_id = _check_str(self.source_id, "ReportHeader.source_id")
        if not _SOURCE_ID_RE.match(source_id):
            _fail(f"ReportHeader.source_id must be 's-' plus 64-hex, got {source_id!r}")
        delivery_id = _check_str(self.delivery_id, "ReportHeader.delivery_id")
        if not _DELIVERY_ID_RE.match(delivery_id):
            _fail(f"ReportHeader.delivery_id must be 64-hex, got {delivery_id!r}")
        if self.generated_at is not None:
            value = _check_str(self.generated_at, "ReportHeader.generated_at")
            if not value or len(value) > 64:
                _fail("ReportHeader.generated_at must be 1..64 chars or None")
        if not isinstance(self.known_limitations, tuple):
            _fail("ReportHeader.known_limitations must be a tuple")
        previous: Optional[str] = None
        for item in self.known_limitations:
            value = _check_str(item, "ReportHeader.known_limitations item")
            if not value or len(value) > 128:
                _fail("ReportHeader.known_limitations items must be 1..128 chars")
            if previous is not None and value <= previous:
                _fail("ReportHeader.known_limitations must be sorted and unique")
            previous = value

    def to_obj(self) -> dict[str, object]:
        return {
            "tool_name": self.tool_name,
            "writer_version": self.writer_version,
            "native_kind": str(self.native_kind.value),
            "synthetic": str(self.synthetic.value),
            "original_run_status": self.original_run_status,
            "structural": self.structural.to_obj(),
            "semantic": self.semantic.to_obj(),
            "provenance": self.provenance.to_obj(),
            "execution_safety": self.execution_safety.to_obj(),
            "producer": self.producer.to_obj() if self.producer is not None else None,
            "source_commit": self.source_commit,
            "source_id": self.source_id,
            "delivery_id": self.delivery_id,
            "generated_at": self.generated_at,
            "known_limitations": list(self.known_limitations),
        }


@dataclass(frozen=True)
class ReportInventory:
    """Package inventory, audit problems and reproduction notes (6.4.5 item 5).

    ``reproduction_notes`` are short human steps without any host, port,
    credential or connection data (design 6.2.3: 完整报告只链接本包文件，
    不留下可连接目标)。
    """

    files: tuple[EvidenceFile, ...] = ()
    problems: tuple[Problem, ...] = ()
    reproduction_notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.files, tuple) or any(
            not isinstance(item, EvidenceFile) for item in self.files
        ):
            _fail("ReportInventory.files must be a tuple of EvidenceFile")
        previous: Optional[str] = None
        for item in self.files:
            if previous is not None and item.path <= previous:
                _fail("ReportInventory.files must be sorted by unique path")
            previous = item.path
        if not isinstance(self.problems, tuple) or any(
            not isinstance(item, Problem) for item in self.problems
        ):
            _fail("ReportInventory.problems must be a tuple of Problem")
        if not isinstance(self.reproduction_notes, tuple):
            _fail("ReportInventory.reproduction_notes must be a tuple")
        for item in self.reproduction_notes:
            value = _check_str(item, "ReportInventory.reproduction_notes item")
            if not value or len(value) > 512:
                _fail("ReportInventory.reproduction_notes items must be 1..512 chars")

    def to_obj(self) -> dict[str, object]:
        return {
            "files": [item.to_obj() for item in self.files],
            "problems": [
                {"code": item.code, "path": item.path, "detail": item.detail}
                for item in self.problems
            ],
            "reproduction_notes": list(self.reproduction_notes),
        }


# --------------------------------------------------------------------------
# Report document
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ReportDocument:
    """The single display-fact source behind report.json/md/html (6.4.5).

    ``occurrences`` is ordered by (risk rank, occurrence_id); ``case_details``
    follow the same order and bind to known occurrences only.  ``reviews``
    holds the review section (accepted / duplicates / historical / conflicts)
    exactly as the review evaluator produced it — the report never re-decides
    reviews and never lets them modify the observed comparisons.
    """

    header: ReportHeader
    findings: FindingsSummary
    occurrences: tuple[FindingOccurrence, ...]
    case_details: tuple[CaseDetail, ...]
    reviews: ReviewSet
    inventory: ReportInventory
    generation_counts: Optional[GenerationCounts] = None
    execution_counts: Optional[ExecutionCounts] = None
    coverage: Optional[CoverageSummary] = None
    schema_version: int = REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "ReportDocument.schema_version")
        if self.schema_version != REPORT_SCHEMA_VERSION:
            _fail(f"unsupported report schema_version {self.schema_version}")
        if not isinstance(self.header, ReportHeader):
            _fail("ReportDocument.header must be a ReportHeader")
        if not isinstance(self.findings, FindingsSummary):
            _fail("ReportDocument.findings must be a FindingsSummary")
        if not isinstance(self.generation_counts, (GenerationCounts, type(None))):
            _fail("ReportDocument.generation_counts must be GenerationCounts or None")
        if not isinstance(self.execution_counts, (ExecutionCounts, type(None))):
            _fail("ReportDocument.execution_counts must be ExecutionCounts or None")
        if not isinstance(self.coverage, (CoverageSummary, type(None))):
            _fail("ReportDocument.coverage must be a CoverageSummary or None")
        if not isinstance(self.occurrences, tuple) or any(
            not isinstance(item, FindingOccurrence) for item in self.occurrences
        ):
            _fail("ReportDocument.occurrences must be a tuple of FindingOccurrence")
        previous: Optional[tuple[int, str]] = None
        for item in self.occurrences:
            key = (occurrence_risk_rank(item), item.occurrence_id)
            if previous is not None and key <= previous:
                _fail(
                    "ReportDocument.occurrences must be sorted by (risk rank, "
                    "occurrence_id), never run-random order"
                )
            previous = key
        known = {item.occurrence_id: item for item in self.occurrences}
        if not isinstance(self.case_details, tuple) or any(
            not isinstance(item, CaseDetail) for item in self.case_details
        ):
            _fail("ReportDocument.case_details must be a tuple of CaseDetail")
        previous_detail: Optional[tuple[int, str]] = None
        for item in self.case_details:
            occurrence = known.get(item.occurrence_id)
            if occurrence is None:
                _fail(
                    f"ReportDocument case detail binds unknown occurrence "
                    f"{item.occurrence_id!r}"
                )
            key = (occurrence_risk_rank(occurrence), item.occurrence_id)
            if previous_detail is not None and key <= previous_detail:
                _fail("ReportDocument.case_details must follow the occurrence order")
            previous_detail = key
        if not isinstance(self.reviews, ReviewSet):
            _fail("ReportDocument.reviews must be a ReviewSet")
        if not isinstance(self.inventory, ReportInventory):
            _fail("ReportDocument.inventory must be a ReportInventory")

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "header": self.header.to_obj(),
            "counts": {
                "generation": (
                    _generation_counts_obj(self.generation_counts)
                    if self.generation_counts is not None
                    else None
                ),
                "execution": (
                    _execution_counts_obj(self.execution_counts)
                    if self.execution_counts is not None
                    else None
                ),
                "coverage": _coverage_obj(self.coverage) if self.coverage is not None else None,
            },
            "findings": {
                "summary": {
                    "real_candidates": self.findings.real_candidates,
                    "synthetic_candidates": self.findings.synthetic_candidates,
                    "unknown_synthetic_candidates": self.findings.unknown_synthetic_candidates,
                    "conflicts": self.findings.conflicts,
                    "unique_case_ids": self.findings.unique_case_ids,
                    "distinct_signatures": self.findings.distinct_signatures,
                    "distinct_fingerprints": self.findings.distinct_fingerprints,
                    "reviewed_confirmed": self.findings.reviewed_confirmed,
                },
                "occurrences": [item.to_obj() for item in self.occurrences],
                "case_details": [item.to_obj() for item in self.case_details],
            },
            "reviews": _review_set_obj(self.reviews),
            "inventory": self.inventory.to_obj(),
        }


# --------------------------------------------------------------------------
# Encoding helpers for the Phase 2 count models (no to_obj on those classes,
# which this module must not modify)
# --------------------------------------------------------------------------


def _generation_counts_obj(counts: GenerationCounts) -> dict[str, object]:
    return {
        "requested_ordinals": counts.requested_ordinals,
        "attempted_candidates": counts.attempted_candidates,
        "emitted_occurrences": counts.emitted_occurrences,
        "unique_cases": counts.unique_cases,
        "rejected_ordinals": counts.rejected_ordinals,
        "interrupted_ordinals": counts.interrupted_ordinals,
        "not_attempted": counts.not_attempted,
        "receipt_recheck": counts.receipt_recheck,
        "receipt_mismatch_reason": counts.receipt_mismatch_reason,
        "denominator_known": counts.denominator_known,
    }


_GENERATION_COUNTS_FIELDS = frozenset(
    {
        "requested_ordinals",
        "attempted_candidates",
        "emitted_occurrences",
        "unique_cases",
        "rejected_ordinals",
        "interrupted_ordinals",
        "not_attempted",
        "receipt_recheck",
        "receipt_mismatch_reason",
        "denominator_known",
    }
)


def _decode_generation_counts(obj: object, what: str) -> GenerationCounts:
    obj = _expect_dict(obj, what)
    _no_extra(obj, _GENERATION_COUNTS_FIELDS, what)
    return GenerationCounts(
        requested_ordinals=_as_opt_int(obj.get("requested_ordinals"), f"{what}.requested_ordinals"),
        attempted_candidates=_as_opt_int(obj.get("attempted_candidates"), f"{what}.attempted_candidates"),
        emitted_occurrences=_as_opt_int(obj.get("emitted_occurrences"), f"{what}.emitted_occurrences"),
        unique_cases=_as_opt_int(obj.get("unique_cases"), f"{what}.unique_cases"),
        rejected_ordinals=_as_opt_int(obj.get("rejected_ordinals"), f"{what}.rejected_ordinals"),
        interrupted_ordinals=_as_opt_int(obj.get("interrupted_ordinals"), f"{what}.interrupted_ordinals"),
        not_attempted=_as_opt_int(obj.get("not_attempted"), f"{what}.not_attempted"),
        receipt_recheck=_as_str(_field(obj, "receipt_recheck", what), f"{what}.receipt_recheck"),
        receipt_mismatch_reason=obj.get("receipt_mismatch_reason"),
        denominator_known=_as_bool(_field(obj, "denominator_known", what), f"{what}.denominator_known"),
    )


def _as_opt_int(value: object, what: str) -> Optional[int]:
    if value is None:
        return None
    return _as_int(value, what)


def _execution_counts_obj(counts: ExecutionCounts) -> dict[str, object]:
    return {
        "requested_attempts": counts.requested_attempts,
        "completed_both_selects": counts.completed_both_selects,
        "match_candidates": counts.match_candidates,
        "not_applicable": counts.not_applicable,
        "undecidable": counts.undecidable,
        "preflight_failures": counts.preflight_failures,
        "undispatched": counts.undispatched,
    }


_EXECUTION_COUNTS_FIELDS = frozenset(
    {
        "requested_attempts",
        "completed_both_selects",
        "match_candidates",
        "not_applicable",
        "undecidable",
        "preflight_failures",
        "undispatched",
    }
)


def _decode_execution_counts(obj: object, what: str) -> ExecutionCounts:
    obj = _expect_dict(obj, what)
    _no_extra(obj, _EXECUTION_COUNTS_FIELDS, what)
    return ExecutionCounts(
        requested_attempts=_as_opt_int(obj.get("requested_attempts"), f"{what}.requested_attempts"),
        completed_both_selects=_as_opt_int(obj.get("completed_both_selects"), f"{what}.completed_both_selects"),
        match_candidates=_as_opt_int(obj.get("match_candidates"), f"{what}.match_candidates"),
        not_applicable=_as_opt_int(obj.get("not_applicable"), f"{what}.not_applicable"),
        undecidable=_as_opt_int(obj.get("undecidable"), f"{what}.undecidable"),
        preflight_failures=_as_opt_int(obj.get("preflight_failures"), f"{what}.preflight_failures"),
        undispatched=_as_opt_int(obj.get("undispatched"), f"{what}.undispatched"),
    )


def _coverage_entry_obj(entry: CoverageEntry) -> dict[str, object]:
    return {
        "rule_id": entry.rule_id,
        "rule_version": entry.rule_version,
        "type_pair": entry.type_pair,
        "template": entry.template,
        "index_variant": entry.index_variant,
        "comparable_unique_cases": entry.comparable_unique_cases,
        "denominator": entry.denominator,
        "build_key": entry.build_key,
    }


def _coverage_obj(summary: CoverageSummary) -> dict[str, object]:
    return {
        "entries": [_coverage_entry_obj(entry) for entry in summary.entries],
        "denominator_known": summary.denominator_known,
        "unknown_reason": summary.unknown_reason,
        "identity_only_cases": summary.identity_only_cases,
        "empty_result_cases": summary.empty_result_cases,
    }


_COVERAGE_ENTRY_FIELDS = frozenset(
    {
        "rule_id",
        "rule_version",
        "type_pair",
        "template",
        "index_variant",
        "comparable_unique_cases",
        "denominator",
        "build_key",
    }
)


def _decode_coverage_entry(obj: object, what: str) -> CoverageEntry:
    obj = _expect_dict(obj, what)
    _no_extra(obj, _COVERAGE_ENTRY_FIELDS, what)
    return CoverageEntry(
        rule_id=_as_str(_field(obj, "rule_id", what), f"{what}.rule_id"),
        rule_version=_as_int(_field(obj, "rule_version", what), f"{what}.rule_version"),
        type_pair=_as_str(_field(obj, "type_pair", what), f"{what}.type_pair"),
        template=_as_str(_field(obj, "template", what), f"{what}.template"),
        index_variant=_as_str(_field(obj, "index_variant", what), f"{what}.index_variant"),
        comparable_unique_cases=_as_int(
            _field(obj, "comparable_unique_cases", what), f"{what}.comparable_unique_cases"
        ),
        denominator=obj.get("denominator"),
        build_key=obj.get("build_key"),
    )


def _decode_coverage(obj: object, what: str) -> CoverageSummary:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {"entries", "denominator_known", "unknown_reason", "identity_only_cases", "empty_result_cases"},
        what,
    )
    unknown_reason = obj.get("unknown_reason")
    if unknown_reason is not None:
        _as_str(unknown_reason, f"{what}.unknown_reason")
    return CoverageSummary(
        entries=tuple(
            _decode_coverage_entry(item, f"{what}.entries[{index}]")
            for index, item in enumerate(
                _as_list(_field(obj, "entries", what), f"{what}.entries")
            )
        ),
        denominator_known=_as_bool(_field(obj, "denominator_known", what), f"{what}.denominator_known"),
        unknown_reason=unknown_reason,
        identity_only_cases=_as_int(_field(obj, "identity_only_cases", what), f"{what}.identity_only_cases"),
        empty_result_cases=_as_int(_field(obj, "empty_result_cases", what), f"{what}.empty_result_cases"),
    )


def _review_set_obj(reviews: ReviewSet) -> dict[str, object]:
    return {
        "accepted": [item.to_obj() for item in reviews.accepted],
        "duplicates_ignored": list(reviews.duplicates_ignored),
        "historical": [
            {"review": item.review.to_obj(), "detail": item.detail}
            for item in reviews.historical
        ],
        "conflicts": [
            {
                "occurrence_ids": list(item.occurrence_ids),
                "review_ids": list(item.review_ids),
                "detail": item.detail,
            }
            for item in reviews.conflicts
        ],
        "has_conflict": reviews.has_conflict,
    }


# --------------------------------------------------------------------------
# Strict decoder (unknown fields rejected, hashes validated, schema_version=1)
# --------------------------------------------------------------------------


def _decode_case_detail(obj: object, what: str) -> CaseDetail:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "occurrence_id",
            "case_id",
            "rule_id",
            "rule_version",
            "type_pair",
            "select_text",
            "diff_summary",
            "original_ref",
            "best_ref",
            "round_outcomes",
            "review_ids",
        },
        what,
    )
    select_text = obj.get("select_text")
    if select_text is not None:
        _as_str(select_text, f"{what}.select_text")
    diff_summary = obj.get("diff_summary")
    if diff_summary is not None:
        _as_str(diff_summary, f"{what}.diff_summary")
    original_ref = obj.get("original_ref")
    if original_ref is not None:
        _as_str(original_ref, f"{what}.original_ref")
    best_ref = obj.get("best_ref")
    if best_ref is not None:
        _as_str(best_ref, f"{what}.best_ref")
    return CaseDetail(
        occurrence_id=_as_str(_field(obj, "occurrence_id", what), f"{what}.occurrence_id"),
        case_id=_as_str(_field(obj, "case_id", what), f"{what}.case_id"),
        rule_id=_as_str(_field(obj, "rule_id", what), f"{what}.rule_id"),
        rule_version=_as_int(_field(obj, "rule_version", what), f"{what}.rule_version"),
        type_pair=_as_str(_field(obj, "type_pair", what), f"{what}.type_pair"),
        select_text=select_text,
        diff_summary=diff_summary,
        original_ref=original_ref,
        best_ref=best_ref,
        round_outcomes=tuple(
            _as_str(item, f"{what}.round_outcomes[{index}]")
            for index, item in enumerate(
                _as_list(_field(obj, "round_outcomes", what), f"{what}.round_outcomes")
            )
        ),
        review_ids=tuple(
            _as_str(item, f"{what}.review_ids[{index}]")
            for index, item in enumerate(
                _as_list(_field(obj, "review_ids", what), f"{what}.review_ids")
            )
        ),
    )


def _decode_header(obj: object, what: str) -> ReportHeader:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "tool_name",
            "writer_version",
            "native_kind",
            "synthetic",
            "original_run_status",
            "structural",
            "semantic",
            "provenance",
            "execution_safety",
            "producer",
            "source_commit",
            "source_id",
            "delivery_id",
            "generated_at",
            "known_limitations",
        },
        what,
    )
    original_run_status = obj.get("original_run_status")
    if original_run_status is not None:
        _as_str(original_run_status, f"{what}.original_run_status")
    source_commit = obj.get("source_commit")
    if source_commit is not None:
        _as_str(source_commit, f"{what}.source_commit")
    generated_at = obj.get("generated_at")
    if generated_at is not None:
        _as_str(generated_at, f"{what}.generated_at")
    producer_obj = obj.get("producer")
    return ReportHeader(
        tool_name=_as_str(_field(obj, "tool_name", what), f"{what}.tool_name"),
        writer_version=_as_str(_field(obj, "writer_version", what), f"{what}.writer_version"),
        native_kind=_as_enum(NativeKind, _field(obj, "native_kind", what), f"{what}.native_kind"),
        synthetic=_as_enum(SyntheticKind, _field(obj, "synthetic", what), f"{what}.synthetic"),
        structural=decode_dimension_result(obj["structural"], f"{what}.structural"),
        semantic=decode_dimension_result(obj["semantic"], f"{what}.semantic"),
        provenance=decode_dimension_result(obj["provenance"], f"{what}.provenance"),
        execution_safety=decode_dimension_result(
            obj["execution_safety"], f"{what}.execution_safety"
        ),
        source_id=_as_str(_field(obj, "source_id", what), f"{what}.source_id"),
        delivery_id=_as_str(_field(obj, "delivery_id", what), f"{what}.delivery_id"),
        original_run_status=original_run_status,
        producer=None if producer_obj is None else decode_producer_info(producer_obj, f"{what}.producer"),
        source_commit=source_commit,
        generated_at=generated_at,
        known_limitations=tuple(
            _as_str(item, f"{what}.known_limitations[{index}]")
            for index, item in enumerate(
                _as_list(_field(obj, "known_limitations", what), f"{what}.known_limitations")
            )
        ),
    )


def _decode_findings(obj: object, what: str) -> tuple[FindingsSummary, tuple[FindingOccurrence, ...], tuple[CaseDetail, ...]]:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"summary", "occurrences", "case_details"}, what)
    summary_obj = _expect_dict(_field(obj, "summary", what), f"{what}.summary")
    _no_extra(
        summary_obj,
        {
            "real_candidates",
            "synthetic_candidates",
            "unknown_synthetic_candidates",
            "conflicts",
            "unique_case_ids",
            "distinct_signatures",
            "distinct_fingerprints",
            "reviewed_confirmed",
        },
        f"{what}.summary",
    )
    summary = FindingsSummary(
        real_candidates=_as_int(summary_obj["real_candidates"], f"{what}.summary.real_candidates"),
        synthetic_candidates=_as_int(
            summary_obj["synthetic_candidates"], f"{what}.summary.synthetic_candidates"
        ),
        unknown_synthetic_candidates=_as_int(
            summary_obj["unknown_synthetic_candidates"],
            f"{what}.summary.unknown_synthetic_candidates",
        ),
        conflicts=_as_int(summary_obj["conflicts"], f"{what}.summary.conflicts"),
        unique_case_ids=_as_int(summary_obj["unique_case_ids"], f"{what}.summary.unique_case_ids"),
        distinct_signatures=_as_int(
            summary_obj["distinct_signatures"], f"{what}.summary.distinct_signatures"
        ),
        distinct_fingerprints=_as_int(
            summary_obj["distinct_fingerprints"], f"{what}.summary.distinct_fingerprints"
        ),
        reviewed_confirmed=_as_int(
            summary_obj["reviewed_confirmed"], f"{what}.summary.reviewed_confirmed"
        ),
    )
    occurrences = tuple(
        decode_finding_occurrence(item, f"{what}.occurrences[{index}]")
        for index, item in enumerate(
            _as_list(_field(obj, "occurrences", what), f"{what}.occurrences")
        )
    )
    case_details = tuple(
        _decode_case_detail(item, f"{what}.case_details[{index}]")
        for index, item in enumerate(
            _as_list(_field(obj, "case_details", what), f"{what}.case_details")
        )
    )
    return summary, occurrences, case_details


def _decode_reviews(obj: object, what: str) -> ReviewSet:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {"accepted", "duplicates_ignored", "historical", "conflicts", "has_conflict"},
        what,
    )
    accepted = tuple(
        decode_finding_review(item, f"{what}.accepted[{index}]")
        for index, item in enumerate(_as_list(_field(obj, "accepted", what), f"{what}.accepted"))
    )
    duplicates = tuple(
        _as_str(item, f"{what}.duplicates_ignored[{index}]")
        for index, item in enumerate(
            _as_list(_field(obj, "duplicates_ignored", what), f"{what}.duplicates_ignored")
        )
    )
    historical: list[HistoricalReview] = []
    for index, item in enumerate(
        _as_list(_field(obj, "historical", what), f"{what}.historical")
    ):
        entry = _expect_dict(item, f"{what}.historical[{index}]")
        _no_extra(entry, {"review", "detail"}, f"{what}.historical[{index}]")
        historical.append(
            HistoricalReview(
                review=decode_finding_review(entry["review"], f"{what}.historical[{index}].review"),
                detail=_as_str(entry["detail"], f"{what}.historical[{index}].detail"),
            )
        )
    conflicts: list[ReviewConflict] = []
    for index, item in enumerate(_as_list(_field(obj, "conflicts", what), f"{what}.conflicts")):
        entry = _expect_dict(item, f"{what}.conflicts[{index}]")
        _no_extra(entry, {"occurrence_ids", "review_ids", "detail"}, f"{what}.conflicts[{index}]")
        conflicts.append(
            ReviewConflict(
                occurrence_ids=tuple(
                    _as_str(oid, f"{what}.conflicts[{index}].occurrence_ids[{i}]")
                    for i, oid in enumerate(
                        _as_list(entry["occurrence_ids"], f"{what}.conflicts[{index}].occurrence_ids")
                    )
                ),
                review_ids=tuple(
                    _as_str(rid, f"{what}.conflicts[{index}].review_ids[{i}]")
                    for i, rid in enumerate(
                        _as_list(entry["review_ids"], f"{what}.conflicts[{index}].review_ids")
                    )
                ),
                detail=_as_str(entry["detail"], f"{what}.conflicts[{index}].detail"),
            )
        )
    return ReviewSet(
        accepted=accepted,
        duplicates_ignored=duplicates,
        historical=tuple(historical),
        conflicts=tuple(conflicts),
        has_conflict=_as_bool(_field(obj, "has_conflict", what), f"{what}.has_conflict"),
    )


def _decode_inventory(obj: object, what: str) -> ReportInventory:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"files", "problems", "reproduction_notes"}, what)
    problems: list[Problem] = []
    for index, item in enumerate(_as_list(_field(obj, "problems", what), f"{what}.problems")):
        entry = _expect_dict(item, f"{what}.problems[{index}]")
        _no_extra(entry, {"code", "path", "detail"}, f"{what}.problems[{index}]")
        path = entry.get("path")
        if path is not None:
            _as_str(path, f"{what}.problems[{index}].path")
        problems.append(
            Problem(
                code=_as_str(entry["code"], f"{what}.problems[{index}].code"),
                path=path,
                detail=_as_str(entry["detail"], f"{what}.problems[{index}].detail"),
            )
        )
    return ReportInventory(
        files=tuple(
            decode_evidence_file(item, f"{what}.files[{index}]")
            for index, item in enumerate(_as_list(_field(obj, "files", what), f"{what}.files"))
        ),
        problems=tuple(problems),
        reproduction_notes=tuple(
            _as_str(item, f"{what}.reproduction_notes[{index}]")
            for index, item in enumerate(
                _as_list(_field(obj, "reproduction_notes", what), f"{what}.reproduction_notes")
            )
        ),
    )


def decode_report_document(obj: object, what: str = "report document") -> ReportDocument:
    """Strictly decode a :class:`ReportDocument` from its ``to_obj`` form.

    Unknown fields are rejected, hashes and identities are re-validated by
    the underlying contract decoders, and ``schema_version`` must be 1.
    """
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"schema_version", "header", "counts", "findings", "reviews", "inventory"}, what)
    version = _as_int(_field(obj, "schema_version", what), f"{what}.schema_version")
    if version != REPORT_SCHEMA_VERSION:
        _fail(f"{what} has unsupported schema_version {version}")
    counts = _expect_dict(_field(obj, "counts", what), f"{what}.counts")
    _no_extra(counts, {"generation", "execution", "coverage"}, f"{what}.counts")
    generation_obj = counts.get("generation")
    execution_obj = counts.get("execution")
    coverage_obj = counts.get("coverage")
    summary, occurrences, case_details = _decode_findings(
        _field(obj, "findings", what), f"{what}.findings"
    )
    return ReportDocument(
        schema_version=version,
        header=_decode_header(_field(obj, "header", what), f"{what}.header"),
        generation_counts=(
            None if generation_obj is None else _decode_generation_counts(generation_obj, f"{what}.counts.generation")
        ),
        execution_counts=(
            None if execution_obj is None else _decode_execution_counts(execution_obj, f"{what}.counts.execution")
        ),
        coverage=None if coverage_obj is None else _decode_coverage(coverage_obj, f"{what}.counts.coverage"),
        findings=summary,
        occurrences=occurrences,
        case_details=case_details,
        reviews=_decode_reviews(_field(obj, "reviews", what), f"{what}.reviews"),
        inventory=_decode_inventory(_field(obj, "inventory", what), f"{what}.inventory"),
    )
