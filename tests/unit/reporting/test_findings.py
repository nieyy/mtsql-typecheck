"""Unit tests for finding occurrence collection/aggregation (design 6.4.4).

The pinned ``AttemptSemanticResult`` shape (Phase 2, evidence/assessment.py)
is reproduced here as a local frozen dataclass so these tests never import
the assessment module; ``collect_occurrences`` consumes the pinned attributes
structurally.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from mtsql_typecheck.contracts.delivery import (
    FindingReview,
    ReviewDecision,
    SemanticStatus,
    SyntheticKind,
    compute_occurrence_id,
)
from mtsql_typecheck.reporting.findings import (
    DuplicateOccurrenceError,
    aggregate_findings,
    collect_occurrences,
)

# --------------------------------------------------------------------------
# Frozen fixture constants (chosen literals, not derived)
# --------------------------------------------------------------------------

SOURCE_ID = "s-" + "aa" * 32
CASE_A = "ab" * 32
CASE_B = "cd" * 32
CASE_C = "ef" * 32
CASE_D = "12" * 32
CASE_E = "34" * 32
HASH_1 = "11" * 32
HASH_2 = "22" * 32
HASH_3 = "33" * 32
SIG_1 = "44" * 32
SIG_2 = "55" * 32
SIG_3 = "66" * 32
FP_GROUP = "77" * 32
FP_OTHER = "88" * 32
DELIVERY_DIGEST = "99" * 32
OTHER_DIGEST = "aa" * 32


@dataclass(frozen=True)
class FakeAttempt:
    """Local replica of the pinned AttemptSemanticResult shape (Phase 2)."""

    source_id: str
    attempt_id: str | None
    case_id: str | None
    original_comparison_hash: str | None
    static_check_status: str | None
    recompute: SemanticStatus
    recomputed_comparison_hash: str | None
    exact_signature: str | None
    fingerprint: str | None
    synthetic: SyntheticKind
    reason_codes: tuple[str, ...]
    limit_reasons: tuple[str, ...]


def _attempt(
    attempt_id: str | None,
    case_id: str | None,
    *,
    recompute: SemanticStatus = SemanticStatus.RECOMPUTED,
    recomputed: str | None = HASH_2,
    comparison: str | None = HASH_1,
    signature: str | None = SIG_1,
    fingerprint: str | None = FP_GROUP,
    synthetic: SyntheticKind = SyntheticKind.REAL,
) -> FakeAttempt:
    return FakeAttempt(
        source_id=SOURCE_ID,
        attempt_id=attempt_id,
        case_id=case_id,
        original_comparison_hash=comparison,
        static_check_status="PASS",
        recompute=recompute,
        recomputed_comparison_hash=recomputed,
        exact_signature=signature,
        fingerprint=fingerprint,
        synthetic=synthetic,
        reason_codes=(),
        limit_reasons=(),
    )


def _review(
    review_id: str,
    decision: ReviewDecision,
    occurrence_ids: tuple[str, ...],
    digest: str = DELIVERY_DIGEST,
) -> FindingReview:
    return FindingReview(
        review_id=review_id,
        reviewer="alice",
        reviewed_at="2026-09-06T00:00:00Z",
        evidence_digest=digest,
        occurrence_ids=occurrence_ids,
        decision=decision,
        reason="hand-verified against the original database",
    )


# --------------------------------------------------------------------------
# collect_occurrences
# --------------------------------------------------------------------------


class TestCollectOccurrences:
    def test_attempt_less_rows_are_skipped(self) -> None:
        attempts = (
            _attempt(None, CASE_A),  # generation-only row: no execution occurrence
            _attempt("att-1", CASE_B),
        )
        occurrences = collect_occurrences(attempts, SOURCE_ID)
        assert len(occurrences) == 1
        assert occurrences[0].attempt_id == "att-1"
        assert occurrences[0].case_id == CASE_B

    def test_case_less_rows_are_skipped(self) -> None:
        attempts = (_attempt("att-1", None), _attempt("att-2", CASE_A))
        occurrences = collect_occurrences(attempts, SOURCE_ID)
        assert [o.attempt_id for o in occurrences] == ["att-2"]

    def test_occurrence_id_matches_identity_hash(self) -> None:
        occurrences = collect_occurrences((_attempt("att-1", CASE_A),), SOURCE_ID)
        assert occurrences[0].occurrence_id == compute_occurrence_id(SOURCE_ID, "att-1", CASE_A)

    def test_original_signature_and_fingerprint_pass_through(self) -> None:
        occurrences = collect_occurrences((_attempt("att-1", CASE_A),), SOURCE_ID)
        occurrence = occurrences[0]
        assert occurrence.comparison_hash == HASH_1
        assert occurrence.original_exact_signature == SIG_1
        assert occurrence.fingerprint == FP_GROUP
        assert occurrence.recompute_status is SemanticStatus.RECOMPUTED
        assert occurrence.recomputed_comparison_hash == HASH_2
        assert occurrence.synthetic is SyntheticKind.REAL

    def test_not_recomputed_carries_no_recomputed_hash(self) -> None:
        occurrences = collect_occurrences(
            (
                _attempt(
                    "att-1",
                    CASE_A,
                    recompute=SemanticStatus.NOT_RECOMPUTED,
                    recomputed=None,
                ),
            ),
            SOURCE_ID,
        )
        assert occurrences[0].recompute_status is SemanticStatus.NOT_RECOMPUTED
        assert occurrences[0].recomputed_comparison_hash is None

    def test_conflict_keeps_recomputed_hash(self) -> None:
        occurrences = collect_occurrences(
            (
                _attempt(
                    "att-1",
                    CASE_A,
                    recompute=SemanticStatus.CONFLICT,
                    recomputed=HASH_3,
                ),
            ),
            SOURCE_ID,
        )
        assert occurrences[0].recompute_status is SemanticStatus.CONFLICT
        assert occurrences[0].recomputed_comparison_hash == HASH_3

    def test_duplicate_triple_is_rejected(self) -> None:
        attempts = (_attempt("att-1", CASE_A), _attempt("att-1", CASE_A))
        with pytest.raises(DuplicateOccurrenceError):
            collect_occurrences(attempts, SOURCE_ID)

    def test_same_case_in_different_attempts_is_not_a_duplicate(self) -> None:
        attempts = (_attempt("att-1", CASE_A), _attempt("att-2", CASE_A))
        occurrences = collect_occurrences(attempts, SOURCE_ID)
        assert len(occurrences) == 2


# --------------------------------------------------------------------------
# aggregate_findings
# --------------------------------------------------------------------------


def _mixed_occurrences():
    return collect_occurrences(
        (
            # Three REAL candidates sharing one fingerprint group.
            _attempt("att-1", CASE_A, signature=SIG_1),
            _attempt("att-2", CASE_B, signature=SIG_2),
            _attempt("att-3", CASE_C, signature=SIG_3),
            # Two synthetic candidates.
            _attempt(
                "att-4",
                CASE_D,
                signature=SIG_1,
                fingerprint=FP_OTHER,
                synthetic=SyntheticKind.SYNTHETIC,
            ),
            _attempt(
                "att-5",
                CASE_E,
                signature=None,
                fingerprint=None,
                synthetic=SyntheticKind.SYNTHETIC,
            ),
            # One UNKNOWN-synthetic conflict.
            _attempt(
                "att-6",
                CASE_D,
                recompute=SemanticStatus.CONFLICT,
                recomputed=HASH_3,
                synthetic=SyntheticKind.UNKNOWN,
            ),
        ),
        SOURCE_ID,
    )


class TestAggregateFindings:
    def test_split_by_synthetic_kind(self) -> None:
        summary = aggregate_findings(_mixed_occurrences())
        assert summary.real_candidates == 3
        assert summary.synthetic_candidates == 2
        assert summary.unknown_synthetic_candidates == 1
        # UNKNOWN is never folded into the real column.
        assert summary.real_candidates + summary.synthetic_candidates + (
            summary.unknown_synthetic_candidates
        ) == 6

    def test_conflicts_counted(self) -> None:
        summary = aggregate_findings(_mixed_occurrences())
        assert summary.conflicts == 1

    def test_unique_cases_and_distinct_surfaces(self) -> None:
        summary = aggregate_findings(_mixed_occurrences())
        # CASE_D appears twice (att-4 and att-6): 5 unique case ids overall.
        assert summary.unique_case_ids == 5
        # Signatures: SIG_1, SIG_2, SIG_3 present; one occurrence lacks one.
        assert summary.distinct_signatures == 3
        # Fingerprints: FP_GROUP and FP_OTHER; one occurrence lacks one.
        assert summary.distinct_fingerprints == 2

    def test_fingerprint_group_is_not_a_bug_count(self) -> None:
        # Three REAL occurrences in ONE fingerprint group: one browsing group,
        # but three per-execution candidates (design 6.4.4).
        occurrences = collect_occurrences(
            (
                _attempt("att-1", CASE_A),
                _attempt("att-2", CASE_B),
                _attempt("att-3", CASE_C),
            ),
            SOURCE_ID,
        )
        summary = aggregate_findings(occurrences)
        assert summary.distinct_fingerprints == 1
        assert summary.real_candidates == 3
        assert summary.unique_case_ids == 3

    def test_empty_input_gives_zero_summary(self) -> None:
        summary = aggregate_findings(())
        assert summary.real_candidates == 0
        assert summary.unique_case_ids == 0
        assert summary.reviewed_confirmed == 0


class TestReviewedConfirmed:
    def test_confirmed_review_counts_bound_occurrence(self) -> None:
        occurrences = _mixed_occurrences()
        bound = occurrences[0].occurrence_id
        summary = aggregate_findings(
            occurrences,
            (_review("rev-1", ReviewDecision.CONFIRMED_DB_BUG, (bound,)),),
            evidence_digest=DELIVERY_DIGEST,
        )
        assert summary.reviewed_confirmed == 1

    def test_review_with_wrong_digest_is_ignored(self) -> None:
        occurrences = _mixed_occurrences()
        bound = occurrences[0].occurrence_id
        summary = aggregate_findings(
            occurrences,
            (_review("rev-1", ReviewDecision.CONFIRMED_DB_BUG, (bound,), digest=OTHER_DIGEST),),
            evidence_digest=DELIVERY_DIGEST,
        )
        assert summary.reviewed_confirmed == 0

    def test_unbound_occurrence_id_is_ignored(self) -> None:
        occurrences = _mixed_occurrences()
        ghost = "bb" * 32
        summary = aggregate_findings(
            occurrences,
            (_review("rev-1", ReviewDecision.CONFIRMED_DB_BUG, (ghost,)),),
            evidence_digest=DELIVERY_DIGEST,
        )
        assert summary.reviewed_confirmed == 0

    def test_non_confirmed_decisions_never_count(self) -> None:
        occurrences = _mixed_occurrences()
        bound = occurrences[0].occurrence_id
        reviews = tuple(
            _review(f"rev-{n}", decision, (bound,))
            for n, decision in enumerate(
                (
                    ReviewDecision.EXPECTED_BEHAVIOR,
                    ReviewDecision.TOOL_OR_EVIDENCE_ISSUE,
                    ReviewDecision.NEEDS_MORE_EVIDENCE,
                )
            )
        )
        summary = aggregate_findings(reviews=reviews, occurrences=occurrences,
                                     evidence_digest=DELIVERY_DIGEST)
        assert summary.reviewed_confirmed == 0

    def test_no_digest_applies_no_reviews(self) -> None:
        occurrences = _mixed_occurrences()
        bound = occurrences[0].occurrence_id
        summary = aggregate_findings(
            occurrences,
            (_review("rev-1", ReviewDecision.CONFIRMED_DB_BUG, (bound,)),),
        )
        assert summary.reviewed_confirmed == 0

    def test_two_reviews_one_occurrence_counts_once(self) -> None:
        occurrences = _mixed_occurrences()
        bound = occurrences[0].occurrence_id
        summary = aggregate_findings(
            occurrences,
            (
                _review("rev-1", ReviewDecision.CONFIRMED_DB_BUG, (bound,)),
                _review("rev-2", ReviewDecision.CONFIRMED_DB_BUG, (bound,)),
            ),
            evidence_digest=DELIVERY_DIGEST,
        )
        assert summary.reviewed_confirmed == 1
