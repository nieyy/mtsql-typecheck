"""Unit tests for review validation/conflict resolution (design 6.4.5).

All expectations below are hand-authored from design 6.4.5 and the pinned
Phase 3 models; none are derived by running :mod:`mtsql_typecheck.reporting.review`
first.  The golden case freezes the canonical JSON bytes of a ``FindingReview``
as a hand-written literal (Phase 1 contract codec), not a value produced by
the function under test.
"""

from __future__ import annotations

import json

import pytest

from mtsql_typecheck.contracts.case import ContractError
from mtsql_typecheck.contracts.codec import canonical_json
from mtsql_typecheck.contracts.delivery import (
    FindingReview,
    ReviewDecision,
    decode_finding_review,
)
from mtsql_typecheck.reporting.review import (
    HistoricalReview,
    ReviewConflict,
    ReviewSet,
    ReviewValidationError,
    apply_reviews,
)

# --------------------------------------------------------------------------
# Frozen fixture constants (chosen literals, not derived)
# --------------------------------------------------------------------------

DELIVERY_DIGEST = "aa" * 32
OTHER_DIGEST = "bb" * 32
OCC_1 = "cc" * 32
OCC_2 = "dd" * 32
OCC_3 = "ee" * 32
ALL_OCCURRENCES = frozenset({OCC_1, OCC_2, OCC_3})
TS = "2026-09-06T08:30:00Z"

# Hand-written canonical JSON of the golden FindingReview (bytes-level
# golden; the key order decision, evidence_digest, issue_url, occurrence_ids,
# reason, review_id, reviewed_at, reviewer, schema_version, supersedes is
# canonical_json's sorted-key order, transcribed by hand).
GOLDEN_REVIEW_JSON = (
    '{"decision":"CONFIRMED_DB_BUG",'
    '"evidence_digest":"' + "bb" * 32 + '",'
    '"issue_url":null,'
    '"occurrence_ids":["' + "cc" * 32 + '","' + "dd" * 32 + '"],'
    '"reason":"A and B row order differs for NULL sort keys",'
    '"review_id":"rev-golden-1",'
    '"reviewed_at":"2026-09-06T08:30:00Z",'
    '"reviewer":"alice",'
    '"schema_version":1,'
    '"supersedes":null}'
)


def make_review(
    review_id: str,
    *,
    digest: str = DELIVERY_DIGEST,
    occurrences: tuple[str, ...] = (OCC_1,),
    decision: ReviewDecision = ReviewDecision.CONFIRMED_DB_BUG,
    supersedes: str | None = None,
    reviewer: str = "alice",
    reason: str = "checked against the recorded evidence",
) -> FindingReview:
    """Build a FindingReview fixture with explicit literals."""
    return FindingReview(
        review_id=review_id,
        reviewer=reviewer,
        reviewed_at=TS,
        evidence_digest=digest,
        occurrence_ids=occurrences,
        decision=decision,
        reason=reason,
        supersedes=supersedes,
    )


def rejection_codes(exc: ReviewValidationError) -> dict[str, str]:
    """Map review_id -> reason_code for the rejections carried by exc."""
    return {r.review_id: r.reason_code for r in exc.rejections if r.review_id is not None}


# --------------------------------------------------------------------------
# Basic application
# --------------------------------------------------------------------------


class TestBasics:
    def test_empty_input_yields_empty_review_set(self) -> None:
        result = apply_reviews((), evidence_digest=DELIVERY_DIGEST,
                               occurrence_ids=ALL_OCCURRENCES, mode="explicit")
        assert isinstance(result, ReviewSet)
        assert result.accepted == ()
        assert result.duplicates_ignored == ()
        assert result.historical == ()
        assert result.conflicts == ()
        assert result.has_conflict is False

    def test_accepted_sorted_by_review_id(self) -> None:
        result = apply_reviews(
            (make_review("r-c"), make_review("r-a"), make_review("r-b")),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="explicit",
        )
        assert [r.review_id for r in result.accepted] == ["r-a", "r-b", "r-c"]
        assert result.has_conflict is False

    @pytest.mark.parametrize("mode", ["explicit", "embedded"])
    def test_both_modes_accept_a_valid_review(self, mode: str) -> None:
        result = apply_reviews(
            (make_review("r-1", occurrences=(OCC_1, OCC_2)),),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode=mode,
        )
        assert [r.review_id for r in result.accepted] == ["r-1"]
        assert result.historical == ()
        assert result.duplicates_ignored == ()

    def test_invalid_mode_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="mode"):
            apply_reviews((), evidence_digest=DELIVERY_DIGEST,
                          occurrence_ids=ALL_OCCURRENCES, mode="auto")

    def test_malformed_evidence_digest_argument_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="evidence_digest"):
            apply_reviews((), evidence_digest="not-a-digest",
                          occurrence_ids=ALL_OCCURRENCES, mode="explicit")

    def test_malformed_occurrence_id_argument_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="occurrence_ids"):
            apply_reviews((), evidence_digest=DELIVERY_DIGEST,
                          occurrence_ids=frozenset({"xyz"}), mode="explicit")

    def test_non_review_item_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="FindingReview"):
            apply_reviews(("r-1",), evidence_digest=DELIVERY_DIGEST,
                          occurrence_ids=ALL_OCCURRENCES, mode="explicit")


# --------------------------------------------------------------------------
# Dedup and duplicate rejection (6.4.5: 同 ID 同字节去重, 不同字节拒绝)
# --------------------------------------------------------------------------


class TestDuplicates:
    def test_same_id_same_bytes_is_deduplicated(self) -> None:
        result = apply_reviews(
            (make_review("r-1"), make_review("r-1")),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="explicit",
        )
        assert [r.review_id for r in result.accepted] == ["r-1"]
        assert result.duplicates_ignored == ("r-1",)

    def test_three_identical_copies_dedup_to_one_entry(self) -> None:
        result = apply_reviews(
            (make_review("r-1"), make_review("r-1"), make_review("r-1")),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="embedded",
        )
        assert [r.review_id for r in result.accepted] == ["r-1"]
        assert result.duplicates_ignored == ("r-1",)

    def test_same_id_different_bytes_rejected(self) -> None:
        with pytest.raises(ReviewValidationError) as excinfo:
            apply_reviews(
                (
                    make_review("r-1", reason="first opinion"),
                    make_review("r-1", reason="second opinion"),
                ),
                evidence_digest=DELIVERY_DIGEST,
                occurrence_ids=ALL_OCCURRENCES,
                mode="explicit",
            )
        codes = rejection_codes(excinfo.value)
        assert codes == {"r-1": "duplicate_id_different_bytes"}

    def test_same_id_different_bytes_rejected_in_embedded_mode_too(self) -> None:
        with pytest.raises(ReviewValidationError) as excinfo:
            apply_reviews(
                (
                    make_review("r-1", decision=ReviewDecision.CONFIRMED_DB_BUG),
                    make_review("r-1", decision=ReviewDecision.EXPECTED_BEHAVIOR),
                ),
                evidence_digest=DELIVERY_DIGEST,
                occurrence_ids=ALL_OCCURRENCES,
                mode="embedded",
            )
        assert rejection_codes(excinfo.value) == {"r-1": "duplicate_id_different_bytes"}


# --------------------------------------------------------------------------
# Occurrence binding (6.4.5: review 必须精确绑定 occurrence)
# --------------------------------------------------------------------------


class TestOccurrenceBinding:
    def test_subset_of_occurrence_ids_is_accepted(self) -> None:
        result = apply_reviews(
            (make_review("r-1", occurrences=(OCC_1,)),),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=frozenset({OCC_1}),
            mode="explicit",
        )
        assert [r.review_id for r in result.accepted] == ["r-1"]

    def test_unknown_occurrence_rejected_in_explicit_mode(self) -> None:
        with pytest.raises(ReviewValidationError) as excinfo:
            apply_reviews(
                (make_review("r-1", occurrences=(OCC_3,)),),
                evidence_digest=DELIVERY_DIGEST,
                occurrence_ids=frozenset({OCC_1, OCC_2}),
                mode="explicit",
            )
        assert rejection_codes(excinfo.value) == {"r-1": "unknown_occurrence"}
        assert "unknown" in excinfo.value.rejections[0].detail

    def test_unknown_occurrence_is_historical_in_embedded_mode(self) -> None:
        # Documented decision: in embedded mode a review whose occurrence
        # binding the current snapshot cannot satisfy was valid against an
        # older snapshot's occurrence set and is shown as history with a
        # detail explaining the unmet binding.
        result = apply_reviews(
            (make_review("r-1", occurrences=(OCC_2, OCC_3)),),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=frozenset({OCC_1, OCC_2}),
            mode="embedded",
        )
        assert result.accepted == ()
        assert len(result.historical) == 1
        entry = result.historical[0]
        assert isinstance(entry, HistoricalReview)
        assert entry.review.review_id == "r-1"
        assert OCC_3 in entry.detail
        assert "older snapshot" in entry.detail


# --------------------------------------------------------------------------
# Digest binding (6.4.5: 旧 review 面对新 evidence 仅显示为历史)
# --------------------------------------------------------------------------


class TestDigestBinding:
    def test_matching_digest_is_accepted(self) -> None:
        result = apply_reviews(
            (make_review("r-1"),),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="explicit",
        )
        assert [r.review_id for r in result.accepted] == ["r-1"]

    def test_mismatched_digest_rejected_in_explicit_mode(self) -> None:
        with pytest.raises(ReviewValidationError) as excinfo:
            apply_reviews(
                (make_review("r-1", digest=OTHER_DIGEST),),
                evidence_digest=DELIVERY_DIGEST,
                occurrence_ids=ALL_OCCURRENCES,
                mode="explicit",
            )
        assert rejection_codes(excinfo.value) == {"r-1": "evidence_digest_mismatch"}

    def test_mismatched_digest_is_historical_in_embedded_mode(self) -> None:
        result = apply_reviews(
            (make_review("r-1", digest=OTHER_DIGEST),),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="embedded",
        )
        assert result.accepted == ()
        assert len(result.historical) == 1
        assert result.historical[0].review.review_id == "r-1"
        assert "history" in result.historical[0].detail

    def test_historical_reviews_are_excluded_from_conflict_evaluation(self) -> None:
        # A historical review must not create a review_conflict with a
        # current review on the same occurrence.
        result = apply_reviews(
            (
                make_review("r-old", digest=OTHER_DIGEST,
                            decision=ReviewDecision.CONFIRMED_DB_BUG),
                make_review("r-new", decision=ReviewDecision.EXPECTED_BEHAVIOR),
            ),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="embedded",
        )
        assert [r.review_id for r in result.accepted] == ["r-new"]
        assert len(result.historical) == 1
        assert result.has_conflict is False


# --------------------------------------------------------------------------
# supersedes (6.4.5: 无环明确继承, 保留前记录, 拒绝悬空/循环/跨证据)
# --------------------------------------------------------------------------


class TestSupersedes:
    def test_valid_chain_keeps_superseded_record_in_accepted_without_conflict(self) -> None:
        # B supersedes A; the two disagree on the same occurrence, but A is
        # superseded so only B survives conflict evaluation.
        result = apply_reviews(
            (
                make_review("r-a", decision=ReviewDecision.CONFIRMED_DB_BUG),
                make_review("r-b", decision=ReviewDecision.EXPECTED_BEHAVIOR,
                            supersedes="r-a"),
            ),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="explicit",
        )
        assert [r.review_id for r in result.accepted] == ["r-a", "r-b"]
        assert result.has_conflict is False
        assert result.conflicts == ()

    def test_dangling_supersedes_rejected(self) -> None:
        with pytest.raises(ReviewValidationError) as excinfo:
            apply_reviews(
                (make_review("r-b", supersedes="r-missing"),),
                evidence_digest=DELIVERY_DIGEST,
                occurrence_ids=ALL_OCCURRENCES,
                mode="explicit",
            )
        assert rejection_codes(excinfo.value) == {"r-b": "dangling_supersedes"}

    def test_supersedes_referencing_historical_review_is_dangling(self) -> None:
        # Cross-evidence scope: the target exists in the provided sequence but
        # binds a different digest, so it is not a current-evidence candidate.
        with pytest.raises(ReviewValidationError) as excinfo:
            apply_reviews(
                (
                    make_review("r-old", digest=OTHER_DIGEST),
                    make_review("r-new", supersedes="r-old"),
                ),
                evidence_digest=DELIVERY_DIGEST,
                occurrence_ids=ALL_OCCURRENCES,
                mode="embedded",
            )
        codes = rejection_codes(excinfo.value)
        assert codes == {"r-new": "dangling_supersedes"}
        assert "cross-evidence" in excinfo.value.rejections[0].detail

    def test_supersedes_referencing_unknown_occurrence_target_is_dangling(self) -> None:
        # Explicit mode: the target is rejected for a bad occurrence binding,
        # so it is not a candidate and the reference dangles.
        with pytest.raises(ReviewValidationError) as excinfo:
            apply_reviews(
                (
                    make_review("r-a", occurrences=(OCC_3,)),
                    make_review("r-b", supersedes="r-a"),
                ),
                evidence_digest=DELIVERY_DIGEST,
                occurrence_ids=frozenset({OCC_1}),
                mode="explicit",
            )
        assert set(rejection_codes(excinfo.value).values()) == {
            "unknown_occurrence",
            "dangling_supersedes",
        }

    def test_self_supersedes_is_blocked_by_the_contract_model(self) -> None:
        # FindingReview.__post_init__ already forbids self-reference, which
        # keeps review.py's defensive self_supersedes branch unreachable for
        # real FindingReview inputs.
        with pytest.raises(ContractError, match="supersedes"):
            make_review("r-a", supersedes="r-a")

    def test_two_review_cycle_rejects_both_participants(self) -> None:
        with pytest.raises(ReviewValidationError) as excinfo:
            apply_reviews(
                (
                    make_review("r-a", supersedes="r-b"),
                    make_review("r-b", supersedes="r-a"),
                ),
                evidence_digest=DELIVERY_DIGEST,
                occurrence_ids=ALL_OCCURRENCES,
                mode="explicit",
            )
        assert rejection_codes(excinfo.value) == {
            "r-a": "supersedes_cycle",
            "r-b": "supersedes_cycle",
        }

    def test_three_review_cycle_rejects_every_participant(self) -> None:
        with pytest.raises(ReviewValidationError) as excinfo:
            apply_reviews(
                (
                    make_review("r-a", supersedes="r-b"),
                    make_review("r-b", supersedes="r-c"),
                    make_review("r-c", supersedes="r-a"),
                ),
                evidence_digest=DELIVERY_DIGEST,
                occurrence_ids=ALL_OCCURRENCES,
                mode="explicit",
            )
        assert set(rejection_codes(excinfo.value).values()) == {"supersedes_cycle"}
        assert len(excinfo.value.rejections) == 3

    def test_chain_terminating_in_existing_review_is_not_a_cycle(self) -> None:
        result = apply_reviews(
            (
                make_review("r-a"),
                make_review("r-b", supersedes="r-a"),
                make_review("r-c", supersedes="r-b"),
            ),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="explicit",
        )
        assert [r.review_id for r in result.accepted] == ["r-a", "r-b", "r-c"]
        assert result.has_conflict is False


# --------------------------------------------------------------------------
# Conflicts (6.4.5: 多个未被替代的互斥决策 -> review_conflict)
# --------------------------------------------------------------------------


class TestConflicts:
    def test_two_active_reviews_disagreeing_on_one_occurrence(self) -> None:
        result = apply_reviews(
            (
                make_review("r-a", decision=ReviewDecision.CONFIRMED_DB_BUG),
                make_review("r-b", decision=ReviewDecision.EXPECTED_BEHAVIOR),
            ),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="explicit",
        )
        assert result.has_conflict is True
        assert len(result.conflicts) == 1
        conflict = result.conflicts[0]
        assert isinstance(conflict, ReviewConflict)
        assert conflict.occurrence_ids == (OCC_1,)
        assert conflict.review_ids == ("r-a", "r-b")
        assert "CONFIRMED_DB_BUG" in conflict.detail
        assert "EXPECTED_BEHAVIOR" in conflict.detail

    def test_conflicts_grouped_per_occurrence(self) -> None:
        result = apply_reviews(
            (
                make_review("r-a", occurrences=(OCC_1, OCC_2),
                            decision=ReviewDecision.CONFIRMED_DB_BUG),
                make_review("r-b", occurrences=(OCC_1,),
                            decision=ReviewDecision.EXPECTED_BEHAVIOR),
                make_review("r-c", occurrences=(OCC_2,),
                            decision=ReviewDecision.TOOL_OR_EVIDENCE_ISSUE),
            ),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="explicit",
        )
        assert result.has_conflict is True
        assert [c.occurrence_ids for c in result.conflicts] == [(OCC_1,), (OCC_2,)]
        by_occ = {c.occurrence_ids[0]: c.review_ids for c in result.conflicts}
        assert by_occ[OCC_1] == ("r-a", "r-b")
        assert by_occ[OCC_2] == ("r-a", "r-c")

    def test_two_reviewers_agreeing_is_not_a_conflict(self) -> None:
        # Documented decision: two humans recording the same decision on one
        # occurrence agree; only distinct decisions conflict.
        result = apply_reviews(
            (
                make_review("r-a", reviewer="alice"),
                make_review("r-b", reviewer="bob"),
            ),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="explicit",
        )
        assert [r.review_id for r in result.accepted] == ["r-a", "r-b"]
        assert result.has_conflict is False

    def test_disjoint_occurrences_do_not_conflict(self) -> None:
        result = apply_reviews(
            (
                make_review("r-a", occurrences=(OCC_1,),
                            decision=ReviewDecision.CONFIRMED_DB_BUG),
                make_review("r-b", occurrences=(OCC_2,),
                            decision=ReviewDecision.EXPECTED_BEHAVIOR),
            ),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="explicit",
        )
        assert result.has_conflict is False

    def test_direct_supersession_without_transitive_veto(self) -> None:
        # Documented decision: supersession is direct only.  A is removed by
        # B and B is removed by C even though B is itself superseded, so only
        # C's decision survives and no conflict is reported.
        result = apply_reviews(
            (
                make_review("r-a", decision=ReviewDecision.CONFIRMED_DB_BUG),
                make_review("r-b", decision=ReviewDecision.EXPECTED_BEHAVIOR,
                            supersedes="r-a"),
                make_review("r-c", decision=ReviewDecision.TOOL_OR_EVIDENCE_ISSUE,
                            supersedes="r-b"),
            ),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="explicit",
        )
        assert [r.review_id for r in result.accepted] == ["r-a", "r-b", "r-c"]
        assert result.has_conflict is False

    def test_superseded_review_only_disagreement_is_no_conflict(self) -> None:
        result = apply_reviews(
            (
                make_review("r-a", decision=ReviewDecision.CONFIRMED_DB_BUG,
                            occurrences=(OCC_1,)),
                make_review("r-b", decision=ReviewDecision.EXPECTED_BEHAVIOR,
                            occurrences=(OCC_2,), supersedes="r-a"),
            ),
            evidence_digest=DELIVERY_DIGEST,
            occurrence_ids=ALL_OCCURRENCES,
            mode="explicit",
        )
        assert result.has_conflict is False

    def test_rejections_aggregate_across_reviews(self) -> None:
        # One run reports every problem: a digest mismatch, an unknown
        # occurrence and a dangling supersedes in the same sequence.
        with pytest.raises(ReviewValidationError) as excinfo:
            apply_reviews(
                (
                    make_review("r-bad-digest", digest=OTHER_DIGEST),
                    make_review("r-bad-occ", occurrences=(OCC_3,)),
                    make_review("r-dangling", supersedes="r-nowhere"),
                ),
                evidence_digest=DELIVERY_DIGEST,
                occurrence_ids=frozenset({OCC_1}),
                mode="explicit",
            )
        assert rejection_codes(excinfo.value) == {
            "r-bad-digest": "evidence_digest_mismatch",
            "r-bad-occ": "unknown_occurrence",
            "r-dangling": "dangling_supersedes",
        }


# --------------------------------------------------------------------------
# Golden: hand-written canonical bytes accepted verbatim
# --------------------------------------------------------------------------


class TestGolden:
    def test_hand_written_canonical_review_is_accepted_exactly(self) -> None:
        # The literal above was transcribed by hand from the frozen Phase 1
        # canonical-JSON contract, not produced by apply_reviews.
        review = decode_finding_review(json.loads(GOLDEN_REVIEW_JSON))
        assert canonical_json(review.to_obj()) == GOLDEN_REVIEW_JSON.encode("utf-8")

        result = apply_reviews(
            (review,),
            evidence_digest=OTHER_DIGEST,
            occurrence_ids=frozenset({OCC_1, OCC_2}),
            mode="explicit",
        )
        assert result.accepted == (review,)
        assert result.has_conflict is False
        assert result.duplicates_ignored == ()
        assert result.historical == ()
