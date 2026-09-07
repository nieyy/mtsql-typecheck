"""Human review validation and conflict resolution (design 6.4.5).

Pure module: no file I/O, no database access, no clock.  ``apply_reviews``
consumes already-constructed :class:`~mtsql_typecheck.contracts.delivery.FindingReview`
objects plus the current evidence binding (delivery digest and occurrence-id
set) and classifies every review as accepted, deduplicated, historical, or
rejected, then computes :class:`ReviewConflict` items among the surviving
reviews.

Design 6.4.5 rules implemented here:

- 同 review_id 同字节允许去重 (``duplicates_ignored``); 同 ID 不同字节拒绝
  (``duplicate_id_different_bytes``).  Identity is the canonical JSON bytes of
  ``FindingReview.to_obj()`` (``contracts.codec.canonical_json``).
- review 必须精确绑定当前 evidence digest 及 occurrence。旧 review 面对新
  evidence 仅显示为历史，不自动应用 (embedded mode -> ``historical``).
  本次显式提交 (explicit mode) 的错 hash、错 occurrence 属输入错误 ->
  :class:`ReviewValidationError`, which the CLI maps to exit code 2
  (design 6.3: illegal input / bad review).
- supersedes 形成无环明确继承，保留前记录。supersedes must reference another
  review provided in the SAME call and accepted as current-evidence; 拒绝悬空
  (``dangling_supersedes``)、自指 (``self_supersedes``)、循环
  (``supersedes_cycle``)。跨证据替代 (superseding a historical or
  otherwise-rejected record) is therefore rejected as dangling by
  construction: a target that is not a current-evidence candidate of this
  call can never be resolved.
- 多个未被替代的互斥决策 -> ``review_conflict``; 四维原观察不被修改,
  报告保留全部意见, regression 导出拒绝 (handled by callers).

Documented decisions (this project's interpretation of 6.4.5, not paper
facts):

- Embedded mode treats a wrong occurrence binding as historical too, with a
  detail explaining the unmet binding: only a digest mismatch was named by
  the design as the historical case, but a review valid against an older
  snapshot's occurrence set is equally "面对新 evidence" and cannot be
  applied to the current one; silently applying it would violate the exact
  occurrence binding.  Explicit mode rejects it instead (input error).
- Supersession is DIRECT only: a review superseded by any accepted review is
  excluded from conflict evaluation, even if the superseder is itself
  superseded (no transitive veto).  The chain is acyclic (checked), so
  "replace" semantics stay well defined while the retained history remains
  complete in ``accepted``.
- Two surviving reviewers recording the SAME decision on one occurrence is
  agreement, not a conflict; only more than one distinct decision conflicts.
- Rejections are aggregated across the whole provided sequence and raised as
  one :class:`ReviewValidationError` so a single run reports every problem;
  the pinned :class:`ReviewSet` carries no rejection list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Sequence

from mtsql_typecheck.contracts.codec import canonical_json
from mtsql_typecheck.contracts.delivery import FindingReview, ReviewDecision

__all__ = [
    "ReviewRejection",
    "ReviewConflict",
    "HistoricalReview",
    "ReviewSet",
    "ReviewValidationError",
    "apply_reviews",
]

_MODES = ("explicit", "embedded")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------
# Pinned result models (Phase 3 orchestration notes; design 6.4.5)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewRejection:
    """One structurally invalid review; stable lowercase ``reason_code``."""

    review_id: Optional[str]
    reason_code: str
    detail: str


@dataclass(frozen=True)
class ReviewConflict:
    """Disagreeing surviving decisions for one occurrence (6.4.5).

    Conflicts are grouped per occurrence: ``occurrence_ids`` holds exactly one
    occurrence id and ``review_ids`` the sorted ids of the surviving reviews
    binding it.
    """

    occurrence_ids: tuple[str, ...]
    review_ids: tuple[str, ...]
    detail: str


@dataclass(frozen=True)
class HistoricalReview:
    """A review valid against older evidence, shown as history only (6.4.5)."""

    review: FindingReview
    detail: str


@dataclass(frozen=True)
class ReviewSet:
    """Outcome of applying reviews to one evidence snapshot (6.4.5).

    ``accepted`` keeps every current-evidence, binding-valid review including
    superseded ones (前记录保留), sorted by ``review_id``.  Historical reviews
    are never in ``accepted``; superseded reviews are excluded from conflict
    evaluation only.
    """

    accepted: tuple[FindingReview, ...]
    duplicates_ignored: tuple[str, ...]
    historical: tuple[HistoricalReview, ...]
    conflicts: tuple[ReviewConflict, ...]
    has_conflict: bool


class ReviewValidationError(Exception):
    """Aggregated rejections from :func:`apply_reviews`.

    The CLI maps this to exit code 2 (design 6.3: illegal input / bad
    review).  All rejections found across the provided sequence are carried
    in ``rejections`` so one run surfaces every problem.
    """

    def __init__(self, rejections: Sequence[ReviewRejection]) -> None:
        self.rejections: tuple[ReviewRejection, ...] = tuple(rejections)
        joined = "; ".join(
            f"{item.reason_code}[{item.review_id}]: {item.detail}"
            for item in self.rejections
        )
        super().__init__(f"{len(self.rejections)} review rejection(s): {joined}")


# --------------------------------------------------------------------------
# Classification (design 6.4.5)
# --------------------------------------------------------------------------


def _validate_inputs(
    evidence_digest: str, occurrence_ids: "frozenset[str] | set[str]", mode: str
) -> frozenset[str]:
    if mode not in _MODES:
        raise ValueError(
            f"mode must be one of {_MODES}, got {mode!r}"
        )
    if not isinstance(evidence_digest, str) or not _HEX64_RE.match(evidence_digest):
        raise ValueError(
            f"evidence_digest must be a lowercase 64-hex sha256, got {evidence_digest!r}"
        )
    occ_set = frozenset(occurrence_ids)
    for occ in occ_set:
        if not isinstance(occ, str) or not _HEX64_RE.match(occ):
            raise ValueError(
                f"occurrence_ids must hold lowercase 64-hex sha256 ids, got {occ!r}"
            )
    return occ_set


def _is_on_cycle(review_id: str, targets: dict[str, str]) -> bool:
    """Walk the supersedes chain from ``review_id``; True if it returns to it."""
    current = targets.get(review_id)
    seen: set[str] = set()
    while current is not None:
        if current == review_id:
            return True
        if current in seen:
            return False
        seen.add(current)
        current = targets.get(current)
    return False


def apply_reviews(
    reviews: Sequence[FindingReview],
    *,
    evidence_digest: str,
    occurrence_ids: "frozenset[str] | set[str]",
    mode: str,
) -> ReviewSet:
    """Classify reviews against the current evidence and find conflicts.

    See the module docstring for the full rule set and documented decisions.
    Raises :class:`ReviewValidationError` when any review is rejected
    (aggregate of all rejections); raises ``ValueError`` for malformed
    arguments (bad ``mode``, non-hex digest/occurrence ids, non-FindingReview
    items).  Pure: no I/O, no clock.
    """
    occ_set = _validate_inputs(evidence_digest, occurrence_ids, mode)
    if not isinstance(reviews, (tuple, list)):
        raise ValueError("reviews must be a tuple or list of FindingReview items")

    rejections: list[ReviewRejection] = []
    duplicates: set[str] = set()
    seen_bytes: dict[str, bytes] = {}
    historical: list[HistoricalReview] = []
    candidates: list[FindingReview] = []
    provided_ids: set[str] = set()
    historical_ids: set[str] = set()

    # Pass 1: dedup, digest binding, occurrence binding (per review, in order).
    for review in reviews:
        if not isinstance(review, FindingReview):
            raise ValueError(f"reviews must hold FindingReview items, got {type(review)!r}")
        provided_ids.add(review.review_id)
        raw = canonical_json(review.to_obj())
        previous = seen_bytes.get(review.review_id)
        if previous is not None:
            if previous == raw:
                # Same id + identical canonical bytes -> dedup (6.4.5).
                duplicates.add(review.review_id)
                continue
            rejections.append(
                ReviewRejection(
                    review_id=review.review_id,
                    reason_code="duplicate_id_different_bytes",
                    detail=(
                        f"review_id {review.review_id!r} appears multiple times "
                        "with different canonical bytes"
                    ),
                )
            )
            continue
        seen_bytes[review.review_id] = raw
        if review.evidence_digest != evidence_digest:
            if mode == "explicit":
                rejections.append(
                    ReviewRejection(
                        review_id=review.review_id,
                        reason_code="evidence_digest_mismatch",
                        detail=(
                            f"review binds evidence_digest {review.evidence_digest!r}, "
                            f"expected {evidence_digest!r}"
                        ),
                    )
                )
            else:
                historical_ids.add(review.review_id)
                historical.append(
                    HistoricalReview(
                        review=review,
                        detail=(
                            f"review binds evidence_digest {review.evidence_digest!r} "
                            f"but the current delivery digest is {evidence_digest!r}; "
                            "shown as history only, not applied (design 6.4.5)"
                        ),
                    )
                )
            continue
        unknown = sorted(set(review.occurrence_ids) - occ_set)
        if unknown:
            if mode == "explicit":
                rejections.append(
                    ReviewRejection(
                        review_id=review.review_id,
                        reason_code="unknown_occurrence",
                        detail=(
                            "review binds unknown occurrence ids for the current "
                            f"evidence set: {', '.join(unknown)}"
                        ),
                    )
                )
            else:
                # Documented decision: an occurrence binding that the current
                # snapshot cannot satisfy makes the review historical too --
                # it was valid against an older snapshot's occurrence set and
                # must not be silently applied to the new one.
                historical_ids.add(review.review_id)
                historical.append(
                    HistoricalReview(
                        review=review,
                        detail=(
                            "review was valid against an older snapshot: occurrence "
                            f"ids {', '.join(unknown)} are not in the current "
                            "occurrence set; shown as history only, not applied"
                        ),
                    )
                )
            continue
        candidates.append(review)

    # Pass 2: supersedes references must resolve to a current-evidence
    # candidate of this same call; this makes cross-evidence supersedes
    # (historical or rejected target) dangling by construction.
    candidate_by_id = {review.review_id: review for review in candidates}
    supersede_targets: dict[str, str] = {}
    for review in candidates:
        target = review.supersedes
        if target is None:
            continue
        if target == review.review_id:
            # Defensive: FindingReview.__post_init__ already forbids this.
            rejections.append(
                ReviewRejection(
                    review_id=review.review_id,
                    reason_code="self_supersedes",
                    detail=f"review {review.review_id!r} supersedes itself",
                )
            )
            continue
        if target not in candidate_by_id:
            if target in provided_ids or target in historical_ids:
                detail = (
                    f"supersedes target {target!r} exists but is not a "
                    "current-evidence candidate; cross-evidence supersedes "
                    "is rejected (design 6.4.5)"
                )
            else:
                detail = f"supersedes target {target!r} is not among the provided reviews"
            rejections.append(
                ReviewRejection(
                    review_id=review.review_id,
                    reason_code="dangling_supersedes",
                    detail=detail,
                )
            )
            continue
        supersede_targets[review.review_id] = target

    # Pass 3: cycles.  Every participant of a cycle is rejected.
    cyclic_ids = {
        review_id
        for review_id in supersede_targets
        if _is_on_cycle(review_id, supersede_targets)
    }
    for review_id in sorted(cyclic_ids):
        rejections.append(
            ReviewRejection(
                review_id=review_id,
                reason_code="supersedes_cycle",
                detail=(
                    f"review {review_id!r} participates in a supersedes cycle "
                    f"through {supersede_targets[review_id]!r}"
                ),
            )
        )
    if cyclic_ids:
        candidates = [r for r in candidates if r.review_id not in cyclic_ids]
        supersede_targets = {
            k: v for k, v in supersede_targets.items() if k not in cyclic_ids
        }

    accepted = tuple(sorted(candidates, key=lambda r: r.review_id))
    accepted_ids = {r.review_id for r in accepted}

    # Direct supersession only (documented decision): a review superseded by
    # any accepted review is removed from conflict evaluation even when the
    # superseder is itself superseded; no transitive veto.
    superseded_ids = {
        target for source, target in supersede_targets.items() if source in accepted_ids
    }

    by_occurrence: dict[str, list[FindingReview]] = {}
    for review in accepted:
        if review.review_id in superseded_ids:
            continue
        for occ in review.occurrence_ids:
            by_occurrence.setdefault(occ, []).append(review)

    conflicts: list[ReviewConflict] = []
    for occ in sorted(by_occurrence):
        participants = by_occurrence[occ]
        decisions = {review.decision for review in participants}
        if len(decisions) <= 1:
            # Same decision from several reviewers is agreement, not conflict.
            continue
        participants = sorted(participants, key=lambda r: r.review_id)
        review_ids = tuple(review.review_id for review in participants)
        detail = (
            f"occurrence {occ} carries disagreeing decisions from surviving "
            "reviews: "
            + ", ".join(
                f"{review.review_id}={str(review.decision.value)}"
                for review in participants
            )
        )
        conflicts.append(
            ReviewConflict(
                occurrence_ids=(occ,),
                review_ids=review_ids,
                detail=detail,
            )
        )

    if rejections:
        raise ReviewValidationError(rejections)

    return ReviewSet(
        accepted=accepted,
        duplicates_ignored=tuple(sorted(duplicates)),
        historical=tuple(
            sorted(historical, key=lambda item: item.review.review_id)
        ),
        conflicts=tuple(conflicts),
        has_conflict=bool(conflicts),
    )
