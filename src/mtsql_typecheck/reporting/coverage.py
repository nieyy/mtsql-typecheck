"""Pure coverage/statistics computations for D4 reporting (design 6.4.4).

Every function here is pure: typed inputs in, frozen models out; no file I/O,
no database access, no clock.  The caller reads native manifests, attempt
documents and the rule registry elsewhere and passes them in.

Denominators come from the :class:`~mtsql_typecheck.contracts.case.Profile`
restricted to the static legal combinations of the reviewed rule registry
(:func:`mtsql_typecheck.rules.registry.iter_combinations` or an explicitly
supplied equivalent sequence).  When the profile is missing, a profile rule
cannot be resolved to legal combinations, or case rows span several build
keys, the denominator is unknown: counters stay ``None`` with a reason and no
percentage may ever be computed (design 6.4.4).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Sequence

from ..contracts.case import (
    GenerationManifest,
    GenerationStatus,
    OrdinalOutcome,
    Profile,
)
from ..contracts.runner import RunnerManifest
from ..rules.registry import canonical_type_pair
from .model import (
    RECEIPT_RECHECK_CONSERVED,
    RECEIPT_RECHECK_MISMATCH,
    RECEIPT_RECHECK_NOT_CHECKED,
    AttemptSummary,
    CaseCoverageRow,
    CoverageEntry,
    CoverageSummary,
    ExecutionCounts,
    GenerationCounts,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..rules.registry import RuleCombo

__all__ = [
    "compute_coverage",
    "compute_execution_counts",
    "compute_generation_counts",
]

_COMPARABLE = "comparable"
_IDENTITY = "identity_only"
_EMPTY = "empty_result"
_INCOMPARABLE = "incomparable"


def compute_generation_counts(manifest: GenerationManifest) -> GenerationCounts:
    """Build generation-layer counts and re-check them against receipts (6.4.4).

    The counters are taken from the manifest unchanged -- a receipt mismatch
    keeps the manifest's numbers and is reported through
    ``receipt_recheck="MISMATCH"`` plus a reason, never silently corrected.
    The re-check re-derives the per-outcome receipt counts (EMITTED /
    REJECTED / INTERRUPTED) and the distinct emitted case ids independently
    and compares them with the manifest's own statistics.  A manifest without
    receipts is ``NOT_CHECKED``.

    ``denominator_known`` requires a final status (a RUNNING manifest may
    still attribute more ordinals) and an uncontradicted receipt set.
    """
    receipts = manifest.receipts
    if not receipts:
        recheck = RECEIPT_RECHECK_NOT_CHECKED
        mismatch_reason: str | None = None
    else:
        problems: list[str] = []
        emitted = sum(1 for r in receipts if r.outcome is OrdinalOutcome.EMITTED)
        rejected = sum(1 for r in receipts if r.outcome is OrdinalOutcome.REJECTED)
        interrupted = sum(1 for r in receipts if r.outcome is OrdinalOutcome.INTERRUPTED)
        emitted_case_ids = {
            r.case_id for r in receipts if r.outcome is OrdinalOutcome.EMITTED
        }
        if emitted != manifest.emitted_occurrences:
            problems.append(
                f"receipt EMITTED count {emitted} != manifest emitted_occurrences "
                f"{manifest.emitted_occurrences}"
            )
        if len(emitted_case_ids) != manifest.unique_cases:
            problems.append(
                f"receipt unique emitted case_ids {len(emitted_case_ids)} != manifest "
                f"unique_cases {manifest.unique_cases}"
            )
        if rejected != manifest.rejected_ordinals:
            problems.append(
                f"receipt REJECTED count {rejected} != manifest rejected_ordinals "
                f"{manifest.rejected_ordinals}"
            )
        if interrupted != manifest.interrupted_ordinals:
            problems.append(
                f"receipt INTERRUPTED count {interrupted} != manifest "
                f"interrupted_ordinals {manifest.interrupted_ordinals}"
            )
        if problems:
            recheck = RECEIPT_RECHECK_MISMATCH
            mismatch_reason = "; ".join(problems)
        else:
            recheck = RECEIPT_RECHECK_CONSERVED
            mismatch_reason = None
    denominator_known = (
        manifest.status is not GenerationStatus.RUNNING and recheck != RECEIPT_RECHECK_MISMATCH
    )
    return GenerationCounts(
        requested_ordinals=manifest.requested_ordinals,
        attempted_candidates=manifest.attempted_candidates,
        emitted_occurrences=manifest.emitted_occurrences,
        unique_cases=manifest.unique_cases,
        rejected_ordinals=manifest.rejected_ordinals,
        interrupted_ordinals=manifest.interrupted_ordinals,
        not_attempted=manifest.not_attempted,
        receipt_recheck=recheck,
        receipt_mismatch_reason=mismatch_reason,
        denominator_known=denominator_known,
    )


def compute_execution_counts(
    runner_manifest: RunnerManifest,
    attempt_summaries: Sequence[AttemptSummary],
    *,
    undispatched: int | None = None,
) -> ExecutionCounts:
    """Build execution-layer counts (design 6.4.4 execution row).

    Manifest counters are authoritative for dispatch/completion/candidate
    splits; ``preflight_failures`` is derived from the supplied attempt
    summaries because the runner manifest has no such counter.  Undispatched
    cases are never counted as attempts; the ``undispatched`` number must be
    supplied by a caller that actually knows the un-dispatched part of the
    requested set (for example from the generation unique-case set versus the
    dispatch list).  It is ``None`` by default and never fabricated from the
    difference of partial inputs.
    """
    if undispatched is not None:
        if not isinstance(undispatched, int) or isinstance(undispatched, bool):
            raise TypeError("undispatched must be int or None")
        if undispatched < 0:
            raise ValueError("undispatched must be >= 0")
    summaries = tuple(attempt_summaries)
    for summary in summaries:
        if not isinstance(summary, AttemptSummary):
            raise TypeError(
                f"attempt_summaries must hold AttemptSummary items, got "
                f"{type(summary).__name__}"
            )
    preflight_failures = sum(
        1 for summary in summaries if summary.status == "PREFLIGHT_FAILURE"
    )
    return ExecutionCounts(
        requested_attempts=runner_manifest.requested,
        completed_both_selects=runner_manifest.completed,
        match_candidates=runner_manifest.candidate,
        not_applicable=runner_manifest.not_applicable,
        undecidable=runner_manifest.inconclusive,
        preflight_failures=preflight_failures,
        undispatched=undispatched,
    )


def _classify_cases(rows: Sequence[CaseCoverageRow]) -> tuple[dict[str, str], int, int]:
    """Classify each unique case once (design 6.4.4).

    Precedence per case across all of its rows: ``identity_only`` beats
    ``empty_result`` beats ``comparable``; an identity transform or empty
    result observed for a case holds it out of non-trivial coverage even if
    another row claims comparability (contradictory rows keep the conservative
    classification).  Cases with no qualifying row are incomparable.
    """
    by_case: dict[str, list] = {}
    for row in rows:
        by_case.setdefault(row.case_id, []).append(row)
    classification: dict[str, str] = {}
    for case_id, case_rows in by_case.items():
        if any(row.identity_only for row in case_rows):
            classification[case_id] = _IDENTITY
        elif any(row.empty_result for row in case_rows):
            classification[case_id] = _EMPTY
        elif any(row.comparable for row in case_rows):
            classification[case_id] = _COMPARABLE
        else:
            classification[case_id] = _INCOMPARABLE
    identity_only_cases = sum(1 for c in classification.values() if c == _IDENTITY)
    empty_result_cases = sum(1 for c in classification.values() if c == _EMPTY)
    return classification, identity_only_cases, empty_result_cases


def compute_coverage(
    profile: Profile | None,
    registry_combos: Sequence["RuleCombo"],
    case_index: Sequence[CaseCoverageRow],
) -> CoverageSummary:
    """Compute unique-case coverage against static legal combinations (6.4.4).

    ``registry_combos`` is the static legal combination enumeration of the
    reviewed rule registry (``rules.registry.iter_combinations()`` or an
    explicitly supplied equivalent); this function never mutates or extends
    it.  The denominator of one rule version is the number of its legal
    combinations restricted to the profile's templates and index variants
    (supported type pairs x templates x variants); it is attached only to
    entries whose own combination is legal and inside the profile.

    Case rows are deduplicated by ``case_id``: a case observed through two
    attempts counts once for coverage while remaining two rows of work.
    Rows with different ``build_key`` values never merge into one denominator:
    with several build keys the summary reports the denominator as unknown
    instead of combining environments/builds/profiles.  ``profile=None`` (or
    an unrestorable requested set) also forces an unknown denominator; no
    percentage is computable in any of those states.
    """
    rows = tuple(case_index)
    for row in rows:
        if not isinstance(row, CaseCoverageRow):
            raise TypeError(
                f"case_index must hold CaseCoverageRow items, got {type(row).__name__}"
            )

    classification, identity_only_cases, empty_result_cases = _classify_cases(rows)

    build_keys = sorted({row.build_key for row in rows})
    multi_build = len(build_keys) > 1

    # Group comparable unique cases per (build, rule, pair, template, variant).
    group_cases: dict[tuple[str, str, int, str, str, str], set[str]] = {}
    for row in rows:
        if classification[row.case_id] != _COMPARABLE:
            continue
        key = (
            row.build_key,
            row.rule_id,
            row.rule_version,
            row.type_pair,
            row.template,
            row.index_variant,
        )
        group_cases.setdefault(key, set()).add(row.case_id)

    # Static legal combinations per profile rule version.  With several build
    # keys the denominators stay unknown: they must never be merged across
    # environments/builds/profiles (design 6.4.4).
    legal: dict[tuple[str, int], set[tuple[str, str, str]]] = {}
    unresolvable: list[str] = []
    if profile is not None and not multi_build:
        profile_templates = {str(template.value) for template in profile.templates}
        profile_variants = {str(variant.value) for variant in profile.index_variants}
        for selector in profile.rules:
            combos = {
                (
                    canonical_type_pair(combo.a_type, combo.b_type),
                    str(combo.template_id.value),
                    str(combo.index_variant.value),
                )
                for combo in registry_combos
                if combo.rule_id == selector.rule_id
                and combo.rule_version == selector.rule_version
                and str(combo.template_id.value) in profile_templates
                and str(combo.index_variant.value) in profile_variants
            }
            legal[(selector.rule_id, selector.rule_version)] = combos
            if not combos:
                unresolvable.append(f"{selector.rule_id} v{selector.rule_version}")

    entries: list[CoverageEntry] = []
    off_legal: list[str] = []
    for key in sorted(group_cases):
        build_key, rule_id, rule_version, type_pair, template, index_variant = key
        entry_denominator: int | None = None
        rule_legal = legal.get((rule_id, rule_version))
        if rule_legal and (type_pair, template, index_variant) in rule_legal:
            entry_denominator = len(rule_legal)
        elif profile is not None:
            off_legal.append(f"{rule_id} v{rule_version} [{type_pair}/{template}/{index_variant}]")
        entries.append(
            CoverageEntry(
                rule_id=rule_id,
                rule_version=rule_version,
                type_pair=type_pair,
                template=template,
                index_variant=index_variant,
                comparable_unique_cases=len(group_cases[key]),
                denominator=entry_denominator,
                build_key=build_key if multi_build else None,
            )
        )

    unknown_reason: str | None = None
    if profile is None:
        unknown_reason = (
            "no profile available; the requested rule/template/index combination "
            "set cannot be restored"
        )
    elif multi_build:
        unknown_reason = (
            "case rows span multiple build keys ("
            + ", ".join(build_keys)
            + "); coverage denominators are not merged across environments/"
            "builds/profiles (design 6.4.4)"
        )
    elif unresolvable:
        unknown_reason = (
            "profile rule(s) not resolvable to static legal combinations in the "
            "supplied registry: " + ", ".join(sorted(unresolvable))
        )
    elif off_legal:
        unknown_reason = (
            "observed combination(s) outside the profile/registry legal set: "
            + "; ".join(sorted(off_legal))
        )
    denominator_known = unknown_reason is None
    return CoverageSummary(
        entries=tuple(entries),
        denominator_known=denominator_known,
        unknown_reason=unknown_reason,
        identity_only_cases=identity_only_cases,
        empty_result_cases=empty_result_cases,
    )
