"""Unit tests for reporting coverage/count computations (design 6.4.4).

All inputs are hand-built typed objects; the golden denominators are
hand-derived from the reviewed registry's declared supported type pairs
(decimal-widen: 3 pairs, signed-widen: 4 pairs -- read from the rule
definitions, never recomputed by the function under test).
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from mtsql_typecheck.contracts.case import (
    GenerationManifest,
    GenerationStatus,
    IndexVariant,
    OrdinalOutcome,
    OrdinalReceipt,
    Profile,
    RuleSelector,
    SemverIdentity,
    SignedIntName,
    SignedIntegerType,
    TemplateId,
)
from mtsql_typecheck.contracts.runner import (
    RUNNER_EVIDENCE_PROFILE,
    RunnerCommand,
    RunnerManifest,
    RunnerStatus,
)
from mtsql_typecheck.reporting.coverage import (
    compute_coverage,
    compute_execution_counts,
    compute_generation_counts,
)
from mtsql_typecheck.reporting.model import (
    RECEIPT_RECHECK_CONSERVED,
    RECEIPT_RECHECK_MISMATCH,
    RECEIPT_RECHECK_NOT_CHECKED,
    AttemptSummary,
    CaseCoverageRow,
)
from mtsql_typecheck.rules.registry import canonical_type_pair, iter_combinations

# --------------------------------------------------------------------------
# Frozen fixture constants
# --------------------------------------------------------------------------

CASE_A = "aa" * 32
CASE_B = "bb" * 32
CASE_C = "cc" * 32
CASE_D = "dd" * 32
PROFILE_HASH = "11" * 32
DIGEST_UNKNOWN = "22" * 32


def _int(name: SignedIntName) -> SignedIntegerType:
    return SignedIntegerType(name)


def _profile(
    *rules: RuleSelector,
    templates: tuple[TemplateId, ...] = (TemplateId.Q1, TemplateId.Q2),
) -> Profile:
    return Profile(
        rules=rules,
        templates=templates,
        # StrEnum ASCII order: "ix_v" sorts before "none".
        index_variants=(IndexVariant.IX_V, IndexVariant.NONE),
        row_count=8,
        predicate_atoms=1,
        attempts_per_ordinal=2,
        max_payload_bytes=65536,
        max_bundle_bytes=1 << 20,
    )


def _manifest(**overrides: object) -> GenerationManifest:
    fields: dict[str, object] = {
        "profile_hash": PROFILE_HASH,
        "seed": 1,
        "requested_ordinals": 4,
        "attempted_candidates": 4,
        "emitted_occurrences": 2,
        "unique_cases": 2,
        "rejected_ordinals": 1,
        "interrupted_ordinals": 1,
        "not_attempted": 0,
        "status": GenerationStatus.COMPLETE,
        "generator": SemverIdentity("g1", "1"),
    }
    fields.update(overrides)
    return GenerationManifest(**fields)  # type: ignore[arg-type]


def _receipts() -> tuple[OrdinalReceipt, ...]:
    return (
        OrdinalReceipt(0, OrdinalOutcome.EMITTED, CASE_A),
        OrdinalReceipt(1, OrdinalOutcome.EMITTED, CASE_B),
        OrdinalReceipt(2, OrdinalOutcome.REJECTED),
        OrdinalReceipt(3, OrdinalOutcome.INTERRUPTED),
    )


def _runner_manifest(**overrides: object) -> RunnerManifest:
    fields: dict[str, object] = {
        "command": RunnerCommand.RUN,
        "run_id": "run-1",
        "status": RunnerStatus.COMPLETE,
        "requested": 5,
        "completed": 4,
        "comparable": 2,
        "match": 1,
        "candidate": 1,
        "inconclusive": 1,
        "not_applicable": 1,
        "leftover_objects": 0,
        "leftover_sessions": 0,
        "synthetic": False,
        "evidence_profile": RUNNER_EVIDENCE_PROFILE,
        "tool_version": "d3/1",
        "contract_versions": (
            ("case", "1"),
            ("execution", "1"),
            ("oracle", "1"),
            ("runner", "1"),
        ),
        "refs": (),
        "sanitized_config_hash": DIGEST_UNKNOWN,
    }
    fields.update(overrides)
    return RunnerManifest(**fields)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Generation counts: receipt re-check
# --------------------------------------------------------------------------


class TestGenerationCounts:
    def test_conserved_receipts_reproduce_manifest(self) -> None:
        manifest = _manifest(receipts=_receipts())
        counts = compute_generation_counts(manifest)
        # Independently re-derived by hand: 2 EMITTED / 1 REJECTED / 1
        # INTERRUPTED receipts, two distinct emitted case ids.
        assert counts.receipt_recheck == RECEIPT_RECHECK_CONSERVED
        assert counts.receipt_mismatch_reason is None
        assert counts.requested_ordinals == 4
        assert counts.emitted_occurrences == 2
        assert counts.unique_cases == 2
        assert counts.rejected_ordinals == 1
        assert counts.interrupted_ordinals == 1
        assert counts.not_attempted == 0
        assert counts.attempted_candidates == 4
        assert counts.denominator_known is True

    def test_not_attempted_ordinals_carry_no_receipt(self) -> None:
        manifest = _manifest(
            requested_ordinals=4,
            emitted_occurrences=1,
            unique_cases=1,
            rejected_ordinals=0,
            interrupted_ordinals=0,
            not_attempted=3,
            receipts=(OrdinalReceipt(0, OrdinalOutcome.EMITTED, CASE_A),),
        )
        counts = compute_generation_counts(manifest)
        assert counts.receipt_recheck == RECEIPT_RECHECK_CONSERVED
        assert counts.not_attempted == 3
        assert counts.denominator_known is True

    def test_receipt_disagreement_is_mismatch_with_reason(self) -> None:
        # Manifest claims 3 emitted / 1 rejected, but only 2 EMITTED and 1
        # REJECTED receipts exist (conservation still holds on the manifest).
        manifest = _manifest(
            requested_ordinals=5,
            emitted_occurrences=3,
            unique_cases=2,
            receipts=_receipts(),
        )
        counts = compute_generation_counts(manifest)
        assert counts.receipt_recheck == RECEIPT_RECHECK_MISMATCH
        assert counts.receipt_mismatch_reason is not None
        assert "EMITTED" in counts.receipt_mismatch_reason
        # Manifest numbers are kept, not silently corrected.
        assert counts.emitted_occurrences == 3
        assert counts.unique_cases == 2
        # A contradicted counter set is not a trustworthy denominator.
        assert counts.denominator_known is False

    def test_unique_case_mismatch_is_reported(self) -> None:
        manifest = _manifest(
            unique_cases=1,
            receipts=_receipts(),  # two distinct emitted case ids
        )
        counts = compute_generation_counts(manifest)
        assert counts.receipt_recheck == RECEIPT_RECHECK_MISMATCH
        assert counts.receipt_mismatch_reason is not None
        assert "case_ids" in counts.receipt_mismatch_reason

    def test_no_receipts_means_not_checked(self) -> None:
        counts = compute_generation_counts(_manifest(receipts=()))
        assert counts.receipt_recheck == RECEIPT_RECHECK_NOT_CHECKED
        assert counts.receipt_mismatch_reason is None
        assert counts.denominator_known is True

    def test_running_manifest_has_no_known_denominator(self) -> None:
        # RUNNING manifests are not required to conserve ordinals yet.
        manifest = GenerationManifest(
            profile_hash=PROFILE_HASH,
            seed=1,
            requested_ordinals=3,
            attempted_candidates=2,
            emitted_occurrences=2,
            unique_cases=2,
            rejected_ordinals=0,
            interrupted_ordinals=0,
            not_attempted=0,
            status=GenerationStatus.RUNNING,
            generator=SemverIdentity("g1", "1"),
            receipts=(
                OrdinalReceipt(0, OrdinalOutcome.EMITTED, CASE_A),
                OrdinalReceipt(1, OrdinalOutcome.EMITTED, CASE_B),
            ),
        )
        counts = compute_generation_counts(manifest)
        assert counts.receipt_recheck == RECEIPT_RECHECK_CONSERVED
        assert counts.denominator_known is False

    def test_negative_counts_rejected(self) -> None:
        with pytest.raises(ValueError):
            replace(compute_generation_counts(_manifest()), requested_ordinals=-1)


# --------------------------------------------------------------------------
# Execution counts
# --------------------------------------------------------------------------

_SUMMARIES = (
    AttemptSummary("att-1", True, "MATCH_CANDIDATE"),
    AttemptSummary("att-2", True, "COMPLETED"),
    AttemptSummary("att-3", False, "NOT_APPLICABLE"),
    AttemptSummary("att-4", None, "UNDECIDABLE"),
    AttemptSummary("att-5", None, "PREFLIGHT_FAILURE"),
)


class TestExecutionCounts:
    def test_preflight_failures_stay_separate(self) -> None:
        counts = compute_execution_counts(_runner_manifest(), _SUMMARIES)
        assert counts.preflight_failures == 1
        assert counts.completed_both_selects == 4
        assert counts.match_candidates == 1
        assert counts.not_applicable == 1
        assert counts.undecidable == 1
        # Preflight failures are not folded into completed or undecidable.
        assert counts.completed_both_selects + counts.undecidable + counts.not_applicable != 5

    def test_undispatched_cases_are_never_attempts(self) -> None:
        counts = compute_execution_counts(_runner_manifest(), _SUMMARIES)
        assert counts.requested_attempts == 5
        assert counts.undispatched is None  # never fabricated from partial input
        supplied = compute_execution_counts(_runner_manifest(), _SUMMARIES, undispatched=2)
        assert supplied.undispatched == 2
        # Even with undispatched cases, requested_attempts counts dispatches only.
        assert supplied.requested_attempts == 5

    def test_invalid_inputs_rejected(self) -> None:
        with pytest.raises(ValueError):
            AttemptSummary("att-1", None, "DISPATCHED")
        with pytest.raises(ValueError):
            AttemptSummary("", None, "COMPLETED")
        with pytest.raises(ValueError):
            compute_execution_counts(_runner_manifest(), _SUMMARIES, undispatched=-1)
        with pytest.raises(TypeError):
            compute_execution_counts(_runner_manifest(), ("att-1",))  # type: ignore[list-item]


# --------------------------------------------------------------------------
# Coverage
# --------------------------------------------------------------------------


def _rows_for_all_combos(
    rule: str,
    version: int,
    build_key: str = "build-a",
    templates: tuple[TemplateId, ...] = (TemplateId.Q1, TemplateId.Q2),
) -> list[CaseCoverageRow]:
    """One comparable row per static legal combo of one rule (test input)."""
    rows = []
    for combo in iter_combinations():
        if combo.rule_id != rule or combo.rule_version != version:
            continue
        if combo.template_id not in templates:
            continue
        rows.append(
            CaseCoverageRow(
                case_id=CASE_A,
                rule_id=combo.rule_id,
                rule_version=combo.rule_version,
                type_pair=canonical_type_pair(combo.a_type, combo.b_type),
                template=str(combo.template_id.value),
                index_variant=str(combo.index_variant.value),
                comparable=True,
                identity_only=False,
                empty_result=False,
                build_key=build_key,
            )
        )
    return rows


def _row(case_id: str, combo_index: int, rule: str, **overrides: object) -> CaseCoverageRow:
    combo = iter_combinations()[combo_index]
    assert combo.rule_id == rule
    fields: dict[str, object] = {
        "case_id": case_id,
        "rule_id": combo.rule_id,
        "rule_version": combo.rule_version,
        "type_pair": canonical_type_pair(combo.a_type, combo.b_type),
        "template": str(combo.template_id.value),
        "index_variant": str(combo.index_variant.value),
        "comparable": True,
        "identity_only": False,
        "empty_result": False,
        "build_key": "build-a",
    }
    fields.update(overrides)
    return CaseCoverageRow(**fields)  # type: ignore[arg-type]


class TestCoverageDenominator:
    def test_denominator_equals_static_legal_combinations(self) -> None:
        # Hand-derived golden: within templates {Q1, Q2} and both index
        # variants, decimal-widen supports 3 type pairs -> 3*2*2 = 12 legal
        # combos; signed-widen supports 4 type pairs -> 4*2*2 = 16.
        profile = _profile(
            RuleSelector("mysql80.decimal-widen", 1),
            RuleSelector("mysql80.signed-widen", 1),
        )
        rows = _rows_for_all_combos("mysql80.decimal-widen", 1)
        rows += _rows_for_all_combos("mysql80.signed-widen", 1)
        summary = compute_coverage(profile, iter_combinations(), rows)
        assert summary.denominator_known is True
        assert summary.unknown_reason is None
        assert summary.identity_only_cases == 0
        assert summary.empty_result_cases == 0
        by_rule = {entry.rule_id: entry for entry in summary.entries}
        assert by_rule["mysql80.decimal-widen"].denominator == 12
        assert by_rule["mysql80.signed-widen"].denominator == 16
        assert all(entry.build_key is None for entry in summary.entries)

    def test_profile_restricts_denominator_to_its_templates(self) -> None:
        profile = _profile(
            RuleSelector("mysql80.signed-add-sub", 1), templates=(TemplateId.Q4,)
        )
        rows = _rows_for_all_combos(
            "mysql80.signed-add-sub", 1, templates=(TemplateId.Q4,)
        )
        summary = compute_coverage(profile, iter_combinations(), rows)
        # signed-add-sub: 4 pairs x 1 template (Q4) x 2 variants = 8.
        assert summary.entries[0].denominator == 8
        assert summary.denominator_known is True

    def test_identity_and_empty_cases_are_separate_counters(self) -> None:
        profile = _profile(RuleSelector("mysql80.decimal-widen", 1))
        rows = [
            _row(CASE_A, 0, "mysql80.decimal-widen"),
            _row(CASE_B, 0, "mysql80.decimal-widen", comparable=False, identity_only=True),
            _row(CASE_C, 0, "mysql80.decimal-widen", comparable=False, empty_result=True),
        ]
        summary = compute_coverage(profile, iter_combinations(), rows)
        assert len(summary.entries) == 1
        entry = summary.entries[0]
        # Only CASE_A counts as non-trivial comparable coverage.
        assert entry.comparable_unique_cases == 1
        assert summary.identity_only_cases == 1
        assert summary.empty_result_cases == 1
        assert entry.denominator == 12

    def test_missing_profile_means_unknown_denominator(self) -> None:
        rows = [_row(CASE_A, 0, "mysql80.decimal-widen")]
        summary = compute_coverage(None, iter_combinations(), rows)
        assert summary.denominator_known is False
        assert summary.unknown_reason
        assert all(entry.denominator is None for entry in summary.entries)

    def test_unknown_profile_rule_means_unknown_denominator(self) -> None:
        profile = _profile(RuleSelector("mysql80.future-rule", 7))
        rows = [_row(CASE_A, 0, "mysql80.decimal-widen")]
        summary = compute_coverage(profile, iter_combinations(), rows)
        assert summary.denominator_known is False
        assert summary.unknown_reason is not None
        assert "mysql80.future-rule" in summary.unknown_reason
        assert all(entry.denominator is None for entry in summary.entries)

    def test_two_build_keys_never_share_a_denominator(self) -> None:
        profile = _profile(RuleSelector("mysql80.decimal-widen", 1))
        rows = [
            _row(CASE_A, 0, "mysql80.decimal-widen", build_key="build-a"),
            _row(CASE_B, 0, "mysql80.decimal-widen", build_key="build-b"),
        ]
        summary = compute_coverage(profile, iter_combinations(), rows)
        assert summary.denominator_known is False
        assert summary.unknown_reason is not None
        assert "build" in summary.unknown_reason
        assert len(summary.entries) == 2
        # No entry carries a denominator, and each keeps its own build key.
        assert all(entry.denominator is None for entry in summary.entries)
        assert {entry.build_key for entry in summary.entries} == {"build-a", "build-b"}

    def test_single_build_key_collapses_to_none(self) -> None:
        profile = _profile(RuleSelector("mysql80.decimal-widen", 1))
        rows = [_row(CASE_A, 0, "mysql80.decimal-widen", build_key="build-a")]
        summary = compute_coverage(profile, iter_combinations(), rows)
        assert summary.entries[0].build_key is None
        assert summary.denominator_known is True

    def test_combination_outside_legal_set_blocks_denominator(self) -> None:
        profile = _profile(RuleSelector("mysql80.decimal-widen", 1))
        rows = [_row(CASE_A, 0, "mysql80.decimal-widen", type_pair="[not-a-pair]")]
        summary = compute_coverage(profile, iter_combinations(), rows)
        assert summary.denominator_known is False
        assert summary.unknown_reason is not None
        assert "outside" in summary.unknown_reason
        assert summary.entries[0].denominator is None


class TestCoverageCaseDedup:
    def test_same_case_two_attempts_counts_once_for_coverage(self) -> None:
        # Two attempts of the same case: two rows of work, one unique case.
        profile = _profile(RuleSelector("mysql80.decimal-widen", 1))
        rows = [
            _row(CASE_A, 0, "mysql80.decimal-widen"),
            _row(CASE_A, 0, "mysql80.decimal-widen"),
        ]
        assert len(rows) == 2  # work: two execution rows
        summary = compute_coverage(profile, iter_combinations(), rows)
        assert len(summary.entries) == 1
        assert summary.entries[0].comparable_unique_cases == 1

    def test_distinct_cases_in_same_combo_accumulate(self) -> None:
        profile = _profile(RuleSelector("mysql80.decimal-widen", 1))
        rows = [
            _row(CASE_A, 0, "mysql80.decimal-widen"),
            _row(CASE_B, 0, "mysql80.decimal-widen"),
            _row(CASE_C, 1, "mysql80.decimal-widen"),
        ]
        summary = compute_coverage(profile, iter_combinations(), rows)
        entries = {(e.type_pair, e.template, e.index_variant): e for e in summary.entries}
        first = (rows[0].type_pair, rows[0].template, rows[0].index_variant)
        assert entries[first].comparable_unique_cases == 2

    def test_identity_row_in_another_combo_does_not_poison_other_combo(self) -> None:
        profile = _profile(RuleSelector("mysql80.decimal-widen", 1))
        rows = [
            _row(CASE_A, 0, "mysql80.decimal-widen"),
            _row(CASE_B, 2, "mysql80.decimal-widen", identity_only=True, comparable=False),
        ]
        summary = compute_coverage(profile, iter_combinations(), rows)
        assert summary.identity_only_cases == 1
        first = (rows[0].type_pair, rows[0].template, rows[0].index_variant)
        entry_first = next(
            e
            for e in summary.entries
            if (e.type_pair, e.template, e.index_variant) == first
        )
        assert entry_first.comparable_unique_cases == 1


class TestCoverageValidation:
    def test_invalid_row_rejected(self) -> None:
        with pytest.raises(ValueError):
            CaseCoverageRow(
                case_id=CASE_A,
                rule_id="mysql80.decimal-widen",
                rule_version=1,
                type_pair="x",
                template="Q1",
                index_variant="none",
                comparable=True,
                identity_only=False,
                empty_result=False,
                build_key="",
            )
        with pytest.raises(TypeError):
            CaseCoverageRow(
                case_id=CASE_A,
                rule_id="mysql80.decimal-widen",
                rule_version=1,
                type_pair="x",
                template="Q1",
                index_variant="none",
                comparable="yes",  # type: ignore[arg-type]
                identity_only=False,
                empty_result=False,
                build_key="b",
            )
        with pytest.raises(TypeError):
            compute_coverage(None, iter_combinations(), ("not-a-row",))  # type: ignore[list-item]

    def test_no_percent_fields_exist(self) -> None:
        # Design 6.4.4: unknown denominators must not be turned into percentages.
        from mtsql_typecheck.reporting import model

        for name in dir(model):
            assert "percent" not in name.lower() or name.startswith("_")
