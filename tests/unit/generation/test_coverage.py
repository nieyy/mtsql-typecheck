"""G02: coverage and accounting tests for the deterministic generator.

The profile selector filters rules/templates/index variants; type pairs are
not selectable, so the smallest reachable combination set is N=2 (the
integer-decimal rule restricted to one template and one index variant).  The
slot-cycle property is asserted for that N=2 profile over N*20=40 ordinals
with hand-computed slot assignments, and for the default profile over
62*20=1240 ordinals.

Slot schedule (frozen g1 behavior, design 6.4.1 step 3): with N combinations,
``combo_index = ordinal % N``, ``visit = ordinal // N``,
``slot = (visit + combo_index) % 20``; slot 18 -> empty, slot 19 -> all-NULL.
For the N=2 profile this gives, hand-computed:
combo 0 (even ordinals): empty at ordinal 36 (visit 18), all-NULL at 38;
combo 1 (odd ordinals):  empty at ordinal 35 (visit 17), all-NULL at 37.
"""

from __future__ import annotations

from collections import Counter, defaultdict

import pytest

from mtsql_typecheck.contracts.case import (
    IndexVariant,
    Profile,
    RuleSelector,
    TemplateId,
)
from mtsql_typecheck.generation.generator import (
    ALL_NULL_SLOT,
    EMPTY_SLOT,
    SLOTS_PER_COMBO,
    default_profile,
    generate_cases,
    profile_hash,
    resolve_combinations,
)

COMBO_COUNT = 62  # 31 rule/type-pair/template combos x 2 index variants


def _small_profile(template: TemplateId, **overrides: object) -> Profile:
    values: dict[str, object] = {
        "rules": (RuleSelector("mysql80.integer-decimal", 1),),
        "templates": (template,),
        "index_variants": (IndexVariant.NONE,),
        "row_count": 32,
        "predicate_atoms": 1,
        "attempts_per_ordinal": 8,
        "max_payload_bytes": 1024 * 1024,
        "max_bundle_bytes": 256 * 1024 * 1024,
    }
    values.update(overrides)
    return Profile(**values)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def default_result():
    """One default-profile run over 62*20 ordinals, shared by several tests."""
    profile = default_profile()
    assert len(resolve_combinations(profile)) == COMBO_COUNT
    return generate_cases(profile, 42, COMBO_COUNT * SLOTS_PER_COMBO)


# --------------------------------------------------------------------------
# Slot cycle on the smallest reachable combination set (N=2)
# --------------------------------------------------------------------------


def test_smallest_profile_slot_cycle_over_40_ordinals() -> None:
    profile = _small_profile(TemplateId.Q1)
    assert len(resolve_combinations(profile)) == 2
    result = generate_cases(profile, 42, 40)
    assert result.status.value == "COMPLETE"
    assert result.rejected == 0

    # Hand-computed slot assignments for N=2 (see module docstring).
    assert result.records[36].input_class == "empty"
    assert result.records[38].input_class == "all_null"
    assert result.records[35].input_class == "empty"
    assert result.records[37].input_class == "all_null"

    per_combo: dict[int, Counter] = defaultdict(Counter)
    for record in result.records:
        per_combo[record.combo_index][record.input_class] += 1
    assert len(per_combo) == 2
    for combo_index in (0, 1):
        assert per_combo[combo_index]["normal"] == 18
        assert per_combo[combo_index]["empty"] == 1
        assert per_combo[combo_index]["all_null"] == 1

    # The two integer-decimal type pairs, one template, one index variant.
    assert {record.rule_id for record in result.records} == {"mysql80.integer-decimal"}
    assert {record.template_id for record in result.records} == {"Q1"}
    assert {record.index_variant for record in result.records} == {"none"}

    # Row counts by class: normal=32, empty=0, all_null=32 NULL-only rows.
    for record in result.records:
        if record.input_class == "normal":
            assert record.row_count == 32
            assert "null" in record.value_categories
            assert record.value_categories != ("null",)
        elif record.input_class == "empty":
            assert record.row_count == 0
            assert record.value_categories == ()
        else:
            assert record.row_count == 32
            assert record.value_categories == ("null",)
    # Every emitted receipt references a real bundle case_id.
    bundle_ids = {bundle.case_id for bundle in result.bundles}
    for receipt in result.receipts:
        assert receipt.outcome.value == "emitted"
        assert receipt.case_id in bundle_ids


def test_row_count_zero_profile_marks_every_ordinal_empty() -> None:
    profile = _small_profile(TemplateId.Q1, row_count=0)
    result = generate_cases(profile, 42, 20)
    assert result.status.value == "COMPLETE"
    assert {record.input_class for record in result.records} == {"empty"}
    assert all(record.row_count == 0 for record in result.records)
    assert all(record.value_categories == () for record in result.records)
    # Empty inputs are still emitted cases with receipts, not rejections.
    assert result.emitted_occurrences == 20
    assert result.rejected == 0
    assert all(len(bundle.payload.rows.rows) == 0 for bundle in result.bundles)


def test_row_count_one_normal_case_contains_non_null_zero() -> None:
    profile = _small_profile(TemplateId.Q1, row_count=1)
    result = generate_cases(profile, 42, 40)
    normals = [record for record in result.records if record.input_class == "normal"]
    assert len(normals) == 36  # 18 per combo x 2 combos
    assert all(record.row_count == 1 for record in normals)
    # The 1-row dictionary prefix is exactly the non-NULL zero.
    assert all(record.value_categories == ("zero",) for record in normals)
    normal_ids = {record.case_id for record in normals}
    zero_bundles = [
        bundle for bundle in result.bundles if bundle.case_id in normal_ids
    ]
    assert zero_bundles, "unique bundles for normal 1-row cases must exist"
    for bundle in zero_bundles:
        rows = bundle.payload.rows.rows
        assert len(rows) == 1
        assert rows[0].rid == 1
        assert rows[0].value.kind == "integer"
        assert rows[0].value.value == 0  # non-NULL zero (never bool/str/float)

    # All 18 normal ordinals per combo produce the identical 1-row payload,
    # so occurrences collapse onto one unique case per combo: this exercises
    # occurrence accounting without discarding any receipt.
    assert result.emitted_occurrences == 40
    assert result.unique_cases == len(result.bundles)
    assert result.unique_cases <= result.emitted_occurrences
    assert sum(occurrence.count for occurrence in result.occurrences) == (
        result.emitted_occurrences
    )
    emitted_receipts = [
        receipt
        for receipt in result.receipts
        if receipt.outcome.value == "emitted"
    ]
    assert len(emitted_receipts) == result.emitted_occurrences
    per_case = Counter(receipt.case_id for receipt in emitted_receipts)
    assert dict(per_case) == {o.case_id: o.count for o in result.occurrences}


def test_row_count_1024_is_feasible() -> None:
    profile = _small_profile(TemplateId.Q1, row_count=1024)
    result = generate_cases(profile, 42, 6)
    assert result.status.value == "COMPLETE"
    assert result.rejected == 0
    for record in result.records:
        if record.input_class == "normal":
            assert record.row_count == 1024
        elif record.input_class == "empty":
            assert record.row_count == 0
        else:
            assert record.row_count == 1024
    for bundle in result.bundles:
        assert len(bundle.payload.rows.rows) <= 1024
        rids = [row.rid for row in bundle.payload.rows.rows]
        assert rids == list(range(1, len(rids) + 1))


# --------------------------------------------------------------------------
# Default profile: all 62 combinations x 20 visits
# --------------------------------------------------------------------------


def test_default_profile_all_combos_visited_20_times(default_result) -> None:
    result = default_result
    assert len(result.records) == COMBO_COUNT * SLOTS_PER_COMBO
    assert len({record.combo_key for record in result.records}) == COMBO_COUNT
    assert result.status.value == "COMPLETE"
    assert result.rejected == 0
    assert result.not_attempted == 0
    assert result.interrupted == 0

    per_combo: dict[int, Counter] = defaultdict(Counter)
    for record in result.records:
        per_combo[record.combo_index][record.input_class] += 1
    assert len(per_combo) == COMBO_COUNT
    for combo_index in range(COMBO_COUNT):
        assert per_combo[combo_index]["normal"] == SLOTS_PER_COMBO - 2
        assert per_combo[combo_index]["empty"] == 1
        assert per_combo[combo_index]["all_null"] == 1

    # Default row_count=32 always fits the 12-item dictionary, so every
    # normal case carries the full base dictionary plus random fill; only
    # actually-placed categories are recorded.
    base_categories = {
        "zero",
        "null",
        "unit_pos",
        "unit_neg",
        "dup_zero",
        "lower_bound",
        "upper_bound",
        "random",
    }
    for record in result.records:
        if record.input_class == "normal":
            assert base_categories <= set(record.value_categories)
            assert record.row_count == 32
        elif record.input_class == "empty":
            assert record.value_categories == ()
        else:
            assert record.value_categories == ("null",)

    # The 2^53 neighborhood is representable only in some domains; the
    # BIGINT -> DECIMAL(20,0) Q1/Q2 combos have it in their common domain, so
    # it must actually appear among the recorded categories of normal Q1/Q2
    # integer-decimal cases (the narrower INT pair cannot place it).
    int_dec_q1q2 = [
        record
        for record in result.records
        if record.input_class == "normal"
        and record.rule_id == "mysql80.integer-decimal"
        and record.template_id in ("Q1", "Q2")
    ]
    assert int_dec_q1q2
    pow53_records = [
        record
        for record in int_dec_q1q2
        if {"pow53_minus1", "pow53", "pow53_plus1"} <= set(record.value_categories)
    ]
    assert pow53_records, "expected 2^53-neighborhood boundaries for BIGINT->DECIMAL(20,0) Q1/Q2"


def test_default_profile_template_distribution(default_result) -> None:
    result = default_result
    # 9 type pairs (4 signed-widen + 3 decimal-widen + 2 integer-decimal)
    # x 2 variants = 18 combos per Q1/Q2/Q3 template; Q4 belongs only to
    # signed-add-sub (4 pairs x 2 = 8 combos).  x20 visits each.
    counts = Counter(record.template_id for record in result.records)
    assert counts["Q1"] == 18 * SLOTS_PER_COMBO
    assert counts["Q2"] == 18 * SLOTS_PER_COMBO
    assert counts["Q3"] == 18 * SLOTS_PER_COMBO
    assert counts["Q4"] == 8 * SLOTS_PER_COMBO
    # Q1 never carries a predicate; Q2 always does.
    for record in result.records:
        if record.template_id == "Q1":
            assert not record.predicate_present
        elif record.template_id == "Q2":
            assert record.predicate_present
        else:
            assert isinstance(record.predicate_present, bool)


def test_occurrence_and_conservation_accounting(default_result) -> None:
    result = default_result
    manifest = result.manifest
    assert manifest.status.value == "COMPLETE"
    assert result.requested == COMBO_COUNT * SLOTS_PER_COMBO
    assert result.emitted_occurrences == result.requested
    assert result.unique_cases <= result.emitted_occurrences
    assert len(result.bundles) == result.unique_cases
    assert len(result.receipts) == result.requested
    emitted = [r for r in result.receipts if r.outcome.value == "emitted"]
    assert len(emitted) == result.emitted_occurrences
    per_case = Counter(receipt.case_id for receipt in emitted)
    assert dict(per_case) == {o.case_id: o.count for o in result.occurrences}
    assert sum(o.count for o in result.occurrences) == result.emitted_occurrences
    # Conservation: requested = emitted + rejected + interrupted + not_attempted
    assert result.requested == (
        result.emitted_occurrences
        + result.rejected
        + result.interrupted
        + result.not_attempted
    )
    # Attempt accounting: one candidate per ordinal (no retries happened).
    assert result.attempted_candidates == result.requested
    assert all(receipt.retry_count == 0 for receipt in result.receipts)


def test_q4_operator_and_constant_coverage_records(default_result) -> None:
    result = default_result
    q4_records = [record for record in result.records if record.template_id == "Q4"]
    assert len(q4_records) == 8 * SLOTS_PER_COMBO
    ops = Counter(record.arithmetic_op for record in q4_records)
    # Both operators were actually produced (coverage recorded, not assumed).
    assert set(ops) == {"add", "subtract"}
    ks = [record.arithmetic_k for record in q4_records]
    assert all(k is not None for k in ks)
    assert all(-16 <= k <= 16 for k in ks)
    assert any(k > 0 for k in ks)
    assert any(k < 0 for k in ks)
    # Non-Q4 records carry no arithmetic; Q4 records always do.
    for record in result.records:
        if record.template_id == "Q4":
            assert record.arithmetic_op is not None
            assert record.arithmetic_k is not None
        else:
            assert record.arithmetic_op is None
            assert record.arithmetic_k is None


def test_predicate_atom_cap_is_respected() -> None:
    profile = _small_profile(TemplateId.Q2, predicate_atoms=2)
    result = generate_cases(profile, 42, 40)
    atom_counts = Counter(len(record.predicate_ops) for record in result.records)
    assert set(atom_counts) <= {1, 2}
    assert atom_counts[2] > 0, "atom cap 2 must actually produce two-atom predicates"
    assert atom_counts[1] > 0
    vocabulary = {
        "=",
        "<>",
        "<",
        "<=",
        ">",
        ">=",
        "<=>",
        "BETWEEN",
        "IS NULL",
        "IS NOT NULL",
    }
    for record in result.records:
        assert record.predicate_present
        assert set(record.predicate_ops) <= vocabulary
