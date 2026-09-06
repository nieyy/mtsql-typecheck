"""R01 registry tests: rule definitions, the 31/62 combination matrix, and
domain-legal / illegal cases through the exact-domain checks.

The expected 31 (rule_id, rule_version, A type, B type, template) combos and
all numeric bounds below are hand-written from design 6.2.1/6.4.1; no
expectation is computed by calling the enumeration under test.
"""

from __future__ import annotations

import dataclasses

import pytest

from mtsql_typecheck.contracts import codec
from mtsql_typecheck.contracts.case import (
    Arithmetic,
    ArithmeticOp,
    CheckStatus,
    Compare,
    CompareOp,
    ConditionResult,
    ContractError,
    DecimalType,
    DecimalValue,
    ExactLiteral,
    IndexVariant,
    IntegerValue,
    NullValue,
    Projection,
    QuerySpec,
    ReasonCode,
    Row,
    Rows,
    RuleReviewStatus,
    RuleSpec,
    SignedIntName,
    SignedIntegerType,
    TemplateId,
    TypeSpec,
)
from mtsql_typecheck.rules import exact_numeric
from mtsql_typecheck.rules.registry import (
    DuplicateDefinitionError,
    RuleCombo,
    RuleRegistry,
    RuleRegistryError,
    UnknownRuleError,
    canonical_type_pair,
    combo_key,
    get_rule,
    iter_combinations,
    list_rules,
    register_rule,
)


def _int(name: str) -> SignedIntegerType:
    return SignedIntegerType(SignedIntName(name))


def _dec(precision: int, scale: int) -> DecimalType:
    return DecimalType(precision, scale)


# --------------------------------------------------------------------------
# Hand-written expected combination matrix (31 rule/pair/template combos)
# --------------------------------------------------------------------------

EXPECTED_COMBOS: list[tuple[str, int, TypeSpec, TypeSpec, str]] = [
    # mysql80.decimal-widen: 3 pairs x Q1-Q3 = 9
    ("mysql80.decimal-widen", 1, _dec(18, 6), _dec(30, 6), "Q1"),
    ("mysql80.decimal-widen", 1, _dec(18, 6), _dec(30, 6), "Q2"),
    ("mysql80.decimal-widen", 1, _dec(18, 6), _dec(30, 6), "Q3"),
    ("mysql80.decimal-widen", 1, _dec(20, 0), _dec(30, 0), "Q1"),
    ("mysql80.decimal-widen", 1, _dec(20, 0), _dec(30, 0), "Q2"),
    ("mysql80.decimal-widen", 1, _dec(20, 0), _dec(30, 0), "Q3"),
    ("mysql80.decimal-widen", 1, _dec(9, 2), _dec(18, 2), "Q1"),
    ("mysql80.decimal-widen", 1, _dec(9, 2), _dec(18, 2), "Q2"),
    ("mysql80.decimal-widen", 1, _dec(9, 2), _dec(18, 2), "Q3"),
    # mysql80.integer-decimal: 2 pairs x Q1-Q3 = 6
    ("mysql80.integer-decimal", 1, _int("BIGINT"), _dec(20, 0), "Q1"),
    ("mysql80.integer-decimal", 1, _int("BIGINT"), _dec(20, 0), "Q2"),
    ("mysql80.integer-decimal", 1, _int("BIGINT"), _dec(20, 0), "Q3"),
    ("mysql80.integer-decimal", 1, _int("INT"), _dec(12, 0), "Q1"),
    ("mysql80.integer-decimal", 1, _int("INT"), _dec(12, 0), "Q2"),
    ("mysql80.integer-decimal", 1, _int("INT"), _dec(12, 0), "Q3"),
    # mysql80.signed-add-sub: 4 pairs x Q4 = 4
    ("mysql80.signed-add-sub", 1, _int("INT"), _int("BIGINT"), "Q4"),
    ("mysql80.signed-add-sub", 1, _int("MEDIUMINT"), _int("INT"), "Q4"),
    ("mysql80.signed-add-sub", 1, _int("SMALLINT"), _int("MEDIUMINT"), "Q4"),
    ("mysql80.signed-add-sub", 1, _int("TINYINT"), _int("SMALLINT"), "Q4"),
    # mysql80.signed-widen: 4 pairs x Q1-Q3 = 12
    ("mysql80.signed-widen", 1, _int("INT"), _int("BIGINT"), "Q1"),
    ("mysql80.signed-widen", 1, _int("INT"), _int("BIGINT"), "Q2"),
    ("mysql80.signed-widen", 1, _int("INT"), _int("BIGINT"), "Q3"),
    ("mysql80.signed-widen", 1, _int("MEDIUMINT"), _int("INT"), "Q1"),
    ("mysql80.signed-widen", 1, _int("MEDIUMINT"), _int("INT"), "Q2"),
    ("mysql80.signed-widen", 1, _int("MEDIUMINT"), _int("INT"), "Q3"),
    ("mysql80.signed-widen", 1, _int("SMALLINT"), _int("MEDIUMINT"), "Q1"),
    ("mysql80.signed-widen", 1, _int("SMALLINT"), _int("MEDIUMINT"), "Q2"),
    ("mysql80.signed-widen", 1, _int("SMALLINT"), _int("MEDIUMINT"), "Q3"),
    ("mysql80.signed-widen", 1, _int("TINYINT"), _int("SMALLINT"), "Q1"),
    ("mysql80.signed-widen", 1, _int("TINYINT"), _int("SMALLINT"), "Q2"),
    ("mysql80.signed-widen", 1, _int("TINYINT"), _int("SMALLINT"), "Q3"),
]


def _rows(*values):
    return Rows(tuple(Row(i + 1, value) for i, value in enumerate(values)))


def _assert_all_satisfied(conditions: tuple[ConditionResult, ...]) -> None:
    for condition in conditions:
        assert condition.status is CheckStatus.SATISFIED, (
            f"{condition.condition_id}: {condition.detail}"
        )


# --------------------------------------------------------------------------
# Combination enumeration
# --------------------------------------------------------------------------


def test_exactly_31_rule_typepair_template_combos() -> None:
    combos = iter_combinations()
    as_tuples = {
        (c.rule_id, c.rule_version, c.a_type, c.b_type, str(c.template_id.value))
        for c in combos
    }
    expected = {(rid, ver, a, b, tpl) for rid, ver, a, b, tpl in EXPECTED_COMBOS}
    assert as_tuples == expected
    assert len(EXPECTED_COMBOS) == 31


def test_both_index_variants_multiply_to_62() -> None:
    combos = iter_combinations()
    assert len(combos) == 62
    variants = {(c.rule_id, c.rule_version, c.a_type, c.b_type, str(c.template_id.value),
                 str(c.index_variant.value)) for c in combos}
    expected = {
        (rid, ver, a, b, tpl, variant)
        for rid, ver, a, b, tpl in EXPECTED_COMBOS
        for variant in ("ix_v", "none")
    }
    assert variants == expected


def test_combination_keys_are_ascii_sorted_and_unique() -> None:
    combos = iter_combinations()
    keys = [c.combo_key for c in combos]
    assert keys == sorted(keys)
    assert len(set(keys)) == len(keys)
    for key in keys:
        key.encode("ascii")


def test_combo_key_is_canonical_and_stable() -> None:
    a, b = _int("TINYINT"), _int("SMALLINT")
    key = combo_key("mysql80.signed-widen", 1, a, b, TemplateId.Q1, IndexVariant.NONE)
    # canonical_json layout: rule_id, version, pair text, template, variant
    assert key.startswith('["mysql80.signed-widen",1,"[{\\"kind\\":\\"signed_integer\\"')
    assert key.endswith(',"Q1","none"]')
    assert canonical_type_pair(a, b) == (
        '[{"kind":"signed_integer","name":"TINYINT"},'
        '{"kind":"signed_integer","name":"SMALLINT"}]'
    )


def test_no_q4_outside_signed_add_sub_and_no_q1_q3_inside() -> None:
    for combo in iter_combinations():
        if str(combo.template_id.value) == "Q4":
            assert combo.rule_id == "mysql80.signed-add-sub"
        else:
            assert combo.rule_id != "mysql80.signed-add-sub"


# --------------------------------------------------------------------------
# Rule lookup and registration
# --------------------------------------------------------------------------


def test_list_rules_holds_four_reviewed_v1_rules() -> None:
    rules = list_rules()
    assert [(r.rule_id, r.rule_version) for r in rules] == [
        ("mysql80.decimal-widen", 1),
        ("mysql80.integer-decimal", 1),
        ("mysql80.signed-add-sub", 1),
        ("mysql80.signed-widen", 1),
    ]
    for rule in rules:
        assert rule.review_status is RuleReviewStatus.REVIEWED
        assert len(rule.definition_hash) == 64
        int(rule.definition_hash, 16)  # lowercase hex


def test_get_rule_returns_definition_and_unknown_versions_fail() -> None:
    rule = get_rule("mysql80.signed-widen", 1)
    assert rule.rule_id == "mysql80.signed-widen"
    assert rule.rule_version == 1
    with pytest.raises(UnknownRuleError):
        get_rule("mysql80.nope", 1)
    with pytest.raises(UnknownRuleError):
        get_rule("mysql80.signed-widen", 2)  # no "latest" fallback
    with pytest.raises(RuleRegistryError):
        get_rule("mysql80.signed-widen", 2)
    with pytest.raises(ContractError):
        get_rule("mysql80.signed-widen", 2)


def test_duplicate_definition_with_different_semantics_is_rejected() -> None:
    base = get_rule("mysql80.signed-widen", 1)
    registry = RuleRegistry()
    registry.register(base)
    # identical definition re-registration is an idempotent no-op
    registry.register(base)
    # same (id, version), different type pairs -> rejected; the definition hash
    # must be recomputed (empty marker) for a genuinely new semantic draft
    conflicting = dataclasses.replace(
        base,
        type_pairs=base.type_pairs + ((_int("TINYINT"), _int("INT")),),
        definition_hash="",
    )
    with pytest.raises(DuplicateDefinitionError):
        registry.register(conflicting)
    # the stored definition is untouched
    assert registry.get("mysql80.signed-widen", 1).definition_hash == base.definition_hash
    # a bumped version is a new registration, not a conflict
    registry.register(dataclasses.replace(base, rule_version=2))
    assert registry.get("mysql80.signed-widen", 2).rule_version == 2


def test_disabled_rule_is_retrievable_and_marked() -> None:
    base = get_rule("mysql80.decimal-widen", 1)
    registry = RuleRegistry()
    registry.register(base)
    disabled = dataclasses.replace(base, review_status=RuleReviewStatus.DISABLED)
    registry.register(disabled)  # same semantics: management-state update
    fetched = registry.get("mysql80.decimal-widen", 1)
    assert fetched.review_status is RuleReviewStatus.DISABLED
    assert fetched.definition_hash == base.definition_hash


# --------------------------------------------------------------------------
# definition_hash semantics
# --------------------------------------------------------------------------


def _rebuild_signed_widen(**overrides) -> RuleSpec:
    base = get_rule("mysql80.signed-widen", 1)
    return dataclasses.replace(base, definition_hash="", **overrides)


def test_definition_hash_is_stable_for_equal_semantics() -> None:
    assert _rebuild_signed_widen().definition_hash == get_rule(
        "mysql80.signed-widen", 1
    ).definition_hash


def test_definition_hash_changes_with_semantic_fields() -> None:
    base_hash = get_rule("mysql80.signed-widen", 1).definition_hash
    changed_pair = _rebuild_signed_widen(
        type_pairs=((_int("TINYINT"), _int("MEDIUMINT")),),
    ).definition_hash
    changed_templates = _rebuild_signed_widen(
        templates=(TemplateId.Q1, TemplateId.Q2), sum_abs_coefficient_budget=None
    ).definition_hash
    changed_budget = _rebuild_signed_widen(
        sum_abs_coefficient_budget=10**13
    ).definition_hash
    changed_k = _rebuild_signed_widen(
        templates=(TemplateId.Q4,),
        sum_abs_coefficient_budget=None,
        arithmetic_k_min=-8,
        arithmetic_k_max=8,
    ).definition_hash
    for other in (changed_pair, changed_templates, changed_budget, changed_k):
        assert other != base_hash


def test_definition_hash_ignores_management_data() -> None:
    base_hash = get_rule("mysql80.signed-widen", 1).definition_hash
    assert _rebuild_signed_widen(
        rationale=("different link",),
        review_notes="different notes",
        review_status=RuleReviewStatus.DISABLED,
    ).definition_hash == base_hash


def test_forged_definition_hash_is_rejected() -> None:
    with pytest.raises(ContractError):
        dataclasses.replace(get_rule("mysql80.signed-widen", 1), definition_hash="0" * 64)


# --------------------------------------------------------------------------
# Domain-legal cases (R01 positive side; Q3 also SUM-budget limited)
# --------------------------------------------------------------------------


def test_signed_widen_q1_bounds_null_and_duplicates_pass() -> None:
    rule = get_rule("mysql80.signed-widen", 1)
    conditions = exact_numeric.check_exact_domain(
        rule,
        _int("TINYINT"),
        _int("SMALLINT"),
        _rows(IntegerValue(-128), IntegerValue(127), IntegerValue(0),
              IntegerValue(0), NullValue()),
        QuerySpec(TemplateId.Q1),
    )
    _assert_all_satisfied(conditions)


def test_signed_widen_q2_with_predicate_passes() -> None:
    rule = get_rule("mysql80.signed-widen", 1)
    query = QuerySpec(
        TemplateId.Q2,
        predicate=Compare(CompareOp.GE, ExactLiteral(IntegerValue(-128))),
    )
    conditions = exact_numeric.check_exact_domain(
        rule, _int("TINYINT"), _int("SMALLINT"),
        _rows(IntegerValue(-128), IntegerValue(127), NullValue()),
        query,
    )
    _assert_all_satisfied(conditions)


def test_signed_widen_q3_passes_within_sum_budget() -> None:
    rule = get_rule("mysql80.signed-widen", 1)
    conditions = exact_numeric.check_exact_domain(
        rule, _int("INT"), _int("BIGINT"),
        _rows(IntegerValue(1000000), IntegerValue(-1000000), NullValue()),
        QuerySpec(TemplateId.Q3),
    )
    _assert_all_satisfied(conditions)


def test_decimal_widen_domain_legal_case_passes() -> None:
    rule = get_rule("mysql80.decimal-widen", 1)
    conditions = exact_numeric.check_exact_domain(
        rule,
        _dec(9, 2),
        _dec(18, 2),
        _rows(DecimalValue(-999999999, 2), DecimalValue(999999999, 2),
              DecimalValue(0, 2), DecimalValue(0, 2), NullValue()),
        QuerySpec(TemplateId.Q1),
    )
    _assert_all_satisfied(conditions)


def test_decimal_widen_q3_passes_within_sum_budget() -> None:
    rule = get_rule("mysql80.decimal-widen", 1)
    conditions = exact_numeric.check_exact_domain(
        rule, _dec(20, 0), _dec(30, 0),
        _rows(DecimalValue(500000000000, 0), DecimalValue(-500000000000, 0)),
        QuerySpec(TemplateId.Q3),
    )
    _assert_all_satisfied(conditions)


def test_integer_decimal_domain_legal_case_passes() -> None:
    rule = get_rule("mysql80.integer-decimal", 1)
    conditions = exact_numeric.check_exact_domain(
        rule,
        _int("INT"),
        _dec(12, 0),
        _rows(IntegerValue(-2147483648), IntegerValue(2147483647),
              IntegerValue(0), IntegerValue(0), NullValue()),
        QuerySpec(TemplateId.Q1),
    )
    _assert_all_satisfied(conditions)


def test_signed_add_sub_q4_legal_case_passes() -> None:
    rule = get_rule("mysql80.signed-add-sub", 1)
    arithmetic = Arithmetic(ArithmeticOp.ADD, IntegerValue(16))
    query = QuerySpec(
        TemplateId.Q4,
        arithmetic=arithmetic,
        projections=(Projection("c0", arithmetic),),
    )
    conditions = exact_numeric.check_exact_domain(
        rule, _int("TINYINT"), _int("SMALLINT"),
        _rows(IntegerValue(-128), IntegerValue(127), IntegerValue(0), NullValue()),
        query,
    )
    _assert_all_satisfied(conditions)


def test_null_rows_are_legal_for_every_rule() -> None:
    cases = [
        (get_rule("mysql80.signed-widen", 1), _int("TINYINT"), _int("SMALLINT"), TemplateId.Q1),
        (get_rule("mysql80.decimal-widen", 1), _dec(9, 2), _dec(18, 2), TemplateId.Q1),
        (get_rule("mysql80.integer-decimal", 1), _int("BIGINT"), _dec(20, 0), TemplateId.Q1),
    ]
    for rule, a, b, template in cases:
        conditions = exact_numeric.check_exact_domain(rule, a, b, _rows(NullValue()), QuerySpec(template))
        _assert_all_satisfied(conditions)


# --------------------------------------------------------------------------
# Illegal cases
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "narrow,wide,too_high,too_low",
    [
        ("TINYINT", "SMALLINT", 128, -129),
        ("SMALLINT", "MEDIUMINT", 32768, -32769),
        ("MEDIUMINT", "INT", 8388608, -8388609),
        ("INT", "BIGINT", 2147483648, -2147483649),
    ],
)
def test_out_of_domain_by_one_unit_is_rejected(narrow, wide, too_high, too_low) -> None:
    rule = get_rule("mysql80.signed-widen", 1)
    for value in (too_high, too_low):
        conditions = exact_numeric.check_exact_domain(
            rule, _int(narrow), _int(wide), _rows(IntegerValue(value)), QuerySpec(TemplateId.Q1)
        )
        violated = [c for c in conditions if c.status is CheckStatus.VIOLATED]
        assert len(violated) == 1
        assert violated[0].condition_id == "common_value_domain"
        assert violated[0].reason is ReasonCode.VALUE_OUT_OF_DOMAIN


def test_wrong_decimal_scale_is_rejected() -> None:
    rule = get_rule("mysql80.decimal-widen", 1)
    for value in (DecimalValue(123, 3), DecimalValue(123, 0), DecimalValue(1, 4)):
        conditions = exact_numeric.check_exact_domain(
            rule, _dec(9, 2), _dec(18, 2), _rows(value), QuerySpec(TemplateId.Q1)
        )
        violated = [c for c in conditions if c.status is CheckStatus.VIOLATED]
        assert len(violated) == 1
        assert violated[0].reason is ReasonCode.INVALID_STRUCTURE


def test_scale_changed_pair_is_not_registered() -> None:
    a, b = _dec(9, 2), _dec(18, 4)
    rule = get_rule("mysql80.decimal-widen", 1)
    result = exact_numeric.check_rule_binding(rule, a, b, TemplateId.Q1)
    assert result.status is CheckStatus.VIOLATED
    assert result.reason is ReasonCode.INVALID_STRUCTURE
    registered_pairs = {
        (c.a_type, c.b_type) for c in iter_combinations()
    }
    assert (a, b) not in registered_pairs


def test_unauthorized_type_pairs_are_rejected_and_unregistered() -> None:
    rule = get_rule("mysql80.signed-widen", 1)
    for a, b in ((_int("TINYINT"), _int("INT")), (_int("INT"), _int("TINYINT"))):
        result = exact_numeric.check_rule_binding(rule, a, b, TemplateId.Q1)
        assert result.status is CheckStatus.VIOLATED
        assert result.reason is ReasonCode.INVALID_STRUCTURE
    registered_pairs = {(c.a_type, c.b_type) for c in iter_combinations()}
    assert (_int("TINYINT"), _int("INT")) not in registered_pairs
    assert (_int("INT"), _int("TINYINT")) not in registered_pairs


def test_float_and_unsigned_are_outside_the_type_model() -> None:
    # No TypeSpec kind exists for FLOAT/UNSIGNED; the strict decoder rejects them.
    with pytest.raises(ContractError):
        codec.decode_type_spec({"kind": "float", "precision": 9, "scale": 2})
    with pytest.raises(ContractError):
        codec.decode_type_spec({"kind": "unsigned_integer", "name": "INT"})
    with pytest.raises(ContractError):
        codec.decode_type_spec({"kind": "signed_integer", "name": "BIGINT UNSIGNED"})


def test_q4_with_non_signed_add_sub_rule_is_rejected() -> None:
    rule = get_rule("mysql80.signed-widen", 1)
    result = exact_numeric.check_rule_binding(rule, _int("TINYINT"), _int("SMALLINT"), TemplateId.Q4)
    assert result.status is CheckStatus.VIOLATED
    assert result.reason is ReasonCode.INVALID_STRUCTURE


def test_q1_to_q3_with_signed_add_sub_rule_is_rejected() -> None:
    rule = get_rule("mysql80.signed-add-sub", 1)
    for template in (TemplateId.Q1, TemplateId.Q2, TemplateId.Q3):
        result = exact_numeric.check_rule_binding(
            rule, _int("TINYINT"), _int("SMALLINT"), template
        )
        assert result.status is CheckStatus.VIOLATED
        assert result.reason is ReasonCode.INVALID_STRUCTURE


def test_registering_into_default_registry_rejects_conflict() -> None:
    base = get_rule("mysql80.integer-decimal", 1)
    conflicting = dataclasses.replace(
        base,
        type_pairs=base.type_pairs + ((_int("INT"), _dec(30, 0)),),
        definition_hash="",
    )
    with pytest.raises(DuplicateDefinitionError):
        register_rule(conflicting)
