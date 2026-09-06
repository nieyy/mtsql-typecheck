"""R03 + domain tests for the exact numeric checks.

All budgets and bounds are hand-written decimal literals from design
6.2.1/6.2.2 (10^12 SUM budget, [-16,16] k range, 2^53 neighborhood, BIGINT
extremes, DECIMAL(9,2) coefficient limit 10^9-1); no expectation is computed
by calling the code under test.  The BIGINT intermediate-value tests are
synthetic helper tests: real generated cases keep the narrow side at most
INT, so they exercise the check, not a certified real BIGINT arithmetic rule
(design 6.4.1).
"""

from __future__ import annotations

import pytest

from mtsql_typecheck.contracts.case import (
    Arithmetic,
    ArithmeticOp,
    And,
    Between,
    CheckStatus,
    Compare,
    CompareOp,
    ConditionResult,
    ContractError,
    DecimalType,
    DecimalValue,
    ExactLiteral,
    IntegerValue,
    NullValue,
    Projection,
    QuerySpec,
    ReasonCode,
    Row,
    Rows,
    RuleRef,
    SignedIntName,
    SignedIntegerType,
    TemplateId,
    signed_range,
)
from mtsql_typecheck.rules import exact_numeric
from mtsql_typecheck.rules.registry import get_rule

# Hand-written bounds [MySQL 8.0 manual, signed ranges].
INT_BOUNDS = {
    "TINYINT": (-128, 127),
    "SMALLINT": (-32768, 32767),
    "MEDIUMINT": (-8388608, 8388607),
    "INT": (-2147483648, 2147483647),
    "BIGINT": (-9223372036854775808, 9223372036854775807),
}

BUDGET = 1000000000000  # 10^12, design 6.2.2 SUM protection


def _int(name: str) -> SignedIntegerType:
    return SignedIntegerType(SignedIntName(name))


def _dec(precision: int, scale: int) -> DecimalType:
    return DecimalType(precision, scale)


def _rows(*values) -> Rows:
    return Rows(tuple(Row(i + 1, value) for i, value in enumerate(values)))


def _q4_query(k: int, op: ArithmeticOp = ArithmeticOp.ADD) -> QuerySpec:
    arithmetic = Arithmetic(op, IntegerValue(k))
    return QuerySpec(
        TemplateId.Q4, arithmetic=arithmetic, projections=(Projection("c0", arithmetic),)
    )


def _violations(conditions: tuple[ConditionResult, ...]) -> list[ConditionResult]:
    return [c for c in conditions if c.status is CheckStatus.VIOLATED]


# --------------------------------------------------------------------------
# Value domains
# --------------------------------------------------------------------------


def test_contracts_signed_range_matches_handwritten_bounds() -> None:
    for name, (lo, hi) in INT_BOUNDS.items():
        assert signed_range(SignedIntName(name)) == (lo, hi)


@pytest.mark.parametrize(
    "name", ["TINYINT", "SMALLINT", "MEDIUMINT", "INT", "BIGINT"]
)
def test_integer_type_bounds_each_way(name: str) -> None:
    lo, hi = INT_BOUNDS[name]
    type_spec = _int(name)
    for value in (lo, hi, 0):
        result = exact_numeric.check_value_in_type(IntegerValue(value), type_spec)
        assert result.status is CheckStatus.SATISFIED
    for value in (lo - 1, hi + 1):
        result = exact_numeric.check_value_in_type(IntegerValue(value), type_spec)
        assert result.status is CheckStatus.VIOLATED
        assert result.reason is ReasonCode.VALUE_OUT_OF_DOMAIN


def test_decimal_value_in_type_boundary() -> None:
    # DECIMAL(9,2): abs(coefficient) <= 10^9 - 1 = 999999999
    assert exact_numeric.check_value_in_type(
        DecimalValue(999999999, 2), _dec(9, 2)
    ).status is CheckStatus.SATISFIED
    below = exact_numeric.check_value_in_type(DecimalValue(999999999, 2), _dec(18, 2))
    assert below.status is CheckStatus.SATISFIED  # also within the wide side
    over = exact_numeric.check_value_in_type(DecimalValue(1000000000, 2), _dec(9, 2))
    assert over.status is CheckStatus.VIOLATED
    assert over.reason is ReasonCode.VALUE_OUT_OF_DOMAIN


def test_decimal_widen_requires_narrower_side_too() -> None:
    rule = get_rule("mysql80.decimal-widen", 1)
    # coefficient 10^9 fits DECIMAL(18,2) but not DECIMAL(9,2): common domain
    # requires both sides, so it is rejected.
    conditions = exact_numeric.check_exact_domain(
        rule, _dec(9, 2), _dec(18, 2),
        _rows(DecimalValue(1000000000, 2)), QuerySpec(TemplateId.Q1),
    )
    violations = _violations(conditions)
    assert len(violations) == 1
    assert violations[0].condition_id == "common_value_domain"
    assert violations[0].reason is ReasonCode.VALUE_OUT_OF_DOMAIN


def test_null_is_legal_for_every_rule() -> None:
    cases = [
        (get_rule("mysql80.signed-widen", 1), _int("TINYINT"), _int("SMALLINT")),
        (get_rule("mysql80.decimal-widen", 1), _dec(9, 2), _dec(18, 2)),
        (get_rule("mysql80.integer-decimal", 1), _int("BIGINT"), _dec(20, 0)),
    ]
    for rule, a, b in cases:
        result = exact_numeric.check_common_value_domain(rule, a, b, NullValue())
        assert result.status is CheckStatus.SATISFIED


# --------------------------------------------------------------------------
# 2^53 neighborhood and BIGINT extremes
# --------------------------------------------------------------------------


def test_2pow53_neighborhood_legal_in_integer_decimal() -> None:
    rule = get_rule("mysql80.integer-decimal", 1)
    conditions = exact_numeric.check_exact_domain(
        rule, _int("BIGINT"), _dec(20, 0),
        _rows(
            IntegerValue(9007199254740991),   # 2^53 - 1
            IntegerValue(9007199254740992),   # 2^53
            IntegerValue(9007199254740993),   # 2^53 + 1
            NullValue(),
        ),
        QuerySpec(TemplateId.Q1),
    )
    assert not _violations(conditions)


def test_bigint_extremes_legal_in_integer_decimal() -> None:
    rule = get_rule("mysql80.integer-decimal", 1)
    conditions = exact_numeric.check_exact_domain(
        rule, _int("BIGINT"), _dec(20, 0),
        _rows(
            IntegerValue(9223372036854775807),   # 2^63 - 1
            IntegerValue(-9223372036854775808),  # -2^63
        ),
        QuerySpec(TemplateId.Q1),
    )
    assert not _violations(conditions)


def test_2pow53_and_bigint_extremes_out_of_int_narrow_side() -> None:
    rule = get_rule("mysql80.signed-widen", 1)
    for value in (9007199254740992, 9223372036854775807, -9223372036854775808):
        conditions = exact_numeric.check_exact_domain(
            rule, _int("INT"), _int("BIGINT"),
            _rows(IntegerValue(value)), QuerySpec(TemplateId.Q1),
        )
        violations = _violations(conditions)
        assert len(violations) == 1
        assert violations[0].condition_id == "common_value_domain"
        assert violations[0].reason is ReasonCode.VALUE_OUT_OF_DOMAIN


# --------------------------------------------------------------------------
# Q3 SUM absolute-value budget (10^12)
# --------------------------------------------------------------------------


def test_q3_budget_exactly_at_limit_passes() -> None:
    result = exact_numeric.check_q3_sum_budget(
        _rows(IntegerValue(500000000000), IntegerValue(500000000000)), 0
    )
    assert result.status is CheckStatus.SATISFIED
    single = exact_numeric.check_q3_sum_budget(
        _rows(IntegerValue(1000000000000)), 0
    )
    assert single.status is CheckStatus.SATISFIED


def test_q3_budget_exceeded_by_one_is_rejected() -> None:
    result = exact_numeric.check_q3_sum_budget(
        _rows(IntegerValue(1000000000000), IntegerValue(1)), 0
    )
    assert result.status is CheckStatus.VIOLATED
    assert result.condition_id == "q3_sum_abs_budget"
    assert result.reason is ReasonCode.BUDGET_EXCEEDED


def test_q3_cancellation_cannot_evade_budget() -> None:
    # +10^12 and -1 net to 10^12 - 1 but the absolute sum is 10^12 + 1.
    mixed = exact_numeric.check_q3_sum_budget(
        _rows(IntegerValue(1000000000000), IntegerValue(-1)), 0
    )
    assert mixed.status is CheckStatus.VIOLATED
    assert mixed.reason is ReasonCode.BUDGET_EXCEEDED
    # +10^12 with -10^12 nets to 0 but the absolute sum is 2 * 10^12.
    paired = exact_numeric.check_q3_sum_budget(
        _rows(IntegerValue(1000000000000), IntegerValue(-1000000000000)), 0
    )
    assert paired.status is CheckStatus.VIOLATED


def test_q3_budget_folds_decimal_scale_exactly() -> None:
    # scale 6: limit is 10^12 * 10^6 = 10^18 on integer coefficients.
    at_limit = exact_numeric.check_q3_sum_budget(
        _rows(DecimalValue(500000000000000000, 6), DecimalValue(500000000000000000, 6)),
        6,
    )
    assert at_limit.status is CheckStatus.SATISFIED
    over = exact_numeric.check_q3_sum_budget(
        _rows(
            DecimalValue(500000000000000000, 6),
            DecimalValue(500000000000000001, 6),
        ),
        6,
    )
    assert over.status is CheckStatus.VIOLATED
    assert over.reason is ReasonCode.BUDGET_EXCEEDED


def test_q3_empty_and_all_null_pass_with_zero_sum() -> None:
    empty = exact_numeric.check_q3_sum_budget(Rows(()), 0)
    assert empty.status is CheckStatus.SATISFIED
    all_null = exact_numeric.check_q3_sum_budget(_rows(NullValue(), NullValue()), 0)
    assert all_null.status is CheckStatus.SATISFIED


def test_q3_budget_not_relaxed_by_where_clause() -> None:
    rule = get_rule("mysql80.integer-decimal", 1)
    query = QuerySpec(
        TemplateId.Q3,
        predicate=Compare(CompareOp.LT, ExactLiteral(IntegerValue(1))),
    )
    # The predicate would select only the -10^12 row, but the budget counts
    # all loaded rows: absolute sum 2 * 10^12 > 10^12.
    conditions = exact_numeric.check_exact_domain(
        rule, _int("BIGINT"), _dec(20, 0),
        _rows(IntegerValue(1000000000000), IntegerValue(-1000000000000)),
        query,
    )
    budget_violations = [
        c for c in _violations(conditions) if c.condition_id == "q3_sum_abs_budget"
    ]
    assert len(budget_violations) == 1
    assert budget_violations[0].reason is ReasonCode.BUDGET_EXCEEDED
    # Small rows with the same predicate still pass completely.
    ok = exact_numeric.check_exact_domain(
        rule, _int("BIGINT"), _dec(20, 0),
        _rows(IntegerValue(5), IntegerValue(-5), NullValue()),
        query,
    )
    assert not _violations(ok)


# --------------------------------------------------------------------------
# Q4 arithmetic k and BIGINT intermediate domain
# --------------------------------------------------------------------------


@pytest.mark.parametrize("k", [-16, 0, 16])
def test_q4_legal_k_passes(k: int) -> None:
    rule = get_rule("mysql80.signed-add-sub", 1)
    conditions = exact_numeric.check_exact_domain(
        rule, _int("TINYINT"), _int("SMALLINT"),
        _rows(IntegerValue(-128), IntegerValue(127), IntegerValue(0), NullValue()),
        _q4_query(k),
    )
    assert not _violations(conditions)


@pytest.mark.parametrize("k", [17, -17])
def test_q4_out_of_range_k_is_rejected(k: int) -> None:
    rule = get_rule("mysql80.signed-add-sub", 1)
    conditions = exact_numeric.check_exact_domain(
        rule, _int("TINYINT"), _int("SMALLINT"),
        _rows(IntegerValue(0)), _q4_query(k),
    )
    violations = _violations(conditions)
    assert len(violations) == 1
    assert violations[0].condition_id == "q4_bigint_domain"
    assert violations[0].reason is ReasonCode.VALUE_OUT_OF_DOMAIN


def test_bigint_intermediate_helper_boundaries_synthetic() -> None:
    """Synthetic helper test near +/-2^63.

    This exercises the domain check helper directly; it does NOT certify the
    real BIGINT arithmetic rule on MySQL (real generated rows keep the narrow
    side at most INT, so they never approach these values; design 6.4.1).
    """
    lo = -9223372036854775808  # -2^63
    hi = 9223372036854775807   # 2^63 - 1
    assert exact_numeric.check_bigint_intermediate(hi, 0).status is CheckStatus.SATISFIED
    assert exact_numeric.check_bigint_intermediate(lo, 0).status is CheckStatus.SATISFIED
    # One unit inside on each side with k = 16 still keeps both intermediates.
    assert (
        exact_numeric.check_bigint_intermediate(hi - 16, 16).status is CheckStatus.SATISFIED
    )
    assert (
        exact_numeric.check_bigint_intermediate(lo + 16, -16).status is CheckStatus.SATISFIED
    )
    # Overflow by the smallest possible margin.
    overflow = exact_numeric.check_bigint_intermediate(hi, 16)
    assert overflow.status is CheckStatus.VIOLATED
    assert overflow.reason is ReasonCode.VALUE_OUT_OF_DOMAIN
    assert "v + k" in (overflow.detail or "")
    underflow = exact_numeric.check_bigint_intermediate(lo, -16)
    assert underflow.status is CheckStatus.VIOLATED
    assert underflow.reason is ReasonCode.VALUE_OUT_OF_DOMAIN
    # Subtracting below the lower bound also overflows.
    neg_side = exact_numeric.check_bigint_intermediate(hi, -16)
    assert neg_side.status is CheckStatus.VIOLATED
    pos_side = exact_numeric.check_bigint_intermediate(lo, 16)
    assert pos_side.status is CheckStatus.VIOLATED


def test_q4_bigint_domain_check_on_synthetic_rows() -> None:
    """Synthetic: loaded values near 2^63 fail the intermediate-value check.

    Not representative of generated cases (narrow side is at most INT); it
    proves the check is present and independent (design 6.4.1).
    """
    rule = get_rule("mysql80.signed-add-sub", 1)
    conditions = exact_numeric.check_exact_domain(
        rule, _int("INT"), _int("BIGINT"),
        _rows(IntegerValue(9223372036854775807)), _q4_query(1),
    )
    # The synthetic value also exceeds the INT narrow side, so the common
    # domain check fires too; the q4 intermediate-value check must fire as
    # well, independently.
    q4_violations = [
        c for c in _violations(conditions) if c.condition_id == "q4_bigint_domain"
    ]
    assert len(q4_violations) == 1
    assert q4_violations[0].reason is ReasonCode.VALUE_OUT_OF_DOMAIN


# --------------------------------------------------------------------------
# Predicate constants
# --------------------------------------------------------------------------


def test_signed_rule_rejects_decimal_constant() -> None:
    rule = get_rule("mysql80.signed-widen", 1)
    query = QuerySpec(
        TemplateId.Q2,
        predicate=Compare(CompareOp.EQ, ExactLiteral(DecimalValue(1, 2))),
    )
    conditions = exact_numeric.check_exact_domain(
        rule, _int("TINYINT"), _int("SMALLINT"), _rows(IntegerValue(1)), query,
    )
    violations = _violations(conditions)
    assert len(violations) == 1
    assert violations[0].condition_id == "predicate_constants"
    assert violations[0].reason is ReasonCode.INVALID_STRUCTURE


def test_signed_rule_rejects_out_of_range_integer_constant() -> None:
    rule = get_rule("mysql80.signed-widen", 1)
    query = QuerySpec(
        TemplateId.Q2,
        predicate=Compare(CompareOp.GE, ExactLiteral(IntegerValue(128))),
    )
    conditions = exact_numeric.check_exact_domain(
        rule, _int("TINYINT"), _int("SMALLINT"), _rows(IntegerValue(0)), query,
    )
    violations = _violations(conditions)
    assert len(violations) == 1
    assert violations[0].condition_id == "predicate_constants"
    assert violations[0].reason is ReasonCode.VALUE_OUT_OF_DOMAIN


def test_integer_decimal_rejects_decimal_constant() -> None:
    rule = get_rule("mysql80.integer-decimal", 1)
    query = QuerySpec(
        TemplateId.Q2,
        predicate=Compare(CompareOp.EQ, ExactLiteral(DecimalValue(5, 0))),
    )
    conditions = exact_numeric.check_exact_domain(
        rule, _int("BIGINT"), _dec(20, 0), _rows(IntegerValue(5)), query,
    )
    violations = _violations(conditions)
    assert len(violations) == 1
    assert violations[0].condition_id == "predicate_constants"
    assert violations[0].reason is ReasonCode.INVALID_STRUCTURE


def test_decimal_widen_constant_kind_and_scale_rules() -> None:
    rule = get_rule("mysql80.decimal-widen", 1)
    a, b = _dec(9, 2), _dec(18, 2)

    def predicate(value) -> QuerySpec:
        return QuerySpec(
            TemplateId.Q2, predicate=Compare(CompareOp.EQ, ExactLiteral(value))
        )

    integer_constant = exact_numeric.check_predicate_constants(
        rule, a, b, predicate(IntegerValue(5))
    )
    assert integer_constant.reason is ReasonCode.INVALID_STRUCTURE
    wrong_scale = exact_numeric.check_predicate_constants(
        rule, a, b, predicate(DecimalValue(5, 3))
    )
    assert wrong_scale.reason is ReasonCode.INVALID_STRUCTURE
    legal = exact_numeric.check_predicate_constants(
        rule, a, b, predicate(DecimalValue(123, 2))
    )
    assert legal.status is CheckStatus.SATISFIED
    null_constant = exact_numeric.check_predicate_constants(
        rule, a, b, predicate(NullValue())
    )
    assert null_constant.status is CheckStatus.SATISFIED


def test_between_and_compound_constants_are_checked() -> None:
    rule = get_rule("mysql80.decimal-widen", 1)
    a, b = _dec(9, 2), _dec(18, 2)
    between = QuerySpec(
        TemplateId.Q2,
        predicate=Between(
            ExactLiteral(DecimalValue(0, 2)), ExactLiteral(DecimalValue(100, 2))
        ),
    )
    assert (
        exact_numeric.check_predicate_constants(rule, a, b, between).status
        is CheckStatus.SATISFIED
    )
    bad_between = QuerySpec(
        TemplateId.Q2,
        predicate=Between(
            ExactLiteral(DecimalValue(0, 2)), ExactLiteral(DecimalValue(100, 4))
        ),
    )
    bad = exact_numeric.check_predicate_constants(rule, a, b, bad_between)
    assert bad.status is CheckStatus.VIOLATED
    assert bad.reason is ReasonCode.INVALID_STRUCTURE

    signed_rule = get_rule("mysql80.signed-widen", 1)
    compound = QuerySpec(
        TemplateId.Q2,
        predicate=And(
            Compare(CompareOp.GE, ExactLiteral(IntegerValue(0))),
            Compare(CompareOp.LE, ExactLiteral(IntegerValue(127))),
        ),
    )
    assert (
        exact_numeric.check_predicate_constants(
            signed_rule, _int("TINYINT"), _int("SMALLINT"), compound
        ).status
        is CheckStatus.SATISFIED
    )
    bad_compound = QuerySpec(
        TemplateId.Q2,
        predicate=And(
            Compare(CompareOp.GE, ExactLiteral(IntegerValue(0))),
            Compare(CompareOp.LE, ExactLiteral(IntegerValue(128))),
        ),
    )
    rejected = exact_numeric.check_predicate_constants(
        signed_rule, _int("TINYINT"), _int("SMALLINT"), bad_compound
    )
    assert rejected.reason is ReasonCode.VALUE_OUT_OF_DOMAIN


# --------------------------------------------------------------------------
# Result relation derivation
# --------------------------------------------------------------------------


def _ref() -> RuleRef:
    return RuleRef("mysql80.signed-widen", 1)


def test_derive_relation_q1_families_follow_column_types() -> None:
    signed = exact_numeric.derive_relation(_ref(), _int("TINYINT"), _int("SMALLINT"), TemplateId.Q1)
    assert str(signed.mode.value) == "multiset_exact"
    (c0,) = signed.columns
    assert c0.alias == "c0"
    assert str(c0.a_family.value) == "signed_integer"
    assert str(c0.b_family.value) == "signed_integer"
    assert str(c0.null_policy.value) == "preserve"

    decimal = exact_numeric.derive_relation(
        RuleRef("mysql80.decimal-widen", 1), _dec(9, 2), _dec(18, 2), TemplateId.Q1
    )
    (c0,) = decimal.columns
    assert str(c0.a_family.value) == "decimal"
    assert str(c0.b_family.value) == "decimal"

    mixed = exact_numeric.derive_relation(
        RuleRef("mysql80.integer-decimal", 1), _int("INT"), _dec(12, 0), TemplateId.Q1
    )
    (c0,) = mixed.columns
    assert str(c0.a_family.value) == "signed_integer"
    assert str(c0.b_family.value) == "decimal"
    assert str(c0.null_policy.value) == "preserve"


def test_derive_relation_q2_rid_is_signed_and_forbids_null() -> None:
    relation = exact_numeric.derive_relation(
        RuleRef("mysql80.integer-decimal", 1), _int("BIGINT"), _dec(20, 0), TemplateId.Q2
    )
    (c0,) = relation.columns
    assert c0.alias == "c0"
    assert str(c0.a_family.value) == "signed_integer"
    assert str(c0.b_family.value) == "signed_integer"
    assert str(c0.null_policy.value) == "forbid"


def test_derive_relation_q3_columns() -> None:
    relation = exact_numeric.derive_relation(
        RuleRef("mysql80.integer-decimal", 1), _int("INT"), _dec(12, 0), TemplateId.Q3
    )
    assert [c.alias for c in relation.columns] == ["c0", "c1", "c2", "c3", "c4"]
    c0, c1, c2, c3, c4 = relation.columns
    # COUNT(*) / COUNT(v): signed integers, NULL forbidden.
    for column in (c0, c1):
        assert str(column.a_family.value) == "signed_integer"
        assert str(column.b_family.value) == "signed_integer"
        assert str(column.null_policy.value) == "forbid"
    # MIN/MAX follow each side's declared family, NULL preserved.
    for column in (c2, c3):
        assert str(column.a_family.value) == "signed_integer"
        assert str(column.b_family.value) == "decimal"
        assert str(column.null_policy.value) == "preserve"
    # SUM is decimal on both sides.
    assert str(c4.a_family.value) == "decimal"
    assert str(c4.b_family.value) == "decimal"
    assert str(c4.null_policy.value) == "preserve"
    for column in relation.columns:
        assert str(column.value_equivalence.value) == "exact_numeric"


def test_derive_relation_q4_is_signed_integer_preserving_null() -> None:
    relation = exact_numeric.derive_relation(_ref(), _int("INT"), _int("BIGINT"), TemplateId.Q4)
    (c0,) = relation.columns
    assert str(c0.a_family.value) == "signed_integer"
    assert str(c0.b_family.value) == "signed_integer"
    assert str(c0.null_policy.value) == "preserve"


def test_derive_relation_rejects_non_rule_ref() -> None:
    with pytest.raises(ContractError):
        exact_numeric.derive_relation("mysql80.signed-widen", _int("INT"), _int("BIGINT"), TemplateId.Q1)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Aggregate entry point shape
# --------------------------------------------------------------------------


def test_check_exact_domain_condition_ids_per_template() -> None:
    rule = get_rule("mysql80.signed-widen", 1)
    q1_ids = {
        c.condition_id
        for c in exact_numeric.check_exact_domain(
            rule, _int("TINYINT"), _int("SMALLINT"), _rows(IntegerValue(0)),
            QuerySpec(TemplateId.Q1),
        )
    }
    assert q1_ids == {"rule_binding", "common_value_domain", "predicate_constants"}
    q3_ids = {
        c.condition_id
        for c in exact_numeric.check_exact_domain(
            rule, _int("INT"), _int("BIGINT"), _rows(IntegerValue(0)),
            QuerySpec(TemplateId.Q3),
        )
    }
    assert q3_ids == q1_ids | {"q3_sum_abs_budget"}
    add_sub = get_rule("mysql80.signed-add-sub", 1)
    q4_ids = {
        c.condition_id
        for c in exact_numeric.check_exact_domain(
            add_sub, _int("TINYINT"), _int("SMALLINT"), _rows(IntegerValue(0)),
            _q4_query(0),
        )
    }
    assert q4_ids == {"rule_binding", "common_value_domain", "predicate_constants",
                      "q4_bigint_domain"}
