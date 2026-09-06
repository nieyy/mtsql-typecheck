"""Exact numeric domain checks and relation derivation (design 6.2.1/6.2.2).

Pure functions over contract models: no I/O, no randomness, no clocks and no
floats -- signed integer domains and DECIMAL coefficients use Python
arbitrary-precision integers only.  These checks inspect encoded values,
rids and coefficients; they never interpret SQL or compute query results
(design 6.2.3).  Every check returns a :class:`ConditionResult` carrying a
stable condition id and reason code instead of a bare bool.

Domains (design 6.2.1):
- signed n-bit integer: ``[-2^(n-1), 2^(n-1)-1]`` (via ``signed_range``);
- ``DECIMAL(p, s)``: value ``= coefficient * 10^(-s)`` with
  ``abs(coefficient) <= 10^p - 1``.
"""

from __future__ import annotations

from ..contracts.case import (
    And,
    Arithmetic,
    Between,
    CheckStatus,
    Compare,
    ConditionResult,
    ContractError,
    DecimalType,
    DecimalValue,
    ExactValue,
    IntegerValue,
    IsNull,
    NullPolicy,
    NullValue,
    Or,
    Predicate,
    QuerySpec,
    ReasonCode,
    RelationMode,
    ResultColumnSpec,
    ResultRelationSpec,
    Rows,
    RuleRef,
    RuleSpec,
    SignedIntegerType,
    SignedIntName,
    TemplateId,
    TypeFamily,
    TypeSpec,
    ValueEquivalence,
    signed_range,
)

# Q3 SUM input budget (design 6.2.2): the sum of absolute values of all
# non-NULL loaded inputs must not exceed 10^12, computed exactly on integer
# coefficients at the rule scale.  A WHERE clause never relaxes this budget.
SUM_ABS_COEFFICIENT_BUDGET = 10**12

# Q4 arithmetic constant bounds (design 6.2.1 signed-add-sub precondition).
ARITHMETIC_K_MIN = -16
ARITHMETIC_K_MAX = 16

_BIGINT_LO, _BIGINT_HI = signed_range(SignedIntName.BIGINT)


def _satisfied(condition_id: str, detail: str | None = None) -> ConditionResult:
    return ConditionResult(condition_id, CheckStatus.SATISFIED, None, detail)


def _violated(
    condition_id: str, reason: ReasonCode, detail: str
) -> ConditionResult:
    return ConditionResult(condition_id, CheckStatus.VIOLATED, reason, detail)


# --------------------------------------------------------------------------
# Value domains
# --------------------------------------------------------------------------


def check_value_in_type(value: ExactValue, type_spec: TypeSpec) -> ConditionResult:
    """Exact representability of one value in one declared type.

    Kind and scale must match, not only the mathematical value: an integer
    literal is not silently accepted for a scale>0 DECIMAL and vice versa.
    """
    condition = "value_representable"
    if isinstance(value, NullValue):
        return _satisfied(condition, "NULL is representable in every supported type")
    if isinstance(value, IntegerValue):
        if isinstance(type_spec, SignedIntegerType):
            lo, hi = signed_range(type_spec.name)
            if lo <= value.value <= hi:
                return _satisfied(condition)
            return _violated(
                condition,
                ReasonCode.VALUE_OUT_OF_DOMAIN,
                f"integer {value.value} outside signed {str(type_spec.name.value)} "
                f"[{lo}, {hi}]",
            )
        if isinstance(type_spec, DecimalType):
            if type_spec.scale != 0:
                return _violated(
                    condition,
                    ReasonCode.INVALID_STRUCTURE,
                    "integer value with a scale>0 DECIMAL type "
                    f"(scale {type_spec.scale})",
                )
            limit = 10**type_spec.precision - 1
            if abs(value.value) <= limit:
                return _satisfied(condition)
            return _violated(
                condition,
                ReasonCode.VALUE_OUT_OF_DOMAIN,
                f"integer {value.value} outside DECIMAL({type_spec.precision},"
                f"{type_spec.scale}) coefficient domain [-{limit}, {limit}]",
            )
    if isinstance(value, DecimalValue):
        if isinstance(type_spec, SignedIntegerType):
            return _violated(
                condition,
                ReasonCode.INVALID_STRUCTURE,
                "decimal value with a signed integer type",
            )
        if value.scale != type_spec.scale:
            return _violated(
                condition,
                ReasonCode.INVALID_STRUCTURE,
                f"decimal value scale {value.scale} != declared scale "
                f"{type_spec.scale}",
            )
        limit = 10**type_spec.precision - 1
        if abs(value.coefficient) <= limit:
            return _satisfied(condition)
        return _violated(
            condition,
            ReasonCode.VALUE_OUT_OF_DOMAIN,
            f"coefficient {value.coefficient} outside DECIMAL("
            f"{type_spec.precision},{type_spec.scale}) domain [-{limit}, {limit}]",
        )
    return _violated(
        condition,
        ReasonCode.INVALID_STRUCTURE,
        f"unsupported value/type combination: {type(value).__name__} vs "
        f"{type(type_spec).__name__}",
    )


def check_common_value_domain(
    rule: RuleSpec,
    a_type: TypeSpec,
    b_type: TypeSpec,
    value: ExactValue,
    condition_id: str = "common_value_domain",
) -> ConditionResult:
    """One shared logical value must be exactly representable on both sides.

    NULL is legal for every rule.  Value kind must follow the rule: rules
    with ``integer_only_values`` accept integer/NULL only, and equal-scale
    decimal rules (decimal-widen) accept decimal/NULL at the shared scale
    only -- an equal mathematical value in another literal kind is rejected.
    """
    if isinstance(value, NullValue):
        return _satisfied(condition_id, "NULL is legal for every rule")
    if rule.integer_only_values and isinstance(value, DecimalValue):
        return _violated(
            condition_id,
            ReasonCode.INVALID_STRUCTURE,
            f"rule {rule.rule_id} accepts integer/NULL logical values only",
        )
    if rule.requires_equal_scale and isinstance(value, IntegerValue):
        return _violated(
            condition_id,
            ReasonCode.INVALID_STRUCTURE,
            f"rule {rule.rule_id} requires decimal values at the shared scale; "
            "an integer literal is not auto-converted",
        )
    for side_name, side_type in (("A", a_type), ("B", b_type)):
        result = check_value_in_type(value, side_type)
        if result.status is CheckStatus.VIOLATED:
            assert result.reason is not None
            return _violated(
                condition_id, result.reason, f"side {side_name}: {result.detail}"
            )
    return _satisfied(condition_id)


def check_rows_domain(
    rule: RuleSpec, a_type: TypeSpec, b_type: TypeSpec, rows: Rows
) -> ConditionResult:
    """Every shared row value must lie in the common domain of both sides."""
    condition = "common_value_domain"
    for row in rows.rows:
        result = check_common_value_domain(rule, a_type, b_type, row.value)
        if result.status is CheckStatus.VIOLATED:
            assert result.reason is not None
            return _violated(
                condition, result.reason, f"rid {row.rid}: {result.detail}"
            )
    return _satisfied(condition, f"{len(rows.rows)} shared rows checked")


# --------------------------------------------------------------------------
# Predicate constants (design 6.2.2, 6.2.5 "predicate constant legality")
# --------------------------------------------------------------------------


def _atom_constants(atom: Compare | Between | IsNull) -> tuple[ExactValue, ...]:
    if isinstance(atom, Compare):
        return (atom.right.value,)
    if isinstance(atom, Between):
        return (atom.lower.value, atom.upper.value)
    return ()  # IsNull carries no constant


def _predicate_constants(predicate: Predicate | None) -> tuple[ExactValue, ...]:
    if predicate is None:
        return ()
    if isinstance(predicate, (And, Or)):
        return _atom_constants(predicate.left) + _atom_constants(predicate.right)
    return _atom_constants(predicate)


def check_predicate_constants(
    rule: RuleSpec, a_type: TypeSpec, b_type: TypeSpec, query: QuerySpec
) -> ConditionResult:
    """Every predicate constant must have the rule's literal kind and be
    representable on both sides (same judgment as the common value domain)."""
    condition = "predicate_constants"
    for value in _predicate_constants(query.predicate):
        result = check_common_value_domain(rule, a_type, b_type, value)
        if result.status is CheckStatus.VIOLATED:
            assert result.reason is not None
            return _violated(condition, result.reason, f"predicate constant: {result.detail}")
    return _satisfied(condition)


# --------------------------------------------------------------------------
# Q3 SUM budget (design 6.2.2 "SUM protection")
# --------------------------------------------------------------------------


def check_q3_sum_budget(
    rows: Rows, scale: int, budget: int = SUM_ABS_COEFFICIENT_BUDGET
) -> ConditionResult:
    """Sum of absolute values of all non-NULL inputs must not exceed ``budget``.

    ``scale`` is the exact scale of the loaded data (0 for integer logical
    data); values are folded to integer coefficients ``abs(coefficient)`` and
    compared against ``budget * 10**scale``.  Positive/negative cancellation
    cannot evade the budget because absolute values are summed, and a WHERE
    clause never relaxes the check: all loaded rows count.
    """
    if isinstance(scale, bool) or not isinstance(scale, int) or scale < 0:
        raise ContractError("check_q3_sum_budget scale must be a non-negative int")
    if isinstance(budget, bool) or not isinstance(budget, int) or budget <= 0:
        raise ContractError("check_q3_sum_budget budget must be a positive int")
    condition = "q3_sum_abs_budget"
    total = 0
    for row in rows.rows:
        value = row.value
        if isinstance(value, NullValue):
            continue
        if isinstance(value, IntegerValue):
            total += abs(value.value)
        elif isinstance(value, DecimalValue):
            total += abs(value.coefficient)
        else:
            return _violated(
                condition,
                ReasonCode.INVALID_STRUCTURE,
                f"rid {row.rid}: unsupported value kind for SUM budget",
            )
    limit = budget * 10**scale
    if total <= limit:
        return _satisfied(
            condition,
            f"absolute coefficient sum {total} within budget {limit} "
            f"({budget} * 10**{scale})",
        )
    return _violated(
        condition,
        ReasonCode.BUDGET_EXCEEDED,
        f"absolute coefficient sum {total} exceeds budget {limit} "
        f"({budget} * 10**{scale})",
    )


# --------------------------------------------------------------------------
# Q4 BIGINT intermediate-value domain (design 6.2.1 signed-add-sub)
# --------------------------------------------------------------------------


def check_bigint_intermediate(value: int, k: int) -> ConditionResult:
    """Both intermediate results ``value + k`` and ``value - k`` must stay in
    the signed BIGINT domain ``[-2^63, 2^63 - 1]``.

    Helper usable independently; with real generated cases the narrow side is
    at most INT so the check never fires, but it must exist and be testable
    on its own (design 6.4.1).
    """
    condition = "q4_bigint_intermediate"
    for label, result in (("v + k", value + k), ("v - k", value - k)):
        if not _BIGINT_LO <= result <= _BIGINT_HI:
            return _violated(
                condition,
                ReasonCode.VALUE_OUT_OF_DOMAIN,
                f"intermediate {label} = {result} outside signed BIGINT "
                f"[{_BIGINT_LO}, {_BIGINT_HI}]",
            )
    return _satisfied(
        condition, f"v={value}, k={k}: both intermediates within signed BIGINT"
    )


def check_q4_arithmetic(
    rows: Rows, arithmetic: Arithmetic | None, a_type: TypeSpec, b_type: TypeSpec
) -> ConditionResult:
    """Q4 preconditions: k in [-16, 16] and every non-NULL loaded value keeps
    both intermediate results inside the signed BIGINT domain."""
    condition = "q4_bigint_domain"
    if not isinstance(arithmetic, Arithmetic):
        return _violated(
            condition,
            ReasonCode.INVALID_STRUCTURE,
            "Q4 requires exactly one v +/- k arithmetic node",
        )
    k = arithmetic.constant.value
    if not ARITHMETIC_K_MIN <= k <= ARITHMETIC_K_MAX:
        return _violated(
            condition,
            ReasonCode.VALUE_OUT_OF_DOMAIN,
            f"arithmetic constant k={k} outside [{ARITHMETIC_K_MIN}, "
            f"{ARITHMETIC_K_MAX}]",
        )
    for row in rows.rows:
        value = row.value
        if isinstance(value, NullValue):
            continue
        if not isinstance(value, IntegerValue):
            return _violated(
                condition,
                ReasonCode.INVALID_STRUCTURE,
                f"rid {row.rid}: Q4 accepts integer/NULL logical values only",
            )
        result = check_bigint_intermediate(value.value, k)
        if result.status is CheckStatus.VIOLATED:
            assert result.reason is not None
            return _violated(
                condition, result.reason, f"rid {row.rid}: {result.detail}"
            )
    return _satisfied(condition, f"k={k}; {len(rows.rows)} rows checked")


# --------------------------------------------------------------------------
# Rule binding whitelist and aggregate entry point
# --------------------------------------------------------------------------


def check_rule_binding(
    rule: RuleSpec, a_type: TypeSpec, b_type: TypeSpec, template_id: TemplateId
) -> ConditionResult:
    """(A, B) type pair and template must be exactly whitelisted by the rule."""
    condition = "rule_binding"
    if template_id not in rule.templates:
        return _violated(
            condition,
            ReasonCode.INVALID_STRUCTURE,
            f"template {str(template_id.value)} is not allowed by rule "
            f"{rule.rule_id}@{rule.rule_version}",
        )
    if (a_type, b_type) not in rule.type_pairs:
        return _violated(
            condition,
            ReasonCode.INVALID_STRUCTURE,
            f"type pair ({a_type.to_obj()}, {b_type.to_obj()}) is not allowed by "
            f"rule {rule.rule_id}@{rule.rule_version}",
        )
    return _satisfied(condition)


def check_exact_domain(
    rule: RuleSpec, a_type: TypeSpec, b_type: TypeSpec, rows: Rows, query: QuerySpec
) -> tuple[ConditionResult, ...]:
    """Full offline domain check for one case: rule binding, shared rows,
    predicate constants and the template-specific arithmetic safety checks."""
    conditions = [check_rule_binding(rule, a_type, b_type, query.template_id)]
    conditions.append(check_rows_domain(rule, a_type, b_type, rows))
    conditions.append(check_predicate_constants(rule, a_type, b_type, query))
    if query.template_id is TemplateId.Q3:
        budget = rule.sum_abs_coefficient_budget
        if budget is None:  # guarded by the RuleSpec invariant for Q3 rules
            raise ContractError(
                f"rule {rule.rule_id} allows Q3 without a SUM budget; "
                "registry definition is inconsistent"
            )
        scale = a_type.scale if isinstance(a_type, DecimalType) else 0
        conditions.append(check_q3_sum_budget(rows, scale, budget))
    if query.template_id is TemplateId.Q4:
        conditions.append(check_q4_arithmetic(rows, query.arithmetic, a_type, b_type))
    return tuple(conditions)


# --------------------------------------------------------------------------
# Result relation derivation (design 6.2.2)
# --------------------------------------------------------------------------


def _family(type_spec: TypeSpec) -> TypeFamily:
    if isinstance(type_spec, SignedIntegerType):
        return TypeFamily.SIGNED_INTEGER
    return TypeFamily.DECIMAL


def derive_relation(
    rule_ref: RuleRef, a_type: TypeSpec, b_type: TypeSpec, template_id: TemplateId
) -> ResultRelationSpec:
    """Derive the declared result relation for one rule binding.

    Q1 and Q3 MIN/MAX take each side's column family; Q2, Q3 COUNT(*)/COUNT(v)
    and Q4 are signed_integer on both sides; Q3 SUM is decimal on both sides.
    ``null_policy`` is ``forbid`` for COUNT/rid columns and ``preserve``
    otherwise.  ``value_equivalence=exact_numeric`` and
    ``mode=multiset_exact`` everywhere.
    """
    if not isinstance(rule_ref, RuleRef):
        raise ContractError("derive_relation rule_ref must be a RuleRef")
    equivalence = ValueEquivalence.EXACT_NUMERIC
    a_family = _family(a_type)
    b_family = _family(b_type)
    if template_id is TemplateId.Q1:
        columns = (
            ResultColumnSpec("c0", a_family, b_family, equivalence, NullPolicy.PRESERVE),
        )
    elif template_id is TemplateId.Q2:
        columns = (
            ResultColumnSpec(
                "c0",
                TypeFamily.SIGNED_INTEGER,
                TypeFamily.SIGNED_INTEGER,
                equivalence,
                NullPolicy.FORBID,
            ),
        )
    elif template_id is TemplateId.Q3:
        columns = (
            ResultColumnSpec(
                "c0",
                TypeFamily.SIGNED_INTEGER,
                TypeFamily.SIGNED_INTEGER,
                equivalence,
                NullPolicy.FORBID,
            ),
            ResultColumnSpec(
                "c1",
                TypeFamily.SIGNED_INTEGER,
                TypeFamily.SIGNED_INTEGER,
                equivalence,
                NullPolicy.FORBID,
            ),
            ResultColumnSpec("c2", a_family, b_family, equivalence, NullPolicy.PRESERVE),
            ResultColumnSpec("c3", a_family, b_family, equivalence, NullPolicy.PRESERVE),
            ResultColumnSpec(
                "c4", TypeFamily.DECIMAL, TypeFamily.DECIMAL, equivalence, NullPolicy.PRESERVE
            ),
        )
    elif template_id is TemplateId.Q4:
        columns = (
            ResultColumnSpec(
                "c0",
                TypeFamily.SIGNED_INTEGER,
                TypeFamily.SIGNED_INTEGER,
                equivalence,
                NullPolicy.PRESERVE,
            ),
        )
    else:
        raise ContractError(f"unknown template {template_id!r}")
    return ResultRelationSpec(RelationMode.MULTISET_EXACT, columns)
