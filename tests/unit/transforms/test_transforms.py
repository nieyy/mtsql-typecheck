"""T01 transform tests (design 6.4.3, 6.3.1 ``apply_transform``; Phase 4).

Every expectation in this file is hand-written from the design and from the
frozen contract models: expected child rows/predicates are constructed
literally, expected rejection reasons are the reason codes of the named
validator conditions, and none is computed by calling ``apply_transform``
(the function under test).  ``validate_case`` is called only as an
independent re-derivation of a child's validity and of the parent's
precondition, never to produce an expectation.

Payload construction mirrors the frozen contract models (the relation
columns are transcribed by hand from design 6.2.2, not derived from
``derive_relation``).
"""

from __future__ import annotations

import dataclasses
import inspect
import json

import pytest

from mtsql_typecheck.contracts.case import (
    And,
    Arithmetic,
    ArithmeticOp,
    Between,
    CasePayload,
    CheckStatus,
    ColumnSpec,
    Compare,
    CompareOp,
    CompatibilityCheck,
    ContractError,
    DecimalType,
    DecimalValue,
    EnvironmentRequirements,
    ExactLiteral,
    IndexVariant,
    IntegerValue,
    IsNull,
    NullPolicy,
    NullValue,
    Or,
    PathNode,
    Projection,
    Provenance,
    QuerySpec,
    ReasonCode,
    RelationMode,
    RemoveRows,
    ReplaceLiteral,
    ReplaceValue,
    ResultColumnSpec,
    ResultRelationSpec,
    Row,
    Rows,
    RuleRef,
    SemverIdentity,
    SignedIntegerType,
    SignedIntName,
    SimplifyPredicate,
    StaticCheckStatus,
    TableSpec,
    TemplateId,
    TransformStatus,
    TransformResult,
    TypeFamily,
    ValueEquivalence,
    REQUIRED_SQL_MODE_TOKENS,
)
from mtsql_typecheck.contracts.codec import case_id_of, dump_payload
from mtsql_typecheck.generation.transforms import apply_transform, list_rejected
from mtsql_typecheck.generation.validation import validate_case

TINYINT = SignedIntegerType(SignedIntName.TINYINT)
SMALLINT = SignedIntegerType(SignedIntName.SMALLINT)
INT = SignedIntegerType(SignedIntName.INT)
BIGINT = SignedIntegerType(SignedIntName.BIGINT)
DEC92 = DecimalType(9, 2)
DEC182 = DecimalType(18, 2)
DEC200 = DecimalType(20, 0)


# --------------------------------------------------------------------------
# Hand-written payload construction helpers
# --------------------------------------------------------------------------


def _family(type_spec) -> TypeFamily:
    return TypeFamily(type_spec.kind)


def _relation(query: QuerySpec, a_type, b_type) -> ResultRelationSpec:
    """Relation columns transcribed by hand from design 6.2.2."""
    templates: dict[TemplateId, list[tuple[str, TypeFamily, TypeFamily, NullPolicy]]] = {
        TemplateId.Q1: [("c0", _family(a_type), _family(b_type), NullPolicy.PRESERVE)],
        TemplateId.Q2: [
            ("c0", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.FORBID)
        ],
        TemplateId.Q3: [
            ("c0", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.FORBID),
            ("c1", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.FORBID),
            ("c2", _family(a_type), _family(b_type), NullPolicy.PRESERVE),
            ("c3", _family(a_type), _family(b_type), NullPolicy.PRESERVE),
            ("c4", TypeFamily.DECIMAL, TypeFamily.DECIMAL, NullPolicy.PRESERVE),
        ],
        TemplateId.Q4: [
            ("c0", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.PRESERVE)
        ],
    }
    columns = tuple(
        ResultColumnSpec(alias, a_family, b_family, ValueEquivalence.EXACT_NUMERIC, null_policy)
        for alias, a_family, b_family, null_policy in templates[query.template_id]
    )
    return ResultRelationSpec(RelationMode.MULTISET_EXACT, columns)


def make_payload(
    *,
    a_type,
    b_type,
    rows: Rows,
    query: QuerySpec,
    rule_id: str = "mysql80.signed-widen",
) -> CasePayload:
    table = TableSpec(
        logical_id="t0",
        columns=(
            ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
            ColumnSpec("v", a_type, True),
        ),
        primary_key=("rid",),
        index_variant=IndexVariant.NONE,
    )
    return CasePayload(
        rule=RuleRef(rule_id, 1),
        a_type=a_type,
        b_type=b_type,
        table=table,
        rows=rows,
        query=query,
        relation=_relation(query, a_type, b_type),
        environment=EnvironmentRequirements(
            database="mysql80",
            engine="innodb",
            scope="same-instance",
            sql_mode_tokens=REQUIRED_SQL_MODE_TOKENS,
            character_set="utf8mb4",
            collation="utf8mb4_bin",
            time_zone="+00:00",
        ),
        generator=SemverIdentity("g1", "1"),
        renderer=SemverIdentity("r1", "1"),
    )


def int_rows(*values: int | None) -> Rows:
    """rids 1..n; a None entry is the shared NULL value."""
    return Rows(
        tuple(
            Row(index + 1, NullValue() if value is None else IntegerValue(value))
            for index, value in enumerate(values)
        )
    )


def dec_rows(scale: int, *coefficients: int) -> Rows:
    """rids 1..n of same-scale decimal values."""
    return Rows(
        tuple(Row(index + 1, DecimalValue(coefficient, scale)) for index, coefficient in enumerate(coefficients))
    )


def condition_map(check: CompatibilityCheck) -> dict[str, object]:
    return {condition.condition_id: condition for condition in check.conditions}


# --------------------------------------------------------------------------
# Shared assertions (hand-written expectations of the transform contract)
# --------------------------------------------------------------------------


def _snapshot(payload: CasePayload) -> tuple[str, bytes]:
    return (case_id_of(payload), dump_payload(payload))


def _assert_applied(result: TransformResult, parent: CasePayload, snapshot) -> None:
    parent_id, parent_bytes = snapshot
    assert result.status is TransformStatus.APPLIED
    assert result.rejection_reason is None
    child = result.child
    assert child is not None
    assert result.static_check is not None
    # Identity is content-derived and differs from the parent.
    assert child.case_id != parent_id
    assert child.case_id == case_id_of(child.payload)
    assert result.static_check.case_id == child.case_id
    # The child independently passes full static validation.
    assert result.static_check.status is StaticCheckStatus.VALID_STATIC
    assert str(result.static_check.stage.value) == "static"
    assert validate_case(child.payload).status is StaticCheckStatus.VALID_STATIC
    # The parent payload is untouched.
    assert case_id_of(parent) == parent_id
    assert dump_payload(parent) == parent_bytes
    # The child really differs from the parent.
    assert dump_payload(child.payload) != parent_bytes
    # No inherited run conclusions: the child's check is a fresh static check
    # whose runtime conditions are PENDING/missing_fact only.
    runtime = [
        condition
        for condition in result.static_check.conditions
        if condition.condition_id.startswith("runtime_")
    ]
    assert [condition.condition_id for condition in runtime] == [
        "runtime_environment",
        "runtime_load",
        "runtime_isolation",
    ]
    for condition in runtime:
        assert condition.status is CheckStatus.PENDING
        assert condition.reason is ReasonCode.MISSING_FACT
    encoded = json.dumps(result.static_check.to_obj())
    for word in ("READY", "BLOCKED", "INCOMPLETE"):
        assert word not in encoded


def _assert_rejected(result: TransformResult, reason: ReasonCode) -> None:
    assert result.status is TransformStatus.REJECTED
    assert result.rejection_reason is reason
    assert result.child is None  # no executable child exists
    assert result.static_check is None


# --------------------------------------------------------------------------
# remove_rows
# --------------------------------------------------------------------------


class TestRemoveRows:
    def test_remove_all_null_rows_keeps_remaining_rids(self):
        # signed-widen INT->BIGINT, Q1; rid 2 is the only NULL row.
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(0, None, 5, -5),
            query=QuerySpec(TemplateId.Q1),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, RemoveRows((2,)))
        _assert_applied(result, parent, snapshot)
        # Remaining rids keep their original values and order: 1, 3, 4 - no
        # renumbering to 1, 2, 3.
        assert result.child.payload.rows == Rows(
            (
                Row(1, IntegerValue(0)),
                Row(3, IntegerValue(5)),
                Row(4, IntegerValue(-5)),
            )
        )

    def test_remove_several_rows_q2(self):
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(1, 2, 3),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.GT, ExactLiteral(IntegerValue(0))),
            ),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, RemoveRows((1, 3)))
        _assert_applied(result, parent, snapshot)
        assert result.child.payload.rows == Rows((Row(2, IntegerValue(2)),))

    def test_remove_down_to_empty_table_is_valid_static(self):
        # decimal-widen DECIMAL(9,2)->DECIMAL(18,2), Q1; deleting the only
        # row yields the empty table, which stays VALID_STATIC.
        parent = make_payload(
            a_type=DEC92,
            b_type=DEC182,
            rows=dec_rows(2, 0),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.decimal-widen",
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, RemoveRows((1,)))
        _assert_applied(result, parent, snapshot)
        assert result.child.payload.rows.rows == ()

    def test_missing_rid_is_rejected(self):
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(1),
            query=QuerySpec(TemplateId.Q1),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, RemoveRows((999,)))
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)
        # The parent is untouched by the rejected attempt.
        assert dump_payload(parent) == snapshot[1]

    def test_empty_rid_list_is_no_change(self):
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(1),
            query=QuerySpec(TemplateId.Q1),
        )
        result = apply_transform(parent, RemoveRows(()))
        assert result.status is TransformStatus.NO_CHANGE
        assert result.child is None
        assert result.static_check is None
        assert result.rejection_reason is None


# --------------------------------------------------------------------------
# replace_value
# --------------------------------------------------------------------------


class TestReplaceValue:
    def test_replace_with_zero_q3_signed_widen(self):
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(1, 2, None),
            query=QuerySpec(TemplateId.Q3),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, ReplaceValue(1, IntegerValue(0)))
        _assert_applied(result, parent, snapshot)
        assert result.child.payload.rows == Rows(
            (Row(1, IntegerValue(0)), Row(2, IntegerValue(2)), Row(3, NullValue()))
        )

    def test_replace_with_null_integer_decimal_q1(self):
        parent = make_payload(
            a_type=BIGINT,
            b_type=DEC200,
            rows=int_rows(None, 0, 9007199254740993),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.integer-decimal",
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, ReplaceValue(3, NullValue()))
        _assert_applied(result, parent, snapshot)
        assert result.child.payload.rows == Rows(
            (Row(1, NullValue()), Row(2, IntegerValue(0)), Row(3, NullValue()))
        )

    def test_replace_with_smaller_legal_decimal_q2(self):
        parent = make_payload(
            a_type=DEC92,
            b_type=DEC182,
            rows=dec_rows(2, 150, -25),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.LE, ExactLiteral(DecimalValue(100, 2))),
            ),
            rule_id="mysql80.decimal-widen",
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, ReplaceValue(1, DecimalValue(50, 2)))
        _assert_applied(result, parent, snapshot)
        assert result.child.payload.rows == Rows(
            (Row(1, DecimalValue(50, 2)), Row(2, DecimalValue(-25, 2)))
        )

    def test_replace_with_same_value_is_no_change(self):
        parent = make_payload(
            a_type=BIGINT,
            b_type=DEC200,
            rows=int_rows(None, 0),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.integer-decimal",
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, ReplaceValue(2, IntegerValue(0)))
        assert result.status is TransformStatus.NO_CHANGE
        # NO_CHANGE is not a reduction success: no child, no check, no reason.
        assert result.status is not TransformStatus.APPLIED
        assert result.child is None
        assert result.static_check is None
        assert result.rejection_reason is None
        assert dump_payload(parent) == snapshot[1]

    def test_replace_breaking_q3_sum_budget_is_rejected(self):
        # Hand-written budget arithmetic: existing non-NULL sum is 5; after
        # replacing rid 1 (value 0) with 10**12 the sum is 10**12 + 5, which
        # exceeds the 10**12 coefficient budget.
        parent = make_payload(
            a_type=BIGINT,
            b_type=DEC200,
            rows=int_rows(0, 5),
            query=QuerySpec(TemplateId.Q3),
            rule_id="mysql80.integer-decimal",
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, ReplaceValue(1, IntegerValue(10**12)))
        _assert_rejected(result, ReasonCode.BUDGET_EXCEEDED)
        assert dump_payload(parent) == snapshot[1]

    def test_replace_outside_tinyint_domain_is_rejected(self):
        # 100 fits signed TINYINT [-128, 127]; 200 does not.
        parent = make_payload(
            a_type=TINYINT,
            b_type=SMALLINT,
            rows=int_rows(100),
            query=QuerySpec(TemplateId.Q1),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, ReplaceValue(1, IntegerValue(200)))
        _assert_rejected(result, ReasonCode.VALUE_OUT_OF_DOMAIN)
        assert dump_payload(parent) == snapshot[1]

    def test_replace_missing_rid_is_rejected(self):
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(1),
            query=QuerySpec(TemplateId.Q1),
        )
        result = apply_transform(parent, ReplaceValue(9, IntegerValue(0)))
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)

    def test_single_sided_value_edit_is_unrepresentable(self):
        # Design 6.4.3: replace_value is a shared-value replacement; a
        # single-sided modification must be unrepresentable.  This is
        # guaranteed by the type system, not by runtime filtering:
        # - ReplaceValue carries exactly one shared (rid, value) pair and no
        #   side selector; the closed Transform union has no other
        #   value-editing node;
        # - CasePayload holds exactly one logical `rows` sequence (one Rows
        #   object serving A and B), so there is no per-side row store any
        #   transform could address;
        # - apply_transform(payload, transform) takes no side parameter.
        assert {field.name for field in dataclasses.fields(ReplaceValue)} == {
            "rid",
            "value",
            "kind",
        }
        payload_fields = {field.name for field in dataclasses.fields(CasePayload)}
        assert "rows" in payload_fields
        assert not any("rows_a" in name or "rows_b" in name for name in payload_fields)
        parameters = tuple(inspect.signature(apply_transform).parameters)
        assert parameters == ("payload", "transform")


# --------------------------------------------------------------------------
# simplify_predicate
# --------------------------------------------------------------------------


class TestSimplifyPredicate:
    def test_and_simplifies_to_left_atom_q2(self):
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(None, 5),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=And(
                    Compare(CompareOp.GE, ExactLiteral(IntegerValue(0))),
                    IsNull(True),
                ),
            ),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, SimplifyPredicate((PathNode.PREDICATE, PathNode.LEFT)))
        _assert_applied(result, parent, snapshot)
        # (A AND B) -> A: the compound node is replaced by the existing atom.
        assert result.child.payload.query.predicate == Compare(
            CompareOp.GE, ExactLiteral(IntegerValue(0))
        )

    def test_or_simplifies_to_right_atom_q2(self):
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(3, -3),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Or(
                    Between(
                        ExactLiteral(IntegerValue(-3)), ExactLiteral(IntegerValue(-3))
                    ),
                    IsNull(False),
                ),
            ),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, SimplifyPredicate((PathNode.PREDICATE, PathNode.RIGHT)))
        _assert_applied(result, parent, snapshot)
        assert result.child.payload.query.predicate == IsNull(False)

    def test_and_simplifies_to_left_atom_decimal_widen_q3(self):
        parent = make_payload(
            a_type=DEC92,
            b_type=DEC182,
            rows=dec_rows(2, 150, -25),
            query=QuerySpec(
                TemplateId.Q3,
                predicate=And(
                    Compare(CompareOp.LE, ExactLiteral(DecimalValue(100, 2))),
                    IsNull(False),
                ),
            ),
            rule_id="mysql80.decimal-widen",
        )
        snapshot = _snapshot(parent)
        result = apply_transform(parent, SimplifyPredicate((PathNode.PREDICATE, PathNode.LEFT)))
        _assert_applied(result, parent, snapshot)
        assert result.child.payload.query.predicate == Compare(
            CompareOp.LE, ExactLiteral(DecimalValue(100, 2))
        )

    def test_path_pointing_at_non_compound_predicate_is_rejected(self):
        # The root predicate is an atom; there is no AND/OR node to simplify.
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(1),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.GT, ExactLiteral(IntegerValue(0))),
            ),
        )
        result = apply_transform(parent, SimplifyPredicate((PathNode.PREDICATE, PathNode.LEFT)))
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)

    def test_path_beyond_the_compound_level_is_rejected(self):
        # The frozen IR allows one compound level; a second branch step is
        # out of range.
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(None, 5),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=And(
                    Compare(CompareOp.GE, ExactLiteral(IntegerValue(0))),
                    IsNull(True),
                ),
            ),
        )
        result = apply_transform(
            parent,
            SimplifyPredicate((PathNode.PREDICATE, PathNode.LEFT, PathNode.LEFT)),
        )
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)

    def test_path_with_step_the_node_does_not_have_is_rejected(self):
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(None, 5),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=And(
                    Compare(CompareOp.GE, ExactLiteral(IntegerValue(0))),
                    IsNull(True),
                ),
            ),
        )
        # A compound predicate has no lower/upper/constant/arithmetic slots.
        for step in (
            PathNode.LOWER,
            PathNode.UPPER,
            PathNode.CONSTANT,
            PathNode.ARITHMETIC,
        ):
            result = apply_transform(parent, SimplifyPredicate((PathNode.PREDICATE, step)))
            _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)

    def test_removing_the_only_q2_predicate_is_unrepresentable(self):
        # Design 6.4.3/T01: a simplification must not remove Q2's only
        # predicate.  No public transform can express predicate removal:
        # - SimplifyPredicate requires at least two steps starting with
        #   'predicate', and its application always yields an existing atom
        #   of the compound, so the predicate can never become None;
        # - the Q2 template itself forbids a predicate-free QuerySpec at the
        #   model layer, and the transforms module additionally guards the
        #   invariant explicitly.
        with pytest.raises(ContractError):
            SimplifyPredicate((PathNode.PREDICATE,))
        with pytest.raises(ContractError):
            QuerySpec(TemplateId.Q2)
        # And an applied simplification keeps a (non-None) predicate:
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(None, 5),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=And(
                    Compare(CompareOp.GE, ExactLiteral(IntegerValue(0))),
                    IsNull(True),
                ),
            ),
        )
        result = apply_transform(parent, SimplifyPredicate((PathNode.PREDICATE, PathNode.LEFT)))
        assert result.status is TransformStatus.APPLIED
        assert result.child.payload.query.predicate is not None


# --------------------------------------------------------------------------
# replace_literal
# --------------------------------------------------------------------------


class TestReplaceLiteral:
    def test_compare_constant_replacement_q2(self):
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(5, 20),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.GE, ExactLiteral(IntegerValue(5))),
            ),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.RIGHT, PathNode.CONSTANT),
                IntegerValue(10),
            ),
        )
        _assert_applied(result, parent, snapshot)
        assert result.child.payload.query.predicate == Compare(
            CompareOp.GE, ExactLiteral(IntegerValue(10))
        )

    def test_compare_constant_replaced_by_null_q2(self):
        # NULL is legal at the constant position of a plain comparison
        # (design 6.2.2); NULL-safe equality keeps the predicate legal.
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(0),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.NULL_SAFE_EQ, ExactLiteral(IntegerValue(0))),
            ),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.RIGHT, PathNode.CONSTANT),
                NullValue(),
            ),
        )
        _assert_applied(result, parent, snapshot)
        assert result.child.payload.query.predicate == Compare(
            CompareOp.NULL_SAFE_EQ, ExactLiteral(NullValue())
        )

    @pytest.mark.parametrize("new_k", [16, 0, -16])
    def test_q4_arithmetic_k_replacement(self, new_k):
        # Q4's k is addressed through the same replace_literal entry point:
        # ("predicate", "arithmetic", "constant").
        old_arithmetic = Arithmetic(ArithmeticOp.ADD, IntegerValue(5))
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(100, -100),
            query=QuerySpec(
                TemplateId.Q4,
                arithmetic=old_arithmetic,
                projections=(Projection("c0", old_arithmetic),),
            ),
            rule_id="mysql80.signed-add-sub",
        )
        snapshot = _snapshot(parent)
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.ARITHMETIC, PathNode.CONSTANT),
                IntegerValue(new_k),
            ),
        )
        _assert_applied(result, parent, snapshot)
        expected_arithmetic = Arithmetic(ArithmeticOp.ADD, IntegerValue(new_k))
        assert result.child.payload.query.arithmetic == expected_arithmetic
        # The Q4 projection is re-bound to the new arithmetic node.
        assert result.child.payload.query.projections == (
            Projection("c0", expected_arithmetic),
        )

    def test_between_lower_endpoint_replacement(self):
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(3),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Between(
                    ExactLiteral(IntegerValue(1)), ExactLiteral(IntegerValue(5))
                ),
            ),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.LOWER, PathNode.CONSTANT),
                IntegerValue(2),
            ),
        )
        _assert_applied(result, parent, snapshot)
        # lower 2 <= upper 5 keeps the BETWEEN legal.
        assert result.child.payload.query.predicate == Between(
            ExactLiteral(IntegerValue(2)), ExactLiteral(IntegerValue(5))
        )

    def test_compound_atom_constant_replacement(self):
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(None, 5),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=And(
                    Compare(CompareOp.GE, ExactLiteral(IntegerValue(0))),
                    IsNull(True),
                ),
            ),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.LEFT, PathNode.RIGHT, PathNode.CONSTANT),
                IntegerValue(5),
            ),
        )
        _assert_applied(result, parent, snapshot)
        assert result.child.payload.query.predicate == And(
            Compare(CompareOp.GE, ExactLiteral(IntegerValue(5))),
            IsNull(True),
        )

    def test_q4_k_seventeen_is_rejected(self):
        # k=17 leaves [-16, 16]: the first VIOLATED condition of the child's
        # revalidation is predicate_structure (checked before q4_bigint_domain
        # in the frozen condition order), so the reason is invalid_structure.
        old_arithmetic = Arithmetic(ArithmeticOp.ADD, IntegerValue(5))
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(100),
            query=QuerySpec(
                TemplateId.Q4,
                arithmetic=old_arithmetic,
                projections=(Projection("c0", old_arithmetic),),
            ),
            rule_id="mysql80.signed-add-sub",
        )
        snapshot = _snapshot(parent)
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.ARITHMETIC, PathNode.CONSTANT),
                IntegerValue(17),
            ),
        )
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)
        assert dump_payload(parent) == snapshot[1]

    @pytest.mark.parametrize(
        "value",
        [
            DecimalValue(1, 0),  # decimal literal is not an integer k
            NullValue(),  # NULL is not an integer k
        ],
    )
    def test_q4_k_with_wrong_literal_kind_is_rejected(self, value):
        old_arithmetic = Arithmetic(ArithmeticOp.ADD, IntegerValue(5))
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(100),
            query=QuerySpec(
                TemplateId.Q4,
                arithmetic=old_arithmetic,
                projections=(Projection("c0", old_arithmetic),),
            ),
            rule_id="mysql80.signed-add-sub",
        )
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.ARITHMETIC, PathNode.CONSTANT),
                value,
            ),
        )
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)

    def test_decimal_constant_with_wrong_scale_is_rejected(self):
        # decimal-widen accepts same-scale decimal/NULL constants only; a
        # scale-3 decimal is not auto-converted even though the value fits.
        parent = make_payload(
            a_type=DEC92,
            b_type=DEC182,
            rows=dec_rows(2, 300),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.LE, ExactLiteral(DecimalValue(100, 2))),
            ),
            rule_id="mysql80.decimal-widen",
        )
        snapshot = _snapshot(parent)
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.RIGHT, PathNode.CONSTANT),
                DecimalValue(100, 3),
            ),
        )
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)
        assert dump_payload(parent) == snapshot[1]

    def test_integer_rule_decimal_constant_is_rejected(self):
        # integer-decimal accepts integer/NULL constants only; a scale-0
        # decimal literal of the same mathematical value is still rejected.
        parent = make_payload(
            a_type=BIGINT,
            b_type=DEC200,
            rows=int_rows(5),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.LE, ExactLiteral(IntegerValue(5))),
            ),
            rule_id="mysql80.integer-decimal",
        )
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.RIGHT, PathNode.CONSTANT),
                DecimalValue(5, 0),
            ),
        )
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)

    def test_between_endpoint_reversal_is_rejected(self):
        # Replacing the upper endpoint with 0 makes lower 1 > upper 0; the
        # child revalidation's first VIOLATED condition is predicate_structure.
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(3),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Between(
                    ExactLiteral(IntegerValue(1)), ExactLiteral(IntegerValue(5))
                ),
            ),
        )
        snapshot = _snapshot(parent)
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.UPPER, PathNode.CONSTANT),
                IntegerValue(0),
            ),
        )
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)
        assert dump_payload(parent) == snapshot[1]

    def test_path_without_constant_step_is_rejected(self):
        # The path must end at a constant slot; ("predicate", "right") stops
        # short of the exact value.
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(5),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.GE, ExactLiteral(IntegerValue(5))),
            ),
        )
        result = apply_transform(
            parent,
            ReplaceLiteral((PathNode.PREDICATE, PathNode.RIGHT), IntegerValue(10)),
        )
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)

    def test_arithmetic_path_on_non_q4_template_is_rejected(self):
        # A Q2 payload has no arithmetic node to address.
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(5),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.GE, ExactLiteral(IntegerValue(5))),
            ),
        )
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.ARITHMETIC, PathNode.CONSTANT),
                IntegerValue(1),
            ),
        )
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)

    def test_path_into_is_null_atom_is_rejected(self):
        # IsNull carries no constant slot.
        parent = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(5),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=And(
                    IsNull(False),
                    Compare(CompareOp.GT, ExactLiteral(IntegerValue(0))),
                ),
            ),
        )
        result = apply_transform(
            parent,
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.LEFT, PathNode.RIGHT, PathNode.CONSTANT),
                IntegerValue(1),
            ),
        )
        _assert_rejected(result, ReasonCode.INVALID_STRUCTURE)


# --------------------------------------------------------------------------
# General transform contract
# --------------------------------------------------------------------------


class TestGeneralTransformContract:
    def _parent(self) -> CasePayload:
        return make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(None, 5, -5),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=And(
                    Compare(CompareOp.GE, ExactLiteral(IntegerValue(0))),
                    IsNull(True),
                ),
            ),
        )

    def test_parent_is_never_mutated_by_any_transform(self):
        parent = self._parent()
        snapshot = _snapshot(parent)
        transforms = [
            RemoveRows((1,)),
            ReplaceValue(2, NullValue()),
            SimplifyPredicate((PathNode.PREDICATE, PathNode.RIGHT)),
            ReplaceLiteral(
                (PathNode.PREDICATE, PathNode.LEFT, PathNode.RIGHT, PathNode.CONSTANT),
                IntegerValue(3),
            ),
            RemoveRows((999,)),  # rejected attempt
        ]
        for transform in transforms:
            apply_transform(parent, transform)
        assert case_id_of(parent) == snapshot[0]
        assert dump_payload(parent) == snapshot[1]

    def test_transforms_cannot_change_rule_types_or_template(self):
        # Cross-rule transforms are impossible by construction: no transform
        # model carries a rule, type or template field, so D2 cannot express
        # switching the rule, narrowing a column type, changing the scale or
        # switching the query template.
        forbidden = {"rule", "a_type", "b_type", "template", "query", "relation"}
        for transform_cls in (RemoveRows, ReplaceValue, SimplifyPredicate, ReplaceLiteral):
            names = {field.name for field in dataclasses.fields(transform_cls)}
            assert names & forbidden == set()
        # And an applied child keeps the parent's rule binding and types.
        parent = self._parent()
        result = apply_transform(parent, RemoveRows((1,)))
        child = result.child.payload
        assert child.rule == parent.rule
        assert child.a_type == parent.a_type
        assert child.b_type == parent.b_type
        assert child.query.template_id is parent.query.template_id
        assert child.relation == parent.relation

    def test_no_change_is_not_recorded_as_reduction_success(self):
        parent = self._parent()
        result = apply_transform(parent, ReplaceValue(2, IntegerValue(5)))
        assert str(result.status.value) == "NO_CHANGE"
        assert result.status is not TransformStatus.APPLIED
        assert result.status is not TransformStatus.REJECTED
        assert result.child is None

    def test_list_rejected_filters_and_preserves_order(self):
        parent = self._parent()
        applied = apply_transform(parent, RemoveRows((1,)))
        rejected = apply_transform(parent, RemoveRows((999,)))
        no_change = apply_transform(parent, ReplaceValue(2, IntegerValue(5)))
        assert list_rejected([applied, rejected, no_change, rejected]) == (
            rejected,
            rejected,
        )
        assert list_rejected([applied, no_change]) == ()
        assert list_rejected([]) == ()

    def test_malformed_input_types_raise(self):
        parent = self._parent()
        with pytest.raises(ContractError):
            apply_transform("not a payload", RemoveRows(()))  # type: ignore[arg-type]
        with pytest.raises(ContractError):
            apply_transform(parent, "not a transform")  # type: ignore[arg-type]

    def test_child_bundle_preview_and_provenance_marker(self):
        # The applied child bundle carries freshly derived preview SQL and a
        # zero provenance marker (provenance never enters case_id).
        parent = self._parent()
        result = apply_transform(parent, RemoveRows((1,)))
        child = result.child
        assert child.provenance == Provenance(
            seed=0, ordinal=0, profile_hash="0" * 64, retry=0
        )
        assert "CREATE TABLE `preview_a`" in child.preview_a_sql
        assert "CREATE TABLE `preview_b`" in child.preview_b_sql
        # Parent rows are (1,NULL),(2,5),(3,-5); removing rid 1 leaves the
        # remaining rids untouched in the INSERT text.
        assert "INSERT INTO `preview_a` VALUES (2,5),(3,-5);" in child.preview_a_sql
