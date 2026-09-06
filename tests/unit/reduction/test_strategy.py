"""S01 strategy tests for D2 Phase 4 (design 6.4.4, docs/oracle-d2-contract.md section 8).

Every expectation is hand-written from the design text: complexity components
are counted by hand on literal payloads, proposal sequences are transcribed
from the fixed 6.4.4 order, and none is computed by calling
``complexity``/``iter_proposals`` (the functions under test).  The only
reused primitive is ``codec.canonical_json`` for the byte-length component --
it is a D1 contract primitive already independently tested in
``tests/contract/test_case_codec.py``, so calling it here re-derives the
expected bytes independently of the strategy module.

Payload construction mirrors the frozen contract models (relation columns
transcribed by hand from design 6.2.2, not derived from ``derive_relation``).
"""

from __future__ import annotations

import pytest

from mtsql_typecheck.contracts.case import (
    And,
    Arithmetic,
    ArithmeticOp,
    Between,
    CasePayload,
    ColumnSpec,
    Compare,
    CompareOp,
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
    PathNode,
    Projection,
    QuerySpec,
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
    TableSpec,
    TemplateId,
    Transform,
    TransformStatus,
    TypeFamily,
    ValueEquivalence,
    REQUIRED_SQL_MODE_TOKENS,
)
from mtsql_typecheck.contracts.codec import canonical_json
from mtsql_typecheck.generation.transforms import apply_transform
from mtsql_typecheck.reduction.strategy import complexity, iter_proposals

TINYINT = SignedIntegerType(SignedIntName.TINYINT)
SMALLINT = SignedIntegerType(SignedIntName.SMALLINT)
INT = SignedIntegerType(SignedIntName.INT)
BIGINT = SignedIntegerType(SignedIntName.BIGINT)
DEC92 = DecimalType(9, 2)
DEC182 = DecimalType(18, 2)


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


def dec_rows(scale: int, *coefficients: int | None) -> Rows:
    """rids 1..n of same-scale decimal values; None is the shared NULL."""
    return Rows(
        tuple(
            Row(index + 1, NullValue() if coefficient is None else DecimalValue(coefficient, scale))
            for index, coefficient in enumerate(coefficients)
        )
    )


def collect(payload: CasePayload) -> list[Transform]:
    return list(iter_proposals(payload))


def of_kind(payload: CasePayload, kind: type) -> list[Transform]:
    return [proposal for proposal in collect(payload) if isinstance(proposal, kind)]


# --------------------------------------------------------------------------
# complexity: hand-computed vectors, one payload per template
# --------------------------------------------------------------------------


class TestComplexity:
    def test_q1_no_predicate_null_and_negative_rows(self):
        # rows 5, NULL, -7: row_count 3; no predicate -> 0 nodes;
        # non-NULL row values 2; magnitude |5| + |-7| = 12.
        payload = make_payload(a_type=TINYINT, b_type=SMALLINT, rows=int_rows(5, None, -7),
                               query=QuerySpec(TemplateId.Q1))
        expected_bytes = len(canonical_json(payload.to_obj()))
        # canonical_json is the D1 contract primitive independently tested in
        # tests/contract/test_case_codec.py; only the byte length is reused here.
        assert complexity(payload) == (3, 0, 2, 12, expected_bytes)

    def test_q2_single_compare_atom_counts_literal_slot(self):
        # rows NULL, -7, 5: 2 non-NULL values + literal 3 -> 3 values;
        # magnitude 7 + 5 + 3 = 15; predicate Compare -> 1 node.
        payload = make_payload(
            a_type=TINYINT,
            b_type=SMALLINT,
            rows=int_rows(None, -7, 5),
            query=QuerySpec(TemplateId.Q2, Compare(CompareOp.GT, ExactLiteral(IntegerValue(3)))),
        )
        expected_bytes = len(canonical_json(payload.to_obj()))
        assert complexity(payload) == (3, 1, 3, 15, expected_bytes)

    def test_q2_and_of_two_counts_three_predicate_nodes(self):
        # And(Compare, IsNull): 1 compound + 2 atoms = 3 nodes; literal 0 and
        # row value 1 are the non-NULL value slots; magnitude 1 + 0 = 1.
        payload = make_payload(
            a_type=TINYINT,
            b_type=SMALLINT,
            rows=int_rows(1),
            query=QuerySpec(
                TemplateId.Q2,
                And(
                    Compare(CompareOp.GE, ExactLiteral(IntegerValue(0))),
                    IsNull(negated=False),
                ),
            ),
        )
        expected_bytes = len(canonical_json(payload.to_obj()))
        assert complexity(payload) == (1, 3, 2, 1, expected_bytes)

    def test_q3_between_decimal_coefficients(self):
        # rows -12.50 (coefficient -1250), NULL, 0.07 (coefficient 7):
        # 2 non-NULL rows + 2 BETWEEN endpoints = 4 values; magnitude
        # 1250 + 7 + 100 + 100 = 1457; BETWEEN -> 1 node.
        payload = make_payload(
            a_type=DEC92,
            b_type=DEC182,
            rows=dec_rows(2, -1250, None, 7),
            query=QuerySpec(
                TemplateId.Q3,
                Between(
                    ExactLiteral(DecimalValue(-100, 2)),
                    ExactLiteral(DecimalValue(100, 2)),
                ),
            ),
            rule_id="mysql80.decimal-widen",
        )
        expected_bytes = len(canonical_json(payload.to_obj()))
        assert complexity(payload) == (3, 1, 4, 1457, expected_bytes)

    def test_q4_arithmetic_k_counted_exactly_once(self):
        # rows 10, NULL, -3 with k = -5 and no predicate: the projection
        # re-uses query.arithmetic's node, so k contributes exactly one value
        # (3 = 2 rows + k) and |k| once to the magnitude (10 + 3 + 5 = 18).
        arithmetic = Arithmetic(ArithmeticOp.SUBTRACT, IntegerValue(-5))
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(10, None, -3),
            query=QuerySpec(
                TemplateId.Q4,
                arithmetic=arithmetic,
                projections=(Projection("c0", arithmetic),),
            ),
            rule_id="mysql80.signed-add-sub",
        )
        expected_bytes = len(canonical_json(payload.to_obj()))
        assert complexity(payload) == (3, 0, 3, 18, expected_bytes)

    def test_non_payload_input_rejected(self):
        with pytest.raises(ContractError):
            complexity(None)  # type: ignore[arg-type]
        with pytest.raises(ContractError):
            complexity("not a payload")  # type: ignore[arg-type]
        with pytest.raises(ContractError):
            complexity(Rows(()))  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Phase 1: remove_rows order
# --------------------------------------------------------------------------


class TestRemoveRowsOrder:
    def test_exact_sequence_for_five_rows(self):
        # Hand-transcribed from design 6.4.4: delete-all; g=2 block i=1 over
        # [floor(5/2), floor(10/2)) = positions 2..4, then its complement;
        # i=2 block is empty (skipped); g=4 blocks [1,2) [2,3) [3,5) (i=4
        # empty); finally the single rows not already proposed.
        payload = make_payload(a_type=TINYINT, b_type=SMALLINT, rows=int_rows(9, 8, 7, 6, 5),
                               query=QuerySpec(TemplateId.Q1))
        expected = [
            (1, 2, 3, 4, 5),
            (3, 4, 5),  # g=2 block
            (1, 2),  # g=2 complement
            (2,),  # g=4 block i=1
            (1, 3, 4, 5),  # g=4 block i=1 complement
            (3,),  # g=4 block i=2
            (1, 2, 4, 5),  # g=4 block i=2 complement
            (4, 5),  # g=4 block i=3
            (1, 2, 3),  # g=4 block i=3 complement
            (1,),  # singles (2, 3 already proposed as g=4 blocks)
            (4,),
            (5,),
        ]
        actual = [proposal.rids for proposal in of_kind(payload, RemoveRows)]
        assert actual == expected

    def test_empty_rows_propose_nothing(self):
        payload = make_payload(a_type=TINYINT, b_type=SMALLINT, rows=Rows(()),
                               query=QuerySpec(TemplateId.Q1))
        # Q1 with no rows and no predicate has no other phase either.
        assert collect(payload) == []

    def test_single_row_only_delete_all(self):
        payload = make_payload(a_type=TINYINT, b_type=SMALLINT, rows=int_rows(42),
                               query=QuerySpec(TemplateId.Q1))
        assert [proposal.rids for proposal in of_kind(payload, RemoveRows)] == [(1,)]

    def test_two_rows_block_complement_duplicate_suppression(self):
        # g=2: block [1,2) = (2,), complement (1,); i=2 block is empty; the
        # later single-row proposals duplicate both and are suppressed.
        payload = make_payload(a_type=TINYINT, b_type=SMALLINT, rows=int_rows(4, 2),
                               query=QuerySpec(TemplateId.Q1))
        assert [proposal.rids for proposal in of_kind(payload, RemoveRows)] == [
            (1, 2),
            (2,),
            (1,),
        ]

    def test_three_rows_floor_block_boundaries(self):
        # g=2, n=3: block [floor(3/2), floor(6/2)) = [1,3) = (2, 3), then
        # complement (1,); singles (1,) is a duplicate, (2,) and (3,) are new.
        payload = make_payload(a_type=TINYINT, b_type=SMALLINT, rows=int_rows(5, 6, 7),
                               query=QuerySpec(TemplateId.Q1))
        assert [proposal.rids for proposal in of_kind(payload, RemoveRows)] == [
            (1, 2, 3),
            (2, 3),
            (1,),
            (2,),
            (3,),
        ]

    def test_rid_values_are_preserved_not_renumbered(self):
        payload = make_payload(
            a_type=TINYINT,
            b_type=SMALLINT,
            rows=Rows((Row(10, IntegerValue(1)), Row(20, IntegerValue(2)), Row(30, IntegerValue(3)))),
            query=QuerySpec(TemplateId.Q1),
        )
        for proposal in of_kind(payload, RemoveRows):
            for rid in proposal.rids:
                assert rid in (10, 20, 30)


# --------------------------------------------------------------------------
# Phase order across the four transform kinds
# --------------------------------------------------------------------------


def _and_predicate_payload() -> CasePayload:
    """Q2, five rows, compound predicate: exercises all four phases."""
    return make_payload(
        a_type=TINYINT,
        b_type=SMALLINT,
        rows=int_rows(-3, 7, None, 0, 12),
        query=QuerySpec(
            TemplateId.Q2,
            And(
                Compare(CompareOp.GT, ExactLiteral(IntegerValue(0))),
                Between(
                    ExactLiteral(IntegerValue(1)),
                    ExactLiteral(IntegerValue(10)),
                ),
            ),
        ),
    )


class TestPhaseOrder:
    def test_phases_run_in_design_order(self):
        payload = _and_predicate_payload()
        proposals = collect(payload)
        kinds = [type(proposal) for proposal in proposals]
        assert RemoveRows in kinds
        assert SimplifyPredicate in kinds
        assert ReplaceValue in kinds
        assert ReplaceLiteral in kinds
        # Each phase is fully drained before the next begins.
        last_remove = max(index for index, kind in enumerate(kinds) if kind is RemoveRows)
        first_simplify = kinds.index(SimplifyPredicate)
        last_simplify = max(index for index, kind in enumerate(kinds) if kind is SimplifyPredicate)
        first_replace_value = kinds.index(ReplaceValue)
        last_replace_value = max(index for index, kind in enumerate(kinds) if kind is ReplaceValue)
        first_replace_literal = kinds.index(ReplaceLiteral)
        assert last_remove < first_simplify
        assert last_simplify < first_replace_value
        assert last_replace_value < first_replace_literal

    def test_simplify_paths_are_left_then_right(self):
        payload = _and_predicate_payload()
        simplifications = of_kind(payload, SimplifyPredicate)
        assert [simplification.path for simplification in simplifications] == [
            (PathNode.PREDICATE, PathNode.LEFT),
            (PathNode.PREDICATE, PathNode.RIGHT),
        ]

    def test_replace_literal_slot_paths_in_ir_preorder(self):
        # Preorder: left Compare constant, then right Between lower, upper.
        # Each slot emits one proposal per candidate value, so paths repeat;
        # the deduplicated path order must still be the IR preorder.
        payload = _and_predicate_payload()
        unique_paths: list[tuple[PathNode, ...]] = []
        for proposal in of_kind(payload, ReplaceLiteral):
            if proposal.path not in unique_paths:
                unique_paths.append(proposal.path)
        assert unique_paths == [
            (PathNode.PREDICATE, PathNode.LEFT, PathNode.RIGHT, PathNode.CONSTANT),
            (PathNode.PREDICATE, PathNode.RIGHT, PathNode.LOWER, PathNode.CONSTANT),
            (PathNode.PREDICATE, PathNode.RIGHT, PathNode.UPPER, PathNode.CONSTANT),
        ]

    def test_between_endpoints_never_receive_null_proposals(self):
        payload = _and_predicate_payload()
        for proposal in of_kind(payload, ReplaceLiteral):
            if PathNode.LOWER in proposal.path or PathNode.UPPER in proposal.path:
                assert not isinstance(proposal.value, NullValue)

    def test_replace_value_rids_ascending(self):
        payload = _and_predicate_payload()
        rids = [proposal.rid for proposal in of_kind(payload, ReplaceValue)]
        assert rids == sorted(rids)
        assert set(rids) == {1, 2, 3, 4, 5}


# --------------------------------------------------------------------------
# Phase 3: replace_value candidate order
# --------------------------------------------------------------------------


class TestReplaceValueCandidates:
    def test_negative_decimal_candidates_use_slot_scale(self):
        # Current value -7.00 (coefficient -700, scale 2): NULL, 0.00, +unit
        # 0.01, -unit -0.01, then toward-zero half -3.50 (coefficient -350).
        payload = make_payload(
            a_type=DEC92,
            b_type=DEC182,
            rows=dec_rows(2, -700, 5),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.decimal-widen",
        )
        candidates = [proposal.value for proposal in of_kind(payload, ReplaceValue)
                      if proposal.rid == 1]
        assert candidates == [
            NullValue(),
            DecimalValue(0, 2),
            DecimalValue(1, 2),
            DecimalValue(-1, 2),
            DecimalValue(-350, 2),
        ]

    def test_dedup_when_value_equals_a_candidate(self):
        # Current 1: 1 is skipped (equals current) and its half 0 duplicates
        # the already-proposed 0; current 0: 0 is skipped and the half is 0.
        payload = make_payload(a_type=TINYINT, b_type=SMALLINT, rows=int_rows(1, 0),
                               query=QuerySpec(TemplateId.Q1))
        candidates = of_kind(payload, ReplaceValue)
        rid1 = [proposal.value for proposal in candidates if proposal.rid == 1]
        rid2 = [proposal.value for proposal in candidates if proposal.rid == 2]
        assert rid1 == [NullValue(), IntegerValue(0), IntegerValue(-1)]
        assert rid2 == [NullValue(), IntegerValue(1), IntegerValue(-1)]

    def test_negative_integer_halving_is_toward_zero(self):
        # Current -7: half is -3 (not -4, which floor division would give).
        payload = make_payload(a_type=TINYINT, b_type=SMALLINT, rows=int_rows(-7),
                               query=QuerySpec(TemplateId.Q1))
        candidates = [proposal.value for proposal in of_kind(payload, ReplaceValue)]
        assert candidates == [
            NullValue(),
            IntegerValue(0),
            IntegerValue(1),
            IntegerValue(-1),
            IntegerValue(-3),
        ]

    def test_null_row_value_proposes_integer_candidates(self):
        # A NULL shared value has no half; the unit keeps the payload's
        # integer kind.
        payload = make_payload(a_type=TINYINT, b_type=SMALLINT, rows=int_rows(None, 4),
                               query=QuerySpec(TemplateId.Q1))
        candidates = [proposal.value for proposal in of_kind(payload, ReplaceValue)
                      if proposal.rid == 1]
        assert candidates == [IntegerValue(0), IntegerValue(1), IntegerValue(-1)]


# --------------------------------------------------------------------------
# Phase 4: replace_literal candidate order and NULL placement
# --------------------------------------------------------------------------


class TestReplaceLiteralCandidates:
    @pytest.mark.parametrize(
        ("k", "expected_candidates"),
        [
            (5, [IntegerValue(0), IntegerValue(1), IntegerValue(-1), IntegerValue(2)]),
            (-5, [IntegerValue(0), IntegerValue(1), IntegerValue(-1), IntegerValue(-2)]),
            (1, [IntegerValue(0), IntegerValue(-1)]),
            (0, [IntegerValue(1), IntegerValue(-1)]),
        ],
    )
    def test_q4_constant_path_text_and_candidate_order(self, k, expected_candidates):
        arithmetic = Arithmetic(ArithmeticOp.ADD, IntegerValue(k))
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=int_rows(10, None, -3),
            query=QuerySpec(
                TemplateId.Q4,
                arithmetic=arithmetic,
                projections=(Projection("c0", arithmetic),),
            ),
            rule_id="mysql80.signed-add-sub",
        )
        literals = of_kind(payload, ReplaceLiteral)
        # Q4 with no predicate: the arithmetic constant is the only slot.
        assert [proposal.path for proposal in literals] == [
            (PathNode.PREDICATE, PathNode.ARITHMETIC, PathNode.CONSTANT)
        ] * len(expected_candidates)
        assert [str(step.value) for step in literals[0].path] == [
            "predicate",
            "arithmetic",
            "constant",
        ]
        assert [proposal.value for proposal in literals] == expected_candidates
        # The Q4 constant never accepts NULL.
        assert all(not isinstance(proposal.value, NullValue) for proposal in literals)

    def test_compare_constant_receives_null_last(self):
        # Q2 bare Compare: candidates 0, +unit, -unit, halve, then NULL last.
        payload = make_payload(
            a_type=TINYINT,
            b_type=SMALLINT,
            rows=int_rows(4),
            query=QuerySpec(TemplateId.Q2, Compare(CompareOp.LT, ExactLiteral(IntegerValue(9)))),
        )
        candidates = [proposal.value for proposal in of_kind(payload, ReplaceLiteral)]
        assert candidates == [
            IntegerValue(0),
            IntegerValue(1),
            IntegerValue(-1),
            IntegerValue(4),
            NullValue(),
        ]

    def test_non_q4_payload_has_no_arithmetic_constant_proposal(self):
        payload = _and_predicate_payload()
        for proposal in of_kind(payload, ReplaceLiteral):
            assert PathNode.ARITHMETIC not in proposal.path

    def test_predicate_none_has_no_simplify_and_no_literal(self):
        payload = make_payload(a_type=TINYINT, b_type=SMALLINT, rows=int_rows(1, 2),
                               query=QuerySpec(TemplateId.Q1))
        assert of_kind(payload, SimplifyPredicate) == []
        assert of_kind(payload, ReplaceLiteral) == []


# --------------------------------------------------------------------------
# Apply compatibility: every proposal round-trips through D1
# --------------------------------------------------------------------------


class TestApplyCompatibility:
    @pytest.mark.parametrize(
        "payload",
        [
            _and_predicate_payload(),
            make_payload(
                a_type=INT,
                b_type=BIGINT,
                rows=int_rows(10, None, -3),
                query=QuerySpec(
                    TemplateId.Q4,
                    arithmetic=Arithmetic(ArithmeticOp.ADD, IntegerValue(5)),
                    projections=(
                        Projection("c0", Arithmetic(ArithmeticOp.ADD, IntegerValue(5))),
                    ),
                ),
                rule_id="mysql80.signed-add-sub",
            ),
            make_payload(
                a_type=DEC92,
                b_type=DEC182,
                rows=dec_rows(2, -1250, None, 7),
                query=QuerySpec(
                    TemplateId.Q3,
                    Between(
                        ExactLiteral(DecimalValue(-100, 2)),
                        ExactLiteral(DecimalValue(100, 2)),
                    ),
                ),
                rule_id="mysql80.decimal-widen",
            ),
        ],
        ids=["q2-and", "q4-k", "q3-between-decimal"],
    )
    def test_every_proposal_applies_without_raising(self, payload):
        proposals = collect(payload)
        assert proposals, "the strategy must propose something for a non-trivial payload"
        for proposal in proposals:
            result = apply_transform(payload, proposal)
            assert isinstance(result.status, TransformStatus)
            assert result.status in (
                TransformStatus.APPLIED,
                TransformStatus.REJECTED,
                TransformStatus.NO_CHANGE,
            )


# --------------------------------------------------------------------------
# Determinism and entry validation
# --------------------------------------------------------------------------


class TestDeterminismAndValidation:
    def test_two_drainings_are_equal(self):
        payload = _and_predicate_payload()
        assert collect(payload) == collect(payload)

    def test_iter_proposals_rejects_non_payload_input(self):
        with pytest.raises(ContractError):
            list(iter_proposals(None))  # type: ignore[arg-type]
        with pytest.raises(ContractError):
            list(iter_proposals(123))  # type: ignore[arg-type]
        with pytest.raises(ContractError):
            list(iter_proposals(Rows(())))  # type: ignore[arg-type]
