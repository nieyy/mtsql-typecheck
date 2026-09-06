"""Phase 2 static validation tests: R02 predicate/IR semantics, V01 static
pending part, C02 semantic identity, and the rule/binding negatives
(design 6.2.1, 6.2.2, 6.2.5, 6.4.1 step 6; tests/unit/validation).

Every expected condition id list, status and reason in this file is written
by hand from the design; none is derived by calling the validator under
test.  The C02 expected case_id is the SHA-256 of a hand-written canonical
JSON text (cross-checked once with an independent ``shasum -a 256`` run);
it is never computed by the codec under test inside an assertion.

Note on registry tests: the two tests that register extra rule definitions
use unique rule ids (``mysql80.test-disabled-rule``,
``mysql80.test-hashflip-rule``) so no reviewed rule is touched, and the
``_restore_default_registry`` fixture restores the default registry after
each of them, keeping the tests/unit/rules combination-count assertions
valid in any collection order.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest

from mtsql_typecheck.contracts.case import (
    And,
    Arithmetic,
    ArithmeticOp,
    Between,
    CaseBundle,
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
    Projection,
    Provenance,
    QuerySpec,
    ReasonCode,
    RelationMode,
    ResultColumnSpec,
    ResultRelationSpec,
    Row,
    Rows,
    RuleRef,
    RuleReviewStatus,
    RuleSpec,
    SemverIdentity,
    SignedIntegerType,
    SignedIntName,
    StaticCheckStatus,
    TableSpec,
    TemplateId,
    TypeFamily,
    ValueEquivalence,
    REQUIRED_SQL_MODE_TOKENS,
)
from mtsql_typecheck.contracts.codec import case_id_of, decode_predicate
from mtsql_typecheck.generation.validation import (
    DEFAULT_PREDICATE_ATOM_LIMIT,
    GENERATOR_IDENTITY,
    StaticValidationError,
    VALIDATOR_IDENTITY,
    static_check_or_raise,
    validate_case,
)
from mtsql_typecheck.rules.registry import DEFAULT_REGISTRY

TINYINT = SignedIntegerType(SignedIntName.TINYINT)
SMALLINT = SignedIntegerType(SignedIntName.SMALLINT)
INT = SignedIntegerType(SignedIntName.INT)
BIGINT = SignedIntegerType(SignedIntName.BIGINT)


# --------------------------------------------------------------------------
# Payload construction helpers (contract models assembled by hand; the
# relation columns mirror design 6.2.2, they are never taken from the
# validator or from derive_relation)
# --------------------------------------------------------------------------


def _family(type_spec) -> TypeFamily:
    return TypeFamily(type_spec.kind)


def _relation(query: QuerySpec, a_type, b_type) -> ResultRelationSpec:
    templates: dict[TemplateId, list[tuple[str, TypeFamily, TypeFamily, NullPolicy]]] = {
        TemplateId.Q1: [("c0", _family(a_type), _family(b_type), NullPolicy.PRESERVE)],
        TemplateId.Q2: [
            ("c0", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.FORBID)
        ],
        TemplateId.Q4: [
            ("c0", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.PRESERVE)
        ],
        TemplateId.Q3: [
            ("c0", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.FORBID),
            ("c1", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.FORBID),
            ("c2", _family(a_type), _family(b_type), NullPolicy.PRESERVE),
            ("c3", _family(a_type), _family(b_type), NullPolicy.PRESERVE),
            ("c4", TypeFamily.DECIMAL, TypeFamily.DECIMAL, NullPolicy.PRESERVE),
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
    rule_id: str = "mysql80.integer-decimal",
    index_variant: IndexVariant = IndexVariant.NONE,
    renderer: SemverIdentity = SemverIdentity("r1", "1"),
    generator: SemverIdentity = SemverIdentity("g1", "1"),
) -> CasePayload:
    table = TableSpec(
        logical_id="t0",
        columns=(
            ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
            ColumnSpec("v", a_type, True),
        ),
        primary_key=("rid",),
        index_variant=index_variant,
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
        generator=generator,
        renderer=renderer,
    )


def integer_rows(*values: int) -> Rows:
    return Rows(tuple(Row(index + 1, IntegerValue(value)) for index, value in enumerate(values)))


def mixed_integer_rows(*values: int | None) -> Rows:
    return Rows(
        tuple(
            Row(index + 1, NullValue() if value is None else IntegerValue(value))
            for index, value in enumerate(values)
        )
    )


def decimal_rows(*values: DecimalValue) -> Rows:
    return Rows(tuple(Row(index + 1, value) for index, value in enumerate(values)))


def condition_map(check: CompatibilityCheck) -> dict[str, object]:
    return {condition.condition_id: condition for condition in check.conditions}


GOLDEN_PAYLOAD = make_payload(
    a_type=BIGINT,
    b_type=DecimalType(20, 0),
    rows=mixed_integer_rows(None, 0),
    query=QuerySpec(TemplateId.Q1),
    rule_id="mysql80.integer-decimal",
)


# Hand-written expected condition lists for a statically valid payload,
# in the exact order validate_case must emit them.
_VALID_Q1_CONDITIONS = (
    "codec_roundtrip",
    "rule_registered",
    "rule_enabled",
    "rule_binding",
    "predicate_structure",
    "common_value_domain",
    "predicate_constants",
    "relation_declaration",
    "environment_requirements",
    "generation_identity",
    "runtime_environment",
    "runtime_load",
    "runtime_isolation",
)
_VALID_Q3_CONDITIONS = (
    _VALID_Q1_CONDITIONS[:7] + ("q3_sum_abs_budget",) + _VALID_Q1_CONDITIONS[7:]
)
_VALID_Q4_CONDITIONS = (
    _VALID_Q1_CONDITIONS[:7] + ("q4_bigint_domain",) + _VALID_Q1_CONDITIONS[7:]
)


# --------------------------------------------------------------------------
# Positive cases: one legal payload per reviewed rule
# --------------------------------------------------------------------------


class TestValidStaticPerRule:
    def test_signed_widen_q1_full_condition_list(self):
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=integer_rows(-128, 0, 127),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.signed-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.VALID_STATIC
        assert check.stage.value == "static"
        assert check.validator_version == VALIDATOR_IDENTITY.version == "1"
        assert tuple(c.condition_id for c in check.conditions) == _VALID_Q1_CONDITIONS

    def test_signed_widen_q2_with_and_predicate(self):
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=mixed_integer_rows(None, 5),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=And(
                    Compare(CompareOp.GE, ExactLiteral(IntegerValue(0))),
                    IsNull(True),
                ),
            ),
            rule_id="mysql80.signed-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.VALID_STATIC
        assert condition_map(check)["predicate_structure"].status is CheckStatus.SATISFIED
        assert condition_map(check)["predicate_constants"].status is CheckStatus.SATISFIED

    def test_decimal_widen_q3_with_where(self):
        payload = make_payload(
            a_type=DecimalType(9, 2),
            b_type=DecimalType(18, 2),
            rows=decimal_rows(DecimalValue(150, 2), DecimalValue(-25, 2)),
            query=QuerySpec(
                TemplateId.Q3,
                predicate=Compare(CompareOp.LE, ExactLiteral(DecimalValue(100, 2))),
            ),
            rule_id="mysql80.decimal-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.VALID_STATIC
        assert tuple(c.condition_id for c in check.conditions) == _VALID_Q3_CONDITIONS
        assert condition_map(check)["q3_sum_abs_budget"].status is CheckStatus.SATISFIED

    def test_integer_decimal_q1_golden_rows(self):
        # Design 6.4.2 data: NULL, 0 and 9007199254740993 twice.
        payload = make_payload(
            a_type=BIGINT,
            b_type=DecimalType(20, 0),
            rows=mixed_integer_rows(None, 0, 9007199254740993, 9007199254740993),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.integer-decimal",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.VALID_STATIC
        assert condition_map(check)["common_value_domain"].status is CheckStatus.SATISFIED

    def test_integer_decimal_q3_small_rows(self):
        payload = make_payload(
            a_type=BIGINT,
            b_type=DecimalType(20, 0),
            rows=mixed_integer_rows(5, None, -3),
            query=QuerySpec(TemplateId.Q3),
            rule_id="mysql80.integer-decimal",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.VALID_STATIC
        assert tuple(c.condition_id for c in check.conditions) == _VALID_Q3_CONDITIONS

    def test_signed_add_sub_q4_with_predicate(self):
        arithmetic = Arithmetic(ArithmeticOp.SUBTRACT, IntegerValue(-16))
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=integer_rows(1),
            query=QuerySpec(
                TemplateId.Q4,
                predicate=Compare(CompareOp.GT, ExactLiteral(IntegerValue(0))),
                arithmetic=arithmetic,
                projections=(Projection("c0", arithmetic),),
            ),
            rule_id="mysql80.signed-add-sub",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.VALID_STATIC
        assert tuple(c.condition_id for c in check.conditions) == _VALID_Q4_CONDITIONS
        assert condition_map(check)["q4_bigint_domain"].status is CheckStatus.SATISFIED

    def test_index_variant_ix_v_is_a_legal_combination(self):
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=integer_rows(0),
            query=QuerySpec(TemplateId.Q1),
            index_variant=IndexVariant.IX_V,
            rule_id="mysql80.signed-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.VALID_STATIC
        assert condition_map(check)["rule_binding"].status is CheckStatus.SATISFIED

    def test_between_equal_endpoints_and_or_forms_pass(self):
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=integer_rows(3, -3),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Or(
                    Between(ExactLiteral(IntegerValue(-3)), ExactLiteral(IntegerValue(-3))),
                    IsNull(False),
                ),
            ),
            rule_id="mysql80.signed-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.VALID_STATIC


# --------------------------------------------------------------------------
# V01 (static part): VALID_STATIC keeps runtime conditions PENDING
# --------------------------------------------------------------------------


class TestV01StaticPending:
    def test_valid_static_carries_only_pending_runtime_conditions(self):
        check = validate_case(GOLDEN_PAYLOAD)
        assert check.status is StaticCheckStatus.VALID_STATIC
        runtime = [c for c in check.conditions if c.condition_id.startswith("runtime_")]
        assert [c.condition_id for c in runtime] == [
            "runtime_environment",
            "runtime_load",
            "runtime_isolation",
        ]
        for condition in runtime:
            assert condition.status is CheckStatus.PENDING
            assert condition.reason is ReasonCode.MISSING_FACT
        static_ids = {c.condition_id for c in check.conditions if not c.condition_id.startswith("runtime_")}
        assert "runtime" not in " ".join(sorted(static_ids))

    def test_no_satisfied_or_ready_runtime_semantics(self):
        check = validate_case(GOLDEN_PAYLOAD)
        assert str(check.status.value) == "VALID_STATIC"
        # No READY/BLOCKED/INCOMPLETE anywhere in the serialized check.
        encoded = json.dumps(check.to_obj())
        for word in ("READY", "BLOCKED", "INCOMPLETE"):
            assert word not in encoded
        for condition in check.conditions:
            if condition.condition_id.startswith("runtime_"):
                assert condition.status is not CheckStatus.SATISFIED
                assert condition.status is not CheckStatus.VIOLATED

    def test_invalid_check_has_no_runtime_conditions(self):
        payload = make_payload(
            a_type=TINYINT,
            b_type=INT,  # TINYINT->INT is not an authorized pair
            rows=integer_rows(1),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.signed-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        assert all(not c.condition_id.startswith("runtime_") for c in check.conditions)


# --------------------------------------------------------------------------
# R02: predicate/IR semantics
# --------------------------------------------------------------------------


class TestR02TemplateShape:
    # The Q1-with-WHERE / Q2-without-WHERE / Q3-with-arithmetic /
    # Q4-without-arithmetic shapes cannot be turned into a CasePayload at
    # all: QuerySpec.__post_init__ rejects them, so the equivalent-payload
    # path demanded by the design does not exist and the validator-level
    # re-check (predicate_structure) is a defensive duplicate only.
    def test_q1_with_predicate_rejected_by_model_layer(self):
        with pytest.raises(ContractError):
            QuerySpec(TemplateId.Q1, predicate=IsNull(False))

    def test_q2_without_predicate_rejected_by_model_layer(self):
        with pytest.raises(ContractError):
            QuerySpec(TemplateId.Q2)

    def test_q3_with_arithmetic_rejected_by_model_layer(self):
        with pytest.raises(ContractError):
            QuerySpec(
                TemplateId.Q3,
                arithmetic=Arithmetic(ArithmeticOp.ADD, IntegerValue(1)),
            )

    def test_q4_without_arithmetic_rejected_by_model_layer(self):
        with pytest.raises(ContractError):
            QuerySpec(TemplateId.Q4)

    def test_q4_nested_arithmetic_has_no_ir_path(self):
        # "Nested arithmetic" would mean an arithmetic node inside the
        # predicate; Compare.right must be an ExactLiteral, so no such IR
        # object can be constructed - rejected by the model layer.
        with pytest.raises(ContractError):
            Compare(CompareOp.EQ, Arithmetic(ArithmeticOp.ADD, IntegerValue(1)))  # type: ignore[arg-type]

    def test_between_rejected_endpoints_at_model_layer(self):
        with pytest.raises(ContractError):
            Between(ExactLiteral(NullValue()), ExactLiteral(IntegerValue(1)))
        with pytest.raises(ContractError):
            Between(ExactLiteral(IntegerValue(1)), ExactLiteral(NullValue()))

    def test_between_reversed_rejected_by_validator(self):
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=integer_rows(1),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Between(
                    ExactLiteral(IntegerValue(5)), ExactLiteral(IntegerValue(1))
                ),
            ),
            rule_id="mysql80.signed-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        structure = condition_map(check)["predicate_structure"]
        assert structure.status is CheckStatus.VIOLATED
        assert structure.reason is ReasonCode.INVALID_STRUCTURE
        assert "reversed" in str(structure.detail)

    def test_between_reversed_decimal_same_scale_rejected(self):
        payload = make_payload(
            a_type=DecimalType(9, 2),
            b_type=DecimalType(18, 2),
            rows=decimal_rows(DecimalValue(0, 2)),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Between(
                    ExactLiteral(DecimalValue(300, 2)),
                    ExactLiteral(DecimalValue(150, 2)),
                ),
            ),
            rule_id="mysql80.decimal-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        assert condition_map(check)["predicate_structure"].status is CheckStatus.VIOLATED

    def test_between_cross_kind_endpoints_rejected(self):
        payload = make_payload(
            a_type=DecimalType(9, 2),
            b_type=DecimalType(18, 2),
            rows=decimal_rows(DecimalValue(0, 2)),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Between(
                    ExactLiteral(IntegerValue(1)), ExactLiteral(DecimalValue(150, 2))
                ),
            ),
            rule_id="mysql80.decimal-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        assert condition_map(check)["predicate_structure"].status is CheckStatus.VIOLATED

    def test_between_mixed_scale_endpoints_rejected(self):
        payload = make_payload(
            a_type=DecimalType(9, 2),
            b_type=DecimalType(18, 2),
            rows=decimal_rows(DecimalValue(0, 2)),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Between(
                    ExactLiteral(DecimalValue(1, 2)), ExactLiteral(DecimalValue(200, 3))
                ),
            ),
            rule_id="mysql80.decimal-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        assert condition_map(check)["predicate_structure"].status is CheckStatus.VIOLATED

    def test_legal_null_compare_passes(self):
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=integer_rows(0),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.NULL_SAFE_EQ, ExactLiteral(NullValue())),
            ),
            rule_id="mysql80.signed-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.VALID_STATIC

    def test_illegal_column_operator_and_depth_rejected_by_contracts(self):
        # Representative contract-layer rejections: the validator never sees
        # these shapes because no CasePayload can hold them.
        with pytest.raises(ContractError):
            decode_predicate(
                {
                    "kind": "compare",
                    "op": "=",
                    "left": {"kind": "column_ref", "column": "rid"},
                    "right": {"kind": "literal", "value": {"kind": "integer", "value": "5"}},
                }
            )
        with pytest.raises(ContractError):
            decode_predicate(
                {
                    "kind": "compare",
                    "op": "LIKE",
                    "left": {"kind": "column_ref", "column": "v"},
                    "right": {"kind": "literal", "value": {"kind": "integer", "value": "5"}},
                }
            )
        atom = {
            "kind": "compare",
            "op": "=",
            "left": {"kind": "column_ref", "column": "v"},
            "right": {"kind": "literal", "value": {"kind": "integer", "value": "5"}},
        }
        with pytest.raises(ContractError):  # more than two atoms / nesting
            decode_predicate({"kind": "and", "left": {"kind": "and", "left": atom, "right": atom}, "right": atom})

    def test_validate_case_rejects_non_payload(self):
        with pytest.raises(ContractError):
            validate_case("not a payload")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Negatives: rule registration, enablement, binding, domains, identity
# --------------------------------------------------------------------------


@pytest.fixture
def _restore_default_registry():
    """Snapshot and restore the default registry around tests that register
    extra rule definitions, so tests/unit/rules combo-count assertions stay
    valid regardless of collection order."""
    saved = dict(DEFAULT_REGISTRY._rules)
    yield
    DEFAULT_REGISTRY._rules.clear()
    DEFAULT_REGISTRY._rules.update(saved)


_DISABLED_RULE_SPEC = RuleSpec(
    rule_id="mysql80.test-disabled-rule",
    rule_version=1,
    type_pairs=((TINYINT, SMALLINT),),
    templates=(TemplateId.Q1,),
    requires_equal_scale=False,
    integer_only_values=True,
    sum_abs_coefficient_budget=None,  # Q1-only test rule: no Q3 budget
    arithmetic_k_min=None,
    arithmetic_k_max=None,
    static_conditions=("common_value_domain", "structure_whitelist"),
    runtime_requirements=EnvironmentRequirements(
        database="mysql80",
        engine="innodb",
        scope="same-instance",
        sql_mode_tokens=REQUIRED_SQL_MODE_TOKENS,
        character_set="utf8mb4",
        collation="utf8mb4_bin",
        time_zone="+00:00",
    ),
    rationale=("test-only definition registered in the disabled state",),
    review_notes="registered disabled by tests/unit/validation; never reviewed",
    review_status=RuleReviewStatus.DISABLED,
)


class TestRuleRegistrationNegatives:
    def test_unknown_rule_id(self):
        payload = make_payload(
            a_type=BIGINT,
            b_type=DecimalType(20, 0),
            rows=mixed_integer_rows(None, 0),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.nonexistent",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        registered = condition_map(check)["rule_registered"]
        assert registered.status is CheckStatus.VIOLATED
        assert registered.reason is ReasonCode.UNKNOWN_VERSION
        # Rule-dependent checks are not fabricated when the rule is unknown.
        assert tuple(c.condition_id for c in check.conditions) == (
            "codec_roundtrip",
            "rule_registered",
            "predicate_structure",
            "relation_declaration",
            "environment_requirements",
            "generation_identity",
        )
        assert "common_value_domain" not in {c.condition_id for c in check.conditions}

    def test_unknown_rule_version(self):
        payload = dataclasses.replace(
            GOLDEN_PAYLOAD, rule=RuleRef("mysql80.integer-decimal", 2)
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        registered = condition_map(check)["rule_registered"]
        assert registered.status is CheckStatus.VIOLATED
        assert registered.reason is ReasonCode.UNKNOWN_VERSION

    @pytest.mark.usefixtures("_restore_default_registry")
    def test_disabled_rule_reports_rule_disabled(self):
        # Registered only for this test under a unique id; the fixture
        # restores the default registry afterwards.  No reviewed rule is
        # modified.
        DEFAULT_REGISTRY.register(_DISABLED_RULE_SPEC)
        payload = make_payload(
            a_type=TINYINT,
            b_type=SMALLINT,
            rows=integer_rows(1),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.test-disabled-rule",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        assert condition_map(check)["rule_registered"].status is CheckStatus.SATISFIED
        enabled = condition_map(check)["rule_enabled"]
        assert enabled.status is CheckStatus.VIOLATED
        assert enabled.reason is ReasonCode.RULE_DISABLED

    @pytest.mark.usefixtures("_restore_default_registry")
    def test_registered_definition_hash_mismatch_detected(self):
        # Simulates a registry object whose definition_hash was swapped after
        # registration: validate_case re-derives the semantic hash and must
        # refuse.  Uses a unique rule id; the global registry is untouched.
        spec = RuleSpec(
            rule_id="mysql80.test-hashflip-rule",
            rule_version=1,
            type_pairs=((TINYINT, SMALLINT),),
            templates=(TemplateId.Q1,),
            requires_equal_scale=False,
            integer_only_values=True,
            sum_abs_coefficient_budget=None,  # Q1-only test rule: no Q3 budget
            arithmetic_k_min=None,
            arithmetic_k_max=None,
            static_conditions=("common_value_domain", "structure_whitelist"),
            runtime_requirements=EnvironmentRequirements(
                database="mysql80",
                engine="innodb",
                scope="same-instance",
                sql_mode_tokens=REQUIRED_SQL_MODE_TOKENS,
                character_set="utf8mb4",
                collation="utf8mb4_bin",
                time_zone="+00:00",
            ),
            rationale=("test-only definition for the hash re-derivation check",),
            review_notes="registered by tests/unit/validation",
            review_status=RuleReviewStatus.REVIEWED,
        )
        object.__setattr__(spec, "definition_hash", "0" * 64)
        DEFAULT_REGISTRY.register(spec)
        payload = make_payload(
            a_type=TINYINT,
            b_type=SMALLINT,
            rows=integer_rows(1),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.test-hashflip-rule",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        registered = condition_map(check)["rule_registered"]
        assert registered.status is CheckStatus.VIOLATED
        assert registered.reason is ReasonCode.INTERNAL_ERROR


class TestBindingAndDomainNegatives:
    def test_unauthorized_type_pair_tinyint_to_int(self):
        payload = make_payload(
            a_type=TINYINT,
            b_type=INT,
            rows=integer_rows(1),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.signed-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        binding = condition_map(check)["rule_binding"]
        assert binding.status is CheckStatus.VIOLATED
        assert binding.reason is ReasonCode.INVALID_STRUCTURE

    def test_authorized_rule_with_unauthorized_template(self):
        # signed-add-sub only allows Q4; a Q1 payload under it must fail.
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=integer_rows(1),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.signed-add-sub",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        assert condition_map(check)["rule_binding"].status is CheckStatus.VIOLATED

    def test_row_value_out_of_narrow_type_domain(self):
        payload = make_payload(
            a_type=TINYINT,
            b_type=SMALLINT,
            rows=integer_rows(200),  # outside signed TINYINT
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.signed-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        domain = condition_map(check)["common_value_domain"]
        assert domain.status is CheckStatus.VIOLATED
        assert domain.reason is ReasonCode.VALUE_OUT_OF_DOMAIN

    def test_decimal_row_with_wrong_scale(self):
        payload = make_payload(
            a_type=DecimalType(9, 2),
            b_type=DecimalType(18, 2),
            rows=decimal_rows(DecimalValue(5, 3)),  # scale 3, rule scale is 2
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.decimal-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        domain = condition_map(check)["common_value_domain"]
        assert domain.status is CheckStatus.VIOLATED
        assert domain.reason is ReasonCode.INVALID_STRUCTURE

    def test_predicate_constant_of_wrong_literal_kind(self):
        # decimal-widen accepts same-scale decimal/NULL constants only; an
        # integer literal is not auto-converted even though the value fits.
        payload = make_payload(
            a_type=DecimalType(9, 2),
            b_type=DecimalType(18, 2),
            rows=decimal_rows(DecimalValue(300, 2)),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.LE, ExactLiteral(IntegerValue(3))),
            ),
            rule_id="mysql80.decimal-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        constants = condition_map(check)["predicate_constants"]
        assert constants.status is CheckStatus.VIOLATED
        assert constants.reason is ReasonCode.INVALID_STRUCTURE

    def test_predicate_constant_with_wrong_scale(self):
        payload = make_payload(
            a_type=DecimalType(9, 2),
            b_type=DecimalType(18, 2),
            rows=decimal_rows(DecimalValue(0, 2)),
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.LE, ExactLiteral(DecimalValue(100, 3))),
            ),
            rule_id="mysql80.decimal-widen",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        assert condition_map(check)["predicate_constants"].status is CheckStatus.VIOLATED

    def test_q3_sum_budget_exceeded(self):
        # 2 * 9007199254740993 > 10^12: the design 6.4.2 data is legal for
        # Q1 but must be rejected for Q3; a WHERE would not relax this.
        payload = make_payload(
            a_type=BIGINT,
            b_type=DecimalType(20, 0),
            rows=mixed_integer_rows(None, 0, 9007199254740993, 9007199254740993),
            query=QuerySpec(TemplateId.Q3),
            rule_id="mysql80.integer-decimal",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        budget = condition_map(check)["q3_sum_abs_budget"]
        assert budget.status is CheckStatus.VIOLATED
        assert budget.reason is ReasonCode.BUDGET_EXCEEDED

    def test_q4_constant_out_of_bounds(self):
        arithmetic = Arithmetic(ArithmeticOp.ADD, IntegerValue(17))
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=integer_rows(1),
            query=QuerySpec(
                TemplateId.Q4,
                arithmetic=arithmetic,
                projections=(Projection("c0", arithmetic),),
            ),
            rule_id="mysql80.signed-add-sub",
        )
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        assert condition_map(check)["predicate_structure"].status is CheckStatus.VIOLATED
        domain = condition_map(check)["q4_bigint_domain"]
        assert domain.status is CheckStatus.VIOLATED
        assert domain.reason is ReasonCode.VALUE_OUT_OF_DOMAIN
        # Intermediate-value violations beyond the k check are unreachable
        # with the registered pairs (narrow side is at most INT, so v +/- 16
        # stays far inside signed BIGINT); the BIGINT helper itself is
        # covered by the rules unit tests on synthetic values.

    def test_relation_tampering_detected(self):
        payload = make_payload(
            a_type=BIGINT,
            b_type=DecimalType(20, 0),
            rows=mixed_integer_rows(None, 0),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.integer-decimal",
        )
        forged = ResultRelationSpec(
            RelationMode.MULTISET_EXACT,
            (
                ResultColumnSpec(
                    "c0",
                    TypeFamily.SIGNED_INTEGER,
                    TypeFamily.DECIMAL,
                    ValueEquivalence.EXACT_NUMERIC,
                    NullPolicy.FORBID,  # derived relation declares preserve
                ),
            ),
        )
        tampered = dataclasses.replace(payload, relation=forged)
        check = validate_case(tampered)
        assert check.status is StaticCheckStatus.INVALID
        relation = condition_map(check)["relation_declaration"]
        assert relation.status is CheckStatus.VIOLATED
        assert relation.reason is ReasonCode.INVALID_STRUCTURE

    def test_relation_with_wrong_column_count_detected(self):
        payload = make_payload(
            a_type=BIGINT,
            b_type=DecimalType(20, 0),
            rows=mixed_integer_rows(None, 0),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.integer-decimal",
        )
        forged = ResultRelationSpec(
            RelationMode.MULTISET_EXACT,
            (
                ResultColumnSpec(
                    "c0",
                    TypeFamily.SIGNED_INTEGER,
                    TypeFamily.DECIMAL,
                    ValueEquivalence.EXACT_NUMERIC,
                    NullPolicy.PRESERVE,
                ),
                ResultColumnSpec(
                    "c1",
                    TypeFamily.SIGNED_INTEGER,
                    TypeFamily.SIGNED_INTEGER,
                    ValueEquivalence.EXACT_NUMERIC,
                    NullPolicy.FORBID,
                ),
            ),
        )
        tampered = dataclasses.replace(payload, relation=forged)
        check = validate_case(tampered)
        assert check.status is StaticCheckStatus.INVALID
        assert condition_map(check)["relation_declaration"].status is CheckStatus.VIOLATED


class TestEnvironmentAndIdentityNegatives:
    def test_environment_with_wrong_tokens_or_zone_rejected_by_model(self):
        # The contract model rejects a deviating environment at construction,
        # so a payload cannot carry one built through the normal path.
        with pytest.raises(ContractError):
            EnvironmentRequirements(
                database="mysql80",
                engine="innodb",
                scope="same-instance",
                sql_mode_tokens=("STRICT_ALL_TABLES",),  # incomplete token set
                character_set="utf8mb4",
                collation="utf8mb4_bin",
                time_zone="+00:00",
            )
        with pytest.raises(ContractError):
            EnvironmentRequirements(
                database="mysql80",
                engine="innodb",
                scope="same-instance",
                sql_mode_tokens=REQUIRED_SQL_MODE_TOKENS,
                character_set="utf8mb4",
                collation="utf8mb4_bin",
                time_zone="+08:00",
            )

    def test_environment_deviation_caught_by_validator_on_bypass(self):
        # Construction-bypass simulation: corrupt a valid environment through
        # the frozen-dataclass back door and hand it to the payload.  Both
        # the validator's own environment check and the codec round trip
        # (whose loader rebuilds EnvironmentRequirements strictly) must fire.
        env = EnvironmentRequirements(
            database="mysql80",
            engine="innodb",
            scope="same-instance",
            sql_mode_tokens=REQUIRED_SQL_MODE_TOKENS,
            character_set="utf8mb4",
            collation="utf8mb4_bin",
            time_zone="+00:00",
        )
        object.__setattr__(env, "time_zone", "+08:00")
        payload = dataclasses.replace(GOLDEN_PAYLOAD, environment=env)
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        environment = condition_map(check)["environment_requirements"]
        assert environment.status is CheckStatus.VIOLATED
        assert environment.reason is ReasonCode.UNSUPPORTED_ENVIRONMENT
        assert condition_map(check)["codec_roundtrip"].status is CheckStatus.VIOLATED

    def test_wrong_renderer_identity_rejected(self):
        payload = dataclasses.replace(GOLDEN_PAYLOAD, renderer=SemverIdentity("r9", "1"))
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        identity = condition_map(check)["generation_identity"]
        assert identity.status is CheckStatus.VIOLATED
        assert identity.reason is ReasonCode.UNKNOWN_VERSION

    def test_wrong_renderer_version_rejected(self):
        payload = dataclasses.replace(GOLDEN_PAYLOAD, renderer=SemverIdentity("r1", "2"))
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        assert condition_map(check)["generation_identity"].reason is ReasonCode.UNKNOWN_VERSION

    def test_wrong_generator_identity_rejected(self):
        payload = dataclasses.replace(GOLDEN_PAYLOAD, generator=SemverIdentity("g2", "1"))
        check = validate_case(payload)
        assert check.status is StaticCheckStatus.INVALID
        identity = condition_map(check)["generation_identity"]
        assert identity.status is CheckStatus.VIOLATED
        assert identity.reason is ReasonCode.UNKNOWN_VERSION
        assert str(GENERATOR_IDENTITY.id) == "g1"


# --------------------------------------------------------------------------
# C02: semantic identity
# --------------------------------------------------------------------------

# Hand-written canonical JSON of GOLDEN_PAYLOAD (design 6.2.4: UTF-8, sorted
# keys, compact separators, ASCII).  Written out by hand from the design's
# encoding rules; its SHA-256 was cross-checked once with `shasum -a 256`.
GOLDEN_CANONICAL_JSON = (
    '{"a_type":{"kind":"signed_integer","name":"BIGINT"},'
    '"b_type":{"kind":"decimal","precision":20,"scale":0},'
    '"case_schema_version":1,'
    '"environment":{"character_set":"utf8mb4","collation":"utf8mb4_bin",'
    '"database":"mysql80","engine":"innodb","scope":"same-instance",'
    '"sql_mode_tokens":["NO_ENGINE_SUBSTITUTION","ONLY_FULL_GROUP_BY",'
    '"STRICT_ALL_TABLES"],"time_zone":"+00:00"},'
    '"generator":{"id":"g1","version":"1"},'
    '"query":{"projections":[{"alias":"c0","expr":{"column":"v",'
    '"kind":"column_ref"}}],"template_id":"Q1"},'
    '"relation":{"columns":[{"a_family":"signed_integer","alias":"c0",'
    '"b_family":"decimal","null_policy":"preserve",'
    '"value_equivalence":"exact_numeric"}],"mode":"multiset_exact"},'
    '"renderer":{"id":"r1","version":"1"},'
    '"rows":[[1,{"kind":"null"}],[2,{"kind":"integer","value":"0"}]],'
    '"rule":{"rule_id":"mysql80.integer-decimal","rule_version":1},'
    '"table":{"columns":[{"name":"rid","nullable":false,'
    '"type":{"kind":"signed_integer","name":"BIGINT"}},{"name":"v",'
    '"nullable":true,"type":{"kind":"signed_integer","name":"BIGINT"}}],'
    '"index_variant":"none","logical_id":"t0","primary_key":["rid"]}}'
)

# Fixed once from the hand-written text via an independent sha256 run.
EXPECTED_GOLDEN_CASE_ID = "506ceb29656edc8e12871461c825845d7ace51a2cdb3a32b6457519032b76b53"


class TestC02Identity:
    def test_case_id_matches_handwritten_canonical_bytes(self):
        assert (
            hashlib.sha256(GOLDEN_CANONICAL_JSON.encode("utf-8")).hexdigest()
            == EXPECTED_GOLDEN_CASE_ID
        )
        assert case_id_of(GOLDEN_PAYLOAD) == EXPECTED_GOLDEN_CASE_ID

    @pytest.mark.parametrize(
        "variant",
        ["rows", "query", "a_type", "b_type", "relation"],
    )
    def test_every_semantic_field_change_changes_case_id(self, variant):
        base_id = case_id_of(GOLDEN_PAYLOAD)
        assert base_id == EXPECTED_GOLDEN_CASE_ID
        if variant == "rows":
            changed = make_payload(
                a_type=BIGINT,
                b_type=DecimalType(20, 0),
                rows=mixed_integer_rows(None, 0, 5),
                query=QuerySpec(TemplateId.Q1),
                rule_id="mysql80.integer-decimal",
            )
        elif variant == "query":
            changed = make_payload(
                a_type=BIGINT,
                b_type=DecimalType(20, 0),
                rows=mixed_integer_rows(None, 0),
                query=QuerySpec(TemplateId.Q3),
                rule_id="mysql80.integer-decimal",
            )
        elif variant == "a_type":
            changed = make_payload(
                a_type=INT,
                b_type=DecimalType(20, 0),
                rows=mixed_integer_rows(None, 0),
                query=QuerySpec(TemplateId.Q1),
                rule_id="mysql80.integer-decimal",
            )
        elif variant == "b_type":
            changed = make_payload(
                a_type=BIGINT,
                b_type=DecimalType(30, 0),
                rows=mixed_integer_rows(None, 0),
                query=QuerySpec(TemplateId.Q1),
                rule_id="mysql80.integer-decimal",
            )
        else:
            forged = ResultRelationSpec(
                RelationMode.MULTISET_EXACT,
                (
                    ResultColumnSpec(
                        "c0",
                        TypeFamily.DECIMAL,  # derived: signed_integer
                        TypeFamily.DECIMAL,
                        ValueEquivalence.EXACT_NUMERIC,
                        NullPolicy.PRESERVE,
                    ),
                ),
            )
            changed = dataclasses.replace(GOLDEN_PAYLOAD, relation=forged)
        assert case_id_of(changed) != base_id

    def test_static_conclusion_follows_semantic_change(self):
        # The base payload is VALID_STATIC...
        assert validate_case(GOLDEN_PAYLOAD).status is StaticCheckStatus.VALID_STATIC
        # ...but the b_type variant leaves the reviewed combination set...
        changed = make_payload(
            a_type=BIGINT,
            b_type=DecimalType(30, 0),
            rows=mixed_integer_rows(None, 0),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.integer-decimal",
        )
        check = validate_case(changed)
        assert check.status is StaticCheckStatus.INVALID
        assert condition_map(check)["rule_binding"].status is CheckStatus.VIOLATED
        # ...and a value beyond the shared domain flips the conclusion too.
        out_of_domain = make_payload(
            a_type=BIGINT,
            b_type=DecimalType(20, 0),
            rows=mixed_integer_rows(None, 0, 2**63),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.integer-decimal",
        )
        domain_check = validate_case(out_of_domain)
        assert domain_check.status is StaticCheckStatus.INVALID
        assert condition_map(domain_check)["common_value_domain"].status is CheckStatus.VIOLATED

    def test_provenance_does_not_enter_case_id(self):
        check = validate_case(GOLDEN_PAYLOAD)
        assert check.status is StaticCheckStatus.VALID_STATIC
        bundle_low = CaseBundle(
            payload=GOLDEN_PAYLOAD,
            provenance=Provenance(seed=1, ordinal=0, profile_hash="a" * 64, retry=0),
            preview_a_sql="SELECT 1;",
            preview_b_sql="SELECT 1;",
            static_check=check,
        )
        bundle_high = CaseBundle(
            payload=GOLDEN_PAYLOAD,
            provenance=Provenance(seed=2**64 - 1, ordinal=999, profile_hash="b" * 64, retry=7),
            preview_a_sql="SELECT 1;",
            preview_b_sql="SELECT 1;",
            static_check=check,
        )
        assert bundle_low.case_id == bundle_high.case_id == EXPECTED_GOLDEN_CASE_ID


# --------------------------------------------------------------------------
# Generator/transforms convenience entry point
# --------------------------------------------------------------------------


class TestStaticCheckOrRaise:
    def test_valid_payload_returns_check(self):
        check = static_check_or_raise(GOLDEN_PAYLOAD)
        assert check.status is StaticCheckStatus.VALID_STATIC
        assert check.case_id == case_id_of(GOLDEN_PAYLOAD)

    def test_invalid_payload_raises_with_check_attached(self):
        payload = make_payload(
            a_type=TINYINT,
            b_type=INT,
            rows=integer_rows(1),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.signed-widen",
        )
        with pytest.raises(StaticValidationError) as excinfo:
            static_check_or_raise(payload)
        assert isinstance(excinfo.value, ContractError)
        assert excinfo.value.check.status is StaticCheckStatus.INVALID
        assert condition_map(excinfo.value.check)["rule_binding"].status is CheckStatus.VIOLATED


def test_predicate_atom_limit_constant_is_two():
    # Design 6.4.1 budget table default without profile context.
    assert DEFAULT_PREDICATE_ATOM_LIMIT == 2
