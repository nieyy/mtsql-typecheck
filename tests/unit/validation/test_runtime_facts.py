"""Phase 4 runtime-fact validation tests: V01 status semantics, V02 binding,
V03 load fidelity, the static gate, input errors, and the synthetic contract
fixtures (design 6.2.5, 6.3.1, 7 Phase 4; tests/unit/validation).

Every expected status/reason/condition id in this file is written by hand from
the design; none is derived by calling ``validate_runtime_facts`` to compute
an expectation.  The only code under test used while *constructing inputs* is
``render_pair`` (the renderer, not the validator): legal receipt hashes must
come from the real renderer output, per the design's renderer-linkage
requirement.  Content hashes for bindings are computed with the codec
primitive (``sha256_hex`` over ``canonical_json``), which is the frozen hash
specification, not the validator under test.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.case import (
    CasePayload,
    CheckStatus,
    ColumnSpec,
    CompatibilityCheck,
    ConditionResult,
    ContractError,
    DecimalType,
    DecimalValue,
    EnvironmentRequirements,
    ExactLiteral,
    ExpectedBinding,
    IndexVariant,
    IntegerValue,
    NameMap,
    NullPolicy,
    NullValue,
    ObservedEnvironment,
    QuerySpec,
    ReasonCode,
    RelationMode,
    ResultColumnSpec,
    ResultRelationSpec,
    Row,
    Rows,
    RuleRef,
    RuntimeCheckStatus,
    RuntimeFacts,
    SideFacts,
    SignedIntegerType,
    SignedIntName,
    StatementPhase,
    StatementReceipt,
    TableSpec,
    TemplateId,
    TypeFamily,
    ValueEquivalence,
    REQUIRED_SQL_MODE_TOKENS,
)
from mtsql_typecheck.contracts.codec import (
    canonical_json,
    case_id_of,
    decode_expected_binding,
    decode_runtime_facts,
    parse_strict_json,
    load_payload,
    sha256_hex,
)
from mtsql_typecheck.generation.render import RenderPhase, render_pair
from mtsql_typecheck.generation.validation import (
    RUNTIME_VALIDATOR_IDENTITY,
    RuntimeFactsError,
    parse_mysql_version_series,
    validate_runtime_facts,
)

TINYINT = SignedIntegerType(SignedIntName.TINYINT)
SMALLINT = SignedIntegerType(SignedIntName.SMALLINT)
INT = SignedIntegerType(SignedIntName.INT)
BIGINT = SignedIntegerType(SignedIntName.BIGINT)
DECIMAL_9_2 = DecimalType(9, 2)
DECIMAL_18_2 = DecimalType(18, 2)
DECIMAL_20_0 = DecimalType(20, 0)

FIXTURES = Path(__file__).parents[2] / "contract" / "fixtures"

# Synthetic namespace shared by the unit tests and the contract fixtures.
NAME_MAP = NameMap(database_a="tc_a", database_b="tc_b", table_a="t_a", table_b="t_b")

# Fixed wrong-value hex64 strings used for deliberate mismatches.
BOGUS_HASH = "0" * 64
OTHER_HASH = "f" * 64


# --------------------------------------------------------------------------
# Hand-written payload construction (mirrors the design 6.2.2 relation table;
# expected relations are written here, never derived from the validator)
# --------------------------------------------------------------------------


def _family(type_spec) -> TypeFamily:
    return TypeFamily(type_spec.kind)


def _relation(query: QuerySpec, a_type, b_type) -> ResultRelationSpec:
    templates: dict[TemplateId, list[tuple[str, TypeFamily, TypeFamily, NullPolicy]]] = {
        TemplateId.Q1: [("c0", _family(a_type), _family(b_type), NullPolicy.PRESERVE)],
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
    rule_id: str = "mysql80.signed-widen",
    index_variant: IndexVariant = IndexVariant.NONE,
) -> CasePayload:
    from mtsql_typecheck.contracts.case import SemverIdentity

    table = TableSpec(
        logical_id="t0",
        columns=(ColumnSpec("rid", BIGINT, False), ColumnSpec("v", a_type, True)),
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
        generator=SemverIdentity("g1", "1"),
        renderer=SemverIdentity("r1", "1"),
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


def condition_map(check: CompatibilityCheck) -> dict[str, ConditionResult]:
    return {condition.condition_id: condition for condition in check.conditions}


# --------------------------------------------------------------------------
# Runtime-facts input builders (inputs only; expected conclusions are
# handwritten in the assertions below)
# --------------------------------------------------------------------------


def observed_environment(**overrides) -> ObservedEnvironment:
    values = dict(
        instance_identity="mysql-8039-local",
        version="8.0.39",
        vendor="mysql",
        build_id="20250715",
        engine="innodb",
        sql_mode_tokens=REQUIRED_SQL_MODE_TOKENS,
        character_set="utf8mb4",
        collation="utf8mb4_bin",
        time_zone="+00:00",
        optimizer_switch="index_merge=on,mrr=off",
    )
    values.update(overrides)
    return ObservedEnvironment(**values)


def env_content_hash(environment: ObservedEnvironment) -> str:
    return sha256_hex(canonical_json(environment.to_obj()))


def nm_content_hash(name_map: NameMap) -> str:
    return sha256_hex(canonical_json(name_map.to_obj()))


def make_expected_binding(
    payload: CasePayload,
    environment: ObservedEnvironment | None,
    name_map: NameMap | None,
    *,
    run_id: str = "run-1",
    attempt_id: str = "attempt-1",
) -> ExpectedBinding:
    """The caller-side expectation, built independently of the facts object."""
    environment_hash = env_content_hash(environment) if environment is not None else OTHER_HASH
    name_map_hash = nm_content_hash(name_map) if name_map is not None else OTHER_HASH
    return ExpectedBinding(
        run_id=run_id,
        case_id=case_id_of(payload),
        attempt_id=attempt_id,
        environment_hash=environment_hash,
        name_map_hash=name_map_hash,
    )


def side_facts_for(payload: CasePayload, name_map: NameMap, side: str) -> SideFacts:
    """Full correct side facts; receipt hashes come from render_pair output."""
    pair = render_pair(payload, name_map)
    receipts: list[StatementReceipt] = []
    counters: dict[str, int] = {}
    for statement in getattr(pair, side):
        if statement.phase is RenderPhase.SELECT:
            continue
        phase = StatementPhase(str(statement.phase.value))
        ordinal = counters.setdefault(str(statement.phase.value), 0)
        counters[str(statement.phase.value)] = ordinal + 1
        receipts.append(StatementReceipt(phase, ordinal, statement.sql_hash, True, True))
    v_type = payload.a_type if side == "a" else payload.b_type
    actual_schema = TableSpec(
        "t0",
        (ColumnSpec("rid", BIGINT, False), ColumnSpec("v", v_type, True)),
        ("rid",),
        payload.table.index_variant,
    )
    return SideFacts(
        statement_receipts=tuple(receipts),
        readback=payload.rows,
        readback_complete=True,
        actual_schema=actual_schema,
        load_committed=True,
        isolation_confirmed=True,
    )


_UNSET = object()


def full_facts(
    payload: CasePayload,
    *,
    environment=_UNSET,
    name_map: NameMap | None = NAME_MAP,
    run_id: str = "run-1",
    attempt_id: str = "attempt-1",
    side_a=_UNSET,
    side_b=_UNSET,
) -> RuntimeFacts:
    environment = observed_environment() if environment is _UNSET else environment
    return RuntimeFacts(
        binding=ExpectedBinding(
            run_id=run_id,
            case_id=case_id_of(payload),
            attempt_id=attempt_id,
            environment_hash=env_content_hash(environment) if environment is not None else OTHER_HASH,
            name_map_hash=nm_content_hash(name_map) if name_map is not None else OTHER_HASH,
        ),
        observed_environment=environment,
        name_map=name_map,
        a=side_facts_for(payload, name_map, "a") if side_a is _UNSET else side_a,
        b=side_facts_for(payload, name_map, "b") if side_b is _UNSET else side_b,
    )


def binding_only_facts(
    payload: CasePayload, expected: ExpectedBinding, *, run_id: str = "run-1",
    attempt_id: str = "attempt-1",
) -> RuntimeFacts:
    """Facts with nothing collected yet; binding mirrors the expectation."""
    return RuntimeFacts(
        binding=ExpectedBinding(
            run_id=expected.run_id,
            case_id=expected.case_id,
            attempt_id=expected.attempt_id,
            environment_hash=expected.environment_hash,
            name_map_hash=expected.name_map_hash,
        ),
    )


BASE_PAYLOAD = make_payload(
    a_type=INT,
    b_type=BIGINT,
    rows=mixed_integer_rows(5, None, -7),
    query=QuerySpec(TemplateId.Q1),
)


# --------------------------------------------------------------------------
# V01: status semantics
# --------------------------------------------------------------------------


class TestV01StatusSemantics:
    def test_binding_only_facts_are_incomplete_with_pending_facts(self):
        expected = make_expected_binding(BASE_PAYLOAD, None, None)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, binding_only_facts(BASE_PAYLOAD, expected))
        assert check.status is RuntimeCheckStatus.INCOMPLETE
        assert check.stage.value == "runtime"
        assert check.case_id == case_id_of(BASE_PAYLOAD)
        conditions = condition_map(check)
        # Handwritten: binding identity conditions are evaluable; every fact
        # condition stays PENDING with missing_fact and nothing is VIOLATED.
        assert conditions["static_revalidation"].status is CheckStatus.SATISFIED
        for condition_id in (
            "binding_expected_case",
            "binding_run_id",
            "binding_case_id",
            "binding_attempt_id",
            "binding_environment_hash",
            "binding_name_map_hash",
        ):
            assert conditions[condition_id].status is CheckStatus.SATISFIED
        for condition_id in (
            "binding_content_environment",
            "binding_content_name_map",
            "observed_environment",
            "version_series",
            "vendor_build",
            "engine",
            "session_snapshot",
            "optimizer_switch",
            "a_schema",
            "a_receipts",
            "a_readback",
            "a_load",
            "b_schema",
            "b_receipts",
            "b_readback",
            "b_load",
        ):
            assert conditions[condition_id].status is CheckStatus.PENDING
            assert conditions[condition_id].reason is ReasonCode.MISSING_FACT
        assert all(c.status is not CheckStatus.VIOLATED for c in check.conditions)

    def test_complete_correct_facts_are_ready(self):
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, full_facts(BASE_PAYLOAD))
        assert check.status is RuntimeCheckStatus.READY
        assert all(c.status is CheckStatus.SATISFIED for c in check.conditions)
        assert check.validator_version == RUNTIME_VALIDATOR_IDENTITY.version == "1"

    def test_ready_never_produces_match_semantics(self):
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, full_facts(BASE_PAYLOAD))
        assert check.status is RuntimeCheckStatus.READY
        encoded = json.dumps(check.to_obj())
        assert "MATCH" not in encoded
        # No match-ish status exists in the status vocabulary.
        assert {str(status.value) for status in RuntimeCheckStatus} == {
            "READY",
            "BLOCKED",
            "INCOMPLETE",
        }
        assert all("MATCH" not in str(status.value) for status in CheckStatus)
        # No match-ish field on the check object either.
        assert not any("match" in field.name for field in dataclasses.fields(CompatibilityCheck))

    def test_known_violation_wins_over_pending_blocked(self):
        # Side A schema is wrong (known error) while side B was never
        # collected (pending): the aggregate must be BLOCKED, not INCOMPLETE.
        facts = full_facts(BASE_PAYLOAD, side_b=None)
        wrong_schema = TableSpec(
            "t0",
            (ColumnSpec("rid", BIGINT, False), ColumnSpec("v", TINYINT, True)),
            ("rid",),
            IndexVariant.NONE,
        )
        object.__setattr__(facts.a, "actual_schema", wrong_schema)
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        conditions = condition_map(check)
        assert conditions["a_schema"].status is CheckStatus.VIOLATED
        assert conditions["a_schema"].reason is ReasonCode.SCHEMA_MISMATCH
        assert conditions["b_schema"].status is CheckStatus.PENDING

    def test_zero_row_case_still_requires_full_facts(self):
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=Rows(()),
            query=QuerySpec(TemplateId.Q1),
        )
        expected = make_expected_binding(payload, observed_environment(), NAME_MAP)
        check = validate_runtime_facts(payload, expected, full_facts(payload))
        assert check.status is RuntimeCheckStatus.READY
        # Zero rows: exactly one DDL receipt per side, no INSERT receipt; the
        # satisfied receipt conditions still cover the DDL receipt.
        conditions = condition_map(check)
        assert conditions["a_receipts"].status is CheckStatus.SATISFIED
        assert "1 expected DDL/INSERT receipts" in str(conditions["a_receipts"].detail)

    def test_all_null_case_still_requires_full_facts(self):
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=mixed_integer_rows(None, None),
            query=QuerySpec(TemplateId.Q1),
        )
        expected = make_expected_binding(payload, observed_environment(), NAME_MAP)
        check = validate_runtime_facts(payload, expected, full_facts(payload))
        assert check.status is RuntimeCheckStatus.READY
        assert all(c.status is CheckStatus.SATISFIED for c in check.conditions)


# --------------------------------------------------------------------------
# V02: binding
# --------------------------------------------------------------------------


class TestV02Binding:
    def _check_with_tampered_binding_field(self, field: str, wrong_value: object) -> CompatibilityCheck:
        environment = observed_environment()
        expected = make_expected_binding(BASE_PAYLOAD, environment, NAME_MAP)
        facts = full_facts(BASE_PAYLOAD)
        tampered = dataclasses.replace(facts.binding, **{field: wrong_value})
        object.__setattr__(facts, "binding", tampered)
        return validate_runtime_facts(BASE_PAYLOAD, expected, facts)

    @pytest.mark.parametrize(
        ("field", "wrong_value"),
        [
            ("run_id", "run-other"),
            ("case_id", BOGUS_HASH),
            ("attempt_id", "attempt-parent"),
            ("environment_hash", OTHER_HASH),
            ("name_map_hash", OTHER_HASH),
        ],
    )
    def test_single_binding_field_mismatch_blocks(self, field, wrong_value):
        check = self._check_with_tampered_binding_field(field, wrong_value)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)[f"binding_{field}"]
        assert condition.status is CheckStatus.VIOLATED
        assert condition.reason is ReasonCode.BINDING_MISMATCH
        # The other binding field conditions stay satisfied.
        other_fields = [
            f"binding_{name}"
            for name in ("run_id", "case_id", "attempt_id", "environment_hash", "name_map_hash")
            if name != field
        ]
        for condition_id in other_fields:
            assert condition_map(check)[condition_id].status is CheckStatus.SATISFIED

    def test_expected_case_id_mismatch_with_payload_blocks(self):
        environment = observed_environment()
        expected = make_expected_binding(BASE_PAYLOAD, environment, NAME_MAP)
        wrong_expected = dataclasses.replace(expected, case_id=BOGUS_HASH)
        facts = full_facts(BASE_PAYLOAD)
        check = validate_runtime_facts(BASE_PAYLOAD, wrong_expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["binding_expected_case"]
        assert condition.status is CheckStatus.VIOLATED
        assert condition.reason is ReasonCode.BINDING_MISMATCH

    def test_environment_content_tamper_caught_by_recomputed_hash(self):
        # Same self-reported binding hash as the caller expectation, but the
        # attached environment content was altered (8.0.39 -> 8.0.40): only
        # the recomputed content hash can catch this.
        environment = observed_environment()
        expected = make_expected_binding(BASE_PAYLOAD, environment, NAME_MAP)
        facts = full_facts(BASE_PAYLOAD)
        tampered_env = observed_environment(version="8.0.40")
        object.__setattr__(facts, "observed_environment", tampered_env)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["binding_content_environment"]
        assert condition.status is CheckStatus.VIOLATED
        assert condition.reason is ReasonCode.BINDING_MISMATCH
        # The field-level hash comparison passed (self-reported strings agree);
        # the content recomputation is what fired.
        assert condition_map(check)["binding_environment_hash"].status is CheckStatus.SATISFIED
        # 8.0.40 is still a legal series, so the environment conditions
        # themselves are not the reason for the block.
        assert condition_map(check)["version_series"].status is CheckStatus.SATISFIED

    def test_name_map_content_tamper_caught_by_recomputed_hash(self):
        environment = observed_environment()
        expected = make_expected_binding(BASE_PAYLOAD, environment, NAME_MAP)
        facts = full_facts(BASE_PAYLOAD)
        tampered_map = NameMap(
            database_a="tc_a", database_b="tc_x", table_a="t_a", table_b="t_b"
        )
        object.__setattr__(facts, "name_map", tampered_map)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["binding_content_name_map"]
        assert condition.status is CheckStatus.VIOLATED
        assert condition.reason is ReasonCode.BINDING_MISMATCH

    def test_replayed_parent_attempt_facts_are_rejected(self):
        environment = observed_environment()
        expected = make_expected_binding(
            BASE_PAYLOAD, environment, NAME_MAP, attempt_id="attempt-child"
        )
        facts = full_facts(BASE_PAYLOAD, attempt_id="attempt-parent")
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["binding_attempt_id"]
        assert condition.status is CheckStatus.VIOLATED
        assert condition.reason is ReasonCode.BINDING_MISMATCH
        assert "attempt-parent" in str(condition.detail)
        assert "attempt-child" in str(condition.detail)

    def test_empty_optimizer_switch_snapshot_is_pending(self):
        environment = observed_environment(optimizer_switch="")
        expected = make_expected_binding(BASE_PAYLOAD, environment, NAME_MAP)
        facts = full_facts(BASE_PAYLOAD, environment=environment)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.INCOMPLETE
        condition = condition_map(check)["optimizer_switch"]
        assert condition.status is CheckStatus.PENDING
        assert condition.reason is ReasonCode.MISSING_FACT

    def test_missing_observed_environment_is_pending_not_ready(self):
        expected = make_expected_binding(BASE_PAYLOAD, None, NAME_MAP)
        facts = full_facts(BASE_PAYLOAD, environment=None)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.INCOMPLETE
        conditions = condition_map(check)
        for condition_id in ("observed_environment", "binding_content_environment", "engine"):
            assert conditions[condition_id].status is CheckStatus.PENDING
        # The load facts themselves are fine; only the environment is missing.
        assert conditions["a_readback"].status is CheckStatus.SATISFIED

    def test_one_missing_insert_receipt_blocks(self):
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        facts = full_facts(BASE_PAYLOAD)
        dropped = tuple(receipt for receipt in facts.a.statement_receipts if receipt.phase is not StatementPhase.INSERT)
        object.__setattr__(facts, "a", dataclasses.replace(facts.a, statement_receipts=dropped))
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["a_receipts"]
        assert condition.status is CheckStatus.VIOLATED
        assert condition.reason is ReasonCode.MISSING_FACT


# --------------------------------------------------------------------------
# V03: load fidelity
# --------------------------------------------------------------------------


class TestV03LoadFidelity:
    def test_readback_dropped_row_is_load_value_mismatch(self):
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        facts = full_facts(BASE_PAYLOAD)
        short_readback = Rows(facts.a.readback.rows[:-1])
        object.__setattr__(
            facts, "a", dataclasses.replace(facts.a, readback=short_readback)
        )
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["a_readback"]
        assert condition.status is CheckStatus.VIOLATED
        assert condition.reason is ReasonCode.LOAD_VALUE_MISMATCH

    def test_readback_duplicate_rid_cannot_exist(self):
        # A duplicated rid cannot even be represented as a readback: the Rows
        # contract rejects non-increasing rids at construction, so a duplicate
        # is an input error at the model layer, never a BLOCKED condition.
        with pytest.raises(ContractError):
            Rows((Row(1, IntegerValue(1)), Row(1, IntegerValue(1))))
        with pytest.raises(ContractError):
            Rows((Row(2, IntegerValue(1)), Row(1, IntegerValue(1))))

    def test_readback_precision_loss_is_load_value_mismatch(self):
        payload = make_payload(
            a_type=DECIMAL_9_2,
            b_type=DECIMAL_18_2,
            rows=decimal_rows(DecimalValue(12345, 2)),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.decimal-widen",
        )
        expected = make_expected_binding(payload, observed_environment(), NAME_MAP)
        facts = full_facts(payload)
        # One unit off in the last coefficient: the value was loaded or read
        # back with loss even though the scale matches.
        lossy_a = Rows((Row(1, DecimalValue(12344, 2)),))
        object.__setattr__(facts, "a", dataclasses.replace(facts.a, readback=lossy_a))
        check = validate_runtime_facts(payload, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["a_readback"]
        assert condition.reason is ReasonCode.LOAD_VALUE_MISMATCH

    def test_readback_scale_drift_is_load_value_mismatch(self):
        payload = make_payload(
            a_type=DECIMAL_9_2,
            b_type=DECIMAL_18_2,
            rows=decimal_rows(DecimalValue(12345, 2)),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.decimal-widen",
        )
        expected = make_expected_binding(payload, observed_environment(), NAME_MAP)
        facts = full_facts(payload)
        # Same mathematical magnitude, wrong scale: 123.45 -> 1234.5.
        drifted_b = Rows((Row(1, DecimalValue(12345, 1)),))
        object.__setattr__(facts, "b", dataclasses.replace(facts.b, readback=drifted_b))
        check = validate_runtime_facts(payload, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        assert condition_map(check)["b_readback"].reason is ReasonCode.LOAD_VALUE_MISMATCH

    def test_readback_null_becoming_zero_is_load_value_mismatch(self):
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=mixed_integer_rows(None),
            query=QuerySpec(TemplateId.Q1),
        )
        expected = make_expected_binding(payload, observed_environment(), NAME_MAP)
        facts = full_facts(payload)
        zeroed = Rows((Row(1, IntegerValue(0)),))
        object.__setattr__(facts, "a", dataclasses.replace(facts.a, readback=zeroed))
        check = validate_runtime_facts(payload, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["a_readback"]
        assert condition.reason is ReasonCode.LOAD_VALUE_MISMATCH
        assert "NULL" in str(condition.detail)

    def test_ddl_type_error_on_b_side_is_schema_mismatch(self):
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        facts = full_facts(BASE_PAYLOAD)
        wrong_type = TableSpec(
            "t0",
            (ColumnSpec("rid", BIGINT, False), ColumnSpec("v", INT, True)),
            ("rid",),
            IndexVariant.NONE,
        )
        object.__setattr__(facts.b, "actual_schema", wrong_type)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["b_schema"]
        assert condition.status is CheckStatus.VIOLATED
        assert condition.reason is ReasonCode.SCHEMA_MISMATCH

    def test_missing_index_variant_is_schema_mismatch(self):
        payload = make_payload(
            a_type=INT,
            b_type=BIGINT,
            rows=integer_rows(1),
            query=QuerySpec(TemplateId.Q1),
            index_variant=IndexVariant.IX_V,
        )
        expected = make_expected_binding(payload, observed_environment(), NAME_MAP)
        facts = full_facts(payload)
        no_index = TableSpec(
            "t0",
            (ColumnSpec("rid", BIGINT, False), ColumnSpec("v", INT, True)),
            ("rid",),
            IndexVariant.NONE,
        )
        object.__setattr__(facts.a, "actual_schema", no_index)
        check = validate_runtime_facts(payload, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        assert condition_map(check)["a_schema"].reason is ReasonCode.SCHEMA_MISMATCH

    def test_unsuccessful_statement_is_load_diagnostics(self):
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        facts = full_facts(BASE_PAYLOAD)
        failed = tuple(
            dataclasses.replace(receipt, success=False)
            if receipt.phase is StatementPhase.DDL
            else receipt
            for receipt in facts.a.statement_receipts
        )
        object.__setattr__(facts, "a", dataclasses.replace(facts.a, statement_receipts=failed))
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["a_receipts"]
        assert condition.reason is ReasonCode.LOAD_DIAGNOSTICS
        assert "success=false" in str(condition.detail)

    def test_incomplete_diagnostics_is_load_diagnostics(self):
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        facts = full_facts(BASE_PAYLOAD)
        incomplete = tuple(
            dataclasses.replace(receipt, diagnostics_complete=False)
            if receipt.phase is StatementPhase.INSERT
            else receipt
            for receipt in facts.b.statement_receipts
        )
        object.__setattr__(facts, "b", dataclasses.replace(facts.b, statement_receipts=incomplete))
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["b_receipts"]
        assert condition.reason is ReasonCode.LOAD_DIAGNOSTICS
        assert "diagnostics_complete=false" in str(condition.detail)

    def test_tampered_receipt_hash_is_missing_fact(self):
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        facts = full_facts(BASE_PAYLOAD)
        forged = tuple(
            dataclasses.replace(receipt, sql_hash=BOGUS_HASH)
            if receipt.phase is StatementPhase.INSERT
            else receipt
            for receipt in facts.a.statement_receipts
        )
        object.__setattr__(facts, "a", dataclasses.replace(facts.a, statement_receipts=forged))
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["a_receipts"]
        assert condition.reason is ReasonCode.MISSING_FACT
        assert "sql_hash" in str(condition.detail)

    def test_integer_decimal_b_scale0_decimal_matches_exactly(self):
        # mysql80.integer-decimal BIGINT -> DECIMAL(20,0): B may report the
        # loaded integers as scale-0 decimals with the same mathematical value.
        payload = make_payload(
            a_type=BIGINT,
            b_type=DECIMAL_20_0,
            rows=mixed_integer_rows(5, None),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.integer-decimal",
        )
        expected = make_expected_binding(payload, observed_environment(), NAME_MAP)
        facts = full_facts(payload)
        b_decimal_readback = Rows((Row(1, DecimalValue(5, 0)), Row(2, NullValue())))
        object.__setattr__(facts, "b", dataclasses.replace(facts.b, readback=b_decimal_readback))
        check = validate_runtime_facts(payload, expected, facts)
        assert check.status is RuntimeCheckStatus.READY
        assert condition_map(check)["b_readback"].status is CheckStatus.SATISFIED

    def test_nonzero_scale_decimal_readback_of_integer_mismatches(self):
        payload = make_payload(
            a_type=BIGINT,
            b_type=DECIMAL_20_0,
            rows=mixed_integer_rows(5),
            query=QuerySpec(TemplateId.Q1),
            rule_id="mysql80.integer-decimal",
        )
        expected = make_expected_binding(payload, observed_environment(), NAME_MAP)
        facts = full_facts(payload)
        drifted = Rows((Row(1, DecimalValue(5, 1)),))
        object.__setattr__(facts, "b", dataclasses.replace(facts.b, readback=drifted))
        check = validate_runtime_facts(payload, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        assert condition_map(check)["b_readback"].reason is ReasonCode.LOAD_VALUE_MISMATCH

    def test_float_readback_is_an_input_error_at_the_model_layer(self):
        # ExactValue has no float kind and the codec forbids float literals,
        # so a driver float cannot reach the validator at all.
        with pytest.raises(ContractError):
            decode_rows_json([[1, 1.5]])
        with pytest.raises(ContractError):
            decode_rows_json([[1, {"kind": "integer", "value": "abc"}]])

    def test_readback_over_1024_rows_is_an_input_error(self):
        with pytest.raises(ContractError):
            Rows(tuple(Row(index + 1, IntegerValue(0)) for index in range(1025)))


def decode_rows_json(raw: list) -> Rows:
    """Decode readback rows from strict JSON (floats/strings must fail)."""
    from mtsql_typecheck.contracts.codec import decode_rows

    return decode_rows(parse_strict_json(json.dumps(raw)), "readback")


# --------------------------------------------------------------------------
# Renderer linkage, fresh attempts, static gate and input errors
# --------------------------------------------------------------------------


class TestRendererLinkageAndFreshAttempts:
    def test_legal_receipts_match_live_render_pair(self):
        # The receipt hashes in full_facts come from render_pair; running the
        # renderer again here must reproduce them (pure function) and the
        # validator must accept the pair.
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        facts = full_facts(BASE_PAYLOAD)
        pair = render_pair(BASE_PAYLOAD, NAME_MAP)
        rendered_hashes = [s.sql_hash for s in pair.a if s.phase is not RenderPhase.SELECT]
        receipt_hashes = [r.sql_hash for r in facts.a.statement_receipts]
        assert rendered_hashes == receipt_hashes
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.READY

    def test_facts_rendered_under_another_name_map_are_rejected_by_binding(self):
        # Receipts are re-derived from the facts' own name map, so a facts set
        # is internally consistent under any map; what pins the legitimate
        # namespace is the caller's frozen name_map_hash in the binding.
        other_map = NameMap(
            database_a="tc_c", database_b="tc_d", table_a="t_c", table_b="t_d"
        )
        environment = observed_environment()
        expected = make_expected_binding(BASE_PAYLOAD, environment, other_map)
        facts = full_facts(BASE_PAYLOAD)  # facts binding and receipts use NAME_MAP
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["binding_name_map_hash"]
        assert condition.status is CheckStatus.VIOLATED
        assert condition.reason is ReasonCode.BINDING_MISMATCH
        # The facts are self-consistent under their own name map.
        assert condition_map(check)["a_receipts"].status is CheckStatus.SATISFIED
        assert condition_map(check)["binding_content_name_map"].status is CheckStatus.SATISFIED

    def test_fresh_attempt_with_new_facts_is_ready(self):
        # A legal re-execution: a brand-new attempt id and its own complete
        # facts validate on their own, without any parent-attempt state.
        environment = observed_environment()
        expected = make_expected_binding(
            BASE_PAYLOAD, environment, NAME_MAP, attempt_id="attempt-2"
        )
        facts = full_facts(BASE_PAYLOAD, attempt_id="attempt-2")
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.READY


class TestStaticGateAndInputErrors:
    def test_static_invalid_blocks_with_first_violated_condition(self):
        payload = make_payload(
            a_type=TINYINT,
            b_type=INT,  # TINYINT -> INT is not an authorized pair
            rows=integer_rows(1),
            query=QuerySpec(TemplateId.Q1),
        )
        environment = observed_environment()
        expected = make_expected_binding(payload, environment, NAME_MAP)
        facts = full_facts(payload)
        check = validate_runtime_facts(payload, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        # Exactly the first VIOLATED static condition is retained.
        assert tuple(c.condition_id for c in check.conditions) == ("rule_binding",)
        assert check.conditions[0].status is CheckStatus.VIOLATED

    def test_malformed_facts_are_input_errors(self):
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        with pytest.raises(RuntimeFactsError):
            validate_runtime_facts(BASE_PAYLOAD, expected, "not facts")  # type: ignore[arg-type]
        with pytest.raises(RuntimeFactsError):
            validate_runtime_facts(BASE_PAYLOAD, expected, None)  # type: ignore[arg-type]
        with pytest.raises(RuntimeFactsError):
            validate_runtime_facts(BASE_PAYLOAD, "not a binding", full_facts(BASE_PAYLOAD))  # type: ignore[arg-type]
        facts = full_facts(BASE_PAYLOAD)
        object.__setattr__(facts, "facts_schema_version", 2)
        with pytest.raises(RuntimeFactsError):
            validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert issubclass(RuntimeFactsError, ContractError)

    def test_facts_binding_must_be_present(self):
        # A facts object without a binding cannot be constructed through the
        # contract model at all; the validator would also refuse a bypass.
        with pytest.raises(ContractError):
            RuntimeFacts(binding=None)  # type: ignore[arg-type]
        expected = make_expected_binding(BASE_PAYLOAD, observed_environment(), NAME_MAP)
        facts = full_facts(BASE_PAYLOAD)
        object.__setattr__(facts, "binding", None)
        with pytest.raises(RuntimeFactsError):
            validate_runtime_facts(BASE_PAYLOAD, expected, facts)

    def test_mariadb_vendor_is_not_mysql80(self):
        environment = observed_environment(vendor="mariadb", version="8.0.39")
        expected = make_expected_binding(BASE_PAYLOAD, environment, NAME_MAP)
        facts = full_facts(BASE_PAYLOAD, environment=environment)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["version_series"]
        assert condition.reason is ReasonCode.UNSUPPORTED_ENVIRONMENT
        assert "MariaDB" in str(condition.detail)

    def test_non_80_series_version_rejected(self):
        environment = observed_environment(version="5.7.44-log")
        expected = make_expected_binding(BASE_PAYLOAD, environment, NAME_MAP)
        facts = full_facts(BASE_PAYLOAD, environment=environment)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        assert condition_map(check)["version_series"].reason is ReasonCode.UNSUPPORTED_ENVIRONMENT

    def test_wrong_engine_rejected(self):
        environment = observed_environment(engine="MyRocks")
        expected = make_expected_binding(BASE_PAYLOAD, environment, NAME_MAP)
        facts = full_facts(BASE_PAYLOAD, environment=environment)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        assert condition_map(check)["engine"].reason is ReasonCode.UNSUPPORTED_ENVIRONMENT

    def test_wrong_session_tokens_rejected(self):
        environment = observed_environment(sql_mode_tokens=("STRICT_ALL_TABLES",))
        expected = make_expected_binding(BASE_PAYLOAD, environment, NAME_MAP)
        facts = full_facts(BASE_PAYLOAD, environment=environment)
        check = validate_runtime_facts(BASE_PAYLOAD, expected, facts)
        assert check.status is RuntimeCheckStatus.BLOCKED
        condition = condition_map(check)["session_snapshot"]
        assert condition.reason is ReasonCode.UNSUPPORTED_ENVIRONMENT
        assert condition.status is CheckStatus.VIOLATED

    @pytest.mark.parametrize(
        ("version", "expected_series"),
        [
            ("8.0.39", (8, 0)),
            ("8.0.39-log", (8, 0)),
            ("8.0", (8, 0)),
            (" 8.0.39", (8, 0)),
            ("5.7.44", (5, 7)),
            ("10.11.6-MariaDB", (10, 11)),
            ("8", None),
            ("not-a-version", None),
            ("", None),
        ],
    )
    def test_version_series_parser(self, version, expected_series):
        assert parse_mysql_version_series(version) == expected_series


# --------------------------------------------------------------------------
# Contract fixtures (tests/contract/fixtures/runtime_facts_*.json)
# --------------------------------------------------------------------------


def _load_synthetic_fixture(name: str) -> dict:
    """Load a synthetic fixture and strip its ``_``-prefixed documentation
    keys (JSON has no comments; the strict contract loader rejects unknown
    fields, so the documentation keys must come off before decoding)."""
    data = parse_strict_json((FIXTURES / name).read_text(encoding="utf-8"))
    assert data["_synthetic"] is True
    assert isinstance(data["_note"], str) and data["_note"]
    return {key: value for key, value in data.items() if not key.startswith("_")}


class TestContractFixtures:
    def test_expected_binding_with_ready_facts_is_ready(self):
        payload = load_payload(
            (FIXTURES / "payload_signed_widen_q1.json").read_text(encoding="utf-8")
        )
        expected = decode_expected_binding(
            _load_synthetic_fixture("runtime_facts_expected_binding.json")
        )
        facts = decode_runtime_facts(_load_synthetic_fixture("runtime_facts_ready.json"))
        check = validate_runtime_facts(payload, expected, facts)
        # Handwritten expectation from the fixture README: READY, all satisfied.
        assert check.status is RuntimeCheckStatus.READY
        assert all(c.status is CheckStatus.SATISFIED for c in check.conditions)

    @pytest.mark.parametrize(
        ("fixture_name", "expected_status", "expected_failures"),
        [
            # Handwritten from the fixture _note fields / README.
            (
                "runtime_facts_pending.json",
                RuntimeCheckStatus.INCOMPLETE,
                [],
            ),
            (
                "runtime_facts_blocked.json",
                RuntimeCheckStatus.BLOCKED,
                [("a_readback", ReasonCode.LOAD_VALUE_MISMATCH)],
            ),
            (
                "runtime_facts_incomplete.json",
                RuntimeCheckStatus.INCOMPLETE,
                [],
            ),
        ],
    )
    def test_facts_fixture_conclusions(self, fixture_name, expected_status, expected_failures):
        payload = load_payload(
            (FIXTURES / "payload_signed_widen_q1.json").read_text(encoding="utf-8")
        )
        expected = decode_expected_binding(
            _load_synthetic_fixture("runtime_facts_expected_binding.json")
        )
        facts = decode_runtime_facts(_load_synthetic_fixture(fixture_name))
        check = validate_runtime_facts(payload, expected, facts)
        assert check.status is expected_status
        conditions = condition_map(check)
        for condition_id, reason in expected_failures:
            assert conditions[condition_id].status is CheckStatus.VIOLATED
            assert conditions[condition_id].reason is reason
        violated = [c for c in check.conditions if c.status is CheckStatus.VIOLATED]
        assert [(c.condition_id, c.reason) for c in violated] == expected_failures

    def test_pending_fixture_has_only_pending_fact_conditions(self):
        payload = load_payload(
            (FIXTURES / "payload_signed_widen_q1.json").read_text(encoding="utf-8")
        )
        expected = decode_expected_binding(
            _load_synthetic_fixture("runtime_facts_expected_binding.json")
        )
        facts = decode_runtime_facts(_load_synthetic_fixture("runtime_facts_pending.json"))
        check = validate_runtime_facts(payload, expected, facts)
        assert check.status is RuntimeCheckStatus.INCOMPLETE
        conditions = condition_map(check)
        for condition_id in ("observed_environment", "a_receipts", "b_readback", "b_load"):
            assert conditions[condition_id].status is CheckStatus.PENDING
            assert conditions[condition_id].reason is ReasonCode.MISSING_FACT

    def test_incomplete_fixture_keeps_side_b_pending(self):
        payload = load_payload(
            (FIXTURES / "payload_signed_widen_q1.json").read_text(encoding="utf-8")
        )
        expected = decode_expected_binding(
            _load_synthetic_fixture("runtime_facts_expected_binding.json")
        )
        facts = decode_runtime_facts(_load_synthetic_fixture("runtime_facts_incomplete.json"))
        check = validate_runtime_facts(payload, expected, facts)
        assert check.status is RuntimeCheckStatus.INCOMPLETE
        conditions = condition_map(check)
        for condition_id in ("b_schema", "b_receipts", "b_readback", "b_load"):
            assert conditions[condition_id].status is CheckStatus.PENDING
        for condition_id in ("a_schema", "a_receipts", "a_readback", "a_load"):
            assert conditions[condition_id].status is CheckStatus.SATISFIED
