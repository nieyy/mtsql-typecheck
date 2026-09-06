"""C02 contract tests: case identity, canonical bytes, and hash guards.

The golden canonical bytes and case_id below were produced once by an
independent script (payload built via the contract models, canonical JSON
hashed with the external ``shasum -a 256`` tool) and frozen as literals; no
assertion recomputes its own expectation with the code under test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mtsql_typecheck.contracts import codec
from mtsql_typecheck.contracts.case import (
    CaseBundle,
    CasePayload,
    CheckStage,
    CheckStatus,
    ColumnSpec,
    CompatibilityCheck,
    ConditionResult,
    ContractError,
    DecimalType,
    EnvironmentRequirements,
    IndexVariant,
    IntegerValue,
    NullValue,
    Provenance,
    QuerySpec,
    ResultColumnSpec,
    ResultRelationSpec,
    RelationMode,
    Row,
    Rows,
    RuleRef,
    NullPolicy,
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

FIXTURES = Path(__file__).parent / "fixtures"

# Frozen by hand: canonical JSON of the golden payload and its SHA-256,
# cross-checked with `shasum -a 256 golden_payload.json`.
GOLDEN_CANONICAL_BYTES = (
    b'{"a_type":{"kind":"signed_integer","name":"TINYINT"},'
    b'"b_type":{"kind":"signed_integer","name":"SMALLINT"},'
    b'"case_schema_version":1,'
    b'"environment":{"character_set":"utf8mb4","collation":"utf8mb4_bin",'
    b'"database":"mysql80","engine":"innodb","scope":"same-instance",'
    b'"sql_mode_tokens":["NO_ENGINE_SUBSTITUTION","ONLY_FULL_GROUP_BY",'
    b'"STRICT_ALL_TABLES"],"time_zone":"+00:00"},'
    b'"generator":{"id":"g1","version":"1"},'
    b'"query":{"projections":[{"alias":"c0","expr":{"column":"v","kind":"column_ref"}}],'
    b'"template_id":"Q1"},'
    b'"relation":{"columns":[{"a_family":"signed_integer","alias":"c0",'
    b'"b_family":"signed_integer","null_policy":"preserve",'
    b'"value_equivalence":"exact_numeric"}],"mode":"multiset_exact"},'
    b'"renderer":{"id":"r1","version":"1"},'
    b'"rows":[[1,{"kind":"integer","value":"-128"}],[2,{"kind":"integer","value":"0"}],'
    b'[3,{"kind":"null"}],[4,{"kind":"integer","value":"127"}]],'
    b'"rule":{"rule_id":"mysql80.signed-widen","rule_version":1},'
    b'"table":{"columns":[{"name":"rid","nullable":false,'
    b'"type":{"kind":"signed_integer","name":"BIGINT"}},'
    b'{"name":"v","nullable":true,"type":{"kind":"signed_integer","name":"TINYINT"}}],'
    b'"index_variant":"none","logical_id":"t0","primary_key":["rid"]}}'
)
GOLDEN_CASE_ID = "bd3875f716326cd0c0e361fcc52f7db71967558e4113ab8be1bbb99109e6c305"


def _golden_payload() -> CasePayload:
    return CasePayload(
        rule=RuleRef("mysql80.signed-widen", 1),
        a_type=SignedIntegerType(SignedIntName.TINYINT),
        b_type=SignedIntegerType(SignedIntName.SMALLINT),
        table=TableSpec(
            "t0",
            (
                ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
                ColumnSpec("v", SignedIntegerType(SignedIntName.TINYINT), True),
            ),
            ("rid",),
            IndexVariant.NONE,
        ),
        rows=Rows(
            (
                Row(1, IntegerValue(-128)),
                Row(2, IntegerValue(0)),
                Row(3, NullValue()),
                Row(4, IntegerValue(127)),
            )
        ),
        query=QuerySpec(TemplateId.Q1),
        relation=ResultRelationSpec(
            RelationMode.MULTISET_EXACT,
            (
                ResultColumnSpec(
                    "c0",
                    TypeFamily.SIGNED_INTEGER,
                    TypeFamily.SIGNED_INTEGER,
                    ValueEquivalence.EXACT_NUMERIC,
                    NullPolicy.PRESERVE,
                ),
            ),
        ),
        environment=EnvironmentRequirements(
            "mysql80",
            "innodb",
            "same-instance",
            REQUIRED_SQL_MODE_TOKENS,
            "utf8mb4",
            "utf8mb4_bin",
            "+00:00",
        ),
        generator=SemverIdentity("g1", "1"),
        renderer=SemverIdentity("r1", "1"),
    )


def _static_check(case_id: str) -> CompatibilityCheck:
    return CompatibilityCheck(
        stage=CheckStage.STATIC,
        case_id=case_id,
        validator_version="1",
        conditions=(
            ConditionResult("structure.whitelist", CheckStatus.PENDING),
            ConditionResult("domain.shared_values", CheckStatus.SATISFIED),
        ),
        status=StaticCheckStatus.VALID_STATIC,
    )


# --------------------------------------------------------------------------
# Golden identity
# --------------------------------------------------------------------------


def test_golden_payload_has_frozen_canonical_bytes_and_case_id():
    payload = _golden_payload()
    assert codec.dump_payload(payload) == GOLDEN_CANONICAL_BYTES
    assert codec.case_id_of(payload) == GOLDEN_CASE_ID


def test_payload_constructor_accepts_derived_case_id_and_loader_matches():
    # Same semantic content from the hand-written fixture file must reproduce
    # the frozen identity byte-for-byte.
    loaded = codec.load_payload(
        FIXTURES.joinpath("payload_signed_widen_q1.json").read_text(encoding="utf-8")
    )
    assert loaded == _golden_payload()
    assert codec.case_id_of(loaded) == GOLDEN_CASE_ID


@pytest.mark.parametrize(
    "mutation_name",
    ["rule_version", "b_type", "row_value", "template", "relation_family", "index"],
)
def test_any_semantic_change_alters_case_id(mutation_name):
    base = _golden_payload()
    changed = _golden_payload()
    if mutation_name == "rule_version":
        changed_rule = RuleRef(changed.rule.rule_id, 2)
        object.__setattr__(changed, "rule", changed_rule)
    elif mutation_name == "b_type":
        object.__setattr__(changed, "b_type", SignedIntegerType(SignedIntName.INT))
    elif mutation_name == "row_value":
        rows = list(changed.rows.rows)
        rows[1] = Row(2, IntegerValue(1))
        object.__setattr__(changed, "rows", Rows(tuple(rows)))
    elif mutation_name == "template":
        predicate = _golden_payload().query.predicate
        from mtsql_typecheck.contracts.case import Compare, CompareOp, ExactLiteral

        object.__setattr__(
            changed,
            "query",
            QuerySpec(
                TemplateId.Q2,
                predicate=Compare(CompareOp.EQ, ExactLiteral(IntegerValue(0))),
            ),
        )
    elif mutation_name == "relation_family":
        relation = ResultRelationSpec(
            RelationMode.MULTISET_EXACT,
            (
                ResultColumnSpec(
                    "c0",
                    TypeFamily.SIGNED_INTEGER,
                    TypeFamily.DECIMAL,
                    ValueEquivalence.EXACT_NUMERIC,
                    NullPolicy.PRESERVE,
                ),
            ),
        )
        object.__setattr__(changed, "relation", relation)
    else:
        table = TableSpec(
            changed.table.logical_id,
            changed.table.columns,
            changed.table.primary_key,
            IndexVariant.IX_V,
        )
        object.__setattr__(changed, "table", table)
    assert codec.case_id_of(changed) != codec.case_id_of(base)
    # Sanity: the base still hashes to the frozen golden value.
    assert codec.case_id_of(base) == GOLDEN_CASE_ID


def test_provenance_and_runtime_fields_do_not_affect_case_id():
    payload = _golden_payload()
    check = _static_check(GOLDEN_CASE_ID)
    bundle_one = CaseBundle(
        payload=payload,
        provenance=Provenance(seed=42, ordinal=0, profile_hash="ab" * 32, retry=0),
        preview_a_sql="-- a",
        preview_b_sql="-- b",
        static_check=check,
    )
    bundle_two = CaseBundle(
        payload=payload,
        provenance=Provenance(seed=43, ordinal=7, profile_hash="cd" * 32, retry=4),
        preview_a_sql="-- a",
        preview_b_sql="-- b",
        static_check=check,
    )
    assert bundle_one.case_id == bundle_two.case_id == GOLDEN_CASE_ID


def test_forged_bundle_case_id_is_rejected():
    payload = _golden_payload()
    check = _static_check(GOLDEN_CASE_ID)
    with pytest.raises(ContractError, match="does not match payload hash"):
        CaseBundle(
            payload=payload,
            provenance=Provenance(seed=42, ordinal=0, profile_hash="ab" * 32, retry=0),
            preview_a_sql="-- a",
            preview_b_sql="-- b",
            static_check=check,
            case_id="0" * 64,
        )


def test_static_check_referencing_another_case_is_rejected():
    payload = _golden_payload()
    forged_check = _static_check("1" * 64)
    with pytest.raises(ContractError, match="same case_id"):
        CaseBundle(
            payload=payload,
            provenance=Provenance(seed=42, ordinal=0, profile_hash="ab" * 32, retry=0),
            preview_a_sql="-- a",
            preview_b_sql="-- b",
            static_check=forged_check,
        )


# --------------------------------------------------------------------------
# Row canonicality and rid guards
# --------------------------------------------------------------------------


def test_unsorted_rows_are_rejected_not_repaired():
    payload_rows = _golden_payload().rows.rows
    with pytest.raises(ContractError, match="strictly increasing"):
        Rows((payload_rows[1], payload_rows[0]))


def test_duplicate_rid_is_rejected():
    from mtsql_typecheck.contracts.case import normalize_row_pairs

    with pytest.raises(ContractError, match="duplicate rid"):
        normalize_row_pairs([(1, IntegerValue(0)), (1, IntegerValue(1))])


@pytest.mark.parametrize("bad_rid", [0, -(2**63), 2**63, 2**64])
def test_rid_out_of_bounds_is_rejected(bad_rid):
    with pytest.raises(ContractError, match="rid"):
        Row(bad_rid, IntegerValue(0))


def test_loader_rejects_tampered_row_order_in_sealed_payload():
    payload = _golden_payload()
    tampered = payload.to_obj()
    tampered["rows"] = [tampered["rows"][1], tampered["rows"][0]]
    with pytest.raises(ContractError, match="strictly increasing"):
        codec.load_payload(codec.canonical_json(tampered))


def test_environment_rejects_unsorted_and_duplicate_sql_mode_tokens():
    base = _golden_payload().environment
    for tokens in (
        ("STRICT_ALL_TABLES", "ONLY_FULL_GROUP_BY", "NO_ENGINE_SUBSTITUTION"),
        ("NO_ENGINE_SUBSTITUTION", "NO_ENGINE_SUBSTITUTION"),
        ("STRICT_ALL_TABLES", "ONLY_FULL_GROUP_BY"),
    ):
        with pytest.raises(ContractError, match="sql_mode_tokens"):
            EnvironmentRequirements(
                base.database,
                base.engine,
                base.scope,
                tokens,
                base.character_set,
                base.collation,
                base.time_zone,
            )


def test_decimal_type_and_family_tampering_changes_identity_not_acceptance():
    # A decimal B-side is semantically a different case (different rule), so
    # it must hash differently; the loader still accepts it as structurally
    # valid payload because rule preconditions are validated separately.
    changed = _golden_payload()
    object.__setattr__(changed, "b_type", DecimalType(3, 0))
    assert codec.case_id_of(changed) != GOLDEN_CASE_ID
    reloaded = codec.load_payload(codec.dump_payload(changed))
    assert reloaded.b_type == DecimalType(3, 0)
