"""O01 tests for oracle.fingerprint (contract 5).

Expectations are hand-constructed count tables and payload parameters; the
golden hashes were computed once by an independent plain-``hashlib`` script
(own ``json.dumps(sort_keys=True, separators=(",", ":"))`` canonicalization,
never calling the functions under test) and are frozen below as literals.
"""

from __future__ import annotations

import pytest

from mtsql_typecheck.contracts.case import (
    CasePayload,
    ColumnSpec,
    Compare,
    CompareOp,
    ContractError,
    DecimalType,
    EnvironmentRequirements,
    ExactLiteral,
    IndexVariant,
    IntegerValue,
    NullPolicy,
    QuerySpec,
    RelationMode,
    ResultColumnSpec,
    ResultRelationSpec,
    Row,
    Rows,
    RuleRef,
    SemverIdentity,
    SignedIntName,
    SignedIntegerType,
    TableSpec,
    TemplateId,
    TypeFamily,
    ValueEquivalence,
    REQUIRED_CHARACTER_SET,
    REQUIRED_COLLATION,
    REQUIRED_SQL_MODE_TOKENS,
    REQUIRED_TIME_ZONE,
)
from mtsql_typecheck.contracts.execution import (
    SessionProfile,
    TransactionIsolation,
)
from mtsql_typecheck.oracle.fingerprint import (
    exact_signature,
    fingerprint,
    relation_hash,
)

ENVIRONMENT_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
CODEC_VERSION = "c1"
RENDERER = SemverIdentity("r1", "1")
SESSION_PROFILE = SessionProfile(True, TransactionIsolation.REPEATABLE_READ)
ORACLE_VERSION = "o1"

# Hand-written multiset count tables (never derived from the code under test).
COUNTS_A = {("number", "1", 0): 1, ("number", "2", 0): 2}
COUNTS_B = {("number", "1", 0): 1}
COUNTS_A_ALT_ORDER = {("number", "2", 0): 2, ("number", "1", 0): 1}
COUNTS_A_CHANGED = {("number", "1", 0): 2, ("number", "2", 0): 2}


ENV = EnvironmentRequirements(
    database="mysql80",
    engine="innodb",
    scope="same-instance",
    sql_mode_tokens=REQUIRED_SQL_MODE_TOKENS,
    character_set=REQUIRED_CHARACTER_SET,
    collation=REQUIRED_COLLATION,
    time_zone=REQUIRED_TIME_ZONE,
)


def _family(type_spec: object) -> TypeFamily:
    if isinstance(type_spec, SignedIntegerType):
        return TypeFamily.SIGNED_INTEGER
    return TypeFamily.DECIMAL


def make_payload(
    *,
    row_values: tuple = (1, 2, 3),
    a_type: object = None,
    b_type: object = None,
    template: TemplateId = TemplateId.Q1,
    index_variant: IndexVariant = IndexVariant.NONE,
    rule: tuple[str, int] = ("mysql80.integer-decimal", 1),
    renderer: SemverIdentity = RENDERER,
    alias: str = "c0",
    null_policy: NullPolicy = NullPolicy.PRESERVE,
) -> CasePayload:
    a = a_type if a_type is not None else SignedIntegerType(SignedIntName.INT)
    b = b_type if b_type is not None else DecimalType(12, 2)
    predicate = None
    if template is TemplateId.Q2:
        predicate = Compare(
            CompareOp.EQ, ExactLiteral(IntegerValue(1))
        )
    return CasePayload(
        rule=RuleRef(rule[0], rule[1]),
        a_type=a,
        b_type=b,
        table=TableSpec(
            "t0",
            (
                ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
                ColumnSpec("v", a, True),
            ),
            ("rid",),
            index_variant,
        ),
        rows=Rows(tuple(Row(index + 1, IntegerValue(value)) for index, value in enumerate(row_values))),
        query=QuerySpec(template, predicate=predicate),
        relation=ResultRelationSpec(
            RelationMode.MULTISET_EXACT,
            (
                ResultColumnSpec(
                    alias,
                    _family(a),
                    _family(b),
                    ValueEquivalence.EXACT_NUMERIC,
                    null_policy,
                ),
            ),
        ),
        environment=ENV,
        generator=SemverIdentity("g1", "1"),
        renderer=renderer,
    )


# --------------------------------------------------------------------------
# relation_hash helper
# --------------------------------------------------------------------------


def test_relation_hash_is_the_hash_of_the_canonical_relation_object() -> None:
    payload = make_payload()
    # hand-computed expectation: canonical JSON of the single-column relation
    import hashlib
    import json

    relation_obj = payload.relation.to_obj()
    expected = hashlib.sha256(
        json.dumps(
            relation_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()
    assert relation_hash(payload) == expected


def test_relation_hash_changes_with_the_declared_relation() -> None:
    assert relation_hash(make_payload()) != relation_hash(
        make_payload(null_policy=NullPolicy.FORBID)
    )
    assert relation_hash(make_payload()) != relation_hash(make_payload(alias="c1"))


# --------------------------------------------------------------------------
# exact_signature
# --------------------------------------------------------------------------


def test_exact_signature_ignores_count_insertion_order() -> None:
    payload = make_payload()
    assert exact_signature(payload, ORACLE_VERSION, COUNTS_A, COUNTS_B) == (
        exact_signature(payload, ORACLE_VERSION, COUNTS_A_ALT_ORDER, COUNTS_B)
    )


def test_exact_signature_accepts_canonical_byte_key_tables() -> None:
    # the same tables keyed by hand-written canonical row_key_bytes literals
    byte_counts_a = {b'[["number","1",0]]': 1, b'[["number","2",0]]': 2}
    byte_counts_b = {b'[["number","1",0]]': 1}
    payload = make_payload()
    assert exact_signature(payload, ORACLE_VERSION, byte_counts_a, byte_counts_b) == (
        exact_signature(payload, ORACLE_VERSION, COUNTS_A, COUNTS_B)
    )


def test_exact_signature_changes_with_multiplicity() -> None:
    payload = make_payload()
    baseline = exact_signature(payload, ORACLE_VERSION, COUNTS_A, COUNTS_B)
    assert baseline != exact_signature(payload, ORACLE_VERSION, COUNTS_A_CHANGED, COUNTS_B)
    assert baseline != exact_signature(payload, ORACLE_VERSION, COUNTS_A, {})


def test_exact_signature_binds_the_case_identity() -> None:
    # same counts, same everything but the rows (hence a different case_id)
    first = exact_signature(
        make_payload(row_values=(1, 2, 3)), ORACLE_VERSION, COUNTS_A, COUNTS_B
    )
    second = exact_signature(
        make_payload(row_values=(1, 2, 3, 4)), ORACLE_VERSION, COUNTS_A, COUNTS_B
    )
    assert first != second


def test_exact_signature_binds_rule_and_relation() -> None:
    counts_a, counts_b = COUNTS_A, COUNTS_B
    baseline = exact_signature(make_payload(), ORACLE_VERSION, counts_a, counts_b)
    assert baseline != exact_signature(
        make_payload(rule=("mysql80.signed-widen", 1)), ORACLE_VERSION, counts_a, counts_b
    )
    assert baseline != exact_signature(
        make_payload(null_policy=NullPolicy.FORBID), ORACLE_VERSION, counts_a, counts_b
    )


def test_exact_signature_golden_hash() -> None:
    # Frozen golden, computed once by an independent plain-hashlib script:
    # material = ["exact_signature_v1", case_id, "mysql80.integer-decimal", 1,
    #   <registered definition_hash>, <relation_hash>, "o1",
    #   [["A", [["number","1",0],1], [["number","2",0],2]],
    #    ["B", [["number","1",0],1]]]]
    payload = make_payload()
    assert exact_signature(payload, ORACLE_VERSION, COUNTS_A, COUNTS_B) == (
        "50ba6555ff2de095d1103506906e934797c765157617e1a4131d6c19557fe20c"
    )


# --------------------------------------------------------------------------
# fingerprint
# --------------------------------------------------------------------------


def test_fingerprint_excludes_case_id_values_and_row_counts() -> None:
    base = fingerprint(
        make_payload(row_values=(1, 2, 3)),
        ORACLE_VERSION,
        RENDERER,
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SESSION_PROFILE,
    )
    # different rows -> different case_id, same fingerprint
    assert base == fingerprint(
        make_payload(row_values=(9, 9, 9, 9, 9)),
        ORACLE_VERSION,
        RENDERER,
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SESSION_PROFILE,
    )
    assert base == fingerprint(
        make_payload(row_values=(0,)),
        ORACLE_VERSION,
        RENDERER,
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SESSION_PROFILE,
    )


def test_fingerprint_changes_with_grouping_relevant_inputs() -> None:
    base_payload = make_payload()
    base = fingerprint(
        base_payload, ORACLE_VERSION, RENDERER, CODEC_VERSION, ENVIRONMENT_HASH, SESSION_PROFILE
    )
    assert base != fingerprint(
        make_payload(template=TemplateId.Q2),
        ORACLE_VERSION,
        RENDERER,
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SESSION_PROFILE,
    )
    assert base != fingerprint(
        make_payload(b_type=DecimalType(12, 4)),
        ORACLE_VERSION,
        RENDERER,
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SESSION_PROFILE,
    )
    assert base != fingerprint(
        make_payload(a_type=SignedIntegerType(SignedIntName.BIGINT)),
        ORACLE_VERSION,
        RENDERER,
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SESSION_PROFILE,
    )
    assert base != fingerprint(
        make_payload(index_variant=IndexVariant.IX_V),
        ORACLE_VERSION,
        RENDERER,
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SESSION_PROFILE,
    )
    assert base != fingerprint(
        base_payload,
        ORACLE_VERSION,
        RENDERER,
        CODEC_VERSION,
        "1" * 64,
        SESSION_PROFILE,
    )
    assert base != fingerprint(
        base_payload,
        ORACLE_VERSION,
        RENDERER,
        "c2",
        ENVIRONMENT_HASH,
        SESSION_PROFILE,
    )
    assert base != fingerprint(
        base_payload,
        ORACLE_VERSION,
        SemverIdentity("r1", "2"),
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SESSION_PROFILE,
    )
    assert base != fingerprint(
        base_payload,
        ORACLE_VERSION,
        SemverIdentity("r2", "1"),
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SESSION_PROFILE,
    )
    assert base != fingerprint(
        base_payload,
        ORACLE_VERSION,
        RENDERER,
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SessionProfile(False, TransactionIsolation.REPEATABLE_READ),
    )
    assert base != fingerprint(
        base_payload,
        ORACLE_VERSION,
        RENDERER,
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SessionProfile(True, TransactionIsolation.SERIALIZABLE),
    )
    assert base != fingerprint(
        make_payload(rule=("mysql80.signed-widen", 1)),
        ORACLE_VERSION,
        RENDERER,
        CODEC_VERSION,
        ENVIRONMENT_HASH,
        SESSION_PROFILE,
    )


def test_fingerprint_golden_hash() -> None:
    # Frozen golden, computed once by an independent plain-hashlib script.
    payload = make_payload()
    assert fingerprint(
        payload, ORACLE_VERSION, RENDERER, CODEC_VERSION, ENVIRONMENT_HASH, SESSION_PROFILE
    ) == "cbb8bcacf3f5ab299174014c2d68343113145fbb493355d85613ec5cba4f3a71"


def test_exact_signature_and_fingerprint_are_different_identities() -> None:
    payload = make_payload()
    signature = exact_signature(payload, ORACLE_VERSION, COUNTS_A, COUNTS_B)
    group = fingerprint(
        payload, ORACLE_VERSION, RENDERER, CODEC_VERSION, ENVIRONMENT_HASH, SESSION_PROFILE
    )
    assert signature != group
    # a multiplicity change moves the exact signature but not the fingerprint
    assert exact_signature(payload, ORACLE_VERSION, COUNTS_A_CHANGED, COUNTS_B) != signature
    assert fingerprint(
        payload, ORACLE_VERSION, RENDERER, CODEC_VERSION, ENVIRONMENT_HASH, SESSION_PROFILE
    ) == group


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------


def test_exact_signature_input_validation() -> None:
    payload = make_payload()
    with pytest.raises(ContractError):
        exact_signature("payload", ORACLE_VERSION, COUNTS_A, COUNTS_B)
    with pytest.raises(ContractError):
        exact_signature(payload, "o2", COUNTS_A, COUNTS_B)
    with pytest.raises(ContractError):
        exact_signature(payload, 1, COUNTS_A, COUNTS_B)
    with pytest.raises(ContractError):
        exact_signature(payload, ORACLE_VERSION, COUNTS_A.items(), COUNTS_B)
    with pytest.raises(ContractError):
        exact_signature(payload, ORACLE_VERSION, {("number", "01", 0): 1}, COUNTS_B)
    with pytest.raises(ContractError):
        exact_signature(payload, ORACLE_VERSION, {"not-a-key": 1}, COUNTS_B)
    with pytest.raises(ContractError):
        exact_signature(payload, ORACLE_VERSION, {("number", "1", 0): 0}, COUNTS_B)
    with pytest.raises(ContractError):
        exact_signature(payload, ORACLE_VERSION, {("number", "1", 0): True}, COUNTS_B)
    with pytest.raises(ContractError):
        exact_signature(payload, ORACLE_VERSION, {("number", "1", 0): -1}, COUNTS_B)
    with pytest.raises(ContractError):
        # non-canonical byte key: 0-padded text would re-encode differently
        exact_signature(
            payload, ORACLE_VERSION, {b'[["number", "1", 0]]': 1}, COUNTS_B
        )
    with pytest.raises(ContractError):
        exact_signature(payload, ORACLE_VERSION, {("number", "1", 66): 1}, COUNTS_B)


def test_fingerprint_input_validation() -> None:
    payload = make_payload()
    with pytest.raises(ContractError):
        fingerprint(None, ORACLE_VERSION, RENDERER, CODEC_VERSION, ENVIRONMENT_HASH, SESSION_PROFILE)
    with pytest.raises(ContractError):
        fingerprint(payload, "o2", RENDERER, CODEC_VERSION, ENVIRONMENT_HASH, SESSION_PROFILE)
    with pytest.raises(ContractError):
        fingerprint(payload, ORACLE_VERSION, "r1/1", CODEC_VERSION, ENVIRONMENT_HASH, SESSION_PROFILE)
    with pytest.raises(ContractError):
        fingerprint(payload, ORACLE_VERSION, RENDERER, "", ENVIRONMENT_HASH, SESSION_PROFILE)
    with pytest.raises(ContractError):
        fingerprint(payload, ORACLE_VERSION, RENDERER, 1, ENVIRONMENT_HASH, SESSION_PROFILE)
    with pytest.raises(ContractError):
        fingerprint(payload, ORACLE_VERSION, RENDERER, CODEC_VERSION, "xyz", SESSION_PROFILE)
    with pytest.raises(ContractError):
        fingerprint(payload, ORACLE_VERSION, RENDERER, CODEC_VERSION, "A" * 64, SESSION_PROFILE)
    with pytest.raises(ContractError):
        fingerprint(payload, ORACLE_VERSION, RENDERER, CODEC_VERSION, ENVIRONMENT_HASH, {"autocommit": True})
    with pytest.raises(ContractError):
        fingerprint(payload, ORACLE_VERSION, RENDERER, CODEC_VERSION, ENVIRONMENT_HASH, None)
