"""C01 contract tests: exact-value roundtrips and strict codec rejections.

Expected canonical bytes, hashes and substream vectors were produced once by
independent scripts (plain ``hashlib``/``shasum``, no project imports) and are
frozen as literals below; they are never recomputed by the code under test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mtsql_typecheck.contracts import codec
from mtsql_typecheck.contracts.case import (
    CASE_SCHEMA_VERSION,
    CasePayload,
    ColumnSpec,
    ColumnName,
    ColumnRef,
    DecimalType,
    DecimalValue,
    EnvironmentRequirements,
    IndexVariant,
    IntegerValue,
    NullValue,
    QuerySpec,
    ResultColumnSpec,
    ResultRelationSpec,
    RelationMode,
    Row,
    Rows,
    RuleRef,
    NullPolicy,
    NullValue,
    SemverIdentity,
    SignedIntegerType,
    SignedIntName,
    TableSpec,
    TemplateId,
    TypeFamily,
    ValueEquivalence,
    ContractError,
    REQUIRED_SQL_MODE_TOKENS,
)

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------
# canonical_json: exact bytes, sorted keys, ASCII, no trailing newline
# --------------------------------------------------------------------------


def test_canonical_json_bytes_are_sorted_compact_ascii_without_newline():
    assert codec.canonical_json({"b": 1, "a": [1, 2]}) == b'{"a":[1,2],"b":1}'
    assert codec.canonical_json("x") == b'"x"'
    # Non-ASCII must be escaped, and the value must end without a newline.
    assert codec.canonical_json({"k": "表"}) == b'{"k":"\\u8868"}'
    assert not codec.canonical_json({"k": "v"}).endswith(b"\n")


def test_canonical_json_array_order_is_preserved():
    # Meaningful array order is never sorted by the encoder.
    assert codec.canonical_json([3, 1, 2]) == b"[3,1,2]"


@pytest.mark.parametrize("value", [1.5, float("nan"), float("inf"), {"a": 2.0}, [1, 0.5]])
def test_canonical_json_rejects_floats_everywhere(value):
    with pytest.raises(ContractError, match="float"):
        codec.canonical_json(value)


def test_canonical_json_rejects_non_string_object_keys_and_unknown_types():
    with pytest.raises(ContractError, match="keys"):
        codec.canonical_json({1: "x"})
    with pytest.raises(ContractError, match="keys"):
        codec.canonical_json({b"x": 1})
    with pytest.raises(ContractError, match="forbids value of type"):
        codec.canonical_json(object())


def test_canonical_json_rejects_input_deeper_than_32_levels():
    ok = json.loads("[" * 32 + "]" * 32)
    codec.canonical_json(ok)  # exactly 32 is allowed
    too_deep = json.loads("[" * 33 + "]" * 33)
    with pytest.raises(ContractError, match="depth"):
        codec.canonical_json(too_deep)


# --------------------------------------------------------------------------
# Exact value roundtrips
# --------------------------------------------------------------------------


def test_null_value_roundtrip():
    assert NullValue().to_obj() == {"kind": "null"}
    assert codec.decode_exact_value({"kind": "null"}) == NullValue()


def test_integer_value_above_float53_roundtrip():
    # 9007199254740993 = 2**53 + 1: unpickable as a float, exact here.
    value = IntegerValue(9007199254740993)
    assert value.to_obj() == {"kind": "integer", "value": "9007199254740993"}
    parsed = codec.parse_strict_json(b'{"kind":"integer","value":"9007199254740993"}')
    assert codec.decode_exact_value(parsed) == value


@pytest.mark.parametrize(
    "number",
    [-(2**63), -(2**62), 2**62 - 1, 2**63 - 1],
)
def test_signed_extreme_integers_roundtrip(number):
    value = IntegerValue(number)
    encoded = codec.canonical_json(value.to_obj())
    decoded = codec.decode_exact_value(codec.parse_strict_json(encoded))
    assert decoded == value
    assert isinstance(decoded.value, int) and not isinstance(decoded.value, bool)


def test_decimal_value_coefficient_and_scale_roundtrip():
    value = DecimalValue(-12345, 2)
    assert value.to_obj() == {"kind": "decimal", "coefficient": "-12345", "scale": 2}
    encoded = codec.canonical_json(value.to_obj())
    assert codec.decode_exact_value(codec.parse_strict_json(encoded)) == value


def test_decimal_value_scale_zero_and_zero_coefficient_roundtrip():
    for coefficient, scale in ((0, 0), (5, 0), (-7, 6)):
        value = DecimalValue(coefficient, scale)
        encoded = codec.canonical_json(value.to_obj())
        assert codec.decode_exact_value(codec.parse_strict_json(encoded)) == value


def test_full_payload_roundtrip_preserves_large_and_null_values():
    payload = _build_payload()
    restored = codec.load_payload(codec.dump_payload(payload))
    assert restored == payload
    assert restored.rows.rows[0].value == IntegerValue(-(2**63) + 1)
    assert restored.rows.rows[3].value == IntegerValue(9007199254740993)


# --------------------------------------------------------------------------
# Strict rejections: floats, bools, non-canonical text, kinds, encodings
# --------------------------------------------------------------------------


def test_loader_rejects_json_float_literal():
    with pytest.raises(ContractError, match="float"):
        codec.parse_strict_json(b'{"kind":"integer","value":1.5}')


def test_loader_rejects_nan_and_infinity_tokens():
    with pytest.raises(ContractError, match="non-finite"):
        codec.parse_strict_json(b'{"v":NaN}')
    with pytest.raises(ContractError, match="non-finite"):
        codec.parse_strict_json(b'{"v":Infinity}')


def test_loader_rejects_bool_in_integer_position():
    document = b'{"kind":"decimal","coefficient":"1","scale":true}'
    with pytest.raises(ContractError, match="must be a JSON integer"):
        codec.decode_exact_value(codec.parse_strict_json(document))


def test_model_constructors_reject_bool_and_float_where_int_required():
    with pytest.raises(ContractError, match="must be an int"):
        IntegerValue(True)
    with pytest.raises(ContractError, match="must be an int"):
        DecimalValue(True, 0)
    with pytest.raises(ContractError, match="must be an int"):
        DecimalValue(1, 2.0)
    with pytest.raises(ContractError, match="must be an int"):
        Row(True, IntegerValue(1))


def test_loader_rejects_minus_zero_integer_text():
    with pytest.raises(ContractError, match="canonical"):
        codec.decode_exact_value(codec.parse_strict_json(b'{"kind":"integer","value":"-0"}'))


def test_loader_rejects_json_integer_minus_zero():
    with pytest.raises(ContractError, match="canonical"):
        codec.parse_strict_json(b"-0")


def test_loader_rejects_leading_zero_and_plus_sign_integer_literals():
    # Raw JSON grammar already rejects these forms; the loader must surface
    # them as contract errors, not crash with a non-contract exception.
    for raw in (b"01", b"+1", b"1.", b".5", b"1e3"):
        with pytest.raises(ContractError):
            codec.parse_strict_json(raw)


def test_model_rejects_leading_zero_coefficient_text():
    with pytest.raises(ContractError, match="canonical"):
        codec.decode_exact_value({"kind": "decimal", "coefficient": "007", "scale": 2})


def test_model_rejects_integer_and_decimal_text_over_80_chars():
    with pytest.raises(ContractError, match="canonical"):
        IntegerValue(10**80)  # 81 digits
    IntegerValue(10**79 - 1)  # 80 digits is the exact limit
    with pytest.raises(ContractError, match="canonical"):
        codec.decode_exact_value({"kind": "integer", "value": "-" + "9" * 80})


def test_loader_rejects_unknown_and_wrong_kinds():
    with pytest.raises(ContractError, match="unknown kind"):
        codec.decode_exact_value({"kind": "string", "value": "x"})
    with pytest.raises(ContractError, match="missing required field"):
        codec.decode_exact_value({"kind": "integer"})
    with pytest.raises(ContractError, match="unknown kind"):
        codec.decode_type_spec({"kind": "varchar", "name": "TINYTEXT"})


def test_loader_rejects_invalid_utf8_bytes():
    with pytest.raises(ContractError, match="UTF-8"):
        codec.parse_strict_json(b'{"a": "\xff\xfe"}')


def test_loader_rejects_duplicate_object_keys():
    with pytest.raises(ContractError, match="duplicate"):
        codec.parse_strict_json(b'{"a":1,"a":2}')
    with pytest.raises(ContractError, match="duplicate"):
        codec.load_payload(FIXTURES.joinpath("invalid_duplicate_key.json").read_bytes())


def test_loader_rejects_unknown_fields_at_every_level():
    with pytest.raises(ContractError, match="unknown fields"):
        codec.load_payload(FIXTURES.joinpath("invalid_unknown_field.json").read_bytes())
    with pytest.raises(ContractError, match="unknown fields"):
        codec.decode_exact_value({"kind": "null", "extra": 1})


def test_loader_rejects_depth_over_32():
    with pytest.raises(ContractError, match="depth"):
        codec.parse_strict_json(("[" * 33 + "]" * 33).encode())


def test_loader_rejects_malformed_json_and_non_text_input():
    with pytest.raises(ContractError, match="invalid JSON"):
        codec.parse_strict_json(b'{"a": }')
    with pytest.raises(ContractError, match="expects bytes or str"):
        codec.parse_strict_json(123)  # type: ignore[arg-type]


def test_loader_rejects_unsorted_rows_semantically():
    with pytest.raises(ContractError, match="strictly increasing"):
        codec.load_payload(FIXTURES.joinpath("invalid_unsorted_rows.json").read_bytes())


# --------------------------------------------------------------------------
# Golden fixture and payload identity helpers
# --------------------------------------------------------------------------


def _build_payload() -> CasePayload:
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
                Row(1, IntegerValue(-(2**63) + 1)),
                Row(2, IntegerValue(0)),
                Row(3, NullValue()),
                Row(4, IntegerValue(9007199254740993)),
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


def test_valid_fixture_loads_with_frozen_schema_version():
    payload = codec.load_payload(
        FIXTURES.joinpath("payload_signed_widen_q1.json").read_text(encoding="utf-8")
    )
    assert payload.case_schema_version == CASE_SCHEMA_VERSION
    assert payload.rows.rows[2].value == NullValue()
    assert payload.query.projections[0].expr == ColumnRef(ColumnName.V)


def test_case_seed_and_substream_block_match_independent_vectors():
    # Vectors recomputed with plain hashlib only:
    #   sha256(b'["typecheck-g1",42,0]')
    #   sha256(b'["typecheck-g1-block","<seed>",0,"rows",0]')
    #   sha256(b'["typecheck-g1-block","<seed>",3,"arithmetic",7]')
    seed_hex = "c09a293d95f6f1fa0a1178ddf72259d898bb65b9f23a413800e55dda481c290d"
    block_rows = bytes.fromhex(
        "cdfe409cc23bf3f1e87f8fc570e5ce3e5aed44161dee6504f30d47437cb4f6bb"
    )
    block_arith = bytes.fromhex(
        "d2b58d72d04b87044451acd5947acbde93121becb434332293aaa03917f47f19"
    )
    assert codec.case_seed(42, 0) == seed_hex
    assert codec.substream_block(seed_hex, 0, "rows", 0) == block_rows
    assert codec.substream_block(seed_hex, 3, "arithmetic", 7) == block_arith
    assert codec.take_from_list(block_rows, 4) == 3
    assert codec.take_in_range(block_arith, -16, 16) == 1


def test_substream_helpers_reject_bad_domains_and_bounds():
    seed_hex = codec.case_seed(1, 0)
    with pytest.raises(ContractError, match="domain"):
        codec.substream_block(seed_hex, 0, "booleans", 0)
    with pytest.raises(ContractError, match="uint64"):
        codec.case_seed(2**64, 0)
    with pytest.raises(ContractError, match="hi >= lo"):
        codec.take_in_range(b"\x00" * 32, 5, 4)
    with pytest.raises(ContractError, match="positive"):
        codec.take_from_list(b"\x00" * 32, 0)
