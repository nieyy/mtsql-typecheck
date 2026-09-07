"""Exact value decoding under the frozen mysql80-pymysql112-exact-v1 mapping
(design 6.4.3; negative P01).

Pure decoding: no connection, no float, no Decimal context.
"""

from __future__ import annotations

import pytest

from mtsql_typecheck.adapters import mysql_protocol as mp
from mtsql_typecheck.adapters.base import (
    RESULT_CONTRACT_VIOLATION,
    RESULT_ENCODING_UNSUPPORTED,
    FieldMetadata,
    ResultContractViolation,
    ResultEncodingError,
)
from mtsql_typecheck.contracts.execution import ResultValueKind

MAPPING = mp.MAPPING_VERSION


def meta(type_code: int, *, flags: int = 0, decimals: int = 0, ordinal: int = 0) -> FieldMetadata:
    return FieldMetadata(
        ordinal=ordinal,
        type_code=type_code,
        flags=flags,
        decimals=decimals,
        length=11,
        charset=63,
        alias="v",
        table_alias="t",
    )


# --------------------------------------------------------------------------
# Integer wire types -> INTEGER via strict canonical decimal text
# --------------------------------------------------------------------------


@pytest.mark.parametrize("type_code", [1, 2, 3, 8, 9])  # TINY/SHORT/LONG/LONGLONG/INT24
@pytest.mark.parametrize("text", [b"0", b"1", b"-1", b"127", b"-128", b"9223372036854775807"])
def test_integer_texts_decode_exactly(type_code, text):
    value = mp.decode_result_value(text, meta(type_code))
    assert value.kind is ResultValueKind.INTEGER
    assert value.int_value == int(text)
    assert value.to_obj() == {"kind": "integer", "value": text.decode()}


def test_unsigned_flag_value_stays_integer_and_flags_survive_mapping():
    value = mp.decode_result_value(b"18446744073709551615", meta(8, flags=32))
    assert value.kind is ResultValueKind.INTEGER
    assert value.int_value == 2**64 - 1
    column = mp.map_column(meta(8, flags=32), 0)
    assert column.flags == 32  # unsigned flag preserved, never auto-widened


@pytest.mark.parametrize("type_code", [1, 2, 3, 8, 9])
@pytest.mark.parametrize("text", [b"-0", b"+1", b"01", b"007", b"", b" 1", b"1 ", b"1.0", b"abc"])
def test_non_canonical_integer_text_is_rejected(type_code, text):
    with pytest.raises(ResultEncodingError) as excinfo:
        mp.decode_result_value(text, meta(type_code))
    assert excinfo.value.code == RESULT_ENCODING_UNSUPPORTED
    assert excinfo.value.type_code == type_code
    assert excinfo.value.mapping_version == MAPPING


def test_integer_text_over_scalar_budget_is_rejected():
    text = b"-" + b"9" * 80
    assert len(text) > 80
    with pytest.raises(ResultEncodingError):
        mp.decode_result_value(text, meta(8))


def test_integer_metadata_with_decimals_fails_closed():
    with pytest.raises(ResultContractViolation) as excinfo:
        mp.decode_result_value(b"5", meta(3, decimals=1))
    assert excinfo.value.code == RESULT_CONTRACT_VIOLATION


# --------------------------------------------------------------------------
# DECIMAL / NEWDECIMAL -> (coefficient, scale) with pure integer arithmetic
# --------------------------------------------------------------------------


@pytest.mark.parametrize("type_code", [0, 246])
@pytest.mark.parametrize(
    ("text", "coefficient", "scale"),
    [
        (b"0", 0, 0),
        (b"123", 123, 0),
        (b"-123", -123, 0),
        (b"1.23", 123, 2),
        (b"-1.23", -123, 2),
        (b"0.50", 50, 2),
        (b"-0.50", -50, 2),
        (b"1.2300", 12300, 4),  # trailing zeros preserved exactly as sent
        (b"0.00", 0, 2),
    ],
)
def test_decimal_texts_decode_losslessly(type_code, text, coefficient, scale):
    meta_decimals = len(text.rsplit(b".", 1)[1]) if b"." in text else 0
    value = mp.decode_result_value(text, meta(type_code, decimals=meta_decimals))
    assert value.kind is ResultValueKind.DECIMAL
    assert value.coefficient == coefficient
    assert value.scale == scale
    # Reconstructing the text from (coefficient, scale) must reproduce the
    # server-sent bytes exactly (negative zero is rejected, never folded).
    sign = "-" if value.coefficient < 0 else ""
    digits = str(abs(value.coefficient))
    if value.scale:
        digits = digits.rjust(value.scale + 1, "0")
        rendered = f"{sign}{digits[:-value.scale]}.{digits[-value.scale:]}"
    else:
        rendered = f"{sign}{digits}"
    assert rendered == text.decode()


@pytest.mark.parametrize("type_code", [0, 246])
@pytest.mark.parametrize(
    "text",
    [b"", b"+1.5", b"1.", b".5", b"1.2.3", b"01.5", b"abc", b" 1.5", b"1e3", b"-0", b"-0.000"],
)
def test_non_canonical_decimal_text_is_rejected(type_code, text):
    with pytest.raises(ResultEncodingError):
        mp.decode_result_value(text, meta(type_code, decimals=2))


def test_decimal_huge_coefficient_within_scalar_budget():
    # 79 digits total: representable exactly, never via float.
    int_digits = "9" * 70
    text = f"{int_digits}.123456789".encode()
    assert len(text) <= 80
    value = mp.decode_result_value(text, meta(246, decimals=9))
    assert value.coefficient == int(int_digits + "123456789")
    assert value.scale == 9


def test_decimal_over_scalar_budget_is_rejected():
    text = (b"9" * 80) + b".5"
    with pytest.raises(ResultEncodingError):
        mp.decode_result_value(text, meta(246, decimals=1))


def test_decimal_scale_over_contract_maximum_is_rejected():
    text = b"0." + b"1" * 66  # scale 66 > 65, still within 80 chars
    with pytest.raises(ResultEncodingError) as excinfo:
        mp.decode_result_value(text, meta(246, decimals=66))
    assert excinfo.value.code == RESULT_ENCODING_UNSUPPORTED


@pytest.mark.parametrize(
    ("text", "meta_decimals", "server_scale"),
    [(b"1.234", 2, 3), (b"1.23", 5, 2)],
)
def test_decimal_metadata_disagreement_flags_contract_violation(text, meta_decimals, server_scale):
    with pytest.raises(ResultContractViolation) as excinfo:
        mp.decode_result_value(text, meta(246, decimals=meta_decimals))
    assert excinfo.value.code == RESULT_CONTRACT_VIOLATION
    assert f"scale {server_scale}" in str(excinfo.value)
    assert f"decimals={meta_decimals}" in str(excinfo.value)


# --------------------------------------------------------------------------
# NULL independence
# --------------------------------------------------------------------------


@pytest.mark.parametrize("type_code", [1, 3, 8, 9, 0, 246, 6])
def test_null_decodes_to_null_kind_never_zero_or_empty(type_code):
    value = mp.decode_result_value(None, meta(type_code))
    assert value.kind is ResultValueKind.NULL
    assert value.int_value is None
    assert value.coefficient is None
    assert value.scale is None
    assert value.to_obj() == {"kind": "null"}


# --------------------------------------------------------------------------
# Unsupported wire types are never guessed from the value text (P01)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("type_code", "label"),
    [
        (4, "FLOAT"),
        (5, "DOUBLE"),
        (245, "JSON"),
        (250, "TINY_BLOB"),
        (252, "BLOB"),
        (253, "VAR_STRING"),
        (254, "STRING"),
        (10, "DATE"),
        (12, "DATETIME"),
        (16, "BIT"),
        (99, "unknown"),
    ],
)
def test_unsupported_wire_types_raise_encoding_error_even_if_text_looks_numeric(
    type_code, label
):
    with pytest.raises(ResultEncodingError) as excinfo:
        mp.decode_result_value(b"3", meta(type_code))
    assert excinfo.value.code == RESULT_ENCODING_UNSUPPORTED
    assert excinfo.value.type_code == type_code
    assert excinfo.value.column_ordinal == 0
    assert excinfo.value.mapping_version == MAPPING


def test_non_bytes_value_fails_closed():
    with pytest.raises(ResultContractViolation):
        mp.decode_result_value("3", meta(3))


# --------------------------------------------------------------------------
# Column mapping: family stays unassigned, precision stays None
# --------------------------------------------------------------------------


def test_map_column_stamps_mapping_version_and_raw_metadata():
    column = mp.map_column(meta(246, flags=1, decimals=2), 0)
    assert column.mapping_version == MAPPING
    assert column.type_code == 246
    assert column.flags == 1
    assert column.scale == 2
    assert column.precision is None  # display length is not a precision
    assert column.alias == "v"


def test_map_column_precision_none_for_integer_types():
    column = mp.map_column(meta(8, decimals=0), 0)
    assert column.precision is None
    assert column.scale is None
    assert column.type_code == 8


def test_map_column_decimal_scale_comes_from_metadata():
    column = mp.map_column(meta(246, decimals=4, ordinal=3), 3)
    assert column.scale == 4
    assert column.ordinal == 3


def test_map_column_rejects_ordinal_mismatch():
    with pytest.raises(ResultContractViolation):
        mp.map_column(meta(246, decimals=2, ordinal=1), 0)
