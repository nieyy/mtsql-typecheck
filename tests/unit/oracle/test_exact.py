"""O01 tests for oracle.exact (contract 4; design 6.4.2 manual examples).

Every expectation below is a hand-written multiset table, literal key tuple
or literal canonical-JSON byte string taken from the frozen manual examples
(design 6.4.2 and oracle-d2-contract section 4).  No expectation is computed
by calling the code under test and feeding its output back as an
expectation.
"""

from __future__ import annotations

import pytest

from mtsql_typecheck.contracts.case import ContractError
from mtsql_typecheck.contracts.execution import ResultValue, ResultValueKind
from mtsql_typecheck.contracts.oracle import WITNESS_LIMIT, WitnessEntry
from mtsql_typecheck.oracle.exact import (
    compare_multisets,
    key_persistent,
    row_key,
    row_key_bytes,
    value_key,
)


def null() -> ResultValue:
    return ResultValue(ResultValueKind.NULL)


def i(value: int) -> ResultValue:
    return ResultValue(ResultValueKind.INTEGER, int_value=value)


def dec(coefficient: int, scale: int) -> ResultValue:
    return ResultValue(ResultValueKind.DECIMAL, coefficient=coefficient, scale=scale)


def raw_value(kind: object, **fields: object) -> ResultValue:
    """A ResultValue bypassing __post_init__, to exercise exact.py's own
    input validation independently of the model constructor."""
    value = ResultValue.__new__(ResultValue)
    object.__setattr__(value, "kind", kind)
    for name, field_value in fields.items():
        object.__setattr__(value, name, field_value)
    return value


# --------------------------------------------------------------------------
# value_key: the frozen design 6.4.2 numeric identity facts
# --------------------------------------------------------------------------


def test_value_key_null_is_its_own_key_and_never_zero() -> None:
    assert value_key(null()) == ("null",)
    assert value_key(null()) != value_key(i(0))
    assert value_key(null()) != value_key(dec(0, 2))


def test_value_key_integer_literal_form() -> None:
    assert value_key(i(1)) == ("number", "1", 0)
    assert value_key(i(0)) == ("number", "0", 0)
    assert value_key(i(-7)) == ("number", "-7", 0)


def test_value_key_2_53_neighbourhood_stays_exact() -> None:
    above = value_key(i(9007199254740993))
    below = value_key(i(9007199254740992))
    assert above == ("number", "9007199254740993", 0)
    assert below == ("number", "9007199254740992", 0)
    assert above != below


def test_value_key_integer_and_declared_decimal_share_one_key() -> None:
    # integer 1 == decimal 1.00 once the declaration allows the equivalence:
    # trailing decimal zeros are stripped from the coefficient.
    assert value_key(i(1)) == value_key(dec(100, 2))
    assert value_key(i(1)) == ("number", "1", 0)


def test_value_key_decimal_trailing_zero_stripping() -> None:
    assert value_key(dec(100, 2)) == ("number", "1", 0)
    assert value_key(dec(1200, 2)) == ("number", "12", 0)
    assert value_key(dec(-150, 1)) == ("number", "-15", 0)
    assert value_key(dec(-1500, 3)) == ("number", "-15", 1)  # -1.500 -> -1.5
    # a non-zero fractional residue keeps its scale
    assert value_key(dec(1, 2)) == ("number", "1", 2)
    assert value_key(dec(105, 2)) == ("number", "105", 2)
    assert value_key(dec(-1, 0)) == ("number", "-1", 0)


def test_value_key_decimal_zero_is_normalized() -> None:
    assert value_key(dec(0, 0)) == ("number", "0", 0)
    assert value_key(dec(0, 5)) == ("number", "0", 0)
    assert value_key(dec(0, 65)) == ("number", "0", 0)
    assert value_key(dec(0, 5)) != value_key(null())


def test_value_key_rejects_non_result_value_inputs() -> None:
    for bad in (None, "1", 1, ("number", "1", 0)):
        with pytest.raises(ContractError):
            value_key(bad)


def test_value_key_rejects_illegal_scale() -> None:
    for scale in (-1, 66, 1000):
        with pytest.raises(ContractError):
            value_key(
                raw_value(ResultValueKind.DECIMAL, coefficient=1, scale=scale)
            )
    with pytest.raises(ContractError):
        value_key(raw_value(ResultValueKind.DECIMAL, coefficient=1, scale=True))


def test_value_key_rejects_oversized_coefficient() -> None:
    # 81 decimal digits: one over the 80-char canonical scalar budget
    with pytest.raises(ContractError):
        value_key(
            raw_value(ResultValueKind.DECIMAL, coefficient=10**80, scale=0)
        )
    with pytest.raises(ContractError):
        value_key(raw_value(ResultValueKind.INTEGER, int_value=10**80))


def test_value_key_rejects_unknown_kind() -> None:
    with pytest.raises(ContractError):
        value_key(raw_value("rational"))
    with pytest.raises(ContractError):
        value_key(raw_value(None))


# --------------------------------------------------------------------------
# key_persistent / row_key / row_key_bytes
# --------------------------------------------------------------------------


def test_key_persistent_literal_forms() -> None:
    assert key_persistent(("null",)) == ["null"]
    assert key_persistent(("number", "1", 0)) == ["number", "1", 0]
    assert key_persistent(("number", "-15", 0)) == ["number", "-15", 0]
    assert key_persistent(("number", "1", 2)) == ["number", "1", 2]


def test_key_persistent_rejects_malformed_keys() -> None:
    for bad in (
        (),
        ("null", "extra"),
        ("number", "1",),
        ("number", "01", 0),
        ("number", "1", 66),
        ("number", "1", -1),
        ("number", 1, 0),
        ("rational",),
        "number",
    ):
        with pytest.raises(ContractError):
            key_persistent(bad)


def test_row_key_follows_column_order_and_cannot_cancel() -> None:
    assert row_key((i(1), null())) == (("number", "1", 0), ("null",))
    assert row_key((null(), i(1))) == (("null",), ("number", "1", 0))
    # a different column arrangement is a different key, never cancellable
    assert row_key((i(1), null())) != row_key((null(), i(1)))


def test_row_key_distinguishes_sign_and_duplicates() -> None:
    assert row_key((i(-2),)) != row_key((i(2),))
    assert row_key((i(0),)) != row_key((null(),))
    assert row_key((dec(200, 2),)) == row_key((i(2),))


def test_row_key_input_validation() -> None:
    with pytest.raises(ContractError):
        row_key([i(1)])  # list of values is not a row tuple
    with pytest.raises(ContractError):
        row_key((i(1), "x"))  # non-ResultValue column
    with pytest.raises(ContractError):
        row_key(i(1))  # a bare value is not a row
    assert row_key(()) == ()  # empty row is structurally a valid (empty) key


def test_row_key_bytes_are_literal_canonical_json() -> None:
    assert row_key_bytes((("number", "1", 0),)) == b'[["number","1",0]]'
    assert row_key_bytes((("null",),)) == b'[["null"]]'
    assert (
        row_key_bytes((("number", "1", 0), ("null",)))
        == b'[["number","1",0],["null"]]'
    )
    assert row_key_bytes(()) == b"[]"


def test_row_key_bytes_rejects_non_row_key_input() -> None:
    with pytest.raises(ContractError):
        row_key_bytes([["number", "1", 0]])  # list, not a row_key tuple
    with pytest.raises(ContractError):
        row_key_bytes((("number", "01", 0),))  # non-canonical coefficient text


# --------------------------------------------------------------------------
# compare_multisets: design 6.4.2 manual example table
# --------------------------------------------------------------------------


def test_same_multiset_in_different_order_is_a_match() -> None:
    a = ((i(1),), (i(2),), (i(2),), (null(),))
    b = ((null(),), (i(2),), (i(1),), (i(2),))
    counts, witness, truncated = compare_multisets(a, b, WITNESS_LIMIT)
    assert (counts.a_rows, counts.b_rows) == (4, 4)
    assert (counts.a_distinct, counts.b_distinct) == (3, 3)
    assert counts.matched_rows == 4
    assert witness == ()
    assert truncated is False


def test_one_missing_duplicate_gives_diff_of_one() -> None:
    a = ((i(2),), (i(2),), (i(2),))
    b = ((i(2),), (i(2),))
    counts, witness, truncated = compare_multisets(a, b, WITNESS_LIMIT)
    assert (counts.a_rows, counts.b_rows) == (3, 2)
    assert (counts.a_distinct, counts.b_distinct) == (1, 1)
    assert counts.matched_rows == 2
    assert truncated is False
    assert len(witness) == 1
    entry = witness[0]
    assert isinstance(entry, WitnessEntry)
    # the witness key is the full row key: a 1-tuple for single-column rows
    assert entry.key == (("number", "2", 0),)
    assert (entry.a_count, entry.b_count, entry.diff) == (3, 2, 1)


def test_extra_duplicate_on_b_side_gives_negative_diff() -> None:
    a = ((i(2),), (i(2),))
    b = ((i(2),), (i(2),), (i(2),))
    counts, witness, truncated = compare_multisets(a, b, WITNESS_LIMIT)
    assert (counts.a_rows, counts.b_rows) == (2, 3)
    assert counts.matched_rows == 2
    assert len(witness) == 1
    assert (witness[0].a_count, witness[0].b_count, witness[0].diff) == (2, 3, -1)


def test_null_and_zero_never_cancel() -> None:
    counts, witness, truncated = compare_multisets(
        ((null(),),), ((i(0),),), WITNESS_LIMIT
    )
    assert counts.matched_rows == 0
    assert truncated is False
    # byte order: '["null"]' < '["number","0",0]' ('l' < 'm' at offset 3)
    assert [(entry.key, entry.a_count, entry.b_count, entry.diff) for entry in witness] == [
        ((("null",),), 1, 0, 1),
        ((("number", "0", 0),), 0, 1, -1),
    ]


def test_empty_vs_empty_is_a_match_with_zero_rows() -> None:
    counts, witness, truncated = compare_multisets((), (), WITNESS_LIMIT)
    assert (counts.a_rows, counts.b_rows) == (0, 0)
    assert (counts.a_distinct, counts.b_distinct) == (0, 0)
    assert counts.matched_rows == 0
    assert witness == ()
    assert truncated is False


def test_negative_zero_and_duplicate_rows_stay_faithful() -> None:
    a = ((i(-2),), (i(0),), (i(0),), (i(-2),))
    b = ((i(-2),), (i(-2),), (i(0),), (i(0),))
    counts, witness, truncated = compare_multisets(a, b, WITNESS_LIMIT)
    assert (counts.a_rows, counts.b_rows) == (4, 4)
    assert (counts.a_distinct, counts.b_distinct) == (2, 2)
    assert counts.matched_rows == 4
    assert witness == ()
    # one missing 0 on A: only the zero key differs
    counts, witness, truncated = compare_multisets(
        ((i(-2),), (i(0),), (i(0),)), ((i(-2),), (i(0),)), WITNESS_LIMIT
    )
    assert counts.matched_rows == 2
    assert [(entry.key, entry.a_count, entry.b_count, entry.diff) for entry in witness] == [
        ((("number", "0", 0),), 2, 1, 1)
    ]


def test_integer_and_declared_decimal_values_share_keys_in_comparison() -> None:
    # A returned integer 2, B returned decimal 2.00: with exact_numeric
    # value equivalence these are the same multiset key.
    counts, witness, truncated = compare_multisets(
        ((i(2),), (i(3),)), ((dec(200, 2),), (dec(300, 2),)), WITNESS_LIMIT
    )
    assert counts.matched_rows == 2
    assert witness == ()
    assert truncated is False


def test_column_permutation_cannot_produce_a_match() -> None:
    # Row keys differ by column order (see row_key tests); the witness
    # carries the full multi-column row key so the difference is reported
    # instead of silently dropped or faked into a match.
    counts, witness, truncated = compare_multisets(
        ((i(1), null()),), ((null(), i(1)),), WITNESS_LIMIT
    )
    assert counts.matched_rows == 0
    assert truncated is False
    # byte order: '["null"]' sorts before '["number",...]' within a column
    assert [entry.key for entry in witness] == [
        (("null",), ("number", "1", 0)),
        (("number", "1", 0), ("null",)),
    ]
    # without any difference the same multi-column shapes compare normally
    counts, witness, truncated = compare_multisets(
        ((i(1), null()), (null(), i(1))),
        ((null(), i(1)), (i(1), null())),
        WITNESS_LIMIT,
    )
    assert counts.matched_rows == 2
    assert witness == ()


# --------------------------------------------------------------------------
# Witness ordering, truncation and limits
# --------------------------------------------------------------------------

# Hand-written canonical row-key byte strings for A-side integers 1..25.
_INT_KEYS_1_25 = [b'[["number","%d",0]]' % n for n in range(1, 26)]
_SORTED_INT_KEY_BYTES = sorted(_INT_KEYS_1_25)


def test_witness_is_sorted_by_canonical_key_bytes() -> None:
    a = tuple((i(n),) for n in (2, 10, 1))
    counts, witness, truncated = compare_multisets(a, (), WITNESS_LIMIT)
    assert truncated is False
    # hand-written canonical literals; byte order puts "10" before "2"
    expected_bytes = sorted(
        [b'[["number","1",0]]', b'[["number","2",0]]', b'[["number","10",0]]']
    )
    assert expected_bytes == [
        b'[["number","1",0]]',
        b'[["number","10",0]]',
        b'[["number","2",0]]',
    ]
    assert [entry.key for entry in witness] == [
        (("number", "1", 0),),
        (("number", "10", 0),),
        (("number", "2", 0),),
    ]
    assert all(entry.a_count == 1 and entry.b_count == 0 and entry.diff == 1 for entry in witness)


def test_witness_truncation_over_twenty_differing_keys() -> None:
    a = tuple((i(n),) for n in range(1, 26))
    counts, witness, truncated = compare_multisets(a, (), WITNESS_LIMIT)
    assert (counts.a_rows, counts.b_rows) == (25, 0)
    assert (counts.a_distinct, counts.b_distinct) == (25, 0)
    assert counts.matched_rows == 0
    assert truncated is True
    assert len(witness) == WITNESS_LIMIT == 20
    # hand-decoded persistent tuple form of the first 20 canonical byte
    # literals sorted ascending (string order: "1","10",...,"19","2","20",...)
    hand_keys = [
        (("number", text, 0),)
        for text in (
            "1", "10", "11", "12", "13", "14", "15", "16", "17", "18",
            "19", "2", "20", "21", "22", "23", "24", "25", "3", "4",
        )
    ]
    # cross-check the hand order against the hand-written byte literals
    assert sorted(_INT_KEYS_1_25)[:20] == [
        b'[["number","%s",0]]' % key[0][1].encode("ascii") for key in hand_keys
    ]
    assert [entry.key for entry in witness] == hand_keys
    assert all(entry.diff == 1 for entry in witness)


def test_witness_limit_is_honoured_and_smaller_caps_apply() -> None:
    a = tuple((i(n),) for n in range(1, 6))
    counts, witness, truncated = compare_multisets(a, (), 3)
    assert truncated is True
    assert len(witness) == 3
    assert [entry.key for entry in witness] == [
        (("number", "1", 0),),
        (("number", "2", 0),),
        (("number", "3", 0),),
    ]
    # exactly at the limit: nothing truncated
    counts, witness, truncated = compare_multisets(a, (), 5)
    assert truncated is False
    assert len(witness) == 5


def test_witness_limit_validation() -> None:
    a = ((i(1),),)
    for bad in (0, -1, 21, True, "3", None, 2.0):
        with pytest.raises(ContractError):
            compare_multisets(a, (), bad)


# --------------------------------------------------------------------------
# Input validation of the row containers
# --------------------------------------------------------------------------


def test_rows_must_be_tuples_of_result_value_tuples() -> None:
    with pytest.raises(ContractError):
        compare_multisets([ (i(1),) ], (), WITNESS_LIMIT)  # list container
    with pytest.raises(ContractError):
        compare_multisets((i(1),), (), WITNESS_LIMIT)  # flat values
    with pytest.raises(ContractError):
        compare_multisets(((i(1), [null()])), (), WITNESS_LIMIT)  # list column
    with pytest.raises(ContractError):
        compare_multisets(((i(1),),), (None,), WITNESS_LIMIT)  # non-tuple row
    with pytest.raises(ContractError):
        compare_multisets(((i(1), "x"),), (), WITNESS_LIMIT)  # bad column


def test_zero_differences_with_equal_row_counts_match_exactly() -> None:
    cases = [
        (((i(5),),), ((dec(500, 2),),)),
        (((null(),), (i(1),)), ((i(1),), (null(),))),
    ]
    for a, b in cases:
        counts, witness, truncated = compare_multisets(a, b, WITNESS_LIMIT)
        assert witness == ()
        assert truncated is False
        assert counts.a_rows == counts.b_rows == counts.matched_rows
