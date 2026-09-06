"""Exact multiset keys and comparison for the D2 oracle.

Implements oracle-d2-contract section 4 (``oracle/exact.py``) and the frozen
manual multiset examples of design 6.4.2 (design
``2026-09-05-mtsql-typecheck-result-oracle-counterexample-reduction-design-zh.md``):

- numeric identity is exact integer arithmetic only (no ``Decimal``, no
  ``float``): ``9007199254740993`` and ``9007199254740992`` always get
  different keys, integer ``1`` and decimal ``(coefficient=100, scale=2)``
  share one key after trailing decimal zeros are stripped, and ``NULL`` is
  never equal to ``0``;
- a row key is the per-column tuple of value keys in declared column order,
  so a different column arrangement can never cancel out;
- comparison is a full multiset comparison (one ``Counter`` per side over
  canonical row-key bytes); MATCH requires full equality, and witness
  truncation happens only after the underlying comparison completed.

Importing this module performs no I/O.  All arithmetic is integer-only.
"""

from __future__ import annotations

import re
from collections import Counter

from ..contracts.case import ContractError
from ..contracts.codec import canonical_json
from ..contracts.execution import ResultValue, ResultValueKind
from ..contracts.oracle import (
    MAX_RESULT_SCALE,
    MAX_SCALAR_TEXT_CHARS,
    WITNESS_LIMIT,
    ComparisonCounts,
    WitnessEntry,
)

__all__ = [
    "value_key",
    "key_persistent",
    "row_key",
    "row_key_bytes",
    "compare_multisets",
]

_NULL_KEY = ("null",)
_NUMBER_KEY_LEN = 3
_CANONICAL_DECIMAL_TEXT_RE = re.compile(r"^(0|-?[1-9][0-9]{0,79})$")


def _fail(msg: str) -> None:
    raise ContractError(msg)


# --------------------------------------------------------------------------
# Value keys (contract 4; design 6.4.2)
# --------------------------------------------------------------------------


def _check_coefficient_text(value: int, name: str) -> str:
    """Canonical decimal text of an exact scalar, at most 80 characters."""
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{name} must be an int, got {type(value).__name__}")
    text = str(value)
    if not _CANONICAL_DECIMAL_TEXT_RE.match(text) or len(text) > MAX_SCALAR_TEXT_CHARS:
        _fail(
            f"{name} is not canonical decimal text within "
            f"{MAX_SCALAR_TEXT_CHARS} chars: {text!r}"
        )
    return text


def _check_scale(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{name} must be an int, got {type(value).__name__}")
    if not 0 <= value <= MAX_RESULT_SCALE:
        _fail(f"{name} must be in [0, {MAX_RESULT_SCALE}], got {value}")
    return value


def value_key(value: ResultValue) -> tuple:
    """Canonical numeric identity of one observed result scalar.

    NULL -> ``("null",)``; integer -> ``("number", str(int_value), 0)``;
    decimal -> ``("number", coeff_text, scale)`` with trailing decimal zeros
    stripped while ``scale > 0`` and zero normalized to ``("number", "0", 0)``.
    Raises ``ContractError`` for any input that is not a well-formed
    ``ResultValue`` (independently of the model's own ``__post_init__``).
    """
    if not isinstance(value, ResultValue):
        _fail(f"value_key expects a ResultValue, got {type(value).__name__}")
    kind = value.kind
    if kind is ResultValueKind.NULL:
        return _NULL_KEY
    if kind is ResultValueKind.INTEGER:
        text = _check_coefficient_text(value.int_value, "ResultValue.int_value")
        return ("number", text, 0)
    if kind is ResultValueKind.DECIMAL:
        text = _check_coefficient_text(value.coefficient, "ResultValue.coefficient")
        scale = _check_scale(value.scale, "ResultValue.scale")
        if value.coefficient == 0:
            return ("number", "0", 0)
        coefficient = value.coefficient
        while scale > 0 and coefficient % 10 == 0:
            coefficient //= 10
            scale -= 1
        return ("number", str(coefficient), scale)
    _fail(f"ResultValue has unknown kind {kind!r}")


def _check_value_key(key: object, name: str) -> tuple:
    """Validate one value key: ``("null",)`` or ``("number", text, scale)``."""
    if not isinstance(key, tuple) or not key:
        _fail(f"{name} must be a non-empty tuple, got {key!r}")
    if key == _NULL_KEY:
        return key
    if (
        len(key) == _NUMBER_KEY_LEN
        and key[0] == "number"
        and isinstance(key[1], str)
    ):
        if not _CANONICAL_DECIMAL_TEXT_RE.match(key[1]) or len(key[1]) > MAX_SCALAR_TEXT_CHARS:
            _fail(f"{name}[1] is not canonical decimal text: {key[1]!r}")
        _check_scale(key[2], f"{name}[2]")
        return key
    _fail(f"{name} must be ('null',) or ('number', coeff_text, scale), got {key!r}")


def key_persistent(key: tuple) -> list:
    """JSON-encodable persistent form of one value key.

    ``("null",)`` -> ``["null"]``; ``("number", text, scale)`` ->
    ``["number", text, scale]``.  This is the only encoding that survives
    serialization; bare tuples with mixed element types are never sorted or
    compared directly.
    """
    _check_value_key(key, "key")
    if key == _NULL_KEY:
        return ["null"]
    return ["number", key[1], key[2]]


# --------------------------------------------------------------------------
# Row keys (contract 4)
# --------------------------------------------------------------------------


def row_key(row: tuple) -> tuple:
    """Per-column tuple of value keys in declared column order.

    Column order is part of the key: a different column arrangement produces
    a different key and can never cancel out.  ``row`` must be a tuple of
    ``ResultValue``; anything else raises ``ContractError``.
    """
    if not isinstance(row, tuple):
        _fail(f"row_key expects a tuple of ResultValue, got {type(row).__name__}")
    return tuple(value_key(value) for value in row)


def row_key_bytes(row_key_tuple: tuple) -> bytes:
    """Canonical JSON bytes of the persistent row-key encoding.

    This byte string is the multiset comparison key; ordering witnesses by
    these bytes is a total, deterministic order (no Python set/hash order).
    """
    if not isinstance(row_key_tuple, tuple):
        _fail(
            f"row_key_bytes expects a row_key tuple, got "
            f"{type(row_key_tuple).__name__}"
        )
    return canonical_json([key_persistent(key) for key in row_key_tuple])


# --------------------------------------------------------------------------
# Multiset comparison (contract 4; design 6.4.2)
# --------------------------------------------------------------------------


def _validated_rows(rows: object, name: str) -> tuple:
    if not isinstance(rows, tuple):
        _fail(f"{name} must be a tuple of rows, got {type(rows).__name__}")
    for row in rows:
        if not isinstance(row, tuple):
            _fail(f"{name} rows must be tuples of ResultValue, got {type(row).__name__}")
        for value in row:
            if not isinstance(value, ResultValue):
                _fail(
                    f"{name} rows must hold ResultValue items, got "
                    f"{type(value).__name__}"
                )
    return rows


def _check_witness_limit(witness_limit: object) -> int:
    if isinstance(witness_limit, bool) or not isinstance(witness_limit, int):
        _fail(f"witness_limit must be an int, got {type(witness_limit).__name__}")
    if not 1 <= witness_limit <= WITNESS_LIMIT:
        _fail(f"witness_limit must be in [1, {WITNESS_LIMIT}], got {witness_limit}")
    return witness_limit


def compare_multisets(
    a_rows: tuple, b_rows: tuple, witness_limit: int = WITNESS_LIMIT
) -> tuple[ComparisonCounts, tuple[WitnessEntry, ...], bool]:
    """Full exact multiset comparison of two result row multisets.

    Returns ``(counts, witness, truncated)``.  ``matched_rows`` is the
    multiset intersection size ``sum(min(a_count, b_count))`` over all keys,
    so a MATCH is exactly ``a_rows == b_rows == matched_rows`` with no
    differing keys.  The comparison is always completed in full before the
    witness is truncated to the first ``witness_limit`` differing keys in
    ascending canonical row-key byte order; ``truncated`` reports whether
    further differing keys existed beyond that cap.
    """
    limit = _check_witness_limit(witness_limit)
    a_validated = _validated_rows(a_rows, "a_rows")
    b_validated = _validated_rows(b_rows, "b_rows")

    a_counter: Counter = Counter()
    b_counter: Counter = Counter()
    representative: dict = {}
    for side, rows, counter in (
        ("a", a_validated, a_counter),
        ("b", b_validated, b_counter),
    ):
        for row in rows:
            key = row_key(row)
            key_bytes = row_key_bytes(key)
            counter[key_bytes] += 1
            representative.setdefault(key_bytes, key)

    matched_rows = 0
    differing: list = []
    for key_bytes in set(a_counter) | set(b_counter):
        a_count = a_counter.get(key_bytes, 0)
        b_count = b_counter.get(key_bytes, 0)
        matched_rows += min(a_count, b_count)
        if a_count != b_count:
            differing.append((key_bytes, a_count, b_count))
    # Byte order is a total order over canonical JSON bytes; the comparison
    # above is complete before this truncation.
    differing.sort(key=lambda item: item[0])

    truncated = len(differing) > limit
    # WitnessEntry.key is the full row key (design 6.2.2): the ordered tuple
    # of per-column value keys, 1-tuple for single-column results.
    witness = tuple(
        WitnessEntry(
            key=representative[key_bytes],
            a_count=a_count,
            b_count=b_count,
            diff=a_count - b_count,
        )
        for key_bytes, a_count, b_count in differing[:limit]
    )
    counts = ComparisonCounts(
        a_rows=len(a_validated),
        b_rows=len(b_validated),
        a_distinct=len(a_counter),
        b_distinct=len(b_counter),
        matched_rows=matched_rows,
    )
    return counts, witness, truncated
