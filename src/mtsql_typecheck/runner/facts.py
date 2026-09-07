"""Runtime fact collection for the D3 execution port (design 6.2.1/6.3.1, Phase 4).

Pure, driver-free helpers used by ``runner.execution`` to turn adapter probe
results into contract models.  Everything here operates on data the caller
already fetched from an adapter (identity fact mappings, raw byte cells,
information-schema rows); importing this module performs no I/O and imports
neither PyMySQL nor the concrete adapter modules.

Contents:

- :func:`observed_environment_from_facts`: assembles an
  :class:`ObservedEnvironment` from an adapter's identity facts, with exactly
  the same field mapping as ``runner.preflight.run_preflight`` (single source
  of truth for the *mapping*; this module re-derives it so the execution port
  can snapshot the environment at probe time without a ``TargetConfig``).
  ``build_id`` is the caller-supplied configured declaration -- a build id is
  never fabricated from unrelated version strings (provenance stays
  CONFIGURED; the 8.0 identity variables carry no commit id).

  Probe-source choice: preflight reads a fact *mapping* via
  ``fetch_environment_facts()``; the execution port reuses that same mapping
  (never a fresh ad-hoc read) so the recorded snapshot is exactly the facts
  the preflight-style probe produced.  Consumers that need the richer
  manifest (probe records, runtime identities) call ``run_preflight``
  directly; the port needs only the content hash, which is computed here
  with D1's frozen helpers.

- :func:`rejected_requirement_id`: maps a drifted observed snapshot to the
  frozen preflight requirement id (``oracle.gates`` vocabulary) whose
  violation the snapshot itself proves, or ``None`` when the hash drift is
  not covered by a violated frozen condition.

- :func:`decode_readback_rows`: exact canonical decode of the fixed
  ``SELECT rid, v ... ORDER BY rid`` readback cells (raw UTF-8 text, never
  float) into D1 :class:`ExactValue` items under the declared side type.

- :func:`normalize_side_schema`: normalizes information-schema probe rows
  into a D1 :class:`TableSpec` for the gate-3 ``actual_schema`` comparison
  (structural, never SHOW CREATE TABLE text).

- :func:`attempt_fact_summary`: the inline trace START/attempt record values,
  with the environment/name-map content hashes **reused from D1's
  ``generation.validation`` helpers** (never re-implemented here).
"""

from __future__ import annotations

import re
from typing import Mapping, Optional, Sequence

from ..contracts.case import (
    CasePayload,
    CheckStatus,
    ColumnSpec,
    ContractError,
    DecimalType,
    DecimalValue,
    ExactValue,
    IndexVariant,
    IntegerValue,
    NameMap,
    NullValue,
    ObservedEnvironment,
    Row,
    Rows,
    SignedIntName,
    SignedIntegerType,
    TableSpec,
    TypeSpec,
)
from ..contracts.codec import sha256_hex
from ..generation.validation import (
    evaluate_observed_environment,
    environment_content_hash,
    name_map_content_hash,
)
from .preflight import _canonical_uuid

__all__ = [
    "FACTS_IDENTITY",
    "FactCollectionError",
    "observed_environment_from_facts",
    "rejected_requirement_id",
    "decode_readback_rows",
    "normalize_side_schema",
    "attempt_fact_summary",
]

#: Semantic identity of this facts collector (snapshot mapping + decoders).
FACTS_IDENTITY = "runner-execution-facts-v1"


class FactCollectionError(ContractError):
    """A raw probe result cannot be normalized into a contract model.

    Fail closed: a cell that is not canonical text, a column set that does
    not match the declared schema, or an information-schema answer that is
    structurally impossible for the declared table is an error, never a
    coerced fact."""


# --------------------------------------------------------------------------
# ObservedEnvironment assembly (same mapping as runner.preflight)
# --------------------------------------------------------------------------


def observed_environment_from_facts(
    facts: Mapping[str, str], *, build_id: str
) -> ObservedEnvironment:
    """Build the observed environment snapshot from adapter identity facts.

    The mapping mirrors ``runner.preflight.run_preflight`` field for field;
    ``build_id`` is the configured declaration passed through (CONFIGURED
    provenance), never a server-measured value.  Missing optional facts become
    empty strings exactly as in preflight; facts the snapshot cannot represent
    (unusable ``server_uuid``, ``sql_mode`` without tokens) raise.
    """

    if not isinstance(facts, Mapping):
        raise FactCollectionError("observed_environment_from_facts needs a facts Mapping")
    for key, value in facts.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise FactCollectionError(
                f"environment fact {key!r} is not a (str, str) pair (fail closed)"
            )
    server_uuid_raw = facts.get("server_uuid")
    server_uuid = _canonical_uuid(server_uuid_raw) if server_uuid_raw else None
    if server_uuid is None:
        raise FactCollectionError(
            f"observed server_uuid {server_uuid_raw!r} is not a usable UUID "
            "(the environment snapshot cannot be produced; fail closed)"
        )
    sql_mode_raw = facts.get("sql_mode") or ""
    sql_mode_tokens = tuple(
        sorted({token.strip() for token in sql_mode_raw.split(",") if token.strip()})
    )
    if not sql_mode_tokens:
        raise FactCollectionError(
            f"observed sql_mode {sql_mode_raw!r} yields no mode tokens "
            "(the environment snapshot cannot be produced; fail closed)"
        )
    return ObservedEnvironment(
        instance_identity=server_uuid,
        version=facts.get("version", ""),
        # Raw observed version_comment; never rewritten into a vendor guess.
        vendor=facts.get("version_comment", ""),
        # The caller's configured declaration; never presented as
        # server-measured (the 8.0 identity probes carry no build id).
        build_id=build_id,
        engine="innodb" if facts.get("innodb_version") else "",
        sql_mode_tokens=sql_mode_tokens,
        character_set=facts.get("character_set_connection", ""),
        collation=facts.get("collation_connection", ""),
        time_zone=facts.get("time_zone", ""),
        optimizer_switch=facts.get("optimizer_switch", ""),
    )


# Frozen preflight requirement ids (oracle.gates._REJECTION_PROOF_CONDITIONS
# keys) keyed by the D1 runtime condition id whose VIOLATED status proves the
# rejection from the snapshot itself.  "environment.same-instance" is
# deliberately absent: a single session snapshot cannot prove it.
_CONDITION_TO_REQUIREMENT_ID = {
    "version_series": "environment.version_series",
    "engine": "environment.innodb",
    "vendor_build": "environment.vendor_build",
    "session_snapshot": "environment.session_snapshot",
    "optimizer_switch": "environment.optimizer_switch",
}


def rejected_requirement_id(
    payload: CasePayload, observed: ObservedEnvironment
) -> Optional[str]:
    """First frozen requirement id a drifted snapshot itself disproves.

    Returns ``None`` when the observed snapshot violates no frozen condition
    (pure content drift such as an ``optimizer_switch`` text change is
    recorded as drift by the caller, but no structured NOT_APPLICABLE
    rejection can be proven from the snapshot alone).
    """

    if not isinstance(payload, CasePayload):
        raise FactCollectionError("rejected_requirement_id needs a CasePayload")
    if not isinstance(observed, ObservedEnvironment):
        raise FactCollectionError("rejected_requirement_id needs an ObservedEnvironment")
    for condition in evaluate_observed_environment(payload, observed):
        if condition.status is CheckStatus.VIOLATED:
            requirement = _CONDITION_TO_REQUIREMENT_ID.get(condition.condition_id)
            if requirement is not None:
                return requirement
    return None


# --------------------------------------------------------------------------
# Readback decode (fixed `SELECT rid, v ... ORDER BY rid` probe; design 6.4.2)
# --------------------------------------------------------------------------

# Same canonical integer text grammar as D1 (case._CANONICAL_INT_TEXT_RE):
# "0", or "-?[1-9][0-9]*"; rejects "-0", leading zeros and "+".
_INT_TEXT_RE = re.compile(r"^(0|-?[1-9][0-9]{0,79})$")

# Fixed-point decimal text as the server sends it for DECIMAL wire types:
# optional sign, digits, optional fraction; no exponent, no "+", no "".
_DECIMAL_TEXT_RE = re.compile(r"^(-?)([0-9]+)(?:\.([0-9]+))?$")


def _decode_cell(cell: object, what: str) -> Optional[str]:
    if cell is None:
        return None
    if isinstance(cell, (bytes, bytearray)):
        try:
            return bytes(cell).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FactCollectionError(
                f"{what} is not valid UTF-8 (fail closed)"
            ) from exc
    if isinstance(cell, str):
        return cell
    raise FactCollectionError(
        f"{what} arrived as {type(cell).__name__}, expected raw text (fail closed)"
    )


def _decode_value(text: str, declared: TypeSpec, what: str) -> ExactValue:
    if isinstance(declared, SignedIntegerType):
        if _INT_TEXT_RE.match(text) is None:
            raise FactCollectionError(
                f"{what} {text!r} is not canonical signed-integer text (fail closed)"
            )
        return IntegerValue(int(text))
    if isinstance(declared, DecimalType):
        match = _DECIMAL_TEXT_RE.match(text)
        if match is None:
            raise FactCollectionError(
                f"{what} {text!r} is not fixed-point decimal text (fail closed)"
            )
        sign, int_part, frac_part = match.group(1), match.group(2), match.group(3)
        scale = len(frac_part) if frac_part else 0
        coefficient = int(int_part + (frac_part or ""))
        if sign == "-":
            coefficient = -coefficient
        return DecimalValue(coefficient, scale)
    raise FactCollectionError(
        f"declared type {type(declared).__name__} has no readback decoder (fail closed)"
    )


def decode_readback_rows(
    raw_rows: Sequence[Sequence[object]], *, declared_type: TypeSpec
) -> tuple[Row, ...]:
    """Decode readback cells ``(rid, v)`` into exact D1 rows.

    NULL stays NULL (never 0 or ""); integers require canonical decimal text;
    decimals are decoded as (coefficient, scale) with the server-sent scale.
    The returned tuple is ordered as fetched (the probe is ``ORDER BY rid``);
    the :class:`Rows` constructor enforces strictly increasing rids and any
    disorder surfaces as a :class:`ContractError` at Rows construction.
    """

    if not isinstance(declared_type, (SignedIntegerType, DecimalType)):
        raise FactCollectionError("decode_readback_rows needs a declared TypeSpec")
    rows: list[Row] = []
    for index, raw in enumerate(raw_rows):
        if len(raw) != 2:
            raise FactCollectionError(
                f"readback row {index} has {len(raw)} cells, expected exactly 2 (fail closed)"
            )
        rid_text = _decode_cell(raw[0], f"readback row {index} rid")
        if rid_text is None or _INT_TEXT_RE.match(rid_text) is None:
            raise FactCollectionError(
                f"readback row {index} rid {rid_text!r} is not canonical integer text "
                "(fail closed)"
            )
        v_text = _decode_cell(raw[1], f"readback row {index} v")
        if v_text is None:
            value: ExactValue = NullValue()
        else:
            value = _decode_value(v_text, declared_type, f"readback row {index} v")
        rows.append(Row(int(rid_text), value))
    return tuple(rows)


# --------------------------------------------------------------------------
# Side schema normalization (gate-3 actual_schema; structural comparison)
# --------------------------------------------------------------------------


def _column_type_text(declared: TypeSpec) -> str:
    """Normalized COLUMN_TYPE text for one declared side type."""
    if isinstance(declared, SignedIntegerType):
        return str(declared.name.value).lower()
    return f"decimal({declared.precision},{declared.scale})"


def _as_text_rows(raw_rows: Sequence[Sequence[object]], what: str) -> list[tuple[str, ...]]:
    rows: list[tuple[str, ...]] = []
    for index, raw in enumerate(raw_rows):
        texts = tuple(
            _decode_cell(cell, f"{what} row {index} column {position}")
            for position, cell in enumerate(raw)
        )
        if any(text is None for text in texts):
            raise FactCollectionError(f"{what} row {index} has a NULL cell (fail closed)")
        rows.append(tuple(text or "" for text in texts))
    return rows


def normalize_side_schema(
    *,
    tables_rows: Sequence[Sequence[object]],
    columns_rows: Sequence[Sequence[object]],
    statistics_rows: Sequence[Sequence[object]],
    declared_table: str,
    declared_type: TypeSpec,
    index_variant: IndexVariant,
) -> TableSpec:
    """Normalize information-schema probe rows into the declared TableSpec.

    Probe row shapes (facts-owned SQL in ``runner.execution``):

    - tables: ``(TABLE_NAME, TABLE_TYPE, ENGINE)`` -- exactly one row, the
      declared table, BASE TABLE, InnoDB.
    - columns: ``(COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY,
      ORDINAL_POSITION)`` -- exactly ``rid`` (bigint, NO, PRI) then ``v``
      (declared type, YES, no key), in ordinal order.
    - statistics: ``(INDEX_NAME, NON_UNIQUE, COLUMN_NAME)`` -- empty for
      ``IndexVariant.NONE``; exactly one secondary index ``ix_v`` on ``v``
      (NON_UNIQUE=1) for ``IndexVariant.IX_V``.

    Anything else is a schema mismatch and raises (fail closed); the caller
    records the probe answer, this function never invents a fact.
    """

    tables = _as_text_rows(tables_rows, "schema tables probe")
    if len(tables) != 1:
        raise FactCollectionError(
            f"schema tables probe returned {len(tables)} tables, expected exactly "
            f"{declared_table!r} (fail closed)"
        )
    table_name, table_type, engine = tables[0]
    if table_name != declared_table:
        raise FactCollectionError(
            f"schema tables probe found table {table_name!r}, expected "
            f"{declared_table!r} (fail closed)"
        )
    if table_type.lower() != "base table":
        raise FactCollectionError(
            f"table {declared_table!r} TABLE_TYPE {table_type!r} is not BASE TABLE "
            "(fail closed)"
        )
    if engine.lower() != "innodb":
        raise FactCollectionError(
            f"table {declared_table!r} ENGINE {engine!r} is not InnoDB (fail closed)"
        )

    columns = _as_text_rows(columns_rows, "schema columns probe")
    expected = (
        ("rid", "bigint", "NO", "PRI"),
        ("v", _column_type_text(declared_type), "YES", ""),
    )
    if len(columns) != len(expected):
        raise FactCollectionError(
            f"schema columns probe returned {len(columns)} columns for "
            f"{declared_table!r}, expected {len(expected)} (fail closed)"
        )
    for position, (actual, want) in enumerate(zip(columns, expected)):
        name, column_type, is_nullable, column_key = actual[0], actual[1], actual[2], actual[3]
        if (name, column_type, is_nullable, column_key) != want:
            raise FactCollectionError(
                f"column {position} of {declared_table!r} is "
                f"({name!r}, {column_type!r}, {is_nullable!r}, {column_key!r}), expected "
                f"{want} (fail closed)"
            )

    statistics = _as_text_rows(statistics_rows, "schema statistics probe")
    if index_variant is IndexVariant.NONE:
        if statistics:
            raise FactCollectionError(
                f"table {declared_table!r} declares no secondary index but the probe "
                f"returned {len(statistics)} index rows (fail closed)"
            )
    else:
        if len(statistics) != 1 or statistics[0] != ("ix_v", "1", "v"):
            raise FactCollectionError(
                f"table {declared_table!r} must carry exactly one secondary index "
                f"ix_v on v, probe returned {statistics!r} (fail closed)"
            )

    rid_column = ColumnSpec(
        "rid", SignedIntegerType(SignedIntName.BIGINT), False
    )
    return TableSpec(
        "t0",
        (rid_column, ColumnSpec("v", declared_type, True)),
        ("rid",),
        index_variant,
    )


# --------------------------------------------------------------------------
# Trace record values
# --------------------------------------------------------------------------


def attempt_fact_summary(
    *,
    binding,
    name_map: NameMap,
    observed_environment: Optional[ObservedEnvironment],
) -> dict[str, str]:
    """Inline trace START/attempt record values (short strings only).

    The environment and name-map content hashes are recomputed with D1's
    frozen helpers (``generation.validation``), never copied from the binding
    or re-implemented here.  ``observed_environment_hash`` is empty when no
    snapshot was collected (the absence is visible, not papered over).
    """

    from ..contracts.case import ExpectedBinding

    if not isinstance(binding, ExpectedBinding):
        raise FactCollectionError("attempt_fact_summary needs an ExpectedBinding")
    if not isinstance(name_map, NameMap):
        raise FactCollectionError("attempt_fact_summary needs a NameMap")
    return {
        "run_id": binding.run_id,
        "case_id": binding.case_id,
        "attempt_id": binding.attempt_id,
        "environment_hash": binding.environment_hash,
        "observed_environment_hash": (
            environment_content_hash(observed_environment)
            if observed_environment is not None
            else ""
        ),
        "name_map_hash": name_map_content_hash(name_map),
    }


# sha256_hex is re-exported for callers that hash payload side-table files the
# same way the trace sink does (content-addressed files).
content_hash_of_bytes = sha256_hex
