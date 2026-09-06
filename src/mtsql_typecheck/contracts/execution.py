"""D2 execution evidence contracts (design 6.2.1/6.2.2; docs/oracle-d2-contract.md 1-2).

Frozen models for AttemptRequest, AttemptExpectation and ExecutionEvidence plus
every nested evidence record.  House rules follow D1
(``contracts/case.py``, ``contracts/codec.py``): frozen dataclasses, closed
enums, tuples in memory, full ``__post_init__`` validation on both the
construction and the loader path, unknown fields rejected, ``bool`` never
accepted where an int is required, no floats in documents, optional fields
only for genuinely absent facts.  Content hashes always exclude the record's
own hash field.  Importing this module performs no I/O and production code
must never import a driver or network library here.
"""

from __future__ import annotations

import enum
import math
import re
import time
from dataclasses import dataclass
from typing import Callable, Optional, Protocol, Tuple, Union

from .case import (
    CasePayload,
    ContractError,
    ExpectedBinding,
    NameMap,
    ObservedEnvironment,
    RuntimeFacts,
    StatementPhase,
    TypeFamily,
    _check_bool,
    _check_enum,
    _check_hex64,
    _check_int,
    _check_str,
)
from .codec import (
    _as_bool,
    _as_enum,
    _as_int,
    _as_list,
    _as_opt,
    _as_str,
    _expect_dict,
    _field,
    _no_extra,
    canonical_json,
    case_id_of,
    decode_case_payload,
    decode_expected_binding,
    decode_name_map,
    decode_observed_environment,
    decode_runtime_facts,
    parse_strict_json,
    sha256_hex,
)

__all__ = [
    "EXECUTION_SCHEMA_VERSION",
    "MAX_RESULT_ROWS",
    "MAX_RESULT_BYTES",
    "MAX_RESULT_COLUMNS",
    "MAX_EVIDENCE_BYTES",
    "ATTEMPT_BUDGET_MS",
    "CANCEL_GRACE_MS",
    "MAX_SCALAR_TEXT_CHARS",
    "MAX_RESULT_SCALE",
    "ExecutionOrder",
    "Side",
    "QueryStatus",
    "ResultTerminal",
    "AttemptStage",
    "TerminationState",
    "CleanupState",
    "DiagnosticLevel",
    "TransactionIsolation",
    "ResultValueKind",
    "SelectPhase",
    "ResultValue",
    "ResultColumn",
    "ResultSet",
    "SessionProfile",
    "DiagnosticEntry",
    "StatementDiagnostics",
    "SideContext",
    "IsolationReceipt",
    "TerminalReceipt",
    "AttemptFailure",
    "PreflightRejection",
    "AttemptRequest",
    "AttemptExpectation",
    "QueryEvidence",
    "ExecutionEvidence",
    "Control",
    "ControlCancelled",
    "default_control",
    "ExecutionPortError",
    "ExecutionPort",
    "decode_result_value",
    "decode_result_set",
    "decode_session_profile",
    "decode_statement_diagnostics",
    "decode_attempt_request",
    "decode_attempt_expectation",
    "decode_query_evidence",
    "decode_execution_evidence",
    "load_attempt_request",
    "load_attempt_expectation",
    "load_execution_evidence",
    "dump_attempt_request",
    "dump_attempt_expectation",
    "dump_execution_evidence",
]

# --------------------------------------------------------------------------
# Frozen versions and budgets (docs/oracle-d2-contract.md section 1)
# --------------------------------------------------------------------------

EXECUTION_SCHEMA_VERSION = 1  # AttemptRequest/AttemptExpectation/ExecutionEvidence

MAX_RESULT_ROWS = 4096  # per side
MAX_RESULT_BYTES = 8 * 1024 * 1024  # per side, canonical UTF-8 ResultSet incl. metadata
MAX_RESULT_COLUMNS = 5
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024  # single ExecutionEvidence envelope
ATTEMPT_BUDGET_MS = 30_000
CANCEL_GRACE_MS = 5000
MAX_SCALAR_TEXT_CHARS = 80  # reuse case.MAX_NUMERIC_TEXT_CHARS
MAX_RESULT_SCALE = 65

_UNBOUNDED_REMAINING_MS = 2**63 - 1

# Same canonical integer text grammar as D1 (case._CANONICAL_INT_TEXT_RE):
# "0", or "-?[1-9][0-9]*"; rejects "-0", leading zeros and "+".
_CANONICAL_INT_TEXT_RE = re.compile(r"^(0|-?[1-9][0-9]{0,79})$")


def _fail(msg: str) -> None:
    raise ContractError(msg)


def _opt_int(value: object, what: str) -> Optional[int]:
    return None if value is None else _as_int(value, what)


def _opt_str(value: object, what: str) -> Optional[str]:
    return None if value is None else _as_str(value, what)


def _check_nonempty_str(value: object, name: str, max_chars: Optional[int] = None) -> str:
    value = _check_str(value, name)
    if not value:
        _fail(f"{name} must be non-empty")
    if max_chars is not None and len(value) > max_chars:
        _fail(f"{name} must be at most {max_chars} chars, got {len(value)}")
    return value


# --------------------------------------------------------------------------
# Enumerations (contract 2.1)
# --------------------------------------------------------------------------


class ExecutionOrder(enum.StrEnum):
    AB = "AB"
    BA = "BA"


class Side(enum.StrEnum):
    A = "A"
    B = "B"


class QueryStatus(enum.StrEnum):
    COMPLETE = "COMPLETE"
    SQL_ERROR = "SQL_ERROR"
    TIMEOUT = "TIMEOUT"
    CONNECTION_LOST = "CONNECTION_LOST"
    CANCELLED = "CANCELLED"


class ResultTerminal(enum.StrEnum):
    CONFIRMED = "CONFIRMED"
    UNKNOWN = "UNKNOWN"


class AttemptStage(enum.StrEnum):
    PREPARE = "PREPARE"
    SETUP = "SETUP"
    QUERY = "QUERY"
    FETCH = "FETCH"
    CANCEL = "CANCEL"
    CLEANUP = "CLEANUP"


class TerminationState(enum.StrEnum):
    NOT_STARTED = "NOT_STARTED"
    CONFIRMED = "CONFIRMED"
    UNKNOWN = "UNKNOWN"


class CleanupState(enum.StrEnum):
    DONE = "DONE"
    PENDING = "PENDING"
    FAILED = "FAILED"


class DiagnosticLevel(enum.StrEnum):
    WARNING = "WARNING"
    NOTE = "NOTE"
    ERROR = "ERROR"


class TransactionIsolation(enum.StrEnum):
    READ_UNCOMMITTED = "READ-UNCOMMITTED"
    READ_COMMITTED = "READ-COMMITTED"
    REPEATABLE_READ = "REPEATABLE-READ"
    SERIALIZABLE = "SERIALIZABLE"


class ResultValueKind(enum.StrEnum):
    NULL = "null"
    INTEGER = "integer"
    DECIMAL = "decimal"


class SelectPhase(enum.StrEnum):
    """Local SELECT marker for QueryEvidence.diagnostics serialization.

    D1 StatementPhase stays ddl/insert only; the SELECT statement carries its
    own receipt (QueryEvidence), whose to_obj()/loader fix the phase string to
    ``"select"`` (contract 2.3/2.4).  This member is legal only as the phase
    of ``QueryEvidence.diagnostics``; setup diagnostics reject it.
    """

    SELECT = "select"


# --------------------------------------------------------------------------
# Result values and result sets (contract 2.2)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ResultValue:
    """One observed result scalar; independent model, not D1 ExactValue reuse.

    null -> only ``kind``; integer -> only ``int_value``; decimal -> only
    ``coefficient``/``scale`` (value = coefficient * 10**-scale, scale >= 0).
    Canonical decimal text rules as D1: at most MAX_SCALAR_TEXT_CHARS chars,
    no exponent, no non-canonical negative zero, no float/bool/string kinds.
    """

    kind: ResultValueKind
    int_value: Optional[int] = None
    coefficient: Optional[int] = None
    scale: Optional[int] = None

    def __post_init__(self) -> None:
        _check_enum(self.kind, ResultValueKind, "ResultValue.kind")
        if self.kind is ResultValueKind.NULL:
            for name in ("int_value", "coefficient", "scale"):
                if getattr(self, name) is not None:
                    _fail(f"ResultValue NULL must not carry {name}")
            return
        if self.kind is ResultValueKind.INTEGER:
            if self.coefficient is not None or self.scale is not None:
                _fail("ResultValue integer must not carry coefficient/scale")
            _check_int(self.int_value, "ResultValue.int_value")
            _check_scalar_text(str(self.int_value), "ResultValue.int_value")
            return
        # decimal
        if self.int_value is not None:
            _fail("ResultValue decimal must not carry int_value")
        _check_int(self.coefficient, "ResultValue.coefficient")
        _check_int(self.scale, "ResultValue.scale")
        _check_scalar_text(str(self.coefficient), "ResultValue.coefficient")
        if not 0 <= self.scale <= MAX_RESULT_SCALE:
            _fail(f"ResultValue.scale must be in [0, {MAX_RESULT_SCALE}], got {self.scale}")

    def to_obj(self) -> dict[str, object]:
        if self.kind is ResultValueKind.NULL:
            return {"kind": "null"}
        if self.kind is ResultValueKind.INTEGER:
            return {"kind": "integer", "value": str(self.int_value)}
        return {
            "kind": "decimal",
            "coefficient": str(self.coefficient),
            "scale": self.scale,
        }


def _check_scalar_text(text: str, name: str) -> None:
    if not _CANONICAL_INT_TEXT_RE.match(text) or len(text) > MAX_SCALAR_TEXT_CHARS:
        _fail(f"{name} is not canonical decimal text within {MAX_SCALAR_TEXT_CHARS} chars")


def decode_result_value(obj: object, what: str = "result value") -> ResultValue:
    obj = _expect_dict(obj, what)
    kind = obj.get("kind")
    if kind == "null":
        _no_extra(obj, {"kind"}, what)
        return ResultValue(ResultValueKind.NULL)
    if kind == "integer":
        _no_extra(obj, {"kind", "value"}, what)
        text = _as_str(_field(obj, "value", what), f"{what}.value")
        _check_scalar_text(text, f"{what}.value")
        return ResultValue(ResultValueKind.INTEGER, int_value=int(text))
    if kind == "decimal":
        _no_extra(obj, {"kind", "coefficient", "scale"}, what)
        coefficient_text = _as_str(_field(obj, "coefficient", what), f"{what}.coefficient")
        _check_scalar_text(coefficient_text, f"{what}.coefficient")
        scale = _as_int(_field(obj, "scale", what), f"{what}.scale")
        return ResultValue(ResultValueKind.DECIMAL, coefficient=int(coefficient_text), scale=scale)
    raise ContractError(f"{what} has unknown kind {kind!r}")


@dataclass(frozen=True)
class ResultColumn:
    """One result column; the family comes from the declared relation, never
    guessed from values (value-kind checks are oracle gates, not the model)."""

    ordinal: int
    alias: str
    family: TypeFamily
    type_code: int
    flags: int
    precision: Optional[int]
    scale: Optional[int]
    mapping_version: str

    def __post_init__(self) -> None:
        _check_int(self.ordinal, "ResultColumn.ordinal")
        if self.ordinal < 0:
            _fail(f"ResultColumn.ordinal must be >= 0, got {self.ordinal}")
        _check_nonempty_str(self.alias, "ResultColumn.alias", max_chars=128)
        _check_enum(self.family, TypeFamily, "ResultColumn.family")
        _check_int(self.type_code, "ResultColumn.type_code")
        if self.type_code < 0:
            _fail(f"ResultColumn.type_code must be >= 0, got {self.type_code}")
        _check_int(self.flags, "ResultColumn.flags")
        if self.flags < 0:
            _fail(f"ResultColumn.flags must be >= 0, got {self.flags}")
        for name in ("precision", "scale"):
            value = getattr(self, name)
            if value is not None:
                _check_int(value, f"ResultColumn.{name}")
                if value < 0:
                    _fail(f"ResultColumn.{name} must be >= 0, got {value}")
        _check_nonempty_str(self.mapping_version, "ResultColumn.mapping_version", max_chars=128)

    def to_obj(self) -> dict[str, object]:
        return {
            "ordinal": self.ordinal,
            "alias": self.alias,
            "family": str(self.family.value),
            "type_code": self.type_code,
            "flags": self.flags,
            "precision": self.precision,
            "scale": self.scale,
            "mapping_version": self.mapping_version,
        }


def decode_result_column(obj: object, what: str = "result column") -> ResultColumn:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "ordinal",
            "alias",
            "family",
            "type_code",
            "flags",
            "precision",
            "scale",
            "mapping_version",
        },
        what,
    )
    precision = _opt_int(obj.get("precision"), f"{what}.precision")
    scale = _opt_int(obj.get("scale"), f"{what}.scale")
    return ResultColumn(
        ordinal=_as_int(_field(obj, "ordinal", what), f"{what}.ordinal"),
        alias=_as_str(_field(obj, "alias", what), f"{what}.alias"),
        family=_as_enum(TypeFamily, _field(obj, "family", what), f"{what}.family"),
        type_code=_as_int(_field(obj, "type_code", what), f"{what}.type_code"),
        flags=_as_int(_field(obj, "flags", what), f"{what}.flags"),
        precision=precision,
        scale=scale,
        mapping_version=_as_str(
            _field(obj, "mapping_version", what), f"{what}.mapping_version"
        ),
    )


@dataclass(frozen=True)
class ResultSet:
    """One fetched result set; a missing result is ``result=None`` on
    QueryEvidence, never an empty-rows stand-in.

    ``payload_hash`` is a derived field: constructed with the default empty
    marker it is computed over ``result_obj()``; a supplied value that
    disagrees is rejected.
    """

    columns: tuple[ResultColumn, ...]
    rows: tuple[tuple[ResultValue, ...], ...]
    observed_row_count: int
    fetch_complete: bool
    truncated: bool
    extra_result_sets: int
    payload_hash: str = ""
    encoding_version: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.columns, tuple) or not 1 <= len(self.columns) <= MAX_RESULT_COLUMNS:
            _fail(f"ResultSet.columns must hold 1..{MAX_RESULT_COLUMNS} columns")
        for ordinal, column in enumerate(self.columns):
            if not isinstance(column, ResultColumn):
                _fail("ResultSet.columns must hold ResultColumn items")
            if column.ordinal != ordinal:
                _fail("ResultSet.columns ordinals must be 0-based and consecutive")
        if not isinstance(self.rows, tuple) or len(self.rows) > MAX_RESULT_ROWS:
            _fail(f"ResultSet.rows must be a tuple of at most {MAX_RESULT_ROWS} rows")
        width = len(self.columns)
        for row in self.rows:
            if not isinstance(row, tuple) or len(row) != width:
                _fail("every ResultSet row must hold exactly len(columns) values")
            for value in row:
                if not isinstance(value, ResultValue):
                    _fail("ResultSet rows must hold ResultValue items")
        _check_int(self.observed_row_count, "ResultSet.observed_row_count")
        if self.observed_row_count != len(self.rows):
            _fail(
                f"ResultSet.observed_row_count {self.observed_row_count} != len(rows) "
                f"{len(self.rows)}"
            )
        _check_bool(self.fetch_complete, "ResultSet.fetch_complete")
        _check_bool(self.truncated, "ResultSet.truncated")
        if self.fetch_complete and self.truncated:
            _fail("ResultSet fetch_complete and truncated are contradictory")
        _check_int(self.extra_result_sets, "ResultSet.extra_result_sets")
        if self.extra_result_sets < 0:
            _fail(f"ResultSet.extra_result_sets must be >= 0, got {self.extra_result_sets}")
        _check_nonempty_str(self.encoding_version, "ResultSet.encoding_version", max_chars=128)
        derived = sha256_hex(canonical_json(self.result_obj()))
        if self.payload_hash == "":
            object.__setattr__(self, "payload_hash", derived)
        elif self.payload_hash != derived:
            _fail(
                f"ResultSet.payload_hash {self.payload_hash!r} does not match the "
                f"content hash {derived}"
            )
        _check_hex64(self.payload_hash, "ResultSet.payload_hash")
        if len(canonical_json(self.to_obj())) > MAX_RESULT_BYTES:
            _fail(f"ResultSet canonical form exceeds MAX_RESULT_BYTES ({MAX_RESULT_BYTES})")

    def result_obj(self) -> dict[str, object]:
        """Hashed payload: columns plus rows only (contract 2.2)."""
        return {
            "columns": [column.to_obj() for column in self.columns],
            "rows": [[value.to_obj() for value in row] for row in self.rows],
        }

    def to_obj(self) -> dict[str, object]:
        return {
            "columns": [column.to_obj() for column in self.columns],
            "rows": [[value.to_obj() for value in row] for row in self.rows],
            "observed_row_count": self.observed_row_count,
            "fetch_complete": self.fetch_complete,
            "truncated": self.truncated,
            "extra_result_sets": self.extra_result_sets,
            "payload_hash": self.payload_hash,
            "encoding_version": self.encoding_version,
        }


def decode_result_set(obj: object, what: str = "result set") -> ResultSet:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "columns",
            "rows",
            "observed_row_count",
            "fetch_complete",
            "truncated",
            "extra_result_sets",
            "payload_hash",
            "encoding_version",
        },
        what,
    )
    columns = tuple(
        decode_result_column(item, f"{what}.columns[{index}]")
        for index, item in enumerate(_as_list(_field(obj, "columns", what), f"{what}.columns"))
    )
    rows: list[tuple[ResultValue, ...]] = []
    raw_rows = _as_list(_field(obj, "rows", what), f"{what}.rows")
    for row_index, raw_row in enumerate(raw_rows):
        items = _as_list(raw_row, f"{what}.rows[{row_index}]")
        rows.append(
            tuple(
                decode_result_value(item, f"{what}.rows[{row_index}][{value_index}]")
                for value_index, item in enumerate(items)
            )
        )
    return ResultSet(
        columns=columns,
        rows=tuple(rows),
        observed_row_count=_as_int(
            _field(obj, "observed_row_count", what), f"{what}.observed_row_count"
        ),
        fetch_complete=_as_bool(_field(obj, "fetch_complete", what), f"{what}.fetch_complete"),
        truncated=_as_bool(_field(obj, "truncated", what), f"{what}.truncated"),
        extra_result_sets=_as_int(
            _field(obj, "extra_result_sets", what), f"{what}.extra_result_sets"
        ),
        payload_hash=_as_str(_field(obj, "payload_hash", what), f"{what}.payload_hash"),
        encoding_version=_as_str(
            _field(obj, "encoding_version", what), f"{what}.encoding_version"
        ),
    )


# --------------------------------------------------------------------------
# Session, context, receipts (contract 2.3)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionProfile:
    """Fixed session contract for the whole attempt (contract schema 1)."""

    autocommit: bool
    transaction_isolation: TransactionIsolation

    def __post_init__(self) -> None:
        _check_bool(self.autocommit, "SessionProfile.autocommit")
        _check_enum(
            self.transaction_isolation, TransactionIsolation, "SessionProfile.transaction_isolation"
        )

    def to_obj(self) -> dict[str, object]:
        return {
            "autocommit": self.autocommit,
            "transaction_isolation": str(self.transaction_isolation.value),
        }


def decode_session_profile(obj: object, what: str = "session profile") -> SessionProfile:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"autocommit", "transaction_isolation"}, what)
    return SessionProfile(
        autocommit=_as_bool(_field(obj, "autocommit", what), f"{what}.autocommit"),
        transaction_isolation=_as_enum(
            TransactionIsolation,
            _field(obj, "transaction_isolation", what),
            f"{what}.transaction_isolation",
        ),
    )


@dataclass(frozen=True)
class DiagnosticEntry:
    """One collected diagnostic; ``message_ref`` is a controlled reference,
    never a raw server text dump."""

    level: DiagnosticLevel
    code: str
    sqlstate: Optional[str]
    message_ref: Optional[str]

    def __post_init__(self) -> None:
        _check_enum(self.level, DiagnosticLevel, "DiagnosticEntry.level")
        _check_nonempty_str(self.code, "DiagnosticEntry.code", max_chars=128)
        if self.sqlstate is not None:
            _check_nonempty_str(self.sqlstate, "DiagnosticEntry.sqlstate", max_chars=16)
        if self.message_ref is not None:
            _check_nonempty_str(self.message_ref, "DiagnosticEntry.message_ref", max_chars=256)

    def to_obj(self) -> dict[str, object]:
        return {
            "level": str(self.level.value),
            "code": self.code,
            "sqlstate": self.sqlstate,
            "message_ref": self.message_ref,
        }


def decode_diagnostic_entry(obj: object, what: str = "diagnostic entry") -> DiagnosticEntry:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"level", "code", "sqlstate", "message_ref"}, what)
    return DiagnosticEntry(
        level=_as_enum(DiagnosticLevel, _field(obj, "level", what), f"{what}.level"),
        code=_as_str(_field(obj, "code", what), f"{what}.code"),
        sqlstate=_opt_str(obj.get("sqlstate"), f"{what}.sqlstate"),
        message_ref=_opt_str(obj.get("message_ref"), f"{what}.message_ref"),
    )


@dataclass(frozen=True)
class StatementDiagnostics:
    """Diagnostics for one DDL/INSERT statement (D1 phases) or the SELECT
    receipt carried by QueryEvidence (phase serialized as ``"select"``).

    Invariants: not collected => not complete; complete=True is only
    comparable when entries == ().
    """

    side: Side
    phase: Union[StatementPhase, SelectPhase]
    ordinal: int
    sql_hash: str
    collected: bool
    complete: bool
    entries: tuple[DiagnosticEntry, ...]

    def __post_init__(self) -> None:
        _check_enum(self.side, Side, "StatementDiagnostics.side")
        if not isinstance(self.phase, (StatementPhase, SelectPhase)):
            _fail(f"StatementDiagnostics.phase must be ddl/insert/select, got {self.phase!r}")
        _check_int(self.ordinal, "StatementDiagnostics.ordinal")
        if self.ordinal < 0:
            _fail(f"StatementDiagnostics.ordinal must be >= 0, got {self.ordinal}")
        _check_hex64(self.sql_hash, "StatementDiagnostics.sql_hash")
        _check_bool(self.collected, "StatementDiagnostics.collected")
        _check_bool(self.complete, "StatementDiagnostics.complete")
        if not isinstance(self.entries, tuple):
            _fail("StatementDiagnostics.entries must be a tuple")
        for entry in self.entries:
            if not isinstance(entry, DiagnosticEntry):
                _fail("StatementDiagnostics.entries must hold DiagnosticEntry items")
        if not self.collected:
            if self.complete:
                _fail("StatementDiagnostics not collected cannot be complete")
            if self.entries:
                _fail("StatementDiagnostics not collected must have empty entries")
        if self.complete and self.entries:
            _fail("StatementDiagnostics complete=True is only comparable with empty entries")

    def to_obj(self) -> dict[str, object]:
        return {
            "side": str(self.side.value),
            "phase": str(self.phase.value),
            "ordinal": self.ordinal,
            "sql_hash": self.sql_hash,
            "collected": self.collected,
            "complete": self.complete,
            "entries": [entry.to_obj() for entry in self.entries],
        }


def decode_statement_diagnostics(
    obj: object, what: str = "statement diagnostics", *, select: bool = False
) -> StatementDiagnostics:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {"side", "phase", "ordinal", "sql_hash", "collected", "complete", "entries"},
        what,
    )
    phase_value = _field(obj, "phase", what)
    if phase_value == SelectPhase.SELECT.value:
        if not select:
            _fail(f"{what}.phase must be ddl/insert for setup diagnostics")
        phase: Union[StatementPhase, SelectPhase] = SelectPhase.SELECT
    else:
        if select:
            _fail(f"{what}.phase must be \"select\" for query diagnostics")
        phase = _as_enum(StatementPhase, phase_value, f"{what}.phase")
    return StatementDiagnostics(
        side=_as_enum(Side, _field(obj, "side", what), f"{what}.side"),
        phase=phase,
        ordinal=_as_int(_field(obj, "ordinal", what), f"{what}.ordinal"),
        sql_hash=_as_str(_field(obj, "sql_hash", what), f"{what}.sql_hash"),
        collected=_as_bool(_field(obj, "collected", what), f"{what}.collected"),
        complete=_as_bool(_field(obj, "complete", what), f"{what}.complete"),
        entries=tuple(
            decode_diagnostic_entry(item, f"{what}.entries[{index}]")
            for index, item in enumerate(_as_list(_field(obj, "entries", what), f"{what}.entries"))
        ),
    )


@dataclass(frozen=True)
class SideContext:
    """Per-side session identity and environment snapshots.

    The three connection ids are one session identity and must be equal;
    ``current_database`` must be the side's NameMap database.  Environment
    snapshots hashing to the request's target hash is checked by the oracle
    gates, not the model.
    """

    side: Side
    setup_connection_id: str
    readback_connection_id: str
    select_connection_id: str
    current_database: str
    name_map: NameMap
    autocommit: bool
    transaction_isolation: TransactionIsolation
    environment_before: ObservedEnvironment
    environment_after: ObservedEnvironment

    def __post_init__(self) -> None:
        _check_enum(self.side, Side, "SideContext.side")
        for name in (
            "setup_connection_id",
            "readback_connection_id",
            "select_connection_id",
        ):
            _check_nonempty_str(getattr(self, name), f"SideContext.{name}")
        if len({self.setup_connection_id, self.readback_connection_id, self.select_connection_id}) != 1:
            _fail("SideContext session identity must be equal across setup/readback/select")
        _check_nonempty_str(self.current_database, "SideContext.current_database")
        if not isinstance(self.name_map, NameMap):
            _fail("SideContext.name_map must be a NameMap")
        expected = self.name_map.database_a if self.side is Side.A else self.name_map.database_b
        if self.current_database != expected:
            _fail(
                f"SideContext.current_database {self.current_database!r} must equal the "
                f"NameMap database for side {self.side.value} ({expected!r})"
            )
        _check_bool(self.autocommit, "SideContext.autocommit")
        _check_enum(
            self.transaction_isolation,
            TransactionIsolation,
            "SideContext.transaction_isolation",
        )
        for name in ("environment_before", "environment_after"):
            if not isinstance(getattr(self, name), ObservedEnvironment):
                _fail(f"SideContext.{name} must be an ObservedEnvironment")

    def to_obj(self) -> dict[str, object]:
        return {
            "side": str(self.side.value),
            "setup_connection_id": self.setup_connection_id,
            "readback_connection_id": self.readback_connection_id,
            "select_connection_id": self.select_connection_id,
            "current_database": self.current_database,
            "name_map": self.name_map.to_obj(),
            "autocommit": self.autocommit,
            "transaction_isolation": str(self.transaction_isolation.value),
            "environment_before": self.environment_before.to_obj(),
            "environment_after": self.environment_after.to_obj(),
        }


def decode_side_context(obj: object, what: str = "side context") -> SideContext:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "side",
            "setup_connection_id",
            "readback_connection_id",
            "select_connection_id",
            "current_database",
            "name_map",
            "autocommit",
            "transaction_isolation",
            "environment_before",
            "environment_after",
        },
        what,
    )
    return SideContext(
        side=_as_enum(Side, _field(obj, "side", what), f"{what}.side"),
        setup_connection_id=_as_str(
            _field(obj, "setup_connection_id", what), f"{what}.setup_connection_id"
        ),
        readback_connection_id=_as_str(
            _field(obj, "readback_connection_id", what), f"{what}.readback_connection_id"
        ),
        select_connection_id=_as_str(
            _field(obj, "select_connection_id", what), f"{what}.select_connection_id"
        ),
        current_database=_as_str(
            _field(obj, "current_database", what), f"{what}.current_database"
        ),
        name_map=decode_name_map(_field(obj, "name_map", what), f"{what}.name_map"),
        autocommit=_as_bool(_field(obj, "autocommit", what), f"{what}.autocommit"),
        transaction_isolation=_as_enum(
            TransactionIsolation,
            _field(obj, "transaction_isolation", what),
            f"{what}.transaction_isolation",
        ),
        environment_before=decode_observed_environment(
            _field(obj, "environment_before", what), f"{what}.environment_before"
        ),
        environment_after=decode_observed_environment(
            _field(obj, "environment_after", what), f"{what}.environment_after"
        ),
    )


@dataclass(frozen=True)
class IsolationReceipt:
    """Positive isolation evidence; false flags stay false and are rejected
    by the oracle gates, never silently flipped here."""

    attempt_id: str
    name_map_hash: str
    ownership_ref: str
    objects_created_confirmed: bool
    load_committed: bool
    no_concurrent_write_confirmed: bool
    method_version: str

    def __post_init__(self) -> None:
        _check_nonempty_str(self.attempt_id, "IsolationReceipt.attempt_id", max_chars=128)
        _check_hex64(self.name_map_hash, "IsolationReceipt.name_map_hash")
        _check_nonempty_str(self.ownership_ref, "IsolationReceipt.ownership_ref")
        for name in (
            "objects_created_confirmed",
            "load_committed",
            "no_concurrent_write_confirmed",
        ):
            _check_bool(getattr(self, name), f"IsolationReceipt.{name}")
        _check_nonempty_str(self.method_version, "IsolationReceipt.method_version", max_chars=128)

    def to_obj(self) -> dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "name_map_hash": self.name_map_hash,
            "ownership_ref": self.ownership_ref,
            "objects_created_confirmed": self.objects_created_confirmed,
            "load_committed": self.load_committed,
            "no_concurrent_write_confirmed": self.no_concurrent_write_confirmed,
            "method_version": self.method_version,
        }


def decode_isolation_receipt(obj: object, what: str = "isolation receipt") -> IsolationReceipt:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "attempt_id",
            "name_map_hash",
            "ownership_ref",
            "objects_created_confirmed",
            "load_committed",
            "no_concurrent_write_confirmed",
            "method_version",
        },
        what,
    )
    return IsolationReceipt(
        attempt_id=_as_str(_field(obj, "attempt_id", what), f"{what}.attempt_id"),
        name_map_hash=_as_str(_field(obj, "name_map_hash", what), f"{what}.name_map_hash"),
        ownership_ref=_as_str(_field(obj, "ownership_ref", what), f"{what}.ownership_ref"),
        objects_created_confirmed=_as_bool(
            _field(obj, "objects_created_confirmed", what), f"{what}.objects_created_confirmed"
        ),
        load_committed=_as_bool(_field(obj, "load_committed", what), f"{what}.load_committed"),
        no_concurrent_write_confirmed=_as_bool(
            _field(obj, "no_concurrent_write_confirmed", what),
            f"{what}.no_concurrent_write_confirmed",
        ),
        method_version=_as_str(_field(obj, "method_version", what), f"{what}.method_version"),
    )


@dataclass(frozen=True)
class TerminalReceipt:
    """Termination/cleanup proof; NOT_STARTED with any held object is illegal."""

    attempt_id: str
    termination: TerminationState
    cleanup: CleanupState
    owned_objects: tuple[str, ...]

    def __post_init__(self) -> None:
        _check_nonempty_str(self.attempt_id, "TerminalReceipt.attempt_id", max_chars=128)
        _check_enum(self.termination, TerminationState, "TerminalReceipt.termination")
        _check_enum(self.cleanup, CleanupState, "TerminalReceipt.cleanup")
        if not isinstance(self.owned_objects, tuple):
            _fail("TerminalReceipt.owned_objects must be a tuple")
        for item in self.owned_objects:
            _check_nonempty_str(item, "TerminalReceipt.owned_objects item")
        if self.termination is TerminationState.NOT_STARTED and self.owned_objects:
            _fail("TerminalReceipt NOT_STARTED is only legal with no owned objects")

    def to_obj(self) -> dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "termination": str(self.termination.value),
            "cleanup": str(self.cleanup.value),
            "owned_objects": list(self.owned_objects),
        }


def decode_terminal_receipt(obj: object, what: str = "terminal receipt") -> TerminalReceipt:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"attempt_id", "termination", "cleanup", "owned_objects"}, what)
    return TerminalReceipt(
        attempt_id=_as_str(_field(obj, "attempt_id", what), f"{what}.attempt_id"),
        termination=_as_enum(
            TerminationState, _field(obj, "termination", what), f"{what}.termination"
        ),
        cleanup=_as_enum(CleanupState, _field(obj, "cleanup", what), f"{what}.cleanup"),
        owned_objects=tuple(
            _as_str(item, f"{what}.owned_objects[{index}]")
            for index, item in enumerate(
                _as_list(_field(obj, "owned_objects", what), f"{what}.owned_objects")
            )
        ),
    )


@dataclass(frozen=True)
class AttemptFailure:
    """Structured stage failure; ``code`` is a stable code, not message text."""

    stage: AttemptStage
    code: str
    side: Optional[Side]
    diagnostics_ref: Optional[str]

    def __post_init__(self) -> None:
        _check_enum(self.stage, AttemptStage, "AttemptFailure.stage")
        _check_nonempty_str(self.code, "AttemptFailure.code", max_chars=128)
        if self.side is not None:
            _check_enum(self.side, Side, "AttemptFailure.side")
        if self.diagnostics_ref is not None:
            _check_nonempty_str(self.diagnostics_ref, "AttemptFailure.diagnostics_ref")

    def to_obj(self) -> dict[str, object]:
        return {
            "stage": str(self.stage.value),
            "code": self.code,
            "side": None if self.side is None else str(self.side.value),
            "diagnostics_ref": self.diagnostics_ref,
        }


def decode_attempt_failure(obj: object, what: str = "attempt failure") -> AttemptFailure:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"stage", "code", "side", "diagnostics_ref"}, what)
    return AttemptFailure(
        stage=_as_enum(AttemptStage, _field(obj, "stage", what), f"{what}.stage"),
        code=_as_str(_field(obj, "code", what), f"{what}.code"),
        side=_as_opt(Side, obj.get("side"), f"{what}.side"),
        diagnostics_ref=_as_opt(str, obj.get("diagnostics_ref"), f"{what}.diagnostics_ref"),
    )


@dataclass(frozen=True)
class PreflightRejection:
    """Structured pre-execution refusal bound to the paired request; the
    request hash is reconciled by consumers (gates), not by this model."""

    request_hash: str
    observed_environment: ObservedEnvironment
    rejected_requirement_id: str
    capability_check_version: str

    def __post_init__(self) -> None:
        _check_hex64(self.request_hash, "PreflightRejection.request_hash")
        if not isinstance(self.observed_environment, ObservedEnvironment):
            _fail("PreflightRejection.observed_environment must be an ObservedEnvironment")
        _check_nonempty_str(
            self.rejected_requirement_id, "PreflightRejection.rejected_requirement_id"
        )
        _check_nonempty_str(
            self.capability_check_version, "PreflightRejection.capability_check_version"
        )

    def to_obj(self) -> dict[str, object]:
        return {
            "request_hash": self.request_hash,
            "observed_environment": self.observed_environment.to_obj(),
            "rejected_requirement_id": self.rejected_requirement_id,
            "capability_check_version": self.capability_check_version,
        }


def decode_preflight_rejection(obj: object, what: str = "preflight rejection") -> PreflightRejection:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "request_hash",
            "observed_environment",
            "rejected_requirement_id",
            "capability_check_version",
        },
        what,
    )
    return PreflightRejection(
        request_hash=_as_str(_field(obj, "request_hash", what), f"{what}.request_hash"),
        observed_environment=decode_observed_environment(
            _field(obj, "observed_environment", what), f"{what}.observed_environment"
        ),
        rejected_requirement_id=_as_str(
            _field(obj, "rejected_requirement_id", what), f"{what}.rejected_requirement_id"
        ),
        capability_check_version=_as_str(
            _field(obj, "capability_check_version", what), f"{what}.capability_check_version"
        ),
    )


# --------------------------------------------------------------------------
# AttemptRequest / AttemptExpectation / QueryEvidence / ExecutionEvidence
# (contract 2.4)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AttemptRequest:
    """Caller-generated execution request; case_id is recomputed from the
    payload and never carried as a field (contract 2.4)."""

    run_id: str
    attempt_id: str
    payload: CasePayload
    target_environment: ObservedEnvironment
    session_profile: SessionProfile
    execution_order: ExecutionOrder
    result_row_budget: int
    result_byte_budget: int
    time_budget_ms: int
    synthetic: bool
    schema_version: int = EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "AttemptRequest.schema_version")
        if self.schema_version != EXECUTION_SCHEMA_VERSION:
            _fail(f"unsupported execution schema_version {self.schema_version}")
        _check_nonempty_str(self.run_id, "AttemptRequest.run_id", max_chars=128)
        _check_nonempty_str(self.attempt_id, "AttemptRequest.attempt_id", max_chars=128)
        if not isinstance(self.payload, CasePayload):
            _fail("AttemptRequest.payload must be a CasePayload")
        if not isinstance(self.target_environment, ObservedEnvironment):
            _fail("AttemptRequest.target_environment must be an ObservedEnvironment")
        if not isinstance(self.session_profile, SessionProfile):
            _fail("AttemptRequest.session_profile must be a SessionProfile")
        _check_enum(self.execution_order, ExecutionOrder, "AttemptRequest.execution_order")
        _check_int(self.result_row_budget, "AttemptRequest.result_row_budget")
        if not 1 <= self.result_row_budget <= MAX_RESULT_ROWS:
            _fail(
                f"AttemptRequest.result_row_budget must be in [1, {MAX_RESULT_ROWS}], "
                f"got {self.result_row_budget}"
            )
        _check_int(self.result_byte_budget, "AttemptRequest.result_byte_budget")
        if not 1 <= self.result_byte_budget <= MAX_RESULT_BYTES:
            _fail(
                f"AttemptRequest.result_byte_budget must be in [1, {MAX_RESULT_BYTES}], "
                f"got {self.result_byte_budget}"
            )
        _check_int(self.time_budget_ms, "AttemptRequest.time_budget_ms")
        if not 1 <= self.time_budget_ms <= ATTEMPT_BUDGET_MS:
            _fail(
                f"AttemptRequest.time_budget_ms must be in [1, {ATTEMPT_BUDGET_MS}], "
                f"got {self.time_budget_ms}"
            )
        _check_bool(self.synthetic, "AttemptRequest.synthetic")

    @property
    def case_id(self) -> str:
        """case_id recomputed from the payload; never stored."""
        return case_id_of(self.payload)

    @property
    def request_hash(self) -> str:
        """sha256 over the canonical request document."""
        return sha256_hex(canonical_json(self.to_obj()))

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "attempt_id": self.attempt_id,
            "payload": self.payload.to_obj(),
            "target_environment": self.target_environment.to_obj(),
            "session_profile": self.session_profile.to_obj(),
            "execution_order": str(self.execution_order.value),
            "result_row_budget": self.result_row_budget,
            "result_byte_budget": self.result_byte_budget,
            "time_budget_ms": self.time_budget_ms,
            "synthetic": self.synthetic,
        }


def decode_attempt_request(obj: object, what: str = "attempt request") -> AttemptRequest:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "schema_version",
            "run_id",
            "attempt_id",
            "payload",
            "target_environment",
            "session_profile",
            "execution_order",
            "result_row_budget",
            "result_byte_budget",
            "time_budget_ms",
            "synthetic",
        },
        what,
    )
    return AttemptRequest(
        schema_version=_as_int(_field(obj, "schema_version", what), f"{what}.schema_version"),
        run_id=_as_str(_field(obj, "run_id", what), f"{what}.run_id"),
        attempt_id=_as_str(_field(obj, "attempt_id", what), f"{what}.attempt_id"),
        payload=decode_case_payload(_field(obj, "payload", what), f"{what}.payload"),
        target_environment=decode_observed_environment(
            _field(obj, "target_environment", what), f"{what}.target_environment"
        ),
        session_profile=decode_session_profile(
            _field(obj, "session_profile", what), f"{what}.session_profile"
        ),
        execution_order=_as_enum(
            ExecutionOrder, _field(obj, "execution_order", what), f"{what}.execution_order"
        ),
        result_row_budget=_as_int(
            _field(obj, "result_row_budget", what), f"{what}.result_row_budget"
        ),
        result_byte_budget=_as_int(
            _field(obj, "result_byte_budget", what), f"{what}.result_byte_budget"
        ),
        time_budget_ms=_as_int(_field(obj, "time_budget_ms", what), f"{what}.time_budget_ms"),
        synthetic=_as_bool(_field(obj, "synthetic", what), f"{what}.synthetic"),
    )


@dataclass(frozen=True)
class AttemptExpectation:
    """Returned by ExecutionPort.prepare and sealed before execute."""

    binding: ExpectedBinding
    request_hash: str
    codec_version: str
    execution_order: ExecutionOrder
    name_map: NameMap
    schema_version: int = EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "AttemptExpectation.schema_version")
        if self.schema_version != EXECUTION_SCHEMA_VERSION:
            _fail(f"unsupported execution schema_version {self.schema_version}")
        if not isinstance(self.binding, ExpectedBinding):
            _fail("AttemptExpectation.binding must be an ExpectedBinding")
        _check_hex64(self.request_hash, "AttemptExpectation.request_hash")
        _check_nonempty_str(self.codec_version, "AttemptExpectation.codec_version", max_chars=128)
        _check_enum(self.execution_order, ExecutionOrder, "AttemptExpectation.execution_order")
        if not isinstance(self.name_map, NameMap):
            _fail("AttemptExpectation.name_map must be a NameMap")

    @property
    def expectation_hash(self) -> str:
        """Content hash of the expectation document (no self-hash field)."""
        return sha256_hex(canonical_json(self.to_obj()))

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "binding": self.binding.to_obj(),
            "request_hash": self.request_hash,
            "codec_version": self.codec_version,
            "execution_order": str(self.execution_order.value),
            "name_map": self.name_map.to_obj(),
        }


def decode_attempt_expectation(obj: object, what: str = "attempt expectation") -> AttemptExpectation:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "schema_version",
            "binding",
            "request_hash",
            "codec_version",
            "execution_order",
            "name_map",
        },
        what,
    )
    return AttemptExpectation(
        schema_version=_as_int(_field(obj, "schema_version", what), f"{what}.schema_version"),
        binding=decode_expected_binding(_field(obj, "binding", what), f"{what}.binding"),
        request_hash=_as_str(_field(obj, "request_hash", what), f"{what}.request_hash"),
        codec_version=_as_str(_field(obj, "codec_version", what), f"{what}.codec_version"),
        execution_order=_as_enum(
            ExecutionOrder, _field(obj, "execution_order", what), f"{what}.execution_order"
        ),
        name_map=decode_name_map(_field(obj, "name_map", what), f"{what}.name_map"),
    )


@dataclass(frozen=True)
class QueryEvidence:
    """Per-side SELECT evidence; the SELECT diagnostics phase is serialized
    as ``"select"`` (see SelectPhase).

    Session ids are both present and equal once a session existed; they stay
    jointly absent only when no session could be established (never exactly
    one).  A COMPLETE status requires the fetched result, full and
    untruncated.
    """

    side: Side
    binding: ExpectedBinding
    select_text: str
    select_sql_hash: str
    protocol: str
    parameters: Tuple[()]
    status: QueryStatus
    result: Optional[ResultSet]
    session_start_id: Optional[str]
    session_end_id: Optional[str]
    actual_database: str
    environment_before: ObservedEnvironment
    environment_after: ObservedEnvironment
    diagnostics: StatementDiagnostics
    duration_ms: int
    result_terminal: ResultTerminal

    def __post_init__(self) -> None:
        _check_enum(self.side, Side, "QueryEvidence.side")
        if not isinstance(self.binding, ExpectedBinding):
            _fail("QueryEvidence.binding must be an ExpectedBinding")
        _check_nonempty_str(self.select_text, "QueryEvidence.select_text")
        _check_hex64(self.select_sql_hash, "QueryEvidence.select_sql_hash")
        if self.select_sql_hash != sha256_hex(self.select_text.encode("utf-8")):
            _fail("QueryEvidence.select_sql_hash does not match its select_text")
        if self.protocol != "text":
            _fail(f"QueryEvidence.protocol is fixed to \"text\", got {self.protocol!r}")
        if self.parameters != ():
            _fail("QueryEvidence.parameters is fixed to the empty tuple")
        _check_enum(self.status, QueryStatus, "QueryEvidence.status")
        if self.result is not None and not isinstance(self.result, ResultSet):
            _fail("QueryEvidence.result must be a ResultSet or None")
        if self.status is QueryStatus.COMPLETE:
            if self.result is None:
                _fail("QueryEvidence COMPLETE requires a fetched result")
            if not self.result.fetch_complete or self.result.truncated:
                _fail("QueryEvidence COMPLETE requires a full, untruncated fetch")
        for name in ("session_start_id", "session_end_id"):
            value = getattr(self, name)
            if value is not None:
                _check_nonempty_str(value, f"QueryEvidence.{name}")
        if (self.session_start_id is None) != (self.session_end_id is None):
            _fail("QueryEvidence session ids must be both present or both absent")
        if (
            self.session_start_id is not None
            and self.session_end_id != self.session_start_id
        ):
            _fail("QueryEvidence session ids must be equal (no mid-fetch reconnect)")
        if self.status is QueryStatus.COMPLETE and self.session_start_id is None:
            _fail("QueryEvidence COMPLETE requires session identity")
        _check_nonempty_str(self.actual_database, "QueryEvidence.actual_database")
        for name in ("environment_before", "environment_after"):
            if not isinstance(getattr(self, name), ObservedEnvironment):
                _fail(f"QueryEvidence.{name} must be an ObservedEnvironment")
        if not isinstance(self.diagnostics, StatementDiagnostics):
            _fail("QueryEvidence.diagnostics must be a StatementDiagnostics")
        if self.diagnostics.phase is not SelectPhase.SELECT:
            _fail("QueryEvidence.diagnostics phase must be SELECT")
        _check_int(self.duration_ms, "QueryEvidence.duration_ms")
        if self.duration_ms < 0:
            _fail(f"QueryEvidence.duration_ms must be >= 0, got {self.duration_ms}")
        _check_enum(self.result_terminal, ResultTerminal, "QueryEvidence.result_terminal")
        if self.result_terminal is ResultTerminal.CONFIRMED:
            if self.status is not QueryStatus.COMPLETE or self.result is None:
                _fail("result_terminal CONFIRMED requires a COMPLETE query with a result")
            if not self.result.fetch_complete or self.result.truncated:
                _fail("result_terminal CONFIRMED requires full, untruncated fetch evidence")

    def to_obj(self) -> dict[str, object]:
        return {
            "side": str(self.side.value),
            "binding": self.binding.to_obj(),
            "select_text": self.select_text,
            "select_sql_hash": self.select_sql_hash,
            "protocol": self.protocol,
            "parameters": list(self.parameters),
            "status": str(self.status.value),
            "result": None if self.result is None else self.result.to_obj(),
            "session_start_id": self.session_start_id,
            "session_end_id": self.session_end_id,
            "actual_database": self.actual_database,
            "environment_before": self.environment_before.to_obj(),
            "environment_after": self.environment_after.to_obj(),
            "diagnostics": self.diagnostics.to_obj(),
            "duration_ms": self.duration_ms,
            "result_terminal": str(self.result_terminal.value),
        }


def decode_query_evidence(obj: object, what: str = "query evidence") -> QueryEvidence:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "side",
            "binding",
            "select_text",
            "select_sql_hash",
            "protocol",
            "parameters",
            "status",
            "result",
            "session_start_id",
            "session_end_id",
            "actual_database",
            "environment_before",
            "environment_after",
            "diagnostics",
            "duration_ms",
            "result_terminal",
        },
        what,
    )
    result_obj = _field(obj, "result", what)
    parameters = _as_list(_field(obj, "parameters", what), f"{what}.parameters")
    if parameters:
        _fail(f"{what}.parameters is fixed to the empty list")
    return QueryEvidence(
        side=_as_enum(Side, _field(obj, "side", what), f"{what}.side"),
        binding=decode_expected_binding(_field(obj, "binding", what), f"{what}.binding"),
        select_text=_as_str(_field(obj, "select_text", what), f"{what}.select_text"),
        select_sql_hash=_as_str(
            _field(obj, "select_sql_hash", what), f"{what}.select_sql_hash"
        ),
        protocol=_as_str(_field(obj, "protocol", what), f"{what}.protocol"),
        parameters=(),
        status=_as_enum(QueryStatus, _field(obj, "status", what), f"{what}.status"),
        result=(
            None
            if result_obj is None
            else decode_result_set(result_obj, f"{what}.result")
        ),
        session_start_id=_opt_str(obj.get("session_start_id"), f"{what}.session_start_id"),
        session_end_id=_opt_str(obj.get("session_end_id"), f"{what}.session_end_id"),
        actual_database=_as_str(
            _field(obj, "actual_database", what), f"{what}.actual_database"
        ),
        environment_before=decode_observed_environment(
            _field(obj, "environment_before", what), f"{what}.environment_before"
        ),
        environment_after=decode_observed_environment(
            _field(obj, "environment_after", what), f"{what}.environment_after"
        ),
        diagnostics=decode_statement_diagnostics(
            _field(obj, "diagnostics", what), f"{what}.diagnostics", select=True
        ),
        duration_ms=_as_int(_field(obj, "duration_ms", what), f"{what}.duration_ms"),
        result_terminal=_as_enum(
            ResultTerminal, _field(obj, "result_terminal", what), f"{what}.result_terminal"
        ),
    )


@dataclass(frozen=True)
class ExecutionEvidence:
    """Complete per-attempt execution evidence (contract 2.4).

    ``evidence_hash`` is a derived field over ``to_obj()`` (which excludes the
    hash itself); a supplied value that disagrees is rejected.  A preflight
    rejection excludes every post-PREPARE content.  A missing side is an
    absence (None), not a success.
    """

    request_hash: str
    expectation: Optional[AttemptExpectation]
    runtime_facts: Optional[RuntimeFacts]
    setup_diagnostics: tuple[StatementDiagnostics, ...]
    actual_execution_order: Optional[ExecutionOrder]
    a_context: Optional[SideContext]
    b_context: Optional[SideContext]
    a_query: Optional[QueryEvidence]
    b_query: Optional[QueryEvidence]
    isolation_receipt: Optional[IsolationReceipt]
    terminal: Optional[TerminalReceipt]
    failure: Optional[AttemptFailure]
    preflight_rejection: Optional[PreflightRejection]
    synthetic: bool
    schema_version: int = EXECUTION_SCHEMA_VERSION
    evidence_hash: str = ""

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "ExecutionEvidence.schema_version")
        if self.schema_version != EXECUTION_SCHEMA_VERSION:
            _fail(f"unsupported execution schema_version {self.schema_version}")
        _check_hex64(self.request_hash, "ExecutionEvidence.request_hash")
        if self.expectation is not None and not isinstance(self.expectation, AttemptExpectation):
            _fail("ExecutionEvidence.expectation must be an AttemptExpectation or None")
        if self.runtime_facts is not None and not isinstance(self.runtime_facts, RuntimeFacts):
            _fail("ExecutionEvidence.runtime_facts must be RuntimeFacts or None")
        if not isinstance(self.setup_diagnostics, tuple):
            _fail("ExecutionEvidence.setup_diagnostics must be a tuple")
        for item in self.setup_diagnostics:
            if not isinstance(item, StatementDiagnostics):
                _fail("ExecutionEvidence.setup_diagnostics must hold StatementDiagnostics items")
            if not isinstance(item.phase, StatementPhase):
                _fail("ExecutionEvidence.setup_diagnostics phases must be ddl/insert")
        if self.actual_execution_order is not None:
            _check_enum(
                self.actual_execution_order,
                ExecutionOrder,
                "ExecutionEvidence.actual_execution_order",
            )
        for name in ("a_context", "b_context"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, SideContext):
                _fail(f"ExecutionEvidence.{name} must be a SideContext or None")
        for name in ("a_query", "b_query"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, QueryEvidence):
                _fail(f"ExecutionEvidence.{name} must be a QueryEvidence or None")
        if self.a_query is not None and self.a_context is None:
            _fail("ExecutionEvidence.a_query requires a_context")
        if self.b_query is not None and self.b_context is None:
            _fail("ExecutionEvidence.b_query requires b_context")
        if self.isolation_receipt is not None and not isinstance(
            self.isolation_receipt, IsolationReceipt
        ):
            _fail("ExecutionEvidence.isolation_receipt must be an IsolationReceipt or None")
        if self.terminal is not None and not isinstance(self.terminal, TerminalReceipt):
            _fail("ExecutionEvidence.terminal must be a TerminalReceipt or None")
        if self.failure is not None and not isinstance(self.failure, AttemptFailure):
            _fail("ExecutionEvidence.failure must be an AttemptFailure or None")
        if self.preflight_rejection is not None and not isinstance(
            self.preflight_rejection, PreflightRejection
        ):
            _fail("ExecutionEvidence.preflight_rejection must be a PreflightRejection or None")
        _check_bool(self.synthetic, "ExecutionEvidence.synthetic")
        if self.preflight_rejection is not None:
            if self.expectation is not None:
                _fail("a preflight rejection excludes an expectation")
            if self.runtime_facts is not None:
                _fail("a preflight rejection excludes runtime facts")
            if self.setup_diagnostics:
                _fail("a preflight rejection excludes setup diagnostics")
            if self.actual_execution_order is not None:
                _fail("a preflight rejection excludes an actual execution order")
            if self.a_context is not None or self.b_context is not None:
                _fail("a preflight rejection excludes side contexts")
            if self.a_query is not None or self.b_query is not None:
                _fail("a preflight rejection excludes query evidence")
            if self.isolation_receipt is not None:
                _fail("a preflight rejection excludes an isolation receipt")
            if self.failure is not None:
                _fail("a preflight rejection excludes an attempt failure")
            if self.terminal is not None and (
                self.terminal.termination is not TerminationState.NOT_STARTED
            ):
                _fail("a preflight rejection only allows NOT_STARTED terminal semantics")
        else:
            if self.failure is not None:
                if self.failure.stage is AttemptStage.PREPARE:
                    if self.expectation is not None:
                        _fail("a PREPARE failure cannot carry an expectation")
                    if self.a_context is not None or self.b_context is not None:
                        _fail("a PREPARE failure cannot carry side contexts")
                    if self.a_query is not None or self.b_query is not None:
                        _fail("a PREPARE failure cannot carry query evidence")
                else:
                    if self.expectation is None:
                        _fail("a post-PREPARE failure requires the sealed expectation")
            elif self.expectation is None:
                _fail(
                    "ExecutionEvidence records neither a preflight rejection, a failure, "
                    "nor a prepare success"
                )
        derived = sha256_hex(canonical_json(self.to_obj()))
        if self.evidence_hash == "":
            object.__setattr__(self, "evidence_hash", derived)
        elif self.evidence_hash != derived:
            _fail(
                f"ExecutionEvidence.evidence_hash {self.evidence_hash!r} does not match "
                f"the content hash {derived}"
            )
        _check_hex64(self.evidence_hash, "ExecutionEvidence.evidence_hash")

    def to_obj(self) -> dict[str, object]:
        """Canonical content; the ``evidence_hash`` field is excluded."""
        return {
            "schema_version": self.schema_version,
            "request_hash": self.request_hash,
            "expectation": None if self.expectation is None else self.expectation.to_obj(),
            "runtime_facts": None if self.runtime_facts is None else self.runtime_facts.to_obj(),
            "setup_diagnostics": [item.to_obj() for item in self.setup_diagnostics],
            "actual_execution_order": (
                None
                if self.actual_execution_order is None
                else str(self.actual_execution_order.value)
            ),
            "a_context": None if self.a_context is None else self.a_context.to_obj(),
            "b_context": None if self.b_context is None else self.b_context.to_obj(),
            "a_query": None if self.a_query is None else self.a_query.to_obj(),
            "b_query": None if self.b_query is None else self.b_query.to_obj(),
            "isolation_receipt": (
                None if self.isolation_receipt is None else self.isolation_receipt.to_obj()
            ),
            "terminal": None if self.terminal is None else self.terminal.to_obj(),
            "failure": None if self.failure is None else self.failure.to_obj(),
            "preflight_rejection": (
                None if self.preflight_rejection is None else self.preflight_rejection.to_obj()
            ),
            "synthetic": self.synthetic,
        }


def decode_execution_evidence(obj: object, what: str = "execution evidence") -> ExecutionEvidence:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "schema_version",
            "request_hash",
            "expectation",
            "runtime_facts",
            "setup_diagnostics",
            "actual_execution_order",
            "a_context",
            "b_context",
            "a_query",
            "b_query",
            "isolation_receipt",
            "terminal",
            "failure",
            "preflight_rejection",
            "synthetic",
            "evidence_hash",
        },
        what,
    )
    expectation_obj = _field(obj, "expectation", what)
    facts_obj = _field(obj, "runtime_facts", what)
    order_obj = _field(obj, "actual_execution_order", what)
    isolation_obj = _field(obj, "isolation_receipt", what)
    terminal_obj = _field(obj, "terminal", what)
    failure_obj = _field(obj, "failure", what)
    preflight_obj = _field(obj, "preflight_rejection", what)
    return ExecutionEvidence(
        schema_version=_as_int(_field(obj, "schema_version", what), f"{what}.schema_version"),
        request_hash=_as_str(_field(obj, "request_hash", what), f"{what}.request_hash"),
        expectation=(
            None
            if expectation_obj is None
            else decode_attempt_expectation(expectation_obj, f"{what}.expectation")
        ),
        runtime_facts=(
            None if facts_obj is None else decode_runtime_facts(facts_obj, f"{what}.runtime_facts")
        ),
        setup_diagnostics=tuple(
            decode_statement_diagnostics(item, f"{what}.setup_diagnostics[{index}]")
            for index, item in enumerate(
                _as_list(_field(obj, "setup_diagnostics", what), f"{what}.setup_diagnostics")
            )
        ),
        actual_execution_order=(
            None
            if order_obj is None
            else _as_enum(ExecutionOrder, order_obj, f"{what}.actual_execution_order")
        ),
        a_context=(
            None
            if obj["a_context"] is None
            else decode_side_context(obj["a_context"], f"{what}.a_context")
        ),
        b_context=(
            None
            if obj["b_context"] is None
            else decode_side_context(obj["b_context"], f"{what}.b_context")
        ),
        a_query=(
            None
            if obj["a_query"] is None
            else decode_query_evidence(obj["a_query"], f"{what}.a_query")
        ),
        b_query=(
            None
            if obj["b_query"] is None
            else decode_query_evidence(obj["b_query"], f"{what}.b_query")
        ),
        isolation_receipt=(
            None
            if isolation_obj is None
            else decode_isolation_receipt(isolation_obj, f"{what}.isolation_receipt")
        ),
        terminal=(
            None if terminal_obj is None else decode_terminal_receipt(terminal_obj, f"{what}.terminal")
        ),
        failure=(
            None if failure_obj is None else decode_attempt_failure(failure_obj, f"{what}.failure")
        ),
        preflight_rejection=(
            None
            if preflight_obj is None
            else decode_preflight_rejection(preflight_obj, f"{what}.preflight_rejection")
        ),
        synthetic=_as_bool(_field(obj, "synthetic", what), f"{what}.synthetic"),
        evidence_hash=_as_str(_field(obj, "evidence_hash", what), f"{what}.evidence_hash"),
    )


# --------------------------------------------------------------------------
# Public load/dump entry points (contract 2.4)
# --------------------------------------------------------------------------


def _load_document(decode: Callable[[object, str], object], data: object, what: str) -> object:
    if isinstance(data, dict):
        return decode(data, what)
    return decode(parse_strict_json(data), what)


def load_attempt_request(data: bytes | str | dict) -> AttemptRequest:
    """Strict loader: untrusted bytes/str/dict -> validated AttemptRequest."""
    return _load_document(decode_attempt_request, data, "attempt request")  # type: ignore[return-value]


def load_attempt_expectation(data: bytes | str | dict) -> AttemptExpectation:
    return _load_document(decode_attempt_expectation, data, "attempt expectation")  # type: ignore[return-value]


def load_execution_evidence(data: bytes | str | dict) -> ExecutionEvidence:
    """Strict loader; a raw envelope over MAX_EVIDENCE_BYTES is rejected
    before parsing."""
    if isinstance(data, (bytes, str)):
        raw = data.encode("utf-8") if isinstance(data, str) else data
        if len(raw) > MAX_EVIDENCE_BYTES:
            _fail(f"execution evidence exceeds MAX_EVIDENCE_BYTES ({MAX_EVIDENCE_BYTES})")
    return _load_document(decode_execution_evidence, data, "execution evidence")  # type: ignore[return-value]


def dump_attempt_request(model: AttemptRequest) -> bytes:
    """Canonical request bytes (no trailing newline)."""
    return canonical_json(model.to_obj())


def dump_attempt_expectation(model: AttemptExpectation) -> bytes:
    return canonical_json(model.to_obj())


def dump_execution_evidence(model: ExecutionEvidence) -> bytes:
    """Canonical evidence bytes including the ``evidence_hash`` field."""
    obj = model.to_obj()
    obj["evidence_hash"] = model.evidence_hash
    return canonical_json(obj)


# --------------------------------------------------------------------------
# Control, errors and the ExecutionPort protocol (contract 2.5)
# --------------------------------------------------------------------------


class ControlCancelled(ContractError):
    """Raised by Control.raise_if_cancelled on cooperative cancellation."""


@dataclass(frozen=True)
class Control:
    """Injectable deadline/cancellation handle; no document model, floats are
    process-local monotonic seconds and never serialized."""

    clock: Callable[[], float]
    deadline: Optional[float]
    cancelled: Callable[[], bool]

    def __post_init__(self) -> None:
        if not callable(self.clock):
            _fail("Control.clock must be callable")
        if not callable(self.cancelled):
            _fail("Control.cancelled must be callable")
        if self.deadline is not None:
            if isinstance(self.deadline, bool) or not isinstance(self.deadline, (int, float)):
                _fail("Control.deadline must be a monotonic float or None")
            if not math.isfinite(self.deadline):
                _fail("Control.deadline must be finite")

    def remaining_ms(self) -> int:
        """Whole milliseconds left; an unbounded control reports a large
        sentinel, an expired control reports 0."""
        if self.deadline is None:
            return _UNBOUNDED_REMAINING_MS
        remaining = (self.deadline - self.clock()) * 1000
        if remaining <= 0:
            return 0
        return int(remaining)

    def expired(self) -> bool:
        return self.deadline is not None and self.clock() >= self.deadline

    def raise_if_cancelled(self) -> None:
        if self.cancelled():
            raise ControlCancelled("control cancelled")

    def child(self, deadline_s: Optional[float]) -> "Control":
        """Same clock/token; the deadline is the min of this control's
        deadline and now + deadline_s (None keeps this control's deadline)."""
        if deadline_s is not None:
            if isinstance(deadline_s, bool) or not isinstance(deadline_s, (int, float)):
                _fail("Control.child deadline_s must be a number of seconds or None")
            if not math.isfinite(deadline_s) or deadline_s < 0:
                _fail("Control.child deadline_s must be finite and non-negative")
        if deadline_s is None:
            return Control(self.clock, self.deadline, self.cancelled)
        candidate = self.clock() + deadline_s
        if self.deadline is None:
            return Control(self.clock, candidate, self.cancelled)
        return Control(self.clock, min(self.deadline, candidate), self.cancelled)


def default_control(deadline_s: Optional[float] = None) -> Control:
    """Test/default factory: time.monotonic clock, never cancelled."""
    clock = time.monotonic
    deadline = None if deadline_s is None else clock() + deadline_s
    return Control(clock, deadline, lambda: False)


class ExecutionPortError(ContractError):
    """Port refusal/failure carrying the partial evidence gathered so far.

    Contains no executable callbacks and never retries internally.
    """

    def __init__(
        self,
        message: str,
        *,
        failure: Optional[AttemptFailure] = None,
        evidence: Optional[ExecutionEvidence] = None,
        terminal: Optional[TerminalReceipt] = None,
    ) -> None:
        super().__init__(message)
        self.failure = failure
        self.evidence = evidence
        self.terminal = terminal


class ExecutionPort(Protocol):
    """D3-owned executor boundary (contract 2.5).

    ``prepare`` must refuse/return before any test SQL runs; ``execute``
    never internally retries into the same attempt.  Synchronous calls must
    return inside the deadline or cooperatively terminate via ``control``.
    """

    def prepare(self, request: AttemptRequest, control: Control) -> AttemptExpectation: ...

    def execute(
        self, request: AttemptRequest, expectation: AttemptExpectation, control: Control
    ) -> ExecutionEvidence: ...

    def cancel_and_wait(self, attempt_id: str, grace_seconds: float) -> TerminalReceipt: ...
