"""MySQL 8.0 adapter over the PyMySQL shim (D3 design 6.3.2, Phase 2).

Implements the :class:`ProtocolAdapter` surface on top of
``adapters.mysql_protocol.PyMySQLAdapter``:

- ``connect_and_probe``: driver baseline first, one connection from
  :class:`ConnectionParams`, identity facts read exactly once each via fixed
  batched constant SELECTs (the frozen 5-column result budget caps one round
  trip at five ``@@variables``), fail closed on missing/empty required
  facts, no session mutation;
- ``apply_session``: the caller's SET statements one at a time in the given
  order, then every applied setting read back with a SELECT and compared to
  the requested value; any mismatch raises the typed
  :class:`SessionMismatch` (never continues silently);
- ``execute_statement``: shim execution + immediate diagnostics, wrapped
  with a statement ordinal and timing from an injected monotonic clock;
- ``open_query``/``fetch_result``: the shim's bounded fetch path with the
  ``contracts.execution`` budgets (inherited unchanged);
- ``inspect_schema``: INFORMATION_SCHEMA tables/columns for one attempt
  database; the database name must match a strict identifier grammar before
  any quoting (no unvalidated interpolation, no driver-side string
  substitution in the raw-query path);
- ``cancel_current``: ``KILL QUERY <id>`` issued from an independent control
  connection injected at construction (KILL QUERY cannot be issued on the
  worker connection's own id); without a control connection this raises a
  clear unsupported error -- Phase 5 wires the real control plane;
- ``execute_ddl``/``is_database_present``: the narrow ``CleanupExecutor``
  binding for ``runner.cleanup`` (design 6.2.3): only whitelisted,
  tool-generated cleanup statements over names that pass the ``tc_`` naming
  validator are ever executed (no prefix scans, no free-form DDL);
- ``close``: idempotent, safe after unusable marking (inherited).

Safety boundaries kept here (design 6.3.1/Phase 2 constraints): no TLS
auto-downgrade (the TLS mode comes verbatim from ``runner.config``),
``server_public_key`` stays refused by ``ConnectionParams``, no global SET,
no init_command, and every session name/value passes a strict allowlist
before any SQL is built (the quoting helpers below are the only string
assembly and the allowlists admit no metacharacters).
"""

from __future__ import annotations

import platform
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Mapping, Optional, Protocol, runtime_checkable

from ..contracts import execution as _execution
from ..contracts.case import ContractError
from .base import AdapterError, ConnectionParams
from .mysql_protocol import (
    MAPPING_VERSION,
    PyMySQLAdapter,
    RawQueryResult,
    StatementReceipt,
    verify_driver_baseline,
)

if TYPE_CHECKING:  # pragma: no cover - annotation-only import
    from ..runner.preflight import ProbeRuntimeIdentity

__all__ = [
    "ADAPTER_VERSION",
    "SESSION_APPLY_FAILED",
    "SESSION_MISMATCH",
    "IDENTITY_INCOMPLETE",
    "CANCEL_UNSUPPORTED",
    "CLEANUP_DDL_FAILED",
    "SessionMismatchEntry",
    "SessionMismatch",
    "ExecutedStatement",
    "CancelReceipt",
    "SchemaSummary",
    "MySQL80Adapter",
]

#: Semantic identity of this adapter implementation (stamped on manifests).
ADAPTER_VERSION = "mysql80-adapter-v1"

# Stable error codes (contract, not text).
SESSION_APPLY_FAILED = "SESSION_APPLY_FAILED"
SESSION_MISMATCH = "SESSION_MISMATCH"
IDENTITY_INCOMPLETE = "IDENTITY_INCOMPLETE"
CANCEL_UNSUPPORTED = "CANCEL_UNSUPPORTED"
CLEANUP_DDL_FAILED = "CLEANUP_DDL_FAILED"

#: Identity/environment facts; the names are the shared preflight/D1
#: vocabulary (``runner.preflight``, ``generation.validation``).
_IDENTITY_FACT_KEYS: tuple[str, ...] = (
    "server_uuid",
    "version",
    "version_comment",
    "sql_mode",
    "character_set_server",
    "character_set_connection",
    "collation_server",
    "collation_connection",
    "time_zone",
    "system_time_zone",
    "innodb_version",
    "sql_notes",
    "optimizer_switch",
)

#: Facts that must be present and non-empty after the identity probe;
#: ``version_comment`` / ``innodb_version`` / ``system_time_zone`` /
#: ``optimizer_switch`` / ``sql_notes`` are recorded when readable (design:
#: "if readable") but do not fail the connection.
_REQUIRED_IDENTITY_FACTS: tuple[str, ...] = (
    "server_uuid",
    "version",
    "sql_mode",
    "character_set_server",
    "character_set_connection",
    "collation_server",
    "collation_connection",
    "time_zone",
)

#: Identity probes are constant-text SELECTs reading ``@@variables``; no user
#: data is ever interpolated.  The frozen ``MAX_RESULT_COLUMNS = 5`` budget
#: (contracts.execution, enforced by the shim before field structures are
#: allocated) caps one SELECT at five columns, so the fixed fact list is read
#: via a fixed sequence of batched SELECTs -- every fact is read exactly once.
_IDENTITY_COLUMN_BUDGET = 5
_IDENTITY_SELECTS: tuple[str, ...] = tuple(
    "SELECT " + ", ".join(f"@@{name}" for name in _IDENTITY_FACT_KEYS[i : i + _IDENTITY_COLUMN_BUDGET])
    for i in range(0, len(_IDENTITY_FACT_KEYS), _IDENTITY_COLUMN_BUDGET)
)

# Strict allowlists (design 6.3.2: no string interpolation of unvalidated
# values).  Session variable names are plain identifiers; session values admit
# only the characters that occur in legal MySQL session literals for this
# tool's settings (sql_mode tokens, charsets/collations, time zones,
# isolation levels, autocommit) -- no whitespace, no quotes, no backslashes,
# no semicolons or comments.
_SESSION_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SESSION_VALUE_RE = re.compile(r"^[A-Za-z0-9_:@=+.,\-]{1,128}$")
# Attempt database names come from the controlled ``tc_`` namespace; the
# grammar admits no quoting metacharacters, so the quoted literal below is
# injection-proof by construction.
_DATABASE_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")

# CleanupExecutor whitelist (design 6.2.3): the only statement shapes
# ``runner.cleanup`` builders can produce.  Object names are additionally
# re-validated through the frozen ``runner.naming`` validators before any
# SQL is sent; marker INSERT literals mirror the ``runner.cleanup`` literal
# grammar (no quotes, backslashes or whitespace).
_CLEANUP_DROP_TABLE_RE = re.compile(
    r"^DROP TABLE `([A-Za-z0-9_]+)`\.`([A-Za-z0-9_]+)`$"
)
_CLEANUP_DROP_DATABASE_RE = re.compile(r"^DROP DATABASE `([A-Za-z0-9_]+)`$")
_CLEANUP_CREATE_DATABASE_RE = re.compile(r"^CREATE DATABASE `([A-Za-z0-9_]+)`$")
_CLEANUP_MARKER_INSERT_RE = re.compile(
    r"^INSERT INTO `tc_ownership_marker` \(run_id, attempt_id, token\) "
    r"VALUES \('([^']*)', '([^']*)', '([^']*)'\)$"
)
_CLEANUP_LITERAL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

# Small budgets for single-row identity/readback probes (well inside the
# contracts.execution caps).
_PROBE_ROW_BUDGET = 1
_PROBE_BYTE_BUDGET = 64 * 1024


def _decode_cell(cell: object, what: str) -> str:
    """Decode one raw protocol cell to text; non-bytes fails closed."""

    if cell is None:
        raise AdapterError(f"identity fact {what} arrived as NULL (fail closed)")
    if isinstance(cell, (bytes, bytearray)):
        try:
            return bytes(cell).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AdapterError(
                f"identity fact {what} is not valid UTF-8 (fail closed)"
            ) from exc
    raise AdapterError(
        f"identity fact {what} arrived as {type(cell).__name__}, expected raw bytes "
        f"(fail closed)"
    )


# --------------------------------------------------------------------------
# Typed results and errors
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionMismatchEntry:
    """One setting that did not read back as requested."""

    name: str
    expected: str
    observed: str


class SessionMismatch(AdapterError):
    """A session setting did not read back as requested (design 6.3.2:
    readback is mandatory and a mismatch never continues silently)."""

    def __init__(self, message: str, *, mismatches: tuple[SessionMismatchEntry, ...]) -> None:
        super().__init__(message, code=SESSION_MISMATCH)
        self.mismatches = mismatches


@dataclass(frozen=True)
class ExecutedStatement:
    """Receipt for one statement executed through this adapter: the shim's
    :class:`StatementReceipt` (diagnostics collected immediately) plus the
    statement ordinal and timing from the injected clock."""

    ordinal: int
    receipt: StatementReceipt
    duration_ms: int


@dataclass(frozen=True)
class CancelReceipt:
    """Best-effort cancellation observation: the worker connection id that
    KILL QUERY targeted and the kill statement's own receipt.  This is
    observation evidence, not a termination proof (design C01)."""

    connection_id: int
    kill: StatementReceipt


@dataclass(frozen=True)
class SchemaSummary:
    """INFORMATION_SCHEMA tables and columns for one attempt database."""

    database: str
    tables: RawQueryResult
    columns: RawQueryResult


@runtime_checkable
class _ControlStatementExecutor(Protocol):
    """Narrow surface the control connection must provide (a
    ``PyMySQLAdapter`` satisfies it)."""

    def execute_statement(self, sql: str) -> StatementReceipt: ...


# --------------------------------------------------------------------------
# Adapter
# --------------------------------------------------------------------------


class MySQL80Adapter(PyMySQLAdapter):
    """MySQL 8.0/MTSQL adapter over the certified PyMySQL shim.

    ``charset`` is required explicitly (keyword-only): the connection charset
    is part of the caller's session configuration and is never defaulted
    silently.  ``clock`` is an injected monotonic-seconds callable
    (``contracts.execution`` discipline); ``control`` is the independent
    control-plane connection used for KILL QUERY (None until Phase 5 wires
    it).
    """

    def __init__(
        self,
        params: ConnectionParams,
        *,
        charset: str,
        deadline_cb: Optional[Callable[[], None]] = None,
        clock: Optional[Callable[[], float]] = None,
        control: Optional[_ControlStatementExecutor] = None,
    ) -> None:
        super().__init__(params, charset=charset, deadline_cb=deadline_cb)
        self._clock = clock if clock is not None else time.monotonic
        self._control = control
        self._identity_facts: Optional[dict[str, str]] = None
        self._statement_ordinal = 0

    # -- connect / identity probe ------------------------------------------

    def connect_and_probe(self) -> dict[str, str]:
        """Verify the driver baseline, open one connection, and read the
        identity facts exactly once each (fixed batched constant SELECTs --
        the frozen 5-column result budget caps one round trip at five
        variables).

        Fails closed (``AdapterError`` with code ``IDENTITY_INCOMPLETE``) on
        missing/empty required facts.  No session state is mutated here.
        """

        if self._conn is None:
            # verify_driver_baseline() runs inside connect(), before any
            # network traffic is treated as usable.
            self.connect()
        facts = self._read_identity_facts()
        missing = [
            name for name in _REQUIRED_IDENTITY_FACTS if not facts.get(name)
        ]
        if missing:
            raise AdapterError(
                f"identity probe returned missing/empty required facts {missing} "
                f"(fail closed)",
                code=IDENTITY_INCOMPLETE,
            )
        return dict(facts)

    def _read_identity_facts(self) -> dict[str, str]:
        """Read every identity fact exactly once via the fixed batched
        constant SELECTs; NULL cells mean the fact is absent."""

        self._check_usable()
        facts: dict[str, str] = {}
        offset = 0
        for select in _IDENTITY_SELECTS:
            result = self.execute_raw_query(
                select,
                row_budget=_PROBE_ROW_BUDGET,
                byte_budget=_PROBE_BYTE_BUDGET,
            )
            if result.observed_row_count != 1:
                raise AdapterError(
                    f"identity probe {select!r} returned {result.observed_row_count} "
                    f"rows, expected exactly 1 (fail closed)"
                )
            row = result.rows[0]
            names = _IDENTITY_FACT_KEYS[offset : offset + _IDENTITY_COLUMN_BUDGET]
            if len(row) != len(names):
                raise AdapterError(
                    f"identity probe {select!r} returned {len(row)} columns, expected "
                    f"{len(names)} (fail closed)"
                )
            for name, cell in zip(names, row):
                if cell is None:
                    continue  # absent fact; callers fail closed per fact
                facts[name] = _decode_cell(cell, name)
            offset += _IDENTITY_COLUMN_BUDGET
        self._identity_facts = facts
        return facts

    def fetch_environment_facts(self) -> Mapping[str, str]:
        """Read-only environment facts for ``runner.preflight`` (probe-source
        protocol).  Absent (NULL) facts are simply missing keys; preflight
        turns each into a FAILED probe record.  Never mutates session state.
        """

        if self._identity_facts is None:
            self._read_identity_facts()
        return dict(self._identity_facts or {})

    def runtime_identity(self) -> "ProbeRuntimeIdentity":
        """Host/driver/adapter/mapping identities for ``runner.preflight``.

        Imported lazily so this module's import graph stays
        adapters->shim only.
        """

        from ..runner.preflight import ProbeRuntimeIdentity

        driver_version = self._driver_version
        if driver_version is None:
            driver_version = verify_driver_baseline()
        return ProbeRuntimeIdentity(
            python_version=platform.python_version(),
            os_platform=platform.platform(),
            driver_name="pymysql",
            driver_version=driver_version,
            adapter_version=ADAPTER_VERSION,
            mapping_version=MAPPING_VERSION,
        )

    def observed_build_id(self) -> Optional[str]:
        """Server-measured build id, if the frozen identity probe set can
        provide one.  The 8.0 identity variables carry no commit id, so this
        returns ``None`` and preflight records the configured build id with
        source CONFIGURED -- a build id is never fabricated from unrelated
        version strings."""

        return None

    # -- session application with mandatory readback -------------------------

    def apply_session(self, session_settings: Mapping[str, str]) -> dict[str, str]:
        """Apply the caller's session settings in the given order, then read
        every applied setting back and compare.

        Returns the readback map on success; raises :class:`SessionMismatch`
        listing every expected/observed difference, or ``AdapterError`` with
        code ``SESSION_APPLY_FAILED`` when a SET statement errors.  Nothing
        is applied before every name/value passes the strict allowlists.
        """

        self._check_usable()
        if not isinstance(session_settings, Mapping):
            raise AdapterError("apply_session needs a Mapping of session settings")
        validated: list[tuple[str, str]] = []
        for name, value in session_settings.items():
            _validate_session_name(name)
            _validate_session_value(name, value)
            validated.append((name, value))
        if not validated:
            return {}

        for name, value in validated:
            # Both parts are allowlist-validated above: the name admits only
            # identifier characters, the value admits no quote/backslash, so
            # the quoted literal is injection-proof by construction.
            receipt = self.execute_statement(f"SET {name} = '{value}'")
            if receipt.receipt.error is not None:
                error = receipt.receipt.error
                raise AdapterError(
                    f"session SET {name} failed: errno={error.errno} {error.message}",
                    code=SESSION_APPLY_FAILED,
                )

        readback = self._readback_session([name for name, _ in validated])
        mismatches = tuple(
            SessionMismatchEntry(name=name, expected=value, observed=readback[name])
            for name, value in validated
            if readback.get(name) != value
        )
        if mismatches:
            raise SessionMismatch(
                "session readback mismatch for: "
                + ", ".join(entry.name for entry in mismatches)
                + " (fail closed)",
                mismatches=mismatches,
            )
        return {name: readback[name] for name, _ in validated}

    def _readback_session(self, names: list[str]) -> dict[str, str]:
        """SELECT every applied variable back, batched by the frozen
        5-column result budget (names are allowlist-validated identifiers,
        so the interpolation is safe)."""

        readback: dict[str, str] = {}
        for start in range(0, len(names), _IDENTITY_COLUMN_BUDGET):
            chunk = names[start : start + _IDENTITY_COLUMN_BUDGET]
            select = "SELECT " + ", ".join(f"@@{name}" for name in chunk)
            result = self.execute_raw_query(
                select,
                row_budget=_PROBE_ROW_BUDGET,
                byte_budget=_PROBE_BYTE_BUDGET,
            )
            if result.observed_row_count != 1:
                raise AdapterError(
                    f"session readback returned {result.observed_row_count} rows, expected "
                    f"exactly 1 (fail closed)"
                )
            row = result.rows[0]
            if len(row) != len(chunk):
                raise AdapterError(
                    f"session readback returned {len(row)} columns, expected "
                    f"{len(chunk)} (fail closed)"
                )
            for name, cell in zip(chunk, row):
                if cell is None:
                    continue  # absent readback; the mismatch check below fails
                readback[name] = _decode_cell(cell, name)
        return readback

    # -- statement execution with ordinal + timing ---------------------------

    def execute_statement(self, sql: str) -> ExecutedStatement:
        """Execute one non-result statement; diagnostics are collected
        immediately by the shim, timing comes from the injected clock."""

        start = self._clock()
        receipt = super().execute_statement(sql)
        duration_ms = int((self._clock() - start) * 1000)
        self._statement_ordinal += 1
        return ExecutedStatement(
            ordinal=self._statement_ordinal, receipt=receipt, duration_ms=duration_ms
        )

    # -- schema inspection ----------------------------------------------------

    def inspect_schema(
        self,
        database: str,
        *,
        row_budget: int = _execution.MAX_RESULT_ROWS,
        byte_budget: int = _execution.MAX_RESULT_BYTES,
    ) -> SchemaSummary:
        """INFORMATION_SCHEMA tables and columns for one attempt database.

        The database name must match ``^[A-Za-z0-9_]{1,64}$`` before any SQL
        is built; the grammar admits no metacharacters, so the quoted literal
        is equivalent to binding a parameter (the shim's raw-query path takes
        SQL text only).  Anything else is refused, never interpolated.
        """

        self._check_usable()
        if not isinstance(database, str) or _DATABASE_NAME_RE.match(database) is None:
            raise AdapterError(
                f"inspect_schema database name {database!r} does not match the strict "
                f"identifier grammar ^[A-Za-z0-9_]{{1,64}}$ (refused)"
            )
        literal = f"'{database}'"
        tables = self.execute_raw_query(
            "SELECT TABLE_NAME, TABLE_TYPE, ENGINE FROM INFORMATION_SCHEMA.TABLES "
            f"WHERE TABLE_SCHEMA = {literal} ORDER BY TABLE_NAME",
            row_budget=row_budget,
            byte_budget=byte_budget,
            database=database,
        )
        columns = self.execute_raw_query(
            "SELECT TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, DATA_TYPE, COLUMN_TYPE "
            f"FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = {literal} "
            "ORDER BY TABLE_NAME, ORDINAL_POSITION",
            row_budget=row_budget,
            byte_budget=byte_budget,
            database=database,
        )
        return SchemaSummary(database=database, tables=tables, columns=columns)

    # -- cancellation ---------------------------------------------------------

    def cancel_current(self) -> CancelReceipt:
        """Issue ``KILL QUERY <own connection id>`` from the independent
        control connection.

        KILL QUERY cannot be issued on the worker connection's own id, so the
        control connection must have been injected at construction; without
        it this raises ``AdapterError`` with code ``CANCEL_UNSUPPORTED``
        (Phase 5 wires the real control plane).  The receipt is observation
        evidence -- a KILL acknowledgment is not, by itself, termination
        proof (design C01).
        """

        if self._control is None:
            raise AdapterError(
                "cancel_current requires an injected independent control connection "
                "(KILL QUERY cannot target the worker connection itself); Phase 5 "
                "wires the control plane",
                code=CANCEL_UNSUPPORTED,
            )
        conn = self._check_usable()
        connection_id = int(conn.thread_id)
        kill_receipt = self._control.execute_statement(f"KILL QUERY {connection_id}")
        return CancelReceipt(connection_id=connection_id, kill=kill_receipt)

    # -- CleanupExecutor binding (runner.cleanup, design 6.2.3) ---------------

    def execute_ddl(self, sql: str) -> None:
        """Execute one whitelisted cleanup DDL statement (``CleanupExecutor``).

        Only the statement shapes ``runner.cleanup`` builders can produce are
        accepted, and every quoted object name is re-validated through the
        frozen naming validator before any SQL is sent -- anything else is
        refused without touching the server (no prefix scans, no wildcards,
        no free-form DDL on this connection).
        """

        _validate_cleanup_ddl(sql)
        self._check_usable()
        executed = self.execute_statement(sql)
        if executed.receipt.error is not None:
            error = executed.receipt.error
            raise AdapterError(
                f"cleanup DDL failed: errno={error.errno} {error.message}",
                code=CLEANUP_DDL_FAILED,
            )

    def is_database_present(self, name: str) -> bool:
        """Answer whether one validated attempt database still exists
        (``CleanupExecutor`` presence probe via INFORMATION_SCHEMA)."""

        if not isinstance(name, str) or _DATABASE_NAME_RE.match(name) is None:
            raise AdapterError(
                f"presence probe refused database name {name!r}: outside the "
                "strict identifier grammar"
            )
        from ..runner.naming import validate_database_name

        try:
            validate_database_name(name)
        except ContractError as exc:
            raise AdapterError(f"presence probe refused name {name!r}: {exc}") from exc
        # The validator's grammar admits no quoting metacharacters, so the
        # quoted literal is injection-proof by construction.
        result = self.execute_raw_query(
            "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA "
            f"WHERE SCHEMA_NAME = '{name}'",
            row_budget=1,
            byte_budget=_PROBE_BYTE_BUDGET,
        )
        if result.truncated:  # pragma: no cover - a one-row probe cannot truncate
            raise AdapterError(
                f"presence probe for {name!r} truncated (fail closed)"
            )
        return result.observed_row_count == 1


def _validate_session_name(name: object) -> None:
    if not isinstance(name, str) or _SESSION_NAME_RE.match(name) is None:
        raise AdapterError(
            f"session variable name {name!r} does not match the strict identifier "
            f"allowlist (refused)"
        )


def _validate_session_value(name: str, value: object) -> None:
    if not isinstance(value, str) or _SESSION_VALUE_RE.match(value) is None:
        raise AdapterError(
            f"session value for {name!r} does not match the strict value allowlist "
            f"(refused; no unvalidated value is ever interpolated)"
        )


def _validate_cleanup_ddl(sql: object) -> None:
    """Whitelist guard for the ``CleanupExecutor`` DDL binding.

    Accepts exactly the statement shapes ``runner.cleanup`` builds -- the
    marker table DDL, a marker INSERT, DROP TABLE of a validated short table
    inside a validated attempt database, and CREATE/DROP DATABASE of a
    validated attempt database name (the ``runner.naming`` validator is the
    single ownership guard: no prefix scans, no wildcards, no free-form DDL).
    """

    from ..runner.naming import (
        TABLE_A,
        TABLE_B,
        validate_database_name,
        validate_marker_table_name,
    )
    from ..runner.ownership import MARKER_TABLE_DDL

    if not isinstance(sql, str) or not sql:
        raise AdapterError("cleanup DDL must be a non-empty str")

    if sql == MARKER_TABLE_DDL:
        return

    match = _CLEANUP_DROP_TABLE_RE.match(sql)
    if match is not None:
        database, table = match.group(1), match.group(2)
        try:
            validate_database_name(database)
            if table in (TABLE_A, TABLE_B):
                return
            validate_marker_table_name(table)
        except ContractError as exc:
            raise AdapterError(
                f"cleanup DDL refused {sql!r}: {exc}"
            ) from None
        return

    for regex in (_CLEANUP_DROP_DATABASE_RE, _CLEANUP_CREATE_DATABASE_RE):
        match = regex.match(sql)
        if match is not None:
            try:
                validate_database_name(match.group(1))
            except ContractError as exc:
                raise AdapterError(
                    f"cleanup DDL refused {sql!r}: {exc}"
                ) from None
            return

    match = _CLEANUP_MARKER_INSERT_RE.match(sql)
    if match is not None:
        for literal in match.groups():
            if _CLEANUP_LITERAL_RE.match(literal) is None:
                raise AdapterError(
                    f"cleanup marker INSERT refused: literal {literal!r} is "
                    "outside the allowed grammar"
                )
        return

    raise AdapterError(
        f"cleanup DDL refused: {sql[:80]!r} is not a whitelisted cleanup "
        "statement shape"
    )
