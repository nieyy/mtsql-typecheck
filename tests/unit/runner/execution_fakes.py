"""Hand-written fakes for the execution-port tests (Phase 4, no live MySQL).

Scripted, in-memory only.  ``FakeAdapter`` simulates one MySQL 8.0 session
(CREATE/USE/INSERT/DROP ledger on a shared catalog, canned result packets,
per-SQL-substring failure injection); ``InMemoryJournal`` replays the frozen
``OwnershipJournal`` append/hash-chain surface; ``StubClock`` /
``CancelToken`` / ``make_control`` mirror the reduction replay fakes.

Independence rule: no expected value is derived from the code under test.
Result packets are stated per test, payload builders reuse the registered
rule definitions plus the frozen ``derive_relation`` helper (exactly like
``tests/unit/reduction/replay_fakes.py``), and the request's target
environment is built here by an independent inline mapping (the identity of
that mapping is separately cross-checked against ``runner.preflight`` in
``test_facts.py``).
"""

from __future__ import annotations

import re
import uuid as _uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from mtsql_typecheck.adapters.base import AdapterError
from mtsql_typecheck.contracts.case import (
    CasePayload,
    ColumnSpec,
    DecimalType,
    DecimalValue,
    EnvironmentRequirements,
    ExactValue,
    IndexVariant,
    IntegerValue,
    NullValue,
    ObservedEnvironment,
    QuerySpec,
    REQUIRED_SQL_MODE_TOKENS,
    Row,
    Rows,
    RuleRef,
    SemverIdentity,
    SignedIntegerType,
    SignedIntName,
    TableSpec,
    TemplateId,
    TypeSpec,
)
from mtsql_typecheck.contracts.execution import (
    ATTEMPT_BUDGET_MS,
    MAX_RESULT_BYTES,
    AttemptRequest,
    Control,
    ExecutionOrder,
    ResultValue,
    ResultValueKind,
    SessionProfile,
    TransactionIsolation,
)
from mtsql_typecheck.contracts.runner import OwnershipEvent, OwnershipEventKind
from mtsql_typecheck.rules.exact_numeric import derive_relation

__all__ = [
    "SERVER_UUID",
    "BUILD_ID",
    "DEFAULT_FACTS",
    "MAPPING_VERSION",
    "StubClock",
    "CancelToken",
    "make_control",
    "InMemoryJournal",
    "FakeCatalog",
    "FakeControlConnection",
    "FakeAdapter",
    "FakeMappedColumn",
    "FakeErr",
    "make_factory",
    "environment_from_facts",
    "make_payload",
    "readback_rows_for",
    "make_request",
    "int_value",
    "dec_value",
    "null_value",
]

# --------------------------------------------------------------------------
# Clocks / cancellation (same semantics as the reduction replay fakes)
# --------------------------------------------------------------------------


class StubClock:
    """Injectable monotonic clock in whole milliseconds (Control wants seconds)."""

    def __init__(self, now_ms: int = 0) -> None:
        self.now_ms = now_ms

    def advance_ms(self, ms: int) -> None:
        self.now_ms += ms

    def __call__(self) -> float:
        return self.now_ms / 1000


class CancelToken:
    def __init__(self) -> None:
        self.cancelled_flag = False

    def __call__(self) -> bool:
        return self.cancelled_flag


def make_control(
    clock: StubClock,
    cancelled: Optional[Callable[[], bool]] = None,
    deadline_ms: Optional[int] = None,
) -> Control:
    return Control(
        clock=clock,
        deadline=None if deadline_ms is None else clock() + deadline_ms / 1000,
        cancelled=cancelled if cancelled is not None else (lambda: False),
    )


# --------------------------------------------------------------------------
# In-memory ownership journal (same append surface as OwnershipJournal)
# --------------------------------------------------------------------------


class InMemoryJournal:
    """Hash-chained in-memory stand-in for the frozen OwnershipJournal."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.events: List[OwnershipEvent] = []
        self._next_seq = 1
        self._prev_hash = "0" * 64

    def append(
        self,
        event_kind: OwnershipEventKind,
        *,
        attempt_id: Optional[str] = None,
        server_uuid: Optional[str] = None,
        object_name: Optional[str] = None,
        token: Optional[str] = None,
        session_generation: Optional[int] = None,
        connection_id: Optional[str] = None,
    ) -> OwnershipEvent:
        event = OwnershipEvent(
            seq=self._next_seq,
            prev_event_hash=self._prev_hash,
            run_id=self.run_id,
            event_kind=event_kind,
            attempt_id=attempt_id,
            server_uuid=server_uuid,
            object_name=object_name,
            token=token,
            session_generation=session_generation,
            connection_id=connection_id,
        )
        self.events.append(event)
        self._next_seq += 1
        self._prev_hash = event.content_hash
        return event

    def kinds(self, attempt_id: Optional[str] = None) -> List[str]:
        return [
            str(event.event_kind.value)
            for event in self.events
            if attempt_id is None or event.attempt_id == attempt_id
        ]


# --------------------------------------------------------------------------
# Receipt-shaped records (structural matches for the adapter surface)
# --------------------------------------------------------------------------

MAPPING_VERSION = "mysql-text-1"


@dataclass(frozen=True)
class FakeErr:
    errno: int
    sqlstate: Optional[str]
    message: str


@dataclass(frozen=True)
class FakeWarning:
    level: str
    code: str
    sqlstate: Optional[str]
    message: str


@dataclass(frozen=True)
class FakeDiagnostics:
    collected: bool
    complete: bool
    entries: Tuple[FakeWarning, ...] = ()


@dataclass(frozen=True)
class FakeStatementReceipt:
    sql: str
    error: Optional[FakeErr]
    diagnostics: FakeDiagnostics
    affected_rows: Optional[int] = 0
    server_status: Optional[int] = 2
    warning_count: Optional[int] = 0
    has_next: bool = False


@dataclass(frozen=True)
class FakeExecuted:
    ordinal: int
    receipt: FakeStatementReceipt
    duration_ms: int = 0


@dataclass(frozen=True)
class FakeMappedColumn:
    ordinal: int
    alias: str
    type_code: int
    flags: int
    precision: Optional[int] = None
    scale: Optional[int] = None
    charset: int = 33
    length: int = 0
    decimals: int = 0
    mapping_version: str = MAPPING_VERSION


@dataclass(frozen=True)
class FakeFetch:
    columns: Tuple[FakeMappedColumn, ...]
    values: Tuple[Tuple[ResultValue, ...], ...]
    observed_row_count: int
    fetch_complete: bool
    truncated: bool
    extra_result_sets: int
    warning_count: Optional[int]
    encoded_bytes: int = 0


@dataclass(frozen=True)
class FakeRaw:
    database: Optional[str]
    columns: Tuple[FakeMappedColumn, ...]
    rows: Tuple[Tuple[Optional[bytes], ...], ...]
    observed_row_count: int
    fetch_complete: bool
    truncated: bool
    warning_count: Optional[int] = 0


@dataclass(frozen=True)
class FakeCancelReceipt:
    connection_id: int
    kill: FakeStatementReceipt


@dataclass(frozen=True)
class FakeHandle:
    sql: str
    columns: Tuple[FakeMappedColumn, ...]


# --------------------------------------------------------------------------
# Catalog simulation
# --------------------------------------------------------------------------


@dataclass
class FakeDatabase:
    """One simulated attempt database's physical state."""

    column_type: bytes
    index_variant: IndexVariant
    tables: Set[str] = field(default_factory=set)


@dataclass
class FakeCatalog:
    """Shared server state across all fake connections of one test.

    ``readback_rows`` is the canned ``SELECT rid, v ... ORDER BY rid`` answer
    served for any existing attempt database (``readback_override`` overrides
    it per database for load-fidelity failure tests).
    """

    databases: Dict[str, FakeDatabase] = field(default_factory=dict)
    readback_rows: Tuple[Tuple[bytes, Optional[bytes]], ...] = ()
    readback_override: Dict[str, Tuple[Tuple[Optional[bytes], ...], ...]] = field(
        default_factory=dict
    )

    def present(self, name: str) -> bool:
        return name in self.databases


_CREATE_DB_RE = re.compile(r"^CREATE DATABASE `([^`]+)`$")
_USE_RE = re.compile(r"^USE `([^`]+)`$")
_CREATE_TABLE_RE = re.compile(r"^CREATE TABLE `([^`]+)` ")
_INSERT_RE = re.compile(r"^INSERT INTO `([^`]+)` ")
_DROP_TABLE_RE = re.compile(r"^DROP TABLE `([^`]+)`\\.`([^`]+)`$")
_DROP_DB_RE = re.compile(r"^DROP DATABASE `([^`]+)`$")
_SCHEMA_DB_RE = re.compile(r"TABLE_SCHEMA = '([A-Za-z0-9_]+)'")
_SCHEMA_TABLE_RE = re.compile(r"TABLE_NAME = '([A-Za-z0-9_]+)'")
_PRESENT_DB_RE = re.compile(r"SCHEMA_NAME = '([A-Za-z0-9_]+)'")
_VARIABLE_RE = re.compile(r"@@([A-Za-z_][A-Za-z0-9_]*)")

_ERR_DB_EXISTS = 1007
_ERR_DB_DROP_MISSING = 1008
_ERR_NO_DB_SELECTED = 1046
_ERR_UNKNOWN_DATABASE = 1049
_ERR_TABLE_EXISTS = 1050
_ERR_TABLE_DROP_MISSING = 1051
_ERR_NO_SUCH_TABLE = 1146

_MARKER_TABLE = "tc_ownership_marker"


class FakeControlConnection:
    """The independent control-plane connection used for KILL QUERY."""

    def __init__(
        self, *, sql_log: Optional[List[str]] = None, kill_error: bool = False
    ) -> None:
        self.sql_log = sql_log if sql_log is not None else []
        self.kill_error = kill_error
        self.statements: List[str] = []

    def execute_statement(self, sql: str) -> FakeStatementReceipt:
        self.sql_log.append(sql)
        self.statements.append(sql)
        if self.kill_error:
            return FakeStatementReceipt(
                sql=sql,
                error=FakeErr(1094, "HY000", "unknown thread id"),
                diagnostics=FakeDiagnostics(collected=True, complete=False),
                warning_count=None,
            )
        return FakeStatementReceipt(
            sql=sql, error=None, diagnostics=FakeDiagnostics(collected=True, complete=True)
        )


class FakeAdapter:
    """One scripted connection: DDL ledger, catalog effects, canned results.

    Failure injection is per-SQL substring:

    - ``fail`` raises the mapped exception at statement execution time;
    - ``statement_errors`` makes a DDL/INSERT report a server error packet;
    - ``select_errors`` raises from ``open_query``;
    - ``session_error`` raises from ``apply_session``;
    - ``facts_sequence`` feeds successive ``fetch_environment_facts`` answers
      (environment-drift injection; when exhausted the base ``facts`` return).
    """

    def __init__(
        self,
        *,
        catalog: FakeCatalog,
        connection_id: int,
        facts: Mapping[str, str],
        column_type: bytes = b"tinyint",
        index_variant: IndexVariant = IndexVariant.NONE,
        sql_log: Optional[List[str]] = None,
        fail: Optional[Dict[str, Exception]] = None,
        statement_errors: Optional[Dict[str, FakeErr]] = None,
        select_errors: Optional[Dict[str, Exception]] = None,
        select_columns: Tuple[FakeMappedColumn, ...] = (),
        default_result: Tuple[Tuple[ResultValue, ...], ...] = (),
        fetch_truncated: bool = False,
        extra_result_sets: int = 0,
        warning_count: Optional[int] = 0,
        warning_rows: Tuple[Tuple[bytes, bytes, bytes], ...] = (),
        facts_sequence: Optional[List[Dict[str, str]]] = None,
        session_error: Optional[Exception] = None,
        readback_truncated: bool = False,
        on_fetch: Optional[Callable[[], None]] = None,
        control: Optional[FakeControlConnection] = None,
        connect_error: Optional[Exception] = None,
    ) -> None:
        self.catalog = catalog
        self._connection_id = connection_id
        self.facts = dict(facts)
        self.column_type = column_type
        self.index_variant = index_variant
        self.sql_log = sql_log if sql_log is not None else []
        self.fail = fail or {}
        self.statement_errors = statement_errors or {}
        self.select_errors = select_errors or {}
        self.select_columns = select_columns
        self.default_result = default_result
        self.fetch_truncated = fetch_truncated
        self.extra_result_sets = extra_result_sets
        self.warning_count = warning_count
        self.warning_rows = warning_rows
        self.facts_sequence = facts_sequence or []
        self.session_error = session_error
        self.readback_truncated = readback_truncated
        self.on_fetch = on_fetch
        self.control = control
        self.connect_error = connect_error
        self.current_database: Optional[str] = None
        self.applied_session: Dict[str, str] = {}
        self.statement_ordinal = 0
        self.closed = False
        self.session_calls: List[Dict[str, str]] = []

    # -- identity / probing ---------------------------------------------------

    def connect_and_probe(self) -> Dict[str, str]:
        self.sql_log.append("-- connect")
        if self.connect_error is not None:
            raise self.connect_error
        return dict(self.facts)

    def fetch_environment_facts(self) -> Dict[str, str]:
        if self.facts_sequence:
            return dict(self.facts_sequence.pop(0))
        return dict(self.facts)

    def connection_id(self) -> int:
        return self._connection_id

    def close(self) -> None:
        self.closed = True

    # -- session --------------------------------------------------------------

    def apply_session(self, session_settings: Mapping[str, str]) -> Dict[str, str]:
        self.session_calls.append(dict(session_settings))
        if self.session_error is not None:
            raise self.session_error
        for name, value in session_settings.items():
            self.sql_log.append(f"SET {name} = '{value}'")
        self.applied_session.update(session_settings)
        return dict(session_settings)

    # -- statements -----------------------------------------------------------

    def execute_statement(self, sql: str) -> FakeExecuted:
        self.sql_log.append(sql)
        self.statement_ordinal += 1
        for substring, exception in self.fail.items():
            if substring in sql:
                raise exception
        error: Optional[FakeErr] = None
        for substring, packet in self.statement_errors.items():
            if substring in sql:
                error = packet
                break
        if error is None:
            error = self._apply_statement(sql)
        if error is not None:
            receipt = FakeStatementReceipt(
                sql=sql,
                error=error,
                diagnostics=FakeDiagnostics(
                    collected=True,
                    complete=False,
                    entries=(
                        FakeWarning("ERROR", str(error.errno), error.sqlstate, error.message),
                    ),
                ),
                warning_count=None,
            )
        else:
            receipt = FakeStatementReceipt(
                sql=sql,
                error=None,
                diagnostics=FakeDiagnostics(collected=True, complete=True),
            )
        return FakeExecuted(ordinal=self.statement_ordinal, receipt=receipt)

    def _apply_statement(self, sql: str) -> Optional[FakeErr]:
        match = _CREATE_DB_RE.match(sql)
        if match is not None:
            name = match.group(1)
            if self.catalog.present(name):
                return FakeErr(_ERR_DB_EXISTS, "HY000", f"database {name} exists")
            self.catalog.databases[name] = FakeDatabase(
                column_type=self.column_type, index_variant=self.index_variant
            )
            return None
        match = _USE_RE.match(sql)
        if match is not None:
            name = match.group(1)
            if not self.catalog.present(name):
                return FakeErr(_ERR_UNKNOWN_DATABASE, "HY000", f"unknown database {name}")
            self.current_database = name
            return None
        match = _CREATE_TABLE_RE.match(sql)
        if match is not None:
            state = self.catalog.databases.get(self.current_database or "")
            if state is None:
                return FakeErr(_ERR_NO_DB_SELECTED, "3D000", "no database selected")
            name = match.group(1)
            if name in state.tables:
                return FakeErr(_ERR_TABLE_EXISTS, "42S01", f"table {name} exists")
            state.tables.add(name)
            return None
        match = _INSERT_RE.match(sql)
        if match is not None:
            state = self.catalog.databases.get(self.current_database or "")
            if state is None or match.group(1) not in state.tables:
                return FakeErr(_ERR_NO_SUCH_TABLE, "42S02", "table missing")
            return None
        match = _DROP_TABLE_RE.match(sql)
        if match is not None:
            database, table = match.group(1), match.group(2)
            state = self.catalog.databases.get(database)
            if state is None or table not in state.tables:
                return FakeErr(_ERR_TABLE_DROP_MISSING, "42S02", "unknown table")
            state.tables.discard(table)
            return None
        match = _DROP_DB_RE.match(sql)
        if match is not None:
            name = match.group(1)
            if not self.catalog.present(name):
                return FakeErr(_ERR_DB_DROP_MISSING, "HY000", "database does not exist")
            del self.catalog.databases[name]
            if self.current_database == name:
                self.current_database = None
            return None
        return None

    # -- raw queries ----------------------------------------------------------

    def execute_raw_query(
        self,
        sql: str,
        *,
        row_budget: int,
        byte_budget: int,
        database: Optional[str] = None,
    ) -> FakeRaw:
        self.sql_log.append(sql)
        for substring, exception in self.fail.items():
            if substring in sql:
                raise exception
        if "INFORMATION_SCHEMA.SCHEMATA" in sql:
            match = _PRESENT_DB_RE.search(sql)
            name = match.group(1) if match else ""
            rows: Tuple[Tuple[Optional[bytes], ...], ...] = (
                ((name.encode(),),) if self.catalog.present(name) else ()
            )
            return self._raw(rows, database, truncated=False)
        if "INFORMATION_SCHEMA.TABLES" in sql:
            return self._raw(self._schema_tables_rows(sql), database, truncated=False)
        if "INFORMATION_SCHEMA.COLUMNS" in sql:
            return self._raw(self._schema_columns_rows(sql), database, truncated=False)
        if "INFORMATION_SCHEMA.STATISTICS" in sql:
            return self._raw(self._schema_statistics_rows(sql), database, truncated=False)
        if "SHOW WARNINGS" in sql:
            return self._raw(self.warning_rows, database, truncated=False)
        if "`rid`, `v` FROM" in sql:
            source = self.current_database or database or ""
            rows = self.catalog.readback_override.get(
                source,
                tuple(tuple(row) for row in self.catalog.readback_rows),
            )
            return self._raw(rows, database, truncated=self.readback_truncated)
        if "@@" in sql:
            names = _VARIABLE_RE.findall(sql)
            facts = self.fetch_environment_facts()
            rows = (tuple((facts.get(name) or "").encode() or None for name in names),)
            return self._raw(rows, database, truncated=False)
        raise AssertionError(f"fake adapter cannot answer raw query: {sql!r}")

    def _raw(self, rows, database: Optional[str], *, truncated: bool) -> FakeRaw:
        return FakeRaw(
            database=database,
            columns=(),
            rows=tuple(rows),
            observed_row_count=len(rows),
            fetch_complete=not truncated,
            truncated=truncated,
        )

    def _schema_targets(self, sql: str) -> Tuple[str, str]:
        db_match = _SCHEMA_DB_RE.search(sql)
        table_match = _SCHEMA_TABLE_RE.search(sql)
        return (
            db_match.group(1) if db_match else "",
            table_match.group(1) if table_match else "",
        )

    def _schema_tables_rows(self, sql: str) -> Tuple[Tuple[Optional[bytes], ...], ...]:
        database, table = self._schema_targets(sql)
        state = self.catalog.databases.get(database)
        if state is not None and table in state.tables:
            return ((table.encode(), b"BASE TABLE", b"InnoDB"),)
        return ()

    def _schema_columns_rows(self, sql: str) -> Tuple[Tuple[Optional[bytes], ...], ...]:
        database, table = self._schema_targets(sql)
        state = self.catalog.databases.get(database)
        if state is None or table not in state.tables:
            return ()
        return (
            (b"rid", b"bigint", b"NO", b"PRI", b"1"),
            (b"v", state.column_type, b"YES", b"", b"2"),
        )

    def _schema_statistics_rows(self, sql: str) -> Tuple[Tuple[Optional[bytes], ...], ...]:
        database, table = self._schema_targets(sql)
        state = self.catalog.databases.get(database)
        if (
            state is not None
            and table in state.tables
            and state.index_variant is IndexVariant.IX_V
        ):
            return ((b"ix_v", b"1", b"v"),)
        return ()

    # -- result sets ----------------------------------------------------------

    def open_query(self, sql: str) -> FakeHandle:
        self.sql_log.append(sql)
        for substring, exception in self.select_errors.items():
            if substring in sql:
                raise exception
        return FakeHandle(sql=sql, columns=self.select_columns)

    def fetch_result(
        self, handle: FakeHandle, *, row_budget: int, byte_budget: int
    ) -> FakeFetch:
        if self.on_fetch is not None:
            self.on_fetch()
        values = self.default_result
        truncated = self.fetch_truncated or len(values) > row_budget
        if truncated:
            values = values[:row_budget]
        return FakeFetch(
            columns=handle.columns,
            values=tuple(values),
            observed_row_count=len(values),
            fetch_complete=not truncated,
            truncated=truncated,
            extra_result_sets=self.extra_result_sets,
            warning_count=self.warning_count,
        )

    # -- cancellation ---------------------------------------------------------

    def cancel_current(self) -> FakeCancelReceipt:
        if self.control is None:
            raise AdapterError(
                "fake adapter has no independent control connection "
                "(KILL QUERY cannot target its own id)",
                code="CANCEL_UNSUPPORTED",
            )
        kill = self.control.execute_statement(f"KILL QUERY {self._connection_id}")
        return FakeCancelReceipt(connection_id=self._connection_id, kill=kill)


def make_factory(*adapters: FakeAdapter) -> Callable[[], FakeAdapter]:
    """Adapter factory serving the scripted adapters in connection order."""

    queue = list(adapters)

    def factory() -> FakeAdapter:
        if not queue:
            raise AssertionError("adapter factory exhausted: unexpected connection")
        return queue.pop(0)

    return factory


# --------------------------------------------------------------------------
# Environment / payload / request builders
# --------------------------------------------------------------------------

SERVER_UUID = "01234567-89ab-cdef-0123-456789abcdef"
BUILD_ID = "20250715"

DEFAULT_FACTS: Dict[str, str] = {
    "server_uuid": SERVER_UUID,
    "version": "8.0.39",
    "version_comment": "mysql",
    "sql_mode": "NO_ENGINE_SUBSTITUTION,ONLY_FULL_GROUP_BY,STRICT_ALL_TABLES",
    "character_set_server": "utf8mb4",
    "character_set_connection": "utf8mb4",
    "collation_server": "utf8mb4_bin",
    "collation_connection": "utf8mb4_bin",
    "time_zone": "+00:00",
    "system_time_zone": "UTC",
    "innodb_version": "8.0.39",
    "optimizer_switch": "index_merge=on,mrr=off",
    "sql_notes": "on",
}


def environment_from_facts(
    facts: Mapping[str, str], *, build_id: str
) -> ObservedEnvironment:
    """Independent environment-snapshot builder (no port or facts imports)."""
    return ObservedEnvironment(
        instance_identity=str(_uuid.UUID(facts["server_uuid"])),
        version=facts.get("version", ""),
        vendor=facts.get("version_comment", ""),
        build_id=build_id,
        engine="innodb" if facts.get("innodb_version") else "",
        sql_mode_tokens=tuple(
            sorted(
                {
                    token.strip()
                    for token in (facts.get("sql_mode") or "").split(",")
                    if token.strip()
                }
            )
        ),
        character_set=facts.get("character_set_connection", ""),
        collation=facts.get("collation_connection", ""),
        time_zone=facts.get("time_zone", ""),
        optimizer_switch=facts.get("optimizer_switch", ""),
    )


def _canonical_text(value: ExactValue) -> Optional[bytes]:
    """Exact canonical text the text-protocol server sends for one value."""
    if isinstance(value, NullValue):
        return None
    if isinstance(value, IntegerValue):
        return str(value.value).encode()
    if isinstance(value, DecimalValue):
        sign = "-" if value.coefficient < 0 else ""
        digits = str(abs(value.coefficient)).rjust(value.scale + 1, "0")
        if value.scale == 0:
            return f"{sign}{digits}".encode()
        return f"{sign}{digits[:-value.scale]}.{digits[-value.scale:]}".encode()
    raise AssertionError(f"unexpected exact value kind {type(value).__name__}")


def make_payload(
    *,
    decimal: bool = False,
    row_values: Sequence[ExactValue],
    index_variant: IndexVariant = IndexVariant.NONE,
) -> CasePayload:
    """Signed-widen TINYINT->SMALLINT (or decimal-widen 9,2->18,2) payload."""
    a_type: TypeSpec
    b_type: TypeSpec
    if decimal:
        a_type = DecimalType(9, 2)
        b_type = DecimalType(18, 2)
        rule_ref = RuleRef("mysql80.decimal-widen", 1)
    else:
        a_type = SignedIntegerType(SignedIntName.TINYINT)
        b_type = SignedIntegerType(SignedIntName.SMALLINT)
        rule_ref = RuleRef("mysql80.signed-widen", 1)
    table = TableSpec(
        "t0",
        (
            ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
            ColumnSpec("v", a_type, True),
        ),
        ("rid",),
        index_variant,
    )
    return CasePayload(
        rule=rule_ref,
        a_type=a_type,
        b_type=b_type,
        table=table,
        rows=Rows(tuple(Row(i + 1, value) for i, value in enumerate(row_values))),
        query=QuerySpec(TemplateId.Q1),
        relation=derive_relation(rule_ref, a_type, b_type, TemplateId.Q1),
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


def readback_rows_for(payload: CasePayload) -> Tuple[Tuple[bytes, Optional[bytes]], ...]:
    """Raw readback cells exactly representing the payload's declared rows."""
    return tuple(
        (str(row.rid).encode(), _canonical_text(row.value)) for row in payload.rows.rows
    )


def make_request(
    payload: CasePayload,
    *,
    attempt_id: str,
    run_id: str = "run-exec-1",
    execution_order: ExecutionOrder = ExecutionOrder.AB,
    session_profile: Optional[SessionProfile] = None,
    result_row_budget: int = 1024,
    time_budget_ms: int = ATTEMPT_BUDGET_MS,
    target_environment: Optional[ObservedEnvironment] = None,
) -> AttemptRequest:
    return AttemptRequest(
        run_id=run_id,
        attempt_id=attempt_id,
        payload=payload,
        target_environment=(
            target_environment
            if target_environment is not None
            else environment_from_facts(DEFAULT_FACTS, build_id=BUILD_ID)
        ),
        session_profile=(
            session_profile
            if session_profile is not None
            else SessionProfile(True, TransactionIsolation.REPEATABLE_READ)
        ),
        execution_order=execution_order,
        result_row_budget=result_row_budget,
        result_byte_budget=MAX_RESULT_BYTES,
        time_budget_ms=time_budget_ms,
        synthetic=True,
    )


# Result-value shorthand used by the tests to state canned SELECT packets.
def int_value(v: int) -> ResultValue:
    return ResultValue(ResultValueKind.INTEGER, int_value=v)


def dec_value(coefficient: int, scale: int) -> ResultValue:
    return ResultValue(ResultValueKind.DECIMAL, coefficient=coefficient, scale=scale)


def null_value() -> ResultValue:
    return ResultValue(ResultValueKind.NULL)
