"""Unit tests for the MySQL 8.0 adapter (D3 Phase 2) -- no live server.

Every database interaction runs against a scripted fake connection that
speaks just enough of the PyMySQL cursor surface (execute / description /
_result / read_next / fetchmany) for the shim paths used by
``MySQL80Adapter``.  Live-server behaviour is NOT_RUN here; the protocol
level is covered by the shim fixtures.
"""

from __future__ import annotations

import pytest
import pymysql.err

from mtsql_typecheck.adapters.base import AdapterError, ConnectionParams
from mtsql_typecheck.adapters.mysql80 import (
    ADAPTER_VERSION,
    CANCEL_UNSUPPORTED,
    IDENTITY_INCOMPLETE,
    SESSION_APPLY_FAILED,
    MySQL80Adapter,
    SessionMismatch,
)
from mtsql_typecheck.adapters.mysql_protocol import (
    MAPPING_VERSION,
    DiagnosticsRecord,
    ErrPacketInfo,
    StatementReceipt,
)

PARAMS = ConnectionParams(
    host="mysql-test.example.internal", port=3306, user="typecheck", password="pw"
)

# Canonical fake identity row (values are raw wire bytes).  Key order fixes
# the SELECT column order used by the responses below.
IDENTITY_ROW = {
    "server_uuid": b"3f0a41c2-6b1e-11ef-9d3a-0242ac110002",
    "version": b"8.0.39",
    "version_comment": b"MySQL Community Server - GPL",
    "sql_mode": b"NO_ENGINE_SUBSTITUTION,ONLY_FULL_GROUP_BY,STRICT_ALL_TABLES",
    "character_set_server": b"utf8mb4",
    "character_set_connection": b"utf8mb4",
    "collation_server": b"utf8mb4_bin",
    "collation_connection": b"utf8mb4_bin",
    "time_zone": b"+00:00",
    "system_time_zone": b"UTC",
    "innodb_version": b"8.0.39",
    "sql_notes": b"1",
    "optimizer_switch": b"index_merge=on",
}


class FakeField:
    """Minimal FieldDescriptorPacket surface for extract_field_metadata."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.table_name = ""
        self.type_code = 253  # VAR_STRING; the raw path never decodes
        self.flags = 0
        self.scale = 0
        self.length = 128
        self.charsetnr = 45


class FakeResult:
    def __init__(self, fields, warning_count: int = 0) -> None:
        self.fields = fields
        self.warning_count = warning_count
        self.affected_rows = 0
        self.server_status = 2
        self.has_next = 0


class FakeCursor:
    def __init__(self, conn: "FakeConnection") -> None:
        self.conn = conn
        self.description = None
        self._result = None
        self._pending: list = []

    def execute(self, sql: str) -> None:
        self.conn.executed.append(sql)
        response = self.conn.next_response(sql)
        if isinstance(response, Exception):
            raise response
        fields, rows, warning_count = response
        self._result = FakeResult(fields=fields, warning_count=warning_count)
        self._pending = list(rows)
        if fields is not None:
            self.description = tuple((f.name,) + (None,) * 6 for f in fields)

    def fetchmany(self, size: int = 1):
        out, self._pending = self._pending[:size], self._pending[size:]
        return out

    def read_next(self):
        if not self._pending:
            return None
        return self._pending.pop(0)


class FakeConnection:
    """Scripted connection: each non-SHOW-WARNINGS statement pops the next
    response; SHOW WARNINGS always returns no rows."""

    def __init__(self, responses=None, thread_id: int = 42) -> None:
        self.executed: list[str] = []
        self.thread_id = thread_id
        self._responses = list(responses or [])
        self._result = None  # shim's _mark_unusable observes this attribute

    def cursor(self, cursor_class=None) -> FakeCursor:
        return FakeCursor(self)

    def next_response(self, sql: str):
        if sql == "SHOW WARNINGS":
            return (None, [], 0)
        if not self._responses:
            raise AssertionError(f"unexpected SQL executed: {sql}")
        return self._responses.pop(0)


def make_adapter(responses=None, thread_id: int = 42, **kwargs):
    """Adapter with a scripted connection attached (no live connect)."""

    adapter = MySQL80Adapter(PARAMS, charset="utf8mb4", **kwargs)
    fake = FakeConnection(responses=responses, thread_id=thread_id)
    adapter._conn = fake  # noqa: SLF001 - test-double injection
    adapter._usable = True
    adapter._driver_version = "1.1.2"
    return adapter, fake


#: The shim enforces the frozen MAX_RESULT_COLUMNS = 5 budget per result set,
#: so the adapter reads the identity facts through batched constant SELECTs.
IDENTITY_FACT_NAMES = list(IDENTITY_ROW)
COLUMN_BUDGET = 5
IDENTITY_SELECTS = [
    "SELECT " + ", ".join(f"@@{n}" for n in IDENTITY_FACT_NAMES[i : i + COLUMN_BUDGET])
    for i in range(0, len(IDENTITY_FACT_NAMES), COLUMN_BUDGET)
]


def identity_responses(overrides: dict | None = None, nulls: set[str] | None = None):
    """Scripted responses for the batched identity SELECTs."""

    row = dict(IDENTITY_ROW)
    for key in nulls or ():
        row[key] = None
    for key, value in (overrides or {}).items():
        row[key] = value
    responses = []
    for start in range(0, len(IDENTITY_FACT_NAMES), COLUMN_BUDGET):
        names = IDENTITY_FACT_NAMES[start : start + COLUMN_BUDGET]
        fields = [FakeField(f"@@{name}") for name in names]
        responses.append((fields, [tuple(row[name] for name in names)], 0))
    return responses


def readback_response(values: dict[str, bytes]):
    fields = [FakeField(f"@@{name}") for name in values]
    return (fields, [tuple(values.values())], 0)


def ok_statement():
    return (None, [], 0)


def kill_receipt(sql: str = "KILL QUERY 42") -> StatementReceipt:
    return StatementReceipt(
        sql=sql,
        affected_rows=0,
        server_status=2,
        warning_count=0,
        has_next=False,
        error=None,
        diagnostics=DiagnosticsRecord.not_collected(),
    )


class FakeControl:
    def __init__(self) -> None:
        self.executed: list[str] = []

    def execute_statement(self, sql: str) -> StatementReceipt:
        self.executed.append(sql)
        return kill_receipt(sql)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_construction_requires_explicit_charset():
    with pytest.raises(TypeError):
        MySQL80Adapter(PARAMS)


def test_construction_records_charset_and_identity():
    adapter, _ = make_adapter()
    assert adapter._charset == "utf8mb4"
    assert ADAPTER_VERSION == "mysql80-adapter-v1"
    assert adapter.observed_build_id() is None


# ---------------------------------------------------------------------------
# Identity probe
# ---------------------------------------------------------------------------


def test_identity_probe_uses_fixed_constant_batched_selects():
    adapter, fake = make_adapter(responses=identity_responses())
    facts = adapter.fetch_environment_facts()
    assert facts["server_uuid"] == IDENTITY_ROW["server_uuid"].decode()
    assert facts["sql_mode"] == IDENTITY_ROW["sql_mode"].decode()
    # Every fact is read exactly once, through the fixed constant SELECT
    # batch (at most MAX_RESULT_COLUMNS = 5 columns per round trip).
    assert fake.executed == IDENTITY_SELECTS


def test_identity_probe_null_fact_is_absent_not_empty():
    adapter, _ = make_adapter(responses=identity_responses(nulls={"system_time_zone"}))
    facts = adapter.fetch_environment_facts()
    assert "system_time_zone" not in facts
    assert facts["time_zone"] == "+00:00"


def test_connect_and_probe_fails_closed_on_missing_required_fact():
    adapter, fake = make_adapter(responses=identity_responses(nulls={"sql_mode"}))
    with pytest.raises(AdapterError) as excinfo:
        adapter.connect_and_probe()
    assert excinfo.value.code == IDENTITY_INCOMPLETE
    # The failed probe is still exactly the fixed constant batch; no session
    # SQL ran.
    assert fake.executed == IDENTITY_SELECTS


def test_connect_and_probe_fails_closed_on_empty_required_fact():
    adapter, _ = make_adapter(
        responses=identity_responses(overrides={"time_zone": b""})
    )
    with pytest.raises(AdapterError) as excinfo:
        adapter.connect_and_probe()
    assert excinfo.value.code == IDENTITY_INCOMPLETE


def test_connect_and_probe_accepts_unreadable_optional_fact():
    adapter, _ = make_adapter(responses=identity_responses(nulls={"version_comment"}))
    facts = adapter.connect_and_probe()
    assert "version_comment" not in facts
    assert facts["server_uuid"].startswith("3f0a41c2")


def test_connect_and_probe_caches_for_the_probe_source():
    adapter, fake = make_adapter(responses=identity_responses())
    adapter.connect_and_probe()
    assert adapter.fetch_environment_facts()["version"] == "8.0.39"
    assert fake.executed == IDENTITY_SELECTS  # facts cached, no re-read


def test_runtime_identity_reports_certified_versions():
    adapter, _ = make_adapter()
    identity = adapter.runtime_identity()
    assert identity.driver_name == "pymysql"
    assert identity.driver_version == "1.1.2"
    assert identity.adapter_version == ADAPTER_VERSION
    assert identity.mapping_version == MAPPING_VERSION


# ---------------------------------------------------------------------------
# apply_session: SET one at a time, mandatory readback
# ---------------------------------------------------------------------------


def test_apply_session_issues_set_then_readback_in_order():
    adapter, fake = make_adapter(
        responses=[
            ok_statement(),
            ok_statement(),
            readback_response({"autocommit": b"1", "time_zone": b"+00:00"}),
        ]
    )
    readback = adapter.apply_session({"autocommit": "1", "time_zone": "+00:00"})
    assert readback == {"autocommit": "1", "time_zone": "+00:00"}
    statements = [sql for sql in fake.executed if sql != "SHOW WARNINGS"]
    assert statements[0] == "SET autocommit = '1'"
    assert statements[1] == "SET time_zone = '+00:00'"
    # Diagnostics run immediately after each SET, before the readback SELECT.
    assert fake.executed[1] == "SHOW WARNINGS"
    assert fake.executed[3] == "SHOW WARNINGS"
    assert statements[2] == "SELECT @@autocommit, @@time_zone"


def test_apply_session_set_error_fails_typed():
    adapter, _ = make_adapter(
        responses=[pymysql.err.OperationalError(1227, "Access denied")]
    )
    with pytest.raises(AdapterError) as excinfo:
        adapter.apply_session({"sql_mode": "STRICT_ALL_TABLES"})
    assert excinfo.value.code == SESSION_APPLY_FAILED


def test_apply_session_readback_mismatch_raises_typed():
    adapter, _ = make_adapter(
        responses=[ok_statement(), readback_response({"autocommit": b"0"})]
    )
    with pytest.raises(SessionMismatch) as excinfo:
        adapter.apply_session({"autocommit": "1"})
    entry = excinfo.value.mismatches[0]
    assert entry.name == "autocommit"
    assert entry.expected == "1"
    assert entry.observed == "0"
    assert excinfo.value.code == "SESSION_MISMATCH"


def test_apply_session_empty_settings_is_a_no_op():
    adapter, fake = make_adapter()
    assert adapter.apply_session({}) == {}
    assert fake.executed == []


@pytest.mark.parametrize(
    "name,value",
    [
        ("autocommit", "1; DROP DATABASE tc_x"),
        ("autocommit", "1' OR '1'='1"),
        ("autocommit", "1\\"),
        ("autocommit", "unconfirmed value"),
        ("autocommit", 1),
        ("autocommit", None),
        ("autocommit; SET x=1", "1"),
        ("1autocommit", "1"),
        ("aut'ocommit", "1"),
        ("autocommit--", "1"),
    ],
)
def test_apply_session_rejects_values_outside_the_strict_allowlist(name, value):
    adapter, fake = make_adapter()
    with pytest.raises(AdapterError):
        adapter.apply_session({name: value})
    assert fake.executed == []  # nothing was sent before validation


# ---------------------------------------------------------------------------
# Statement execution receipt (ordinal + injected clock)
# ---------------------------------------------------------------------------


def test_execute_statement_wraps_receipt_with_ordinal_and_clock():
    ticks = iter([100.0, 100.25])

    class FakeClock:
        def __call__(self) -> float:
            return next(ticks)

    adapter, fake = make_adapter(responses=[ok_statement()], clock=FakeClock())
    executed = adapter.execute_statement("SET autocommit = '1'")
    assert executed.ordinal == 1
    assert executed.duration_ms == 250
    assert executed.receipt.sql == "SET autocommit = '1'"
    assert executed.receipt.error is None
    assert fake.executed == ["SET autocommit = '1'", "SHOW WARNINGS"]


# ---------------------------------------------------------------------------
# inspect_schema (INFORMATION_SCHEMA, strict identifier grammar)
# ---------------------------------------------------------------------------


def test_inspect_schema_queries_tables_and_columns():
    table_fields = [FakeField("TABLE_NAME"), FakeField("TABLE_TYPE"), FakeField("ENGINE")]
    column_fields = [
        FakeField("TABLE_NAME"),
        FakeField("COLUMN_NAME"),
        FakeField("ORDINAL_POSITION"),
        FakeField("DATA_TYPE"),
        FakeField("COLUMN_TYPE"),
    ]
    adapter, fake = make_adapter(
        responses=[
            (table_fields, [(b"t_a", b"BASE TABLE", b"InnoDB")], 0),
            (
                column_fields,
                [(b"t_a", b"c1", b"1", b"decimal", b"decimal(10,2)")],
                0,
            ),
        ]
    )
    summary = adapter.inspect_schema("tc_attempt_a")
    assert summary.database == "tc_attempt_a"
    assert summary.tables.rows == ((b"t_a", b"BASE TABLE", b"InnoDB"),)
    assert "WHERE TABLE_SCHEMA = 'tc_attempt_a'" in fake.executed[0]
    assert "INFORMATION_SCHEMA.TABLES" in fake.executed[0]
    assert "INFORMATION_SCHEMA.COLUMNS" in fake.executed[1]


@pytest.mark.parametrize("database", ["", "tc_x; DROP DATABASE x", "tc-x", "a" * 65])
def test_inspect_schema_refuses_names_outside_the_identifier_grammar(database):
    adapter, fake = make_adapter()
    with pytest.raises(AdapterError):
        adapter.inspect_schema(database)
    assert fake.executed == []


# ---------------------------------------------------------------------------
# cancel_current
# ---------------------------------------------------------------------------


def test_cancel_current_without_control_connection_is_unsupported():
    adapter, _ = make_adapter()
    with pytest.raises(AdapterError) as excinfo:
        adapter.cancel_current()
    assert excinfo.value.code == CANCEL_UNSUPPORTED


def test_cancel_current_kills_own_connection_id_from_control():
    control = FakeControl()
    adapter, fake = make_adapter(thread_id=4242, control=control)
    receipt = adapter.cancel_current()
    assert receipt.connection_id == 4242
    assert control.executed == ["KILL QUERY 4242"]
    assert receipt.kill.sql == "KILL QUERY 4242"
    assert not any("KILL" in sql for sql in fake.executed)  # worker never self-kills


def test_cancel_current_kill_error_is_carried_not_swallowed():
    class FailingControl:
        def execute_statement(self, sql: str) -> StatementReceipt:
            return StatementReceipt(
                sql=sql,
                affected_rows=None,
                server_status=None,
                warning_count=None,
                has_next=False,
                error=ErrPacketInfo(errno=1094, sqlstate=None, message="Unknown thread id"),
                diagnostics=DiagnosticsRecord.not_collected(),
            )

    adapter, _ = make_adapter(thread_id=7, control=FailingControl())
    receipt = adapter.cancel_current()
    assert receipt.kill.error is not None
    assert receipt.kill.error.errno == 1094


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


def test_close_is_idempotent_and_safe_after_unusable_marking():
    close_calls = []

    adapter, fake = make_adapter()

    def record_close(*args, **kwargs) -> None:
        close_calls.append(1)

    fake.close = record_close  # type: ignore[method-assign]
    adapter._mark_unusable()
    adapter.close()
    adapter.close()
    assert len(close_calls) == 1
