"""Diagnostics capture: packet count extraction and SHOW WARNINGS
reconciliation (design 6.4.3 [R6]; negatives P02/P03).

All inputs are SYNTHETIC (tests/contract/fixtures/mysql112/); no connection
is opened.
"""

from __future__ import annotations

import pytest

from mtsql_typecheck.adapters import mysql_protocol as mp
from mtsql_typecheck.adapters.base import ConnectionParams, ResultContractViolation
from mtsql_typecheck.adapters.mysql_protocol import PyMySQLAdapter

from _helpers import load_fixture, read_message_bytes

# --------------------------------------------------------------------------
# Terminating packet parsing (P02: only the final count is authoritative)
# --------------------------------------------------------------------------


def test_fixture_ok_packet_with_warning_count():
    stream, doc = load_fixture("ok_warning_count")
    info = mp.parse_ok_packet(read_message_bytes(stream))
    assert info.warning_count == doc["expected"]["warning_count"]
    assert info.affected_rows == doc["expected"]["affected_rows"]
    assert info.server_status == doc["expected"]["server_status"]
    assert info.has_next is False


def test_fixture_err_packet_keeps_errno_and_sqlstate():
    stream, doc = load_fixture("err_sqlstate")
    info = mp.parse_err_packet(read_message_bytes(stream))
    assert info.errno == doc["expected"]["errno"]
    assert info.sqlstate == doc["expected"]["sqlstate"]
    assert info.message == doc["expected"]["message"]


def test_err_without_sqlstate_marker_keeps_none():
    # Pre-4.1 style ERR: no '#' marker -> sqlstate stays None, never guessed.
    payload = b"\xff\x1d\x04" + b"Access denied"
    info = mp.parse_err_packet(payload)
    assert info.errno == 0x041D
    assert info.sqlstate is None
    assert info.message == "Access denied"


def test_err_with_non_ascii_sqlstate_fails_closed():
    payload = b"\xff\x1d\x04#\xff\xfe\xfd\xfc\xfb" + b"msg"
    with pytest.raises(ResultContractViolation):
        mp.parse_err_packet(payload)


def test_column_definition_eof_count_is_not_the_final_count():
    # P02: the column-definition EOF carries its own (smaller) count; the
    # final result EOF carries the authoritative one.
    col_stream, col_doc = load_fixture("eof_column_definition")
    final_stream, final_doc = load_fixture("eof_result_final")
    col = mp.parse_eof_packet(read_message_bytes(col_stream))
    final = mp.parse_eof_packet(read_message_bytes(final_stream))
    assert col.warning_count == col_doc["expected"]["warning_count"] == 3
    assert final.warning_count == final_doc["expected"]["warning_count"] == 7
    assert col.warning_count != final.warning_count
    assert final.warning_count > col.warning_count


def test_deprecated_eof_terminator_is_an_ok_packet_with_final_count():
    stream, doc = load_fixture("eof_deprecated_terminator")
    payload = read_message_bytes(stream)
    assert mp.classify_terminator(payload) == "ok"
    info = mp.parse_ok_packet(payload)
    assert info.warning_count == doc["expected"]["warning_count"] == 7
    assert info.has_next is True  # SERVER_MORE_RESULTS_EXISTS observed


def test_classify_terminator_rejects_unknown_payload():
    assert mp.classify_terminator(b"\xfb") == "unknown"  # NULL marker alone


def test_eof_with_negative_count_fails_closed():
    # EOFPacketWrapper reads signed shorts; a negative count is impossible.
    with pytest.raises(ResultContractViolation):
        mp.parse_eof_packet(b"\xfe\xff\xff\x02\x00")


# --------------------------------------------------------------------------
# SHOW WARNINGS reconciliation (P03)
# --------------------------------------------------------------------------


def _row(level: str, code: int, message: str):
    return (level.encode(), str(code).encode(), message.encode())


def test_reconcile_counts_agree_is_complete():
    record = mp.reconcile_diagnostics(2, [_row("Warning", 1366, "a"), _row("Note", 1592, "b")])
    assert record.collected is True
    assert record.complete is True
    assert record.truncated is False
    assert record.shown_count == 2
    assert [(e.level, e.code) for e in record.entries] == [("WARNING", "1366"), ("NOTE", "1592")]


def test_reconcile_zero_diagnostics_is_complete_and_empty():
    record = mp.reconcile_diagnostics(0, [])
    assert record.complete is True
    assert record.entries == ()


def test_reconcile_over_128_entries_is_truncated():
    rows = [_row("Note", 1000 + i, f"m{i}") for i in range(200)]
    record = mp.reconcile_diagnostics(200, rows)
    assert record.truncated is True
    assert record.complete is False
    assert len(record.entries) == mp.MAX_DIAGNOSTIC_ENTRIES
    assert record.shown_count == 200


def test_reconcile_oversized_message_is_truncated():
    message = "x" * (mp.MAX_DIAGNOSTIC_MESSAGE_BYTES + 1)
    record = mp.reconcile_diagnostics(1, [_row("Warning", 1264, message)])
    assert record.truncated is True
    assert record.complete is False


def test_reconcile_count_mismatch_is_incomplete():
    record = mp.reconcile_diagnostics(3, [_row("Warning", 1366, "a")])
    assert record.complete is False
    assert record.truncated is False  # counts disagree; not a truncation claim


def test_reconcile_err_without_packet_count_is_incomplete():
    record = mp.reconcile_diagnostics(None, [_row("Error", 1049, "Unknown database")])
    assert record.collected is True
    assert record.complete is False
    assert record.entries[0].level == "ERROR"
    assert record.entries[0].sqlstate is None


def test_reconcile_note_level_is_preserved_not_filtered():
    record = mp.reconcile_diagnostics(1, [_row("Note", 1592, "note text")])
    assert record.complete is True
    assert record.entries[0].level == "NOTE"


def test_reconcile_unknown_level_fails_closed():
    with pytest.raises(ResultContractViolation):
        mp.reconcile_diagnostics(1, [_row("Info", 1, "m")])


def test_reconcile_non_numeric_code_fails_closed():
    with pytest.raises(ResultContractViolation):
        mp.reconcile_diagnostics(1, [_row("Warning", "12x6", "m")])


def test_reconcile_short_row_fails_closed():
    with pytest.raises(ResultContractViolation):
        mp.reconcile_diagnostics(1, [(b"Warning", 1)])


def test_not_collected_record_is_incomplete_by_construction():
    record = mp.DiagnosticsRecord.not_collected()
    assert record.collected is False
    assert record.complete is False
    assert record.entries == ()


# --------------------------------------------------------------------------
# Adapter diagnostics ordering (count first, then SHOW WARNINGS)
# --------------------------------------------------------------------------


class FakeResultHolder:
    """What the adapter reads off MySQLResult after a statement."""

    def __init__(self, warning_count, has_next=0) -> None:
        self.affected_rows = 1
        self.warning_count = warning_count
        self.server_status = 2
        self.has_next = has_next


class FakeStmtCursor:
    """Buffered-cursor stand-in recording execution order."""

    def __init__(self, description, result, warning_rows) -> None:
        self.description = description
        self._result = result
        self._warning_rows = warning_rows
        self.executed: list[str] = []

    def execute(self, sql: str) -> None:
        self.executed.append(sql)

    def fetchmany(self, size: int):
        return self._warning_rows[:size]


class FakeOkConnection:
    """One cursor handles the statement and the following SHOW WARNINGS."""

    def __init__(self, warning_count, warning_rows) -> None:
        self._cursor = FakeStmtCursor(
            None, FakeResultHolder(warning_count), warning_rows
        )
        self.cursor_log: list[object] = []

    def cursor(self, cursor_class):
        self.cursor_log.append(self._cursor)
        return self._cursor


def _fresh_adapter(connection) -> PyMySQLAdapter:
    params = ConnectionParams(
        host="db.test.internal",
        port=3306,
        user="typecheck",
        password="secret-not-used-here",
    )
    adapter = PyMySQLAdapter(params, charset="utf8mb4")
    adapter._conn = connection
    adapter._usable = True
    return adapter


def test_execute_statement_collects_count_then_show_warnings():
    conn = FakeOkConnection(
        warning_count=2,
        warning_rows=[_row("Warning", 1366, "a"), _row("Note", 1592, "b")],
    )
    adapter = _fresh_adapter(conn)
    receipt = adapter.execute_statement("CREATE TABLE t (rid BIGINT PRIMARY KEY)")
    assert receipt.warning_count == 2
    assert receipt.error is None
    assert receipt.diagnostics.complete is True
    # The terminating packet count is taken from the statement result, and
    # SHOW WARNINGS is the very next statement -- nothing in between.
    assert conn._cursor.executed == [
        "CREATE TABLE t (rid BIGINT PRIMARY KEY)",
        "SHOW WARNINGS",
    ]


def test_execute_statement_error_keeps_errno_without_sqlstate_and_stays_incomplete():
    import pymysql.err

    class FakeErrConnection(FakeOkConnection):
        """First cursor.execute raises (ERR packet); the SHOW WARNINGS call
        afterwards succeeds."""

        def __init__(self) -> None:
            super().__init__(0, [])
            self._calls = 0

        def cursor(self, cursor_class):
            self._calls += 1
            if self._calls == 1:
                return _ErrorCursor()
            return self._cursor

    class _ErrorCursor:
        description = None
        _result = None

        def execute(self, sql: str) -> None:
            raise pymysql.err.OperationalError(1049, "Unknown database 'nope'")

    conn = FakeErrConnection()
    adapter = _fresh_adapter(conn)
    receipt = adapter.execute_statement("CREATE DATABASE nope")
    assert receipt.error is not None
    assert receipt.error.errno == 1049
    assert receipt.error.sqlstate is None  # driver drops SQLSTATE; never guessed
    assert receipt.warning_count is None
    assert receipt.diagnostics.complete is False
    assert receipt.diagnostics.collected is True
    assert conn._cursor.executed == ["SHOW WARNINGS"]


def test_execute_statement_refuses_result_sets():
    class FakeSelectConnection(FakeOkConnection):
        def __init__(self) -> None:
            super().__init__(0, [])
            self._cursor = FakeStmtCursor(
                [("v", None, None, None, None, 0, False)],  # DB-API description
                FakeResultHolder(0),
                [],
            )

    adapter = _fresh_adapter(FakeSelectConnection())
    with pytest.raises(ResultContractViolation):
        adapter.execute_statement("SELECT 1")


def test_show_warnings_failure_is_not_collected():
    import pymysql.err

    class FailingShowCursor(FakeStmtCursor):
        def execute(self, sql: str) -> None:
            if sql == "SHOW WARNINGS":
                raise pymysql.err.OperationalError(2006, "server has gone away")
            self.executed.append(sql)

    conn = FakeOkConnection(1, [_row("Warning", 1366, "a")])
    conn.cursor = lambda cursor_class: FailingShowCursor(  # type: ignore[method-assign]
        None, FakeResultHolder(1), [_row("Warning", 1366, "a")]
    )
    adapter = _fresh_adapter(conn)
    receipt = adapter.execute_statement("CREATE TABLE t (rid BIGINT PRIMARY KEY)")
    assert receipt.diagnostics.collected is False
    assert receipt.diagnostics.complete is False
