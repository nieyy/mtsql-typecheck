"""Cleanup-executor binding tests (D3 seam closure): the real
``MySQL80Adapter`` bound to ``AttemptCleaner`` (``CleanupExecutor``).

Every interaction runs against the scripted fake connection from
``tests/unit/adapters/test_mysql80.py``; no live MySQL, no network.  The
assertions pin the safety contract of the binding:

- only whitelisted cleanup statement shapes reach the server, and every
  quoted object name is re-validated through ``runner.naming`` (a wrong or
  unowned name is refused before any SQL is sent);
- ``AttemptCleaner`` drops exactly the marker table plus the two created
  attempt tables, then the two attempt databases, journaling every drop;
- an already-absent database is an idempotent no-op (CLEANUP_CONFIRMED);
- executor failures become journaled CLEANUP_FAILED outcomes, never raises;
- ``cleanup --apply --target`` binds the real adapter end to end through the
  CLI instead of reporting NOT_RUN.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import pymysql.err

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapters"))

from test_mysql80 import (  # noqa: E402
    FakeField,
    identity_responses,
    make_adapter,
    ok_statement,
)

from controller_fakes import make_target_config  # noqa: E402
from mtsql_typecheck.adapters.base import AdapterError  # noqa: E402
from mtsql_typecheck.adapters.mysql80 import (  # noqa: E402
    CLEANUP_DDL_FAILED,
    MySQL80Adapter,
)
from mtsql_typecheck.cli import online  # noqa: E402
from mtsql_typecheck.cli.main import main  # noqa: E402
from mtsql_typecheck.contracts.runner import (  # noqa: E402
    OwnershipEventKind,
    load_ownership_journal,
)
from mtsql_typecheck.runner.cleanup import (  # noqa: E402
    AttemptCleaner,
    CleanupAction,
    ensure_marker,
)
from mtsql_typecheck.runner.naming import (  # noqa: E402
    attempt_database_names,
    marker_table_name,
)
from mtsql_typecheck.runner.ownership import (  # noqa: E402
    MARKER_TABLE_DDL,
    OwnershipJournal,
)

RUN_TOKEN = "0123456789abcdef"
ATTEMPT_TOKEN = "fedcba9876543210"
RUN_ID = "run-clean-1"
ATTEMPT_ID = "attempt-1"
DB_A, DB_B = attempt_database_names(RUN_TOKEN, ATTEMPT_TOKEN)
MARKER = marker_table_name()

SCHEMA_PROBE_SQL = (
    "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = "
)


def sent_sql(fake):
    """The fake records the shim's SHOW WARNINGS round-trips too; the
    assertions below care only about statements the adapter actually sent."""
    return [sql for sql in fake.executed if sql != "SHOW WARNINGS"]


def present_response(database: str):
    # The raw fetch path demands bytes/None cells (frozen result mapping).
    return ([FakeField("SCHEMA_NAME")], [(database.encode(),)], 0)


ABSENT_RESPONSE = ([FakeField("SCHEMA_NAME")], [], 0)


def marker_insert_sql(run_id: str, attempt_id: str, token: str) -> str:
    return (
        f"INSERT INTO `{MARKER}` (run_id, attempt_id, token) "
        f"VALUES ('{run_id}', '{attempt_id}', '{token}')"
    )


def side_responses(database: str, test_table: str):
    """One fully-present side: presence probe, two table drops, a database
    drop, and the absence re-check."""
    return [
        present_response(database),
        ok_statement(),  # DROP TABLE <db>.<test_table>
        ok_statement(),  # DROP TABLE <db>.tc_ownership_marker
        ok_statement(),  # DROP DATABASE <db>
        ABSENT_RESPONSE,  # post-drop absence re-check
    ]


# --------------------------------------------------------------------------
# execute_ddl: whitelist and naming validation
# --------------------------------------------------------------------------


def test_execute_ddl_whitelisted_cleanup_shapes_run():
    adapter, fake = make_adapter(
        responses=[ok_statement() for _ in range(5)]
    )
    insert = marker_insert_sql(RUN_ID, ATTEMPT_ID, RUN_TOKEN)
    statements = [
        MARKER_TABLE_DDL,
        insert,
        f"DROP TABLE `{DB_A}`.`case_a`",
        f"DROP TABLE `{DB_A}`.`{MARKER}`",
        f"DROP DATABASE `{DB_A}`",
    ]
    for sql in statements:
        adapter.execute_ddl(sql)
    assert sent_sql(fake) == statements


def test_execute_ddl_refuses_non_cleanup_shapes_without_sending():
    adapter, fake = make_adapter(responses=[])
    refused = [
        "DROP DATABASE `production`",  # valid shape, unowned name
        f"DROP TABLE `{DB_A}`.`sneaky_table`",  # wrong table in an owned db
        f"TRUNCATE TABLE `{DB_A}`.`case_a`",  # not a whitelisted shape
        "DROP DATABASE",  # malformed
        f"UPDATE `{DB_A}`.`case_a` SET c0 = 1",  # not DDL at all
        f"DROP DATABASE `{DB_A}`; DROP DATABASE `{DB_B}`",  # stacked
    ]
    for sql in refused:
        with pytest.raises(AdapterError):
            adapter.execute_ddl(sql)
    # Nothing reached the server: every refusal happened before any SQL.
    assert sent_sql(fake) == []


def test_execute_ddl_reports_server_error_typed():
    adapter, _ = make_adapter(
        responses=[pymysql.err.OperationalError(1050, "table exists")]
    )
    with pytest.raises(AdapterError) as excinfo:
        adapter.execute_ddl(f"DROP DATABASE `{DB_A}`")
    assert excinfo.value.code == CLEANUP_DDL_FAILED


def test_ensure_marker_statements_pass_the_whitelist():
    adapter, fake = make_adapter(responses=[ok_statement(), ok_statement()])
    ensure_marker(adapter, run_id=RUN_ID, attempt_id=ATTEMPT_ID, token=RUN_TOKEN)
    assert sent_sql(fake) == [
        MARKER_TABLE_DDL,
        marker_insert_sql(RUN_ID, ATTEMPT_ID, RUN_TOKEN),
    ]


# --------------------------------------------------------------------------
# is_database_present: probe + name guard
# --------------------------------------------------------------------------


def test_is_database_present_probes_information_schema():
    adapter, fake = make_adapter(responses=[present_response(DB_A), ABSENT_RESPONSE])
    assert adapter.is_database_present(DB_A) is True
    assert adapter.is_database_present(DB_A) is False
    assert len(sent_sql(fake)) == 2
    assert all(sql.startswith(SCHEMA_PROBE_SQL) for sql in sent_sql(fake))


def test_is_database_present_refuses_names_outside_ownership_grammar():
    adapter, fake = make_adapter(responses=[])
    for bad in (
        "production",  # not a tc_ attempt database
        f"{DB_A}; DROP DATABASE x",  # injection attempt
        "tc_",  # grammar fragment
        "`x`",  # quoting metacharacters
    ):
        with pytest.raises(AdapterError):
            adapter.is_database_present(bad)
    assert sent_sql(fake) == []


# --------------------------------------------------------------------------
# AttemptCleaner over the real adapter + a real on-disk journal
# --------------------------------------------------------------------------


def test_cleaner_drops_marker_and_exact_created_objects(tmp_path: Path):
    journal = OwnershipJournal(tmp_path / "ownership.jsonl", run_id=RUN_ID)
    adapter, fake = make_adapter(
        responses=side_responses(DB_A, "case_a") + side_responses(DB_B, "case_b")
    )
    cleaner = AttemptCleaner(adapter, journal)

    outcome = cleaner.clean(
        run_id=RUN_ID,
        attempt_id=ATTEMPT_ID,
        run_token=RUN_TOKEN,
        attempt_token=ATTEMPT_TOKEN,
    )
    assert outcome.completed is True
    assert outcome.failures == ()

    probes = [sql for sql in sent_sql(fake) if sql.startswith(SCHEMA_PROBE_SQL)]
    assert len(probes) == 4  # per side: the initial probe + the post-drop re-check
    # The presence probe precedes every drop; the drop DDL is exactly the
    # marker + the two created tables + the two attempt databases.
    assert sent_sql(fake).index(probes[0]) == 0
    assert [sql for sql in sent_sql(fake) if sql not in probes] == [
        f"DROP TABLE `{DB_A}`.`case_a`",
        f"DROP TABLE `{DB_A}`.`{MARKER}`",
        f"DROP DATABASE `{DB_A}`",
        f"DROP TABLE `{DB_B}`.`case_b`",
        f"DROP TABLE `{DB_B}`.`{MARKER}`",
        f"DROP DATABASE `{DB_B}`",
    ]

    dropped = [
        event.object_name
        for event in journal.events()
        if event.event_kind is OwnershipEventKind.OBJECT_DROPPED
    ]
    assert dropped == [
        f"{DB_A}.case_a",
        f"{DB_A}.{MARKER}",
        DB_A,
        f"{DB_B}.case_b",
        f"{DB_B}.{MARKER}",
        DB_B,
    ]
    assert not any(
        event.event_kind is OwnershipEventKind.CLEANUP_FAILED
        for event in journal.events()
    )
    journal.close()


def test_cleaner_reclean_of_absent_databases_is_a_journaled_noop(tmp_path: Path):
    journal = OwnershipJournal(tmp_path / "ownership.jsonl", run_id=RUN_ID)
    adapter, fake = make_adapter(responses=[ABSENT_RESPONSE, ABSENT_RESPONSE])
    cleaner = AttemptCleaner(adapter, journal)

    outcome = cleaner.clean(
        run_id=RUN_ID,
        attempt_id=ATTEMPT_ID,
        run_token=RUN_TOKEN,
        attempt_token=ATTEMPT_TOKEN,
    )
    assert outcome.completed is True
    # No DDL was sent at all -- only the two presence probes.
    assert sent_sql(fake) == [
        SCHEMA_PROBE_SQL + f"'{DB_A}'",
        SCHEMA_PROBE_SQL + f"'{DB_B}'",
    ]
    confirmed = [
        event.object_name
        for event in journal.events()
        if event.event_kind is OwnershipEventKind.CLEANUP_CONFIRMED
    ]
    assert confirmed == [DB_A, DB_B]
    journal.close()


def test_cleaner_journals_failure_without_raising(tmp_path: Path):
    journal = OwnershipJournal(tmp_path / "ownership.jsonl", run_id=RUN_ID)
    adapter, _ = make_adapter(
        responses=[
            present_response(DB_A),
            pymysql.err.OperationalError(1050, "table exists"),  # DROP TABLE fails
            ABSENT_RESPONSE,  # side B is already gone
        ]
    )
    cleaner = AttemptCleaner(adapter, journal)

    outcome = cleaner.clean(
        run_id=RUN_ID,
        attempt_id=ATTEMPT_ID,
        run_token=RUN_TOKEN,
        attempt_token=ATTEMPT_TOKEN,
    )
    assert outcome.completed is False
    assert len(outcome.failures) == 1
    failure = outcome.failures[0]
    assert failure.object_name == DB_A
    assert failure.action is CleanupAction.DROP_TABLE
    failed = [
        event.object_name
        for event in journal.events()
        if event.event_kind is OwnershipEventKind.CLEANUP_FAILED
    ]
    assert failed == [DB_A]
    journal.close()


# --------------------------------------------------------------------------
# CLI end to end: cleanup --apply --target binds the real adapter
# --------------------------------------------------------------------------


def _seed_run_output(root: Path) -> None:
    journal = OwnershipJournal(root / "ownership.jsonl", run_id=RUN_ID)
    journal.append(OwnershipEventKind.RUN_LOCK_ACQUIRED, token=RUN_TOKEN)
    journal.append(OwnershipEventKind.ATTEMPT_ALLOCATED, attempt_id=ATTEMPT_ID, token=ATTEMPT_TOKEN)
    journal.append(
        OwnershipEventKind.OBJECT_CREATED, attempt_id=ATTEMPT_ID, object_name=DB_A
    )
    journal.append(
        OwnershipEventKind.OBJECT_CREATED, attempt_id=ATTEMPT_ID, object_name=DB_B
    )
    journal.close()


def test_cli_cleanup_apply_binds_real_adapter_and_drops(tmp_path: Path, monkeypatch):
    root = tmp_path / "run-out"
    root.mkdir()
    _seed_run_output(root)

    adapter, fake = make_adapter(
        responses=list(identity_responses())
        + side_responses(DB_A, "case_a")
        + side_responses(DB_B, "case_b")
    )
    fake.close = lambda: None  # the shim's close expects a driver connection
    monkeypatch.setattr(online, "build_probe_source", lambda config: adapter)

    target = tmp_path / "target.json"
    from mtsql_typecheck.contracts.runner import dump_target_config

    target.write_bytes(dump_target_config(make_target_config()))

    exit_code = main(["cleanup", "--input", str(root), "--apply", "--target", str(target)])
    assert exit_code == 0

    # The CLI adapter was probed, then used as the cleanup executor.
    probes = [sql for sql in sent_sql(fake) if sql.startswith(SCHEMA_PROBE_SQL)]
    assert len(probes) == 4  # 2 cleanup sides x (initial probe + re-check)
    non_probe = [
        sql
        for sql in sent_sql(fake)
        if sql not in probes and not sql.startswith("SELECT @@")  # identity facts
    ]
    assert non_probe == [
        f"DROP TABLE `{DB_A}`.`case_a`",
        f"DROP TABLE `{DB_A}`.`{MARKER}`",
        f"DROP DATABASE `{DB_A}`",
        f"DROP TABLE `{DB_B}`.`case_b`",
        f"DROP TABLE `{DB_B}`.`{MARKER}`",
        f"DROP DATABASE `{DB_B}`",
    ]

    # The run's ownership journal was continued in place with drop records.
    events = load_ownership_journal((root / "ownership.jsonl").read_bytes())
    dropped = [
        event.object_name
        for event in events
        if event.event_kind is OwnershipEventKind.OBJECT_DROPPED
    ]
    assert len(dropped) == 6
    assert DB_A in dropped and DB_B in dropped
    assert not any(
        event.event_kind is OwnershipEventKind.CLEANUP_FAILED for event in events
    )
