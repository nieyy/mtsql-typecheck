"""Cleanup tests (design 6.2.3/6.4.5; negative matrix S02/S03).

The executor is the recording fake in ``runner_fakes``; DDL expectations
are hand-built strings.  No MySQL anywhere: live marker verification is
NOT_RUN for Phase 3 and is only shape-checked here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mtsql_typecheck.contracts.case import ContractError
from mtsql_typecheck.contracts.runner import (
    OwnershipEventKind,
    load_ownership_journal,
)
from mtsql_typecheck.runner.cleanup import (
    CleanupAction,
    CleanupFailure,
    CleanupOutcome,
    CleanupRefusedError,
    AttemptCleaner,
    database_create_sql,
    database_drop_sql,
    ensure_marker,
    table_drop_sql,
)
from mtsql_typecheck.runner.naming import attempt_database_names
from mtsql_typecheck.runner.ownership import (
    MARKER_TABLE_DDL,
    OwnershipJournal,
)
from runner_fakes import RecordingExecutor

RUN_ID = "run-1"
ATTEMPT_ID = "attempt-1"
RUN_TOKEN = "ab" * 8
ATTEMPT_TOKEN = "cd" * 8
DB_A, DB_B = attempt_database_names(RUN_TOKEN, ATTEMPT_TOKEN)
DROP_A = f"DROP DATABASE `{DB_A}`"
DROP_B = f"DROP DATABASE `{DB_B}`"


def make_journal(tmp_path: Path) -> OwnershipJournal:
    return OwnershipJournal(tmp_path / "ownership.jsonl", run_id=RUN_ID)


class TestDdlBuilders:
    def test_create_has_no_if_not_exists(self):
        sql = database_create_sql(DB_A)
        assert sql == f"CREATE DATABASE `{DB_A}`"
        assert "IF NOT EXISTS" not in sql

    def test_drop_uses_explicit_names(self):
        assert database_drop_sql(DB_B) == DROP_B
        assert table_drop_sql(DB_A, "case_a") == f"DROP TABLE `{DB_A}`.`case_a`"
        assert (
            table_drop_sql(DB_B, "tc_ownership_marker")
            == f"DROP TABLE `{DB_B}`.`tc_ownership_marker`"
        )

    def test_non_tc_names_are_refused_everywhere(self):
        for name in ("production", "tc_", "other_db", "tc_notourtoken_x_a", "DROP DATABASE x"):
            with pytest.raises(CleanupRefusedError):
                database_drop_sql(name)
            with pytest.raises(CleanupRefusedError):
                database_create_sql(name)

    def test_non_owned_table_names_are_refused(self):
        for table in ("secret_table", "case_c", "", "tc_ownership_marker2"):
            with pytest.raises(CleanupRefusedError):
                table_drop_sql(DB_A, table)


class TestAttemptCleaner:
    def test_happy_path_drops_tables_then_databases_in_order(self, tmp_path):
        executor = RecordingExecutor(present=[DB_A, DB_B])
        with make_journal(tmp_path) as journal:
            cleaner = AttemptCleaner(executor, journal)
            outcome = cleaner.clean(
                run_id=RUN_ID,
                attempt_id=ATTEMPT_ID,
                run_token=RUN_TOKEN,
                attempt_token=ATTEMPT_TOKEN,
            )
        assert outcome.completed
        assert outcome.failures == ()
        assert executor.ddl == [
            f"DROP TABLE `{DB_A}`.`case_a`",
            f"DROP TABLE `{DB_A}`.`tc_ownership_marker`",
            DROP_A,
            f"DROP TABLE `{DB_B}`.`case_b`",
            f"DROP TABLE `{DB_B}`.`tc_ownership_marker`",
            DROP_B,
        ]
        # Databases are only dropped after their tables.
        assert executor.ddl.index(DROP_A) > executor.ddl.index(f"DROP TABLE `{DB_A}`.`case_a`")
        assert executor.ddl.index(DROP_B) > executor.ddl.index(f"DROP TABLE `{DB_B}`.`case_b`")

    def test_journal_records_every_drop_and_confirms(self, tmp_path):
        executor = RecordingExecutor(present=[DB_A, DB_B])
        with make_journal(tmp_path) as journal:
            cleaner = AttemptCleaner(executor, journal)
            cleaner.clean(
                run_id=RUN_ID,
                attempt_id=ATTEMPT_ID,
                run_token=RUN_TOKEN,
                attempt_token=ATTEMPT_TOKEN,
            )
            journal.verify()
        events = load_ownership_journal((tmp_path / "ownership.jsonl").read_bytes())
        drops = [event for event in events if event.event_kind is OwnershipEventKind.OBJECT_DROPPED]
        assert [(event.object_name, event.attempt_id) for event in drops] == [
            (f"{DB_A}.case_a", ATTEMPT_ID),
            (f"{DB_A}.tc_ownership_marker", ATTEMPT_ID),
            (DB_A, ATTEMPT_ID),
            (f"{DB_B}.case_b", ATTEMPT_ID),
            (f"{DB_B}.tc_ownership_marker", ATTEMPT_ID),
            (DB_B, ATTEMPT_ID),
        ]
        assert all(event.run_id == RUN_ID for event in drops)

    def test_already_absent_database_is_idempotent_success(self, tmp_path):
        executor = RecordingExecutor(present=[])  # nothing on the server
        with make_journal(tmp_path) as journal:
            cleaner = AttemptCleaner(executor, journal)
            outcome = cleaner.clean(
                run_id=RUN_ID,
                attempt_id=ATTEMPT_ID,
                run_token=RUN_TOKEN,
                attempt_token=ATTEMPT_TOKEN,
            )
        assert outcome.completed
        assert executor.ddl == []  # no DDL executed at all
        events = load_ownership_journal((tmp_path / "ownership.jsonl").read_bytes())
        confirmed = [
            event
            for event in events
            if event.event_kind is OwnershipEventKind.CLEANUP_CONFIRMED
        ]
        assert [event.object_name for event in confirmed] == [DB_A, DB_B]

    def test_partial_database_present_only_is_still_cleaned(self, tmp_path):
        # DB present but the table was already dropped in an earlier failed
        # pass: this is ownership-uncertain and must NOT silently succeed.
        executor = RecordingExecutor(
            present=[DB_A, DB_B],
            fail_on_substrings=[f"DROP TABLE `{DB_A}`."],
            fail_times=2,
        )
        with make_journal(tmp_path) as journal:
            cleaner = AttemptCleaner(executor, journal)
            outcome = cleaner.clean(
                run_id=RUN_ID,
                attempt_id=ATTEMPT_ID,
                run_token=RUN_TOKEN,
                attempt_token=ATTEMPT_TOKEN,
            )
        assert not outcome.completed
        assert outcome.failures[0].object_name == DB_A

    def test_malformed_tokens_refuse_before_any_ddl(self, tmp_path):
        executor = RecordingExecutor(present=[DB_A, DB_B])
        with make_journal(tmp_path) as journal:
            cleaner = AttemptCleaner(executor, journal)
            with pytest.raises(CleanupRefusedError):
                cleaner.clean(
                    run_id=RUN_ID,
                    attempt_id=ATTEMPT_ID,
                    run_token="ZZ" * 8,
                    attempt_token=ATTEMPT_TOKEN,
                )
            with pytest.raises(CleanupRefusedError):
                cleaner.clean(
                    run_id=RUN_ID,
                    attempt_id=ATTEMPT_ID,
                    run_token=RUN_TOKEN,
                    attempt_token="../etc",
                )
        assert executor.ddl == []

    def test_drop_failure_becomes_structured_failure_and_event(self, tmp_path):
        executor = RecordingExecutor(present=[DB_A, DB_B], fail_on_substrings=[DROP_A])
        with make_journal(tmp_path) as journal:
            cleaner = AttemptCleaner(executor, journal)
            outcome = cleaner.clean(
                run_id=RUN_ID,
                attempt_id=ATTEMPT_ID,
                run_token=RUN_TOKEN,
                attempt_token=ATTEMPT_TOKEN,
            )
        assert not outcome.completed
        assert len(outcome.failures) == 1
        failure = outcome.failures[0]
        assert failure.object_name == DB_A
        assert failure.action is CleanupAction.DROP_DATABASE
        assert "executor failure injected" in failure.detail
        # The failed DROP DATABASE leaves DB_A behind; the sibling was cleaned.
        assert executor.present == {DB_A}
        events = load_ownership_journal((tmp_path / "ownership.jsonl").read_bytes())
        failed = [event for event in events if event.event_kind is OwnershipEventKind.CLEANUP_FAILED]
        assert [event.object_name for event in failed] == [DB_A]

    def test_table_drop_failure_reports_drop_table_action(self, tmp_path):
        executor = RecordingExecutor(
            present=[DB_A, DB_B],
            fail_on_substrings=[f"DROP TABLE `{DB_B}`.`case_b`"],
        )
        with make_journal(tmp_path) as journal:
            cleaner = AttemptCleaner(executor, journal)
            outcome = cleaner.clean(
                run_id=RUN_ID,
                attempt_id=ATTEMPT_ID,
                run_token=RUN_TOKEN,
                attempt_token=ATTEMPT_TOKEN,
            )
        assert not outcome.completed
        assert outcome.failures[0].action is CleanupAction.DROP_TABLE

    def test_outcome_completed_flag_must_match_failures(self):
        # completed is exactly "no failures"; inconsistent construction fails.
        assert CleanupOutcome(completed=True, failures=()).completed
        failure = CleanupFailure(
            object_name=DB_A, action=CleanupAction.DROP_DATABASE, detail="x"
        )
        with pytest.raises(ContractError):
            CleanupOutcome(completed=True, failures=(failure,))
        assert CleanupOutcome(completed=False, failures=(failure,)).completed is False


class TestEnsureMarker:
    def test_runs_marker_ddl_and_stamp(self, tmp_path):
        executor = RecordingExecutor()
        ensure_marker(executor, run_id=RUN_ID, attempt_id=ATTEMPT_ID, token=RUN_TOKEN)
        assert executor.ddl[0] == MARKER_TABLE_DDL
        assert executor.ddl[0].startswith("CREATE TABLE `tc_ownership_marker`")
        assert "IF NOT EXISTS" not in executor.ddl[0]
        assert executor.ddl[1] == (
            "INSERT INTO `tc_ownership_marker` (run_id, attempt_id, token) "
            f"VALUES ('{RUN_ID}', '{ATTEMPT_ID}', '{RUN_TOKEN}')"
        )

    def test_unsafe_literals_are_refused(self):
        executor = RecordingExecutor()
        for bad in ("'; DROP TABLE x; --", "", "run id with space", "x" * 129):
            with pytest.raises(CleanupRefusedError):
                ensure_marker(executor, run_id=bad, attempt_id=ATTEMPT_ID, token=RUN_TOKEN)
        with pytest.raises(CleanupRefusedError):
            ensure_marker(executor, run_id=RUN_ID, attempt_id=ATTEMPT_ID, token="ZZZZ")
        assert executor.ddl == []



