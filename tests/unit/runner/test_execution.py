"""Unit tests for runner.execution (Phase 4) -- fakes only, no live MySQL.

The fake adapters are scripted (tests/unit/runner/execution_fakes.py); every
result packet and failure is stated per test and never derived from the code
under test.  Failure codes asserted here are the frozen vocabulary documented
in ``runner.execution`` (QueryStatus / adapters.base / ComparisonReason /
StopReason values, plus the one surfaced free-form code ATTEMPT_NOT_FOUND).

NOT_RUN (needs a live MySQL 8.0 target or the Phase 5 driver binding):
- real PyMySQL / MySQL80Adapter behaviour behind the AdapterLike surface;
- KILL QUERY against a genuinely running statement (fakes answer instantly);
- mid-execute cancellation delivered from another thread into
  ``cancel_and_wait`` while ``execute`` is parked on a blocking adapter (the
  synchronous fakes cannot hold a statement in flight); the exercised
  cancel_and_wait paths here are the post-prepare and post-terminal ones;
- real server-side CREATE/DROP/INSERT effects (the catalog is simulated).
"""

from __future__ import annotations

import pytest

from execution_fakes import (
    BUILD_ID,
    DEFAULT_FACTS,
    CancelToken,
    FakeAdapter,
    FakeCatalog,
    FakeControlConnection,
    FakeErr,
    FakeMappedColumn,
    InMemoryJournal,
    StubClock,
    dec_value,
    environment_from_facts,
    int_value,
    make_control,
    make_payload,
    make_request,
    null_value,
    readback_rows_for,
)

from mtsql_typecheck.adapters.base import (
    AdapterError,
    ProtocolBudgetError,
    ResultContractViolation,
    ResultEncodingError,
)
from mtsql_typecheck.adapters.mysql80 import SessionMismatch, SessionMismatchEntry
from mtsql_typecheck.contracts.case import (
    ContractError,
    DecimalValue,
    ExpectedBinding,
    NameMap,
    NullValue as NullValueCase,
    IntegerValue,
)
from mtsql_typecheck.contracts.execution import (
    ATTEMPT_BUDGET_MS,
    AttemptExpectation,
    AttemptStage,
    CleanupState,
    ExecutionOrder,
    ExecutionPortError,
    QueryStatus,
    ResultTerminal,
    Side,
    TerminationState,
    dump_execution_evidence,
    load_execution_evidence,
)
from mtsql_typecheck.contracts.oracle import (
    ComparisonBudget,
    ComparisonReason,
    ComparisonStatus,
)
from mtsql_typecheck.generation.render import render_pair
from mtsql_typecheck.generation.validation import (
    environment_content_hash,
    name_map_content_hash,
)
from mtsql_typecheck.oracle.gates import compare_case
from mtsql_typecheck.runner.cancellation import LifecycleState
from mtsql_typecheck.runner.ownership import QuarantineError
from mtsql_typecheck.runner.execution import MySQLExecutionPort

# Deterministic token stream: the run token first, then one attempt token per
# prepare.  Every name the port derives is thus reproducible from these.
RUN_TOKEN = "0123456789abcdef"
ATTEMPT_TOKENS = [f"{i:016x}" for i in range(1, 31)]

# Canned payload rows shared by most tests (exact D1 values, never floats).
_ROW_VALUES = (IntegerValue(1), NullValueCase(), IntegerValue(-5))

def token_source(tokens=None):
    stream = iter(list(tokens) if tokens is not None else [RUN_TOKEN] + ATTEMPT_TOKENS)
    return lambda: next(stream)


class Setup:
    """One scripted port: 4 adapters (prepare A/B, then dispatch order), a
    shared catalog and sql_log, one journal, one stub clock."""

    def __init__(self, *, row_values=_ROW_VALUES, decimal: bool = False):
        self.payload = make_payload(decimal=decimal, row_values=row_values)
        self.catalog = FakeCatalog(readback_rows=readback_rows_for(self.payload))
        self.sql_log: list[str] = []
        self.clock = StubClock()
        self.journal = InMemoryJournal("run-exec-1")
        self.controls: dict[str, FakeControlConnection] = {}
        self.adapters: list = []
        self._next_connection_id = 10

    def _append(self, **adapter_kwargs) -> None:
        connection_id = self._next_connection_id
        self._next_connection_id += 1
        self.adapters.append(
            FakeAdapter(
                catalog=self.catalog,
                connection_id=connection_id,
                facts=dict(DEFAULT_FACTS),
                sql_log=self.sql_log,
                **adapter_kwargs,
            )
        )

    def add_prepare_adapters(self, **kwargs) -> None:
        column_type = kwargs.pop("column_type", None)
        for side in ("a", "b"):
            resolved = column_type(side) if callable(column_type) else column_type
            self._append(
                column_type=resolved
                if resolved is not None
                else (b"tinyint" if side == "a" else b"smallint"),
                **kwargs,
            )

    def add_query_adapters(self, **kwargs) -> None:
        select_column = FakeMappedColumn(
            ordinal=0, alias="c0", type_code=253, flags=0, scale=0
        )
        kwargs.setdefault("select_columns", (select_column,))
        for side in ("a", "b"):
            control = FakeControlConnection(sql_log=self.sql_log)
            self.controls[side] = control
            self._append(control=control, **kwargs)

    def build(self, tokens=None) -> MySQLExecutionPort:
        # The factory serves the scripted adapters in connection order and
        # recycles them afterwards (every prepare/execute opens fresh
        # connections; the fakes accept reconnection by design).
        pool = list(self.adapters)

        def factory():
            if not pool:
                raise AssertionError("adapter factory exhausted: unexpected connection")
            adapter = pool.pop(0)
            pool.append(adapter)
            return adapter

        return MySQLExecutionPort(
            adapter_factory=factory,
            journal=self.journal,
            token_source=token_source(tokens),
            clock=self.clock,
        )

    def request(self, attempt_id: str, **kwargs):
        return make_request(self.payload, attempt_id=attempt_id, run_id="run-exec-1", **kwargs)


# Canned payload rows shared by most tests (exact D1 values, never floats).


# --------------------------------------------------------------------------
# Setup helpers
# --------------------------------------------------------------------------


def default_setup(tokens=None):
    setup = Setup()
    setup.add_prepare_adapters()
    setup.add_query_adapters()
    return setup, setup.build(tokens)


def column_type_bytes(*, decimal: bool, side: str) -> bytes:
    if decimal:
        return b"decimal(9,2)" if side == "a" else b"decimal(18,2)"
    return b"tinyint" if side == "a" else b"smallint"


def run_with_select_error(setup, exception):
    setup.add_prepare_adapters()
    setup.add_query_adapters(select_errors={"SELECT": exception})
    port = setup.build()
    request = setup.request("attempt-1")
    expectation = port.prepare(request, make_control(setup.clock))
    with pytest.raises(ExecutionPortError) as excinfo:
        port.execute(request, expectation, make_control(setup.clock))
    return excinfo.value, port


# --------------------------------------------------------------------------
# prepare: happy path
# --------------------------------------------------------------------------


class TestPrepareHappyPath:
    def test_returns_expectation_bound_to_the_request(self):
        setup, port = default_setup()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))

        assert isinstance(expectation, AttemptExpectation)
        assert expectation.request_hash == request.request_hash
        assert expectation.execution_order is ExecutionOrder.AB
        assert expectation.codec_version == "mysql-text-1"
        assert expectation.binding.run_id == request.run_id
        assert expectation.binding.case_id == request.case_id
        assert expectation.binding.attempt_id == request.attempt_id
        assert expectation.binding.environment_hash == environment_content_hash(
            request.target_environment
        )
        assert expectation.binding.name_map_hash == name_map_content_hash(
            expectation.name_map
        )
        # prepare leaves the attempt READY; the seal happens in execute.
        assert port.lifecycle_state("attempt-1") is LifecycleState.READY

    def test_marker_table_created_before_test_table_on_both_sides(self):
        setup, port = default_setup()
        port.prepare(setup.request("attempt-1"), make_control(setup.clock))
        log = setup.sql_log
        marker_indexes = [
            position
            for position, sql in enumerate(log)
            if sql.startswith("CREATE TABLE `tc_ownership_marker`")
        ]
        case_a_index = next(
            position
            for position, sql in enumerate(log)
            if sql.startswith("CREATE TABLE `case_a`")
        )
        case_b_index = next(
            position
            for position, sql in enumerate(log)
            if sql.startswith("CREATE TABLE `case_b`")
        )
        assert len(marker_indexes) == 2
        assert marker_indexes[0] < case_a_index < marker_indexes[1] < case_b_index

    def test_fresh_names_and_hashes_across_attempts(self):
        setup = Setup()
        setup.add_prepare_adapters()
        port = setup.build()
        control = make_control(setup.clock)
        first = port.prepare(setup.request("attempt-1"), control)
        second = port.prepare(setup.request("attempt-2"), control)

        assert first.name_map.database_a != second.name_map.database_a
        assert first.name_map.database_b != second.name_map.database_b
        assert name_map_content_hash(first.name_map) != name_map_content_hash(
            second.name_map
        )
        # One run token prefixes every attempt database of the run.
        run_prefix = f"tc_{RUN_TOKEN}_"
        assert first.name_map.database_a.startswith(run_prefix)
        assert second.name_map.database_b.startswith(run_prefix)
        # Both attempts' databases exist server-side (simulated catalog).
        for name_map in (first.name_map, second.name_map):
            assert setup.catalog.present(name_map.database_a)
            assert setup.catalog.present(name_map.database_b)

    def test_insert_statements_are_the_rendered_exact_value_texts(self):
        setup, port = default_setup()
        expectation = port.prepare(
            setup.request("attempt-1"), make_control(setup.clock)
        )
        rendered = render_pair(setup.payload, expectation.name_map)
        payload_texts = {
            data.decode("utf-8") for data in port.payloads("attempt-1").values()
        }
        for side in (rendered.a, rendered.b):
            for statement in side:
                if str(statement.phase.value) == "select":
                    continue  # the tested SELECT runs in the query phase only
                assert statement.text in payload_texts
        insert_text = next(
            statement.text
            for statement in rendered.a
            if str(statement.phase.value) == "insert"
        )
        assert "NULL" in insert_text  # NULL stays NULL, never 0
        assert "-5" in insert_text  # exact signed value in canonical text

    def test_fact_summary_carries_recomputed_hashes(self):
        setup, port = default_setup()
        expectation = port.prepare(
            setup.request("attempt-1"), make_control(setup.clock)
        )
        summary = port.fact_summary("attempt-1")
        assert summary["run_id"] == "run-exec-1"
        assert summary["attempt_id"] == "attempt-1"
        assert summary["environment_hash"] == expectation.binding.environment_hash
        assert summary["name_map_hash"] == expectation.binding.name_map_hash
        assert summary["observed_environment_hash"] == environment_content_hash(
            environment_from_facts(DEFAULT_FACTS, build_id=BUILD_ID)
        )

    def test_stage_observations_and_payload_refs_are_controlled(self):
        setup, port = default_setup()
        port.prepare(setup.request("attempt-1"), make_control(setup.clock))
        payloads = port.payloads("attempt-1")
        assert payloads  # the SQL side table is populated
        for observation in port.stage_observations("attempt-1"):
            assert observation.sql_ref in payloads
            assert not observation.sql_ref.startswith("/")
        stages = {
            str(item.stage.value) for item in port.stage_observations("attempt-1")
        }
        assert {
            "DATABASE_CREATE",
            "MARKER",
            "DDL",
            "INSERT",
            "READBACK",
            "PROBE",
        } <= stages

    def test_journal_records_allocation_and_creation(self):
        setup, port = default_setup()
        expectation = port.prepare(
            setup.request("attempt-1"), make_control(setup.clock)
        )
        kinds = setup.journal.kinds("attempt-1")
        assert kinds[0] == "ATTEMPT_ALLOCATED"
        assert kinds.count("OBJECT_ALLOCATED") == 2
        assert kinds.count("MARKER_CREATED") == 2
        created = [
            event.object_name
            for event in setup.journal.events
            if event.attempt_id == "attempt-1"
            and str(event.event_kind.value) == "OBJECT_CREATED"
        ]
        assert expectation.name_map.database_a in created
        assert f"{expectation.name_map.database_a}.case_a" in created
        assert f"{expectation.name_map.database_b}.case_b" in created

    def test_compare_case_matches_after_the_full_flow(self):
        rows = ((int_value(1),), (int_value(1),), (null_value(),), (int_value(-7),))
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=rows)
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        evidence = port.execute(request, expectation, make_control(setup.clock))
        verdict = compare_case(request, expectation, evidence, ComparisonBudget())
        assert verdict.status is ComparisonStatus.MATCH

    def test_decimal_payload_prepare_and_match(self):
        setup = Setup(
            row_values=(DecimalValue(150, 2), DecimalValue(-10025, 2)), decimal=True
        )
        setup.add_prepare_adapters(
            column_type=lambda side: column_type_bytes(decimal=True, side=side)
        )
        setup.add_query_adapters(
            default_result=((dec_value(150, 2),), (dec_value(-10025, 2),))
        )
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        evidence = port.execute(request, expectation, make_control(setup.clock))
        assert evidence.failure is None
        assert evidence.terminal.cleanup is CleanupState.DONE
        verdict = compare_case(request, expectation, evidence, ComparisonBudget())
        assert verdict.status is ComparisonStatus.MATCH


# --------------------------------------------------------------------------
# execute: happy path and dispatch
# --------------------------------------------------------------------------


class TestExecuteHappyPath:
    def test_full_evidence_shape(self):
        rows = ((int_value(1),), (int_value(1),), (null_value(),))
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=rows)
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        evidence = port.execute(request, expectation, make_control(setup.clock))

        assert evidence.failure is None
        assert evidence.preflight_rejection is None
        assert evidence.expectation == expectation
        assert evidence.actual_execution_order is ExecutionOrder.AB
        assert evidence.terminal.termination is TerminationState.CONFIRMED
        assert evidence.terminal.cleanup is CleanupState.DONE
        assert evidence.isolation_receipt is not None
        assert evidence.isolation_receipt.method_version == (
            "runner-execution-isolation-v1"
        )
        assert port.lifecycle_state("attempt-1") is LifecycleState.SEALED

        for context, query in (
            (evidence.a_context, evidence.a_query),
            (evidence.b_context, evidence.b_query),
        ):
            assert context is not None and query is not None
            assert (
                context.setup_connection_id
                == context.readback_connection_id
                == context.select_connection_id
            )
            assert context.select_connection_id == query.session_start_id
            assert context.current_database == (
                expectation.name_map.database_a
                if context.side is Side.A
                else expectation.name_map.database_b
            )

    def test_duplicate_rows_preserved_in_order(self):
        rows = ((int_value(7),), (int_value(7),), (null_value(),), (int_value(7),))
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=rows)
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        evidence = port.execute(request, expectation, make_control(setup.clock))
        result = evidence.a_query.result
        assert result.rows == rows  # exact order, duplicates kept, no sorting
        assert result.observed_row_count == 4
        assert result.encoding_version == "mysql-text-1"
        assert evidence.a_query.status.value == "COMPLETE"
        assert evidence.a_query.result_terminal.value == "CONFIRMED"
        assert evidence.a_query.session_start_id == evidence.a_query.session_end_id

    def test_ba_dispatch_order_drives_side_sequence(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=((int_value(3),),))
        port = setup.build()
        request = setup.request("attempt-1", execution_order=ExecutionOrder.BA)
        expectation = port.prepare(request, make_control(setup.clock))
        evidence = port.execute(request, expectation, make_control(setup.clock))

        assert evidence.actual_execution_order is ExecutionOrder.BA
        started = [
            event.connection_id
            for event in setup.journal.events
            if event.attempt_id == "attempt-1"
            and str(event.event_kind.value) == "QUERY_STARTED"
        ]
        # Query connections got ids 12 and 13; BA dispatch uses 12 first.
        assert started == ["12", "13"]
        assert evidence.b_query.session_start_id == "12"
        assert evidence.a_query.session_start_id == "13"

    def test_session_settings_applied_per_side(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=((int_value(1),),))
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        port.execute(request, expectation, make_control(setup.clock))
        query_adapters = [a for a in setup.adapters if a.control is not None]
        assert len(query_adapters) == 2
        for adapter in query_adapters:
            assert adapter.session_calls == [
                {"autocommit": "1", "transaction_isolation": "REPEATABLE-READ"}
            ]

    def test_select_diagnostics_clean_when_no_warnings(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=((int_value(1),),))
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        evidence = port.execute(request, expectation, make_control(setup.clock))
        assert evidence.a_query.diagnostics.collected is True
        assert evidence.a_query.diagnostics.complete is True
        assert evidence.a_query.diagnostics.entries == ()

    def test_select_warnings_reconciled_via_show_warnings(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(
            default_result=((int_value(1),),),
            warning_count=1,
            warning_rows=((b"Warning", b"1264", b"out of range value"),),
        )
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        evidence = port.execute(request, expectation, make_control(setup.clock))
        diagnostics = evidence.a_query.diagnostics
        assert diagnostics.collected is True
        assert diagnostics.complete is False  # entries exist: never "clean"
        assert len(diagnostics.entries) == 1
        assert diagnostics.entries[0].code == "1264"
        assert diagnostics.entries[0].level.value == "WARNING"
        message_ref = diagnostics.entries[0].message_ref
        assert message_ref in port.payloads("attempt-1")
        assert port.payloads("attempt-1")[message_ref] == b"out of range value"

    def test_cleanup_drops_everything_and_seals(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=((int_value(1),),))
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        port.execute(request, expectation, make_control(setup.clock))
        # Nothing is left in the simulated catalog.
        assert setup.catalog.databases == {}
        log = setup.sql_log
        assert any(
            sql.startswith("DROP TABLE `") and "`.`case_a`" in sql for sql in log
        )
        assert any(
            sql.startswith("DROP TABLE `") and "`.`tc_ownership_marker`" in sql
            for sql in log
        )
        assert any(sql.startswith("DROP DATABASE `") for sql in log)
        kinds = setup.journal.kinds("attempt-1")
        assert kinds.count("OBJECT_DROPPED") == 6  # 2 tables + 2 markers + 2 dbs
        assert "CLEANUP_FAILED" not in kinds

    def test_evidence_dump_load_roundtrip(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=((int_value(1),),))
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        evidence = port.execute(request, expectation, make_control(setup.clock))
        loaded = load_execution_evidence(dump_execution_evidence(evidence))
        assert loaded == evidence


# --------------------------------------------------------------------------
# prepare: refusals and failures
# --------------------------------------------------------------------------


class TestPrepareRefusals:
    def test_version_series_violation_is_structured_rejection(self):
        setup = Setup()
        setup.add_prepare_adapters()
        drifted = dict(DEFAULT_FACTS, version="5.7.44")
        for adapter in setup.adapters:
            adapter.facts = dict(drifted)
        port = setup.build()
        request = setup.request("attempt-1")
        with pytest.raises(ExecutionPortError) as excinfo:
            port.prepare(request, make_control(setup.clock))
        rejection = excinfo.value.evidence.preflight_rejection
        assert rejection is not None
        assert rejection.rejected_requirement_id == "environment.version_series"
        assert rejection.request_hash == request.request_hash
        assert rejection.capability_check_version == "mysql80-execution-capability-v1"
        assert rejection.observed_environment.version == "5.7.44"
        # Nothing was created server-side and the terminal is honest.
        assert excinfo.value.terminal.termination is TerminationState.NOT_STARTED
        assert excinfo.value.terminal.owned_objects == ()
        assert setup.catalog.databases == {}
        assert excinfo.value.evidence.expectation is None
        assert excinfo.value.evidence.failure is None

    def test_unprovable_drift_is_environment_drift_failure(self):
        setup = Setup()
        setup.add_prepare_adapters()
        # optimizer_switch is recorded, never pinned: pure content drift.
        for adapter in setup.adapters:
            adapter.facts = dict(DEFAULT_FACTS, optimizer_switch="index_merge=off")
        port = setup.build()
        with pytest.raises(ExecutionPortError) as excinfo:
            port.prepare(setup.request("attempt-1"), make_control(setup.clock))
        failure = excinfo.value.failure
        assert failure.code == "ENVIRONMENT_DRIFT"
        assert failure.stage is AttemptStage.PREPARE
        assert excinfo.value.evidence.preflight_rejection is None
        assert setup.catalog.databases == {}

    def test_readback_mismatch_fails_with_cleanup(self):
        setup = Setup(row_values=(IntegerValue(1), IntegerValue(2), IntegerValue(3)))
        setup.add_prepare_adapters()
        port = setup.build()
        # Deterministic names let the test poison side A's readback.
        database_a = f"tc_{RUN_TOKEN}_{ATTEMPT_TOKENS[0]}_a"
        setup.catalog.readback_override[database_a] = ((b"1", b"1"), (b"2", b"2"))
        with pytest.raises(ExecutionPortError) as excinfo:
            port.prepare(setup.request("attempt-1"), make_control(setup.clock))
        failure = excinfo.value.failure
        assert failure.code == "RUNTIME_NOT_READY"
        assert excinfo.value.evidence.terminal.termination is TerminationState.CONFIRMED
        assert excinfo.value.evidence.terminal.cleanup is CleanupState.DONE
        assert setup.catalog.databases == {}
        assert "QUARANTINED" not in setup.journal.kinds("attempt-1")

    def test_create_database_conflict_cleans_up_side_a(self):
        setup = Setup()
        setup.add_prepare_adapters()
        # The second prepare adapter is side B.
        setup.adapters[1].statement_errors = {
            "CREATE DATABASE": FakeErr(1007, "HY000", "database exists")
        }
        setup.add_query_adapters(default_result=((int_value(1),),))
        port = setup.build()
        with pytest.raises(ExecutionPortError) as excinfo:
            port.prepare(setup.request("attempt-1"), make_control(setup.clock))
        failure = excinfo.value.failure
        assert failure.code == "SQL_ERROR"
        assert str(failure.side.value) == "B"
        # Prepare-stage failures record stage PREPARE (evidence-model rule).
        assert failure.stage is AttemptStage.PREPARE
        assert excinfo.value.evidence.terminal.cleanup is CleanupState.DONE
        assert excinfo.value.evidence.terminal.termination is TerminationState.CONFIRMED
        assert setup.catalog.databases == {}

    def test_setup_statement_error_carries_diagnostics_ref(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.adapters[0].statement_errors = {
            "CREATE TABLE `case_a`": FakeErr(1050, "42S01", "table exists")
        }
        setup.add_query_adapters(default_result=((int_value(1),),))
        port = setup.build()
        with pytest.raises(ExecutionPortError) as excinfo:
            port.prepare(setup.request("attempt-1"), make_control(setup.clock))
        failure = excinfo.value.failure
        assert failure.code == "SQL_ERROR"
        assert str(failure.side.value) == "A"
        assert failure.diagnostics_ref is not None
        assert failure.diagnostics_ref in port.payloads("attempt-1")
        assert excinfo.value.evidence.terminal.cleanup is CleanupState.DONE

    def test_duplicate_attempt_id_refused(self):
        setup, port = default_setup()
        control = make_control(setup.clock)
        port.prepare(setup.request("attempt-1"), control)
        with pytest.raises(ExecutionPortError) as excinfo:
            port.prepare(setup.request("attempt-1"), control)
        assert excinfo.value.failure.code == "EXECUTION_PROTOCOL_ERROR"
        assert excinfo.value.failure.stage is AttemptStage.PREPARE


# --------------------------------------------------------------------------
# execute: failures
# --------------------------------------------------------------------------


class TestExecuteFailures:
    @pytest.mark.parametrize(
        ("exception", "expected_code"),
        [
            (
                ResultEncodingError(
                    "unsupported wire type",
                    type_code=4,
                    flags=0,
                    column_ordinal=0,
                    mapping_version="mysql-text-1",
                ),
                "RESULT_ENCODING_UNSUPPORTED",
            ),
            (ResultContractViolation("bad packet"), "RESULT_CONTRACT_VIOLATION"),
            (ProtocolBudgetError("over budget"), "PROTOCOL_BUDGET_EXCEEDED"),
            (TimeoutError("statement deadline"), "TIMEOUT"),
            (
                AdapterError("connection gone", code="CONNECTION_LOST"),
                "CONNECTION_LOST",
            ),
        ],
    )
    def test_failure_mapping_table(self, exception, expected_code):
        setup = Setup()
        error, port = run_with_select_error(setup, exception)
        assert error.failure.code == expected_code
        assert error.failure.stage is AttemptStage.QUERY  # open_query stage
        assert str(error.failure.side.value) == "A"
        assert error.evidence is not None
        assert error.evidence.expectation is not None
        assert error.evidence.terminal.cleanup is CleanupState.DONE
        assert setup.catalog.databases == {}
        assert port.lifecycle_state("attempt-1") is not LifecycleState.SEALED

    def test_missing_after_facts_leave_the_side_null_with_the_real_cause(self):
        # Design 6.2.4 row 4: a disconnect during the SELECT means the
        # after/session facts cannot be collected from the same connection;
        # the side stays null and the failure names QUERY/FETCH + the cause.
        setup = Setup()
        error, port = run_with_select_error(
            setup, AdapterError("connection gone", code="CONNECTION_LOST")
        )
        assert error.failure.code == "CONNECTION_LOST"
        assert error.failure.stage in (AttemptStage.QUERY, AttemptStage.FETCH)
        assert str(error.failure.side.value) == "A"
        evidence = error.evidence
        assert evidence.a_query is None
        assert evidence.a_context is None
        assert evidence.b_query is None

    def test_side_sql_error_is_recorded_and_the_attempt_continues(self):
        # Design 6.2.4 row 2: a per-side SELECT error with recoverable
        # context (the same connection still answers the after probe) is
        # recorded in that side's QueryEvidence and the attempt continues;
        # comparison then sees a non-comparable side, never a match.
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=((int_value(1),),))
        setup.adapters[2].select_errors = {"SELECT": RuntimeError("errno 3024")}
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        evidence = port.execute(request, expectation, make_control(setup.clock))
        assert evidence.failure is None
        assert evidence.terminal.termination is TerminationState.CONFIRMED
        assert evidence.terminal.cleanup is CleanupState.DONE
        assert port.lifecycle_state("attempt-1") is LifecycleState.SEALED
        # Side A: the error row, exactly as the design table writes it.
        a_query = evidence.a_query
        assert a_query is not None
        assert a_query.status is QueryStatus.SQL_ERROR
        assert a_query.result is None
        assert a_query.result_terminal is ResultTerminal.UNKNOWN
        assert a_query.session_start_id == evidence.a_context.select_connection_id
        assert a_query.actual_database == evidence.a_context.current_database
        assert a_query.diagnostics.collected is True
        assert a_query.diagnostics.complete is False
        assert len(a_query.diagnostics.entries) == 1
        entry = a_query.diagnostics.entries[0]
        assert str(entry.level.value) == "ERROR"
        assert entry.message_ref in port.payloads("attempt-1")
        assert b"errno 3024" in port.payloads("attempt-1")[entry.message_ref]
        # Side B still ran to completion under the AB dispatch order.
        assert evidence.b_query is not None
        assert evidence.b_query.status is QueryStatus.COMPLETE
        assert evidence.b_query.result_terminal is ResultTerminal.CONFIRMED
        # The comparison can never turn this into a match.
        verdict = compare_case(request, expectation, evidence, ComparisonBudget())
        assert verdict.status is not ComparisonStatus.MATCH
        assert ComparisonReason.QUERY_NOT_COMPLETE in verdict.reasons

    def test_both_sides_erroring_before_any_fetch_still_seals(self):
        # If every SELECT fails before any fetch starts, the linear machine
        # never left QUERY; the attempt must still seal with both sides
        # recorded as SQL_ERROR rows (never an illegal transition, never a
        # silent match).
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(
            select_errors={"SELECT": RuntimeError("errno 3024")},
            default_result=((int_value(1),),),
        )
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        evidence = port.execute(request, expectation, make_control(setup.clock))
        assert evidence.failure is None
        assert port.lifecycle_state("attempt-1") is LifecycleState.SEALED
        for query in (evidence.a_query, evidence.b_query):
            assert query is not None
            assert query.status is QueryStatus.SQL_ERROR
            assert query.result is None
            assert query.result_terminal is ResultTerminal.UNKNOWN
        assert evidence.terminal.termination is TerminationState.CONFIRMED
        assert evidence.terminal.cleanup is CleanupState.DONE
        verdict = compare_case(request, expectation, evidence, ComparisonBudget())
        assert verdict.status is not ComparisonStatus.MATCH

    def test_result_budget_truncation_keeps_the_partial_result_visible(self):
        # Design 6.2.4 row 3: the over-budget cancel row -- QueryStatus
        # CANCELLED with the partial result set explicitly marked truncated,
        # and AttemptFailure code RESULT_BUDGET_EXCEEDED (no fabricated
        # SQL_ERROR).
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=((int_value(1),),), fetch_truncated=True)
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        with pytest.raises(ExecutionPortError) as excinfo:
            port.execute(request, expectation, make_control(setup.clock))
        failure = excinfo.value.failure
        assert failure.code == "RESULT_BUDGET_EXCEEDED"
        assert failure.stage is AttemptStage.FETCH
        assert str(failure.side.value) == "A"
        evidence = excinfo.value.evidence
        a_query = evidence.a_query
        assert a_query is not None
        assert a_query.status is QueryStatus.CANCELLED
        assert a_query.result is not None
        assert a_query.result.truncated is True
        assert a_query.result_terminal is ResultTerminal.UNKNOWN
        assert evidence.b_query is None  # the attempt aborted before side B
        assert evidence.terminal.cleanup is CleanupState.DONE
        assert setup.catalog.databases == {}

    def test_session_mismatch_stops_before_side_b(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(
            session_error=SessionMismatch(
                "session readback mismatch",
                mismatches=(
                    SessionMismatchEntry(
                        name="transaction_isolation",
                        expected="REPEATABLE-READ",
                        observed="READ-COMMITTED",
                    ),
                ),
            ),
            default_result=((int_value(1),),),
        )
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        with pytest.raises(ExecutionPortError) as excinfo:
            port.execute(request, expectation, make_control(setup.clock))
        failure = excinfo.value.failure
        assert failure.code == "SESSION_MISMATCH"
        assert str(failure.side.value) == "A"
        # No side produced query evidence, and side B never ran a session.
        assert excinfo.value.evidence.a_query is None
        assert excinfo.value.evidence.b_query is None
        query_adapters = [a for a in setup.adapters if a.control is not None]
        assert query_adapters[1].session_calls == []

    def test_session_apply_failure_maps_to_its_code(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(
            session_error=AdapterError("SET failed", code="SESSION_APPLY_FAILED"),
            default_result=((int_value(1),),),
        )
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        with pytest.raises(ExecutionPortError) as excinfo:
            port.execute(request, expectation, make_control(setup.clock))
        assert excinfo.value.failure.code == "SESSION_APPLY_FAILED"

    def test_budget_expiry_mid_fetch_is_never_a_partial_success(self):
        setup = Setup()
        setup.add_prepare_adapters()

        def expire() -> None:
            setup.clock.advance_ms(60_000)

        setup.add_query_adapters(default_result=((int_value(1),),), on_fetch=expire)
        port = setup.build()
        request = setup.request("attempt-1", time_budget_ms=ATTEMPT_BUDGET_MS)
        control = make_control(setup.clock, deadline_ms=5_000)
        expectation = port.prepare(request, control)
        with pytest.raises(ExecutionPortError) as excinfo:
            port.execute(request, expectation, control)
        failure = excinfo.value.failure
        assert failure.code == "RESULT_BUDGET_EXCEEDED"
        assert failure.stage is AttemptStage.FETCH
        evidence = excinfo.value.evidence
        # The cancelled side is recorded as CANCELLED (design 6.2.4 row
        # 3) with its actually observed result and UNKNOWN terminal.
        assert evidence.a_query is not None
        assert evidence.a_query.status is QueryStatus.CANCELLED
        assert evidence.a_query.result is not None
        assert evidence.a_query.result_terminal is ResultTerminal.UNKNOWN
        assert evidence.b_query is None
        # KILL confirmed through the injected control connections; cleanup done.
        assert evidence.terminal.termination is TerminationState.CONFIRMED
        assert evidence.terminal.cleanup is CleanupState.DONE
        assert setup.catalog.databases == {}
        assert any(
            "KILL QUERY" in statement
            for control_conn in setup.controls.values()
            for statement in control_conn.statements
        )

    def test_budget_expiry_without_kill_confirmation_quarantines(self):
        setup = Setup()
        setup.add_prepare_adapters()

        def expire() -> None:
            setup.clock.advance_ms(60_000)

        setup.add_query_adapters(default_result=((int_value(1),),), on_fetch=expire)
        for adapter in setup.adapters[-2:]:
            adapter.control = None  # cancellation unconfirmable
        port = setup.build()
        request = setup.request("attempt-1")
        control = make_control(setup.clock, deadline_ms=5_000)
        expectation = port.prepare(request, control)
        with pytest.raises(ExecutionPortError) as excinfo:
            port.execute(request, expectation, control)
        failure = excinfo.value.failure
        assert failure.code == "RESULT_BUDGET_EXCEEDED"
        evidence = excinfo.value.evidence
        assert evidence.terminal.termination is TerminationState.UNKNOWN
        assert evidence.terminal.cleanup is CleanupState.PENDING
        # Objects preserved for forensics: nothing was dropped.
        assert len(setup.catalog.databases) == 2
        kinds = setup.journal.kinds("attempt-1")
        assert kinds.count("QUARANTINED") == 1
        assert kinds.count("TERMINATION_UNKNOWN") == 1
        assert port.lifecycle_state("attempt-1") is LifecycleState.QUARANTINED
        # The quarantine latch stops all further dispatch on this run
        # (the latch raises its own typed refusal, not an ExecutionPortError).
        with pytest.raises(QuarantineError):
            port.prepare(setup.request("attempt-2"), make_control(setup.clock))

    def test_extra_result_sets_rejected(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(
            default_result=((int_value(1),),), extra_result_sets=1
        )
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        with pytest.raises(ExecutionPortError) as excinfo:
            port.execute(request, expectation, make_control(setup.clock))
        assert excinfo.value.failure.code == "RESULT_CONTRACT_VIOLATION"
        assert excinfo.value.failure.stage is AttemptStage.FETCH

    def test_post_query_environment_drift_aborts(self):
        setup = Setup()
        setup.add_prepare_adapters()
        # Side A's query adapter: first probe normal, post-query probe drifted.
        setup.add_query_adapters(default_result=((int_value(1),),))
        setup.adapters[2].facts_sequence = [
            dict(DEFAULT_FACTS),
            dict(DEFAULT_FACTS, optimizer_switch="index_merge=off"),
        ]
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        with pytest.raises(ExecutionPortError) as excinfo:
            port.execute(request, expectation, make_control(setup.clock))
        assert excinfo.value.failure.code == "ENVIRONMENT_DRIFT"
        assert excinfo.value.failure.stage is AttemptStage.FETCH
        assert str(excinfo.value.failure.side.value) == "A"

    def test_cooperative_cancellation_after_the_first_side(self):
        setup = Setup()
        setup.add_prepare_adapters()
        token = CancelToken()
        setup.add_query_adapters(default_result=((int_value(1),),))
        setup.adapters[2].on_fetch = lambda: setattr(token, "cancelled_flag", True)
        port = setup.build()
        request = setup.request("attempt-1")
        control = make_control(setup.clock, cancelled=token)
        expectation = port.prepare(request, control)
        with pytest.raises(ExecutionPortError) as excinfo:
            port.execute(request, expectation, control)
        assert excinfo.value.failure.code == "CANCELLED"
        assert excinfo.value.failure.stage is AttemptStage.FETCH
        assert excinfo.value.evidence.terminal.cleanup is CleanupState.DONE
        assert setup.catalog.databases == {}

    def test_execute_requires_a_prepared_attempt(self):
        setup, port = default_setup()
        request = setup.request("attempt-x")
        expectation = AttemptExpectation(
            binding=ExpectedBinding(
                run_id=request.run_id,
                case_id=request.case_id,
                attempt_id=request.attempt_id,
                environment_hash="0" * 64,
                name_map_hash="0" * 64,
            ),
            request_hash=request.request_hash,
            codec_version="mysql-text-1",
            execution_order=ExecutionOrder.AB,
            name_map=NameMap(
                database_a=f"tc_{RUN_TOKEN}_{'f' * 16}_a",
                database_b=f"tc_{RUN_TOKEN}_{'f' * 16}_b",
                table_a="case_a",
                table_b="case_b",
            ),
        )
        with pytest.raises(ExecutionPortError) as excinfo:
            port.execute(request, expectation, make_control(setup.clock))
        assert excinfo.value.failure.code == "EXECUTION_PROTOCOL_ERROR"

    def test_execute_with_a_foreign_expectation_refused(self):
        setup = Setup()
        setup.add_prepare_adapters()
        port = setup.build()
        control = make_control(setup.clock)
        expectation_1 = port.prepare(setup.request("attempt-1"), control)
        expectation_2 = port.prepare(setup.request("attempt-2"), control)
        with pytest.raises(ExecutionPortError) as excinfo:
            port.execute(setup.request("attempt-2"), expectation_1, control)
        assert excinfo.value.failure.code == "EXECUTION_PROTOCOL_ERROR"
        assert expectation_2.request_hash != expectation_1.request_hash


# --------------------------------------------------------------------------
# cancel_and_wait
# --------------------------------------------------------------------------


class TestCancelAndWait:
    def test_unknown_attempt_reports_attempt_not_found(self):
        setup, port = default_setup()
        with pytest.raises(ExecutionPortError) as excinfo:
            port.cancel_and_wait("no-such-attempt", 1.0)
        assert excinfo.value.failure.code == "ATTEMPT_NOT_FOUND"
        assert excinfo.value.failure.stage is AttemptStage.CANCEL
        assert excinfo.value.evidence is None

    def test_terminal_attempt_returns_the_stored_receipt(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=((int_value(1),),))
        port = setup.build()
        request = setup.request("attempt-1")
        expectation = port.prepare(request, make_control(setup.clock))
        evidence = port.execute(request, expectation, make_control(setup.clock))
        terminal = port.cancel_and_wait("attempt-1", 1.0)
        assert terminal == evidence.terminal
        assert terminal.cleanup is CleanupState.DONE

    def test_prepared_attempt_terminates_but_cleanup_needs_a_connection(self):
        # After prepare() the port closed its connections; termination is
        # trivially confirmed (nothing is in flight) but the drops cannot be
        # verified without a live adapter, so the attempt quarantines with its
        # objects preserved.  This documents the synchronous-port behaviour;
        # Phase 5 keeps a cleanup connection for this path.
        setup = Setup()
        setup.add_prepare_adapters()
        port = setup.build()
        port.prepare(setup.request("attempt-1"), make_control(setup.clock))
        # Termination is confirmed, so the receipt is returned (like the
        # terminal idempotent path); only UNKNOWN termination raises.
        terminal = port.cancel_and_wait("attempt-1", 1.0)
        assert terminal.termination is TerminationState.CONFIRMED
        assert terminal.cleanup is CleanupState.FAILED
        # Both databases and both test tables are preserved for forensics.
        assert len(terminal.owned_objects) == 4
        assert port.lifecycle_state("attempt-1") is LifecycleState.QUARANTINED
        assert setup.journal.kinds("attempt-1").count("QUARANTINED") == 1
        assert len(setup.catalog.databases) == 2

    def test_invalid_arguments_refused(self):
        setup, port = default_setup()
        with pytest.raises(ContractError):
            port.cancel_and_wait("attempt-1", 0)
        with pytest.raises(ContractError):
            port.cancel_and_wait("attempt-1", True)
        with pytest.raises(ExecutionPortError):
            port.cancel_and_wait("", 1.0)

    def test_cancel_and_wait_after_an_unconfirmable_unwind_is_idempotent(self):
        setup = Setup()
        setup.add_prepare_adapters()

        def expire() -> None:
            setup.clock.advance_ms(60_000)

        setup.add_query_adapters(default_result=((int_value(1),),), on_fetch=expire)
        for adapter in setup.adapters[-2:]:
            adapter.control = None
        port = setup.build()
        request = setup.request("attempt-1")
        control = make_control(setup.clock, deadline_ms=5_000)
        expectation = port.prepare(request, control)
        with pytest.raises(ExecutionPortError):
            port.execute(request, expectation, control)
        terminal = port.cancel_and_wait("attempt-1", 1.0)
        assert terminal.termination is TerminationState.UNKNOWN
        assert terminal.cleanup is CleanupState.PENDING


# --------------------------------------------------------------------------
# Determinism / injection seams
# --------------------------------------------------------------------------


class TestInjectionSeams:
    def test_token_source_drives_every_name(self):
        tokens = ["abcd1234abcd1234", "0000000000000001", "0000000000000002"]
        setup = Setup()
        setup.add_prepare_adapters()
        port = setup.build(tokens=tokens)
        first = port.prepare(setup.request("attempt-1"), make_control(setup.clock))
        second = port.prepare(setup.request("attempt-2"), make_control(setup.clock))
        assert first.name_map.database_a == "tc_abcd1234abcd1234_0000000000000001_a"
        assert second.name_map.database_b == "tc_abcd1234abcd1234_0000000000000002_b"

    def test_ports_share_no_state(self):
        setup = Setup()
        setup.add_prepare_adapters()
        setup.add_query_adapters(default_result=((int_value(1),),))
        first = setup.build()
        second = setup.build(
            tokens=["0123456789abcdef", "ffffffffffffffff"]
        )
        request = setup.request("attempt-1")
        control = make_control(setup.clock)
        expectation_a = first.prepare(request, control)
        expectation_b = second.prepare(request, control)
        assert expectation_a.name_map.database_a != expectation_b.name_map.database_a
        evidence_a = first.execute(request, expectation_a, make_control(setup.clock))
        evidence_b = second.execute(request, expectation_b, make_control(setup.clock))
        assert evidence_a.evidence_hash != evidence_b.evidence_hash
        assert first.lifecycle_state("attempt-1") is LifecycleState.SEALED
        assert second.lifecycle_state("attempt-1") is LifecycleState.SEALED
