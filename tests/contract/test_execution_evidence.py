"""C01/D2 contract tests: execution evidence models, loaders and hash chain.

The golden hashes below were produced once by an independent script (plain
``json.dumps`` canonicalization hashed with ``hashlib`` and cross-checked with
the external ``shasum -a 256`` tool) and are frozen as literals; no assertion
recomputes its own expectation through a project hash helper.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from mtsql_typecheck.contracts import codec
from mtsql_typecheck.contracts.case import (
    CasePayload,
    ColumnSpec,
    ContractError,
    EnvironmentRequirements,
    ExpectedBinding,
    IndexVariant,
    IntegerValue,
    NameMap,
    NullValue,
    ObservedEnvironment,
    QuerySpec,
    ResultColumnSpec,
    ResultRelationSpec,
    RelationMode,
    Row,
    Rows,
    RuleRef,
    NullPolicy,
    RuntimeFacts,
    SemverIdentity,
    SideFacts,
    SignedIntegerType,
    SignedIntName,
    StatementPhase,
    StatementReceipt,
    TableSpec,
    TemplateId,
    TypeFamily,
    ValueEquivalence,
    REQUIRED_SQL_MODE_TOKENS,
)
from mtsql_typecheck.contracts.execution import (
    ATTEMPT_BUDGET_MS,
    EXECUTION_SCHEMA_VERSION,
    MAX_EVIDENCE_BYTES,
    MAX_RESULT_BYTES,
    MAX_RESULT_COLUMNS,
    MAX_RESULT_SCALE,
    AttemptExpectation,
    AttemptFailure,
    AttemptRequest,
    AttemptStage,
    CleanupState,
    Control,
    ControlCancelled,
    DiagnosticEntry,
    DiagnosticLevel,
    ExecutionEvidence,
    ExecutionOrder,
    ExecutionPortError,
    IsolationReceipt,
    PreflightRejection,
    QueryEvidence,
    QueryStatus,
    ResultColumn,
    ResultTerminal,
    ResultSet,
    ResultValue,
    ResultValueKind,
    SelectPhase,
    SessionProfile,
    Side,
    SideContext,
    StatementDiagnostics,
    TerminalReceipt,
    TerminationState,
    TransactionIsolation,
    decode_attempt_request,
    decode_execution_evidence,
    decode_result_value,
    decode_statement_diagnostics,
    default_control,
    dump_attempt_expectation,
    dump_attempt_request,
    dump_execution_evidence,
    load_attempt_expectation,
    load_attempt_request,
    load_execution_evidence,
)
from mtsql_typecheck.contracts.codec import canonical_json, parse_strict_json

FIXTURES = Path(__file__).parent / "fixtures"
D2 = FIXTURES / "d2"

# Frozen once with plain json.dumps + hashlib over the canonical content of
# evidence_success_match.json, cross-checked with the external `shasum -a 256`
# tool; no assertion recomputes its own expectation with the code under test.
# Re-frozen for the D3 online-handover fix (A02): the fixture's query session
# ids were unified with their SideContext select_connection_id, so the
# evidence content (and only the evidence content) changed.
GOLDEN_EVIDENCE_HASH = "116295b572748ebe04fc2c9b9eb5101b1a12271399f5da6eac443917559df85c"
GOLDEN_REQUEST_HASH = "bddacf5bc2b7c9c484183940304dcc7f3ec1562a44760537385d4970c98058fc"


# --------------------------------------------------------------------------
# Shared builders
# --------------------------------------------------------------------------


def _rv_int(value: int) -> ResultValue:
    return ResultValue(ResultValueKind.INTEGER, int_value=value)


def _rv_dec(coefficient: int, scale: int) -> ResultValue:
    return ResultValue(ResultValueKind.DECIMAL, coefficient=coefficient, scale=scale)


def _payload():
    return CasePayload(
        rule=RuleRef("mysql80.signed-widen", 1),
        a_type=SignedIntegerType(SignedIntName.TINYINT),
        b_type=SignedIntegerType(SignedIntName.SMALLINT),
        table=TableSpec(
            "t0",
            (
                ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
                ColumnSpec("v", SignedIntegerType(SignedIntName.TINYINT), True),
            ),
            ("rid",),
            IndexVariant.NONE,
        ),
        rows=Rows(
            (
                Row(1, IntegerValue(-(2**63) + 1)),
                Row(2, IntegerValue(0)),
                Row(3, NullValue()),
                Row(4, IntegerValue(9007199254740993)),
            )
        ),
        query=QuerySpec(TemplateId.Q1),
        relation=ResultRelationSpec(
            RelationMode.MULTISET_EXACT,
            (
                ResultColumnSpec(
                    "c0",
                    TypeFamily.SIGNED_INTEGER,
                    TypeFamily.SIGNED_INTEGER,
                    ValueEquivalence.EXACT_NUMERIC,
                    NullPolicy.PRESERVE,
                ),
            ),
        ),
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


def _env() -> ObservedEnvironment:
    return ObservedEnvironment(
        instance_identity="mysql-8039-local",
        version="8.0.39",
        vendor="mysql",
        build_id="20250715",
        engine="innodb",
        sql_mode_tokens=("NO_ENGINE_SUBSTITUTION", "ONLY_FULL_GROUP_BY", "STRICT_ALL_TABLES"),
        character_set="utf8mb4",
        collation="utf8mb4_bin",
        time_zone="+00:00",
        optimizer_switch="index_merge=on,mrr=off",
    )


def _profile() -> SessionProfile:
    return SessionProfile(True, TransactionIsolation.REPEATABLE_READ)


def _request() -> AttemptRequest:
    return AttemptRequest(
        run_id="run-test-1",
        attempt_id="attempt-test-1",
        payload=_payload(),
        target_environment=_env(),
        session_profile=_profile(),
        execution_order=ExecutionOrder.AB,
        result_row_budget=1024,
        result_byte_budget=MAX_RESULT_BYTES,
        time_budget_ms=ATTEMPT_BUDGET_MS,
        synthetic=True,
    )


def _binding(request: AttemptRequest, name_map: NameMap) -> ExpectedBinding:
    return ExpectedBinding(
        run_id=request.run_id,
        case_id=request.case_id,
        attempt_id=request.attempt_id,
        environment_hash=codec.sha256_hex(canonical_json(request.target_environment.to_obj())),
        name_map_hash=codec.sha256_hex(canonical_json(name_map.to_obj())),
    )


def _name_map() -> NameMap:
    return NameMap("tc_a", "tc_b", "t_a", "t_b")


def _d2_doc(name: str) -> dict:
    doc = json.loads((D2 / f"{name}.json").read_text(encoding="utf-8"))
    return {k: v for k, v in doc.items() if not k.startswith("_")}


def _result_set() -> ResultSet:
    return ResultSet(
        columns=(
            ResultColumn(0, "c0", TypeFamily.SIGNED_INTEGER, 1, 0, 3, 0, "d3-mapping-1"),
        ),
        rows=((_rv_int(-128),), (ResultValue(ResultValueKind.NULL),)),
        observed_row_count=2,
        fetch_complete=True,
        truncated=False,
        extra_result_sets=0,
        encoding_version="mysql-text-1",
    )


def _query(request: AttemptRequest, status: QueryStatus = QueryStatus.COMPLETE) -> QueryEvidence:
    return QueryEvidence(
        side=Side.A,
        binding=_binding(request, _name_map()),
        select_text="SELECT `v` AS `c0` FROM `t_a`;",
        select_sql_hash=codec.sha256_hex(b"SELECT `v` AS `c0` FROM `t_a`;"),
        protocol="text",
        parameters=(),
        status=status,
        result=_result_set() if status is QueryStatus.COMPLETE else None,
        session_start_id="sess-a-1",
        session_end_id="sess-a-1",
        actual_database="tc_a",
        environment_before=request.target_environment,
        environment_after=request.target_environment,
        diagnostics=StatementDiagnostics(
            side=Side.A,
            phase=SelectPhase.SELECT,
            ordinal=0,
            sql_hash=codec.sha256_hex(b"SELECT `v` AS `c0` FROM `t_a`;"),
            collected=True,
            complete=True,
            entries=(),
        ),
        duration_ms=5,
        result_terminal=ResultTerminal.CONFIRMED,
    )


# --------------------------------------------------------------------------
# ResultValue roundtrips
# --------------------------------------------------------------------------


def test_result_value_integer_above_float53_roundtrip():
    value = _rv_int(9007199254740993)
    assert value.to_obj() == {"kind": "integer", "value": "9007199254740993"}
    assert canonical_json(value.to_obj()) == b'{"kind":"integer","value":"9007199254740993"}'
    assert decode_result_value(parse_strict_json(canonical_json(value.to_obj()))) == value


def test_result_value_decimal_and_null_roundtrip():
    for value in (
        _rv_dec(-12345, 2),
        _rv_dec(5, 0),
        _rv_dec(0, MAX_RESULT_SCALE),
        ResultValue(ResultValueKind.NULL),
    ):
        encoded = canonical_json(value.to_obj())
        assert decode_result_value(parse_strict_json(encoded)) == value
        assert decode_result_value(value.to_obj()) == value


# --------------------------------------------------------------------------
# ResultValue strict rejections: both the constructor and the loader path
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "make,raw",
    [
        (lambda: _rv_int(1.5), b'{"kind":"integer","value":1.5}'),
        (lambda: _rv_int(True), b'{"kind":"integer","value":true}'),
        (lambda: _rv_int(10**80), b'{"kind":"integer","value":"' + b"9" * 81 + b'"}'),
        (
            lambda: _rv_dec(1, 66),
            b'{"kind":"decimal","coefficient":"1","scale":66}',
        ),
        (lambda: ResultValue(ResultValueKind.NULL, int_value=0), b'{"kind":"null","value":"0"}'),
    ],
)
def test_result_value_rejected_by_constructor_and_loader(make, raw):
    with pytest.raises(ContractError):
        make()
    with pytest.raises(ContractError):
        decode_result_value(parse_strict_json(raw))


def test_result_value_loader_rejects_non_canonical_negative_zero_and_exponent():
    with pytest.raises(ContractError, match="canonical"):
        decode_result_value(parse_strict_json(b'{"kind":"integer","value":"-0"}'))
    with pytest.raises(ContractError, match="canonical"):
        decode_result_value({"kind": "decimal", "coefficient": "-0", "scale": 0})
    with pytest.raises(ContractError, match="float"):
        parse_strict_json(b'{"kind":"decimal","coefficient":1e3,"scale":0}')


def test_result_value_rejects_unknown_kind_and_unknown_fields():
    with pytest.raises(ContractError, match="ResultValueKind"):
        ResultValue("string")  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="unknown kind"):
        decode_result_value({"kind": "string", "value": "x"})
    with pytest.raises(ContractError, match="unknown fields"):
        decode_result_value({"kind": "null", "extra": 1})


def test_execution_loaders_reject_duplicate_keys_and_depth_and_unknown_schema():
    with pytest.raises(ContractError, match="duplicate"):
        load_attempt_request(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(ContractError, match="depth"):
        load_execution_evidence(("[" * 33 + "]" * 33).encode())
    doc = _d2_doc("evidence_prepare_failure")["request"]
    doc["schema_version"] = EXECUTION_SCHEMA_VERSION + 1
    with pytest.raises(ContractError, match="schema_version"):
        decode_attempt_request(doc)
    missing = {k: v for k, v in _d2_doc("evidence_prepare_failure")["request"].items()}
    del missing["schema_version"]
    with pytest.raises(ContractError, match="missing required field"):
        decode_attempt_request(missing)


# --------------------------------------------------------------------------
# ResultSet invariants
# --------------------------------------------------------------------------


def test_result_set_roundtrip_and_payload_hash_shape():
    rs = _result_set()
    assert rs.payload_hash == codec.sha256_hex(canonical_json(rs.result_obj()))
    assert rs.result_obj() == {
        "columns": [rs.columns[0].to_obj()],
        "rows": [[{"kind": "integer", "value": "-128"}], [{"kind": "null"}]],
    }
    from mtsql_typecheck.contracts.execution import decode_result_set

    assert decode_result_set(parse_strict_json(canonical_json(rs.to_obj()))) == rs


def test_result_set_rejects_payload_hash_tampering():
    fields = dict(
        columns=(_result_set().columns[0],),
        rows=_result_set().rows,
        observed_row_count=2,
        fetch_complete=True,
        truncated=False,
        extra_result_sets=0,
        encoding_version="mysql-text-1",
    )
    with pytest.raises(ContractError, match="payload_hash"):
        ResultSet(payload_hash="0" * 64, **fields)


def test_result_set_rejects_row_width_and_count_mismatches_and_contradiction():
    column = ResultColumn(0, "c0", TypeFamily.SIGNED_INTEGER, 1, 0, 3, 0, "d3-mapping-1")
    with pytest.raises(ContractError, match="row must hold exactly"):
        ResultSet(
            columns=(column,),
            rows=((_rv_int(1), _rv_int(2)),),
            observed_row_count=1,
            fetch_complete=True,
            truncated=False,
            extra_result_sets=0,
            encoding_version="v1",
        )
    with pytest.raises(ContractError, match="observed_row_count"):
        ResultSet(
            columns=(column,),
            rows=((_rv_int(1),),),
            observed_row_count=2,
            fetch_complete=True,
            truncated=False,
            extra_result_sets=0,
            encoding_version="v1",
        )
    with pytest.raises(ContractError, match="contradictory"):
        ResultSet(
            columns=(column,),
            rows=(),
            observed_row_count=0,
            fetch_complete=True,
            truncated=True,
            extra_result_sets=0,
            encoding_version="v1",
        )


def test_result_set_rejects_non_consecutive_ordinals_and_too_many_columns():
    columns = tuple(
        ResultColumn(i, f"c{i}", TypeFamily.SIGNED_INTEGER, 1, 0, 3, 0, "d3-mapping-1")
        for i in range(MAX_RESULT_COLUMNS + 1)
    )
    with pytest.raises(ContractError, match="columns"):
        ResultSet(
            columns=columns,
            rows=(),
            observed_row_count=0,
            fetch_complete=True,
            truncated=False,
            extra_result_sets=0,
            encoding_version="v1",
        )
    with pytest.raises(ContractError, match="consecutive"):
        ResultSet(
            columns=(
                ResultColumn(0, "c0", TypeFamily.SIGNED_INTEGER, 1, 0, 3, 0, "m"),
                ResultColumn(2, "c1", TypeFamily.SIGNED_INTEGER, 1, 0, 3, 0, "m"),
            ),
            rows=(),
            observed_row_count=0,
            fetch_complete=True,
            truncated=False,
            extra_result_sets=0,
            encoding_version="v1",
        )


# --------------------------------------------------------------------------
# ExecutionEvidence status matrix
# --------------------------------------------------------------------------


def _full_evidence(request: AttemptRequest) -> ExecutionEvidence:
    return ExecutionEvidence(
        request_hash=request.request_hash,
        expectation=AttemptExpectation(
            binding=_binding(request, _name_map()),
            request_hash=request.request_hash,
            codec_version="mysql-text-1",
            execution_order=request.execution_order,
            name_map=_name_map(),
        ),
        runtime_facts=_facts(request, with_b=True),
        setup_diagnostics=_setup_diagnostics(),
        actual_execution_order=ExecutionOrder.AB,
        a_context=_context(Side.A),
        b_context=_context(Side.B),
        a_query=_query(request),
        b_query=_query(request),
        isolation_receipt=IsolationReceipt(
            attempt_id=request.attempt_id,
            name_map_hash=codec.sha256_hex(canonical_json(_name_map().to_obj())),
            ownership_ref="run-test-1/objects/tc_a,tc_b",
            objects_created_confirmed=True,
            load_committed=True,
            no_concurrent_write_confirmed=True,
            method_version="d3-isolation-1",
        ),
        terminal=TerminalReceipt(
            request.attempt_id, TerminationState.CONFIRMED, CleanupState.DONE, ()
        ),
        failure=None,
        preflight_rejection=None,
        synthetic=True,
    )


def _facts(request: AttemptRequest, with_b: bool) -> RuntimeFacts:
    receipt = StatementReceipt(
        StatementPhase.DDL, 0, codec.sha256_hex(b"CREATE TABLE"), True, True
    )
    # codec.decode_side_facts requires the "actual_schema" key, so model a
    # real collected schema here (as real D3 evidence would).
    schema = TableSpec(
        "t0",
        (
            ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
            ColumnSpec("v", SignedIntegerType(SignedIntName.TINYINT), True),
        ),
        ("rid",),
        IndexVariant.NONE,
    )
    return RuntimeFacts(
        binding=_binding(request, _name_map()),
        observed_environment=request.target_environment,
        name_map=_name_map(),
        a=SideFacts(statement_receipts=(receipt,), actual_schema=schema),
        b=SideFacts(statement_receipts=(receipt,), actual_schema=schema) if with_b else None,
    )


def _setup_diagnostics() -> tuple:
    return (
        StatementDiagnostics(
            Side.A,
            StatementPhase.DDL,
            0,
            codec.sha256_hex(b"CREATE TABLE `t_a`"),
            True,
            True,
            (),
        ),
    )


def _context(side: Side) -> SideContext:
    return SideContext(
        side=side,
        setup_connection_id="conn-1",
        readback_connection_id="conn-1",
        select_connection_id="conn-1",
        current_database=_name_map().database_a if side is Side.A else _name_map().database_b,
        name_map=_name_map(),
        autocommit=True,
        transaction_isolation=TransactionIsolation.REPEATABLE_READ,
        environment_before=_env(),
        environment_after=_env(),
    )


def test_full_evidence_roundtrip_through_loader():
    evidence = _full_evidence(_request())
    restored = load_execution_evidence(dump_execution_evidence(evidence))
    assert restored == evidence
    assert restored.evidence_hash == evidence.evidence_hash


def test_prepare_failure_allows_missing_expectation_facts_and_queries():
    request = _request()
    evidence = ExecutionEvidence(
        request_hash=request.request_hash,
        expectation=None,
        runtime_facts=None,
        setup_diagnostics=(),
        actual_execution_order=None,
        a_context=None,
        b_context=None,
        a_query=None,
        b_query=None,
        isolation_receipt=None,
        terminal=TerminalReceipt(
            request.attempt_id, TerminationState.NOT_STARTED, CleanupState.DONE, ()
        ),
        failure=AttemptFailure(AttemptStage.PREPARE, "prepare_refused", None, None),
        preflight_rejection=None,
        synthetic=True,
    )
    assert load_execution_evidence(dump_execution_evidence(evidence)) == evidence


def test_side_b_not_started_and_missing_terminal_are_legal():
    request = _request()
    base = _full_evidence(request)
    partial = ExecutionEvidence(
        request_hash=base.request_hash,
        expectation=base.expectation,
        runtime_facts=_facts(request, with_b=False),
        setup_diagnostics=(),
        actual_execution_order=ExecutionOrder.AB,
        a_context=base.a_context,
        b_context=None,
        a_query=base.a_query,
        b_query=None,
        isolation_receipt=None,
        terminal=None,  # missing terminal is legal; consumers treat UNKNOWN
        failure=None,
        preflight_rejection=None,
        synthetic=True,
    )
    assert load_execution_evidence(dump_execution_evidence(partial)) == partial


def test_evidence_with_neither_rejection_failure_nor_prepare_success_is_rejected():
    request = _request()
    with pytest.raises(ContractError, match="neither a preflight rejection"):
        ExecutionEvidence(
            request_hash=request.request_hash,
            expectation=None,
            runtime_facts=None,
            setup_diagnostics=(),
            actual_execution_order=None,
            a_context=None,
            b_context=None,
            a_query=None,
            b_query=None,
            isolation_receipt=None,
            terminal=None,
            failure=None,
            preflight_rejection=None,
            synthetic=True,
        )


def test_preflight_rejection_excludes_post_prepare_content():
    request = _request()
    rejection = PreflightRejection(
        request_hash=request.request_hash,
        observed_environment=request.target_environment,
        rejected_requirement_id="environment.same-instance",
        capability_check_version="d3-capability-1",
    )
    legal = ExecutionEvidence(
        request_hash=request.request_hash,
        expectation=None,
        runtime_facts=None,
        setup_diagnostics=(),
        actual_execution_order=None,
        a_context=None,
        b_context=None,
        a_query=None,
        b_query=None,
        isolation_receipt=None,
        terminal=TerminalReceipt(
            request.attempt_id, TerminationState.NOT_STARTED, CleanupState.DONE, ()
        ),
        failure=None,
        preflight_rejection=rejection,
        synthetic=True,
    )
    assert load_execution_evidence(dump_execution_evidence(legal)) == legal
    base = _full_evidence(request)
    for field, value in (
        ("expectation", base.expectation),
        ("runtime_facts", base.runtime_facts),
        ("a_context", base.a_context),
        ("isolation_receipt", base.isolation_receipt),
    ):
        kwargs = {k: getattr(legal, k) for k in (
            "request_hash", "expectation", "runtime_facts", "setup_diagnostics",
            "actual_execution_order", "a_context", "b_context", "a_query", "b_query",
            "isolation_receipt", "terminal", "failure", "preflight_rejection", "synthetic",
        )}
        kwargs[field] = value
        with pytest.raises(ContractError, match="preflight rejection"):
            ExecutionEvidence(**kwargs)


def test_prepare_failure_with_post_prepare_content_is_rejected():
    request = _request()
    base = _full_evidence(request)
    for field, value in (
        ("expectation", base.expectation),
        ("a_context", base.a_context),
        ("a_query", base.a_query),
    ):
        kwargs = {k: getattr(base, k) for k in (
            "request_hash", "expectation", "runtime_facts", "setup_diagnostics",
            "actual_execution_order", "a_context", "b_context", "a_query", "b_query",
            "isolation_receipt", "terminal", "failure", "preflight_rejection", "synthetic",
        )}
        kwargs["failure"] = AttemptFailure(AttemptStage.PREPARE, "prepare_refused", None, None)
        kwargs[field] = value
        with pytest.raises(ContractError, match="PREPARE failure"):
            ExecutionEvidence(**kwargs)


def test_post_prepare_failure_requires_expectation():
    request = _request()
    with pytest.raises(ContractError, match="post-PREPARE failure requires"):
        ExecutionEvidence(
            request_hash=request.request_hash,
            expectation=None,
            runtime_facts=None,
            setup_diagnostics=(),
            actual_execution_order=None,
            a_context=None,
            b_context=None,
            a_query=None,
            b_query=None,
            isolation_receipt=None,
            terminal=None,
            failure=AttemptFailure(AttemptStage.QUERY, "query_failed", Side.A, None),
            preflight_rejection=None,
            synthetic=True,
        )


def test_contradictory_success_is_rejected():
    request = _request()
    with pytest.raises(ContractError, match="COMPLETE requires a fetched result"):
        QueryEvidence(
            side=Side.A,
            binding=_binding(request, _name_map()),
            select_text="SELECT `v` AS `c0` FROM `t_a`;",
            select_sql_hash=codec.sha256_hex(b"SELECT `v` AS `c0` FROM `t_a`;"),
            protocol="text",
            parameters=(),
            status=QueryStatus.COMPLETE,
            result=None,
            session_start_id="sess-a-1",
            session_end_id="sess-a-1",
            actual_database="tc_a",
            environment_before=request.target_environment,
            environment_after=request.target_environment,
            diagnostics=StatementDiagnostics(
                Side.A, SelectPhase.SELECT, 0,
                codec.sha256_hex(b"SELECT `v` AS `c0` FROM `t_a`;"), True, True, (),
            ),
            duration_ms=1,
            result_terminal=ResultTerminal.UNKNOWN,
        )
    with pytest.raises(ContractError, match="contradictory"):
        ResultSet(
            columns=(ResultColumn(0, "c0", TypeFamily.SIGNED_INTEGER, 1, 0, 3, 0, "m"),),
            rows=((_rv_int(1),),),
            observed_row_count=1,
            fetch_complete=True,
            truncated=True,
            extra_result_sets=0,
            encoding_version="v1",
        )


def test_statement_diagnostics_contradictions_are_rejected():
    with pytest.raises(ContractError, match="not collected"):
        StatementDiagnostics(Side.A, StatementPhase.DDL, 0, "0" * 64, False, True, ())
    with pytest.raises(ContractError, match="not collected must have empty entries"):
        StatementDiagnostics(
            Side.A, StatementPhase.DDL, 0, "0" * 64, False, False,
            (DiagnosticEntry(DiagnosticLevel.ERROR, "ER_X", None, None),),
        )
    with pytest.raises(ContractError, match="empty entries"):
        StatementDiagnostics(
            Side.A, StatementPhase.DDL, 0, "0" * 64, True, True,
            (DiagnosticEntry(DiagnosticLevel.NOTE, "N_X", None, None),),
        )


def test_setup_diagnostics_reject_select_phase_and_queries_require_it():
    request = _request()
    with pytest.raises(ContractError, match="ddl/insert"):
        ExecutionEvidence(
            request_hash=request.request_hash,
            expectation=None,
            runtime_facts=None,
            setup_diagnostics=(
                StatementDiagnostics(
                    Side.A, SelectPhase.SELECT, 0,
                    codec.sha256_hex(b"SELECT"), True, True, (),
                ),
            ),
            actual_execution_order=None,
            a_context=None,
            b_context=None,
            a_query=None,
            b_query=None,
            isolation_receipt=None,
            terminal=None,
            failure=AttemptFailure(AttemptStage.PREPARE, "prepare_refused", None, None),
            preflight_rejection=None,
            synthetic=True,
        )
    # The loader mirrors the constructor: setup diagnostics must decode as
    # ddl/insert, query diagnostics must decode as "select".
    with pytest.raises(ContractError, match="must be \"select\""):
        decode_statement_diagnostics(
            {
                "side": "A",
                "phase": "ddl",
                "ordinal": 0,
                "sql_hash": "0" * 64,
                "collected": True,
                "complete": True,
                "entries": [],
            },
            "query diagnostics",
            select=True,
        )


def test_query_evidence_requires_session_identity_and_rejects_parameter_mismatch():
    request = _request()
    base = _query(request)
    with pytest.raises(ContractError, match="session"):
        QueryEvidence(**{**base.__dict__, "session_start_id": None, "session_end_id": None})
    with pytest.raises(ContractError, match="equal"):
        QueryEvidence(**{**base.__dict__, "session_end_id": "sess-a-2"})
    with pytest.raises(ContractError, match="text"):
        QueryEvidence(**{**base.__dict__, "protocol": "binary"})


def test_evidence_size_budget_rejects_oversized_raw_bytes_before_parsing():
    oversized = b" " * (MAX_EVIDENCE_BYTES + 1)
    with pytest.raises(ContractError, match="MAX_EVIDENCE_BYTES"):
        load_execution_evidence(oversized)


# --------------------------------------------------------------------------
# Hash chain
# --------------------------------------------------------------------------


def _canonical_content_bytes(doc: dict) -> bytes:
    content = {k: v for k, v in doc.items() if k != "evidence_hash"}
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def test_golden_evidence_hash_matches_independent_canonicalization():
    doc = _d2_doc("evidence_success_match")["evidence"]
    assert hashlib.sha256(_canonical_content_bytes(doc)).hexdigest() == GOLDEN_EVIDENCE_HASH
    assert doc["evidence_hash"] == GOLDEN_EVIDENCE_HASH
    evidence = load_execution_evidence(doc)
    assert evidence.evidence_hash == GOLDEN_EVIDENCE_HASH
    # The hash never covers itself.
    assert "evidence_hash" not in evidence.to_obj()


def test_golden_request_hash_and_case_id_binding():
    doc = _d2_doc("evidence_success_match")
    request = load_attempt_request(doc["request"])
    assert request.request_hash == GOLDEN_REQUEST_HASH
    assert doc["expectation"]["binding"]["case_id"] == request.case_id
    expectation = load_attempt_expectation(doc["expectation"])
    assert expectation.request_hash == request.request_hash
    assert expectation.binding.case_id == request.case_id


def test_request_hash_and_case_id_track_payload_content():
    request = _request()
    assert request.case_id == codec.case_id_of(request.payload)
    tampered_doc = _d2_doc("evidence_success_match")["request"]
    tampered_doc["payload"]["rows"][0][1]["value"] = "127"  # was "-128"
    tampered = decode_attempt_request(tampered_doc)
    assert tampered.case_id != request.case_id
    assert tampered.request_hash != request.request_hash


def test_evidence_hash_covers_content_and_rejects_mismatch():
    evidence = load_execution_evidence(_d2_doc("evidence_success_match")["evidence"])
    candidate = load_execution_evidence(_d2_doc("evidence_success_candidate")["evidence"])
    assert evidence.evidence_hash != candidate.evidence_hash
    # Same content deterministically produces the same hash.
    again = load_execution_evidence(_d2_doc("evidence_success_match")["evidence"])
    assert again.evidence_hash == evidence.evidence_hash
    # Tampered content with the stale hash is rejected.
    tampered = copy.deepcopy(_d2_doc("evidence_success_match")["evidence"])
    tampered["a_query"]["duration_ms"] = 99
    with pytest.raises(ContractError, match="evidence_hash"):
        decode_execution_evidence(tampered)


def test_dump_roundtrips_for_request_and_expectation():
    request = _request()
    assert load_attempt_request(dump_attempt_request(request)) == request
    expectation = AttemptExpectation(
        binding=_binding(request, _name_map()),
        request_hash=request.request_hash,
        codec_version="mysql-text-1",
        execution_order=ExecutionOrder.AB,
        name_map=_name_map(),
    )
    assert expectation.expectation_hash == codec.sha256_hex(
        canonical_json(expectation.to_obj())
    )
    assert load_attempt_expectation(dump_attempt_expectation(expectation)) == expectation


# --------------------------------------------------------------------------
# Control and port errors
# --------------------------------------------------------------------------


def test_control_remaining_expired_and_child_deadline():
    now = 1000.0
    control = Control(lambda: now, 1002.0, lambda: False)
    assert control.remaining_ms() == 2000
    assert not control.expired()
    child = control.child(1.0)
    assert child.deadline == 1001.0  # min(1002, now + 1)
    assert child.child(10.0).deadline == 1001.0  # never extends
    assert Control(lambda: now, None, lambda: False).child(1.0).deadline == 1001.0
    late = Control(lambda: 1003.0, 1002.0, lambda: False)
    assert late.remaining_ms() == 0
    assert late.expired()


def test_control_unbounded_and_validation():
    control = default_control()
    assert control.remaining_ms() > 10**12
    assert not control.expired()
    assert control.child(None).deadline is None
    with pytest.raises(ContractError, match="callable"):
        Control(None, None, lambda: False)  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="finite"):
        Control(lambda: 0.0, float("nan"), lambda: False)
    with pytest.raises(ContractError, match="non-negative"):
        default_control(1.0).child(-1.0)


def test_control_raise_if_cancelled():
    flag = {"cancelled": False}
    control = Control(lambda: 0.0, None, lambda: flag["cancelled"])
    control.raise_if_cancelled()
    flag["cancelled"] = True
    with pytest.raises(ControlCancelled):
        control.raise_if_cancelled()
    assert isinstance(ControlCancelled("x"), ContractError)


def test_execution_port_error_carries_failure_evidence_and_terminal():
    request = _request()
    evidence = _full_evidence(request)
    terminal = TerminalReceipt(
        request.attempt_id, TerminationState.UNKNOWN, CleanupState.PENDING, ()
    )
    error = ExecutionPortError(
        "execution failed", failure=evidence.failure, evidence=evidence, terminal=terminal
    )
    assert error.failure is evidence.failure
    assert error.evidence is evidence
    assert error.terminal is terminal
    assert isinstance(error, ContractError)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


_SCENARIOS = [
    "evidence_success_match",
    "evidence_success_candidate",
    "evidence_prepare_failure",
    "evidence_b_not_started",
    "evidence_cleanup_failed",
    "evidence_termination_unknown",
    "evidence_preflight_rejection",
    "evidence_preflight_forged",
    "evidence_stale_ready",
]


@pytest.mark.parametrize("name", _SCENARIOS)
def test_fixture_bundle_loads_and_hash_chain_binds(name):
    doc = _d2_doc(name)
    request = load_attempt_request(doc["request"])
    assert request.synthetic is True
    evidence = load_execution_evidence(doc["evidence"])
    assert evidence.synthetic is True
    assert evidence.request_hash == request.request_hash
    if doc["expectation"] is None:
        assert evidence.expectation is None
    else:
        expectation = load_attempt_expectation(doc["expectation"])
        assert evidence.expectation == expectation
        assert expectation.request_hash == request.request_hash
        assert expectation.binding.case_id == request.case_id


def test_fixture_success_match_and_candidate_differ_only_in_results():
    match = load_execution_evidence(_d2_doc("evidence_success_match")["evidence"])
    candidate = load_execution_evidence(_d2_doc("evidence_success_candidate")["evidence"])
    assert match.a_query.result.rows == match.b_query.result.rows
    assert candidate.a_query.result.rows != candidate.b_query.result.rows
    for evidence in (match, candidate):
        assert evidence.terminal.termination is TerminationState.CONFIRMED
        assert evidence.terminal.cleanup is CleanupState.DONE
        assert evidence.a_query.result_terminal is ResultTerminal.CONFIRMED
        assert evidence.a_query.diagnostics.phase is SelectPhase.SELECT
        assert evidence.a_query.diagnostics.to_obj()["phase"] == "select"


def test_fixture_scenario_specific_facts():
    prepared = load_execution_evidence(_d2_doc("evidence_prepare_failure")["evidence"])
    assert prepared.failure.stage is AttemptStage.PREPARE
    assert prepared.expectation is None and prepared.runtime_facts is None
    assert prepared.a_query is None and prepared.b_query is None

    partial = load_execution_evidence(_d2_doc("evidence_b_not_started")["evidence"])
    assert partial.a_query is not None and partial.b_query is None
    assert partial.b_context is None and partial.a_context is not None
    assert partial.runtime_facts.b is None

    cleanup = load_execution_evidence(_d2_doc("evidence_cleanup_failed")["evidence"])
    assert cleanup.terminal.cleanup is CleanupState.FAILED
    assert cleanup.terminal.owned_objects != ()

    unknown = load_execution_evidence(_d2_doc("evidence_termination_unknown")["evidence"])
    assert unknown.terminal.termination is TerminationState.UNKNOWN

    rejection = load_execution_evidence(_d2_doc("evidence_preflight_rejection")["evidence"])
    assert rejection.preflight_rejection is not None
    assert rejection.terminal.termination is TerminationState.NOT_STARTED
    assert rejection.a_query is None and rejection.expectation is None

    stale = load_execution_evidence(_d2_doc("evidence_stale_ready")["evidence"])
    assert stale.runtime_facts is not None
    assert stale.runtime_facts.a.isolation_confirmed is True
    assert stale.a_query is None and stale.b_query is None


def test_fixture_forged_preflight_is_reconciled_only_against_the_request():
    doc = _d2_doc("evidence_preflight_forged")
    request = load_attempt_request(doc["request"])
    evidence = load_execution_evidence(doc["evidence"])  # structurally valid alone
    assert evidence.preflight_rejection.request_hash != request.request_hash
    legit = load_execution_evidence(_d2_doc("evidence_preflight_rejection")["evidence"])
    legit_request = load_attempt_request(_d2_doc("evidence_preflight_rejection")["request"])
    assert legit.preflight_rejection.request_hash == legit_request.request_hash


def test_fixture_select_diagnostics_phase_serialization_roundtrip():
    doc = _d2_doc("evidence_success_match")
    assert doc["evidence"]["a_query"]["diagnostics"]["phase"] == "select"
    evidence = load_execution_evidence(doc["evidence"])
    assert evidence.a_query.diagnostics.phase is SelectPhase.SELECT
    assert evidence.a_query.diagnostics.to_obj()["phase"] == "select"
    assert evidence.to_obj()["a_query"]["diagnostics"]["phase"] == "select"
