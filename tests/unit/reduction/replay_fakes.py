"""Hand-written fakes and model builders for the replay tests.

No expected value here is derived from the code under test: evidence bundles
are built from first principles (the same model-level construction as
``tests/unit/oracle/conftest.py``), the candidate is verified through the
independent oracle gates, and the scripted executor's behaviour is stated
explicitly per test.  This module is uniquely named suite-wide so tests can
import it directly without a conftest (pytest prepend import mode).
"""

from __future__ import annotations

from dataclasses import replace
from typing import Callable, Optional

from mtsql_typecheck.contracts.case import (
    CasePayload,
    ColumnSpec,
    EnvironmentRequirements,
    ExpectedBinding,
    IndexVariant,
    IntegerValue,
    NameMap,
    NullValue,
    ObservedEnvironment,
    QuerySpec,
    REQUIRED_SQL_MODE_TOKENS,
    Row,
    Rows,
    RuleRef,
    SemverIdentity,
    SideFacts,
    SignedIntegerType,
    SignedIntName,
    StatementPhase,
    StatementReceipt,
    TableSpec,
    TemplateId,
    TypeFamily,
)
from mtsql_typecheck.contracts.codec import canonical_json, sha256_hex
from mtsql_typecheck.contracts.execution import (
    ATTEMPT_BUDGET_MS,
    MAX_RESULT_BYTES,
    AttemptExpectation,
    AttemptRequest,
    CleanupState,
    Control,
    ExecutionEvidence,
    ExecutionOrder,
    ExecutionPort,
    IsolationReceipt,
    QueryEvidence,
    QueryStatus,
    ResultColumn,
    ResultSet,
    ResultTerminal,
    ResultValue,
    ResultValueKind,
    RuntimeFacts,
    SelectPhase,
    SessionProfile,
    Side,
    SideContext,
    StatementDiagnostics,
    TerminalReceipt,
    TerminationState,
    TransactionIsolation,
)
from mtsql_typecheck.contracts.oracle import (
    ArtifactRef,
    CandidateInput,
    ComparisonBudget,
    ComparisonStatus,
    PersistedReceipt,
    ReplayPolicy,
    ReplayResult,
    TRACE_SCHEMA_VERSION,
    TraceRecord,
)
from mtsql_typecheck.generation.render import RenderPhase, render_pair
from mtsql_typecheck.oracle.gates import compare_case
from mtsql_typecheck.reduction.replay import replay_candidate
from mtsql_typecheck.rules.exact_numeric import derive_relation

_BUDGET = ComparisonBudget()

_ENV = ObservedEnvironment(
    instance_identity="mysql-8039-local",
    version="8.0.39",
    vendor="mysql",
    build_id="20250715",
    engine="innodb",
    sql_mode_tokens=REQUIRED_SQL_MODE_TOKENS,
    character_set="utf8mb4",
    collation="utf8mb4_bin",
    time_zone="+00:00",
    optimizer_switch="index_merge=on,mrr=off",
)

_PROFILE = SessionProfile(True, TransactionIsolation.REPEATABLE_READ)

DEFAULT_ROW_VALUES = (IntegerValue(-128), NullValue(), IntegerValue(127))
# Mismatch: the candidate observes -128 on A but -127 on B (signed-widen).
CANDIDATE_A_ROWS = (IntegerValue(-128), NullValue())
CANDIDATE_B_ROWS = (IntegerValue(-127), NullValue())
# Match: B observes the same multiset as A.
MATCH_B_ROWS = (IntegerValue(-128), NullValue())
# Drift: B observes a third value.
DRIFT_B_ROWS = (IntegerValue(-126), NullValue())


def _family_of(type_spec) -> TypeFamily:
    if isinstance(type_spec, SignedIntegerType):
        return TypeFamily.SIGNED_INTEGER
    raise AssertionError("unexpected type spec in replay fakes")


def _result_value(value):
    if isinstance(value, ResultValue):
        return value
    if isinstance(value, NullValue):
        return ResultValue(ResultValueKind.NULL)
    if isinstance(value, IntegerValue):
        return ResultValue(ResultValueKind.INTEGER, int_value=value.value)
    raise AssertionError("unexpected value kind in replay fakes")


def _column_meta(type_spec):
    precision = {SignedIntName.TINYINT: 3, SignedIntName.SMALLINT: 5}[type_spec.name]
    return (15, precision, 0)


def build_attempt(
    *,
    run_id: str = "run-replay-1",
    attempt_id: str = "attempt-orig",
    name_map: Optional[NameMap] = None,
    execution_order: ExecutionOrder = ExecutionOrder.AB,
    row_values: tuple = DEFAULT_ROW_VALUES,
    a_readback: Optional[tuple] = None,
    b_readback: Optional[tuple] = None,
    a_result_rows: tuple = CANDIDATE_A_ROWS,
    b_result_rows: tuple = CANDIDATE_B_ROWS,
    terminal: Optional[TerminalReceipt] = None,
    synthetic: bool = True,
    result_row_budget: int = 1024,
):
    """Build a complete consistent (request, expectation, evidence) triple for
    the signed-widen TINYINT->SMALLINT rule under template Q1.

    ``row_values`` are the shared payload rows and default readbacks; result
    rows are per-side ExactValue items.  ``terminal`` defaults to a confirmed,
    cleaned-up receipt.
    """
    nm = name_map if name_map is not None else NameMap("tc_a", "tc_b", "t_a", "t_b")
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
        IndexVariant.NONE,
    )
    payload = CasePayload(
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
    request = AttemptRequest(
        run_id=run_id,
        attempt_id=attempt_id,
        payload=payload,
        target_environment=_ENV,
        session_profile=_PROFILE,
        execution_order=execution_order,
        result_row_budget=result_row_budget,
        result_byte_budget=MAX_RESULT_BYTES,
        time_budget_ms=ATTEMPT_BUDGET_MS,
        synthetic=synthetic,
    )
    binding = ExpectedBinding(
        run_id=run_id,
        case_id=request.case_id,
        attempt_id=attempt_id,
        environment_hash=sha256_hex(canonical_json(_ENV.to_obj())),
        name_map_hash=sha256_hex(canonical_json(nm.to_obj())),
    )
    expectation = AttemptExpectation(
        binding=binding,
        request_hash=request.request_hash,
        codec_version="mysql-text-1",
        execution_order=execution_order,
        name_map=nm,
    )
    evidence = evidence_for(
        request,
        expectation,
        a_readback=row_values if a_readback is None else a_readback,
        b_readback=row_values if b_readback is None else b_readback,
        a_result_rows=a_result_rows,
        b_result_rows=b_result_rows,
        terminal=terminal,
    )
    return request, expectation, evidence


def evidence_for(
    request: AttemptRequest,
    expectation: AttemptExpectation,
    *,
    a_readback: tuple,
    b_readback: tuple,
    a_result_rows: tuple,
    b_result_rows: tuple,
    terminal: Optional[TerminalReceipt] = None,
    readback_rids: Optional[tuple[int, ...]] = None,
) -> ExecutionEvidence:
    """Full successful evidence for one attempt, bound to request/expectation.

    Result rows are ExactValue items (converted to ResultValue) or already
    ResultValue items; every other fact derives from the frozen models.
    ``readback_rids`` overrides the readback row rids (default 1..n), so
    reduced children whose rids do not start at 1 can be modeled.
    """
    payload = request.payload
    nm = expectation.name_map
    binding = expectation.binding
    pair = render_pair(payload, nm)
    setup_diagnostics = []
    side_facts = {}
    side_queries = {}
    side_contexts = {}
    for side, side_type, readback_values, result_rows, statements in (
        (Side.A, payload.a_type, a_readback, a_result_rows, pair.a),
        (Side.B, payload.b_type, b_readback, b_result_rows, pair.b),
    ):
        label = str(side.value)
        database = nm.database_a if side is Side.A else nm.database_b
        select = None
        receipts = []
        ordinals: dict = {}
        for statement in statements:
            if statement.phase is RenderPhase.SELECT:
                select = statement
                continue
            phase = (
                StatementPhase.DDL if statement.phase is RenderPhase.DDL else StatementPhase.INSERT
            )
            ordinal = ordinals.get(phase, 0)
            ordinals[phase] = ordinal + 1
            receipts.append(StatementReceipt(phase, ordinal, statement.sql_hash, True, True))
            setup_diagnostics.append(
                StatementDiagnostics(
                    side=side,
                    phase=phase,
                    ordinal=ordinal,
                    sql_hash=statement.sql_hash,
                    collected=True,
                    complete=True,
                    entries=(),
                )
            )
        actual_schema = TableSpec(
            "t0",
            (
                ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
                ColumnSpec("v", side_type, True),
            ),
            ("rid",),
            IndexVariant.NONE,
        )
        side_facts[label] = SideFacts(
            statement_receipts=tuple(receipts),
            readback=Rows(
                tuple(
                    Row(
                        readback_rids[index]
                        if readback_rids is not None
                        else index + 1,
                        value,
                    )
                    for index, value in enumerate(readback_values)
                )
            ),
            readback_complete=True,
            actual_schema=actual_schema,
            load_committed=True,
            isolation_confirmed=True,
        )
        type_code, precision, scale = _column_meta(side_type)
        relation = payload.relation
        result_set = ResultSet(
            columns=(
                ResultColumn(
                    0,
                    relation.columns[0].alias,
                    relation.columns[0].a_family
                    if side is Side.A
                    else relation.columns[0].b_family,
                    type_code,
                    0,
                    precision,
                    scale,
                    "d3-mapping-1",
                ),
            ),
            rows=tuple((_result_value(value),) for value in result_rows),
            observed_row_count=len(result_rows),
            fetch_complete=True,
            truncated=False,
            extra_result_sets=0,
            encoding_version="mysql-text-1",
        )
        side_queries[label] = QueryEvidence(
            side=side,
            binding=binding,
            select_text=select.text,
            select_sql_hash=select.sql_hash,
            protocol="text",
            parameters=(),
            status=QueryStatus.COMPLETE,
            result=result_set,
            # The SELECT runs on the side context's select connection (the
            # same session identity the oracle's session-chain gate requires).
            session_start_id=f"{request.attempt_id}-conn-{label.lower()}",
            session_end_id=f"{request.attempt_id}-conn-{label.lower()}",
            actual_database=database,
            environment_before=_ENV,
            environment_after=_ENV,
            diagnostics=StatementDiagnostics(
                side=side,
                phase=SelectPhase.SELECT,
                ordinal=0,
                sql_hash=select.sql_hash,
                collected=True,
                complete=True,
                entries=(),
            ),
            duration_ms=1,
            result_terminal=ResultTerminal.CONFIRMED,
        )
        side_contexts[label] = SideContext(
            side=side,
            setup_connection_id=f"{request.attempt_id}-conn-{label.lower()}",
            readback_connection_id=f"{request.attempt_id}-conn-{label.lower()}",
            select_connection_id=f"{request.attempt_id}-conn-{label.lower()}",
            current_database=database,
            name_map=nm,
            autocommit=request.session_profile.autocommit,
            transaction_isolation=request.session_profile.transaction_isolation,
            environment_before=_ENV,
            environment_after=_ENV,
        )

    facts = RuntimeFacts(
        binding=binding,
        observed_environment=_ENV,
        name_map=nm,
        a=side_facts["A"],
        b=side_facts["B"],
    )
    return ExecutionEvidence(
        request_hash=request.request_hash,
        expectation=expectation,
        runtime_facts=facts,
        setup_diagnostics=tuple(setup_diagnostics),
        actual_execution_order=request.execution_order,
        a_context=side_contexts["A"],
        b_context=side_contexts["B"],
        a_query=side_queries["A"],
        b_query=side_queries["B"],
        isolation_receipt=IsolationReceipt(
            attempt_id=request.attempt_id,
            name_map_hash=binding.name_map_hash,
            ownership_ref=f"{request.run_id}/objects/{nm.database_a},{nm.database_b}",
            objects_created_confirmed=True,
            load_committed=True,
            no_concurrent_write_confirmed=True,
            method_version="d3-isolation-1",
        ),
        terminal=terminal
        if terminal is not None
        else TerminalReceipt(
            attempt_id=request.attempt_id,
            termination=TerminationState.CONFIRMED,
            cleanup=CleanupState.DONE,
            owned_objects=(),
        ),
        failure=None,
        preflight_rejection=None,
        synthetic=request.synthetic,
    )


class CandidateBundle:
    """A verified mismatch candidate plus its parts, for replay tests."""

    def __init__(self, run_id: str = "run-replay-1") -> None:
        self.request, self.expectation, self.evidence = build_attempt(
            run_id=run_id, attempt_id="attempt-orig"
        )
        comparison = compare_case(self.request, self.expectation, self.evidence, _BUDGET)
        if comparison.status is not ComparisonStatus.MISMATCH_CANDIDATE:
            raise AssertionError(
                f"fixture candidate is {comparison.status}, expected MISMATCH_CANDIDATE"
            )
        self.comparison = comparison
        self.candidate = CandidateInput(
            payload=self.request.payload,
            request=self.request,
            expectation=self.expectation,
            evidence=self.evidence,
            comparison_hash=comparison.hash,
            source="test",
        )

    @property
    def exact_signature(self) -> str:
        return self.comparison.exact_signature

    @property
    def fingerprint(self) -> str:
        return self.comparison.fingerprint


class StubClock:
    """Injectable monotonic clock in whole milliseconds (Control wants seconds)."""

    def __init__(self, now_ms: int = 0) -> None:
        self.now_ms = now_ms

    def advance_ms(self, ms: int) -> None:
        self.now_ms += ms

    def __call__(self) -> float:
        return self.now_ms / 1000


class CancelToken:
    """Mutable cancelled() predicate shared with the Control under test."""

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


class ScriptedExecutor:
    """ExecutionPort stub with per-dispatch scripting.

    ``prepare_errors``/``execute_errors`` map the dispatch index (0-based, one
    index per dispatched attempt) to an exception; a callable error receives
    the freshly built evidence (used to attach salvageable evidence to an
    ExecutionPortError).  ``result_overrides``/``terminal_overrides`` map the
    dispatch index to alternate (a_rows, b_rows) / terminal receipt.  Every
    prepare allocates a fresh NameMap and per-attempt connection/session ids,
    modeling the executor's fresh-objects obligation.
    """

    def __init__(self, base: CandidateBundle) -> None:
        self.base = base
        self.calls: list[tuple[str, str, str]] = []
        self.cancel_calls: list[str] = []
        self.evidence_by_attempt: dict[str, ExecutionEvidence] = {}
        self.prepare_errors: dict[int, object] = {}
        self.execute_errors: dict[int, object] = {}
        self.result_overrides: dict[int, tuple] = {}
        self.terminal_overrides: dict[int, TerminalReceipt] = {}
        self.on_execute: Optional[Callable[[int], None]] = None
        self.cancel_receipt: Optional[TerminalReceipt] = None
        self.cancel_error: Optional[BaseException] = None
        self._dispatch = 0
        self._index_by_attempt: dict[str, int] = {}
        self._default_a = tuple(row[0] for row in base.evidence.a_query.result.rows)
        self._default_b = tuple(row[0] for row in base.evidence.b_query.result.rows)
        self._default_readback = tuple(row.value for row in base.request.payload.rows.rows)

    def prepare(self, request: AttemptRequest, control: Control) -> AttemptExpectation:
        index = self._dispatch
        self._dispatch += 1
        self._index_by_attempt[request.attempt_id] = index
        self.calls.append(("prepare", request.attempt_id, str(request.execution_order.value)))
        nm = NameMap(
            f"tc_a_{index + 1}", f"tc_b_{index + 1}", f"t_a_{index + 1}", f"t_b_{index + 1}"
        )
        binding = ExpectedBinding(
            run_id=request.run_id,
            case_id=request.case_id,
            attempt_id=request.attempt_id,
            environment_hash=sha256_hex(canonical_json(request.target_environment.to_obj())),
            name_map_hash=sha256_hex(canonical_json(nm.to_obj())),
        )
        expectation = AttemptExpectation(
            binding=binding,
            request_hash=request.request_hash,
            codec_version="mysql-text-1",
            execution_order=request.execution_order,
            name_map=nm,
        )
        error = self.prepare_errors.get(index)
        if error is not None:
            raise error() if callable(error) else error
        return expectation

    def execute(
        self, request: AttemptRequest, expectation: AttemptExpectation, control: Control
    ) -> ExecutionEvidence:
        index = self._index_by_attempt[request.attempt_id]
        self.calls.append(("execute", request.attempt_id, str(request.execution_order.value)))
        if self.on_execute is not None:
            self.on_execute(index)
        rows = self.result_overrides.get(index)
        terminal = self.terminal_overrides.get(index)
        if terminal is not None:
            terminal = replace(terminal, attempt_id=request.attempt_id)
        evidence = evidence_for(
            request,
            expectation,
            a_readback=self._default_readback,
            b_readback=self._default_readback,
            a_result_rows=rows[0] if rows else self._default_a,
            b_result_rows=rows[1] if rows else self._default_b,
            terminal=terminal,
        )
        self.evidence_by_attempt[request.attempt_id] = evidence
        error = self.execute_errors.get(index)
        if error is not None:
            raise error(evidence) if callable(error) else error
        return evidence

    def cancel_and_wait(self, attempt_id: str, grace_seconds: float) -> TerminalReceipt:
        self.calls.append(("cancel", attempt_id, f"grace={grace_seconds}"))
        self.cancel_calls.append(attempt_id)
        if self.cancel_error is not None:
            raise self.cancel_error
        if self.cancel_receipt is not None:
            return replace(self.cancel_receipt, attempt_id=attempt_id)
        return TerminalReceipt(
            attempt_id=attempt_id,
            termination=TerminationState.CONFIRMED,
            cleanup=CleanupState.DONE,
            owned_objects=(),
        )


class SpyTraceSink:
    """In-memory TraceSink spy: record kinds, ordering and the hash chain,
    with an optional per-kind write failure.  ``publish_payload`` records
    payload bytes under their sha256 (the same layout the real sink uses);
    ``fail_publish`` makes every dependency publication raise instead."""

    def __init__(self, fail_on=(), fail_publish: bool = False) -> None:
        self.records: list[TraceRecord] = []
        self.reserved: list[int] = []
        self.payloads: dict[str, bytes] = {}
        self.fail_on = frozenset(fail_on)
        self.fail_publish = fail_publish

    def reserve(self, size_hint: int) -> None:
        self.reserved.append(size_hint)

    def publish_payload(self, data: bytes) -> ArtifactRef:
        if self.fail_publish:
            raise RuntimeError("simulated payload publication failure")
        payload = bytes(data)
        digest = sha256_hex(payload)
        self.payloads[digest] = payload
        return ArtifactRef(
            path=f"files/{digest}.json",
            size_bytes=len(payload),
            sha256=digest,
            schema_version=TRACE_SCHEMA_VERSION,
        )

    def append(self, record: TraceRecord) -> PersistedReceipt:
        if record.kind in self.fail_on:
            raise RuntimeError(f"simulated sink failure at {record.kind}")
        self.records.append(record)
        return PersistedReceipt(seq=record.seq, kind=record.kind, record_hash=record.hash)

    @property
    def kinds(self) -> list[str]:
        return [record.kind for record in self.records]


def run_replay(
    bundle: CandidateBundle,
    executor,
    sink=None,
    *,
    policy=None,
    control=None,
    require_fresh_name_maps: bool = False,
):
    return replay_candidate(
        bundle.candidate,
        executor,
        sink,
        policy if policy is not None else ReplayPolicy(),
        control if control is not None else make_control(StubClock()),
        require_fresh_name_maps=require_fresh_name_maps,
        # In-memory test runs without a sink keep the pre-D3 unpersisted
        # behaviour; sink-less NO_SINK semantics are tested explicitly.
        unpersisted=(sink is None),
    )


def assert_counter_invariants(result: ReplayResult) -> None:
    """Frozen-model counter invariants, asserted in every replay test."""
    assert (
        result.matching_signature
        <= result.comparable
        <= result.completed
        <= result.requested
    )
    assert len(result.attempt_hashes) == result.requested
    assert len(result.exact_signatures) == result.comparable


def prepare_dispatches(executor: ScriptedExecutor) -> list[tuple[str, str]]:
    return [(aid, order) for kind, aid, order in executor.calls if kind == "prepare"]
