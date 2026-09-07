"""MySQL 8.0 execution port for D3 (design 6.2.2/6.3.2/6.4/6.5, Phase 4).

``MySQLExecutionPort`` implements the frozen :class:`ExecutionPort` protocol
(``contracts.execution``) over an **injected adapter factory** and an
**injected ownership journal**.  It owns the attempt lifecycle: fresh object
names per attempt, marker-first object creation, exact-value loading, readback
verification, session application, bounded result collection, cancellation and
cleanup.  All randomness, clocks and I/O are injectable; the module keeps no
global state and opens no connection at import time.

Import discipline (Phase 4 seam): this module imports ``adapters.base``
(driver-free typed errors/constants) but never ``adapters.mysql80`` or
``adapters.mysql_protocol`` at module level (both import PyMySQL at module
level).  :func:`build_execution_port` -- design 6.3.2's single public
assembly entry -- imports the real adapter lazily inside its call body; the
port itself binds anything satisfying the structural :class:`AdapterLike`
protocol below (the unit tests bind scripted fakes).

Seam decisions (documented for review):

- **Declared NameMap -> physical names.**  The run token is drawn once per
  port (the journal is per-run); every ``prepare`` draws a fresh attempt
  token and derives ``tc_<run>_<attempt>_[ab]`` via
  ``runner.naming.attempt_database_names``.  Tables are the fixed
  ``case_a``/``case_b``.  The returned ``AttemptExpectation.name_map`` is the
  *physical* NameMap; its content hash is what the replay ledger tracks, and
  the port redraws tokens (bounded) until it has never returned the same
  name-map hash before in this run.

- **Evidence payloads ride a side table.**  Raw SQL text, diagnostics text
  and column metadata are not inline in the contract models; the port keeps
  them in a per-attempt in-memory ``dict[ref, bytes]`` keyed by
  deterministically allocated controlled relative paths:
  ``attempts/<attempt_id>/<side|run>/<stage-slug>-<ordinal>.sql|`.diagnostics-<n>.txt``
  with per-(stage, side) 0-based ordinals.  ``StageObservation`` records carry
  ``sql_hash`` (sha256 of the exact SQL) plus these refs.  Phase 5's trace
  sink persists the dict verbatim.

- **Failure vocabulary.**  ``AttemptFailure.code`` is a stable string, not a
  closed enum.  Codes used here, with provenance: ``SESSION_MISMATCH`` /
  ``SESSION_APPLY_FAILED`` (frozen ``adapters.mysql80`` constants, not
  importable here without the PyMySQL chain), ``SQL_ERROR`` / ``TIMEOUT`` /
  ``CANCELLED`` / ``CONNECTION_LOST`` (frozen ``QueryStatus`` values),
  ``RESULT_ENCODING_UNSUPPORTED`` / ``RESULT_CONTRACT_VIOLATION`` /
  ``PROTOCOL_BUDGET_EXCEEDED`` (frozen ``adapters.base`` constants),
  ``UNKNOWN`` (frozen ``TerminationState`` value), ``ENVIRONMENT_DRIFT`` /
  ``RUNTIME_NOT_READY`` / ``RESULT_BUDGET_EXCEEDED`` (frozen
  ``ComparisonReason`` values), ``EXECUTION_PROTOCOL_ERROR`` /
  ``TIME_BUDGET`` (frozen ``StopReason`` values), ``CLEANUP_FAILED`` /
  ``QUARANTINED`` (frozen ``OwnershipEventKind`` values), and
  ``ATTEMPT_NOT_FOUND`` -- the one code with no frozen enum member (the
  ownership-journal attempt vocabulary has no such concept).  It is surfaced
  here rather than silently mapped into an unrelated frozen value.

- **Design 6.2.4 failure rows.**  A per-side SELECT error whose context is
  still collectible from the same connection (verified by re-probing, not
  assumed) is *absorbed*: that side's ``QueryEvidence`` records
  ``SQL_ERROR`` with ``result=None``, ``ResultTerminal.UNKNOWN`` and the
  error response captured as an ``ERROR`` diagnostic, the side context stays
  complete, and the attempt continues so comparison sees a non-comparable
  side (never a match).  An over-budget result (truncated fetch or budget
  expiry during QUERY/FETCH) records that side as ``CANCELLED`` with the
  partial result set explicitly marked truncated, and the attempt-level
  failure carries the frozen ``RESULT_BUDGET_EXCEEDED`` code (never a
  fabricated ``SQL_ERROR``).  When the required after/session facts cannot
  be collected (disconnect/timeout), the side stays ``QueryEvidence=null``
  with an incomplete null ``SideContext`` and the ``AttemptFailure`` names
  QUERY/FETCH and the real cause; ``before`` is never copied to ``after``.

- **SELECT diagnostics.**  The shim's ``open_query`` collects no SELECT
  diagnostics, but oracle gate 4 requires clean SELECT diagnostics for a
  comparable attempt.  The port collects them itself from the authoritative
  terminator warning count (0 -> collected/complete/empty; >0 -> SHOW
  WARNINGS on the same connection; count/truncation mismatch -> collected
  but never complete).  A driver error during a query propagates from the
  adapter unwrapped today; wrapping it into a coded ``AdapterError`` is a
  Phase 5 binding responsibility (this port maps unknown exceptions to
  ``SQL_ERROR`` so nothing becomes a silent match).

- **Schema readback.**  Gate 3 needs nullability/PK evidence the frozen
  adapter ``inspect_schema`` does not probe; the port owns the
  information-schema probe SQL (TABLES/COLUMNS/STATISTICS) and normalizes it
  through ``runner.facts.normalize_side_schema``.  The probe answer, not the
  declaration, is what enters the runtime facts.

- **Termination confirmation.**  Adapter calls are synchronous: when a stage
  fails through an exception, the statement has already terminated, so no
  KILL is needed (termination CONFIRMED).  Explicit cancellation
  (``ControlCancelled``, budget expiry, ``cancel_and_wait``) goes through
  ``cancel_current`` on every live adapter; if any cancel is unsupported or
  its kill receipt errors, termination is UNKNOWN, the attempt is
  quarantined (latch + ``QUARANTINED`` journal event) and its objects are
  left in place for forensics -- never silently dropped.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Union,
)

from ..adapters.base import (
    PROTOCOL_BUDGET_EXCEEDED,
    RESULT_CONTRACT_VIOLATION,
    RESULT_ENCODING_UNSUPPORTED,
    AdapterError,
    ConnectionParams,
    ProtocolBudgetError,
    ResultContractViolation,
    ResultEncodingError,
)
from ..contracts import execution as _exec
from ..contracts.case import (
    CasePayload,
    ContractError,
    ExpectedBinding,
    NameMap,
    ObservedEnvironment,
    ResultColumnSpec,
    ResultRelationSpec,
    Row,
    Rows,
    RuntimeCheckStatus,
    RuntimeFacts,
    SideFacts,
    StatementPhase,
    StatementReceipt,
    TableSpec,
    TypeFamily,
)
from ..contracts.codec import sha256_hex
from ..contracts.execution import (
    AttemptExpectation,
    AttemptFailure,
    AttemptRequest,
    AttemptStage,
    Control,
    ControlCancelled,
    DiagnosticEntry,
    DiagnosticLevel,
    ExecutionOrder,
    ExecutionPortError,
    ExecutionEvidence,
    IsolationReceipt,
    PreflightRejection,
    QueryEvidence,
    QueryStatus,
    ResultColumn,
    ResultTerminal,
    ResultSet,
    ResultValue,
    SelectPhase,
    Side,
    SideContext,
    StatementDiagnostics,
    TerminalReceipt,
    TerminationState,
    CleanupState,
    MAX_RESULT_BYTES,
    MAX_RESULT_ROWS,
)
from ..contracts.oracle import ComparisonReason, StopReason
from ..contracts.runner import (
    OwnershipEvent,
    OwnershipEventKind,
    StageObservation,
    StageObservationKind,
)
from ..generation.render import render_pair
from ..generation.validation import (
    environment_content_hash,
    name_map_content_hash,
    validate_runtime_facts,
)
from . import naming
from .cancellation import CANCEL_ENTRY_STATES, TERMINAL_STATES, LifecycleState, transition
from .cleanup import (
    AttemptCleaner,
    CleanupAction,
    CleanupFailure,
    CleanupOutcome,
    database_create_sql,
    ensure_marker,
)
from .facts import (
    FactCollectionError,
    attempt_fact_summary,
    decode_readback_rows,
    normalize_side_schema,
    observed_environment_from_facts,
    rejected_requirement_id,
)
from .ownership import OWNERSHIP_GENESIS_HASH, OwnershipJournal, QuarantineLatch

__all__ = [
    "PORT_IDENTITY",
    "CODEC_VERSION",
    "CAPABILITY_CHECK_VERSION",
    "ISOLATION_METHOD_VERSION",
    "ATTEMPT_NOT_FOUND",
    "SESSION_MISMATCH",
    "SESSION_APPLY_FAILED",
    "MySQLExecutionPort",
    "build_execution_port",
]

#: Semantic identity of this execution port implementation.
PORT_IDENTITY = "runner-execution-mysql80-v1"

#: Result codec identity stamped on every expectation and result set
#: (text protocol mapping, frozen in Phase 2).
CODEC_VERSION = "mysql-text-1"

#: Capability-check identity for structured preflight rejections.
CAPABILITY_CHECK_VERSION = "mysql80-execution-capability-v1"

#: Isolation-method identity stamped on the isolation receipt.
ISOLATION_METHOD_VERSION = "runner-execution-isolation-v1"

# Stable failure codes with no frozen enum member (documented in the module
# docstring; surfaced here instead of being silently mapped).
ATTEMPT_NOT_FOUND = "ATTEMPT_NOT_FOUND"
SESSION_MISMATCH = "SESSION_MISMATCH"  # adapters.mysql80 frozen constant
SESSION_APPLY_FAILED = "SESSION_APPLY_FAILED"  # adapters.mysql80 frozen constant

# Frozen budget vocabulary (contracts.oracle): the result-budget cancel row
# of design 6.2.4 and the attempt time budget, respectively.
_RESULT_BUDGET_EXCEEDED = str(ComparisonReason.RESULT_BUDGET_EXCEEDED.value)
_TIME_BUDGET = str(StopReason.TIME_BUDGET.value)

# Adapter error codes this port understands (string literals: the codes live
# in frozen modules this file must not import at module level).
_CONNECTION_LOST = "CONNECTION_LOST"
_CANCEL_UNSUPPORTED = "CANCEL_UNSUPPORTED"

#: Bounded raw-probe budgets: identity/schema/readback probes are tiny and
#: bounded far below the per-result contract caps on purpose.
_PROBE_ROW_BUDGET = 1024
_PROBE_BYTE_BUDGET = 64 * 1024

#: Maximum attempt-token redraws while hunting an unused name-map hash.
_NAME_MAP_DRAWS = 8

_PLAIN_IDENT_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")

# Port-owned information-schema probe SQL.  Every interpolated identifier is
# a tool-generated name validated below before formatting; the grammar admits
# no quoting metacharacters, so the quoted literal is injection-proof.
_SCHEMA_TABLES_SQL = (
    "SELECT TABLE_NAME, TABLE_TYPE, ENGINE FROM INFORMATION_SCHEMA.TABLES "
    "WHERE TABLE_SCHEMA = '{database}' AND TABLE_NAME = '{table}' ORDER BY TABLE_NAME"
)
_SCHEMA_COLUMNS_SQL = (
    "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, ORDINAL_POSITION "
    "FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '{database}' "
    "AND TABLE_NAME = '{table}' ORDER BY ORDINAL_POSITION"
)
_SCHEMA_STATISTICS_SQL = (
    "SELECT INDEX_NAME, NON_UNIQUE, COLUMN_NAME FROM INFORMATION_SCHEMA.STATISTICS "
    "WHERE TABLE_SCHEMA = '{database}' AND TABLE_NAME = '{table}' "
    "AND INDEX_NAME <> 'PRIMARY' ORDER BY INDEX_NAME, SEQ_IN_INDEX"
)
_SCHEMA_PRESENT_SQL = (
    "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '{database}'"
)
_READBACK_SQL = "SELECT `rid`, `v` FROM `{table}` ORDER BY `rid`;"
_SHOW_WARNINGS_SQL = "SHOW WARNINGS"

_DIAGNOSTIC_LEVELS = {
    "ERROR": DiagnosticLevel.ERROR,
    "WARNING": DiagnosticLevel.WARNING,
    "NOTE": DiagnosticLevel.NOTE,
}


def _diagnostic_level(level_text: Optional[str]) -> Optional[DiagnosticLevel]:
    """Map a server diagnostic level onto the frozen vocabulary.

    MySQL sends capitalized levels ("Warning", "Note", "Error"); the frozen
    DiagnosticLevel members are uppercase, so the match is case-insensitive.
    Anything else is outside the vocabulary and must fail closed upstream.
    """

    if level_text is None:
        return None
    return _DIAGNOSTIC_LEVELS.get(level_text.upper())

# Dispatch orders: the frozen replay dispatch orders drive per-side order.
_DISPATCH_SIDES: Dict[ExecutionOrder, Tuple[Side, Side]] = {
    ExecutionOrder.AB: (Side.A, Side.B),
    ExecutionOrder.BA: (Side.B, Side.A),
}


# --------------------------------------------------------------------------
# Structural adapter surface (Phase 5 binds the real adapter; tests bind fakes)
# --------------------------------------------------------------------------


class _WarningEntryLike(Protocol):
    level: str
    code: str
    sqlstate: Optional[str]
    message: str


class _ErrPacketLike(Protocol):
    errno: int
    sqlstate: Optional[str]
    message: str


class _DiagnosticsLike(Protocol):
    collected: bool
    complete: bool
    entries: Sequence[_WarningEntryLike]


class _StatementReceiptLike(Protocol):
    sql: str
    error: Optional[_ErrPacketLike]
    diagnostics: _DiagnosticsLike


class _ExecutedStatementLike(Protocol):
    ordinal: int
    receipt: _StatementReceiptLike
    duration_ms: int


class _MappedColumnLike(Protocol):
    alias: str
    type_code: int
    flags: int
    precision: Optional[int]
    scale: Optional[int]
    mapping_version: str


class _FetchResultLike(Protocol):
    columns: Sequence[_MappedColumnLike]
    values: Sequence[Tuple[ResultValue, ...]]
    observed_row_count: int
    fetch_complete: bool
    truncated: bool
    extra_result_sets: int
    warning_count: Optional[int]


class _RawResultLike(Protocol):
    database: Optional[str]
    columns: Sequence[_MappedColumnLike]
    rows: Sequence[Tuple[Optional[bytes], ...]]
    observed_row_count: int
    fetch_complete: bool
    truncated: bool


class _CancelReceiptLike(Protocol):
    connection_id: int
    kill: _StatementReceiptLike


class AdapterLike(Protocol):
    """Structural surface the port needs from one connected adapter.

    ``connect_and_probe`` must have been called before the session-bearing
    methods; ``fetch_environment_facts`` is the preflight probe source.  All
    calls are synchronous; a statement that raises has already terminated.
    """

    def connect_and_probe(self) -> Dict[str, str]: ...

    def fetch_environment_facts(self) -> Mapping[str, str]: ...

    def apply_session(self, session_settings: Mapping[str, str]) -> Mapping[str, str]: ...

    def execute_statement(self, sql: str) -> _ExecutedStatementLike: ...

    def open_query(self, sql: str) -> Any: ...

    def fetch_result(
        self, handle: Any, *, row_budget: int, byte_budget: int
    ) -> _FetchResultLike: ...

    def execute_raw_query(
        self,
        sql: str,
        *,
        row_budget: int,
        byte_budget: int,
        database: Optional[str] = None,
    ) -> _RawResultLike: ...

    def cancel_current(self) -> _CancelReceiptLike: ...

    def connection_id(self) -> int: ...

    def close(self) -> None: ...


AdapterFactory = Callable[[], AdapterLike]


class OwnershipSink(Protocol):
    """Structural surface of the frozen ``OwnershipJournal`` (fakes allowed)."""

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
    ) -> Any: ...


# --------------------------------------------------------------------------
# Evidence side table (payloads + stage observations)
# --------------------------------------------------------------------------


class _EvidenceRecorder:
    """Per-attempt payload side table and stage-observation log.

    Ref convention (documented seam): controlled relative paths
    ``attempts/<attempt_id>/<side|run>/<stage-slug>-<ordinal>.sql`` for SQL
    text, ``...diagnostics-<n>.txt`` for diagnostics text, with per-(stage,
    side) 0-based ordinals.  Refs are allocated deterministically from the
    stage vocabulary so a trace sink can persist the dict verbatim.
    """

    def __init__(self, attempt_id: str) -> None:
        self._attempt_id = attempt_id
        self.observations: List[StageObservation] = []
        self.payloads: Dict[str, bytes] = {}
        self._counters: Dict[Tuple[str, Optional[Side]], int] = {}

    def _next_ordinal(self, slug: str, side: Optional[Side]) -> int:
        key = (slug, side)
        ordinal = self._counters.get(key, 0)
        self._counters[key] = ordinal + 1
        return ordinal

    def ref(self, side: Optional[Side], slug: str, ordinal: int, suffix: str) -> str:
        part = "run" if side is None else str(side.value)
        return f"attempts/{self._attempt_id}/{part}/{slug}-{ordinal}{suffix}"

    def add_payload(self, ref: str, data: bytes) -> str:
        self.payloads[ref] = data
        return ref

    def record_sql(
        self,
        *,
        side: Optional[Side],
        stage: StageObservationKind,
        slug: str,
        sql: str,
        connection_id: Optional[str],
        actual_database: Optional[str] = None,
        session_id: Optional[str] = None,
        detail: str = "",
    ) -> Tuple[StageObservation, str]:
        ordinal = self._next_ordinal(slug, side)
        sql_hash = sha256_hex(sql.encode("utf-8"))
        sql_ref = self.ref(side, slug, ordinal, ".sql")
        self.add_payload(sql_ref, sql.encode("utf-8"))
        observation = StageObservation(
            side=side,
            stage=stage,
            ordinal=ordinal,
            connection_id=connection_id,
            actual_database=actual_database,
            session_id=session_id,
            sql_hash=sql_hash,
            sql_ref=sql_ref,
            diagnostics_ref=None,
            field_metadata_ref=None,
            detail=detail,
        )
        self.observations.append(observation)
        return observation, sql_ref


# --------------------------------------------------------------------------
# Attempt state and internal aborts
# --------------------------------------------------------------------------


class _AttemptState:
    """Mutable per-attempt bookkeeping (single-threaded port, no locking)."""

    def __init__(
        self,
        *,
        run_id: str,
        attempt_id: str,
        run_token: str,
        attempt_token: str,
        name_map: NameMap,
    ) -> None:
        self.run_id = run_id
        self.attempt_id = attempt_id
        self.run_token = run_token
        self.attempt_token = attempt_token
        self.name_map = name_map
        self.state = LifecycleState.NEW
        self.expectation: Optional[AttemptExpectation] = None
        self.facts: Optional[RuntimeFacts] = None
        self.observed_environment: Optional[ObservedEnvironment] = None
        self.summary: Optional[Dict[str, str]] = None
        self.recorder = _EvidenceRecorder(attempt_id)
        self.setup_diagnostics: List[StatementDiagnostics] = []
        self.adapters: Dict[str, AdapterLike] = {}
        self.contexts: Dict[str, SideContext] = {}
        self.queries: Dict[str, QueryEvidence] = {}
        self.actual_order: Optional[ExecutionOrder] = None
        self.owned_objects: List[str] = []
        self.failure: Optional[AttemptFailure] = None
        self.terminal: Optional[TerminalReceipt] = None
        self.evidence: Optional[ExecutionEvidence] = None
        self.server_uuid: Optional[str] = None


class _AttemptAbort(Exception):
    """Internal failure carrier; finalized into evidence by the port."""

    def __init__(
        self,
        *,
        code: str,
        stage: AttemptStage,
        message: str,
        side: Optional[Side] = None,
        need_kill: bool = False,
        diagnostics_ref: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.side = side
        self.need_kill = need_kill
        self.diagnostics_ref = diagnostics_ref


class _RejectionAbort(Exception):
    """Structured preflight refusal; finalized into rejection evidence."""

    def __init__(self, rejection: PreflightRejection, message: str) -> None:
        super().__init__(message)
        self.rejection = rejection


# --------------------------------------------------------------------------
# Cleanup executors (CleanupExecutor protocol bindings)
# --------------------------------------------------------------------------


class _MarkerExecutor:
    """CleanupExecutor binding used while creating one attempt database:
    executes the unqualified marker DDL/INSERT on the side's adapter and
    records every statement as a MARKER stage observation."""

    def __init__(
        self,
        adapter: AdapterLike,
        recorder: _EvidenceRecorder,
        *,
        side: Side,
        database: str,
        connection_id: str,
    ) -> None:
        self._adapter = adapter
        self._recorder = recorder
        self._side = side
        self._database = database
        self._connection_id = connection_id

    def execute_ddl(self, sql: str) -> None:
        self._recorder.record_sql(
            side=self._side,
            stage=StageObservationKind.MARKER,
            slug="marker",
            sql=sql,
            connection_id=self._connection_id,
            actual_database=self._database,
            session_id=self._connection_id,
        )
        executed = self._adapter.execute_statement(sql)
        if executed.receipt.error is not None:
            error = executed.receipt.error
            raise ContractError(
                f"marker statement failed on {self._database}: "
                f"errno={error.errno} {error.message}"
            )

    def is_database_present(self, name: str) -> bool:  # pragma: no cover - unused here
        raise ContractError("marker executor does not answer presence probes")


class _CleanupExecutor:
    """CleanupExecutor binding for :class:`AttemptCleaner`: runs the
    qualified drop DDL and answers presence via INFORMATION_SCHEMA."""

    def __init__(
        self,
        adapters: Sequence[AdapterLike],
        recorder: _EvidenceRecorder,
        *,
        side: Optional[Side],
    ) -> None:
        if not adapters:
            raise ContractError("cleanup needs at least one live adapter")
        self._adapter = adapters[0]
        self._recorder = recorder
        self._side = side

    def execute_ddl(self, sql: str) -> None:
        self._recorder.record_sql(
            side=None,
            stage=StageObservationKind.CLEANUP,
            slug="cleanup",
            sql=sql,
            connection_id=None,
        )
        executed = self._adapter.execute_statement(sql)
        if executed.receipt.error is not None:
            error = executed.receipt.error
            raise ContractError(f"cleanup DDL failed: errno={error.errno} {error.message}")

    def is_database_present(self, name: str) -> bool:
        if not isinstance(name, str) or _PLAIN_IDENT_RE.match(name) is None:
            raise ContractError(f"cleanup presence probe refused name {name!r}")
        sql = _SCHEMA_PRESENT_SQL.format(database=name)
        result = self._adapter.execute_raw_query(
            sql,
            row_budget=_PROBE_ROW_BUDGET,
            byte_budget=_PROBE_BYTE_BUDGET,
        )
        if result.truncated:  # pragma: no cover - a one-row probe cannot truncate
            raise ContractError(f"presence probe for {name!r} truncated (fail closed)")
        return result.observed_row_count == 1


# --------------------------------------------------------------------------
# The port
# --------------------------------------------------------------------------


class MySQLExecutionPort:
    """ExecutionPort over injected adapters, journal and clock.

    One port instance serves one run (the ownership journal is per-run);
    ``prepare`` may be called for several attempts of that run.  The port is
    synchronous and single-threaded; ``cancel_and_wait`` is meant for a
    control-plane caller while this thread is blocked in ``execute`` on a
    real (blocking) adapter, or after a failure returned.
    """

    def __init__(
        self,
        *,
        adapter_factory: AdapterFactory,
        journal: OwnershipSink,
        quarantine: Optional[QuarantineLatch] = None,
        token_source: Optional[naming.TokenSource] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not callable(adapter_factory):
            raise ContractError("MySQLExecutionPort adapter_factory must be callable")
        if journal is None:
            raise ContractError("MySQLExecutionPort needs an ownership journal")
        self._adapter_factory = adapter_factory
        self._journal = journal
        self._latch = quarantine if quarantine is not None else QuarantineLatch()
        self._token_source = token_source
        self._clock = clock if clock is not None else time.monotonic
        self._run_token: Optional[str] = None
        self._used_name_map_hashes: Set[str] = set()
        self._attempts: Dict[str, _AttemptState] = {}

    # -- introspection (test/trace seams; no server I/O) --------------------

    def lifecycle_state(self, attempt_id: str) -> LifecycleState:
        return self._require_state(attempt_id).state

    def stage_observations(self, attempt_id: str) -> Tuple[StageObservation, ...]:
        return tuple(self._require_state(attempt_id).recorder.observations)

    def payloads(self, attempt_id: str) -> Dict[str, bytes]:
        return dict(self._require_state(attempt_id).recorder.payloads)

    def fact_summary(self, attempt_id: str) -> Dict[str, str]:
        summary = self._require_state(attempt_id).summary
        if summary is None:
            raise ContractError(f"attempt {attempt_id!r} has no fact summary yet")
        return dict(summary)

    def _require_state(self, attempt_id: str) -> _AttemptState:
        state = self._attempts.get(attempt_id)
        if state is None:
            raise ContractError(f"unknown attempt {attempt_id!r}")
        return state

    # -- prepare --------------------------------------------------------------

    def prepare(self, request: AttemptRequest, control: Control) -> AttemptExpectation:
        if not isinstance(request, AttemptRequest):
            raise ExecutionPortError("prepare needs an AttemptRequest")
        if not isinstance(control, Control):
            raise ExecutionPortError("prepare needs a Control")
        self._latch.require_dispatch_allowed()
        control.raise_if_cancelled()

        if self._run_token is None:
            self._run_token = naming.new_run_token(self._token_source)
        if request.attempt_id in self._attempts:
            raise ExecutionPortError(
                f"attempt id {request.attempt_id!r} was already prepared",
                failure=AttemptFailure(
                    stage=AttemptStage.PREPARE,
                    code=str(StopReason.EXECUTION_PROTOCOL_ERROR.value),
                    side=None,
                    diagnostics_ref=None,
                ),
            )
        name_map, attempt_token = self._allocate_name_map()
        state = _AttemptState(
            run_id=request.run_id,
            attempt_id=request.attempt_id,
            run_token=self._run_token,
            attempt_token=attempt_token,
            name_map=name_map,
        )
        self._attempts[request.attempt_id] = state
        state.state = transition(state.state, LifecycleState.PREPARED)
        self._journal.append(
            OwnershipEventKind.ATTEMPT_ALLOCATED,
            attempt_id=request.attempt_id,
            token=state.attempt_token,
        )
        for database in (name_map.database_a, name_map.database_b):
            self._journal.append(
                OwnershipEventKind.OBJECT_ALLOCATED,
                attempt_id=request.attempt_id,
                object_name=database,
                token=state.attempt_token,
            )
            state.owned_objects.append(database)

        try:
            return self._prepare_body(request, control, state)
        except _RejectionAbort as abort:
            self._seal_rejection(request, state, abort)
            raise ExecutionPortError(
                str(abort),
                evidence=state.evidence,
                terminal=state.terminal,
            ) from abort
        except _AttemptAbort as abort:
            self._unwind_and_raise(request, state, abort)
        except Exception as exc:  # noqa: BLE001 - every failure becomes typed evidence
            self._unwind_and_raise(request, state, _map_exception(exc, AttemptStage.PREPARE))
        raise AssertionError("unreachable: every prepare failure path raises")

    def _allocate_name_map(self) -> Tuple[NameMap, str]:
        for _ in range(_NAME_MAP_DRAWS):
            attempt_token = naming.new_attempt_token(self._token_source)
            database_a, database_b = naming.attempt_database_names(
                self._run_token, attempt_token
            )
            name_map = NameMap(
                database_a=database_a,
                database_b=database_b,
                table_a=naming.TABLE_A,
                table_b=naming.TABLE_B,
            )
            name_map_hash = name_map_content_hash(name_map)
            if name_map_hash not in self._used_name_map_hashes:
                return name_map, attempt_token
        raise ExecutionPortError(
            f"no fresh name map after {_NAME_MAP_DRAWS} attempt-token draws",
            failure=AttemptFailure(
                stage=AttemptStage.PREPARE,
                code=str(StopReason.EXECUTION_PROTOCOL_ERROR.value),
                side=None,
                diagnostics_ref=None,
            ),
        )

    def _prepare_body(
        self, request: AttemptRequest, control: Control, state: _AttemptState
    ) -> AttemptExpectation:
        # Read-only probes first: the environment decision happens before any
        # test object exists, so a refusal leaves nothing to clean up.
        adapter_a = self._adapter_factory()
        state.adapters["a"] = adapter_a
        connection_a = self._connect(
            adapter_a, request, control, state, Side.A, AttemptStage.PREPARE
        )
        observed = self._probe_environment(
            adapter_a, state, request, Side.A, connection_a
        )
        self._check_target_environment(request, state, observed)
        state.server_uuid = observed.instance_identity

        adapter_b = self._adapter_factory()
        state.adapters["b"] = adapter_b
        connection_b = self._connect(
            adapter_b, request, control, state, Side.B, AttemptStage.PREPARE
        )
        observed_b = self._probe_environment(
            adapter_b, state, request, Side.B, connection_b
        )
        if observed_b.instance_identity != observed.instance_identity:
            # A proxy routing the second connection to another instance stops
            # here; the D3 same-instance proof is this server-uuid check.
            raise _AttemptAbort(
                code=str(ComparisonReason.ENVIRONMENT_DRIFT.value),
                stage=AttemptStage.PREPARE,
                message=(
                    "side B connection observed a different server identity "
                    f"({observed_b.instance_identity} != {observed.instance_identity})"
                ),
            )

        rendered = render_pair(request.payload, state.name_map)
        # Lifecycle: the whole prepare walk is one SETUP -> READBACK sweep over
        # both sides (per-side sub-states are not representable in the frozen
        # linear machine; the observations carry the per-side detail).
        state.state = transition(state.state, LifecycleState.SETUP)
        facts_sides: Dict[str, SideFacts] = {}
        for side, adapter, connection, database, table, declared_type in (
            (Side.A, adapter_a, connection_a, state.name_map.database_a,
             state.name_map.table_a, request.payload.a_type),
            (Side.B, adapter_b, connection_b, state.name_map.database_b,
             state.name_map.table_b, request.payload.b_type),
        ):
            facts_sides["a" if side is Side.A else "b"] = self._load_side(
                request, control, state, rendered, adapter,
                side=side, connection_id=connection, database=database,
                table=table, declared_type=declared_type,
            )

        observed_environment = observed
        state.state = transition(state.state, LifecycleState.READBACK)
        binding = ExpectedBinding(
            run_id=request.run_id,
            case_id=request.case_id,
            attempt_id=request.attempt_id,
            environment_hash=environment_content_hash(request.target_environment),
            name_map_hash=name_map_content_hash(state.name_map),
        )
        facts = RuntimeFacts(
            binding=binding,
            observed_environment=observed_environment,
            name_map=state.name_map,
            a=facts_sides["a"],
            b=facts_sides["b"],
        )
        state.facts = facts
        state.observed_environment = observed_environment
        state.summary = attempt_fact_summary(
            binding=binding,
            name_map=state.name_map,
            observed_environment=observed_environment,
        )
        check = validate_runtime_facts(request.payload, binding, facts)
        if check.status is not RuntimeCheckStatus.READY:
            raise _AttemptAbort(
                code=str(ComparisonReason.RUNTIME_NOT_READY.value),
                stage=AttemptStage.SETUP,
                message=(
                    "runtime fact validation is "
                    f"{str(check.status.value)}; the attempt is not comparable"
                ),
            )

        state.state = transition(state.state, LifecycleState.READY)
        self._used_name_map_hashes.add(name_map_content_hash(state.name_map))
        expectation = AttemptExpectation(
            binding=binding,
            request_hash=request.request_hash,
            codec_version=CODEC_VERSION,
            execution_order=request.execution_order,
            name_map=state.name_map,
        )
        state.expectation = expectation
        self._close_adapters(state)
        return expectation

    def _connect(
        self,
        adapter: AdapterLike,
        request: AttemptRequest,
        control: Control,
        state: _AttemptState,
        side: Side,
        stage: AttemptStage,
    ) -> str:
        control.raise_if_cancelled()
        self._check_deadline(control, stage)
        try:
            adapter.connect_and_probe()
        except Exception as exc:  # noqa: BLE001 - typed below
            raise _map_exception(exc, stage, side=side) from exc
        connection_id = str(adapter.connection_id())
        state.recorder.record_sql(
            side=side,
            stage=StageObservationKind.PROBE,
            slug="probe",
            sql="CONNECT + identity probe (adapter-owned batched constant SELECTs)",
            connection_id=connection_id,
            session_id=connection_id,
        )
        return connection_id

    def _probe_environment(
        self,
        adapter: AdapterLike,
        state: _AttemptState,
        request: AttemptRequest,
        side: Side,
        connection_id: str,
    ) -> ObservedEnvironment:
        try:
            facts = dict(adapter.fetch_environment_facts())
            observed = observed_environment_from_facts(
                facts, build_id=request.target_environment.build_id
            )
        except Exception as exc:  # noqa: BLE001
            raise _map_exception(exc, AttemptStage.PREPARE) from exc
        state.recorder.record_sql(
            side=side,
            stage=StageObservationKind.PROBE,
            slug="probe",
            sql="environment facts snapshot (adapter-owned constant SELECTs)",
            connection_id=connection_id,
            session_id=connection_id,
            detail=f"environment content hash {environment_content_hash(observed)}",
        )
        return observed

    def _check_target_environment(
        self,
        request: AttemptRequest,
        state: _AttemptState,
        observed: ObservedEnvironment,
    ) -> None:
        target_hash = environment_content_hash(request.target_environment)
        observed_hash = environment_content_hash(observed)
        if observed_hash == target_hash:
            return
        requirement = rejected_requirement_id(request.payload, observed)
        if requirement is not None:
            # The snapshot itself proves a frozen requirement is violated:
            # structured NOT_APPLICABLE rejection (oracle gate 2 proof).
            raise _RejectionAbort(
                PreflightRejection(
                    request_hash=request.request_hash,
                    observed_environment=observed,
                    rejected_requirement_id=requirement,
                    capability_check_version=CAPABILITY_CHECK_VERSION,
                ),
                f"observed environment violates frozen requirement {requirement!r}",
            )
        raise _AttemptAbort(
            code=str(ComparisonReason.ENVIRONMENT_DRIFT.value),
            stage=AttemptStage.PREPARE,
            message=(
                f"observed environment content hash {observed_hash} does not match the "
                f"target {target_hash} and no frozen requirement is provably violated"
            ),
        )

    def _load_side(
        self,
        request: AttemptRequest,
        control: Control,
        state: _AttemptState,
        rendered,
        adapter: AdapterLike,
        *,
        side: Side,
        connection_id: str,
        database: str,
        table: str,
        declared_type,
    ) -> SideFacts:
        """Create the side's objects marker-first, load rows, read back."""
        self._check_budget(request, control, side)

        # 1. CREATE DATABASE (no IF NOT EXISTS: an existing name is a conflict).
        #    Not a rendered statement: it produces a stage observation and a
        #    journal event, never a setup diagnostic or statement receipt
        #    (gate 4/3 compare those against the render_pair sequence only).
        create = database_create_sql(database)
        _, create_ref = state.recorder.record_sql(
            side=side,
            stage=StageObservationKind.DATABASE_CREATE,
            slug="database-create",
            sql=create,
            connection_id=connection_id,
            actual_database=database,
            session_id=connection_id,
        )
        try:
            executed_create = adapter.execute_statement(create)
        except Exception as exc:  # noqa: BLE001
            raise _map_exception(exc, AttemptStage.SETUP, side=side) from exc
        if executed_create.receipt.error is not None:
            error = executed_create.receipt.error
            raise _AttemptAbort(
                code=_sql_error_code(),
                stage=AttemptStage.SETUP,
                side=side,
                diagnostics_ref=create_ref,
                message=(
                    f"CREATE DATABASE {database} failed: errno={error.errno} "
                    f"{error.message}"
                ),
            )
        self._journal.append(
            OwnershipEventKind.OBJECT_CREATED,
            attempt_id=request.attempt_id,
            server_uuid=state.server_uuid,
            object_name=database,
            token=state.attempt_token,
        )

        # 2. Select the database (rendered DDL/INSERT texts are unqualified).
        use_sql = f"USE `{database}`"
        state.recorder.record_sql(
            side=side,
            stage=StageObservationKind.DDL,
            slug="ddl",
            sql=use_sql,
            connection_id=connection_id,
            actual_database=database,
            session_id=connection_id,
            detail="select the attempt database (unqualified statements follow)",
        )
        executed_use = adapter.execute_statement(use_sql)
        if executed_use.receipt.error is not None:
            error = executed_use.receipt.error
            raise _AttemptAbort(
                code=_sql_error_code(),
                stage=AttemptStage.SETUP,
                side=side,
                message=f"USE `{database}` failed: errno={error.errno} {error.message}",
            )

        # 3. Marker table FIRST inside the attempt database (before any test
        #    table; matches the frozen cleanup drop order).
        ensure_marker(
            _MarkerExecutor(adapter, state.recorder, side=side, database=database,
                            connection_id=connection_id),
            run_id=request.run_id,
            attempt_id=request.attempt_id,
            token=state.attempt_token,
        )
        self._journal.append(
            OwnershipEventKind.MARKER_CREATED,
            attempt_id=request.attempt_id,
            server_uuid=state.server_uuid,
            object_name=f"{database}.{naming.marker_table_name()}",
            token=state.attempt_token,
        )

        # 4. Rendered DDL + INSERTs with per-phase 0-based receipts.
        statement_receipts = []
        per_phase_ordinal = {StatementPhase.DDL: 0, StatementPhase.INSERT: 0}
        for rendered_statement in _side_statements(rendered, side):
            if str(rendered_statement.phase.value) == "select":
                # The tested SELECT is never part of the load: it runs in the
                # query phase only (design 6.2.2 boundary).
                continue
            phase = (
                StatementPhase.DDL
                if str(rendered_statement.phase.value) == str(StatementPhase.DDL.value)
                else StatementPhase.INSERT
            )
            self._check_budget(request, control, side)
            _, sql_ref = state.recorder.record_sql(
                side=side,
                stage=StageObservationKind.DDL
                if phase is StatementPhase.DDL
                else StageObservationKind.INSERT,
                slug="ddl" if phase is StatementPhase.DDL else "insert",
                sql=rendered_statement.text,
                connection_id=connection_id,
                actual_database=database,
                session_id=connection_id,
            )
            executed = self._execute_setup_statement(
                request, state, adapter, rendered_statement.text, side=side,
                phase=phase, ordinal=per_phase_ordinal[phase],
                diagnostics_ref=sql_ref,
            )
            per_phase_ordinal[phase] += 1
            statement_receipts.append(executed)
            if phase is StatementPhase.DDL:
                self._journal.append(
                    OwnershipEventKind.OBJECT_CREATED,
                    attempt_id=request.attempt_id,
                    server_uuid=state.server_uuid,
                    object_name=f"{database}.{table}",
                    token=state.attempt_token,
                )
                state.owned_objects.append(f"{database}.{table}")

        # 5. Readback: exact rows over the fixed port-owned probe.
        readback_rows, readback_complete = self._readback_side(
            request, state, adapter, side=side, connection_id=connection_id,
            database=database, table=table,
        )

        # 6. Structural schema probe (port-owned SQL; the answer, not the
        #    declaration, becomes the fact).
        actual_schema = self._probe_schema(
            request, state, adapter, side=side, connection_id=connection_id,
            database=database, table=table, declared_type=declared_type,
        )

        return SideFacts(
            statement_receipts=tuple(statement_receipts),
            readback=Rows(readback_rows),
            readback_complete=readback_complete,
            actual_schema=actual_schema,
            load_committed=True,
            isolation_confirmed=True,
        )

    def _execute_setup_statement(
        self,
        request: AttemptRequest,
        state: _AttemptState,
        adapter: AdapterLike,
        sql: str,
        *,
        side: Side,
        phase: StatementPhase,
        ordinal: int,
        diagnostics_ref: str,
    ) -> "Any":
        try:
            executed = adapter.execute_statement(sql)
        except Exception as exc:  # noqa: BLE001
            raise _map_exception(exc, AttemptStage.SETUP, side=side) from exc
        receipt = executed.receipt
        diagnostics = self._statement_diagnostics(
            state, side=side, phase=phase, ordinal=ordinal, sql=sql,
            receipt=receipt, diagnostics_ref=diagnostics_ref,
        )
        state.setup_diagnostics.append(diagnostics)
        if receipt.error is not None:
            error = receipt.error
            raise _AttemptAbort(
                code=_sql_error_code(),
                stage=AttemptStage.SETUP,
                side=side,
                diagnostics_ref=diagnostics_ref,
                message=(
                    f"{str(phase.value)} statement failed on side "
                    f"{side.value}: errno={error.errno} {error.message}"
                ),
            )
        return StatementReceipt(
            phase=phase,
            ordinal=ordinal,
            sql_hash=sha256_hex(sql.encode("utf-8")),
            success=True,
            diagnostics_complete=(
                diagnostics.collected and diagnostics.complete and not diagnostics.entries
            ),
        )

    def _statement_diagnostics(
        self,
        state: _AttemptState,
        *,
        side: Side,
        phase,
        ordinal: int,
        sql: str,
        receipt: Any,
        diagnostics_ref: str,
    ) -> StatementDiagnostics:
        raw = receipt.diagnostics
        if not raw.collected:
            return StatementDiagnostics(
                side=side,
                phase=phase,
                ordinal=ordinal,
                sql_hash=sha256_hex(sql.encode("utf-8")),
                collected=False,
                complete=False,
                entries=(),
            )
        entries = []
        for index, entry in enumerate(raw.entries):
            level = _diagnostic_level(str(entry.level))
            if level is None:
                raise FactCollectionError(
                    f"diagnostic entry level {entry.level!r} is outside the frozen "
                    "vocabulary (fail closed)"
                )
            message_ref = state.recorder.add_payload(
                diagnostics_ref.rsplit(".", 1)[0] + f".diagnostics-{index}.txt",
                str(entry.message).encode("utf-8"),
            )
            entries.append(
                DiagnosticEntry(
                    level=level,
                    code=str(entry.code),
                    sqlstate=entry.sqlstate,
                    message_ref=message_ref,
                )
            )
        return StatementDiagnostics(
            side=side,
            phase=phase,
            ordinal=ordinal,
            sql_hash=sha256_hex(sql.encode("utf-8")),
            collected=True,
            # complete=True is only comparable with no entries (model rule).
            complete=bool(raw.complete) and not entries,
            entries=tuple(entries),
        )

    def _readback_side(
        self,
        request: AttemptRequest,
        state: _AttemptState,
        adapter: AdapterLike,
        *,
        side: Side,
        connection_id: str,
        database: str,
        table: str,
    ) -> Tuple[Tuple[Row, ...], bool]:
        sql = _READBACK_SQL.format(table=table)
        state.recorder.record_sql(
            side=side,
            stage=StageObservationKind.READBACK,
            slug="readback",
            sql=sql,
            connection_id=connection_id,
            actual_database=database,
            session_id=connection_id,
        )
        try:
            result = adapter.execute_raw_query(
                sql,
                row_budget=MAX_RESULT_ROWS,
                byte_budget=MAX_RESULT_BYTES,
            )
        except Exception as exc:  # noqa: BLE001
            raise _map_exception(exc, AttemptStage.SETUP, side=side) from exc
        if result.truncated:
            raise _AttemptAbort(
                code=PROTOCOL_BUDGET_EXCEEDED,
                stage=AttemptStage.SETUP,
                side=side,
                message="readback probe truncated (fail closed)",
            )
        if not result.fetch_complete:
            raise _AttemptAbort(
                code=RESULT_CONTRACT_VIOLATION,
                stage=AttemptStage.SETUP,
                side=side,
                message="readback probe fetch did not complete (fail closed)",
            )
        declared_type = (
            request.payload.a_type if side is Side.A else request.payload.b_type
        )
        try:
            rows = decode_readback_rows(result.rows, declared_type=declared_type)
        except Exception as exc:  # noqa: BLE001
            raise _map_exception(exc, AttemptStage.SETUP, side=side) from exc
        return rows, True

    def _probe_schema(
        self,
        request: AttemptRequest,
        state: _AttemptState,
        adapter: AdapterLike,
        *,
        side: Side,
        connection_id: str,
        database: str,
        table: str,
        declared_type,
    ) -> TableSpec:
        if _PLAIN_IDENT_RE.match(database) is None or _PLAIN_IDENT_RE.match(table) is None:
            raise _AttemptAbort(
                code=str(StopReason.EXECUTION_PROTOCOL_ERROR.value),
                stage=AttemptStage.SETUP,
                side=side,
                message="schema probe refused a name outside the identifier grammar",
            )
        probes = (
            ("schema-tables", _SCHEMA_TABLES_SQL),
            ("schema-columns", _SCHEMA_COLUMNS_SQL),
            ("schema-statistics", _SCHEMA_STATISTICS_SQL),
        )
        answers = []
        for slug, template in probes:
            sql = template.format(database=database, table=table)
            state.recorder.record_sql(
                side=side,
                stage=StageObservationKind.PROBE,
                slug=slug,
                sql=sql,
                connection_id=connection_id,
                actual_database=database,
                session_id=connection_id,
            )
            try:
                result = adapter.execute_raw_query(
                    sql,
                    row_budget=_PROBE_ROW_BUDGET,
                    byte_budget=_PROBE_BYTE_BUDGET,
                )
            except Exception as exc:  # noqa: BLE001
                raise _map_exception(exc, AttemptStage.SETUP, side=side) from exc
            if result.truncated:
                raise _AttemptAbort(
                    code=PROTOCOL_BUDGET_EXCEEDED,
                    stage=AttemptStage.SETUP,
                    side=side,
                    message=f"schema probe {slug} truncated (fail closed)",
                )
            answers.append(result.rows)
        try:
            return normalize_side_schema(
                tables_rows=answers[0],
                columns_rows=answers[1],
                statistics_rows=answers[2],
                declared_table=table,
                declared_type=declared_type,
                index_variant=request.payload.table.index_variant,
            )
        except Exception as exc:  # noqa: BLE001
            raise _map_exception(exc, AttemptStage.SETUP, side=side) from exc

    def _seal_rejection(
        self, request: AttemptRequest, state: _AttemptState, abort: _RejectionAbort
    ) -> None:
        """Finalize a structured preflight refusal: nothing was created, so
        the attempt seals cleanly with NOT_STARTED terminal semantics."""
        self._close_adapters(state)
        if state.state in CANCEL_ENTRY_STATES:
            state.state = transition(state.state, LifecycleState.CANCELLING)
            state.state = transition(state.state, LifecycleState.CLEANING)
            state.state = transition(state.state, LifecycleState.SEALED)
        state.terminal = TerminalReceipt(
            attempt_id=request.attempt_id,
            termination=TerminationState.NOT_STARTED,
            cleanup=CleanupState.DONE,
            owned_objects=(),
        )
        state.evidence = ExecutionEvidence(
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
            terminal=state.terminal,
            failure=None,
            preflight_rejection=abort.rejection,
            synthetic=request.synthetic,
        )

    def _unwind_and_raise(
        self, request: AttemptRequest, state: _AttemptState, abort: _AttemptAbort
    ) -> None:
        # The evidence model requires it: a failure whose stage is anything
        # but PREPARE must carry the sealed expectation, and before prepare
        # returns there is none -- so prepare-stage failures always record
        # stage PREPARE regardless of the internal sub-stage.
        stage = (
            abort.stage if state.expectation is not None else AttemptStage.PREPARE
        )
        failure = AttemptFailure(
            stage=stage,
            code=abort.code,
            side=abort.side,
            diagnostics_ref=abort.diagnostics_ref,
        )
        state.failure = failure
        terminal = self._terminate_and_clean(state, need_kill=abort.need_kill)
        state.evidence = self._build_evidence(
            request,
            state,
            failure=failure,
            terminal=terminal,
        )
        raise ExecutionPortError(
            str(abort), failure=failure, evidence=state.evidence, terminal=terminal
        ) from abort

    def _build_evidence(
        self,
        request: AttemptRequest,
        state: _AttemptState,
        *,
        failure: Optional[AttemptFailure],
        terminal: TerminalReceipt,
    ) -> ExecutionEvidence:
        return ExecutionEvidence(
            request_hash=request.request_hash,
            expectation=state.expectation,
            runtime_facts=state.facts,
            setup_diagnostics=tuple(state.setup_diagnostics),
            actual_execution_order=state.actual_order,
            a_context=state.contexts.get("a"),
            b_context=state.contexts.get("b"),
            a_query=state.queries.get("a"),
            b_query=state.queries.get("b"),
            isolation_receipt=None,
            terminal=terminal,
            failure=failure,
            preflight_rejection=None,
            synthetic=request.synthetic,
        )

    def _terminate_and_clean(
        self, state: _AttemptState, *, need_kill: bool
    ) -> TerminalReceipt:
        """Unwind entry: confirm termination, then clean or quarantine.

        Returns the terminal receipt; mutates the lifecycle state and journal.
        Never raises for cleanup DDL failures (they become quarantine or a
        FAILED terminal), and never drops objects when termination is
        unconfirmed.
        """
        if state.state in CANCEL_ENTRY_STATES and state.state is not LifecycleState.CANCELLING:
            state.state = transition(state.state, LifecycleState.CANCELLING)
        state.recorder.record_sql(
            side=None,
            stage=StageObservationKind.TERMINATION,
            slug="termination",
            sql="CANCEL (KILL QUERY via injected control connection)"
            if need_kill
            else "no statement in flight (synchronous adapter calls); no KILL needed",
            connection_id=None,
            detail=f"need_kill={need_kill}",
        )

        confirmed = True
        if need_kill:
            for adapter in state.adapters.values():
                try:
                    receipt = adapter.cancel_current()
                    if receipt.kill.error is not None:
                        confirmed = False
                except Exception:  # noqa: BLE001 - unconfirmable is a fact
                    confirmed = False
        if confirmed:
            self._journal.append(
                OwnershipEventKind.TERMINATION_CONFIRMED,
                attempt_id=state.attempt_id,
                server_uuid=state.server_uuid,
            )
            if state.state is LifecycleState.CANCELLING:
                state.state = transition(state.state, LifecycleState.CLEANING)
            outcome = self._clean(state)
            if outcome.completed:
                terminal = TerminalReceipt(
                    attempt_id=state.attempt_id,
                    termination=TerminationState.CONFIRMED,
                    cleanup=CleanupState.DONE,
                    owned_objects=tuple(state.owned_objects),
                )
            else:
                self._quarantine(state, "cleanup failed during unwind")
                terminal = TerminalReceipt(
                    attempt_id=state.attempt_id,
                    termination=TerminationState.CONFIRMED,
                    cleanup=CleanupState.FAILED,
                    owned_objects=tuple(state.owned_objects),
                )
        else:
            self._journal.append(
                OwnershipEventKind.TERMINATION_UNKNOWN,
                attempt_id=state.attempt_id,
                server_uuid=state.server_uuid,
            )
            self._quarantine(
                state, "cancellation unconfirmed; objects kept for forensics"
            )
            terminal = TerminalReceipt(
                attempt_id=state.attempt_id,
                termination=TerminationState.UNKNOWN,
                cleanup=CleanupState.PENDING,
                owned_objects=tuple(state.owned_objects),
            )
        state.terminal = terminal
        self._close_adapters(state)
        return terminal

    def _clean(self, state: _AttemptState) -> CleanupOutcome:
        live = [state.adapters[key] for key in ("a", "b") if key in state.adapters]
        if not live:
            # No connection survives; presence probes answer "absent" and the
            # cleaner records idempotent confirmations.
            return _clean_without_adapter(state, self._journal)
        cleaner = AttemptCleaner(
            _CleanupExecutor(live, state.recorder, side=None), self._journal
        )
        return cleaner.clean(
            run_id=state.run_id,
            attempt_id=state.attempt_id,
            run_token=state.run_token,
            attempt_token=state.attempt_token,
        )

    def _quarantine(self, state: _AttemptState, reason: str) -> None:
        self._latch.trip(reason)
        self._journal.append(
            OwnershipEventKind.QUARANTINED,
            attempt_id=state.attempt_id,
            server_uuid=state.server_uuid,
        )
        if state.state in (LifecycleState.CANCELLING, LifecycleState.TERMINATING,
                           LifecycleState.CLEANING):
            state.state = transition(state.state, LifecycleState.QUARANTINED)

    def _close_adapters(self, state: _AttemptState) -> None:
        for adapter in list(state.adapters.values()):
            try:
                adapter.close()
            except Exception:  # noqa: BLE001 - close is best-effort
                pass
        state.adapters.clear()

    # -- execute --------------------------------------------------------------

    def execute(
        self,
        request: AttemptRequest,
        expectation: AttemptExpectation,
        control: Control,
    ) -> ExecutionEvidence:
        if not isinstance(request, AttemptRequest) or not isinstance(
            expectation, AttemptExpectation
        ):
            raise ExecutionPortError("execute needs an AttemptRequest and expectation")
        if not isinstance(control, Control):
            raise ExecutionPortError("execute needs a Control")
        self._latch.require_dispatch_allowed()
        state = self._attempts.get(request.attempt_id)
        if state is None or state.expectation is None:
            raise ExecutionPortError(
                f"attempt {request.attempt_id!r} was never prepared",
                failure=AttemptFailure(
                    stage=AttemptStage.QUERY,
                    code=str(StopReason.EXECUTION_PROTOCOL_ERROR.value),
                    side=None,
                    diagnostics_ref=None,
                ),
            )
        if (
            request.request_hash != state.expectation.request_hash
            or request.request_hash != expectation.request_hash
            or expectation.expectation_hash != state.expectation.expectation_hash
            or state.state is not LifecycleState.READY
        ):
            raise ExecutionPortError(
                "execute identity/lifecycle check failed (request, expectation or "
                "attempt state does not match the prepared attempt)",
                failure=AttemptFailure(
                    stage=AttemptStage.QUERY,
                    code=str(StopReason.EXECUTION_PROTOCOL_ERROR.value),
                    side=None,
                    diagnostics_ref=None,
                ),
            )
        control.raise_if_cancelled()
        self._check_deadline(control, AttemptStage.QUERY)
        state.actual_order = request.execution_order
        try:
            return self._execute_body(request, expectation, control, state)
        except _AttemptAbort as abort:
            self._unwind_and_raise(request, state, abort)
        except Exception as exc:  # noqa: BLE001
            self._unwind_and_raise(request, state, _map_exception(exc, AttemptStage.QUERY))
        raise AssertionError("unreachable: every execute failure path raises")

    def _execute_body(
        self,
        request: AttemptRequest,
        expectation: AttemptExpectation,
        control: Control,
        state: _AttemptState,
    ) -> ExecutionEvidence:
        # prepare() closed its connections; the query phase opens one fresh
        # connection per side so setup/readback/select share one session
        # identity (SideContext invariant).
        adapter_for_side: Dict[Side, AdapterLike] = {}
        connection_for_side: Dict[Side, str] = {}
        environment_for_side: Dict[Side, ObservedEnvironment] = {}
        for side in _DISPATCH_SIDES[request.execution_order]:
            adapter = self._adapter_factory()
            state.adapters["a" if side is Side.A else "b"] = adapter
            adapter_for_side[side] = adapter
            connection_for_side[side] = self._connect(
                adapter, request, control, state, side, AttemptStage.QUERY
            )
            environment_for_side[side] = self._probe_environment(
                adapter, state, request, side, connection_for_side[side]
            )
            if (
                environment_for_side[side].instance_identity != state.observed_environment.instance_identity
                or environment_content_hash(environment_for_side[side])
                != environment_content_hash(request.target_environment)
            ):
                raise _AttemptAbort(
                    code=str(ComparisonReason.ENVIRONMENT_DRIFT.value),
                    stage=AttemptStage.QUERY,
                    side=side,
                    message=(
                        f"side {side.value} query-phase environment drifted from the "
                        "target snapshot"
                    ),
                )

        rendered = render_pair(request.payload, state.name_map)
        relation = request.payload.relation
        for index, side in enumerate(_DISPATCH_SIDES[request.execution_order]):
            # Both sides' select work happens in the frozen QUERY/FETCH
            # region (the linear machine has no per-side states); the first
            # side enters QUERY here, the first fetch moves to FETCH, and
            # the second side completes inside the FETCH region.
            if state.state is LifecycleState.READY:
                state.state = transition(state.state, LifecycleState.QUERY)
            adapter = adapter_for_side[side]
            connection_id = connection_for_side[side]
            database = (
                state.name_map.database_a if side is Side.A else state.name_map.database_b
            )

            # 1. Session application with mandatory readback.
            profile = request.session_profile
            settings = {
                "autocommit": "1" if profile.autocommit else "0",
                "transaction_isolation": str(profile.transaction_isolation.value),
            }
            try:
                adapter.apply_session(settings)
            except Exception as exc:  # noqa: BLE001
                raise _map_session_exception(exc, side=side) from exc
            self._journal.append(
                OwnershipEventKind.SESSION_REGISTERED,
                attempt_id=request.attempt_id,
                server_uuid=state.server_uuid,
                connection_id=connection_id,
                session_generation=index,
            )
            state.recorder.record_sql(
                side=side,
                stage=StageObservationKind.SESSION,
                slug="session",
                sql="apply_session(" + ", ".join(f"{k}={v}" for k, v in settings.items())
                + ") with mandatory readback",
                connection_id=connection_id,
                actual_database=database,
                session_id=connection_id,
            )
            self._use_database(state, adapter, side, database, connection_id)

            # 2. The declared SELECT.
            select_statement = _side_select(rendered, side)
            self._journal.append(
                OwnershipEventKind.QUERY_STARTED,
                attempt_id=request.attempt_id,
                server_uuid=state.server_uuid,
                connection_id=connection_id,
            )
            started_s = self._clock()
            handle = None
            fetch = None
            stage = AttemptStage.QUERY
            try:
                try:
                    handle = adapter.open_query(select_statement.text)
                    stage = AttemptStage.FETCH
                    if state.state is LifecycleState.QUERY:
                        state.state = transition(state.state, LifecycleState.FETCH)
                    fetch = adapter.fetch_result(
                        handle,
                        row_budget=request.result_row_budget,
                        byte_budget=request.result_byte_budget,
                    )
                except _AttemptAbort:
                    raise
                except Exception as exc:  # noqa: BLE001
                    raise _map_exception(exc, stage, side=side) from exc
                duration_ms = int((self._clock() - started_s) * 1000)

                # 3. Budgets are re-checked after the fetch: a result that
                #    arrived after expiry is never a partial success.
                self._check_budget(request, control, side, stage=AttemptStage.FETCH)

                # 4. Defensive result-contract checks before any evidence is built.
                self._check_fetch(fetch, relation, side)

                # 5. SELECT diagnostics (port-collected; see module docstring).
                diagnostics = self._select_diagnostics(
                    request, state, adapter, side=side, sql=select_statement.text,
                    warning_count=fetch.warning_count, connection_id=connection_id,
                )

                # 6. Post-query environment snapshot.
                environment_after = self._probe_environment(
                    adapter, state, request, side, connection_id
                )
                if (
                    environment_after.instance_identity != state.observed_environment.instance_identity
                    or environment_content_hash(environment_after)
                    != environment_content_hash(request.target_environment)
                ):
                    raise _AttemptAbort(
                        code=str(ComparisonReason.ENVIRONMENT_DRIFT.value),
                        stage=AttemptStage.FETCH,
                        side=side,
                        message=(
                            f"side {side.value} post-query environment drifted from the "
                            "target snapshot"
                        ),
                    )
                self._journal.append(
                    OwnershipEventKind.QUERY_FINISHED,
                    attempt_id=request.attempt_id,
                    server_uuid=state.server_uuid,
                    connection_id=connection_id,
                )

                # 7. Frozen evidence models (duplicates and order preserved).
                result_set = self._result_set(fetch, relation, side)
                state.queries["a" if side is Side.A else "b"] = QueryEvidence(
                    side=side,
                    binding=expectation.binding,
                    select_text=select_statement.text,
                    select_sql_hash=select_statement.sql_hash,
                    protocol="text",
                    parameters=(),
                    status=QueryStatus.COMPLETE,
                    result=result_set,
                    session_start_id=connection_id,
                    session_end_id=connection_id,
                    actual_database=database,
                    environment_before=environment_for_side[side],
                    environment_after=environment_after,
                    diagnostics=diagnostics,
                    duration_ms=duration_ms,
                    result_terminal=ResultTerminal.CONFIRMED,
                )
                state.contexts["a" if side is Side.A else "b"] = SideContext(
                    side=side,
                    setup_connection_id=connection_id,
                    readback_connection_id=connection_id,
                    select_connection_id=connection_id,
                    current_database=database,
                    name_map=state.name_map,
                    autocommit=profile.autocommit,
                    transaction_isolation=profile.transaction_isolation,
                    environment_before=environment_for_side[side],
                    environment_after=environment_after,
                )
            except _AttemptAbort as abort:
                if self._absorb_side_query_failure(
                    request,
                    state,
                    expectation,
                    side,
                    abort=abort,
                    select_statement=select_statement,
                    fetch=fetch,
                    adapter=adapter,
                    connection_id=connection_id,
                    database=database,
                    environment_before=environment_for_side[side],
                    started_s=started_s,
                    relation=relation,
                ):
                    # Design 6.2.4 row 2: the side's SQL error is recorded in
                    # its QueryEvidence; the attempt continues (side B runs).
                    continue
                raise

        # 8. Normal termination and cleanup.
        # If every side's SELECT failed before any fetch started, the linear
        # machine never left QUERY; the query region is over now (no
        # statement in flight), so advance the region edge before sealing.
        if state.state is LifecycleState.QUERY:
            state.state = transition(state.state, LifecycleState.FETCH)
        state.state = transition(state.state, LifecycleState.TERMINATING)
        state.recorder.record_sql(
            side=None,
            stage=StageObservationKind.TERMINATION,
            slug="termination",
            sql="all statements terminated (synchronous adapter calls)",
            connection_id=None,
        )
        self._journal.append(
            OwnershipEventKind.TERMINATION_CONFIRMED,
            attempt_id=request.attempt_id,
            server_uuid=state.server_uuid,
        )
        state.state = transition(state.state, LifecycleState.CLEANING)
        outcome = self._clean(state)
        if not outcome.completed:
            failure = AttemptFailure(
                stage=AttemptStage.CLEANUP,
                code=str(OwnershipEventKind.CLEANUP_FAILED.value),
                side=None,
                diagnostics_ref=None,
            )
            state.failure = failure
            self._quarantine(state, "cleanup failed after a complete attempt")
            terminal = TerminalReceipt(
                attempt_id=request.attempt_id,
                termination=TerminationState.CONFIRMED,
                cleanup=CleanupState.FAILED,
                owned_objects=tuple(state.owned_objects),
            )
            state.terminal = terminal
            evidence = self._build_evidence(
                request,
                state,
                failure=failure,
                terminal=terminal,
            )
            state.evidence = evidence
            self._close_adapters(state)
            # The comparison data is complete but the attempt did not clean
            # up: returned as failed evidence, never as a success.
            return evidence

        state.state = transition(state.state, LifecycleState.SEALED)
        terminal = TerminalReceipt(
            attempt_id=request.attempt_id,
            termination=TerminationState.CONFIRMED,
            cleanup=CleanupState.DONE,
            owned_objects=tuple(state.owned_objects),
        )
        state.terminal = terminal
        isolation_receipt = IsolationReceipt(
            attempt_id=request.attempt_id,
            name_map_hash=name_map_content_hash(state.name_map),
            ownership_ref=(
                f"{request.run_id}/objects/{state.name_map.database_a},"
                f"{state.name_map.database_b}"
            ),
            objects_created_confirmed=True,
            load_committed=True,
            no_concurrent_write_confirmed=True,
            method_version=ISOLATION_METHOD_VERSION,
        )
        evidence = ExecutionEvidence(
            request_hash=request.request_hash,
            expectation=state.expectation,
            runtime_facts=state.facts,
            setup_diagnostics=tuple(state.setup_diagnostics),
            actual_execution_order=request.execution_order,
            a_context=state.contexts.get("a"),
            b_context=state.contexts.get("b"),
            a_query=state.queries.get("a"),
            b_query=state.queries.get("b"),
            isolation_receipt=isolation_receipt,
            terminal=terminal,
            failure=None,
            preflight_rejection=None,
            synthetic=request.synthetic,
        )
        state.evidence = evidence
        self._close_adapters(state)
        return evidence

    def _use_database(
        self,
        state: _AttemptState,
        adapter: AdapterLike,
        side: Side,
        database: str,
        connection_id: str,
    ) -> None:
        sql = f"USE `{database}`"
        state.recorder.record_sql(
            side=side,
            stage=StageObservationKind.DDL,
            slug="ddl",
            sql=sql,
            connection_id=connection_id,
            actual_database=database,
            session_id=connection_id,
            detail="re-select the attempt database for the query phase",
        )
        try:
            executed = adapter.execute_statement(sql)
        except Exception as exc:  # noqa: BLE001
            raise _map_exception(exc, AttemptStage.QUERY, side=side) from exc
        if executed.receipt.error is not None:
            error = executed.receipt.error
            raise _AttemptAbort(
                code=_sql_error_code(),
                stage=AttemptStage.QUERY,
                side=side,
                message=f"USE `{database}` failed: errno={error.errno} {error.message}",
            )

    def _absorb_side_query_failure(
        self,
        request: AttemptRequest,
        state: _AttemptState,
        expectation: AttemptExpectation,
        side: Side,
        *,
        abort: _AttemptAbort,
        select_statement,
        fetch,
        adapter,
        connection_id: str,
        database: str,
        environment_before: ObservedEnvironment,
        started_s: float,
        relation,
    ) -> bool:
        """Design 6.2.4 rows 2/3 for one side's query region.

        Row 2 (SQL_ERROR, context still collectible): record that side's
        ``QueryEvidence`` (SQL_ERROR, ``result=None`` after the error
        response, ``ResultTerminal.UNKNOWN``, the error response captured as
        an ERROR diagnostic), keep the side context complete, and return
        True so the attempt continues -- comparison then sees a
        non-comparable side, never a match.

        Row 3 (over-budget cancel): record the side as CANCELLED with the
        partial result set explicitly marked truncated, then return False so
        the attempt-level failure still unwinds with the frozen
        ``RESULT_BUDGET_EXCEEDED`` code.

        Row 4 (disconnect/timeout: required after/session facts cannot be
        collected): return False without recording a side; the side stays
        null in the evidence and the raised failure names QUERY/FETCH and
        the real cause.  The row-2/3 precondition is verified by re-probing
        the same connection, never assumed; if the probe fails, row 4
        applies.  ``environment_before`` is never copied to ``after``.
        """
        budget_cancelled = abort.code == _RESULT_BUDGET_EXCEEDED
        if not budget_cancelled and (abort.code != _sql_error_code() or abort.need_kill):
            return False
        side_key = "a" if side is Side.A else "b"
        duration_ms = int((self._clock() - started_s) * 1000)

        # StageObservation keeps every partially observed fact either way.
        state.recorder.record_sql(
            side=side,
            stage=StageObservationKind.SELECT,
            slug="select-budget" if budget_cancelled else "select-error",
            sql=select_statement.text,
            connection_id=connection_id,
            session_id=connection_id,
            actual_database=database,
            detail=str(abort),
        )
        # Row 2/3 precondition, verified: the same connection must still
        # answer the after snapshot.  A failure here is row 4 -- the probe's
        # own mapped failure (QUERY/FETCH + real cause) replaces the absorb.
        try:
            facts = dict(adapter.fetch_environment_facts())
            environment_after = observed_environment_from_facts(
                facts, build_id=request.target_environment.build_id
            )
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, _AttemptAbort):
                raise
            raise _map_exception(exc, AttemptStage.FETCH, side=side) from exc
        if (
            environment_after.instance_identity
            != state.observed_environment.instance_identity
            or environment_content_hash(environment_after)
            != environment_content_hash(request.target_environment)
        ):
            raise _AttemptAbort(
                code=str(ComparisonReason.ENVIRONMENT_DRIFT.value),
                stage=AttemptStage.FETCH,
                side=side,
                message=(
                    f"side {side.value} post-failure environment drifted from the "
                    "target snapshot"
                ),
            )

        if budget_cancelled:
            status = QueryStatus.CANCELLED
            # The partial result set stays visible, explicitly truncated.
            try:
                result = self._result_set(fetch, relation, side) if fetch is not None else None
            except Exception:  # noqa: BLE001 - an unbuildable partial stays null
                result = None
            if fetch is not None:
                diagnostics = self._select_diagnostics(
                    request, state, adapter, side=side, sql=select_statement.text,
                    warning_count=fetch.warning_count, connection_id=connection_id,
                )
            else:
                diagnostics = self._uncollected_diagnostics(side, select_statement.text)
        else:
            status = QueryStatus.SQL_ERROR
            result = None  # the error response is the observed outcome
            diagnostics = self._error_diagnostics(state, side, select_statement.text, abort)
        self._journal.append(
            OwnershipEventKind.QUERY_FINISHED,
            attempt_id=request.attempt_id,
            server_uuid=state.server_uuid,
            connection_id=connection_id,
        )
        state.queries[side_key] = QueryEvidence(
            side=side,
            binding=expectation.binding,
            select_text=select_statement.text,
            select_sql_hash=select_statement.sql_hash,
            protocol="text",
            parameters=(),
            status=status,
            result=result,
            session_start_id=connection_id,
            session_end_id=connection_id,
            actual_database=database,
            environment_before=environment_before,
            environment_after=environment_after,
            diagnostics=diagnostics,
            duration_ms=duration_ms,
            result_terminal=ResultTerminal.UNKNOWN,
        )
        state.contexts[side_key] = SideContext(
            side=side,
            setup_connection_id=connection_id,
            readback_connection_id=connection_id,
            select_connection_id=connection_id,
            current_database=database,
            name_map=state.name_map,
            autocommit=request.session_profile.autocommit,
            transaction_isolation=request.session_profile.transaction_isolation,
            environment_before=environment_before,
            environment_after=environment_after,
        )
        return not budget_cancelled

    def _uncollected_diagnostics(self, side: Side, sql: str) -> StatementDiagnostics:
        return StatementDiagnostics(
            side=side,
            phase=SelectPhase.SELECT,
            ordinal=0,
            sql_hash=sha256_hex(sql.encode("utf-8")),
            collected=False,
            complete=False,
            entries=(),
        )

    def _error_diagnostics(
        self,
        state: _AttemptState,
        side: Side,
        sql: str,
        abort: _AttemptAbort,
    ) -> StatementDiagnostics:
        """Capture the SELECT error response as one ERROR diagnostic.

        The message text is the adapter's error surface (the original cause
        when mapped from one); it rides as a recorded payload reference,
        never inline.  A collected diagnostic with an entry is never
        "complete", so gate 4 can never read this side as clean.
        """
        cause = abort.__cause__
        code_text = ""
        if cause is not None:
            errno = getattr(cause, "errno", None)
            if isinstance(errno, int) and not isinstance(errno, bool):
                code_text = str(errno)
            else:
                adapter_code = getattr(cause, "code", None)
                if isinstance(adapter_code, str) and adapter_code:
                    code_text = adapter_code
        if not code_text:
            code_text = "UNKNOWN"
        message_ref = state.recorder.add_payload(
            state.recorder.ref(side, "select-error", 0, ".diagnostics-0.txt"),
            (str(cause) if cause is not None else str(abort)).encode("utf-8"),
        )
        return StatementDiagnostics(
            side=side,
            phase=SelectPhase.SELECT,
            ordinal=0,
            sql_hash=sha256_hex(sql.encode("utf-8")),
            collected=True,
            complete=False,
            entries=(
                DiagnosticEntry(
                    level=DiagnosticLevel.ERROR,
                    code=code_text,
                    sqlstate=None,
                    message_ref=message_ref,
                ),
            ),
        )

    def _check_fetch(
        self, fetch: Any, relation: ResultRelationSpec, side: Side
    ) -> None:
        if fetch.truncated:
            # The per-attempt result budget bounded the result: the design
            # 6.2.4 over-budget cancel row (QueryStatus CANCELLED with the
            # partial result kept visible; never a fabricated SQL_ERROR).
            raise _AttemptAbort(
                code=_RESULT_BUDGET_EXCEEDED,
                stage=AttemptStage.FETCH,
                side=side,
                message="result fetch hit the row/byte budget and was truncated",
            )
        if not fetch.fetch_complete:
            raise _AttemptAbort(
                code=RESULT_CONTRACT_VIOLATION,
                stage=AttemptStage.FETCH,
                side=side,
                message="fetch neither completed nor reported truncation",
            )
        if fetch.extra_result_sets:
            raise _AttemptAbort(
                code=RESULT_CONTRACT_VIOLATION,
                stage=AttemptStage.FETCH,
                side=side,
                message=f"unexpected {fetch.extra_result_sets} extra result set(s)",
            )
        if len(fetch.columns) != len(relation.columns):
            raise _AttemptAbort(
                code=RESULT_CONTRACT_VIOLATION,
                stage=AttemptStage.FETCH,
                side=side,
                message=(
                    f"result has {len(fetch.columns)} columns, the declared relation "
                    f"has {len(relation.columns)}"
                ),
            )
        if fetch.observed_row_count != len(fetch.values):
            raise _AttemptAbort(
                code=RESULT_CONTRACT_VIOLATION,
                stage=AttemptStage.FETCH,
                side=side,
                message="fetch row count disagrees with the returned rows",
            )
        if fetch.observed_row_count > MAX_RESULT_ROWS:
            raise _AttemptAbort(
                code=RESULT_CONTRACT_VIOLATION,
                stage=AttemptStage.FETCH,
                side=side,
                message="result exceeds the frozen MAX_RESULT_ROWS cap",
            )
        for row in fetch.values:
            if len(row) != len(relation.columns) or not all(
                isinstance(value, ResultValue) for value in row
            ):
                raise _AttemptAbort(
                    code=RESULT_CONTRACT_VIOLATION,
                    stage=AttemptStage.FETCH,
                    side=side,
                    message="fetched row is not a tuple of declared-width ResultValues",
                )

    def _select_diagnostics(
        self,
        request: AttemptRequest,
        state: _AttemptState,
        adapter: AdapterLike,
        *,
        side: Side,
        sql: str,
        warning_count: Optional[int],
        connection_id: str,
    ) -> StatementDiagnostics:
        sql_hash = sha256_hex(sql.encode("utf-8"))
        if warning_count is None:
            # The authoritative terminator count was not observable; the
            # diagnostics are honestly incomplete.
            return StatementDiagnostics(
                side=side,
                phase=SelectPhase.SELECT,
                ordinal=0,
                sql_hash=sql_hash,
                collected=False,
                complete=False,
                entries=(),
            )
        if warning_count == 0:
            return StatementDiagnostics(
                side=side,
                phase=SelectPhase.SELECT,
                ordinal=0,
                sql_hash=sql_hash,
                collected=True,
                complete=True,
                entries=(),
            )
        # SHOW WARNINGS on the same connection, before any other statement.
        state.recorder.record_sql(
            side=side,
            stage=StageObservationKind.SELECT,
            slug="select-diagnostics",
            sql=_SHOW_WARNINGS_SQL,
            connection_id=connection_id,
            session_id=connection_id,
            detail=f"terminator warning_count={warning_count}",
        )
        try:
            raw = adapter.execute_raw_query(
                _SHOW_WARNINGS_SQL,
                row_budget=_PROBE_ROW_BUDGET,
                byte_budget=_PROBE_BYTE_BUDGET,
            )
        except Exception as exc:  # noqa: BLE001
            raise _map_exception(exc, AttemptStage.FETCH, side=side) from exc
        entries = []
        complete = (
            not raw.truncated
            and raw.fetch_complete
            and raw.observed_row_count == warning_count
        )
        for index, row in enumerate(raw.rows):
            if len(row) != 3:
                raise _AttemptAbort(
                    code=RESULT_CONTRACT_VIOLATION,
                    stage=AttemptStage.FETCH,
                    side=side,
                    message=f"SHOW WARNINGS row {index} does not have 3 columns",
                )
            level_text = _decode_probe_cell(row[0], f"SHOW WARNINGS row {index} level")
            code_text = _decode_probe_cell(row[1], f"SHOW WARNINGS row {index} code")
            message_text = _decode_probe_cell(
                row[2], f"SHOW WARNINGS row {index} message"
            )
            level = _diagnostic_level(level_text or "")
            if level is None:
                raise FactCollectionError(
                    f"SHOW WARNINGS level {level_text!r} is outside the frozen "
                    "vocabulary (fail closed)"
                )
            message_ref = state.recorder.add_payload(
                state.recorder.ref(side, "select-diagnostics", 0,
                                   f".diagnostics-{index}.txt"),
                (message_text or "").encode("utf-8"),
            )
            entries.append(
                DiagnosticEntry(
                    level=level,
                    code=code_text or "",
                    sqlstate=None,  # SHOW WARNINGS carries no SQLSTATE
                    message_ref=message_ref,
                )
            )
        # complete=True is only comparable with no entries (model rule), so a
        # SELECT that produced warnings is recorded but never "clean".
        return StatementDiagnostics(
            side=side,
            phase=SelectPhase.SELECT,
            ordinal=0,
            sql_hash=sql_hash,
            collected=True,
            complete=complete and not entries,
            entries=tuple(entries),
        )

    def _result_set(
        self, fetch: Any, relation: ResultRelationSpec, side: Side
    ) -> ResultSet:
        def family_of(spec: ResultColumnSpec) -> TypeFamily:
            return spec.a_family if side is Side.A else spec.b_family

        columns = tuple(
            ResultColumn(
                ordinal=ordinal,
                alias=relation.columns[ordinal].alias,
                family=family_of(relation.columns[ordinal]),
                type_code=mapped.type_code,
                flags=mapped.flags,
                precision=mapped.precision,
                scale=mapped.scale,
                mapping_version=mapped.mapping_version,
            )
            for ordinal, mapped in enumerate(fetch.columns)
        )
        return ResultSet(
            columns=columns,
            rows=tuple(tuple(row) for row in fetch.values),
            observed_row_count=fetch.observed_row_count,
            fetch_complete=fetch.fetch_complete,
            truncated=fetch.truncated,
            extra_result_sets=fetch.extra_result_sets,
            encoding_version=CODEC_VERSION,
        )

    # -- budget checkpoints ---------------------------------------------------

    def _check_deadline(self, control: Control, stage: AttemptStage) -> None:
        if control.expired():
            # The attempt *time* budget (no result was being fetched): the
            # frozen StopReason vocabulary names this honestly.
            raise _AttemptAbort(
                code=_TIME_BUDGET,
                stage=stage,
                message="attempt time budget expired before the stage started",
                need_kill=True,
            )

    def _check_budget(
        self,
        request: AttemptRequest,
        control: Control,
        side: Side,
        *,
        stage: AttemptStage = AttemptStage.SETUP,
    ) -> None:
        try:
            control.raise_if_cancelled()
        except ControlCancelled as exc:
            # Keep the caller's stage: a cancellation detected at a checkpoint
            # belongs to that stage, not to the coarse dispatch stage.
            raise _AttemptAbort(
                code=str(QueryStatus.CANCELLED.value),
                stage=stage,
                side=side,
                message="control cancelled the attempt",
                need_kill=True,
            ) from exc
        if control.expired():
            # Inside the QUERY/FETCH region this is the design 6.2.4
            # over-budget cancel row (frozen RESULT_BUDGET_EXCEEDED); outside
            # it, the attempt time budget expired with no result involved.
            code = (
                _RESULT_BUDGET_EXCEEDED
                if stage in (AttemptStage.QUERY, AttemptStage.FETCH)
                else _TIME_BUDGET
            )
            raise _AttemptAbort(
                code=code,
                stage=stage,
                side=side,
                message=(
                    f"attempt budget expired during side {side.value} "
                    f"{str(stage.value.lower())}"
                ),
                need_kill=True,
            )

    # -- cancel_and_wait ------------------------------------------------------

    def cancel_and_wait(self, attempt_id: str, grace_seconds: float) -> TerminalReceipt:
        if not isinstance(attempt_id, str) or not attempt_id:
            raise ExecutionPortError("cancel_and_wait needs a non-empty attempt id")
        if isinstance(grace_seconds, bool) or not isinstance(grace_seconds, (int, float)):
            raise ContractError("cancel_and_wait grace_seconds must be a number")
        if grace_seconds <= 0:
            raise ContractError("cancel_and_wait grace_seconds must be > 0")
        state = self._attempts.get(attempt_id)
        if state is None:
            # No attempt state: no evidence can exist for it either.
            raise ExecutionPortError(
                f"unknown attempt {attempt_id!r}",
                failure=AttemptFailure(
                    stage=AttemptStage.CANCEL,
                    code=ATTEMPT_NOT_FOUND,
                    side=None,
                    diagnostics_ref=None,
                ),
            )
        if state.state in TERMINAL_STATES:
            if state.terminal is not None:
                return state.terminal  # idempotent
            raise ExecutionPortError(
                f"attempt {attempt_id!r} is terminal without a stored receipt",
                failure=AttemptFailure(
                    stage=AttemptStage.CANCEL,
                    code=str(StopReason.EXECUTION_PROTOCOL_ERROR.value),
                    side=None,
                    diagnostics_ref=None,
                ),
            )
        # Synchronous adapters answer the KILL immediately; the grace bound
        # is honoured by construction here and by the control plane in Phase 5.
        del grace_seconds
        terminal = self._terminate_and_clean(state, need_kill=True)
        if terminal.termination is TerminationState.UNKNOWN:
            failure = AttemptFailure(
                stage=AttemptStage.CANCEL,
                code=str(TerminationState.UNKNOWN.value),
                side=None,
                diagnostics_ref=None,
            )
            state.failure = failure
            raise ExecutionPortError(
                f"cancellation of attempt {attempt_id!r} is unconfirmed; the attempt "
                "is quarantined and its objects preserved",
                failure=failure,
                evidence=state.evidence,
                terminal=terminal,
            )
        return terminal


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def _side_statements(rendered, side: Side):
    return rendered.a if side is Side.A else rendered.b


def _side_select(rendered, side: Side):
    statements = _side_statements(rendered, side)
    if not statements or str(statements[-1].phase.value) != "select":
        raise ContractError("rendered pair does not end with a SELECT statement")
    return statements[-1]


def _sql_error_code() -> str:
    return str(QueryStatus.SQL_ERROR.value)


def _decode_probe_cell(cell: object, what: str) -> Optional[str]:
    if cell is None:
        return None
    if isinstance(cell, (bytes, bytearray)):
        try:
            return bytes(cell).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FactCollectionError(f"{what} is not valid UTF-8 (fail closed)") from exc
    if isinstance(cell, str):
        return cell
    raise FactCollectionError(
        f"{what} arrived as {type(cell).__name__}, expected raw text (fail closed)"
    )


def _map_exception(exc: Exception, stage: AttemptStage, side: Optional[Side] = None) -> _AttemptAbort:
    """Frozen failure mapping for setup/readback/query/fetch exceptions."""
    if isinstance(exc, _AttemptAbort):
        return exc
    if isinstance(exc, ControlCancelled):
        return _AttemptAbort(
            code=str(QueryStatus.CANCELLED.value),
            stage=stage,
            side=side,
            message="control cancelled the attempt",
            need_kill=True,
        )
    if isinstance(exc, ResultEncodingError):
        return _AttemptAbort(
            code=RESULT_ENCODING_UNSUPPORTED,
            stage=stage,
            side=side,
            message=str(exc),
        )
    if isinstance(exc, ResultContractViolation):
        return _AttemptAbort(
            code=RESULT_CONTRACT_VIOLATION,
            stage=stage,
            side=side,
            message=str(exc),
        )
    if isinstance(exc, ProtocolBudgetError):
        return _AttemptAbort(
            code=PROTOCOL_BUDGET_EXCEEDED,
            stage=stage,
            side=side,
            message=str(exc),
        )
    if isinstance(exc, TimeoutError):
        return _AttemptAbort(
            code=str(QueryStatus.TIMEOUT.value),
            stage=stage,
            side=side,
            message=str(exc),
        )
    if isinstance(exc, AdapterError) and exc.code == _CONNECTION_LOST:
        return _AttemptAbort(
            code=str(QueryStatus.CONNECTION_LOST.value),
            stage=stage,
            side=side,
            message=str(exc),
        )
    if isinstance(exc, (FactCollectionError, ContractError)):
        return _AttemptAbort(
            code=str(ComparisonReason.RUNTIME_NOT_READY.value),
            stage=stage,
            side=side,
            message=str(exc),
        )
    # Driver and other unexpected errors: an honest SQL_ERROR bucket; the
    # Phase 5 binding refines the wrapping, never the honesty.
    return _AttemptAbort(
        code=_sql_error_code(),
        stage=stage,
        side=side,
        message=f"{type(exc).__name__}: {exc}",
    )


def _map_session_exception(exc: Exception, side: Side) -> _AttemptAbort:
    """Session application fails the attempt before side B starts."""
    if isinstance(exc, _AttemptAbort):
        return exc
    if isinstance(exc, ControlCancelled):
        return _map_exception(exc, AttemptStage.QUERY, side=side)
    if isinstance(exc, AdapterError) and exc.code == SESSION_MISMATCH:
        return _AttemptAbort(
            code=SESSION_MISMATCH,
            stage=AttemptStage.QUERY,
            side=side,
            message=str(exc),
        )
    if isinstance(exc, AdapterError) and exc.code == SESSION_APPLY_FAILED:
        return _AttemptAbort(
            code=SESSION_APPLY_FAILED,
            stage=AttemptStage.QUERY,
            side=side,
            message=str(exc),
        )
    return _map_exception(exc, AttemptStage.QUERY, side=side)


def _clean_without_adapter(state: _AttemptState, journal: OwnershipSink) -> CleanupOutcome:
    """AttemptCleaner run without a live connection: every presence probe
    would fail, so nothing is dropped and the outcome reports the failure."""
    del journal
    return CleanupOutcome(
        completed=False,
        failures=tuple(
            CleanupFailure(
                object_name=database,
                action=CleanupAction.VERIFY_ABSENT,
                detail="no live adapter connection for cleanup",
            )
            for database in (state.name_map.database_a, state.name_map.database_b)
        ),
    )


# --------------------------------------------------------------------------
# Design 6.3.2: the single public assembly entry
# --------------------------------------------------------------------------


class _InMemoryRunJournal:
    """In-process ``OwnershipSink`` for ports without a persisted journal.

    Used when a port is assembled without ``journal``/``journal_path`` (a
    worker that was not told where the run's ownership journal lives).
    Surfaced seam: events recorded here stay inside the worker process -- the
    parent's run journal remains the single-writer record; worker-side events
    are NOT folded into it (documented design conflict, not silently merged).
    """

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.events: List[OwnershipEvent] = []
        self._next_seq = 1
        self._prev_hash = OWNERSHIP_GENESIS_HASH

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


class _LazyControlConnection:
    """Independent control connection for KILL QUERY, connected on first use.

    Satisfies the adapter's narrow ``_ControlStatementExecutor`` surface
    (``execute_statement`` returning the raw statement receipt); the wrapped
    adapter is the certified ``MySQL80Adapter`` built over the control
    connection parameters.  Building and connecting lazily keeps a port that
    never cancels free of a second connection.
    """

    def __init__(self, build: Callable[[], Any]) -> None:
        self._build = build
        self._adapter: Optional[Any] = None

    def execute_statement(self, sql: str) -> Any:
        if self._adapter is None:
            adapter = self._build()
            adapter.connect_and_probe()
            self._adapter = adapter
        return self._adapter.execute_statement(sql).receipt


def build_execution_port(
    *,
    params: ConnectionParams,
    control_params: Optional[ConnectionParams] = None,
    journal: Optional[OwnershipSink] = None,
    journal_path: Union[str, Path, None] = None,
    run_id: Optional[str] = None,
    token_source: Optional[naming.TokenSource] = None,
    clock: Optional[Callable[[], float]] = None,
    quarantine: Optional[QuarantineLatch] = None,
    charset: str = "utf8mb4",
) -> MySQLExecutionPort:
    """Assemble the production :class:`MySQLExecutionPort` (design 6.3.2).

    Binds the certified ``MySQL80Adapter`` (imported lazily: the PyMySQL
    chain must not load at runner import time) over ``params`` for the test
    connections and over ``control_params`` (default: the same parameters,
    one independent connection) for the KILL QUERY control plane.

    Exactly one ownership-journal source:

    - ``journal`` -- an injected ``OwnershipSink`` (tests, or a worker that
      already opened the run journal);
    - ``journal_path`` + ``run_id`` -- open/continue the frozen
      ``OwnershipJournal`` at that path;
    - neither -- an in-process :class:`_InMemoryRunJournal` (worker-side
      events stay in the worker; the parent's run journal stays
      single-writer).

    ``token_source``/``clock``/``quarantine`` are the port's injectables.
    This function opens no connection itself; connections happen when the
    port (or a cancellation) first needs them.
    """

    if journal is not None and journal_path is not None:
        raise ContractError(
            "build_execution_port needs exactly one of journal / journal_path"
        )
    if journal_path is not None:
        if not isinstance(run_id, str) or not run_id:
            raise ContractError(
                "build_execution_port journal_path requires the owning run_id"
            )
        journal = OwnershipJournal(Path(journal_path), run_id=run_id)
    if journal is None:
        journal = _InMemoryRunJournal(run_id if isinstance(run_id, str) and run_id else "run-unassigned")
    if not isinstance(params, ConnectionParams):
        raise ContractError("build_execution_port needs ConnectionParams for the test connections")
    if control_params is not None and not isinstance(control_params, ConnectionParams):
        raise ContractError(
            "build_execution_port control_params must be ConnectionParams when given"
        )

    # Lazy import: keeps this module (and everything importing it) free of the
    # PyMySQL chain at import time (design I01).  Only reached on real assembly.
    from ..adapters.mysql80 import MySQL80Adapter

    control = _LazyControlConnection(
        lambda: MySQL80Adapter(
            control_params if control_params is not None else params,
            charset=charset,
            clock=clock,
        )
    )

    def adapter_factory() -> AdapterLike:
        return MySQL80Adapter(params, charset=charset, clock=clock, control=control)

    return MySQLExecutionPort(
        adapter_factory=adapter_factory,
        journal=journal,
        quarantine=quarantine,
        token_source=token_source,
        clock=clock,
    )
