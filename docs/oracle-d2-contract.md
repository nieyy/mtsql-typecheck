# D2 Oracle / Reduction Contract (oracle-d2-contract)

Status: frozen implementation baseline for D2 v1.0 (design
`2026-09-05-mtsql-typecheck-result-oracle-counterexample-reduction-design-zh.md`,
sections 6.2/6.3/6.4/6.5). This document fixes the field names, schema
versions, enumerations, budgets and function signatures that
`contracts/execution.py`, `contracts/oracle.py`, `oracle/*` and
`reduction/*` must implement. Where this file and prose differ, this file
wins; changing anything here requires a design revision, not a code default.

All models follow D1 house rules (`contracts/case.py`, `contracts/codec.py`):
frozen dataclasses, closed enums, tuples (never lists) in memory, strict
`__post_init__` validation on **both** the construction and the loader path,
unknown fields rejected, `bool` never accepted as `int`, no floats, no free
SQL text, optional fields only for genuinely absent facts (never a default
success). Canonical bytes come from `codec.canonical_json` /
`codec.sha256_hex`. Importing any D2 module performs no I/O.

## 1. Frozen versions and constants

```python
# contracts/execution.py
EXECUTION_SCHEMA_VERSION = 1          # AttemptRequest/AttemptExpectation/ExecutionEvidence
# contracts/oracle.py
ORACLE_VERSION = "o1"
COMPARISON_SCHEMA_VERSION = 1
REPLAY_SCHEMA_VERSION = 1
REDUCTION_SCHEMA_VERSION = 1
TRACE_SCHEMA_VERSION = 1

# Budget constants (design 6.4.5); these are the v1.0 hard limits.
MAX_RESULT_ROWS = 4096                # per side
MAX_RESULT_BYTES = 8 * 1024 * 1024    # per side, canonical UTF-8 ResultSet incl. metadata
MAX_RESULT_COLUMNS = 5
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024 # single ExecutionEvidence envelope
MAX_TRACE_META_BYTES = 64 * 1024      # single trace record payload metadata
COMPARISON_DEADLINE_MS = 5000
REPLAY_ATTEMPTS = 3                   # fixed, not configurable
REPLAY_TOTAL_BUDGET_MS = 120_000
REDUCTION_MAX_PROPOSALS = 200         # hard cap 2000
REDUCTION_MAX_EXECUTIONS = 120        # hard cap 1200
REDUCTION_TOTAL_BUDGET_MS = 600_000   # hard cap 3_600_000
REDUCTION_HARD_MAX_PROPOSALS = 2000
REDUCTION_HARD_MAX_EXECUTIONS = 1200
REDUCTION_HARD_TOTAL_BUDGET_MS = 3_600_000
ATTEMPT_BUDGET_MS = 30_000
CANCEL_GRACE_MS = 5000
EVIDENCE_APPEND_BUDGET = 256 * 1024 * 1024          # default
EVIDENCE_APPEND_HARD_CAP = 1024 * 1024 * 1024
EVIDENCE_RESERVE_BYTES = 64 * 1024                  # kept free for termination records
WITNESS_LIMIT = 20                    # display cap only
MAX_SCALAR_TEXT_CHARS = 80            # reuse case.MAX_NUMERIC_TEXT_CHARS
MAX_RESULT_SCALE = 65
```

`ExecutionEvidence` and every trace/JSONL input is size-checked on raw bytes
**before** parsing; a single ExecutionEvidence over `MAX_EVIDENCE_BYTES` is
rejected before decode. JSON depth follows D1 (`MAX_JSON_DEPTH = 32`).

## 2. contracts/execution.py — execution evidence models

Module-private helpers mirror `codec.py` (`_check_int`, `_check_hex64`,
`_check_enum`, ...). Every model has `to_obj()` and every top-level document
has a strict `decode_*` loader in the same module (using
`codec.parse_strict_json` at the byte entry points `load_*`). Content hashes
always exclude the record's own hash field.

### 2.1 Enumerations

```python
class ExecutionOrder(enum.StrEnum):  AB = "AB"; BA = "BA"
class Side(enum.StrEnum):            A = "A"; B = "B"
class QueryStatus(enum.StrEnum):     COMPLETE / SQL_ERROR / TIMEOUT / CONNECTION_LOST / CANCELLED
class ResultTerminal(enum.StrEnum):  CONFIRMED / UNKNOWN
class AttemptStage(enum.StrEnum):    PREPARE / SETUP / QUERY / FETCH / CANCEL / CLEANUP
class TerminationState(enum.StrEnum):NOT_STARTED / CONFIRMED / UNKNOWN
class CleanupState(enum.StrEnum):    DONE / PENDING / FAILED
class DiagnosticLevel(enum.StrEnum): WARNING / NOTE / ERROR
class TransactionIsolation(enum.StrEnum):
    READ_UNCOMMITTED = "READ-UNCOMMITTED"; READ_COMMITTED = "READ-COMMITTED"
    REPEATABLE_READ = "REPEATABLE-READ";   SERIALIZABLE = "SERIALIZABLE"
class ResultValueKind(enum.StrEnum): NULL = "null"; INTEGER = "integer"; DECIMAL = "decimal"
```

### 2.2 Result values and result sets

```python
@dataclass(frozen=True)
class ResultValue:                    # independent loader, NOT D1 ExactValue reuse
    # kind: ResultValueKind; int_value: Optional[int] (integer kind);
    # coefficient: Optional[int]; scale: Optional[int] (decimal kind).
    # Canonical decimal text rules as D1: <= 80 chars, scale 0..65, canonical
    # form, no float/exponent/non-canonical negative zero/string/unknown kind.
    kind: ResultValueKind
    int_value: Optional[int] = None
    coefficient: Optional[int] = None
    scale: Optional[int] = None
    # null -> {"kind":"null"}; integer -> {"kind":"integer","value":"<text>"};
    # decimal -> {"kind":"decimal","coefficient":"<text>","scale":n}

@dataclass(frozen=True)
class ResultColumn:
    ordinal: int          # 0-based, consecutive
    alias: str            # matches the declared relation alias
    family: TypeFamily    # imported from contracts.case; never guessed from values
    type_code: int        # raw protocol type code
    flags: int            # raw protocol flags
    precision: Optional[int]   # collected when available
    scale: Optional[int]       # collected when available
    mapping_version: str  # driver/adapter mapping version, non-empty

@dataclass(frozen=True)
class ResultSet:
    columns: tuple[ResultColumn, ...]        # 1..MAX_RESULT_COLUMNS
    rows: tuple[tuple[ResultValue, ...], ...]
    observed_row_count: int                  # == len(rows)
    fetch_complete: bool
    truncated: bool
    extra_result_sets: int                   # must be 0 for comparable results
    payload_hash: str                        # sha256 over canonical_json(self.result_obj())
    encoding_version: str                    # non-empty
```

`ResultSet` post-init invariants: every row has exactly `len(columns)`
values; `observed_row_count == len(rows)`; `payload_hash` recomputed and
matched; a missing result must be modeled as `result=None` on QueryEvidence,
never as empty rows. Per-column non-NULL value kind must equal the observed
column family (checked by the oracle gates, not the model).

### 2.3 Session / context / receipts

```python
@dataclass(frozen=True)
class SessionProfile:                 # schema=1
    autocommit: bool
    transaction_isolation: TransactionIsolation

@dataclass(frozen=True)
class DiagnosticEntry:
    level: DiagnosticLevel
    code: str                         # stable code, non-empty, <= 128 chars
    sqlstate: Optional[str]           # <= 16 chars when present
    message_ref: Optional[str]        # controlled reference, never raw text dump

@dataclass(frozen=True)
class StatementDiagnostics:
    side: Side
    phase: StatementPhase             # D1 ddl/insert enum; SELECT uses its own receipt below
    ordinal: int                      # >= 0
    sql_hash: str                     # hex64
    collected: bool                   # False => entries must be empty ("not collected" != empty)
    complete: bool
    entries: tuple[DiagnosticEntry, ...]
    # Invariant: not collected => not complete. complete=True is only
    # comparable when entries == ().

@dataclass(frozen=True)
class SideContext:
    side: Side
    setup_connection_id: str
    readback_connection_id: str
    select_connection_id: str         # all three non-empty and equal: one session identity
    current_database: str             # == name_map.database_a / database_b for that side
    name_map: NameMap                 # D1 NameMap
    autocommit: bool
    transaction_isolation: TransactionIsolation
    environment_before: ObservedEnvironment   # D1 model, canonical content
    environment_after: ObservedEnvironment
    # invariant: environment_before/after content must both hash to the fixed
    # target environment hash of the request (checked by gates)

@dataclass(frozen=True)
class IsolationReceipt:
    attempt_id: str
    name_map_hash: str                # hex64, == name_map_content_hash of the expectation NameMap
    ownership_ref: str                # reference to run-owned object records, non-empty
    objects_created_confirmed: bool
    load_committed: bool
    no_concurrent_write_confirmed: bool
    method_version: str               # non-empty, D3-owned collection method version

@dataclass(frozen=True)
class TerminalReceipt:
    attempt_id: str
    termination: TerminationState
    cleanup: CleanupState
    owned_objects: tuple[str, ...]    # run-owned object references still held
    # NOT_STARTED + DONE is legal only when owned_objects == () and nothing started.

@dataclass(frozen=True)
class AttemptFailure:
    stage: AttemptStage
    code: str                         # stable code, not message text
    side: Optional[Side]
    diagnostics_ref: Optional[str]    # controlled reference into collected diagnostics

@dataclass(frozen=True)
class PreflightRejection:
    request_hash: str                 # hex64
    observed_environment: ObservedEnvironment
    rejected_requirement_id: str      # matches a case environment requirement id
    capability_check_version: str     # non-empty
```

### 2.4 AttemptRequest / AttemptExpectation / ExecutionEvidence

```python
@dataclass(frozen=True)
class AttemptRequest:                 # schema=1, caller-generated identity
    run_id: str                       # non-empty <= 128 chars
    attempt_id: str                   # non-empty <= 128 chars, unique per dispatch
    payload: CasePayload              # D1 model; case_id recomputed, never carried
    target_environment: ObservedEnvironment  # fixed target content
    session_profile: SessionProfile
    execution_order: ExecutionOrder   # logical dispatch order for the attempt
    result_row_budget: int            # 1..MAX_RESULT_ROWS
    result_byte_budget: int           # 1..MAX_RESULT_BYTES
    time_budget_ms: int               # 1..ATTEMPT_BUDGET_MS
    synthetic: bool
    # case_id property: recomputed via case_id_of(payload); constructor has no
    # case_id field at all. request_hash = sha256_hex(canonical_json(to_obj())).

@dataclass(frozen=True)
class AttemptExpectation:             # returned by ExecutionPort.prepare, sealed before execute
    binding: ExpectedBinding          # D1 ExpectedBinding (run/case/attempt/env/name_map hashes)
    request_hash: str                 # hex64, must equal hash of the paired request
    codec_version: str                # protocol/driver encoding version, non-empty
    execution_order: ExecutionOrder   # == request.execution_order
    name_map: NameMap                 # actual objects allocated by prepare()

@dataclass(frozen=True)
class QueryEvidence:
    side: Side
    binding: ExpectedBinding          # matches the expectation binding
    select_text: str                  # exact SELECT text from render_pair
    select_sql_hash: str              # hex64 over select_text
    protocol: str                     # fixed "text"
    parameters: tuple[()]             # fixed empty
    status: QueryStatus
    result: Optional[ResultSet]       # None when not fetched; never empty-rows stand-in
    session_start_id: str             # non-empty when side started
    session_end_id: str               # non-empty; must equal start (no mid-fetch reconnect)
    actual_database: str              # == context.current_database
    environment_before: ObservedEnvironment
    environment_after: ObservedEnvironment
    diagnostics: StatementDiagnostics # phase carried as SELECT in to_obj ("select")
    duration_ms: int                  # >= 0
    result_terminal: ResultTerminal   # CONFIRMED requires fetch_complete evidence
```

```python
@dataclass(frozen=True)
class ExecutionEvidence:              # schema=1
    request_hash: str                          # hex64
    expectation: Optional[AttemptExpectation]  # None only after PREPARE failure
    runtime_facts: Optional[RuntimeFacts]      # D1 facts schema 1, untouched
    setup_diagnostics: tuple[StatementDiagnostics, ...]
      # must exactly cover render_pair DDL/INSERT receipts per side, aligned by
      # (side, phase, ordinal, sql_hash); comparable only when complete=True and entries=()
    actual_execution_order: Optional[ExecutionOrder]
    a_context: Optional[SideContext]
    b_context: Optional[SideContext]
    a_query: Optional[QueryEvidence]
    b_query: Optional[QueryEvidence]
    isolation_receipt: Optional[IsolationReceipt]
    terminal: Optional[TerminalReceipt]
    failure: Optional[AttemptFailure]
    preflight_rejection: Optional[PreflightRejection]
    synthetic: bool
    evidence_hash: str               # content hash, excludes itself
```

ExecutionEvidence invariants (constructor + loader):
- `evidence_hash = sha256_hex(canonical_json(to_obj()))` where `to_obj()`
  excludes the `evidence_hash` field itself.
- At most one of `preflight_rejection` / any post-PREPARE content: a
  preflight rejection means no expectation, no facts, no queries, no
  isolation/terminal beyond NOT_STARTED semantics.
- `failure is not None` with `stage=PREPARE` allows
  expectation/runtime_facts/a_query/b_query to be None; a side that never
  started has `None` for its context+query (a missing side is an absence,
  not a success).
- `evidence_hash` always present; unknown/missing schema rejected.
- Contradictory success is rejected: e.g. a `QueryEvidence` with
  `status=COMPLETE` but `result=None`, or `fetch_complete=True` with
  `truncated=True`.

### 2.5 ExecutionPort, Control, errors (frozen protocols)

```python
@dataclass(frozen=True)
class Control:
    clock: Callable[[], float]        # injectable, monotonic seconds
    deadline: Optional[float]         # absolute monotonic time of this process
    cancelled: Callable[[], bool]     # cooperative cancellation token
    # methods: remaining_ms() -> int; expired() -> bool; raise_if_cancelled()
    #   (raises ControlCancelled, a ContractError subclass);
    # child(deadline_s: Optional[float]) -> Control (min of deadlines, same clock/token)

class ControlCancelled(ContractError): ...

class ExecutionPortError(ContractError):
    failure: Optional[AttemptFailure]
    evidence: Optional[ExecutionEvidence]   # partial evidence gathered so far
    terminal: Optional[TerminalReceipt]
    # carried for prepare refusals / execution-stage failures; contains no
    # executable callbacks and never retries internally.

class ExecutionPort(Protocol):
    def prepare(self, request: AttemptRequest, control: Control) -> AttemptExpectation: ...
    def execute(self, request: AttemptRequest, expectation: AttemptExpectation,
                control: Control) -> ExecutionEvidence: ...
    def cancel_and_wait(self, attempt_id: str, grace_seconds: float) -> TerminalReceipt: ...
```

`prepare` must refuse/return before any test SQL runs; `execute` never
internally retries into the same attempt. Synchronous calls must return
inside the deadline or cooperatively terminate via `control`. D2 never
imports a driver; fake executors live only under `tests/`.

Loaders: `load_attempt_request(data)`, `load_attempt_expectation(data)`,
`load_execution_evidence(data)` accept raw JSON (bytes/str via
`parse_strict_json`) or an already-parsed dict; plus `dump_*` returning
canonical bytes. `AttemptRequest.to_obj()` embeds the full payload object.

## 3. contracts/oracle.py — comparison / replay / reduction models

```python
class ComparisonStatus(enum.StrEnum): NOT_APPLICABLE / INCONCLUSIVE / MATCH / MISMATCH_CANDIDATE
class ReplayOutcome(enum.StrEnum):    REPRODUCED / UNSTABLE / NOT_REPLAYED
class ReductionOutcome(enum.StrEnum): REDUCED / UNCHANGED / BUDGET_EXHAUSTED / FAILED
```

### 3.1 Reason codes (comparison; fixed enum, extend only with design revision)

```python
class ComparisonReason(enum.StrEnum):
    INPUT_INVALID = "INPUT_INVALID"
    VERSION_UNSUPPORTED = "VERSION_UNSUPPORTED"
    RULE_DISABLED = "RULE_DISABLED"
    UNSUPPORTED_ENVIRONMENT = "UNSUPPORTED_ENVIRONMENT"
    BINDING_MISMATCH = "BINDING_MISMATCH"
    RUNTIME_NOT_READY = "RUNTIME_NOT_READY"
    SETUP_DIAGNOSTICS = "SETUP_DIAGNOSTICS"
    LOAD_ANOMALY = "LOAD_ANOMALY"
    QUERY_NOT_COMPLETE = "QUERY_NOT_COMPLETE"
    QUERY_DIAGNOSTICS = "QUERY_DIAGNOSTICS"
    ENVIRONMENT_DRIFT = "ENVIRONMENT_DRIFT"
    DATABASE_BINDING_MISMATCH = "DATABASE_BINDING_MISMATCH"
    ISOLATION_UNCONFIRMED = "ISOLATION_UNCONFIRMED"
    RESULT_INCOMPLETE = "RESULT_INCOMPLETE"
    RESULT_CONTRACT_VIOLATION = "RESULT_CONTRACT_VIOLATION"
    RESULT_BUDGET_EXCEEDED = "RESULT_BUDGET_EXCEEDED"
    COMPARISON_DEADLINE = "COMPARISON_DEADLINE"
    CANCELLED = "CANCELLED"
    TERMINATION_UNCONFIRMED = "TERMINATION_UNCONFIRMED"
```

### 3.2 Stop reasons (replay/reduction; fixed enum)

```python
class StopReason(enum.StrEnum):
    INVALID_CANDIDATE = "INVALID_CANDIDATE"
    NO_EXECUTOR = "NO_EXECUTOR"
    ORIGINAL_NOT_REPRODUCED = "ORIGINAL_NOT_REPRODUCED"
    SIGNATURE_CHANGED = "SIGNATURE_CHANGED"
    MATCH_OBSERVED = "MATCH_OBSERVED"
    EXECUTION_INCOMPLETE = "EXECUTION_INCOMPLETE"
    EXECUTOR_EXCEPTION = "EXECUTOR_EXCEPTION"
    EXECUTION_PROTOCOL_ERROR = "EXECUTION_PROTOCOL_ERROR"
    ENVIRONMENT_DRIFT = "ENVIRONMENT_DRIFT"
    TERMINATION_UNCONFIRMED = "TERMINATION_UNCONFIRMED"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    EVIDENCE_WRITE_FAILED = "EVIDENCE_WRITE_FAILED"
    TIME_BUDGET = "TIME_BUDGET"
    EXECUTION_BUDGET = "EXECUTION_BUDGET"
    PROPOSAL_BUDGET = "PROPOSAL_BUDGET"
    EVIDENCE_BUDGET = "EVIDENCE_BUDGET"
    CANCELLED = "CANCELLED"
    SEARCH_EXHAUSTED = "SEARCH_EXHAUSTED"
    REPLAY_COMPLETE = "REPLAY_COMPLETE"
```

### 3.3 Models

```python
@dataclass(frozen=True)
class WitnessEntry:
    key: tuple[object, ...]   # full row key (design 6.2.2): ordered tuple of value keys
                              # ("null",) / ("number", coeff_text, scale); 1-tuple for
                              # single-column results. Persistent JSON encoding is the
                              # ordered list of value-key arrays:
                              # [["null"]] / [["number", coeff_text, scale]] etc.
    a_count: int              # >= 0
    b_count: int              # >= 0
    diff: int                 # a_count - b_count, != 0

@dataclass(frozen=True)
class ComparisonCounts:
    a_rows: int; b_rows: int              # observed row counts
    a_distinct: int; b_distinct: int      # distinct canonical row keys
    matched_rows: int                     # multiset intersection size (MATCH == a_rows == b_rows == matched)

@dataclass(frozen=True)
class Comparison:                     # schema=1
    schema_version: int = COMPARISON_SCHEMA_VERSION
    oracle_version: str = ORACLE_VERSION
    case_id: str                      # hex64
    request_hash: str                 # hex64
    expectation_hash: Optional[str]   # hex64 when an expectation was checked
    execution_hash: str               # hex64 == evidence_hash of the consumed evidence
    runtime_check_hash: Optional[str] # hex64 when D1 runtime revalidation ran
    status: ComparisonStatus
    reasons: tuple[ComparisonReason, ...]   # gate order, side A/B, condition id; deduped;
                                            # reasons[0] is primary_reason
    comparable: bool                  # True only for MATCH / MISMATCH_CANDIDATE
    counts: Optional[ComparisonCounts]      # only when comparable
    witness: Optional[tuple[WitnessEntry, ...]]   # only for MISMATCH_CANDIDATE, <= 20 entries
    witness_truncated: bool
    exact_signature: Optional[str]    # hex64, only for MISMATCH_CANDIDATE
    fingerprint: Optional[str]        # hex64, only for MISMATCH_CANDIDATE
    hash: str                         # content hash over to_obj() minus "hash"
    # causes (D1 condition ids/reasons) are NOT re-enumerated here; consumers
    # re-run gates. No fake zero-row counts for non-comparable statuses.

@dataclass(frozen=True)
class InputFailure:                   # schema=1, entry-layer mapping of ContractError
    schema_version: int = COMPARISON_SCHEMA_VERSION
    status: ComparisonStatus = ComparisonStatus.INCONCLUSIVE (frozen literal)
    code: str                         # stable code, e.g. "CONTRACT_ERROR"
    input_ref: str                    # root-relative reference or "<memory>"
    detail: str                       # short reason, no raw untrusted dump
    trusted_case_id: Optional[str]    # only when independently re-derived

@dataclass(frozen=True)
class ReplayResult:                   # schema=1
    comparison_hash: str              # reference to the original comparison
    policy_hash: str                  # hex64 over canonical replay policy object
    attempt_hashes: tuple[str, ...]   # evidence_hash per dispatched attempt, in order
    requested: int                    # prepare dispatches (incl. prepare failures)
    completed: int                    # both sides COMPLETE with full, untruncated fetch
    comparable: int                   # passed all gates
    matching_signature: int           # comparable attempts with the group's baseline signature
    exact_signatures: tuple[str, ...] # per comparable attempt
    outcome: ReplayOutcome
    stop_reason: Optional[StopReason]
    operational_failure: bool
    synthetic: bool
    hash: str                         # content hash minus itself
    # invariant: matching_signature <= comparable <= completed <= requested

@dataclass(frozen=True)
class ReductionResult:                # schema=1
    reduction_id: str                 # non-empty caller id
    outcome: ReductionOutcome
    stop_reason: Optional[StopReason]
    original_case_id: str             # hex64
    original_comparison_hash: str
    original_fingerprint: Optional[str]
    best_case_id: str                 # == original_case_id when nothing accepted
    best_comparison_hashes: tuple[str, ...]   # the three child comparisons of best
    has_reduction: bool               # an accepted child exists (best != original)
    search_complete: bool
    proposals: int; executions: int; accepted: int
    rejected_static: int; inconclusive_candidates: int; unstable_candidates: int
    synthetic: bool
    hash: str

@dataclass(frozen=True)
class CandidateInput:                 # in-memory bundle handed to replay/reduce
    payload: CasePayload
    request: AttemptRequest
    expectation: AttemptExpectation
    evidence: ExecutionEvidence
    comparison_hash: str              # reference; replay/reduce re-compare and never trust status
    source: str                       # non-empty provenance label, e.g. "original"/"child:<rid>"
```

### 3.4 Policy models (hashable, hash goes into policy_hash)

```python
@dataclass(frozen=True)
class ComparisonBudget:
    deadline_ms: int = COMPARISON_DEADLINE_MS       # 1..COMPARISON_DEADLINE_MS
    max_rows: int = MAX_RESULT_ROWS                 # 1..MAX_RESULT_ROWS
    max_bytes: int = MAX_RESULT_BYTES               # 1..MAX_RESULT_BYTES
    max_columns: int = MAX_RESULT_COLUMNS           # 1..MAX_RESULT_COLUMNS
    witness_limit: int = WITNESS_LIMIT              # 1..WITNESS_LIMIT

@dataclass(frozen=True)
class ReplayPolicy:
    attempts: int = REPLAY_ATTEMPTS                 # frozen: only 3 accepted
    total_budget_ms: int = REPLAY_TOTAL_BUDGET_MS   # 1..REPLAY_TOTAL_BUDGET_MS
    attempt_budget_ms: int = ATTEMPT_BUDGET_MS      # 1..ATTEMPT_BUDGET_MS
    cancel_grace_ms: int = CANCEL_GRACE_MS
    # policy_hash = sha256_hex(canonical_json(to_obj()))

@dataclass(frozen=True)
class ReductionPolicy:
    max_proposals: int = REDUCTION_MAX_PROPOSALS        # 1..hard cap
    max_executions: int = REDUCTION_MAX_EXECUTIONS      # 1..hard cap
    total_budget_ms: int = REDUCTION_TOTAL_BUDGET_MS    # 1..hard cap
    attempt_budget_ms: int = ATTEMPT_BUDGET_MS
    cancel_grace_ms: int = CANCEL_GRACE_MS
    evidence_append_budget: int = EVIDENCE_APPEND_BUDGET  # <= hard cap
    # replay_policy derived: ReplayPolicy(attempt_budget_ms, cancel_grace_ms)

@dataclass(frozen=True)
class ArtifactRef:
    path: str          # root-relative, POSIX separators, no "..", no leading "/"
    size_bytes: int    # >= 0
    sha256: str        # hex64 of file bytes
    schema_version: int
```

Illegal policy values raise `ContractError` before any side effect; policies
are never silently clamped.

### 3.5 TraceSink protocol (contract layer; real impl is reduction/trace.py)

```python
@dataclass(frozen=True)
class PersistedReceipt:
    seq: int
    kind: str
    record_hash: str

class TraceSink(Protocol):
    def reserve(self, size_hint: int) -> None: ...       # pre-flight budget check
    def append(self, record: "TraceRecord") -> PersistedReceipt: ...

@dataclass(frozen=True)
class TraceRecord:                    # schema=1 JSONL record (see reduction/trace.py)
    seq: int                          # strictly increasing from 1
    kind: str                         # SNAPSHOT/START/REQUESTED/EXPECTATION/EVIDENCE/
                                      # RESULT/COMPARISON/REPLAY/ACCEPTED/FINISHED
    payload_ref: Optional[ArtifactRef]   # published dependency file (atomic, exclusive)
    inline: Optional[dict]            # small metadata <= MAX_TRACE_META_BYTES canonical
    prev_hash: str                    # hex64 of previous record, "0"*64 for seq 1
    hash: str                         # sha256 over canonical record content minus "hash"
```

## 4. oracle/exact.py — exact keys and multiset comparison

```python
def value_key(value: ResultValue) -> tuple[str, ...]
    # NULL -> ("null",); integer -> ("number", str(int_value), 0);
    # decimal -> ("number", stripped_coefficient_text, scale) with trailing
    # decimal zeros stripped when scale > 0; zero -> ("number", "0", 0).
    # Integer arithmetic only; 9007199254740993 != 9007199254740992;
    # integer 1 and decimal (100, scale 2) share a key; NULL != 0.
def key_persistent(key) -> list        # ["null"] or ["number", coeff_text, scale]
def row_key(row: tuple[ResultValue, ...]) -> tuple[tuple[str, ...], ...]
def row_key_bytes(row_key) -> bytes    # canonical_json(key_persistent list)
def compare_multisets(a_rows, b_rows, ...) -> (counts, witness_entries, truncated)
```

Comparison uses one `Counter` per side over `row_key_bytes`; full equality
required for MATCH. Witness = first 20 distinct differing keys sorted by
canonical key bytes (a_count, b_count, diff). Never sorts bare tuples with
mixed types; never uses Python set iteration order; the underlying
comparison is always complete before witness truncation.

## 5. oracle/fingerprint.py — signatures

```python
def exact_signature(payload, oracle_version, a_key_counts, b_key_counts) -> str
    # sha256 over canonical_json of:
    # ["exact_signature_v1", case_id, rule_id, rule_version, definition_hash,
    #  relation_hash (sha256 of canonical relation to_obj), oracle_version,
    #  [["A", sorted [key, count] list], ["B", sorted [key, count] list]]]
    # sorted by canonical row-key bytes; excludes attempt ids, row order, timing.
def fingerprint(payload, oracle_version, renderer_version, codec_version,
                environment_hash, session_profile) -> str
    # sha256 over canonical_json of:
    # ["fingerprint_v1", rule_id, rule_version, definition_hash,
    #  a_type, b_type, template_id, index_variant, relation_hash,
    #  oracle_version, renderer id/version, codec_version,
    #  environment_hash, session profile object, "ROW_MULTISET_DIFFERENCE"]
    # excludes case_id/values/row counts; coarse grouping only, never proof
    # of the same root cause.
```

## 6. oracle/gates.py — compare_case

```python
def compare_case(request: AttemptRequest,
                 expectation: AttemptExpectation | None,
                 evidence: ExecutionEvidence,
                 budget: ComparisonBudget,
                 control: Control | None = None) -> Comparison
def compare_case_document(request_doc, expectation_doc | None, evidence_doc,
                          budget: ComparisonBudget) -> Comparison | InputFailure
```

Gate order (6.4.1), first failure stops; reasons collected in gate order,
then side (A before B), then stable condition id; dedup preserved order:

1. Budget/strict-loader/hash recheck: recompute case_id, request hash,
   expectation hash, evidence hash; envelope size; schema versions.
   `ContractError` -> `InputFailure` (entry layer only, `compare_case_document`).
2. D1 `validate_case` re-run must be VALID_STATIC; rule/type/template/index
   identity re-checked; disabled rule -> NOT_APPLICABLE/RULE_DISABLED only
   when identified and explicitly disabled; everything else INVALID ->
   INCONCLUSIVE.
3. D1 `validate_runtime_facts(payload, expectation.binding, evidence.runtime_facts)`
   must be READY (READY necessary, not sufficient); missing facts ->
   RUNTIME_NOT_READY. `RuntimeFactsError` -> INCONCLUSIVE/INPUT_INVALID.
4. Evidence gates: setup diagnostics exactly cover render_pair DDL/INSERT per
   side ((side, phase, ordinal, sql_hash) aligned, complete=True, entries=());
   SideContext per side: session identity equal across setup/readback/select,
   current_database == NameMap database for the side, A/B databases differ,
   autocommit/isolation equal the fixed SessionProfile and stable
   before/after, environments before/after hash to the request's target
   environment hash; isolation receipt positively true; SELECT text/hash
   equal render_pair, protocol=text, parameters=(); terminal CONFIRMED
   (termination unconfirmed blocks the comparison: TERMINATION_UNCONFIRMED);
   cleanup failure does NOT block an already-complete comparison but is
   recorded by replay/reduction.
5. Result gates per side: status COMPLETE, result present, fetch_complete,
   not truncated, extra_result_sets == 0, SELECT diagnostics complete and
   empty, row count == observed, columns 1..max, aliases/families match the
   declared relation, value kinds match the observed family, null_policy
   respected, scalar encoding legal. Violations -> INCONCLUSIVE with
   RESULT_* reasons; result contract violations raise/retain
   `RESULT_CONTRACT_VIOLATION` (exception class `ResultContractViolation`,
   a ContractError subclass) — never treated as a logic candidate.
6. Both sides pass -> build Counters (deadline-checked) -> MATCH or
   MISMATCH_CANDIDATE (+ counts, witness, exact_signature, fingerprint).
   Any single-side budget failure stops the whole pair (RESULT_BUDGET_EXCEEDED);
   a differing prefix never yields an early candidate.

NOT_APPLICABLE requires a structured `PreflightRejection` bound to the
request and reconcilable with case requirements; corrupted/unknown input is
INCONCLUSIVE/INPUT_INVALID, never "unsupported".

## 7. reduction/replay.py — replay_candidate

```python
def replay_candidate(candidate: CandidateInput | None, executor: ExecutionPort | None,
                     trace_sink: TraceSink | None, policy: ReplayPolicy,
                     control: Control) -> ReplayResult
```

- None executor -> NOT_REPLAYED/NO_EXECUTOR, zero dispatches. None candidate
  or a candidate that does not re-compare to MISMATCH_CANDIDATE ->
  NOT_REPLAYED/INVALID_CANDIDATE, zero dispatches.
- First re-compare the original input via `compare_case` (never trust
  `candidate.comparison_hash`/status).
- Dispatch exactly 3 fresh attempts in execution order AB, BA, AB; logical
  A/B labels follow the schema, never the dispatch order. Each attempt:
  fresh attempt_id, fresh NameMap, fresh connections; REQUESTED record ->
  prepare (EXPECTATION record) -> execute (EVIDENCE/RESULT/COMPARISON
  records) -> group REPLAY record. Counters follow section 3.3 invariants
  (prepare failures count as requested, never comparable).
- Early exit: any MATCH, a different exact_signature/fingerprint/environment/
  execution profile, missing/errored evidence, or
  operational failure (protocol violation, cleanup != DONE, termination
  != CONFIRMED, sink write failure, executor exception) stops the group;
  remaining rounds are not dispatched and not retried.
- REPRODUCED requires all three attempts comparable, identical
  exact_signature equal to the original observation's signature, identical
  fingerprint, unchanged environment/profile, terminal CONFIRMED and
  cleanup DONE on every attempt. synthetic propagates.
- Budgets: attempt deadline = min(attempt_budget, remaining total); on
  budget/cancel after confirmed termination -> UNSTABLE with the
  corresponding EXECUTION_INCOMPLETE/... reason; unconfirmed termination ->
  operational failure, TERMINATION_UNCONFIRMED, stop dispatching.
- Exceptions from prepare/execute are recorded (attempt still counted,
  EXECUTOR_EXCEPTION), evidence that could be salvaged is kept, cancel via
  `cancel_and_wait` is attempted; KeyboardInterrupt is never swallowed.

## 8. reduction/strategy.py — proposals and complexity

```python
def complexity(payload: CasePayload) -> tuple[int, int, int, int, int]
    # (row_count, predicate_node_count, non_null_value_count, magnitude_sum,
    #  canonical payload byte length of canonical_json(payload.to_obj()))
    # predicate_node_count counts Compare/Between/IsNull/And/Or; 0 when None.
    # non_null_value_count: non-NULL shared row values + non-NULL logical
    # literal slots (Compare right, Between lower/upper); Q4 k counted once
    # even though projection references it. magnitude_sum: sum |coefficient|
    # over the same set (integer value = coefficient), NULL contributes 0,
    # scale fixed, rids excluded.

def iter_proposals(payload: CasePayload) -> Iterator[Transform]
    # Deterministic order (6.4.4):
    # 1. remove_rows: rid ascending. Try delete-all first. Then for
    #    g = 2,4,...,<=n: for each block i (1-based) over
    #    [floor(i*n/g), floor((i+1)*n/g)) propose deleting that block, then
    #    propose deleting its complement; skip empty deletions and duplicates;
    #    continue down to single-row deletions. n == 0 -> nothing; n == 1 ->
    #    only delete-all. rids keep original values (no renumbering).
    # 2. simplify_predicate: And/Or left child then right child
    #    (SimplifyPredicate with PathNode paths).
    # 3. replace_value (shared row values): per rid ascending, candidate
    #    values in order NULL, 0, +unit, -unit, sign(x)*(abs(x)//2), dedup,
    #    preserving kind and decimal scale (decimal unit coefficient=1 at the
    #    slot's scale; integer unit 1). Halving is integer // 2 toward zero.
    # 4. replace_literal: IR preorder — And/Or left then right; Between lower
    #    then upper; finally Q4 arithmetic constant. Candidate order for
    #    literals: 0, +unit, -unit, halve, then NULL at positions D1 allows
    #    (Compare constant; never BETWEEN endpoints). Paths use the D1
    #    PathNode grammar ("predicate", ..., "constant"); Q4 k path is
    #    ("predicate", "arithmetic", "constant").
```

The engine never proposes a candidate whose complexity is >= the current
best's complexity (same-or-worse rejected before execution); visited child
case_ids are tracked across the whole run; no fingerprint-based child
dedup.

## 9. reduction/engine.py — reduce_candidate

```python
def reduce_candidate(candidate: CandidateInput | None, executor: ExecutionPort | None,
                     trace_sink: TraceSink | None, policy: ReductionPolicy,
                     control: Control) -> ReductionResult
```

- None executor -> FAILED/NO_EXECUTOR; invalid/non-candidate input ->
  FAILED/INVALID_CANDIDATE, zero executions.
- Always re-runs the original 3-attempt replay first (fresh, not cached,
  not substituted by a prior REPRODUCED label). Original not reproduced ->
  FAILED/ORIGINAL_NOT_REPRODUCED, best_reproduced stays false, no child
  executions.
- Serial candidate loop over `iter_proposals(best.payload)`: proposal budget
  is decremented per transform submitted to D1 (`apply_transform`),
  including REJECTED/NO_CHANGE/already-visited children; execution budget
  per prepare (including prepare failures); a new 3-round group needs >= 3
  remaining execution slots; attempt deadline = min(budget, remaining
  total). Initial replay consumes execution budget but no proposals.
- APPLIED child: re-run `validate_case`, verify rule/type pair/template/
  index unchanged (transforms cannot change them; re-check anyway), compare
  complexity strictly less than current best's; then 3 fresh attempts
  (AB, BA, AB). Accept only when: three valid comparable MISMATCH_CANDIDATE
  comparisons, identical in-group exact_signature (established by the first
  comparable candidate), fingerprint equal to the original fingerprint,
  terminal CONFIRMED + cleanup DONE on all three. A MATCH or in-group
  signature change stops that group and rejects the child; rule/binding/
  environment drift is a whole-run fault (FAILED, stop dispatching), a
  plain child SQL_ERROR with CONFIRMED termination and DONE cleanup merely
  rejects that child and continues (counted inconclusive).
- ACCEPTED: persist ACCEPTED trace record, then commit the best pointer in
  memory. best starts as the original candidate with best_reproduced=false
  semantics (never called a verified best before its own replay passed).
- Final states: all ordered candidates exhausted -> REDUCED/UNCHANGED,
  search_complete=true; budget/cancel with confirmed termination ->
  BUDGET_EXHAUSTED + matching stop reason, best preserved; safety/
  persistence faults (binding, environment, protocol, termination unknown,
  sink failure) outrank budget exhaustion -> FAILED with the stable
  stop reason; priority: safety > budget > ordinary non-reproduction.
  FAILED/BUDGET_EXHAUSTED still report the original and last persisted
  best. No global-minimality claims.

## 10. reduction/trace.py — append-only bounded JSONL trace

Single writer, dedicated output root (created exclusively, no symlink
components, never follows `..`; new files created with O_EXCL semantics,
existing outputs never overwritten). Layout:

```text
<root>/trace.jsonl
<root>/files/<sha256>.json   # payload_ref files, atomically published
```

Record kinds and mandatory order (6.4.6): original/candidate SNAPSHOT ->
START; per attempt REQUESTED -> prepare -> EXPECTATION -> execute ->
EVIDENCE(file) -> RESULT -> COMPARISON; group REPLAY; child ACCEPTED ->
best pointer update; terminal FINISHED. prepare failure takes the
EVIDENCE/RESULT failure branch without EXPECTATION.

JSONL record = TraceRecord as section 3.5: `seq` increments from 1, each
record carries `prev_hash` and its own `hash` (over canonical content minus
`hash`); dependency files are published atomically before the record is
appended, flushed and fsynced; only then is a PersistedReceipt returned.
Append budget: reserve the max receipt + control record size before each
dispatch, settle actual bytes after writing; insufficient reserve stops
dispatching before execution (never "run first, save later"), leaving >=
EVIDENCE_RESERVE_BYTES free. Sink failure stops dispatching and returns
FAILED with the last persisted best.

Read-side audit (`read_trace(root)`, read-only): rebuild records; a final
record without trailing newline or bad JSON = PARTIAL tail; corruption in a
completed record (hash/seq/reference mismatch) = CORRUPT, trust stops at
that point (never search past corruption for a smaller best); best is
rebuilt only from the last verified ACCEPTED (validating the child, its
three comparisons and the strict complexity decrease) else falls back to
the original candidate. Partial/corrupt traces keep the original input and
never patch history or auto-resume SQL.

## 11. Ownership and D3 handover

- D2 owns: all models above, oracle/*, reduction/*, tests, this document.
- D3 owns: producing AttemptExpectation (prepare) and ExecutionEvidence
  (execute), diagnostics collection, isolation evidence, terminal receipts,
  driver type_code/flags -> family mapping (mapping_version), and the
  authorization layer. D3 must fill: per-statement diagnostics entries,
  pre/post environment snapshots, session ids, actual database binding,
  isolation method evidence, termination proof. Missing facts must stay
  absent (None + failure record), never defaulted to true.
- `synthetic=True` marks test-fixture evidence and propagates to every
  Comparison/ReplayResult/ReductionResult; it never counts as real
  reproduction.
