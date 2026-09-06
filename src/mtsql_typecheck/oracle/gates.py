"""D2 oracle comparison gates (design 6.4.1/6.4.2; docs/oracle-d2-contract.md §6).

``compare_case`` re-derives the whole trust chain for one attempt before any
result multiset is compared:

1. budget/identity: recompute ``case_id`` and the request canonical hash and
   require three-way agreement with ``evidence.request_hash`` and
   ``expectation.request_hash``; the expectation hash is carried into
   ``Comparison.expectation_hash`` and the evidence hash into
   ``Comparison.execution_hash``;
2. D1 ``validate_case`` re-run must be ``VALID_STATIC`` (a disabled but
   identified rule is NOT_APPLICABLE/RULE_DISABLED, every other INVALID
   reason is mapped onto INCONCLUSIVE);
3. D1 ``validate_runtime_facts`` must be ``READY`` (READY is necessary, never
   sufficient); INCOMPLETE -> RUNTIME_NOT_READY, BLOCKED -> the mapped
   VIOLATED reason; ``RuntimeFactsError`` -> INCONCLUSIVE/INPUT_INVALID;
4. evidence gates: setup diagnostics exactly cover the ``render_pair``
   DDL/INSERT receipts per side, per-side session identity/database/profile/
   environment snapshots, positive isolation evidence, CONFIRMED termination
   (cleanup != DONE does *not* block an already-complete comparison);
5. result gates per side: full untruncated fetch, no extra result sets,
   budget limits, and the declared-relation column/family/kind/null-policy
   contract.  Result-contract violations raise :class:`ResultContractViolation`
   (carrying the fully-formed INCONCLUSIVE ``Comparison``) so that no caller
   can mistake them for a logic candidate; entry layers that prefer a value
   return the carried comparison, which retains
   ``ComparisonReason.RESULT_CONTRACT_VIOLATION``;
6. both sides pass -> :func:`oracle.exact.compare_multisets` (deadline
   checked) -> MATCH or MISMATCH_CANDIDATE with counts, witness,
   ``exact_signature`` and ``fingerprint``.  A single-side budget failure
   stops the whole pair (RESULT_BUDGET_EXCEEDED); a differing prefix never
   yields an early candidate.

Reasons are ordered by gate, then side (globals, then A, then B), then stable
condition id, deduplicated preserving first occurrence; ``reasons[0]`` is the
primary reason.  Gate 6.4.1 stops at the first failing gate: the first
untrustworthy structure is never dereferenced further and the comparison
returns non-comparable immediately.  This module performs no I/O, never
normalizes values, and never imports an executor, sink or driver.
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

from mtsql_typecheck.contracts.case import (
    CheckStatus,
    ContractError,
    NullPolicy,
    ReasonCode,
    StaticCheckStatus,
    RuntimeCheckStatus,
    TypeFamily,
)
from mtsql_typecheck.contracts.codec import canonical_json, sha256_hex
from mtsql_typecheck.contracts.execution import (
    MAX_EVIDENCE_BYTES,
    AttemptExpectation,
    AttemptRequest,
    Control,
    ControlCancelled,
    ExecutionEvidence,
    QueryStatus,
    ResultValueKind,
    Side,
    TerminationState,
    load_attempt_expectation,
    load_attempt_request,
    load_execution_evidence,
)
from mtsql_typecheck.contracts.oracle import (
    ORACLE_VERSION,
    Comparison,
    ComparisonBudget,
    ComparisonReason,
    ComparisonStatus,
    InputFailure,
)
from mtsql_typecheck.generation.render import RenderPhase, render_pair
from mtsql_typecheck.generation.validation import (
    RuntimeFactsError,
    environment_content_hash,
    name_map_content_hash,
    validate_case,
    validate_runtime_facts,
)
from mtsql_typecheck.oracle.exact import compare_multisets, row_key
from mtsql_typecheck.oracle.fingerprint import exact_signature, fingerprint

__all__ = [
    "ResultContractViolation",
    "compare_case",
    "compare_case_document",
]


class ResultContractViolation(ContractError):
    """A result metadata/encoding contract violation (contract §6 gate 5).

    Raised by :func:`compare_case` so that upper layers can never treat a
    broken result encoding as a logic candidate.  Carries the gate-ordered
    reasons (including ``RESULT_CONTRACT_VIOLATION``) and the fully formed
    INCONCLUSIVE :class:`Comparison` for entry layers that return values.
    """

    def __init__(self, message: str, *, reasons: tuple, comparison: Comparison) -> None:
        super().__init__(message)
        self.reasons = reasons
        self.comparison = comparison


# --------------------------------------------------------------------------
# Frozen preflight requirement-id vocabulary (contract §6: NOT_APPLICABLE
# requires a structured rejection "reconcilable with case requirements").
# Extending this set is a design revision, not a code default.
# --------------------------------------------------------------------------

_RECONCILABLE_REQUIREMENT_IDS = frozenset(
    {
        "environment.mysql80",
        "environment.innodb",
        "environment.same-instance",
        "environment.sql_mode",
        "environment.character_set",
        "environment.collation",
        "environment.time_zone",
        "environment.version_series",
        "environment.vendor_build",
        "environment.session_snapshot",
        "environment.optimizer_switch",
    }
)


# --------------------------------------------------------------------------
# D1 reason -> D2 comparison reason mapping (contract §6 gates 2-3)
# --------------------------------------------------------------------------

_D1_TO_COMPARISON_REASON: dict[str, ComparisonReason] = {
    str(ReasonCode.RULE_DISABLED): ComparisonReason.RULE_DISABLED,
    str(ReasonCode.UNKNOWN_VERSION): ComparisonReason.VERSION_UNSUPPORTED,
    str(ReasonCode.UNSUPPORTED_ENVIRONMENT): ComparisonReason.UNSUPPORTED_ENVIRONMENT,
    str(ReasonCode.BINDING_MISMATCH): ComparisonReason.BINDING_MISMATCH,
    str(ReasonCode.INVALID_STRUCTURE): ComparisonReason.INPUT_INVALID,
    str(ReasonCode.VALUE_OUT_OF_DOMAIN): ComparisonReason.INPUT_INVALID,
    str(ReasonCode.BUDGET_EXCEEDED): ComparisonReason.INPUT_INVALID,
    str(ReasonCode.INTERNAL_ERROR): ComparisonReason.INPUT_INVALID,
    str(ReasonCode.MISSING_FACT): ComparisonReason.RUNTIME_NOT_READY,
    str(ReasonCode.LOAD_VALUE_MISMATCH): ComparisonReason.LOAD_ANOMALY,
    str(ReasonCode.LOAD_DIAGNOSTICS): ComparisonReason.SETUP_DIAGNOSTICS,
    str(ReasonCode.SCHEMA_MISMATCH): ComparisonReason.LOAD_ANOMALY,
}


def _map_d1_reason(reason: Optional[ReasonCode]) -> ComparisonReason:
    if reason is None:
        return ComparisonReason.INPUT_INVALID
    return _D1_TO_COMPARISON_REASON.get(str(reason.value), ComparisonReason.INPUT_INVALID)


# --------------------------------------------------------------------------
# Reason collector: gate order -> side (globals, A, B) -> condition id
# --------------------------------------------------------------------------

_SIDE_RANK = {"*": 0, "A": 1, "B": 2}


class _ReasonCollector:
    """Collects (gate, side, condition_id, reason) and finalizes sorted/deduped."""

    def __init__(self) -> None:
        self._items: list[tuple[int, int, str, int, ComparisonReason]] = []
        self._seq = 0

    def add(
        self,
        gate: int,
        side: str,
        condition_id: str,
        reason: ComparisonReason,
    ) -> None:
        self._items.append((gate, _SIDE_RANK[side], condition_id, self._seq, reason))
        self._seq += 1

    @property
    def empty(self) -> bool:
        return not self._items

    def finalize(self) -> tuple[ComparisonReason, ...]:
        ordered = sorted(self._items, key=lambda item: item[:4])
        reasons: list[ComparisonReason] = []
        for *_, reason in ordered:
            if reason not in reasons:
                reasons.append(reason)
        return tuple(reasons)


class _Identity:
    """Per-comparison identity fields needed by every returned Comparison."""

    def __init__(
        self,
        case_id: str,
        request_hash: str,
        expectation_hash: Optional[str],
        execution_hash: str,
    ) -> None:
        self.case_id = case_id
        self.request_hash = request_hash
        self.expectation_hash = expectation_hash
        self.execution_hash = execution_hash
        self.runtime_check_hash: Optional[str] = None

    def non_comparable(
        self,
        status: ComparisonStatus,
        reasons: tuple[ComparisonReason, ...],
    ) -> Comparison:
        return Comparison(
            case_id=self.case_id,
            request_hash=self.request_hash,
            expectation_hash=self.expectation_hash,
            execution_hash=self.execution_hash,
            runtime_check_hash=self.runtime_check_hash,
            status=status,
            reasons=reasons,
            comparable=False,
            counts=None,
            witness=None,
            witness_truncated=False,
            exact_signature=None,
            fingerprint=None,
        )


class _DeadlineReached(Exception):
    """Internal: the control deadline expired at a checkpoint."""


def _checkpoint(control: Optional[Control]) -> None:
    """Cooperative cancellation/deadline checkpoint between gates."""
    if control is None:
        return
    control.raise_if_cancelled()
    if control.expired():
        raise _DeadlineReached()


# --------------------------------------------------------------------------
# Evidence helpers
# --------------------------------------------------------------------------


def _expected_setup_receipts(
    payload, name_map
) -> tuple[list[tuple[str, str, int, str]], dict[str, object]]:
    """Expected DDL/INSERT receipt keys per side, in render order, plus the
    per-side SELECT statements of ``render_pair`` (design 6.4.2)."""
    pair = render_pair(payload, name_map)
    expected: list[tuple[str, str, int, str]] = []
    selects: dict[str, object] = {}
    for side, statements in (("A", pair.a), ("B", pair.b)):
        counters: dict[str, int] = {}
        select = None
        for statement in statements:
            if statement.phase is RenderPhase.SELECT:
                select = statement
                continue
            phase_value = str(statement.phase.value)
            ordinal = counters.get(phase_value, 0)
            counters[phase_value] = ordinal + 1
            expected.append((side, phase_value, ordinal, statement.sql_hash))
        if select is None:
            raise ContractError(f"render_pair produced no SELECT for side {side}")
        selects[side] = select
    return expected, selects


def _clean_diagnostics(diagnostics) -> bool:
    """True when the receipt is comparable: collected, complete, no entries."""
    return diagnostics.collected and diagnostics.complete and not diagnostics.entries


def _environment_matches_target(environment, target_hash: str) -> bool:
    return environment_content_hash(environment) == target_hash


def _signature_key_counts(rows: tuple) -> dict:
    """row_key -> count mapping (byte-order irrelevant; the signature layer
    sorts by canonical key bytes itself)."""
    counter: Counter = Counter()
    for row in rows:
        counter[row_key(row)] += 1
    return dict(counter)


# --------------------------------------------------------------------------
# compare_case
# --------------------------------------------------------------------------


def compare_case(
    request: AttemptRequest,
    expectation: Optional[AttemptExpectation],
    evidence: ExecutionEvidence,
    budget: ComparisonBudget,
    control: Optional[Control] = None,
) -> Comparison:
    """Full D2 comparison gate walk for one attempt (contract §6, design 6.4.1).

    Returns a frozen :class:`Comparison`.  Result-contract violations raise
    :class:`ResultContractViolation` (never returned as a candidate/match);
    deadline expiry and cooperative cancellation return INCONCLUSIVE with
    COMPARISON_DEADLINE / CANCELLED.
    """
    collector = _ReasonCollector()
    identity_holder: list[_Identity] = []
    try:
        return _compare_case_inner(
            request, expectation, evidence, budget, control, collector, identity_holder
        )
    except ControlCancelled:
        if identity_holder:
            return identity_holder[0].non_comparable(
                ComparisonStatus.INCONCLUSIVE, (ComparisonReason.CANCELLED,)
            )
        raise
    except _DeadlineReached:
        if identity_holder:
            return identity_holder[0].non_comparable(
                ComparisonStatus.INCONCLUSIVE, (ComparisonReason.COMPARISON_DEADLINE,)
            )
        raise


def _compare_case_inner(
    request: AttemptRequest,
    expectation: Optional[AttemptExpectation],
    evidence: ExecutionEvidence,
    budget: ComparisonBudget,
    control: Optional[Control],
    collector: _ReasonCollector,
    identity_holder: list,
) -> Comparison:
    payload = request.payload
    profile = request.session_profile
    target_env_hash = sha256_hex(canonical_json(request.target_environment.to_obj()))

    # ------------------------------------------------------------------
    # Gate 1: budget/identity/hash recheck.
    # ------------------------------------------------------------------
    case_id = request.case_id
    request_hash = request.request_hash
    if evidence.request_hash != request_hash:
        collector.add(1, "*", "evidence_request_hash", ComparisonReason.BINDING_MISMATCH)
        identity = _Identity(case_id, request_hash, None, evidence.evidence_hash)
        return identity.non_comparable(
            ComparisonStatus.INCONCLUSIVE, collector.finalize()
        )
    expectation_hash: Optional[str] = None
    if expectation is not None:
        expectation_hash = expectation.expectation_hash
        if expectation.request_hash != request_hash:
            collector.add(1, "*", "expectation_request_hash", ComparisonReason.BINDING_MISMATCH)
            identity = _Identity(case_id, request_hash, expectation_hash, evidence.evidence_hash)
            return identity.non_comparable(
                ComparisonStatus.INCONCLUSIVE, collector.finalize()
            )
        if expectation.execution_order != request.execution_order:
            collector.add(
                1, "*", "expectation_execution_order", ComparisonReason.BINDING_MISMATCH
            )
            identity = _Identity(case_id, request_hash, expectation_hash, evidence.evidence_hash)
            return identity.non_comparable(
                ComparisonStatus.INCONCLUSIVE, collector.finalize()
            )
        if expectation.binding.case_id != case_id:
            collector.add(1, "*", "expectation_case_id", ComparisonReason.BINDING_MISMATCH)
            identity = _Identity(case_id, request_hash, expectation_hash, evidence.evidence_hash)
            return identity.non_comparable(
                ComparisonStatus.INCONCLUSIVE, collector.finalize()
            )
    identity = _Identity(case_id, request_hash, expectation_hash, evidence.evidence_hash)
    identity_holder.append(identity)
    _checkpoint(control)

    # ------------------------------------------------------------------
    # Structured preflight rejection: NOT_APPLICABLE requires a rejection
    # bound to this request and reconcilable with the case requirements.
    # ------------------------------------------------------------------
    if evidence.preflight_rejection is not None:
        rejection = evidence.preflight_rejection
        if rejection.request_hash != request_hash:
            collector.add(1, "*", "preflight_request_hash", ComparisonReason.INPUT_INVALID)
            return identity.non_comparable(
                ComparisonStatus.INCONCLUSIVE, collector.finalize()
            )
        if rejection.rejected_requirement_id not in _RECONCILABLE_REQUIREMENT_IDS:
            collector.add(1, "*", "preflight_requirement_id", ComparisonReason.INPUT_INVALID)
            return identity.non_comparable(
                ComparisonStatus.INCONCLUSIVE, collector.finalize()
            )
        return identity.non_comparable(
            ComparisonStatus.NOT_APPLICABLE, (ComparisonReason.UNSUPPORTED_ENVIRONMENT,)
        )

    # ------------------------------------------------------------------
    # Gate 2: D1 static re-validation must be VALID_STATIC.
    # ------------------------------------------------------------------
    static_check = validate_case(payload)
    if static_check.status is not StaticCheckStatus.VALID_STATIC:
        violated = [
            condition
            for condition in static_check.conditions
            if condition.status is CheckStatus.VIOLATED
        ]
        disabled_but_identified = any(
            condition.condition_id == "rule_enabled"
            and condition.reason is ReasonCode.RULE_DISABLED
            for condition in violated
        )
        if disabled_but_identified:
            return identity.non_comparable(
                ComparisonStatus.NOT_APPLICABLE, (ComparisonReason.RULE_DISABLED,)
            )
        for condition in violated:
            collector.add(2, "*", f"static_{condition.condition_id}", _map_d1_reason(condition.reason))
        if collector.empty:
            collector.add(2, "*", "static_check", ComparisonReason.INPUT_INVALID)
        return identity.non_comparable(
            ComparisonStatus.INCONCLUSIVE, collector.finalize()
        )
    _checkpoint(control)

    # ------------------------------------------------------------------
    # Gate 3: D1 runtime fact revalidation must be READY.
    # ------------------------------------------------------------------
    if expectation is None or evidence.runtime_facts is None:
        collector.add(3, "*", "runtime_facts_presence", ComparisonReason.RUNTIME_NOT_READY)
        return identity.non_comparable(
            ComparisonStatus.INCONCLUSIVE, collector.finalize()
        )
    try:
        runtime_check = validate_runtime_facts(
            payload, expectation.binding, evidence.runtime_facts
        )
    except RuntimeFactsError:
        collector.add(3, "*", "runtime_facts_input", ComparisonReason.INPUT_INVALID)
        return identity.non_comparable(
            ComparisonStatus.INCONCLUSIVE, collector.finalize()
        )
    identity.runtime_check_hash = sha256_hex(canonical_json(runtime_check.to_obj()))
    if runtime_check.status is RuntimeCheckStatus.INCOMPLETE:
        collector.add(3, "*", "runtime_facts_ready", ComparisonReason.RUNTIME_NOT_READY)
        return identity.non_comparable(
            ComparisonStatus.INCONCLUSIVE, collector.finalize()
        )
    if runtime_check.status is RuntimeCheckStatus.BLOCKED:
        for condition in runtime_check.conditions:
            if condition.status is CheckStatus.VIOLATED:
                collector.add(
                    3,
                    "*",
                    f"runtime_{condition.condition_id}",
                    _map_d1_reason(condition.reason),
                )
        if collector.empty:
            collector.add(3, "*", "runtime_check", ComparisonReason.INPUT_INVALID)
        return identity.non_comparable(
            ComparisonStatus.INCONCLUSIVE, collector.finalize()
        )
    _checkpoint(control)

    # ------------------------------------------------------------------
    # Gate 4: evidence gates.
    # ------------------------------------------------------------------
    try:
        expected_receipts, selects = _expected_setup_receipts(payload, expectation.name_map)
    except ContractError:
        collector.add(4, "*", "render_pair", ComparisonReason.INPUT_INVALID)
        return identity.non_comparable(
            ComparisonStatus.INCONCLUSIVE, collector.finalize()
        )

    # Setup diagnostics: exact (side, phase, ordinal, sql_hash) coverage of
    # the render_pair DDL/INSERT statements, in render order.
    actual_receipts = [
        (str(item.side.value), str(item.phase.value), item.ordinal, item.sql_hash)
        for item in evidence.setup_diagnostics
    ]
    if actual_receipts != expected_receipts:
        collector.add(4, "*", "setup_diagnostics_coverage", ComparisonReason.SETUP_DIAGNOSTICS)
    for item in evidence.setup_diagnostics:
        if not _clean_diagnostics(item):
            collector.add(
                4,
                str(item.side.value),
                "setup_diagnostics_clean",
                ComparisonReason.SETUP_DIAGNOSTICS,
            )

    # Isolation receipt: positively true, bound to this attempt and name map.
    receipt = evidence.isolation_receipt
    if (
        receipt is None
        or not receipt.objects_created_confirmed
        or not receipt.load_committed
        or not receipt.no_concurrent_write_confirmed
        or receipt.name_map_hash != name_map_content_hash(expectation.name_map)
        or receipt.attempt_id != request.attempt_id
    ):
        collector.add(4, "*", "isolation_receipt", ComparisonReason.ISOLATION_UNCONFIRMED)

    # Termination must be positively confirmed; cleanup != DONE does NOT
    # block an already-complete comparison (recorded by replay/reduction).
    terminal = evidence.terminal
    if terminal is None or terminal.termination is not TerminationState.CONFIRMED:
        collector.add(4, "*", "terminal_termination", ComparisonReason.TERMINATION_UNCONFIRMED)

    rows_eff = min(budget.max_rows, request.result_row_budget)
    bytes_eff = min(budget.max_bytes, request.result_byte_budget)

    for side in (Side.A, Side.B):
        side_label = str(side.value)
        context = evidence.a_context if side is Side.A else evidence.b_context
        query = evidence.a_query if side is Side.A else evidence.b_query

        # Side context: one session identity, database binding, fixed session
        # profile and environments that hash to the request target.
        if context is None:
            collector.add(4, side_label, "context_presence", ComparisonReason.QUERY_NOT_COMPLETE)
        else:
            if context.name_map != expectation.name_map:
                collector.add(
                    4, side_label, "context_name_map", ComparisonReason.DATABASE_BINDING_MISMATCH
                )
            expected_database = (
                expectation.name_map.database_a
                if side is Side.A
                else expectation.name_map.database_b
            )
            if context.current_database != expected_database:
                collector.add(
                    4, side_label, "context_database", ComparisonReason.DATABASE_BINDING_MISMATCH
                )
            if (
                context.autocommit != profile.autocommit
                or context.transaction_isolation != profile.transaction_isolation
            ):
                collector.add(
                    4, side_label, "context_session_profile", ComparisonReason.ENVIRONMENT_DRIFT
                )
            if not _environment_matches_target(context.environment_before, target_env_hash):
                collector.add(
                    4, side_label, "context_environment_before", ComparisonReason.ENVIRONMENT_DRIFT
                )
            if not _environment_matches_target(context.environment_after, target_env_hash):
                collector.add(
                    4, side_label, "context_environment_after", ComparisonReason.ENVIRONMENT_DRIFT
                )

        # Query evidence: binding, exact SELECT identity, database, drift,
        # diagnostics, completion and session identity.
        if query is None:
            collector.add(4, side_label, "query_presence", ComparisonReason.QUERY_NOT_COMPLETE)
            continue
        if query.binding != expectation.binding:
            collector.add(4, side_label, "query_binding", ComparisonReason.BINDING_MISMATCH)
        select = selects[side_label]
        if (
            query.select_text != select.text
            or query.select_sql_hash != select.sql_hash
            or query.protocol != "text"
            or query.parameters != ()
        ):
            collector.add(4, side_label, "query_select", ComparisonReason.BINDING_MISMATCH)
        if context is not None and query.actual_database != context.current_database:
            collector.add(
                4, side_label, "query_database", ComparisonReason.DATABASE_BINDING_MISMATCH
            )
        if not _environment_matches_target(query.environment_before, target_env_hash):
            collector.add(
                4, side_label, "query_environment_before", ComparisonReason.ENVIRONMENT_DRIFT
            )
        if not _environment_matches_target(query.environment_after, target_env_hash):
            collector.add(
                4, side_label, "query_environment_after", ComparisonReason.ENVIRONMENT_DRIFT
            )
        if not _clean_diagnostics(query.diagnostics):
            collector.add(4, side_label, "query_diagnostics", ComparisonReason.QUERY_DIAGNOSTICS)
        if query.status is not QueryStatus.COMPLETE:
            collector.add(4, side_label, "query_status", ComparisonReason.QUERY_NOT_COMPLETE)
        if query.session_start_id is None or query.session_end_id is None:
            collector.add(4, side_label, "query_session", ComparisonReason.QUERY_NOT_COMPLETE)

    if not collector.empty:
        return identity.non_comparable(
            ComparisonStatus.INCONCLUSIVE, collector.finalize()
        )
    _checkpoint(control)

    # ------------------------------------------------------------------
    # Gate 5: per-side result gates.
    # ------------------------------------------------------------------
    results = {}
    for side in (Side.A, Side.B):
        side_label = str(side.value)
        query = evidence.a_query if side is Side.A else evidence.b_query
        assert query is not None  # gate 4 guarantees presence
        result = query.result
        if result is None:
            collector.add(5, side_label, "result_presence", ComparisonReason.RESULT_INCOMPLETE)
            continue
        if not result.fetch_complete or result.truncated or result.extra_result_sets != 0:
            collector.add(5, side_label, "result_fetch", ComparisonReason.RESULT_INCOMPLETE)
            continue
        if len(result.columns) > budget.max_columns:
            collector.add(
                5, side_label, "result_columns", ComparisonReason.RESULT_BUDGET_EXCEEDED
            )
            continue
        if len(result.rows) > rows_eff:
            collector.add(
                5, side_label, "result_rows", ComparisonReason.RESULT_BUDGET_EXCEEDED
            )
            continue
        if len(canonical_json(result.to_obj())) > bytes_eff:
            collector.add(
                5, side_label, "result_bytes", ComparisonReason.RESULT_BUDGET_EXCEEDED
            )
            continue
        _check_result_contract(payload, side, result, collector, identity)
        results[side_label] = result

    if not collector.empty:
        return identity.non_comparable(
            ComparisonStatus.INCONCLUSIVE, collector.finalize()
        )
    _checkpoint(control)

    # ------------------------------------------------------------------
    # Gate 6: exact multiset comparison (deadline checked).
    # ------------------------------------------------------------------
    a_rows = results["A"].rows
    b_rows = results["B"].rows
    try:
        counts, witness, truncated = compare_multisets(a_rows, b_rows, budget.witness_limit)
    except ContractError:
        # e.g. a differing multi-column key that the frozen WitnessEntry
        # encoding cannot represent: never silently matched.
        collector.add(6, "*", "witness_encoding", ComparisonReason.INPUT_INVALID)
        return identity.non_comparable(
            ComparisonStatus.INCONCLUSIVE, collector.finalize()
        )
    if counts.a_rows == counts.b_rows == counts.matched_rows and not witness:
        return Comparison(
            case_id=identity.case_id,
            request_hash=identity.request_hash,
            expectation_hash=identity.expectation_hash,
            execution_hash=identity.execution_hash,
            runtime_check_hash=identity.runtime_check_hash,
            status=ComparisonStatus.MATCH,
            reasons=(),
            comparable=True,
            counts=counts,
            witness=None,
            witness_truncated=False,
            exact_signature=None,
            fingerprint=None,
        )
    signature = exact_signature(
        payload,
        ORACLE_VERSION,
        _signature_key_counts(a_rows),
        _signature_key_counts(b_rows),
    )
    group_fingerprint = fingerprint(
        payload,
        ORACLE_VERSION,
        payload.renderer,
        expectation.codec_version,
        target_env_hash,
        profile,
    )
    return Comparison(
        case_id=identity.case_id,
        request_hash=identity.request_hash,
        expectation_hash=identity.expectation_hash,
        execution_hash=identity.execution_hash,
        runtime_check_hash=identity.runtime_check_hash,
        status=ComparisonStatus.MISMATCH_CANDIDATE,
        reasons=(),
        comparable=True,
        counts=counts,
        witness=witness if witness else None,
        witness_truncated=truncated,
        exact_signature=signature,
        fingerprint=group_fingerprint,
    )


def _check_result_contract(
    payload,
    side: Side,
    result,
    collector: _ReasonCollector,
    identity: _Identity,
) -> None:
    """Declared-relation contract for one side's result (gate 5).

    Raises :class:`ResultContractViolation` on the first violation; the
    exception carries the gate-ordered reasons and the INCONCLUSIVE
    Comparison, so a broken result encoding can never be compared.
    """

    def _violation() -> ResultContractViolation:
        reasons = collector.finalize()
        return ResultContractViolation(
            "result contract violation: declared relation does not match the "
            f"observed result for side {side.value}",
            reasons=reasons,
            comparison=identity.non_comparable(
                ComparisonStatus.INCONCLUSIVE, reasons
            ),
        )

    side_label = str(side.value)
    relation_columns = payload.relation.columns
    if len(result.columns) != len(relation_columns):
        collector.add(5, side_label, "result_column_shape", ComparisonReason.RESULT_CONTRACT_VIOLATION)
        raise _violation()
    for index, column in enumerate(result.columns):
        declared = relation_columns[index]
        expected_family = declared.a_family if side is Side.A else declared.b_family
        if column.alias != declared.alias or column.family is not expected_family:
            collector.add(
                5, side_label, "result_column_contract", ComparisonReason.RESULT_CONTRACT_VIOLATION
            )
            raise _violation()
    for index, declared in enumerate(relation_columns):
        expected_family = declared.a_family if side is Side.A else declared.b_family
        for row in result.rows:
            value = row[index]
            if value.kind is ResultValueKind.NULL:
                if declared.null_policy is NullPolicy.FORBID:
                    collector.add(
                        5,
                        side_label,
                        "result_null_policy",
                        ComparisonReason.RESULT_CONTRACT_VIOLATION,
                    )
                    raise _violation()
                continue
            if expected_family is TypeFamily.SIGNED_INTEGER:
                legal = value.kind is ResultValueKind.INTEGER
            else:
                legal = value.kind is ResultValueKind.DECIMAL
            if not legal:
                collector.add(
                    5,
                    side_label,
                    "result_value_kind",
                    ComparisonReason.RESULT_CONTRACT_VIOLATION,
                )
                raise _violation()


# --------------------------------------------------------------------------
# compare_case_document (entry layer)
# --------------------------------------------------------------------------


def _failure(
    code: str,
    input_ref: str,
    detail: str,
    trusted_case_id: Optional[str],
) -> InputFailure:
    return InputFailure(
        code=code,
        input_ref=input_ref,
        detail=detail[:512],
        trusted_case_id=trusted_case_id,
    )


def compare_case_document(
    request_doc,
    expectation_doc,
    evidence_doc,
    budget: ComparisonBudget,
    *,
    input_ref: str = "<memory>",
) -> Comparison | InputFailure:
    """Entry layer: untrusted documents -> Comparison or InputFailure.

    Pre-checks the evidence envelope size, parses the three documents with
    the strict loaders, and maps every ``ContractError`` (loader or model
    construction) onto an INCONCLUSIVE :class:`InputFailure` — corrupted or
    unknown-version input is never wrapped as NOT_APPLICABLE.  A
    :class:`ResultContractViolation` raised by :func:`compare_case` is
    returned as its carried INCONCLUSIVE Comparison, which retains the
    ``RESULT_CONTRACT_VIOLATION`` reason.
    """
    trusted_case_id: Optional[str] = None

    if isinstance(evidence_doc, (bytes, str)):
        raw = evidence_doc.encode("utf-8") if isinstance(evidence_doc, str) else evidence_doc
        if len(raw) > MAX_EVIDENCE_BYTES:
            return _failure(
                "INPUT_INVALID",
                input_ref,
                f"execution evidence exceeds MAX_EVIDENCE_BYTES ({MAX_EVIDENCE_BYTES})",
                None,
            )

    try:
        request = load_attempt_request(request_doc)
    except ContractError as exc:
        return _failure("CONTRACT_ERROR", input_ref, str(exc), None)
    except ValueError as exc:
        return _failure("INPUT_INVALID", input_ref, str(exc), None)
    trusted_case_id = request.case_id

    expectation = None
    if expectation_doc is not None:
        try:
            expectation = load_attempt_expectation(expectation_doc)
        except ContractError as exc:
            return _failure("CONTRACT_ERROR", input_ref, str(exc), trusted_case_id)
        except ValueError as exc:
            return _failure("INPUT_INVALID", input_ref, str(exc), trusted_case_id)

    try:
        evidence = load_execution_evidence(evidence_doc)
    except ContractError as exc:
        return _failure("CONTRACT_ERROR", input_ref, str(exc), trusted_case_id)
    except ValueError as exc:
        return _failure("INPUT_INVALID", input_ref, str(exc), trusted_case_id)

    try:
        return compare_case(request, expectation, evidence, budget)
    except ResultContractViolation as exc:
        return exc.comparison
    except ContractError as exc:
        return _failure("CONTRACT_ERROR", input_ref, str(exc), trusted_case_id)
