"""Provenance cross-checks and execution-safety assessment (design 6.2.2, 6.4.3).

Both dimensions read ONLY the snapshot copy of a native source through a
:class:`~evidence.reader.SourceReader` (design 6.4.1 item 5) and never infer
a fact that no record shows:

- Provenance cross-checks run/attempt/side identities across the independent
  records the D3 runner published (StageObservation ledger, SideContext
  session identities, ownership journal, terminal receipts).  When the
  original setup/readback connection ids are recorded AND the query phase
  reused (rewrote) them, that is a CONFLICT; when the original records are
  missing it stays UNVERIFIED — absence is never upgraded to corroboration.
- Execution safety is CONFIRMED only with a terminal receipt corroborated by
  cleanup/ownership facts; a KILL reply without terminal/ownership
  confirmation is UNKNOWN; manifest leftover counts alone never confirm
  safety (they can only contradict it); sources with no execution are
  NOT_APPLICABLE.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..contracts.case import ContractError
from ..contracts.codec import parse_strict_json
from ..contracts.delivery import (
    AssessmentDimension,
    DimensionObservation,
    DimensionResult,
    ExecutionSafetyStatus,
    Limits,
    NativeKind,
    ProvenanceStatus,
    aggregate_provenance,
    aggregate_safety,
)
from ..contracts.execution import (
    CleanupState,
    ExecutionEvidence,
    Side,
    TerminalReceipt,
    TerminationState,
    decode_terminal_receipt,
    load_execution_evidence,
)
from ..contracts.runner import (
    OwnershipEvent,
    OwnershipEventKind,
    RunnerManifest,
    load_ownership_journal,
    load_runner_manifest,
    load_stage_observation,
)
from ..runner.evidence import MANIFEST_NAME as _RUNNER_MANIFEST_NAME
from ..runner.ownership import OWNERSHIP_JOURNAL_FILE_NAME
from .native import SourcePlan
from .reader import (
    BudgetExhaustedError,
    EvidenceReadError,
    MissingEntryError,
    ReadLimitExceededError,
    SourceReader,
)

__all__ = [
    "assess_provenance",
    "assess_execution_safety",
]

_SETUP_STAGES = frozenset({"DATABASE_CREATE", "DDL", "INSERT"})
_QUERY_STAGES = frozenset({"SESSION", "SELECT", "FETCH"})

# Kinds with no runner-owned execution records at all.
_NO_EXECUTION_KINDS = frozenset(
    {NativeKind.GENERATION, NativeKind.TRACE, NativeKind.DELIVERY, NativeKind.UNKNOWN}
)


# --------------------------------------------------------------------------
# Shared attempt-record state
# --------------------------------------------------------------------------


def iter_attempt_ids(plan: SourcePlan) -> set[str]:
    """Attempt ids declared by the plan's closure (attempts/<id>/...).

    Derived from the enumerated closure only; never from directory sizes
    (design 6.4.2: requested counts are never inferred)."""
    ids: set[str] = set()
    for planned in plan.files:
        parts = planned.relpath.split("/")
        if len(parts) >= 3 and parts[0] == "attempts":
            ids.add(parts[1])
    return ids


@dataclass(frozen=True)
class _AttemptState:
    """Everything one attempt's provenance/safety checks may look at."""

    attempt_id: Optional[str]
    prefix: str
    observations: Optional[list[object]] = None  # StageObservation records
    observation_errors: int = 0
    observations_missing: bool = False
    observations_limit: bool = False
    evidence: Optional[ExecutionEvidence] = None
    evidence_missing: bool = False
    evidence_invalid: bool = False
    terminal: Optional[TerminalReceipt] = None
    terminal_missing: bool = False
    terminal_invalid: bool = False
    events: tuple[OwnershipEvent, ...] = ()
    manifest: Optional[RunnerManifest] = None


def _read_jsonl_observations(
    reader: SourceReader, relpath: str, limits: Limits
) -> tuple[Optional[list[object]], int, bool, bool]:
    """Read one attempt's observation ledger.

    Returns ``(records, decode_error_count, missing, over_limit)``."""
    try:
        lines = reader.read_jsonl(
            relpath,
            max_line_bytes=limits.max_jsonl_line_bytes,
            max_total_bytes=limits.max_total_source_bytes,
        )
    except MissingEntryError:
        return None, 0, True, False
    except ReadLimitExceededError:
        return None, 0, False, True
    except (BudgetExhaustedError, EvidenceReadError):
        return None, 0, True, False
    records: list[object] = []
    errors = 0
    for _line_no, raw_line in lines:
        if not raw_line.strip():
            continue
        try:
            record = load_stage_observation(parse_strict_json(raw_line))
        except ContractError:
            errors += 1
            continue
        records.append(record)
    return records, errors, False, False


def _load_attempt_state(
    reader: SourceReader,
    plan: SourcePlan,
    attempt_id: str,
    limits: Limits,
    events_by_attempt: dict[str, tuple[OwnershipEvent, ...]],
    manifest: Optional[RunnerManifest],
) -> _AttemptState:
    prefix = f"attempts/{attempt_id}/" if attempt_id else ""

    records, errors, observations_missing, observations_limit = _read_jsonl_observations(
        reader, prefix + "observations.jsonl", limits
    )

    evidence: Optional[ExecutionEvidence] = None
    evidence_missing = False
    evidence_invalid = False
    try:
        raw = reader.read_bytes(
            prefix + "execution-evidence.json", max_bytes=limits.max_json_document_bytes
        )
        evidence = load_execution_evidence(parse_strict_json(raw))
    except MissingEntryError:
        evidence_missing = True
    except (ContractError, ReadLimitExceededError, BudgetExhaustedError, EvidenceReadError):
        evidence_invalid = True

    terminal: Optional[TerminalReceipt] = None
    terminal_missing = False
    terminal_invalid = False
    try:
        raw = reader.read_bytes(prefix + "terminal.json", max_bytes=limits.max_json_document_bytes)
        terminal = decode_terminal_receipt(parse_strict_json(raw))
    except MissingEntryError:
        terminal_missing = True
    except (ContractError, ReadLimitExceededError, BudgetExhaustedError, EvidenceReadError):
        terminal = None
        terminal_invalid = True

    attempt_events = events_by_attempt.get(attempt_id, ()) if attempt_id else ()
    return _AttemptState(
        attempt_id=attempt_id or None,
        prefix=prefix,
        observations=records,
        observation_errors=errors,
        observations_missing=observations_missing,
        observations_limit=observations_limit,
        evidence=evidence,
        evidence_missing=evidence_missing,
        evidence_invalid=evidence_invalid,
        terminal=terminal,
        terminal_missing=terminal_missing,
        terminal_invalid=terminal_invalid,
        events=attempt_events,
        manifest=manifest,
    )


def _load_run_context(
    reader: SourceReader, plan: SourcePlan, limits: Limits
) -> tuple[dict[str, tuple[OwnershipEvent, ...]], Optional[RunnerManifest], bool, bool, bool]:
    """Read the run-level ownership journal and runner manifest once.

    Returns ``(events_by_attempt, manifest, journal_missing, journal_invalid,
    manifest_missing)``.  A standalone attempt source has no journal or
    manifest; that absence is a structural fact of the native format, not a
    missing record, so it does not by itself force UNVERIFIED."""
    if plan.kind is not NativeKind.RUN:
        return {}, None, False, False, False

    journal_missing = False
    journal_invalid = False
    events_by_attempt: dict[str, tuple[OwnershipEvent, ...]] = {}
    try:
        raw = reader.read_bytes(
            OWNERSHIP_JOURNAL_FILE_NAME, max_bytes=limits.max_total_source_bytes
        )
        events = load_ownership_journal(raw)
    except MissingEntryError:
        journal_missing = True
    except (ContractError, ReadLimitExceededError, BudgetExhaustedError, EvidenceReadError):
        journal_invalid = True
    else:
        grouped: dict[str, list[OwnershipEvent]] = {}
        for event in events:
            if event.attempt_id is not None:
                grouped.setdefault(event.attempt_id, []).append(event)
        events_by_attempt = {key: tuple(items) for key, items in grouped.items()}

    manifest: Optional[RunnerManifest] = None
    manifest_missing = False
    try:
        raw = reader.read_bytes(
            _RUNNER_MANIFEST_NAME, max_bytes=limits.max_json_document_bytes
        )
        manifest = load_runner_manifest(parse_strict_json(raw))
    except (MissingEntryError, ContractError, ReadLimitExceededError, BudgetExhaustedError, EvidenceReadError):
        manifest_missing = True
    return events_by_attempt, manifest, journal_missing, journal_invalid, manifest_missing


def _check_snapshot_root(reader: SourceReader, snapshot_root: Optional[object]) -> None:
    if snapshot_root is not None and str(reader.root) != str(snapshot_root):
        raise ValueError(
            "the SourceReader must be opened on the snapshot copy "
            f"({str(snapshot_root)!r}), not on {str(reader.root)!r}"
        )


def _obs_records(state: _AttemptState) -> list[object]:
    return state.observations or []


def _stage_connection_ids(records: list[object], side: Side, stages: frozenset[str]) -> set[str]:
    return {
        record.connection_id  # type: ignore[attr-defined]
        for record in records
        if record.side is side  # type: ignore[attr-defined]
        and str(record.stage.value) in stages  # type: ignore[attr-defined]
        and record.connection_id is not None  # type: ignore[attr-defined]
    }


# --------------------------------------------------------------------------
# Provenance dimension
# --------------------------------------------------------------------------


def assess_provenance(
    reader: SourceReader,
    plan: SourcePlan,
    limits: Limits,
    control=None,
    *,
    snapshot_root=None,
) -> DimensionResult:
    """Provenance dimension for one source (design 6.4.3).

    ``reader`` must be opened on the snapshot copy of the source
    (``<output_root>/raw/<source-id>/``); with ``snapshot_root`` given, the
    two are cross-checked.  Sources without runner execution records are
    not applicable; a run/attempt source is always applicable — missing
    records keep it UNVERIFIED instead of skipping it."""
    _check_snapshot_root(reader, snapshot_root)

    if plan.kind in _NO_EXECUTION_KINDS:
        code = (
            "no_execution_records"
            if plan.kind in (NativeKind.GENERATION, NativeKind.UNKNOWN)
            else (
                "trace_has_no_stage_observations"
                if plan.kind is NativeKind.TRACE
                else "delivery_raw_not_reaudited"
            )
        )
        return DimensionResult(
            dimension=AssessmentDimension.PROVENANCE,
            applicable=False,
            status=ProvenanceStatus.UNVERIFIED,
            reason_codes=(code,),
        )

    events_by_attempt, _manifest, journal_missing, journal_invalid, _manifest_missing = (
        _load_run_context(reader, plan, limits)
    )

    observations: list[DimensionObservation] = []
    reasons: set[str] = set()
    unchecked = 0
    for attempt_id in sorted(iter_attempt_ids(plan)) if plan.kind is NativeKind.RUN else [""]:
        if control is not None and control.expired():
            unchecked += 1
            continue
        state = _load_attempt_state(
            reader, plan, attempt_id, limits, events_by_attempt, None
        )
        status, codes = _attempt_provenance(
            state, plan, journal_missing, journal_invalid
        )
        reasons.update(codes)
        observations.append(
            DimensionObservation(
                AssessmentDimension.PROVENANCE,
                True,
                status,
                object_ref=(state.prefix[:256] or "attempt/"),
            )
        )

    if not observations:
        reasons.add("budget_exhausted" if unchecked else "no_attempts")
        return DimensionResult(
            dimension=AssessmentDimension.PROVENANCE,
            applicable=False,
            status=ProvenanceStatus.UNVERIFIED,
            reason_codes=tuple(sorted(reasons)),
            unchecked_objects=unchecked,
        )
    return DimensionResult(
        dimension=AssessmentDimension.PROVENANCE,
        applicable=True,
        status=aggregate_provenance(observations),
        reason_codes=tuple(sorted(reasons)),
        checked_objects=len(observations),
        unchecked_objects=unchecked,
        detail=None,
    )


def _worse(current: ProvenanceStatus, candidate: ProvenanceStatus) -> ProvenanceStatus:
    order = {
        ProvenanceStatus.CORROBORATED: 0,
        ProvenanceStatus.UNVERIFIED: 1,
        ProvenanceStatus.CONFLICT: 2,
    }
    return candidate if order[candidate] > order[current] else current


def _attempt_provenance(
    state: _AttemptState,
    plan: SourcePlan,
    journal_missing: bool,
    journal_invalid: bool,
) -> tuple[ProvenanceStatus, set[str]]:
    """Cross-check one attempt's independent records (design 6.4.3)."""
    status = ProvenanceStatus.CORROBORATED
    codes: set[str] = set()

    def note(candidate: ProvenanceStatus, code: str) -> None:
        nonlocal status
        status = _worse(status, candidate)
        codes.add(code)

    if state.observations_missing:
        note(ProvenanceStatus.UNVERIFIED, "observations_missing")
    elif state.observations_limit:
        note(ProvenanceStatus.UNVERIFIED, "limit_exceeded")
    elif state.observation_errors:
        note(ProvenanceStatus.UNVERIFIED, "observation_record_invalid")

    records = _obs_records(state)
    evidence = state.evidence
    if state.evidence_missing:
        note(ProvenanceStatus.UNVERIFIED, "evidence_missing")
    elif state.evidence_invalid:
        note(ProvenanceStatus.UNVERIFIED, "evidence_invalid")
        evidence = None

    if evidence is not None and state.attempt_id:
        # Attempt identity across independent records (design 6.4.3).
        binding = evidence.expectation.binding if evidence.expectation is not None else None
        if binding is not None and binding.attempt_id != state.attempt_id:
            note(ProvenanceStatus.CONFLICT, "attempt_identity_mismatch")
        if state.terminal is not None and state.terminal.attempt_id != state.attempt_id:
            note(ProvenanceStatus.CONFLICT, "attempt_identity_mismatch")

    for side in (Side.A, Side.B):
        context = evidence.a_context if side is Side.A else evidence.b_context
        if context is None:
            continue
        setup_ids = _stage_connection_ids(records, side, _SETUP_STAGES)
        readback_ids = _stage_connection_ids(records, side, frozenset({"READBACK"}))
        query_ids = _stage_connection_ids(records, side, _QUERY_STAGES)

        # Session identity cross-checks: when the original setup/readback ids
        # are recorded AND the query-phase id was rewritten into them, that is
        # a CONFLICT (the known D3 id rewrite); missing originals stay
        # UNVERIFIED, never corroborated.
        if not setup_ids:
            note(ProvenanceStatus.UNVERIFIED, "setup_observations_missing")
        elif context.setup_connection_id not in setup_ids:
            if context.setup_connection_id in query_ids:
                note(ProvenanceStatus.CONFLICT, "session_identity_rewritten")
            else:
                note(ProvenanceStatus.CONFLICT, "setup_connection_mismatch")
        if not readback_ids:
            note(ProvenanceStatus.UNVERIFIED, "readback_observations_missing")
        elif context.readback_connection_id not in readback_ids:
            if context.readback_connection_id in query_ids:
                note(ProvenanceStatus.CONFLICT, "session_identity_rewritten")
            else:
                note(ProvenanceStatus.CONFLICT, "readback_connection_mismatch")

        queries_ran = (
            (evidence.a_query if side is Side.A else evidence.b_query) is not None
            or bool(query_ids)
        )
        if queries_ran:
            if not query_ids:
                note(ProvenanceStatus.UNVERIFIED, "query_observations_missing")
            elif context.select_connection_id not in query_ids:
                note(ProvenanceStatus.CONFLICT, "select_connection_mismatch")
        # A query phase on the same connection id as setup/readback is the
        # legal single-session layout (SideContext requires the three ids to
        # be equal); the contradiction D4 surfaces is the rewrite case above,
        # where the context claims a query id the original setup records
        # never used.
        for record in records:
            if (
                record.side is side  # type: ignore[attr-defined]
                and str(record.stage.value) == "SELECT"  # type: ignore[attr-defined]
                and record.actual_database is not None  # type: ignore[attr-defined]
                and record.actual_database != context.current_database  # type: ignore[attr-defined]
            ):
                note(ProvenanceStatus.CONFLICT, "database_binding_mismatch")

    # Ownership ledger cross-checks (run sources only).
    if plan.kind is NativeKind.RUN:
        if journal_missing:
            note(ProvenanceStatus.UNVERIFIED, "ownership_journal_missing")
        elif journal_invalid:
            note(ProvenanceStatus.UNVERIFIED, "ownership_journal_invalid")
        else:
            session_ids = {
                event.connection_id
                for event in state.events
                if event.event_kind is OwnershipEventKind.SESSION_REGISTERED
                and event.connection_id is not None
            }
            if session_ids:
                observed_ids = set()
                for side in (Side.A, Side.B):
                    observed_ids |= _stage_connection_ids(records, side, _QUERY_STAGES)
                if observed_ids and not (session_ids & observed_ids):
                    note(ProvenanceStatus.CONFLICT, "ownership_session_mismatch")
            # Ownership events must line up with the terminal facts.
            terminal_confirm = any(
                event.event_kind is OwnershipEventKind.TERMINATION_CONFIRMED
                for event in state.events
            )
            terminal_unknown = any(
                event.event_kind is OwnershipEventKind.TERMINATION_UNKNOWN
                for event in state.events
            )
            if terminal_confirm and state.terminal is None:
                note(ProvenanceStatus.UNVERIFIED, "terminal_receipt_missing")
            elif terminal_confirm and state.terminal is not None and (
                state.terminal.termination is not TerminationState.CONFIRMED
            ):
                note(ProvenanceStatus.CONFLICT, "ownership_terminal_mismatch")
            elif terminal_unknown and state.terminal is not None and (
                state.terminal.termination is TerminationState.CONFIRMED
            ):
                note(ProvenanceStatus.CONFLICT, "ownership_terminal_mismatch")
    return status, codes


# --------------------------------------------------------------------------
# Execution-safety dimension
# --------------------------------------------------------------------------


def assess_execution_safety(
    reader: SourceReader,
    plan: SourcePlan,
    limits: Limits,
    control=None,
    *,
    snapshot_root=None,
) -> DimensionResult:
    """Execution-safety dimension for one source (design 6.4.3).

    CONFIRMED requires a terminal receipt plus cleanup/ownership
    corroboration; queries without terminal confirmation are UNKNOWN (never
    NOT_APPLICABLE); leftover/unknown objects make it UNSAFE; sources without
    execution are NOT_APPLICABLE."""
    _check_snapshot_root(reader, snapshot_root)

    if plan.kind in _NO_EXECUTION_KINDS:
        code = (
            "no_execution_records"
            if plan.kind in (NativeKind.GENERATION, NativeKind.UNKNOWN)
            else (
                "trace_has_no_stage_observations"
                if plan.kind is NativeKind.TRACE
                else "delivery_raw_not_reaudited"
            )
        )
        return DimensionResult(
            dimension=AssessmentDimension.EXECUTION_SAFETY,
            applicable=False,
            status=ExecutionSafetyStatus.NOT_APPLICABLE,
            reason_codes=(code,),
        )

    events_by_attempt, manifest, _journal_missing, _journal_invalid, _manifest_missing = (
        _load_run_context(reader, plan, limits)
    )

    observations: list[DimensionObservation] = []
    reasons: set[str] = set()
    unchecked = 0
    attempt_iter = (
        sorted(iter_attempt_ids(plan)) if plan.kind is NativeKind.RUN else [""]
    )
    for attempt_id in attempt_iter:
        if control is not None and control.expired():
            unchecked += 1
            continue
        state = _load_attempt_state(reader, plan, attempt_id, limits, events_by_attempt, manifest)
        applicable, status, codes = _attempt_safety(state)
        reasons.update(codes)
        observations.append(
            DimensionObservation(
                AssessmentDimension.EXECUTION_SAFETY,
                applicable,
                status,
                object_ref=(state.prefix[:256] or "attempt/"),
            )
        )

    if plan.kind is NativeKind.RUN and manifest is not None:
        # Manifest leftover counts can only ever contradict safety; a zero
        # count alone never confirms it (design 6.4.3).
        if manifest.leftover_objects > 0:
            reasons.add("manifest_leftover_objects")
            observations.append(
                DimensionObservation(
                    AssessmentDimension.EXECUTION_SAFETY,
                    True,
                    ExecutionSafetyStatus.UNSAFE,
                    object_ref=_RUNNER_MANIFEST_NAME,
                )
            )
        if manifest.leftover_sessions > 0:
            reasons.add("manifest_leftover_sessions")
            observations.append(
                DimensionObservation(
                    AssessmentDimension.EXECUTION_SAFETY,
                    True,
                    ExecutionSafetyStatus.UNSAFE,
                    object_ref=_RUNNER_MANIFEST_NAME,
                )
            )

    applicable_observations = [
        obs for obs in observations if obs.applicable
    ]
    if not applicable_observations:
        reasons.add("budget_exhausted" if unchecked else "no_execution")
        return DimensionResult(
            dimension=AssessmentDimension.EXECUTION_SAFETY,
            applicable=False,
            status=ExecutionSafetyStatus.NOT_APPLICABLE,
            reason_codes=tuple(sorted(reasons)),
            unchecked_objects=unchecked,
        )
    return DimensionResult(
        dimension=AssessmentDimension.EXECUTION_SAFETY,
        applicable=True,
        status=aggregate_safety(observations),
        reason_codes=tuple(sorted(reasons)),
        checked_objects=len(applicable_observations),
        unchecked_objects=unchecked,
        detail=None,
    )


def _attempt_safety(
    state: _AttemptState,
) -> tuple[bool, ExecutionSafetyStatus, set[str]]:
    """Safety verdict for one attempt from terminal/ownership corroboration.

    Returns ``(applicable, status, reason_codes)``."""
    codes: set[str] = set()

    records = _obs_records(state)
    has_select_obs = any(
        str(record.stage.value) == "SELECT" for record in records  # type: ignore[attr-defined]
    )
    has_termination_obs = any(
        str(record.stage.value) == "TERMINATION" for record in records  # type: ignore[attr-defined]
    )
    evidence = state.evidence
    has_queries = bool(has_select_obs)
    if evidence is not None and (evidence.a_query is not None or evidence.b_query is not None):
        has_queries = True

    terminal = state.terminal

    if terminal is None:
        if state.terminal_invalid:
            # An unreadable receipt is its own honest verdict; nothing is
            # inferred from its absence.
            codes.add("terminal_receipt_invalid")
            return True, ExecutionSafetyStatus.UNKNOWN, codes
        if evidence is not None and not has_queries and not has_select_obs:
            # No query ever ran on this attempt: nothing to keep safe.
            return False, ExecutionSafetyStatus.NOT_APPLICABLE, codes
        codes.add(
            "kill_reply_without_terminal" if has_termination_obs else "terminal_receipt_missing"
        )
        return True, ExecutionSafetyStatus.UNKNOWN, codes

    if terminal.termination is TerminationState.NOT_STARTED:
        if has_queries:
            # Queries ran but the receipt says nothing started: contradiction.
            codes.add("termination_not_started_with_queries")
            return True, ExecutionSafetyStatus.UNSAFE, codes
        return False, ExecutionSafetyStatus.NOT_APPLICABLE, codes

    if terminal.termination is TerminationState.UNKNOWN:
        codes.add("kill_reply_without_terminal" if has_termination_obs else "termination_unknown")
        return True, ExecutionSafetyStatus.UNKNOWN, codes

    # Terminal receipt says CONFIRMED; cleanup/ownership must corroborate.
    verdict = ExecutionSafetyStatus.CONFIRMED
    if terminal.cleanup is not CleanupState.DONE:
        verdict = ExecutionSafetyStatus.UNSAFE
        codes.add("cleanup_not_done")

    for event in state.events:
        if event.event_kind is OwnershipEventKind.CLEANUP_FAILED:
            verdict = ExecutionSafetyStatus.UNSAFE
            codes.add("ownership_cleanup_failed")
        elif event.event_kind is OwnershipEventKind.QUARANTINED:
            verdict = ExecutionSafetyStatus.UNSAFE
            codes.add("ownership_quarantined")
        elif event.event_kind is OwnershipEventKind.TERMINATION_UNKNOWN:
            verdict = ExecutionSafetyStatus.UNKNOWN
            codes.add("ownership_termination_unknown")

    created = {
        event.object_name
        for event in state.events
        if event.event_kind
        in (OwnershipEventKind.OBJECT_CREATED, OwnershipEventKind.OBJECT_ALLOCATED)
        and event.object_name is not None
    }
    dropped = {
        event.object_name
        for event in state.events
        if event.event_kind is OwnershipEventKind.OBJECT_DROPPED and event.object_name is not None
    }
    if created - dropped:
        verdict = ExecutionSafetyStatus.UNSAFE
        codes.add("ownership_objects_undropped")

    return True, verdict, codes
