"""Online run controller (design 6.3.1/6.4/6.5, Phase 5).

``RunController.run`` executes one online ``run`` command end to end:

1. the output root is created exclusively by :class:`EvidenceWriter`
   (an existing directory is an input refusal, exit 2);
2. the JSONL trace sink is created *before any dispatch* (design A05: real
   execution has nowhere to go without it -- sink creation failure stops the
   run as a persistence failure);
3. preflight runs inside a supervised worker (read-only probes; the parent
   process stays driver-free) and a probe FAIL stops the run before any
   attempt (environment unsatisfied, exit 3);
4. per case: reserve evidence budget -> seal ``request.json`` -> dispatch
   ``prepare``/``execute`` to the worker -> seal expectation/evidence/
   observations/terminal -> compare (D2 gates) -> seal ``comparison.json``
   *before* the next dispatch decision (evidence-before-decision ordering);
5. candidates are recorded only; replay/reduce are separate commands
   (design 6.3.1: ``run`` does not start long reductions by default).

Safety semantics: any dispatcher failure without salvageable evidence, an
UNKNOWN termination or a FAILED cleanup trips the :class:`QuarantineLatch`
(zero further dispatch) and maps to exit 1.  Evidence budget exhaustion
stops the run as a persistence failure (exit 1 territory per the Phase 5
decision; the design's exit-3 "budget exhausted" row is read as the D2
comparison/replay budgets, while a full evidence disk is an operational
fault per design 6.5).  Cooperative user cancellation bounds the in-flight
attempt, seals the partial manifest and maps to exit 130.

``exit_code_for`` is the pure outranking table (design 6.3.3): usage (2) >
unsafe termination (1) > persistence failure (1) > user cancel (130) >
incomplete/unsatisfied (3) > complete (0, or 4 with at least one candidate).

Evidence streaming (design 6.6): after an attempt's evidence and terminal
are sealed, the runner pulls the worker port's stage observations and raw
payload side table over bounded IPC pages.  Payload bytes are published into
the content-addressed payload store; the observations file is the JSONL of
the frozen ``StageObservation`` documents.  A pull that fails or a page
stream that disagrees with its declared total trips the quarantine latch --
incomplete evidence never reads as a completed attempt.

Worker-side configuration (design 6.3.2): the child environment carries the
secrets-free target document plus the one password variable (never an IPC
payload); the supervisor re-adds exactly those names via
``env_passthrough``.

Import discipline: driver-free at import; adapter imports stay inside the
worker process.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional, Protocol, Sequence, Tuple

from ..contracts.case import CasePayload, ContractError
from ..contracts.codec import canonical_json, case_id_of, decode_case_payload, parse_strict_json
from ..generation.bundle import case_doc_bytes
from ..contracts.execution import (
    ATTEMPT_BUDGET_MS,
    AttemptRequest,
    Control,
    ControlCancelled,
    CleanupState,
    ExecutionOrder,
    ExecutionPortError,
    MAX_RESULT_BYTES,
    QueryStatus,
    SessionProfile,
    TerminationState,
    TransactionIsolation,
    default_control,
    dump_attempt_expectation,
    dump_attempt_request,
    dump_execution_evidence,
    load_attempt_expectation,
    load_attempt_request,
    load_execution_evidence,
    decode_terminal_receipt,
)
from ..contracts.oracle import (
    ORACLE_VERSION,
    COMPARISON_DEADLINE_MS,
    CandidateInput,
    Comparison,
    ComparisonBudget,
    ComparisonStatus,
    ReplayOutcome,
    ReplayPolicy,
    ReplayResult,
    ReductionOutcome,
    ReductionPolicy,
    ReductionResult,
    dump_comparison,
    dump_replay_result,
    dump_reduction_result,
    load_comparison,
)
from ..contracts.runner import (
    RUNNER_EVIDENCE_PROFILE,
    RUNNER_SCHEMA_VERSION,
    EnvironmentManifest,
    OwnershipEventKind,
    ProbeOutcome,
    RunnerCommand,
    RunnerManifest,
    RunnerStatus,
    StageObservation,
    decode_stage_observation,
    dump_stage_observation,
    dump_target_config,
)
from ..oracle.gates import ResultContractViolation, compare_case
from ..reduction.engine import reduce_candidate
from ..reduction.replay import attempt_reserve_hint, replay_candidate
from ..reduction.trace import JsonlTraceSink, TraceError
from .cancellation import CancelCoordinator  # noqa: F401 (re-exported seam)
from .evidence import (
    EVIDENCE_BUDGET_DEFAULT,
    ENVIRONMENT_NAME,
    MANIFEST_NAME,
    EvidenceBudgetExceeded,
    EvidenceError,
    EvidencePathError,
    EvidenceWriter,
)
from .handlers import (
    ATTEMPT_WORKER_MODULE,
    WORKER_TARGET_ENV,
    decode_environment_payload,
    decode_failure_payload,
)
from .naming import TokenSource, new_attempt_token, new_run_token
from .ownership import OWNERSHIP_JOURNAL_FILE_NAME, OwnershipJournal, QuarantineLatch
from .supervisor import SupervisorError, WorkerSupervisor, default_child_env
from . import ipc

__all__ = [
    "TOOL_VERSION",
    "RUN_WALL_CLOCK_S",
    "RunOptions",
    "RunOutcome",
    "CaseInputError",
    "Dispatcher",
    "DispatcherError",
    "WorkerDispatcher",
    "dispatcher_env_for",
    "dispatcher_env_passthrough",
    "exit_code_for",
    "replay_exit_code",
    "reduce_exit_code",
    "load_case_bundle",
    "load_attempt_documents",
    "replay_candidate_documents",
    "reduce_candidate_documents",
    "RunController",
]

TOOL_VERSION = "0.1.0"  # pyproject project.version
RUN_WALL_CLOCK_S = 600.0  # design 6.4.6 run wall-clock default

RUNNER_SCHEMA_VERSION_STR = str(RUNNER_SCHEMA_VERSION)
CASE_SCHEMA_VERSION_STR = "1"  # contracts.case.CASE_SCHEMA_VERSION
EXECUTION_SCHEMA_VERSION_STR = "1"  # contracts.execution.EXECUTION_SCHEMA_VERSION
GENERATION_MANIFEST_NAME = "generation-manifest.json"
CASES_DIRNAME = "cases"
CASE_DOC_NAME = "case.json"
CANCEL_GRACE_S = 5.0  # contracts.execution.CANCEL_GRACE_MS


class CaseInputError(ContractError):
    """The case bundle (or an attempt directory) is not usable; exit 2."""


class DispatcherError(ExecutionPortError):
    """A dispatcher/transport failure carrying any salvage documents."""


def _dump_terminal(receipt: TerminalReceipt) -> bytes:
    """Canonical terminal-receipt bytes (no dump helper in the frozen
    contracts module)."""
    return canonical_json(receipt.to_obj())


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _unb64(value: object, what: str) -> bytes:
    import base64

    if not isinstance(value, str):
        raise DispatcherError(f"worker reply is missing {what}")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001 - protocol failure, never a hang
        raise DispatcherError(f"worker reply {what} is not valid base64") from exc


def _page_total(payload: dict) -> int:
    total = payload.get("total")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        raise DispatcherError("worker evidence reply has no valid page total")
    return total


def _decode_observation_page(data: bytes) -> list:
    """Decode one observations page; every item must satisfy the frozen
    ``StageObservation`` contract (worker output is untrusted evidence)."""
    page = parse_strict_json(data)
    if not isinstance(page, list):
        raise DispatcherError("worker observations page is not a JSON list")
    return [
        decode_stage_observation(item, "worker stage observation") for item in page
    ]


def _decode_payload_page(data: bytes) -> list:
    """Decode one payload page (``[ref, base64 bytes]`` entries)."""
    import base64 as _base64

    page = parse_strict_json(data)
    if not isinstance(page, list):
        raise DispatcherError("worker payload page is not a JSON list")
    items: list = []
    for entry in page:
        if (
            not isinstance(entry, list)
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or not entry[0]
            or not isinstance(entry[1], str)
        ):
            raise DispatcherError("worker payload page entry is not [ref, base64]")
        try:
            data_bytes = _base64.b64decode(entry[1], validate=True)
        except Exception as exc:  # noqa: BLE001 - protocol failure
            raise DispatcherError(
                f"worker payload bytes for {entry[0]!r} are not valid base64"
            ) from exc
        items.append((entry[0], data_bytes))
    return items


# --------------------------------------------------------------------------
# Dispatcher: ExecutionPort-shaped adapter over the supervised worker path
# --------------------------------------------------------------------------


class Dispatcher(Protocol):
    """The controller's execution boundary: the frozen :class:`ExecutionPort`
    shape plus a lifecycle ``close`` and the design-6.6 evidence streaming
    (stage observations and the raw payload side table, pulled in bounded
    pages after the attempt's evidence is sealed)."""

    def prepare(self, request: AttemptRequest, control: Control): ...

    def execute(self, request: AttemptRequest, expectation, control: Control): ...

    def cancel_and_wait(self, attempt_id: str, grace_seconds: float): ...

    def observations(self, attempt_id: str) -> Sequence[StageObservation]: ...

    def payloads(self, attempt_id: str) -> Mapping[str, bytes]: ...

    def close(self) -> None: ...


def dispatcher_env_for(config) -> dict:
    """Child env for attempt workers: the minimal supervisor set plus exactly
    the secrets-free worker target document and the one password variable
    named by ``config.password_env``.  Both travel only through the
    environment (never an IPC payload); ``default_child_env`` strips them
    from the child environment, so callers must pass the names from
    :func:`dispatcher_env_passthrough` to the supervisor."""
    env = default_child_env()
    password = os.environ.get(config.password_env)
    if password is not None:
        env[config.password_env] = password
    env[WORKER_TARGET_ENV] = dump_target_config(config).decode("utf-8")
    return env


def dispatcher_env_passthrough(config) -> tuple[str, ...]:
    """The variable names the supervisor must re-add after filtering."""
    return (config.password_env, WORKER_TARGET_ENV)


class WorkerDispatcher:
    """One attempt worker subprocess per dispatcher instance.

    Speaks real ``runner.ipc`` envelopes with the worker's ``EXEC`` handler
    (:mod:`mtsql_typecheck.runner.handlers`): ``op=prepare``/``execute``/
    ``cancel``/``preflight`` plus the evidence-paging ``op=observations``/
    ``op=payloads`` pulls.  Structured port failures arrive as a
    ``failure`` payload and are re-raised as :class:`DispatcherError` with
    the salvage evidence/terminal documents; transport failures and worker
    ERROR envelopes become :class:`DispatcherError` without salvage.  The
    class also satisfies the D2 ``ExecutionPort`` protocol shape, so the
    same object can serve as the replay/reduction executor.
    """

    # Bounded evidence-pull page parameters (design 6.4.6); each reply stays
    # far inside the IPC MAX_MESSAGE_BYTES envelope.
    _OBSERVATIONS_PAGE = 32
    _PAYLOAD_PAGE_BUDGET = 64 * 1024

    def __init__(self, *, supervisor: WorkerSupervisor) -> None:
        self._supervisor = supervisor
        self._closed = False

    @classmethod
    def spawn(
        cls,
        *,
        env: Optional[Mapping[str, str]] = None,
        env_passthrough: tuple[str, ...] = (),
        worker_module: str = ATTEMPT_WORKER_MODULE,
        startup_deadline_s: float = 10.0,
    ) -> "WorkerDispatcher":
        supervisor = WorkerSupervisor(
            env=env,
            env_passthrough=env_passthrough,
            worker_module=worker_module,
            startup_deadline_s=startup_deadline_s,
        )
        supervisor.start()
        return cls(supervisor=supervisor)

    # -- rpc -----------------------------------------------------------------

    def _rpc(self, payload: dict, control: Optional[Control]) -> dict:
        if self._closed:
            raise DispatcherError("worker dispatcher is closed")
        try:
            envelope = self._supervisor.connection.request("EXEC", payload, control)
        except ipc.IpcError as exc:
            raise DispatcherError(f"worker transport failure: {exc}") from exc
        except SupervisorError as exc:
            raise DispatcherError(f"worker supervision failure: {exc}") from exc
        if envelope.kind == "ERROR":
            raise DispatcherError(
                f"worker refused op {payload.get('op')!r}: "
                f"{envelope.payload.get('message', '')}"
            )
        return envelope.payload

    def _raise_failure(self, payload: dict, fallback: str) -> "DispatcherError":
        failure = decode_failure_payload(payload) or {}
        return DispatcherError(
            failure.get("message", fallback),
            evidence=failure.get("evidence"),
            terminal=failure.get("terminal"),
        )

    # -- ExecutionPort shape (plus the preflight op) --------------------------

    def preflight(self, config, control: Control) -> EnvironmentManifest:
        """Run the read-only environment probes inside this worker."""
        payload = self._rpc(
            {
                "op": "preflight",
                "target": dump_target_config(config).decode("utf-8"),
            },
            control,
        )
        if "failure" in payload or "error" in payload:
            if "error" in payload:
                raise DispatcherError(str(payload["error"]))
            raise self._raise_failure(payload, "preflight failed")
        return decode_environment_payload(payload)

    def prepare(self, request: AttemptRequest, control: Control):
        payload = self._rpc(
            {"op": "prepare", "request_b64": _b64(dump_attempt_request(request))}, control
        )
        if "failure" in payload:
            raise self._raise_failure(payload, "prepare failed")
        return load_attempt_expectation(_unb64(payload.get("expectation_b64"), "expectation_b64"))

    def execute(self, request: AttemptRequest, expectation, control: Control):
        payload = self._rpc(
            {
                "op": "execute",
                "request_b64": _b64(dump_attempt_request(request)),
                "expectation_b64": _b64(dump_attempt_expectation(expectation)),
            },
            control,
        )
        if "failure" in payload:
            raise self._raise_failure(payload, "execute failed")
        return load_execution_evidence(_unb64(payload.get("evidence_b64"), "evidence_b64"))

    def cancel_and_wait(self, attempt_id: str, grace_seconds: float):
        payload = self._rpc(
            {"op": "cancel", "attempt_id": attempt_id, "grace_ms": int(grace_seconds * 1000)},
            None,
        )
        if "failure" in payload:
            raise self._raise_failure(payload, "cancel failed")
        terminal_b64 = payload.get("terminal_b64")
        if terminal_b64 is None:
            return None
        return decode_terminal_receipt(parse_strict_json(_unb64(terminal_b64, "terminal_b64")))

    # -- evidence streaming (design 6.6) --------------------------------------

    def observations(self, attempt_id: str) -> list:
        """Pull the attempt's stage observations over bounded IPC pages.

        Every decoded item is re-validated against the frozen
        ``StageObservation`` contract before it is returned; a page stream
        that disagrees with the declared total fails closed.
        """
        items: list = []
        offset = 0
        while True:
            payload = self._rpc(
                {"op": "observations", "attempt_id": attempt_id, "offset": offset},
                None,
            )
            if "failure" in payload:
                raise self._raise_failure(payload, "observations pull failed")
            total = _page_total(payload)
            batch = _decode_observation_page(_unb64(payload.get("items_b64"), "items_b64"))
            if offset + len(batch) > total:
                raise DispatcherError(
                    "worker observations page stream exceeds the declared total"
                )
            items.extend(batch)
            offset += len(batch)
            if not batch:
                if offset < total:
                    raise DispatcherError(
                        "worker observations page stream ended before the declared total"
                    )
                return items

    def payloads(self, attempt_id: str) -> Mapping[str, bytes]:
        """Pull the attempt's raw payload side table over bounded pages."""
        payloads: dict[str, bytes] = {}
        offset = 0
        while True:
            payload = self._rpc(
                {
                    "op": "payloads",
                    "attempt_id": attempt_id,
                    "offset": offset,
                    "byte_budget": self._PAYLOAD_PAGE_BUDGET,
                },
                None,
            )
            if "failure" in payload:
                raise self._raise_failure(payload, "payload pull failed")
            total = _page_total(payload)
            batch = _decode_payload_page(_unb64(payload.get("items_b64"), "items_b64"))
            if offset + len(batch) > total:
                raise DispatcherError(
                    "worker payload page stream exceeds the declared total"
                )
            for ref, data in batch:
                if ref in payloads:
                    raise DispatcherError(f"worker payload stream repeated ref {ref!r}")
                payloads[ref] = data
            offset += len(batch)
            if not batch:
                if offset < total:
                    raise DispatcherError(
                        "worker payload page stream ended before the declared total"
                    )
                return payloads

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._supervisor.shutdown()
        except SupervisorError:
            pass
        finally:
            self._supervisor.close()


# --------------------------------------------------------------------------
# Exit codes (pure outranking table) and outcome
# --------------------------------------------------------------------------


def exit_code_for(
    manifest: Optional[RunnerManifest],
    *,
    cancelled: bool = False,
    unsafe: bool = False,
    persistence_failure: bool = False,
    usage_error: bool = False,
) -> int:
    """Design 6.3.3 outranking: usage (2) > unsafe termination (1) >
    persistence failure (1) > user cancel (130) > incomplete (3) >
    complete (0, or 4 with at least one candidate)."""
    if usage_error:
        return 2
    if unsafe:
        return 1
    if persistence_failure:
        return 1
    if cancelled:
        return 130
    if manifest is None:
        return 1
    if manifest.status is RunnerStatus.COMPLETE:
        return 4 if manifest.candidate > 0 else 0
    return 3


def replay_exit_code(result: ReplayResult) -> int:
    """Design 6.3.3: REPRODUCED -> 4; operational/safety failure -> 1;
    UNSTABLE/NOT_REPLAYED -> 3."""
    if result.operational_failure:
        return 1
    if result.outcome is ReplayOutcome.REPRODUCED:
        return 4
    return 3


def reduce_exit_code(result: ReductionResult) -> int:
    """Design 6.3.3: search finished with a valid counterexample -> 4;
    FAILED (operational) -> 1; a budget-stopped partial search -> 3."""
    if result.outcome is ReductionOutcome.FAILED:
        return 1
    if result.search_complete and result.outcome in (
        ReductionOutcome.REDUCED,
        ReductionOutcome.UNCHANGED,
    ):
        return 4
    return 3


@dataclass(frozen=True)
class RunOptions:
    evidence_budget_bytes: int = EVIDENCE_BUDGET_DEFAULT
    run_wall_clock_s: float = RUN_WALL_CLOCK_S
    cases_limit: Optional[int] = None
    startup_deadline_s: float = 10.0
    dispatcher_env: Optional[Mapping[str, str]] = None
    cancelled: Callable[[], bool] = lambda: False


@dataclass(frozen=True)
class RunOutcome:
    manifest: Optional[RunnerManifest]
    cancelled: bool = False
    unsafe: bool = False
    persistence_failure: bool = False
    usage_error: bool = False
    message: Optional[str] = None

    def exit_code(self) -> int:
        return exit_code_for(
            self.manifest,
            cancelled=self.cancelled,
            unsafe=self.unsafe,
            persistence_failure=self.persistence_failure,
            usage_error=self.usage_error,
        )


# --------------------------------------------------------------------------
# Case bundle / attempt document loading
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseRef:
    case_id: str
    payload: CasePayload


def load_case_bundle(bundle_dir: Path, *, limit: Optional[int] = None) -> Tuple[CaseRef, ...]:
    """Strictly load ``cases/<case_id>/case.json`` documents from a D1 bundle.

    Raises :class:`CaseInputError` (exit 2) for a missing/corrupt manifest or
    case document, a case_id mismatch, or an empty bundle (zero comparable
    cases is never a pass, so an empty bundle is an input refusal).
    """
    bundle_dir = Path(bundle_dir)
    manifest_path = bundle_dir / GENERATION_MANIFEST_NAME
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise CaseInputError(f"cannot read {GENERATION_MANIFEST_NAME}: {exc}") from exc
    try:
        document = parse_strict_json(raw)
    except ContractError as exc:
        raise CaseInputError(f"{GENERATION_MANIFEST_NAME} is not strict JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise CaseInputError(f"{GENERATION_MANIFEST_NAME} must contain a JSON object")

    cases_dir = bundle_dir / CASES_DIRNAME
    if not cases_dir.is_dir():
        raise CaseInputError(f"bundle has no {CASES_DIRNAME!r} directory: {str(cases_dir)!r}")
    try:
        entries = sorted(entry.name for entry in os.scandir(cases_dir) if entry.is_dir())
    except OSError as exc:
        raise CaseInputError(f"cannot list the cases directory: {exc}") from exc
    refs: list[CaseRef] = []
    for name in entries:
        if name.startswith("."):
            continue
        if limit is not None and len(refs) >= limit:
            break
        case_path = cases_dir / name / CASE_DOC_NAME
        try:
            case_raw = case_path.read_bytes()
        except OSError as exc:
            raise CaseInputError(f"cannot read {str(case_path)!r}: {exc}") from exc
        try:
            case_doc = parse_strict_json(case_raw)
        except ContractError as exc:
            raise CaseInputError(f"{str(case_path)!r} is not strict JSON: {exc}") from exc
        if not isinstance(case_doc, dict) or set(case_doc) != {"case_id", "payload"}:
            raise CaseInputError(f"{str(case_path)!r} must hold exactly case_id and payload")
        if case_doc["case_id"] != name:
            raise CaseInputError(
                f"case_id {case_doc['case_id']!r} does not match directory {name!r}"
            )
        try:
            payload = decode_case_payload(case_doc["payload"], f"case {name!r}")
        except ContractError as exc:
            raise CaseInputError(f"case {name!r} payload rejected: {exc}") from exc
        if case_id_of(payload) != name:
            raise CaseInputError(f"case {name!r}: payload derives a different case_id")
        refs.append(CaseRef(case_id=name, payload=payload))
    if not refs:
        raise CaseInputError("bundle contains zero cases; nothing to execute")
    return tuple(refs)


def _both_sides_complete(evidence) -> bool:
    """Full two-sided SELECT completion (design 6.6 ``completed`` counter)."""
    a, b = evidence.a_query, evidence.b_query
    return (
        a is not None
        and b is not None
        and a.status is QueryStatus.COMPLETE
        and b.status is QueryStatus.COMPLETE
    )


# --------------------------------------------------------------------------
# Controller
# --------------------------------------------------------------------------


@dataclass
class _Counts:
    requested: int = 0
    completed: int = 0
    match: int = 0
    candidate: int = 0
    inconclusive: int = 0
    not_applicable: int = 0
    leftover_objects: int = 0

    def as_kwargs(self) -> dict:
        return {
            "requested": self.requested,
            "completed": self.completed,
            "comparable": self.match + self.candidate,
            "match": self.match,
            "candidate": self.candidate,
            "inconclusive": self.inconclusive,
            "not_applicable": self.not_applicable,
            "leftover_objects": self.leftover_objects,
        }


class RunController:
    """Online ``run`` loop over a D1 case bundle (see module docstring)."""

    def __init__(
        self,
        *,
        config,
        bundle_dir: Path,
        output: Path,
        options: RunOptions = RunOptions(),
        clock: Callable[[], float] = time.monotonic,
        token_source: Optional[TokenSource] = None,
        dispatcher_factory: Optional[Callable[[AttemptRequest], Dispatcher]] = None,
        preflight_fn: Optional[Callable[[object, Control], EnvironmentManifest]] = None,
    ) -> None:
        self._config = config
        self._bundle_dir = Path(bundle_dir)
        self._output = Path(output)
        self._options = options
        self._clock = clock
        self._token_source = token_source
        if dispatcher_factory is not None:
            self._dispatcher_factory = dispatcher_factory
        else:
            env = (
                options.dispatcher_env
                if options.dispatcher_env is not None
                else dispatcher_env_for(config)
            )
            passthrough = (
                ()
                if options.dispatcher_env is not None
                else dispatcher_env_passthrough(config)
            )
            startup = options.startup_deadline_s
            self._dispatcher_factory = lambda request: WorkerDispatcher.spawn(
                env=env,
                env_passthrough=passthrough,
                startup_deadline_s=startup,
            )
        self._preflight_fn = preflight_fn if preflight_fn is not None else self._worker_preflight

    # -- preflight -----------------------------------------------------------

    def _worker_preflight(self, config, control: Control) -> EnvironmentManifest:
        """Preflight inside a supervised worker; the parent stays driver-free."""
        dispatcher = WorkerDispatcher.spawn(
            env=dispatcher_env_for(config),
            env_passthrough=dispatcher_env_passthrough(config),
            startup_deadline_s=self._options.startup_deadline_s,
        )
        try:
            return dispatcher.preflight(config, control)
        finally:
            dispatcher.close()

    # -- run -------------------------------------------------------------------

    def run(self) -> RunOutcome:
        try:
            writer = EvidenceWriter(self._output, self._options.evidence_budget_bytes)
        except EvidencePathError as exc:
            return RunOutcome(manifest=None, usage_error=True, message=str(exc))
        # A05: real execution forces the sink; it is created before any
        # dispatch and its failure stops the run (persistence failure).
        try:
            sink = JsonlTraceSink(writer.root, self._options.evidence_budget_bytes)
        except (TraceError, OSError) as exc:
            manifest = self._sealed_manifest(
                writer,
                _Counts(),
                run_id="run-unknown",
                sanitized_config_hash="0" * 64,
                status=RunnerStatus.ABORTED,
                stop_reason="EVIDENCE_WRITE_FAILED",
            )
            return RunOutcome(manifest, persistence_failure=True, message=str(exc))
        try:
            return self._run_body(writer, sink)
        finally:
            sink.close()

    def _run_body(self, writer: EvidenceWriter, sink: JsonlTraceSink) -> RunOutcome:
        del sink  # the run loop persists attempt evidence via the writer; the
        # forced sink stands guard over the persistence precondition (A05).
        run_token = new_run_token(self._token_source)
        run_id = f"run-{run_token}"
        control = Control(
            clock=self._clock,
            deadline=self._clock() + self._options.run_wall_clock_s,
            cancelled=self._options.cancelled,
        )
        try:
            cases = load_case_bundle(self._bundle_dir, limit=self._options.cases_limit)
        except CaseInputError as exc:
            manifest = self._sealed_manifest(
                writer, _Counts(), run_id, "0" * 64, RunnerStatus.ABORTED, "CASE_INPUT_INVALID"
            )
            return RunOutcome(manifest, usage_error=True, message=str(exc))

        try:
            environment = self._preflight_fn(self._config, control)
        except (DispatcherError, ContractError) as exc:
            manifest = self._sealed_manifest(
                writer, _Counts(), run_id, "0" * 64, RunnerStatus.ABORTED, "PREFLIGHT_FAILED"
            )
            return RunOutcome(manifest, persistence_failure=True, message=str(exc))
        if any(probe.outcome is ProbeOutcome.FAIL for probe in environment.probes):
            try:
                writer.write_environment(environment)
            except EvidenceError:
                pass
            manifest = self._sealed_manifest(
                writer,
                _Counts(),
                run_id,
                environment.sanitized_config_hash,
                RunnerStatus.ABORTED,
                "ENVIRONMENT_UNSATISFIED",
            )
            return RunOutcome(manifest, message="environment probes failed")
        try:
            writer.write_environment(environment)
            journal = OwnershipJournal(writer.root / OWNERSHIP_JOURNAL_FILE_NAME, run_id=run_id)
        except (EvidenceError, ContractError, OSError) as exc:
            manifest = self._sealed_manifest(
                writer,
                _Counts(),
                run_id,
                environment.sanitized_config_hash,
                RunnerStatus.ABORTED,
                "EVIDENCE_WRITE_FAILED",
            )
            return RunOutcome(manifest, persistence_failure=True, message=str(exc))
        journal.append(
            OwnershipEventKind.RUN_LOCK_ACQUIRED,
            server_uuid=environment.server_uuid,
            token=run_token,
        )

        latch = QuarantineLatch()
        counts = _Counts()
        stop: Optional[str] = None
        cancelled = False
        unsafe = False
        persistence_failure = False
        attempt_refs: list = []

        for index, case in enumerate(cases):
            if not latch.allow_dispatch():
                stop = "QUARANTINED"
                unsafe = True
                break
            if self._options.cancelled():
                stop = "CANCELLED"
                cancelled = True
                break
            if control.expired():
                stop = "RUN_TIME_BUDGET"
                break
            attempt_token = new_attempt_token(self._token_source)
            attempt_id = f"at-{index + 1:06d}-{attempt_token}"
            result = self._run_attempt(
                writer=writer,
                journal=journal,
                latch=latch,
                request=self._build_request(
                    request_run_id=run_id,
                    attempt_id=attempt_id,
                    environment=environment,
                    payload=case.payload,
                ),
                attempt_token=attempt_token,
                control=control,
                counts=counts,
                attempt_refs=attempt_refs,
            )
            if result == "budget":
                stop = "EVIDENCE_BUDGET_EXCEEDED"
                persistence_failure = True
                break
            if result == "quarantined":
                stop = "QUARANTINED"
                unsafe = True
                break
            if result == "cancel":
                stop = "CANCELLED"
                cancelled = True
                break

        journal.append(OwnershipEventKind.RUN_SEALED)
        status = RunnerStatus.COMPLETE
        if stop is not None:
            status = RunnerStatus.ABORTED if (cancelled or unsafe) else RunnerStatus.PARTIAL
        manifest = self._sealed_manifest(
            writer,
            counts,
            run_id,
            environment.sanitized_config_hash,
            status,
            stop,
            refs=tuple(attempt_refs),
        )
        journal.close()
        return RunOutcome(
            manifest,
            cancelled=cancelled,
            unsafe=unsafe,
            persistence_failure=persistence_failure,
        )

    # -- per-attempt -----------------------------------------------------------

    def _build_request(
        self, *, request_run_id: str, attempt_id: str, environment, payload: CasePayload
    ) -> AttemptRequest:
        return AttemptRequest(
            run_id=request_run_id,
            attempt_id=attempt_id,
            payload=payload,
            target_environment=environment.observed_environment,
            session_profile=SessionProfile(True, TransactionIsolation.REPEATABLE_READ),
            execution_order=ExecutionOrder.AB,
            result_row_budget=1024,
            result_byte_budget=MAX_RESULT_BYTES,
            time_budget_ms=ATTEMPT_BUDGET_MS,
            synthetic=False,
        )

    def _run_attempt(
        self,
        *,
        writer: EvidenceWriter,
        journal: OwnershipJournal,
        latch: QuarantineLatch,
        request: AttemptRequest,
        attempt_token: str,
        control: Control,
        counts: _Counts,
        attempt_refs: list,
    ) -> str:
        """Execute one attempt; returns "ok", "budget", "quarantined" or "cancel".

        Evidence-before-decision ordering (design 6.4.6): the request,
        expectation, execution evidence and comparison of this attempt are
        all sealed before the caller decides anything about the next
        dispatch.
        """
        request_doc = dump_attempt_request(request)
        try:
            writer.reserve(attempt_reserve_hint(len(request_doc)))
            writer.write_attempt_document(request.attempt_id, "request.json", request_doc)
        except EvidenceBudgetExceeded:
            return "budget"
        journal.append(
            OwnershipEventKind.ATTEMPT_ALLOCATED,
            attempt_id=request.attempt_id,
            token=attempt_token,
        )
        # Content-addressed payload store (design 6.6): the case document is
        # published once per distinct content before any dispatch decision.
        try:
            writer.publish_payload(case_doc_bytes(request.payload, case_id_of(request.payload)))
        except EvidenceBudgetExceeded:
            return "budget"
        counts.requested += 1

        dispatcher = self._dispatcher_factory(request)
        evidence = None
        salvage_terminal = None
        dispatch_failed: Optional[ExecutionPortError] = None
        try:
            attempt_control = control.child(request.time_budget_ms / 1000)
            try:
                expectation = dispatcher.prepare(request, attempt_control)
            except ControlCancelled:
                self._bounded_cancel(dispatcher, request, writer, salvage_terminal)
                return "cancel"
            except ExecutionPortError as exc:
                dispatch_failed = exc
            else:
                writer.write_attempt_document(
                    request.attempt_id, "expectation.json", dump_attempt_expectation(expectation)
                )
                if self._options.cancelled():
                    self._bounded_cancel(dispatcher, request, writer, salvage_terminal)
                    return "cancel"
                try:
                    evidence = dispatcher.execute(request, expectation, attempt_control)
                except ControlCancelled:
                    self._bounded_cancel(dispatcher, request, writer, salvage_terminal)
                    return "cancel"
                except ExecutionPortError as exc:
                    dispatch_failed = exc

            if dispatch_failed is not None:
                evidence = getattr(dispatch_failed, "evidence", None)
                salvage_terminal = getattr(dispatch_failed, "terminal", None)
                if evidence is not None:
                    try:
                        writer.write_attempt_document(
                            request.attempt_id,
                            "execution-evidence.json",
                            dump_execution_evidence(evidence),
                        )
                    except EvidenceBudgetExceeded:
                        return "budget"
                # Bounded cancellation of the in-flight worker attempt (A05).
                terminal = self._bounded_cancel(dispatcher, request, writer, salvage_terminal)
                if evidence is None:
                    # No salvageable evidence: the attempt state is unknown.
                    journal.append(
                        OwnershipEventKind.TERMINATION_UNKNOWN, attempt_id=request.attempt_id
                    )
                    if terminal is None or terminal.termination is TerminationState.UNKNOWN:
                        latch.trip(
                            f"dispatcher failure without salvage: {str(dispatch_failed)[:96]}"
                        )
                        return "quarantined"
                    counts.inconclusive += 1
                    return "ok"
                if (
                    terminal is None
                    or terminal.termination is TerminationState.UNKNOWN
                    or terminal.cleanup is CleanupState.FAILED
                ):
                    journal.append(
                        OwnershipEventKind.TERMINATION_UNKNOWN, attempt_id=request.attempt_id
                    )
                    latch.trip(
                        f"dispatcher failure with unconfirmed cleanup: {str(dispatch_failed)[:96]}"
                    )
                    return "quarantined"

            if evidence is None:  # pragma: no cover - defensive
                latch.trip("internal: no evidence and no recorded dispatch failure")
                return "quarantined"

            writer.write_attempt_document(
                request.attempt_id, "execution-evidence.json", dump_execution_evidence(evidence)
            )
            terminal = evidence.terminal
            if terminal is not None:
                writer.write_attempt_document(
                    request.attempt_id, "terminal.json", _dump_terminal(terminal)
                )
                if terminal.cleanup is not CleanupState.DONE:
                    counts.leftover_objects += len(terminal.owned_objects)
                if (
                    terminal.termination is TerminationState.UNKNOWN
                    or terminal.cleanup is CleanupState.FAILED
                ):
                    journal.append(
                        OwnershipEventKind.TERMINATION_UNKNOWN, attempt_id=request.attempt_id
                    )
                    latch.trip("attempt terminated with unconfirmed state")
                    return "quarantined"
            # Evidence streaming (design 6.6): the worker port records stage
            # observations and a raw payload side table in memory; the runner
            # pulls them over bounded IPC pages and persists them.  Payload
            # bytes go into the content-addressed payload store (an
            # observation's sql_ref resolves by publishing the payload whose
            # bytes hash to the recorded sql_hash); the observations file is
            # the JSONL of the frozen StageObservation documents, verbatim.
            try:
                for data in dispatcher.payloads(request.attempt_id).values():
                    writer.publish_payload(data)
                lines = bytearray()
                for observation in dispatcher.observations(request.attempt_id):
                    lines += dump_stage_observation(observation)
                    lines += b"\n"
                writer.write_attempt_document(
                    request.attempt_id, "observations.jsonl", bytes(lines)
                )
            except DispatcherError as exc:
                # The observations are part of the attempt's evidence: an
                # incomplete pull must never look like a completed attempt.
                journal.append(
                    OwnershipEventKind.TERMINATION_UNKNOWN, attempt_id=request.attempt_id
                )
                latch.trip(f"observations pull failed: {str(exc)[:96]}")
                return "quarantined"

            if _both_sides_complete(evidence):
                counts.completed += 1
            comparison = self._compare(request, evidence, control)
            writer.write_attempt_document(
                request.attempt_id, "comparison.json", dump_comparison(comparison)
            )
            attempt_refs.append(
                (f"attempt:{request.attempt_id}", f"attempts/{request.attempt_id}/comparison.json")
            )
            if comparison.status is ComparisonStatus.MATCH:
                counts.match += 1
            elif comparison.status is ComparisonStatus.MISMATCH_CANDIDATE:
                counts.candidate += 1
            elif comparison.status is ComparisonStatus.INCONCLUSIVE:
                counts.inconclusive += 1
            else:
                counts.not_applicable += 1
            return "ok"
        except EvidenceBudgetExceeded:
            return "budget"
        finally:
            dispatcher.close()

    def _bounded_cancel(self, dispatcher, request, writer, salvage_terminal):
        """Best-effort bounded cancellation; returns the receipt or None."""
        try:
            terminal = dispatcher.cancel_and_wait(request.attempt_id, CANCEL_GRACE_S)
        except ExecutionPortError:
            return salvage_terminal
        if terminal is not None:
            try:
                writer.write_attempt_document(
                    request.attempt_id, "terminal.json", _dump_terminal(terminal)
                )
            except EvidenceBudgetExceeded:
                pass
        return terminal

    def _compare(self, request: AttemptRequest, evidence, control: Control) -> Comparison:
        try:
            return compare_case(
                request,
                evidence.expectation,
                evidence,
                ComparisonBudget(),
                control.child(COMPARISON_DEADLINE_MS / 1000),
            )
        except ResultContractViolation as exc:
            return exc.comparison

    # -- manifest ------------------------------------------------------------

    def _sealed_manifest(
        self,
        writer: EvidenceWriter,
        counts: _Counts,
        run_id: str,
        sanitized_config_hash: str,
        status: RunnerStatus,
        stop_reason: Optional[str],
        refs: Tuple[Tuple[str, str], ...] = (),
    ) -> Optional[RunnerManifest]:
        """Assemble and persist the terminating manifest (best effort).

        Only refs whose file actually exists are recorded; a manifest never
        points at evidence that was not persisted.
        """
        ref_names = (
            (ENVIRONMENT_NAME, "environment"),
            (OWNERSHIP_JOURNAL_FILE_NAME, "ownership"),
            ("trace.jsonl", "trace"),
        )
        all_refs: list = []
        for filename, name in ref_names:
            if (writer.root / filename).exists():
                all_refs.append((name, filename))
        # The manifest itself is sealed by this same call, so its ref is
        # unconditional (a manifest never points at unpersisted evidence,
        # but its own document is written right below).
        all_refs.append(("runner_manifest", MANIFEST_NAME))
        all_refs.extend(refs)
        try:
            manifest = RunnerManifest(
                command=RunnerCommand.RUN,
                run_id=run_id,
                status=status,
                stop_reason=stop_reason,
                synthetic=False,
                evidence_profile=RUNNER_EVIDENCE_PROFILE,
                tool_version=TOOL_VERSION,
                contract_versions=(
                    ("case", CASE_SCHEMA_VERSION_STR),
                    ("execution", EXECUTION_SCHEMA_VERSION_STR),
                    ("oracle", ORACLE_VERSION),
                    ("runner", RUNNER_SCHEMA_VERSION_STR),
                ),
                refs=tuple(all_refs),
                sanitized_config_hash=sanitized_config_hash,
                **counts.as_kwargs(),
                leftover_sessions=0,
            )
            writer.write_manifest(manifest)
            return manifest
        except (ContractError, EvidenceError, OSError):
            return None


# --------------------------------------------------------------------------
# Replay / reduction entry points (CLI replay/reduce commands)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AttemptDocuments:
    request: AttemptRequest
    expectation: object
    evidence: object
    comparison: Comparison


def load_attempt_documents(attempt_dir: Path) -> AttemptDocuments:
    """Load the four sealed documents of one attempt directory (exit-2 on
    any missing/corrupt item)."""
    attempt_dir = Path(attempt_dir)

    def _read(name: str) -> bytes:
        try:
            return (attempt_dir / name).read_bytes()
        except OSError as exc:
            raise CaseInputError(f"cannot read {name} in {str(attempt_dir)!r}: {exc}") from exc

    try:
        request = load_attempt_request(_read("request.json"))
        expectation = load_attempt_expectation(_read("expectation.json"))
        evidence = load_execution_evidence(_read("execution-evidence.json"))
        comparison = load_comparison(_read("comparison.json"))
    except ContractError as exc:
        raise CaseInputError(f"attempt documents rejected in {str(attempt_dir)!r}: {exc}") from exc
    if evidence.request_hash != request.request_hash:
        raise CaseInputError("execution evidence does not match the request hash")
    return AttemptDocuments(
        request=request, expectation=expectation, evidence=evidence, comparison=comparison
    )


def _candidate_from_documents(docs: AttemptDocuments) -> CandidateInput:
    return CandidateInput(
        payload=docs.request.payload,
        request=docs.request,
        expectation=docs.expectation,
        evidence=docs.evidence,
        comparison_hash=docs.comparison.hash,
        source="runner:attempt-documents",
    )


def replay_candidate_documents(
    attempt_dir: Path,
    *,
    executor,
    trace_sink,
    policy: Optional[ReplayPolicy] = None,
    control: Optional[Control] = None,
) -> ReplayResult:
    """Replay the candidate recorded in one attempt directory (fresh name
    maps are mandatory: design 6.2 G01 forbids cross-round object reuse)."""
    docs = load_attempt_documents(attempt_dir)
    return replay_candidate(
        _candidate_from_documents(docs),
        executor,
        trace_sink,
        policy if policy is not None else ReplayPolicy(),
        control if control is not None else default_control(),
        require_fresh_name_maps=True,
    )


def reduce_candidate_documents(
    attempt_dir: Path,
    *,
    executor,
    trace_sink,
    policy: Optional[ReductionPolicy] = None,
    control: Optional[Control] = None,
) -> ReductionResult:
    """Reduce the candidate recorded in one attempt directory (fresh name
    maps are mandatory: design 6.2 G01 forbids cross-round object reuse)."""
    docs = load_attempt_documents(attempt_dir)
    return reduce_candidate(
        _candidate_from_documents(docs),
        executor,
        trace_sink,
        policy if policy is not None else ReductionPolicy(),
        control if control is not None else default_control(),
        require_fresh_name_maps=True,
    )
