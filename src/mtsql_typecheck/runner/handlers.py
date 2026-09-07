"""Worker-side attempt command handlers (design 6.3.2/6.4.6, Phase 5).

The worker subprocess speaks ``runner.ipc`` envelopes; the parent dispatches
one ``EXEC`` request per operation and the handlers below translate the
payload dictionaries into :class:`~mtsql_typecheck.contracts.execution.
ExecutionPort` calls.  Handlers are registered through
``WorkerApp.register_handler`` (worker.py itself is untouched); they are
plain ``payload -> payload`` callables.

Operations (one ``EXEC`` kind, dispatched on ``payload["op"]``):

- ``prepare``  -> build the port for this attempt via the injected factory,
  run ``port.prepare`` and return the sealed expectation document;
- ``execute``  -> run ``port.execute`` for the already-prepared port and
  return the execution-evidence document;
- ``cancel``   -> run ``port.cancel_and_wait`` (bounded termination) and
  return the terminal receipt;
- ``preflight``-> run the read-only environment probes via the injected
  probe factory and return the environment manifest document;
- ``observations`` -> return a bounded page of the attempt's recorded
  :class:`StageObservation` documents (design 6.6 evidence streaming);
- ``payloads`` -> return a bounded page of the attempt's raw payload side
  table (``[ref, base64 bytes]`` entries; SQL text, diagnostics text, column
  metadata).

Structured port failures (``ExecutionPortError``) are returned as a
``failure`` payload carrying the salvage evidence/terminal documents so the
parent can persist partial evidence; any other exception propagates and the
worker loop turns it into an ERROR envelope (exit 1).

Documents cross the wire base64-encoded; a single message stays within the
``runner.ipc`` ``MAX_MESSAGE_BYTES`` budget -- oversized evidence fails
closed instead of being truncated, and the page budgets below keep each
reply far inside that bound.

Worker-side assembly (design 6.3.2): when the worker was started with the
target configuration in its environment (``WORKER_TARGET_ENV``, a
secrets-free serialized ``TargetConfig``; the password travels only through
its own environment variable, never an IPC payload), the default factories
build the production port via ``build_execution_port`` and the probe source
via the certified adapter.  A worker started without a target configuration
fails closed with :class:`PortFactoryNotConfigured` on first use -- it never
guesses a connection target.

Import discipline: importing this module imports neither PyMySQL nor the
adapters package (the adapter import happens inside the env factory call
bodies).
"""

from __future__ import annotations

import base64
import binascii
import os
import signal
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from ..contracts.case import ContractError
from ..contracts.execution import (
    ATTEMPT_BUDGET_MS,
    AttemptRequest,
    Control,
    dump_attempt_expectation,
    dump_execution_evidence,
    ExecutionPortError,
    load_attempt_expectation,
    load_attempt_request,
    load_execution_evidence,
    decode_terminal_receipt,
    TerminalReceipt,
)
from ..contracts.runner import (
    EnvironmentManifest,
    TargetConfig,
    dump_environment_manifest,
    load_environment_manifest,
    load_target_config,
)
from ..contracts.codec import canonical_json, parse_strict_json
from .ownership import OwnershipJournal
from .preflight import run_preflight
from . import worker as worker_loop


def _dump_terminal(receipt) -> bytes:
    return canonical_json(receipt.to_obj())


def _load_terminal(data: bytes) -> TerminalReceipt:
    return decode_terminal_receipt(parse_strict_json(data))

__all__ = [
    "ATTEMPT_WORKER_MODULE",
    "WORKER_TARGET_ENV",
    "WORKER_JOURNAL_ENV",
    "PortFactoryNotConfigured",
    "default_port_factory",
    "env_port_factory",
    "env_probe_factory",
    "make_exec_handler",
    "register_attempt_handlers",
    "attempt_worker_main",
]

#: Supervisor ``worker_module`` for attempt workers (handlers module entry).
ATTEMPT_WORKER_MODULE = "mtsql_typecheck.runner.handlers"

#: Worker startup environment: the secrets-free serialized ``TargetConfig``
#: (the password travels only under its own variable name, resolved inside
#: the worker process from ``os.environ``).  The supervisor strips unknown
#: variables from the child environment, so the parent must pass this name
#: (plus ``config.password_env``) explicitly via ``env_passthrough``.
WORKER_TARGET_ENV = "MTSQL_TC_WORKER_TARGET"

#: Optional worker startup environment: path of the run's ownership journal.
#: When unset the worker port keeps its ownership events in memory (the
#: parent's run journal remains the single-writer record).
WORKER_JOURNAL_ENV = "MTSQL_TC_WORKER_JOURNAL"

ProbeFactory = Callable[[], object]
PortFactory = Callable[[AttemptRequest], object]
Handler = Callable[[dict], dict]

_PREPARE_OPS = frozenset({"prepare", "execute", "cancel"})

#: Evidence-page budgets (design 6.4.6 diagnostics bounds): each reply stays
#: far inside the IPC ``MAX_MESSAGE_BYTES`` envelope.
_OBSERVATIONS_PAGE = 32
_MAX_PAGE_PAYLOAD_BYTES = 64 * 1024
_MAX_PAGE_BUDGET = 128 * 1024


class PortFactoryNotConfigured(ContractError):
    """The worker has no wired production port factory (fail closed)."""


def _load_worker_target() -> Optional[TargetConfig]:
    """The worker's target configuration from its startup environment.

    ``None`` when the worker was started without one; a malformed document
    fails closed with the typed refusal rather than a guessed default.
    """
    raw = os.environ.get(WORKER_TARGET_ENV)
    if not raw:
        return None
    try:
        return load_target_config(raw.encode("utf-8"))
    except ContractError as exc:
        raise PortFactoryNotConfigured(
            f"worker target configuration is invalid: {exc}"
        ) from exc


def env_port_factory() -> PortFactory:
    """Build the worker-side port factory from the startup environment.

    Per attempt the factory maps ``WORKER_TARGET_ENV`` to ``ConnectionParams``
    (the password is read from its own environment variable inside the worker)
    and assembles the production port via ``build_execution_port``
    (design 6.3.2).  The first factory call raises
    :class:`PortFactoryNotConfigured` when the worker was started without a
    target configuration.

    The ownership journal comes from ``WORKER_JOURNAL_ENV`` when set (opened
    once per run id and shared across the worker's attempts); otherwise each
    run gets an in-process sink whose events never leave the worker.
    """

    from .config import ConfigError, connection_params_from_target
    from .execution import build_execution_port

    journals: Dict[str, object] = {}

    def factory(request: AttemptRequest) -> object:
        config = _load_worker_target()
        if config is None:
            raise PortFactoryNotConfigured(
                "worker was started without a target configuration "
                f"({WORKER_TARGET_ENV} is not set); refusing to guess a "
                "connection target"
            )
        try:
            params = connection_params_from_target(config)
        except ConfigError as exc:
            raise PortFactoryNotConfigured(str(exc)) from exc
        journal = journals.get(request.run_id)
        if journal is None:
            journal_path = os.environ.get(WORKER_JOURNAL_ENV)
            if journal_path:
                journal = OwnershipJournal(Path(journal_path), run_id=request.run_id)
            else:
                from .execution import _InMemoryRunJournal

                journal = _InMemoryRunJournal(request.run_id)
            journals[request.run_id] = journal
        return build_execution_port(params=params, journal=journal)

    return factory


def env_probe_factory() -> ProbeFactory:
    """Build the worker-side preflight probe factory from the environment.

    Returns an unconnected certified adapter; ``run_preflight`` drives the
    read-only probes.  Fails closed like :func:`env_port_factory` when the
    worker has no target configuration.
    """

    def factory() -> object:
        from ..adapters.mysql80 import MySQL80Adapter
        from .config import ConfigError, connection_params_from_target

        config = _load_worker_target()
        if config is None:
            raise PortFactoryNotConfigured(
                "worker was started without a target configuration "
                f"({WORKER_TARGET_ENV} is not set); refusing to probe an "
                "unknown target"
            )
        try:
            params = connection_params_from_target(config)
        except ConfigError as exc:
            raise PortFactoryNotConfigured(str(exc)) from exc
        return MySQL80Adapter(params, charset="utf8mb4")

    return factory


def default_port_factory(request: AttemptRequest) -> object:
    """Fail-closed default for embedded use without explicit wiring.

    Production workers register :func:`env_port_factory` /
    :func:`env_probe_factory` (see :func:`attempt_worker_main`); this
    standalone default refuses so an unwired worker can never guess a
    connection target or run SQL.
    """
    del request
    raise PortFactoryNotConfigured(
        "no production execution-port factory is wired in this worker: "
        "register env_port_factory() (design 6.3.2 build_execution_port) "
        "or an explicit factory"
    )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: object, what: str) -> bytes:
    if not isinstance(value, str):
        raise ContractError(f"{what} must be a base64 str")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ContractError(f"{what} is not valid base64: {exc}") from exc


def _page_offset(payload: dict) -> int:
    offset = payload.get("offset", 0)
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ContractError("page offset must be a non-negative int")
    return offset


def _introspection_port(payload: dict, ports: dict, method: str):
    """Look up the prepared port for an observations/payloads page request."""
    attempt_id = payload.get("attempt_id")
    if not isinstance(attempt_id, str) or not attempt_id:
        raise ContractError("evidence paging needs a non-empty attempt_id")
    port = ports.get(attempt_id)
    if port is None:
        raise ContractError(f"no prepared port for attempt {attempt_id!r}")
    introspect = getattr(port, method, None)
    if not callable(introspect):
        raise ContractError(
            f"port for attempt {attempt_id!r} does not expose {method} "
            "(evidence streaming requires an introspectable port)"
        )
    return attempt_id, port


def make_exec_handler(
    *,
    port_factory: Optional[PortFactory] = None,
    probe_factory: Optional[ProbeFactory] = None,
    cancel_token: Optional[Callable[[], bool]] = None,
) -> Handler:
    """Build the ``EXEC`` handler with an injected port/probe factory.

    ``cancel_token`` is the worker cancel predicate observed by the
    per-request :class:`Control` (the parent's CANCEL message flips it).
    """
    ports: dict[str, object] = {}
    cancelled = cancel_token if cancel_token is not None else (lambda: False)

    def _control_for(time_budget_ms: int) -> Control:
        clock = time.monotonic
        budget = time_budget_ms if 1 <= time_budget_ms <= ATTEMPT_BUDGET_MS else ATTEMPT_BUDGET_MS
        return Control(clock=clock, deadline=clock() + budget / 1000, cancelled=cancelled)

    def _port_for(request: AttemptRequest) -> object:
        if port_factory is None:
            raise PortFactoryNotConfigured("no port factory configured for EXEC")
        port = port_factory(request)
        if not hasattr(port, "prepare") or not hasattr(port, "execute"):
            raise ContractError("port factory must return an ExecutionPort-shaped object")
        ports[request.attempt_id] = port
        return port

    def handler(payload: dict) -> dict:
        op = payload.get("op")
        if op == "preflight":
            if probe_factory is None:
                raise ContractError("no probe factory configured for EXEC/preflight")
            config = load_target_config(payload.get("target"))
            manifest = run_preflight(config, probe_factory(), _control_for(ATTEMPT_BUDGET_MS))
            return {"environment": dump_environment_manifest(manifest).decode("utf-8")}

        if op == "prepare":
            request = load_attempt_request(_unb64(payload.get("request_b64"), "request_b64"))
            port = _port_for(request)
            try:
                expectation = port.prepare(request, _control_for(request.time_budget_ms))
            except ExecutionPortError as exc:
                return _failure_payload(exc)
            return {"expectation_b64": _b64(dump_attempt_expectation(expectation))}

        if op == "execute":
            request = load_attempt_request(_unb64(payload.get("request_b64"), "request_b64"))
            expectation = load_attempt_expectation(
                _unb64(payload.get("expectation_b64"), "expectation_b64")
            )
            port = ports.get(request.attempt_id)
            if port is None:
                raise ContractError(
                    f"no prepared port for attempt {request.attempt_id!r} "
                    "(execute requires prepare first)"
                )
            try:
                evidence = port.execute(request, expectation, _control_for(request.time_budget_ms))
            except ExecutionPortError as exc:
                return _failure_payload(exc)
            return {"evidence_b64": _b64(dump_execution_evidence(evidence))}

        if op == "cancel":
            attempt_id = payload.get("attempt_id")
            if not isinstance(attempt_id, str) or not attempt_id:
                raise ContractError("cancel needs a non-empty attempt_id")
            port = ports.get(attempt_id)
            if port is None:
                raise ContractError(f"no prepared port for attempt {attempt_id!r}")
            grace_ms = payload.get("grace_ms", 5000)
            if isinstance(grace_ms, bool) or not isinstance(grace_ms, int) or grace_ms <= 0:
                raise ContractError("cancel grace_ms must be a positive int")
            try:
                terminal = port.cancel_and_wait(attempt_id, grace_ms / 1000)
            except ExecutionPortError as exc:
                return _failure_payload(exc)
            if terminal is None:
                return {"terminal_b64": None}
            return {"terminal_b64": _b64(_dump_terminal(terminal))}

        if op == "observations":
            attempt_id, port = _introspection_port(payload, ports, "stage_observations")
            offset = _page_offset(payload)
            observations = port.stage_observations(attempt_id)
            page = observations[offset : offset + _OBSERVATIONS_PAGE]
            items = [observation.to_obj() for observation in page]
            return {
                "total": len(observations),
                "items_b64": _b64(canonical_json(items)),
            }

        if op == "payloads":
            attempt_id, port = _introspection_port(payload, ports, "payloads")
            offset = _page_offset(payload)
            byte_budget = payload.get("byte_budget", _MAX_PAGE_PAYLOAD_BYTES)
            if (
                isinstance(byte_budget, bool)
                or not isinstance(byte_budget, int)
                or not 1 <= byte_budget <= _MAX_PAGE_BUDGET
            ):
                raise ContractError(
                    f"payloads byte_budget must be an int in [1, {_MAX_PAGE_BUDGET}]"
                )
            items: List[List[object]] = []
            budget = byte_budget
            for ref, data in list(port.payloads(attempt_id).items())[offset:]:
                encoded = _b64(data)
                if items and len(encoded) > budget:
                    break
                items.append([ref, encoded])
                budget -= len(encoded)
                if budget <= 0:
                    break
            return {
                "total": len(list(port.payloads(attempt_id).items())),
                "items_b64": _b64(canonical_json(items)),
            }

        raise ContractError(f"unsupported EXEC op {op!r}")

    return handler


def _failure_payload(exc: ExecutionPortError) -> dict:
    """Structured failure with the salvage evidence/terminal documents."""
    return {
        "failure": {
            "message": str(exc)[:512],
            "evidence_b64": (
                None if getattr(exc, "evidence", None) is None
                else _b64(dump_execution_evidence(exc.evidence))
            ),
            "terminal_b64": (
                None if getattr(exc, "terminal", None) is None
                else _b64(_dump_terminal(exc.terminal))
            ),
        }
    }


def decode_failure_payload(payload: dict) -> Optional[dict]:
    """Parent-side decode of a structured failure payload (None if absent)."""
    failure = payload.get("failure")
    if failure is None:
        return None
    evidence = failure.get("evidence_b64")
    terminal = failure.get("terminal_b64")
    return {
        "message": str(failure.get("message", "execution port failure")),
        "evidence": (
            None if evidence is None else load_execution_evidence(_unb64(evidence, "evidence_b64"))
        ),
        "terminal": (
            None if terminal is None else _load_terminal(_unb64(terminal, "terminal_b64"))
        ),
    }


def decode_environment_payload(payload: dict) -> EnvironmentManifest:
    """Parent-side decode of a preflight RESULT payload."""
    document = payload.get("environment")
    if not isinstance(document, str):
        raise ContractError("preflight result must carry an environment document")
    return load_environment_manifest(document)


def register_attempt_handlers(
    app: worker_loop.WorkerApp,
    *,
    port_factory: Optional[PortFactory] = default_port_factory,
    probe_factory: Optional[ProbeFactory] = None,
) -> None:
    """Register the ``EXEC`` handler on a worker app (worker.py untouched)."""
    app.register_handler(
        "EXEC",
        make_exec_handler(
            port_factory=port_factory,
            probe_factory=probe_factory,
            cancel_token=app.control.cancelled,
        ),
    )


def attempt_worker_main(argv: Optional[list] = None) -> int:
    """Attempt-worker entry point (``python -m mtsql_typecheck.runner.handlers``).

    Builds a plain ``WorkerApp``, registers the attempt ``EXEC`` handlers
    wired to the environment-built port and probe factories (design 6.3.2
    assembly; a worker started without a target configuration fails closed
    on first use) and runs the standard loop (HELLO/READY handshake, SIGTERM
    hook, SHUTDOWN).
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        print(f"attempt worker: unexpected arguments {args!r}", file=sys.stderr)
        return worker_loop.EXIT_STATUS_USAGE
    app = worker_loop.WorkerApp()
    register_attempt_handlers(
        app,
        port_factory=env_port_factory(),
        probe_factory=env_probe_factory(),
    )
    try:
        signal.signal(signal.SIGTERM, worker_loop._make_sigterm_handler(app))
    except ValueError:
        pass  # not the main thread; embedded use handles SIGTERM itself
    return app.run()


if __name__ == "__main__":
    sys.exit(attempt_worker_main())
