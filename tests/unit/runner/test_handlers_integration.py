"""Integration tests for the D3 online-loop seams (Phase 5 closure).

Covers the previously-open worker seams end to end with fakes only:

- ``build_execution_port`` (design 6.3.2 assembly): journal-source rules and
  the production wiring driven through the environment-built worker factory
  (``env_port_factory``) with the real adapter class patched by scripted
  fakes, including a full ``prepare``/``execute`` attempt over the worker
  ``EXEC`` handler;
- worker EXEC evidence streaming: the ``observations``/``payloads`` ops
  deliver the port's stage observations and raw payload side table in
  bounded pages, and a full worker round-trip through the real controller
  lands them in the run output directory (``observations.jsonl`` plus the
  content-addressed payload store);
- fail-closed worker startup: without the target configuration the worker
  wiring refuses with ``PortFactoryNotConfigured`` before any SQL.

No MySQL, no network; the real ``MySQL80Adapter`` is never constructed.
"""

from __future__ import annotations

import base64
import threading
from pathlib import Path

import pytest

from controller_fakes import (
    AttemptFakes,
    FakeProbeSource,
    make_bundle,
    make_signed_payloads,
    make_target_config,
)
from execution_fakes import (
    SERVER_UUID,
    InMemoryJournal,
    IntegerValue,
    make_payload,
    make_request,
)
from mtsql_typecheck.adapters.base import ConnectionParams
from mtsql_typecheck.contracts.case import ContractError
from mtsql_typecheck.contracts.codec import parse_strict_json, sha256_hex
from mtsql_typecheck.contracts.execution import (
    TerminationState,
    dump_attempt_expectation,
    dump_attempt_request,
    load_attempt_expectation,
    load_execution_evidence,
)
from mtsql_typecheck.contracts.runner import (
    decode_stage_observation,
    dump_target_config,
    load_stage_observation,
)
from mtsql_typecheck.runner import handlers
from mtsql_typecheck.runner.controller import RunController, RunOptions, WorkerDispatcher
from mtsql_typecheck.runner.execution import MySQLExecutionPort, build_execution_port
from mtsql_typecheck.runner.handlers import (
    PortFactoryNotConfigured,
    make_exec_handler,
    register_attempt_handlers,
)
from mtsql_typecheck.runner.preflight import run_preflight

TARGET_PASSWORD_ENV = "MTTC_TEST_PW"  # make_target_config's password_env


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _set_target_env(monkeypatch) -> None:
    monkeypatch.setenv(
        handlers.WORKER_TARGET_ENV,
        dump_target_config(make_target_config()).decode("utf-8"),
    )
    monkeypatch.setenv(TARGET_PASSWORD_ENV, "pw")


def _patch_adapter_class(monkeypatch, adapters):
    """Replace the certified adapter class with a scripted-pool pop."""
    import mtsql_typecheck.adapters.mysql80 as mysql80

    pool = list(adapters)

    def patched(params, *, charset, deadline_cb=None, clock=None, control=None):
        if not pool:
            raise AssertionError("adapter pool exhausted: unexpected connection")
        return pool.pop(0)

    monkeypatch.setattr(mysql80, "MySQL80Adapter", patched)


# --------------------------------------------------------------------------
# build_execution_port: journal sources and parameter validation
# --------------------------------------------------------------------------


def test_build_execution_port_needs_exactly_one_journal_source(tmp_path: Path) -> None:
    params = ConnectionParams(host="db.internal", port=3306, user="tc", password="pw")
    with pytest.raises(ContractError):
        build_execution_port(
            params=params,
            journal=InMemoryJournal("run-x"),
            journal_path=tmp_path / "ownership.jsonl",
        )


def test_build_execution_port_journal_path_requires_run_id(tmp_path: Path) -> None:
    params = ConnectionParams(host="db.internal", port=3306, user="tc", password="pw")
    with pytest.raises(ContractError):
        build_execution_port(params=params, journal_path=tmp_path / "ownership.jsonl")


def test_build_execution_port_journals(tmp_path: Path) -> None:
    params = ConnectionParams(host="db.internal", port=3306, user="tc", password="pw")
    port = build_execution_port(
        params=params, journal_path=tmp_path / "ownership.jsonl", run_id="run-x"
    )
    assert isinstance(port, MySQLExecutionPort)
    # The frozen journal is created (O_EXCL) at open time, not on first append.
    assert (tmp_path / "ownership.jsonl").is_file()
    # Neither injected nor path-given: the in-process fallback sink.
    fallback = build_execution_port(params=params)
    assert isinstance(fallback, MySQLExecutionPort)


def test_build_execution_port_needs_connection_params() -> None:
    with pytest.raises(ContractError):
        build_execution_port(params=object())  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Fail-closed worker startup without target configuration
# --------------------------------------------------------------------------


def test_env_port_factory_without_target_config_fails_closed(monkeypatch) -> None:
    monkeypatch.delenv(handlers.WORKER_TARGET_ENV, raising=False)
    factory = handlers.env_port_factory()
    request = make_request(make_payload(row_values=(IntegerValue(1),)), attempt_id="at-1")
    with pytest.raises(PortFactoryNotConfigured):
        factory(request)


def test_default_port_factory_stays_fail_closed(monkeypatch) -> None:
    monkeypatch.delenv(handlers.WORKER_TARGET_ENV, raising=False)
    with pytest.raises(PortFactoryNotConfigured):
        handlers.default_port_factory(None)  # type: ignore[arg-type]


def test_env_port_factory_with_malformed_target_fails_closed(monkeypatch) -> None:
    monkeypatch.setenv(handlers.WORKER_TARGET_ENV, '{"host": 1}')
    factory = handlers.env_port_factory()
    request = make_request(make_payload(row_values=(IntegerValue(1),)), attempt_id="at-1")
    with pytest.raises(PortFactoryNotConfigured):
        factory(request)


# --------------------------------------------------------------------------
# env wiring builds a working production port (patched adapter class)
# --------------------------------------------------------------------------


def test_env_port_factory_runs_a_full_attempt(monkeypatch) -> None:
    payload = make_payload(row_values=(IntegerValue(1),))
    request = make_request(payload, attempt_id="at-000001-" + "f" * 16, run_id="run-h1")
    fakes = AttemptFakes(payload)
    _patch_adapter_class(monkeypatch, fakes.adapters)
    _set_target_env(monkeypatch)

    factory = handlers.env_port_factory()
    port = factory(request)
    assert isinstance(port, MySQLExecutionPort)

    handler = make_exec_handler(port_factory=factory)
    request_b64 = _b64(dump_attempt_request(request))
    reply = handler({"op": "prepare", "request_b64": request_b64})
    expectation = load_attempt_expectation(_unb64(reply["expectation_b64"]))
    assert expectation.request_hash == request.request_hash

    reply = handler(
        {
            "op": "execute",
            "request_b64": request_b64,
            "expectation_b64": _b64(dump_attempt_expectation(expectation)),
        }
    )
    evidence = load_execution_evidence(_unb64(reply["evidence_b64"]))
    assert evidence.failure is None
    assert evidence.terminal is not None
    assert evidence.terminal.termination is TerminationState.CONFIRMED


def test_env_probe_factory_answers_environment_facts(monkeypatch) -> None:
    payload = make_payload(row_values=(IntegerValue(1),))
    probe_adapter = AttemptFakes(payload).adapters[0]
    _patch_adapter_class(monkeypatch, [probe_adapter])
    _set_target_env(monkeypatch)

    probe = handlers.env_probe_factory()()
    facts = dict(probe.fetch_environment_facts())
    assert facts["server_uuid"] == SERVER_UUID


def test_env_probe_factory_without_target_config_fails_closed(monkeypatch) -> None:
    monkeypatch.delenv(handlers.WORKER_TARGET_ENV, raising=False)
    with pytest.raises(PortFactoryNotConfigured):
        handlers.env_probe_factory()()


# --------------------------------------------------------------------------
# EXEC evidence paging: observations and payloads ops
# --------------------------------------------------------------------------


def test_exec_handler_streams_observations_and_payloads() -> None:
    payload = make_payload(row_values=(IntegerValue(1),))
    attempt_id = "at-000001-" + "e" * 16
    request = make_request(payload, attempt_id=attempt_id, run_id="run-h2")
    port = AttemptFakes(payload).build()
    handler = make_exec_handler(port_factory=lambda req: port)

    request_b64 = _b64(dump_attempt_request(request))
    reply = handler({"op": "prepare", "request_b64": request_b64})
    expectation = load_attempt_expectation(_unb64(reply["expectation_b64"]))
    handler(
        {
            "op": "execute",
            "request_b64": request_b64,
            "expectation_b64": _b64(dump_attempt_expectation(expectation)),
        }
    )

    recorded = port.stage_observations(attempt_id)
    assert recorded
    # Pull every page, exactly as the controller does; each item satisfies
    # the frozen StageObservation contract.
    decoded = []
    offset = 0
    while offset < len(recorded):
        reply = handler({"op": "observations", "attempt_id": attempt_id, "offset": offset})
        assert reply["total"] == len(recorded)
        page = parse_strict_json(_unb64(reply["items_b64"]))
        decoded.extend(decode_stage_observation(item) for item in page)
        offset += len(page)
    assert decoded == list(recorded)

    # A single bounded page (handler-side cap) carries at most 32 items.
    reply = handler({"op": "observations", "attempt_id": attempt_id, "offset": 0})
    page = parse_strict_json(_unb64(reply["items_b64"]))
    assert len(page) == min(32, len(recorded))

    # Payload pages carry [ref, bytes]; a recorded sql_ref resolves to bytes
    # whose content hash is exactly the observation's sql_hash.
    reply = handler({"op": "payloads", "attempt_id": attempt_id, "offset": 0})
    entries = parse_strict_json(_unb64(reply["items_b64"]))
    assert entries
    sql_hashes = {obs.sql_ref: obs.sql_hash for obs in recorded if obs.sql_ref}
    for ref, encoded in entries:
        data = _unb64(encoded)
        if ref in sql_hashes:
            assert sha256_hex(data) == sql_hashes[ref]

    # Unknown attempt and bad offsets refuse typed (never silently empty).
    with pytest.raises(ContractError):
        handler({"op": "observations", "attempt_id": "at-nope", "offset": 0})
    with pytest.raises(ContractError):
        handler({"op": "observations", "attempt_id": attempt_id, "offset": -1})
    with pytest.raises(ContractError):
        handler({"op": "payloads", "attempt_id": attempt_id, "offset": 0, "byte_budget": 0})


# --------------------------------------------------------------------------
# Full worker round-trip: observations land in the run output directory
# --------------------------------------------------------------------------


def _make_pipes():
    import os

    p2c_r, p2c_w = os.pipe()
    c2p_r, c2p_w = os.pipe()
    child_stdin = os.fdopen(p2c_r, "rb")
    child_stdout = os.fdopen(c2p_w, "wb")
    parent_reader = os.fdopen(c2p_r, "rb")
    parent_writer = os.fdopen(p2c_w, "wb")
    return child_stdin, child_stdout, parent_reader, parent_writer


def test_worker_round_trip_delivers_observations_to_run_output(tmp_path: Path) -> None:
    from mtsql_typecheck.runner import ipc
    from mtsql_typecheck.runner.worker import WorkerApp

    case_payloads = make_signed_payloads()[:1]
    bundle = make_bundle(tmp_path / "bundle", case_payloads)

    child_stdin, child_stdout, parent_reader, parent_writer = _make_pipes()
    app = WorkerApp(stdin=child_stdin, stdout=child_stdout)
    port_holder: dict = {}

    def port_factory(request):
        # One worker serves the run's attempts with one port per attempt.
        port = AttemptFakes(request.payload).build()
        port_holder[request.attempt_id] = port
        return port

    register_attempt_handlers(app, port_factory=port_factory)
    exit_status: list = []
    thread = threading.Thread(target=lambda: exit_status.append(app.run()), daemon=True)
    thread.start()

    parent = ipc.IpcConnection(parent_reader, parent_writer, name="test-parent")
    hello = parent.recv()
    assert hello.kind == "HELLO"
    parent.send("READY", {})

    class _FakeSupervisor:
        """Just enough supervisor surface for WorkerDispatcher's transport."""

        def __init__(self, connection) -> None:
            self.connection = connection

        def shutdown(self) -> None:
            pass

        def close(self) -> None:
            parent.close()

    dispatcher = WorkerDispatcher(supervisor=_FakeSupervisor(parent))
    controller = RunController(
        config=make_target_config(),
        bundle_dir=bundle,
        output=tmp_path / "out",
        options=RunOptions(),
        dispatcher_factory=lambda request: dispatcher,
        preflight_fn=lambda config, control: run_preflight(config, FakeProbeSource(), control),
    )
    outcome = controller.run()
    assert outcome.exit_code() == 0, outcome.message

    attempt_dirs = list((tmp_path / "out" / "attempts").iterdir())
    assert len(attempt_dirs) == 1
    lines = (attempt_dirs[0] / "observations.jsonl").read_bytes().splitlines()
    assert lines  # the streaming gap is closed: no empty observations file
    observations = [load_stage_observation(line) for line in lines]
    recorded = port_holder[attempt_dirs[0].name].stage_observations(attempt_dirs[0].name)
    assert observations == list(recorded)
    # Every recorded sql_ref resolves through the content-addressed payload
    # store: payloads/<sql_hash>.json hashes back to the recorded sql_hash.
    sql_observations = [obs for obs in observations if obs.sql_ref]
    assert sql_observations
    for obs in sql_observations:
        payload_file = tmp_path / "out" / "payloads" / f"{obs.sql_hash}.json"
        assert payload_file.is_file()
        assert sha256_hex(payload_file.read_bytes()) == obs.sql_hash

    thread.join(timeout=5)
