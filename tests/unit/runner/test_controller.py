"""Unit tests for the online run controller (runner/controller.py).

Fakes only: attempts run against scripted in-process execution ports built
from ``controller_fakes`` (which reuses the Phase 4 ``execution_fakes``
primitives); the worker EXEC round-trip speaks real ``runner.ipc`` envelopes
over OS pipes with a threaded ``WorkerApp``.  No MySQL, no network, no
PyMySQL import.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from pathlib import Path

import pytest

from controller_fakes import (
    AttemptFakes,
    FakeProbeSource,
    FailingDispatcher,
    InlineDispatcher,
    make_bundle,
    make_signed_payloads,
    make_target_config,
)
from execution_fakes import int_value, make_request
from mtsql_typecheck.contracts.codec import case_id_of, parse_strict_json
from mtsql_typecheck.contracts.execution import (
    default_control,
    dump_attempt_expectation,
    dump_attempt_request,
    load_attempt_expectation,
    load_execution_evidence,
)
from mtsql_typecheck.contracts.oracle import (
    ComparisonStatus,
    ReplayOutcome,
    ReductionOutcome,
    StopReason,
    load_comparison,
)
from mtsql_typecheck.contracts.runner import (
    OwnershipEventKind,
    RunnerCommand,
    RunnerStatus,
    load_ownership_journal,
)
from mtsql_typecheck.runner.controller import (
    CaseInputError,
    DispatcherError,
    RunController,
    RunOptions,
    exit_code_for,
    load_attempt_documents,
    load_case_bundle,
    reduce_candidate_documents,
    reduce_exit_code,
    replay_candidate_documents,
    replay_exit_code,
)
from mtsql_typecheck.runner.evidence import MANIFEST_NAME, EvidenceWriter
from mtsql_typecheck.runner.preflight import run_preflight
from mtsql_typecheck.contracts.runner import decode_runner_manifest


def _preflight_ok(config, control):
    return run_preflight(config, FakeProbeSource(), control)


def _preflight_failing(config, control):
    return run_preflight(config, FakeProbeSource(facts={"version": "5.7.40-log"}), control)


def _inline_factory(mismatch_case_ids=frozenset()):
    def factory(request):
        cid = case_id_of(request.payload)
        b_result = ((int_value(999),),) if cid in mismatch_case_ids else None
        return InlineDispatcher(AttemptFakes(request.payload, b_result=b_result).build())

    return factory


def make_controller(
    tmp_path: Path,
    *,
    bundle: Path,
    output: str = "out",
    options: RunOptions | None = None,
    mismatch_case_ids=frozenset(),
    dispatcher_factory=None,
    preflight_fn=_preflight_ok,
) -> RunController:
    return RunController(
        config=make_target_config(),
        bundle_dir=bundle,
        output=tmp_path / output,
        options=options if options is not None else RunOptions(),
        dispatcher_factory=(
            dispatcher_factory if dispatcher_factory is not None else _inline_factory(mismatch_case_ids)
        ),
        preflight_fn=preflight_fn,
    )


def manifest_record(candidate: int = 0, status=RunnerStatus.COMPLETE):
    from mtsql_typecheck.contracts.runner import RUNNER_EVIDENCE_PROFILE, RunnerManifest

    return RunnerManifest(
        command=RunnerCommand.RUN,
        run_id="run-x",
        status=status,
        requested=1,
        completed=1,
        comparable=1,
        match=1 - candidate,
        candidate=candidate,
        inconclusive=0,
        not_applicable=0,
        leftover_objects=0,
        leftover_sessions=0,
        synthetic=False,
        evidence_profile=RUNNER_EVIDENCE_PROFILE,
        tool_version="0.1.0",
        contract_versions=(("case", "1"), ("execution", "1"), ("oracle", "o1"), ("runner", "1")),
        refs=(("runner_manifest", MANIFEST_NAME),),
        sanitized_config_hash="a" * 64,
    )


# --------------------------------------------------------------------------
# Pure exit-code outranking table (design 6.3.3)
# --------------------------------------------------------------------------


def test_exit_code_outranking_table() -> None:
    complete = manifest_record(candidate=0)
    with_candidate = manifest_record(candidate=1)
    partial = manifest_record(candidate=0, status=RunnerStatus.PARTIAL)

    # Base rows.
    assert exit_code_for(complete) == 0
    assert exit_code_for(with_candidate) == 4
    assert exit_code_for(partial) == 3
    assert exit_code_for(None) == 1
    # Cancel outranks completeness.
    assert exit_code_for(with_candidate, cancelled=True) == 130
    # Persistence failure outranks cancel and completeness.
    assert exit_code_for(complete, cancelled=True, persistence_failure=True) == 1
    # Unsafe termination outranks persistence failure.
    assert exit_code_for(complete, unsafe=True, persistence_failure=True, cancelled=True) == 1
    # Usage error outranks everything.
    assert exit_code_for(complete, unsafe=True, persistence_failure=True, cancelled=True, usage_error=True) == 2
    # No manifest at all is exit-1 territory -- unless the user cancelled,
    # which still outranks it (the partial evidence was sealed).
    assert exit_code_for(None) == 1
    assert exit_code_for(None, cancelled=True) == 130


# --------------------------------------------------------------------------
# Happy path: 2 cases, 1 match + 1 candidate -> exit 4
# --------------------------------------------------------------------------


def test_run_happy_path_two_cases(tmp_path: Path) -> None:
    payloads = make_signed_payloads()
    bundle = make_bundle(tmp_path / "bundle", payloads)
    controller = make_controller(
        tmp_path, bundle=bundle, mismatch_case_ids=frozenset({case_id_of(payloads[1])})
    )
    outcome = controller.run()

    assert outcome.exit_code() == 4
    assert outcome.manifest is not None
    manifest = outcome.manifest
    assert manifest.status is RunnerStatus.COMPLETE
    assert (manifest.requested, manifest.completed) == (2, 2)
    assert (manifest.comparable, manifest.match, manifest.candidate) == (2, 1, 1)
    assert manifest.inconclusive == 0
    assert manifest.leftover_objects == 0
    assert manifest.stop_reason is None

    root = tmp_path / "out"
    # The manifest on disk decodes to the same record.
    on_disk = decode_runner_manifest(parse_strict_json((root / MANIFEST_NAME).read_bytes()), "m")
    assert on_disk.to_obj() == manifest.to_obj()

    # Per-attempt evidence: the frozen six-document layout for both attempts.
    attempt_dirs = sorted((root / "attempts").iterdir())
    assert len(attempt_dirs) == 2
    expected_files = {
        "request.json",
        "expectation.json",
        "execution-evidence.json",
        "comparison.json",
        "observations.jsonl",
        "terminal.json",
    }
    statuses = []
    for attempt_dir in attempt_dirs:
        assert {p.name for p in attempt_dir.iterdir()} == expected_files
        comparison = load_comparison((attempt_dir / "comparison.json").read_bytes())
        statuses.append(comparison.status)
    # Bundle iteration order is by case_id, not payload order: exactly one
    # MATCH and one MISMATCH_CANDIDATE must be recorded.
    assert sorted(status.value for status in statuses) == [
        ComparisonStatus.MATCH.value,
        ComparisonStatus.MISMATCH_CANDIDATE.value,
    ]

    # Manifest refs point at the real evidence.
    ref_paths = [path for _, path in manifest.refs]
    for name in ("environment.json", "ownership.jsonl", "trace.jsonl", MANIFEST_NAME):
        assert name in ref_paths
        assert (root / name).is_file()
    attempt_refs = [path for name, path in manifest.refs if name.startswith("attempt:")]
    assert len(attempt_refs) == 2
    for relpath in attempt_refs:
        assert (root / relpath).is_file()

    # Ownership journal: run lock, one allocation per attempt, sealed run.
    events = load_ownership_journal((root / "ownership.jsonl").read_bytes())
    kinds = [str(event.event_kind.value) for event in events]
    assert kinds.count(str(OwnershipEventKind.ATTEMPT_ALLOCATED.value)) == 2
    assert kinds[0] == str(OwnershipEventKind.RUN_LOCK_ACQUIRED.value)
    assert kinds[-1] == str(OwnershipEventKind.RUN_SEALED.value)

    # The payload store is content-addressed and non-empty.
    assert any((root / "payloads").iterdir())


def test_run_without_candidate_exits_zero(tmp_path: Path) -> None:
    payloads = make_signed_payloads()[:1]
    bundle = make_bundle(tmp_path / "bundle", payloads)
    controller = make_controller(tmp_path, bundle=bundle)
    outcome = controller.run()
    assert outcome.exit_code() == 0
    assert outcome.manifest.match == 1


# --------------------------------------------------------------------------
# Input refusals (exit 2)
# --------------------------------------------------------------------------


def test_existing_output_root_is_a_usage_error(tmp_path: Path) -> None:
    payloads = make_signed_payloads()
    bundle = make_bundle(tmp_path / "bundle", payloads)
    output = tmp_path / "out"
    output.mkdir()
    controller = make_controller(tmp_path, bundle=bundle, output="out")
    outcome = controller.run()
    assert outcome.exit_code() == 2
    assert outcome.usage_error is True
    assert outcome.manifest is None
    # Nothing was dispatched, no evidence was merged into the directory.
    assert not (output / "attempts").exists()


def test_corrupt_case_bundle_is_a_usage_error(tmp_path: Path) -> None:
    payloads = make_signed_payloads()
    bundle = make_bundle(tmp_path / "bundle", payloads)
    # Corrupt one case document: case_id no longer matches the directory.
    case_dir = next((bundle / "cases").iterdir())
    (case_dir / "case.json").write_bytes(json.dumps({"case_id": "other", "payload": {}}).encode())
    with pytest.raises(CaseInputError):
        load_case_bundle(bundle)


def test_empty_bundle_is_refused(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "generation-manifest.json").write_bytes(b"{}")
    (bundle / "cases").mkdir()
    with pytest.raises(CaseInputError):
        load_case_bundle(bundle)
    controller = make_controller(tmp_path, bundle=bundle)
    outcome = controller.run()
    assert outcome.exit_code() == 2
    assert outcome.manifest.stop_reason == "CASE_INPUT_INVALID"


# --------------------------------------------------------------------------
# Preflight gating
# --------------------------------------------------------------------------


def test_environment_unsatisfied_stops_before_any_attempt(tmp_path: Path) -> None:
    payloads = make_signed_payloads()
    bundle = make_bundle(tmp_path / "bundle", payloads)
    controller = make_controller(tmp_path, bundle=bundle, preflight_fn=_preflight_failing)
    outcome = controller.run()

    assert outcome.exit_code() == 3
    assert outcome.manifest.status is RunnerStatus.ABORTED
    assert outcome.manifest.stop_reason == "ENVIRONMENT_UNSATISFIED"
    assert outcome.manifest.requested == 0
    # The failing environment is persisted, but no attempt happened.
    assert (tmp_path / "out" / "environment.json").is_file()
    assert not any((tmp_path / "out" / "attempts").iterdir())


def test_preflight_failure_is_a_persistence_failure(tmp_path: Path) -> None:
    payloads = make_signed_payloads()
    bundle = make_bundle(tmp_path / "bundle", payloads)

    def failing_preflight(config, control):
        raise DispatcherError("worker unavailable")

    controller = make_controller(tmp_path, bundle=bundle, preflight_fn=failing_preflight)
    outcome = controller.run()
    assert outcome.exit_code() == 1
    assert outcome.persistence_failure is True
    assert outcome.manifest.stop_reason == "PREFLIGHT_FAILED"
    assert outcome.manifest.requested == 0


# --------------------------------------------------------------------------
# Budget / quarantine / cancel
# --------------------------------------------------------------------------


def test_evidence_budget_exhaustion_stops_the_run(tmp_path: Path) -> None:
    payloads = make_signed_payloads()
    bundle = make_bundle(tmp_path / "bundle", payloads)
    # 1 MiB admits the small control documents but not the per-attempt
    # reserve hint (~32 MiB), so the first dispatch is refused.
    controller = make_controller(
        tmp_path, bundle=bundle, options=RunOptions(evidence_budget_bytes=1024 * 1024)
    )
    outcome = controller.run()
    assert outcome.exit_code() == 1
    assert outcome.persistence_failure is True
    assert outcome.manifest.status is RunnerStatus.PARTIAL
    assert outcome.manifest.stop_reason == "EVIDENCE_BUDGET_EXCEEDED"
    assert outcome.manifest.requested == 0
    # The sink still exists (A05: no dispatch without a trace sink).
    assert (tmp_path / "out" / "trace.jsonl").is_file()


def test_dispatcher_failure_without_salavage_trips_quarantine(tmp_path: Path) -> None:
    payloads = make_signed_payloads()
    bundle = make_bundle(tmp_path / "bundle", payloads)
    controller = make_controller(
        tmp_path,
        bundle=bundle,
        dispatcher_factory=lambda request: FailingDispatcher(),
    )
    outcome = controller.run()
    assert outcome.exit_code() == 1
    assert outcome.unsafe is True
    assert outcome.manifest.status is RunnerStatus.ABORTED
    assert outcome.manifest.stop_reason == "QUARANTINED"
    # Only the first case was dispatched; the latch stopped the rest.
    assert outcome.manifest.requested == 1
    assert len(list((tmp_path / "out" / "attempts").iterdir())) == 1


def test_user_cancel_after_first_attempt_seals_partial(tmp_path: Path) -> None:
    payloads = make_signed_payloads()
    bundle = make_bundle(tmp_path / "bundle", payloads)
    flag = {"cancelled": False}

    def cancelled():
        return flag["cancelled"]

    inner_factory = _inline_factory()

    class CancelAfterFirstExecute:
        def __init__(self, inner):
            self._inner = inner

        def prepare(self, request, control):
            return self._inner.prepare(request, control)

        def execute(self, request, expectation, control):
            evidence = self._inner.execute(request, expectation, control)
            flag["cancelled"] = True  # SIGINT arrives during attempt 1
            return evidence

        def cancel_and_wait(self, attempt_id, grace_seconds):
            return self._inner.cancel_and_wait(attempt_id, grace_seconds)

        def observations(self, attempt_id):
            return self._inner.observations(attempt_id)

        def payloads(self, attempt_id):
            return self._inner.payloads(attempt_id)

        def close(self):
            self._inner.close()

    dispatched = []

    def factory(request):
        dispatched.append(request)
        return CancelAfterFirstExecute(inner_factory(request))

    controller = make_controller(
        tmp_path,
        bundle=bundle,
        options=RunOptions(cancelled=cancelled),
        dispatcher_factory=factory,
    )
    outcome = controller.run()

    assert outcome.exit_code() == 130
    assert outcome.cancelled is True
    assert outcome.manifest.status is RunnerStatus.ABORTED
    assert outcome.manifest.stop_reason == "CANCELLED"
    assert outcome.manifest.requested == 1
    # The first attempt's evidence is sealed even though the run was cancelled.
    assert len(list((tmp_path / "out" / "attempts").iterdir())) == 1
    assert len(dispatched) == 1


# --------------------------------------------------------------------------
# Attempt documents -> D2 replay/reduce entry points
# --------------------------------------------------------------------------


def _run_one_candidate(tmp_path: Path) -> Path:
    payloads = make_signed_payloads()
    bundle = make_bundle(tmp_path / "bundle", payloads)
    controller = make_controller(
        tmp_path, bundle=bundle, mismatch_case_ids=frozenset({case_id_of(payloads[1])})
    )
    outcome = controller.run()
    assert outcome.exit_code() == 4
    attempts = sorted((tmp_path / "out" / "attempts").iterdir())
    for attempt_dir in attempts:
        comparison = load_comparison((attempt_dir / "comparison.json").read_bytes())
        if comparison.status is ComparisonStatus.MISMATCH_CANDIDATE:
            return attempt_dir
    raise AssertionError("no mismatch-candidate attempt was recorded")


def test_load_attempt_documents_and_replay_without_executor(tmp_path: Path) -> None:
    from mtsql_typecheck.reduction.trace import JsonlTraceSink

    attempt_dir = _run_one_candidate(tmp_path)
    docs = load_attempt_documents(attempt_dir)
    assert docs.request.attempt_id == attempt_dir.name
    # Evidence and request are hash-bound.
    assert docs.evidence.request_hash == docs.request.request_hash

    sink = JsonlTraceSink(tmp_path / "replay-out", 8 * 1024 * 1024)
    try:
        result = replay_candidate_documents(attempt_dir, executor=None, trace_sink=sink)
    finally:
        sink.close()
    assert result.outcome is ReplayOutcome.NOT_REPLAYED
    assert result.stop_reason is StopReason.NO_EXECUTOR
    assert replay_exit_code(result) == 3


def test_reduce_without_executor_reports_failed(tmp_path: Path) -> None:
    from mtsql_typecheck.reduction.trace import JsonlTraceSink

    attempt_dir = _run_one_candidate(tmp_path)
    sink = JsonlTraceSink(tmp_path / "reduce-out", 8 * 1024 * 1024)
    try:
        result = reduce_candidate_documents(attempt_dir, executor=None, trace_sink=sink)
    finally:
        sink.close()
    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.NO_EXECUTOR
    assert reduce_exit_code(result) == 1


# --------------------------------------------------------------------------
# Worker EXEC handler round-trip over real ipc envelopes (in-process)
# --------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _start_worker(app):
    status = {}

    def target():
        status["code"] = app.run()

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, status


def _make_pipes():
    p2c_r, p2c_w = os.pipe()
    c2p_r, c2p_w = os.pipe()
    child_stdin = os.fdopen(p2c_r, "rb")
    child_stdout = os.fdopen(c2p_w, "wb")
    parent_reader = os.fdopen(c2p_r, "rb")
    parent_writer = os.fdopen(p2c_w, "wb")
    return child_stdin, child_stdout, parent_reader, parent_writer


def test_worker_exec_handler_round_trip(tmp_path: Path) -> None:
    from mtsql_typecheck.runner import ipc
    from mtsql_typecheck.runner.handlers import register_attempt_handlers
    from mtsql_typecheck.runner.worker import WorkerApp

    payload = make_signed_payloads()[0]
    request = make_request(payload, attempt_id="attempt-1", run_id="run-ipc")
    request_b64 = _b64(dump_attempt_request(request))

    child_stdin, child_stdout, parent_reader, parent_writer = _make_pipes()
    app = WorkerApp(stdin=child_stdin, stdout=child_stdout)
    fakes_holder = {}
    register_attempt_handlers(
        app, port_factory=lambda req: fakes_holder.setdefault("fakes", AttemptFakes(req.payload)).build()
    )
    thread, status = _start_worker(app)

    parent = ipc.IpcConnection(parent_reader, parent_writer, name="test-parent")
    try:
        hello = parent.recv()
        assert hello.kind == "HELLO"
        assert "EXEC" in hello.payload["capabilities"]
        parent.send("READY", {})

        reply = parent.request("EXEC", {"op": "prepare", "request_b64": request_b64}, None)
        assert reply.kind == "RESULT"
        expectation = load_attempt_expectation(
            base64.b64decode(reply.payload["expectation_b64"])
        )
        assert expectation.request_hash == request.request_hash
        assert expectation.execution_order == request.execution_order

        reply = parent.request(
            "EXEC",
            {
                "op": "execute",
                "request_b64": request_b64,
                "expectation_b64": _b64(dump_attempt_expectation(expectation)),
            },
            None,
        )
        assert reply.kind == "RESULT"
        evidence = load_execution_evidence(base64.b64decode(reply.payload["evidence_b64"]))
        assert evidence.request_hash == request.request_hash

        parent.send("SHUTDOWN", {})
        exited = parent.recv()
        assert exited.kind == "EXITED"
    finally:
        parent.close()
    thread.join(timeout=10)
    assert status.get("code") == 0


def test_worker_exec_handler_reports_unknown_op_as_error(tmp_path: Path) -> None:
    from mtsql_typecheck.runner import ipc
    from mtsql_typecheck.runner.handlers import register_attempt_handlers
    from mtsql_typecheck.runner.worker import WorkerApp

    child_stdin, child_stdout, parent_reader, parent_writer = _make_pipes()
    app = WorkerApp(stdin=child_stdin, stdout=child_stdout)
    register_attempt_handlers(app, port_factory=lambda req: AttemptFakes(make_signed_payloads()[0]).build())
    thread, status = _start_worker(app)

    parent = ipc.IpcConnection(parent_reader, parent_writer, name="test-parent")
    try:
        hello = parent.recv()
        assert hello.kind == "HELLO"
        parent.send("READY", {})

        reply = parent.request("EXEC", {"op": "no-such-op"}, None)
        assert reply.kind == "ERROR"
        assert "no-such-op" in reply.payload["message"]
    finally:
        parent.close()
    thread.join(timeout=10)
    # A handler exception exits the worker with the error status (never silent).
    assert status.get("code") == 1
