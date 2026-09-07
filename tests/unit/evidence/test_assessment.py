"""Unit tests for evidence/assessment.py (Phase 2 layered assessment).

Every fixture is built from first principles: run attempts come from the
hand-written reduction fakes (the same model-level construction the oracle
tests use), the honest and forged traces come from a REAL engine run against
the real JsonlTraceSink, and every expected verdict is stated explicitly.
Nothing here derives an expectation from the code under test.
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.delivery import Limits
from mtsql_typecheck.contracts.case import (
    ObservedEnvironment,
    Profile,
    RuleRef,
    RuleSelector,
    REQUIRED_SQL_MODE_TOKENS,
    TemplateId,
    IndexVariant,
)
from mtsql_typecheck.contracts.codec import canonical_json, sha256_hex
from mtsql_typecheck.contracts.execution import (
    Control,
    dump_attempt_expectation,
    dump_attempt_request,
    dump_execution_evidence,
)
from mtsql_typecheck.contracts.oracle import (
    ComparisonBudget,
    EVIDENCE_APPEND_BUDGET,
    decode_trace_record,
    dump_comparison,
)
from mtsql_typecheck.contracts.runner import (
    BuildIdSource as RunnerBuildIdSource,
)
from mtsql_typecheck.contracts.runner import (
    EnvironmentManifest,
    OwnershipEvent,
    OwnershipEventKind,
    RunnerCommand,
    RunnerManifest,
    RunnerStatus,
    dump_ownership_journal,
)
from mtsql_typecheck.evidence.assessment import assess_snapshot
from mtsql_typecheck.evidence.native import detect_native_kind, enumerate_source
from mtsql_typecheck.evidence.reader import SourceReader
from mtsql_typecheck.evidence.snapshot import Snapshotter
from mtsql_typecheck.generation.bundle import generate_and_write, validate_output_dir
from mtsql_typecheck.oracle.gates import compare_case
from mtsql_typecheck.reduction.trace import (
    TRACE_FILE_NAME,
    JsonlTraceSink,
    read_trace,
)

# The reduction fakes are uniquely named suite-wide and importable directly
# (pytest prepend import mode); add their directory to the path explicitly so
# this suite does not depend on rootdir configuration.
_REDUCTION_TEST_DIR = Path(__file__).resolve().parent.parent / "reduction"
if str(_REDUCTION_TEST_DIR) not in sys.path:
    sys.path.append(str(_REDUCTION_TEST_DIR))

import engine_fakes as ef  # noqa: E402
import replay_fakes as rf  # noqa: E402

_GENESIS = "0" * 64


# --------------------------------------------------------------------------
# Fixture builders
# --------------------------------------------------------------------------


def hex64(seed: str) -> str:
    return sha256_hex(seed.encode("utf-8"))


def _write(root: Path, relpath: str, data: bytes) -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _write_json(root: Path, relpath: str, obj: object) -> None:
    _write(root, relpath, canonical_json(obj) + b"\n")


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


def _environment_manifest() -> EnvironmentManifest:
    return EnvironmentManifest(
        observed_environment=_ENV,
        server_uuid="1" * 32,
        python_version="3.11.0",
        os_platform="Linux",
        driver_name="pymysql",
        driver_version="1.0.0",
        adapter_version="d3-adapter-1",
        mapping_version="d3-mapping-1",
        build_id="20250715",
        build_id_source=RunnerBuildIdSource.OBSERVED,
        sanitized_config_hash=hex64("config"),
        probes=(),
    )


def _runner_manifest(attempt_ids: list[str], **overrides: object) -> RunnerManifest:
    fields: dict[str, object] = dict(
        command=RunnerCommand.RUN,
        run_id="run-replay-1",
        status=RunnerStatus.COMPLETE,
        requested=len(attempt_ids),
        completed=len(attempt_ids),
        comparable=len(attempt_ids),
        match=0,
        candidate=len(attempt_ids),
        inconclusive=0,
        not_applicable=0,
        leftover_objects=0,
        leftover_sessions=0,
        synthetic=True,
        evidence_profile="typecheck-full-evidence-v1",
        tool_version="0.1.0",
        contract_versions=(("case", "1"), ("execution", "1"), ("oracle", "o1"), ("runner", "1")),
        refs=tuple(
            [
                ("environment", "environment.json"),
                ("runner_manifest", "runner-manifest.json"),
            ]
            + [("attempt:" + aid, f"attempts/{aid}/comparison.json") for aid in attempt_ids]
        ),
        sanitized_config_hash=hex64("config"),
        stop_reason=None,
    )
    fields.update(overrides)
    return RunnerManifest(**fields)  # type: ignore[arg-type]


def _write_attempt_docs(root: Path, attempt_id: str, bundle: tuple) -> None:
    request, expectation, evidence = bundle
    prefix = f"attempts/{attempt_id}/"
    _write(root, prefix + "request.json", dump_attempt_request(request) + b"\n")
    _write(root, prefix + "expectation.json", dump_attempt_expectation(expectation) + b"\n")
    _write(root, prefix + "execution-evidence.json", dump_execution_evidence(evidence) + b"\n")
    comparison = compare_case(request, expectation, evidence, ComparisonBudget())
    _write(root, prefix + "comparison.json", dump_comparison(comparison) + b"\n")
    # The runner always writes an observation ledger for a dispatched attempt;
    # the closure enumerates it, so an honest fixture cannot omit it.
    _write(root, prefix + "observations.jsonl", b"")
    if evidence.terminal is not None:
        _write(root, prefix + "terminal.json", canonical_json(evidence.terminal.to_obj()) + b"\n")


def _write_run_root(root: Path, attempt_ids: list[str], **manifest_overrides: object) -> None:
    """A run root with one consistent attempt per id (real oracle comparisons)."""
    for attempt_id in attempt_ids:
        bundle = rf.build_attempt(run_id="run-replay-1", attempt_id=attempt_id)
        _write_attempt_docs(root, attempt_id, bundle)
    _write_json(root, "environment.json", _environment_manifest().to_obj())
    _write_json(root, "runner-manifest.json", _runner_manifest(attempt_ids, **manifest_overrides).to_obj())


def _snapshot_and_assess(root: Path, tmp_path: Path, name: str, control: Control | None = None):
    limits = _LIMITS
    out = tmp_path / f"out-{name}"
    with SourceReader(root, limits=limits) as reader:
        kind = detect_native_kind(root)
        plan = enumerate_source(reader, kind, limits)
        snapshot = Snapshotter(reader, out, limits).capture(plan)
        return assess_snapshot(snapshot, reader, plan, limits, control, snapshot_root=out)


_LIMITS = Limits()


# --------------------------------------------------------------------------
# Trace helpers (real engine runs; forgeries rebuild the whole hash chain)
# --------------------------------------------------------------------------


def _run_engine_trace(root: Path):
    bundle = rf.CandidateBundle()
    executor = ef.ReductionExecutor(bundle)
    with JsonlTraceSink(root, EVIDENCE_APPEND_BUDGET) as sink:
        return ef.run_reduction(bundle, executor, sink)


def _load_records(root: Path) -> list[dict]:
    lines = [line for line in (root / TRACE_FILE_NAME).read_bytes().split(b"\n") if line]
    return [json.loads(line) for line in lines]


def _write_records(root: Path, records: list[dict]) -> None:
    """Rebuild the record chain; ACCEPTED inline comparison_hashes are fixed
    up to the recomputed hashes of the just-closed group (exactly what a real
    forger rebuilding the chain would have to do)."""
    previous = _GENESIS
    lines: list[bytes] = []
    group_hashes: list[str] = []
    last_kind = None
    for obj in records:
        kind = obj["kind"]
        if kind == "REQUESTED" and last_kind != "COMPARISON":
            group_hashes = []
        if kind == "ACCEPTED":
            obj["inline"]["comparison_hashes"] = list(group_hashes)
        obj["prev_hash"] = previous
        obj["hash"] = ""
        record = decode_trace_record(obj)
        previous = record.hash
        if kind == "COMPARISON":
            group_hashes.append(record.hash)
        last_kind = kind
        lines.append(canonical_json(record.to_obj()))
    (root / TRACE_FILE_NAME).write_bytes(b"\n".join(lines) + b"\n")


# --------------------------------------------------------------------------
# Generation-only source
# --------------------------------------------------------------------------


def _write_generation_bundle(root: Path) -> None:
    """A real two-case COMPLETE bundle written by the offline generator (the
    input material only; every expected verdict in the test is hand-stated).

    A zero-case bundle would lose its empty ``cases/`` directory in the
    file-only snapshot copy, so the fixture emits real case documents."""
    profile = Profile(
        rules=(RuleSelector("mysql80.integer-decimal", 1),),
        templates=(TemplateId.Q1,),
        index_variants=(IndexVariant.NONE,),
        row_count=8,
        predicate_atoms=1,
        attempts_per_ordinal=8,
        max_payload_bytes=64 * 1024,
        max_bundle_bytes=4 * 1024 * 1024,
    )
    generate_and_write(profile, 42, 2, root)


def test_generation_only_source_semantic_and_safety_not_applicable(tmp_path: Path) -> None:
    root = tmp_path / "gen"
    _write_generation_bundle(root)
    assert validate_output_dir(root).problems == ()  # fixture sanity
    assessment = _snapshot_and_assess(root, tmp_path, "gen")

    assert assessment.native_kind.value == "generation"
    assert assessment.selection is None
    assert assessment.attempts == ()

    assert assessment.semantic.applicable is False
    assert assessment.semantic.status.value == "NOT_RECOMPUTED"
    assert "generation_has_no_comparison" in assessment.semantic.reason_codes

    assert assessment.execution_safety.applicable is False
    assert assessment.execution_safety.status.value == "NOT_APPLICABLE"

    assert assessment.provenance.applicable is False
    assert assessment.structural.status.value == "COMPLETE"


# --------------------------------------------------------------------------
# Run source: consistent attempt recomputes
# --------------------------------------------------------------------------


def test_consistent_run_recomputes_attempt(tmp_path: Path) -> None:
    root = tmp_path / "run"
    _write_run_root(root, ["attempt-orig"])
    assessment = _snapshot_and_assess(root, tmp_path, "run")

    assert assessment.native_kind.value == "run"
    assert assessment.selection is None

    # Structural: manifest + environment + full attempt doc set present.
    assert assessment.structural.status.value == "COMPLETE"
    assert assessment.structural.checked_objects == 1
    assert assessment.structural.unchecked_objects == 0

    # Semantic: the recorded comparison was produced by a real compare_case
    # call over these very documents, so the independent recompute matches.
    assert assessment.semantic.applicable is True
    assert assessment.semantic.status.value == "RECOMPUTED"
    assert len(assessment.attempts) == 1
    result = assessment.attempts[0]
    assert result.attempt_id == "attempt-orig"
    assert result.case_id is not None
    assert result.static_check_status == "PASS"
    assert result.recompute.value == "RECOMPUTED"
    assert result.recomputed_comparison_hash == result.original_comparison_hash
    assert result.synthetic.value == "SYNTHETIC"

    # Provenance/safety: no observation ledger was written; safety comes from
    # the confirmed terminal receipt only.
    assert assessment.provenance.status.value == "UNVERIFIED"
    assert assessment.execution_safety.status.value == "CONFIRMED"


def test_forged_comparison_conflicts_and_original_is_preserved(tmp_path: Path) -> None:
    root = tmp_path / "forged-run"
    request, expectation, evidence = rf.build_attempt(
        run_id="run-replay-1", attempt_id="attempt-orig"
    )
    prefix = "attempts/attempt-orig/"
    _write(root, prefix + "request.json", dump_attempt_request(request) + b"\n")
    _write(root, prefix + "expectation.json", dump_attempt_expectation(expectation) + b"\n")
    _write(root, prefix + "execution-evidence.json", dump_execution_evidence(evidence) + b"\n")

    # A real comparison over DIFFERENT observed rows (match instead of the
    # fixture's mismatch): internally consistent, so every loader accepts it —
    # only the semantic recompute can catch the contradiction.
    other_bundle = rf.build_attempt(
        run_id="run-replay-1",
        attempt_id="attempt-orig",
        b_result_rows=rf.MATCH_B_ROWS,
    )
    forged = compare_case(other_bundle[0], other_bundle[1], other_bundle[2], ComparisonBudget())
    original_bytes = dump_comparison(forged) + b"\n"
    _write(root, prefix + "comparison.json", original_bytes)
    _write(root, prefix + "terminal.json", canonical_json(evidence.terminal.to_obj()) + b"\n")
    _write_json(root, "environment.json", _environment_manifest().to_obj())
    _write_json(root, "runner-manifest.json", _runner_manifest(["attempt-orig"]).to_obj())

    assessment = _snapshot_and_assess(root, tmp_path, "forged-run")

    assert assessment.semantic.status.value == "CONFLICT"
    assert "semantic_conflict" in assessment.semantic.reason_codes
    assert len(assessment.attempts) == 1
    result = assessment.attempts[0]
    assert result.recompute.value == "CONFLICT"
    # The recompute runs over the STORED request/expectation/evidence (the
    # mismatch fixture), so it reproduces the honest comparison — which
    # contradicts the forged hash that was published.
    honest = compare_case(request, expectation, evidence, ComparisonBudget())
    assert result.recomputed_comparison_hash == honest.hash
    assert result.recomputed_comparison_hash != result.original_comparison_hash
    assert result.original_comparison_hash == forged.hash
    # The original document is preserved verbatim; nothing was rewritten.
    stored = root / (prefix + "comparison.json")
    assert stored.read_bytes() == original_bytes
    snapshot_copy = (
        tmp_path / "out-forged-run" / "raw" / assessment.source_id / (prefix + "comparison.json")
    )
    assert snapshot_copy.read_bytes() == original_bytes


def test_unknown_rule_is_not_recomputed(tmp_path: Path) -> None:
    root = tmp_path / "unknown-rule"
    request, expectation, evidence = rf.build_attempt(
        run_id="run-replay-1", attempt_id="attempt-orig"
    )
    payload = replace(request.payload, rule=RuleRef("mysql80.does-not-exist", 1))
    request = replace(request, payload=payload)
    _write_attempt_docs(root, "attempt-orig", (request, expectation, evidence))
    _write_json(root, "environment.json", _environment_manifest().to_obj())
    _write_json(root, "runner-manifest.json", _runner_manifest(["attempt-orig"]).to_obj())

    assessment = _snapshot_and_assess(root, tmp_path, "unknown-rule")
    assert assessment.semantic.status.value == "NOT_RECOMPUTED"
    assert "unknown_rule" in assessment.semantic.reason_codes
    assert assessment.attempts[0].static_check_status == "FAIL"
    assert assessment.attempts[0].recomputed_comparison_hash is None


def test_run_missing_attempt_document_is_structurally_partial(tmp_path: Path) -> None:
    root = tmp_path / "run-gap"
    _write_run_root(root, ["attempt-orig"])
    (root / "attempts/attempt-orig/comparison.json").unlink()
    assessment = _snapshot_and_assess(root, tmp_path, "run-gap")

    assert assessment.structural.status.value == "PARTIAL"
    assert "missing_attempt_documents" in assessment.structural.reason_codes
    assert "missing_snapshot_file" in assessment.structural.reason_codes
    # Without the recorded comparison nothing can be recomputed.
    assert assessment.semantic.status.value == "NOT_RECOMPUTED"
    assert "document_missing" in assessment.semantic.reason_codes
    assert assessment.attempts[0].recompute.value == "NOT_RECOMPUTED"


def test_deadline_exhausted_attempts_stay_unaudited(tmp_path: Path) -> None:
    root = tmp_path / "run-two"
    _write_run_root(root, ["attempt-a", "attempt-b"])
    expired = Control(clock=lambda: 10.0, deadline=5.0, cancelled=lambda: False)
    assessment = _snapshot_and_assess(root, tmp_path, "run-two", control=expired)

    assert assessment.semantic.status.value == "NOT_RECOMPUTED"
    assert "budget_exhausted" in assessment.semantic.reason_codes
    assert assessment.semantic.checked_objects == 0
    assert assessment.semantic.unchecked_objects == 2
    assert len(assessment.attempts) == 2
    for result in assessment.attempts:
        assert result.recompute.value == "NOT_RECOMPUTED"
        assert result.limit_reasons == ("budget_exhausted",)
    assert assessment.structural.unchecked_objects == 2


# --------------------------------------------------------------------------
# Trace sources
# --------------------------------------------------------------------------


def test_honest_full_trace_is_verified_and_recomputed(tmp_path: Path) -> None:
    root = tmp_path / "trace-honest"
    _run_engine_trace(root)
    structural = read_trace(root)
    assert structural.trace_status == "COMPLETE"

    assessment = _snapshot_and_assess(root, tmp_path, "trace-honest")
    assert assessment.native_kind.value == "trace"
    assert assessment.structural.status.value == "COMPLETE"

    assert assessment.semantic.applicable is True
    assert assessment.semantic.status.value == "RECOMPUTED"
    assert assessment.attempts
    for result in assessment.attempts:
        assert result.recompute.value == "RECOMPUTED"

    selection = assessment.selection
    assert selection is not None
    assert selection.chain_status == "VERIFIED"
    assert selection.chain_verified is True
    assert selection.constraints == ()
    assert selection.best_payload_ref is not None
    assert selection.best_case_id is not None


def test_legacy_trace_is_not_recomputed_and_not_exportable(tmp_path: Path) -> None:
    root = tmp_path / "trace-legacy"
    _run_engine_trace(root)
    records = _load_records(root)
    for obj in records:
        if obj["kind"] == "START":
            del obj["inline"]["evidence_profile"]
    _write_records(root, records)
    assert read_trace(root).trace_status == "COMPLETE"

    assessment = _snapshot_and_assess(root, tmp_path, "trace-legacy")

    assert assessment.semantic.applicable is False
    assert assessment.semantic.status.value == "NOT_RECOMPUTED"
    assert "legacy_trace" in assessment.semantic.reason_codes

    selection = assessment.selection
    assert selection is not None
    assert selection.chain_status == "LEGACY"
    assert selection.chain_verified is False
    assert "legacy_trace_no_best_export" in selection.constraints


def test_forged_trace_evidence_is_a_semantic_conflict(tmp_path: Path) -> None:
    root = tmp_path / "trace-forged"
    _run_engine_trace(root)
    records = _load_records(root)
    target = next(obj for obj in records if obj["kind"] == "EVIDENCE")
    ref = target["payload_ref"]
    document = json.loads((root / ref["path"]).read_bytes())
    row = document["b_query"]["result"]["rows"][0][0]
    row["value"] = str(int(row["value"]) - 1)
    result_doc = document["b_query"]["result"]
    result_doc["payload_hash"] = sha256_hex(
        canonical_json({"columns": result_doc["columns"], "rows": result_doc["rows"]})
    )
    document["evidence_hash"] = ""
    from mtsql_typecheck.contracts.execution import load_execution_evidence
    from mtsql_typecheck.contracts.execution import dump_execution_evidence as dump_ev

    sealed = load_execution_evidence(document)
    document["evidence_hash"] = sealed.evidence_hash
    payload = dump_ev(sealed)
    digest = sha256_hex(payload)
    (root / "files" / f"{digest}.json").write_bytes(payload)
    ref["path"] = f"files/{digest}.json"
    ref["size_bytes"] = len(payload)
    ref["sha256"] = digest
    target["inline"]["evidence_hash"] = document["evidence_hash"]
    _write_records(root, records)
    assert read_trace(root).trace_status == "COMPLETE"

    assessment = _snapshot_and_assess(root, tmp_path, "trace-forged")

    assert assessment.semantic.status.value == "CONFLICT"
    assert "semantic_conflict" in assessment.semantic.reason_codes
    assert any(result.recompute.value == "CONFLICT" for result in assessment.attempts)

    selection = assessment.selection
    assert selection is not None
    assert selection.chain_status == "CONFLICT"
    assert selection.chain_verified is False


def test_trace_missing_third_round_stays_not_audited(tmp_path: Path) -> None:
    root = tmp_path / "trace-partial"
    _run_engine_trace(root)
    records = _load_records(root)
    # Cut the trace before the last replay round completes: the group never
    # closes, so the run is structurally incomplete and NO attempt after the
    # cut may be reported as audited.
    last_comparison = max(
        index for index, obj in enumerate(records) if obj["kind"] == "COMPARISON"
    )
    records = records[:last_comparison]
    _write_records(root, records)
    assert read_trace(root).trace_status == "PARTIAL"

    assessment = _snapshot_and_assess(root, tmp_path, "trace-partial")

    assert assessment.structural.status.value == "PARTIAL"
    assert "trace_incomplete" in assessment.structural.reason_codes
    assert assessment.semantic.status.value == "NOT_RECOMPUTED"
    for result in assessment.attempts:
        assert result.recompute.value != "RECOMPUTED"

    selection = assessment.selection
    assert selection is not None
    assert selection.chain_status == "UNVERIFIED"
    assert selection.chain_verified is False


def test_zero_record_trace_claiming_completion_is_partial(tmp_path: Path) -> None:
    root = tmp_path / "trace-empty"
    (root / TRACE_FILE_NAME).parent.mkdir(parents=True, exist_ok=True)
    (root / TRACE_FILE_NAME).write_bytes(b"")
    # A declared replay result beside the sink root: work WAS declared.
    from mtsql_typecheck.contracts.oracle import ReplayOutcome, ReplayResult, dump_replay_result

    result = ReplayResult(
        comparison_hash=hex64("cmp"),
        policy_hash=hex64("policy"),
        attempt_hashes=(),
        requested=0,
        completed=0,
        comparable=0,
        matching_signature=0,
        exact_signatures=(),
        outcome=ReplayOutcome.NOT_REPLAYED,
        stop_reason=None,
        operational_failure=False,
        synthetic=False,
    )
    (root / "replay-result.json").write_bytes(dump_replay_result(result) + b"\n")

    assessment = _snapshot_and_assess(root, tmp_path, "trace-empty")

    # read_trace reports zero-record "COMPLETE"; the D4 gate downgrades it:
    # an empty trace can never show SNAPSHOT/START, so no run is complete.
    assert assessment.structural.status.value == "PARTIAL"
    assert "trace_zero_records" in assessment.structural.reason_codes
    assert assessment.semantic.status.value == "NOT_RECOMPUTED"


@pytest.mark.parametrize(
    "record_bytes",
    [
        b"{not json}\n",
        b'{"seq": 1, "kind": "BOGUS", "payload_ref": null, "inline": {}, '
        b'"prev_hash": "' + b"0" * 64 + b'", "hash": "' + b"1" * 64 + b'"}\n',
    ],
)
def test_corrupt_trace_records_are_structurally_corrupt(tmp_path: Path, record_bytes: bytes) -> None:
    root = tmp_path / "trace-corrupt"
    root.mkdir(parents=True)
    (root / TRACE_FILE_NAME).write_bytes(record_bytes)

    assessment = _snapshot_and_assess(root, tmp_path, "trace-corrupt")
    assert assessment.structural.status.value in ("CORRUPT", "PARTIAL")
    assert assessment.semantic.status.value == "NOT_RECOMPUTED"
    selection = assessment.selection
    if selection is not None:
        assert selection.chain_verified is False


def test_ownership_journal_bytes_are_untouched_by_assessment(tmp_path: Path) -> None:
    """Assessment is strictly read-only over the snapshot copy."""
    root = tmp_path / "run"
    _write_run_root(root, ["attempt-orig"])
    events = [
        OwnershipEvent(
            seq=1,
            prev_event_hash="0" * 64,
            run_id="run-replay-1",
            event_kind=OwnershipEventKind.RUN_LOCK_ACQUIRED,
            token="lock-1",
        )
    ]
    journal_bytes = dump_ownership_journal(tuple(events)) + b"\n"
    _write(root, "ownership.jsonl", journal_bytes)

    before = {p: (root / p).read_bytes() for p in ("ownership.jsonl",)}
    _snapshot_and_assess(root, tmp_path, "run")
    for relpath, data in before.items():
        assert (root / relpath).read_bytes() == data
