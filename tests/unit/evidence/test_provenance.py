"""Unit tests for evidence/provenance.py (design 6.4.3 cross-checks).

Run fixtures are built from the hand-written reduction fakes; the
StageObservation ledgers and ownership journals are crafted per test so every
expected provenance/safety verdict is stated explicitly, never derived from
the code under test.  Both dimensions read only the snapshot copy.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

from mtsql_typecheck.contracts.case import (
    GenerationManifest,
    GenerationStatus,
    IndexVariant,
    NameMap,
    ObservedEnvironment,
    Profile,
    REQUIRED_SQL_MODE_TOKENS,
    RuleSelector,
    SemverIdentity,
    TemplateId,
)
from mtsql_typecheck.contracts.codec import canonical_json, sha256_hex
from mtsql_typecheck.contracts.delivery import Limits
from mtsql_typecheck.contracts.execution import (
    CleanupState,
    Side,
    TerminalReceipt,
    TerminationState,
    dump_attempt_expectation,
    dump_attempt_request,
    dump_execution_evidence,
)
from mtsql_typecheck.contracts.oracle import ComparisonBudget, dump_comparison
from mtsql_typecheck.contracts.runner import (
    BuildIdSource,
    EnvironmentManifest,
    OwnershipEvent,
    OwnershipEventKind,
    RUNNER_EVIDENCE_PROFILE,
    RunnerCommand,
    RunnerManifest,
    RunnerStatus,
    StageObservation,
    StageObservationKind,
    dump_ownership_journal,
    dump_stage_observation,
)
from mtsql_typecheck.evidence.native import detect_native_kind, enumerate_source
from mtsql_typecheck.evidence.provenance import (
    assess_execution_safety,
    assess_provenance,
)
from mtsql_typecheck.evidence.reader import SourceReader
from mtsql_typecheck.evidence.snapshot import Snapshotter
from mtsql_typecheck.oracle.gates import compare_case

# The reduction fakes are uniquely named suite-wide; add their directory to
# the path explicitly so this suite does not depend on rootdir configuration.
_REDUCTION_TEST_DIR = Path(__file__).resolve().parent.parent / "reduction"
if str(_REDUCTION_TEST_DIR) not in sys.path:
    sys.path.append(str(_REDUCTION_TEST_DIR))

import replay_fakes as rf  # noqa: E402

_RUN_ID = "run-replay-1"


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


def _env() -> ObservedEnvironment:
    return ObservedEnvironment(
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
        observed_environment=_env(),
        server_uuid="1" * 32,
        python_version="3.11.0",
        os_platform="Linux",
        driver_name="pymysql",
        driver_version="1.0.0",
        adapter_version="d3-adapter-1",
        mapping_version="d3-mapping-1",
        build_id="20250715",
        build_id_source=BuildIdSource.OBSERVED,
        sanitized_config_hash=hex64("config"),
        probes=(),
    )


def _runner_manifest(
    attempt_ids: list[str], *, ownership: bool = False, **overrides: object
) -> RunnerManifest:
    refs: list[tuple[str, str]] = [
        ("environment", "environment.json"),
        ("runner_manifest", "runner-manifest.json"),
    ]
    if ownership:
        refs.append(("ownership", "ownership.jsonl"))
    refs.extend(("attempt:" + aid, f"attempts/{aid}/comparison.json") for aid in attempt_ids)
    fields: dict[str, object] = dict(
        command=RunnerCommand.RUN,
        run_id=_RUN_ID,
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
        evidence_profile=RUNNER_EVIDENCE_PROFILE,
        tool_version="0.1.0",
        contract_versions=(
            ("case", "1"),
            ("execution", "1"),
            ("oracle", "o1"),
            ("runner", "1"),
        ),
        refs=tuple(refs),
        sanitized_config_hash=hex64("config"),
        stop_reason=None,
    )
    fields.update(overrides)
    return RunnerManifest(**fields)  # type: ignore[arg-type]


def _observation(
    side: Side | None,
    stage: str,
    ordinal: int,
    connection_id: str | None,
    actual_database: str | None = None,
) -> StageObservation:
    return StageObservation(
        side=side,
        stage=StageObservationKind[stage],
        ordinal=ordinal,
        connection_id=connection_id,
        actual_database=actual_database,
        session_id=None,
        sql_hash=None,
        sql_ref=None,
        diagnostics_ref=None,
        field_metadata_ref=None,
    )


def _consistent_observations(attempt_id: str) -> list[StageObservation]:
    """A ledger that agrees with the evidence SideContexts: the query-phase
    connection id equals the setup/readback ids on both sides."""
    records: list[StageObservation] = []
    ordinal = 0
    for side in (Side.A, Side.B):
        label = str(side.value).lower()
        connection_id = f"{attempt_id}-conn-{label}"
        database = "tc_a" if side is Side.A else "tc_b"
        for stage in ("DDL", "INSERT"):
            records.append(_observation(side, stage, ordinal, connection_id, database))
            ordinal += 1
        records.append(_observation(side, "READBACK", ordinal, connection_id, database))
        ordinal += 1
        records.append(_observation(side, "SESSION", ordinal, connection_id, database))
        ordinal += 1
        records.append(_observation(side, "SELECT", ordinal, connection_id, database))
        ordinal += 1
    return records


def _rewritten_observations(attempt_id: str) -> list[StageObservation]:
    """The D3 id rewrite: setup/readback stages recorded the ORIGINAL
    connections while SESSION/SELECT reuse the query id that the SideContext
    then claims for all three roles."""
    records: list[StageObservation] = []
    ordinal = 0
    for side in (Side.A, Side.B):
        label = str(side.value).lower()
        original = f"prep-{attempt_id}-conn-{label}"
        query_id = f"{attempt_id}-conn-{label}"
        database = "tc_a" if side is Side.A else "tc_b"
        for stage in ("DDL", "INSERT"):
            records.append(_observation(side, stage, ordinal, original, database))
            ordinal += 1
        records.append(_observation(side, "READBACK", ordinal, original, database))
        ordinal += 1
        records.append(_observation(side, "SESSION", ordinal, query_id, database))
        ordinal += 1
        records.append(_observation(side, "SELECT", ordinal, query_id, database))
        ordinal += 1
    return records


def _journal(event_specs: list[dict[str, object]]) -> bytes:
    """Chain the given event payloads into a loadable journal (callers own
    seq/prev_event_hash construction; load_ownership_journal verifies it)."""
    previous = "0" * 64
    chained: list[OwnershipEvent] = []
    for seq, spec in enumerate(event_specs, start=1):
        event = OwnershipEvent(seq=seq, prev_event_hash=previous, run_id=_RUN_ID, **spec)
        chained.append(event)
        previous = event.content_hash
    return dump_ownership_journal(tuple(chained)) + b"\n"


def _write_run_root(
    root: Path,
    *,
    observations: list[StageObservation] | None,
    terminal: TerminalReceipt | None | bool = True,  # True -> keep the evidence default
    events: list[dict[str, object]] | None = None,
    manifest_overrides: dict[str, object] | None = None,
):
    """Run root with one attempt; returns (request, expectation, evidence)."""
    request, expectation, evidence = rf.build_attempt(run_id=_RUN_ID, attempt_id="attempt-orig")
    prefix = "attempts/attempt-orig/"
    _write(root, prefix + "request.json", dump_attempt_request(request) + b"\n")
    _write(root, prefix + "expectation.json", dump_attempt_expectation(expectation) + b"\n")
    _write(root, prefix + "execution-evidence.json", dump_execution_evidence(evidence) + b"\n")
    comparison = compare_case(request, expectation, evidence, ComparisonBudget())
    _write(root, prefix + "comparison.json", dump_comparison(comparison) + b"\n")

    if terminal is True:
        terminal = evidence.terminal
    if terminal is not None:
        _write(root, prefix + "terminal.json", canonical_json(terminal.to_obj()) + b"\n")
    if observations is not None:
        lines = b"".join(dump_stage_observation(record) + b"\n" for record in observations)
        _write(root, prefix + "observations.jsonl", lines)
    if events is not None:
        _write(root, "ownership.jsonl", _journal(events))
    _write_json(root, "environment.json", _environment_manifest().to_obj())
    _write_json(
        root,
        "runner-manifest.json",
        _runner_manifest(
            ["attempt-orig"], ownership=events is not None, **(manifest_overrides or {})
        ).to_obj(),
    )
    return request, expectation, evidence


def _assess_dimensions(root: Path, tmp_path: Path, name: str):
    limits = Limits()
    out = tmp_path / f"out-{name}"
    with SourceReader(root, limits=limits) as reader:
        kind = detect_native_kind(root)
        plan = enumerate_source(reader, kind, limits)
        snapshot = Snapshotter(reader, out, limits).capture(plan)
        # Both dimensions read ONLY the snapshot copy through the reader,
        # exactly as assess_snapshot opens it.
        with SourceReader(out / "raw" / snapshot.source_id, limits=limits) as snap_reader:
            provenance = assess_provenance(
                snap_reader,
                plan,
                limits,
                None,
                snapshot_root=out / "raw" / snapshot.source_id,
            )
            safety = assess_execution_safety(
                snap_reader,
                plan,
                limits,
                None,
                snapshot_root=out / "raw" / snapshot.source_id,
            )
    return provenance, safety


# --------------------------------------------------------------------------
# Provenance: session identity cross-checks
# --------------------------------------------------------------------------


def test_consistent_run_provenance_is_corroborated(tmp_path: Path) -> None:
    root = tmp_path / "run-ok"
    _write_run_root(
        root,
        observations=_consistent_observations("attempt-orig"),
        events=[
            {"event_kind": OwnershipEventKind.SESSION_REGISTERED,
             "attempt_id": "attempt-orig", "connection_id": "attempt-orig-conn-a"},
            {"event_kind": OwnershipEventKind.SESSION_REGISTERED,
             "attempt_id": "attempt-orig", "connection_id": "attempt-orig-conn-b"},
            {"event_kind": OwnershipEventKind.TERMINATION_CONFIRMED,
             "attempt_id": "attempt-orig"},
            {"event_kind": OwnershipEventKind.CLEANUP_CONFIRMED,
             "attempt_id": "attempt-orig"},
        ],
    )
    provenance, safety = _assess_dimensions(root, tmp_path, "run-ok")

    assert provenance.applicable is True
    assert provenance.status.value == "CORROBORATED"
    assert provenance.reason_codes == ()
    assert safety.applicable is True
    assert safety.status.value == "CONFIRMED"
    assert safety.reason_codes == ()


def test_session_identity_rewrite_is_a_conflict(tmp_path: Path) -> None:
    root = tmp_path / "run-rewrite"
    _write_run_root(root, observations=_rewritten_observations("attempt-orig"))
    provenance, _safety = _assess_dimensions(root, tmp_path, "run-rewrite")

    assert provenance.status.value == "CONFLICT"
    assert "session_identity_rewritten" in provenance.reason_codes


def test_missing_setup_records_stay_unverified(tmp_path: Path) -> None:
    root = tmp_path / "run-partial-ledger"
    _write_run_root(
        root,
        observations=[
            _observation(Side.A, "SESSION", 0, "attempt-orig-conn-a", "tc_a"),
            _observation(Side.B, "SELECT", 1, "attempt-orig-conn-b", "tc_b"),
        ],
    )
    provenance, _safety = _assess_dimensions(root, tmp_path, "run-partial-ledger")

    # Original setup/readback records absent: the session identity cannot be
    # corroborated — UNVERIFIED, never upgraded (design 6.4.3).
    assert provenance.status.value == "UNVERIFIED"
    assert "setup_observations_missing" in provenance.reason_codes
    assert "readback_observations_missing" in provenance.reason_codes


def test_select_connection_mismatch_is_a_conflict(tmp_path: Path) -> None:
    root = tmp_path / "run-select"
    _write_run_root(
        root,
        observations=[
            _observation(Side.A, "DDL", 0, "attempt-orig-conn-a", "tc_a"),
            _observation(Side.A, "READBACK", 1, "attempt-orig-conn-a", "tc_a"),
            _observation(Side.A, "SELECT", 2, "other-conn", "tc_a"),
            _observation(Side.B, "DDL", 3, "attempt-orig-conn-b", "tc_b"),
            _observation(Side.B, "READBACK", 4, "attempt-orig-conn-b", "tc_b"),
            _observation(Side.B, "SELECT", 5, "attempt-orig-conn-b", "tc_b"),
        ],
    )
    provenance, _safety = _assess_dimensions(root, tmp_path, "run-select")

    assert provenance.status.value == "CONFLICT"
    assert "select_connection_mismatch" in provenance.reason_codes


def test_database_binding_mismatch_is_a_conflict(tmp_path: Path) -> None:
    root = tmp_path / "run-db"
    _write_run_root(
        root,
        observations=_consistent_observations("attempt-orig")
        + [_observation(Side.A, "SELECT", 99, "attempt-orig-conn-a", "wrong-db")],
    )
    provenance, _safety = _assess_dimensions(root, tmp_path, "run-db")

    assert provenance.status.value == "CONFLICT"
    assert "database_binding_mismatch" in provenance.reason_codes


def test_missing_observations_and_journal_are_unverified_not_corroborated(
    tmp_path: Path,
) -> None:
    root = tmp_path / "run-no-records"
    _write_run_root(root, observations=None, terminal=None)
    provenance, safety = _assess_dimensions(root, tmp_path, "run-no-records")

    assert provenance.status.value == "UNVERIFIED"
    assert "observations_missing" in provenance.reason_codes
    assert "ownership_journal_missing" in provenance.reason_codes
    assert provenance.status.value != "CORROBORATED"
    # Queries ran (evidence carries them) but there is no terminal receipt:
    # safety stays UNKNOWN, never NOT_APPLICABLE.
    assert safety.applicable is True
    assert safety.status.value == "UNKNOWN"
    assert "terminal_receipt_missing" in safety.reason_codes


# --------------------------------------------------------------------------
# Execution safety
# --------------------------------------------------------------------------


def test_kill_reply_without_terminal_is_unknown(tmp_path: Path) -> None:
    root = tmp_path / "run-kill"
    _write_run_root(
        root,
        observations=_consistent_observations("attempt-orig")
        + [_observation(None, "TERMINATION", 50, "kill-conn")],
        terminal=None,
    )
    _provenance, safety = _assess_dimensions(root, tmp_path, "run-kill")

    assert safety.applicable is True
    assert safety.status.value == "UNKNOWN"
    assert "kill_reply_without_terminal" in safety.reason_codes


def test_leftover_count_without_termination_evidence_is_unknown(tmp_path: Path) -> None:
    """A zero leftover count in the manifest alone must never CONFIRM safety:
    with the terminal receipt removed the verdict is UNKNOWN."""
    root = tmp_path / "run-no-terminal"
    _write_run_root(
        root,
        observations=None,
        terminal=None,
        manifest_overrides={"leftover_objects": 0, "leftover_sessions": 0},
    )
    _provenance, safety = _assess_dimensions(root, tmp_path, "run-no-terminal")

    assert safety.applicable is True
    assert safety.status.value == "UNKNOWN"
    assert safety.status.value != "CONFIRMED"
    assert safety.status.value != "NOT_APPLICABLE"


def test_manifest_leftover_objects_are_unsafe(tmp_path: Path) -> None:
    root = tmp_path / "run-leftover"
    _write_run_root(
        root,
        observations=_consistent_observations("attempt-orig"),
        events=[
            {"event_kind": OwnershipEventKind.SESSION_REGISTERED,
             "attempt_id": "attempt-orig", "connection_id": "attempt-orig-conn-a"},
            {"event_kind": OwnershipEventKind.SESSION_REGISTERED,
             "attempt_id": "attempt-orig", "connection_id": "attempt-orig-conn-b"},
            {"event_kind": OwnershipEventKind.TERMINATION_CONFIRMED,
             "attempt_id": "attempt-orig"},
            {"event_kind": OwnershipEventKind.CLEANUP_CONFIRMED,
             "attempt_id": "attempt-orig"},
        ],
        manifest_overrides={"leftover_objects": 2},
    )
    provenance, safety = _assess_dimensions(root, tmp_path, "run-leftover")

    assert safety.status.value == "UNSAFE"
    assert "manifest_leftover_objects" in safety.reason_codes
    assert provenance.status.value == "CORROBORATED"  # unaffected dimension


def test_ownership_contradicting_terminal_is_unknown(tmp_path: Path) -> None:
    root = tmp_path / "run-term-unknown"
    _write_run_root(
        root,
        observations=_consistent_observations("attempt-orig"),
        events=[
            {"event_kind": OwnershipEventKind.TERMINATION_UNKNOWN,
             "attempt_id": "attempt-orig"},
        ],
    )
    provenance, safety = _assess_dimensions(root, tmp_path, "run-term-unknown")

    # The journal says termination is unknown while the receipt says CONFIRMED:
    # both dimensions must surface the contradiction.
    assert provenance.status.value == "CONFLICT"
    assert "ownership_terminal_mismatch" in provenance.reason_codes
    assert safety.status.value == "UNKNOWN"
    assert "ownership_termination_unknown" in safety.reason_codes


def test_ownership_undropped_objects_are_unsafe(tmp_path: Path) -> None:
    root = tmp_path / "run-undropped"
    _write_run_root(
        root,
        observations=_consistent_observations("attempt-orig"),
        events=[
            {"event_kind": OwnershipEventKind.OBJECT_CREATED,
             "attempt_id": "attempt-orig", "object_name": "tc_a"},
        ],
    )
    _provenance, safety = _assess_dimensions(root, tmp_path, "run-undropped")

    assert safety.status.value == "UNSAFE"
    assert "ownership_objects_undropped" in safety.reason_codes


def test_cleanup_failed_is_unsafe(tmp_path: Path) -> None:
    root = tmp_path / "run-cleanup-failed"
    _write_run_root(
        root,
        observations=_consistent_observations("attempt-orig"),
        terminal=TerminalReceipt(
            attempt_id="attempt-orig",
            termination=TerminationState.CONFIRMED,
            cleanup=CleanupState.FAILED,
            owned_objects=(),
        ),
    )
    _provenance, safety = _assess_dimensions(root, tmp_path, "run-cleanup-failed")

    assert safety.status.value == "UNSAFE"
    assert "cleanup_not_done" in safety.reason_codes


def test_preflight_only_attempt_without_queries_is_not_applicable(tmp_path: Path) -> None:
    root = tmp_path / "run-no-queries"
    request, expectation, evidence = rf.build_attempt(run_id=_RUN_ID, attempt_id="attempt-orig")
    no_query_evidence = replace(
        evidence, a_query=None, b_query=None, terminal=None, evidence_hash=""
    )
    prefix = "attempts/attempt-orig/"
    _write(root, prefix + "request.json", dump_attempt_request(request) + b"\n")
    _write(root, prefix + "expectation.json", dump_attempt_expectation(expectation) + b"\n")
    _write(
        root, prefix + "execution-evidence.json", dump_execution_evidence(no_query_evidence)
        + b"\n"
    )
    _write_json(root, "environment.json", _environment_manifest().to_obj())
    _write_json(root, "runner-manifest.json", _runner_manifest(["attempt-orig"]).to_obj())

    provenance, safety = _assess_dimensions(root, tmp_path, "run-no-queries")

    # No execution happened: safety is honestly not applicable; provenance has
    # no records to cross-check and stays UNVERIFIED (still applicable).
    assert safety.applicable is False
    assert safety.status.value == "NOT_APPLICABLE"
    assert provenance.status.value == "UNVERIFIED"


# --------------------------------------------------------------------------
# Non-run kinds
# --------------------------------------------------------------------------


def test_generation_source_provenance_and_safety_not_applicable(tmp_path: Path) -> None:
    """A generation-only bundle has no execution: safety is NOT_APPLICABLE and
    provenance is not applicable either (no records could ever exist)."""
    root = tmp_path / "gen"
    profile = Profile(
        rules=(RuleSelector("mysql80.signed-widen", 1),),
        templates=(TemplateId.Q1,),
        index_variants=(IndexVariant.NONE,),
        row_count=3,
        predicate_atoms=1,
        attempts_per_ordinal=2,
        max_payload_bytes=64 * 1024,
        max_bundle_bytes=1024 * 1024,
    )
    manifest = GenerationManifest(
        profile_hash=sha256_hex(canonical_json(profile.to_obj())),
        seed=0,
        requested_ordinals=0,
        attempted_candidates=0,
        emitted_occurrences=0,
        unique_cases=0,
        rejected_ordinals=0,
        interrupted_ordinals=0,
        not_attempted=0,
        status=GenerationStatus.COMPLETE,
        generator=SemverIdentity("g1", "1"),
    )
    _write(root, "profile.json", canonical_json(profile.to_obj()) + b"\n")
    _write(root, "generation-manifest.json", canonical_json(manifest.to_obj()) + b"\n")

    limits = Limits()
    out = tmp_path / "out-gen"
    with SourceReader(root, limits=limits) as reader:
        kind = detect_native_kind(root)
        plan = enumerate_source(reader, kind, limits)
        snapshot = Snapshotter(reader, out, limits).capture(plan)
        with SourceReader(out / "raw" / snapshot.source_id, limits=limits) as snap_reader:
            provenance = assess_provenance(snap_reader, plan, limits)
            safety = assess_execution_safety(snap_reader, plan, limits)

    assert provenance.applicable is False
    assert provenance.status.value == "UNVERIFIED"
    assert "no_execution_records" in provenance.reason_codes
    assert safety.applicable is False
    assert safety.status.value == "NOT_APPLICABLE"
    assert "no_execution_records" in safety.reason_codes


def test_snapshot_root_mismatch_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "run-ok"
    _write_run_root(root, observations=None)
    limits = Limits()
    out = tmp_path / "out-mismatch"
    with SourceReader(root, limits=limits) as reader:
        kind = detect_native_kind(root)
        plan = enumerate_source(reader, kind, limits)
        snapshot = Snapshotter(reader, out, limits).capture(plan)
        with SourceReader(out / "raw" / snapshot.source_id, limits=limits) as snap_reader:
            try:
                assess_provenance(snap_reader, plan, limits, None, snapshot_root=root)
            except ValueError:
                pass
            else:
                raise AssertionError("snapshot_root cross-check did not refuse a mismatch")


def test_name_map_fixture_guard() -> None:
    """Guard that the reduction fakes still expose the documented session ids
    these cross-checks rely on."""
    _request, _expectation, evidence = rf.build_attempt(run_id=_RUN_ID, attempt_id="attempt-orig")
    nm = NameMap("tc_a", "tc_b", "t_a", "t_b")
    assert evidence.a_context is not None
    assert evidence.a_context.name_map.database_a == nm.database_a
    assert evidence.a_context.setup_connection_id == "attempt-orig-conn-a"
