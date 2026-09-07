"""Unit tests for the run output-directory writer (runner/evidence.py).

Fakes only: no database, no network, no PyMySQL.  The preflight manifest
used for the environment round-trip comes from the shared controller fakes
(a fake probe source), never from a live server.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from controller_fakes import make_target_config
from mtsql_typecheck.contracts.codec import parse_strict_json
from mtsql_typecheck.contracts.execution import default_control
from mtsql_typecheck.contracts.runner import RunnerCommand, RunnerStatus
from mtsql_typecheck.runner.evidence import (
    ATTEMPTS_DIRNAME,
    ATTEMPT_FILE_NAMES,
    EVIDENCE_BUDGET_DEFAULT,
    ENVIRONMENT_NAME,
    MANIFEST_NAME,
    PAYLOADS_DIRNAME,
    RUN_LOCK_NAME,
    EvidenceBudgetExceeded,
    EvidencePathError,
    EvidenceWriter,
    write_exclusive_document,
)
from mtsql_typecheck.runner.preflight import run_preflight


def make_writer(root: Path, budget_bytes: int = EVIDENCE_BUDGET_DEFAULT) -> EvidenceWriter:
    return EvidenceWriter(root, budget_bytes)


def sample_manifest_record():
    """A minimal, contract-valid terminating manifest (zero counts)."""
    from mtsql_typecheck.contracts.runner import RUNNER_EVIDENCE_PROFILE, RunnerManifest

    return RunnerManifest(
        command=RunnerCommand.RUN,
        run_id="run-abc123",
        status=RunnerStatus.COMPLETE,
        requested=0,
        completed=0,
        comparable=0,
        match=0,
        candidate=0,
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


def environment_manifest(tmp_path: Path):
    config = make_target_config()
    return run_preflight(config, _FakeProbe(), default_control(5.0))


class _FakeProbe:
    def fetch_environment_facts(self):
        from controller_fakes import FakeProbeSource

        return FakeProbeSource().fetch_environment_facts()

    def runtime_identity(self):
        from controller_fakes import FakeProbeSource

        return FakeProbeSource().runtime_identity()

    def observed_build_id(self):
        from controller_fakes import BUILD_ID

        return BUILD_ID


# --------------------------------------------------------------------------
# Root layout / exclusivity
# --------------------------------------------------------------------------


def test_root_layout_is_created_exclusively(tmp_path: Path) -> None:
    root = tmp_path / "out"
    writer = make_writer(root)
    try:
        assert (root / RUN_LOCK_NAME).is_file()
        assert (root / ATTEMPTS_DIRNAME).is_dir()
        assert (root / PAYLOADS_DIRNAME).is_dir()
        assert writer.root == root.resolve()
        assert writer.remaining_bytes == EVIDENCE_BUDGET_DEFAULT
    finally:
        writer.close()


def test_existing_output_root_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "out"
    root.mkdir()
    (root / "keep.txt").write_bytes(b"user data")
    with pytest.raises(EvidencePathError) as excinfo:
        make_writer(root)
    assert "already exists" in str(excinfo.value)
    # The pre-existing content is untouched (never merged or overwritten).
    assert (root / "keep.txt").read_bytes() == b"user data"


def test_second_writer_over_the_same_root_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "out"
    first = make_writer(root)
    try:
        with pytest.raises(EvidencePathError):
            make_writer(root)
    finally:
        first.close()


def test_symlink_path_component_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    os.symlink(real, link)
    with pytest.raises(EvidencePathError):
        make_writer(link / "out")


def test_budget_bounds_are_enforced(tmp_path: Path) -> None:
    with pytest.raises(EvidencePathError):
        EvidenceWriter(tmp_path / "out-zero", 0)
    with pytest.raises(EvidencePathError):
        EvidenceWriter(tmp_path / "out-bool", True)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Per-attempt documents
# --------------------------------------------------------------------------


def test_attempt_document_round_trip(tmp_path: Path) -> None:
    writer = make_writer(tmp_path / "out")
    try:
        data = b'{"case_id": "x"}'
        written = writer.write_attempt_document("at-000001-abc", "request.json", data)
        assert written == len(data)
        path = writer.root / ATTEMPTS_DIRNAME / "at-000001-abc" / "request.json"
        assert path.read_bytes() == data
    finally:
        writer.close()


def test_attempt_document_idempotent_identical_rewrite(tmp_path: Path) -> None:
    writer = make_writer(tmp_path / "out")
    try:
        data = b"same-bytes"
        writer.write_attempt_document("at-1", "comparison.json", data)
        # Sealing the identical bytes again is a no-op (idempotent re-seal).
        assert writer.write_attempt_document("at-1", "comparison.json", data) == 0
        path = writer.root / ATTEMPTS_DIRNAME / "at-1" / "comparison.json"
        assert path.read_bytes() == data
        # Only the first write was charged to the budget.
        assert writer.bytes_written == len(data)
    finally:
        writer.close()


def test_attempt_document_different_content_is_refused(tmp_path: Path) -> None:
    writer = make_writer(tmp_path / "out")
    try:
        writer.write_attempt_document("at-1", "request.json", b"first")
        with pytest.raises(EvidencePathError):
            writer.write_attempt_document("at-1", "request.json", b"second")
        path = writer.root / ATTEMPTS_DIRNAME / "at-1" / "request.json"
        assert path.read_bytes() == b"first"
    finally:
        writer.close()


def test_attempt_document_unknown_name_and_bad_id_refused(tmp_path: Path) -> None:
    writer = make_writer(tmp_path / "out")
    try:
        with pytest.raises(EvidencePathError):
            writer.write_attempt_document("at-1", "extra.json", b"x")
        with pytest.raises(EvidencePathError):
            writer.write_attempt_document("../escape", "request.json", b"x")
        with pytest.raises(EvidencePathError):
            writer.write_attempt_document("", "request.json", b"x")
        # Nothing was created outside the writer root.
        assert not (tmp_path / "escape").exists()
    finally:
        writer.close()


def test_all_frozen_attempt_names_are_accepted(tmp_path: Path) -> None:
    writer = make_writer(tmp_path / "out")
    try:
        for name in sorted(ATTEMPT_FILE_NAMES):
            writer.write_attempt_document("at-1", name, b"{}")
    finally:
        writer.close()


# --------------------------------------------------------------------------
# Payload store
# --------------------------------------------------------------------------


def test_payload_publish_is_content_addressed_and_idempotent(tmp_path: Path) -> None:
    writer = make_writer(tmp_path / "out")
    try:
        data = b'{"payload": 1}'
        relpath = writer.publish_payload(data)
        assert relpath.startswith(f"{PAYLOADS_DIRNAME}/")
        assert relpath.endswith(".json")
        assert (writer.root / relpath).read_bytes() == data
        # Same bytes again: no rewrite, no extra charge.
        assert writer.publish_payload(data) == relpath
        assert writer.bytes_written == len(data)
        # Different bytes hash to a different file.
        other = writer.publish_payload(b'{"payload": 2}')
        assert other != relpath
    finally:
        writer.close()


# --------------------------------------------------------------------------
# Budget accounting
# --------------------------------------------------------------------------


def test_budget_exhaustion_refuses_with_reserve_floor(tmp_path: Path) -> None:
    writer = make_writer(tmp_path / "out", budget_bytes=1)
    try:
        # A 1-byte budget minus the 64 KiB reserve floor cannot admit anything.
        with pytest.raises(EvidenceBudgetExceeded):
            writer.write_attempt_document("at-1", "request.json", b"x")
        assert writer.bytes_written == 0
        assert not (writer.root / ATTEMPTS_DIRNAME / "at-1" / "request.json").exists()
    finally:
        writer.close()


def test_reserve_is_a_check_only(tmp_path: Path) -> None:
    writer = make_writer(tmp_path / "out")
    try:
        hint = writer.remaining_bytes  # would exhaust everything
        with pytest.raises(EvidenceBudgetExceeded):
            writer.reserve(hint)
        # reserve() charges nothing, so small writes still succeed afterwards.
        writer.write_attempt_document("at-1", "request.json", b"small")
        assert writer.bytes_written == len(b"small")
    finally:
        writer.close()


def test_closed_writer_refuses_writes(tmp_path: Path) -> None:
    writer = make_writer(tmp_path / "out")
    writer.close()
    from mtsql_typecheck.runner.evidence import EvidenceError

    with pytest.raises(EvidenceError):
        writer.publish_payload(b"x")


# --------------------------------------------------------------------------
# Environment / manifest documents
# --------------------------------------------------------------------------


def test_environment_round_trip(tmp_path: Path) -> None:
    from mtsql_typecheck.contracts.runner import load_environment_manifest

    writer = make_writer(tmp_path / "out")
    try:
        manifest = environment_manifest(tmp_path)
        writer.write_environment(manifest)
        path = writer.root / ENVIRONMENT_NAME
        loaded = load_environment_manifest(path.read_bytes())
        assert loaded.to_obj() == manifest.to_obj()
        # A re-seal of the identical document is an idempotent no-op.
        first_written = writer.bytes_written
        assert writer.write_environment(manifest) == 0
        assert writer.bytes_written == first_written
    finally:
        writer.close()


def test_manifest_round_trip(tmp_path: Path) -> None:
    from mtsql_typecheck.contracts.runner import decode_runner_manifest

    writer = make_writer(tmp_path / "out")
    try:
        record = sample_manifest_record()
        writer.write_manifest(record)
        path = writer.root / MANIFEST_NAME
        loaded = decode_runner_manifest(parse_strict_json(path.read_bytes()), "manifest")
        assert loaded.to_obj() == record.to_obj()
        # A re-seal of the identical manifest is an idempotent no-op.
        first_written = writer.bytes_written
        assert writer.write_manifest(record) == 0
        assert writer.bytes_written == first_written
    finally:
        writer.close()


# --------------------------------------------------------------------------
# write_exclusive_document
# --------------------------------------------------------------------------


def test_write_exclusive_document_semantics(tmp_path: Path) -> None:
    path = tmp_path / "doc.json"
    assert write_exclusive_document(path, b"v1") == 2
    assert path.read_bytes() == b"v1"
    # Identical rewrite: no-op.
    assert write_exclusive_document(path, b"v1") == 0
    # Different content: refusal, file untouched.
    with pytest.raises(EvidencePathError):
        write_exclusive_document(path, b"v2")
    assert path.read_bytes() == b"v1"
    # Directory target: refused.
    with pytest.raises(EvidencePathError):
        write_exclusive_document(tmp_path, b"x")
