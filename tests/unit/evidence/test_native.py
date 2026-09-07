"""Unit tests for evidence/native.py: detection and bounded closure enumeration.

The reader module is delivered in parallel; a small in-memory-on-disk fake
implementing the pinned ``SourceReader`` interface (exists/stat/read_bytes/
read_jsonl/list_dir/walk, caps and max_entries refusal) stands in for it.
All documents are minimal but valid for the strict typed codecs.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.codec import canonical_json, parse_strict_json
from mtsql_typecheck.contracts.delivery import (
    Limits,
    NativeKind,
    compute_delivery_id,
    compute_snapshot_digest,
    compute_source_id,
    decode_evidence_manifest,
)
from mtsql_typecheck.contracts.delivery import (
    DeliveryCompletion,
    DeliveryKind,
    EvidenceFile,
    EvidenceManifest,
    FileRole,
    SourceDescriptor,
    SyntheticKind,
    CollectionStatus,
)
from mtsql_typecheck.contracts.oracle import (
    EVIDENCE_PROFILE_FULL,
    ReplayOutcome,
    ReplayResult,
    dump_replay_result,
)
from mtsql_typecheck.evidence.native import (
    MissingEntryError,
    ReadLimitExceededError,
    RootDetectionError,
    SourcePlan,
    TEXT_FILE_CAP_BYTES,
    detect_native_kind,
    enumerate_source,
)

# --------------------------------------------------------------------------
# Fake SourceReader (pinned interface from /tmp/d4-orchestration/notes.md)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class EntryStat:
    relpath: str
    kind: str  # "file" | "dir" | "other"
    size_bytes: int
    mtime_ns: int


class FakeReader:
    """Duck-typed SourceReader over a real directory; refuses nothing else.

    ``walk`` calls are recorded so tests can prove enumeration is bounded
    (max_entries is forwarded and the overflow is refused before full
    enumeration).
    """

    def __init__(self, root: Path, limits: Limits) -> None:
        self.root = Path(root)
        self.limits = limits
        self.walk_calls: list[int] = []

    def _path(self, relpath: str) -> Path:
        if relpath == "":
            return self.root
        return self.root / relpath

    def exists(self, relpath: str) -> bool:
        try:
            st = os.lstat(self._path(relpath))
        except OSError:
            return False
        return stat.S_ISREG(st.st_mode)

    def stat(self, relpath: str) -> EntryStat:
        try:
            st = os.lstat(self._path(relpath))
        except FileNotFoundError as exc:
            raise MissingEntryError(relpath) from exc
        if stat.S_ISDIR(st.st_mode):
            kind = "dir"
        elif stat.S_ISREG(st.st_mode):
            kind = "file"
        else:
            kind = "other"
        return EntryStat(relpath=relpath, kind=kind, size_bytes=st.st_size, mtime_ns=st.st_mtime_ns)

    def read_bytes(self, relpath: str, *, max_bytes: int) -> bytes:
        data = self._path(relpath).read_bytes()
        if len(data) > max_bytes:
            raise ReadLimitExceededError(
                f"{relpath} is {len(data)} bytes, over the cap {max_bytes}"
            )
        return data

    def read_jsonl(self, relpath: str, *, max_line_bytes: int, max_total_bytes: int):
        data = self.read_bytes(relpath, max_bytes=max_total_bytes)
        raw_lines = data.split(b"\n")
        if raw_lines and raw_lines[-1] == b"":
            raw_lines.pop()
        lines: list[tuple[int, bytes]] = []
        for index, line in enumerate(raw_lines, start=1):
            if len(line) > max_line_bytes:
                raise ReadLimitExceededError(
                    f"{relpath} line {index} exceeds {max_line_bytes} bytes"
                )
            lines.append((index, line))
        return lines

    def list_dir(self, relpath: str) -> list[str]:
        path = self._path(relpath)
        if not path.is_dir():
            raise MissingEntryError(relpath)
        return sorted(os.listdir(path))

    def walk(self, relprefix: str, *, max_entries: int):
        self.walk_calls.append(max_entries)
        count = 0
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames.sort()
            for name in sorted(dirnames):
                count += 1
                if count > max_entries:
                    raise ReadLimitExceededError("walk exceeded max_entries")
                rel = os.path.relpath(os.path.join(dirpath, name), self.root)
                yield rel.replace(os.sep, "/"), "dir"
            for name in sorted(filenames):
                count += 1
                if count > max_entries:
                    raise ReadLimitExceededError("walk exceeded max_entries")
                rel = os.path.relpath(os.path.join(dirpath, name), self.root)
                yield rel.replace(os.sep, "/"), "file"


# --------------------------------------------------------------------------
# Document builders (minimal valid documents for the strict codecs)
# --------------------------------------------------------------------------


def hex64(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def write_doc(root: Path, relpath: str, obj: object) -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(obj) + b"\n")


def write_raw(root: Path, relpath: str, data: bytes) -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def generation_manifest_obj(case_ids: list[str]) -> dict:
    return {
        "generation_schema_version": 1,
        "profile_hash": hex64("profile"),
        "seed": 0,
        "generator": {"id": "g1", "version": "0.1.0"},
        "status": "COMPLETE",
        "statistics": {
            "requested_ordinals": len(case_ids),
            "attempted_candidates": 0,
            "emitted_occurrences": len(case_ids),
            "unique_cases": len(case_ids),
            "rejected_ordinals": 0,
            "interrupted_ordinals": 0,
            "not_attempted": 0,
        },
        "receipts": [],
        "case_files": [
            {"case_id": case_id, "artifact_hash": hex64(case_id), "size_bytes": 4}
            for case_id in case_ids
        ],
        "reason": None,
    }


def runner_manifest_obj(refs: dict) -> dict:
    return {
        "schema_version": 1,
        "command": "RUN",
        "run_id": "run-1",
        "status": "COMPLETE",
        "stop_reason": None,
        "requested": 0,
        "completed": 0,
        "comparable": 0,
        "match": 0,
        "candidate": 0,
        "inconclusive": 0,
        "not_applicable": 0,
        "leftover_objects": 0,
        "leftover_sessions": 0,
        "synthetic": False,
        "evidence_profile": "typecheck-full-evidence-v1",
        "tool_version": "0.1.0",
        "contract_versions": {
            "case": "1",
            "execution": "1",
            "oracle": "o1",
            "runner": "1",
        },
        "refs": refs,
        "sanitized_config_hash": hex64("config"),
    }


def trace_ref(sha: str) -> dict:
    return {"path": f"files/{sha}.json", "size_bytes": 2, "sha256": sha, "schema_version": 1}


def snapshot_record(ref: dict | None) -> dict:
    return {
        "seq": 1,
        "kind": "SNAPSHOT",
        "payload_ref": ref,
        "inline": {"case_id": hex64("case")},
        "prev_hash": "0" * 64,
        "hash": hex64("rec1"),
    }


def start_record() -> dict:
    return {
        "seq": 2,
        "kind": "START",
        "payload_ref": None,
        "inline": {
            "complexity": [0, 0, 0, 0, 0],
            "payload_ref": None,
            "case_id": hex64("case"),
            "evidence_profile": EVIDENCE_PROFILE_FULL,
        },
        "prev_hash": hex64("rec1"),
        "hash": hex64("rec2"),
    }


def replay_result_bytes() -> bytes:
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
    return dump_replay_result(result) + b"\n"


def delivery_manifest_obj(tmp_path: Path) -> tuple[dict, str]:
    """A minimal sealed delivery manifest document plus its delivery_id."""
    raw_rel = f"raw/{hex64('src')}/native.json"
    write_raw(tmp_path, raw_rel, b"native bytes\n")
    write_raw(tmp_path, "assessment.json", b"assessment\n")
    files = sorted([raw_rel, "assessment.json"])
    digest = compute_snapshot_digest(
        "generation",
        "generation-manifest.json",
        [("generation-manifest.json", 10, hex64("gen"))],
        [],
    )
    source_id = compute_source_id(digest)
    descriptor = SourceDescriptor(
        source_id=source_id,
        native_kind=NativeKind.GENERATION,
        root_document="generation-manifest.json",
        snapshot_digest=digest,
        synthetic=SyntheticKind.REAL,
        collection_status=CollectionStatus.COLLECTED,
    )
    evidence_files = tuple(
        EvidenceFile(
            path=relpath,
            role=FileRole.RAW_NATIVE if relpath.startswith("raw/") else FileRole.ASSESSMENT,
            size_bytes=(tmp_path / relpath).stat().st_size,
            sha256=hashlib.sha256((tmp_path / relpath).read_bytes()).hexdigest(),
            source_id=source_id if relpath.startswith("raw/") else None,
        )
        for relpath in files
    )
    manifest = EvidenceManifest(
        delivery_id=compute_delivery_id((descriptor,)),
        kind=DeliveryKind.VERIFICATION,
        writer_version="0.1.0",
        sources=(descriptor,),
        files=evidence_files,
        completion=DeliveryCompletion.COMPLETE,
    )
    return manifest.to_obj(), manifest.delivery_id


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------


def test_detect_each_kind(tmp_path):
    gen = tmp_path / "gen"
    gen.mkdir()
    write_doc(gen, "generation-manifest.json", generation_manifest_obj([]))
    run = tmp_path / "run"
    run.mkdir()
    write_doc(run, "runner-manifest.json", runner_manifest_obj({}))
    trace = tmp_path / "trace"
    trace.mkdir()
    write_raw(trace, "trace.jsonl", b"\n")
    attempt = tmp_path / "attempt"
    attempt.mkdir()
    write_raw(attempt, "request.json", b"{}\n")
    delivery = tmp_path / "delivery"
    delivery.mkdir()
    write_raw(delivery, "evidence-manifest.json", b"{}\n")

    assert detect_native_kind(gen) is NativeKind.GENERATION
    assert detect_native_kind(run) is NativeKind.RUN
    assert detect_native_kind(trace) is NativeKind.TRACE
    assert detect_native_kind(attempt) is NativeKind.ATTEMPT
    assert detect_native_kind(delivery) is NativeKind.DELIVERY


def test_detect_conflicting_markers_refused(tmp_path):
    gen_run = tmp_path / "gen_run"
    gen_run.mkdir()
    write_doc(gen_run, "generation-manifest.json", generation_manifest_obj([]))
    write_doc(gen_run, "runner-manifest.json", runner_manifest_obj({}))
    with pytest.raises(RootDetectionError):
        detect_native_kind(gen_run)

    delivery_trace = tmp_path / "delivery_trace"
    delivery_trace.mkdir()
    write_raw(delivery_trace, "evidence-manifest.json", b"{}\n")
    write_raw(delivery_trace, "trace.jsonl", b"\n")
    with pytest.raises(RootDetectionError):
        detect_native_kind(delivery_trace)

    trace_attempt = tmp_path / "trace_attempt"
    trace_attempt.mkdir()
    write_raw(trace_attempt, "trace.jsonl", b"\n")
    write_raw(trace_attempt, "request.json", b"{}\n")
    with pytest.raises(RootDetectionError):
        detect_native_kind(trace_attempt)


def test_detect_empty_root_and_hints(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert detect_native_kind(empty) is NativeKind.UNKNOWN
    # The hint selects a parser for a root missing its summary document.
    assert detect_native_kind(empty, kind_hint="run") is NativeKind.RUN
    with pytest.raises(RootDetectionError):
        detect_native_kind(empty, kind_hint="bogus")

    # A hint contradicting existing markers is refused.
    gen = tmp_path / "gen"
    gen.mkdir()
    write_doc(gen, "generation-manifest.json", generation_manifest_obj([]))
    assert detect_native_kind(gen, kind_hint="generation") is NativeKind.GENERATION
    with pytest.raises(RootDetectionError):
        detect_native_kind(gen, kind_hint="run")


def test_detect_refuses_non_directory_root(tmp_path):
    file_root = tmp_path / "afile"
    file_root.write_bytes(b"x")
    with pytest.raises(RootDetectionError):
        detect_native_kind(file_root)
    with pytest.raises(RootDetectionError):
        detect_native_kind(tmp_path / "missing")


# --------------------------------------------------------------------------
# Enumeration: generation
# --------------------------------------------------------------------------


def _reader(tmp_path: Path, limits: Limits | None = None) -> FakeReader:
    return FakeReader(tmp_path, limits or Limits())


def test_enumerate_generation_closure(tmp_path):
    case_id = hex64("case-1")
    write_doc(tmp_path, "generation-manifest.json", generation_manifest_obj([case_id]))
    write_raw(tmp_path, "profile.json", b"{}\n")
    for name in ("case.json", "static-check.json", "preview-a.sql", "preview-b.sql"):
        write_raw(tmp_path, f"cases/{case_id}/{name}", b"ab\n")
    write_raw(tmp_path, "extra.txt", b"orphan\n")

    limits = Limits()
    plan = enumerate_source(_reader(tmp_path, limits), NativeKind.GENERATION, limits)

    assert isinstance(plan, SourcePlan)
    assert plan.kind is NativeKind.GENERATION
    assert plan.root_document == "generation-manifest.json"
    relpaths = [planned.relpath for planned in plan.files]
    assert relpaths == sorted(
        [
            "generation-manifest.json",
            "profile.json",
            f"cases/{case_id}/case.json",
            f"cases/{case_id}/static-check.json",
            f"cases/{case_id}/preview-a.sql",
            f"cases/{case_id}/preview-b.sql",
        ]
    )
    assert plan.orphan_files == ("extra.txt",)
    assert plan.diagnostics == ()
    caps = {planned.relpath: planned.max_bytes for planned in plan.files}
    assert caps["profile.json"] == limits.max_json_document_bytes
    assert caps[f"cases/{case_id}/preview-a.sql"] == TEXT_FILE_CAP_BYTES
    versions = {component.kind_field: component.value for component in plan.native_versions}
    assert versions == {"generation_schema": "1"}
    assert plan.observed_writer_version == "0.1.0"
    assert plan.source_commit is None
    assert plan.producer is None


# --------------------------------------------------------------------------
# Enumeration: run
# --------------------------------------------------------------------------


def _build_run_root(tmp_path: Path, with_manifest: bool = True) -> str:
    attempt_id = "a1"
    payload_sha = hex64("sql-payload")
    refs = {
        "environment": "environment.json",
        "runner_manifest": "runner-manifest.json",
        f"attempt:{attempt_id}": f"attempts/{attempt_id}/comparison.json",
    }
    if with_manifest:
        write_doc(tmp_path, "runner-manifest.json", runner_manifest_obj(refs))
    write_raw(tmp_path, "environment.json", b"{}\n")
    for name in (
        "request.json",
        "expectation.json",
        "execution-evidence.json",
        "comparison.json",
        "observations.jsonl",
        "terminal.json",
    ):
        write_raw(tmp_path, f"attempts/{attempt_id}/{name}", b"{}\n")
    observation = {
        "side": "A",
        "stage": "INSERT",
        "ordinal": 0,
        "connection_id": None,
        "actual_database": None,
        "session_id": None,
        "sql_hash": payload_sha,
        "sql_ref": f"payloads/{payload_sha}.json",
        "diagnostics_ref": None,
        "field_metadata_ref": None,
        "detail": "",
    }
    write_raw(
        tmp_path,
        f"attempts/{attempt_id}/observations.jsonl",
        canonical_json(observation) + b"\n",
    )
    write_raw(tmp_path, f"payloads/{payload_sha}.json", b"{}\n")
    write_raw(tmp_path, "payloads/unreferenced.json", b"{}\n")
    return attempt_id


def test_enumerate_run_closure(tmp_path):
    attempt_id = _build_run_root(tmp_path, with_manifest=True)
    limits = Limits()
    plan = enumerate_source(_reader(tmp_path, limits), NativeKind.RUN, limits)

    relpaths = {planned.relpath for planned in plan.files}
    assert plan.diagnostics == ()
    assert "runner-manifest.json" in relpaths
    assert "environment.json" in relpaths
    for name in (
        "request.json",
        "expectation.json",
        "execution-evidence.json",
        "comparison.json",
        "observations.jsonl",
        "terminal.json",
    ):
        assert f"attempts/{attempt_id}/{name}" in relpaths
    # The payload referenced from observations is inside the closure ...
    assert f"payloads/{hex64('sql-payload')}.json" in relpaths
    # ... while the unreferenced payload stays an orphan (recorded, not copied).
    assert "payloads/unreferenced.json" in plan.orphan_files
    assert "payloads/unreferenced.json" not in relpaths

    versions = {component.kind_field: component.value for component in plan.native_versions}
    assert versions == {
        "case_schema": "1",
        "execution_schema": "1",
        "replay_schema": "o1",
        "runner_schema": "1",
    }
    assert plan.observed_writer_version == "0.1.0"


def test_run_missing_manifest_limited_scan(tmp_path):
    _build_run_root(tmp_path, with_manifest=False)
    limits = Limits()
    kind = detect_native_kind(tmp_path, kind_hint="run")
    assert kind is NativeKind.RUN
    plan = enumerate_source(_reader(tmp_path, limits), kind, limits)

    assert plan.diagnostics == ("missing_root_manifest",)
    relpaths = {planned.relpath for planned in plan.files}
    assert "environment.json" in relpaths
    assert f"attempts/a1/comparison.json" in relpaths
    assert f"payloads/{hex64('sql-payload')}.json" in relpaths
    # No requested counts are inferred anywhere on the plan.
    assert plan.native_versions == ()
    assert plan.observed_writer_version is None


# --------------------------------------------------------------------------
# Enumeration: trace
# --------------------------------------------------------------------------


def test_enumerate_trace_closure_and_marker(tmp_path):
    dep_sha = hex64("dep")
    write_raw(tmp_path, f"files/{dep_sha}.json", b"{}\n")
    lines = canonical_json(snapshot_record(trace_ref(dep_sha))) + b"\n" + canonical_json(
        start_record()
    ) + b"\n"
    write_raw(tmp_path, "trace.jsonl", lines)
    write_raw(tmp_path, "replay-result.json", replay_result_bytes())
    write_raw(tmp_path, "stray.txt", b"orphan\n")

    limits = Limits()
    plan = enumerate_source(_reader(tmp_path, limits), NativeKind.TRACE, limits)
    relpaths = {planned.relpath for planned in plan.files}
    assert relpaths == {"trace.jsonl", f"files/{dep_sha}.json", "replay-result.json"}
    assert plan.orphan_files == ("stray.txt",)
    assert len(plan.native_versions) == 1
    assert plan.native_versions[0].kind_field == "trace_format"
    assert plan.native_versions[0].value == EVIDENCE_PROFILE_FULL
    assert plan.root_document == "trace.jsonl"


def test_enumerate_legacy_trace_has_no_versions(tmp_path):
    lines = canonical_json(snapshot_record(trace_ref(hex64("dep")))) + b"\n"
    write_raw(tmp_path, "trace.jsonl", lines)
    write_raw(tmp_path, f"files/{hex64('dep')}.json", b"{}\n")
    limits = Limits()
    plan = enumerate_source(_reader(tmp_path, limits), NativeKind.TRACE, limits)
    assert plan.kind is NativeKind.TRACE
    assert plan.native_versions == ()


def test_trace_marker_contradiction_refused(tmp_path):
    bad = start_record()
    bad["inline"]["evidence_profile"] = "typecheck-full-evidence-v0"
    write_raw(tmp_path, "trace.jsonl", canonical_json(bad) + b"\n")
    limits = Limits()
    with pytest.raises(RootDetectionError):
        enumerate_source(_reader(tmp_path, limits), NativeKind.TRACE, limits)


def test_trace_reduce_result_in_closure(tmp_path):
    from mtsql_typecheck.contracts.oracle import ReductionOutcome, ReductionResult, dump_reduction_result

    result = ReductionResult(
        reduction_id="red-1",
        outcome=ReductionOutcome.UNCHANGED,
        stop_reason=None,
        original_case_id=hex64("case"),
        original_comparison_hash=hex64("cmp"),
        original_fingerprint=None,
        best_case_id=hex64("case"),
        best_comparison_hashes=(),
        has_reduction=False,
        search_complete=False,
        proposals=0,
        executions=0,
        accepted=0,
        rejected_static=0,
        inconclusive_candidates=0,
        unstable_candidates=0,
        synthetic=False,
    )
    write_raw(tmp_path, "trace.jsonl", b"")
    write_raw(tmp_path, "reduce-result.json", dump_reduction_result(result) + b"\n")
    limits = Limits()
    plan = enumerate_source(_reader(tmp_path, limits), NativeKind.TRACE, limits)
    relpaths = {planned.relpath for planned in plan.files}
    assert relpaths == {"trace.jsonl", "reduce-result.json"}


# --------------------------------------------------------------------------
# Enumeration: attempt and delivery
# --------------------------------------------------------------------------


def test_enumerate_attempt_closure(tmp_path):
    for name in (
        "request.json",
        "expectation.json",
        "execution-evidence.json",
        "comparison.json",
        "terminal.json",
    ):
        write_raw(tmp_path, name, b"{}\n")
    write_raw(tmp_path, "side.json", b"orphan\n")
    limits = Limits()
    plan = enumerate_source(_reader(tmp_path, limits), NativeKind.ATTEMPT, limits)
    relpaths = {planned.relpath for planned in plan.files}
    assert relpaths == {
        "request.json",
        "expectation.json",
        "execution-evidence.json",
        "comparison.json",
        "terminal.json",
    }
    assert plan.orphan_files == ("side.json",)
    assert plan.root_document == "request.json"
    assert plan.observed_writer_version is None
    assert plan.producer is None


def test_enumerate_delivery_closure(tmp_path):
    obj, delivery_id = delivery_manifest_obj(tmp_path)
    write_doc(tmp_path, "evidence-manifest.json", obj)
    write_raw(tmp_path, "reviews/r1.json", b"{}\n")
    write_raw(tmp_path, "report.json", b"{}\n")
    write_raw(tmp_path, "unlisted.txt", b"orphan\n")

    limits = Limits()
    plan = enumerate_source(_reader(tmp_path, limits), NativeKind.DELIVERY, limits)
    relpaths = {planned.relpath for planned in plan.files}
    raw_rel = f"raw/{hex64('src')}/native.json"
    assert "evidence-manifest.json" in relpaths
    assert "assessment.json" in relpaths
    assert raw_rel in relpaths
    assert "reviews/r1.json" in relpaths
    assert "report.json" in relpaths
    assert "unlisted.txt" in plan.orphan_files
    assert plan.observed_writer_version == "0.1.0"
    # No producer recorded in this fixture; producer stays None, never inferred.
    assert plan.producer is None


def test_enumerate_unknown_kind_refused(tmp_path):
    limits = Limits()
    with pytest.raises(RootDetectionError):
        enumerate_source(_reader(tmp_path, limits), NativeKind.UNKNOWN, limits)


# --------------------------------------------------------------------------
# Bounded enumeration
# --------------------------------------------------------------------------


def test_enumeration_is_bounded_by_max_files(tmp_path):
    _build_run_root(tmp_path, with_manifest=True)
    # The manifest closure alone holds 9 files; the tree holds 13 entries, so
    # with max_files=10 the closure passes but the orphan walk is refused
    # before enumerating the whole tree.
    limits = Limits(max_files=10)
    reader = _reader(tmp_path, limits)
    with pytest.raises(ReadLimitExceededError):
        enumerate_source(reader, NativeKind.RUN, limits)
    # Proof of boundedness: the walk was capped at limits.max_files, so the
    # reader refused before enumerating the whole tree.
    assert reader.walk_calls
    assert all(call == limits.max_files for call in reader.walk_calls)


def test_enumeration_never_infers_requested_from_dirs(tmp_path):
    # Five attempt directories on disk but no manifest: the limited scan lists
    # their known files but the plan carries no count data at all.
    for index in range(5):
        write_raw(tmp_path, f"attempts/a{index}/request.json", b"{}\n")
    limits = Limits()
    plan = enumerate_source(_reader(tmp_path, limits), NativeKind.RUN, limits)
    assert plan.diagnostics == ("missing_root_manifest",)
    assert len([f for f in plan.files if f.relpath.endswith("/request.json")]) == 5
    # All six known attempt files per attempt are planned; no count is inferred.
    assert all(f.relpath.startswith("attempts/") for f in plan.files)
    assert len(plan.files) == 30


def test_generation_manifest_rejects_corrupt_root(tmp_path):
    # Statistics inconsistent with the case list: rejected by the strict
    # typed codec (unique_cases > emitted_occurrences), not by ad-hoc checks.
    doc = generation_manifest_obj([hex64("case")])
    doc["statistics"]["emitted_occurrences"] = 0
    write_doc(tmp_path, "generation-manifest.json", doc)
    limits = Limits()
    from mtsql_typecheck.contracts.case import ContractError

    with pytest.raises(ContractError):
        enumerate_source(_reader(tmp_path, limits), NativeKind.GENERATION, limits)


def test_plan_model_rejects_bad_files(tmp_path):
    limits = Limits()
    reader = _reader(tmp_path, limits)
    plan = enumerate_source(reader, NativeKind.ATTEMPT, limits)
    assert plan.files[0].relpath == "comparison.json"
    from mtsql_typecheck.evidence.native import PlannedFile
    from mtsql_typecheck.contracts.case import ContractError

    with pytest.raises(ContractError):
        PlannedFile(relpath="../escape.json", max_bytes=10)
    with pytest.raises(ContractError):
        PlannedFile(relpath="ok.json", max_bytes=0)
