"""Unit tests for evidence/manifest.py: role classification and the D4
delivery-package write/validate round trip.

The package fixtures follow design 6.2.3: ``raw/<source-id>/native.json``,
``assessment.json``, optional report renderings and reviews.  Source
identity is derived through the frozen contract helpers
(``compute_snapshot_digest`` -> ``compute_source_id`` ->
``compute_delivery_id``) so the sealed manifest satisfies the typed
constructor's own identity rules.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.case import ContractError
from mtsql_typecheck.contracts.delivery import (
    ASSESSMENT_FILENAME,
    MANIFEST_FILENAME,
    DeliveryCompletion,
    DeliveryKind,
    EvidenceFile,
    EvidenceManifest,
    FileRole,
    Limits,
    NativeKind,
    SourceDescriptor,
    SyntheticKind,
    CollectionStatus,
    compute_delivery_id,
    compute_snapshot_digest,
    compute_source_id,
)
from mtsql_typecheck.evidence.manifest import (
    DeliveryError,
    FsyncFailedError,
    ManifestExistsError,
    Problem,
    SymlinkEntryError,
    UnclassifiableFileError,
    classify_role,
    collect_delivery_files,
    required_files_for,
    validate_delivery_dir,
    write_evidence_manifest,
)

# --------------------------------------------------------------------------
# Package builders
# --------------------------------------------------------------------------


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def add_file(root: Path, relpath: str, data: bytes) -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def make_source(root: Path, *, raw_bytes: bytes = b"native bytes\n") -> SourceDescriptor:
    """Write ``raw/<source-id>/native.json`` and return its descriptor.

    The source id is derived from a snapshot digest over the raw bytes, the
    same way the snapshot stage would derive it (design 6.2.1).
    """
    native_files = [("generation-manifest.json", len(raw_bytes), sha256(raw_bytes))]
    digest = compute_snapshot_digest(
        NativeKind.GENERATION, "generation-manifest.json", native_files, ()
    )
    source_id = compute_source_id(digest)
    add_file(root, f"raw/{source_id}/native.json", raw_bytes)
    return SourceDescriptor(
        source_id=source_id,
        native_kind=NativeKind.GENERATION,
        root_document="generation-manifest.json",
        snapshot_digest=digest,
        synthetic=SyntheticKind.REAL,
        collection_status=CollectionStatus.COLLECTED,
    )


def build_package(root: Path, *, kind: DeliveryKind = DeliveryKind.VERIFICATION) -> EvidenceManifest:
    """Create a complete on-disk package and its sealed manifest object."""
    descriptor = make_source(root)
    add_file(root, ASSESSMENT_FILENAME, b"assessment payload\n")
    if kind is DeliveryKind.REPORT:
        add_file(root, "report.json", b"{}\n")
        add_file(root, "report.md", b"# report\n")
        add_file(root, "report.html", b"<p>report</p>\n")
    limits = Limits()
    evidence_files = collect_delivery_files(root, limits)
    manifest = EvidenceManifest(
        delivery_id=compute_delivery_id((descriptor,)),
        kind=kind,
        writer_version="0.1.0",
        sources=(descriptor,),
        files=evidence_files,
        completion=DeliveryCompletion.COMPLETE,
    )
    write_evidence_manifest(root, manifest)
    return manifest


def codes(problems: tuple[Problem, ...]) -> list[str]:
    return [problem.code for problem in problems]


# --------------------------------------------------------------------------
# classify_role
# --------------------------------------------------------------------------


def test_classify_role_known_paths():
    assert classify_role("raw/s-abc/native.json") is FileRole.RAW_NATIVE
    assert classify_role("raw/s-abc/nested/case.json") is FileRole.RAW_NATIVE
    assert classify_role(ASSESSMENT_FILENAME) is FileRole.ASSESSMENT
    assert classify_role("report.json") is FileRole.REPORT_JSON
    assert classify_role("report.md") is FileRole.REPORT_MD
    assert classify_role("report.html") is FileRole.REPORT_HTML
    assert classify_role("reviews/r1.json") is FileRole.REVIEW
    assert classify_role("exports/a.sql") is FileRole.EXPORT_SQL_A
    assert classify_role("exports/case.json") is FileRole.EXPORT_CASE
    assert classify_role("README.md") is FileRole.EXPORT_README
    assert classify_role("unknown.bin") is None
    assert classify_role("reviews/r1.txt") is None


def test_classify_role_source_id_parameter_is_accepted():
    # The parameter exists for interface stability; classification is
    # syntactic and must not change with it.
    assert (
        classify_role("raw/s-abc/native.json", "s-abc") is FileRole.RAW_NATIVE
    )


def test_required_files_for_kinds():
    assert required_files_for(DeliveryKind.VERIFICATION) == (
        MANIFEST_FILENAME,
        ASSESSMENT_FILENAME,
    )
    assert required_files_for(DeliveryKind.REPORT) == (
        MANIFEST_FILENAME,
        ASSESSMENT_FILENAME,
        "report.json",
        "report.md",
        "report.html",
    )


# --------------------------------------------------------------------------
# collect_delivery_files
# --------------------------------------------------------------------------


def test_collect_hashes_actual_bytes_and_excludes_manifest(tmp_path):
    descriptor = make_source(tmp_path)
    add_file(tmp_path, ASSESSMENT_FILENAME, b"assessment payload\n")
    add_file(tmp_path, MANIFEST_FILENAME, b"stale manifest from a previous life\n")

    files = collect_delivery_files(tmp_path, Limits())

    by_path = {entry.path: entry for entry in files}
    assert MANIFEST_FILENAME not in by_path
    raw_rel = f"raw/{descriptor.source_id}/native.json"
    raw_entry = by_path[raw_rel]
    assert raw_entry.role is FileRole.RAW_NATIVE
    assert raw_entry.source_id == descriptor.source_id
    assert raw_entry.size_bytes == len(b"native bytes\n")
    assert raw_entry.sha256 == sha256(b"native bytes\n")
    assert by_path[ASSESSMENT_FILENAME].role is FileRole.ASSESSMENT
    assert by_path[ASSESSMENT_FILENAME].source_id is None
    assert [entry.path for entry in files] == sorted(by_path)


def test_collect_refuses_symlink_entry(tmp_path):
    make_source(tmp_path)
    add_file(tmp_path, ASSESSMENT_FILENAME, b"assessment\n")
    target = tmp_path / "raw"
    link = tmp_path / "review-link.json"
    link.symlink_to(target)
    with pytest.raises(SymlinkEntryError):
        collect_delivery_files(tmp_path, Limits())


def test_collect_refuses_unclassifiable_file(tmp_path):
    make_source(tmp_path)
    add_file(tmp_path, ASSESSMENT_FILENAME, b"assessment\n")
    add_file(tmp_path, "stray.bin", b"\x00\x01")
    with pytest.raises(UnclassifiableFileError):
        collect_delivery_files(tmp_path, Limits())


# --------------------------------------------------------------------------
# write_evidence_manifest
# --------------------------------------------------------------------------


def test_write_is_atomic_and_canonical(tmp_path):
    descriptor = make_source(tmp_path)
    add_file(tmp_path, ASSESSMENT_FILENAME, b"assessment\n")
    manifest = EvidenceManifest(
        delivery_id=compute_delivery_id((descriptor,)),
        kind=DeliveryKind.VERIFICATION,
        writer_version="0.1.0",
        sources=(descriptor,),
        files=collect_delivery_files(tmp_path, Limits()),
        completion=DeliveryCompletion.COMPLETE,
    )

    write_evidence_manifest(tmp_path, manifest)

    written = (tmp_path / MANIFEST_FILENAME).read_bytes()
    # Canonical JSON (sorted keys, compact separators) plus exactly one
    # trailing newline; no temp residue.
    from mtsql_typecheck.contracts.codec import canonical_json

    assert written == canonical_json(manifest.to_obj()) + b"\n"
    assert not list(tmp_path.glob(".*part*"))


def test_write_refuses_overwrite(tmp_path):
    manifest = build_package(tmp_path)
    with pytest.raises(ManifestExistsError):
        write_evidence_manifest(tmp_path, manifest)


def test_write_refuses_non_manifest_argument(tmp_path):
    with pytest.raises(DeliveryError):
        write_evidence_manifest(tmp_path, {"not": "a manifest"})


def test_write_fsync_failure_leaves_originals_intact(tmp_path):
    descriptor = make_source(tmp_path)
    add_file(tmp_path, ASSESSMENT_FILENAME, b"assessment\n")
    manifest = EvidenceManifest(
        delivery_id=compute_delivery_id((descriptor,)),
        kind=DeliveryKind.VERIFICATION,
        writer_version="0.1.0",
        sources=(descriptor,),
        files=collect_delivery_files(tmp_path, Limits()),
        completion=DeliveryCompletion.COMPLETE,
    )

    def broken_fsync(fd: int) -> None:
        raise OSError("disk on fire")

    with pytest.raises(FsyncFailedError):
        write_evidence_manifest(tmp_path, manifest, fsync=broken_fsync)

    assert not (tmp_path / MANIFEST_FILENAME).exists()
    assert not list(tmp_path.glob(".*part*"))
    # The original package files are untouched.
    assert (tmp_path / f"raw/{descriptor.source_id}/native.json").read_bytes() == (
        b"native bytes\n"
    )
    assert (tmp_path / ASSESSMENT_FILENAME).read_bytes() == b"assessment\n"


# --------------------------------------------------------------------------
# validate_delivery_dir
# --------------------------------------------------------------------------


def test_round_trip_verification_package_ok(tmp_path):
    manifest = build_package(tmp_path)
    result = validate_delivery_dir(tmp_path, Limits())
    assert result.ok
    assert result.problems == ()
    assert result.kind is DeliveryKind.VERIFICATION
    assert result.completion is DeliveryCompletion.COMPLETE
    assert result.delivery_id == manifest.delivery_id


def test_round_trip_report_package_ok(tmp_path):
    build_package(tmp_path, kind=DeliveryKind.REPORT)
    result = validate_delivery_dir(tmp_path, Limits())
    assert result.ok
    assert result.kind is DeliveryKind.REPORT


def test_tampered_raw_file_reports_hash_mismatch(tmp_path):
    build_package(tmp_path)
    raw_file = next((tmp_path / "raw").iterdir()).joinpath("native.json")
    data = bytearray(raw_file.read_bytes())
    data[0] = data[0] ^ 0x20
    raw_file.write_bytes(bytes(data))

    result = validate_delivery_dir(tmp_path, Limits())
    assert not result.ok
    assert "hash_mismatch" in codes(result.problems)


def test_tampered_file_size_and_hash_both_reported_once(tmp_path):
    build_package(tmp_path)
    raw_file = next((tmp_path / "raw").iterdir()).joinpath("native.json")
    raw_file.write_bytes(b"native bytes\n\n")  # different size and hash
    result = validate_delivery_dir(tmp_path, Limits())
    mismatches = [
        p for p in result.problems if p.code == "hash_mismatch"
    ]
    assert len(mismatches) == 1
    assert raw_file.relative_to(tmp_path).as_posix() == mismatches[0].path


def test_missing_required_report_file(tmp_path):
    build_package(tmp_path, kind=DeliveryKind.REPORT)
    (tmp_path / "report.html").unlink()
    result = validate_delivery_dir(tmp_path, Limits())
    assert not result.ok
    missing = [p for p in result.problems if p.code == "missing_required"]
    assert [p.path for p in missing] == ["report.html"]
    # The extra/missing symmetry must not produce a phantom extra_file.
    assert "extra_file" not in codes(result.problems)


def test_extra_file_after_sealing(tmp_path):
    build_package(tmp_path)
    add_file(tmp_path, "reviews/late.json", b"{}\n")
    result = validate_delivery_dir(tmp_path, Limits())
    assert not result.ok
    extras = [p for p in result.problems if p.code == "extra_file"]
    assert [p.path for p in extras] == ["reviews/late.json"]


def test_deleted_listed_file_reports_missing_file(tmp_path):
    build_package(tmp_path)
    (tmp_path / ASSESSMENT_FILENAME).unlink()
    result = validate_delivery_dir(tmp_path, Limits())
    assert not result.ok
    missing = [p for p in result.problems if p.code == "missing_file"]
    assert [p.path for p in missing] == [ASSESSMENT_FILENAME]
    # Also flagged as a required file of every kind.
    assert "missing_required" in codes(result.problems)


def test_manifest_listed_file_replaced_by_symlink(tmp_path):
    build_package(tmp_path)
    raw_file = next((tmp_path / "raw").iterdir()).joinpath("native.json")
    assessment = tmp_path / ASSESSMENT_FILENAME
    assessment.unlink()
    assessment.symlink_to(raw_file)
    result = validate_delivery_dir(tmp_path, Limits())
    assert not result.ok
    assert "not_regular_file" in codes(result.problems)


def test_symlink_entry_in_validated_package(tmp_path):
    build_package(tmp_path)
    link = tmp_path / "review-link.json"
    link.symlink_to(tmp_path / MANIFEST_FILENAME)
    result = validate_delivery_dir(tmp_path, Limits())
    assert not result.ok
    assert "symlink_entry" in codes(result.problems)


def test_missing_manifest_reports_and_never_raises(tmp_path):
    make_source(tmp_path)
    add_file(tmp_path, ASSESSMENT_FILENAME, b"assessment\n")
    result = validate_delivery_dir(tmp_path, Limits())
    assert result.ok is False
    assert result.kind is None
    assert result.completion is None
    assert result.delivery_id is None
    assert codes(result.problems) == ["missing_manifest"]


def test_corrupt_manifest_reports_manifest_corrupt(tmp_path):
    build_package(tmp_path)
    (tmp_path / MANIFEST_FILENAME).write_bytes(b"{not json")
    result = validate_delivery_dir(tmp_path, Limits())
    assert result.ok is False
    assert result.kind is None
    assert codes(result.problems) == ["manifest_corrupt"]


def test_manifest_with_wrong_delivery_id_reports_corrupt(tmp_path):
    build_package(tmp_path)
    # A valid strict-JSON document that fails contract identity rules.
    (tmp_path / MANIFEST_FILENAME).write_bytes(b'{"schema_version": 1}\n')
    result = validate_delivery_dir(tmp_path, Limits())
    assert not result.ok
    assert "manifest_corrupt" in codes(result.problems)


def test_manifest_listing_itself_is_rejected_at_construction(tmp_path):
    descriptor = make_source(tmp_path)
    add_file(tmp_path, ASSESSMENT_FILENAME, b"assessment\n")
    files = list(collect_delivery_files(tmp_path, Limits()))
    files.append(
        EvidenceFile(
            path=MANIFEST_FILENAME,
            role=FileRole.ASSESSMENT,
            size_bytes=3,
            sha256=sha256(b"{}\n"),
        )
    )
    with pytest.raises(ContractError):
        EvidenceManifest(
            delivery_id=compute_delivery_id((descriptor,)),
            kind=DeliveryKind.VERIFICATION,
            writer_version="0.1.0",
            sources=(descriptor,),
            files=tuple(sorted(files, key=lambda entry: entry.path)),
            completion=DeliveryCompletion.COMPLETE,
        )


def test_validate_refuses_non_directory_root(tmp_path):
    file_root = tmp_path / "afile"
    file_root.write_bytes(b"x")
    with pytest.raises(DeliveryError):
        validate_delivery_dir(file_root, Limits())
    link = tmp_path / "link"
    link.symlink_to(tmp_path)
    with pytest.raises(DeliveryError):
        validate_delivery_dir(link, Limits())


def test_validate_detects_raw_source_id_path_mismatch(tmp_path):
    # A manifest whose RAW_NATIVE entry claims a different source_id than the
    # directory it lives under is structurally broken even though hashes match.
    descriptor = make_source(tmp_path)
    add_file(tmp_path, ASSESSMENT_FILENAME, b"assessment\n")
    files = list(collect_delivery_files(tmp_path, Limits()))
    other_sid = "s-" + "b" * 64
    moved = tmp_path / "raw" / other_sid
    moved.mkdir(parents=True, exist_ok=True)
    (tmp_path / f"raw/{descriptor.source_id}/native.json").rename(moved / "native.json")
    relisted = []
    for entry in files:
        if entry.path.startswith("raw/"):
            relisted.append(
                EvidenceFile(
                    path=f"raw/{other_sid}/native.json",
                    role=entry.role,
                    size_bytes=entry.size_bytes,
                    sha256=entry.sha256,
                    source_id=descriptor.source_id,
                )
            )
        else:
            relisted.append(entry)
    manifest = EvidenceManifest(
        delivery_id=compute_delivery_id((descriptor,)),
        kind=DeliveryKind.VERIFICATION,
        writer_version="0.1.0",
        sources=(descriptor,),
        files=tuple(sorted(relisted, key=lambda entry: entry.path)),
        completion=DeliveryCompletion.COMPLETE,
    )
    write_evidence_manifest(tmp_path, manifest)

    result = validate_delivery_dir(tmp_path, Limits())
    assert not result.ok
    assert "source_id_mismatch" in codes(result.problems)


def test_problem_model_is_frozen():
    problem = Problem(code="x", path=None, detail="d")
    with pytest.raises(Exception):
        problem.code = "y"  # type: ignore[misc]
