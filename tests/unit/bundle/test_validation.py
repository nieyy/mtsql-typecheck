"""B01/B02: bundle write + offline validation, corruption matrix (design 6.6).

Every expected verdict is written by hand here: exit codes come from design
6.3.3, the counter conservation from design 6.6, and the pinned case ids are
frozen once by generating them and asserting the frozen values afterwards.
The validator is never used to produce the expectations it is judged against.
"""

from __future__ import annotations

import dataclasses
import json
import shutil

import pytest

from mtsql_typecheck.contracts.case import (
    ContractError,
    GenerationStatus,
    RuleReviewStatus,
)
from mtsql_typecheck.contracts.codec import canonical_json
from mtsql_typecheck.generation import bundle as B
from mtsql_typecheck.generation.bundle import (
    CASES_DIRNAME,
    MANIFEST_NAME,
    PROFILE_NAME,
    BundleBudgetError,
    OutputDirExistsError,
    ProblemKind,
    UnsafePathError,
    exit_code_for,
    generate_and_write,
    validate_output_dir,
    write_bundle,
)
from mtsql_typecheck.rules.registry import get_rule, register_rule

from conftest import (
    CASE_DOC_NAME,
    PREVIEW_A_NAME,
    PREVIEW_B_NAME,
    STATIC_CHECK_NAME,
    case_file_names,
    generate_result,
    read_manifest_document,
    rewrite_manifest,
    small_profile,
)

SEED = 42


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def write_small_bundle(outroot, count: int = 8, **kwargs):
    result = generate_result(small_profile(), SEED, count, **kwargs)
    outcome = write_bundle(result, outroot / "bundle")
    return result, outcome


def problems_of(report, kind: ProblemKind):
    return [problem for problem in report.problems if problem.kind is kind]


def assert_no_corrupt(report) -> None:
    corrupt = [p for p in report.problems if p.severity == "corrupt"]
    assert corrupt == []


# --------------------------------------------------------------------------
# B01: complete / partial / aborted bundles validate with the right exit code
# --------------------------------------------------------------------------


def test_complete_bundle_roundtrip_exit_zero(outroot) -> None:
    result, outcome = write_small_bundle(outroot)
    assert outcome.final_status is GenerationStatus.COMPLETE
    assert outcome.io_error is None
    assert not outcome.budget_exhausted
    report = validate_output_dir(outroot / "bundle")
    assert report.manifest_status is GenerationStatus.COMPLETE
    assert report.problems == ()
    assert report.counts_conserved is True
    assert report.cases_validated == outcome.cases_published
    assert exit_code_for(report) == 0
    # Counter conservation from design 6.6, asserted from the frozen result.
    manifest = result.manifest
    assert (
        manifest.emitted_occurrences
        + manifest.rejected_ordinals
        + manifest.interrupted_ordinals
        + manifest.not_attempted
        == manifest.requested_ordinals
    )


def test_layout_matches_design(outroot) -> None:
    _result, outcome = write_small_bundle(outroot)
    out = outcome.output_dir
    assert sorted(entry.name for entry in out.iterdir()) == [
        CASES_DIRNAME,
        MANIFEST_NAME,
        PROFILE_NAME,
    ]
    published = sorted(
        (out / CASES_DIRNAME).iterdir(), key=lambda path: path.name
    )
    assert published, "the small profile must emit at least one case"
    for case_dir in published:
        assert sorted(entry.name for entry in case_dir.iterdir()) == sorted(
            case_file_names()
        )
    # Temp names are dot-prefixed and never survive a completed write.
    assert not any(entry.name.startswith(".") for entry in out.rglob("*"))


def test_rejected_ordinal_partial_exit_three(outroot) -> None:
    result, outcome = write_small_bundle(outroot, count=8, reject_ordinals=frozenset({2}))
    assert result.manifest.status is GenerationStatus.PARTIAL
    assert result.manifest.rejected_ordinals == 1
    assert result.manifest.emitted_occurrences == 7
    assert outcome.final_status is GenerationStatus.PARTIAL
    report = validate_output_dir(outroot / "bundle")
    assert exit_code_for(report) == 3
    assert report.manifest_status is GenerationStatus.PARTIAL
    assert_no_corrupt(report)
    assert report.counts_conserved is True


def test_zero_success_partial_exit_three(outroot) -> None:
    count = 5
    result, outcome = write_small_bundle(
        outroot, count=count, reject_ordinals=frozenset(range(count))
    )
    assert result.manifest.status is GenerationStatus.PARTIAL
    assert result.manifest.emitted_occurrences == 0
    assert result.manifest.unique_cases == 0
    assert outcome.cases_published == 0
    report = validate_output_dir(outroot / "bundle")
    assert exit_code_for(report) == 3
    assert report.manifest_status is GenerationStatus.PARTIAL
    assert_no_corrupt(report)
    assert report.cases_validated == 0


def test_cancelled_generation_aborted_exit_three(outroot) -> None:
    profile = small_profile()
    limit = 4
    state = {"ordinals": 0}

    def cancel_after_limit() -> bool:
        state["ordinals"] += 1
        return state["ordinals"] > limit

    result, outcome = generate_and_write(
        profile, SEED, 20, outroot / "bundle", should_cancel=cancel_after_limit
    )
    assert result.manifest.status is GenerationStatus.ABORTED
    assert result.manifest.not_attempted == 20 - limit
    assert len(result.manifest.receipts) == limit
    assert outcome.final_status is GenerationStatus.ABORTED
    report = validate_output_dir(outroot / "bundle")
    assert exit_code_for(report) == 3
    assert report.manifest_status is GenerationStatus.ABORTED
    assert_no_corrupt(report)
    assert report.counts_conserved is True
    # Conservation asserted from the written manifest, not the result object.
    written = read_manifest_document(outcome.output_dir)["statistics"]
    assert (
        written["emitted_occurrences"]
        + written["rejected_ordinals"]
        + written["interrupted_ordinals"]
        + written["not_attempted"]
        == written["requested_ordinals"]
        == 20
    )


def test_unique_case_written_once_with_many_occurrences(outroot) -> None:
    """Ordinals 35/36/75/76 repeat earlier payloads: one directory, many receipts."""
    result, outcome = write_small_bundle(outroot, count=77)
    assert result.manifest.emitted_occurrences == 77
    assert result.manifest.unique_cases < result.manifest.emitted_occurrences
    assert outcome.cases_published == result.manifest.unique_cases
    case_dirs = [entry for entry in (outcome.output_dir / CASES_DIRNAME).iterdir()]
    assert len(case_dirs) == result.manifest.unique_cases
    document = read_manifest_document(outcome.output_dir)
    per_case: dict[str, int] = {}
    for receipt in document["receipts"]:
        assert receipt["outcome"] == "emitted"
        per_case[receipt["case_id"]] = per_case.get(receipt["case_id"], 0) + 1
    assert max(per_case.values()) >= 2, "the frozen seed must produce repeats"
    assert sum(per_case.values()) == 77
    assert len(per_case) == len(case_dirs)
    report = validate_output_dir(outcome.output_dir)
    assert exit_code_for(report) == 0
    assert report.problems == ()


# --------------------------------------------------------------------------
# Writer input safety (design 6.5)
# --------------------------------------------------------------------------


def test_existing_output_directory_rejected(outroot) -> None:
    result = generate_result(small_profile(), SEED, 3)
    target = outroot / "bundle"
    target.mkdir()  # empty existing directory
    with pytest.raises(OutputDirExistsError):
        write_bundle(result, target)
    (target / "some-file.txt").write_text("occupied")
    with pytest.raises(OutputDirExistsError):
        write_bundle(result, target)
    assert list(target.iterdir()) == [target / "some-file.txt"]


def test_symlink_component_rejected(outroot) -> None:
    result = generate_result(small_profile(), SEED, 2)
    real = outroot / "real"
    real.mkdir()
    link = outroot / "link"
    link.symlink_to(real)
    with pytest.raises(UnsafePathError):
        write_bundle(result, link / "bundle")
    # The symlinked final component is refused in its own right (covered
    # again in test_symlinked_final_component_rejected); here the traversal
    # through `link` must not have created anything under `real`.
    assert not (real / "bundle").exists()


def test_symlinked_final_component_rejected(outroot) -> None:
    result = generate_result(small_profile(), SEED, 2)
    outside = outroot / "outside"
    outside.mkdir()
    link = outroot / "bundle"
    link.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        write_bundle(result, link)
    assert list(outside.iterdir()) == []


def test_budget_too_small_for_header_is_input_error(outroot) -> None:
    result = generate_result(small_profile(), SEED, 2)
    with pytest.raises(BundleBudgetError):
        write_bundle(result, outroot / "bundle", budget=B.BundleBudget(max_total_bytes=4096))
    assert not (outroot / "bundle").exists()


# --------------------------------------------------------------------------
# B02: corruption matrix
# --------------------------------------------------------------------------


def _copied_bundle(outroot, name: str):
    _result, outcome = write_small_bundle(outroot)
    target = outroot / name
    shutil.copytree(outcome.output_dir, target, symlinks=False)
    assert exit_code_for(validate_output_dir(target)) == 0
    return target


def _some_case_dir(bundle: Path):
    case_dirs = sorted((bundle / CASES_DIRNAME).iterdir())
    assert case_dirs
    return case_dirs[0]


def test_tampered_case_payload_is_caught_semantically(outroot) -> None:
    """Changing the payload invalidates case_id even with hashes left stale.

    The last row's rid is bumped by one: structurally legal (strictly
    increasing, in range), independent of column types, and guaranteed to
    change the payload hash.  The manifest artifact hash is deliberately NOT
    updated, but the decisive assertion is the semantic one: the recomputed
    payload hash no longer matches the stored case_id.
    """
    bundle = _copied_bundle(outroot, "tamper-case")
    case_dir = _some_case_dir(bundle)
    document = json.loads((case_dir / CASE_DOC_NAME).read_text(encoding="utf-8"))
    rows = document["payload"]["rows"]
    assert rows, "the frozen bundle must contain rows"
    rows[-1][0] = int(rows[-1][0]) + 1
    (case_dir / CASE_DOC_NAME).write_bytes(canonical_json(document) + b"\n")
    report = validate_output_dir(bundle)
    assert exit_code_for(report) == 2
    kinds = {problem.kind for problem in report.problems}
    assert ProblemKind.CASE_ID_MISMATCH in kinds


def test_tampered_case_id_field_is_caught(outroot) -> None:
    bundle = _copied_bundle(outroot, "tamper-id")
    case_dir = _some_case_dir(bundle)
    document = json.loads((case_dir / CASE_DOC_NAME).read_text(encoding="utf-8"))
    document["case_id"] = "f" * 64
    (case_dir / CASE_DOC_NAME).write_bytes(canonical_json(document) + b"\n")
    report = validate_output_dir(bundle)
    assert exit_code_for(report) == 2
    assert problems_of(report, ProblemKind.CASE_ID_MISMATCH)


def test_tampered_preview_sql_is_caught(outroot) -> None:
    bundle = _copied_bundle(outroot, "tamper-preview")
    case_dir = _some_case_dir(bundle)
    text = (case_dir / PREVIEW_A_NAME).read_text(encoding="utf-8")
    # render_preview emits no trailing newline, so appending one is a
    # guaranteed byte difference against the re-rendered text.
    (case_dir / PREVIEW_A_NAME).write_text(text + "\n", encoding="utf-8")
    report = validate_output_dir(bundle)
    assert exit_code_for(report) == 2
    assert problems_of(report, ProblemKind.PREVIEW_MISMATCH)


def test_tampered_static_check_is_caught(outroot) -> None:
    bundle = _copied_bundle(outroot, "tamper-check")
    case_dir = _some_case_dir(bundle)
    document = json.loads((case_dir / STATIC_CHECK_NAME).read_text(encoding="utf-8"))
    document["status"] = "INVALID"
    (case_dir / STATIC_CHECK_NAME).write_bytes(canonical_json(document) + b"\n")
    report = validate_output_dir(bundle)
    assert exit_code_for(report) == 2
    assert problems_of(report, ProblemKind.STATIC_CHECK_MISMATCH)


def test_tampered_profile_is_caught(outroot) -> None:
    bundle = _copied_bundle(outroot, "tamper-profile")
    document = json.loads((bundle / PROFILE_NAME).read_text(encoding="utf-8"))
    document["row_count"] = 9
    (bundle / PROFILE_NAME).write_bytes(canonical_json(document) + b"\n")
    report = validate_output_dir(bundle)
    assert exit_code_for(report) == 2
    assert problems_of(report, ProblemKind.PROFILE_MISMATCH)


def test_deleted_referenced_file_is_caught(outroot) -> None:
    bundle = _copied_bundle(outroot, "deleted-file")
    case_dir = _some_case_dir(bundle)
    (case_dir / PREVIEW_B_NAME).unlink()
    report = validate_output_dir(bundle)
    assert exit_code_for(report) == 2
    assert problems_of(report, ProblemKind.MISSING_FILE)


def test_duplicate_ordinal_receipt_is_caught(outroot) -> None:
    bundle = _copied_bundle(outroot, "dup-ordinal")

    def duplicate_first_receipt(document):
        document["receipts"].append(dict(document["receipts"][0]))
        document["statistics"]["emitted_occurrences"] += 1

    rewrite_manifest(bundle, duplicate_first_receipt)
    report = validate_output_dir(bundle)
    assert exit_code_for(report) == 2
    assert problems_of(report, ProblemKind.ORDINAL_DUPLICATE)


def test_path_escape_case_reference_is_caught(outroot) -> None:
    bundle = _copied_bundle(outroot, "path-escape")

    def inject_traversal(document):
        document["case_files"].append(
            {"case_id": "../evil", "artifact_hash": "0" * 64, "size_bytes": 0}
        )

    rewrite_manifest(bundle, inject_traversal)
    report = validate_output_dir(bundle)
    assert exit_code_for(report) == 2
    assert problems_of(report, ProblemKind.PATH_ESCAPE)


def test_unknown_case_reference_is_caught(outroot) -> None:
    bundle = _copied_bundle(outroot, "unknown-case")

    def inject_unknown_case(document):
        document["case_files"].append(
            {"case_id": "a" * 64, "artifact_hash": "0" * 64, "size_bytes": 10}
        )
        document["statistics"]["unique_cases"] += 1

    rewrite_manifest(bundle, inject_unknown_case)
    report = validate_output_dir(bundle)
    assert exit_code_for(report) == 2
    kinds = {problem.kind for problem in report.problems}
    assert ProblemKind.UNREFERENCED_CASE_ENTRY in kinds
    assert ProblemKind.MISSING_FILE in kinds


def test_unknown_manifest_schema_version_is_rejected(outroot) -> None:
    bundle = _copied_bundle(outroot, "bad-manifest-version")

    def bump_version(document):
        document["generation_schema_version"] = 2

    rewrite_manifest(bundle, bump_version)
    report = validate_output_dir(bundle)
    assert exit_code_for(report) == 2
    assert problems_of(report, ProblemKind.UNKNOWN_SCHEMA_VERSION)


def test_unknown_case_schema_version_is_rejected(outroot) -> None:
    bundle = _copied_bundle(outroot, "bad-case-version")
    case_dir = _some_case_dir(bundle)
    document = json.loads((case_dir / CASE_DOC_NAME).read_text(encoding="utf-8"))
    document["payload"]["case_schema_version"] = 2
    (case_dir / CASE_DOC_NAME).write_bytes(canonical_json(document) + b"\n")
    report = validate_output_dir(bundle)
    assert exit_code_for(report) == 2
    assert problems_of(report, ProblemKind.CASE_CORRUPT)


def test_partial_manifest_cannot_be_promoted_to_complete(outroot) -> None:
    result = generate_result(small_profile(), SEED, 8, reject_ordinals=frozenset({1}))
    outcome = write_bundle(result, outroot / "bundle")
    assert outcome.final_status is GenerationStatus.PARTIAL

    def promote(document):
        document["status"] = "COMPLETE"

    rewrite_manifest(outcome.output_dir, promote)
    report = validate_output_dir(outcome.output_dir)
    assert exit_code_for(report) == 2
    assert problems_of(report, ProblemKind.COUNT_MISMATCH)


def test_legacy_running_manifest_validates_as_incomplete(outroot) -> None:
    _result, outcome = write_small_bundle(outroot)

    def mark_running(document):
        document["status"] = "RUNNING"

    rewrite_manifest(outcome.output_dir, mark_running)
    report = validate_output_dir(outcome.output_dir)
    assert exit_code_for(report) == 3
    assert report.manifest_status is GenerationStatus.RUNNING
    assert_no_corrupt(report)


def test_orphan_case_dir_is_listed_and_blocks_complete(outroot) -> None:
    _result, outcome = write_small_bundle(outroot)
    case_dirs = sorted((outcome.output_dir / CASES_DIRNAME).iterdir())
    orphan = outcome.output_dir / CASES_DIRNAME / ("b" * 64)
    shutil.copytree(case_dirs[0], orphan)
    report = validate_output_dir(outcome.output_dir)
    found = problems_of(report, ProblemKind.ORPHAN_CASE_DIR)
    assert found and found[0].path.endswith("b" * 64)
    assert exit_code_for(report) == 3


def test_part_residue_under_complete_manifest_is_inconsistent(outroot) -> None:
    _result, outcome = write_small_bundle(outroot)
    residue = outcome.output_dir / CASES_DIRNAME / f".{'c' * 64}{B.PART_SUFFIX}"
    residue.mkdir()
    (residue / CASE_DOC_NAME).write_bytes(b"{}")
    report = validate_output_dir(outcome.output_dir)
    assert problems_of(report, ProblemKind.PART_RESIDUE)
    assert exit_code_for(report) == 2


def test_unexpected_top_level_entry_is_reported(outroot) -> None:
    _result, outcome = write_small_bundle(outroot)
    (outcome.output_dir / "extra.txt").write_text("stray")
    report = validate_output_dir(outcome.output_dir)
    assert exit_code_for(report) == 2
    assert problems_of(report, ProblemKind.UNEXPECTED_ENTRY)


# --------------------------------------------------------------------------
# Rule registry state (design 6.2.1)
# --------------------------------------------------------------------------


def test_disabled_rule_blocks_validation(outroot) -> None:
    _result, outcome = write_small_bundle(outroot)
    original = get_rule("mysql80.integer-decimal", 1)
    disabled = dataclasses.replace(original, review_status=RuleReviewStatus.DISABLED)
    register_rule(disabled)
    try:
        report = validate_output_dir(outcome.output_dir)
        assert exit_code_for(report) == 2
        found = problems_of(report, ProblemKind.RULE_DISABLED)
        assert found
        assert all("disabled" in problem.detail for problem in found)
        assert report.manifest_status is GenerationStatus.COMPLETE
    finally:
        register_rule(original)
    # Restoration: the same bundle validates cleanly again.
    assert exit_code_for(validate_output_dir(outcome.output_dir)) == 0


# --------------------------------------------------------------------------
# Missing manifest and exit-code mapping
# --------------------------------------------------------------------------


def test_missing_manifest_cannot_verify(outroot) -> None:
    _result, outcome = write_small_bundle(outroot)
    (outcome.output_dir / MANIFEST_NAME).unlink()
    report = validate_output_dir(outcome.output_dir)
    assert report.manifest_status is None
    assert problems_of(report, ProblemKind.MISSING_MANIFEST)
    assert exit_code_for(report) == 2


def test_missing_output_directory_cannot_verify(tmp_path) -> None:
    report = validate_output_dir(tmp_path / "does-not-exist")
    assert problems_of(report, ProblemKind.MISSING_MANIFEST)
    assert exit_code_for(report) == 2


def test_exit_code_mapping() -> None:
    from mtsql_typecheck.generation.bundle import ValidationProblem

    def report_with(*problems, status=GenerationStatus.COMPLETE):
        return B.ValidationReport(
            output_dir="/unused",
            manifest_status=status,
            problems=tuple(problems),
            cases_validated=0,
            counts_conserved=True,
        )

    corrupt = ValidationProblem(
        ProblemKind.CASE_CORRUPT, "case.json", "detail", "corrupt"
    )
    incomplete = ValidationProblem(
        ProblemKind.PART_RESIDUE, ".x.part", "detail", "incomplete"
    )
    io = ValidationProblem(ProblemKind.IO_ERROR, "manifest", "detail", "io")
    assert exit_code_for(report_with()) == 0
    assert exit_code_for(report_with(status=GenerationStatus.PARTIAL)) == 3
    assert exit_code_for(report_with(status=GenerationStatus.ABORTED)) == 3
    assert exit_code_for(report_with(status=GenerationStatus.RUNNING)) == 3
    assert exit_code_for(report_with(incomplete)) == 3
    assert exit_code_for(report_with(io)) == 1
    assert exit_code_for(report_with(corrupt)) == 2
    # Corruption outranks both incompleteness and I/O trouble.
    assert exit_code_for(report_with(incomplete, io, corrupt)) == 2


# --------------------------------------------------------------------------
# The strict loader keeps rejecting non-canonical documents
# --------------------------------------------------------------------------


def test_noncanonical_manifest_document_is_caught(outroot) -> None:
    _result, outcome = write_small_bundle(outroot)
    path = outcome.output_dir / MANIFEST_NAME
    document = json.loads(path.read_text(encoding="utf-8"))
    path.write_bytes(json.dumps(document, indent=2).encode("utf-8"))
    report = validate_output_dir(outcome.output_dir)
    assert exit_code_for(report) == 2
    kinds = {problem.kind for problem in report.problems}
    assert ProblemKind.NONCANONICAL_JSON in kinds


def test_writer_rejects_non_generation_result(outroot) -> None:
    with pytest.raises(ContractError):
        write_bundle("not a result", outroot / "bundle")  # type: ignore[arg-type]
    assert not (outroot / "bundle").exists()
