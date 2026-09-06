"""B03: interrupted bundle writes stay self-consistent (design 6.5, 6.6).

Fault injection happens at the module-level ``_write_bytes`` seam.  Everything
the tests assert - statuses, conservation, published directories, validator
verdicts - is hand-written from the design, never derived by running the
validator and feeding its verdict back as an expectation.
"""

from __future__ import annotations

import errno

import pytest

from mtsql_typecheck.contracts.case import GenerationStatus
from mtsql_typecheck.generation import bundle as B
from mtsql_typecheck.generation.bundle import (
    CASES_DIRNAME,
    MANIFEST_NAME,
    ProblemKind,
    exit_code_for,
    generate_and_write,
    validate_output_dir,
    write_bundle,
)

from conftest import (
    CASE_DOC_NAME,
    case_file_names,
    generate_result,
    read_manifest_document,
    small_profile,
)

SEED = 7


def _enospc_after(path_name: str, successful_writes: int):
    """A ``_write_bytes`` replacement failing on the next write of ``path_name``."""
    real_write = B._write_bytes
    seen = {"count": 0}

    def flaky(path, data):
        if path.name == path_name:
            seen["count"] += 1
            if seen["count"] > successful_writes:
                raise OSError(errno.ENOSPC, "No space left on device")
        real_write(path, data)

    return flaky


# --------------------------------------------------------------------------
# I/O failure (ENOSPC) during case publication
# --------------------------------------------------------------------------


def test_enospc_mid_write_aborts_and_keeps_completed_cases(outroot, monkeypatch) -> None:
    """The 3rd case.json write raises ENOSPC: I/O failure, not budget (6.5)."""
    result = generate_result(small_profile(), SEED, 12)
    limit = 2
    monkeypatch.setattr(B, "_write_bytes", _enospc_after(CASE_DOC_NAME, limit))
    outcome = write_bundle(result, outroot / "bundle")
    monkeypatch.undo()

    assert outcome.final_status is GenerationStatus.ABORTED
    assert outcome.io_error is not None
    assert "No space left" in outcome.io_error
    assert outcome.budget_exhausted is False
    assert outcome.manifest_written is True
    assert outcome.cases_published == limit
    # Completed evidence is kept, never deleted (design 6.5).
    published = [
        entry
        for entry in (outcome.output_dir / CASES_DIRNAME).iterdir()
        if not entry.name.startswith(".")
    ]
    assert len(published) == limit

    # The persisted manifest: ABORTED, every ordinal attributed exactly once.
    # Repeated occurrences of an already-published case only add receipts, so
    # the emitted count can exceed the number of published directories.
    document = read_manifest_document(outcome.output_dir)
    assert document["status"] == "ABORTED"
    statistics = document["statistics"]
    published_names = {entry.name for entry in published}
    emitted = 0
    for receipt in document["receipts"]:
        if receipt["outcome"] == "emitted":
            emitted += 1
            assert receipt["case_id"] in published_names
    interrupted = sum(
        1
        for receipt in document["receipts"]
        if receipt["outcome"] == "interrupted"
    )
    assert emitted >= limit
    assert interrupted == 12 - emitted
    assert statistics["emitted_occurrences"] == emitted
    assert statistics["unique_cases"] == limit
    assert (
        statistics["emitted_occurrences"]
        + statistics["rejected_ordinals"]
        + statistics["interrupted_ordinals"]
        + statistics["not_attempted"]
        == statistics["requested_ordinals"]
        == 12
    )

    # The validator accepts the aborted bundle as legal incomplete evidence.
    report = validate_output_dir(outcome.output_dir)
    assert exit_code_for(report) == 3
    assert report.manifest_status is GenerationStatus.ABORTED
    assert report.counts_conserved is True
    assert report.cases_validated == limit
    assert [
        problem for problem in report.problems if problem.severity == "corrupt"
    ] == []


def test_enospc_leaves_no_half_published_case_dir(outroot, monkeypatch) -> None:
    """A failed publication leaves at most dot-prefixed .part traces."""
    result = generate_result(small_profile(), SEED, 10)
    monkeypatch.setattr(B, "_write_bytes", _enospc_after(CASE_DOC_NAME, 1))
    outcome = write_bundle(result, outroot / "bundle")
    monkeypatch.undo()

    cases_dir = outcome.output_dir / CASES_DIRNAME
    for entry in cases_dir.iterdir():
        if entry.name.startswith("."):
            assert entry.name.endswith(B.PART_SUFFIX)
        else:
            # Every published directory is complete.
            assert sorted(item.name for item in entry.iterdir()) == sorted(
                case_file_names()
            )


def test_enospc_on_every_manifest_write_is_recorded(outroot, monkeypatch) -> None:
    """A header/terminating-manifest failure is best effort and reported (6.5)."""
    result = generate_result(small_profile(), SEED, 4)
    real_write = B._write_bytes

    def flaky(path, data):
        # Atomic manifest writes go through a ".<name>.part" temp name first;
        # fail both the temp write and (hypothetically) the final name.
        if MANIFEST_NAME in path.name:
            raise OSError(errno.EACCES, "Permission denied")
        real_write(path, data)

    monkeypatch.setattr(B, "_write_bytes", flaky)
    outcome = write_bundle(result, outroot / "bundle")
    monkeypatch.undo()

    assert outcome.manifest_written is False
    assert outcome.io_error is not None
    assert outcome.final_status is GenerationStatus.ABORTED
    # No manifest on disk at all: cannot verify (exit 2), never a fake pass.
    report = validate_output_dir(outcome.output_dir)
    assert exit_code_for(report) == 2
    assert any(
        problem.kind is ProblemKind.MISSING_MANIFEST for problem in report.problems
    )


# --------------------------------------------------------------------------
# Cancellation during generation
# --------------------------------------------------------------------------


def test_cancellation_mid_generation_aborts_and_conserves(outroot) -> None:
    profile = small_profile()
    limit = 10
    state = {"seen": 0}

    def should_cancel() -> bool:
        state["seen"] += 1
        return state["seen"] > limit

    result, outcome = generate_and_write(
        profile, SEED, 40, outroot / "bundle", should_cancel=should_cancel
    )
    assert result.manifest.status is GenerationStatus.ABORTED
    assert len(result.manifest.receipts) == limit
    assert result.manifest.not_attempted == 40 - limit
    assert outcome.final_status is GenerationStatus.ABORTED
    assert outcome.io_error is None
    assert outcome.budget_exhausted is False
    assert outcome.cases_published == result.manifest.unique_cases

    report = validate_output_dir(outcome.output_dir)
    assert exit_code_for(report) == 3
    assert report.manifest_status is GenerationStatus.ABORTED
    assert report.counts_conserved is True
    assert [
        problem for problem in report.problems if problem.severity == "corrupt"
    ] == []


# --------------------------------------------------------------------------
# Byte budget exhaustion (logical stop, never truncation)
# --------------------------------------------------------------------------


def test_tiny_budget_stops_cleanly_partial(outroot) -> None:
    result = generate_result(small_profile(), SEED, 30)
    outcome = write_bundle(
        result, outroot / "bundle", budget=B.BundleBudget(max_total_bytes=32768)
    )
    assert outcome.budget_exhausted is True
    assert outcome.final_status is GenerationStatus.PARTIAL
    assert outcome.io_error is None
    assert outcome.manifest_written is True
    assert 1 <= outcome.cases_published < result.manifest.unique_cases

    # Nothing was truncated: every written file validates byte-exactly.
    report = validate_output_dir(outcome.output_dir)
    assert exit_code_for(report) == 3
    assert report.manifest_status is GenerationStatus.PARTIAL
    assert report.counts_conserved is True
    assert report.cases_validated == outcome.cases_published
    assert [
        problem for problem in report.problems if problem.severity == "corrupt"
    ] == []

    # Interrupted ordinals carry an explanatory reason and conserve counts.
    # Repeated occurrences only add receipts: emitted >= published.
    manifest = outcome.manifest
    assert manifest.unique_cases == outcome.cases_published
    assert manifest.emitted_occurrences >= outcome.cases_published
    interrupted_reasons = [
        receipt.reason
        for receipt in manifest.receipts
        if receipt.outcome.value == "interrupted"
    ]
    assert interrupted_reasons
    assert manifest.interrupted_ordinals == len(interrupted_reasons)
    assert (
        manifest.emitted_occurrences
        + manifest.rejected_ordinals
        + manifest.interrupted_ordinals
        + manifest.not_attempted
        == manifest.requested_ordinals
        == 30
    )

    # The terminating manifest must not claim more than was persisted.
    document = read_manifest_document(outcome.output_dir)
    assert document["status"] == "PARTIAL"
    assert document["statistics"]["unique_cases"] == outcome.cases_published


def test_budget_exhaustion_writes_only_complete_case_directories(outroot) -> None:
    result = generate_result(small_profile(), SEED, 60)
    outcome = write_bundle(
        result, outroot / "bundle", budget=B.BundleBudget(max_total_bytes=32768)
    )
    assert outcome.budget_exhausted is True
    cases_dir = outcome.output_dir / CASES_DIRNAME
    published = [entry for entry in cases_dir.iterdir() if not entry.name.startswith(".")]
    assert len(published) == outcome.cases_published
    for entry in published:
        assert sorted(item.name for item in entry.iterdir()) == sorted(
            case_file_names()
        )


def test_budget_below_header_is_rejected_before_creating_anything(outroot) -> None:
    result = generate_result(small_profile(), SEED, 3)
    with pytest.raises(B.BundleBudgetError):
        write_bundle(
            result,
            outroot / "bundle",
            budget=B.BundleBudget(max_total_bytes=B.TERMINATION_RESERVE_BYTES),
        )
    assert not (outroot / "bundle").exists()


# --------------------------------------------------------------------------
# The writer never deletes anything
# --------------------------------------------------------------------------


def test_writer_never_cleans_up_interruption_evidence(outroot, monkeypatch) -> None:
    """Interrupted state is preserved: nothing inside the output dir is removed."""
    result = generate_result(small_profile(), SEED, 8)
    monkeypatch.setattr(B, "_write_bytes", _enospc_after(CASE_DOC_NAME, 2))
    outcome = write_bundle(result, outroot / "bundle")
    monkeypatch.undo()

    published = [
        entry
        for entry in (outcome.output_dir / CASES_DIRNAME).iterdir()
        if not entry.name.startswith(".")
    ]
    assert len(published) == outcome.cases_published == 2
    # The .part directory of the failed case is still on disk as evidence.
    residue = [
        entry
        for entry in (outcome.output_dir / CASES_DIRNAME).iterdir()
        if entry.name.startswith(".")
    ]
    assert residue, "interruption evidence must not be silently cleaned up"
