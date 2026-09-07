"""Unit tests for cli/delivery.py (D4 Phase 5a: evidence-verify / report /
export CLI wiring and the design 6.3 exit-code table).

Every expected exit code is hand-stated from the design table; fixtures reuse
the reduction fakes, the real generator and the real trace engine exactly like
tests/unit/evidence and tests/unit/delivery.  Nothing derives an expectation
from the code under test: the delivery id and occurrence ids needed by review
fixtures are read from a FIRST verification run's sealed manifest (the pinned
identity contract), never recomputed by CLI-internal logic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mtsql_typecheck.cli import delivery as cd
from mtsql_typecheck.cli.main import main
from mtsql_typecheck.contracts.codec import (
    canonical_json,
    case_id_of,
    decode_case_payload,
    parse_strict_json,
)
from mtsql_typecheck.contracts.delivery import (
    ReviewDecision,
    compute_occurrence_id,
)
from mtsql_typecheck.contracts.delivery import FindingReview
from mtsql_typecheck.contracts.oracle import EVIDENCE_APPEND_BUDGET
from mtsql_typecheck.reduction.trace import JsonlTraceSink

# Fixture helpers live in the delivery and reduction unit suites; their
# directories are appended explicitly (same technique as the suites
# themselves, so this does not depend on rootdir configuration).
_TEST_DIR = Path(__file__).resolve().parent
_DELIVERY_TEST_DIR = _TEST_DIR.parent / "delivery"
_REDUCTION_TEST_DIR = _TEST_DIR.parent / "reduction"
for _path in (_DELIVERY_TEST_DIR, _REDUCTION_TEST_DIR):
    if str(_path) not in sys.path:
        sys.path.append(str(_path))

import test_selection as ts  # noqa: E402

import engine_fakes as ef  # noqa: E402
import replay_fakes as rf  # noqa: E402


# --------------------------------------------------------------------------
# Fixture builders
# --------------------------------------------------------------------------


def _generation_root(root: Path) -> Path:
    ts._write_generation_bundle(root)
    return root


def _run_root(root: Path, attempt_ids: list[str]) -> Path:
    ts._write_run_root(root, attempt_ids, synthetic=False)
    return root


def _trace_root(root: Path) -> Path:
    bundle = rf.CandidateBundle()
    executor = ef.ReductionExecutor(bundle)
    with JsonlTraceSink(root, EVIDENCE_APPEND_BUDGET) as sink:
        ef.run_reduction(bundle, executor, sink)
    return root


def _attempt_case_id(root: Path, attempt_id: str = "attempt-orig") -> str:
    request = parse_strict_json(
        (root / "attempts" / attempt_id / "request.json").read_bytes()
    )
    return case_id_of(decode_case_payload(request["payload"], what="fixture payload"))


def _verify(root: Path, out: Path, *extra: str) -> int:
    return main(["evidence-verify", "--input", str(root), "--output", str(out), *extra])


def _manifest(out: Path) -> dict:
    return json.loads((out / "evidence-manifest.json").read_text("utf-8"))


def _report_document(out: Path) -> dict:
    return json.loads((out / "report.json").read_text("utf-8"))


def _identity(
    root: Path, scratch: Path, attempt_id: str = "attempt-orig"
) -> tuple[str, str, str]:
    """(source_id, delivery_id, occurrence_id) of a run root's first
    attempt, read from a first verification run's sealed manifest."""
    out = scratch / "identity-scratch"
    assert _verify(root, out) in (0, 3, 4)
    manifest = _manifest(out)
    source_id = manifest["sources"][0]["source_id"]
    delivery_id = manifest["delivery_id"]
    case_id = _attempt_case_id(root, attempt_id)
    return source_id, delivery_id, compute_occurrence_id(source_id, attempt_id, case_id)


def _write_review(
    path: Path,
    delivery_id: str,
    occurrence_id: str,
    *,
    decision: ReviewDecision = ReviewDecision.CONFIRMED_DB_BUG,
    review_id: str = "rev-1",
    digest_override: str | None = None,
) -> Path:
    review = FindingReview(
        review_id=review_id,
        reviewer="alice",
        reviewed_at="2026-09-07T00:00:00Z",
        evidence_digest=digest_override if digest_override is not None else delivery_id,
        occurrence_ids=(occurrence_id,),
        decision=decision,
        reason="reproduced on a disposable instance and confirmed by inspection",
    )
    path.write_bytes(canonical_json(review.to_obj()) + b"\n")
    return path


# --------------------------------------------------------------------------
# evidence-verify
# --------------------------------------------------------------------------


def test_verify_clean_generation_source_exits_zero(outroot: Path, tmp_path: Path) -> None:
    root = _generation_root(tmp_path / "gen")
    out = outroot / "pkg"
    rc = _verify(root, out)
    assert rc == 0
    assert {p.name for p in out.iterdir()} == {
        "assessment.json",
        "evidence-manifest.json",
        "raw",
    }
    manifest = _manifest(out)
    assert manifest["kind"] == "verification"
    assert manifest["completion"] == "COMPLETE"
    assert manifest["assessment_ref"] == "assessment.json"
    assert len(manifest["sources"]) == 1


def test_verify_summary_carries_identity_dimensions_and_reasons(
    outroot: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    root = _generation_root(tmp_path / "gen")
    out = outroot / "pkg"
    assert _verify(root, out) == 0
    text = capsys.readouterr().out
    manifest = _manifest(out)
    assert f"source_id: {manifest['sources'][0]['source_id']}" in text
    assert "native_kind: generation" in text
    for line in (
        "structural: ",
        "semantic: ",
        "provenance: ",
        "execution_safety: ",
    ):
        assert line in text  # all four dimensions, no aggregate PASS line
    assert "completion: COMPLETE" in text
    assert f"delivery_id: {manifest['delivery_id']}" in text
    assert "reasons: none" in text
    assert f"output: {out}" in text


def test_verify_hint_mismatch_is_a_usage_refusal(outroot: Path, tmp_path: Path) -> None:
    root = _generation_root(tmp_path / "gen")
    out = outroot / "pkg"
    rc = _verify(root, out, "--input-kind", "run")
    assert rc == 2
    assert not out.exists()


def test_verify_unknown_root_is_a_usage_refusal(outroot: Path, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    rc = _verify(empty, outroot / "pkg")
    assert rc == 2
    assert not (outroot / "pkg").exists()


def test_verify_run_candidate_keeps_retained_reasons_at_exit_3(
    outroot: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    root = _run_root(tmp_path / "run", ["attempt-orig"])
    out = outroot / "pkg"
    rc = _verify(root, out)
    assert rc == 3
    text = capsys.readouterr().out
    # Both the incomplete provenance AND the candidate finding are retained
    # even though the first-match table picks 3.
    assert "provenance_unverified" in text
    assert "recomputable_candidate_present" in text
    assert "completion: COMPLETE" in text


def test_verify_trace_candidate_exits_4(outroot: Path, tmp_path: Path) -> None:
    root = _trace_root(tmp_path / "trace")
    rc = _verify(root, outroot / "pkg")
    assert rc == 4


def test_verify_existing_output_directory_exit_2(outroot: Path, tmp_path: Path) -> None:
    root = _generation_root(tmp_path / "gen")
    out = outroot / "pkg"
    out.mkdir()
    (out / "keepme.txt").write_bytes(b"keep\n")
    rc = _verify(root, out)
    assert rc == 2
    assert (out / "keepme.txt").read_bytes() == b"keep\n"


def test_verify_orphan_file_is_recorded_never_copied(
    outroot: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    root = _generation_root(tmp_path / "gen")
    (root / "stray-notes.txt").write_bytes(b"not part of the closure\n")
    out = outroot / "pkg"
    rc = _verify(root, out)
    assert rc == 0
    assert "orphan_files: 1" in capsys.readouterr().out
    package_files = {entry["path"] for entry in _manifest(out)["files"]}
    assert not any("stray-notes.txt" in path for path in package_files)


def test_verify_cancelled_run_publishes_no_manifest(
    outroot: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _AlwaysCancelled:
        def flag(self) -> bool:
            return True

        def handler(self, signum, frame) -> None:  # pragma: no cover
            pass

    monkeypatch.setattr(cd, "_CancelState", _AlwaysCancelled)
    root = _generation_root(tmp_path / "gen")
    out = outroot / "pkg"
    rc = _verify(root, out)
    assert rc == 130
    # The unsealed directory stays, but nothing is published as evidence.
    assert out.exists()
    assert not (out / "evidence-manifest.json").exists()
    assert not (out / "assessment.json").exists()


def test_verify_budget_expiry_exits_3(
    outroot: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    def _expiring_clock() -> float:
        calls["n"] += 1
        return 0.0 if calls["n"] <= 2 else 1.0e9

    monkeypatch.setattr(cd, "_monotonic", _expiring_clock)
    root = _generation_root(tmp_path / "gen")
    rc = _verify(root, outroot / "pkg")
    assert rc == 3
    assert not (outroot / "pkg" / "evidence-manifest.json").exists() or _manifest(
        outroot / "pkg"
    )["completion"] == "PARTIAL"


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------


def test_report_generation_source_exits_zero_with_three_renderings(
    outroot: Path, tmp_path: Path
) -> None:
    root = _generation_root(tmp_path / "gen")
    out = outroot / "pkg"
    rc = main(["report", "--input", str(root), "--output", str(out)])
    assert rc == 0
    assert {p.name for p in out.iterdir()} == {
        "assessment.json",
        "evidence-manifest.json",
        "report.json",
        "report.md",
        "report.html",
        "raw",
    }
    manifest = _manifest(out)
    assert manifest["kind"] == "report"
    document = _report_document(out)
    assert document["header"]["delivery_id"] == manifest["delivery_id"]
    # No reviews given: no reviews/ directory is created at all.
    assert not (out / "reviews").exists()


def test_report_review_conflict_exits_3_and_keeps_both_reviews(
    outroot: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    root = _run_root(tmp_path / "run", ["attempt-orig"])
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    _, delivery_id, occurrence_id = _identity(root, scratch)
    review_one = _write_review(
        scratch / "rev-1.json", delivery_id, occurrence_id, review_id="rev-1"
    )
    review_two = _write_review(
        scratch / "rev-2.json",
        delivery_id,
        occurrence_id,
        decision=ReviewDecision.EXPECTED_BEHAVIOR,
        review_id="rev-2",
    )
    out = outroot / "pkg"
    rc = main(
        [
            "report",
            "--input",
            str(root),
            "--output",
            str(out),
            "--review",
            str(review_one),
            "--review",
            str(review_two),
        ]
    )
    assert rc == 3
    assert "review_conflict" in capsys.readouterr().out
    document = _report_document(out)
    assert document["reviews"]["has_conflict"] is True
    assert {review["review_id"] for review in document["reviews"]["accepted"]} == {
        "rev-1",
        "rev-2",
    }
    # Both opinions are copied next to the evidence; the original
    # observation is untouched.
    assert (out / "reviews" / "rev-1.json").is_file()
    assert (out / "reviews" / "rev-2.json").is_file()


def test_report_illegal_review_document_exit_2_before_any_output(
    outroot: Path, tmp_path: Path
) -> None:
    root = _generation_root(tmp_path / "gen")
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"this is not a review document")
    out = outroot / "pkg"
    rc = main(["report", "--input", str(root), "--output", str(out), "--review", str(bad)])
    assert rc == 2
    assert not out.exists()


def test_report_review_bound_to_other_evidence_exit_2(
    outroot: Path, tmp_path: Path
) -> None:
    root = _run_root(tmp_path / "run", ["attempt-orig"])
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    _, _, occurrence_id = _identity(root, scratch)
    historical = _write_review(
        tmp_path / "rev-old.json",
        "0" * 64,
        occurrence_id,
        digest_override="0" * 64,
    )
    out = outroot / "pkg"
    rc = main(
        ["report", "--input", str(root), "--output", str(out), "--review", str(historical)]
    )
    # Explicit CLI reviews must bind the current evidence; anything else is
    # an illegal input, not a silently ignored opinion.  (The digest can
    # only be checked after derivation, so the derivation snapshot stays —
    # but nothing is sealed and no report is written.)
    assert rc == 2
    assert not (out / "evidence-manifest.json").exists()
    assert not (out / "report.json").exists()


# --------------------------------------------------------------------------
# export
# --------------------------------------------------------------------------


_EXPORT_FILES = {
    "README.md",
    "a.sql",
    "b.sql",
    "case.json",
    "environment-requirements.json",
    "expected.json",
    "origin.json",
    "delivery-manifest.json",
}


def _export(root: Path, out: Path, case_id: str, *extra: str) -> int:
    return main(
        [
            "export",
            "--input",
            str(root),
            "--case-id",
            case_id,
            "--select",
            "original",
            "--format",
            "sql",
            "--output",
            str(out),
            *extra,
        ]
    )


def test_export_sql_debug_success(outroot: Path, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    root = _run_root(tmp_path / "run", ["attempt-orig"])
    case_id = _attempt_case_id(root)
    out = outroot / "pkg"
    rc = _export(root, out, case_id)
    assert rc == 0
    assert {p.name for p in out.iterdir()} == _EXPORT_FILES
    readme = (out / "README.md").read_text("utf-8")
    assert "candidate/unverified" in readme
    assert "not accepted by mt-typecheck run --input" in readme
    text = capsys.readouterr().out
    assert "regression_eligible: false" in text


def test_export_regression_without_review_exit_3(outroot: Path, tmp_path: Path) -> None:
    root = _run_root(tmp_path / "run", ["attempt-orig"])
    case_id = _attempt_case_id(root)
    out = outroot / "pkg"
    rc = main(
        [
            "export",
            "--input",
            str(root),
            "--case-id",
            case_id,
            "--select",
            "original",
            "--format",
            "regression",
            "--output",
            str(out),
        ]
    )
    assert rc == 3  # REVIEW_REQUIRED keeps the finding reproducible
    assert not out.exists()


def test_export_regression_with_matching_accepted_review_exit_0(
    outroot: Path, tmp_path: Path
) -> None:
    root = _run_root(tmp_path / "run", ["attempt-orig"])
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    _, delivery_id, occurrence_id = _identity(root, scratch)
    review = _write_review(scratch / "rev-1.json", delivery_id, occurrence_id)
    case_id = _attempt_case_id(root)
    out = outroot / "pkg"
    rc = main(
        [
            "export",
            "--input",
            str(root),
            "--case-id",
            case_id,
            "--select",
            "original",
            "--format",
            "regression",
            "--review",
            str(review),
            "--output",
            str(out),
        ]
    )
    assert rc == 0
    assert (out / "regression-case.json").is_file()
    assert (out / "reviews" / "rev-1.json").is_file()


def test_export_regression_with_conflicting_reviews_exit_2(
    outroot: Path, tmp_path: Path
) -> None:
    root = _run_root(tmp_path / "run", ["attempt-orig"])
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    _, delivery_id, occurrence_id = _identity(root, scratch)
    review_one = _write_review(scratch / "rev-1.json", delivery_id, occurrence_id)
    review_two = _write_review(
        scratch / "rev-2.json",
        delivery_id,
        occurrence_id,
        decision=ReviewDecision.EXPECTED_BEHAVIOR,
        review_id="rev-2",
    )
    case_id = _attempt_case_id(root)
    out = outroot / "pkg"
    rc = main(
        [
            "export",
            "--input",
            str(root),
            "--case-id",
            case_id,
            "--select",
            "original",
            "--format",
            "regression",
            "--review",
            str(review_one),
            "--review",
            str(review_two),
            "--output",
            str(out),
        ]
    )
    assert rc == 2  # REVIEW_CONFLICT is illegal state, not a missing gate
    assert not out.exists()


def test_export_ambiguous_selection_exit_2_then_occurrence_disambiguates(
    outroot: Path, tmp_path: Path
) -> None:
    root = tmp_path / "run"
    ts._write_run_root(root, ["attempt-1", "attempt-2"], synthetic=False)
    case_id = _attempt_case_id(root, "attempt-1")
    out = outroot / "pkg"
    rc = _export(root, out, case_id)
    assert rc == 2  # AMBIGUOUS_SELECTION
    assert not out.exists()

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    source_id, _, _ = _identity(root, scratch, attempt_id="attempt-1")
    target = compute_occurrence_id(source_id, "attempt-1", case_id)
    out2 = outroot / "pkg2"
    rc = _export(root, out2, case_id, "--occurrence-id", target)
    assert rc == 0
    assert {p.name for p in out2.iterdir()} == _EXPORT_FILES


def test_export_best_selection_without_proof_exit_2(outroot: Path, tmp_path: Path) -> None:
    root = _generation_root(tmp_path / "gen")
    case_id = ts._generation_case_ids(root)[0]
    rc = main(
        [
            "export",
            "--input",
            str(root),
            "--case-id",
            case_id,
            "--select",
            "best",
            "--format",
            "sql",
            "--output",
            str(outroot / "pkg"),
        ]
    )
    assert rc == 2  # BEST_UNAVAILABLE: never a silent fallback
    assert not (outroot / "pkg").exists()


# --------------------------------------------------------------------------
# Exit-code table itself
# --------------------------------------------------------------------------


def test_compute_exit_code_first_match_precedence() -> None:
    four = cd.ExitReason(4, "candidate")
    three = cd.ExitReason(3, "partial")
    two = cd.ExitReason(2, "illegal")
    one = cd.ExitReason(1, "internal")
    hundred_thirty = cd.ExitReason(130, "cancelled")
    assert cd.compute_exit_code([]) == 0
    assert cd.compute_exit_code([four]) == 4
    assert cd.compute_exit_code([four, three]) == 3
    assert cd.compute_exit_code([four, three, two]) == 2
    assert cd.compute_exit_code([four, three, two, one]) == 1
    assert cd.compute_exit_code([four, three, two, one, hundred_thirty]) == 130
    assert cd.compute_exit_code([two, four]) == 2
    # Cancellation outranks everything, including internal failures.
    assert cd.compute_exit_code([one, hundred_thirty]) == 130


def test_export_refusal_table_is_the_single_classification() -> None:
    mapping = cd.EXPORT_REFUSAL_EXIT
    # Missing/unsatisfied gates keep the finding reproducible → 3.
    for code in (
        "REVIEW_REQUIRED",
        "RECOMPUTE_NOT_AVAILABLE",
        "STRUCTURAL_NOT_COMPLETE",
        "REVIEW_NOT_CONFIRMED",
        "SYNTHETIC_UNKNOWN",
        "RENDER_NOT_AVAILABLE",
    ):
        assert mapping[code] == 3, code
    # Illegal/conflicting states → 2.
    for code in (
        "REVIEW_INVALID",
        "REVIEW_CONFLICT",
        "REVIEW_HISTORICAL",
        "IDENTITY_BROKEN",
        "STRUCTURAL_CORRUPT",
        "SEMANTIC_CONFLICT",
        "PROVENANCE_CONFLICT",
        "EXECUTION_UNSAFE",
        "CASE_CORRUPT",
        "UNSAFE_SQL_PACKAGE",
        "RELATION_SPEC_OVERSIZE",
        "OUTPUT_NOT_WRITABLE",
        "UNSUPPORTED_NATIVE_KIND",
    ):
        assert mapping[code] == 2, code
    # A failed post-write self-validation is a tool fault → 1.
    assert mapping["SELF_VALIDATION_FAILED"] == 1
