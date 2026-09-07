"""Unit tests for delivery/export.py (phase 4b regression/SQL delivery).

Every expected verdict is hand-stated: gate refusals, package layout, the
separation between expected.json (model truth) and the historical
observation, manifest identity, and self-validation behavior.  The source
fixtures reuse the reduction fakes exactly like tests/unit/evidence, with
``synthetic=False`` for REAL material; no expectation is derived from the
code under test.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.codec import (
    canonical_json,
    decode_case_payload,
    parse_strict_json,
    sha256_hex,
)
from mtsql_typecheck.contracts.delivery import (
    CollectionStatus,
    ExportFormat,
    FindingReview,
    ProducerInfo,
    ReviewDecision,
    SemanticStatus,
    SourceDescriptor,
    StructuralStatus,
    SyntheticKind,
    compute_delivery_id,
    decode_export_manifest,
    decode_regression_case,
    decode_relation_assertion,
)
from mtsql_typecheck.delivery.export import (
    ExportRefused,
    export_case,
    validate_export_dir,
)
from mtsql_typecheck.delivery.selection import CaseSelector
from mtsql_typecheck.delivery.sql import OPTIMIZER_BASELINE_UNKNOWN
from mtsql_typecheck.reporting.review import apply_reviews

import test_selection as ts

_LIMITS = ts._LIMITS

_EXPORT_FILES = (
    "README.md",
    "a.sql",
    "b.sql",
    "case.json",
    "environment-requirements.json",
    "expected.json",
    "origin.json",
)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def _descriptor(assessment, synthetic: SyntheticKind) -> SourceDescriptor:
    return SourceDescriptor(
        source_id=assessment.source_id,
        native_kind=assessment.native_kind,
        root_document="runner-manifest.json",
        snapshot_digest=assessment.source_id[2:],
        synthetic=synthetic,
        collection_status=CollectionStatus.COLLECTED,
    )


def _delivery_id(assessment, synthetic: SyntheticKind = SyntheticKind.REAL) -> str:
    return compute_delivery_id((_descriptor(assessment, synthetic),))


def _real_source(tmp_path: Path, name: str):
    root = tmp_path / f"src-{name}"
    ts._write_run_root(root, ["attempt-orig"], synthetic=False)
    assessment, plan, out = ts._snapshot_and_assess(root, tmp_path, name)
    row = assessment.attempts[0]
    selected = ts._select(
        assessment,
        CaseSelector(case_id=row.case_id, select="original"),
        plan,
        out,
    )
    return assessment, plan, selected, row


def _review(delivery_id, occurrence_ids, decision=ReviewDecision.CONFIRMED_DB_BUG,
            review_id="rev-1"):
    return FindingReview(
        review_id=review_id,
        reviewer="alice",
        reviewed_at="2026-09-07T00:00:00Z",
        evidence_digest=delivery_id,
        occurrence_ids=tuple(sorted(occurrence_ids)),
        decision=decision,
        reason="reproduced on a disposable instance and confirmed by inspection",
    )


def _accepted_reviewset(review, delivery_id, occurrence_ids):
    return apply_reviews(
        [review],
        evidence_digest=delivery_id,
        occurrence_ids=set(occurrence_ids),
        mode="explicit",
    )


def _export(selected, tmp_path, name, *, assessment, plan, delivery_id,
            export_format, review=None, reviewset=None,
            review_validation_error=None):
    return export_case(
        selected,
        output_root=tmp_path / f"pkg-{name}",
        limits=_LIMITS,
        export_format=export_format,
        review=review,
        reviewset=reviewset,
        assessment=assessment,
        delivery_id=delivery_id,
        producer=ProducerInfo(name="mtsql-typecheck", version="0.1.0"),
        plan=plan,
        review_validation_error=review_validation_error,
    )


# --------------------------------------------------------------------------
# SQL debug export (no review)
# --------------------------------------------------------------------------


def test_sql_debug_export_without_review(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "sql")
    outcome = _export(
        selected,
        tmp_path,
        "sql",
        assessment=assessment,
        plan=plan,
        delivery_id=_delivery_id(assessment),
        export_format=ExportFormat.SQL,
    )
    pkg = outcome.output_root
    assert outcome.refusal is None
    assert outcome.regression_eligible is False
    assert outcome.format is ExportFormat.SQL
    for name in _EXPORT_FILES + ("delivery-manifest.json",):
        assert (pkg / name).is_file(), name

    readme = (pkg / "README.md").read_text("utf-8")
    assert "candidate/unverified" in readme
    assert "manual execution material; not accepted by mt-typecheck run --input" in readme
    assert "mysql-test-run" in readme
    assert "REFERENCE ONLY" in readme
    assert "optimizer_baseline" in readme
    assert outcome.manifest.export_id in readme
    assert _delivery_id(assessment) in readme

    for sql_name in ("a.sql", "b.sql"):
        data = (pkg / sql_name).read_bytes()
        text = data.decode("utf-8")
        assert "SET sql_mode" in text
        assert "CREATE DATABASE `" in text
        assert "IF NOT EXISTS" not in text
        assert "DROP" not in text
        assert "--force" not in text

    manifest = decode_export_manifest(
        parse_strict_json((pkg / "delivery-manifest.json").read_bytes()),
        what="delivery-manifest.json",
    )
    assert manifest.format is ExportFormat.SQL
    assert manifest.completion.value == "COMPLETE"
    assert manifest.review_ref is None
    assert manifest.selected_occurrence_id == selected.occurrence_id
    assert {entry.path for entry in manifest.files} == set(_EXPORT_FILES)
    assert "optimizer_baseline_unknown" in manifest.limitations

    env_doc = parse_strict_json(
        (pkg / "environment-requirements.json").read_bytes()
    )
    assert env_doc["optimizer_baseline"] == OPTIMIZER_BASELINE_UNKNOWN

    # Self-validation on the sealed package succeeds, re-run by hand.
    assert validate_export_dir(pkg, _LIMITS) == ()


# --------------------------------------------------------------------------
# Regression gates
# --------------------------------------------------------------------------


def test_regression_without_review_is_refused_before_any_write(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "noreview")
    with pytest.raises(ExportRefused) as caught:
        _export(
            selected,
            tmp_path,
            "noreview",
            assessment=assessment,
            plan=plan,
            delivery_id=_delivery_id(assessment),
            export_format=ExportFormat.REGRESSION,
        )
    assert caught.value.code == "REVIEW_REQUIRED"
    assert not (tmp_path / "pkg-noreview").exists()


def test_regression_review_not_confirmed_is_refused(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "notconfirmed")
    delivery_id = _delivery_id(assessment)
    review = _review(
        delivery_id, [selected.occurrence_id], decision=ReviewDecision.EXPECTED_BEHAVIOR
    )
    reviewset = _accepted_reviewset(review, delivery_id, [selected.occurrence_id])
    with pytest.raises(ExportRefused) as caught:
        _export(
            selected,
            tmp_path,
            "notconfirmed",
            assessment=assessment,
            plan=plan,
            delivery_id=delivery_id,
            export_format=ExportFormat.REGRESSION,
            review=review,
            reviewset=reviewset,
        )
    assert caught.value.code == "REVIEW_NOT_CONFIRMED"
    assert not (tmp_path / "pkg-notconfirmed").exists()


def test_regression_historical_review_is_refused(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "historical")
    review = _review(sha256_hex(b"older-evidence"), [selected.occurrence_id])
    reviewset = apply_reviews(
        [review],
        evidence_digest=_delivery_id(assessment),
        occurrence_ids={selected.occurrence_id},
        mode="embedded",
    )
    assert reviewset.accepted == ()
    with pytest.raises(ExportRefused) as caught:
        _export(
            selected,
            tmp_path,
            "historical",
            assessment=assessment,
            plan=plan,
            delivery_id=_delivery_id(assessment),
            export_format=ExportFormat.REGRESSION,
            review=review,
            reviewset=reviewset,
        )
    assert caught.value.code == "REVIEW_HISTORICAL"


def test_regression_conflicting_reviews_are_refused(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "conflict")
    delivery_id = _delivery_id(assessment)
    occ = selected.occurrence_id
    review_one = _review(delivery_id, [occ], ReviewDecision.CONFIRMED_DB_BUG, "rev-1")
    review_two = _review(delivery_id, [occ], ReviewDecision.EXPECTED_BEHAVIOR, "rev-2")
    reviewset = apply_reviews(
        [review_one, review_two],
        evidence_digest=delivery_id,
        occurrence_ids={occ},
        mode="explicit",
    )
    assert reviewset.has_conflict
    with pytest.raises(ExportRefused) as caught:
        _export(
            selected,
            tmp_path,
            "conflict",
            assessment=assessment,
            plan=plan,
            delivery_id=delivery_id,
            export_format=ExportFormat.REGRESSION,
            review=review_one,
            reviewset=reviewset,
        )
    assert caught.value.code == "REVIEW_CONFLICT"


def test_regression_rejected_review_input_is_refused(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "invalid")
    with pytest.raises(ExportRefused) as caught:
        _export(
            selected,
            tmp_path,
            "invalid",
            assessment=assessment,
            plan=plan,
            delivery_id=_delivery_id(assessment),
            export_format=ExportFormat.REGRESSION,
            review=None,
            reviewset=None,
            review_validation_error=ValueError("evidence_digest_mismatch"),
        )
    assert caught.value.code == "REVIEW_INVALID"


def test_regression_not_recomputed_occurrence_is_refused(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "notrecomputed")
    from mtsql_typecheck.contracts.delivery import SemanticStatus

    broken_row = dataclasses.replace(
        row, recompute=SemanticStatus.NOT_RECOMPUTED, recomputed_comparison_hash=None
    )
    broken_assessment = dataclasses.replace(
        assessment, attempts=(broken_row,)
    )
    broken_selected = ts._select(
        broken_assessment,
        CaseSelector(case_id=selected.case_id, select="original"),
        plan,
        tmp_path / "out-notrecomputed",
    )
    assert broken_selected.recompute_eligible is False
    with pytest.raises(ExportRefused) as caught:
        _export(
            broken_selected,
            tmp_path,
            "notrecomputed",
            assessment=broken_assessment,
            plan=plan,
            delivery_id=_delivery_id(assessment),
            export_format=ExportFormat.REGRESSION,
        )
    assert caught.value.code == "RECOMPUTE_NOT_AVAILABLE"
    assert not (tmp_path / "pkg-notrecomputed").exists()


def test_regression_partial_structure_is_refused(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "partial")
    partial_assessment = dataclasses.replace(
        assessment,
        structural=dataclasses.replace(
            assessment.structural, status=StructuralStatus.PARTIAL
        ),
    )
    partial_selected = ts._select(
        partial_assessment,
        CaseSelector(case_id=selected.case_id, select="original"),
        plan,
        tmp_path / "out-partial",
    )
    with pytest.raises(ExportRefused) as caught:
        _export(
            partial_selected,
            tmp_path,
            "partial",
            assessment=partial_assessment,
            plan=plan,
            delivery_id=_delivery_id(assessment),
            export_format=ExportFormat.REGRESSION,
        )
    assert caught.value.code == "STRUCTURAL_NOT_COMPLETE"
    assert not (tmp_path / "pkg-partial").exists()


# --------------------------------------------------------------------------
# Regression happy paths
# --------------------------------------------------------------------------


def test_regression_happy_path_real_source(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "happy")
    delivery_id = _delivery_id(assessment)
    review = _review(delivery_id, [selected.occurrence_id])
    reviewset = _accepted_reviewset(review, delivery_id, [selected.occurrence_id])
    outcome = _export(
        selected,
        tmp_path,
        "happy",
        assessment=assessment,
        plan=plan,
        delivery_id=delivery_id,
        export_format=ExportFormat.REGRESSION,
        review=review,
        reviewset=reviewset,
    )
    pkg = outcome.output_root
    assert outcome.refusal is None
    assert outcome.regression_eligible is True

    regression = decode_regression_case(
        parse_strict_json((pkg / "regression-case.json").read_bytes()),
        what="regression-case.json",
    )
    assert regression.case_document_hash == sha256_hex(
        (pkg / "case.json").read_bytes()
    )
    assert regression.review_ref == "rev-1"
    assert regression.synthetic is SyntheticKind.REAL
    assert regression.source_inventory_hash == assessment.source_id[2:]
    assert regression.renderer_id == "r1" and regression.renderer_version == "1"
    assert regression.codec_id == "mysql-text-1"

    review_copy = (pkg / "reviews" / "rev-1.json").read_bytes()
    assert review_copy == canonical_json(review.to_obj()) + b"\n"

    manifest = outcome.manifest
    assert manifest.review_ref == "rev-1"
    assert manifest.selected_occurrence_id == selected.occurrence_id
    assert manifest.source_delivery_id == delivery_id
    assert outcome.files == manifest.files

    assert validate_export_dir(pkg, _LIMITS) == ()


def test_regression_synthetic_source_exports_with_limitation(tmp_path: Path) -> None:
    root = tmp_path / "src-synthetic"
    ts._write_run_root(root, ["attempt-orig"], synthetic=True)
    assessment, plan, out = ts._snapshot_and_assess(root, tmp_path, "synthetic")
    row = assessment.attempts[0]
    selected = ts._select(
        assessment,
        CaseSelector(case_id=row.case_id, select="original"),
        plan,
        out,
    )
    delivery_id = _delivery_id(assessment, SyntheticKind.SYNTHETIC)
    review = _review(delivery_id, [selected.occurrence_id])
    reviewset = _accepted_reviewset(review, delivery_id, [selected.occurrence_id])
    outcome = _export(
        selected,
        tmp_path,
        "synthetic",
        assessment=assessment,
        plan=plan,
        delivery_id=delivery_id,
        export_format=ExportFormat.REGRESSION,
        review=review,
        reviewset=reviewset,
    )
    assert outcome.refusal is None
    assert "tool_selftest_only" in outcome.manifest.limitations
    regression = decode_regression_case(
        parse_strict_json(
            (outcome.output_root / "regression-case.json").read_bytes()
        ),
        what="regression-case.json",
    )
    assert regression.synthetic is SyntheticKind.SYNTHETIC


# --------------------------------------------------------------------------
# Identity, expected-truth separation, sealing
# --------------------------------------------------------------------------


def test_identity_mismatch_is_refused_before_any_write(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "identity")
    with pytest.raises(ExportRefused) as caught:
        _export(
            selected,
            tmp_path,
            "identity",
            assessment=assessment,
            plan=plan,
            delivery_id="not-a-digest",
            export_format=ExportFormat.SQL,
        )
    assert caught.value.code == "IDENTITY_BROKEN"
    assert not (tmp_path / "pkg-identity").exists()

    other = dataclasses.replace(selected, source_id="s-" + ts.hex64("other"))
    with pytest.raises(ExportRefused) as caught:
        _export(
            other,
            tmp_path,
            "identity",
            assessment=assessment,
            plan=plan,
            delivery_id=_delivery_id(assessment),
            export_format=ExportFormat.SQL,
        )
    assert caught.value.code == "IDENTITY_BROKEN"
    assert not (tmp_path / "pkg-identity").exists()


def test_expected_json_holds_model_truth_only(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "expected")
    outcome = _export(
        selected,
        tmp_path,
        "expected",
        assessment=assessment,
        plan=plan,
        delivery_id=_delivery_id(assessment),
        export_format=ExportFormat.SQL,
    )
    pkg = outcome.output_root
    expected_bytes = (pkg / "expected.json").read_bytes()
    # The buggy side-B readback value (-127) is observation, never expectation.
    assert b"-127" not in expected_bytes
    assertion = decode_relation_assertion(
        parse_strict_json(expected_bytes), what="expected.json"
    )
    payload = decode_case_payload(selected.case_payload, what="selected payload")
    assert assertion.spec == canonical_json(payload.relation.to_obj()).decode("ascii")
    assert assertion.columns == tuple(
        sorted(column.alias for column in payload.relation.columns)
    )
    assert assertion.mode.value == "typed_multiset_exact"

    origin = parse_strict_json((pkg / "origin.json").read_bytes())
    historical = origin["historical_observation"]
    assert "never the expected truth" in historical["note"]
    assert historical["original_comparison_hash"] == row.original_comparison_hash
    assert historical["occurrence_id"] == selected.occurrence_id
    assert historical["payload_ref"] == selected.payload_ref
    assert historical["snapshot_evidence_location"] == (
        f"raw/{assessment.source_id}/{selected.payload_ref}"
    )


def test_manifest_identity_and_tamper_detection(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "seal")
    outcome = _export(
        selected,
        tmp_path,
        "seal",
        assessment=assessment,
        plan=plan,
        delivery_id=_delivery_id(assessment),
        export_format=ExportFormat.SQL,
    )
    pkg = outcome.output_root
    # The pinned identity: compute_delivery_id over the single-source
    # descriptor; only source_id and snapshot_digest enter the hash.
    assert outcome.export_id == compute_delivery_id(
        (_descriptor(assessment, selected.occurrence.synthetic),)
    )
    for entry in outcome.manifest.files:
        data = (pkg / entry.path).read_bytes()
        assert entry.size_bytes == len(data)
        assert entry.sha256 == sha256_hex(data)

    # Tamper with a sealed file: the validator must notice.
    (pkg / "expected.json").write_bytes(
        (pkg / "expected.json").read_bytes() + b" "
    )
    problems = validate_export_dir(pkg, _LIMITS)
    assert any(problem.code == "hash_mismatch" for problem in problems)

    # A stray file breaks the closure in the other direction.
    (pkg / "stray.txt").write_bytes(b"unlisted\n")
    problems = validate_export_dir(pkg, _LIMITS)
    assert any(problem.code == "extra_file" for problem in problems)


def test_existing_or_symlink_output_root_is_refused(tmp_path: Path) -> None:
    assessment, plan, selected, row = _real_source(tmp_path, "output")
    existing = tmp_path / "pkg-existing"
    existing.mkdir()
    (existing / "marker.txt").write_bytes(b"keep me\n")
    with pytest.raises(ExportRefused) as caught:
        _export(
            selected,
            tmp_path,
            "existing",
            assessment=assessment,
            plan=plan,
            delivery_id=_delivery_id(assessment),
            export_format=ExportFormat.SQL,
        )
    assert caught.value.code == "OUTPUT_NOT_WRITABLE"
    assert (existing / "marker.txt").read_bytes() == b"keep me\n"
    # The refusing call must not have written into the existing directory.
    assert {path.name for path in existing.iterdir()} == {"marker.txt"}

    real_dir = tmp_path / "real-target"
    real_dir.mkdir()
    link = tmp_path / "pkg-link"
    link.symlink_to(real_dir)
    with pytest.raises(ExportRefused) as caught:
        _export(
            selected,
            tmp_path,
            "link",
            assessment=assessment,
            plan=plan,
            delivery_id=_delivery_id(assessment),
            export_format=ExportFormat.SQL,
        )
    assert caught.value.code == "OUTPUT_NOT_WRITABLE"
