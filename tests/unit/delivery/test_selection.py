"""Unit tests for delivery/selection.py (phase 4b case selection).

Fixtures reuse the reduction fakes and the generator exactly like
tests/unit/evidence/test_assessment.py, but every expected verdict here is
stated by hand: the tests assert stable refusal codes, snapshot-copy-only
reads and the identity checks of the pinned selection contract.  Nothing
derives an expectation from the code under test.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.case import (
    IndexVariant,
    ObservedEnvironment,
    Profile,
    REQUIRED_SQL_MODE_TOKENS,
    RuleSelector,
    TemplateId,
)
from mtsql_typecheck.contracts.codec import (
    canonical_json,
    decode_case_payload,
    decode_compatibility_check,
    sha256_hex,
)
from mtsql_typecheck.contracts.delivery import (
    AssessmentDimension,
    ExecutionSafetyStatus,
    Limits,
    NativeKind,
    ProvenanceStatus,
    SemanticStatus,
    StructuralStatus,
    compute_occurrence_id,
)
from mtsql_typecheck.contracts.execution import (
    dump_attempt_expectation,
    dump_attempt_request,
    dump_execution_evidence,
)
from mtsql_typecheck.contracts.oracle import ComparisonBudget, dump_comparison
from mtsql_typecheck.contracts.runner import (
    BuildIdSource as RunnerBuildIdSource,
)
from mtsql_typecheck.contracts.runner import (
    EnvironmentManifest,
    RunnerCommand,
    RunnerManifest,
    RunnerStatus,
)
from mtsql_typecheck.delivery.selection import (
    CaseSelector,
    SelectionError,
    select_case,
)
from mtsql_typecheck.evidence.assessment import (
    AttemptSemanticResult,
    DimensionResult,
    SelectionProof,
    SourceAssessment,
    assess_snapshot,
)
from mtsql_typecheck.evidence.native import (
    SourcePlan,
    detect_native_kind,
    enumerate_source,
)
from mtsql_typecheck.evidence.reader import SourceReader
from mtsql_typecheck.evidence.snapshot import Snapshotter
from mtsql_typecheck.generation.bundle import generate_and_write
from mtsql_typecheck.oracle.gates import compare_case

# The reduction fakes are uniquely named suite-wide (same import shape as
# tests/unit/evidence/test_assessment.py).
_REDUCTION_TEST_DIR = Path(__file__).resolve().parent.parent / "reduction"
if str(_REDUCTION_TEST_DIR) not in sys.path:
    sys.path.append(str(_REDUCTION_TEST_DIR))

import replay_fakes as rf  # noqa: E402

_LIMITS = Limits()


# --------------------------------------------------------------------------
# Fixture builders (mirroring tests/unit/evidence/test_assessment.py)
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


def _runner_manifest(attempt_ids: list[str], synthetic: bool) -> RunnerManifest:
    return RunnerManifest(
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
        synthetic=synthetic,
        evidence_profile="typecheck-full-evidence-v1",
        tool_version="0.1.0",
        contract_versions=(
            ("case", "1"),
            ("execution", "1"),
            ("oracle", "o1"),
            ("runner", "1"),
        ),
        refs=tuple(
            [
                ("environment", "environment.json"),
                ("runner_manifest", "runner-manifest.json"),
            ]
            + [
                ("attempt:" + aid, f"attempts/{aid}/comparison.json")
                for aid in attempt_ids
            ]
        ),
        sanitized_config_hash=hex64("config"),
        stop_reason=None,
    )


def _write_attempt_docs(root: Path, attempt_id: str, bundle: tuple) -> None:
    request, expectation, evidence = bundle
    prefix = f"attempts/{attempt_id}/"
    _write(root, prefix + "request.json", dump_attempt_request(request) + b"\n")
    _write(root, prefix + "expectation.json", dump_attempt_expectation(expectation) + b"\n")
    _write(
        root, prefix + "execution-evidence.json", dump_execution_evidence(evidence) + b"\n"
    )
    comparison = compare_case(request, expectation, evidence, ComparisonBudget())
    _write(root, prefix + "comparison.json", dump_comparison(comparison) + b"\n")
    _write(root, prefix + "observations.jsonl", b"")
    if evidence.terminal is not None:
        _write(
            root,
            prefix + "terminal.json",
            canonical_json(evidence.terminal.to_obj()) + b"\n",
        )


def _write_run_root(
    root: Path, attempt_ids: list[str], *, synthetic: bool = True
) -> None:
    """A run root with one consistent attempt per id (real oracle comparisons)."""
    for attempt_id in attempt_ids:
        bundle = rf.build_attempt(
            run_id="run-replay-1", attempt_id=attempt_id, synthetic=synthetic
        )
        _write_attempt_docs(root, attempt_id, bundle)
    _write_json(root, "environment.json", _environment_manifest().to_obj())
    _write_json(
        root,
        "runner-manifest.json",
        _runner_manifest(attempt_ids, synthetic).to_obj(),
    )


def _write_generation_bundle(root: Path) -> None:
    """A real two-case COMPLETE bundle written by the offline generator."""
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


def _generation_case_ids(root: Path) -> list[str]:
    return sorted(path.name for path in (root / "cases").iterdir())


def _snapshot_and_assess(root: Path, tmp_path: Path, name: str):
    limits = _LIMITS
    out = tmp_path / f"out-{name}"
    with SourceReader(root, limits=limits) as reader:
        kind = detect_native_kind(root)
        plan = enumerate_source(reader, kind, limits)
        snapshot = Snapshotter(reader, out, limits).capture(plan)
        assessment = assess_snapshot(
            snapshot, reader, plan, limits, None, snapshot_root=out
        )
    return assessment, plan, out


def _select(assessment, selector, plan, snapshot_root):
    return select_case(
        assessment,
        selector,
        plan=plan,
        reader=object(),  # deliberately unused; selection opens its own reader
        snapshot_root=snapshot_root,
        limits=_LIMITS,
    )


def _payload_case_id(payload_dict: dict) -> str:
    return case_id_of(decode_case_payload(payload_dict, what="test payload"))


from mtsql_typecheck.contracts.codec import case_id_of  # noqa: E402


# --------------------------------------------------------------------------
# Original selection over run sources
# --------------------------------------------------------------------------


def test_original_selection_run_source_happy_path(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_run_root(root, ["attempt-orig"], synthetic=False)
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "orig")
    row = assessment.attempts[0]
    assert row.attempt_id == "attempt-orig" and row.case_id is not None
    assert row.recompute is SemanticStatus.RECOMPUTED
    assert row.static_check_status == "PASS"
    case_id = row.case_id

    selected = _select(
        assessment, CaseSelector(case_id=case_id, select="original"), plan, out
    )

    assert selected.source_id == assessment.source_id
    assert selected.case_id == case_id
    assert selected.basis == "original"
    assert selected.payload_ref == "attempts/attempt-orig/request.json"
    assert selected.occurrence is row
    assert selected.occurrence_id == compute_occurrence_id(
        assessment.source_id, "attempt-orig", case_id
    )
    assert selected.recompute_eligible is True
    assert _payload_case_id(selected.case_payload) == case_id
    assert selected.static_check is None


def test_unknown_case_for_missing_case_id(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_run_root(root, ["attempt-orig"])
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "unknown")
    with pytest.raises(SelectionError) as caught:
        _select(
            assessment,
            CaseSelector(case_id=hex64("missing"), select="original"),
            plan,
            out,
        )
    assert caught.value.code == "UNKNOWN_CASE"


def test_ambiguous_selection_and_occurrence_disambiguation(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_run_root(root, ["attempt-1", "attempt-2"])
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "ambiguous")
    case_id = assessment.attempts[0].case_id
    assert assessment.attempts[1].case_id == case_id

    with pytest.raises(SelectionError) as caught:
        _select(
            assessment, CaseSelector(case_id=case_id, select="original"), plan, out
        )
    assert caught.value.code == "AMBIGUOUS_SELECTION"
    message = str(caught.value)
    for row in assessment.attempts:
        assert (
            compute_occurrence_id(assessment.source_id, row.attempt_id, case_id)
            in message
        )

    target = compute_occurrence_id(assessment.source_id, "attempt-1", case_id)
    selected = _select(
        assessment,
        CaseSelector(case_id=case_id, select="original", occurrence_id=target),
        plan,
        out,
    )
    assert selected.occurrence is not None
    assert selected.occurrence.attempt_id == "attempt-1"
    assert selected.occurrence_id == target


def test_occurrence_id_mismatch_is_unknown_case(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_run_root(root, ["attempt-orig"])
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "mismatch")
    case_id = assessment.attempts[0].case_id
    with pytest.raises(SelectionError) as caught:
        _select(
            assessment,
            CaseSelector(
                case_id=case_id,
                select="original",
                occurrence_id=hex64("other-occurrence"),
            ),
            plan,
            out,
        )
    assert caught.value.code == "UNKNOWN_CASE"


# --------------------------------------------------------------------------
# Best selection
# --------------------------------------------------------------------------


def _assessed_with_proof(
    assessment: SourceAssessment, proof: SelectionProof
) -> SourceAssessment:
    return SourceAssessment(
        source_id=assessment.source_id,
        native_kind=assessment.native_kind,
        structural=assessment.structural,
        semantic=assessment.semantic,
        provenance=assessment.provenance,
        execution_safety=assessment.execution_safety,
        attempts=assessment.attempts,
        selection=proof,
        reason_codes=assessment.reason_codes,
    )


def test_best_selection_verified_chain_selects_best_case(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_generation_bundle(root)
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "best")
    original_id, best_id = _generation_case_ids(root)
    assert original_id != best_id
    proof = SelectionProof(
        best_payload_ref=f"cases/{best_id}/case.json",
        best_case_id=best_id,
        chain_verified=True,
        chain_status="VERIFIED",
        constraints=(),
    )
    selected = _select(
        _assessed_with_proof(assessment, proof),
        CaseSelector(case_id=best_id, select="best"),
        plan,
        out,
    )
    assert selected.source_id == assessment.source_id
    assert selected.case_id == best_id
    assert selected.payload_ref == f"cases/{best_id}/case.json"
    assert selected.basis == "best"
    assert _payload_case_id(selected.case_payload) == best_id


@pytest.mark.parametrize(
    "chain_status", ["UNVERIFIED", "CONFLICT", "MISSING", "LEGACY"]
)
def test_best_selection_unverified_chain_is_unavailable(
    tmp_path: Path, chain_status: str
) -> None:
    root = tmp_path / "src"
    _write_generation_bundle(root)
    assessment, plan, out = _snapshot_and_assess(
        root, tmp_path, f"chain-{chain_status}"
    )
    best_id = _generation_case_ids(root)[1]
    proof = SelectionProof(
        best_payload_ref=f"cases/{best_id}/case.json",
        best_case_id=best_id,
        chain_verified=False,
        chain_status=chain_status,
        constraints=(),
    )
    with pytest.raises(SelectionError) as caught:
        _select(
            _assessed_with_proof(assessment, proof),
            CaseSelector(case_id=best_id, select="best"),
            plan,
            out,
        )
    assert caught.value.code == "BEST_UNAVAILABLE"
    assert chain_status in str(caught.value)


def test_best_selection_without_proof_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_generation_bundle(root)
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "noproof")
    with pytest.raises(SelectionError) as caught:
        _select(
            assessment,
            CaseSelector(case_id=hex64("anything"), select="best"),
            plan,
            out,
        )
    assert caught.value.code == "SELECTION_PROOF_MISSING"


# --------------------------------------------------------------------------
# Corrupt / identity-broken snapshot copies
# --------------------------------------------------------------------------


def _snapshot_request_doc(out: Path, source_id: str) -> Path:
    return out / "raw" / source_id / "attempts" / "attempt-orig" / "request.json"


def test_corrupt_case_document_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_run_root(root, ["attempt-orig"])
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "corrupt")
    _snapshot_request_doc(out, assessment.source_id).write_bytes(b"this is not json")
    case_id = assessment.attempts[0].case_id
    with pytest.raises(SelectionError) as caught:
        _select(
            assessment, CaseSelector(case_id=case_id, select="original"), plan, out
        )
    assert caught.value.code == "CORRUPT_CASE"


def test_identity_broken_attempt_doc_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_run_root(root, ["attempt-orig"])
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "identity")
    doc_path = _snapshot_request_doc(out, assessment.source_id)
    doc = json.loads(doc_path.read_bytes().decode("utf-8"))
    doc["attempt_id"] = "attempt-forged"
    doc_path.write_bytes(canonical_json(doc) + b"\n")
    case_id = assessment.attempts[0].case_id
    with pytest.raises(SelectionError) as caught:
        _select(
            assessment, CaseSelector(case_id=case_id, select="original"), plan, out
        )
    assert caught.value.code == "IDENTITY_BROKEN"


# --------------------------------------------------------------------------
# Snapshot-copy-only reads
# --------------------------------------------------------------------------


def test_selection_never_reads_outside_the_snapshot_copy(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_run_root(root, ["attempt-orig"])
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "copyonly")
    case_id = assessment.attempts[0].case_id

    first = _select(
        assessment, CaseSelector(case_id=case_id, select="original"), plan, out
    )

    # Destroy the ORIGINAL tree after the snapshot; selection must not care.
    (root / "attempts" / "attempt-orig" / "request.json").write_bytes(
        b"destroyed after snapshot\n"
    )

    second = _select(
        assessment, CaseSelector(case_id=case_id, select="original"), plan, out
    )
    assert second.case_id == first.case_id == case_id
    assert second.case_payload == first.case_payload
    assert _payload_case_id(second.case_payload) == case_id


# --------------------------------------------------------------------------
# Generation sources
# --------------------------------------------------------------------------


def test_generation_original_selection_has_no_occurrence(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_generation_bundle(root)
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "generation")
    assert assessment.attempts == ()
    case_id = _generation_case_ids(root)[0]

    selected = _select(
        assessment, CaseSelector(case_id=case_id, select="original"), plan, out
    )
    assert selected.occurrence is None
    assert selected.occurrence_id is None
    assert selected.recompute_eligible is False
    assert selected.payload_ref == f"cases/{case_id}/case.json"
    assert selected.static_check is not None
    check = decode_compatibility_check(selected.static_check, what="fixture")
    assert check.stage.value == "static"
    assert check.status.value == "VALID_STATIC"


# --------------------------------------------------------------------------
# Selector validation and unsupported kinds
# --------------------------------------------------------------------------


def test_invalid_select_mode_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_run_root(root, ["attempt-orig"])
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "badmode")
    with pytest.raises(SelectionError) as caught:
        _select(
            assessment,
            CaseSelector(case_id=hex64("x"), select="cheapest"),
            plan,
            out,
        )
    assert caught.value.code == "INVALID_SELECTOR"


def test_malformed_case_id_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "src"
    _write_run_root(root, ["attempt-orig"])
    assessment, plan, out = _snapshot_and_assess(root, tmp_path, "badid")
    with pytest.raises(SelectionError) as caught:
        _select(
            assessment,
            CaseSelector(case_id="NOT-A-CASE", select="original"),
            plan,
            out,
        )
    assert caught.value.code == "INVALID_SELECTOR"


def _dimension(name: AssessmentDimension, status) -> DimensionResult:
    return DimensionResult(
        dimension=name, applicable=False, status=status, reason_codes=()
    )


def test_unsupported_native_kind_is_refused(tmp_path: Path) -> None:
    assessment = SourceAssessment(
        source_id="s-" + hex64("delivery-source"),
        native_kind=NativeKind.DELIVERY,
        structural=_dimension(
            AssessmentDimension.STRUCTURAL, StructuralStatus.UNSUPPORTED
        ),
        semantic=_dimension(
            AssessmentDimension.SEMANTIC, SemanticStatus.NOT_RECOMPUTED
        ),
        provenance=_dimension(
            AssessmentDimension.PROVENANCE, ProvenanceStatus.UNVERIFIED
        ),
        execution_safety=_dimension(
            AssessmentDimension.EXECUTION_SAFETY, ExecutionSafetyStatus.NOT_APPLICABLE
        ),
        attempts=(),
        selection=None,
        reason_codes=(),
    )
    plan = SourcePlan(
        kind=NativeKind.DELIVERY,
        root_document="delivery-manifest.json",
        files=(),
        orphan_files=(),
    )
    with pytest.raises(SelectionError) as caught:
        _select(
            assessment,
            CaseSelector(case_id=hex64("x"), select="original"),
            plan,
            tmp_path,
        )
    assert caught.value.code == "UNSUPPORTED_NATIVE_KIND"


# --------------------------------------------------------------------------
# AttemptSemanticResult / occurrence id helpers used above stay importable
# --------------------------------------------------------------------------


def test_attempt_row_helpers_are_importable_for_extension_tests() -> None:
    # Guard the fixture imports the extension tests rely on.
    assert AttemptSemanticResult is not None
    assert SelectionProof is not None
