"""Regression/SQL delivery export (design 6.2.3, 6.4.6, 6.5; phase 4b).

Pure offline writer: consumes a
:class:`~mtsql_typecheck.delivery.selection.SelectedCase` plus its assessment
and plan, applies the design 6.4.6 export gates, then seals one new package
directory with canonical JSON files, two runnable SQL scripts, a hand-written
README and a ``delivery-manifest.json`` written last.  No database, network
or clock access; the only clock-free default is the injectable ``fsync`` hook.

Stable refusal codes (:class:`ExportRefused`, subclass of ``ValueError``):

Pinned by the design/CLI contract:

- ``REVIEW_REQUIRED``         regression export without a review.
- ``REVIEW_NOT_CONFIRMED``    review decision is not ``CONFIRMED_DB_BUG``.
- ``REVIEW_CONFLICT``         reviewset records a decision conflict.
- ``REVIEW_HISTORICAL``       review is not accepted for the current
                              evidence digest / occurrence set.
- ``IDENTITY_BROKEN``         caller-supplied identity disagrees (source id
                              mismatch, malformed delivery id).
- ``STRUCTURAL_NOT_COMPLETE`` regression export from a non-COMPLETE source.
- ``RECOMPUTE_NOT_AVAILABLE`` regression export without a RECOMPUTED
                              attempt-backed occurrence.
- ``UNSUPPORTED_NATIVE_KIND`` source kind is not snapshot-able evidence.

Documented additions (same stability guarantee):

- ``REVIEW_INVALID``          caller passed a ``review_validation_error``:
                              the review input itself was rejected upstream.
- ``SYNTHETIC_UNKNOWN``       regression export from a source whose synthetic
                              kind is UNKNOWN (cannot claim real or self-test
                              provenance).
- ``STRUCTURAL_CORRUPT`` / ``SEMANTIC_CONFLICT`` / ``PROVENANCE_CONFLICT`` /
  ``EXECUTION_UNSAFE``        the source carries a proven broken dimension;
                              the executable export is refused entirely.
- ``CASE_CORRUPT``            the selected payload fails the case contract.
- ``RENDER_NOT_AVAILABLE``    the pinned renderer refuses the payload.
- ``UNSAFE_SQL_PACKAGE``      SQL composition fails or the re-grep finds
                              DROP / IF NOT EXISTS / --force in the bytes.
- ``RELATION_SPEC_OVERSIZE``  the typed relation spec exceeds the pinned
                              character bound for expected.json.
- ``OUTPUT_NOT_WRITABLE``     output directory exists or an unsafe path
                              component (mirrors generation/bundle.py).
- ``SELF_VALIDATION_FAILED``  post-write self-validation found a problem.

Documented decisions (this project's interpretation of design 6.4.6):

- All refusals happen BEFORE any filesystem write; on refusal the output
  directory is never created.  ``ExportOutcome.refusal`` therefore stays
  ``None`` on every returned outcome; the field exists so future streaming
  callers can record partial states without re-pinning the dataclass.
- ``SYNTHETIC`` regression exports are allowed but carry the
  ``tool_selftest_only`` limitation: the contracts ``SyntheticKind`` enum has
  no TOOL_SELFTEST member, so the conservative rule is "same accepted human
  review as REAL material, synthetic recorded in the package".
- The historical observation (original comparison hash / occurrence id /
  evidence location) is embedded in ``origin.json`` as a clearly separated,
  non-truth reference block; ``evidence.manifest.classify_role`` has no role
  for a separate top-level file.
- The review copy is written to ``reviews/<review_id>.json`` (design 6.2.3
  layout; the frozen role table classifies the ``reviews/`` prefix).
- The delivery manifest is written with the same atomic semantics as
  ``evidence.manifest.write_evidence_manifest`` (temp ``.part`` + os.replace
  + fsync) because that helper hard-codes ``evidence-manifest.json``.
- ``export_id`` = ``compute_delivery_id`` over a single-source descriptor
  built from the pinned inputs.  Only ``source_id`` and ``snapshot_digest``
  enter that hash; ``collection_status`` is recorded as the conservative
  ``PARTIALLY_READ`` placeholder because the export inputs do not carry the
  collection outcome, and the remaining descriptor fields are best-effort
  from the plan/occurrence.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from mtsql_typecheck.contracts.case import CasePayload, NameMap
from mtsql_typecheck.contracts.codec import (
    canonical_json,
    case_id_of,
    decode_case_payload,
    parse_strict_json,
    sha256_hex,
)
from mtsql_typecheck.contracts.delivery import (
    CollectionStatus,
    DeliveryCompletion,
    EvidenceFile,
    ExecutionSafetyStatus,
    ExportFormat,
    ExportManifest,
    FindingReview,
    Limits,
    NativeKind,
    ProducerInfo,
    ProvenanceStatus,
    RelationAssertion,
    RelationAssertionMode,
    RegressionCase,
    ReviewDecision,
    SemanticStatus,
    SourceDescriptor,
    StructuralStatus,
    SyntheticKind,
    EXPORT_MANIFEST_FILENAME,
    MAX_RELATION_SPEC_CHARS,
    check_package_path,
    compute_delivery_id,
    decode_export_manifest,
    decode_regression_case,
    decode_relation_assertion,
)
from mtsql_typecheck.delivery.selection import SelectedCase
from mtsql_typecheck.delivery.sql import (
    CANDIDATE_UNVERIFIED_MARKER,
    DeliverySqlError,
    EXPORTER_NOTE,
    ExportNameMap,
    NOT_RUN_INPUT_NOTE,
    SessionPreconditions,
    assign_name_map,
    environment_requirements_document,
    wrap_sql_package,
)
from mtsql_typecheck.evidence.assessment import SourceAssessment
from mtsql_typecheck.evidence.manifest import (
    _walk_package_files,
    collect_delivery_files,
)
from mtsql_typecheck.evidence.native import SourcePlan
from mtsql_typecheck.generation.bundle import (
    OutputDirExistsError,
    UnsafePathError,
    _ensure_new_output_dir,
)
from mtsql_typecheck.generation.render import RenderError, render_pair
from mtsql_typecheck.reporting.review import ReviewSet

__all__ = [
    "ExportRefused",
    "ExportProblem",
    "ExportOutcome",
    "export_case",
    "validate_export_dir",
]

# Stable refusal codes.
REVIEW_REQUIRED = "REVIEW_REQUIRED"
REVIEW_NOT_CONFIRMED = "REVIEW_NOT_CONFIRMED"
REVIEW_CONFLICT = "REVIEW_CONFLICT"
REVIEW_HISTORICAL = "REVIEW_HISTORICAL"
REVIEW_INVALID = "REVIEW_INVALID"
IDENTITY_BROKEN = "IDENTITY_BROKEN"
STRUCTURAL_NOT_COMPLETE = "STRUCTURAL_NOT_COMPLETE"
STRUCTURAL_CORRUPT = "STRUCTURAL_CORRUPT"
SEMANTIC_CONFLICT = "SEMANTIC_CONFLICT"
PROVENANCE_CONFLICT = "PROVENANCE_CONFLICT"
EXECUTION_UNSAFE = "EXECUTION_UNSAFE"
RECOMPUTE_NOT_AVAILABLE = "RECOMPUTE_NOT_AVAILABLE"
SYNTHETIC_UNKNOWN = "SYNTHETIC_UNKNOWN"
UNSUPPORTED_NATIVE_KIND = "UNSUPPORTED_NATIVE_KIND"
CASE_CORRUPT = "CASE_CORRUPT"
RENDER_NOT_AVAILABLE = "RENDER_NOT_AVAILABLE"
UNSAFE_SQL_PACKAGE = "UNSAFE_SQL_PACKAGE"
RELATION_SPEC_OVERSIZE = "RELATION_SPEC_OVERSIZE"
OUTPUT_NOT_WRITABLE = "OUTPUT_NOT_WRITABLE"
SELF_VALIDATION_FAILED = "SELF_VALIDATION_FAILED"

# Stable self-validation problem codes.
_P_MANIFEST_INVALID = "manifest_invalid"
_P_EXTRA_FILE = "extra_file"
_P_MISSING_FILE = "missing_file"
_P_HASH_MISMATCH = "hash_mismatch"
_P_SYMLINK_ENTRY = "symlink_entry"
_P_UNSAFE_SQL = "unsafe_sql"
_P_INVALID_MEMBER = "invalid_member"
_P_MISSING_REQUIRED = "missing_required"
_P_UNCLASSIFIED = "unclassified"

# Same ban surface as delivery/sql.py; re-checked here on the written bytes.
_BANNED_SQL_RE = re.compile(r"\bDROP\b|IF\s+NOT\s+EXISTS|--force", re.IGNORECASE)

_HISTORICAL_NOTE = (
    "reference only; never the expected truth of this package "
    "(expected.json holds the model relation assertion)"
)


class ExportRefused(ValueError):
    """Refusal to export; ``code`` is one of the stable module codes."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ExportProblem:
    """One self-validation problem: stable short code, optional path, detail."""

    code: str
    path: Optional[str]
    detail: str


@dataclass(frozen=True)
class ExportOutcome:
    """Result of one successful export; see module docstring for refusal."""

    output_root: Path
    format: ExportFormat
    export_id: str
    manifest: ExportManifest
    files: tuple[EvidenceFile, ...]
    regression_eligible: bool
    refusal: Optional[str]


# --------------------------------------------------------------------------
# Gates
# --------------------------------------------------------------------------


def _check_hex64(value: object, what: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ExportRefused(
            IDENTITY_BROKEN, f"{what} must be lowercase 64-hex sha256, got {value!r}"
        )
    return value


def _apply_identity_gates(
    selected: SelectedCase, assessment: SourceAssessment, delivery_id: str
) -> None:
    if selected.source_id != assessment.source_id:
        raise ExportRefused(
            IDENTITY_BROKEN,
            f"selected source_id {selected.source_id!r} does not match the "
            f"assessment source_id {assessment.source_id!r}",
        )
    _check_hex64(delivery_id, "delivery_id")
    _check_hex64(selected.case_id, "selected.case_id")


def _apply_source_gates(assessment: SourceAssessment) -> None:
    """Proven broken dimensions refuse the executable export entirely."""
    if assessment.structural.status is StructuralStatus.CORRUPT:
        raise ExportRefused(
            STRUCTURAL_CORRUPT,
            "source structural status is CORRUPT; no executable export",
        )
    if assessment.semantic.status is SemanticStatus.CONFLICT:
        raise ExportRefused(
            SEMANTIC_CONFLICT,
            "source semantic status is CONFLICT; no executable export",
        )
    if assessment.provenance.status is ProvenanceStatus.CONFLICT:
        raise ExportRefused(
            PROVENANCE_CONFLICT,
            "source provenance status is CONFLICT; no executable export",
        )
    if assessment.execution_safety.status is ExecutionSafetyStatus.UNSAFE:
        raise ExportRefused(
            EXECUTION_UNSAFE,
            "source execution_safety status is UNSAFE; no executable export",
        )


def _apply_review_gates(
    export_format: ExportFormat,
    selected: SelectedCase,
    assessment: SourceAssessment,
    delivery_id: str,
    review: Optional[FindingReview],
    reviewset: Optional[ReviewSet],
    review_validation_error: Optional[Exception],
) -> None:
    if export_format is not ExportFormat.REGRESSION:
        return
    if assessment.structural.status is not StructuralStatus.COMPLETE:
        raise ExportRefused(
            STRUCTURAL_NOT_COMPLETE,
            f"source structural status is "
            f"{str(assessment.structural.status.value)!r}; regression export "
            "requires COMPLETE",
        )
    if not selected.recompute_eligible:
        raise ExportRefused(
            RECOMPUTE_NOT_AVAILABLE,
            "regression export requires an attempt-backed occurrence "
            "recomputed to RECOMPUTED",
        )
    occurrence = selected.occurrence
    assert occurrence is not None
    if occurrence.synthetic is SyntheticKind.UNKNOWN:
        raise ExportRefused(
            SYNTHETIC_UNKNOWN,
            "occurrence synthetic kind is UNKNOWN; regression export cannot "
            "claim real or self-test provenance",
        )
    if review_validation_error is not None:
        raise ExportRefused(
            REVIEW_INVALID,
            f"review input was rejected upstream: {review_validation_error}",
        )
    if reviewset is not None and reviewset.has_conflict:
        raise ExportRefused(
            REVIEW_CONFLICT,
            "reviewset records disagreeing decisions for this occurrence; "
            "conflicting reviews must not be exported",
        )
    if review is None:
        raise ExportRefused(
            REVIEW_REQUIRED,
            "regression export requires a human review binding this "
            "evidence digest and occurrence",
        )
    accepted = reviewset.accepted if reviewset is not None else ()
    if all(item is not review for item in accepted) or reviewset is None:
        raise ExportRefused(
            REVIEW_HISTORICAL,
            f"review {review.review_id!r} is not accepted for the current "
            "evidence; reviews facing older evidence are history only",
        )
    if review.evidence_digest != delivery_id:
        raise ExportRefused(
            REVIEW_HISTORICAL,
            f"review {review.review_id!r} binds evidence digest "
            f"{review.evidence_digest!r}, expected {delivery_id!r}",
        )
    occurrence_id = selected.occurrence_id
    if occurrence_id is None or occurrence_id not in review.occurrence_ids:
        raise ExportRefused(
            REVIEW_HISTORICAL,
            f"review {review.review_id!r} does not bind the selected "
            f"occurrence {occurrence_id!r}",
        )
    if review.decision is not ReviewDecision.CONFIRMED_DB_BUG:
        raise ExportRefused(
            REVIEW_NOT_CONFIRMED,
            f"review decision is {str(review.decision.value)!r}; regression "
            "export requires CONFIRMED_DB_BUG",
        )


# --------------------------------------------------------------------------
# Content builders
# --------------------------------------------------------------------------


def _decode_selected_payload(selected: SelectedCase) -> CasePayload:
    try:
        payload = decode_case_payload(selected.case_payload, what="selected case")
    except ValueError as error:
        raise ExportRefused(
            CASE_CORRUPT,
            f"selected case payload fails the case contract: {error}",
        ) from error
    if case_id_of(payload) != selected.case_id:
        raise ExportRefused(
            IDENTITY_BROKEN,
            f"selected payload hashes to case id {case_id_of(payload)}, "
            f"expected {selected.case_id}",
        )
    return payload


def _export_token(selected: SelectedCase) -> str:
    """Deterministic export token: sha256(occurrence id)[:8], or over the
    canonical [source_id, case_id] pair when no occurrence exists."""
    occurrence_id = selected.occurrence_id
    seed = (
        occurrence_id.encode("ascii")
        if occurrence_id is not None
        else canonical_json([selected.source_id, selected.case_id])
    )
    return sha256_hex(seed)[:8]


def _build_sql(
    payload: CasePayload, case_id: str, token: str
) -> tuple:
    token_names = assign_name_map(case_id, token)
    name_map = NameMap(
        database_a=token_names.database_a,
        database_b=token_names.database_b,
        table_a=token_names.table_a,
        table_b=token_names.table_b,
    )
    try:
        rendered = render_pair(payload, name_map)
    except RenderError as error:
        raise ExportRefused(
            RENDER_NOT_AVAILABLE,
            f"pinned renderer refused the payload: {error}",
        ) from error
    pre = SessionPreconditions(
        sql_mode_tokens=tuple(payload.environment.sql_mode_tokens),
        character_set=payload.environment.character_set,
        collation=payload.environment.collation,
        time_zone=payload.environment.time_zone,
    )
    try:
        a_text, b_text = wrap_sql_package(rendered, pre, token_names)
    except DeliverySqlError as error:
        raise ExportRefused(
            UNSAFE_SQL_PACKAGE, f"SQL composition refused the payload: {error}"
        ) from error
    for text in (a_text, b_text):
        if _BANNED_SQL_RE.search(text):
            raise ExportRefused(
                UNSAFE_SQL_PACKAGE,
                "composed SQL contains DROP / IF NOT EXISTS / --force; "
                "refusing export",
            )
    return name_map, token_names, a_text, b_text


def _build_relation_assertion(payload: CasePayload) -> RelationAssertion:
    spec = canonical_json(payload.relation.to_obj()).decode("ascii")
    if len(spec) > MAX_RELATION_SPEC_CHARS:
        raise ExportRefused(
            RELATION_SPEC_OVERSIZE,
            f"relation spec is {len(spec)} chars, limit is "
            f"{MAX_RELATION_SPEC_CHARS}",
        )
    columns = tuple(sorted(column.alias for column in payload.relation.columns))
    return RelationAssertion(
        mode=RelationAssertionMode.TYPED_MULTISET_EXACT,
        columns=columns,
        spec=spec,
    )


def _build_origin_document(
    selected: SelectedCase,
    assessment: SourceAssessment,
    plan: SourcePlan,
    delivery_id: str,
    producer: Optional[ProducerInfo],
) -> dict:
    occurrence = selected.occurrence
    snapshot_digest = assessment.source_id[2:]
    best_payload_ref: Optional[str] = None
    if selected.basis == "best" and assessment.selection is not None:
        best_payload_ref = assessment.selection.best_payload_ref
    historical: dict = {
        "note": _HISTORICAL_NOTE,
        "original_comparison_hash": (
            occurrence.original_comparison_hash if occurrence is not None else None
        ),
        "occurrence_id": selected.occurrence_id,
        "payload_ref": selected.payload_ref,
        "snapshot_evidence_location": (
            f"raw/{assessment.source_id}/{selected.payload_ref}"
        ),
    }
    return {
        "original_case_id": (
            occurrence.case_id
            if occurrence is not None and occurrence.case_id is not None
            else selected.case_id
        ),
        "selected_case_id": selected.case_id,
        "basis": selected.basis,
        "occurrence_id": selected.occurrence_id,
        "source_id": assessment.source_id,
        "snapshot_digest": snapshot_digest,
        "delivery_id": delivery_id,
        "native_kind": str(assessment.native_kind.value),
        "payload_ref": selected.payload_ref,
        "best_payload_ref": best_payload_ref,
        "synthetic": str(
            (occurrence.synthetic if occurrence is not None else SyntheticKind.UNKNOWN).value
        ),
        "producer": plan.producer.to_obj() if plan.producer is not None else None,
        "export_producer": producer.to_obj() if producer is not None else None,
        "historical_observation": historical,
    }


def _build_readme(
    export_format: ExportFormat,
    export_id: str,
    delivery_id: str,
    selected: SelectedCase,
    review: Optional[FindingReview],
    producer: Optional[ProducerInfo],
) -> str:
    producer_text = (
        f"{producer.name} {producer.version or ''}".strip()
        if producer is not None
        else "unknown"
    )
    if export_format is ExportFormat.REGRESSION:
        assert review is not None
        status_block = (
            "regression: this package carries an accepted human review "
            f"(reviews/{review.review_id}.json) that confirmed a database bug "
            "for this exact occurrence and evidence digest. It is a reviewed "
            "regression sample, not a certification of any database release."
        )
        extra_contents = (
            "- regression-case.json  regression sample identity and assertion "
            "contract\n"
            f"- reviews/{review.review_id}.json  canonical copy of the "
            "accepted review\n"
        )
    else:
        status_block = (
            "sql: this package carries an UNVERIFIED CANDIDATE finding "
            f"({CANDIDATE_UNVERIFIED_MARKER}) produced by the tool. No human "
            "review is attached to this export; the statements below have "
            "never been confirmed as a database bug."
        )
        extra_contents = ""
    return f"""# Independent SQL export from mtsql-typecheck

export_id: {export_id}
delivery_id (source evidence): {delivery_id}
format: {str(export_format.value)}
selected case: {selected.case_id}
occurrence id: {selected.occurrence_id or "none (no attempt-backed occurrence; see origin.json)"}
basis: {selected.basis}
tool producer: {producer_text}

## Status

{status_block}

## What this package is NOT

- NOT a D1 generation bundle: {NOT_RUN_INPUT_NOTE}. That command only
  accepts D1 generation bundles produced by the generator.
- NOT MTR / mysqltest material: there is no MTR control flow here and the
  package must not be passed to mysql-test-run.
- The historical observation in origin.json (original comparison hash,
  occurrence id and snapshot evidence location) is a REFERENCE ONLY. It is
  never the expected truth of this package: expected.json holds the typed
  relation assertion (model expectation) and nothing else.

## Session preconditions

- a.sql and b.sql each start with session SET statements rendered ONLY from
  a fixed whitelist of typed environment fields recorded in the case payload
  (see environment-requirements.json). No GLOBAL variables, HA, binlog or
  filesystem settings are touched.
- optimizer baseline: environment-requirements.json records
  optimizer_baseline = "UNKNOWN" because the export never fabricates an
  optimizer baseline. You MUST verify optimizer_switch (and any other
  optimizer-affecting settings) on the target session by hand before
  comparing the two runs; otherwise the comparison is not controlled.
- Each script creates its own dedicated database with CREATE DATABASE (no
  IF NOT EXISTS) and never issues DROP. Do not pass mysql --force: a
  statement failure must stop the script. If a database or table name
  collides, do not reuse this directory; export again into a fresh output
  directory so a new name token is assigned.

## How to run (manual)

    mysql --login-path=<dedicated-test-config> < a.sql
    mysql --login-path=<dedicated-test-config> < b.sql

No host, password or DSN is stored in this package. Use a dedicated,
disposable test instance that you are authorized to create objects on
({EXPORTER_NOTE}).

## Contents

- case.json  the selected case document (case_id + payload), canonical JSON
- expected.json  typed relation assertion (model expectation only)
- environment-requirements.json  required engine/scope/session environment
- origin.json  provenance: source, occurrence, historical observation (reference only)
- a.sql / b.sql  independent runnable SQL scripts for side A and side B
{extra_contents}
## Sealing

delivery-manifest.json lists every file above with SHA-256 and size; verify
the hashes before use. export_id {export_id} is the identity of this
package; delivery_id {delivery_id} identifies the source evidence delivery
it was cut from.
"""


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------


def _write_file(
    output_root: Path, relpath: str, data: bytes, limits: Limits, fsync_fn: Callable
) -> None:
    if len(data) > limits.max_output_single_file_bytes:
        raise ExportRefused(
            OUTPUT_NOT_WRITABLE,
            f"file {relpath!r} is {len(data)} bytes, over the per-file cap",
        )
    target = output_root / relpath
    parent = target.parent
    if str(parent) != str(output_root):
        os.makedirs(parent)
    with open(target, "xb") as handle:
        handle.write(data)
        handle.flush()
        fsync_fn(handle.fileno())


def _write_delivery_manifest(
    output_root: Path, manifest: ExportManifest, limits: Limits, fsync_fn: Callable
) -> None:
    data = canonical_json(manifest.to_obj()) + b"\n"
    if len(data) > limits.max_output_single_file_bytes:
        raise ExportRefused(
            OUTPUT_NOT_WRITABLE, "delivery manifest exceeds the per-file cap"
        )
    part_path = output_root / f".{EXPORT_MANIFEST_FILENAME}.part"
    final_path = output_root / EXPORT_MANIFEST_FILENAME
    try:
        with open(part_path, "xb") as handle:
            handle.write(data)
            handle.flush()
            fsync_fn(handle.fileno())
        os.replace(part_path, final_path)
    except FileExistsError as error:
        raise ExportRefused(
            OUTPUT_NOT_WRITABLE, "delivery manifest already exists"
        ) from error
    dir_fd = os.open(output_root, os.O_RDONLY)
    try:
        fsync_fn(dir_fd)
    finally:
        os.close(dir_fd)


def _limitations(
    selected: SelectedCase, assessment: SourceAssessment
) -> tuple:
    codes = {"optimizer_baseline_unknown"}
    if assessment.structural.status is StructuralStatus.PARTIAL:
        codes.add("source_structural_partial")
    if assessment.provenance.status is ProvenanceStatus.UNVERIFIED:
        codes.add("source_provenance_unverified")
    if assessment.execution_safety.status is ExecutionSafetyStatus.UNKNOWN:
        codes.add("source_safety_unknown")
    occurrence = selected.occurrence
    if occurrence is not None and occurrence.synthetic is SyntheticKind.SYNTHETIC:
        codes.add("tool_selftest_only")
    return tuple(sorted(codes))


def _build_descriptor(
    selected: SelectedCase,
    assessment: SourceAssessment,
    plan: SourcePlan,
) -> SourceDescriptor:
    occurrence = selected.occurrence
    synthetic = (
        occurrence.synthetic if occurrence is not None else SyntheticKind.UNKNOWN
    )
    # Documented decision: collection_status is a conservative placeholder
    # (the export inputs carry no collection outcome); it never enters the
    # export_id, which hashes only source_id + snapshot_digest.
    return SourceDescriptor(
        source_id=assessment.source_id,
        native_kind=plan.kind,
        root_document=plan.root_document,
        snapshot_digest=assessment.source_id[2:],
        synthetic=synthetic,
        collection_status=CollectionStatus.PARTIALLY_READ,
        native_versions=plan.native_versions,
        observed_writer_version=plan.observed_writer_version,
        source_commit=plan.source_commit,
        producer=plan.producer,
        missing_files=(),
    )


# --------------------------------------------------------------------------
# Self-validation
# --------------------------------------------------------------------------


def _walk_export_files(
    output_root: Path, limits: Limits, problems: list
) -> list:
    return _walk_package_files(output_root, limits, problems)


def validate_export_dir(
    output_root: Path, limits: Limits
) -> tuple:
    """Re-read a sealed export package and verify closure and contents.

    Delivery-kind agnostic counterpart of
    ``evidence.manifest.validate_delivery_dir``: re-reads
    ``delivery-manifest.json``, recomputes file hashes/sizes, verifies the
    file closure in both directions, re-greps the SQL bytes and checks the
    regression members.  Returns a tuple of :class:`ExportProblem`; an empty
    tuple means the package is sealed and consistent.
    """
    problems: list[ExportProblem] = []
    root = Path(output_root)
    try:
        root_stat = os.lstat(root)
    except OSError as error:
        return (
            ExportProblem(
                _P_MISSING_REQUIRED, None, f"package root unreadable: {error}"
            ),
        )
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        return (
            ExportProblem(_P_SYMLINK_ENTRY, None, "package root is not a directory"),
        )
    manifest_path = root / EXPORT_MANIFEST_FILENAME
    try:
        manifest_raw = manifest_path.read_bytes()
    except OSError as error:
        return (
            ExportProblem(
                _P_MISSING_REQUIRED,
                EXPORT_MANIFEST_FILENAME,
                f"delivery manifest unreadable: {error}",
            ),
        )
    try:
        manifest_obj = parse_strict_json(manifest_raw)
        if not isinstance(manifest_obj, dict):
            raise ValueError("manifest must hold a JSON object")
        manifest = decode_export_manifest(manifest_obj, what="delivery-manifest.json")
    except ValueError as error:
        return (
            ExportProblem(
                _P_MANIFEST_INVALID,
                EXPORT_MANIFEST_FILENAME,
                f"manifest is not a valid export manifest: {error}",
            ),
        )

    walked = _walk_export_files(root, limits, problems)
    listed = {entry.path: entry for entry in manifest.files}
    seen: set[str] = set()
    for item in walked:
        relpath = item.relpath
        if relpath == EXPORT_MANIFEST_FILENAME:
            continue
        seen.add(relpath)
        entry = listed.get(relpath)
        if entry is None:
            problems.append(
                ExportProblem(_P_EXTRA_FILE, relpath, "file not listed in manifest")
            )
            continue
        target = root / relpath
        data = target.read_bytes()
        if len(data) != entry.size_bytes or sha256_hex(data) != entry.sha256:
            problems.append(
                ExportProblem(_P_HASH_MISMATCH, relpath, "size/hash mismatch")
            )
        if not str(entry.role.value).startswith("export_") and entry.role.value != "review":
            problems.append(
                ExportProblem(
                    _P_UNCLASSIFIED, relpath, f"unexpected role {entry.role.value!r}"
                )
            )
    for relpath in sorted(listed):
        if relpath not in seen:
            problems.append(
                ExportProblem(_P_MISSING_FILE, relpath, "listed file missing on disk")
            )

    required = {
        "case.json",
        "expected.json",
        "environment-requirements.json",
        "origin.json",
        "a.sql",
        "b.sql",
        "README.md",
    }
    if manifest.format.value == "regression":
        required.add("regression-case.json")
    for relpath in sorted(required - seen):
        problems.append(
            ExportProblem(_P_MISSING_REQUIRED, relpath, "required export file missing")
        )

    for sql_name in ("a.sql", "b.sql"):
        if sql_name not in seen:
            continue
        text = (root / sql_name).read_bytes().decode("utf-8")
        if _BANNED_SQL_RE.search(text):
            problems.append(
                ExportProblem(_P_UNSAFE_SQL, sql_name, "banned SQL pattern present")
            )

    expected_path = root / "expected.json"
    if expected_path.exists():
        try:
            expected_obj = parse_strict_json(expected_path.read_bytes())
            decode_relation_assertion(expected_obj, what="expected.json")
        except ValueError as error:
            problems.append(
                ExportProblem(
                    _P_INVALID_MEMBER, "expected.json", f"not a relation assertion: {error}"
                )
            )

    if manifest.format.value == "regression":
        regression_path = root / "regression-case.json"
        if regression_path.exists():
            try:
                regression_obj = parse_strict_json(regression_path.read_bytes())
                regression = decode_regression_case(
                    regression_obj, what="regression-case.json"
                )
            except ValueError as error:
                regression = None
                problems.append(
                    ExportProblem(
                        _P_INVALID_MEMBER,
                        "regression-case.json",
                        f"not a regression case: {error}",
                    )
                )
            if regression is not None:
                case_bytes = (root / "case.json").read_bytes()
                if regression.case_document_hash != sha256_hex(case_bytes):
                    problems.append(
                        ExportProblem(
                            _P_HASH_MISMATCH,
                            "regression-case.json",
                            "case_document_hash does not cover case.json bytes",
                        )
                    )
                if regression.review_ref != manifest.review_ref:
                    problems.append(
                        ExportProblem(
                            _P_INVALID_MEMBER,
                            "regression-case.json",
                            "review_ref disagrees with the manifest",
                        )
                    )
        review_ref = manifest.review_ref
        if review_ref is None:
            problems.append(
                ExportProblem(
                    _P_MISSING_REQUIRED,
                    "reviews/",
                    "regression manifest carries no review_ref",
                )
            )
        else:
            review_relpath = f"reviews/{review_ref}.json"
            if review_relpath not in seen:
                problems.append(
                    ExportProblem(
                        _P_MISSING_FILE,
                        review_relpath,
                        "accepted review copy missing",
                    )
                )
    return tuple(problems)


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def export_case(
    selected: SelectedCase,
    *,
    output_root: Path,
    limits: Limits,
    export_format: ExportFormat,
    review: Optional[FindingReview],
    reviewset: Optional[ReviewSet],
    assessment: SourceAssessment,
    delivery_id: str,
    producer: Optional[ProducerInfo],
    plan: SourcePlan,
    review_validation_error: Optional[Exception] = None,
    fsync: Callable = os.fsync,
) -> ExportOutcome:
    """Gate, render and seal one export package under a NEW ``output_root``.

    Every refusal happens before any filesystem write.  On success the
    package is self-validated (:func:`validate_export_dir`) before the
    outcome is returned; a failed self-validation raises
    ``ExportRefused("SELF_VALIDATION_FAILED")`` with the problems attached
    to the message.
    """
    if not isinstance(selected, SelectedCase):
        raise ValueError("selected must be a SelectedCase")
    if not isinstance(assessment, SourceAssessment):
        raise ValueError("assessment must be a SourceAssessment")
    if not isinstance(plan, SourcePlan):
        raise ValueError("plan must be a SourcePlan")
    if not isinstance(limits, Limits):
        raise ValueError("limits must be a Limits")
    if not isinstance(export_format, ExportFormat):
        raise ValueError("export_format must be an ExportFormat")
    if review is not None and not isinstance(review, FindingReview):
        raise ValueError("review must be a FindingReview or None")
    if reviewset is not None and not isinstance(reviewset, ReviewSet):
        raise ValueError("reviewset must be a ReviewSet or None")
    if producer is not None and not isinstance(producer, ProducerInfo):
        raise ValueError("producer must be a ProducerInfo or None")

    # ---- gates (no filesystem effects yet) --------------------------------
    _apply_identity_gates(selected, assessment, delivery_id)
    if plan.kind not in (
        NativeKind.GENERATION,
        NativeKind.RUN,
        NativeKind.TRACE,
        NativeKind.ATTEMPT,
    ):
        raise ExportRefused(
            UNSUPPORTED_NATIVE_KIND,
            f"source kind {str(plan.kind.value)!r} is not exportable native "
            "evidence",
        )
    _apply_source_gates(assessment)
    _apply_review_gates(
        export_format,
        selected,
        assessment,
        delivery_id,
        review,
        reviewset,
        review_validation_error,
    )
    payload = _decode_selected_payload(selected)
    token = _export_token(selected)
    name_map, token_names, a_text, b_text = _build_sql(payload, selected.case_id, token)
    assertion = _build_relation_assertion(payload)

    # ---- create the output directory (first filesystem effect) ------------
    try:
        output_root = _ensure_new_output_dir(Path(output_root))
    except (OutputDirExistsError, UnsafePathError) as error:
        raise ExportRefused(OUTPUT_NOT_WRITABLE, str(error)) from error

    try:
        return _seal_package(
            output_root=output_root,
            limits=limits,
            fsync_fn=fsync,
            export_format=export_format,
            selected=selected,
            assessment=assessment,
            plan=plan,
            delivery_id=delivery_id,
            producer=producer,
            payload=payload,
            review=review,
            token_names=token_names,
            name_map=name_map,
            a_text=a_text,
            b_text=b_text,
            assertion=assertion,
        )
    except Exception:
        # Never leave a half-written package behind on internal failure.
        _remove_tree(output_root)
        raise


def _seal_package(
    *,
    output_root: Path,
    limits: Limits,
    fsync_fn: Callable,
    export_format: ExportFormat,
    selected: SelectedCase,
    assessment: SourceAssessment,
    plan: SourcePlan,
    delivery_id: str,
    producer: Optional[ProducerInfo],
    payload: CasePayload,
    review: Optional[FindingReview],
    token_names: ExportNameMap,
    name_map: NameMap,
    a_text: str,
    b_text: str,
    assertion: RelationAssertion,
) -> ExportOutcome:
    descriptor = _build_descriptor(selected, assessment, plan)
    export_id = compute_delivery_id((descriptor,))
    limitations = _limitations(selected, assessment)

    case_doc = {"case_id": selected.case_id, "payload": selected.case_payload}
    case_bytes = canonical_json(case_doc) + b"\n"
    expected_bytes = canonical_json(assertion.to_obj()) + b"\n"
    env_bytes = (
        canonical_json(environment_requirements_document(payload).to_obj()) + b"\n"
    )
    origin_bytes = (
        canonical_json(
            _build_origin_document(selected, assessment, plan, delivery_id, producer)
        )
        + b"\n"
    )
    readme_text = _build_readme(
        export_format, export_id, delivery_id, selected, review, producer
    )

    written: list[tuple[str, bytes]] = [
        ("case.json", case_bytes),
        ("expected.json", expected_bytes),
        ("environment-requirements.json", env_bytes),
        ("origin.json", origin_bytes),
        ("a.sql", a_text.encode("utf-8")),
        ("b.sql", b_text.encode("utf-8")),
        ("README.md", readme_text.encode("utf-8")),
    ]
    if export_format is ExportFormat.REGRESSION:
        if review is None:  # guaranteed by the gates; defensive only
            raise ExportRefused(REVIEW_REQUIRED, "regression export requires a review")
        review_relpath = f"reviews/{review.review_id}.json"
        try:
            check_package_path(review_relpath, "review copy path")
        except ValueError as error:
            raise ExportRefused(
                REVIEW_INVALID, f"review_id is not path-safe: {error}"
            ) from error
        synthetic = (
            selected.occurrence.synthetic
            if selected.occurrence is not None
            else SyntheticKind.UNKNOWN
        )
        regression_case = RegressionCase(
            case_document_hash=sha256_hex(case_bytes),
            renderer_id=payload.renderer.id,
            renderer_version=payload.renderer.version,
            codec_id="mysql-text-1",
            codec_version="1",
            relation_assertion=assertion,
            source_inventory_hash=assessment.source_id[2:],
            synthetic=synthetic,
            rule_definition_hash=None,
            review_ref=review.review_id,
        )
        written.append(
            ("regression-case.json", canonical_json(regression_case.to_obj()) + b"\n")
        )
        written.append((review_relpath, canonical_json(review.to_obj()) + b"\n"))

    total = 0
    for relpath, data in written:
        total += len(data)
    if total > limits.max_output_total_bytes:
        raise ExportRefused(
            OUTPUT_NOT_WRITABLE,
            f"package would hold {total} bytes, over the total cap",
        )
    for relpath, data in written:
        _write_file(output_root, relpath, data, limits, fsync_fn)

    files = collect_delivery_files(output_root, limits)
    manifest = ExportManifest(
        export_id=export_id,
        format=export_format,
        source_delivery_id=delivery_id,
        selected_case_id=selected.case_id,
        selected_occurrence_id=selected.occurrence_id,
        review_ref=(
            review.review_id if export_format is ExportFormat.REGRESSION else None
        ),
        name_map=name_map,
        files=files,
        completion=DeliveryCompletion.COMPLETE,
        limitations=limitations,
    )
    _write_delivery_manifest(output_root, manifest, limits, fsync_fn)

    problems = validate_export_dir(output_root, limits)
    if problems:
        detail = "; ".join(
            f"{problem.code}[{problem.path}]: {problem.detail}"
            for problem in problems
        )
        raise ExportRefused(SELF_VALIDATION_FAILED, detail)

    return ExportOutcome(
        output_root=output_root,
        format=export_format,
        export_id=export_id,
        manifest=manifest,
        files=files,
        regression_eligible=(export_format is ExportFormat.REGRESSION),
        refusal=None,
    )


def _remove_tree(root: Path) -> None:
    """Best-effort removal of a package this function created and owns."""
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        for name in filenames:
            try:
                os.unlink(os.path.join(dirpath, name))
            except OSError:
                pass
        for name in dirnames:
            try:
                os.rmdir(os.path.join(dirpath, name))
            except OSError:
                pass
    try:
        os.rmdir(root)
    except OSError:
        pass
