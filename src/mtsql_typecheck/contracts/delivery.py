"""D4 evidence/reporting/regression delivery contracts (design 6.2.1-6.2.3, 6.5, 6.5.1).

Frozen persistent models for the offline D4 consumption layer: the evidence
manifest and its source descriptors, the four-dimension assessment, finding
occurrences, independent human reviews and the SQL/regression export models.
House rules follow D1/D2 (``contracts/case.py``, ``contracts/codec.py``):
frozen dataclasses, closed enums, tuples in memory, full ``__post_init__``
validation on both the construction and the loader path, unknown fields
rejected, ``bool`` never accepted where an int is required, no floats in
documents (the two seconds budget fields are the only float slots and are
stored as floats), optional fields only for genuinely absent facts.  The
snapshot/delivery/occurrence identity formulas of design 6.2.1 are
implemented as pure functions below.  Importing this module performs no I/O;
it never touches a database, the network or a driver.

Design boundaries encoded here: ``DeliveryCompletion`` describes whether the
derived delivery was sealed, never test success; ``FindingOccurrence`` has no
``confirmed_bug`` field (confirmation lives only in ``FindingReview``);
``aggregate_*`` helpers never produce a total PASS.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Optional, Sequence, Union

from .case import (
    ContractError,
    NameMap,
    _check_bool,
    _check_enum,
    _check_hex64,
    _check_int,
    _check_str,
    _SEMVER_ID_RE,
    _SEMVER_VERSION_RE,
)
from .codec import (
    _as_bool,
    _as_enum,
    _as_int,
    _as_list,
    _as_opt,
    _as_str,
    _expect_dict,
    _field,
    _no_extra,
    canonical_json,
    decode_name_map,
    parse_strict_json,
    sha256_hex,
)

__all__ = [
    "DELIVERY_SCHEMA_VERSION",
    "REVIEW_SCHEMA_VERSION",
    "EXPORT_SCHEMA_VERSION",
    "MAX_PACKAGE_PATH_BYTES",
    "MAX_TIME_BUDGET_SECONDS",
    "NATIVE_VERSION_KEYS",
    "NativeKind",
    "DeliveryKind",
    "DeliveryCompletion",
    "SyntheticKind",
    "CollectionStatus",
    "StructuralStatus",
    "SemanticStatus",
    "ProvenanceStatus",
    "ExecutionSafetyStatus",
    "ReviewDecision",
    "FileRole",
    "ExportFormat",
    "AssessmentDimension",
    "RelationAssertionMode",
    "NativeVersionComponent",
    "ProducerInfo",
    "Limits",
    "EvidenceFile",
    "SourceDescriptor",
    "EvidenceManifest",
    "DimensionObservation",
    "DimensionResult",
    "EvidenceAssessment",
    "FindingOccurrence",
    "FindingReview",
    "RelationAssertion",
    "RegressionCase",
    "ExportManifest",
    "compute_snapshot_digest",
    "compute_source_id",
    "compute_delivery_id",
    "compute_occurrence_id",
    "aggregate_structural",
    "aggregate_semantic",
    "aggregate_provenance",
    "aggregate_safety",
    "decode_producer_info",
    "decode_limits",
    "decode_evidence_file",
    "decode_native_version_component",
    "decode_source_descriptor",
    "decode_evidence_manifest",
    "decode_dimension_observation",
    "decode_dimension_result",
    "decode_evidence_assessment",
    "decode_finding_occurrence",
    "decode_finding_review",
    "decode_relation_assertion",
    "decode_regression_case",
    "decode_export_manifest",
]

# --------------------------------------------------------------------------
# Frozen schema versions and limits constants (design 6.2.1, 6.5)
# --------------------------------------------------------------------------

DELIVERY_SCHEMA_VERSION = 1  # EvidenceManifest / SourceDescriptor / assessment
REVIEW_SCHEMA_VERSION = 1  # FindingReview
EXPORT_SCHEMA_VERSION = 1  # RegressionCase / ExportManifest

# Package-relative path cap; matches the Limits.max_path_bytes default.
MAX_PACKAGE_PATH_BYTES = 1024
MAX_ASSESSMENT_REF_BYTES = 1024
MAX_REVIEW_ID_CHARS = 128
MAX_IDENTITY_VERSION_CHARS = 128
MAX_REASON_CODE_CHARS = 64
MAX_RELATION_SPEC_CHARS = 2000
MAX_OBJECT_REF_CHARS = 256
MAX_LIMITATION_CHARS = 64
# Design 6.5: default wall clock 120s, hard cap 600s; never unlimited.
DEFAULT_TIME_BUDGET_SECONDS = 120.0
MAX_TIME_BUDGET_SECONDS = 600.0

# Known native-version keys (design 6.4.2: fixed schema/codec identifiers).
NATIVE_VERSION_KEYS = (
    "case_schema",
    "comparison_schema",
    "execution_schema",
    "generation_schema",
    "reduction_schema",
    "replay_schema",
    "runner_schema",
    "trace_format",
)

MANIFEST_FILENAME = "evidence-manifest.json"
EXPORT_MANIFEST_FILENAME = "delivery-manifest.json"
ASSESSMENT_FILENAME = "assessment.json"

_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_SOURCE_ID_RE = re.compile(r"^s-[0-9a-f]{64}$")
_REASON_CODE_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_LIMITATION_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_OBJECT_REF_RE = re.compile(r"^[A-Za-z0-9._/@:-]{1,256}$")
_VERSION_TEXT_RE = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$"
)


def _fail(msg: str) -> None:
    raise ContractError(msg)


def _check_hex40(value: object, name: str) -> str:
    value = _check_str(value, name)
    if not _HEX40_RE.match(value):
        _fail(f"{name} must be a full lowercase 40-hex git SHA, got {value!r}")
    return value


def _check_source_id(value: object, name: str) -> str:
    value = _check_str(value, name)
    if not _SOURCE_ID_RE.match(value):
        _fail(f"{name} must be 's-' plus 64-hex sha256, got {value!r}")
    return value


def _check_non_empty(value: object, name: str, max_chars: int) -> str:
    value = _check_str(value, name)
    if not value:
        _fail(f"{name} must be non-empty")
    if len(value) > max_chars:
        _fail(f"{name} exceeds {max_chars} characters")
    return value


def _check_version_text(value: object, name: str) -> str:
    value = _check_non_empty(value, name, MAX_IDENTITY_VERSION_CHARS)
    if not _VERSION_TEXT_RE.match(value):
        _fail(f"{name} has unsupported form: {value!r}")
    return value


def check_package_path(value: object, name: str) -> str:
    """Package-relative POSIX path: no absolute, '..' '.', backslash or NUL."""
    value = _check_str(value, name)
    if not value:
        _fail(f"{name} must be a non-empty package-relative path")
    if "\\" in value:
        _fail(f"{name} must use POSIX separators, backslash found: {value!r}")
    if value.startswith("/"):
        _fail(f"{name} must be relative, got {value!r}")
    if "\x00" in value:
        _fail(f"{name} contains a NUL byte")
    if len(value.encode("utf-8")) > MAX_PACKAGE_PATH_BYTES:
        _fail(f"{name} exceeds {MAX_PACKAGE_PATH_BYTES} bytes")
    parts = value.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            _fail(f"{name} contains an illegal path component {part!r}: {value!r}")
    return value


def _check_sorted_unique(items: Sequence[str], name: str, checker) -> tuple[str, ...]:
    previous: Optional[str] = None
    for item in items:
        checker(item, f"{name} item")
        if previous is not None and item <= previous:
            _fail(f"{name} must be sorted and unique")
        previous = item
    return tuple(items)


# --------------------------------------------------------------------------
# Enums (design 6.2.1-6.2.3 vocabulary)
# --------------------------------------------------------------------------


class NativeKind(enum.StrEnum):
    """Native evidence format family consumed by D4 (design 6.3)."""

    GENERATION = "generation"
    RUN = "run"
    TRACE = "trace"
    ATTEMPT = "attempt"
    DELIVERY = "delivery"
    UNKNOWN = "unknown"


class DeliveryKind(enum.StrEnum):
    """D4 evidence-package kind (design 6.2.1)."""

    VERIFICATION = "verification"
    REPORT = "report"


class DeliveryCompletion(enum.StrEnum):
    """Whether the derived delivery was sealed - never test success (6.2.1)."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class SyntheticKind(enum.StrEnum):
    """Real evidence, self-test fixture, or undetermined (6.2.2)."""

    REAL = "REAL"
    SYNTHETIC = "SYNTHETIC"
    UNKNOWN = "UNKNOWN"


class CollectionStatus(enum.StrEnum):
    """Snapshot collection outcome for one source (design 6.4.1).

    COLLECTED: the enumerated closure was read fully and unchanged.
    SOURCE_CHANGED: the source changed during collection; the snapshot stays
    diagnostic only.  PARTIALLY_READ: parts of the declared closure could not
    be read (missing/oversized/unreadable) without a change signal.
    REFUSED: path-safety or limit checks refused the source before any bytes
    were copied.
    """

    COLLECTED = "COLLECTED"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    PARTIALLY_READ = "PARTIALLY_READ"
    REFUSED = "REFUSED"


class StructuralStatus(enum.StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    CORRUPT = "CORRUPT"
    UNSUPPORTED = "UNSUPPORTED"


class SemanticStatus(enum.StrEnum):
    RECOMPUTED = "RECOMPUTED"
    NOT_RECOMPUTED = "NOT_RECOMPUTED"
    CONFLICT = "CONFLICT"


class ProvenanceStatus(enum.StrEnum):
    CORROBORATED = "CORROBORATED"
    UNVERIFIED = "UNVERIFIED"
    CONFLICT = "CONFLICT"


class ExecutionSafetyStatus(enum.StrEnum):
    CONFIRMED = "CONFIRMED"
    UNKNOWN = "UNKNOWN"
    UNSAFE = "UNSAFE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ReviewDecision(enum.StrEnum):
    CONFIRMED_DB_BUG = "CONFIRMED_DB_BUG"
    EXPECTED_BEHAVIOR = "EXPECTED_BEHAVIOR"
    TOOL_OR_EVIDENCE_ISSUE = "TOOL_OR_EVIDENCE_ISSUE"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"


class FileRole(enum.StrEnum):
    """Package file role: RAW_NATIVE is original bytes, the rest derived."""

    RAW_NATIVE = "raw_native"
    ASSESSMENT = "assessment"
    REPORT_JSON = "report_json"
    REPORT_MD = "report_md"
    REPORT_HTML = "report_html"
    REVIEW = "review"
    EXPORT_README = "export_readme"
    EXPORT_CASE = "export_case"
    EXPORT_EXPECTED = "export_expected"
    EXPORT_ENVIRONMENT_REQUIREMENTS = "export_environment_requirements"
    EXPORT_ORIGIN = "export_origin"
    EXPORT_SQL_A = "export_sql_a"
    EXPORT_SQL_B = "export_sql_b"
    EXPORT_REGRESSION_CASE = "export_regression_case"


class ExportFormat(enum.StrEnum):
    SQL = "sql"
    REGRESSION = "regression"


class AssessmentDimension(enum.StrEnum):
    STRUCTURAL = "structural"
    SEMANTIC = "semantic"
    PROVENANCE = "provenance"
    EXECUTION_SAFETY = "execution_safety"


class RelationAssertionMode(enum.StrEnum):
    TYPED_MULTISET_EXACT = "typed_multiset_exact"


DimensionStatus = Union[
    StructuralStatus, SemanticStatus, ProvenanceStatus, ExecutionSafetyStatus
]

_DIMENSION_STATUS_ENUMS: dict[AssessmentDimension, tuple[type, ...]] = {
    AssessmentDimension.STRUCTURAL: (StructuralStatus,),
    AssessmentDimension.SEMANTIC: (SemanticStatus,),
    AssessmentDimension.PROVENANCE: (ProvenanceStatus,),
    AssessmentDimension.EXECUTION_SAFETY: (ExecutionSafetyStatus,),
}


def _check_dimension_status(dimension: AssessmentDimension, status: object, name: str):
    for enum_cls in _DIMENSION_STATUS_ENUMS[dimension]:
        if isinstance(status, enum_cls):
            return status
    _fail(
        f"{name} must be one of the {dimension.value} statuses, got {status!r}"
    )


# --------------------------------------------------------------------------
# Identity functions (design 6.2.1 exact formulas; pure, no I/O)
# --------------------------------------------------------------------------


def compute_snapshot_digest(
    native_kind: str,
    root_document: str,
    files: Sequence[tuple[str, int, str]],
    missing_paths: Sequence[str],
) -> str:
    """SHA-256 over canonical JSON of the frozen snapshot content.

    Input object: ``{"native_kind", "root_document", "files", "missing_paths"}``
    where ``files`` holds one ``{"path", "size_bytes", "sha256"}`` object per
    read native file sorted by path, and ``missing_paths`` is sorted and
    deduplicated.  Excludes absolute paths, mtimes, wall-clock times, audit
    state, producer inference and the digest itself.
    """
    kind = _as_enum(NativeKind, native_kind, "compute_snapshot_digest native_kind")
    check_package_path(root_document, "compute_snapshot_digest root_document")
    if not isinstance(files, (tuple, list)):
        _fail("compute_snapshot_digest files must be a sequence of (path, size, sha256)")
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, tuple) or len(item) != 3:
            _fail("compute_snapshot_digest file entries must be (path, size_bytes, sha256)")
        path, size_bytes, sha256 = item
        check_package_path(path, "compute_snapshot_digest file path")
        _check_int(size_bytes, "compute_snapshot_digest file size_bytes")
        if size_bytes < 0:
            _fail("compute_snapshot_digest file size_bytes must be >= 0")
        _check_hex64(sha256, "compute_snapshot_digest file sha256")
        if path in seen:
            _fail(f"compute_snapshot_digest duplicate file path {path!r}")
        seen.add(path)
        entries.append({"path": path, "sha256": sha256, "size_bytes": size_bytes})
    entries.sort(key=lambda entry: str(entry["path"]))
    missing = _check_sorted_unique(
        list(missing_paths), "compute_snapshot_digest missing_paths", check_package_path
    )
    return sha256_hex(
        canonical_json(
            {
                "files": entries,
                "missing_paths": list(missing),
                "native_kind": str(kind.value),
                "root_document": root_document,
            }
        )
    )


def compute_source_id(snapshot_digest: str) -> str:
    """source_id = "s-" + full snapshot_digest (design 6.2.1)."""
    _check_hex64(snapshot_digest, "compute_source_id snapshot_digest")
    return "s-" + snapshot_digest


def compute_delivery_id(sources: Sequence["SourceDescriptor"]) -> str:
    """SHA-256 over canonical JSON of the source identity list.

    Input: the list of ``{"source_id", "snapshot_digest"}`` objects sorted by
    ``source_id``; at least one source, unique source_ids.  Moving, re-render
    and added reviews never change it; changed raw bytes or a changed missing
    set do.
    """
    if not isinstance(sources, (tuple, list)) or not sources:
        _fail("compute_delivery_id requires at least one source")
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for source in sources:
        if not isinstance(source, SourceDescriptor):
            _fail("compute_delivery_id sources must hold SourceDescriptor items")
        if source.source_id in seen:
            _fail(f"compute_delivery_id duplicate source_id {source.source_id!r}")
        seen.add(source.source_id)
        entries.append(
            {"snapshot_digest": source.snapshot_digest, "source_id": source.source_id}
        )
    entries.sort(key=lambda entry: entry["source_id"])
    return sha256_hex(canonical_json(entries))


def compute_occurrence_id(source_id: str, attempt_id: str, case_id: str) -> str:
    """SHA-256 over canonical JSON of ``[source_id, attempt_id, case_id]``.

    ``attempt_id`` must be a real native attempt identifier: callers whose
    native format lacks one must not create execution occurrences at all
    (design 6.2.1: 缺失 attempt 标识时不伪造 execution occurrence), so passing
    ``None`` raises instead of hashing an empty substitute.
    """
    _check_source_id(source_id, "compute_occurrence_id source_id")
    if attempt_id is None:
        _fail(
            "compute_occurrence_id requires a native attempt_id; missing attempt "
            "identifiers must not be fabricated into execution occurrences"
        )
    _check_non_empty(attempt_id, "compute_occurrence_id attempt_id", MAX_REVIEW_ID_CHARS)
    _check_hex64(case_id, "compute_occurrence_id case_id")
    return sha256_hex(canonical_json([source_id, attempt_id, case_id]))


# --------------------------------------------------------------------------
# Producer metadata and limits (design 6.5.1, 6.5)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ProducerInfo:
    """Tool version metadata of a native writer or of this delivery (6.5.1).

    ``version``/``revision``/``dirty`` stay ``None`` when unknown; ``dirty``
    is never defaulted to ``False`` and a non-None ``revision`` must be a full
    40-char lowercase git SHA.  This describes the TypeCheck tool, never the
    tested database version.
    """

    name: str
    version: Optional[str] = None
    revision: Optional[str] = None
    dirty: Optional[bool] = None

    def __post_init__(self) -> None:
        _check_non_empty(self.name, "ProducerInfo.name", MAX_IDENTITY_VERSION_CHARS)
        if self.version is not None:
            _check_version_text(self.version, "ProducerInfo.version")
        if self.revision is not None:
            _check_hex40(self.revision, "ProducerInfo.revision")
        if self.dirty is not None:
            _check_bool(self.dirty, "ProducerInfo.dirty")

    def to_obj(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "revision": self.revision,
            "dirty": self.dirty,
        }


@dataclass(frozen=True)
class Limits:
    """Bounded-reader budget table (design 6.5).  No unlimited option exists.

    Every byte/count field is a positive int (bool rejected).  The seconds
    budget is stored as a float, but only whole seconds are accepted (an int
    or integral float such as ``120.0``; the value is normalized to float);
    the persistent document therefore carries an int and the strict
    float-free canonical JSON rule stays intact.  Hard cap 600.0s.
    """

    max_single_source_file_bytes: int = 256 * 1024 * 1024
    max_total_source_bytes: int = 1024 * 1024 * 1024
    max_json_document_bytes: int = 32 * 1024 * 1024
    max_files: int = 10000
    max_jsonl_line_bytes: int = 256 * 1024
    max_dir_depth: int = 16
    max_path_bytes: int = 1024
    max_output_single_file_bytes: int = 256 * 1024 * 1024
    max_output_total_bytes: int = 1024 * 1024 * 1024
    max_html_bytes: int = 8 * 1024 * 1024
    max_markdown_bytes: int = 8 * 1024 * 1024
    min_diagnostic_reserve_bytes: int = 2 * 1024 * 1024
    time_budget_seconds: float = DEFAULT_TIME_BUDGET_SECONDS

    @classmethod
    def default(cls) -> "Limits":
        return cls()

    def __post_init__(self) -> None:
        for name in (
            "max_single_source_file_bytes",
            "max_total_source_bytes",
            "max_json_document_bytes",
            "max_files",
            "max_jsonl_line_bytes",
            "max_dir_depth",
            "max_path_bytes",
            "max_output_single_file_bytes",
            "max_output_total_bytes",
            "max_html_bytes",
            "max_markdown_bytes",
            "min_diagnostic_reserve_bytes",
        ):
            value = _check_int(getattr(self, name), f"Limits.{name}")
            if value <= 0:
                _fail(f"Limits.{name} must be positive, got {value}")
        seconds = self.time_budget_seconds
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            _fail("Limits.time_budget_seconds must be a number")
        seconds = float(seconds)
        if seconds != seconds or seconds in (float("inf"), float("-inf")):
            _fail("Limits.time_budget_seconds must be finite")
        if not seconds.is_integer():
            _fail("Limits.time_budget_seconds must be a whole number of seconds")
        if not 0 < seconds <= MAX_TIME_BUDGET_SECONDS:
            _fail(
                f"Limits.time_budget_seconds must be in (0, {MAX_TIME_BUDGET_SECONDS}], "
                f"got {seconds}"
            )
        object.__setattr__(self, "time_budget_seconds", seconds)
        if self.max_single_source_file_bytes > self.max_total_source_bytes:
            _fail("Limits single-file source cap exceeds the total source cap")
        if self.max_output_single_file_bytes > self.max_output_total_bytes:
            _fail("Limits single-file output cap exceeds the total output cap")
        if self.min_diagnostic_reserve_bytes > self.max_output_total_bytes:
            _fail("Limits diagnostic reserve exceeds the total output cap")
        if self.max_path_bytes != MAX_PACKAGE_PATH_BYTES:
            _fail(f"Limits.max_path_bytes is frozen to {MAX_PACKAGE_PATH_BYTES}")

    def to_obj(self) -> dict[str, object]:
        return {
            "max_single_source_file_bytes": self.max_single_source_file_bytes,
            "max_total_source_bytes": self.max_total_source_bytes,
            "max_json_document_bytes": self.max_json_document_bytes,
            "max_files": self.max_files,
            "max_jsonl_line_bytes": self.max_jsonl_line_bytes,
            "max_dir_depth": self.max_dir_depth,
            "max_path_bytes": self.max_path_bytes,
            "max_output_single_file_bytes": self.max_output_single_file_bytes,
            "max_output_total_bytes": self.max_output_total_bytes,
            "max_html_bytes": self.max_html_bytes,
            "max_markdown_bytes": self.max_markdown_bytes,
            "min_diagnostic_reserve_bytes": self.min_diagnostic_reserve_bytes,
            "time_budget_seconds": int(self.time_budget_seconds),
        }


# --------------------------------------------------------------------------
# Files and source descriptors (design 6.2.1, 6.2.3)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceFile:
    """One sealed package file.  Hash/size match the actual bytes.

    ``path`` is package-relative POSIX.  RAW_NATIVE files must bind a
    ``source_id``; derived files may leave it None (``None`` is allowed only
    for derived files).  Verifying hash against bytes is the manifest
    validator's job, not the model's.
    """

    path: str
    role: FileRole
    size_bytes: int
    sha256: str
    source_id: Optional[str] = None

    def __post_init__(self) -> None:
        check_package_path(self.path, "EvidenceFile.path")
        _check_enum(self.role, FileRole, "EvidenceFile.role")
        _check_int(self.size_bytes, "EvidenceFile.size_bytes")
        if self.size_bytes < 0:
            _fail("EvidenceFile.size_bytes must be >= 0")
        _check_hex64(self.sha256, "EvidenceFile.sha256")
        if self.source_id is not None:
            _check_source_id(self.source_id, "EvidenceFile.source_id")
        if self.role is FileRole.RAW_NATIVE and self.source_id is None:
            _fail("EvidenceFile RAW_NATIVE requires a source_id")

    def to_obj(self) -> dict[str, object]:
        return {
            "path": self.path,
            "role": str(self.role.value),
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "source_id": self.source_id,
        }


@dataclass(frozen=True)
class NativeVersionComponent:
    """One native schema/codec version component (design 6.4.2 fixed keys)."""

    kind_field: str
    value: str

    def __post_init__(self) -> None:
        _check_str(self.kind_field, "NativeVersionComponent.kind_field")
        if self.kind_field not in NATIVE_VERSION_KEYS:
            _fail(
                f"NativeVersionComponent.kind_field {self.kind_field!r} is unknown; "
                f"known keys: {NATIVE_VERSION_KEYS}"
            )
        _check_version_text(self.value, "NativeVersionComponent.value")

    def to_obj(self) -> dict[str, object]:
        return {"kind_field": self.kind_field, "value": self.value}


@dataclass(frozen=True)
class SourceDescriptor:
    """One frozen native source inside a delivery (design 6.2.1).

    ``source_id`` must equal ``"s-" + snapshot_digest``.  ``native_versions``
    is a sorted, duplicate-free tuple over the fixed NATIVE_VERSION_KEYS.
    ``source_commit`` is null when the native writer recorded no commit; D4
    never fills it from its own HEAD.  ``missing_files`` is sorted and
    unique.
    """

    source_id: str
    native_kind: NativeKind
    root_document: str
    snapshot_digest: str
    synthetic: SyntheticKind
    collection_status: CollectionStatus
    native_versions: tuple[NativeVersionComponent, ...] = ()
    observed_writer_version: Optional[str] = None
    source_commit: Optional[str] = None
    producer: Optional[ProducerInfo] = None
    missing_files: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _check_source_id(self.source_id, "SourceDescriptor.source_id")
        _check_enum(self.native_kind, NativeKind, "SourceDescriptor.native_kind")
        check_package_path(self.root_document, "SourceDescriptor.root_document")
        _check_hex64(self.snapshot_digest, "SourceDescriptor.snapshot_digest")
        if self.source_id != compute_source_id(self.snapshot_digest):
            _fail("SourceDescriptor.source_id must equal 's-' + snapshot_digest")
        _check_enum(self.synthetic, SyntheticKind, "SourceDescriptor.synthetic")
        _check_enum(
            self.collection_status, CollectionStatus, "SourceDescriptor.collection_status"
        )
        if not isinstance(self.native_versions, tuple):
            _fail("SourceDescriptor.native_versions must be a tuple")
        previous: Optional[str] = None
        for component in self.native_versions:
            if not isinstance(component, NativeVersionComponent):
                _fail("SourceDescriptor.native_versions must hold NativeVersionComponent")
            if previous is not None and component.kind_field <= previous:
                _fail("SourceDescriptor.native_versions must be sorted by kind_field")
            previous = component.kind_field
        if self.observed_writer_version is not None:
            _check_version_text(
                self.observed_writer_version, "SourceDescriptor.observed_writer_version"
            )
        if self.source_commit is not None:
            _check_hex40(self.source_commit, "SourceDescriptor.source_commit")
        if self.producer is not None and not isinstance(self.producer, ProducerInfo):
            _fail("SourceDescriptor.producer must be a ProducerInfo or None")
        _check_sorted_unique(
            self.missing_files, "SourceDescriptor.missing_files", check_package_path
        )

    def to_obj(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "native_kind": str(self.native_kind.value),
            "native_versions": [item.to_obj() for item in self.native_versions],
            "root_document": self.root_document,
            "observed_writer_version": self.observed_writer_version,
            "source_commit": self.source_commit,
            "producer": self.producer.to_obj() if self.producer is not None else None,
            "synthetic": str(self.synthetic.value),
            "snapshot_digest": self.snapshot_digest,
            "missing_files": list(self.missing_files),
            "collection_status": str(self.collection_status.value),
        }


@dataclass(frozen=True)
class EvidenceManifest:
    """Sealed D4 evidence-package manifest (design 6.2.1, 6.2.3).

    ``delivery_id`` is derived and re-verified against the sources.  The file
    list never contains the manifest itself.  ``assessment_ref`` is required
    for both kinds and fixed to ``assessment.json`` (verify and report both
    write it).  ``completion`` describes only whether this derived delivery
    was sealed, never test success.
    """

    delivery_id: str
    kind: DeliveryKind
    writer_version: str
    sources: tuple[SourceDescriptor, ...]
    files: tuple[EvidenceFile, ...]
    completion: DeliveryCompletion
    assessment_ref: str = ASSESSMENT_FILENAME
    producer: Optional[ProducerInfo] = None
    schema_version: int = DELIVERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "EvidenceManifest.schema_version")
        if self.schema_version != DELIVERY_SCHEMA_VERSION:
            _fail(f"unsupported delivery schema_version {self.schema_version}")
        _check_hex64(self.delivery_id, "EvidenceManifest.delivery_id")
        _check_enum(self.kind, DeliveryKind, "EvidenceManifest.kind")
        _check_version_text(self.writer_version, "EvidenceManifest.writer_version")
        if not isinstance(self.sources, tuple) or not self.sources:
            _fail("EvidenceManifest.sources must be a non-empty tuple")
        previous: Optional[str] = None
        for source in self.sources:
            if not isinstance(source, SourceDescriptor):
                _fail("EvidenceManifest.sources must hold SourceDescriptor items")
            if previous is not None and source.source_id <= previous:
                _fail("EvidenceManifest.sources must be sorted by source_id")
            previous = source.source_id
        derived = compute_delivery_id(self.sources)
        if self.delivery_id != derived:
            _fail(
                f"EvidenceManifest.delivery_id {self.delivery_id!r} does not match "
                f"the source identity hash {derived}"
            )
        if not isinstance(self.files, tuple):
            _fail("EvidenceManifest.files must be a tuple")
        previous_path: Optional[str] = None
        for file_entry in self.files:
            if not isinstance(file_entry, EvidenceFile):
                _fail("EvidenceManifest.files must hold EvidenceFile items")
            if previous_path is not None and file_entry.path <= previous_path:
                _fail("EvidenceManifest.files must be sorted by unique path")
            previous_path = file_entry.path
            if file_entry.path == MANIFEST_FILENAME:
                _fail("EvidenceManifest.files must not list the manifest itself")
        check_package_path(self.assessment_ref, "EvidenceManifest.assessment_ref")
        if self.assessment_ref != ASSESSMENT_FILENAME:
            _fail(f"EvidenceManifest.assessment_ref is fixed to {ASSESSMENT_FILENAME!r}")
        _check_enum(self.completion, DeliveryCompletion, "EvidenceManifest.completion")
        if self.producer is not None and not isinstance(self.producer, ProducerInfo):
            _fail("EvidenceManifest.producer must be a ProducerInfo or None")

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "delivery_id": self.delivery_id,
            "kind": str(self.kind.value),
            "writer_version": self.writer_version,
            "producer": self.producer.to_obj() if self.producer is not None else None,
            "sources": [source.to_obj() for source in self.sources],
            "files": [file_entry.to_obj() for file_entry in self.files],
            "assessment_ref": self.assessment_ref,
            "completion": str(self.completion.value),
        }


# --------------------------------------------------------------------------
# Assessment dimensions and aggregation (design 6.2.2)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DimensionObservation:
    """Per-object observation feeding the aggregation helpers (6.2.2).

    ``status`` must belong to ``dimension``'s enum.  Observations with
    ``applicable=False`` (and safety NOT_APPLICABLE statuses) never change the
    aggregate.
    """

    dimension: AssessmentDimension
    applicable: bool
    status: DimensionStatus
    object_ref: Optional[str] = None

    def __post_init__(self) -> None:
        _check_enum(self.dimension, AssessmentDimension, "DimensionObservation.dimension")
        _check_bool(self.applicable, "DimensionObservation.applicable")
        _check_dimension_status(self.dimension, self.status, "DimensionObservation.status")
        if self.object_ref is not None:
            _check_str(self.object_ref, "DimensionObservation.object_ref")
            if not self.object_ref or len(self.object_ref) > MAX_OBJECT_REF_CHARS:
                _fail(f"DimensionObservation.object_ref must be 1..{MAX_OBJECT_REF_CHARS} chars")

    def to_obj(self) -> dict[str, object]:
        return {
            "dimension": str(self.dimension.value),
            "applicable": self.applicable,
            "status": str(self.status.value),
            "object_ref": self.object_ref,
        }


@dataclass(frozen=True)
class DimensionResult:
    """Aggregated per-dimension result; never a total PASS (6.2.2)."""

    dimension: AssessmentDimension
    applicable: bool
    status: DimensionStatus
    reason_codes: tuple[str, ...] = ()
    checked_objects: int = 0
    unchecked_objects: int = 0
    detail: Optional[str] = None

    def __post_init__(self) -> None:
        _check_enum(self.dimension, AssessmentDimension, "DimensionResult.dimension")
        _check_bool(self.applicable, "DimensionResult.applicable")
        _check_dimension_status(self.dimension, self.status, "DimensionResult.status")
        if not isinstance(self.reason_codes, tuple):
            _fail("DimensionResult.reason_codes must be a tuple")
        previous: Optional[str] = None
        for code in self.reason_codes:
            _check_str(code, "DimensionResult.reason_code")
            if not _REASON_CODE_RE.match(code):
                _fail(f"DimensionResult.reason_code has unsupported form: {code!r}")
            if previous is not None and code <= previous:
                _fail("DimensionResult.reason_codes must be sorted and unique")
            previous = code
        _check_int(self.checked_objects, "DimensionResult.checked_objects")
        _check_int(self.unchecked_objects, "DimensionResult.unchecked_objects")
        if self.checked_objects < 0 or self.unchecked_objects < 0:
            _fail("DimensionResult object counts must be >= 0")
        if self.detail is not None:
            _check_str(self.detail, "DimensionResult.detail")

    def to_obj(self) -> dict[str, object]:
        return {
            "dimension": str(self.dimension.value),
            "applicable": self.applicable,
            "status": str(self.status.value),
            "reason_codes": list(self.reason_codes),
            "checked_objects": self.checked_objects,
            "unchecked_objects": self.unchecked_objects,
            "detail": self.detail,
        }


def _applicable_statuses(
    observations: Sequence[DimensionObservation], dimension: AssessmentDimension, enum_cls: type
) -> list:
    statuses: list = []
    for observation in observations:
        if not isinstance(observation, DimensionObservation):
            _fail("aggregate input must hold DimensionObservation items")
        if observation.dimension is not dimension or not observation.applicable:
            continue
        if isinstance(observation.status, enum_cls):
            statuses.append(observation.status)
    return statuses


def aggregate_structural(
    observations: Sequence[DimensionObservation],
) -> StructuralStatus:
    """CORRUPT > UNSUPPORTED > PARTIAL > COMPLETE (design 6.2.2).

    Nothing applicable is vacuously COMPLETE; the per-object observations stay
    authoritative and are not overwritten by this value.
    """
    statuses = _applicable_statuses(
        observations, AssessmentDimension.STRUCTURAL, StructuralStatus
    )
    for status in (StructuralStatus.CORRUPT, StructuralStatus.UNSUPPORTED, StructuralStatus.PARTIAL):
        if status in statuses:
            return status
    return StructuralStatus.COMPLETE


def aggregate_semantic(observations: Sequence[DimensionObservation]) -> SemanticStatus:
    """CONFLICT first; any applicable-unchecked object keeps NOT_RECOMPUTED.

    With zero applicable observations the honest aggregate is NOT_RECOMPUTED,
    never RECOMPUTED (nothing was recomputed).
    """
    statuses = _applicable_statuses(observations, AssessmentDimension.SEMANTIC, SemanticStatus)
    if SemanticStatus.CONFLICT in statuses:
        return SemanticStatus.CONFLICT
    if SemanticStatus.NOT_RECOMPUTED in statuses or not statuses:
        return SemanticStatus.NOT_RECOMPUTED
    return SemanticStatus.RECOMPUTED


def aggregate_provenance(observations: Sequence[DimensionObservation]) -> ProvenanceStatus:
    """CONFLICT first; missing independent observation keeps UNVERIFIED.

    With zero applicable observations the honest aggregate is UNVERIFIED,
    never CORROBORATED.
    """
    statuses = _applicable_statuses(observations, AssessmentDimension.PROVENANCE, ProvenanceStatus)
    if ProvenanceStatus.CONFLICT in statuses:
        return ProvenanceStatus.CONFLICT
    if ProvenanceStatus.UNVERIFIED in statuses or not statuses:
        return ProvenanceStatus.UNVERIFIED
    return ProvenanceStatus.CORROBORATED


def aggregate_safety(
    observations: Sequence[DimensionObservation],
) -> ExecutionSafetyStatus:
    """UNSAFE > UNKNOWN > CONFIRMED > NOT_APPLICABLE (design 6.2.2).

    NOT_APPLICABLE only when every input is non-applicable/NOT_APPLICABLE.
    """
    statuses = [
        status
        for status in _applicable_statuses(
            observations, AssessmentDimension.EXECUTION_SAFETY, ExecutionSafetyStatus
        )
        if status is not ExecutionSafetyStatus.NOT_APPLICABLE
    ]
    if ExecutionSafetyStatus.UNSAFE in statuses:
        return ExecutionSafetyStatus.UNSAFE
    if ExecutionSafetyStatus.UNKNOWN in statuses:
        return ExecutionSafetyStatus.UNKNOWN
    if ExecutionSafetyStatus.CONFIRMED in statuses:
        return ExecutionSafetyStatus.CONFIRMED
    return ExecutionSafetyStatus.NOT_APPLICABLE


@dataclass(frozen=True)
class EvidenceAssessment:
    """Four-dimension assessment record (design 6.2.2); no aggregate PASS."""

    structural: DimensionResult
    semantic: DimensionResult
    provenance: DimensionResult
    execution_safety: DimensionResult
    schema_version: int = DELIVERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "EvidenceAssessment.schema_version")
        if self.schema_version != DELIVERY_SCHEMA_VERSION:
            _fail(f"unsupported assessment schema_version {self.schema_version}")
        slots = (
            ("structural", AssessmentDimension.STRUCTURAL),
            ("semantic", AssessmentDimension.SEMANTIC),
            ("provenance", AssessmentDimension.PROVENANCE),
            ("execution_safety", AssessmentDimension.EXECUTION_SAFETY),
        )
        for name, dimension in slots:
            result = getattr(self, name)
            if not isinstance(result, DimensionResult):
                _fail(f"EvidenceAssessment.{name} must be a DimensionResult")
            if result.dimension is not dimension:
                _fail(f"EvidenceAssessment.{name} must carry the {dimension.value} dimension")

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "structural": self.structural.to_obj(),
            "semantic": self.semantic.to_obj(),
            "provenance": self.provenance.to_obj(),
            "execution_safety": self.execution_safety.to_obj(),
        }


# --------------------------------------------------------------------------
# Findings and reviews (design 6.2.1, 6.4.5)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingOccurrence:
    """One candidate observation bound to a real execution attempt (6.2.1).

    There is deliberately no ``confirmed_bug`` field: confirmation is only
    expressed by a ``FindingReview`` bound to the evidence digest.  A native
    format without an attempt identifier produces no occurrence record at all,
    so ``attempt_id`` is required.  ``recompute_status`` NOT_RECOMPUTED forbids
    a recomputed hash; RECOMPUTED/CONFLICT require one.
    """

    source_id: str
    attempt_id: str
    case_id: str
    recompute_status: SemanticStatus
    occurrence_id: str = ""
    comparison_hash: Optional[str] = None
    original_exact_signature: Optional[str] = None
    fingerprint: Optional[str] = None
    recomputed_comparison_hash: Optional[str] = None
    replay_ref: Optional[str] = None
    reduction_ref: Optional[str] = None
    synthetic: SyntheticKind = SyntheticKind.UNKNOWN

    def __post_init__(self) -> None:
        _check_source_id(self.source_id, "FindingOccurrence.source_id")
        _check_non_empty(self.attempt_id, "FindingOccurrence.attempt_id", MAX_REVIEW_ID_CHARS)
        _check_hex64(self.case_id, "FindingOccurrence.case_id")
        _check_enum(
            self.recompute_status, SemanticStatus, "FindingOccurrence.recompute_status"
        )
        if self.comparison_hash is not None:
            _check_hex64(self.comparison_hash, "FindingOccurrence.comparison_hash")
        for name in ("original_exact_signature", "fingerprint"):
            value = getattr(self, name)
            if value is not None:
                _check_hex64(value, f"FindingOccurrence.{name}")
        if self.recomputed_comparison_hash is not None:
            _check_hex64(
                self.recomputed_comparison_hash, "FindingOccurrence.recomputed_comparison_hash"
            )
        if self.recompute_status is SemanticStatus.NOT_RECOMPUTED:
            if self.recomputed_comparison_hash is not None:
                _fail(
                    "FindingOccurrence NOT_RECOMPUTED must not carry a "
                    "recomputed_comparison_hash"
                )
        elif self.recomputed_comparison_hash is None:
            _fail(
                f"FindingOccurrence {self.recompute_status} requires a "
                "recomputed_comparison_hash"
            )
        for name in ("replay_ref", "reduction_ref"):
            value = getattr(self, name)
            if value is not None:
                check_package_path(value, f"FindingOccurrence.{name}")
        _check_enum(self.synthetic, SyntheticKind, "FindingOccurrence.synthetic")
        derived = compute_occurrence_id(self.source_id, self.attempt_id, self.case_id)
        if self.occurrence_id == "":
            object.__setattr__(self, "occurrence_id", derived)
        elif self.occurrence_id != derived:
            _fail(
                f"FindingOccurrence.occurrence_id {self.occurrence_id!r} does not match "
                f"the source/attempt/case identity hash {derived}"
            )
        _check_hex64(self.occurrence_id, "FindingOccurrence.occurrence_id")

    def to_obj(self) -> dict[str, object]:
        return {
            "occurrence_id": self.occurrence_id,
            "source_id": self.source_id,
            "attempt_id": self.attempt_id,
            "case_id": self.case_id,
            "comparison_hash": self.comparison_hash,
            "original_exact_signature": self.original_exact_signature,
            "fingerprint": self.fingerprint,
            "recompute_status": str(self.recompute_status.value),
            "recomputed_comparison_hash": self.recomputed_comparison_hash,
            "replay_ref": self.replay_ref,
            "reduction_ref": self.reduction_ref,
            "synthetic": str(self.synthetic.value),
        }


@dataclass(frozen=True)
class FindingReview:
    """Independent human review; never overwrites the observation (6.4.5).

    ``evidence_digest`` is the delivery_id this review binds to; reviews
    facing a different snapshot are shown as history only.  ``reviewer`` is a
    human declaration, not an authenticated identity.  ``supersedes`` must
    differ from ``review_id``; cycle/dangling checks belong to the review
    validator.
    """

    review_id: str
    reviewer: str
    reviewed_at: str
    evidence_digest: str
    occurrence_ids: tuple[str, ...]
    decision: ReviewDecision
    reason: str
    issue_url: Optional[str] = None
    supersedes: Optional[str] = None
    schema_version: int = REVIEW_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "FindingReview.schema_version")
        if self.schema_version != REVIEW_SCHEMA_VERSION:
            _fail(f"unsupported review schema_version {self.schema_version}")
        _check_non_empty(self.review_id, "FindingReview.review_id", MAX_REVIEW_ID_CHARS)
        _check_non_empty(self.reviewer, "FindingReview.reviewer", MAX_REVIEW_ID_CHARS)
        _check_non_empty(self.reviewed_at, "FindingReview.reviewed_at", 64)
        if not _TIMESTAMP_RE.match(self.reviewed_at):
            _fail(f"FindingReview.reviewed_at is not an ISO-8601 timestamp: {self.reviewed_at!r}")
        _check_hex64(self.evidence_digest, "FindingReview.evidence_digest")
        if not isinstance(self.occurrence_ids, tuple) or not self.occurrence_ids:
            _fail("FindingReview.occurrence_ids must be a non-empty tuple")
        _check_sorted_unique(
            self.occurrence_ids, "FindingReview.occurrence_ids", _check_hex64
        )
        _check_enum(self.decision, ReviewDecision, "FindingReview.decision")
        _check_non_empty(self.reason, "FindingReview.reason", 4096)
        if self.issue_url is not None:
            url = _check_str(self.issue_url, "FindingReview.issue_url")
            if not url.startswith("https://") or len(url) <= len("https://"):
                _fail(f"FindingReview.issue_url must be an https URL, got {url!r}")
            if any(char.isspace() for char in url):
                _fail("FindingReview.issue_url must not contain whitespace")
        if self.supersedes is not None:
            _check_non_empty(self.supersedes, "FindingReview.supersedes", MAX_REVIEW_ID_CHARS)
            if self.supersedes == self.review_id:
                _fail("FindingReview.supersedes must differ from review_id")

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "review_id": self.review_id,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
            "evidence_digest": self.evidence_digest,
            "occurrence_ids": list(self.occurrence_ids),
            "decision": str(self.decision.value),
            "reason": self.reason,
            "issue_url": self.issue_url,
            "supersedes": self.supersedes,
        }


# --------------------------------------------------------------------------
# Export models (design 6.2.3, 6.4.6)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RelationAssertion:
    """Typed relation assertion saved as expected.json content (6.4.6).

    ``spec`` carries the serialized canonical assertion JSON (bounded, but
    lossless); the historical mismatch itself is never turned into the
    expected truth here.
    """

    mode: RelationAssertionMode
    columns: tuple[str, ...]
    spec: str

    def __post_init__(self) -> None:
        _check_enum(self.mode, RelationAssertionMode, "RelationAssertion.mode")
        if not isinstance(self.columns, tuple) or not self.columns:
            _fail("RelationAssertion.columns must be a non-empty tuple")
        previous: Optional[str] = None
        for column in self.columns:
            _check_non_empty(column, "RelationAssertion.column", MAX_REASON_CODE_CHARS)
            if not _OBJECT_REF_RE.match(column):
                _fail(f"RelationAssertion.column has unsupported form: {column!r}")
            if previous is not None and column <= previous:
                _fail("RelationAssertion.columns must be sorted and unique")
            previous = column
        _check_non_empty(self.spec, "RelationAssertion.spec", MAX_RELATION_SPEC_CHARS)

    def to_obj(self) -> dict[str, object]:
        return {"mode": str(self.mode.value), "columns": list(self.columns), "spec": self.spec}


@dataclass(frozen=True)
class RegressionCase:
    """Regression sample identity and assertion contract (6.4.6, schema=1)."""

    case_document_hash: str
    renderer_id: str
    renderer_version: str
    codec_id: str
    codec_version: str
    relation_assertion: RelationAssertion
    source_inventory_hash: str
    synthetic: SyntheticKind
    rule_definition_hash: Optional[str] = None
    review_ref: Optional[str] = None
    known_bad_build: Optional[str] = None
    fixed_build: Optional[str] = None
    schema_version: int = EXPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "RegressionCase.schema_version")
        if self.schema_version != EXPORT_SCHEMA_VERSION:
            _fail(f"unsupported regression-case schema_version {self.schema_version}")
        _check_hex64(self.case_document_hash, "RegressionCase.case_document_hash")
        for name in ("renderer_id", "codec_id"):
            value = _check_non_empty(getattr(self, name), f"RegressionCase.{name}", 16)
            if not _SEMVER_ID_RE.match(value):
                _fail(f"RegressionCase.{name} has unsupported form: {value!r}")
        for name in ("renderer_version", "codec_version"):
            value = _check_non_empty(getattr(self, name), f"RegressionCase.{name}", 32)
            if not _SEMVER_VERSION_RE.match(value):
                _fail(f"RegressionCase.{name} has unsupported form: {value!r}")
        if not isinstance(self.relation_assertion, RelationAssertion):
            _fail("RegressionCase.relation_assertion must be a RelationAssertion")
        _check_hex64(self.source_inventory_hash, "RegressionCase.source_inventory_hash")
        _check_enum(self.synthetic, SyntheticKind, "RegressionCase.synthetic")
        if self.rule_definition_hash is not None:
            _check_hex64(self.rule_definition_hash, "RegressionCase.rule_definition_hash")
        if self.review_ref is not None:
            _check_non_empty(self.review_ref, "RegressionCase.review_ref", MAX_REVIEW_ID_CHARS)
        for name in ("known_bad_build", "fixed_build"):
            value = getattr(self, name)
            if value is not None:
                _check_version_text(value, f"RegressionCase.{name}")

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "case_document_hash": self.case_document_hash,
            "rule_definition_hash": self.rule_definition_hash,
            "renderer_id": self.renderer_id,
            "renderer_version": self.renderer_version,
            "codec_id": self.codec_id,
            "codec_version": self.codec_version,
            "relation_assertion": self.relation_assertion.to_obj(),
            "source_inventory_hash": self.source_inventory_hash,
            "review_ref": self.review_ref,
            "synthetic": str(self.synthetic.value),
            "known_bad_build": self.known_bad_build,
            "fixed_build": self.fixed_build,
        }


@dataclass(frozen=True)
class ExportManifest:
    """Sealed SQL/regression export manifest (6.2.3, schema=1, kind=sql/regression).

    The manifest file itself is ``delivery-manifest.json`` and never listed in
    ``files``.  A regression export requires a ``review_ref`` (design 6.3:
    regression 必须有对应人工 review); a plain SQL debug export may leave it
    None.  ``limitations`` is a sorted tuple of stable short codes.
    """

    export_id: str
    format: ExportFormat
    source_delivery_id: str
    selected_case_id: str
    name_map: NameMap
    files: tuple[EvidenceFile, ...]
    completion: DeliveryCompletion
    limitations: tuple[str, ...] = ()
    selected_occurrence_id: Optional[str] = None
    review_ref: Optional[str] = None
    schema_version: int = EXPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "ExportManifest.schema_version")
        if self.schema_version != EXPORT_SCHEMA_VERSION:
            _fail(f"unsupported export schema_version {self.schema_version}")
        _check_hex64(self.export_id, "ExportManifest.export_id")
        _check_enum(self.format, ExportFormat, "ExportManifest.format")
        _check_hex64(self.source_delivery_id, "ExportManifest.source_delivery_id")
        _check_hex64(self.selected_case_id, "ExportManifest.selected_case_id")
        if self.selected_occurrence_id is not None:
            _check_hex64(
                self.selected_occurrence_id, "ExportManifest.selected_occurrence_id"
            )
        if not isinstance(self.name_map, NameMap):
            _fail("ExportManifest.name_map must be a NameMap")
        if not isinstance(self.files, tuple):
            _fail("ExportManifest.files must be a tuple")
        previous_path: Optional[str] = None
        for file_entry in self.files:
            if not isinstance(file_entry, EvidenceFile):
                _fail("ExportManifest.files must hold EvidenceFile items")
            if previous_path is not None and file_entry.path <= previous_path:
                _fail("ExportManifest.files must be sorted by unique path")
            previous_path = file_entry.path
            if file_entry.path in (EXPORT_MANIFEST_FILENAME, MANIFEST_FILENAME):
                _fail("ExportManifest.files must not list a manifest file")
        _check_enum(self.completion, DeliveryCompletion, "ExportManifest.completion")
        if not isinstance(self.limitations, tuple):
            _fail("ExportManifest.limitations must be a tuple")
        previous: Optional[str] = None
        for limitation in self.limitations:
            _check_str(limitation, "ExportManifest.limitation")
            if not _LIMITATION_RE.match(limitation):
                _fail(f"ExportManifest.limitation has unsupported form: {limitation!r}")
            if previous is not None and limitation <= previous:
                _fail("ExportManifest.limitations must be sorted and unique")
            previous = limitation
        if self.review_ref is not None:
            _check_non_empty(self.review_ref, "ExportManifest.review_ref", MAX_REVIEW_ID_CHARS)
        if self.format is ExportFormat.REGRESSION and self.review_ref is None:
            _fail("ExportManifest regression format requires a review_ref")

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "export_id": self.export_id,
            "format": str(self.format.value),
            "source_delivery_id": self.source_delivery_id,
            "selected_case_id": self.selected_case_id,
            "selected_occurrence_id": self.selected_occurrence_id,
            "review_ref": self.review_ref,
            "name_map": self.name_map.to_obj(),
            "files": [file_entry.to_obj() for file_entry in self.files],
            "limitations": list(self.limitations),
            "completion": str(self.completion.value),
        }


# --------------------------------------------------------------------------
# Strict decoding (loader path; mirrors contracts/codec.py helpers)
# --------------------------------------------------------------------------


def decode_producer_info(obj: object, what: str = "producer info") -> ProducerInfo:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"name", "version", "revision", "dirty"}, what)
    version = obj.get("version")
    revision = obj.get("revision")
    dirty = obj.get("dirty")
    if version is not None:
        _as_str(version, f"{what}.version")
    if revision is not None:
        _as_str(revision, f"{what}.revision")
    if dirty is not None:
        _as_bool(dirty, f"{what}.dirty")
    return ProducerInfo(
        name=_as_str(_field(obj, "name", what), f"{what}.name"),
        version=version,
        revision=revision,
        dirty=dirty,
    )


_LIMIT_INT_FIELDS = (
    "max_single_source_file_bytes",
    "max_total_source_bytes",
    "max_json_document_bytes",
    "max_files",
    "max_jsonl_line_bytes",
    "max_dir_depth",
    "max_path_bytes",
    "max_output_single_file_bytes",
    "max_output_total_bytes",
    "max_html_bytes",
    "max_markdown_bytes",
    "min_diagnostic_reserve_bytes",
)


def decode_limits(obj: object, what: str = "limits") -> Limits:
    obj = _expect_dict(obj, what)
    allowed = set(_LIMIT_INT_FIELDS) | {"time_budget_seconds"}
    _no_extra(obj, allowed, what)
    kwargs: dict[str, object] = {
        name: _as_int(_field(obj, name, what), f"{what}.{name}")
        for name in _LIMIT_INT_FIELDS
    }
    seconds = _field(obj, "time_budget_seconds", what)
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        _fail(f"{what}.time_budget_seconds must be a JSON integer (whole seconds)")
    kwargs["time_budget_seconds"] = seconds
    return Limits(**kwargs)  # type: ignore[arg-type]


def decode_evidence_file(obj: object, what: str = "evidence file") -> EvidenceFile:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"path", "role", "size_bytes", "sha256", "source_id"}, what)
    return EvidenceFile(
        path=_as_str(_field(obj, "path", what), f"{what}.path"),
        role=_as_enum(FileRole, _field(obj, "role", what), f"{what}.role"),
        size_bytes=_as_int(_field(obj, "size_bytes", what), f"{what}.size_bytes"),
        sha256=_as_str(_field(obj, "sha256", what), f"{what}.sha256"),
        source_id=obj.get("source_id"),
    )


def decode_native_version_component(
    obj: object, what: str = "native version component"
) -> NativeVersionComponent:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"kind_field", "value"}, what)
    return NativeVersionComponent(
        kind_field=_as_str(_field(obj, "kind_field", what), f"{what}.kind_field"),
        value=_as_str(_field(obj, "value", what), f"{what}.value"),
    )


def decode_source_descriptor(obj: object, what: str = "source descriptor") -> SourceDescriptor:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "source_id",
            "native_kind",
            "native_versions",
            "root_document",
            "observed_writer_version",
            "source_commit",
            "producer",
            "synthetic",
            "snapshot_digest",
            "missing_files",
            "collection_status",
        },
        what,
    )
    producer_obj = obj.get("producer")
    return SourceDescriptor(
        source_id=_as_str(_field(obj, "source_id", what), f"{what}.source_id"),
        native_kind=_as_enum(NativeKind, _field(obj, "native_kind", what), f"{what}.native_kind"),
        root_document=_as_str(_field(obj, "root_document", what), f"{what}.root_document"),
        snapshot_digest=_as_str(
            _field(obj, "snapshot_digest", what), f"{what}.snapshot_digest"
        ),
        synthetic=_as_enum(SyntheticKind, _field(obj, "synthetic", what), f"{what}.synthetic"),
        collection_status=_as_enum(
            CollectionStatus, _field(obj, "collection_status", what), f"{what}.collection_status"
        ),
        native_versions=tuple(
            decode_native_version_component(item, f"{what}.native_versions[{index}]")
            for index, item in enumerate(
                _as_list(_field(obj, "native_versions", what), f"{what}.native_versions")
            )
        ),
        observed_writer_version=obj.get("observed_writer_version"),
        source_commit=obj.get("source_commit"),
        producer=None if producer_obj is None else decode_producer_info(producer_obj, f"{what}.producer"),
        missing_files=tuple(
            _as_str(item, f"{what}.missing_files[{index}]")
            for index, item in enumerate(
                _as_list(_field(obj, "missing_files", what), f"{what}.missing_files")
            )
        ),
    )


def decode_evidence_manifest(obj: object, what: str = "evidence manifest") -> EvidenceManifest:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "schema_version",
            "delivery_id",
            "kind",
            "writer_version",
            "producer",
            "sources",
            "files",
            "assessment_ref",
            "completion",
        },
        what,
    )
    version = _as_int(_field(obj, "schema_version", what), f"{what}.schema_version")
    if version != DELIVERY_SCHEMA_VERSION:
        _fail(f"{what} has unsupported schema_version {version}")
    producer_obj = obj.get("producer")
    return EvidenceManifest(
        schema_version=version,
        delivery_id=_as_str(_field(obj, "delivery_id", what), f"{what}.delivery_id"),
        kind=_as_enum(DeliveryKind, _field(obj, "kind", what), f"{what}.kind"),
        writer_version=_as_str(_field(obj, "writer_version", what), f"{what}.writer_version"),
        producer=None if producer_obj is None else decode_producer_info(producer_obj, f"{what}.producer"),
        sources=tuple(
            decode_source_descriptor(item, f"{what}.sources[{index}]")
            for index, item in enumerate(
                _as_list(_field(obj, "sources", what), f"{what}.sources")
            )
        ),
        files=tuple(
            decode_evidence_file(item, f"{what}.files[{index}]")
            for index, item in enumerate(_as_list(_field(obj, "files", what), f"{what}.files"))
        ),
        assessment_ref=_as_str(
            _field(obj, "assessment_ref", what), f"{what}.assessment_ref"
        ),
        completion=_as_enum(
            DeliveryCompletion, _field(obj, "completion", what), f"{what}.completion"
        ),
    )


def decode_dimension_observation(
    obj: object, what: str = "dimension observation"
) -> DimensionObservation:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"dimension", "applicable", "status", "object_ref"}, what)
    dimension = _as_enum(
        AssessmentDimension, _field(obj, "dimension", what), f"{what}.dimension"
    )
    status_value = _field(obj, "status", what)
    if not isinstance(status_value, str):
        _fail(f"{what}.status must be a JSON string")
    status: object = None
    for enum_cls in _DIMENSION_STATUS_ENUMS[dimension]:
        try:
            status = enum_cls(status_value)
            break
        except ValueError:
            continue
    if status is None:
        _fail(f"{what}.status has unknown value {status_value!r}")
    return DimensionObservation(
        dimension=dimension,
        applicable=_as_bool(_field(obj, "applicable", what), f"{what}.applicable"),
        status=status,  # type: ignore[arg-type]
        object_ref=obj.get("object_ref"),
    )


def decode_dimension_result(
    obj: object, what: str = "dimension result"
) -> DimensionResult:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "dimension",
            "applicable",
            "status",
            "reason_codes",
            "checked_objects",
            "unchecked_objects",
            "detail",
        },
        what,
    )
    dimension = _as_enum(
        AssessmentDimension, _field(obj, "dimension", what), f"{what}.dimension"
    )
    status_value = _field(obj, "status", what)
    if not isinstance(status_value, str):
        _fail(f"{what}.status must be a JSON string")
    status: object = None
    for enum_cls in _DIMENSION_STATUS_ENUMS[dimension]:
        try:
            status = enum_cls(status_value)
            break
        except ValueError:
            continue
    if status is None:
        _fail(f"{what}.status has unknown value {status_value!r}")
    detail = obj.get("detail")
    if detail is not None:
        _as_str(detail, f"{what}.detail")
    return DimensionResult(
        dimension=dimension,
        applicable=_as_bool(_field(obj, "applicable", what), f"{what}.applicable"),
        status=status,  # type: ignore[arg-type]
        reason_codes=tuple(
            _as_str(code, f"{what}.reason_codes[{index}]")
            for index, code in enumerate(
                _as_list(_field(obj, "reason_codes", what), f"{what}.reason_codes")
            )
        ),
        checked_objects=_as_int(
            _field(obj, "checked_objects", what), f"{what}.checked_objects"
        ),
        unchecked_objects=_as_int(
            _field(obj, "unchecked_objects", what), f"{what}.unchecked_objects"
        ),
        detail=detail,
    )


def decode_evidence_assessment(obj: object, what: str = "evidence assessment") -> EvidenceAssessment:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {"schema_version", "structural", "semantic", "provenance", "execution_safety"},
        what,
    )
    version = _as_int(_field(obj, "schema_version", what), f"{what}.schema_version")
    if version != DELIVERY_SCHEMA_VERSION:
        _fail(f"{what} has unsupported schema_version {version}")
    return EvidenceAssessment(
        schema_version=version,
        structural=decode_dimension_result(obj["structural"], f"{what}.structural"),
        semantic=decode_dimension_result(obj["semantic"], f"{what}.semantic"),
        provenance=decode_dimension_result(obj["provenance"], f"{what}.provenance"),
        execution_safety=decode_dimension_result(
            obj["execution_safety"], f"{what}.execution_safety"
        ),
    )


def decode_finding_occurrence(obj: object, what: str = "finding occurrence") -> FindingOccurrence:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "occurrence_id",
            "source_id",
            "attempt_id",
            "case_id",
            "comparison_hash",
            "original_exact_signature",
            "fingerprint",
            "recompute_status",
            "recomputed_comparison_hash",
            "replay_ref",
            "reduction_ref",
            "synthetic",
        },
        what,
    )
    for name in (
        "comparison_hash",
        "original_exact_signature",
        "fingerprint",
        "recomputed_comparison_hash",
        "replay_ref",
        "reduction_ref",
    ):
        value = obj.get(name)
        if value is not None:
            _as_str(value, f"{what}.{name}")
    return FindingOccurrence(
        occurrence_id=_as_str(_field(obj, "occurrence_id", what), f"{what}.occurrence_id"),
        source_id=_as_str(_field(obj, "source_id", what), f"{what}.source_id"),
        attempt_id=_as_str(_field(obj, "attempt_id", what), f"{what}.attempt_id"),
        case_id=_as_str(_field(obj, "case_id", what), f"{what}.case_id"),
        comparison_hash=obj.get("comparison_hash"),
        original_exact_signature=obj.get("original_exact_signature"),
        fingerprint=obj.get("fingerprint"),
        recompute_status=_as_enum(
            SemanticStatus, _field(obj, "recompute_status", what), f"{what}.recompute_status"
        ),
        recomputed_comparison_hash=obj.get("recomputed_comparison_hash"),
        replay_ref=obj.get("replay_ref"),
        reduction_ref=obj.get("reduction_ref"),
        synthetic=_as_enum(
            SyntheticKind, _field(obj, "synthetic", what), f"{what}.synthetic"
        ),
    )


def decode_finding_review(obj: object, what: str = "finding review") -> FindingReview:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "schema_version",
            "review_id",
            "reviewer",
            "reviewed_at",
            "evidence_digest",
            "occurrence_ids",
            "decision",
            "reason",
            "issue_url",
            "supersedes",
        },
        what,
    )
    version = _as_int(_field(obj, "schema_version", what), f"{what}.schema_version")
    if version != REVIEW_SCHEMA_VERSION:
        _fail(f"{what} has unsupported schema_version {version}")
    issue_url = obj.get("issue_url")
    if issue_url is not None:
        _as_str(issue_url, f"{what}.issue_url")
    supersedes = obj.get("supersedes")
    if supersedes is not None:
        _as_str(supersedes, f"{what}.supersedes")
    return FindingReview(
        schema_version=version,
        review_id=_as_str(_field(obj, "review_id", what), f"{what}.review_id"),
        reviewer=_as_str(_field(obj, "reviewer", what), f"{what}.reviewer"),
        reviewed_at=_as_str(_field(obj, "reviewed_at", what), f"{what}.reviewed_at"),
        evidence_digest=_as_str(
            _field(obj, "evidence_digest", what), f"{what}.evidence_digest"
        ),
        occurrence_ids=tuple(
            _as_str(item, f"{what}.occurrence_ids[{index}]")
            for index, item in enumerate(
                _as_list(_field(obj, "occurrence_ids", what), f"{what}.occurrence_ids")
            )
        ),
        decision=_as_enum(ReviewDecision, _field(obj, "decision", what), f"{what}.decision"),
        reason=_as_str(_field(obj, "reason", what), f"{what}.reason"),
        issue_url=issue_url,
        supersedes=supersedes,
    )


def decode_relation_assertion(obj: object, what: str = "relation assertion") -> RelationAssertion:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"mode", "columns", "spec"}, what)
    return RelationAssertion(
        mode=_as_enum(
            RelationAssertionMode, _field(obj, "mode", what), f"{what}.mode"
        ),
        columns=tuple(
            _as_str(column, f"{what}.columns[{index}]")
            for index, column in enumerate(
                _as_list(_field(obj, "columns", what), f"{what}.columns")
            )
        ),
        spec=_as_str(_field(obj, "spec", what), f"{what}.spec"),
    )


def decode_regression_case(obj: object, what: str = "regression case") -> RegressionCase:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "schema_version",
            "case_document_hash",
            "rule_definition_hash",
            "renderer_id",
            "renderer_version",
            "codec_id",
            "codec_version",
            "relation_assertion",
            "source_inventory_hash",
            "review_ref",
            "synthetic",
            "known_bad_build",
            "fixed_build",
        },
        what,
    )
    version = _as_int(_field(obj, "schema_version", what), f"{what}.schema_version")
    if version != EXPORT_SCHEMA_VERSION:
        _fail(f"{what} has unsupported schema_version {version}")
    for name in (
        "rule_definition_hash",
        "review_ref",
        "known_bad_build",
        "fixed_build",
    ):
        value = obj.get(name)
        if value is not None:
            _as_str(value, f"{what}.{name}")
    return RegressionCase(
        schema_version=version,
        case_document_hash=_as_str(
            _field(obj, "case_document_hash", what), f"{what}.case_document_hash"
        ),
        rule_definition_hash=obj.get("rule_definition_hash"),
        renderer_id=_as_str(_field(obj, "renderer_id", what), f"{what}.renderer_id"),
        renderer_version=_as_str(
            _field(obj, "renderer_version", what), f"{what}.renderer_version"
        ),
        codec_id=_as_str(_field(obj, "codec_id", what), f"{what}.codec_id"),
        codec_version=_as_str(_field(obj, "codec_version", what), f"{what}.codec_version"),
        relation_assertion=decode_relation_assertion(
            _field(obj, "relation_assertion", what), f"{what}.relation_assertion"
        ),
        source_inventory_hash=_as_str(
            _field(obj, "source_inventory_hash", what), f"{what}.source_inventory_hash"
        ),
        review_ref=obj.get("review_ref"),
        synthetic=_as_enum(SyntheticKind, _field(obj, "synthetic", what), f"{what}.synthetic"),
        known_bad_build=obj.get("known_bad_build"),
        fixed_build=obj.get("fixed_build"),
    )


def decode_export_manifest(obj: object, what: str = "export manifest") -> ExportManifest:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "schema_version",
            "export_id",
            "format",
            "source_delivery_id",
            "selected_case_id",
            "selected_occurrence_id",
            "review_ref",
            "name_map",
            "files",
            "limitations",
            "completion",
        },
        what,
    )
    version = _as_int(_field(obj, "schema_version", what), f"{what}.schema_version")
    if version != EXPORT_SCHEMA_VERSION:
        _fail(f"{what} has unsupported schema_version {version}")
    selected_occurrence_id = obj.get("selected_occurrence_id")
    if selected_occurrence_id is not None:
        _as_str(selected_occurrence_id, f"{what}.selected_occurrence_id")
    review_ref = obj.get("review_ref")
    if review_ref is not None:
        _as_str(review_ref, f"{what}.review_ref")
    return ExportManifest(
        schema_version=version,
        export_id=_as_str(_field(obj, "export_id", what), f"{what}.export_id"),
        format=_as_enum(ExportFormat, _field(obj, "format", what), f"{what}.format"),
        source_delivery_id=_as_str(
            _field(obj, "source_delivery_id", what), f"{what}.source_delivery_id"
        ),
        selected_case_id=_as_str(
            _field(obj, "selected_case_id", what), f"{what}.selected_case_id"
        ),
        selected_occurrence_id=selected_occurrence_id,
        review_ref=review_ref,
        name_map=decode_name_map(_field(obj, "name_map", what), f"{what}.name_map"),
        files=tuple(
            decode_evidence_file(item, f"{what}.files[{index}]")
            for index, item in enumerate(_as_list(_field(obj, "files", what), f"{what}.files"))
        ),
        limitations=tuple(
            _as_str(limitation, f"{what}.limitations[{index}]")
            for index, limitation in enumerate(
                _as_list(_field(obj, "limitations", what), f"{what}.limitations")
            )
        ),
        completion=_as_enum(
            DeliveryCompletion, _field(obj, "completion", what), f"{what}.completion"
        ),
    )
