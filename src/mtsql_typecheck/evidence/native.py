"""Native evidence-format detection and bounded closure enumeration (D4).

Implements design 6.4.2 (格式 Adapter 与完整性) and 6.3 (``--input-kind``)
for Phase 1: given one native evidence root (D1 generation bundle, D3 run
output, D2 replay/reduction trace, standalone attempt directory or an
existing D4 delivery package), detect the format from root markers and
enumerate the *file closure* that a snapshot must copy, plus the files
present in the tree but outside the closure (orphans, recorded and never
copied).

Boundaries encoded here (design 6.4.1/6.4.2/6.5):

- Detection only inspects root-level marker names with ``os.lstat`` (symlink
  markers are not regular files and therefore not markers); every byte read
  goes through the caller's :class:`~mtsql_typecheck.evidence.reader
  .SourceReader`, which owns path safety, size caps and the deadline.
- Root documents are read with ``reader.read_bytes(max_bytes=
  limits.max_json_document_bytes)``, parsed with
  ``contracts.codec.parse_strict_json`` and decoded with the *matching
  strict typed codec* (``decode_generation_manifest``,
  ``decode_runner_manifest``, ``decode_replay_result`` /
  ``decode_reduction_result``, ``decode_evidence_manifest``).  Version
  checks stay in those codecs; no generic loader is substituted.
- Enumeration lists what SHOULD be read.  A closure member missing on disk
  is NOT an enumeration error: the snapshot records it in
  ``missing_paths`` (design 6.4.1 step 3).
- A run root without ``runner-manifest.json`` (only reachable via
  ``kind_hint="run"``) gets a limited known-file scan and the stable
  diagnostic code ``"missing_root_manifest"``; requested counts are never
  inferred from directory sizes (design 6.4.2).
- Orphan files are recorded in ``SourcePlan.orphan_files`` and never copied
  (design 6.6: raw keeps the native closure only).
- Producer metadata (design 6.5.1) is only taken from explicitly present
  fields; a missing field is never inferred and never an error.
  ``SourcePlan.producer`` stays ``None`` unless the native root document
  carries a ``producer`` object - which no current schema=1 native codec
  accepts, so this is a forward-compatibility path only.  The observed
  writer version / source commit are mapped solely from documented native
  fields (``generation-manifest.json`` ``generator.version``,
  ``runner-manifest.json`` ``tool_version``, D4 ``writer_version``); the
  source commit is ``None`` everywhere because no ad11f11 native format
  records one, and D4 never fills it from its own HEAD.
- Traces: the full-evidence format marker ``typecheck-full-evidence-v1``
  is verified from SNAPSHOT/START inline payloads when present (bounded
  line scan); a legacy trace without the marker still enumerates as
  ``NativeKind.TRACE`` with empty ``native_versions`` (legacy display
  only).  No dynamic code execution, no pickle, no import of user files.

Enumeration bounds: the tree walk and the closure are bounded by
``limits.max_files`` (the reader's ``walk`` raises past ``max_entries``);
per-file read caps are carried on each :class:`PlannedFile` and enforced by
the reader/snapshot at read time.  The deadline is owned by the reader,
which the caller constructs with the limits and the deadline; enumeration
itself only loops over bounded lists and performs no clock checks of its
own (documented decision, design 6.5: "不宣称可以强制中断内核中阻塞的本地 I/O").

Unknown directories: ``detect_native_kind`` returns
``NativeKind.UNKNOWN`` for a directory without markers; ``enumerate_source``
refuses ``NativeKind.UNKNOWN`` with :class:`RootDetectionError` (documented
choice: one refusal point, at enumeration time).
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from ..contracts.case import ContractError
from ..contracts.codec import (
    decode_generation_manifest,
    parse_strict_json,
)
from ..contracts.delivery import (
    MANIFEST_FILENAME,
    Limits,
    NativeKind,
    NativeVersionComponent,
    ProducerInfo,
    check_package_path,
    decode_evidence_manifest,
    decode_producer_info,
)
from ..contracts.oracle import (
    EVIDENCE_PROFILE_FULL,
    TRACE_RECORD_KINDS,
    decode_artifact_ref,
    decode_replay_result,
    decode_reduction_result,
)
from ..contracts.runner import decode_runner_manifest
from ..generation.bundle import (
    CASES_DIRNAME,
    CASE_DOC_NAME,
    MANIFEST_NAME as GENERATION_MANIFEST_NAME,
    PREVIEW_A_NAME,
    PREVIEW_B_NAME,
    PROFILE_NAME,
    STATIC_CHECK_NAME,
)
from ..reduction.trace import FILES_DIR_NAME, TRACE_FILE_NAME
from ..runner.evidence import (
    ATTEMPTS_DIRNAME,
    ATTEMPT_FILE_NAMES,
    ENVIRONMENT_NAME,
    MANIFEST_NAME as RUN_MANIFEST_NAME,
    PAYLOADS_DIRNAME,
)
from ..runner.ownership import OWNERSHIP_JOURNAL_FILE_NAME

if TYPE_CHECKING:  # pragma: no cover - imported for type hints only
    from .reader import SourceReader

# The reader module is delivered in parallel within Phase 1; native.py is
# importable and fully testable against duck-typed readers before it lands.
try:  # pragma: no cover - exercised only once reader.py exists
    from .reader import (
        BudgetExhaustedError,
        EvidenceReadError,
        MissingEntryError,
        ReadLimitExceededError,
        SourceChangedError,
        UnsafePathError,
    )
except ImportError:  # pragma: no cover - reader integration fallback
    class EvidenceReadError(Exception):
        """Fallback base while reader.py has not landed (pinned API)."""

    class UnsafePathError(EvidenceReadError):
        """Fallback alias (pinned API)."""

    class MissingEntryError(EvidenceReadError):
        """Fallback alias (pinned API)."""

    class ReadLimitExceededError(EvidenceReadError):
        """Fallback alias (pinned API)."""

    class SourceChangedError(EvidenceReadError):
        """Fallback alias (pinned API)."""

    class BudgetExhaustedError(EvidenceReadError):
        """Fallback alias (pinned API)."""


__all__ = [
    "TEXT_FILE_CAP_BYTES",
    "BudgetExhaustedError",
    "EvidenceReadError",
    "MissingEntryError",
    "ReadLimitExceededError",
    "RootDetectionError",
    "SourceChangedError",
    "SourcePlan",
    "PlannedFile",
    "UnsafePathError",
    "detect_native_kind",
    "enumerate_source",
]


class RootDetectionError(EvidenceReadError):
    """Unknown root, conflicting mutually-exclusive root markers, or a
    ``kind_hint`` that contradicts the markers present (design 6.3)."""


# Cap class for non-JSON/JSONL text closure members (preview SQL, markdown):
# design 6.5 bounds every read; 64 KiB covers the ad11f11 SQL/MD outputs.
TEXT_FILE_CAP_BYTES = 64 * 1024

_ATTEMPT_REQUIRED_FILE_NAMES = (
    "request.json",
    "expectation.json",
    "execution-evidence.json",
    "comparison.json",
)
_ATTEMPT_OPTIONAL_FILE_NAMES = tuple(
    sorted(ATTEMPT_FILE_NAMES.difference(_ATTEMPT_REQUIRED_FILE_NAMES))
)

# Diagnostic codes carried on SourcePlan.diagnostics (stable short codes).
DIAGNOSTIC_MISSING_ROOT_MANIFEST = "missing_root_manifest"
DIAGNOSTIC_CORRUPT_ROOT_DOCUMENT = "corrupt_root_document"

_HINT_VALUES = {
    NativeKind.GENERATION.value: NativeKind.GENERATION,
    NativeKind.RUN.value: NativeKind.RUN,
    NativeKind.TRACE.value: NativeKind.TRACE,
    NativeKind.ATTEMPT.value: NativeKind.ATTEMPT,
    NativeKind.DELIVERY.value: NativeKind.DELIVERY,
}

_DELIVERY_MANIFEST_NAME = MANIFEST_FILENAME
_ASSESSMENT_NAME = "assessment.json"
_REPORT_JSON_NAME = "report.json"
_REPORT_MD_NAME = "report.md"
_REPORT_HTML_NAME = "report.html"
_REVIEWS_DIRNAME = "reviews"

# RunnerManifest contract_versions names -> NATIVE_VERSION_KEYS (design
# 6.4.2: fixed schema/codec identifiers; the runner's oracle version gates
# replay, so it maps onto replay_schema).  Missing fields are not errors.
_RUNNER_CONTRACT_VERSION_KEYS = {
    "case": "case_schema",
    "execution": "execution_schema",
    "oracle": "replay_schema",
    "runner": "runner_schema",
}


# --------------------------------------------------------------------------
# Pinned plan models (notes.md interface; diagnostics is a documented
# extension - see module docstring and the D4 report)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PlannedFile:
    """One closure file to snapshot, with its per-file read cap."""

    relpath: str
    max_bytes: int

    def __post_init__(self) -> None:
        check_package_path(self.relpath, "PlannedFile.relpath")
        if isinstance(self.max_bytes, bool) or not isinstance(self.max_bytes, int):
            raise ContractError("PlannedFile.max_bytes must be an int")
        if self.max_bytes <= 0:
            raise ContractError("PlannedFile.max_bytes must be positive")


@dataclass(frozen=True)
class SourcePlan:
    """Bounded enumeration result for one native source (design 6.4.2).

    ``files`` is the closure sorted by relpath; ``orphan_files`` lists files
    present in the tree but outside the closure (never copied).
    ``diagnostics`` (extension to the pinned brief) carries stable short
    codes such as ``"missing_root_manifest"`` for the design 6.4.2
    limited-scan case; an empty tuple means the root document was present.
    """

    kind: NativeKind
    root_document: str
    files: tuple[PlannedFile, ...]
    orphan_files: tuple[str, ...]
    native_versions: tuple[NativeVersionComponent, ...] = ()
    observed_writer_version: Optional[str] = None
    source_commit: Optional[str] = None
    producer: Optional[ProducerInfo] = None
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        check_package_path(self.root_document, "SourcePlan.root_document")
        if not isinstance(self.files, tuple):
            raise ContractError("SourcePlan.files must be a tuple")
        previous: Optional[str] = None
        for planned in self.files:
            if not isinstance(planned, PlannedFile):
                raise ContractError("SourcePlan.files must hold PlannedFile items")
            if previous is not None and planned.relpath <= previous:
                raise ContractError("SourcePlan.files must be sorted by relpath")
            previous = planned.relpath
        if not isinstance(self.orphan_files, tuple):
            raise ContractError("SourcePlan.orphan_files must be a tuple")
        previous = None
        for orphan in self.orphan_files:
            check_package_path(orphan, "SourcePlan.orphan_files item")
            if previous is not None and orphan <= previous:
                raise ContractError("SourcePlan.orphan_files must be sorted")
            previous = orphan
        if not isinstance(self.native_versions, tuple):
            raise ContractError("SourcePlan.native_versions must be a tuple")
        previous_key: Optional[str] = None
        for component in self.native_versions:
            if not isinstance(component, NativeVersionComponent):
                raise ContractError(
                    "SourcePlan.native_versions must hold NativeVersionComponent"
                )
            if previous_key is not None and component.kind_field <= previous_key:
                raise ContractError(
                    "SourcePlan.native_versions must be sorted by kind_field"
                )
            previous_key = component.kind_field
        if not isinstance(self.diagnostics, tuple):
            raise ContractError("SourcePlan.diagnostics must be a tuple")


# --------------------------------------------------------------------------
# Detection (root markers only; no byte reads)
# --------------------------------------------------------------------------


def _is_regular_marker(root: Path, name: str) -> bool:
    try:
        st = os.lstat(os.path.join(root, name))
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode)


def detect_native_kind(root: Path, *, kind_hint: Optional[str] = None) -> NativeKind:
    """Detect the native format of ``root`` from its root-level markers.

    Markers: ``evidence-manifest.json`` (delivery), ``generation-manifest.json``
    (generation), ``runner-manifest.json`` (run), ``trace.jsonl`` (trace) and
    the four standalone attempt documents (attempt, only without a runner
    manifest).  A ``trace.jsonl`` inside a run root is a run member (D3 refs
    it), so the runner manifest dominates; every other marker combination is
    a conflict and raises :class:`RootDetectionError`, as does a hint that
    differs from the markers or is not one of the five kind names.

    With no markers at all the hint selects the parser (design 6.3:
    ``--input-kind`` as a diagnostic for a missing root summary document);
    without a hint the result is :attr:`NativeKind.UNKNOWN`.
    """
    root = Path(root)
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        raise RootDetectionError(f"cannot inspect input root {str(root)!r}: {exc}") from exc
    if stat.S_ISLNK(root_stat.st_mode):
        raise RootDetectionError(f"input root {str(root)!r} is a symbolic link")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise RootDetectionError(f"input root {str(root)!r} is not a directory")

    delivery_marker = _is_regular_marker(root, _DELIVERY_MANIFEST_NAME)
    generation_marker = _is_regular_marker(root, GENERATION_MANIFEST_NAME)
    run_marker = _is_regular_marker(root, RUN_MANIFEST_NAME)
    trace_marker = _is_regular_marker(root, TRACE_FILE_NAME)
    attempt_marker = any(
        _is_regular_marker(root, name) for name in _ATTEMPT_REQUIRED_FILE_NAMES
    )

    if delivery_marker and (generation_marker or run_marker or trace_marker or attempt_marker):
        raise RootDetectionError(
            "conflicting root markers: evidence-manifest.json excludes every "
            "other native root marker"
        )
    if generation_marker and (run_marker or trace_marker or attempt_marker):
        raise RootDetectionError(
            "conflicting root markers: generation-manifest.json excludes "
            "runner-manifest.json, trace.jsonl and top-level attempt documents"
        )
    if trace_marker and attempt_marker:
        raise RootDetectionError(
            "conflicting root markers: trace.jsonl and top-level attempt "
            "documents are mutually exclusive"
        )

    kind: Optional[NativeKind] = None
    if delivery_marker:
        kind = NativeKind.DELIVERY
    elif generation_marker:
        kind = NativeKind.GENERATION
    elif run_marker:
        # A D3 run root legitimately contains trace.jsonl (a manifest ref)
        # and never top-level attempt documents; the runner manifest wins.
        kind = NativeKind.RUN
    elif trace_marker:
        kind = NativeKind.TRACE
    elif attempt_marker:
        kind = NativeKind.ATTEMPT

    if kind_hint is not None:
        hinted = _HINT_VALUES.get(kind_hint)
        if hinted is None:
            raise RootDetectionError(
                f"unknown --input-kind hint {kind_hint!r}; expected one of "
                f"{sorted(_HINT_VALUES)}"
            )
        if kind is not None and hinted is not kind:
            raise RootDetectionError(
                f"--input-kind {kind_hint!r} contradicts the root markers, "
                f"which indicate {str(kind.value)!r}"
            )
        return hinted
    if kind is None:
        return NativeKind.UNKNOWN
    return kind


# --------------------------------------------------------------------------
# Enumeration helpers
# --------------------------------------------------------------------------


def _cap_for(relpath: str, limits: Limits) -> int:
    """Per-file read cap: JSON documents, JSONL totals, then text files."""
    if relpath.endswith(".json"):
        return limits.max_json_document_bytes
    if relpath.endswith(".jsonl"):
        # Line caps (limits.max_jsonl_line_bytes) apply at read time; the
        # file cap is the total source budget (documented decision).
        return limits.max_total_source_bytes
    return TEXT_FILE_CAP_BYTES


def _read_root_document(reader: "SourceReader", relpath: str, limits: Limits) -> object:
    """Bounded strict read + parse of one root JSON document."""
    data = reader.read_bytes(relpath, max_bytes=limits.max_json_document_bytes)
    return parse_strict_json(data)


def _producer_from_raw(raw: object) -> Optional[ProducerInfo]:
    """Design 6.5.1: take an explicit ``producer`` object when present.

    No current schema=1 native root codec accepts a ``producer`` field (the
    strict codecs reject unknown fields), so this returns ``None`` for every
    format D4 consumes today; the branch documents the 6.5.1 contract for
    future writers and never infers a producer.
    """
    if isinstance(raw, dict) and "producer" in raw:
        return decode_producer_info(raw["producer"], "native root producer")
    return None


def _plan_from_closure(
    reader: "SourceReader",
    kind: NativeKind,
    root_document: str,
    closure: set[str],
    limits: Limits,
    *,
    native_versions: tuple[NativeVersionComponent, ...] = (),
    observed_writer_version: Optional[str] = None,
    source_commit: Optional[str] = None,
    producer: Optional[ProducerInfo] = None,
    diagnostics: tuple[str, ...] = (),
) -> SourcePlan:
    if len(closure) > limits.max_files:
        raise ReadLimitExceededError(
            f"native closure holds {len(closure)} files, over the "
            f"limits.max_files budget {limits.max_files}"
        )
    for relpath in closure:
        check_package_path(relpath, f"native closure path {relpath!r}")
    orphans: list[str] = []
    for relpath, entry_kind in reader.walk("", max_entries=limits.max_files):
        if entry_kind != "file" or relpath in closure:
            continue
        orphans.append(relpath)
    planned = tuple(
        PlannedFile(relpath=relpath, max_bytes=_cap_for(relpath, limits))
        for relpath in sorted(closure)
    )
    return SourcePlan(
        kind=kind,
        root_document=root_document,
        files=planned,
        orphan_files=tuple(sorted(orphans)),
        native_versions=tuple(
            sorted(native_versions, key=lambda component: component.kind_field)
        ),
        observed_writer_version=observed_writer_version,
        source_commit=source_commit,
        producer=producer,
        diagnostics=diagnostics,
    )


# --------------------------------------------------------------------------
# Per-kind enumerators
# --------------------------------------------------------------------------


def _enumerate_generation(
    reader: "SourceReader", limits: Limits
) -> SourcePlan:
    raw = _read_root_document(reader, GENERATION_MANIFEST_NAME, limits)
    manifest = decode_generation_manifest(raw, GENERATION_MANIFEST_NAME)
    closure = {GENERATION_MANIFEST_NAME, PROFILE_NAME}
    for entry in manifest.case_files:
        for name in (
            CASE_DOC_NAME,
            PREVIEW_A_NAME,
            PREVIEW_B_NAME,
            STATIC_CHECK_NAME,
        ):
            closure.add(f"{CASES_DIRNAME}/{entry.case_id}/{name}")
    return _plan_from_closure(
        reader,
        NativeKind.GENERATION,
        GENERATION_MANIFEST_NAME,
        closure,
        limits,
        native_versions=(
            NativeVersionComponent(
                kind_field="generation_schema",
                value=str(manifest.generation_schema_version),
            ),
        ),
        # Documented native writer field (D1 generator identity); the source
        # commit is never recorded by ad11f11 formats.
        observed_writer_version=manifest.generator.version,
        producer=_producer_from_raw(raw),
    )


def _enumerate_run(
    reader: "SourceReader", limits: Limits
) -> SourcePlan:
    diagnostics: tuple[str, ...] = ()
    manifest = None
    raw: object = None
    if reader.exists(RUN_MANIFEST_NAME):
        raw = _read_root_document(reader, RUN_MANIFEST_NAME, limits)
        manifest = decode_runner_manifest(raw, RUN_MANIFEST_NAME)
    else:
        diagnostics = (DIAGNOSTIC_MISSING_ROOT_MANIFEST,)

    closure: set[str] = set()
    versions: list[NativeVersionComponent] = []
    writer_version: Optional[str] = None
    if manifest is None:
        # Design 6.4.2: without the manifest only a limited scan of known
        # files is allowed (the source can only ever be PARTIAL); requested
        # counts are never inferred from directory sizes.
        for name in (ENVIRONMENT_NAME, OWNERSHIP_JOURNAL_FILE_NAME, TRACE_FILE_NAME):
            if reader.exists(name):
                closure.add(name)
        for dirname in (ATTEMPTS_DIRNAME, PAYLOADS_DIRNAME):
            try:
                names = reader.list_dir(dirname)
            except MissingEntryError:
                continue
            for name in names:
                relpath = f"{dirname}/{name}"
                entry_kind = reader.stat(relpath).kind
                if dirname == ATTEMPTS_DIRNAME:
                    # Each attempt is a directory holding the known attempt
                    # file names; only regular attempt directories are scanned.
                    if entry_kind != "dir":
                        continue
                    for file_name in ATTEMPT_FILE_NAMES:
                        closure.add(f"{relpath}/{file_name}")
                else:
                    if entry_kind != "file":
                        continue
                    closure.add(relpath)
    else:
        writer_version = manifest.tool_version
        for contract_name, version in manifest.contract_versions:
            key = _RUNNER_CONTRACT_VERSION_KEYS.get(contract_name)
            if key is not None:
                versions.append(NativeVersionComponent(kind_field=key, value=version))
        for ref_name, ref_path in manifest.refs:
            check_package_path(ref_path, f"RunnerManifest.refs[{ref_name!r}]")
            closure.add(ref_path)
        closure.add(ENVIRONMENT_NAME)
        attempt_ids: list[str] = []
        for ref_name, _ in manifest.refs:
            if ref_name.startswith("attempt:"):
                attempt_id = ref_name[len("attempt:") :]
                check_package_path(
                    f"{ATTEMPTS_DIRNAME}/{attempt_id}",
                    f"RunnerManifest.refs[{ref_name!r}] attempt id",
                )
                attempt_ids.append(attempt_id)
        for attempt_id in attempt_ids:
            for file_name in sorted(ATTEMPT_FILE_NAMES):
                closure.add(f"{ATTEMPTS_DIRNAME}/{attempt_id}/{file_name}")
            # Design 6.4.2 (run row): "observations 及其引用" - the payload
            # side table is referenced only from the observations JSONL, so
            # its files belong to the closure, not to the orphan list.
            observations = f"{ATTEMPTS_DIRNAME}/{attempt_id}/observations.jsonl"
            if reader.exists(observations):
                closure.update(
                    _payload_refs_from_observations(reader, observations, limits)
                )
    return _plan_from_closure(
        reader,
        NativeKind.RUN,
        RUN_MANIFEST_NAME,
        closure,
        limits,
        native_versions=tuple(versions),
        observed_writer_version=writer_version,
        producer=_producer_from_raw(raw),
        diagnostics=diagnostics,
    )


_OBSERVATION_REF_FIELDS = ("sql_ref", "diagnostics_ref", "field_metadata_ref")


def _payload_refs_from_observations(
    reader: "SourceReader", observations_relpath: str, limits: Limits
) -> set[str]:
    """Controlled payload refs recorded by one attempt's observations."""
    refs: set[str] = set()
    for _line_no, raw_line in reader.read_jsonl(
        observations_relpath,
        max_line_bytes=limits.max_jsonl_line_bytes,
        max_total_bytes=limits.max_total_source_bytes,
    ):
        if not raw_line.strip():
            continue
        try:
            record = parse_strict_json(raw_line)
        except ContractError:
            continue  # opaque line; the audit layer reports it if relevant
        if not isinstance(record, dict):
            continue
        for field in _OBSERVATION_REF_FIELDS:
            value = record.get(field)
            if isinstance(value, str) and value.startswith(f"{PAYLOADS_DIRNAME}/"):
                check_package_path(value, f"observation {field}")
                refs.add(value)
    return refs


def _enumerate_trace(reader: "SourceReader", limits: Limits) -> SourcePlan:
    closure = {TRACE_FILE_NAME}
    marker: Optional[str] = None
    for _line_no, raw_line in reader.read_jsonl(
        TRACE_FILE_NAME,
        max_line_bytes=limits.max_jsonl_line_bytes,
        max_total_bytes=limits.max_total_source_bytes,
    ):
        if not raw_line.strip():
            continue
        try:
            record = parse_strict_json(raw_line)
        except ContractError:
            continue  # bounded scan: bad tail/corrupt lines stay opaque here
        if not isinstance(record, dict):
            continue
        kind = record.get("kind")
        if not isinstance(kind, str) or kind not in TRACE_RECORD_KINDS:
            continue  # unknown record kinds are skipped as opaque
        inline = record.get("inline")
        if kind in ("SNAPSHOT", "START") and isinstance(inline, dict) and (
            "evidence_profile" in inline
        ):
            value = inline["evidence_profile"]
            if value != EVIDENCE_PROFILE_FULL:
                raise RootDetectionError(
                    f"trace record kind {kind!r} declares evidence_profile "
                    f"{value!r}, not the frozen full-trace format "
                    f"{EVIDENCE_PROFILE_FULL!r}"
                )
            marker = value
        ref_objects = [record.get("payload_ref")]
        if isinstance(inline, dict):
            ref_objects.append(inline.get("payload_ref"))
            ref_objects.append(inline.get("child_payload_ref"))
        for ref_obj in ref_objects:
            if ref_obj is None:
                continue
            try:
                ref = decode_artifact_ref(ref_obj, "trace record artifact ref")
            except ContractError:
                continue  # opaque; the trace audit owns corruption verdicts
            if ref.path.startswith(f"{FILES_DIR_NAME}/"):
                check_package_path(ref.path, "trace dependency path")
                closure.add(ref.path)
    for result_name, decode in (
        ("replay-result.json", decode_replay_result),
        ("reduce-result.json", decode_reduction_result),
    ):
        if not reader.exists(result_name):
            continue
        raw = _read_root_document(reader, result_name, limits)
        decode(raw, result_name)  # strict codec validation (design 6.4.2)
        closure.add(result_name)
    native_versions = ()
    if marker is not None:
        native_versions = (NativeVersionComponent(kind_field="trace_format", value=marker),)
    return _plan_from_closure(
        reader,
        NativeKind.TRACE,
        TRACE_FILE_NAME,
        closure,
        limits,
        native_versions=native_versions,
    )


def _enumerate_attempt(reader: "SourceReader", limits: Limits) -> SourcePlan:
    diagnostics: tuple[str, ...] = ()
    if reader.exists("request.json"):
        raw = _read_root_document(reader, "request.json", limits)
        # Strict typed decode of the root document, but only as a *plan*
        # quality gate: the closure itself is the fixed known file names, so
        # a corrupt request must not change which files are enumerated.  It
        # is recorded as a diagnostic; the Phase 2 attempt audit owns the
        # corruption verdict (design 6.4.2, 6.5).
        from ..contracts.execution import load_attempt_request

        try:
            load_attempt_request(raw)
        except ContractError:
            diagnostics = (DIAGNOSTIC_CORRUPT_ROOT_DOCUMENT,)
    else:
        diagnostics = (DIAGNOSTIC_MISSING_ROOT_MANIFEST,)
    closure = set(_ATTEMPT_REQUIRED_FILE_NAMES)
    for name in _ATTEMPT_OPTIONAL_FILE_NAMES:
        if reader.exists(name):
            closure.add(name)
    # A standalone attempt has no parent manifest and no producer/writer
    # metadata at its root; nothing is inferred (design 6.4.2, 6.5.1).
    return _plan_from_closure(
        reader,
        NativeKind.ATTEMPT,
        "request.json",
        closure,
        limits,
        diagnostics=diagnostics,
    )


def _enumerate_delivery(reader: "SourceReader", limits: Limits) -> SourcePlan:
    raw = _read_root_document(reader, _DELIVERY_MANIFEST_NAME, limits)
    manifest = decode_evidence_manifest(raw, _DELIVERY_MANIFEST_NAME)
    closure = {_DELIVERY_MANIFEST_NAME}
    closure.update(file_entry.path for file_entry in manifest.files)
    for name in (
        _ASSESSMENT_NAME,
        _REPORT_JSON_NAME,
        _REPORT_MD_NAME,
        _REPORT_HTML_NAME,
    ):
        if reader.exists(name):
            closure.add(name)
    try:
        review_names = reader.list_dir(_REVIEWS_DIRNAME)
    except MissingEntryError:
        review_names = []
    for name in review_names:
        if name.endswith(".json"):
            closure.add(f"{_REVIEWS_DIRNAME}/{name}")
    return _plan_from_closure(
        reader,
        NativeKind.DELIVERY,
        _DELIVERY_MANIFEST_NAME,
        closure,
        limits,
        observed_writer_version=manifest.writer_version,
        producer=manifest.producer,
    )


_ENUMERATORS = {
    NativeKind.GENERATION: _enumerate_generation,
    NativeKind.RUN: _enumerate_run,
    NativeKind.TRACE: _enumerate_trace,
    NativeKind.ATTEMPT: _enumerate_attempt,
    NativeKind.DELIVERY: _enumerate_delivery,
}


def enumerate_source(
    reader: "SourceReader", kind: NativeKind, limits: Limits
) -> SourcePlan:
    """Enumerate the file closure of one native source (design 6.4.2).

    ``reader`` must be an opened :class:`SourceReader` (it owns path safety,
    per-read caps and the deadline); ``kind`` comes from
    :func:`detect_native_kind`.  ``NativeKind.UNKNOWN`` is refused here -
    the documented single refusal point for marker-less roots.  Contract
    errors from the strict root-codec decoders propagate unchanged: a
    corrupt root document is corrupt input (exit-2 class per design 6.3),
    not a detection failure.
    """
    if isinstance(kind, bool) or not isinstance(kind, NativeKind):
        raise RootDetectionError(f"enumerate_source needs a NativeKind, got {kind!r}")
    enumerator = _ENUMERATORS.get(kind)
    if enumerator is None:
        raise RootDetectionError(
            f"cannot enumerate NativeKind.{str(kind.value)}; detection must "
            "resolve to a concrete native format first"
        )
    return enumerator(reader, limits)
