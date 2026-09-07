"""Bounded offline bundle file I/O for D1 Phase 5 (design 6.5, 6.6; B01-B03).

This module is the only place in D1 where generation results touch the file
system.  All semantic functions elsewhere stay pure; the CLI is a thin wrapper
around :func:`write_bundle` / :func:`generate_and_write` and
:func:`validate_output_dir` / :func:`exit_code_for`.

Directory layout (design 6.6)::

    <new output directory>/
      generation-manifest.json
      profile.json
      cases/<case_id>/
        case.json
        static-check.json
        preview-a.sql
        preview-b.sql

Frozen bundle-layer decisions (all local to this module, none change a
contract in ``contracts/``):

- ``profile.json`` is the canonical JSON document of ``Profile.to_obj()``
  plus one trailing newline.  ``decode_profile`` accepts exactly that field
  set, so no extra ``profile_hash`` field is stored: the profile hash is
  re-derived as ``sha256(canonical_json(Profile.to_obj()))`` and must equal
  ``GenerationManifest.profile_hash``.
- ``case.json`` seals only ``{"case_id": ..., "payload": ...}`` (design 6.6:
  the same case_id is written once, provenance lives in the ordinal
  receipts).  It is *not* a ``decode_case_bundle`` document.
- One ``CaseFileEntry`` per published case_id.  Its ``artifact_hash`` covers
  the actual bytes of the four case files, fed to SHA-256 in the fixed order
  ``(case.json, preview-a.sql, preview-b.sql, static-check.json)`` as
  ``name + b"\\0" + len(data).to_bytes(8, "big") + data``; ``size_bytes`` is
  the sum of the four file sizes.
- The manifest starts as RUNNING, is atomically re-written (temp name with a
  ``.`` prefix + ``.part`` suffix, then ``os.replace``) after every processed
  ordinal, and is finalized once.  Every JSON document is written canonically
  with one trailing newline; the validator re-checks that byte form.
- Budget (``BundleBudget``): before writing a new case directory the writer
  projects ``persisted bytes + candidate bytes + estimated terminating
  manifest bytes + 4096 bytes termination reserve``.  The estimate is a
  conservative upper bound computed once from the known receipts with
  placeholder case entries plus slack.  Exhaustion stops the write phase (no
  file is ever truncated); unprocessed ordinals become INTERRUPTED receipts
  and the manifest is finalized PARTIAL.  ENOSPC/permission errors are I/O
  failures: they finalize ABORTED and are reported in ``WriteOutcome
  .io_error``, never disguised as the logical budget.
- Validator problem kinds and exit-code classes: every problem carries a
  severity, ``"corrupt"`` -> exit 2, ``"incomplete"`` -> exit 3, ``"io"`` ->
  exit 1.  Corruption outranks incompleteness (design 6.3.3: bad evidence is
  never masked by "just unfinished").  A missing manifest is "cannot verify"
  and is classified corrupt (exit 2), distinct from a legal PARTIAL.
  ``.part`` residue is listed as incomplete, but under a COMPLETE manifest it
  contradicts the manifest claim and escalates to corrupt.  Orphan published
  case directories are listed as incomplete (they never allow exit 0).

Reading is side-effect free: the validator deletes, repairs and silently
completes nothing.  Importing this module performs no I/O.
"""

from __future__ import annotations

import enum
import hashlib
import os
import stat
from dataclasses import dataclass, replace as _dc_replace
from pathlib import Path
from typing import Callable, Optional

from mtsql_typecheck.contracts.case import (
    MAX_BUNDLE_BYTES_HARD_CAP,
    CaseBundle,
    CaseFileEntry,
    CasePayload,
    CompatibilityCheck,
    ContractError,
    GenerationManifest,
    GenerationStatus,
    OrdinalOutcome,
    OrdinalReceipt,
    Profile,
    ReasonCode,
)
from mtsql_typecheck.contracts.codec import (
    canonical_json,
    decode_case_payload,
    decode_compatibility_check,
    decode_generation_manifest,
    decode_profile,
    parse_strict_json,
    sha256_hex,
)
from mtsql_typecheck.contracts.execution import Control
from mtsql_typecheck.generation.generator import (
    GenerationResult,
    generate_cases,
)
from mtsql_typecheck.generation.render import render_preview
from mtsql_typecheck.generation.validation import (
    GENERATOR_IDENTITY,
    validate_case,
)

__all__ = [
    "MANIFEST_NAME",
    "PROFILE_NAME",
    "CASES_DIRNAME",
    "CASE_DOC_NAME",
    "STATIC_CHECK_NAME",
    "PREVIEW_A_NAME",
    "PREVIEW_B_NAME",
    "CASE_FILE_ORDER",
    "TERMINATION_RESERVE_BYTES",
    "BundleBudgetError",
    "BundleError",
    "OutputDirExistsError",
    "UnsafePathError",
    "BundleBudget",
    "BundleReadLimits",
    "WriteOutcome",
    "ProblemKind",
    "ValidationProblem",
    "ValidationReport",
    "write_bundle",
    "generate_and_write",
    "validate_output_dir",
    "exit_code_for",
]

MANIFEST_NAME = "generation-manifest.json"
PROFILE_NAME = "profile.json"
CASES_DIRNAME = "cases"
CASE_DOC_NAME = "case.json"
STATIC_CHECK_NAME = "static-check.json"
PREVIEW_A_NAME = "preview-a.sql"
PREVIEW_B_NAME = "preview-b.sql"

# Fixed order in which the four case files feed the aggregate artifact hash.
CASE_FILE_ORDER = (CASE_DOC_NAME, PREVIEW_A_NAME, PREVIEW_B_NAME, STATIC_CHECK_NAME)

TERMINATION_RESERVE_BYTES = 4096
PART_SUFFIX = ".part"

_TOP_LEVEL_NAMES = frozenset({MANIFEST_NAME, PROFILE_NAME, CASES_DIRNAME})


class BundleError(ContractError):
    """Base error for bundle-layer misuse (also a ContractError/ValueError)."""


class OutputDirExistsError(BundleError):
    """The output directory already exists (an empty directory counts)."""


class UnsafePathError(BundleError):
    """A path component is a symlink or a non-directory; never followed."""


class BundleBudgetError(BundleError):
    """The configured budget cannot hold profile + initial manifest + reserve."""


@dataclass(frozen=True)
class BundleReadLimits:
    """Optional read-side caps for :func:`validate_output_dir` (design 6.5:
    the D1 validator's potentially long traversal must be boundable, not
    guarded by a one-off time check before the call).

    Every field is ``None`` (unlimited) or a non-negative int (bools are
    rejected).  All-``None`` keeps the historical unbounded validation and
    exists for compatibility callers only; D4 must always pass real caps.

    - ``max_files``: file reads the validator may perform.
    - ``max_file_bytes``: per-file byte cap, enforced via ``lstat`` BEFORE a
      file is read.
    - ``max_total_bytes``: cumulative bytes the validator may read.
    """

    max_files: Optional[int] = None
    max_file_bytes: Optional[int] = None
    max_total_bytes: Optional[int] = None

    def __post_init__(self) -> None:
        for name in ("max_files", "max_file_bytes", "max_total_bytes"):
            value = getattr(self, name)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int):
                raise BundleBudgetError(
                    f"BundleReadLimits.{name} must be a non-negative int or None"
                )
            if value < 0:
                raise BundleBudgetError(
                    f"BundleReadLimits.{name} must be a non-negative int or "
                    f"None, got {value}"
                )


class _ReadBounds:
    """Mutable read accounting for one ``validate_output_dir`` call.

    Exists only when limits or a control are configured; with neither, the
    historical code path runs unchanged.  A cap is checked BEFORE the
    corresponding unbounded work; exceeding one raises ``BundleBudgetError``
    naming the cap (a budget signal, never listed as a bundle problem), and
    a cancelled/expired control raises at every loop boundary.
    """

    __slots__ = ("limits", "control", "files_read", "bytes_read")

    def __init__(
        self,
        limits: Optional[BundleReadLimits],
        control: Optional["Control"],
    ) -> None:
        self.limits = limits
        self.control = control
        self.files_read = 0
        self.bytes_read = 0

    def check_point(self) -> None:
        """Cooperative cancellation/deadline check (one loop boundary)."""
        if self.control is None:
            return
        if self.control.expired():
            raise BundleBudgetError(
                "bundle read limit exceeded: the validation deadline expired "
                "before the bundle could be fully validated"
            )
        self.control.raise_if_cancelled()

    def before_read(self, path: Path, size: int) -> None:
        """Pre-read caps: file count, per-file bytes and cumulative bytes."""
        self.check_point()
        if self.limits is None:
            return
        file_cap = self.limits.max_files
        if file_cap is not None and self.files_read >= file_cap:
            raise BundleBudgetError(
                f"bundle read limit exceeded: max_files={file_cap}: the "
                f"validator would read a {file_cap + 1}-th file"
            )
        file_bytes_cap = self.limits.max_file_bytes
        if file_bytes_cap is not None and size > file_bytes_cap:
            raise BundleBudgetError(
                f"bundle read limit exceeded: max_file_bytes={file_bytes_cap}: "
                f"file {str(path)!r} is {size} bytes"
            )
        total_cap = self.limits.max_total_bytes
        if total_cap is not None and self.bytes_read + size > total_cap:
            raise BundleBudgetError(
                f"bundle read limit exceeded: max_total_bytes={total_cap}: "
                f"reading {str(path)!r} ({size} bytes) would exceed the "
                f"{total_cap}-byte total after {self.bytes_read} bytes"
            )

    def after_read(self, size: int) -> None:
        self.files_read += 1
        self.bytes_read += size


# --------------------------------------------------------------------------
# Write side
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleBudget:
    """Total byte budget for one output directory (design 6.4.1: 256 MiB)."""

    max_total_bytes: int = MAX_BUNDLE_BYTES_HARD_CAP

    def __post_init__(self) -> None:
        if isinstance(self.max_total_bytes, bool) or not isinstance(
            self.max_total_bytes, int
        ):
            raise BundleBudgetError("BundleBudget.max_total_bytes must be an int")
        if not 1 <= self.max_total_bytes <= MAX_BUNDLE_BYTES_HARD_CAP:
            raise BundleBudgetError(
                "BundleBudget.max_total_bytes must be in "
                f"[1, {MAX_BUNDLE_BYTES_HARD_CAP}], got {self.max_total_bytes}"
            )


@dataclass(frozen=True)
class WriteOutcome:
    """What one bundle write actually persisted (design 6.5, 6.6)."""

    output_dir: Path
    final_status: GenerationStatus
    manifest_written: bool
    cases_published: int
    ordinals_persisted: int
    bytes_written: int
    budget_exhausted: bool
    io_error: Optional[str]
    manifest: GenerationManifest


def _write_bytes(path: Path, data: bytes) -> None:
    """Raw byte write; module-level so tests can inject OSError (B03)."""
    with open(path, "wb") as handle:
        handle.write(data)


def _write_file_atomic(path: Path, data: bytes) -> None:
    temp = path.parent / f".{path.name}{PART_SUFFIX}"
    _write_bytes(temp, data)
    os.replace(temp, path)


def _ensure_new_output_dir(output_dir: Path) -> Path:
    """Reject an existing target and any symlink component; then create it.

    Every existing component is checked with ``os.lstat``; symlinks are never
    followed (design 6.5).  An existing final component - including an empty
    directory - is a stable, dedicated error.
    """
    abspath = Path(os.path.abspath(os.fspath(output_dir)))
    parts = abspath.parts
    for index in range(1, len(parts) + 1):
        prefix = Path(*parts[:index])
        if not os.path.lexists(prefix):
            break
        target_stat = os.lstat(prefix)
        if stat.S_ISLNK(target_stat.st_mode):
            raise UnsafePathError(
                f"path component {str(prefix)!r} is a symlink; symlink "
                "components are never followed"
            )
        if index == len(parts):
            raise OutputDirExistsError(
                f"output directory {str(abspath)!r} already exists; the "
                "bundle writer only creates new directories"
            )
        if not stat.S_ISDIR(target_stat.st_mode):
            raise UnsafePathError(
                f"path component {str(prefix)!r} is not a directory"
            )
    os.makedirs(abspath)
    return abspath


def case_doc_bytes(payload: CasePayload, case_id: str) -> bytes:
    """Canonical ``case.json`` bytes: sealed payload + case_id, one newline."""
    return canonical_json({"case_id": case_id, "payload": payload.to_obj()}) + b"\n"


def case_artifact_digest(files: dict[str, bytes]) -> tuple[int, str]:
    """Aggregate ``(total size, artifact hash)`` over the four case files.

    Feeds ``name + b"\\0" + 8-byte big-endian length + data`` per file in
    :data:`CASE_FILE_ORDER` into SHA-256 over the actual file bytes.
    """
    digest = hashlib.sha256()
    total = 0
    for name in CASE_FILE_ORDER:
        data = files[name]
        digest.update(name.encode("ascii"))
        digest.update(b"\0")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        total += len(data)
    return total, digest.hexdigest()


def _case_files(bundle: CaseBundle) -> dict[str, bytes]:
    preview_a, preview_b = render_preview(bundle.payload)
    return {
        CASE_DOC_NAME: case_doc_bytes(bundle.payload, bundle.case_id),
        PREVIEW_A_NAME: preview_a.encode("utf-8"),
        PREVIEW_B_NAME: preview_b.encode("utf-8"),
        STATIC_CHECK_NAME: canonical_json(bundle.static_check.to_obj()) + b"\n",
    }


def _publish_case(cases_dir: Path, bundle: CaseBundle) -> tuple[int, str]:
    """Write one case directory completely under a ``.part`` temp name, then
    atomically publish it with ``os.replace``.  Returns (size, artifact hash)."""
    files = _case_files(bundle)
    part_dir = cases_dir / f".{bundle.case_id}{PART_SUFFIX}"
    os.mkdir(part_dir)
    for name in CASE_FILE_ORDER:
        _write_bytes(part_dir / name, files[name])
    os.replace(part_dir, cases_dir / bundle.case_id)
    size, artifact = case_artifact_digest(files)
    return size, artifact


def _attempted_candidates(receipts: tuple[OrdinalReceipt, ...], emitted: int) -> int:
    """Retried attempts plus one accepted attempt per emitted ordinal."""
    return sum(receipt.retry_count for receipt in receipts) + emitted


def _interim_running_manifest(
    result: GenerationResult,
    processed: tuple[OrdinalReceipt, ...],
    case_files: tuple[CaseFileEntry, ...],
) -> GenerationManifest:
    """RUNNING manifest state after ``processed`` ordinals (design 6.6)."""
    emitted = sum(
        1 for receipt in processed if receipt.outcome is OrdinalOutcome.EMITTED
    )
    rejected = sum(
        1 for receipt in processed if receipt.outcome is OrdinalOutcome.REJECTED
    )
    return GenerationManifest(
        profile_hash=result.profile_hash,
        seed=result.seed,
        requested_ordinals=result.manifest.requested_ordinals,
        attempted_candidates=_attempted_candidates(processed, emitted),
        emitted_occurrences=emitted,
        unique_cases=len(case_files),
        rejected_ordinals=rejected,
        interrupted_ordinals=0,
        not_attempted=result.manifest.requested_ordinals - len(processed),
        status=GenerationStatus.RUNNING,
        generator=result.manifest.generator,
        receipts=processed,
        case_files=case_files,
        reason=None,
    )


def _estimate_final_manifest_bytes(result: GenerationResult, case_count: int) -> int:
    """Conservative upper bound of the terminating manifest size in bytes.

    Uses the full known receipt set and placeholder case entries (fixed 64-hex
    hashes, zero sizes) plus 8 bytes of slack per case entry for size digits.
    """
    placeholder_entries = tuple(
        CaseFileEntry(case_id=f"{index:064x}", artifact_hash="0" * 64, size_bytes=0)
        for index in range(case_count)
    )
    estimate = _dc_replace(result.manifest, case_files=placeholder_entries)
    return len(canonical_json(estimate.to_obj())) + 8 * case_count + 16


def write_bundle(
    result: GenerationResult,
    output_dir: Path,
    *,
    budget: Optional[BundleBudget] = None,
) -> WriteOutcome:
    """Write a pre-generated :class:`GenerationResult` as an offline bundle.

    The output directory must be new (an existing directory, even an empty
    one, is refused with :class:`OutputDirExistsError`) and no path component
    may be a symlink.  ``profile.json`` is written first, then a RUNNING
    manifest; the manifest is atomically re-written after every processed
    ordinal and finalized once at the end.  Case directories are written
    completely under a ``.part`` temp name and published atomically; a
    case_id is written at most once (repeated occurrences only add manifest
    receipts).  On byte-budget exhaustion the write phase stops cleanly
    (PARTIAL); on ENOSPC/permission errors it finalizes ABORTED and records
    the I/O failure.  Nothing inside the output directory is ever deleted.
    """
    if not isinstance(result, GenerationResult):
        raise BundleError("write_bundle needs a GenerationResult")
    effective_budget = (
        budget if budget is not None else BundleBudget(result.profile.max_bundle_bytes)
    )
    if not isinstance(effective_budget, BundleBudget):
        raise BundleBudgetError("budget must be a BundleBudget")

    bundles_by_id: dict[str, CaseBundle] = {bundle.case_id: bundle for bundle in result.bundles}
    profile_bytes = canonical_json(result.profile.to_obj()) + b"\n"
    initial_manifest = _interim_running_manifest(result, (), ())
    initial_manifest_bytes = len(canonical_json(initial_manifest.to_obj())) + 1
    if (
        len(profile_bytes) + initial_manifest_bytes + TERMINATION_RESERVE_BYTES
        > effective_budget.max_total_bytes
    ):
        # Input error before any directory is created (design 6.6).
        raise BundleBudgetError(
            f"budget {effective_budget.max_total_bytes} cannot hold profile.json "
            f"({len(profile_bytes)} bytes), the initial manifest "
            f"({initial_manifest_bytes} bytes) and the "
            f"{TERMINATION_RESERVE_BYTES}-byte termination reserve"
        )

    out = _ensure_new_output_dir(Path(output_dir))
    cases_dir = out / CASES_DIRNAME
    os.mkdir(cases_dir)

    bytes_written = len(profile_bytes)
    io_error: Optional[str] = None
    try:
        _write_file_atomic(out / PROFILE_NAME, profile_bytes)
        _write_file_atomic(
            out / MANIFEST_NAME, canonical_json(initial_manifest.to_obj()) + b"\n"
        )
    except OSError as exc:
        io_error = f"failed to write bundle header files: {exc}"

    estimate_final_manifest_bytes = _estimate_final_manifest_bytes(
        result, len(bundles_by_id)
    )
    published: dict[str, CaseFileEntry] = {}
    processed: list[OrdinalReceipt] = []
    stopped: Optional[str] = None
    if io_error is not None:
        stopped = "io"

    if stopped is None:
        for receipt in result.receipts:
            if receipt.outcome is OrdinalOutcome.EMITTED:
                case_id = receipt.case_id
                if case_id is None or case_id not in bundles_by_id:
                    # Unreachable for generator-produced results; a hand-built
                    # result referencing an unknown case is a tool error.
                    raise BundleError(
                        f"result receipt for ordinal {receipt.ordinal} references "
                        f"case_id {case_id!r} which has no bundle"
                    )
                if case_id not in published:
                    files = _case_files(bundles_by_id[case_id])
                    candidate_size, candidate_artifact = case_artifact_digest(files)
                    projected = (
                        bytes_written
                        + candidate_size
                        + estimate_final_manifest_bytes
                        + TERMINATION_RESERVE_BYTES
                    )
                    if projected > effective_budget.max_total_bytes:
                        stopped = "budget"
                        break
                    try:
                        _publish_case(cases_dir, bundles_by_id[case_id])
                    except OSError as exc:
                        io_error = f"failed to publish case {case_id}: {exc}"
                        stopped = "io"
                        break
                    published[case_id] = CaseFileEntry(
                        case_id=case_id,
                        artifact_hash=candidate_artifact,
                        size_bytes=candidate_size,
                    )
                    bytes_written += candidate_size
            processed.append(receipt)
            try:
                _write_file_atomic(
                    out / MANIFEST_NAME,
                    canonical_json(
                        _interim_running_manifest(
                            result, tuple(processed), tuple(published.values())
                        ).to_obj()
                    )
                    + b"\n",
                )
            except OSError as exc:
                io_error = f"failed to update the manifest: {exc}"
                stopped = "io"
                break

    if stopped is None:
        final_manifest = _dc_replace(
            result.manifest, case_files=tuple(published.values())
        )
    else:
        extras = tuple(
            OrdinalReceipt(
                ordinal=receipt.ordinal,
                outcome=OrdinalOutcome.INTERRUPTED,
                retry_count=0,
                reason=(
                    "ordinal generated but not persisted: bundle write stopped "
                    + ("at the byte budget" if stopped == "budget" else f"on i/o error: {io_error}")
                ),
            )
            for receipt in result.receipts[len(processed) :]
        )
        final_receipts = tuple(processed) + extras
        final_emitted = sum(
            1 for receipt in final_receipts if receipt.outcome is OrdinalOutcome.EMITTED
        )
        final_rejected = sum(
            1 for receipt in final_receipts if receipt.outcome is OrdinalOutcome.REJECTED
        )
        final_interrupted = sum(
            1 for receipt in final_receipts if receipt.outcome is OrdinalOutcome.INTERRUPTED
        )
        final_status = (
            GenerationStatus.PARTIAL if stopped == "budget" else GenerationStatus.ABORTED
        )
        final_reason = (
            "bundle byte budget exhausted; remaining ordinals not persisted"
            if stopped == "budget"
            else f"bundle write i/o failure: {io_error}"
        )
        final_manifest = GenerationManifest(
            profile_hash=result.profile_hash,
            seed=result.seed,
            requested_ordinals=result.manifest.requested_ordinals,
            attempted_candidates=_attempted_candidates(
                final_receipts, final_emitted
            ),
            emitted_occurrences=final_emitted,
            unique_cases=len(published),
            rejected_ordinals=final_rejected,
            interrupted_ordinals=final_interrupted,
            not_attempted=(
                result.manifest.requested_ordinals
                - final_emitted
                - final_rejected
                - final_interrupted
            ),
            status=final_status,
            generator=result.manifest.generator,
            receipts=final_receipts,
            case_files=tuple(published.values()),
            reason=final_reason,
        )

    manifest_written = False
    try:
        final_bytes = canonical_json(final_manifest.to_obj()) + b"\n"
        _write_file_atomic(out / MANIFEST_NAME, final_bytes)
        manifest_written = True
        bytes_written += len(final_bytes)
    except OSError as exc:
        # Best effort only (design 6.5): the last interim RUNNING manifest may
        # remain on disk; no durability is promised on a failing disk.
        io_error = io_error or f"failed to write the terminating manifest: {exc}"

    return WriteOutcome(
        output_dir=out,
        final_status=final_manifest.status,
        manifest_written=manifest_written,
        cases_published=len(published),
        ordinals_persisted=len(final_manifest.receipts),
        bytes_written=bytes_written,
        budget_exhausted=stopped == "budget",
        io_error=io_error,
        manifest=final_manifest,
    )


def generate_and_write(
    profile: Profile,
    seed: int,
    count: int,
    output_dir: Path,
    *,
    should_cancel: Optional[Callable[[], bool]] = None,
    budget: Optional[BundleBudget] = None,
) -> tuple[GenerationResult, WriteOutcome]:
    """Generate ``count`` ordinals and write the bundle in one step.

    ``should_cancel`` is forwarded to the pure generator (cancellation stops
    before an unstarted ordinal; the persisted evidence keeps every completed
    case and receipt and is finalized ABORTED).  CLI ``generate`` is a thin
    wrapper around this function.
    """
    result = generate_cases(profile, seed, count, should_cancel=should_cancel)
    outcome = write_bundle(result, output_dir, budget=budget)
    return result, outcome


# --------------------------------------------------------------------------
# Read / verify side (side-effect free)
# --------------------------------------------------------------------------


class ProblemKind(enum.StrEnum):
    """Structured validator problem kinds (design 6.6: list every known one)."""

    MISSING_MANIFEST = "missing_manifest"
    MANIFEST_CORRUPT = "manifest_corrupt"
    NONCANONICAL_JSON = "noncanonical_json"
    UNKNOWN_SCHEMA_VERSION = "unknown_schema_version"
    UNKNOWN_GENERATION_IDENTITY = "unknown_generation_identity"
    PROFILE_CORRUPT = "profile_corrupt"
    PROFILE_MISMATCH = "profile_mismatch"
    CASE_CORRUPT = "case_corrupt"
    CASE_ID_MISMATCH = "case_id_mismatch"
    INVALID_CASE = "invalid_case"
    RULE_DISABLED = "rule_disabled"
    UNKNOWN_RULE = "unknown_rule"
    STATIC_CHECK_CORRUPT = "static_check_corrupt"
    STATIC_CHECK_MISMATCH = "static_check_mismatch"
    PREVIEW_MISMATCH = "preview_mismatch"
    ARTIFACT_HASH_MISMATCH = "artifact_hash_mismatch"
    MISSING_FILE = "missing_file"
    UNEXPECTED_ENTRY = "unexpected_entry"
    PART_RESIDUE = "part_residue"
    ORPHAN_CASE_DIR = "orphan_case_dir"
    ORDINAL_DUPLICATE = "ordinal_duplicate"
    ORDINAL_GAP = "ordinal_gap"
    COUNT_MISMATCH = "count_mismatch"
    RECEIPT_CASE_MISMATCH = "receipt_case_mismatch"
    UNREFERENCED_CASE_ENTRY = "unreferenced_case_entry"
    PATH_ESCAPE = "path_escape"
    SYMLINK = "symlink"
    IO_ERROR = "io_error"
    SIZE_BUDGET_EXCEEDED = "size_budget_exceeded"


@dataclass(frozen=True)
class ValidationProblem:
    """One listed validator problem: path, kind, detail and severity class.

    ``severity`` is ``"corrupt"`` (exit 2), ``"incomplete"`` (exit 3) or
    ``"io"`` (exit 1).
    """

    kind: ProblemKind
    path: Optional[str]
    detail: str
    severity: str


@dataclass(frozen=True)
class ValidationReport:
    """Structured result of an offline bundle validation."""

    output_dir: Path
    manifest_status: Optional[GenerationStatus]
    problems: tuple[ValidationProblem, ...]
    cases_validated: int
    counts_conserved: Optional[bool]

    @property
    def ok(self) -> bool:
        return not self.problems and self.manifest_status is GenerationStatus.COMPLETE


def _corrupt(kind: ProblemKind, path: Optional[str], detail: str) -> ValidationProblem:
    return ValidationProblem(kind, path, detail, "corrupt")


def _incomplete(kind: ProblemKind, path: Optional[str], detail: str) -> ValidationProblem:
    return ValidationProblem(kind, path, detail, "incomplete")


def _io(kind: ProblemKind, path: Optional[str], detail: str) -> ValidationProblem:
    return ValidationProblem(kind, path, detail, "io")


def exit_code_for(report: ValidationReport) -> int:
    """Map a report to the ``validate`` CLI exit code (design 6.3.3).

    COMPLETE and every check passed -> 0; any corrupt/illegal/disabled/
    unknown-version/safety problem -> 2 (outranks incompleteness); I/O
    failure -> 1; otherwise content-valid but PARTIAL/ABORTED/RUNNING (or any
    listed inconsistency) -> 3.
    """
    severities = {problem.severity for problem in report.problems}
    if "corrupt" in severities:
        return 2
    if "io" in severities:
        return 1
    if report.manifest_status is GenerationStatus.COMPLETE and not report.problems:
        return 0
    return 3


def _scan_dir(path: Path, problems: list[ValidationProblem]) -> Optional[list[os.DirEntry[str]]]:
    try:
        return list(os.scandir(path))
    except OSError as exc:
        problems.append(_io(ProblemKind.IO_ERROR, str(path), f"cannot scan directory: {exc}"))
        return None


def _read_capped(
    path: Path,
    problems: list[ValidationProblem],
    cap: int = MAX_BUNDLE_BYTES_HARD_CAP,
    bounds: Optional[_ReadBounds] = None,
) -> Optional[bytes]:
    """Read a file only after checking size and symlink status (design 6.5).

    With ``bounds``, the read caps and the control are checked BEFORE the
    file is read; exceeding one raises ``BundleBudgetError``/``ControlCancelled``
    instead of listing a problem (an over-cap read is a budget signal, never
    a bundle verdict).
    """
    if bounds is not None:
        bounds.check_point()
    try:
        file_stat = os.lstat(path)
    except FileNotFoundError:
        problems.append(
            _corrupt(ProblemKind.MISSING_FILE, str(path), "file is missing")
        )
        return None
    except OSError as exc:
        problems.append(_io(ProblemKind.IO_ERROR, str(path), f"cannot stat file: {exc}"))
        return None
    if stat.S_ISLNK(file_stat.st_mode):
        problems.append(
            _corrupt(ProblemKind.SYMLINK, str(path), "file is a symbolic link")
        )
        return None
    if file_stat.st_size > cap:
        problems.append(
            _corrupt(
                ProblemKind.SIZE_BUDGET_EXCEEDED,
                str(path),
                f"file is {file_stat.st_size} bytes, over the read budget {cap}",
            )
        )
        return None
    if bounds is not None:
        bounds.before_read(path, file_stat.st_size)
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        problems.append(_io(ProblemKind.IO_ERROR, str(path), f"cannot read file: {exc}"))
        return None
    if bounds is not None:
        bounds.after_read(len(data))
    return data


def _strict_document(
    data: bytes,
    path_str: str,
    problems: list[ValidationProblem],
    corrupt_kind: ProblemKind,
) -> Optional[object]:
    """Strict-parse a JSON document and re-check its canonical byte form."""
    try:
        value = parse_strict_json(data)
    except ContractError as exc:
        problems.append(_corrupt(corrupt_kind, path_str, f"unreadable JSON: {exc}"))
        return None
    body = data[:-1] if data.endswith(b"\n") else data
    try:
        reencoded = canonical_json(value)
    except ContractError as exc:
        problems.append(_corrupt(corrupt_kind, path_str, f"non-encodable JSON: {exc}"))
        return None
    if reencoded != body:
        problems.append(
            _corrupt(
                ProblemKind.NONCANONICAL_JSON,
                path_str,
                "document bytes are not the canonical encoding of their content",
            )
        )
        return None
    return value


_HEX64_EXPECT = "lowercase 64-hex sha256"


def _raw_manifest_scans(
    value: object, problems: list[ValidationProblem]
) -> Optional[dict[str, object]]:
    """Pre-decode structural scans: schema version, case_id shapes, ordinals."""
    if not isinstance(value, dict):
        problems.append(
            _corrupt(ProblemKind.MANIFEST_CORRUPT, MANIFEST_NAME, "manifest is not a JSON object")
        )
        return None
    version = value.get("generation_schema_version")
    if version != 1:
        problems.append(
            _corrupt(
                ProblemKind.UNKNOWN_SCHEMA_VERSION,
                MANIFEST_NAME,
                f"unsupported generation_schema_version {version!r}",
            )
        )
        return None
    seen_ordinals: dict[int, int] = {}
    receipt_list = value.get("receipts")
    if isinstance(receipt_list, list):
        for index, item in enumerate(receipt_list):
            if not isinstance(item, dict):
                continue
            ordinal = item.get("ordinal")
            if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
                problems.append(
                    _corrupt(
                        ProblemKind.ORDINAL_GAP,
                        MANIFEST_NAME,
                        f"receipts[{index}] has non-ordinal value {ordinal!r}",
                    )
                )
                continue
            seen_ordinals[ordinal] = seen_ordinals.get(ordinal, 0) + 1
            case_id = item.get("case_id")
            if case_id is not None and (
                not isinstance(case_id, str)
                or len(case_id) != 64
                or any(character not in "0123456789abcdef" for character in case_id)
            ):
                problems.append(
                    _corrupt(
                        ProblemKind.PATH_ESCAPE,
                        MANIFEST_NAME,
                        f"receipts[{index}] case_id {case_id!r} is not {_HEX64_EXPECT}",
                    )
                )
    for ordinal, count in sorted(seen_ordinals.items()):
        if count > 1:
            problems.append(
                _corrupt(
                    ProblemKind.ORDINAL_DUPLICATE,
                    MANIFEST_NAME,
                    f"ordinal {ordinal} appears {count} times in receipts",
                )
            )
    case_files = value.get("case_files")
    if isinstance(case_files, list):
        for index, item in enumerate(case_files):
            if not isinstance(item, dict):
                continue
            case_id = item.get("case_id")
            if (
                not isinstance(case_id, str)
                or len(case_id) != 64
                or any(character not in "0123456789abcdef" for character in case_id)
            ):
                problems.append(
                    _corrupt(
                        ProblemKind.PATH_ESCAPE,
                        MANIFEST_NAME,
                        f"case_files[{index}] case_id {case_id!r} is not a safe "
                        f"{_HEX64_EXPECT} directory name",
                    )
                )
    return value


def _check_counts(
    manifest: GenerationManifest, problems: list[ValidationProblem]
) -> bool:
    """Counter/conservation checks beyond the model constructor (design 6.6)."""
    label = MANIFEST_NAME
    conserved = True
    receipts = manifest.receipts
    for index, receipt in enumerate(receipts):
        if receipt.ordinal != index:
            problems.append(
                _corrupt(
                    ProblemKind.ORDINAL_GAP,
                    label,
                    f"receipts[{index}] has ordinal {receipt.ordinal}; generation "
                    "processes ordinals contiguously from 0",
                )
            )
            conserved = False
            break
    emitted = sum(1 for receipt in receipts if receipt.outcome is OrdinalOutcome.EMITTED)
    rejected = sum(1 for receipt in receipts if receipt.outcome is OrdinalOutcome.REJECTED)
    interrupted = sum(
        1 for receipt in receipts if receipt.outcome is OrdinalOutcome.INTERRUPTED
    )
    for name, expected, actual in (
        ("emitted_occurrences", emitted, manifest.emitted_occurrences),
        ("rejected_ordinals", rejected, manifest.rejected_ordinals),
        ("interrupted_ordinals", interrupted, manifest.interrupted_ordinals),
        (
            "not_attempted",
            manifest.requested_ordinals - len(receipts),
            manifest.not_attempted,
        ),
    ):
        if expected != actual:
            problems.append(
                _corrupt(
                    ProblemKind.COUNT_MISMATCH,
                    label,
                    f"statistics.{name} is {actual}, the receipts support {expected}",
                )
            )
            conserved = False
    attributed = (
        manifest.emitted_occurrences
        + manifest.rejected_ordinals
        + manifest.interrupted_ordinals
        + manifest.not_attempted
    )
    if manifest.status is GenerationStatus.RUNNING:
        conserved = False  # RUNNING never conserves by definition
    elif attributed != manifest.requested_ordinals:
        problems.append(
            _corrupt(
                ProblemKind.COUNT_MISMATCH,
                label,
                f"requested_ordinals {manifest.requested_ordinals} != "
                f"emitted {manifest.emitted_occurrences} + rejected "
                f"{manifest.rejected_ordinals} + interrupted "
                f"{manifest.interrupted_ordinals} + not_attempted "
                f"{manifest.not_attempted}",
            )
        )
        conserved = False
    if manifest.status is GenerationStatus.COMPLETE and (
        manifest.rejected_ordinals or manifest.interrupted_ordinals or manifest.not_attempted
    ):
        problems.append(
            _corrupt(
                ProblemKind.COUNT_MISMATCH,
                label,
                "COMPLETE requires zero rejected, interrupted and not_attempted "
                "ordinals",
            )
        )
        conserved = False
    case_ids = [entry.case_id for entry in manifest.case_files]
    if len(set(case_ids)) != len(case_ids):
        problems.append(
            _corrupt(
                ProblemKind.COUNT_MISMATCH,
                label,
                "case_files contains duplicate case_id entries",
            )
        )
        conserved = False
    if manifest.unique_cases != len(set(case_ids)):
        problems.append(
            _corrupt(
                ProblemKind.COUNT_MISMATCH,
                label,
                f"statistics.unique_cases is {manifest.unique_cases}, "
                f"case_files holds {len(set(case_ids))} distinct case ids",
            )
        )
        conserved = False
    return conserved


def _validate_case_directory(
    cases_dir: Path,
    case_id: str,
    entry: CaseFileEntry,
    problems: list[ValidationProblem],
    bounds: Optional[_ReadBounds] = None,
) -> Optional[tuple[CasePayload, dict[str, bytes]]]:
    """Re-derive everything for one referenced case; trust nothing (6.6)."""
    rel = f"{CASES_DIRNAME}/{case_id}"
    case_dir = cases_dir / case_id
    try:
        dir_stat = os.lstat(case_dir)
    except OSError:
        problems.append(
            _corrupt(ProblemKind.MISSING_FILE, rel, "referenced case directory is missing")
        )
        return None
    if stat.S_ISLNK(dir_stat.st_mode):
        problems.append(_corrupt(ProblemKind.SYMLINK, rel, "case directory is a symbolic link"))
        return None
    if not stat.S_ISDIR(dir_stat.st_mode):
        problems.append(
            _corrupt(ProblemKind.UNEXPECTED_ENTRY, rel, "referenced case path is not a directory")
        )
        return None
    names: Optional[list[str]] = None
    scanned = _scan_dir(case_dir, problems)
    if scanned is not None:
        names = []
        for item in scanned:
            if item.is_symlink():
                problems.append(
                    _corrupt(
                        ProblemKind.SYMLINK, f"{rel}/{item.name}", "entry is a symbolic link"
                    )
                )
            elif item.name in CASE_FILE_ORDER:
                names.append(item.name)
            else:
                problems.append(
                    _corrupt(
                        ProblemKind.UNEXPECTED_ENTRY,
                        f"{rel}/{item.name}",
                        "unknown entry inside a case directory",
                    )
                )
    files: dict[str, bytes] = {}
    for name in CASE_FILE_ORDER:
        if bounds is not None:
            bounds.check_point()
        data = _read_capped(case_dir / name, problems, bounds=bounds)
        if data is None:
            if names is not None and name not in names:
                problems.append(
                    _corrupt(ProblemKind.MISSING_FILE, f"{rel}/{name}", "referenced file is missing")
                )
            continue
        files[name] = data
    if len(files) != len(CASE_FILE_ORDER):
        return None

    # case.json: sealed payload + case_id, re-hashed from the payload itself.
    value = _strict_document(files[CASE_DOC_NAME], f"{rel}/{CASE_DOC_NAME}", problems, ProblemKind.CASE_CORRUPT)
    if not isinstance(value, dict) or set(value) != {"case_id", "payload"}:
        if not any(problem.path == f"{rel}/{CASE_DOC_NAME}" for problem in problems):
            problems.append(
                _corrupt(
                    ProblemKind.CASE_CORRUPT,
                    f"{rel}/{CASE_DOC_NAME}",
                    "case.json must hold exactly the fields case_id and payload",
                )
            )
        return None
    try:
        payload = decode_case_payload(value["payload"], f"{rel}/{CASE_DOC_NAME}.payload")
    except ContractError as exc:
        problems.append(
            _corrupt(ProblemKind.CASE_CORRUPT, f"{rel}/{CASE_DOC_NAME}", f"illegal payload: {exc}")
        )
        return None
    derived_case_id = sha256_hex(canonical_json(payload.to_obj()))
    if value["case_id"] != derived_case_id or derived_case_id != case_id:
        problems.append(
            _corrupt(
                ProblemKind.CASE_ID_MISMATCH,
                f"{rel}/{CASE_DOC_NAME}",
                f"case_id fields {value['case_id']!r}/{case_id!r} do not match the "
                f"recomputed payload hash {derived_case_id}",
            )
        )
        return None

    # Independent static re-validation, including rule registry state.
    check = validate_case(payload)
    if check.status.value == "INVALID":
        disabled = any(
            condition.reason is ReasonCode.RULE_DISABLED
            and condition.status.value == "VIOLATED"
            for condition in check.conditions
        )
        unknown = any(
            condition.reason is ReasonCode.UNKNOWN_VERSION
            and condition.status.value == "VIOLATED"
            for condition in check.conditions
        )
        if disabled:
            problems.append(
                _corrupt(
                    ProblemKind.RULE_DISABLED,
                    rel,
                    f"rule {payload.rule.rule_id}@{payload.rule.rule_version} is "
                    "disabled in the registry; the case cannot pass validation",
                )
            )
        elif unknown:
            problems.append(
                _corrupt(
                    ProblemKind.UNKNOWN_RULE,
                    rel,
                    f"rule {payload.rule.rule_id}@{payload.rule.rule_version} is "
                    "unknown or its definition hash no longer matches",
                )
            )
        else:
            violated = next(
                (
                    condition
                    for condition in check.conditions
                    if condition.status.value == "VIOLATED"
                ),
                None,
            )
            problems.append(
                _corrupt(
                    ProblemKind.INVALID_CASE,
                    rel,
                    "independent static re-validation returned INVALID"
                    + (f": {violated.detail}" if violated is not None else ""),
                )
            )

    # static-check.json: recompute and compare with the stored document.
    stored_obj = _strict_document(
        files[STATIC_CHECK_NAME], f"{rel}/{STATIC_CHECK_NAME}", problems, ProblemKind.STATIC_CHECK_CORRUPT
    )
    if stored_obj is not None:
        try:
            stored_check = decode_compatibility_check(
                stored_obj, f"{rel}/{STATIC_CHECK_NAME}"
            )
        except ContractError as exc:
            problems.append(
                _corrupt(
                    ProblemKind.STATIC_CHECK_CORRUPT,
                    f"{rel}/{STATIC_CHECK_NAME}",
                    f"illegal check document: {exc}",
                )
            )
        else:
            if canonical_json(stored_check.to_obj()) != canonical_json(check.to_obj()):
                problems.append(
                    _corrupt(
                        ProblemKind.STATIC_CHECK_MISMATCH,
                        f"{rel}/{STATIC_CHECK_NAME}",
                        "stored static check differs from the independently "
                        "recomputed check (including validator version)",
                    )
                )

    # Preview SQL must re-render from the payload byte-identically.
    try:
        expected_a, expected_b = render_preview(payload)
    except ContractError as exc:
        problems.append(
            _corrupt(ProblemKind.PREVIEW_MISMATCH, rel, f"payload cannot be rendered: {exc}")
        )
        return None
    for name, expected in (
        (PREVIEW_A_NAME, expected_a),
        (PREVIEW_B_NAME, expected_b),
    ):
        try:
            actual = files[name].decode("utf-8")
        except UnicodeDecodeError:
            actual = None
        if actual != expected:
            problems.append(
                _corrupt(
                    ProblemKind.PREVIEW_MISMATCH,
                    f"{rel}/{name}",
                    "preview SQL does not match the re-rendered text of the payload",
                )
            )

    # Artifact hash over the actual file bytes.
    actual_size, actual_artifact = case_artifact_digest(files)
    if actual_artifact != entry.artifact_hash or actual_size != entry.size_bytes:
        problems.append(
            _corrupt(
                ProblemKind.ARTIFACT_HASH_MISMATCH,
                rel,
                f"manifest entry hash/size {entry.artifact_hash}/{entry.size_bytes} "
                f"does not match the actual file bytes "
                f"{actual_artifact}/{actual_size}",
            )
        )
    return payload, files


def validate_output_dir(
    path: Path,
    *,
    limits: Optional[BundleReadLimits] = None,
    control: Optional[Control] = None,
) -> ValidationReport:
    """Offline validation of a written bundle; strictly read-only.

    Re-derives everything: the manifest via the strict loader, the profile
    hash, every case_id from its payload, the static check, the preview SQL,
    the artifact hashes over actual file bytes, the receipt/case-file mapping
    and the counter conservation (design 6.6).  Missing manifest -> cannot
    verify (exit-2 class); a legal PARTIAL/ABORTED/legacy RUNNING with valid
    referenced content stays exit 3.

    Bounded entry (design 6.5): with ``limits``, the traversal stops at the
    first exceeded cap — file count, per-file bytes (checked via ``lstat``
    before reading) or cumulative bytes — by raising ``BundleBudgetError``
    naming the cap; no partial ValidationReport is produced for an over-cap
    bundle.  With ``control``, cancellation and the deadline are checked at
    every loop boundary and before every file read: cancellation raises
    ``ControlCancelled``, an expired deadline raises ``BundleBudgetError``.
    No existing check is weakened: ``limits=None, control=None`` (the
    default) keeps the historical behavior and results byte-for-byte.
    """
    if limits is not None and not isinstance(limits, BundleReadLimits):
        raise BundleBudgetError("limits must be a BundleReadLimits or None")
    bounds = (
        None
        if limits is None and control is None
        else _ReadBounds(limits, control)
    )
    problems: list[ValidationProblem] = []
    out = Path(path)
    manifest_status: Optional[GenerationStatus] = None
    cases_validated = 0
    counts_conserved: Optional[bool] = None

    try:
        root_stat = os.lstat(out)
    except OSError:
        problems.append(
            _corrupt(
                ProblemKind.MISSING_MANIFEST,
                str(out),
                "output directory does not exist; there is nothing to verify",
            )
        )
        return ValidationReport(out, None, tuple(problems), 0, None)
    if stat.S_ISLNK(root_stat.st_mode):
        problems.append(
            _corrupt(ProblemKind.SYMLINK, str(out), "output directory is a symbolic link")
        )
        return ValidationReport(out, None, tuple(problems), 0, None)
    if not stat.S_ISDIR(root_stat.st_mode):
        problems.append(
            _corrupt(ProblemKind.MISSING_MANIFEST, str(out), "output path is not a directory")
        )
        return ValidationReport(out, None, tuple(problems), 0, None)

    # ---- manifest ----
    manifest_bytes = _read_capped(out / MANIFEST_NAME, problems, bounds=bounds)
    if manifest_bytes is None:
        problems.append(
            _corrupt(
                ProblemKind.MISSING_MANIFEST,
                MANIFEST_NAME,
                "generation-manifest.json is missing or unreadable; the bundle "
                "cannot be verified (this is not a legal PARTIAL)",
            )
        )
    manifest: Optional[GenerationManifest] = None
    if manifest_bytes is not None:
        value = _strict_document(manifest_bytes, MANIFEST_NAME, problems, ProblemKind.MANIFEST_CORRUPT)
        if value is not None:
            scanned = _raw_manifest_scans(value, problems)
            if scanned is not None:
                try:
                    manifest = decode_generation_manifest(scanned, MANIFEST_NAME)
                except ContractError as exc:
                    problems.append(
                        _corrupt(
                            ProblemKind.MANIFEST_CORRUPT,
                            MANIFEST_NAME,
                            f"manifest rejected by the strict loader: {exc}",
                        )
                    )
    if manifest is not None:
        manifest_status = manifest.status
        if manifest.generator.id != GENERATOR_IDENTITY.id or (
            manifest.generator.version != GENERATOR_IDENTITY.version
        ):
            problems.append(
                _corrupt(
                    ProblemKind.UNKNOWN_GENERATION_IDENTITY,
                    MANIFEST_NAME,
                    f"manifest generator {manifest.generator.id}/"
                    f"{manifest.generator.version} is not "
                    f"{GENERATOR_IDENTITY.id}/{GENERATOR_IDENTITY.version}",
                )
            )
        counts_conserved = _check_counts(manifest, problems)

    # ---- top-level directory scan ----
    entries = _scan_dir(out, problems)
    case_dir_names: set[str] = set()
    if entries is not None:
        complete_claim = manifest_status is GenerationStatus.COMPLETE
        for item in entries:
            if bounds is not None:
                bounds.check_point()
            if item.name in _TOP_LEVEL_NAMES:
                if item.is_symlink():
                    problems.append(
                        _corrupt(
                            ProblemKind.SYMLINK, item.name, "bundle entry is a symbolic link"
                        )
                    )
                continue
            if item.name.startswith("."):
                problems.append(
                    _incomplete(
                        ProblemKind.PART_RESIDUE,
                        item.name,
                        "interrupted-write residue found"
                        + (
                            "; a COMPLETE manifest must not leave .part traces"
                            if complete_claim
                            else ""
                        ),
                    )
                )
                if complete_claim:
                    problems[-1] = _corrupt(
                        ProblemKind.PART_RESIDUE,
                        item.name,
                        ".part residue contradicts the COMPLETE manifest claim",
                    )
                continue
            problems.append(
                _corrupt(
                    ProblemKind.UNEXPECTED_ENTRY,
                    item.name,
                    "unknown top-level entry in the bundle directory",
                )
            )
        cases_scan = _scan_dir(out / CASES_DIRNAME, problems)
        if cases_scan is not None:
            for item in cases_scan:
                if bounds is not None:
                    bounds.check_point()
                if item.is_symlink():
                    problems.append(
                        _corrupt(
                            ProblemKind.SYMLINK,
                            f"{CASES_DIRNAME}/{item.name}",
                            "cases entry is a symbolic link",
                        )
                    )
                elif item.name.startswith("."):
                    problems.append(
                        _incomplete(
                            ProblemKind.PART_RESIDUE,
                            f"{CASES_DIRNAME}/{item.name}",
                            "interrupted case-write residue found"
                            + (
                                "; a COMPLETE manifest must not leave .part traces"
                                if complete_claim
                                else ""
                            ),
                        )
                    )
                    if complete_claim:
                        problems[-1] = _corrupt(
                            ProblemKind.PART_RESIDUE,
                            f"{CASES_DIRNAME}/{item.name}",
                            ".part residue contradicts the COMPLETE manifest claim",
                        )
                else:
                    case_dir_names.add(item.name)

    # ---- profile.json ----
    if manifest is not None:
        profile_bytes = _read_capped(out / PROFILE_NAME, problems, bounds=bounds)
        if profile_bytes is None:
            problems.append(
                _corrupt(
                    ProblemKind.PROFILE_CORRUPT,
                    PROFILE_NAME,
                    "profile.json is missing or unreadable",
                )
            )
        else:
            profile_value = _strict_document(
                profile_bytes, PROFILE_NAME, problems, ProblemKind.PROFILE_CORRUPT
            )
            if profile_value is not None:
                try:
                    profile = decode_profile(profile_value, PROFILE_NAME)
                except ContractError as exc:
                    problems.append(
                        _corrupt(
                            ProblemKind.PROFILE_CORRUPT,
                            PROFILE_NAME,
                            f"illegal profile document: {exc}",
                        )
                    )
                else:
                    recomputed = sha256_hex(canonical_json(profile.to_obj()))
                    if recomputed != manifest.profile_hash:
                        problems.append(
                            _corrupt(
                                ProblemKind.PROFILE_MISMATCH,
                                PROFILE_NAME,
                                f"recomputed profile hash {recomputed} does not "
                                f"match manifest.profile_hash {manifest.profile_hash}",
                            )
                        )

    # ---- referenced cases ----
    if manifest is not None:
        entries_by_id = {entry.case_id: entry for entry in manifest.case_files}
        emitted_ids = {
            receipt.case_id
            for receipt in manifest.receipts
            if receipt.outcome is OrdinalOutcome.EMITTED and receipt.case_id is not None
        }
        for case_id, entry in sorted(entries_by_id.items()):
            if bounds is not None:
                bounds.check_point()
            if case_id not in emitted_ids:
                problems.append(
                    _corrupt(
                        ProblemKind.UNREFERENCED_CASE_ENTRY,
                        f"{CASES_DIRNAME}/{case_id}",
                        "case_files entry is not referenced by any emitted ordinal receipt",
                    )
                )
            result = _validate_case_directory(
                out / CASES_DIRNAME, case_id, entry, problems, bounds=bounds
            )
            if result is not None:
                cases_validated += 1
        for receipt in manifest.receipts:
            if bounds is not None:
                bounds.check_point()
            if receipt.outcome is OrdinalOutcome.EMITTED:
                if receipt.case_id not in entries_by_id:
                    problems.append(
                        _corrupt(
                            ProblemKind.RECEIPT_CASE_MISMATCH,
                            MANIFEST_NAME,
                            f"ordinal {receipt.ordinal} emits case_id "
                            f"{receipt.case_id!r} with no case_files entry",
                        )
                    )

        # ---- unreferenced directories on disk ----
        for name in sorted(case_dir_names - set(entries_by_id)):
            if bounds is not None:
                bounds.check_point()
            if len(name) == 64 and all(c in "0123456789abcdef" for c in name):
                problems.append(
                    _incomplete(
                        ProblemKind.ORPHAN_CASE_DIR,
                        f"{CASES_DIRNAME}/{name}",
                        "published case directory is not referenced by the manifest",
                    )
                )
            else:
                problems.append(
                    _corrupt(
                        ProblemKind.PATH_ESCAPE,
                        f"{CASES_DIRNAME}/{name}",
                        "cases entry name is not a safe 64-hex case id",
                    )
                )

    return ValidationReport(
        output_dir=out,
        manifest_status=manifest_status,
        problems=tuple(problems),
        cases_validated=cases_validated,
        counts_conserved=counts_conserved,
    )
