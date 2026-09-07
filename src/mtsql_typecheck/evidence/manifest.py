"""D4 delivery package manifest writer and strict validator (design 6.2.3, 6.4.1, 6.5).

The delivery package layout (design 6.2.3)::

    <new-output>/
      evidence-manifest.json      # sealed LAST, never self-referencing
      assessment.json
      report.json / report.md / report.html   (report kind)
      raw/<source-id>/...         # native bytes, package-relative tree
      reviews/<review-id>.json    # explicit user-provided review copies

House rules: every content problem is *reported* through the typed
:class:`DeliveryValidation` problems list and never raised - only I/O
failures and writer-misuse raise.  Hashes and sizes always cover the actual
package bytes; the manifest is written atomically (``.``-prefixed ``.part``
temp name + ``os.replace``) and fsynced (file and parent directory) through
an injectable hook so tests can fail any durability step and verify that
originals stay intact and nothing is half-sealed (design 6.4.1 step 6).
``collect_delivery_files`` walks the package without following symlinks and
refuses symlink entries with a typed error; ``evidence-manifest.json``
itself is excluded (the manifest must never list itself, and the file set it
seals is frozen at write time).  Importing this module performs no I/O.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from ..contracts.case import ContractError
from ..contracts.codec import canonical_json, parse_strict_json
from ..contracts.delivery import (
    ASSESSMENT_FILENAME,
    MANIFEST_FILENAME,
    DeliveryCompletion,
    DeliveryKind,
    EvidenceFile,
    EvidenceManifest,
    FileRole,
    Limits,
    check_package_path,
    decode_evidence_manifest,
)

__all__ = [
    "MANIFEST_FILENAME",
    "DeliveryError",
    "SymlinkEntryError",
    "ManifestExistsError",
    "DeliveryLimitError",
    "UnclassifiableFileError",
    "FsyncFailedError",
    "Problem",
    "DeliveryValidation",
    "classify_role",
    "collect_delivery_files",
    "write_evidence_manifest",
    "validate_delivery_dir",
    "required_files_for",
]

_HASH_CHUNK_BYTES = 1024 * 1024

# Stable problem codes (design 6.3: stable reasons; exit-code mapping is the
# CLI's job, these codes only classify).
P_MISSING_MANIFEST = "missing_manifest"
P_MANIFEST_CORRUPT = "manifest_corrupt"
P_DUPLICATE = "duplicate"
P_MISSING_FILE = "missing_file"
P_HASH_MISMATCH = "hash_mismatch"
P_NOT_REGULAR_FILE = "not_regular_file"
P_EXTRA_FILE = "extra_file"
P_MISSING_REQUIRED = "missing_required"
P_SYMLINK_ENTRY = "symlink_entry"
P_NOT_REGULAR_ENTRY = "not_regular_entry"
P_SOURCE_ID_MISMATCH = "source_id_mismatch"
P_LIMIT_EXCEEDED = "limit_exceeded"

_REQUIRED_REPORT_FILES = ("report.json", "report.md", "report.html")

# Best-effort export file names (design 6.2.3); exports live in their own
# directories, so classification matches the basename and yields None when
# nothing is known.
_EXPORT_BASENAME_ROLES = {
    "a.sql": FileRole.EXPORT_SQL_A,
    "b.sql": FileRole.EXPORT_SQL_B,
    "case.json": FileRole.EXPORT_CASE,
    "expected.json": FileRole.EXPORT_EXPECTED,
    "environment-requirements.json": FileRole.EXPORT_ENVIRONMENT_REQUIREMENTS,
    "origin.json": FileRole.EXPORT_ORIGIN,
    "README.md": FileRole.EXPORT_README,
    "regression-case.json": FileRole.EXPORT_REGRESSION_CASE,
}


class DeliveryError(ContractError):
    """Base class for delivery-package writer/validator errors."""


class SymlinkEntryError(DeliveryError):
    """A package entry is a symbolic link; links are never followed."""


class ManifestExistsError(DeliveryError):
    """evidence-manifest.json already exists; the manifest is sealed once."""


class DeliveryLimitError(DeliveryError):
    """The package exceeds the configured file-count or depth limits."""


class UnclassifiableFileError(DeliveryError):
    """A package file has no known role; the caller must resolve it."""


class FsyncFailedError(DeliveryError):
    """The injected fsync hook failed; nothing was published."""


# --------------------------------------------------------------------------
# Role classification
# --------------------------------------------------------------------------


def classify_role(relpath: str, source_id: Optional[str] = None) -> Optional[FileRole]:
    """Best-effort package role for one package-relative path.

    ``raw/<source-id>/...`` is RAW_NATIVE; the assessment, report and review
    paths are fixed; export file names (design 6.2.3) are recognised by
    basename only, best-effort.  ``None`` means unknown; the ``source_id``
    parameter is accepted for interface stability and is not needed for
    classification (the raw binding is validated from the path itself).
    """
    del source_id  # classification is syntactic; see docstring
    if relpath.startswith("raw/") or relpath == "raw":
        return FileRole.RAW_NATIVE
    if relpath == ASSESSMENT_FILENAME:
        return FileRole.ASSESSMENT
    if relpath == "report.json":
        return FileRole.REPORT_JSON
    if relpath == "report.md":
        return FileRole.REPORT_MD
    if relpath == "report.html":
        return FileRole.REPORT_HTML
    if relpath.startswith("reviews/") and relpath.endswith(".json"):
        return FileRole.REVIEW
    basename = relpath.rsplit("/", 1)[-1]
    return _EXPORT_BASENAME_ROLES.get(basename)


# --------------------------------------------------------------------------
# Package walking / hashing primitives
# --------------------------------------------------------------------------


def _hash_file(path: Path) -> tuple[int, str]:
    """Streaming ``(size, sha256)`` over the actual bytes of one file."""
    running = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(_HASH_CHUNK_BYTES)
            if not chunk:
                break
            running.update(chunk)
            size += len(chunk)
    return size, running.hexdigest()


@dataclass(frozen=True)
class _Walked:
    relpath: str
    source_id: Optional[str]


def _walk_package_files(
    root: Path,
    limits: Limits,
    problems: Optional[list["Problem"]],
) -> list[_Walked]:
    """Bounded recursive scandir walk that never follows symlinks.

    With ``problems`` the walker records symlink/non-regular entries and
    limit overruns as problems and keeps going (validator mode); without it,
    the same conditions raise typed errors (collector mode).
    """
    found: list[_Walked] = []
    count = 0

    def refuse(message: str, error_cls: type[DeliveryError]) -> None:
        if problems is None:
            raise error_cls(message)

    def visit(dirpath: Path, relprefix: str, depth: int) -> None:
        nonlocal count
        if depth > limits.max_dir_depth:
            if problems is None:
                raise DeliveryLimitError(
                    f"package directory depth exceeds limits.max_dir_depth "
                    f"({limits.max_dir_depth}) at {relprefix!r}"
                )
            problems.append(
                Problem(
                    code=P_LIMIT_EXCEEDED,
                    path=relprefix or None,
                    detail=f"directory depth exceeds {limits.max_dir_depth}",
                )
            )
            return
        try:
            entries = list(os.scandir(dirpath))
        except OSError:
            raise
        for entry in entries:
            count += 1
            if count > limits.max_files:
                message = (
                    f"package holds more than limits.max_files "
                    f"({limits.max_files}) entries"
                )
                if problems is None:
                    raise DeliveryLimitError(message)
                problems.append(
                    Problem(code=P_LIMIT_EXCEEDED, path=None, detail=message)
                )
                return
            relpath = f"{relprefix}{entry.name}"
            if entry.is_symlink():
                refuse(
                    f"package entry {relpath!r} is a symbolic link; links are "
                    "never followed in a delivery package",
                    SymlinkEntryError,
                )
                if problems is not None:
                    problems.append(
                        Problem(
                            code=P_SYMLINK_ENTRY,
                            path=relpath,
                            detail="entry is a symbolic link",
                        )
                    )
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                raise
            if is_dir:
                visit(Path(entry.path), f"{relpath}/", depth + 1)
            elif is_file:
                source_id: Optional[str] = None
                parts = relpath.split("/")
                if len(parts) >= 3 and parts[0] == "raw":
                    source_id = parts[1]
                found.append(_Walked(relpath=relpath, source_id=source_id))
            else:
                refuse(
                    f"package entry {relpath!r} is not a regular file or directory",
                    DeliveryError,
                )
                if problems is not None:
                    problems.append(
                        Problem(
                            code=P_NOT_REGULAR_ENTRY,
                            path=relpath,
                            detail="entry is neither a regular file nor a directory",
                        )
                    )

    visit(root, "", 1)
    return found


# --------------------------------------------------------------------------
# Collection (build side)
# --------------------------------------------------------------------------


def collect_delivery_files(output_root: Path, limits: Limits) -> tuple[EvidenceFile, ...]:
    """Seal every package file except the manifest into EvidenceFile entries.

    Walks ``output_root`` (bounded by ``limits.max_files`` /
    ``max_dir_depth``, never following symlinks - symlink entries raise
    :class:`SymlinkEntryError`), hashes the actual bytes streaming and
    classifies each path with :func:`classify_role`.  ``evidence-manifest.json``
    itself is excluded: the manifest never self-references (design 6.2.1).
    Files with no known role raise :class:`UnclassifiableFileError` so that
    nothing unaccounted can enter a sealed package.
    """
    root = Path(output_root)
    root_stat = os.lstat(root)
    if stat.S_ISLNK(root_stat.st_mode):
        raise SymlinkEntryError(f"package root {str(root)!r} is a symbolic link")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise DeliveryError(f"package root {str(root)!r} is not a directory")

    entries = _walk_package_files(root, limits, None)
    files: list[EvidenceFile] = []
    for walked in entries:
        if walked.relpath == MANIFEST_FILENAME:
            continue
        role = classify_role(walked.relpath)
        if role is None:
            raise UnclassifiableFileError(
                f"package file {walked.relpath!r} has no known delivery role; "
                "remove it or extend the role table"
            )
        size, digest = _hash_file(root / walked.relpath)
        try:
            files.append(
                EvidenceFile(
                    path=walked.relpath,
                    role=role,
                    size_bytes=size,
                    sha256=digest,
                    source_id=walked.source_id if role is FileRole.RAW_NATIVE else None,
                )
            )
        except ContractError as exc:
            raise DeliveryError(
                f"package file {walked.relpath!r} rejected by the delivery "
                f"contract: {exc}"
            ) from exc
    return tuple(sorted(files, key=lambda file_entry: file_entry.path))


# --------------------------------------------------------------------------
# Manifest writing (last sealed file)
# --------------------------------------------------------------------------


def _fsync_path(fsync: Callable[[int], None], path: Path, what: str) -> None:
    fd = os.open(str(path), os.O_RDONLY)
    try:
        fsync(fd)
    finally:
        os.close(fd)


def write_evidence_manifest(
    output_root: Path,
    manifest: EvidenceManifest,
    *,
    fsync: Callable[[int], None] = os.fsync,
) -> None:
    """Publish ``evidence-manifest.json`` atomically as the LAST sealed file.

    The manifest is serialized canonically (``manifest.to_obj()`` ->
    ``canonical_json`` plus one trailing newline), written to a
    ``.``-prefixed ``.part`` temp file, fsynced through the injectable hook,
    then ``os.replace``d into place and the parent directory fsynced.  An
    existing manifest is never overwritten (:class:`ManifestExistsError`).
    On any failure the temp file is removed, no manifest appears and the
    package's original files stay untouched (design 6.4.1 step 6).
    """
    if not isinstance(manifest, EvidenceManifest):
        raise DeliveryError("write_evidence_manifest needs an EvidenceManifest")
    root = Path(output_root)
    final = root / MANIFEST_FILENAME
    if os.path.lexists(final):
        raise ManifestExistsError(
            f"{MANIFEST_FILENAME} already exists in {str(root)!r}; the "
            "delivery manifest is sealed exactly once and never overwritten"
        )
    data = canonical_json(manifest.to_obj()) + b"\n"
    temp = root / f".{MANIFEST_FILENAME}.part"
    try:
        fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise DeliveryError(
            f"stale manifest temp file {str(temp)!r} exists; resolve it before sealing"
        ) from exc
    except OSError as exc:
        raise DeliveryError(f"cannot create manifest temp file: {exc}") from exc
    try:
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                fsync(handle.fileno())
        except OSError as exc:
            raise FsyncFailedError(f"cannot make the manifest bytes durable: {exc}") from exc
        os.replace(temp, final)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise
    try:
        _fsync_path(fsync, root, "delivery-root")
    except OSError as exc:
        raise FsyncFailedError(f"cannot make the delivery directory durable: {exc}") from exc


# --------------------------------------------------------------------------
# Validation (read side)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Problem:
    """One validator problem: stable short code, optional path, detail."""

    code: str
    path: Optional[str]
    detail: str


@dataclass(frozen=True)
class DeliveryValidation:
    """Strict re-validation result for an existing D4 package (design 6.5).

    Content problems never raise; ``ok`` is true only when ``problems`` is
    empty.  ``kind``/``completion``/``delivery_id`` come from the decoded
    manifest and are ``None`` whenever the manifest could not be decoded.
    """

    ok: bool
    kind: Optional[DeliveryKind]
    completion: Optional[DeliveryCompletion]
    delivery_id: Optional[str]
    problems: tuple[Problem, ...] = ()


def required_files_for(kind: DeliveryKind) -> tuple[str, ...]:
    """Package-relative files every package of ``kind`` must contain.

    Both kinds need the manifest and the assessment; a report package must
    additionally contain all three report renderings (design 6.2.3).  The
    raw closure presence is checked separately by
    :func:`validate_delivery_dir` because it is a role condition, not a
    fixed path.
    """
    if kind is DeliveryKind.REPORT:
        return (MANIFEST_FILENAME, ASSESSMENT_FILENAME) + _REQUIRED_REPORT_FILES
    return (MANIFEST_FILENAME, ASSESSMENT_FILENAME)


def validate_delivery_dir(root: Path, limits: Limits) -> DeliveryValidation:
    """Re-validate a D4 delivery package against its own sealed manifest.

    Decodes ``evidence-manifest.json`` with the strict loader (schema,
    identity and self-reference rules), then checks every listed file's
    actual size and SHA-256 over the package bytes, closure completeness in
    both directions (missing listed files and unlisted extra files), the
    RAW_NATIVE ``source_id`` path convention, the required files for the
    manifest kind and the presence of a raw closure.  Only I/O errors
    propagate; every content problem is returned as a :class:`Problem`.
    """
    root = Path(root)
    problems: list[Problem] = []
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        raise DeliveryError(f"cannot inspect package root {str(root)!r}: {exc}") from exc
    if stat.S_ISLNK(root_stat.st_mode):
        raise DeliveryError(f"package root {str(root)!r} is a symbolic link")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise DeliveryError(f"package root {str(root)!r} is not a directory")

    manifest_path = root / MANIFEST_FILENAME
    try:
        data = manifest_path.read_bytes()
    except FileNotFoundError:
        return DeliveryValidation(
            ok=False,
            kind=None,
            completion=None,
            delivery_id=None,
            problems=(
                Problem(
                    code=P_MISSING_MANIFEST,
                    path=MANIFEST_FILENAME,
                    detail="the delivery manifest is missing; nothing can be verified",
                ),
            ),
        )
    except OSError as exc:
        raise DeliveryError(f"cannot read {MANIFEST_FILENAME}: {exc}") from exc

    try:
        raw = parse_strict_json(data)
    except ContractError as exc:
        return DeliveryValidation(
            ok=False,
            kind=None,
            completion=None,
            delivery_id=None,
            problems=(
                Problem(
                    code=P_MANIFEST_CORRUPT,
                    path=MANIFEST_FILENAME,
                    detail=f"manifest is not strict canonical JSON: {exc}",
                ),
            ),
        )

    # Duplicate listed paths would fail the typed constructor as a generic
    # corruption; report them under their own stable code first.
    raw_files = raw.get("files") if isinstance(raw, dict) else None
    if isinstance(raw_files, list):
        seen: set[str] = set()
        for index, item in enumerate(raw_files):
            path = item.get("path") if isinstance(item, dict) else None
            if isinstance(path, str):
                if path in seen:
                    problems.append(
                        Problem(
                            code=P_DUPLICATE,
                            path=path,
                            detail=f"files[{index}] repeats path {path!r}",
                        )
                    )
                seen.add(path)

    try:
        manifest = decode_evidence_manifest(raw, MANIFEST_FILENAME)
    except ContractError as exc:
        problems.append(
            Problem(
                code=P_MANIFEST_CORRUPT,
                path=MANIFEST_FILENAME,
                detail=f"manifest rejected by the strict loader: {exc}",
            )
        )
        return DeliveryValidation(
            ok=False,
            kind=None,
            completion=None,
            delivery_id=None,
            problems=tuple(problems),
        )

    kind: DeliveryKind = manifest.kind
    listed = {file_entry.path: file_entry for file_entry in manifest.files}

    walked = _walk_package_files(root, limits, problems)
    present: dict[str, _Walked] = {}
    for walked_entry in walked:
        if walked_entry.relpath == MANIFEST_FILENAME:
            continue
        present[walked_entry.relpath] = walked_entry

    for path, file_entry in sorted(listed.items()):
        target = root / path
        try:
            entry_stat = os.lstat(target)
        except FileNotFoundError:
            problems.append(
                Problem(
                    code=P_MISSING_FILE,
                    path=path,
                    detail="manifest lists this file but it is absent from the package",
                )
            )
            continue
        except OSError as exc:
            raise DeliveryError(f"cannot inspect {path!r}: {exc}") from exc
        if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISREG(entry_stat.st_mode):
            problems.append(
                Problem(
                    code=P_NOT_REGULAR_FILE,
                    path=path,
                    detail="manifest entry is not a regular file in the package",
                )
            )
            continue
        actual_size, actual_digest = _hash_file(target)
        if actual_size != file_entry.size_bytes or actual_digest != file_entry.sha256:
            problems.append(
                Problem(
                    code=P_HASH_MISMATCH,
                    path=path,
                    detail=(
                        f"manifest hash/size {file_entry.sha256}/"
                        f"{file_entry.size_bytes} does not match the actual "
                        f"bytes {actual_digest}/{actual_size}"
                    ),
                )
            )
        if (
            file_entry.role is FileRole.RAW_NATIVE
            and file_entry.source_id is not None
            and not path.startswith(f"raw/{file_entry.source_id}/")
        ):
            problems.append(
                Problem(
                    code=P_SOURCE_ID_MISMATCH,
                    path=path,
                    detail=(
                        f"RAW_NATIVE file must live under raw/{file_entry.source_id}/"
                    ),
                )
            )

    for relpath in sorted(set(present) - set(listed)):
        problems.append(
            Problem(
                code=P_EXTRA_FILE,
                path=relpath,
                detail="package file is not listed in the manifest (closure incomplete)",
            )
        )

    has_raw = any(
        file_entry.role is FileRole.RAW_NATIVE
        for file_entry in manifest.files
        if file_entry.path in present
    )
    if not has_raw:
        problems.append(
            Problem(
                code=P_MISSING_REQUIRED,
                path="raw/",
                detail="the package lists no raw/native closure file; the source "
                "cannot be re-audited",
            )
        )
    for required in required_files_for(kind):
        # The manifest itself is present by construction (it was just decoded);
        # the walker excludes it from `present` because the manifest never
        # lists itself.
        if required != MANIFEST_FILENAME and required not in present:
            problems.append(
                Problem(
                    code=P_MISSING_REQUIRED,
                    path=required,
                    detail=f"every {str(kind.value)} package must contain {required!r}",
                )
            )

    return DeliveryValidation(
        ok=not problems,
        kind=kind,
        completion=manifest.completion,
        delivery_id=manifest.delivery_id,
        problems=tuple(problems),
    )
