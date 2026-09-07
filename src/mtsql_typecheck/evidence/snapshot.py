"""Exclusive immutable snapshot capture into ``raw/<source-id>/`` (design 6.4.1, 6.5).

``Snapshotter.capture`` copies the planned file closure of one native source
into ``output_root/raw/<source-id>/<relpath>`` and nothing else; the D4
evidence manifest itself is written by ``evidence.manifest``, never here.

Guarantees and semantics:

- Output is created exclusively.  The output root must not exist when the
  ``Snapshotter`` is constructed nor when ``capture`` runs; any pre-existing
  directory or file under ``raw/<source-id>/`` is refused, never overwritten.
  No hard links to the original files are ever created; every copied byte is
  written fresh into a file this process created (design 6.4.1 item 3).
- The output root must be neither inside the input root nor contain it.
  Placement is checked by real directory *identity* (st_dev/st_ino) of the
  existing, symlink-resolved ancestors of the output path (design 6.4.1 item
  1 forbids symlink following under the roots; the roots' own components are
  never resolved -- only their existing parent directories are, because a
  nonexistent output leaf cannot be resolved at all).  A spelling-based check
  additionally refuses outputs whose normalized path is an ancestor of the
  input path; since the output does not exist yet, an existing input can
  never truly live inside it, so this second check is defense-in-depth
  against pathological path spellings.
- Reading goes through the :class:`~evidence.reader.SourceReader` only; every
  source file is read twice.  Pass 1 hashes each planned file (bounded by its
  per-file ``max_bytes``) WITHOUT writing anything, so the snapshot digest --
  and therefore ``source_id`` and the ``raw/<source-id>/`` directory name --
  is known before the first output byte is written.  Pass 2 re-reads each
  file, verifies size/mtime against pass 1 and the content hash against the
  pass-1 digest, and only then streams the bytes into the exclusive output
  file, hashing while writing and fsync'ing file and directory through the
  injectable ``fsync`` hook.  The whole source tree is never held in memory;
  at most one file, itself capped by ``max_bytes``, is buffered at a time.
- Budget (design 6.5): raw output may consume at most
  ``max_output_total_bytes - min_diagnostic_reserve_bytes`` bytes (the
  diagnostic/manifest reserve counts inside the total output budget).  Before
  each file is written the projected total is checked; exceeding it raises
  BudgetExhaustedError and already-written files stay exactly where they are
  -- nothing is deleted or "repaired".
- Change handling (design 6.4.1 item 4): a SourceChangedError at any point
  marks the result ``source_changed=True`` and stops further reads.  When the
  change happens during pass 1, nothing is written at all.  When it happens
  during pass 2 or in the final re-stat sweep, the result still carries the
  pass-1 records (the safely-read diagnostic closure with verified hashes)
  and a digest computed over exactly those records plus the missing set --
  ``result.files``/``snapshot_digest``/``source_id`` always describe one
  consistent identity, but when ``source_changed`` is True the ``raw/`` copy
  may be a strict prefix of ``result.files`` and the result is NOT sealed:
  callers decide, and design forbids sealing a SOURCE_CHANGED source as
  COMPLETE.
- ``MissingEntryError`` on read records the path in ``missing_paths`` and
  continues.  ``UnsafePathError`` and ``ReadLimitExceededError`` abort the
  capture by re-raising (the caller turns them into REFUSED diagnostics);
  because pass 1 reads every file before any write, an unsafe or over-limit
  plan produces zero output bytes.
- Orphan files listed in ``plan.orphan_files`` are recorded in the result but
  never read or copied.
"""

from __future__ import annotations

import hashlib
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol, Sequence, Tuple, Union

from ..contracts.delivery import (
    Limits,
    NativeKind,
    check_package_path,
    compute_snapshot_digest,
    compute_source_id,
)
from .reader import (
    BudgetExhaustedError,
    EvidenceReadError,
    MissingEntryError,
    ReadLimitExceededError,
    SourceChangedError,
    SourceReader,
    UnsafePathError,
)

__all__ = [
    "SnapshotFileRecord",
    "SnapshotIoError",
    "SnapshotResult",
    "SnapshotSetupError",
    "Snapshotter",
]

_WRITE_CHUNK = 256 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW
_HEX64_CHARS = frozenset("0123456789abcdef")

_PathLike = Union[str, "os.PathLike[str]"]


class SnapshotSetupError(EvidenceReadError):
    """The capture cannot start or continue safely: the output root exists,
    lies inside the input root or contains it, or a pre-existing output path
    collided with exclusive creation."""


class SnapshotIoError(EvidenceReadError):
    """Output I/O or fsync failed.  Originals are untouched and no sealed
    result is produced; partially written output stays in place (design
    6.4.1 item 6: 中断保留未封存目录, 不自动修好)."""


class PlannedFileLike(Protocol):
    """Structural view of ``evidence.native.PlannedFile`` (avoids an import
    dependency on the sibling module)."""

    relpath: str
    max_bytes: int


class SourcePlanLike(Protocol):
    """Structural view of ``evidence.native.SourcePlan``."""

    kind: NativeKind
    root_document: str
    files: Sequence[PlannedFileLike]
    orphan_files: Sequence[str]


def _check_hex64(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= _HEX64_CHARS:
        raise ValueError(f"{name} must be a lowercase 64-char SHA-256 hex string")
    return value


@dataclass(frozen=True)
class SnapshotFileRecord:
    """One file captured into the snapshot: relative path, size and SHA-256
    of the bytes actually written (design 6.2.1 identity inputs)."""

    relpath: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.relpath, str) or not self.relpath:
            raise ValueError("SnapshotFileRecord.relpath must be a non-empty str")
        check_package_path(self.relpath, "SnapshotFileRecord.relpath")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int):
            raise ValueError("SnapshotFileRecord.size_bytes must be an int")
        if self.size_bytes < 0:
            raise ValueError("SnapshotFileRecord.size_bytes must be >= 0")
        _check_hex64(self.sha256, "SnapshotFileRecord.sha256")


@dataclass(frozen=True)
class SnapshotResult:
    """Outcome of one :meth:`Snapshotter.capture` call.

    ``source_id == "s-" + snapshot_digest`` always holds, and the digest is
    computed over exactly ``files`` (sorted, unique) plus ``missing_paths``.
    When ``source_changed`` is True the result describes a diagnostic closure
    only and must never be sealed as COMPLETE (design 6.4.1 item 4).
    """

    kind: NativeKind
    source_id: str
    snapshot_digest: str
    files: Tuple[SnapshotFileRecord, ...]
    missing_paths: Tuple[str, ...]
    orphan_files: Tuple[str, ...]
    bytes_written: int
    source_changed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.kind, NativeKind):
            raise ValueError("SnapshotResult.kind must be a NativeKind")
        _check_hex64(self.snapshot_digest, "SnapshotResult.snapshot_digest")
        if self.source_id != compute_source_id(self.snapshot_digest):
            raise ValueError("SnapshotResult.source_id must equal 's-' + snapshot_digest")
        if isinstance(self.bytes_written, bool) or not isinstance(self.bytes_written, int):
            raise ValueError("SnapshotResult.bytes_written must be an int")
        if self.bytes_written < 0:
            raise ValueError("SnapshotResult.bytes_written must be >= 0")
        previous: Optional[str] = None
        for record in self.files:
            if not isinstance(record, SnapshotFileRecord):
                raise ValueError("SnapshotResult.files must hold SnapshotFileRecord items")
            if previous is not None and record.relpath <= previous:
                raise ValueError("SnapshotResult.files must be sorted and unique by relpath")
            previous = record.relpath


@dataclass(frozen=True)
class _PassRecord:
    """Internal pass-1 bookkeeping for one planned file."""

    relpath: str
    max_bytes: int
    size_bytes: int
    mtime_ns: int
    sha256: str


class Snapshotter:
    """Captures one exclusive raw snapshot for a SourceReader (agent B pinned
    API).  The output root must not exist at construction time; it is created
    by :meth:`capture` and only under ``raw/<source-id>/`` is anything
    written."""

    def __init__(
        self,
        reader: SourceReader,
        output_root: _PathLike,
        limits: Limits,
        *,
        clock: Callable[[], float] = time.monotonic,
        deadline: Optional[float] = None,
        fsync: Callable[[int], None] = os.fsync,
    ) -> None:
        if not isinstance(reader, SourceReader):
            raise TypeError("Snapshotter requires a SourceReader")
        if not isinstance(limits, Limits):
            raise TypeError("Snapshotter requires a contracts.delivery.Limits instance")
        self._reader = reader
        self._limits = limits
        self._clock = clock
        self._deadline = deadline
        self._fsync_fn = fsync
        self._output_root = Path(os.path.abspath(os.fspath(output_root)))
        self._created_dirs: set[str] = set()
        self._check_placement()

    # -- setup checks --------------------------------------------------------

    def _check_deadline(self, where: str) -> None:
        if self._deadline is not None and self._clock() >= self._deadline:
            raise BudgetExhaustedError(f"time budget exhausted while {where}")

    def _raw_budget(self) -> int:
        """Bytes usable for raw copies: the output total minus the reserved
        diagnostic/manifest budget (design 6.5: 预留本身也计入总限额)."""
        return self._limits.max_output_total_bytes - self._limits.min_diagnostic_reserve_bytes

    def _check_placement(self) -> None:
        out = self._output_root
        try:
            os.lstat(out)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise SnapshotSetupError(f"output root {str(out)!r} cannot be inspected: {exc}") from exc
        else:
            raise SnapshotSetupError(
                f"output root {str(out)!r} already exists; output is never written over "
                f"an existing path"
            )
        try:
            input_str = os.path.abspath(os.fspath(self._reader.root))
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise SnapshotSetupError(f"input root path is unusable: {exc}") from exc
        inp = Path(input_str)
        if out == inp:
            raise SnapshotSetupError("output root equals the input root")
        # Defense-in-depth spelling check: the output does not exist yet, so
        # an existing input can never truly live inside it, but refuse the
        # pathological spelling outright.
        if inp.is_relative_to(out):
            raise SnapshotSetupError(
                f"input root {str(inp)!r} lies inside the output root {str(out)!r}"
            )
        # Identity check: walk the existing, symlink-resolved ancestors of the
        # output path.  Symlinks among existing parents are resolved via
        # os.stat deliberately (their target is the real location); no
        # component under either root is ever followed because none of the
        # output leaves exist yet.
        try:
            in_st = os.lstat(self._reader.root)
        except OSError as exc:
            raise SnapshotSetupError(f"input root cannot be inspected: {exc}") from exc
        in_identity = (in_st.st_dev, in_st.st_ino)
        try:
            ancestor_identities = _existing_ancestor_identities(out)
        except OSError as exc:
            raise SnapshotSetupError(
                f"cannot resolve the output root ancestors to check placement: {exc}"
            ) from exc
        for identity in ancestor_identities:
            if identity == in_identity:
                raise SnapshotSetupError(
                    f"output root {str(out)!r} lies inside the input root"
                )

    # -- output helpers ------------------------------------------------------

    @contextmanager
    def _ensure_dirs(self, raw_fd: int, relpath: str):
        """Yield the fd of the parent directory of ``relpath`` under the raw
        source directory, creating every missing level exclusively.  A
        pre-existing path component (any type) is refused."""
        parts = relpath.split("/")[:-1]
        current = raw_fd
        opened: list[int] = []
        prefix = ""
        try:
            for name in parts:
                prefix = name if prefix == "" else prefix + "/" + name
                if prefix not in self._created_dirs:
                    try:
                        os.mkdir(name, 0o700, dir_fd=current)
                    except FileExistsError as exc:
                        raise SnapshotSetupError(
                            f"pre-existing output path component {prefix!r} refused"
                        ) from exc
                    except OSError as exc:
                        raise SnapshotIoError(f"cannot create output directory: {exc}") from exc
                    self._created_dirs.add(prefix)
                    self._fsync(current)
                try:
                    fd = os.open(name, _DIR_FLAGS, dir_fd=current)
                except OSError as exc:
                    raise SnapshotIoError(f"cannot reopen output directory: {exc}") from exc
                opened.append(fd)
                current = fd
            yield current
        finally:
            for fd in opened:
                os.close(fd)

    def _fsync(self, fd: int) -> None:
        try:
            self._fsync_fn(fd)
        except OSError as exc:
            raise SnapshotIoError(f"fsync failed: {exc}") from exc

    def _mkdir_exclusive(self, parent_fd: Optional[int], name: str, what: str) -> int:
        """mkdir ``name`` (under ``parent_fd`` or at the output root) and
        return its fd; any pre-existing entry is refused."""
        try:
            if parent_fd is None:
                os.mkdir(self._output_root, 0o700)
            else:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise SnapshotSetupError(f"pre-existing output path refused for {what}") from exc
        except OSError as exc:
            raise SnapshotIoError(f"cannot create {what}: {exc}") from exc
        try:
            if parent_fd is None:
                fd = os.open(self._output_root, _DIR_FLAGS)
            else:
                fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        except OSError as exc:  # pragma: no cover - we just created it
            raise SnapshotIoError(f"cannot reopen {what}: {exc}") from exc
        self._fsync(fd if parent_fd is None else parent_fd)
        return fd

    def _write_file(self, dirfd: int, name: str, data: bytes) -> str:
        """Exclusively create one output file, stream ``data`` into it in
        chunks while hashing, fsync the file and its directory.  Returns the
        SHA-256 of the bytes actually written."""
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600,
                         dir_fd=dirfd)
        except FileExistsError as exc:
            raise SnapshotSetupError(f"pre-existing output file {name!r} refused") from exc
        except OSError as exc:
            raise SnapshotIoError(f"cannot create output file {name!r}: {exc}") from exc
        try:
            hasher = hashlib.sha256()
            view = memoryview(data)
            for offset in range(0, len(view), _WRITE_CHUNK):
                chunk = view[offset : offset + _WRITE_CHUNK]
                remaining = chunk
                while remaining:
                    written = os.write(fd, remaining)
                    if written <= 0:  # pragma: no cover - kernel-level failure
                        raise SnapshotIoError("short write to snapshot file")
                    remaining = remaining[written:]
                hasher.update(chunk)
            self._fsync(fd)
            written_sha = hasher.hexdigest()
        finally:
            os.close(fd)
        self._fsync(dirfd)
        return written_sha

    # -- capture -------------------------------------------------------------

    def capture(self, plan: SourcePlanLike) -> SnapshotResult:
        """Snapshot the planned closure; see the module docstring for the
        precise pass-1/pass-2, budget and change semantics."""
        self._check_deadline("capturing the snapshot")
        kind = plan.kind
        if not isinstance(kind, NativeKind):
            raise SnapshotSetupError("plan.kind must be a NativeKind")
        root_document = plan.root_document
        if not isinstance(root_document, str):
            raise SnapshotSetupError("plan.root_document must be a str")
        try:
            ordered = sorted(plan.files, key=lambda item: item.relpath)
        except (AttributeError, TypeError) as exc:
            raise SnapshotSetupError(f"plan.files is not a usable file sequence: {exc}") from exc
        planned: list[Tuple[str, int]] = []
        seen: set[str] = set()
        for item in ordered:
            relpath = item.relpath
            max_bytes = item.max_bytes
            if not isinstance(relpath, str) or not relpath:
                raise SnapshotSetupError("plan file relpath must be a non-empty str")
            if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
                raise SnapshotSetupError(f"plan file {relpath!r} has an invalid max_bytes")
            if relpath in seen:
                raise SnapshotSetupError(f"plan contains duplicate relpath {relpath!r}")
            seen.add(relpath)
            planned.append((relpath, min(max_bytes, self._limits.max_output_single_file_bytes)))
        try:
            orphans = tuple(sorted(set(plan.orphan_files)))
        except TypeError as exc:
            raise SnapshotSetupError(f"plan.orphan_files is not a usable sequence: {exc}") from exc

        # Pass 1: hash every planned file, writing nothing.
        records: list[_PassRecord] = []
        missing: list[str] = []
        source_changed = False
        for relpath, max_bytes in planned:
            self._check_deadline(f"reading {relpath!r} (snapshot pass 1)")
            try:
                entry = self._reader.stat(relpath)
                data = self._reader.read_bytes(relpath, max_bytes=max_bytes)
            except MissingEntryError:
                missing.append(relpath)
                continue
            except SourceChangedError:
                source_changed = True
                break
            records.append(
                _PassRecord(
                    relpath=relpath,
                    max_bytes=max_bytes,
                    size_bytes=len(data),
                    mtime_ns=entry.mtime_ns,
                    sha256=hashlib.sha256(data).hexdigest(),
                )
            )
            del data

        file_entries = [(r.relpath, r.size_bytes, r.sha256) for r in records]
        missing_paths = tuple(sorted(set(missing)))
        snapshot_digest = compute_snapshot_digest(
            str(kind.value), root_document, file_entries, missing_paths
        )
        source_id = compute_source_id(snapshot_digest)
        result_files = tuple(
            SnapshotFileRecord(relpath=r.relpath, size_bytes=r.size_bytes, sha256=r.sha256)
            for r in records
        )
        if source_changed:
            # Diagnostic closure only: nothing was written, the caller decides
            # what to do with a changed source (design 6.4.1 item 4).
            return SnapshotResult(
                kind=kind,
                source_id=source_id,
                snapshot_digest=snapshot_digest,
                files=result_files,
                missing_paths=missing_paths,
                orphan_files=orphans,
                bytes_written=0,
                source_changed=True,
            )

        # Pass 2: verified exclusive copy into raw/<source-id>/.
        raw_budget = self._raw_budget()
        bytes_written = 0
        out_fd = self._mkdir_exclusive(None, str(self._output_root), "output root")
        raw_fd: Optional[int] = None
        source_fd: Optional[int] = None
        try:
            raw_fd = self._mkdir_exclusive(out_fd, "raw", "raw directory")
            source_fd = self._mkdir_exclusive(raw_fd, source_id, f"source directory {source_id}")
            for record in records:
                self._check_deadline(f"publishing {record.relpath!r} (snapshot pass 2)")
                try:
                    entry = self._reader.stat(record.relpath)
                    if (entry.size_bytes, entry.mtime_ns) != (
                        record.size_bytes,
                        record.mtime_ns,
                    ):
                        source_changed = True
                        break
                    data = self._reader.read_bytes(record.relpath, max_bytes=record.max_bytes)
                except (MissingEntryError, SourceChangedError, UnsafePathError):
                    # The source entry is drifting under us: stop publishing,
                    # keep what was already verified and written.
                    source_changed = True
                    break
                if len(data) != record.size_bytes or (
                    hashlib.sha256(data).hexdigest() != record.sha256
                ):
                    source_changed = True
                    break
                if bytes_written + len(data) > raw_budget:
                    raise BudgetExhaustedError(
                        f"output budget exhausted before publishing {record.relpath!r}: "
                        f"{bytes_written} + {len(data)} exceeds the raw budget of "
                        f"{raw_budget} bytes"
                    )
                name = record.relpath.split("/")[-1]
                with self._ensure_dirs(source_fd, record.relpath) as parent_fd:
                    written_sha = self._write_file(parent_fd, name, data)
                if written_sha != record.sha256:  # pragma: no cover - belt & braces
                    raise SnapshotIoError(
                        f"written bytes of {record.relpath!r} do not match the verified hash"
                    )
                bytes_written += len(data)
                del data

            if not source_changed:
                # Final re-stat sweep (design 6.4.1 item 4): every read source
                # file must still be the file we captured.
                for record in records:
                    self._check_deadline(f"re-checking {record.relpath!r} after capture")
                    try:
                        entry = self._reader.stat(record.relpath)
                    except (
                        MissingEntryError,
                        SourceChangedError,
                        UnsafePathError,
                        ReadLimitExceededError,
                    ):
                        source_changed = True
                        break
                    if (entry.size_bytes, entry.mtime_ns) != (
                        record.size_bytes,
                        record.mtime_ns,
                    ):
                        source_changed = True
                        break
        finally:
            for fd in (source_fd, raw_fd, out_fd):
                if fd is not None:
                    os.close(fd)

        return SnapshotResult(
            kind=kind,
            source_id=source_id,
            snapshot_digest=snapshot_digest,
            files=result_files,
            missing_paths=missing_paths,
            orphan_files=orphans,
            bytes_written=bytes_written,
            source_changed=source_changed,
        )


def _existing_ancestor_identities(path: Path) -> "list[Tuple[int, int]]":
    """(st_dev, st_ino) of every existing real ancestor directory of ``path``
    from its parent up to the filesystem root.  Nonexistent prefixes are
    skipped (they cannot contain anything yet); other stat failures fail
    closed by raising OSError to the caller."""
    identities: list[Tuple[int, int]] = []
    current = path
    while True:
        parent = current.parent
        if parent == current:
            break
        current = parent
        try:
            st = os.stat(current)
        except FileNotFoundError:
            continue
        identities.append((st.st_dev, st.st_ino))
    return identities
