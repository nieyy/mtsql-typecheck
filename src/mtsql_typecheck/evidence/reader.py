"""Safe bounded reading of a native evidence source tree (design 6.4.1, 6.5).

``SourceReader`` opens the input root once as a directory file descriptor and
performs every subsequent access *relative to that fd* (openat-style).  Path
components are opened with ``O_NOFOLLOW`` so a symlink component is refused
instead of followed, and the final component is inspected with ``lstat``
(which never follows its target) before any read.  The root itself is refused
when it is a symlink.  This is the design-6.4.1 rule that the reader must not
"first realpath and then reopen unprotected".

Honest residual-race statement (design 6.4.1 closing note): the snapshot can
detect ordinary concurrent changes via size/mtime re-checks before, during and
after each read, but it makes no claim of filesystem-atomic snapshotting and
no guarantee against a same-UID adversary that swaps path components between
the ``lstat`` and the ``open`` of the same name.  On platforms where
``O_NOFOLLOW`` is unavailable the reader falls back to ``lstat``-before /
``fstat``-after identity checks ((st_dev, st_ino) comparison) and refuses any
mismatch.

Bounded reads (design 6.5): sizes are checked via ``lstat``/``fstat`` BEFORE
any byte is read, so an over-limit document is rejected without opening the
file at all; the JSONL reader enforces a hard per-line cap and a total cap and
stops as soon as an over-limit line is detected, never buffering the remainder
of the file.  Tests prove this "stop before over-read" property by injecting
counting ``opener``/read hooks (the instance attribute ``_read`` is a
documented test seam defaulting to ``os.read``).

Deadlines: a monotonic clock is checked at loop boundaries (per chunk while
reading, per directory while walking).  An expired deadline raises
:class:`BudgetExhaustedError`; blocking kernel I/O cannot be interrupted.

No network, no subprocess, no database imports; standard library only.
"""

from __future__ import annotations

import errno
import os
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, Optional, Tuple, Union

from ..contracts.delivery import Limits

__all__ = [
    "BudgetExhaustedError",
    "EntryStat",
    "EvidenceReadError",
    "MissingEntryError",
    "ReadLimitExceededError",
    "RootInvalidError",
    "SourceChangedError",
    "SourceReader",
    "UnsafePathError",
]

# O_NOFOLLOW is optional on POSIX; macOS defines it.  When absent, the
# lstat-before/fstat-after identity checks below carry the safety burden.
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW
_READ_CHUNK = 64 * 1024

_ELOOP = getattr(errno, "ELOOP", 0)
_ENOTDIR = getattr(errno, "ENOTDIR", 0)
_ENAMETOOLONG = getattr(errno, "ENAMETOOLONG", 0)

_PathLike = Union[str, "os.PathLike[str]"]


class EvidenceReadError(Exception):
    """Base class for every safe-reader failure (design 6.4.1, 6.5)."""


class UnsafePathError(EvidenceReadError):
    """A path or entry is structurally unsafe: absolute, ``..``/``.``, empty
    component, backslash, NUL, over-long, over-deep, a symlink component, or a
    non-regular file (FIFO/device/socket/directory) used as a document."""


class MissingEntryError(EvidenceReadError):
    """A referenced path does not exist inside the source tree."""


class ReadLimitExceededError(EvidenceReadError):
    """A size/line/count cap would be exceeded; raised BEFORE the
    corresponding bytes are read (design 6.5: 超过限额不得尝试无界 fallback)."""


class SourceChangedError(EvidenceReadError):
    """The source entry changed (size/mtime/identity) during or across a
    read; the data read so far must not be trusted as a stable snapshot."""


class RootInvalidError(EvidenceReadError):
    """The input root is not a readable real directory (missing, symlink,
    other file type, or unopenable)."""


class BudgetExhaustedError(EvidenceReadError):
    """The injected monotonic deadline expired at a loop boundary."""


def _kind_of(st: os.stat_result) -> str:
    if stat.S_ISREG(st.st_mode):
        return "file"
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    return "other"


@dataclass(frozen=True)
class EntryStat:
    """Type, size and mtime of one source entry, taken without following
    symlinks.  ``kind`` is ``"file"``/``"dir"``/``"other"``."""

    relpath: str
    kind: str
    size_bytes: int
    mtime_ns: int


class SourceReader:
    """Bounded, symlink-refusing reader over one opened source directory.

    The reader is a context manager; the root directory fd is released by
    :meth:`close`.  ``clock``/``deadline`` bound every loop (design 6.5);
    ``opener`` (default :func:`os.open`) is the injectable open hook used by
    tests to count file opens and prove that over-limit inputs are rejected
    before being read.
    """

    def __init__(
        self,
        root: _PathLike,
        *,
        limits: Limits,
        clock: Callable[[], float] = time.monotonic,
        deadline: Optional[float] = None,
        opener: Callable[..., int] = os.open,
    ) -> None:
        if not isinstance(limits, Limits):
            raise TypeError("SourceReader requires a contracts.delivery.Limits instance")
        self._limits = limits
        self._clock = clock
        self._deadline = deadline
        self._opener = opener
        # Documented test seam: replace with a counting wrapper to assert how
        # many bytes were actually delivered from the kernel.
        self._read: Callable[[int, int], bytes] = os.read

        root_str = os.fspath(root)
        self._root_str = root_str
        try:
            st = os.lstat(root_str)
        except OSError as exc:
            raise RootInvalidError(f"input root {root_str!r} cannot be inspected: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise RootInvalidError(f"input root {root_str!r} is a symlink; refused")
        if not stat.S_ISDIR(st.st_mode):
            raise RootInvalidError(f"input root {root_str!r} is not a directory")
        try:
            self._dirfd = self._opener(root_str, _DIR_FLAGS)
        except OSError as exc:
            raise RootInvalidError(f"input root {root_str!r} cannot be opened: {exc}") from exc
        try:
            fst = os.fstat(self._dirfd)
        except OSError as exc:  # pragma: no cover - kernel-level failure
            os.close(self._dirfd)
            self._dirfd = -1
            raise RootInvalidError(f"input root {root_str!r} cannot be fstat'ed: {exc}") from exc
        if not stat.S_ISDIR(fst.st_mode):
            os.close(self._dirfd)
            self._dirfd = -1
            raise RootInvalidError(f"input root {root_str!r} is not a directory after open")
        self._root_identity = (fst.st_dev, fst.st_ino)

    # -- lifecycle -----------------------------------------------------------

    @property
    def root(self) -> str:
        """The root path as given (never re-resolved)."""
        return self._root_str

    def close(self) -> None:
        """Release the root directory fd; idempotent."""
        dirfd = getattr(self, "_dirfd", -1)
        if dirfd >= 0:
            os.close(dirfd)
            self._dirfd = -1

    def __enter__(self) -> "SourceReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._dirfd < 0:
            raise EvidenceReadError("SourceReader is closed")

    def _check_deadline(self, where: str) -> None:
        if self._deadline is not None and self._clock() >= self._deadline:
            raise BudgetExhaustedError(f"time budget exhausted while {where}")

    # -- path validation -----------------------------------------------------

    def _validate_relpath(self, relpath: str, *, allow_root: bool = False) -> str:
        """Reject every structurally unsafe path with UnsafePathError."""
        if not isinstance(relpath, str):
            raise UnsafePathError("relpath must be a str")
        if relpath == "":
            if allow_root:
                return ""
            raise UnsafePathError("relpath must be a non-empty relative path")
        if "\x00" in relpath:
            raise UnsafePathError(f"path contains a NUL byte: {relpath!r}")
        if "\\" in relpath:
            raise UnsafePathError(f"path must use POSIX separators, backslash found: {relpath!r}")
        if relpath.startswith("/"):
            # also covers UNC spellings such as "//server/..." via the empty
            # first component check below; backslash UNC is caught above.
            raise UnsafePathError(f"absolute path refused: {relpath!r}")
        parts = relpath.split("/")
        for part in parts:
            if part in ("", ".", ".."):
                raise UnsafePathError(f"illegal path component {part!r} in {relpath!r}")
        if len(relpath.encode("utf-8")) > self._limits.max_path_bytes:
            raise UnsafePathError(
                f"path exceeds max_path_bytes={self._limits.max_path_bytes}: {relpath!r}"
            )
        if len(parts) > self._limits.max_dir_depth:
            raise UnsafePathError(
                f"path exceeds max_dir_depth={self._limits.max_dir_depth}: {relpath!r}"
            )
        return relpath

    def _map_open_error(self, exc: OSError, relpath: str) -> EvidenceReadError:
        if isinstance(exc, FileNotFoundError):
            return MissingEntryError(f"missing source entry {relpath!r}")
        if exc.errno == _ELOOP:
            return UnsafePathError(f"symlink component refused in {relpath!r}")
        if exc.errno in (_ENOTDIR, _ENAMETOOLONG):
            return UnsafePathError(f"unsafe path {relpath!r}: {exc}")
        return EvidenceReadError(f"cannot access source entry {relpath!r}: {exc}")

    @contextmanager
    def _open_parent(self, relpath: str) -> Iterator[Tuple[int, str]]:
        """Walk the intermediate components of ``relpath`` with O_NOFOLLOW
        directory opens relative to the root fd; yield (parent dirfd, final
        name).  The root fd itself is yielded for single-component paths and
        is owned by the reader, only freshly opened fds are closed."""
        parts = relpath.split("/")
        current = self._dirfd
        opened: list[int] = []
        try:
            for name in parts[:-1]:
                try:
                    fd = self._opener(name, _DIR_FLAGS, dir_fd=current)
                except OSError as exc:
                    raise self._map_open_error(exc, relpath) from exc
                opened.append(fd)
                try:
                    fst = os.fstat(fd)
                except OSError as exc:  # pragma: no cover - kernel-level failure
                    raise EvidenceReadError(
                        f"cannot fstat directory component of {relpath!r}: {exc}"
                    ) from exc
                if not stat.S_ISDIR(fst.st_mode):
                    raise UnsafePathError(f"component of {relpath!r} is not a directory")
                current = fd
            yield current, parts[-1]
        finally:
            for fd in opened:
                os.close(fd)

    # -- public API ----------------------------------------------------------

    def exists(self, relpath: str) -> bool:
        """True when the entry exists; structurally unsafe paths still raise
        UnsafePathError (they are never silently reported as absent)."""
        self._ensure_open()
        try:
            self.stat(relpath)
        except MissingEntryError:
            return False
        return True

    def stat(self, relpath: str) -> EntryStat:
        """EntryStat for one entry, taken without following symlinks."""
        self._ensure_open()
        rel = self._validate_relpath(relpath, allow_root=True)
        self._check_deadline(f"stat {relpath!r}")
        if rel == "":
            fst = os.fstat(self._dirfd)
            return EntryStat(relpath="", kind="dir", size_bytes=fst.st_size,
                             mtime_ns=fst.st_mtime_ns)
        with self._open_parent(rel) as (dirfd, name):
            try:
                st = os.lstat(name, dir_fd=dirfd)
            except OSError as exc:
                raise self._map_open_error(exc, rel) from exc
        if stat.S_ISLNK(st.st_mode):
            # lstat saw the link itself; its size/mtime say nothing about any
            # document, so the entry is refused instead of described.
            raise UnsafePathError(f"{rel!r} is a symlink; refused")
        return EntryStat(relpath=rel, kind=_kind_of(st), size_bytes=st.st_size,
                         mtime_ns=st.st_mtime_ns)

    def read_bytes(self, relpath: str, *, max_bytes: int) -> bytes:
        """Read a regular file fully, refusing before reading when its size
        exceeds ``max_bytes`` (design 6.5: byte caps reject before parsing).

        Identity (size, mtime_ns) is captured before the read and re-checked
        after it; any mismatch raises SourceChangedError and the caller must
        discard the bytes.  Over-limit files raise ReadLimitExceededError
        without the file ever being opened (provably zero ``opener`` calls).
        """
        self._ensure_open()
        rel = self._validate_relpath(relpath)
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative int")
        self._check_deadline(f"reading {relpath!r}")
        with self._open_parent(rel) as (dirfd, name):
            try:
                st = os.lstat(name, dir_fd=dirfd)
            except OSError as exc:
                raise self._map_open_error(exc, rel) from exc
            if stat.S_ISLNK(st.st_mode):
                raise UnsafePathError(f"{rel!r} is a symlink; refused")
            if not stat.S_ISREG(st.st_mode):
                raise UnsafePathError(
                    f"{rel!r} is not a regular file (kind={_kind_of(st)}); refused as document"
                )
            if st.st_size > max_bytes:
                raise ReadLimitExceededError(
                    f"{rel!r} is {st.st_size} bytes, exceeding max_bytes={max_bytes}; "
                    f"refused before opening"
                )
            pre = (st.st_size, st.st_mtime_ns)
            try:
                fd = self._opener(name, os.O_RDONLY | _NOFOLLOW, dir_fd=dirfd)
            except OSError as exc:
                raise self._map_open_error(exc, rel) from exc
            try:
                fst = os.fstat(fd)
                if not stat.S_ISREG(fst.st_mode):
                    raise UnsafePathError(f"{rel!r} is not a regular file after open")
                if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                    raise SourceChangedError(f"{rel!r} was replaced between lstat and open")
                chunks: list[bytes] = []
                total = 0
                while True:
                    self._check_deadline(f"reading {rel!r}")
                    remaining = max_bytes - total
                    if remaining <= 0:
                        break
                    data = self._read(fd, min(_READ_CHUNK, remaining))
                    if not data:
                        break
                    chunks.append(data)
                    total += len(data)
                fst_after = os.fstat(fd)
            finally:
                os.close(fd)
        if (fst_after.st_size, fst_after.st_mtime_ns) != pre or total != fst_after.st_size:
            raise SourceChangedError(f"{rel!r} changed during read (size/mtime mismatch)")
        return b"".join(chunks)

    def read_jsonl(
        self, relpath: str, *, max_line_bytes: int, max_total_bytes: int
    ) -> "list[tuple[int, bytes]]":
        """Read a JSONL file line by line with hard caps (design 6.5).

        Returns ``(line_no, raw_line_without_trailing_newline)`` tuples with
        1-based line numbers.  The whole file is refused before opening when
        its size exceeds ``max_total_bytes``; an individual line longer than
        ``max_line_bytes`` stops the read as soon as the cap is crossed --
        the remainder of the file is never read or buffered.
        """
        self._ensure_open()
        rel = self._validate_relpath(relpath)
        for value, name in ((max_line_bytes, "max_line_bytes"), (max_total_bytes, "max_total_bytes")):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative int")
        self._check_deadline(f"reading {relpath!r}")
        with self._open_parent(rel) as (dirfd, name):
            try:
                st = os.lstat(name, dir_fd=dirfd)
            except OSError as exc:
                raise self._map_open_error(exc, rel) from exc
            if stat.S_ISLNK(st.st_mode):
                raise UnsafePathError(f"{rel!r} is a symlink; refused")
            if not stat.S_ISREG(st.st_mode):
                raise UnsafePathError(
                    f"{rel!r} is not a regular file (kind={_kind_of(st)}); refused as document"
                )
            if st.st_size > max_total_bytes:
                raise ReadLimitExceededError(
                    f"{rel!r} is {st.st_size} bytes, exceeding max_total_bytes="
                    f"{max_total_bytes}; refused before opening"
                )
            pre = (st.st_size, st.st_mtime_ns)
            try:
                fd = self._opener(name, os.O_RDONLY | _NOFOLLOW, dir_fd=dirfd)
            except OSError as exc:
                raise self._map_open_error(exc, rel) from exc
            try:
                fst = os.fstat(fd)
                if not stat.S_ISREG(fst.st_mode):
                    raise UnsafePathError(f"{rel!r} is not a regular file after open")
                if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                    raise SourceChangedError(f"{rel!r} was replaced between lstat and open")
                lines: "list[tuple[int, bytes]]" = []
                buf = bytearray()
                line_no = 0
                consumed = 0
                expected_size = st.st_size
                while consumed < expected_size:
                    self._check_deadline(f"reading JSONL {rel!r}")
                    chunk = self._read(fd, min(_READ_CHUNK, expected_size - consumed))
                    if not chunk:
                        break
                    consumed += len(chunk)
                    if consumed > max_total_bytes:
                        raise ReadLimitExceededError(
                            f"{rel!r} exceeded max_total_bytes={max_total_bytes} during read"
                        )
                    buf += chunk
                    while True:
                        idx = buf.find(b"\n")
                        if idx < 0:
                            break
                        line = bytes(buf[:idx])
                        del buf[: idx + 1]
                        line_no += 1
                        if len(line) > max_line_bytes:
                            raise ReadLimitExceededError(
                                f"{rel!r} line {line_no} is {len(line)} bytes, exceeding "
                                f"max_line_bytes={max_line_bytes}; stopped after reading "
                                f"{consumed} of {expected_size} bytes"
                            )
                        lines.append((line_no, line))
                    if len(buf) > max_line_bytes:
                        raise ReadLimitExceededError(
                            f"{rel!r} line {line_no + 1} exceeds max_line_bytes="
                            f"{max_line_bytes}; stopped after reading {consumed} of "
                            f"{expected_size} bytes"
                        )
                fst_after = os.fstat(fd)
            finally:
                os.close(fd)
        if buf:
            line_no += 1
            if len(buf) > max_line_bytes:
                raise ReadLimitExceededError(
                    f"{rel!r} line {line_no} exceeds max_line_bytes={max_line_bytes}"
                )
            lines.append((line_no, bytes(buf)))
        if (fst_after.st_size, fst_after.st_mtime_ns) != pre or consumed != fst_after.st_size:
            raise SourceChangedError(f"{rel!r} changed during read (size/mtime mismatch)")
        return lines

    def list_dir(self, relpath: str) -> "list[str]":
        """Sorted immediate child names of one directory."""
        self._ensure_open()
        rel = self._validate_relpath(relpath, allow_root=True)
        self._check_deadline(f"listing {relpath!r}")
        if rel == "":
            return sorted(os.listdir(self._dirfd))
        with self._open_parent(rel) as (dirfd, name):
            try:
                fd = self._opener(name, _DIR_FLAGS, dir_fd=dirfd)
            except OSError as exc:
                raise self._map_open_error(exc, rel) from exc
            try:
                fst = os.fstat(fd)
                if not stat.S_ISDIR(fst.st_mode):
                    raise UnsafePathError(f"{rel!r} is not a directory")
                names = sorted(os.listdir(fd))
            finally:
                os.close(fd)
        return names

    def walk(
        self, relprefix: str, *, max_entries: int
    ) -> Iterator[Tuple[str, str]]:
        """Deterministically iterate ``(relpath, kind)`` under ``relprefix``.

        The prefix entry itself is yielded first (kind ``"dir"`` for a
        directory prefix; a file/other prefix yields itself and stops); with
        the empty prefix every entry under the root is yielded.  Children are
        visited in sorted order per directory.  Emits at most ``max_entries``
        tuples, then raises ReadLimitExceededError.  The root directory
        identity is re-checked against the identity captured at open time and
        any drift raises SourceChangedError.  Symlink/FIFO/device entries are
        reported as kind ``"other"`` and are never opened.
        """
        self._ensure_open()
        rel = self._validate_relpath(relprefix, allow_root=True)
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 0:
            raise ValueError("max_entries must be a non-negative int")
        fst = os.fstat(self._dirfd)
        if (fst.st_dev, fst.st_ino) != self._root_identity:
            raise SourceChangedError("input root directory identity changed since open")
        self._check_deadline(f"walking {relprefix!r}")
        return self._walk(rel, max_entries)

    def _walk(self, prefix: str, max_entries: int) -> Iterator[Tuple[str, str]]:
        counter = 0

        def emit(relpath: str, kind: str) -> Tuple[str, str]:
            nonlocal counter
            counter += 1
            if counter > max_entries:
                raise ReadLimitExceededError(
                    f"walk exceeded max_entries={max_entries} at {relpath!r}"
                )
            return (relpath, kind)

        def rec(dirfd: int, base: str) -> Iterator[Tuple[str, str]]:
            for name in sorted(os.listdir(dirfd)):
                self._check_deadline("walking the source tree")
                child = name if base == "" else base + "/" + name
                self._validate_relpath(child)
                try:
                    st = os.lstat(name, dir_fd=dirfd)
                except OSError as exc:
                    raise self._map_open_error(exc, child) from exc
                if stat.S_ISDIR(st.st_mode):
                    yield emit(child, "dir")
                    try:
                        fd = self._opener(name, _DIR_FLAGS, dir_fd=dirfd)
                    except OSError as exc:
                        raise self._map_open_error(exc, child) from exc
                    try:
                        yield from rec(fd, child)
                    finally:
                        os.close(fd)
                elif stat.S_ISREG(st.st_mode):
                    yield emit(child, "file")
                else:
                    # symlink, FIFO, device, socket: reported, never opened
                    yield emit(child, "other")

        if prefix == "":
            yield from rec(self._dirfd, "")
            return
        with self._open_parent(prefix) as (dirfd, name):
            try:
                st = os.lstat(name, dir_fd=dirfd)
            except OSError as exc:
                raise self._map_open_error(exc, prefix) from exc
            kind = _kind_of(st)
            if kind != "dir":
                yield emit(prefix, kind)
                return
            yield emit(prefix, "dir")
            try:
                fd = self._opener(name, _DIR_FLAGS, dir_fd=dirfd)
            except OSError as exc:
                raise self._map_open_error(exc, prefix) from exc
            try:
                yield from rec(fd, prefix)
            finally:
                os.close(fd)

