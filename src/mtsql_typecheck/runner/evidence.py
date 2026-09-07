"""Run output-directory writer (design 6.4.6/6.6, Phase 5).

Single-writer, fail-closed evidence persistence for one runner command.
The writer owns the exclusive creation of the run output root and every
evidence file inside it:

- the root is created exclusively (a second writer over an existing output
  directory is refused, never merged or overwritten);
- ``run.lock`` records the single-writer claim for the whole run;
- per-attempt documents live under ``attempts/<attempt_id>/`` and are
  written with O_EXCL semantics: an existing file is accepted only when the
  content is byte-identical (idempotent re-seal), any other rewrite is a
  typed refusal;
- ``payloads/<sha256>.json`` is a content-addressed store; publishing the
  same bytes twice is a no-op that never rewrites the file;
- ``environment.json`` and ``runner-manifest.json`` are written once.

Every write is charged to the run evidence budget (256 MiB default, 1 GiB
hard cap, ``--evidence-budget-mib`` in the CLI) *before* the bytes hit the
disk, and a 64 KiB termination reserve floor is never consumed (design
6.4.6).  Budget exhaustion raises the typed
:class:`EvidenceBudgetExceeded` -- the caller stops the run and surfaces a
persistence failure; evidence is never truncated silently to fit.

Import discipline: driver-free; importing this module imports neither a
database adapter nor PyMySQL.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable, Optional

from ..contracts.case import ContractError
from ..contracts.codec import sha256_hex
from ..contracts.oracle import (
    EVIDENCE_APPEND_BUDGET,
    EVIDENCE_APPEND_HARD_CAP,
    EVIDENCE_RESERVE_BYTES,
)
from ..contracts.runner import (
    EnvironmentManifest,
    RunnerManifest,
    dump_environment_manifest,
    dump_runner_manifest,
)

__all__ = [
    "EVIDENCE_BUDGET_DEFAULT",
    "EVIDENCE_BUDGET_HARD_CAP",
    "RUN_LOCK_NAME",
    "MANIFEST_NAME",
    "ENVIRONMENT_NAME",
    "ATTEMPTS_DIRNAME",
    "PAYLOADS_DIRNAME",
    "ATTEMPT_FILE_NAMES",
    "EvidenceError",
    "EvidencePathError",
    "EvidenceBudgetExceeded",
    "EvidenceWriter",
    "write_exclusive_document",
]

EVIDENCE_BUDGET_DEFAULT = EVIDENCE_APPEND_BUDGET
EVIDENCE_BUDGET_HARD_CAP = EVIDENCE_APPEND_HARD_CAP

RUN_LOCK_NAME = "run.lock"
MANIFEST_NAME = "runner-manifest.json"
ENVIRONMENT_NAME = "environment.json"
ATTEMPTS_DIRNAME = "attempts"
PAYLOADS_DIRNAME = "payloads"

#: Frozen per-attempt document names (design 6.6 output layout).
ATTEMPT_FILE_NAMES = frozenset(
    {
        "request.json",
        "expectation.json",
        "execution-evidence.json",
        "comparison.json",
        "observations.jsonl",
        "terminal.json",
    }
)

_IDENT_MAX_CHARS = 128
_IDENT_ALLOWED = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
)


class EvidenceError(ContractError):
    """Base class for evidence-layer errors."""


class EvidencePathError(EvidenceError):
    """A path/safety refusal (existing root, overwrite attempt, bad name)."""


class EvidenceBudgetExceeded(EvidenceError):
    """The run evidence budget cannot admit the next write."""


def _default_fsync(fd: int, what: str) -> None:
    del what
    os.fsync(fd)


def _fsync_dir(path: Path, hook: Callable[[int, str], None]) -> None:
    fd = os.open(str(path), os.O_RDONLY)
    try:
        hook(fd, "dir")
    finally:
        os.close(fd)


def _reject_symlink_components(absolute: Path) -> None:
    """Refuse any symlink component among the existing path prefixes."""
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return  # remainder does not exist yet; the mkdir below creates it
        except OSError as exc:
            raise EvidencePathError(f"cannot inspect {str(current)!r}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise EvidencePathError(f"symlink path component is refused: {str(current)!r}")


def _check_ident(value: object, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidencePathError(f"{what} must be a non-empty str, got {value!r}")
    if len(value) > _IDENT_MAX_CHARS:
        raise EvidencePathError(f"{what} must be at most {_IDENT_MAX_CHARS} chars")
    if value.startswith("."):
        raise EvidencePathError(f"{what} must not start with a dot")
    for char in value:
        if char not in _IDENT_ALLOWED:
            raise EvidencePathError(f"{what} contains an illegal character {char!r}")
    return value


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def write_exclusive_document(path: Path, data: bytes) -> int:
    """Write one canonical document with O_EXCL semantics; returns bytes.

    An existing file is accepted only when byte-identical (idempotent
    re-seal); any other rewrite raises :class:`EvidencePathError`.  The
    file becomes durable (fsync + directory fsync) before this returns.
    """
    path = Path(path)
    try:
        st = os.lstat(path)
        if stat.S_ISDIR(st.st_mode):
            raise EvidencePathError(f"{str(path)!r} is a directory")
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise EvidencePathError(f"cannot inspect {str(path)!r}: {exc}") from exc
    else:
        with open(path, "rb") as handle:
            existing = handle.read()
        if existing == data:
            return 0
        raise EvidencePathError(
            f"refusing to rewrite existing evidence file {str(path)!r} with different content"
        )
    temp = path.parent / f".{path.name}.part"
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(str(temp), str(path))
    except FileExistsError as exc:
        raise EvidencePathError(
            f"refusing to overwrite evidence file that appeared concurrently: {str(path)!r}"
        ) from exc
    finally:
        try:
            os.unlink(str(temp))
        except OSError:
            pass
    _fsync_dir(path.parent, _default_fsync)
    return len(data)


class EvidenceWriter:
    """Exclusive creator and single writer of one run output directory."""

    def __init__(
        self,
        root: Path,
        budget_bytes: int = EVIDENCE_BUDGET_DEFAULT,
        *,
        fsync_hook: Optional[Callable[[int, str], None]] = None,
    ) -> None:
        if isinstance(budget_bytes, bool) or not isinstance(budget_bytes, int):
            raise EvidencePathError("evidence budget must be an int")
        if not 1 <= budget_bytes <= EVIDENCE_BUDGET_HARD_CAP:
            raise EvidencePathError(
                f"evidence budget {budget_bytes} outside 1..{EVIDENCE_BUDGET_HARD_CAP}"
            )
        self._fsync = _default_fsync if fsync_hook is None else fsync_hook
        self._budget = budget_bytes
        self._remaining = budget_bytes
        self._bytes_written = 0
        self._closed = False

        absolute = Path(os.path.abspath(root))
        _reject_symlink_components(absolute)
        try:
            os.mkdir(absolute, 0o700)
        except FileExistsError as exc:
            raise EvidencePathError(
                f"output root already exists; runner evidence is never written "
                f"over an existing directory: {str(absolute)!r}"
            ) from exc
        except OSError as exc:
            raise EvidencePathError(f"cannot create output root: {exc}") from exc
        self._root = absolute
        for dirname in (ATTEMPTS_DIRNAME, PAYLOADS_DIRNAME):
            try:
                os.mkdir(absolute / dirname, 0o700)
            except OSError as exc:
                raise EvidencePathError(f"cannot create {dirname!r} directory: {exc}") from exc
        try:
            fd = os.open(
                str(absolute / RUN_LOCK_NAME), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
        except FileExistsError as exc:
            raise EvidencePathError(
                "run lock already exists; a single writer owns this output directory"
            ) from exc
        except OSError as exc:
            raise EvidencePathError(f"cannot create the run lock: {exc}") from exc
        else:
            os.close(fd)
        try:
            _fsync_dir(absolute, self._fsync)
        except OSError as exc:
            raise EvidenceError(f"cannot make the output root durable: {exc}") from exc

    # -- introspection -------------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    @property
    def budget_bytes(self) -> int:
        return self._budget

    @property
    def remaining_bytes(self) -> int:
        return self._remaining

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    # -- accounting ----------------------------------------------------------

    def _usable(self) -> None:
        if self._closed:
            raise EvidenceError("evidence writer is closed")

    def _settle(self, size: int) -> None:
        """Charge ``size`` bytes; the reserve floor is never consumed."""
        if self._remaining - size < EVIDENCE_RESERVE_BYTES:
            raise EvidenceBudgetExceeded(
                f"evidence budget exhausted: {size} more bytes would eat the "
                f"{EVIDENCE_RESERVE_BYTES} termination reserve "
                f"({self._bytes_written}/{self._budget} bytes written)"
            )

    def reserve(self, size_hint: int) -> None:
        """Pre-dispatch budget check (no bytes are charged)."""
        self._usable()
        if isinstance(size_hint, bool) or not isinstance(size_hint, int):
            raise EvidenceError("size_hint must be an int")
        if size_hint < 0:
            raise EvidenceError("size_hint must be >= 0")
        self._settle(size_hint)

    def _charge_and_write(self, path: Path, data: bytes) -> int:
        self._settle(len(data))
        written = write_exclusive_document(path, data)
        self._remaining -= written
        self._bytes_written += written
        return written

    # -- writes --------------------------------------------------------------

    def write_attempt_document(self, attempt_id: str, name: str, data: bytes) -> int:
        """Seal one per-attempt document under ``attempts/<id>/<name>``."""
        self._usable()
        attempt_id = _check_ident(attempt_id, "attempt id")
        if name not in ATTEMPT_FILE_NAMES:
            raise EvidencePathError(f"unknown attempt document name {name!r}")
        directory = self._root / ATTEMPTS_DIRNAME / attempt_id
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise EvidencePathError(f"cannot create attempt directory: {exc}") from exc
        return self._charge_and_write(directory / name, data)

    def publish_payload(self, data: bytes) -> str:
        """Content-addressed payload store; returns the controlled relpath.

        Publishing identical bytes again is a no-op (the existing file is
        verified, never rewritten).
        """
        self._usable()
        digest = sha256_hex(data)
        relpath = f"{PAYLOADS_DIRNAME}/{digest}.json"
        target = self._root / relpath
        try:
            with open(target, "rb") as handle:
                existing = handle.read()
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise EvidencePathError(f"cannot inspect payload {digest!r}: {exc}") from exc
        if existing is not None:
            if existing != data:
                raise EvidencePathError(
                    f"payload hash collision for {digest!r}: existing content differs"
                )
            return relpath
        self._charge_and_write(target, data)
        return relpath

    def write_environment(self, manifest: EnvironmentManifest) -> int:
        """Seal ``environment.json`` exactly once."""
        self._usable()
        if not isinstance(manifest, EnvironmentManifest):
            raise EvidenceError("write_environment needs an EnvironmentManifest")
        return self._charge_and_write(
            self._root / ENVIRONMENT_NAME, dump_environment_manifest(manifest)
        )

    def write_manifest(self, manifest: RunnerManifest) -> int:
        """Seal ``runner-manifest.json`` exactly once (last write of a run)."""
        self._usable()
        if not isinstance(manifest, RunnerManifest):
            raise EvidenceError("write_manifest needs a RunnerManifest")
        return self._charge_and_write(
            self._root / MANIFEST_NAME, dump_runner_manifest(manifest)
        )

    def close(self) -> None:
        """Mark the writer finished (files are already durable per write)."""
        self._closed = True
