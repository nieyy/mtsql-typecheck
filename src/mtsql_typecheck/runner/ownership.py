"""Ownership journal and quarantine latch (design 6.2.1/6.2.3/6.4.5).

``OwnershipJournal`` is the append-only writer for ``ownership.jsonl``: one
canonical ``OwnershipEvent`` per line (contracts/runner.py models), seq
strictly 1..n continuing from the loaded genesis, ``prev_event_hash`` chain
verified by ``load_ownership_journal`` on open and on every ``verify()``.
The fsync hook is injectable (trace.py pattern); a journal write or fsync
failure marks the journal failed and every later append is refused -- a
missing ledger entry must never be papered over by continuing.  After a
load-detected inconsistency (corrupt file, foreign run_id, diverged prefix)
the journal refuses to append; recovery is an operator decision, not an
automatic repair.

``QuarantineLatch`` is the in-process safety latch: ``trip(reason)`` is
idempotent and terminal; once tripped ``allow_dispatch()`` is False forever.
Persistence of the quarantine rides the journal events (QUARANTINED kind);
the latch itself is process state for Phase 3.

Marker-table DDL lives here as constants; execution is delegated to
``runner.cleanup`` (and later the real adapter) so this module performs no
I/O beyond the journal file it is given.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from ..contracts.case import ContractError
from ..contracts.codec import canonical_json
from ..contracts.runner import (
    JOURNAL_MAX_EVENT_BYTES,
    OWNERSHIP_GENESIS_HASH,
    OwnershipEvent,
    OwnershipEventKind,
    load_ownership_journal,
)
from .naming import marker_table_name

__all__ = [
    "OWNERSHIP_JOURNAL_FILE_NAME",
    "MARKER_TABLE_DDL",
    "MARKER_RUN_ID_MAX_CHARS",
    "QuarantineError",
    "OwnershipError",
    "OwnershipJournalError",
    "OwnershipJournalCorruptError",
    "OwnershipWriteError",
    "OwnershipJournal",
    "QuarantineLatch",
]

OWNERSHIP_JOURNAL_FILE_NAME = "ownership.jsonl"

MARKER_RUN_ID_MAX_CHARS = 128

# Design 6.2.3: the marker table is created before any test table, carries
# the run/attempt/token of the attempt, and is created without IF NOT
# EXISTS -- an existing marker is a hard conflict, never silently reused.
MARKER_TABLE_DDL = (
    f"CREATE TABLE `{marker_table_name()}` ("
    "`marker_id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, "
    f"`run_id` VARCHAR({MARKER_RUN_ID_MAX_CHARS}) NOT NULL, "
    "`attempt_id` VARCHAR(128) NOT NULL, "
    "`token` VARCHAR(128) NOT NULL"
    ") ENGINE=InnoDB"
)


def _default_fsync(fd: int, what: str) -> None:
    del what  # single default behaviour; the label exists for test spies
    os.fsync(fd)


class OwnershipError(ContractError):
    """Base class for ownership-layer errors."""


class QuarantineError(OwnershipError):
    """Dispatch was attempted while the quarantine latch is tripped."""


class OwnershipJournalError(OwnershipError):
    """The journal cannot accept the requested append (closed/failed/inconsistent)."""


class OwnershipJournalCorruptError(OwnershipJournalError):
    """A load-detected inconsistency: the on-disk journal is corrupt, foreign
    to this run, or diverged from what this writer appended."""


class OwnershipWriteError(OwnershipJournalError):
    """An OS-level write/fsync failed; the journal is failed and must not be used."""


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


class OwnershipJournal:
    """Append-only, fsync-backed writer for one run's ``ownership.jsonl``.

    The constructor opens the file exclusively: a missing file is created
    (parent directory must exist, O_EXCL), an existing file is opened for
    append after full chain verification via ``load_ownership_journal``.
    Events continue at seq n+1 from the loaded genesis.  Single-writer by
    construction: ``verify()`` compares the fresh on-disk load against the
    in-memory prefix and flags divergence as corruption.
    """

    def __init__(
        self,
        path: Path,
        *,
        run_id: str,
        fsync_hook: Optional[Callable[[int, str], None]] = None,
    ) -> None:
        if not isinstance(run_id, str) or not run_id:
            raise OwnershipJournalError("run_id must be a non-empty str")
        if len(run_id) > MARKER_RUN_ID_MAX_CHARS:
            raise OwnershipJournalError(
                f"run_id must be at most {MARKER_RUN_ID_MAX_CHARS} chars"
            )
        self._fsync = _default_fsync if fsync_hook is None else fsync_hook
        self._run_id = run_id
        self._path = Path(path)
        self._events: List[OwnershipEvent] = []
        self._next_seq = 1
        self._prev_hash = OWNERSHIP_GENESIS_HASH
        self._failed = False
        self._inconsistent = False
        self._closed = False

        parent = self._path.parent
        try:
            parent_st = os.lstat(parent)
        except FileNotFoundError as exc:
            raise OwnershipJournalError(
                f"ownership journal parent directory does not exist: {str(parent)!r}"
            ) from exc
        except OSError as exc:
            raise OwnershipJournalError(f"cannot inspect {str(parent)!r}: {exc}") from exc
        if not stat.S_ISDIR(parent_st.st_mode):
            raise OwnershipJournalError(
                f"ownership journal parent is not a directory: {str(parent)!r}"
            )
        try:
            self._fd: Optional[int] = os.open(
                str(self._path),
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            self._fd = None
        except OSError as exc:
            raise OwnershipJournalError(f"cannot create ownership journal: {exc}") from exc

        if self._fd is None:
            # Existing journal: open for append and continue from its tail.
            try:
                with open(self._path, "rb") as fh:
                    raw = fh.read()
            except OSError as exc:
                raise OwnershipJournalCorruptError(
                    f"cannot read existing ownership journal: {exc}"
                ) from exc
            try:
                loaded = load_ownership_journal(raw)
            except ContractError as exc:
                raise OwnershipJournalCorruptError(
                    f"existing ownership journal failed verification: {exc}"
                ) from exc
            for event in loaded:
                if event.run_id != self._run_id:
                    raise OwnershipJournalCorruptError(
                        f"existing ownership journal carries foreign run_id "
                        f"{event.run_id!r}, expected {self._run_id!r}"
                    )
            self._events = list(loaded)
            self._next_seq = len(loaded) + 1
            self._prev_hash = (
                loaded[-1].content_hash if loaded else OWNERSHIP_GENESIS_HASH
            )
            try:
                self._fd = os.open(str(self._path), os.O_WRONLY | os.O_APPEND, 0o600)
            except OSError as exc:
                raise OwnershipJournalError(
                    f"cannot open existing ownership journal for append: {exc}"
                ) from exc

    # -- introspection -----------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def next_seq(self) -> int:
        return self._next_seq

    @property
    def inconsistent(self) -> bool:
        return self._inconsistent

    @property
    def failed(self) -> bool:
        return self._failed

    @property
    def closed(self) -> bool:
        return self._closed

    def events(self) -> Tuple[OwnershipEvent, ...]:
        """Snapshot of the events this writer has appended/loaded."""
        return tuple(self._events)

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
            self._closed = True

    def __enter__(self) -> "OwnershipJournal":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def _usable(self) -> None:
        if self._closed or self._fd is None:
            raise OwnershipJournalError("ownership journal is closed")
        if self._failed:
            raise OwnershipWriteError("ownership journal failed; no further appends")
        if self._inconsistent:
            raise OwnershipJournalCorruptError(
                "ownership journal is inconsistent; refusing to append"
            )

    # -- appends -----------------------------------------------------------

    def append(
        self,
        event_kind: OwnershipEventKind,
        *,
        attempt_id: Optional[str] = None,
        server_uuid: Optional[str] = None,
        object_name: Optional[str] = None,
        token: Optional[str] = None,
        session_generation: Optional[int] = None,
        connection_id: Optional[str] = None,
    ) -> OwnershipEvent:
        """Build, persist (write + fsync) and record one ownership event."""
        self._usable()
        if not isinstance(event_kind, OwnershipEventKind):
            raise OwnershipJournalError(
                f"event_kind must be OwnershipEventKind, got {event_kind!r}"
            )
        event = OwnershipEvent(
            seq=self._next_seq,
            prev_event_hash=self._prev_hash,
            run_id=self._run_id,
            event_kind=event_kind,
            attempt_id=attempt_id,
            server_uuid=server_uuid,
            object_name=object_name,
            token=token,
            session_generation=session_generation,
            connection_id=connection_id,
        )
        line = canonical_json(event.to_obj()) + b"\n"
        if len(line) > JOURNAL_MAX_EVENT_BYTES:
            raise OwnershipJournalError(
                f"ownership event line exceeds JOURNAL_MAX_EVENT_BYTES "
                f"({JOURNAL_MAX_EVENT_BYTES})"
            )
        assert self._fd is not None
        try:
            _write_all(self._fd, line)
            self._fsync(self._fd, "ownership-journal")
        except OSError as exc:
            self._failed = True
            raise OwnershipWriteError(f"cannot append ownership event: {exc}") from exc
        self._events.append(event)
        self._next_seq += 1
        self._prev_hash = event.content_hash
        return event

    # -- verification ------------------------------------------------------

    def verify(self) -> Tuple[OwnershipEvent, ...]:
        """Re-load the journal from disk with full chain verification.

        Returns the loaded tuple.  Any load failure, foreign run_id, or
        divergence between the on-disk journal and this writer's prefix marks
        the journal inconsistent and future appends are refused.
        """
        try:
            with open(self._path, "rb") as fh:
                raw = fh.read()
            loaded = load_ownership_journal(raw)
            for event in loaded:
                if event.run_id != self._run_id:
                    raise OwnershipJournalCorruptError(
                        f"ownership journal carries foreign run_id "
                        f"{event.run_id!r}, expected {self._run_id!r}"
                    )
            if list(loaded) != self._events:
                raise OwnershipJournalCorruptError(
                    "ownership journal diverged from this writer's event prefix"
                )
        except OwnershipJournalCorruptError:
            self._inconsistent = True
            raise
        except ContractError as exc:
            self._inconsistent = True
            raise OwnershipJournalCorruptError(
                f"ownership journal failed verification: {exc}"
            ) from exc
        except OSError as exc:
            self._inconsistent = True
            raise OwnershipJournalCorruptError(
                f"cannot re-read ownership journal: {exc}"
            ) from exc
        return loaded


class QuarantineLatch:
    """Terminal in-process safety latch (design 6.2.2/6.4.5).

    After termination is UNKNOWN, ownership is uncertain, or cleanup failed,
    the latch trips and ``allow_dispatch()`` is False forever: zero further
    dispatches this process.  ``trip`` is idempotent -- the first reason is
    recorded and later trips cannot change or un-trip it.
    """

    _MAX_REASON_CHARS = 512

    def __init__(self) -> None:
        self._reason: Optional[str] = None

    @property
    def tripped(self) -> bool:
        return self._reason is not None

    @property
    def reason(self) -> Optional[str]:
        return self._reason

    def trip(self, reason: str) -> None:
        if not isinstance(reason, str) or not reason:
            raise OwnershipError("quarantine reason must be a non-empty str")
        if len(reason) > self._MAX_REASON_CHARS:
            raise OwnershipError(
                f"quarantine reason must be at most {self._MAX_REASON_CHARS} chars"
            )
        if self._reason is None:
            self._reason = reason

    def allow_dispatch(self) -> bool:
        return self._reason is None

    def require_dispatch_allowed(self) -> None:
        if self._reason is not None:
            raise QuarantineError(
                f"dispatch refused: quarantine latch tripped ({self._reason})"
            )
