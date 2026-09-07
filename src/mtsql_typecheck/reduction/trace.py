"""Append-only bounded JSONL trace for D2 reduction (reduction/trace.py).

Implements oracle-d2-contract section 10 and design 6.4.6 (design
``2026-09-05-mtsql-typecheck-result-oracle-counterexample-reduction-design-zh.md``):
a small persistence layer for replay/reduction, provided by D2 for D3/D4
reuse.  This is NOT a report-directory system: no indexes, no summaries, no
D4 bundles.

Layout (single writer, dedicated output root, read-only inputs)::

    <root>/trace.jsonl           one TraceRecord per line (canonical JSON + "\\n")
    <root>/files/<sha256>.json   dependency payloads published atomically

Output-safety invariants: the root path must not contain ``.``/``..``
components or traverse any symlink component; the root and ``files/``
directory are created exclusively; ``trace.jsonl`` is created with O_EXCL
semantics so a second writer session is refused and existing outputs are
never overwritten or deleted; dependency files are written to a temporary
file, fsynced, hard-linked into place (race-safe, never replaces an existing
file) and the containing directory is fsynced before the referencing record
is appended.  An append returns a ``PersistedReceipt`` only after the record
bytes are fsynced.  Python flush is never treated as durability; the fsync
hook is injectable for tests.

Mandatory record order (design 6.4.6), enforced by ``JsonlTraceSink`` as a
structural grammar guard (not business logic)::

    SNAPSHOT START
    (REQUESTED [EXPECTATION] EVIDENCE RESULT COMPARISON){1..REPLAY_ATTEMPTS}
    REPLAY
    (child group ... ACCEPTED)*
    FINISHED

A prepare failure takes the EVIDENCE/RESULT failure branch without
EXPECTATION.  Every replay group is closed by a REPLAY record, including
early exits; a group is fixed at ``REPLAY_ATTEMPTS`` attempts.  ACCEPTED is
only valid directly after a REPLAY record.

Record payload schemas consumed by the read-side audit (``read_trace``).
Inline payloads of kinds other than START/ACCEPTED are opaque to the audit;
the audit only requires that a non-null ``payload_ref`` dependency file
exists under ``files/`` with matching size and sha256.

- ``SNAPSHOT`` (seq 1): ``payload_ref`` is the original candidate case
  payload artifact or ``None``; ``inline`` is opaque (recommended:
  ``{"case_id": <hex64>}``).
- ``START`` (seq 2): ``payload_ref`` is ``None``.  ``inline`` must be
  exactly::

      {
        "complexity": [c0, c1, c2, c3, c4],   # exactly 5 ints (original candidate)
        "payload_ref": <ArtifactRef|null>,    # original candidate payload artifact
        "case_id": <hex64>
      }

  When both ``START.inline.payload_ref`` and ``SNAPSHOT.payload_ref`` are
  non-null they must be equal.  ``complexity`` is a plain 5-int tuple
  compared lexicographically; this module treats it as data and never
  imports the strategy module.
- ``ACCEPTED``: ``payload_ref`` is the child case payload artifact
  (required) and ``inline`` must be exactly::

      {
        "child_payload_ref": <ArtifactRef>,   # must equal record.payload_ref
        "parent_complexity": [5 ints],        # == best complexity at acceptance
        "child_complexity": [5 ints],         # strictly lexicographically less
        "comparison_hashes": [h1, h2, h3],    # record hashes of the group's
                                              # three COMPARISON records, in order
        "attempt_hashes": [a1, a2, a3]        # evidence hashes per attempt (data)
      }

The best pointer has no separate authority file: ``read_trace`` rebuilds it
from the last verified ACCEPTED record only (child payload file present,
three matching COMPARISON records of the just-closed group, parent
complexity equal to the previously established best complexity and child
complexity strictly smaller).  A forged ACCEPTED is corruption: trust stops
there and the best falls back to what was verified before.  Without any
verified ACCEPTED the best is the original candidate (``best_source``
ORIGINAL) with not-reproduced semantics.

Trace status semantics:

- ``PARTIAL``: the final line has no trailing newline (or is bad JSON as an
  unterminated tail), or the verified prefix does not end with FINISHED.
  An unterminated tail record is never counted as verified.
- ``CORRUPT``: a completed record fails verification (bad JSON, unknown
  fields, hash mismatch, duplicate/gapped seq, stale prev_hash, missing or
  mismatched dependency file, invalid or forged START/ACCEPTED payload).
  Trust stops at that point; the audit never searches past corruption for a
  smaller best.
- ``COMPLETE``: every line verified and the trace ends with FINISHED.  A
  missing or empty trace.jsonl yields COMPLETE with zero records (nothing
  contradicts; callers decide what an absent trace means for them).

Append budget: the budget bounds the total bytes written under the root
(trace lines plus dependency payloads).  ``reserve(size_hint)`` is a
pre-flight check called by replay/engine before dispatching work; it does
not consume budget and requires ``EVIDENCE_RESERVE_BYTES`` to stay free for
termination records.  Actual writes settle real bytes; a write that would
eat into the reserve is refused (FINISHED is the only kind allowed to
consume the reserve).  The sink's own hard guarantee is a non-negative
remaining budget; the 64 KiB floor is maintained by the reserve discipline
and enforced on every non-FINISHED write.  An OSError (e.g. ENOSPC) marks
the sink failed and stops dispatching; already-written prefixes stay valid
and are never truncated.  A budget refusal does NOT mark the sink failed
(termination records may still fit).

Importing this module performs no I/O.  Python 3.11+, stdlib only, integer
arithmetic only.
"""

from __future__ import annotations

import os
import stat
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional

from ..contracts.case import ContractError
from ..contracts.codec import parse_strict_json, sha256_hex
from ..contracts.oracle import (
    EVIDENCE_APPEND_HARD_CAP,
    EVIDENCE_PROFILE_FULL,
    EVIDENCE_RESERVE_BYTES,
    REPLAY_ATTEMPTS,
    TRACE_SCHEMA_VERSION,
    ArtifactRef,
    PersistedReceipt,
    TraceRecord,
    decode_artifact_ref,
    decode_trace_record,
    dump_trace_record,
)

__all__ = [
    "TRACE_FILE_NAME",
    "FILES_DIR_NAME",
    "TRACE_GENESIS_HASH",
    "TRACE_STATUS_COMPLETE",
    "TRACE_STATUS_PARTIAL",
    "TRACE_STATUS_CORRUPT",
    "BEST_SOURCE_ORIGINAL",
    "BEST_SOURCE_ACCEPTED",
    "TraceError",
    "TracePathError",
    "TraceOrderError",
    "TraceBudgetError",
    "TraceWriteError",
    "TraceAudit",
    "JsonlTraceSink",
    "read_trace",
]

TRACE_FILE_NAME = "trace.jsonl"
FILES_DIR_NAME = "files"
TRACE_GENESIS_HASH = "0" * 64

TRACE_STATUS_COMPLETE = "COMPLETE"
TRACE_STATUS_PARTIAL = "PARTIAL"
TRACE_STATUS_CORRUPT = "CORRUPT"

BEST_SOURCE_ORIGINAL = "ORIGINAL"
BEST_SOURCE_ACCEPTED = "ACCEPTED"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

_READ_CHUNK_BYTES = 1024 * 1024


class TraceError(ContractError):
    """Base class for trace-layer errors (path, order, budget, write)."""


class TracePathError(TraceError):
    """The output root or a payload path is unsafe or already taken."""


class TraceOrderError(TraceError):
    """A record violates the trace grammar, seq order or hash chain."""


class TraceBudgetError(TraceError):
    """The append budget cannot cover the requested write."""


class TraceWriteError(TraceError):
    """An OS-level write/fsync failed; the sink is failed and must not be used."""


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and _HEX64_RE.match(value) is not None


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# --------------------------------------------------------------------------
# Grammar guard (structural, not business logic)
# --------------------------------------------------------------------------


_START_STATE = "EXPECT_SNAPSHOT"

_TRANSITIONS: dict[str, dict[str, str]] = {
    "EXPECT_SNAPSHOT": {"SNAPSHOT": "EXPECT_START"},
    "EXPECT_START": {"START": "IDLE"},
    "IDLE": {"REQUESTED": "ATTEMPT_REQUESTED", "FINISHED": "FINISHED"},
    "ATTEMPT_REQUESTED": {
        "EXPECTATION": "ATTEMPT_EXPECTATION",
        "EVIDENCE": "ATTEMPT_EVIDENCE",
    },
    "ATTEMPT_EXPECTATION": {"EVIDENCE": "ATTEMPT_EVIDENCE"},
    "ATTEMPT_EVIDENCE": {"RESULT": "ATTEMPT_RESULT"},
    "ATTEMPT_RESULT": {"COMPARISON": "ATTEMPT_COMPARISON"},
    "ATTEMPT_COMPARISON": {},  # handled specially (fixed group size)
    "GROUP_REPLAY": {
        "REQUESTED": "ATTEMPT_REQUESTED",
        "ACCEPTED": "ACCEPTED",
        "FINISHED": "FINISHED",
    },
    "ACCEPTED": {"REQUESTED": "ATTEMPT_REQUESTED", "FINISHED": "FINISHED"},
    "FINISHED": {},
}


def _next_state(state: str, kind: str, attempts_in_group: int) -> str:
    if state == "ATTEMPT_COMPARISON":
        if kind == "REPLAY":
            return "GROUP_REPLAY"
        if kind == "REQUESTED":
            if attempts_in_group >= REPLAY_ATTEMPTS:
                raise TraceOrderError(
                    "trace grammar: a replay group is fixed at "
                    f"{REPLAY_ATTEMPTS} attempts; a REPLAY record must close "
                    "the group before a new attempt"
                )
            return "ATTEMPT_REQUESTED"
        if kind == "FINISHED":
            return "FINISHED"
        raise TraceOrderError(
            f"trace grammar: {kind!r} is not allowed after a COMPARISON record"
        )
    allowed = _TRANSITIONS[state]
    if kind not in allowed:
        raise TraceOrderError(
            f"trace grammar: {kind!r} is not allowed in state {state}"
        )
    return allowed[kind]


# --------------------------------------------------------------------------
# Output-root path safety
# --------------------------------------------------------------------------


def _reject_unsafe_components(path: Path) -> None:
    for part in path.parts:
        if part in ("..", "."):
            raise TracePathError(
                f"output path must not contain '.' or '..' components: {str(path)!r}"
            )


def _reject_symlink_components(absolute: Path) -> None:
    """lstat every existing prefix of ``absolute``; any symlink is refused."""
    current = Path(absolute.anchor)
    for part in absolute.parts:
        if part == absolute.anchor:
            continue
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return  # nothing deeper exists yet, so nothing deeper can be a link
        except OSError as exc:
            raise TracePathError(f"cannot inspect path component {current}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise TracePathError(f"path component {current} is a symlink; refusing")


def _checked_absolute(path: Path) -> Path:
    _reject_unsafe_components(path)
    absolute = Path(os.path.abspath(str(path)))
    _reject_symlink_components(absolute)
    return absolute


def _fsync_dir(path: Path, hook: Callable[[int, str], None]) -> None:
    fd = os.open(str(path), os.O_RDONLY)
    try:
        hook(fd, "dir")
    finally:
        os.close(fd)


def _default_fsync(fd: int, what: str) -> None:
    del what  # single default behaviour; the label exists for test spies
    os.fsync(fd)


# --------------------------------------------------------------------------
# Sink
# --------------------------------------------------------------------------


class JsonlTraceSink:
    """Concrete ``TraceSink``: exclusive JSONL root with atomic payload files.

    The constructor creates the output root (exclusively) and opens
    ``trace.jsonl`` with O_EXCL semantics; constructing a second sink over
    the same root is refused.  ``reserve`` is the pre-flight budget check
    for callers (replay/engine) before dispatching work; ``publish_payload``
    atomically publishes a dependency file and returns its ``ArtifactRef``;
    ``append`` validates the grammar/seq/hash chain, writes, fsyncs and only
    then returns a ``PersistedReceipt``.
    """

    def __init__(
        self,
        root: Path,
        append_budget: int,
        *,
        fsync_hook: Optional[Callable[[int, str], None]] = None,
    ) -> None:
        if not _is_int(append_budget):
            raise TraceBudgetError("append_budget must be an int")
        if append_budget < 1 or append_budget > EVIDENCE_APPEND_HARD_CAP:
            raise TraceBudgetError(
                f"append_budget {append_budget} outside 1..{EVIDENCE_APPEND_HARD_CAP}"
            )
        self._fsync = _default_fsync if fsync_hook is None else fsync_hook
        self._append_budget = append_budget
        self._remaining = append_budget
        self._bytes_written = 0
        self._next_seq = 1
        self._prev_hash = TRACE_GENESIS_HASH
        self._state = _START_STATE
        self._attempts_in_group = 0
        self._failed = False
        self._closed = False
        self._temp_counter = 0

        absolute = _checked_absolute(Path(root))
        parent = absolute.parent
        try:
            parent_st = os.lstat(parent)
        except FileNotFoundError as exc:
            raise TracePathError(
                f"output root parent directory does not exist: {str(parent)!r}"
            ) from exc
        except OSError as exc:
            raise TracePathError(f"cannot inspect {str(parent)!r}: {exc}") from exc
        if not stat.S_ISDIR(parent_st.st_mode):
            raise TracePathError(f"output root parent is not a directory: {str(parent)!r}")
        try:
            os.mkdir(absolute, 0o700)
        except FileExistsError:
            root_st = os.lstat(absolute)
            if not stat.S_ISDIR(root_st.st_mode):
                raise TracePathError(
                    f"output root exists and is not a directory: {str(absolute)!r}"
                )
        except OSError as exc:
            raise TracePathError(f"cannot create output root {str(absolute)!r}: {exc}") from exc
        self._root = absolute
        self._files_dir = absolute / FILES_DIR_NAME
        self._trace_path = absolute / TRACE_FILE_NAME
        try:
            os.mkdir(self._files_dir, 0o700)
        except FileExistsError:
            files_st = os.lstat(self._files_dir)
            if not stat.S_ISDIR(files_st.st_mode):
                raise TracePathError(
                    f"{FILES_DIR_NAME!r} exists and is not a directory in the output root"
                )
        except OSError as exc:
            raise TracePathError(f"cannot create files directory: {exc}") from exc
        try:
            self._fd = os.open(
                str(self._trace_path),
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError as exc:
            raise TracePathError(
                "trace.jsonl already exists in the output root; a trace is "
                "written by a single writer and is never reopened or overwritten"
            ) from exc
        except OSError as exc:
            raise TracePathError(f"cannot create trace.jsonl: {exc}") from exc
        try:
            _fsync_dir(absolute, self._fsync)
        except OSError as exc:
            self._failed = True
            os.close(self._fd)
            self._fd = None
            raise TraceWriteError(f"cannot make the new trace durable: {exc}") from exc

    # -- introspection -----------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    @property
    def remaining_bytes(self) -> int:
        """Budget bytes not yet settled (reserve checks, never consumed)."""
        return self._remaining

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    @property
    def failed(self) -> bool:
        return self._failed

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
            self._closed = True

    def __enter__(self) -> "JsonlTraceSink":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def _usable(self) -> None:
        if self._failed:
            raise TraceWriteError("trace sink failed; no further writes are attempted")
        if self._closed or self._fd is None:
            raise TraceWriteError("trace sink is closed")

    # -- budget ------------------------------------------------------------

    def reserve(self, size_hint: int) -> None:
        """Pre-flight check that ``size_hint`` bytes fit while keeping the
        ``EVIDENCE_RESERVE_BYTES`` termination reserve free.  Does not
        consume budget; actual writes settle real bytes."""
        self._usable()
        if not _is_int(size_hint):
            raise TraceBudgetError("size_hint must be an int")
        if size_hint < 0:
            raise TraceBudgetError(f"size_hint must be >= 0, got {size_hint}")
        if self._remaining - size_hint < EVIDENCE_RESERVE_BYTES:
            raise TraceBudgetError(
                f"append budget exhausted: {size_hint} bytes requested, "
                f"{self._remaining} bytes left, {EVIDENCE_RESERVE_BYTES} bytes "
                "must stay reserved for termination records"
            )

    # -- dependency files --------------------------------------------------

    def publish_payload(self, data: bytes) -> ArtifactRef:
        """Atomically publish one dependency file under ``files/``.

        Same-content sha256 name collisions mean the identical file already
        exists and are accepted (verified by hash); a file already occupying
        the target name with different content is refused.  The payload
        bytes count against the append budget only when this call actually
        creates the file.
        """
        self._usable()
        if not isinstance(data, (bytes, bytearray)):
            raise TraceError("payload data must be bytes")
        payload = bytes(data)
        digest = sha256_hex(payload)
        name = f"{digest}.json"
        target = self._files_dir / name
        if self._remaining - len(payload) < EVIDENCE_RESERVE_BYTES:
            raise TraceBudgetError(
                f"append budget exhausted: payload of {len(payload)} bytes, "
                f"{self._remaining} bytes left, {EVIDENCE_RESERVE_BYTES} bytes "
                "must stay reserved for termination records"
            )
        self._temp_counter += 1
        temp: Optional[Path] = None
        fd: Optional[int] = None
        while fd is None:
            candidate = self._files_dir / f".tmp-{digest}-{os.getpid()}-{self._temp_counter}"
            try:
                fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                temp = candidate
            except FileExistsError:
                # Concurrent publishers of the same payload may pick the same
                # temp name; retry with the next counter value.
                self._temp_counter += 1
        try:
            try:
                self._write_all(fd, payload)
                self._fsync(fd, "payload-file")
            finally:
                os.close(fd)
            assert temp is not None
            try:
                os.link(str(temp), str(target))
            except FileExistsError:
                self._verify_existing_payload(target, digest, len(payload))
            finally:
                os.unlink(str(temp))
            _fsync_dir(self._files_dir, self._fsync)
        except OSError as exc:
            self._failed = True
            raise TraceWriteError(f"cannot publish payload file: {exc}") from exc
        self._remaining -= len(payload)
        return ArtifactRef(
            path=f"{FILES_DIR_NAME}/{name}",
            size_bytes=len(payload),
            sha256=digest,
            schema_version=TRACE_SCHEMA_VERSION,
        )

    @staticmethod
    def _verify_existing_payload(target: Path, digest: str, size: int) -> None:
        try:
            st = os.lstat(target)
            if not stat.S_ISREG(st.st_mode):
                raise TracePathError(f"payload target {str(target)!r} is not a regular file")
            if st.st_size != size:
                raise TracePathError(
                    f"payload name collision with different content at {str(target)!r}"
                )
            running = bytearray()
            with open(target, "rb") as fh:
                while True:
                    chunk = fh.read(_READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    running.extend(chunk)
            if sha256_hex(bytes(running)) != digest:
                raise TracePathError(
                    f"payload name collision with different content at {str(target)!r}"
                )
        except OSError as exc:
            raise TracePathError(f"cannot verify existing payload file: {exc}") from exc

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]

    # -- records -----------------------------------------------------------

    def append(self, record: TraceRecord) -> PersistedReceipt:
        """Validate, write, fsync and receipt one trace record.

        Raises ``TraceOrderError`` for grammar/seq/hash-chain violations and
        ``TraceBudgetError`` when the write would break the budget; neither
        writes anything.  Raises ``TraceWriteError`` (and marks the sink
        failed) on OS-level write/fsync failures; bytes already written stay
        in place and are never truncated.
        """
        self._usable()
        if not isinstance(record, TraceRecord):
            raise TraceOrderError("append expects a TraceRecord")
        if record.seq != self._next_seq:
            raise TraceOrderError(
                f"record seq {record.seq} does not match the expected seq {self._next_seq}"
            )
        if record.prev_hash != self._prev_hash:
            raise TraceOrderError(
                "record prev_hash does not extend the current hash chain"
            )
        next_state = _next_state(self._state, record.kind, self._attempts_in_group)
        line = dump_trace_record(record)
        size = len(line) + 1
        floor = 0 if record.kind == "FINISHED" else EVIDENCE_RESERVE_BYTES
        if self._remaining - size < floor:
            raise TraceBudgetError(
                f"append budget exhausted: record needs {size} bytes, "
                f"{self._remaining} bytes left "
                f"(floor for non-FINISHED records: {EVIDENCE_RESERVE_BYTES})"
            )
        try:
            self._write_all(self._fd, line + b"\n")
            self._fsync(self._fd, "trace-file")
        except OSError as exc:
            self._failed = True
            raise TraceWriteError(f"cannot persist trace record: {exc}") from exc
        self._remaining -= size
        self._bytes_written += size
        receipt = PersistedReceipt(seq=record.seq, kind=record.kind, record_hash=record.hash)
        self._next_seq += 1
        self._prev_hash = record.hash
        self._state = next_state
        if record.kind == "REQUESTED":
            self._attempts_in_group += 1
        elif record.kind == "REPLAY":
            self._attempts_in_group = 0
        return receipt


# --------------------------------------------------------------------------
# Read-side audit
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TraceAudit:
    """Read-only verdict over one trace root (see module docstring).

    ``best_payload_ref`` is the artifact of the reconstructed best case: the
    last verified ACCEPTED child payload (``best_source == "ACCEPTED"``) or
    the original candidate snapshot (``best_source == "ORIGINAL"``, the
    not-reproduced fallback).  ``records_verified`` counts only fully
    verified completed records; corruption or an unterminated tail stops
    trust there and later records are ignored (never searched past).
    """

    records_verified: int
    trace_status: str
    best_payload_ref: Optional[ArtifactRef]
    best_source: str
    detail: str
    last_record_hash: Optional[str]


def _iter_complete_lines(fh: "BinaryIO") -> Iterator[tuple[bytes, bool]]:
    """Yield ``(raw_line_without_newline, terminated)`` pairs."""
    tail = b""
    while True:
        chunk = fh.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        parts = (tail + chunk).split(b"\n")
        tail = parts.pop()
        for raw in parts:
            yield raw, True
    if tail:
        yield tail, False


def _complexity5(value: object, what: str) -> tuple[int, int, int, int, int]:
    if not isinstance(value, list) or len(value) != 5:
        raise ContractError(f"{what} must be a list of exactly 5 ints")
    for item in value:
        if not _is_int(item):
            raise ContractError(f"{what} must contain only ints")
    return (value[0], value[1], value[2], value[3], value[4])


def _hex64_list3(value: object, what: str) -> tuple[str, str, str]:
    if not isinstance(value, list) or len(value) != 3:
        raise ContractError(f"{what} must be a list of exactly 3 hash strings")
    for item in value:
        if not _is_hex64(item):
            raise ContractError(f"{what} must contain only 64-char lowercase hex strings")
    return (value[0], value[1], value[2])


def _optional_ref(value: object, what: str) -> Optional[ArtifactRef]:
    if value is None:
        return None
    return decode_artifact_ref(value, what)


def _verify_dependency_file(root: Path, ref: ArtifactRef) -> None:
    parts = ref.path.split("/")
    if (
        len(parts) != 2
        or parts[0] != FILES_DIR_NAME
        or parts[1] != f"{ref.sha256}.json"
    ):
        raise ContractError(
            f"dependency path {ref.path!r} is outside the {FILES_DIR_NAME}/<sha256>.json layout"
        )
    files_dir = root / FILES_DIR_NAME
    target = files_dir / parts[1]
    try:
        dir_st = os.lstat(files_dir)
        if not stat.S_ISDIR(dir_st.st_mode):
            raise ContractError(f"{FILES_DIR_NAME!r} is not a directory in the trace root")
        st = os.lstat(target)
        if not stat.S_ISREG(st.st_mode):
            raise ContractError(f"dependency file {ref.path!r} is not a regular file")
        if st.st_size != ref.size_bytes:
            raise ContractError(
                f"dependency file {ref.path!r} size {st.st_size} does not match "
                f"the recorded {ref.size_bytes}"
            )
    except FileNotFoundError as exc:
        raise ContractError(f"dependency file {ref.path!r} is missing") from exc
    except OSError as exc:
        raise ContractError(f"cannot inspect dependency file {ref.path!r}: {exc}") from exc
    digest = bytearray()
    with open(target, "rb") as fh:
        while True:
            chunk = fh.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            digest.extend(chunk)
    if sha256_hex(bytes(digest)) != ref.sha256:
        raise ContractError(f"dependency file {ref.path!r} content hash mismatch")


def _check_start_inline(record: TraceRecord, snapshot_ref: Optional[ArtifactRef]) -> tuple[
    int, int, int, int, int
]:
    inline = record.inline
    if not isinstance(inline, dict):
        raise ContractError("START inline payload must be a JSON object")
    expected_keys = {"complexity", "payload_ref", "case_id"}
    # D3: a writer on the full-evidence profile additionally marks the START
    # record; the marker value is frozen in contracts.oracle.
    optional_keys = {"evidence_profile"}
    if not expected_keys <= set(inline.keys()) <= expected_keys | optional_keys:
        raise ContractError(
            f"START inline payload must have the keys {sorted(expected_keys)} "
            f"plus optionally {sorted(optional_keys)}"
        )
    if "evidence_profile" in inline and inline["evidence_profile"] != (
        EVIDENCE_PROFILE_FULL
    ):
        raise ContractError(
            f"START inline evidence_profile must be {EVIDENCE_PROFILE_FULL!r}"
        )
    if not _is_hex64(inline["case_id"]):
        raise ContractError("START inline case_id must be 64-char lowercase hex")
    start_ref = _optional_ref(inline["payload_ref"], "START.inline.payload_ref")
    if (
        start_ref is not None
        and snapshot_ref is not None
        and start_ref != snapshot_ref
    ):
        raise ContractError(
            "START.inline.payload_ref does not match the SNAPSHOT payload_ref"
        )
    return _complexity5(inline["complexity"], "START.inline.complexity")


def _check_accepted_inline(
    record: TraceRecord,
    best_complexity: Optional[tuple[int, int, int, int, int]],
    group_comparison_hashes: list[str],
) -> tuple[int, int, int, int, int]:
    if record.payload_ref is None:
        raise ContractError("ACCEPTED record must carry the child payload_ref")
    inline = record.inline
    if not isinstance(inline, dict):
        raise ContractError("ACCEPTED inline payload must be a JSON object")
    expected_keys = {
        "child_payload_ref",
        "parent_complexity",
        "child_complexity",
        "comparison_hashes",
        "attempt_hashes",
    }
    if set(inline.keys()) != expected_keys:
        raise ContractError(
            f"ACCEPTED inline payload must have exactly the keys {sorted(expected_keys)}"
        )
    child_ref = decode_artifact_ref(
        inline["child_payload_ref"], "ACCEPTED.inline.child_payload_ref"
    )
    if child_ref != record.payload_ref:
        raise ContractError(
            "ACCEPTED.inline.child_payload_ref does not match the record payload_ref"
        )
    parent = _complexity5(inline["parent_complexity"], "ACCEPTED.inline.parent_complexity")
    child = _complexity5(inline["child_complexity"], "ACCEPTED.inline.child_complexity")
    comparison_hashes = _hex64_list3(
        inline["comparison_hashes"], "ACCEPTED.inline.comparison_hashes"
    )
    _hex64_list3(inline["attempt_hashes"], "ACCEPTED.inline.attempt_hashes")
    if best_complexity is None:
        raise ContractError("ACCEPTED record without a verified START complexity")
    if parent != best_complexity:
        raise ContractError(
            "ACCEPTED parent_complexity does not match the established best complexity"
        )
    if not child < parent:
        raise ContractError(
            "ACCEPTED child_complexity is not strictly smaller than the parent complexity"
        )
    if group_comparison_hashes != list(comparison_hashes):
        raise ContractError(
            "ACCEPTED comparison_hashes do not match the three COMPARISON records "
            "of the just-closed replay group"
        )
    return child


def read_trace(root: Path) -> TraceAudit:
    """Read-only audit over one trace root (see module docstring).

    Raises ``TracePathError`` for unsafe roots (``..``/symlink components).
    Ordinary absence (missing root or trace.jsonl) is reported as a
    zero-record COMPLETE audit, not an error.
    """
    absolute = _checked_absolute(Path(root))
    if not os.path.isdir(absolute):
        return TraceAudit(
            records_verified=0,
            trace_status=TRACE_STATUS_COMPLETE,
            best_payload_ref=None,
            best_source=BEST_SOURCE_ORIGINAL,
            detail="output root does not exist",
            last_record_hash=None,
        )
    trace_path = absolute / TRACE_FILE_NAME
    try:
        fh = open(trace_path, "rb")
    except FileNotFoundError:
        return TraceAudit(
            records_verified=0,
            trace_status=TRACE_STATUS_COMPLETE,
            best_payload_ref=None,
            best_source=BEST_SOURCE_ORIGINAL,
            detail="trace.jsonl does not exist",
            last_record_hash=None,
        )
    except IsADirectoryError as exc:
        raise TracePathError("trace.jsonl is not a regular file") from exc

    verified = 0
    last_hash: Optional[str] = TRACE_GENESIS_HASH
    last_kind: Optional[str] = None
    corrupt_reason: Optional[str] = None
    unterminated_tail = False

    best_ref: Optional[ArtifactRef] = None
    best_source = BEST_SOURCE_ORIGINAL
    best_complexity: Optional[tuple[int, int, int, int, int]] = None
    snapshot_ref: Optional[ArtifactRef] = None
    group_comparison_hashes: list[str] = []

    def corrupt(seq: int, reason: str) -> ContractError:
        return ContractError(f"record {seq}: {reason}")

    with fh:
        for raw, terminated in _iter_complete_lines(fh):
            if not terminated:
                unterminated_tail = True
                break
            try:
                record = decode_trace_record(parse_strict_json(raw))
                if record.seq != verified + 1:
                    raise corrupt(
                        verified + 1,
                        f"seq gap or duplicate: expected {verified + 1}, got {record.seq}",
                    )
                if record.prev_hash != last_hash:
                    raise corrupt(verified + 1, "stale prev_hash (does not extend the chain)")
                if record.payload_ref is not None:
                    _verify_dependency_file(absolute, record.payload_ref)
                if record.kind == "SNAPSHOT":
                    snapshot_ref = record.payload_ref
                    if record.payload_ref is not None:
                        best_ref = record.payload_ref
                elif record.kind == "START":
                    complexity = _check_start_inline(record, snapshot_ref)
                    inline_ref = _optional_ref(
                        (record.inline or {}).get("payload_ref"),
                        "START.inline.payload_ref",
                    )
                    if inline_ref is not None and best_ref is None:
                        best_ref = inline_ref
                    best_complexity = complexity
                elif record.kind == "COMPARISON":
                    group_comparison_hashes.append(record.hash)
                elif record.kind == "REQUESTED" and last_kind != "COMPARISON":
                    # A REQUESTED that follows REPLAY/ACCEPTED/START opens a
                    # new replay group; the ACCEPTED of a group must match the
                    # comparisons of the group closed by the preceding REPLAY,
                    # so the accumulator is only cleared when a new group opens.
                    group_comparison_hashes = []
                elif record.kind == "ACCEPTED":
                    child = _check_accepted_inline(
                        record, best_complexity, group_comparison_hashes
                    )
                    best_ref = record.payload_ref
                    best_source = BEST_SOURCE_ACCEPTED
                    best_complexity = child
            except ContractError as exc:
                corrupt_reason = str(exc)
                break
            verified += 1
            last_hash = record.hash
            last_kind = record.kind

    if corrupt_reason is not None:
        return TraceAudit(
            records_verified=verified,
            trace_status=TRACE_STATUS_CORRUPT,
            best_payload_ref=best_ref,
            best_source=best_source,
            detail=corrupt_reason,
            last_record_hash=None if verified == 0 else last_hash,
        )
    if unterminated_tail:
        return TraceAudit(
            records_verified=verified,
            trace_status=TRACE_STATUS_PARTIAL,
            best_payload_ref=best_ref,
            best_source=best_source,
            detail=(
                f"trace ends with an unterminated record after {verified} "
                "verified records"
            ),
            last_record_hash=None if verified == 0 else last_hash,
        )
    if verified > 0 and last_kind != "FINISHED":
        return TraceAudit(
            records_verified=verified,
            trace_status=TRACE_STATUS_PARTIAL,
            best_payload_ref=best_ref,
            best_source=best_source,
            detail=(
                f"trace ends after {verified} records without a FINISHED record"
            ),
            last_record_hash=None if verified == 0 else last_hash,
        )
    return TraceAudit(
        records_verified=verified,
        trace_status=TRACE_STATUS_COMPLETE,
        best_payload_ref=best_ref,
        best_source=best_source,
        detail=f"all {verified} records verified; best from {best_source}",
        last_record_hash=None if verified == 0 else last_hash,
    )
