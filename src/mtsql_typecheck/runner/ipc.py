"""Parent<->worker JSON-line IPC (design 6.3.2/6.4.6, Phase 3 subset).

Framing: one canonical-JSON object per line over a pair of binary streams
(parent side: subprocess pipes; worker side: ``sys.stdin.buffer`` /
``sys.stdout.buffer``).  No sockets anywhere in this module.

Envelope (protocol version 1)::

    {"v": 1, "kind": <KIND>, "seq": <n>, "payload": {...}, "corr": <n|absent>}

- ``v`` is frozen at 1; anything else is a protocol violation.
- ``seq`` is per-direction, starts at 1 and must increase by exactly 1;
  out-of-order, duplicate or gapped seq is a protocol violation.
- ``corr`` is the optional request/response correlation id (the request's
  seq); replies carry it back.
- kinds are an open vocabulary (later phases add kinds without touching the
  framing), matched by ``^[A-Z][A-Z0-9_]{0,31}$``.  Known Phase 3 kinds get
  payload shape validation now; unknown kinds pass the transport unchanged
  and are rejected at the dispatch layer (worker loop / ``validate_payload``).

Known kinds: HELLO, READY, PING, EXEC, CANCEL, RESULT, LOG, SHUTDOWN,
EXITED, ERROR.  EXEC/RESULT payloads are intentionally free-form dicts in
Phase 3 (later phases freeze them); everything else is validated now.

Budgets: a single message is capped at ``MAX_MESSAGE_BYTES`` (256 KiB) on
both encode and decode; decode also enforces it on the raw line before any
parsing.  Deadlines are enforced through a ``contracts.execution.Control``
handle: when the reader has a real file descriptor, reads use
``select.select`` slices bounded by the control's remaining time; otherwise
(byte streams without fileno) a blocking read happens and the deadline is
checked around it.  Cancel is cooperative via ``Control.raise_if_cancelled``.
"""

from __future__ import annotations

import os
import re
import select
from collections import deque
from dataclasses import dataclass
from typing import BinaryIO, Deque, FrozenSet, Optional

from ..contracts.case import ContractError
from ..contracts.codec import canonical_json, parse_strict_json
from ..contracts.execution import Control

__all__ = [
    "PROTOCOL_VERSION",
    "MAX_MESSAGE_BYTES",
    "MAX_LOG_TEXT_CHARS",
    "MAX_ERROR_MESSAGE_CHARS",
    "KNOWN_KINDS",
    "KindT",
    "Envelope",
    "IpcError",
    "PeerClosed",
    "ProtocolViolation",
    "IpcTimeout",
    "validate_payload",
    "decode_envelope",
    "IpcConnection",
    "connection_for_process",
    "worker_std_connection",
]

PROTOCOL_VERSION = 1

# Single-message budget (design 6.4.6 keeps control messages small; the
# 256 KiB cap here is the Phase 3 transport budget).
MAX_MESSAGE_BYTES = 256 * 1024

MAX_LOG_TEXT_CHARS = 2048
MAX_ERROR_MESSAGE_CHARS = 512

_HELLO_PID_MAX = 2**31 - 1
_ADAPTER_ID_MAX_CHARS = 64
_CAPABILITY_MAX_CHARS = 64
_MAX_CAPABILITIES = 64

KindT = str

KNOWN_KINDS: FrozenSet[str] = frozenset(
    {
        "HELLO",
        "READY",
        "PING",
        "EXEC",
        "CANCEL",
        "RESULT",
        "LOG",
        "SHUTDOWN",
        "EXITED",
        "ERROR",
    }
)

_KIND_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")

_READ_CHUNK_BYTES = 65536
_SELECT_SLICE_S = 0.05

_UNBOUNDED_SLICE_S = 1.0


class IpcError(ContractError):
    """Base class for IPC transport errors."""


class PeerClosed(IpcError):
    """The peer closed its end cleanly (EOF between messages)."""


class ProtocolViolation(IpcError):
    """Framing, envelope, seq or payload-shape violation; the connection is
    untrusted after this and must be closed."""


class IpcTimeout(IpcError):
    """The control deadline expired while waiting for a message."""


@dataclass(frozen=True)
class Envelope:
    v: int
    kind: str
    seq: int
    payload: dict
    corr: Optional[int] = None


def _expect_int(value: object, what: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolViolation(f"{what} must be an int, got {type(value).__name__}")
    if not minimum <= value <= maximum:
        raise ProtocolViolation(f"{what} must be in [{minimum}, {maximum}], got {value}")
    return value


def _expect_bounded_str(value: object, what: str, max_chars: int) -> str:
    if not isinstance(value, str):
        raise ProtocolViolation(f"{what} must be a str, got {type(value).__name__}")
    if len(value) > max_chars:
        raise ProtocolViolation(f"{what} must be at most {max_chars} chars")
    return value


def validate_payload(kind: str, payload: object) -> None:
    """Validate the payload shape for one kind.

    This is the strict, dispatch-level validator: kinds outside
    ``KNOWN_KINDS`` are rejected here.  The transport keeps the vocabulary
    open for later phases (``decode_envelope`` only shape-checks known
    kinds), so unknown kinds cross the wire and must be refused by whoever
    dispatches them.
    """
    if kind not in KNOWN_KINDS:
        raise ProtocolViolation(f"unknown kind {kind!r}")
    if not isinstance(payload, dict):
        raise ProtocolViolation(f"payload for {kind!r} must be a JSON object")
    if kind == "HELLO":
        extra = set(payload) - {"pid", "adapter_id", "capabilities"}
        if extra:
            raise ProtocolViolation(f"HELLO payload has unknown fields: {sorted(extra)}")
        _expect_int(payload.get("pid"), "HELLO.pid", minimum=1, maximum=_HELLO_PID_MAX)
        _expect_bounded_str(payload.get("adapter_id"), "HELLO.adapter_id", _ADAPTER_ID_MAX_CHARS)
        caps = payload.get("capabilities")
        if not isinstance(caps, list) or len(caps) > _MAX_CAPABILITIES:
            raise ProtocolViolation(f"HELLO.capabilities must be a list of at most {_MAX_CAPABILITIES} strings")
        for index, cap in enumerate(caps):
            _expect_bounded_str(cap, f"HELLO.capabilities[{index}]", _CAPABILITY_MAX_CHARS)
    elif kind in ("READY", "SHUTDOWN", "PING"):
        if payload:
            raise ProtocolViolation(f"{kind} payload must be empty")
    elif kind == "CANCEL":
        extra = set(payload) - {"reason"}
        if extra:
            raise ProtocolViolation(f"CANCEL payload has unknown fields: {sorted(extra)}")
        _expect_bounded_str(payload.get("reason"), "CANCEL.reason", 256)
    elif kind == "LOG":
        extra = set(payload) - {"text"}
        if extra:
            raise ProtocolViolation(f"LOG payload has unknown fields: {sorted(extra)}")
        _expect_bounded_str(payload.get("text"), "LOG.text", MAX_LOG_TEXT_CHARS)
    elif kind == "EXITED":
        extra = set(payload) - {"status"}
        if extra:
            raise ProtocolViolation(f"EXITED payload has unknown fields: {sorted(extra)}")
        _expect_int(payload.get("status"), "EXITED.status", minimum=0, maximum=255)
    elif kind == "ERROR":
        extra = set(payload) - {"message", "code"}
        if extra:
            raise ProtocolViolation(f"ERROR payload has unknown fields: {sorted(extra)}")
        _expect_bounded_str(payload.get("message"), "ERROR.message", MAX_ERROR_MESSAGE_CHARS)
        code = payload.get("code")
        if code is not None:
            _expect_bounded_str(code, "ERROR.code", 64)
    # EXEC, RESULT and unknown kinds: dict-only in Phase 3 (open payload).
    return None


def decode_envelope(obj: object, what: str = "ipc envelope") -> Envelope:
    """Decode and fully validate one envelope object (or its JSON text)."""
    if isinstance(obj, (bytes, str)):
        obj = parse_strict_json(obj)
    if not isinstance(obj, dict):
        raise ProtocolViolation(f"{what} must be a JSON object")
    allowed = {"v", "kind", "seq", "payload"}
    extra = set(obj) - allowed - {"corr"}
    if extra:
        raise ProtocolViolation(f"{what} has unknown fields: {sorted(extra)}")
    version = obj.get("v")
    if isinstance(version, bool) or not isinstance(version, int) or version != PROTOCOL_VERSION:
        raise ProtocolViolation(f"{what}.v must be {PROTOCOL_VERSION}, got {version!r}")
    kind = obj.get("kind")
    if not isinstance(kind, str) or _KIND_RE.match(kind) is None:
        raise ProtocolViolation(f"{what}.kind must match {_KIND_RE.pattern!r}, got {kind!r}")
    seq = _expect_int(obj.get("seq"), f"{what}.seq", minimum=1, maximum=2**63 - 1)
    payload = obj.get("payload")
    if not isinstance(payload, dict):
        raise ProtocolViolation(f"{what}.payload must be a JSON object")
    corr = obj.get("corr")
    if corr is not None:
        corr = _expect_int(corr, f"{what}.corr", minimum=1, maximum=2**63 - 1)
    if kind in KNOWN_KINDS:
        # Open vocabulary: unknown kinds are decoded but remain the
        # dispatcher's problem (see validate_payload).
        validate_payload(kind, payload)
    return Envelope(v=version, kind=kind, seq=seq, payload=payload, corr=corr)


def _encode_envelope(kind: str, payload: dict, seq: int, corr: Optional[int]) -> bytes:
    if not isinstance(kind, str) or _KIND_RE.match(kind) is None:
        raise IpcError(f"kind must match {_KIND_RE.pattern!r}, got {kind!r}")
    obj: dict[str, object] = {"v": PROTOCOL_VERSION, "kind": kind, "seq": seq, "payload": payload}
    if corr is not None:
        obj["corr"] = corr
    # Encode validates shapes too (same path as decode).
    decode_envelope(obj, "outgoing ipc envelope")
    return canonical_json(obj) + b"\n"


class IpcConnection:
    """One direction-pair of JSON-line streams with per-direction seq.

    The reader must be a binary stream (``read(n) -> bytes``); when it also
    exposes a usable ``fileno()``, deadline-bounded reads use ``select``.
    The writer must be a binary stream (``write`` / ``flush``).
    """

    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        *,
        name: str = "peer",
        max_message_bytes: int = MAX_MESSAGE_BYTES,
    ) -> None:
        if not hasattr(reader, "read") or not hasattr(writer, "write"):
            raise IpcError("IpcConnection needs binary reader/writer streams")
        if isinstance(max_message_bytes, bool) or not isinstance(max_message_bytes, int):
            raise IpcError("max_message_bytes must be an int")
        if max_message_bytes < 1:
            raise IpcError(f"max_message_bytes must be >= 1, got {max_message_bytes}")
        self._reader = reader
        self._writer = writer
        self._name = name
        self._max_message_bytes = max_message_bytes
        self._out_seq = 0
        self._in_seq = 0
        self._buffer = bytearray()
        self._eof = False
        self._closed = False
        self._deferred: Deque[Envelope] = deque()

    # -- properties --------------------------------------------------------

    @property
    def name(self) -> str:
        return self._name

    @property
    def closed(self) -> bool:
        return self._closed

    # -- sending -----------------------------------------------------------

    def send(self, kind: str, payload: dict, *, corr: Optional[int] = None) -> int:
        """Validate, encode and write one envelope; returns its seq."""
        if self._closed:
            raise IpcError("ipc connection is closed")
        if corr is not None:
            corr = _expect_int(corr, "corr", minimum=1, maximum=2**63 - 1)
        # Encode (which validates the envelope) before committing the seq so
        # a rejected message leaves the outgoing sequence untouched.
        line = _encode_envelope(kind, payload, self._out_seq + 1, corr)
        if len(line) > self._max_message_bytes:
            raise IpcError(
                f"outgoing message of {len(line)} bytes exceeds "
                f"max_message_bytes ({self._max_message_bytes})"
            )
        self._out_seq += 1
        try:
            self._writer.write(line)
            self._writer.flush()
        except OSError as exc:
            raise PeerClosed(f"{self._name}: cannot write message: {exc}") from exc
        except ValueError as exc:
            raise PeerClosed(f"{self._name}: cannot write message: {exc}") from exc
        return self._out_seq

    # -- receiving ---------------------------------------------------------

    def _deadline_remaining(self, control: Optional[Control]) -> Optional[float]:
        if control is None or control.deadline is None:
            return None
        return control.deadline - control.clock()

    def _check_control(self, control: Optional[Control]) -> float:
        """Raise on expiry/cancel; returns the select slice to use."""
        if control is not None:
            control.raise_if_cancelled()
            remaining = self._deadline_remaining(control)
            if remaining is not None and remaining <= 0:
                raise IpcTimeout(f"{self._name}: ipc read deadline expired")
            if remaining is None:
                return _UNBOUNDED_SLICE_S
            return min(remaining, _SELECT_SLICE_S)
        return _UNBOUNDED_SLICE_S

    def _read_more(self, control: Optional[Control]) -> None:
        """Pull one chunk from the reader; EOF handling happens here."""
        fileno = self._fileno()
        if fileno is not None:
            slice_s = self._check_control(control)
            try:
                ready, _, _ = select.select([fileno], [], [], slice_s)
            except (OSError, ValueError) as exc:
                raise PeerClosed(f"{self._name}: reader not selectable: {exc}") from exc
            if not ready:
                self._check_control(control)  # raises IpcTimeout on expiry
                return
            try:
                chunk = os.read(fileno, _READ_CHUNK_BYTES)
            except OSError as exc:
                raise PeerClosed(f"{self._name}: read failed: {exc}") from exc
        else:
            # No fileno: one blocking read, deadline checked around it.
            self._check_control(control)
            try:
                chunk = self._reader.read(_READ_CHUNK_BYTES)
            except (OSError, ValueError) as exc:
                raise PeerClosed(f"{self._name}: read failed: {exc}") from exc
            self._check_control(control)
        if chunk:
            self._buffer.extend(chunk)
        else:
            self._eof = True
            if self._buffer:
                raise ProtocolViolation(
                    f"{self._name}: peer closed mid-message with "
                    f"{len(self._buffer)} trailing bytes"
                )
            raise PeerClosed(f"{self._name}: peer closed the stream")

    def _fileno(self) -> Optional[int]:
        try:
            fd = self._reader.fileno()
        except (AttributeError, OSError, ValueError):
            return None
        except Exception:  # e.g. io.UnsupportedOperation on BytesIO
            return None
        if not isinstance(fd, int) or fd < 0:
            return None
        return fd

    def _extract_line(self) -> Optional[bytes]:
        newline = self._buffer.find(b"\n")
        if newline < 0:
            if len(self._buffer) > self._max_message_bytes:
                raise ProtocolViolation(
                    f"{self._name}: incoming line exceeds max_message_bytes "
                    f"({self._max_message_bytes})"
                )
            return None
        line = bytes(self._buffer[: newline + 1])
        del self._buffer[: newline + 1]
        if len(line) > self._max_message_bytes:
            raise ProtocolViolation(
                f"{self._name}: incoming message of {len(line)} bytes exceeds "
                f"max_message_bytes ({self._max_message_bytes})"
            )
        return line

    def _recv_envelope(self, control: Optional[Control]) -> Envelope:
        while True:
            line = self._extract_line()
            if line is not None:
                try:
                    envelope = decode_envelope(line, f"{self._name} message")
                except ProtocolViolation:
                    raise
                except ContractError as exc:
                    raise ProtocolViolation(f"{self._name}: bad message framing: {exc}") from exc
                if envelope.seq != self._in_seq + 1:
                    raise ProtocolViolation(
                        f"{self._name}: incoming seq {envelope.seq} must be "
                        f"{self._in_seq + 1} (strictly increasing per direction)"
                    )
                self._in_seq = envelope.seq
                return envelope
            self._read_more(control)

    def recv(self, control: Optional[Control] = None) -> Envelope:
        """Read the next envelope, enforcing seq order and the control budget.

        Messages whose ``corr`` does not match any in-flight request are
        deferred and delivered by later ``recv``/``request`` calls in arrival
        order.
        """
        if self._closed:
            raise IpcError("ipc connection is closed")
        if self._deferred:
            return self._deferred.popleft()
        return self._recv_envelope(control)

    def request(
        self,
        kind: str,
        payload: dict,
        control: Optional[Control],
        *,
        reply_kinds: frozenset[str] = frozenset({"RESULT"}),
    ) -> Envelope:
        """Send a request and wait for the correlated reply.

        The reply must carry ``corr`` equal to the request seq and one of
        ``reply_kinds`` (ERROR is always accepted so failures surface as
        envelopes instead of hangs).  Unrelated messages are deferred.
        """
        seq = self.send(kind, payload, corr=None)
        while True:
            envelope = self._recv_envelope(control)
            if envelope.corr == seq and (envelope.kind in reply_kinds or envelope.kind == "ERROR"):
                return envelope
            self._deferred.append(envelope)

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._closed = True
        self._buffer.clear()
        try:
            self._writer.close()
        except OSError:
            pass


def connection_for_process(proc: object) -> IpcConnection:
    """Parent-side connection over ``proc.stdout`` / ``proc.stdin``."""
    return IpcConnection(proc.stdout, proc.stdin, name="worker")  # type: ignore[attr-defined]


def worker_std_connection(
    stdin: Optional[BinaryIO] = None, stdout: Optional[BinaryIO] = None
) -> IpcConnection:
    """Worker-side connection over the process std streams."""
    import sys

    return IpcConnection(
        stdin if stdin is not None else sys.stdin.buffer,
        stdout if stdout is not None else sys.stdout.buffer,
        name="parent",
    )
