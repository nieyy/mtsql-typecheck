"""Narrow PyMySQL 1.1.2 text-protocol shim (D3 design 6.4.3/6.4.4, Phase 2).

This is the ONLY module allowed to depend on PyMySQL internal metadata and
packet structures (design section 5 [R8]).  Importing this module opens no
connection; PyMySQL is imported at module top because it is a declared
optional dependency (``pip install '.[mysql]'``).

Every behaviour here is fail closed:

- the driver baseline is gated on ``importlib.metadata.version("PyMySQL")``
  being exactly ``1.1.2`` **and** on the presence of the internal structures
  this shim depends on (the installed distribution's ``pymysql.__version__``
  attribute disagrees with its own package metadata, so the metadata version
  is the only trustworthy gate);
- unknown packet layouts, unexpected metadata shapes and non-canonical value
  texts raise typed :class:`AdapterError` subclasses instead of being coerced;
- packet/row/byte budgets are checked before bodies are allocated, and a
  budget violation marks the connection unusable instead of draining results.

Driver internals depended on (PyMySQL 1.1.2 tag):
- ``pymysql/connections.py``: ``Connection._read_packet`` frame loop,
  ``MAX_PACKET_LEN``, ``MySQLResult._get_descriptions`` /
  ``init_unbuffered_query`` / unbuffered row reading, ``Connection.close``
  (COM_QUIT without draining), ``_force_close``.
- ``pymysql/protocol.py``: ``MysqlPacket``, ``FieldDescriptorPacket``
  (``_parse_field_descriptor`` struct ``<xHIBHBxx``), ``OKPacketWrapper``
  (status before warnings), ``EOFPacketWrapper``.
- ``pymysql/cursors.py``: ``Cursor`` (buffered statements), ``SSCursor``
  (unbuffered ``read_next``).
- ``pymysql/constants/{FIELD_TYPE,CLIENT,SERVER_STATUS,CR}.py``: wire codes.
- ``pymysql/err.py``: ``MySQLError`` family; ERR packets surface ``errno``
  only (the driver drops SQLSTATE), so ``sqlstate`` stays ``None`` here and
  is never guessed from the message text.
"""

from __future__ import annotations

import importlib.metadata
import struct
from dataclasses import dataclass
from typing import Callable, Optional, Sequence, Tuple

import pymysql
import pymysql.connections
import pymysql.constants.CR
import pymysql.constants.FIELD_TYPE
import pymysql.constants.SERVER_STATUS
import pymysql.cursors
import pymysql.err
import pymysql.protocol

from ..contracts import execution as _execution
from ..contracts.codec import canonical_json
from .base import (
    AdapterError,
    ConnectionParams,
    FieldMetadata,
    ProtocolBudgetError,
    ResultContractViolation,
    ResultEncodingError,
)

__all__ = [
    "MAPPING_VERSION",
    "PACKET_BUDGET_BYTES",
    "MAX_DIAGNOSTIC_ENTRIES",
    "MAX_DIAGNOSTIC_MESSAGE_BYTES",
    "WIRE_TYPE_INTEGER",
    "WIRE_TYPE_DECIMAL",
    "WIRE_TYPE_FLOAT",
    "WIRE_TYPE_DOUBLE",
    "WIRE_TYPE_NULL",
    "OkPacketInfo",
    "EofPacketInfo",
    "ErrPacketInfo",
    "WarningEntry",
    "DiagnosticsRecord",
    "MappedColumn",
    "BoundedFetchResult",
    "RawQueryResult",
    "StatementReceipt",
    "QueryHandle",
    "BoundedPacketReader",
    "verify_driver_baseline",
    "decode_result_value",
    "map_column",
    "extract_field_metadata",
    "parse_ok_packet",
    "parse_eof_packet",
    "parse_err_packet",
    "classify_terminator",
    "reconcile_diagnostics",
    "bounded_fetch",
    "bounded_fetch_raw",
    "PyMySQLAdapter",
]

# --------------------------------------------------------------------------
# Frozen versions and budgets (design 6.4.3/6.4.4)
# --------------------------------------------------------------------------

#: Frozen mapping identity (design 6.4.3); stamped on every mapped column.
MAPPING_VERSION = "mysql80-pymysql112-exact-v1"

#: Single reassembled-message cap (design 6.4.4 [R8]): one MySQL frame is at
#: most 16 MiB - 1, so the cumulative cap is the binding limit for messages
#: split across continuation frames.
PACKET_BUDGET_BYTES = 16 * 1024 * 1024

_MAX_FRAME_BYTES = 0xFFFFFF  # 16 MiB - 1 (PyMySQL MAX_PACKET_LEN)

#: Diagnostics budgets (design 6.4.6): 128 entries per statement, 2 KiB per
#: message text.
MAX_DIAGNOSTIC_ENTRIES = 128
MAX_DIAGNOSTIC_MESSAGE_BYTES = 2 * 1024

#: Certified driver baseline; upgrades require re-running the protocol
#: fixtures and re-certification (requirements/mysql-certified.txt).
_CERTIFIED_DRIVER_VERSION = "1.1.2"

# Wire type codes (mirrored and cross-checked against
# pymysql.constants.FIELD_TYPE by verify_driver_baseline).
WIRE_TYPE_DECIMAL = 0
WIRE_TYPE_TINY = 1
WIRE_TYPE_SHORT = 2
WIRE_TYPE_LONG = 3
WIRE_TYPE_FLOAT = 4
WIRE_TYPE_DOUBLE = 5
WIRE_TYPE_NULL = 6
WIRE_TYPE_LONGLONG = 8
WIRE_TYPE_INT24 = 9
WIRE_TYPE_NEWDECIMAL = 246

_INTEGER_TYPES = frozenset(
    {WIRE_TYPE_TINY, WIRE_TYPE_SHORT, WIRE_TYPE_LONG, WIRE_TYPE_LONGLONG, WIRE_TYPE_INT24}
)
_DECIMAL_TYPES = frozenset({WIRE_TYPE_DECIMAL, WIRE_TYPE_NEWDECIMAL})

# Same canonical integer grammar as D1/D2: "0" or "-?[1-9][0-9]*".
_INTEGER_TEXT_RE = _execution._CANONICAL_INT_TEXT_RE


# --------------------------------------------------------------------------
# Driver baseline gate (fail closed)
# --------------------------------------------------------------------------


def verify_driver_baseline() -> str:
    """Verify the certified PyMySQL baseline and required internal structures.

    Uses ``importlib.metadata.version("PyMySQL")`` (package metadata), not
    ``pymysql.__version__``: the installed code's ``__version__`` attribute
    disagrees with its own distribution metadata, so the metadata version is
    the only trustworthy gate.  Raises :class:`AdapterError` on any mismatch.
    """

    try:
        version = importlib.metadata.version("PyMySQL")
    except importlib.metadata.PackageNotFoundError as exc:
        raise AdapterError(
            "PyMySQL distribution metadata not found; the certified driver "
            "baseline cannot be verified (fail closed)"
        ) from exc
    if version != _CERTIFIED_DRIVER_VERSION:
        raise AdapterError(
            f"PyMySQL {version!r} is not the certified baseline "
            f"{_CERTIFIED_DRIVER_VERSION!r}; upgrades require re-running the "
            f"protocol fixtures and re-certification (fail closed)"
        )

    connections = pymysql.connections
    protocol = pymysql.protocol
    cursors = pymysql.cursors
    constants_field = pymysql.constants.FIELD_TYPE
    constants_client = pymysql.constants.CLIENT
    constants_server_status = pymysql.constants.SERVER_STATUS

    required = (
        ("pymysql.connections.Connection", getattr(connections, "Connection", None)),
        ("pymysql.connections.MySQLResult", getattr(connections, "MySQLResult", None)),
        ("pymysql.connections.MAX_PACKET_LEN", getattr(connections, "MAX_PACKET_LEN", None)),
        ("pymysql.protocol.MysqlPacket", getattr(protocol, "MysqlPacket", None)),
        ("pymysql.protocol.FieldDescriptorPacket", getattr(protocol, "FieldDescriptorPacket", None)),
        ("pymysql.protocol.OKPacketWrapper", getattr(protocol, "OKPacketWrapper", None)),
        ("pymysql.protocol.EOFPacketWrapper", getattr(protocol, "EOFPacketWrapper", None)),
        ("pymysql.cursors.Cursor", getattr(cursors, "Cursor", None)),
        ("pymysql.cursors.SSCursor", getattr(cursors, "SSCursor", None)),
        ("pymysql.err.MySQLError", getattr(pymysql.err, "MySQLError", None)),
        ("pymysql.err.raise_mysql_exception", getattr(pymysql.err, "raise_mysql_exception", None)),
        ("pymysql.constants.CR", getattr(pymysql.constants, "CR", None)),
        ("pymysql.constants.COMMAND", getattr(pymysql.constants, "COMMAND", None)),
        ("pymysql.constants.CLIENT", constants_client),
        ("pymysql.constants.SERVER_STATUS", constants_server_status),
        ("pymysql.constants.FIELD_TYPE", constants_field),
    )
    for name, obj in required:
        if obj is None:
            raise AdapterError(
                f"PyMySQL internal structure {name} is missing; the shim only "
                f"supports the certified {_CERTIFIED_DRIVER_VERSION} layout "
                f"(fail closed)"
            )

    expected_field_types = {
        "DECIMAL": WIRE_TYPE_DECIMAL,
        "TINY": WIRE_TYPE_TINY,
        "SHORT": WIRE_TYPE_SHORT,
        "LONG": WIRE_TYPE_LONG,
        "FLOAT": WIRE_TYPE_FLOAT,
        "DOUBLE": WIRE_TYPE_DOUBLE,
        "NULL": WIRE_TYPE_NULL,
        "LONGLONG": WIRE_TYPE_LONGLONG,
        "INT24": WIRE_TYPE_INT24,
        "NEWDECIMAL": WIRE_TYPE_NEWDECIMAL,
    }
    for attr, expected in expected_field_types.items():
        actual = getattr(constants_field, attr, None)
        if actual != expected:
            raise AdapterError(
                f"PyMySQL FIELD_TYPE.{attr} is {actual!r}, expected {expected!r} "
                f"(frozen mapping {MAPPING_VERSION}; fail closed)"
            )

    if getattr(constants_client, "PROTOCOL_41", None) != 1 << 9:
        raise AdapterError("PyMySQL CLIENT.PROTOCOL_41 has an unexpected value (fail closed)")
    if getattr(constants_client, "DEPRECATE_EOF", None) != 1 << 24:
        raise AdapterError("PyMySQL CLIENT.DEPRECATE_EOF has an unexpected value (fail closed)")
    if getattr(constants_server_status, "SERVER_MORE_RESULTS_EXISTS", None) != 8:
        raise AdapterError(
            "PyMySQL SERVER_STATUS.SERVER_MORE_RESULTS_EXISTS has an unexpected value "
            "(fail closed)"
        )

    for name, obj in (
        ("Connection._read_packet", getattr(connections.Connection, "_read_packet", None)),
        ("Connection._read_bytes", getattr(connections.Connection, "_read_bytes", None)),
        ("Connection._force_close", getattr(connections.Connection, "_force_close", None)),
        ("MySQLResult._get_descriptions", getattr(connections.MySQLResult, "_get_descriptions", None)),
        ("SSCursor.read_next", getattr(cursors.SSCursor, "read_next", None)),
    ):
        if obj is None:
            raise AdapterError(f"PyMySQL internal method {name} is missing (fail closed)")

    return version


# --------------------------------------------------------------------------
# Bounded packet reading (design 6.4.4 [R8])
# --------------------------------------------------------------------------


class BoundedPacketReader:
    """Reassemble one MySQL message from frames with pre-allocation caps.

    The 3-byte header length is validated against the cumulative reassembled
    message cap BEFORE the frame body is read or allocated, so a message split
    into several ``16 MiB - 1`` frames trips the cap on the cumulative total,
    not per fragment.  ``deadline_cb`` (if given) is invoked before each frame
    read; the frame stream ends with a frame shorter than ``16 MiB - 1``.
    """

    def __init__(
        self,
        read_exactly: Callable[[int], bytes],
        *,
        message_cap: int = PACKET_BUDGET_BYTES,
        deadline_cb: Optional[Callable[[], None]] = None,
        sequence_validator: Optional[Callable[[int], None]] = None,
        continuation_threshold: int = _MAX_FRAME_BYTES,
    ) -> None:
        # The real protocol continues a message only after a 16 MiB - 1 frame;
        # the threshold is injectable so tests can exercise multi-fragment
        # reassembly with small synthetic frames.  The connection-level reader
        # always uses the real threshold.
        self._read_exactly = read_exactly
        self._message_cap = message_cap
        self._deadline_cb = deadline_cb
        self._sequence_validator = sequence_validator
        self._continuation_threshold = continuation_threshold

    def read_message(self) -> bytes:
        parts: list[bytes] = []
        total = 0
        first_sequence: Optional[int] = None
        while True:
            if self._deadline_cb is not None:
                self._deadline_cb()
            header = self._read_exactly(4)
            if len(header) != 4:
                raise ResultContractViolation(
                    f"truncated packet header: got {len(header)} bytes, expected 4"
                )
            btrl, btrh, sequence = struct.unpack("<HBB", header)
            frame_len = btrl + (btrh << 16)
            if self._sequence_validator is not None:
                self._sequence_validator(sequence)
            elif first_sequence is None:
                first_sequence = sequence
            elif sequence != (first_sequence + len(parts)) % 256:
                raise ResultContractViolation(
                    f"packet sequence {sequence} is not contiguous after "
                    f"{first_sequence + len(parts) - 1} (fail closed)"
                )
            # Cap check BEFORE the body is read or allocated: a continuation
            # frame crossing the cumulative cap is refused here, not after.
            if total + frame_len > self._message_cap:
                raise ProtocolBudgetError(
                    f"reassembled message would reach {total + frame_len} bytes, "
                    f"exceeding the single-message cap {self._message_cap}"
                )
            body = self._read_exactly(frame_len)
            if len(body) != frame_len:
                raise ResultContractViolation(
                    f"truncated packet body: got {len(body)} bytes, expected {frame_len}"
                )
            parts.append(body)
            total += frame_len
            if frame_len < self._continuation_threshold:
                break
        return b"".join(parts)


# --------------------------------------------------------------------------
# Packet payload parsers (OK / ERR / EOF, CLIENT_DEPRECATE_EOF aware)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class OkPacketInfo:
    affected_rows: int
    insert_id: int
    server_status: int
    warning_count: int
    has_next: bool  # SERVER_MORE_RESULTS_EXISTS observed (never consumed)


@dataclass(frozen=True)
class EofPacketInfo:
    warning_count: int
    server_status: int
    has_next: bool


@dataclass(frozen=True)
class ErrPacketInfo:
    errno: int
    sqlstate: Optional[str]  # None when the packet carries no SQLSTATE marker
    message: str


def _packet(payload: bytes) -> "pymysql.protocol.MysqlPacket":
    return pymysql.protocol.MysqlPacket(bytes(payload), "utf8")


def classify_terminator(payload: bytes) -> str:
    """Classify a terminating packet payload: "ok" / "eof" / "err" / "unknown".

    Under ``CLIENT_DEPRECATE_EOF`` a result terminator is an OK packet; the
    classic protocol uses an EOF packet.  Both carry the authoritative final
    warning count (negative P02); the caller must treat "unknown" as fail
    closed.
    """

    pkt = _packet(payload)
    if pkt.is_error_packet():
        return "err"
    if pkt.is_ok_packet():
        return "ok"
    if pkt.is_eof_packet():
        return "eof"
    return "unknown"


def parse_ok_packet(payload: bytes) -> OkPacketInfo:
    """Parse an OK packet payload (including a deprecated-EOF terminator)."""

    pkt = _packet(payload)
    if not pkt.is_ok_packet():
        raise ResultContractViolation("payload is not an OK packet (fail closed)")
    wrapper = pymysql.protocol.OKPacketWrapper(pkt)
    for name, value in (
        ("affected_rows", wrapper.affected_rows),
        ("insert_id", wrapper.insert_id),
        ("server_status", wrapper.server_status),
        ("warning_count", wrapper.warning_count),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ResultContractViolation(
                f"OK packet field {name} is not a non-negative int: {value!r} (fail closed)"
            )
    return OkPacketInfo(
        affected_rows=wrapper.affected_rows,
        insert_id=wrapper.insert_id,
        server_status=wrapper.server_status,
        warning_count=wrapper.warning_count,
        has_next=bool(wrapper.server_status & pymysql.constants.SERVER_STATUS.SERVER_MORE_RESULTS_EXISTS),
    )


def parse_eof_packet(payload: bytes) -> EofPacketInfo:
    """Parse a classic EOF packet payload (column-definition or result end)."""

    pkt = _packet(payload)
    if not pkt.is_eof_packet():
        raise ResultContractViolation("payload is not an EOF packet (fail closed)")
    wrapper = pymysql.protocol.EOFPacketWrapper(pkt)
    for name, value in (
        ("warning_count", wrapper.warning_count),
        ("server_status", wrapper.server_status),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ResultContractViolation(
                f"EOF packet field {name} is not a non-negative int: {value!r} (fail closed)"
            )
    return EofPacketInfo(
        warning_count=wrapper.warning_count,
        server_status=wrapper.server_status,
        has_next=bool(wrapper.server_status & pymysql.constants.SERVER_STATUS.SERVER_MORE_RESULTS_EXISTS),
    )


def parse_err_packet(payload: bytes) -> ErrPacketInfo:
    """Parse an ERR packet payload; keep errno + sqlstate verbatim.

    ``sqlstate`` is ``None`` when the packet has no ``#``-prefixed SQLSTATE
    (or it is not decodable ASCII); it is never guessed from the message.
    """

    payload = bytes(payload)
    if len(payload) < 3 or payload[0] != 0xFF:
        raise ResultContractViolation("payload is not an ERR packet (fail closed)")
    errno = struct.unpack_from("<H", payload, 1)[0]
    if len(payload) > 3 and payload[3:4] == b"#":
        if len(payload) < 9:
            raise ResultContractViolation("ERR packet SQLSTATE marker is truncated (fail closed)")
        try:
            sqlstate: Optional[str] = payload[4:9].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ResultContractViolation(
                f"ERR packet SQLSTATE is not ASCII: {payload[4:9]!r} (fail closed)"
            ) from exc
        message = payload[9:]
    else:
        sqlstate = None
        message = payload[3:]
    return ErrPacketInfo(errno=errno, sqlstate=sqlstate, message=message.decode("utf-8", "replace"))


# --------------------------------------------------------------------------
# Field metadata extraction (design 6.4.3; no DB-API description shortcuts)
# --------------------------------------------------------------------------


def _check_meta_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ResultContractViolation(
            f"field packet {name} is not a non-negative int: {value!r} (fail closed)"
        )
    return value


def extract_field_metadata(packet: object, ordinal: int) -> FieldMetadata:
    """Extract raw field metadata from a PyMySQL FieldDescriptorPacket.

    Missing or wrongly-typed internal attributes fail closed; fields DB-API
    does not provide are never zero-filled.
    """

    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
        raise ResultContractViolation(f"column ordinal must be a non-negative int, got {ordinal!r}")
    for name in ("charsetnr", "length", "type_code", "flags", "scale"):
        if not hasattr(packet, name):
            raise ResultContractViolation(
                f"field packet for column {ordinal} is missing internal "
                f"attribute {name!r} (fail closed)"
            )
    for name in ("name", "table_name"):
        if not hasattr(packet, name):
            raise ResultContractViolation(
                f"field packet for column {ordinal} is missing internal "
                f"attribute {name!r} (fail closed)"
            )
    alias = packet.name
    table_alias = packet.table_name
    if not isinstance(alias, str) or not isinstance(table_alias, str):
        raise ResultContractViolation(
            f"field packet names for column {ordinal} are not strings (fail closed)"
        )
    return FieldMetadata(
        ordinal=ordinal,
        type_code=_check_meta_int(packet.type_code, "type_code"),
        flags=_check_meta_int(packet.flags, "flags"),
        decimals=_check_meta_int(packet.scale, "scale"),
        length=_check_meta_int(packet.length, "length"),
        charset=_check_meta_int(packet.charsetnr, "charsetnr"),
        alias=alias,
        table_alias=table_alias,
    )


# --------------------------------------------------------------------------
# Exact value decoding (design 6.4.3 frozen mapping)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class MappedColumn:
    """Shim-side column mapping; the declared relation decides ``family`` at
    the oracle layer, so this record carries raw ``type_code``/``flags`` only
    (never a guessed family, never a cast)."""

    ordinal: int
    alias: str
    type_code: int
    flags: int
    precision: Optional[int]
    scale: Optional[int]
    charset: int
    length: int
    decimals: int
    mapping_version: str


def map_column(meta: FieldMetadata, ordinal: int) -> MappedColumn:
    """Map one column under the frozen mapping (design 6.4.3).

    ``precision`` stays None: the protocol ``length`` is a display length, not
    a reliable precision, and is never presented as one.  ``scale`` comes from
    the metadata only for decimal wire types.  Unsigned flag values stay
    INTEGER (the flags are preserved on the column); integers are never
    auto-widened to decimal to please a relation.
    """

    if meta.ordinal != ordinal:
        raise ResultContractViolation(
            f"map_column ordinal {ordinal} does not match metadata ordinal {meta.ordinal}"
        )
    scale: Optional[int] = meta.decimals if meta.type_code in _DECIMAL_TYPES else None
    return MappedColumn(
        ordinal=meta.ordinal,
        alias=meta.alias,
        type_code=meta.type_code,
        flags=meta.flags,
        precision=None,
        scale=scale,
        charset=meta.charset,
        length=meta.length,
        decimals=meta.decimals,
        mapping_version=MAPPING_VERSION,
    )


def decode_result_value(
    text: Optional[bytes], meta: FieldMetadata
) -> "_execution.ResultValue":
    """Decode one text-protocol scalar exactly under the frozen mapping.

    Integer wire types map to INTEGER via strict canonical decimal text
    validation of the raw bytes (no float, no int-guessing); DECIMAL/
    NEWDECIMAL map to DECIMAL as (coefficient, scale) using pure integer
    string arithmetic with the server-sent scale; NULL maps to the NULL kind.
    Everything else (FLOAT/DOUBLE/string/JSON/date-time/unknown) raises
    :class:`ResultEncodingError` with the raw metadata preserved -- the value
    text is never used to guess a family.
    """

    if text is None:
        # NULL is an independent kind; never 0 or "".
        return _execution.ResultValue(_execution.ResultValueKind.NULL)
    if isinstance(text, (bytes, bytearray)):
        raw = bytes(text)
    else:
        raise ResultContractViolation(
            f"column {meta.ordinal}: driver delivered {type(text).__name__}, "
            f"expected raw bytes (fail closed)"
        )
    if len(raw) > _execution.MAX_SCALAR_TEXT_CHARS:
        raise ResultEncodingError(
            f"column {meta.ordinal}: value text of {len(raw)} chars exceeds the "
            f"{_execution.MAX_SCALAR_TEXT_CHARS}-char scalar budget",
            type_code=meta.type_code,
            flags=meta.flags,
            column_ordinal=meta.ordinal,
            mapping_version=MAPPING_VERSION,
        )
    type_code = meta.type_code
    if type_code in _INTEGER_TYPES:
        if meta.decimals != 0:
            raise ResultContractViolation(
                f"column {meta.ordinal}: integer wire type {type_code} carries "
                f"decimals={meta.decimals} (fail closed)"
            )
        decoded = raw.decode("ascii", errors="strict") if raw.isascii() else None
        if decoded is None or _INTEGER_TEXT_RE.match(decoded) is None:
            raise ResultEncodingError(
                f"column {meta.ordinal}: integer wire type {type_code} sent "
                f"non-canonical decimal text {raw!r}",
                type_code=type_code,
                flags=meta.flags,
                column_ordinal=meta.ordinal,
                mapping_version=MAPPING_VERSION,
            )
        return _execution.ResultValue(
            _execution.ResultValueKind.INTEGER, int_value=int(decoded)
        )
    if type_code in _DECIMAL_TYPES:
        matched = _DECIMAL_TEXT_MATCH(raw)
        if matched is None:
            raise ResultEncodingError(
                f"column {meta.ordinal}: decimal wire type {type_code} sent "
                f"non-canonical decimal text {raw!r}",
                type_code=type_code,
                flags=meta.flags,
                column_ordinal=meta.ordinal,
                mapping_version=MAPPING_VERSION,
            )
        negative, digits, scale = matched
        coefficient = int(digits)
        if negative and coefficient != 0:
            coefficient = -coefficient
        if scale > _execution.MAX_RESULT_SCALE:
            raise ResultEncodingError(
                f"column {meta.ordinal}: server-sent scale {scale} exceeds "
                f"MAX_RESULT_SCALE ({_execution.MAX_RESULT_SCALE})",
                type_code=type_code,
                flags=meta.flags,
                column_ordinal=meta.ordinal,
                mapping_version=MAPPING_VERSION,
            )
        if meta.decimals != scale:
            # The server-sent text is authoritative; the metadata disagreement
            # is a contract violation, never a silent choice of either value.
            raise ResultContractViolation(
                f"column {meta.ordinal}: decimal text {raw.decode('ascii', 'replace')} "
                f"has scale {scale} but field metadata says decimals={meta.decimals} "
                f"(server-sent value recorded; fail closed)"
            )
        return _execution.ResultValue(
            _execution.ResultValueKind.DECIMAL, coefficient=coefficient, scale=scale
        )
    # FLOAT/DOUBLE/string/JSON/date-time/unknown wire types: never guessed.
    raise ResultEncodingError(
        f"column {meta.ordinal}: wire type {type_code} is not representable "
        f"losslessly under mapping {MAPPING_VERSION}",
        type_code=type_code,
        flags=meta.flags,
        column_ordinal=meta.ordinal,
        mapping_version=MAPPING_VERSION,
    )


def _DECIMAL_TEXT_MATCH(raw: bytes) -> Optional[Tuple[bool, str, int]]:
    """Strict canonical decimal text match -> (negative, digit_string, scale).

    Pure string arithmetic: no float, no Decimal context, trailing zeros
    preserved exactly as sent by the server.  Negative zero ("-0", "-0.000")
    is never sent by MySQL and is rejected instead of being silently folded.
    """

    body = raw[1:] if raw[:1] == b"-" else raw
    negative = len(body) != len(raw)
    if not body or not body.isascii():
        return None
    if not all(48 <= b <= 57 or b == 46 for b in body) or body.count(b".") > 1:
        return None  # only digits and at most one decimal point
    if b"." in body:
        int_part, _, frac_part = body.partition(b".")
        if not int_part or not frac_part:
            return None
        if len(int_part) > 1 and int_part[0:1] == b"0":
            return None  # leading zeros are not canonical
        if negative and not any(b != 48 for b in int_part + frac_part):
            return None  # negative zero is not canonical
        return negative, (int_part + frac_part).decode("ascii"), len(frac_part)
    if len(body) > 1 and body[0:1] == b"0":
        return None  # e.g. "007" is not canonical
    if negative and body == b"0":
        return None  # negative zero is not canonical
    return negative, body.decode("ascii"), 0


# --------------------------------------------------------------------------
# Diagnostics capture (design 6.4.3 [R6]; negative P02/P03)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class WarningEntry:
    """One SHOW WARNINGS entry; sqlstate is absent in SHOW WARNINGS output
    and is never fabricated."""

    level: str  # "ERROR" / "WARNING" / "NOTE"
    code: str
    sqlstate: Optional[str]
    message: str


@dataclass(frozen=True)
class DiagnosticsRecord:
    collected: bool
    complete: bool
    truncated: bool
    entries: Tuple[WarningEntry, ...]
    packet_warning_count: Optional[int]
    shown_count: int

    @classmethod
    def not_collected(cls) -> "DiagnosticsRecord":
        return cls(
            collected=False,
            complete=False,
            truncated=False,
            entries=(),
            packet_warning_count=None,
            shown_count=0,
        )


_LEVEL_MAP = {"error": "ERROR", "warning": "WARNING", "note": "NOTE"}


def _decode_cell(value: object, what: str) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    raise ResultContractViolation(
        f"SHOW WARNINGS {what} is neither bytes nor str: {value!r} (fail closed)"
    )


def reconcile_diagnostics(
    packet_warning_count: Optional[int], rows: Sequence[Sequence[object]]
) -> DiagnosticsRecord:
    """Reconcile a terminating packet's warning count with SHOW WARNINGS rows.

    - entries beyond :data:`MAX_DIAGNOSTIC_ENTRIES` -> ``truncated=True`` and
      ``complete=False`` (the first 128 are kept);
    - any message text over 2 KiB -> ``truncated=True``;
    - count mismatch between the packet and the SHOW WARNINGS rows ->
      ``complete=False`` (no truncation claim, the counts simply disagree);
    - a missing packet count (ERR without warning count) -> ``complete=False``.

    NOTE-level entries are preserved, never filtered.
    """

    if packet_warning_count is not None and (
        isinstance(packet_warning_count, bool)
        or not isinstance(packet_warning_count, int)
        or packet_warning_count < 0
    ):
        raise ResultContractViolation(
            f"packet warning count must be a non-negative int or None, got "
            f"{packet_warning_count!r}"
        )
    entries: list[WarningEntry] = []
    for row in rows:
        if len(row) < 3:
            raise ResultContractViolation(
                f"SHOW WARNINGS row has {len(row)} cells, expected at least 3 (fail closed)"
            )
        level_text = _decode_cell(row[0], "Level").strip().lower()
        level = _LEVEL_MAP.get(level_text)
        if level is None:
            raise ResultContractViolation(
                f"SHOW WARNINGS level {row[0]!r} is not ERROR/WARNING/NOTE (fail closed)"
            )
        code_text = _decode_cell(row[1], "Code").strip()
        try:
            code = str(int(code_text))
        except ValueError as exc:
            raise ResultContractViolation(
                f"SHOW WARNINGS code {row[1]!r} is not numeric (fail closed)"
            ) from exc
        message = _decode_cell(row[2], "Message")
        entries.append(WarningEntry(level=level, code=code, sqlstate=None, message=message))
    shown_count = len(entries)
    truncated = False
    if shown_count > MAX_DIAGNOSTIC_ENTRIES:
        entries = entries[:MAX_DIAGNOSTIC_ENTRIES]
        truncated = True
    for entry in entries:
        if len(entry.message.encode("utf-8")) > MAX_DIAGNOSTIC_MESSAGE_BYTES:
            truncated = True
    complete = (
        packet_warning_count is not None
        and packet_warning_count == shown_count
        and not truncated
    )
    return DiagnosticsRecord(
        collected=True,
        complete=complete,
        truncated=truncated,
        entries=tuple(entries),
        packet_warning_count=packet_warning_count,
        shown_count=shown_count,
    )


# --------------------------------------------------------------------------
# Bounded fetch (design 6.4.4; negative P04)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class BoundedFetchResult:
    columns: Tuple[MappedColumn, ...]
    values: Tuple[Tuple["_execution.ResultValue", ...], ...]
    observed_row_count: int
    fetch_complete: bool
    truncated: bool
    extra_result_sets: int
    warning_count: Optional[int]  # final terminator count, never the column-EOF count
    encoded_bytes: int


@dataclass(frozen=True)
class RawQueryResult:
    """Bounded raw byte rows for schema/readback probes (no exact decoding;
    the facts layer interprets them)."""

    database: Optional[str]
    columns: Tuple[MappedColumn, ...]
    rows: Tuple[Tuple[Optional[bytes], ...], ...]
    observed_row_count: int
    fetch_complete: bool
    truncated: bool
    warning_count: Optional[int]


def _bounded_read_rows(
    cursor: object,
    *,
    row_budget: int,
    byte_budget: int,
    deadline_cb: Optional[Callable[[], None]],
    convert: Callable[[tuple], Tuple[object, int]],
) -> Tuple[list, int, bool]:
    """Shared bounded row loop (negative P04).

    Stops before adding a row that would cross either budget, then attempts
    one extra read: exactly-at-limit only counts as complete when the next
    read confirms EOF; one extra row means truncated.  Never calls
    ``cursor.close()``/``nextset()`` (those drain further results).
    """

    rows: list = []
    total_bytes = 0
    at_limit = False
    while True:
        if deadline_cb is not None:
            deadline_cb()
        if len(rows) >= row_budget:
            at_limit = True
            break
        raw = cursor.read_next()
        if raw is None:
            break  # final EOF/OK terminator; result.warning_count is authoritative
        if not isinstance(raw, tuple):
            raise ResultContractViolation(
                f"driver delivered a {type(raw).__name__} row, expected a tuple (fail closed)"
            )
        item, size = convert(raw)
        if total_bytes + size > byte_budget:
            at_limit = True
            break
        rows.append(item)
        total_bytes += size
    truncated = False
    if at_limit:
        if deadline_cb is not None:
            deadline_cb()
        if cursor.read_next() is not None:
            truncated = True
    return rows, total_bytes, truncated


def _check_fetch_budgets(row_budget: int, byte_budget: int) -> None:
    for name, value, cap in (
        ("row_budget", row_budget, _execution.MAX_RESULT_ROWS),
        ("byte_budget", byte_budget, _execution.MAX_RESULT_BYTES),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ProtocolBudgetError(f"{name} must be an int")
        if not 1 <= value <= cap:
            raise ProtocolBudgetError(
                f"{name} must be in [1, {cap}], got {value}"
            )


def _final_warning_count(cursor: object) -> Optional[int]:
    result = getattr(cursor, "_result", None)
    count = getattr(result, "warning_count", None)
    if count is None:
        return None
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ResultContractViolation(
            f"final terminator warning count is not a non-negative int: {count!r}"
        )
    return count


def _extra_result_sets(cursor: object) -> int:
    result = getattr(cursor, "_result", None)
    has_next = getattr(result, "has_next", None)
    if has_next is None:
        return 0
    if not isinstance(has_next, int):
        raise ResultContractViolation(f"has_next flag is not an int: {has_next!r}")
    return 1 if has_next else 0


def bounded_fetch(
    cursor: object,
    metas: Sequence[FieldMetadata],
    *,
    row_budget: int,
    byte_budget: int,
    deadline_cb: Optional[Callable[[], None]] = None,
) -> BoundedFetchResult:
    """Exact-decoding bounded fetch over an unbuffered (SSCursor) cursor.

    The cumulative canonical-encoded byte budget and the row budget are
    checked before each row is kept; exactly-at-limit confirms EOF with one
    extra read (negative P04).  The warning count is taken from the final
    terminator state only -- the column-definition EOF count must never be
    mistaken for it (negative P02).
    """

    _check_fetch_budgets(row_budget, byte_budget)
    if not 1 <= len(metas) <= _execution.MAX_RESULT_COLUMNS:
        raise ProtocolBudgetError(
            f"result column count {len(metas)} outside [1, {_execution.MAX_RESULT_COLUMNS}]"
        )

    def convert(raw: tuple) -> Tuple[Tuple["_execution.ResultValue", ...], int]:
        if len(raw) != len(metas):
            raise ResultContractViolation(
                f"row holds {len(raw)} cells but the result declares {len(metas)} "
                f"columns (fail closed)"
            )
        values = tuple(decode_result_value(cell, meta) for cell, meta in zip(raw, metas))
        size = len(canonical_json([value.to_obj() for value in values]))
        return values, size

    values, total_bytes, truncated = _bounded_read_rows(
        cursor,
        row_budget=row_budget,
        byte_budget=byte_budget,
        deadline_cb=deadline_cb,
        convert=convert,
    )
    return BoundedFetchResult(
        columns=tuple(map_column(meta, meta.ordinal) for meta in metas),
        values=tuple(values),
        observed_row_count=len(values),
        fetch_complete=not truncated,
        truncated=truncated,
        extra_result_sets=_extra_result_sets(cursor) if not truncated else 0,
        warning_count=_final_warning_count(cursor),
        encoded_bytes=total_bytes,
    )


def bounded_fetch_raw(
    cursor: object,
    metas: Sequence[FieldMetadata],
    *,
    row_budget: int,
    byte_budget: int,
    deadline_cb: Optional[Callable[[], None]] = None,
    database: Optional[str] = None,
) -> RawQueryResult:
    """Bounded raw fetch for information-schema/readback probes: rows stay
    raw bytes (or None), no exact decoding, hard row/byte budgets."""

    _check_fetch_budgets(row_budget, byte_budget)
    if not 1 <= len(metas) <= _execution.MAX_RESULT_COLUMNS:
        raise ProtocolBudgetError(
            f"result column count {len(metas)} outside [1, {_execution.MAX_RESULT_COLUMNS}]"
        )

    def convert(raw: tuple) -> Tuple[Tuple[Optional[bytes], ...], int]:
        if len(raw) != len(metas):
            raise ResultContractViolation(
                f"row holds {len(raw)} cells but the result declares {len(metas)} "
                f"columns (fail closed)"
            )
        cells: list[Optional[bytes]] = []
        for cell in raw:
            if cell is None:
                cells.append(None)
            elif isinstance(cell, (bytes, bytearray)):
                cells.append(bytes(cell))
            else:
                raise ResultContractViolation(
                    f"raw fetch cell is {type(cell).__name__}, expected bytes/None "
                    f"(fail closed)"
                )
        return tuple(cells), sum(len(cell) for cell in cells if cell is not None)

    rows, _total, truncated = _bounded_read_rows(
        cursor,
        row_budget=row_budget,
        byte_budget=byte_budget,
        deadline_cb=deadline_cb,
        convert=convert,
    )
    return RawQueryResult(
        database=database,
        columns=tuple(map_column(meta, meta.ordinal) for meta in metas),
        rows=tuple(rows),
        observed_row_count=len(rows),
        fetch_complete=not truncated,
        truncated=truncated,
        warning_count=_final_warning_count(cursor),
    )


# --------------------------------------------------------------------------
# PyMySQL adapter (design 6.3.2; connect/execute/fetch/close only)
# --------------------------------------------------------------------------


class _BoundedMySQLResult(pymysql.connections.MySQLResult):
    """MySQLResult that refuses wide results before allocating field structures
    (design 6.4.4: the column count is checked from the first result packet
    before any field structure is built)."""

    def _get_descriptions(self) -> None:
        field_count = self.field_count
        if isinstance(field_count, bool) or not isinstance(field_count, int) or field_count < 0:
            raise ResultContractViolation(
                f"first result packet declared an unusable field count {field_count!r} "
                f"(fail closed)"
            )
        if field_count > _execution.MAX_RESULT_COLUMNS:
            raise ProtocolBudgetError(
                f"result declares {field_count} columns, exceeding "
                f"MAX_RESULT_COLUMNS ({_execution.MAX_RESULT_COLUMNS})"
            )
        super()._get_descriptions()


class _BoundedConnection(pymysql.connections.Connection):
    """Connection whose packet reader enforces the reassembled-message cap
    and the deadline callback before any frame body is allocated."""

    def __init__(self, *, deadline_cb: Optional[Callable[[], None]] = None, **kwargs) -> None:
        self._shim_deadline_cb = deadline_cb
        kwargs.setdefault("defer_connect", True)
        super().__init__(**kwargs)

    def _set_deadline_cb(self, deadline_cb: Optional[Callable[[], None]]) -> None:
        self._shim_deadline_cb = deadline_cb

    def _read_packet(self, packet_type=pymysql.protocol.MysqlPacket):  # noqa: ANN001
        # Mirrors PyMySQL 1.1.2 Connection._read_packet (connections.py:742)
        # with two shim additions: the cumulative cap check before each body
        # read, and the deadline callback between frames.
        reader = BoundedPacketReader(
            self._read_bytes,
            message_cap=PACKET_BUDGET_BYTES,
            deadline_cb=self._shim_deadline_cb,
            sequence_validator=self._shim_check_sequence,
        )
        try:
            buff = reader.read_message()
        except ProtocolBudgetError:
            self._force_close()
            raise
        packet = packet_type(buff, self.encoding)
        if packet.is_error_packet():
            if self._result is not None and self._result.unbuffered_active is True:
                self._result.unbuffered_active = False
            packet.raise_for_error()
        return packet

    def _shim_check_sequence(self, sequence: int) -> None:
        if sequence != self._next_seq_id:
            self._force_close()
            if sequence == 0:
                raise pymysql.err.OperationalError(
                    pymysql.constants.CR.CR_SERVER_LOST,
                    "Lost connection to MySQL server during query",
                )
            raise pymysql.err.InternalError(
                "Packet sequence number wrong - got %d expected %d"
                % (sequence, self._next_seq_id)
            )
        self._next_seq_id = (self._next_seq_id + 1) % 256

    def _read_query_result(self, unbuffered: bool = False):  # noqa: ANN201
        # Mirrors PyMySQL 1.1.2 Connection._read_query_result (connections.py:820)
        # but instantiates the column-budgeted result object.
        self._result = None
        result = _BoundedMySQLResult(self)
        if unbuffered:
            result.init_unbuffered_query()
        else:
            result.read()
        self._result = result
        if result.server_status is not None:
            self.server_status = result.server_status
        return result.affected_rows


@dataclass(frozen=True)
class StatementReceipt:
    """Receipt for one non-result statement; diagnostics were collected
    immediately after the statement, before any other SQL (design 6.4.3)."""

    sql: str
    affected_rows: Optional[int]
    server_status: Optional[int]
    warning_count: Optional[int]  # None when the terminating packet was ERR
    has_next: bool
    error: Optional[ErrPacketInfo]
    diagnostics: DiagnosticsRecord


@dataclass(frozen=True)
class QueryHandle:
    sql: str
    columns: Tuple[MappedColumn, ...]
    metas: Tuple[FieldMetadata, ...]
    cursor: object


class PyMySQLAdapter:
    """Adapter over the shim: connect, raw statement execution with
    diagnostics, bounded fetch, schema/readback query execution and
    close/cancel observation primitives.

    Session/SET/probe SQL, KILL-based cancellation and preflight belong to
    later D3 phases; ``init_command`` is never used and the driver-level
    autocommit stays off (session SQL is applied by explicit caller
    statements).
    """

    def __init__(
        self,
        params: ConnectionParams,
        *,
        charset: str,
        deadline_cb: Optional[Callable[[], None]] = None,
    ) -> None:
        if not isinstance(params, ConnectionParams):
            raise AdapterError("PyMySQLAdapter requires ConnectionParams")
        if not isinstance(charset, str) or not charset:
            raise AdapterError("charset must be a non-empty string")
        self._params = params
        self._charset = charset
        self._conn: Optional[_BoundedConnection] = None
        self._usable = False
        self._closed = False
        self._deadline_cb = deadline_cb
        self._driver_version: Optional[str] = None

    # -- lifecycle ---------------------------------------------------------

    def connect(self) -> str:
        """Connect and return the verified driver version (fail closed)."""

        if self._conn is not None:
            raise AdapterError("adapter is already connected")
        version = verify_driver_baseline()
        params = self._params
        kwargs: dict = {
            "user": params.user,
            "password": params.password,
            "charset": self._charset,
            "autocommit": False,  # driver level; session SQL is applied by the caller
            "conv": {},  # no driver-side conversion: values stay raw bytes
            "use_unicode": False,
            "connect_timeout": params.connect_timeout_s,
            "read_timeout": params.read_timeout_s,
            "write_timeout": params.write_timeout_s,
            # init_command is intentionally never set (design 6.4.5).
        }
        if params.unix_socket is not None:
            kwargs["unix_socket"] = params.unix_socket
        else:
            kwargs["host"] = params.host
            kwargs["port"] = params.port
        if params.tls_ca_file is not None:
            kwargs["ssl_ca"] = params.tls_ca_file
            kwargs["ssl_verify_cert"] = True
            kwargs["ssl_verify_identity"] = params.tls_verify_identity
        conn = _BoundedConnection(deadline_cb=self._deadline_cb, **kwargs)
        try:
            conn.connect()
        except BaseException:
            conn._force_close()
            raise
        self._conn = conn
        self._usable = True
        self._driver_version = version
        return version

    def set_deadline_callback(self, deadline_cb: Optional[Callable[[], None]]) -> None:
        self._deadline_cb = deadline_cb
        if self._conn is not None:
            self._conn._set_deadline_cb(deadline_cb)

    def _check_usable(self) -> _BoundedConnection:
        if self._closed or self._conn is None:
            raise AdapterError("adapter connection is closed")
        if not self._usable:
            raise AdapterError(
                "adapter connection is unusable after a budget/protocol violation; "
                "the control plane must terminate it (fail closed)"
            )
        return self._conn

    # -- design 6.3.2 operations owned by later phases ----------------------

    def connect_and_probe(self) -> dict:
        raise NotImplementedError(
            "connect_and_probe (server identity/session probes) belongs to a later D3 phase"
        )

    def apply_session(self, session_settings: dict) -> dict:
        raise NotImplementedError(
            "apply_session (session SET + readback) belongs to a later D3 phase"
        )

    def cancel_current(self) -> dict:
        raise NotImplementedError(
            "KILL-based cancellation is the Phase 3 control plane; closing this "
            "connection is not server-side termination evidence"
        )

    # -- raw statement execution with diagnostics ---------------------------

    def execute_statement(self, sql: str) -> StatementReceipt:
        """Execute one non-result statement and collect diagnostics
        immediately (terminating packet count first, then SHOW WARNINGS)."""

        conn = self._check_usable()
        if not isinstance(sql, str) or not sql:
            raise AdapterError("execute_statement requires non-empty SQL text")
        cursor = conn.cursor(pymysql.cursors.Cursor)
        error: Optional[ErrPacketInfo] = None
        warning_count: Optional[int] = None
        affected_rows: Optional[int] = None
        server_status: Optional[int] = None
        has_next = False
        try:
            cursor.execute(sql)
            result = cursor._result
            if cursor.description is not None:
                raise ResultContractViolation(
                    "statement returned a result set; use open_query for SELECT "
                    "(fail closed)"
                )
            affected_rows = result.affected_rows
            warning_count = result.warning_count
            server_status = result.server_status
            has_next = bool(result.has_next)
        except pymysql.err.MySQLError as exc:
            error = _error_from_exception(exc)
        diagnostics = self._collect_diagnostics(warning_count)
        return StatementReceipt(
            sql=sql,
            affected_rows=affected_rows,
            server_status=server_status,
            warning_count=warning_count,
            has_next=has_next,
            error=error,
            diagnostics=diagnostics,
        )

    def _collect_diagnostics(self, packet_warning_count: Optional[int]) -> DiagnosticsRecord:
        """SHOW WARNINGS immediately; never SELECT @@warning_count, never
        sql_notes=0, never GET DIAGNOSTICS (design 6.4.3 [R6])."""

        conn = self._conn
        try:
            cursor = conn.cursor(pymysql.cursors.Cursor)
            cursor.execute("SHOW WARNINGS")
            rows = cursor.fetchmany(MAX_DIAGNOSTIC_ENTRIES + 1)
        except pymysql.err.MySQLError:
            return DiagnosticsRecord.not_collected()
        return reconcile_diagnostics(packet_warning_count, rows)

    # -- bounded query execution --------------------------------------------

    def open_query(self, sql: str) -> QueryHandle:
        """Open an unbuffered (SSCursor) query; the column count is checked
        before field structures are allocated (via _BoundedMySQLResult)."""

        conn = self._check_usable()
        if not isinstance(sql, str) or not sql:
            raise AdapterError("open_query requires non-empty SQL text")
        cursor = conn.cursor(pymysql.cursors.SSCursor)
        cursor.execute(sql)
        fields = getattr(cursor._result, "fields", None)
        if fields is None:
            raise ResultContractViolation(
                "statement did not return a result set; use execute_statement "
                "(fail closed)"
            )
        metas = tuple(
            extract_field_metadata(field, ordinal)
            for ordinal, field in enumerate(fields)
        )
        columns = tuple(map_column(meta, meta.ordinal) for meta in metas)
        return QueryHandle(sql=sql, columns=columns, metas=metas, cursor=cursor)

    def fetch_result(
        self, handle: QueryHandle, *, row_budget: int, byte_budget: int
    ) -> BoundedFetchResult:
        """Bounded exact fetch; over-budget or truncated fetches mark the
        connection unusable and never drain remaining results."""

        self._check_usable()
        try:
            fetched = bounded_fetch(
                handle.cursor,
                handle.metas,
                row_budget=row_budget,
                byte_budget=byte_budget,
                deadline_cb=self._deadline_cb,
            )
        except (ResultEncodingError, ResultContractViolation, ProtocolBudgetError):
            # The prefix cannot be compared / the stream is not trustworthy:
            # stop, mark unusable, never drain.
            self._mark_unusable()
            raise
        if fetched.truncated:
            self._mark_unusable()
        if fetched.extra_result_sets >= 1:
            # Observing SERVER_MORE_RESULTS_EXISTS is enough to reject; extra
            # result sets are never consumed.
            self._mark_unusable()
            raise ResultContractViolation(
                "query announced extra result sets (SERVER_MORE_RESULTS_EXISTS); "
                "multi-result statements are rejected (fail closed)"
            )
        return fetched

    def execute_raw_query(
        self,
        sql: str,
        *,
        row_budget: int,
        byte_budget: int,
        database: Optional[str] = None,
    ) -> RawQueryResult:
        """Bounded raw byte fetch for schema/readback probes; SQL text is
        owned by the caller (facts layer), the adapter only executes it."""

        conn = self._check_usable()
        if not isinstance(sql, str) or not sql:
            raise AdapterError("execute_raw_query requires non-empty SQL text")
        cursor = conn.cursor(pymysql.cursors.SSCursor)
        cursor.execute(sql)
        fields = getattr(cursor._result, "fields", None)
        if fields is None:
            raise ResultContractViolation(
                "statement did not return a result set; use execute_statement "
                "(fail closed)"
            )
        metas = tuple(
            extract_field_metadata(field, ordinal)
            for ordinal, field in enumerate(fields)
        )
        result = bounded_fetch_raw(
            cursor,
            metas,
            row_budget=row_budget,
            byte_budget=byte_budget,
            deadline_cb=self._deadline_cb,
            database=database,
        )
        if result.truncated:
            self._mark_unusable()
        return result

    def inspect_schema(
        self,
        database: str,
        *,
        sql: str,
        row_budget: int = _execution.MAX_RESULT_ROWS,
        byte_budget: int = _execution.MAX_RESULT_BYTES,
    ) -> RawQueryResult:
        """Execute a caller-supplied information-schema probe against one
        database; the SQL text belongs to the facts layer, never the adapter."""

        if not isinstance(database, str) or not database:
            raise AdapterError("inspect_schema requires a non-empty database name")
        return self.execute_raw_query(
            sql,
            row_budget=row_budget,
            byte_budget=byte_budget,
            database=database,
        )

    # -- termination / observation -------------------------------------------

    def connection_id(self) -> int:
        """Observed server thread id of this session (an observation primitive
        for the later control plane; not a cancellation proof)."""

        conn = self._check_usable()
        return int(conn.thread_id)

    def _mark_unusable(self) -> None:
        """Mark the connection unusable after a budget/protocol violation.

        Never drains: no ``cursor.close()``/``nextset()``.  The unbuffered
        flag is cleared so garbage collection cannot silently drain the
        remaining rows in the background; physical close is left to
        :meth:`close` / the control plane.
        """

        self._usable = False
        conn = self._conn
        if conn is not None:
            result = conn._result
            if result is not None:
                result.unbuffered_active = False

    def close(self) -> None:
        """Close the connection (COM_QUIT + socket close; never reads or
        drains a pending result).  Idempotent."""

        if self._closed:
            return
        self._closed = True
        self._usable = False
        conn = self._conn
        if conn is None:
            return
        result = conn._result
        if result is not None:
            result.unbuffered_active = False
        try:
            conn.close()
        except pymysql.err.Error:
            conn._force_close()
        self._conn = None


def _error_from_exception(exc: "pymysql.err.MySQLError") -> ErrPacketInfo:
    """Map a driver exception to the packet-level error record.

    PyMySQL surfaces only ``errno`` and a message (its ERR parser drops
    SQLSTATE), so ``sqlstate`` stays None -- it is never reconstructed from
    the message text.
    """

    args = exc.args
    errno: Optional[int] = None
    message = ""
    if args:
        first = args[0]
        if isinstance(first, int) and not isinstance(first, bool):
            errno = first
        if len(args) > 1 and isinstance(args[1], str):
            message = args[1]
        elif isinstance(first, str):
            message = first
    if errno is None:
        raise ResultContractViolation(
            f"driver error without an errno: {exc!r} (fail closed)"
        )
    return ErrPacketInfo(errno=errno, sqlstate=None, message=message)
