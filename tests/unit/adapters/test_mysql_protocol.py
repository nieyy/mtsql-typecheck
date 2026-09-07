"""Bounded packet reading, field metadata extraction and driver gating.

All inputs are SYNTHETIC byte streams (tests/contract/fixtures/mysql112/);
no test here opens a network connection.
"""

from __future__ import annotations

import importlib
import socket
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest

import pymysql

import mtsql_typecheck.adapters as adapters_pkg
from mtsql_typecheck.adapters import mysql_protocol as mp
from mtsql_typecheck.adapters.base import (
    RESULT_CONTRACT_VIOLATION,
    AdapterError,
    ProtocolBudgetError,
    ResultContractViolation,
)

from _helpers import frame, load_fixture, read_message_bytes

# --------------------------------------------------------------------------
# Bounded packet reader
# --------------------------------------------------------------------------


def _frame_header(length: int, sequence: int) -> bytes:
    return struct.pack("<I", length)[:3] + bytes([sequence])


def test_reader_single_frame_roundtrip():
    payload = b"\x00\x00\x00\x02\x00\x05\x00"
    stream = frame(1, payload)
    offset = 0

    def read_exactly(count):
        nonlocal offset
        chunk = stream[offset : offset + count]
        offset += count
        return chunk

    assert mp.BoundedPacketReader(read_exactly).read_message() == payload


def test_reader_two_fragments_reassemble_under_cap():
    payload = b"0123456789ABCDEFGHIJ"
    stream = frame(0, payload[:12]) + frame(1, payload[12:])
    offset = 0

    def read_exactly(count):
        nonlocal offset
        chunk = stream[offset : offset + count]
        offset += count
        return chunk

    deadlines = []
    # First frame is exactly 12 bytes: with continuation_threshold=12 it
    # signals continuation so the second frame reassembles.
    assert (
        mp.BoundedPacketReader(
            read_exactly,
            deadline_cb=lambda: deadlines.append(1),
            continuation_threshold=12,
        ).read_message()
        == payload
    )
    assert offset == len(stream)
    assert len(deadlines) == 2, "deadline callback must run before each frame"


def test_reader_cumulative_cap_crosses_before_body_read():
    # Two 16 MiB - 1 continuation frames: the cumulative total crosses the
    # 16 MiB cap; the reader must refuse BEFORE reading the second body.
    calls: list[int] = []
    headers = [_frame_header(0xFFFFFF, 0), _frame_header(0xFFFFFF, 1)]

    def read_exactly(count):
        calls.append(count)
        if count == 4:
            return headers.pop(0)
        if count == 0xFFFFFF:
            if calls.count(0xFFFFFF) >= 2:
                raise AssertionError("second 16 MiB body allocated despite the cap")
            return b"\x00" * count
        raise AssertionError(f"unexpected read of {count} bytes")

    with pytest.raises(ProtocolBudgetError):
        mp.BoundedPacketReader(read_exactly).read_message()
    assert calls[-1] == 4, "the refused frame body must never be requested"


def test_reader_small_cap_boundary_exact_fit_allowed():
    payload = b"x" * 64
    stream = frame(0, payload[:40]) + frame(1, payload[40:])
    offset = 0

    def read_exactly(count):
        nonlocal offset
        chunk = stream[offset : offset + count]
        offset += count
        return chunk

    # 40 + 24 == 64 == cap: exactly at the cap is allowed, not a violation.
    assert (
        mp.BoundedPacketReader(
            read_exactly, message_cap=64, continuation_threshold=40
        ).read_message()
        == payload
    )


def test_reader_small_cap_boundary_crossing_refused():
    stream = frame(0, b"x" * 40) + frame(1, b"y" * 40)
    headers = [_frame_header(40, 0), _frame_header(40, 1)]
    body_reads: list[int] = []
    reads = {"n": 0}

    def read_exactly(count):
        if count == 4:
            reads["n"] += 1
            return headers[reads["n"] - 1]
        body_reads.append(count)
        return stream[:count]

    with pytest.raises(ProtocolBudgetError):
        mp.BoundedPacketReader(
            read_exactly, message_cap=64, continuation_threshold=40
        ).read_message()
    assert body_reads == [40], "only the first (legal) frame body may be read"


def test_reader_malformed_truncated_header_fails_closed():
    def read_exactly(count):
        raise ValueError("stream ended inside the 4-byte header")

    with pytest.raises(ValueError):
        mp.BoundedPacketReader(read_exactly).read_message()


def test_reader_truncated_body_fails_closed():
    stream = frame(0, b"abc")[:-1]  # one byte short of the declared body
    offset = 0

    def read_exactly(count):
        nonlocal offset
        chunk = stream[offset : offset + count]
        offset += len(chunk)
        return chunk

    with pytest.raises(ResultContractViolation):
        mp.BoundedPacketReader(read_exactly).read_message()


def test_reader_sequence_gap_fails_closed():
    stream = frame(0, b"a" * 5) + frame(5, b"b" * 5)
    offset = 0

    def read_exactly(count):
        nonlocal offset
        chunk = stream[offset : offset + count]
        offset += count
        return chunk

    with pytest.raises(ResultContractViolation) as excinfo:
        mp.BoundedPacketReader(
            read_exactly, continuation_threshold=5
        ).read_message()
    assert excinfo.value.code == RESULT_CONTRACT_VIOLATION


def test_fixture_message_two_fragments_under_cap():
    stream, doc = load_fixture("message_two_fragments")
    # Synthetic small-frame continuation: the threshold is declared in the
    # fixture so the test seam matches the documented stream layout.
    threshold = doc["continuation_threshold"]
    payload = read_message_bytes(stream, continuation_threshold=threshold)
    assert payload.hex() == doc["payload_hex"]
    assert len(payload) == doc["expected"]["message_bytes"]
    assert [f["payload_length"] for f in doc["frames"]] == [12, 10]
    assert [f["sequence"] for f in doc["frames"]] == [0, 1]


# --------------------------------------------------------------------------
# Field metadata extraction (design 6.4.3)
# --------------------------------------------------------------------------


def test_field_metadata_from_synthetic_newdecimal_fixture():
    stream, doc = load_fixture("field_newdecimal")
    payload = read_message_bytes(stream)
    packet = pymysql.protocol.FieldDescriptorPacket(payload, "utf8")
    meta = mp.extract_field_metadata(packet, 0)
    expected = doc["expected"]
    assert meta.ordinal == expected["ordinal"]
    assert meta.type_code == expected["type_code"]
    assert meta.flags == expected["flags"]
    assert meta.decimals == expected["decimals"]
    assert meta.length == expected["length"]
    assert meta.charset == expected["charset"]
    assert meta.alias == expected["alias"]
    assert meta.table_alias == expected["table_alias"]


def test_field_metadata_missing_attribute_fails_closed():
    packet = SimpleNamespace(
        name="v", table_name="t", charsetnr=63, length=6, type_code=246, flags=0
    )  # no "scale"
    with pytest.raises(ResultContractViolation):
        mp.extract_field_metadata(packet, 0)


def test_field_metadata_wrong_attribute_type_fails_closed():
    packet = SimpleNamespace(
        name="v",
        table_name="t",
        charsetnr=63,
        length=6,
        type_code="246",  # wrong type
        flags=0,
        scale=2,
    )
    with pytest.raises(ResultContractViolation):
        mp.extract_field_metadata(packet, 0)


def test_field_metadata_non_string_name_fails_closed():
    packet = SimpleNamespace(
        name=b"v", table_name="t", charsetnr=63, length=6, type_code=246, flags=0, scale=2
    )
    with pytest.raises(ResultContractViolation):
        mp.extract_field_metadata(packet, 0)


# --------------------------------------------------------------------------
# Driver baseline gate (fail closed; metadata version, not pymysql.__version__)
# --------------------------------------------------------------------------


def test_verify_driver_baseline_accepts_certified_version():
    assert mp.verify_driver_baseline() == "1.1.2"


def test_verify_driver_baseline_ignores_dunder_version_attribute(monkeypatch):
    # The installed code's pymysql.__version__ disagrees with its own package
    # metadata; the gate must consult metadata only.
    monkeypatch.setattr(pymysql, "__version__", "9.9.9-not-real")
    assert mp.verify_driver_baseline() == "1.1.2"


def test_verify_driver_baseline_rejects_other_version(monkeypatch):
    monkeypatch.setattr(
        mp.importlib.metadata, "version", lambda name: "1.1.3"
    )
    with pytest.raises(AdapterError):
        mp.verify_driver_baseline()


def test_verify_driver_baseline_rejects_missing_metadata(monkeypatch):
    def boom(name):
        raise mp.importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(mp.importlib.metadata, "version", boom)
    with pytest.raises(AdapterError):
        mp.verify_driver_baseline()


def test_verify_driver_baseline_rejects_missing_internals(monkeypatch):
    monkeypatch.setattr(mp.pymysql.protocol, "OKPacketWrapper", None)
    with pytest.raises(AdapterError):
        mp.verify_driver_baseline()


def test_verify_driver_baseline_rejects_changed_field_type_code(monkeypatch):
    monkeypatch.setattr(mp.pymysql.constants.FIELD_TYPE, "NEWDECIMAL", 999)
    with pytest.raises(AdapterError):
        mp.verify_driver_baseline()


# --------------------------------------------------------------------------
# Column-count budget (design 6.4.4: checked before field allocation)
# --------------------------------------------------------------------------


def test_bounded_result_refuses_wide_results_before_field_allocation():
    result = mp._BoundedMySQLResult(None)
    result.field_count = 6  # > MAX_RESULT_COLUMNS (5)
    with pytest.raises(ProtocolBudgetError):
        result._get_descriptions()


def test_bounded_result_refuses_unusable_field_count():
    result = mp._BoundedMySQLResult(None)
    result.field_count = None
    with pytest.raises(ResultContractViolation):
        result._get_descriptions()


# --------------------------------------------------------------------------
# Network hygiene: imports and pure parsers must perform zero connections
# --------------------------------------------------------------------------


def _block_sockets(monkeypatch) -> None:
    def _boom(*args, **kwargs):
        raise AssertionError("network attempted during an offline test")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket, "socketpair", _boom)


def test_adapters_import_and_pure_parsers_open_no_socket(monkeypatch):
    _block_sockets(monkeypatch)
    importlib.reload(adapters_pkg)  # package import must stay connection-free

    stream, _doc = load_fixture("ok_warning_count")
    payload = read_message_bytes(stream)
    assert mp.parse_ok_packet(payload).warning_count == 5
    assert mp.classify_terminator(payload) == "ok"
    err_payload = read_message_bytes(load_fixture("err_sqlstate")[0])
    assert mp.parse_err_packet(err_payload).errno == 1049


def test_offline_packages_never_import_driver_or_adapters():
    code = (
        "import sys\n"
        "import mtsql_typecheck.generation\n"
        "import mtsql_typecheck.contracts\n"
        "import mtsql_typecheck.oracle\n"
        "import mtsql_typecheck.reduction\n"
        "assert 'pymysql' not in sys.modules, 'pymysql imported by offline modules'\n"
        "assert not any(\n"
        "    m == 'mtsql_typecheck.adapters' or m.startswith('mtsql_typecheck.adapters.')\n"
        "    for m in sys.modules\n"
        "), 'adapters imported by offline modules'\n"
        "print('ok')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().endswith("ok")


def test_adapters_package_import_does_not_import_pymysql():
    code = (
        "import sys\n"
        "import mtsql_typecheck.adapters\n"
        "assert 'pymysql' not in sys.modules, 'package import pulled the driver'\n"
        "print('ok')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().endswith("ok")


def test_mysql_protocol_import_opens_no_socket(monkeypatch):
    _block_sockets(monkeypatch)
    import mtsql_typecheck.adapters.mysql_protocol  # noqa: F401  (fresh import ok)


# --------------------------------------------------------------------------
# Bounded fetch over an unbuffered cursor (design 6.4.4; negative P04)
# --------------------------------------------------------------------------


class FakeResult:
    def __init__(self, warning_count: int = 7, has_next: int = 0) -> None:
        self.warning_count = warning_count
        self.has_next = has_next


class FakeUnbufferedCursor:
    """SSCursor stand-in: read_next() yields scripted rows then None.

    close()/nextset() are recorded and must never be called by the shim
    (calling them drains further results)."""

    def __init__(self, rows: list, result: FakeResult) -> None:
        self._rows = list(rows)
        self._result = result
        self.close_calls = 0
        self.nextset_calls = 0

    def read_next(self):
        if not self._rows:
            return None
        return self._rows.pop(0)

    def close(self):
        self.close_calls += 1

    def nextset(self):
        self.nextset_calls += 1


_INT_META = mp.FieldMetadata(
    ordinal=0, type_code=1, flags=0, decimals=0, length=4, charset=63, alias="v", table_alias="t"
)


def _meta_int_row(text: bytes):
    return (text,)


def test_bounded_fetch_completes_at_exact_row_limit():
    # Exactly at the row limit the shim must confirm the next read is EOF
    # before declaring the fetch complete.
    rows = [(_int_text,) for _int_text in (b"1", b"2", b"3", b"4")]
    cursor = FakeUnbufferedCursor(rows, FakeResult(warning_count=7))
    fetched = mp.bounded_fetch(cursor, (_INT_META,), row_budget=4, byte_budget=1 << 20)
    assert fetched.observed_row_count == 4
    assert fetched.fetch_complete is True
    assert fetched.truncated is False
    assert fetched.warning_count == 7  # final terminator count, not column-EOF
    assert cursor.close_calls == 0 and cursor.nextset_calls == 0


def test_bounded_fetch_row_limit_with_extra_row_is_truncated():
    rows = [(text,) for text in (b"1", b"2", b"3", b"4", b"5")]
    cursor = FakeUnbufferedCursor(rows, FakeResult(warning_count=7))
    fetched = mp.bounded_fetch(cursor, (_INT_META,), row_budget=4, byte_budget=1 << 20)
    assert fetched.observed_row_count == 4
    assert fetched.fetch_complete is False
    assert fetched.truncated is True
    assert cursor.close_calls == 0 and cursor.nextset_calls == 0


def _canonical_row_bytes(text: bytes) -> int:
    from mtsql_typecheck.contracts.codec import canonical_json
    from mtsql_typecheck.contracts.execution import ResultValue, ResultValueKind

    return len(
        canonical_json(
            [ResultValue(ResultValueKind.INTEGER, int_value=int(text)).to_obj()]
        )
    )


def test_bounded_fetch_byte_limit_crossed_is_truncated():
    # The byte budget allows exactly two kept rows; the third row would cross
    # it and a later row exists, so the confirm read proves truncation.
    rows = [(text,) for text in (b"1111", b"2222", b"3333", b"4444")]
    per_row = _canonical_row_bytes(b"1111")
    cursor = FakeUnbufferedCursor(rows, FakeResult(warning_count=7))
    fetched = mp.bounded_fetch(
        cursor, (_INT_META,), row_budget=100, byte_budget=per_row * 2 + per_row // 2
    )
    assert fetched.observed_row_count == 2
    assert fetched.truncated is True
    assert fetched.fetch_complete is False


def test_bounded_fetch_byte_limit_exactly_reached_confirms_eof():
    # Two rows fit the byte budget exactly; EOF follows, so the fetch is
    # complete (not truncated).
    rows = [(text,) for text in (b"1111", b"2222")]
    per_row = _canonical_row_bytes(b"1111")
    cursor = FakeUnbufferedCursor(rows, FakeResult(warning_count=2))
    fetched = mp.bounded_fetch(
        cursor, (_INT_META,), row_budget=100, byte_budget=per_row * 2
    )
    assert fetched.observed_row_count == 2
    assert fetched.truncated is False
    assert fetched.fetch_complete is True
    assert fetched.encoded_bytes == per_row * 2


def test_bounded_fetch_detects_extra_result_sets_without_consuming():
    rows = [(b"1",), (b"2",)]
    cursor = FakeUnbufferedCursor(rows, FakeResult(warning_count=0, has_next=8))
    fetched = mp.bounded_fetch(cursor, (_INT_META,), row_budget=10, byte_budget=1 << 20)
    assert fetched.extra_result_sets == 1
    assert fetched.fetch_complete is True


def test_bounded_fetch_rejects_budget_out_of_contract():
    cursor = FakeUnbufferedCursor([], FakeResult())
    with pytest.raises(ProtocolBudgetError):
        mp.bounded_fetch(cursor, (_INT_META,), row_budget=0, byte_budget=1 << 20)
    with pytest.raises(ProtocolBudgetError):
        mp.bounded_fetch(
            cursor, (_INT_META,), row_budget=10, byte_budget=mp.PACKET_BUDGET_BYTES * 8
        )


def test_bounded_fetch_rejects_wide_results():
    metas = tuple(
        mp.FieldMetadata(
            ordinal=i, type_code=1, flags=0, decimals=0, length=4, charset=63,
            alias=f"c{i}", table_alias="t",
        )
        for i in range(6)
    )
    cursor = FakeUnbufferedCursor([], FakeResult())
    with pytest.raises(ProtocolBudgetError):
        mp.bounded_fetch(cursor, metas, row_budget=10, byte_budget=1 << 20)


def test_bounded_fetch_row_width_mismatch_fails_closed():
    cursor = FakeUnbufferedCursor([(b"1", b"2")], FakeResult())
    with pytest.raises(ResultContractViolation):
        mp.bounded_fetch(cursor, (_INT_META,), row_budget=10, byte_budget=1 << 20)
