"""Shared helpers for the adapters unit tests (no fixtures from real servers)."""

from __future__ import annotations

import json
import struct
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "contract" / "fixtures" / "mysql112"


def frame(sequence: int, payload: bytes) -> bytes:
    """Build one MySQL frame: 3-byte LE payload length + sequence + payload."""

    return struct.pack("<I", len(payload))[:3] + bytes([sequence]) + payload


def load_fixture(name: str) -> tuple[bytes, dict]:
    """Load a synthetic golden fixture pair from tests/contract/fixtures/mysql112."""

    stream = (FIXTURE_DIR / f"{name}.bin").read_bytes()
    doc = json.loads((FIXTURE_DIR / f"{name}.json").read_text())
    return stream, doc


def read_message_bytes(
    stream: bytes, *, continuation_threshold: int | None = None
):
    """Feed a raw byte stream (with framing) through the bounded reader.

    The real protocol continues a message only after a 16 MiB - 1 frame.
    Synthetic fixtures use small continuation frames, so the continuation
    threshold is injectable here (the connection-level reader keeps the real
    default); the threshold is declared in the fixture JSON when used."""

    from mtsql_typecheck.adapters.mysql_protocol import BoundedPacketReader

    offset = 0

    def read_exactly(count: int) -> bytes:
        nonlocal offset
        if count < 0 or offset + count > len(stream):
            raise ValueError(f"stream exhausted: requested {count} bytes at {offset}")
        chunk = stream[offset : offset + count]
        offset += count
        return chunk

    kwargs = {} if continuation_threshold is None else {
        "continuation_threshold": continuation_threshold
    }
    payload = BoundedPacketReader(read_exactly, **kwargs).read_message()
    assert offset == len(stream), "reader did not consume the full fixture stream"
    return payload
