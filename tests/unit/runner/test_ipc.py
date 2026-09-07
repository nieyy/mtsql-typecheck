"""IPC framing tests (design 6.4.6): canonical JSON lines, seq discipline,
oversize/bad-seq/unknown-kind/truncation/peer-close negatives, deadline and
cancel enforcement, and request/response correlation.

Transport pairs are built from real os.pipe fds (the select-based read path)
and from fileno-less byte streams (the fallback read path).
"""

from __future__ import annotations

import os
import time

import pytest

from mtsql_typecheck.contracts.execution import Control, ControlCancelled
from mtsql_typecheck.runner.ipc import (
    Envelope,
    IpcConnection,
    IpcError,
    IpcTimeout,
    PeerClosed,
    ProtocolViolation,
    decode_envelope,
    validate_payload,
)


class _PipePair:
    """Two os.pipe crossings wrapped as IpcConnections with real filenos."""

    def __init__(self) -> None:
        a_read_fd, b_write_fd = os.pipe()  # B writes -> A reads
        b_read_fd, a_write_fd = os.pipe()  # A writes -> B reads
        self.a = IpcConnection(
            os.fdopen(a_read_fd, "rb"), os.fdopen(a_write_fd, "wb"), name="A"
        )
        self.b = IpcConnection(
            os.fdopen(b_read_fd, "rb"), os.fdopen(b_write_fd, "wb"), name="B"
        )

    def close(self) -> None:
        self.a.close()
        self.b.close()


def _unbounded() -> Control:
    return Control(clock=time.monotonic, deadline=None, cancelled=lambda: False)


@pytest.fixture
def pair():
    pair = _PipePair()
    yield pair
    pair.close()


class TestFraming:
    def test_round_trip_preserves_envelope_fields(self, pair):
        pair.a.send("HELLO", {"pid": 7, "adapter_id": "x", "capabilities": []})
        envelope = pair.b.recv()
        assert isinstance(envelope, Envelope)
        assert envelope.v == 1
        assert envelope.kind == "HELLO"
        assert envelope.seq == 1
        assert envelope.payload == {"pid": 7, "adapter_id": "x", "capabilities": []}
        assert envelope.corr is None

    def test_strict_seq_per_direction(self, pair):
        assert pair.a.send("PING", {}) == 1
        assert pair.a.send("PING", {}) == 2
        assert pair.b.send("LOG", {"text": "hi"}) == 1  # independent direction
        assert pair.b.recv(control=_unbounded()).seq == 1
        assert pair.b.recv(control=_unbounded()).seq == 2
        assert pair.a.recv(control=_unbounded()).seq == 1

    def test_bad_seq_is_a_protocol_violation(self, pair):
        # Write a first message with seq 2 directly (skipping 1).
        pair.b._writer.write(
            b'{"kind":"PING","payload":{},"seq":2,"v":1}\n'
        )
        pair.b._writer.flush()
        with pytest.raises(ProtocolViolation):
            pair.a.recv()

    def test_repeated_seq_is_a_protocol_violation(self, pair):
        pair.a.send("PING", {})
        pair.a.send("PING", {})
        assert pair.b.recv().seq == 1
        assert pair.b.recv().seq == 2  # drain the buffer before the forgery
        # A line carrying seq 1 again repeats the direction's history.
        pair.a._writer.write(b'{"kind":"PING","payload":{},"seq":1,"v":1}\n')
        pair.a._writer.flush()
        with pytest.raises(ProtocolViolation):
            pair.b.recv()

    def test_oversize_incoming_line_is_rejected(self, pair):
        small = IpcConnection(
            pair.b._reader, pair.b._writer, name="A-small", max_message_bytes=64
        )
        # Shape-valid (<= 2048 chars) but over the 64-byte connection budget.
        pair.a.send("LOG", {"text": "x" * 100})
        with pytest.raises(ProtocolViolation):
            small.recv()
        small.close()

    def test_oversize_outgoing_is_refused_before_send(self, pair):
        # Shape-valid payload (<= 2048 chars) but line over the connection
        # budget: refused before any byte is written or seq consumed.
        small = IpcConnection(
            pair.b._reader, pair.b._writer, name="A-small", max_message_bytes=64
        )
        with pytest.raises(IpcError):
            small.send("LOG", {"text": "x" * 100})
        assert small.send("PING", {}) == 1  # seq untouched by the refusal
        small.close()

    def test_truncated_line_at_peer_close_is_a_violation(self, pair):
        pair.a._writer.write(b'{"kind":"PING","payl')
        pair.a._writer.flush()
        pair.a.close()
        with pytest.raises(ProtocolViolation):
            pair.b.recv()

    def test_clean_peer_close_raises_peer_closed(self, pair):
        pair.a.close()
        with pytest.raises(PeerClosed):
            pair.b.recv()

    def test_non_json_line_is_a_protocol_violation(self, pair):
        pair.a._writer.write(b"not json\n")
        pair.a._writer.flush()
        with pytest.raises(ProtocolViolation):
            pair.b.recv()

    def test_float_and_duplicate_keys_are_rejected(self, pair):
        pair.a._writer.write(b'{"kind":"PING","payload":{},"seq":1,"v":1.5}\n')
        pair.a._writer.flush()
        with pytest.raises(ProtocolViolation):
            pair.b.recv()
        pair.a._writer.write(b'{"kind":"PING","payload":{},"seq":1,"seq":1,"v":1}\n')
        pair.a._writer.flush()
        with pytest.raises(ProtocolViolation):
            pair.b.recv()


class TestKinds:
    def test_known_kind_payload_shapes_are_validated(self, pair):
        with pytest.raises(ProtocolViolation):
            pair.a.send("LOG", {"text": "ok", "extra": 1})
        with pytest.raises(ProtocolViolation):
            pair.a.send("EXITED", {"status": 99999})
        with pytest.raises(ProtocolViolation):
            pair.a.send("HELLO", {"pid": 7})  # missing fields
        # Nothing was sent: the seq must still be 1 for the next message.
        assert pair.a.send("PING", {}) == 1

    def test_decode_envelope_validates_known_shapes(self):
        good = decode_envelope(
            b'{"kind":"EXITED","payload":{"status":0},"seq":1,"v":1}'
        )
        assert good.kind == "EXITED"
        with pytest.raises(ProtocolViolation):
            decode_envelope(b'{"kind":"EXITED","payload":{"status":"0"},"seq":1,"v":1}')

    def test_unknown_kind_is_transport_open_but_dispatch_strict(self):
        # The transport keeps the kind vocabulary open for later phases...
        envelope = decode_envelope(b'{"kind":"FUTURE_KIND","payload":{},"seq":1,"v":1}')
        assert envelope.kind == "FUTURE_KIND"
        # ...while the strict validator rejects unknown kinds for dispatchers.
        with pytest.raises(ProtocolViolation):
            validate_payload("NOT_A_KIND_EITHER", {})

    def test_envelope_rejects_unknown_fields_and_wrong_version(self):
        with pytest.raises(ProtocolViolation):
            decode_envelope(b'{"kind":"PING","payload":{},"seq":1,"v":2}')
        with pytest.raises(ProtocolViolation):
            decode_envelope(b'{"kind":"PING","payload":{},"seq":1,"v":1,"junk":1}')
        with pytest.raises(ProtocolViolation):
            decode_envelope(b'{"kind":"ping","payload":{},"seq":1,"v":1}')


class TestDeadlines:
    def test_recv_deadline_expiry_raises_ipc_timeout(self, pair):
        control = Control(clock=time.monotonic, deadline=time.monotonic() + 0.05, cancelled=lambda: False)
        with pytest.raises(IpcTimeout):
            pair.b.recv(control)

    def test_recv_cancel_is_honoured(self, pair):
        control = Control(clock=time.monotonic, deadline=None, cancelled=lambda: True)
        with pytest.raises(ControlCancelled):
            pair.b.recv(control)

    def test_recv_returns_once_data_arrives(self, pair):
        pair.a.send("PING", {})
        envelope = pair.b.recv(Control(clock=time.monotonic, deadline=time.monotonic() + 5.0, cancelled=lambda: False))
        assert envelope.kind == "PING"


class TestCorrelation:
    def test_request_matches_correlated_reply(self, pair):
        # The peer reply references the request's seq (known to be 1 here)
        # and is queued on A's stream before A issues its request.
        pair.b.send("RESULT", {"done": True}, corr=1)
        reply = pair.a.request("EXEC", {"x": 1}, None)
        assert reply.kind == "RESULT" and reply.corr == 1 and reply.payload == {"done": True}

    def test_request_accepts_error_replies(self, pair):
        pair.b.send("ERROR", {"message": "no adapter"}, corr=1)
        reply = pair.a.request("EXEC", {}, None)
        assert reply.kind == "ERROR"

    def test_unrelated_messages_are_deferred_not_dropped(self, pair):
        pair.b.send("LOG", {"text": "noise"})  # no corr
        pair.b.send("RESULT", {"ok": 1}, corr=1)
        reply = pair.a.request("EXEC", {}, None)
        assert reply.kind == "RESULT"
        noise = pair.a.recv()
        assert noise.kind == "LOG" and noise.payload == {"text": "noise"}


class TestFallbackPath:
    def test_filenoless_streams_round_trip(self):
        import io

        reader, writer = io.BytesIO(), io.BytesIO()
        conn = IpcConnection(reader, writer, name="buf")
        conn.send("PING", {})
        # Feed the encoded line back through a fresh reader.
        reader2 = io.BytesIO(writer.getvalue())
        conn2 = IpcConnection(reader2, io.BytesIO(), name="buf2")
        envelope = conn2.recv()
        assert envelope.kind == "PING" and envelope.seq == 1
