"""Worker entry-point tests (design 6.3.2/6.4.6): handshake, handler
registry, control handling (SHUTDOWN/CANCEL/SIGTERM), error envelopes and
import purity.

In-process cases drive ``WorkerApp`` over byte buffers; the SIGTERM case
and the real HELLO/READY/PING/SHUTDOWN round trip use a real subprocess.
No MySQL, no adapters package, no sockets.
"""

from __future__ import annotations

import io
import os
import signal
import subprocess
import sys
import time

import pytest

from mtsql_typecheck.runner import ipc
from mtsql_typecheck.runner.ipc import IpcConnection, PeerClosed
from mtsql_typecheck.runner.worker import (
    EXIT_STATUS_CANCELLED,
    EXIT_STATUS_ERROR,
    EXIT_STATUS_OK,
    HELLO_ADAPTER_ID_PLACEHOLDER,
    WorkerApp,
    main,
)
from runner_fakes import encode_line, parse_envelopes


class GrowableBuffer:
    """A read/write byte stream with independent read and write cursors.

    ``io.BytesIO`` cannot serve as a worker stdin here: one shared pointer
    means each write after a read overwrites unread data.  This buffer
    appends writes and serves reads from a separate offset; reads past the
    written length return b"" (EOF), matching the ipc fallback path.
    """

    def __init__(self) -> None:
        self._data = bytearray()
        self._read_pos = 0

    def write(self, data: bytes) -> int:
        self._data.extend(data)
        return len(data)

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            data = bytes(self._data[self._read_pos:])
            self._read_pos = len(self._data)
            return data
        data = bytes(self._data[self._read_pos:self._read_pos + size])
        self._read_pos += len(data)
        return data

    def flush(self) -> None:
        pass

    def getvalue(self) -> bytes:
        return bytes(self._data)


class ParentView:
    """Test-side parent: writes requests into a buffer the worker reads as
    stdin and parses the worker's stdout envelopes."""

    def __init__(self) -> None:
        self.worker_in = GrowableBuffer()  # parent -> worker
        self.worker_out = io.BytesIO()     # worker -> parent
        self._sent = 0

    def feed_line(self, kind: str, payload: dict) -> None:
        self._sent += 1
        self.worker_in.write(encode_line(kind, payload, self._sent))

    def feed_raw(self, data: bytes) -> None:
        self.worker_in.write(data)

    def envelopes(self) -> list[dict]:
        return parse_envelopes(self.worker_out.getvalue())


def make_app(parent: ParentView, **kwargs) -> WorkerApp:
    return WorkerApp(stdin=parent.worker_in, stdout=parent.worker_out, **kwargs)


class TestHandlerRegistry:
    def test_ping_is_registered_by_default(self):
        app = WorkerApp()
        assert "PING" in app.capabilities

    def test_register_handler_and_dispatch(self):
        app = WorkerApp()
        app.register_handler("ECHO", lambda payload: {"echo": payload["x"]})
        assert "ECHO" in app.capabilities
        assert app._handlers["ECHO"]({"x": 1}) == {"echo": 1}

    def test_duplicate_registration_is_refused(self):
        app = WorkerApp()
        with pytest.raises(ipc.IpcError):
            app.register_handler("PING", lambda payload: {})

    def test_reserved_kinds_cannot_be_registered(self):
        app = WorkerApp()
        for kind in ("SHUTDOWN", "CANCEL"):
            with pytest.raises(ipc.IpcError):
                app.register_handler(kind, lambda payload: {})

    def test_bad_kind_shape_is_refused(self):
        app = WorkerApp()
        for kind in ("lower", "WITH SPACE", "", "A" * 40):
            with pytest.raises(ipc.IpcError):
                app.register_handler(kind, lambda payload: {})


class TestWorkerLoopInProcess:
    def test_handshake_ping_shutdown_round_trip(self):
        parent = ParentView()
        parent.feed_line("READY", {})
        parent.feed_line("PING", {})
        parent.feed_line("SHUTDOWN", {})
        status = make_app(parent).run()
        assert status == EXIT_STATUS_OK
        envelopes = parent.envelopes()
        assert [e["kind"] for e in envelopes] == ["HELLO", "RESULT", "EXITED"]
        hello = envelopes[0]
        assert hello["seq"] == 1
        assert hello["payload"]["adapter_id"] == HELLO_ADAPTER_ID_PLACEHOLDER
        assert hello["payload"]["pid"] == os.getpid()
        assert "PING" in hello["payload"]["capabilities"]
        # Replies carry the request's seq as the correlation id.
        assert envelopes[1]["corr"] == 2
        assert envelopes[1]["payload"] == {"pong": True}
        assert envelopes[2]["corr"] == 3
        assert envelopes[2]["payload"] == {"status": EXIT_STATUS_OK}

    def test_unknown_command_gets_error_and_loop_continues(self):
        parent = ParentView()
        parent.feed_line("READY", {})
        parent.feed_line("FUTURE_KIND", {})
        parent.feed_line("SHUTDOWN", {})
        status = make_app(parent).run()
        assert status == EXIT_STATUS_OK
        envelopes = parent.envelopes()
        assert [e["kind"] for e in envelopes] == ["HELLO", "ERROR", "EXITED"]
        assert "FUTURE_KIND" in envelopes[1]["payload"]["message"]

    def test_handler_exception_emits_error_and_exits_nonzero(self):
        parent = ParentView()

        def boom(payload: dict) -> dict:
            raise RuntimeError("handler exploded")

        app = make_app(parent)
        app.register_handler("BOOM", boom)
        parent.feed_line("READY", {})
        parent.feed_line("BOOM", {})
        status = app.run()
        assert status == EXIT_STATUS_ERROR
        envelopes = parent.envelopes()
        assert [e["kind"] for e in envelopes] == ["HELLO", "ERROR"]
        assert "handler exploded" in envelopes[1]["payload"]["message"]

    def test_cancel_message_aborts_with_status_130(self):
        parent = ParentView()
        parent.feed_line("READY", {})
        parent.feed_line("CANCEL", {"reason": "user"})
        parent.feed_line("PING", {})  # must never be served after cancel
        status = make_app(parent).run()
        assert status == EXIT_STATUS_CANCELLED
        envelopes = parent.envelopes()
        assert [e["kind"] for e in envelopes] == ["HELLO", "RESULT", "ERROR"]
        assert envelopes[1]["payload"] == {"cancelled": True}
        assert envelopes[2]["payload"]["code"] == "CANCELLED"

    def test_seq_violation_from_parent_stops_the_worker(self):
        parent = ParentView()
        parent.feed_line("READY", {})
        # A line repeating seq 1 breaks the parent->worker seq discipline.
        parent.feed_raw(b'{"kind":"READY","payload":{},"seq":1,"v":1}\n')
        status = make_app(parent).run()
        assert status == EXIT_STATUS_ERROR
        envelopes = parent.envelopes()
        assert envelopes[-1]["kind"] == "ERROR"

    def test_truncated_line_from_parent_is_rejected(self):
        parent = ParentView()
        parent.feed_line("READY", {})
        parent.feed_raw(b'{"kind":"PING"')  # truncated, then EOF
        status = make_app(parent).run()
        assert status == EXIT_STATUS_ERROR
        assert parent.envelopes()[-1]["kind"] == "ERROR"


class TestWorkerSubprocess:
    def _spawn(self) -> subprocess.Popen:
        return subprocess.Popen(
            [sys.executable, "-m", "mtsql_typecheck.runner.worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_real_worker_ping_shutdown_exit_zero(self):
        proc = self._spawn()
        try:
            conn = IpcConnection(proc.stdout, proc.stdin, name="worker-under-test")
            hello = conn.recv()
            assert hello.kind == "HELLO"
            assert hello.payload["pid"] == proc.pid
            conn.send("READY", {})
            reply = conn.request("PING", {}, None)
            assert reply.kind == "RESULT" and reply.payload == {"pong": True}
            exited = conn.request(
                "SHUTDOWN", {}, None, reply_kinds=frozenset({"EXITED"})
            )
            assert exited.kind == "EXITED"
            assert exited.payload == {"status": EXIT_STATUS_OK}
            conn.close()
        finally:
            status = proc.wait(timeout=10)
        assert status == EXIT_STATUS_OK

    def test_sigterm_produces_cancelled_error_and_status_130(self):
        proc = self._spawn()
        try:
            conn = IpcConnection(proc.stdout, proc.stdin, name="worker-under-test")
            assert conn.recv().kind == "HELLO"
            conn.send("READY", {})
            conn.send("PING", {})
            os.kill(proc.pid, signal.SIGTERM)
            envelopes = []
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    envelope = conn.recv()
                except PeerClosed:
                    break
                envelopes.append(envelope)
                if envelope.kind == "ERROR":
                    break
            assert envelopes, "worker must answer cancellation with an envelope"
            assert envelopes[-1].kind == "ERROR"
            assert envelopes[-1].payload["code"] == "CANCELLED"
            conn.close()
        finally:
            status = proc.wait(timeout=10)
        assert status == EXIT_STATUS_CANCELLED

    def test_import_is_driver_and_adapter_free(self):
        code = (
            "import sys; import mtsql_typecheck.runner.worker as w;"
            " assert 'pymysql' not in sys.modules;"
            " assert not any(m.startswith('mtsql_typecheck.adapters') for m in sys.modules);"
            " print(w.HELLO_ADAPTER_ID_PLACEHOLDER)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == HELLO_ADAPTER_ID_PLACEHOLDER


class TestMainEntry:
    def test_main_rejects_arguments(self, capsys):
        assert main(["--bogus"]) == 2
