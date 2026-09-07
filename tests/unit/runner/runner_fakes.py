"""Shared fakes for the runner unit tests.

Everything here is hand-written test infrastructure: the fake clock, fake
sleep, recording cleanup executor and the fake supervisor process double
never reuse production internals.  ``FakeProc`` speaks just enough of the
Popen surface (pid, stdin, stdout, poll/wait/terminate/kill) for
``WorkerSupervisor`` to drive it, and its stdio are plain byte buffers
without filenos so the IPC fallback read path is exercised.
"""

from __future__ import annotations

import io
from typing import Dict, Iterable, Set


class FakeClock:
    """Controllable monotonic clock (seconds)."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def fake_sleep(clock: FakeClock, step_s: float = 0.01):
    """Sleep double that advances the fake clock (never actually waits)."""

    def sleep(seconds: float) -> None:
        clock.advance(max(seconds, step_s))

    return sleep


class FakeReader:
    """Byte stream without fileno; ``close()`` makes later reads hit EOF."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self.closed_flag = False

    def feed(self, data: bytes) -> None:
        if self.closed_flag:
            raise AssertionError("feed after close")
        self._buffer.extend(data)

    def read(self, limit: int) -> bytes:
        if not self._buffer:
            return b""  # EOF for the fallback read path
        chunk = bytes(self._buffer[:limit])
        del self._buffer[:limit]
        return chunk

    def close(self) -> None:
        self.closed_flag = True


class FakeWriter:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self.closed_flag = False

    def write(self, data: bytes) -> int:
        if self.closed_flag:
            raise ValueError("write to closed stream")
        self.chunks.append(bytes(data))
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed_flag = True

    @property
    def data(self) -> bytes:
        return b"".join(self.chunks)


class FakeProc:
    """Popen double.  ``exit(status)`` makes it dead; until then it is
    alive and ignores terminate() unless ``die_on_terminate`` is set."""

    def __init__(self, stdout_data: bytes = b"") -> None:
        self.pid = 424242
        self.stdout = FakeReader()
        self.stdout.feed(stdout_data)
        self.stdin = FakeWriter()
        self.returncode: int | None = None
        self.terminated = 0
        self.killed = 0
        self.die_on_terminate = False

    # -- Popen surface ------------------------------------------------------

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        assert self.returncode is not None, "wait() on a live FakeProc"
        return self.returncode

    def terminate(self) -> None:
        self.terminated += 1
        if self.die_on_terminate and self.returncode is None:
            self.exit(-15)

    def kill(self) -> None:
        self.killed += 1
        if self.returncode is None:
            self.exit(-9)

    # -- test control -------------------------------------------------------

    def exit(self, status: int) -> None:
        self.returncode = status
        self.stdout.close()


class RecordingExecutor:
    """CleanupExecutor double: records DDL, emulates drops, can fail."""

    def __init__(
        self,
        present: Iterable[str] = (),
        fail_on_substrings: Iterable[str] = (),
        fail_times: int = 10**9,
    ) -> None:
        self.ddl: list[str] = []
        self.present: Set[str] = set(present)
        self.dropped_tables: Set[str] = set()
        self._fail_on = tuple(fail_on_substrings)
        self._remaining_failures = fail_times

    def execute_ddl(self, sql: str) -> None:
        self.ddl.append(sql)
        if self._remaining_failures > 0 and any(needle in sql for needle in self._fail_on):
            self._remaining_failures -= 1
            raise RuntimeError(f"executor failure injected on {sql!r}")
        if sql.startswith("DROP TABLE "):
            self.dropped_tables.add(sql)
        elif sql.startswith("DROP DATABASE "):
            name = sql[len("DROP DATABASE `") : -len("`")]
            self.present.discard(name)

    def is_database_present(self, name: str) -> bool:
        return name in self.present


def parse_envelopes(data: bytes) -> list[Dict]:
    """Parse newline-delimited canonical JSON envelopes (test-side helper)."""
    import json

    out = []
    for line in data.splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def encode_line(kind: str, payload: dict, seq: int, corr: int | None = None) -> bytes:
    """Build one canonical envelope line the way the transport would."""
    from mtsql_typecheck.runner.ipc import _encode_envelope

    return _encode_envelope(kind, payload, seq, corr)


def duplex_buffers() -> tuple[io.BytesIO, io.BytesIO]:
    """(reader, writer) byte-stream pair with no fileno."""
    return io.BytesIO(), io.BytesIO()
