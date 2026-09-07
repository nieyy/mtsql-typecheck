"""Supervisor tests (design 6.4.5/6.4.6; negative matrix C02/C04).

Happy path and SIGTERM escalation run against real worker processes; the
startup deadline, crash-mid-command and every escalation rung are driven
with the FakeProc double plus a fake clock, so no test waits on the 5s
budget.  One real child ignores SIGTERM to exercise the actual signal path.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time

import pytest

from mtsql_typecheck.runner.ipc import PeerClosed
from mtsql_typecheck.runner.supervisor import (
    EscalationLevel,
    StartupTimeout,
    SupervisorError,
    WorkerDied,
    WorkerSupervisor,
    default_child_env,
)
from runner_fakes import FakeClock, FakeProc, fake_sleep


def hello_bytes(pid: int = 424242) -> bytes:
    return json.dumps(
        {
            "v": 1,
            "kind": "HELLO",
            "seq": 1,
            "payload": {"pid": pid, "adapter_id": "fake", "capabilities": ["PING"]},
        }
    ).encode("utf-8") + b"\n"


def make_supervisor(proc: FakeProc, clock: FakeClock, **kwargs) -> WorkerSupervisor:
    return WorkerSupervisor(
        spawn=lambda argv, env, stderr_fd: proc,
        clock=clock,
        sleep_fn=fake_sleep(clock),
        **kwargs,
    )


class TestHappyPathRealWorker:
    def test_ping_and_shutdown_round_trip(self):
        supervisor = WorkerSupervisor()
        supervisor.start()
        try:
            assert supervisor.is_alive()
            reply = supervisor.connection.request("PING", {}, None)
            assert reply.kind == "RESULT"
            assert reply.payload == {"pong": True}
            receipt = supervisor.shutdown(term_grace_ms=500)
        finally:
            supervisor.close()
        assert receipt.level is EscalationLevel.SHUTDOWN
        assert receipt.graceful
        assert receipt.exit_status == 0
        assert not supervisor.is_alive()

    def test_hello_pid_mismatch_kills_the_worker(self):
        # A real worker always reports the right pid, so drive the mismatch
        # with a fake proc that lies in its HELLO.
        proc = FakeProc(hello_bytes(pid=999999))
        clock = FakeClock()
        supervisor = make_supervisor(proc, clock)
        with pytest.raises(WorkerDied):
            supervisor.start()
        assert proc.killed == 1


class TestStartup:
    def test_worker_dying_before_hello_raises_and_kills(self):
        proc = FakeProc()
        proc.exit(3)  # died before any HELLO
        supervisor = make_supervisor(proc, FakeClock())
        with pytest.raises(WorkerDied):
            supervisor.start()

    def test_startup_deadline_miss_real_child_is_killed(self):
        def spawn(argv, env, stderr_fd):
            return subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_fd,
                start_new_session=True,
                close_fds=True,
                env=dict(env),
            )

        supervisor = WorkerSupervisor(spawn=spawn, startup_deadline_s=0.5)
        with pytest.raises(StartupTimeout):
            supervisor.start()
        assert supervisor.poll() is not None
        supervisor.close()

    def test_double_start_is_refused(self):
        supervisor = make_supervisor(FakeProc(hello_bytes()), FakeClock())
        supervisor.start()
        with pytest.raises(SupervisorError):
            supervisor.start()
        supervisor.close()


class TestCrashMidCommand:
    def test_worker_death_surfaces_as_peer_closed_and_poll(self):
        proc = FakeProc(hello_bytes())
        clock = FakeClock()
        supervisor = make_supervisor(proc, clock)
        supervisor.start()
        proc.exit(1)  # crash between handshake and the next command
        with pytest.raises(PeerClosed):
            supervisor.connection.request("PING", {}, None)
        # The caller owns the UNKNOWN/QUARANTINED decision; the supervisor
        # only reports facts.
        assert supervisor.poll() == 1
        assert not supervisor.is_alive()
        supervisor.close()

    def test_shutdown_after_crash_reports_none_level(self):
        proc = FakeProc(hello_bytes())
        clock = FakeClock()
        supervisor = make_supervisor(proc, clock)
        supervisor.start()
        proc.exit(-9)
        receipt = supervisor.shutdown()
        assert receipt.level is EscalationLevel.NONE
        assert receipt.exit_status == -9
        supervisor.close()


class TestEscalation:
    def test_already_exited_worker_reports_none_level(self):
        proc = FakeProc(hello_bytes())
        clock = FakeClock()
        supervisor = make_supervisor(proc, clock)
        supervisor.start()
        proc.exit(0)  # exits cleanly on its own after the handshake
        receipt = supervisor.shutdown()
        assert receipt.level is EscalationLevel.NONE
        supervisor.close()

    def test_escalates_to_sigterm_when_shutdown_is_ignored(self):
        proc = FakeProc(hello_bytes())
        proc.die_on_terminate = True
        clock = FakeClock()
        supervisor = make_supervisor(proc, clock)
        supervisor.start()
        receipt = supervisor.shutdown()
        assert receipt.level is EscalationLevel.TERM
        assert proc.terminated == 1
        assert proc.killed == 0
        assert receipt.exit_status == -15
        # The SHUTDOWN message reached the child before any escalation.
        assert b'"kind":"SHUTDOWN"' in proc.stdin.data
        supervisor.close()

    def test_escalates_to_sigkill_when_term_is_ignored(self):
        proc = FakeProc(hello_bytes())
        clock = FakeClock()
        supervisor = make_supervisor(proc, clock)
        supervisor.start()
        receipt = supervisor.shutdown(grace_ms=200)
        assert receipt.level is EscalationLevel.KILL
        assert receipt.killed
        assert proc.terminated == 1
        assert proc.killed == 1
        assert receipt.exit_status == -9
        supervisor.close()

    def test_shared_grace_is_not_extended_by_waiting(self):
        proc = FakeProc(hello_bytes())
        clock = FakeClock(start=0.0)
        supervisor = make_supervisor(proc, clock)
        supervisor.start()
        start_t = clock.t
        supervisor.shutdown(grace_ms=500)
        # SHUTDOWN wait (500ms) + TERM grace (default 1000ms) with the fake
        # sleep advancing the clock; the total is bounded and observed.
        assert 1.4 <= clock.t - start_t <= 1.7

    def test_real_sigterm_ignored_child_needs_sigkill(self):
        script = "\n".join(
            [
                "import json, os, signal, sys, time",
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
                "send = lambda o: (sys.stdout.write(json.dumps(o) + chr(10)), sys.stdout.flush())",
                "send({'v': 1, 'kind': 'HELLO', 'seq': 1, 'payload':"
                " {'pid': os.getpid(), 'adapter_id': 'stubborn', 'capabilities': []}})",
                "sys.stdin.readline()",
                "while True: time.sleep(0.05)",
            ]
        )

        def spawn(argv, env, stderr_fd):
            return subprocess.Popen(
                [sys.executable, "-c", script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_fd,
                start_new_session=True,
                close_fds=True,
                env=dict(env),
            )

        supervisor = WorkerSupervisor(spawn=spawn)
        supervisor.start()
        try:
            started = time.monotonic()
            receipt = supervisor.shutdown(grace_ms=100, term_grace_ms=200)
            elapsed = time.monotonic() - started
            assert receipt.level is EscalationLevel.KILL
            assert receipt.killed
            assert receipt.exit_status == -9
            # ~100ms shared grace + ~200ms term grace, far below the 5s budget.
            assert elapsed < 2.0
            assert supervisor.poll() is not None
        finally:
            supervisor.close()


class TestChildEnv:
    def test_only_a_whitelist_is_inherited(self, monkeypatch):
        monkeypatch.setenv("TYPECHECK_SECRET", "nope")
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        monkeypatch.setenv("PYTHONPATH", "/some/path")
        monkeypatch.setenv("TMPDIR", "/tmp")
        monkeypatch.setenv("LANG", "C.UTF-8")  # LANG is whitelisted, others are not
        monkeypatch.setenv("LC_ALL", "en_US.UTF-8")
        env = default_child_env()
        assert env == {
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": "/some/path",
            "TMPDIR": "/tmp",
            "LANG": "C.UTF-8",
        }

    def test_explicit_base_wins_and_path_default_is_set(self):
        env = default_child_env({"PATH": "/custom/bin", "EXTRA": "x"})
        assert env["PATH"] == "/custom/bin"
        assert "EXTRA" not in env
        minimal = default_child_env({})
        assert minimal["PATH"] == "/usr/bin:/bin"
