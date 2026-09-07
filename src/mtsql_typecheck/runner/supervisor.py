"""Subprocess supervision for the attempt worker (design 6.2.2/6.4.5/6.4.6).

``WorkerSupervisor`` spawns one worker per attempt as
``<python> -m mtsql_typecheck.runner.worker`` with:

- ``start_new_session=True`` (own process group; no terminal coupling),
- ``close_fds=True`` and an explicitly built minimal environment (never the
  parent's full environment, so no inherited credentials or database
  configuration; ``env_passthrough`` re-adds only explicitly named
  variables -- the worker target document and the one password variable its
  ``TargetConfig`` names),
- stdin/stdout pipes carrying the JSON-line IPC (``runner.ipc``),
- stderr captured into an anonymous temp file with a bounded tail read.

The startup handshake (worker HELLO -> parent READY) must complete inside
``startup_deadline_s``; a miss, a crash, or a protocol violation during
handshake kills the child immediately.  Every other failure (IPC loss,
crash mid-command) is surfaced to the caller, which owns the UNKNOWN /
QUARANTINED decision -- the supervisor never maps a dead process to a
confirmed termination (design 6.4.5, negative matrix C01/C02).

``shutdown`` implements the escalation ladder: SHUTDOWN message -> shared
cancel grace (``runner.cancellation.CancelCoordinator``, 5s by default,
never extended by repeated calls) -> SIGTERM -> short term grace ->
SIGKILL, and records which escalation level was reached.  All deadlines and
signal delivery are injectable; the process object itself is created by an
injectable ``spawn`` callable so tests can drive every ladder rung without
a real child.
"""

from __future__ import annotations

import enum
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Optional

from ..contracts.case import ContractError
from ..contracts.execution import CANCEL_GRACE_MS, Control
from . import ipc
from .cancellation import CancelCoordinator

__all__ = [
    "DEFAULT_STARTUP_DEADLINE_S",
    "SHUTDOWN_GRACE_MS",
    "DEFAULT_TERM_GRACE_MS",
    "MAX_STDERR_TAIL_BYTES",
    "WORKER_MODULE",
    "EscalationLevel",
    "ShutdownReceipt",
    "SupervisorError",
    "StartupTimeout",
    "WorkerDied",
    "StderrRing",
    "default_child_env",
    "default_spawn",
    "WorkerSupervisor",
]

WORKER_MODULE = "mtsql_typecheck.runner.worker"

DEFAULT_STARTUP_DEADLINE_S = 10.0

# The shutdown grace shares the cancel budget (design 6.4.5: cancellation,
# termination confirmation and necessary cleanup share at most 5s).
SHUTDOWN_GRACE_MS = CANCEL_GRACE_MS

DEFAULT_TERM_GRACE_MS = 1000

MAX_STDERR_TAIL_BYTES = 8192

_POLL_INTERVAL_S = 0.005


class EscalationLevel(enum.StrEnum):
    """How far the shutdown ladder had to go before the child exited."""

    NONE = "NONE"  # already exited when shutdown was called
    SHUTDOWN = "SHUTDOWN"  # exited within the shared grace after SHUTDOWN
    TERM = "TERM"  # needed SIGTERM
    KILL = "KILL"  # needed SIGKILL


@dataclass(frozen=True)
class ShutdownReceipt:
    level: EscalationLevel
    exit_status: Optional[int]
    killed: bool

    @property
    def graceful(self) -> bool:
        return self.level in (EscalationLevel.NONE, EscalationLevel.SHUTDOWN)


class SupervisorError(ContractError):
    """Supervisor-layer failure."""


class StartupTimeout(SupervisorError):
    """The worker did not complete the HELLO handshake in time."""


class WorkerDied(SupervisorError):
    """The worker process died (crash, signal, or closed IPC)."""


class StderrRing:
    """Child stderr captured into an anonymous temp file; only a bounded
    tail is ever read back, so a chatty child cannot grow the parent."""

    def __init__(self) -> None:
        self._file = tempfile.TemporaryFile()

    @property
    def fd(self) -> int:
        return self._file.fileno()

    def read_tail(self, limit: int = MAX_STDERR_TAIL_BYTES) -> bytes:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise SupervisorError(f"limit must be a non-negative int, got {limit}")
        self._file.seek(0, os.SEEK_END)
        end = self._file.tell()
        start = max(0, end - limit)
        self._file.seek(start)
        data = self._file.read(limit)
        self._file.seek(0, os.SEEK_END)
        return data

    def close(self) -> None:
        self._file.close()


def default_child_env(base: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    """Minimal explicit child environment; nothing is inherited silently.

    Only PATH, PYTHONPATH, TMPDIR and LANG are carried over (from ``base``
    or ``os.environ``) because the worker needs them to import the package
    and behave deterministically; everything else starts empty.
    """
    source = dict(base) if base is not None else os.environ
    env: dict[str, str] = {}
    for name in ("PATH", "PYTHONPATH", "TMPDIR", "LANG"):
        value = source.get(name)
        if value:
            env[name] = value
    if "PATH" not in env:
        env["PATH"] = "/usr/bin:/bin"
    return env


def default_spawn(argv: list[str], *, env: Mapping[str, str], stderr_fd: int) -> object:
    """Real Popen with no inherited fds, own session, and piped IPC."""
    return subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr_fd,
        start_new_session=True,
        close_fds=True,
        env=dict(env),
    )


class WorkerSupervisor:
    """Spawn, handshake, monitor and shut down one attempt worker."""

    def __init__(
        self,
        *,
        spawn: Optional[Callable[..., object]] = None,
        python_executable: Optional[str] = None,
        worker_module: str = WORKER_MODULE,
        extra_argv: tuple[str, ...] = (),
        env: Optional[Mapping[str, str]] = None,
        env_passthrough: tuple[str, ...] = (),
        startup_deadline_s: float = DEFAULT_STARTUP_DEADLINE_S,
        clock: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
        sigterm_fn: Optional[Callable[[object], None]] = None,
        sigkill_fn: Optional[Callable[[object], None]] = None,
    ) -> None:
        if not callable(clock):
            raise SupervisorError("clock must be callable")
        if not callable(sleep_fn):
            raise SupervisorError("sleep_fn must be callable")
        if isinstance(startup_deadline_s, bool) or not isinstance(startup_deadline_s, (int, float)):
            raise SupervisorError("startup_deadline_s must be a number")
        if startup_deadline_s <= 0:
            raise SupervisorError(f"startup_deadline_s must be > 0, got {startup_deadline_s}")
        if not isinstance(extra_argv, tuple) or not all(isinstance(a, str) for a in extra_argv):
            raise SupervisorError("extra_argv must be a tuple of str")
        if not isinstance(env_passthrough, tuple) or not all(
            isinstance(name, str) for name in env_passthrough
        ):
            raise SupervisorError("env_passthrough must be a tuple of str")
        self._spawn = spawn if spawn is not None else default_spawn
        self._python = python_executable if python_executable is not None else sys.executable
        self._worker_module = worker_module
        self._extra_argv = extra_argv
        self._env = default_child_env() if env is None else default_child_env(env)
        # Explicitly named variables are re-added from the caller's source
        # mapping after the whitelist filtering: the child never inherits
        # anything the caller did not name here.
        passthrough_source = os.environ if env is None else env
        for name in env_passthrough:
            value = passthrough_source.get(name)
            if value:
                self._env[name] = value
        self._startup_deadline_s = float(startup_deadline_s)
        self._clock = clock
        self._sleep = sleep_fn
        self._sigterm = sigterm_fn if sigterm_fn is not None else _do_terminate
        self._sigkill = sigkill_fn if sigkill_fn is not None else _do_kill
        self._proc: Optional[object] = None
        self._connection: Optional[ipc.IpcConnection] = None
        self._stderr = StderrRing()
        self._closed = False

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Spawn the worker and complete the HELLO/READY handshake."""
        if self._proc is not None:
            raise SupervisorError("supervisor already started")
        argv = [self._python, "-m", self._worker_module, *self._extra_argv]
        try:
            proc = self._spawn(argv, env=self._env, stderr_fd=self._stderr.fd)
        except OSError as exc:
            raise SupervisorError(f"cannot spawn worker: {exc}") from exc
        self._proc = proc
        self._connection = ipc.connection_for_process(proc)
        control = self._control(self._startup_deadline_s)
        try:
            hello = self._connection.recv(control)
            if hello.kind != "HELLO":
                raise ipc.ProtocolViolation(
                    f"worker sent {hello.kind!r} instead of HELLO during handshake"
                )
            reported_pid = hello.payload.get("pid")
            if reported_pid != proc.pid:
                raise ipc.ProtocolViolation(
                    f"worker HELLO pid {reported_pid!r} does not match the spawned pid "
                    f"{proc.pid}"
                )
            self._connection.send("READY", {})
        except ipc.IpcTimeout as exc:
            self._kill_after_failed_start()
            raise StartupTimeout(
                f"worker HELLO handshake did not complete within "
                f"{self._startup_deadline_s}s: {exc}"
            ) from exc
        except (ipc.PeerClosed, ipc.ProtocolViolation) as exc:
            self._kill_after_failed_start()
            raise WorkerDied(f"worker failed the HELLO handshake: {exc}") from exc
        except SupervisorError:
            self._kill_after_failed_start()
            raise

    def _kill_after_failed_start(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            _do_kill(self._proc)
            self._proc.wait()

    def _control(self, deadline_s: float) -> Control:
        return Control(clock=self._clock, deadline=self._clock() + deadline_s, cancelled=lambda: False)

    # -- introspection -----------------------------------------------------

    @property
    def connection(self) -> ipc.IpcConnection:
        if self._connection is None:
            raise SupervisorError("worker not started")
        return self._connection

    @property
    def pid(self) -> Optional[int]:
        return None if self._proc is None else self._proc.pid

    def poll(self) -> Optional[int]:
        """Worker exit status, or None while alive (liveness check)."""
        if self._proc is None:
            raise SupervisorError("worker not started")
        return self._proc.poll()

    def is_alive(self) -> bool:
        return self.poll() is None

    def stderr_tail(self, limit: int = MAX_STDERR_TAIL_BYTES) -> bytes:
        return self._stderr.read_tail(limit)

    # -- shutdown ----------------------------------------------------------

    def shutdown(
        self,
        *,
        grace_ms: int = SHUTDOWN_GRACE_MS,
        term_grace_ms: int = DEFAULT_TERM_GRACE_MS,
    ) -> ShutdownReceipt:
        """SHUTDOWN message -> shared grace -> SIGTERM -> short grace -> SIGKILL."""
        if isinstance(term_grace_ms, bool) or not isinstance(term_grace_ms, int) or term_grace_ms <= 0:
            raise SupervisorError(f"term_grace_ms must be a positive int, got {term_grace_ms}")
        if self._proc is None:
            raise SupervisorError("worker not started")
        if self._closed:
            raise SupervisorError("supervisor already shut down")
        proc = self._proc
        status = proc.poll()
        if status is not None:
            self._closed = True
            return ShutdownReceipt(EscalationLevel.NONE, status, killed=False)

        coordinator = CancelCoordinator(clock=self._clock, grace_ms=grace_ms)
        coordinator.begin("worker-shutdown")
        self._send_shutdown_best_effort()

        status = self._wait_while(lambda: not coordinator.expired())
        if status is not None:
            self._closed = True
            return ShutdownReceipt(EscalationLevel.SHUTDOWN, status, killed=False)

        # Escalate to SIGTERM with a short grace of its own.
        term_deadline = self._clock() + term_grace_ms / 1000
        self._sigterm(proc)
        while self._clock() < term_deadline:
            status = proc.poll()
            if status is not None:
                self._closed = True
                return ShutdownReceipt(EscalationLevel.TERM, status, killed=False)
            self._sleep(_POLL_INTERVAL_S)

        # Final escalation: SIGKILL, then reap unconditionally.
        self._sigkill(proc)
        status = proc.wait()
        self._closed = True
        return ShutdownReceipt(EscalationLevel.KILL, status, killed=True)

    def _send_shutdown_best_effort(self) -> None:
        if self._connection is None:
            return
        try:
            self._connection.send("SHUTDOWN", {})
        except ipc.IpcError:
            # Broken pipe / protocol trouble must not prevent escalation.
            pass

    def _wait_while(self, keep_waiting: Callable[[], bool]) -> Optional[int]:
        proc = self._proc
        assert proc is not None
        while keep_waiting():
            status = proc.poll()
            if status is not None:
                return status
            self._sleep(_POLL_INTERVAL_S)
        return None

    # -- cleanup -----------------------------------------------------------

    def close(self) -> None:
        """Release IPC streams and the stderr capture; does not kill."""
        if self._connection is not None:
            self._connection.close()
        self._stderr.close()

    def __enter__(self) -> "WorkerSupervisor":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


def _do_terminate(proc: object) -> None:
    try:
        proc.terminate()
    except (OSError, ValueError):
        pass


def _do_kill(proc: object) -> None:
    try:
        proc.kill()
    except (OSError, ValueError):
        pass
