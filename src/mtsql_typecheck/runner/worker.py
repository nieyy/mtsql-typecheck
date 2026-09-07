"""Worker process entry point (design 6.3.2/6.4.6; Phase 3 scaffolding).

The worker speaks ``runner.ipc`` over its std streams: HELLO handshake, then
a request/response command loop through a handler registry.  Phase 3 ships
only the PING handler plus the built-in SHUTDOWN/CANCEL control handling and
``WorkerApp.register_handler`` for later phases (EXEC arrives in Phase 4).

Safety properties:

- The worker never performs I/O beyond its std streams and never imports a
  database driver or the adapters package; importing this module is safe on
  a bare install without PyMySQL.
- SIGTERM and the CANCEL message are cooperative: both flip the worker's
  cancel token, which is observed through a ``contracts.execution.Control``
  handle; the resulting ``ControlCancelled`` produces an ERROR envelope
  (code ``CANCELLED``) and exit status 130 (design 6.3.3 user cancel).
- An unhandled exception emits an ERROR envelope and exits non-zero -- the
  worker never dies silently; diagnostics go to stderr only.
- A protocol violation from the parent stops the worker immediately: the
  worker never executes SQL on an untrusted channel (design 6.4.5).
"""

from __future__ import annotations

import os
import signal
import sys
import time
import traceback
from typing import Callable, Dict, List, Optional

from ..contracts.execution import Control, ControlCancelled
from . import ipc

__all__ = [
    "HELLO_ADAPTER_ID_PLACEHOLDER",
    "EXIT_STATUS_OK",
    "EXIT_STATUS_ERROR",
    "EXIT_STATUS_CANCELLED",
    "EXIT_STATUS_USAGE",
    "WorkerApp",
    "main",
]

# Phase 3 scaffolding has no adapter bound yet; Phase 4 replaces this with
# the certified adapter id (contracts.runner.RUNNER_ADAPTER_ID).
HELLO_ADAPTER_ID_PLACEHOLDER = "phase3-scaffold-no-adapter"

EXIT_STATUS_OK = 0
EXIT_STATUS_ERROR = 1
EXIT_STATUS_CANCELLED = 130  # design 6.3.3: user cancel
EXIT_STATUS_USAGE = 2

# Control kinds handled by the loop itself; they cannot be registered.
_RESERVED_KINDS = frozenset({"SHUTDOWN", "CANCEL"})

Handler = Callable[[dict], dict]

_MAX_ERROR_TEXT_CHARS = ipc.MAX_ERROR_MESSAGE_CHARS


def _ping(payload: dict) -> dict:
    del payload
    return {"pong": True}


class WorkerApp:
    """Worker command loop with an injectable handler registry."""

    def __init__(
        self,
        *,
        control: Optional[Control] = None,
        stdin=None,
        stdout=None,
    ) -> None:
        if control is None:
            clock = time.monotonic
            control = Control(clock=clock, deadline=None, cancelled=lambda: False)
        self._cancel_requested = False
        # The cancel token is the worker's own state; Control.observe it.
        self._control = Control(
            clock=control.clock,
            deadline=control.deadline,
            cancelled=lambda: self._cancel_requested,
        )
        self._stdin = stdin
        self._stdout = stdout
        self._handlers: Dict[str, Handler] = {}
        self.register_handler("PING", _ping)

    @property
    def control(self) -> Control:
        return self._control

    @property
    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted(self._handlers))

    def register_handler(self, kind: str, handler: Handler) -> None:
        """Register one command handler (``handler(payload) -> payload``)."""
        if not isinstance(kind, str) or ipc._KIND_RE.match(kind) is None:
            raise ipc.IpcError(
                f"handler kind must match {ipc._KIND_RE.pattern!r}, got {kind!r}"
            )
        if kind in _RESERVED_KINDS:
            raise ipc.IpcError(
                f"kind {kind!r} is handled by the worker loop and cannot be registered"
            )
        if not callable(handler):
            raise ipc.IpcError("handler must be callable")
        if kind in self._handlers:
            raise ipc.IpcError(f"handler for kind {kind!r} already registered")
        self._handlers[kind] = handler

    def request_cancel(self) -> None:
        """Flip the cancel token; observed through the Control discipline."""
        self._cancel_requested = True

    # -- loop ---------------------------------------------------------------

    def run(self) -> int:
        """Handshake, serve commands until SHUTDOWN, return the exit status."""
        connection = ipc.worker_std_connection(self._stdin, self._stdout)
        try:
            return self._run_loop(connection)
        except ControlCancelled:
            _send_error(connection, "CANCELLED", "worker cancelled")
            return EXIT_STATUS_CANCELLED
        except ipc.ProtocolViolation as exc:
            print(f"worker: protocol violation: {exc}", file=sys.stderr)
            _send_error(connection, "PROTOCOL", str(exc))
            return EXIT_STATUS_ERROR
        except Exception as exc:  # noqa: BLE001 - the worker never dies silently
            print(f"worker: unhandled exception: {traceback.format_exc(limit=8)}", file=sys.stderr)
            _send_error(connection, "INTERNAL", str(exc)[:_MAX_ERROR_TEXT_CHARS])
            return EXIT_STATUS_ERROR

    def _run_loop(self, connection: ipc.IpcConnection) -> int:
        connection.send(
            "HELLO",
            {
                "pid": os.getpid(),
                "adapter_id": HELLO_ADAPTER_ID_PLACEHOLDER,
                "capabilities": list(self.capabilities),
            },
        )
        ready = connection.recv(self._control)
        if ready.kind != "READY":
            raise ipc.ProtocolViolation(f"expected READY after HELLO, got {ready.kind!r}")
        while True:
            # Cancellation is checked between every command (SIGTERM and the
            # CANCEL message both flip the token).
            self._control.raise_if_cancelled()
            envelope = connection.recv(self._control)
            if envelope.kind == "SHUTDOWN":
                connection.send("EXITED", {"status": EXIT_STATUS_OK}, corr=envelope.seq)
                return EXIT_STATUS_OK
            if envelope.kind == "CANCEL":
                self._cancel_requested = True
                connection.send("RESULT", {"cancelled": True}, corr=envelope.seq)
                continue
            handler = self._handlers.get(envelope.kind)
            if handler is None:
                connection.send(
                    "ERROR",
                    {"message": f"unknown command kind {envelope.kind!r}"},
                    corr=envelope.seq,
                )
                continue
            try:
                result = handler(envelope.payload)
            except ControlCancelled:
                raise
            except Exception as exc:  # noqa: BLE001 - report, never hang or lie
                connection.send(
                    "ERROR",
                    {"message": str(exc)[:_MAX_ERROR_TEXT_CHARS]},
                    corr=envelope.seq,
                )
                return EXIT_STATUS_ERROR
            connection.send("RESULT", result, corr=envelope.seq)


def _send_error(connection: ipc.IpcConnection, code: str, message: str) -> None:
    try:
        connection.send("ERROR", {"code": code, "message": message[:_MAX_ERROR_TEXT_CHARS]})
    except ipc.IpcError:
        pass


def main(argv: Optional[List[str]] = None) -> int:
    """Process entry: install the SIGTERM hook and run the command loop."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        print(f"worker: unexpected arguments {args!r}", file=sys.stderr)
        return EXIT_STATUS_USAGE
    app = WorkerApp()
    try:
        signal.signal(signal.SIGTERM, _make_sigterm_handler(app))
    except ValueError:
        # Not in the main thread (embedded use); SIGTERM handling is then
        # the embedder's responsibility.
        pass
    return app.run()


def _make_sigterm_handler(app: WorkerApp) -> Callable[[int, object], None]:
    def handler(signum: int, frame: object) -> None:
        del signum, frame
        app.request_cancel()

    return handler


if __name__ == "__main__":
    sys.exit(main())
