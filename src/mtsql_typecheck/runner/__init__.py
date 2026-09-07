"""D3 runner: supervision, cancellation and safe cleanup (design 6.2/6.4).

Subpackages and modules:

- ``naming``      run/attempt tokens and ``tc_`` object names
- ``ownership``   append-only ownership journal + quarantine latch
- ``ipc``         parent<->worker JSON-line protocol
- ``supervisor``  worker subprocess supervision and shutdown escalation
- ``worker``      worker process entry point (scaffolding)
- ``cancellation`` shared cancel grace + lifecycle transition table
- ``cleanup``     attempt cleanup against the narrow executor protocol

Importing this package performs no I/O and never imports a database driver
or the adapters package.
"""

from . import cancellation, cleanup, ipc, naming, ownership, supervisor, worker

__all__ = [
    "cancellation",
    "cleanup",
    "ipc",
    "naming",
    "ownership",
    "supervisor",
    "worker",
]
