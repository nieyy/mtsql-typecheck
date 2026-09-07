"""Cancellation budgets and lifecycle transitions (design 6.2.2/6.4.5/6.4.6).

``CancelCoordinator`` implements the shared cancel grace: the first
cancellation arms a deadline of ``CANCEL_GRACE_MS`` (5s) on the injected
clock; every later ``begin`` for the same window returns the *same* deadline
(repeated cancels never extend it, negative matrix C03) and an expired
window stays expired.  ``reset`` exists for the deliberate start of a new
operation; callers, not the coordinator, decide when that is legal.

``transition`` is the lifecycle state machine helper with the legal
transition table frozen by design 6.2.2::

    NEW -> PREPARED -> SETUP -> READBACK -> READY -> QUERY -> FETCH
        -> TERMINATING -> CLEANING -> SEALED
    any of NEW..TERMINATING -> CANCELLING -> CLEANING -> SEALED_PARTIAL
    CANCELLING / TERMINATING / CLEANING -> QUARANTINED (stop the run)

SEALED, SEALED_PARTIAL and QUARANTINED are terminal.  CLEANING is the
funnel: it is reached from TERMINATING (normal path, ends at SEALED) or
from CANCELLING (cancel path, ends at SEALED_PARTIAL) -- a cancelled
operation always lands the owner in CLEANING and can never reach SEALED.
CLEANING is itself treated as an active stage here; a cancellation arriving
during CLEANING does not re-enter CANCELLING because CLEANING already is
the bounded unwind (surfaced interpretation of "any stage -> CANCELLING";
see the phase report).  Illegal transitions raise IllegalTransitionError,
never a silent fallback.
"""

from __future__ import annotations

import enum
import time
from typing import Callable, Optional

from ..contracts.case import ContractError
from ..contracts.execution import CANCEL_GRACE_MS

__all__ = [
    "LifecycleState",
    "TERMINAL_STATES",
    "CANCEL_ENTRY_STATES",
    "IllegalTransitionError",
    "transition",
    "CancelCoordinator",
]


class LifecycleState(enum.StrEnum):
    NEW = "NEW"
    PREPARED = "PREPARED"
    SETUP = "SETUP"
    READBACK = "READBACK"
    READY = "READY"
    QUERY = "QUERY"
    FETCH = "FETCH"
    TERMINATING = "TERMINATING"
    CLEANING = "CLEANING"
    SEALED = "SEALED"
    CANCELLING = "CANCELLING"
    SEALED_PARTIAL = "SEALED_PARTIAL"
    QUARANTINED = "QUARANTINED"


TERMINAL_STATES = frozenset(
    {LifecycleState.SEALED, LifecycleState.SEALED_PARTIAL, LifecycleState.QUARANTINED}
)

CANCEL_ENTRY_STATES = frozenset(
    {
        LifecycleState.NEW,
        LifecycleState.PREPARED,
        LifecycleState.SETUP,
        LifecycleState.READBACK,
        LifecycleState.READY,
        LifecycleState.QUERY,
        LifecycleState.FETCH,
        LifecycleState.TERMINATING,
    }
)


class IllegalTransitionError(ContractError):
    """A lifecycle transition outside the frozen design table."""


_NORMAL_CHAIN: dict[LifecycleState, LifecycleState] = {
    LifecycleState.NEW: LifecycleState.PREPARED,
    LifecycleState.PREPARED: LifecycleState.SETUP,
    LifecycleState.SETUP: LifecycleState.READBACK,
    LifecycleState.READBACK: LifecycleState.READY,
    LifecycleState.READY: LifecycleState.QUERY,
    LifecycleState.QUERY: LifecycleState.FETCH,
    LifecycleState.FETCH: LifecycleState.TERMINATING,
    LifecycleState.TERMINATING: LifecycleState.CLEANING,
}

_LEGAL: dict[LifecycleState, frozenset[LifecycleState]] = {}
for _state in LifecycleState:
    targets: set[LifecycleState] = set()
    if _state in _NORMAL_CHAIN:
        targets.add(_NORMAL_CHAIN[_state])
    if _state in CANCEL_ENTRY_STATES:
        targets.add(LifecycleState.CANCELLING)
    _LEGAL[_state] = frozenset(targets)

# CLEANING funnels to the two sealed states or to quarantine (cleanup
# failure / uncertainty); CANCELLING funnels to CLEANING or quarantine
# (grace expired with termination UNKNOWN).
# TERMINATING may also land directly in QUARANTINED: the design allows
# CANCELLING / TERMINATING / CLEANING -> QUARANTINED when ownership of the
# attempt objects becomes uncertain during the unwind.
_LEGAL[LifecycleState.TERMINATING] = frozenset(
    {
        _NORMAL_CHAIN[LifecycleState.TERMINATING],
        LifecycleState.CANCELLING,
        LifecycleState.QUARANTINED,
    }
)

_LEGAL[LifecycleState.CLEANING] = frozenset(
    {
        LifecycleState.SEALED,
        LifecycleState.SEALED_PARTIAL,
        LifecycleState.QUARANTINED,
    }
)
_LEGAL[LifecycleState.CANCELLING] = frozenset(
    {LifecycleState.CLEANING, LifecycleState.QUARANTINED}
)
for _state in TERMINAL_STATES:
    _LEGAL[_state] = frozenset()


def transition(current: LifecycleState, target: LifecycleState) -> LifecycleState:
    """Validate one lifecycle transition and return the target state."""
    if not isinstance(current, LifecycleState):
        raise IllegalTransitionError(f"current must be LifecycleState, got {current!r}")
    if not isinstance(target, LifecycleState):
        raise IllegalTransitionError(f"target must be LifecycleState, got {target!r}")
    if target not in _LEGAL[current]:
        raise IllegalTransitionError(
            f"illegal lifecycle transition {current.value} -> {target.value}"
        )
    return target


class CancelCoordinator:
    """Shared 5s cancel/termination grace (design 6.4.5, budget table).

    The first ``begin`` arms ``clock() + grace_ms``; later ``begin`` calls
    return the same deadline without extension, and once expired the window
    stays expired (a new window requires an explicit ``reset``).  ``scope``
    is a bounded diagnostic label only.
    """

    _MAX_SCOPE_CHARS = 128

    def __init__(self, *, clock: Callable[[], float] = time.monotonic, grace_ms: int = CANCEL_GRACE_MS) -> None:
        if not callable(clock):
            raise ContractError("CancelCoordinator clock must be callable")
        if isinstance(grace_ms, bool) or not isinstance(grace_ms, int):
            raise ContractError("CancelCoordinator grace_ms must be an int")
        if grace_ms <= 0:
            raise ContractError(f"CancelCoordinator grace_ms must be > 0, got {grace_ms}")
        self._clock = clock
        self._grace_ms = grace_ms
        self._deadline: Optional[float] = None
        self._scope: Optional[str] = None

    @property
    def grace_ms(self) -> int:
        return self._grace_ms

    @property
    def scope(self) -> Optional[str]:
        return self._scope

    @property
    def deadline_s(self) -> Optional[float]:
        return self._deadline

    @property
    def begun(self) -> bool:
        return self._deadline is not None

    def begin(self, scope: str) -> float:
        """Arm the grace window (once) and return its absolute deadline."""
        if not isinstance(scope, str) or not scope:
            raise ContractError("CancelCoordinator scope must be a non-empty str")
        if len(scope) > self._MAX_SCOPE_CHARS:
            raise ContractError(
                f"CancelCoordinator scope must be at most {self._MAX_SCOPE_CHARS} chars"
            )
        if self._deadline is not None:
            # Shared window: never extend, never re-arm over an expiry.
            return self._deadline
        self._scope = scope
        self._deadline = self._clock() + self._grace_ms / 1000
        return self._deadline

    def reset(self) -> None:
        """Explicitly drop the window (new operation); never called automatically."""
        self._deadline = None
        self._scope = None

    def expired(self) -> bool:
        return self._deadline is not None and self._clock() >= self._deadline

    def remaining_ms(self) -> Optional[int]:
        """Whole milliseconds left; None when never begun, 0 once expired."""
        if self._deadline is None:
            return None
        remaining = (self._deadline - self._clock()) * 1000
        if remaining <= 0:
            return 0
        return int(remaining)
