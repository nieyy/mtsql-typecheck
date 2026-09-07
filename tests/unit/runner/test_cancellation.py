"""Cancellation and lifecycle transition tests (design 6.2.2/6.4.5).

The transition table expectations are transcribed by hand from design
6.2.2; the shared-grace arithmetic uses a fake clock so no test sleeps.
"""

from __future__ import annotations

import pytest

from mtsql_typecheck.contracts.case import ContractError
from mtsql_typecheck.contracts.execution import CANCEL_GRACE_MS
from mtsql_typecheck.runner.cancellation import (
    CANCEL_ENTRY_STATES,
    TERMINAL_STATES,
    CancelCoordinator,
    IllegalTransitionError,
    LifecycleState,
    transition,
)
from runner_fakes import FakeClock

S = LifecycleState

HAPPY_CHAIN = [
    S.NEW,
    S.PREPARED,
    S.SETUP,
    S.READBACK,
    S.READY,
    S.QUERY,
    S.FETCH,
    S.TERMINATING,
    S.CLEANING,
    S.SEALED,
]

CANCEL_CHAIN = [S.NEW, S.CANCELLING, S.CLEANING, S.SEALED_PARTIAL]


class TestTransitionTable:
    def test_full_normal_chain_is_legal(self):
        for current, target in zip(HAPPY_CHAIN, HAPPY_CHAIN[1:]):
            assert transition(current, target) is target

    def test_full_cancel_chain_is_legal_from_every_active_stage(self):
        # any stage -> CANCELLING -> CLEANING -> SEALED_PARTIAL
        for stage in CANCEL_ENTRY_STATES:
            assert transition(stage, S.CANCELLING) is S.CANCELLING
        assert transition(S.CANCELLING, S.CLEANING) is S.CLEANING
        assert transition(S.CLEANING, S.SEALED_PARTIAL) is S.SEALED_PARTIAL

    def test_unknown_paths_land_in_quarantined(self):
        # Termination UNKNOWN / ownership uncertain stop the run.
        assert transition(S.CANCELLING, S.QUARANTINED) is S.QUARANTINED
        assert transition(S.TERMINATING, S.QUARANTINED) is S.QUARANTINED
        assert transition(S.CLEANING, S.QUARANTINED) is S.QUARANTINED

    @pytest.mark.parametrize(
        "current,target",
        [
            (S.NEW, S.SETUP),  # skipping stages
            (S.NEW, S.QUERY),
            (S.QUERY, S.SEALED),  # sealing without cleanup
            (S.READY, S.PREPARED),  # backwards
            (S.CLEANING, S.CANCELLING),  # cleaning already is the unwind
            (S.CANCELLING, S.SEALED),  # cancelled work never reaches SEALED
            (S.SEALED, S.CLEANING),  # terminal states
            (S.SEALED, S.QUARANTINED),
            (S.SEALED_PARTIAL, S.CLEANING),
            (S.QUARANTINED, S.CANCELLING),
            (S.QUARANTINED, S.SEALED),
        ],
    )
    def test_illegal_transitions_raise_a_typed_error(self, current, target):
        with pytest.raises(IllegalTransitionError):
            transition(current, target)

    def test_non_state_arguments_are_rejected(self):
        with pytest.raises(IllegalTransitionError):
            transition("NEW", S.PREPARED)  # type: ignore[arg-type]
        with pytest.raises(IllegalTransitionError):
            transition(S.NEW, "PREPARED")  # type: ignore[arg-type]

    def test_terminal_states_and_cancel_entries_are_frozen_sets(self):
        assert TERMINAL_STATES == frozenset({S.SEALED, S.SEALED_PARTIAL, S.QUARANTINED})
        assert S.SEALED not in CANCEL_ENTRY_STATES
        assert S.CLEANING not in CANCEL_ENTRY_STATES
        assert S.QUARANTINED not in CANCEL_ENTRY_STATES


class TestCancelCoordinator:
    def test_default_grace_is_the_shared_5s_budget(self):
        coordinator = CancelCoordinator()
        assert coordinator.grace_ms == CANCEL_GRACE_MS == 5000

    def test_begin_arms_deadline_at_clock_plus_grace(self):
        clock = FakeClock(start=100.0)
        coordinator = CancelCoordinator(clock=clock)
        assert coordinator.remaining_ms() is None
        assert not coordinator.expired()
        deadline = coordinator.begin("attempt-cancel")
        assert deadline == 105.0  # 100s + 5s
        assert coordinator.deadline_s == deadline
        assert coordinator.scope == "attempt-cancel"

    def test_repeated_begin_never_extends_the_deadline(self):
        clock = FakeClock(start=100.0)
        coordinator = CancelCoordinator(clock=clock)
        first = coordinator.begin("cancel")
        clock.advance(2.0)
        second = coordinator.begin("cancel-again")
        assert second == first
        clock.advance(2.5)
        third = coordinator.begin("and-again")
        assert third == first
        # 4.5s elapsed: still inside the ORIGINAL window.
        assert not coordinator.expired()
        assert coordinator.remaining_ms() == 500

    def test_expiry_is_terminal_until_reset(self):
        clock = FakeClock(start=0.0)
        coordinator = CancelCoordinator(clock=clock, grace_ms=1000)
        coordinator.begin("cancel")
        clock.advance(1.0)
        assert coordinator.expired()
        assert coordinator.remaining_ms() == 0
        # begin() over an expiry does not re-arm (no silent new 5s window).
        assert coordinator.begin("cancel") == clock.t
        assert coordinator.expired()
        coordinator.reset()
        assert not coordinator.begun
        assert coordinator.remaining_ms() is None

    def test_remaining_ms_arithmetic(self):
        clock = FakeClock(start=10.0)
        coordinator = CancelCoordinator(clock=clock, grace_ms=1500)
        coordinator.begin("cancel")
        assert coordinator.remaining_ms() == 1500
        clock.advance(0.25)
        assert coordinator.remaining_ms() == 1250
        clock.advance(2.0)
        assert coordinator.remaining_ms() == 0

    def test_validation(self):
        with pytest.raises(ContractError):
            CancelCoordinator(clock=None)  # type: ignore[arg-type]
        with pytest.raises(ContractError):
            CancelCoordinator(grace_ms=0)
        with pytest.raises(ContractError):
            CancelCoordinator(grace_ms=True)
        clock = FakeClock()
        coordinator = CancelCoordinator(clock=clock)
        with pytest.raises(ContractError):
            coordinator.begin("")
        with pytest.raises(ContractError):
            coordinator.begin("x" * 129)
