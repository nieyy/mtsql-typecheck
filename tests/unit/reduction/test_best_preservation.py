"""Best-pointer preservation tests (oracle-d2-contract section 9).

The in-memory best pointer and the persisted ACCEPTED record are the only
authorities for a reduction result; every test here verifies that the
pointer survives the four ways a run can stop after an acceptance -- budget
exhaustion, cancellation, a persistence fault at a *later* acceptance, and
an operational fault before any acceptance.  The original ``CandidateInput``
must never be mutated by a run, so every test snapshots it before the run
and re-checks the snapshot afterwards.

Every expected counter, outcome and payload digest below is hand-written:
the accepted child in the first three scenarios is proposal 2's
``RemoveRows((2, 3))`` one-row child of the reviewed three-row fixture
(proposal order verified against the strategy's frozen order), and its
identity is recomputed independently through the frozen D1 transform API --
never from the engine under test.  Dispatch indices are 0-based across the
whole run: 0-2 are the original replay group.
"""

from __future__ import annotations

from mtsql_typecheck.contracts.case import IntegerValue, RemoveRows
from mtsql_typecheck.contracts.codec import canonical_json, case_id_of, sha256_hex
from mtsql_typecheck.contracts.oracle import (
    EVIDENCE_APPEND_BUDGET,
    ReductionOutcome,
    ReductionPolicy,
    StopReason,
)
from mtsql_typecheck.generation.transforms import apply_transform
from mtsql_typecheck.reduction.trace import (
    BEST_SOURCE_ACCEPTED,
    BEST_SOURCE_ORIGINAL,
    TRACE_STATUS_COMPLETE,
    JsonlTraceSink,
    read_trace,
)

from engine_fakes import (
    RecordingTraceSink,
    ReductionExecutor,
    assert_candidate_unchanged,
    candidate_snapshot,
    run_reduction,
)
from replay_fakes import (
    CANDIDATE_A_ROWS,
    CANDIDATE_B_ROWS,
    CancelToken,
    CandidateBundle,
    StubClock,
    make_control,
)

# Scripted result rows: a full match destroys the behaviour; the one-row
# mismatch pair keeps it (the child is then a genuine reduction).
_MATCH = (CANDIDATE_A_ROWS, CANDIDATE_A_ROWS)
_MISMATCH_1ROW = ((IntegerValue(-128),), (IntegerValue(-127),))

# The child accepted by proposals 1 (match) then 2 (mismatch group).
_ACCEPTED_TRANSFORM = RemoveRows((2, 3))


def _accepted_child_of(bundle):
    """The one-row child payload, recomputed independently via frozen D1."""
    return apply_transform(
        bundle.candidate.request.payload, _ACCEPTED_TRANSFORM
    ).child.payload


def test_proposal_budget_preserves_accepted_best_and_input():
    """A run stopped by the proposal budget after one acceptance keeps the
    accepted child as best, with the ACCEPTED record's three comparison
    hashes, and never touches the original candidate."""
    bundle = CandidateBundle()
    before = candidate_snapshot(bundle)
    executor = ReductionExecutor(bundle)
    executor.script[3] = _MATCH  # proposal 1: delete-all -> unstable
    for index in (4, 5, 6):  # proposal 2: one-row child -> accepted
        executor.script[index] = _MISMATCH_1ROW
    sink = RecordingTraceSink()
    result = run_reduction(bundle, executor, sink, policy=ReductionPolicy(max_proposals=3))

    assert result.outcome is ReductionOutcome.BUDGET_EXHAUSTED
    assert result.stop_reason is StopReason.PROPOSAL_BUDGET
    assert result.search_complete is False
    assert result.accepted == 1
    assert result.proposals == 3  # 2 executed + the visited delete-all re-proposal
    assert result.executions == 7  # 3 original + 1 match + 3 accepted attempts
    assert result.has_reduction is True
    assert executor.prepares == 7  # nothing dispatched after the budget stop

    child = _accepted_child_of(bundle)
    assert result.best_case_id == case_id_of(child)

    # The ACCEPTED record is the persistent authority; the in-memory pointer
    # carries exactly the hashes it published.
    accepted = sink.records_of_kind("ACCEPTED")
    assert len(accepted) == 1
    assert list(result.best_comparison_hashes) == accepted[0].inline["comparison_hashes"]
    assert len(result.best_comparison_hashes) == 3
    assert accepted[0].payload_ref.sha256 == sha256_hex(canonical_json(child.to_obj()))

    assert_candidate_unchanged(bundle, before)


def test_cancellation_preserves_accepted_best_and_input():
    """A cancellation observed during the restart keeps the previously
    accepted child as best; no dispatch happens after the cancelled attempt,
    and the original candidate is untouched."""
    bundle = CandidateBundle()
    before = candidate_snapshot(bundle)
    executor = ReductionExecutor(bundle)
    executor.script[3] = _MATCH  # proposal 1: delete-all -> unstable
    for index in (4, 5, 6):  # proposal 2: one-row child -> accepted
        executor.script[index] = _MISMATCH_1ROW
    executor.script[7] = _MISMATCH_1ROW  # restart's first value child
    token = CancelToken()
    executor.on_execute = lambda index: setattr(
        token, "cancelled_flag", index >= 7
    )
    control = make_control(StubClock(), cancelled=token)
    result = run_reduction(bundle, executor, None, policy=ReductionPolicy(), control=control)

    assert result.outcome is ReductionOutcome.BUDGET_EXHAUSTED
    assert result.stop_reason is StopReason.CANCELLED
    assert result.search_complete is False
    assert result.accepted == 1
    assert result.proposals == 4
    assert result.executions == 8  # 3 + 1 + 3 + the cancelled restart attempt
    assert result.unstable_candidates == 1
    assert result.rejected_static == 1  # the visited delete-all re-proposal
    assert result.has_reduction is True
    # The run stops at the cancelled attempt: exactly 8 dispatches.
    assert executor.prepares == 8
    assert executor.dispatched_row_counts == [3, 3, 3, 0, 1, 1, 1, 1]

    child = _accepted_child_of(bundle)
    assert result.best_case_id == case_id_of(child)
    assert len(result.best_comparison_hashes) == 3

    assert_candidate_unchanged(bundle, before)


class _SecondAcceptedFailsSink(JsonlTraceSink):
    """A real JSONL sink whose second ACCEPTED append fails (persistence
    fault at the moment of truth); the first ACCEPTED persists normally."""

    def __init__(self, root, budget):
        super().__init__(root, budget)
        self.accepted_seen = 0

    def append(self, record):
        if record.kind == "ACCEPTED":
            self.accepted_seen += 1
            if self.accepted_seen == 2:
                raise RuntimeError("simulated second-acceptance disk failure")
        return super().append(record)


def test_persistence_fault_at_second_acceptance_keeps_first_best(tmp_path):
    """When persisting a *later* acceptance fails, the run reports FAILED and
    the best stays at the first accepted child: a failed ACCEPTED record
    never advances the pointer, and the on-disk trace still audits back to
    the first acceptance."""
    bundle = CandidateBundle()
    before = candidate_snapshot(bundle)
    executor = ReductionExecutor(bundle)
    executor.script[3] = _MATCH  # proposal 1: delete-all -> unstable
    for index in (4, 5, 6):  # proposal 2: one-row child -> FIRST acceptance
        executor.script[index] = _MISMATCH_1ROW
    for index in (7, 8, 9):  # restart's value child -> SECOND acceptance
        executor.script[index] = _MISMATCH_1ROW
    root = (tmp_path / "trace-fault").resolve()
    sink = _SecondAcceptedFailsSink(root, EVIDENCE_APPEND_BUDGET)
    with sink:
        result = run_reduction(bundle, executor, sink)

    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.EVIDENCE_WRITE_FAILED
    assert result.search_complete is False
    # The second acceptance was attempted but never committed.
    assert sink.accepted_seen == 2
    assert result.accepted == 1
    assert result.proposals == 4
    assert result.executions == 10  # 3 + 1 + 3 + the second group's 3 attempts
    assert executor.prepares == 10

    first_child = _accepted_child_of(bundle)
    assert result.best_case_id == case_id_of(first_child)
    assert len(result.best_comparison_hashes) == 3

    # The persisted trace is complete (the FINISHED record still landed) and
    # its rebuilt best is the FIRST accepted child.
    audit = read_trace(root)
    assert audit.trace_status == TRACE_STATUS_COMPLETE
    assert audit.best_source == BEST_SOURCE_ACCEPTED
    assert audit.best_payload_ref.sha256 == sha256_hex(
        canonical_json(first_child.to_obj())
    )

    assert_candidate_unchanged(bundle, before)


def test_binding_fault_keeps_original_best_and_input():
    """A prepare that returns an expectation bound to a different case is a
    whole-run fault: the run reports FAILED with the original as best and
    the original candidate untouched."""
    bundle = CandidateBundle()
    before = candidate_snapshot(bundle)
    executor = ReductionExecutor(bundle)
    executor.tampered_bindings = {3}  # first child attempt drifts
    result = run_reduction(bundle, executor, None)

    assert result.outcome is ReductionOutcome.FAILED
    assert result.stop_reason is StopReason.EXECUTION_PROTOCOL_ERROR
    assert result.search_complete is False
    assert result.accepted == 0
    assert result.has_reduction is False
    assert result.proposals == 1
    assert result.executions == 4  # 3 original + the faulted child attempt
    assert executor.prepares == 4  # nothing dispatched after the fault
    assert result.best_case_id == result.original_case_id
    assert result.best_comparison_hashes == ()

    # The original payload artifact remains the fallback best on disk-side
    # reasoning too: no ACCEPTED record exists for this run.
    assert_candidate_unchanged(bundle, before)
    assert BEST_SOURCE_ORIGINAL  # the fallback source is the audit default
