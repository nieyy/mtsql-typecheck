"""C02 contract tests: D2 oracle models, codecs and frozen invariants.

Golden policy hashes below were produced once with plain ``hashlib`` +
``json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`` on the
frozen default policy objects (no project imports) and are never recomputed by
the code under test.
"""

from __future__ import annotations

import re

import pytest

from mtsql_typecheck.contracts import oracle
from mtsql_typecheck.contracts.case import ContractError
from mtsql_typecheck.contracts.oracle import (
    ATTEMPT_BUDGET_MS,
    CANCEL_GRACE_MS,
    COMPARISON_DEADLINE_MS,
    COMPARISON_SCHEMA_VERSION,
    EVIDENCE_APPEND_HARD_CAP,
    MAX_RESULT_BYTES,
    MAX_RESULT_COLUMNS,
    MAX_RESULT_ROWS,
    MAX_RESULT_SCALE,
    MAX_TRACE_META_BYTES,
    REDUCTION_HARD_MAX_EXECUTIONS,
    REDUCTION_HARD_MAX_PROPOSALS,
    REDUCTION_HARD_TOTAL_BUDGET_MS,
    REDUCTION_MAX_EXECUTIONS,
    REDUCTION_MAX_PROPOSALS,
    REDUCTION_TOTAL_BUDGET_MS,
    REPLAY_ATTEMPTS,
    REPLAY_TOTAL_BUDGET_MS,
    TRACE_RECORD_KINDS,
    WITNESS_LIMIT,
    ArtifactRef,
    Comparison,
    ComparisonBudget,
    ComparisonCounts,
    ComparisonReason,
    ComparisonStatus,
    InputFailure,
    PersistedReceipt,
    ReductionOutcome,
    ReductionPolicy,
    ReductionResult,
    ReplayOutcome,
    ReplayPolicy,
    ReplayResult,
    StopReason,
    TraceRecord,
    WitnessEntry,
    decode_comparison,
    decode_witness_entry,
    dump_comparison,
    dump_input_failure,
    dump_reduction_result,
    dump_replay_result,
    dump_trace_record,
    load_comparison,
    load_input_failure,
    load_reduction_result,
    load_replay_result,
    load_trace_record,
)

try:  # parallel work item; tests below degrade gracefully when absent
    from mtsql_typecheck.contracts import execution as _execution
except ImportError:  # pragma: no cover - depends on branch state
    _execution = None

requires_execution = pytest.mark.skipif(
    _execution is None, reason="contracts/execution.py not available yet"
)


def _hx(byte: int) -> str:
    """Deterministic lowercase 64-hex string for fixtures."""
    return f"{byte:02x}" * 32


def _append_field(doc: bytes, snippet: bytes) -> bytes:
    assert doc.endswith(b"}")
    return doc[:-1] + b"," + snippet + b"}"


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------


def _counts(**overrides) -> ComparisonCounts:
    params = dict(a_rows=3, b_rows=3, a_distinct=3, b_distinct=3, matched_rows=3)
    params.update(overrides)
    return ComparisonCounts(**params)


def _witness() -> tuple[WitnessEntry, ...]:
    # key is the full row key: a 1-tuple of value keys for single-column rows.
    return (
        WitnessEntry((("number", "7", 0),), 2, 1, 1),
        WitnessEntry((("null",),), 0, 1, -1),
    )


def _comparison(**overrides) -> Comparison:
    params = dict(
        case_id=_hx(0x01),
        request_hash=_hx(0x02),
        expectation_hash=_hx(0x03),
        execution_hash=_hx(0x04),
        runtime_check_hash=_hx(0x05),
        status=ComparisonStatus.MISMATCH_CANDIDATE,
        reasons=(ComparisonReason.RESULT_INCOMPLETE,),
        comparable=True,
        counts=_counts(),
        witness=_witness(),
        witness_truncated=False,
        exact_signature=_hx(0x06),
        fingerprint=_hx(0x07),
    )
    params.update(overrides)
    return Comparison(**params)


def _inconclusive(**overrides) -> Comparison:
    overrides.setdefault(
        "reasons", (ComparisonReason.QUERY_NOT_COMPLETE, ComparisonReason.CANCELLED)
    )
    for name, value in (
        ("status", ComparisonStatus.INCONCLUSIVE),
        ("comparable", False),
        ("counts", None),
        ("witness", None),
        ("witness_truncated", False),
        ("exact_signature", None),
        ("fingerprint", None),
    ):
        overrides.setdefault(name, value)
    return _comparison(**overrides)


def _match(**overrides) -> Comparison:
    for name, value in (
        ("status", ComparisonStatus.MATCH),
        ("comparable", True),
        ("witness", None),
        ("witness_truncated", False),
        ("exact_signature", None),
        ("fingerprint", None),
    ):
        overrides.setdefault(name, value)
    return _comparison(**overrides)


def _replay(**overrides) -> ReplayResult:
    params = dict(
        comparison_hash=_hx(0x10),
        policy_hash=ReplayPolicy().policy_hash(),
        attempt_hashes=(_hx(0xA1), _hx(0xA2), _hx(0xA3)),
        requested=3,
        completed=3,
        comparable=3,
        matching_signature=3,
        exact_signatures=(_hx(0xB1),) * 3,
        outcome=ReplayOutcome.REPRODUCED,
        stop_reason=StopReason.REPLAY_COMPLETE,
        operational_failure=False,
        synthetic=False,
    )
    params.update(overrides)
    return ReplayResult(**params)


def _reduction(**overrides) -> ReductionResult:
    params = dict(
        reduction_id="rid-1",
        outcome=ReductionOutcome.REDUCED,
        stop_reason=StopReason.SEARCH_EXHAUSTED,
        original_case_id=_hx(0x01),
        original_comparison_hash=_hx(0x10),
        original_fingerprint=_hx(0x07),
        best_case_id=_hx(0x02),
        best_comparison_hashes=(_hx(0x20), _hx(0x21), _hx(0x22)),
        has_reduction=True,
        search_complete=True,
        proposals=10,
        executions=6,
        accepted=1,
        rejected_static=2,
        inconclusive_candidates=1,
        unstable_candidates=0,
        synthetic=False,
    )
    params.update(overrides)
    return ReductionResult(**params)


def _failure(**overrides) -> InputFailure:
    params = dict(
        code="CONTRACT_ERROR",
        input_ref="runs/r1/case.json",
        detail="unknown field 'x' in case payload",
        trusted_case_id=_hx(0x01),
    )
    params.update(overrides)
    return InputFailure(**params)


def _chain() -> tuple[TraceRecord, TraceRecord]:
    first = TraceRecord(seq=1, kind="START", inline={"run": "r1"})
    second = TraceRecord(
        seq=2,
        kind="EVIDENCE",
        payload_ref=ArtifactRef("files/" + _hx(0x30) + ".json", 128, _hx(0x31), 1),
        prev_hash=first.hash,
    )
    return first, second


# --------------------------------------------------------------------------
# Comparison: status-dependent field matrix
# --------------------------------------------------------------------------


def test_comparison_all_four_statuses_construct_and_derive_hash():
    mismatch = _comparison()
    match = _match()
    inconclusive = _inconclusive()
    not_applicable = _inconclusive(
        status=ComparisonStatus.NOT_APPLICABLE,
        reasons=(ComparisonReason.RULE_DISABLED,),
    )
    for comparison in (mismatch, match, inconclusive, not_applicable):
        assert len(comparison.hash) == 64 and comparison.hash == comparison.hash.lower()
    assert mismatch.hash != match.hash != inconclusive.hash


def test_inconclusive_rejects_comparable_only_fields():
    with pytest.raises(ContractError, match="counts"):
        _inconclusive(counts=_counts())
    with pytest.raises(ContractError, match="witness"):
        _inconclusive(witness=_witness())
    with pytest.raises(ContractError, match="exact_signature"):
        _inconclusive(exact_signature=_hx(0x06))
    with pytest.raises(ContractError, match="fingerprint"):
        _inconclusive(fingerprint=_hx(0x07))
    with pytest.raises(ContractError, match="witness_truncated"):
        _inconclusive(witness_truncated=True)


def test_non_comparable_requires_reasons():
    for status in (ComparisonStatus.INCONCLUSIVE, ComparisonStatus.NOT_APPLICABLE):
        with pytest.raises(ContractError, match="reason"):
            _inconclusive(status=status, reasons=())


def test_mismatch_candidate_requires_signature_and_fingerprint():
    with pytest.raises(ContractError, match="exact_signature"):
        _comparison(exact_signature=None)
    with pytest.raises(ContractError, match="fingerprint"):
        _comparison(fingerprint=None)


def test_match_forbids_witness_and_mismatch_fields():
    with pytest.raises(ContractError, match="witness"):
        _match(witness=_witness())
    with pytest.raises(ContractError, match="witness_truncated"):
        _match(witness_truncated=True)
    with pytest.raises(ContractError, match="exact_signature"):
        _match(exact_signature=_hx(0x06))
    with pytest.raises(ContractError, match="fingerprint"):
        _match(fingerprint=_hx(0x07))


def test_comparable_flag_must_follow_status():
    with pytest.raises(ContractError, match="comparable"):
        _comparison(comparable=False, status=ComparisonStatus.MISMATCH_CANDIDATE)
    with pytest.raises(ContractError, match="comparable"):
        _inconclusive(comparable=True)


def test_comparison_schema_and_oracle_version_frozen():
    with pytest.raises(ContractError, match="schema_version"):
        _comparison(schema_version=2)
    with pytest.raises(ContractError, match="oracle_version"):
        _comparison(oracle_version="o2")


def test_reasons_reject_unknown_codes_and_non_tuples():
    with pytest.raises(ContractError, match="ComparisonReason"):
        _comparison(reasons=("BOGUS_REASON",))
    with pytest.raises(ContractError, match="tuple"):
        _comparison(reasons=[ComparisonReason.CANCELLED])


def test_reason_dedup_is_caller_responsibility():
    # Frozen spec: the caller records reasons in gate order and dedupes; the
    # model must not silently rewrite them.
    duplicated = (ComparisonReason.CANCELLED, ComparisonReason.CANCELLED)
    comparison = _inconclusive(reasons=duplicated)
    assert comparison.reasons == duplicated
    assert len(comparison.reasons) == 2


def test_witness_limit_is_enforced():
    entries = tuple(WitnessEntry((("number", str(i), 0),), 1, 0, 1) for i in range(1, 21))
    _comparison(witness=entries)  # exactly WITNESS_LIMIT is legal
    with pytest.raises(ContractError, match="over limit"):
        _comparison(witness=entries + (WitnessEntry((("null",),), 1, 0, 1),))


@pytest.mark.parametrize(
    "key",
    [
        (("number", "007", 0),),          # non-canonical text
        (("number", "", 0),),             # empty text
        (("number", "1", 66),),           # scale over 65
        (("number", "1", -1),),           # negative scale
        (("number", "1"),),               # wrong arity
        (("number", "1", 0, "extra"),),   # wrong arity
        (("string", "x"),),               # unknown first element
        (("null", "extra"),),             # null takes no payload
        ((0,),),                          # non-str first element
        (("null",), "number", "1", 0),    # flat value key, not a row key
        (("null",), ()),                  # empty value key inside the row key
        (),                               # empty row key
    ],
)
def test_witness_key_shape_is_validated(key):
    with pytest.raises(ContractError):
        WitnessEntry(key, 1, 0, 1)


def test_witness_key_accepts_multicolumn_row_key_and_persists_it():
    # Design 6.2.2: the witness key is the ordered array of per-column value
    # keys, so multi-column differing rows are witnessed like any other.
    row_key = (("null",), ("number", "9007199254740993", 0))
    entry = WitnessEntry(row_key, 2, 1, 1)
    assert entry.to_obj() == {
        "key": [["null"], ["number", "9007199254740993", 0]],
        "a_count": 2,
        "b_count": 1,
        "diff": 1,
    }
    restored = decode_witness_entry(entry.to_obj())
    assert restored == entry


def test_witness_entry_counts_and_diff():
    WitnessEntry((("null",),), 3, 1, 2)
    WitnessEntry((("number", "-12", 2),), 0, 5, -5)
    with pytest.raises(ContractError, match="diff"):
        WitnessEntry((("null",),), 3, 1, 1)  # diff != a - b
    with pytest.raises(ContractError, match="non-zero"):
        WitnessEntry((("null",),), 3, 3, 0)
    with pytest.raises(ContractError, match="a_count"):
        WitnessEntry((("null",),), -1, 0, -1)
    with pytest.raises(ContractError, match="b_count"):
        WitnessEntry((("null",),), 0, True, 0)  # bool never counts as int


def test_comparison_counts_reject_negative_and_bool():
    with pytest.raises(ContractError, match="a_rows"):
        _counts(a_rows=-1)
    with pytest.raises(ContractError, match="must be an int"):
        _counts(matched_rows=True)


# --------------------------------------------------------------------------
# Comparison: content hash
# --------------------------------------------------------------------------


def test_comparison_hash_is_deterministic_and_excludes_itself():
    assert _comparison().hash == _comparison().hash
    assert _match().hash == _match().hash
    changed = _comparison(
        witness=(
            WitnessEntry((("number", "7", 0),), 2, 1, 1),
            WitnessEntry((("null",),), 1, 0, 1),
        )
    )
    assert changed.hash != _comparison().hash
    # An explicit matching hash is accepted; a tampered one is rejected.
    template = _comparison()
    assert _comparison(hash=template.hash).hash == template.hash
    with pytest.raises(ContractError, match="does not match"):
        _comparison(hash=_hx(0xEE))


# --------------------------------------------------------------------------
# Comparison: strict loader
# --------------------------------------------------------------------------


def test_comparison_roundtrip_bytes_are_stable():
    for comparison in (_comparison(), _match(), _inconclusive()):
        first = dump_comparison(comparison)
        restored = load_comparison(first)
        assert restored == comparison
        assert dump_comparison(restored) == first


def test_comparison_loader_accepts_parsed_dict():
    comparison = _comparison()
    assert decode_comparison(comparison.to_obj()) == comparison


def test_comparison_loader_rejects_unknown_fields():
    doc = _append_field(dump_comparison(_comparison()), b'"extra":1')
    with pytest.raises(ContractError, match="unknown fields"):
        load_comparison(doc)


def test_comparison_loader_rejects_duplicate_keys():
    doc = _append_field(
        dump_comparison(_comparison()), b'"case_id":"' + _hx(0x01).encode() + b'"'
    )
    with pytest.raises(ContractError, match="duplicate"):
        load_comparison(doc)


def test_comparison_loader_rejects_float_and_bool_in_integer_positions():
    doc = dump_comparison(_comparison())
    assert b'"a_rows":3' in doc
    with pytest.raises(ContractError, match="float"):
        load_comparison(doc.replace(b'"a_rows":3', b'"a_rows":3.0'))
    with pytest.raises(ContractError, match="JSON integer"):
        load_comparison(doc.replace(b'"a_rows":3', b'"a_rows":true'))


def test_comparison_loader_rejects_unknown_status_reason_and_bad_hash():
    doc = dump_comparison(_comparison())
    with pytest.raises(ContractError, match="unknown value"):
        load_comparison(doc.replace(b'"status":"MISMATCH_CANDIDATE"', b'"status":"BUG"'))
    assert b'"RESULT_INCOMPLETE"' in doc
    with pytest.raises(ContractError, match="unknown value"):
        load_comparison(doc.replace(b'"RESULT_INCOMPLETE"', b'"NO_SUCH_REASON"'))
    match = re.search(rb'"hash":"([0-9a-f]{64})"', doc)
    assert match is not None
    tampered = doc.replace(match.group(1), b"ff" + match.group(1)[2:])
    with pytest.raises(ContractError, match="does not match"):
        load_comparison(tampered)


def test_load_rejects_non_text_input():
    with pytest.raises(ContractError, match="expects bytes or str"):
        load_comparison(123)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# InputFailure
# --------------------------------------------------------------------------


def test_input_failure_constructs_and_roundtrips():
    failure = _failure()
    assert failure.status is ComparisonStatus.INCONCLUSIVE
    assert failure.schema_version == COMPARISON_SCHEMA_VERSION
    restored = load_input_failure(dump_input_failure(failure))
    assert restored == failure
    assert dump_input_failure(restored) == dump_input_failure(failure)


def test_input_failure_status_is_frozen_to_inconclusive():
    with pytest.raises(ContractError, match="INCONCLUSIVE"):
        _failure(status=ComparisonStatus.MATCH)


def test_input_failure_field_validation():
    with pytest.raises(ContractError, match="code"):
        _failure(code="")
    with pytest.raises(ContractError, match="input_ref"):
        _failure(input_ref="")
    with pytest.raises(ContractError, match="detail"):
        _failure(detail="")
    with pytest.raises(ContractError, match="64-hex"):
        _failure(trusted_case_id="deadbeef")
    assert _failure(trusted_case_id=None).trusted_case_id is None
    with pytest.raises(ContractError, match="unknown fields"):
        load_input_failure(dump_input_failure(_failure())[:-1] + b',"x":1}')


# --------------------------------------------------------------------------
# ReplayResult
# --------------------------------------------------------------------------


def test_replay_result_reproduced_constructs_and_roundtrips():
    result = _replay()
    assert result.hash == _replay().hash
    restored = load_replay_result(dump_replay_result(result))
    assert restored == result
    assert dump_replay_result(restored) == dump_replay_result(result)


def test_replay_count_chain_must_be_monotonic():
    # matching_signature <= comparable <= completed <= requested
    with pytest.raises(ContractError, match="matching_signature <= comparable"):
        _replay(
            outcome=ReplayOutcome.UNSTABLE,
            comparable=2,
            matching_signature=3,
            exact_signatures=(_hx(0xB1),) * 2,
        )
    with pytest.raises(ContractError, match="matching_signature <= comparable"):
        _replay(
            outcome=ReplayOutcome.UNSTABLE,
            completed=2,
            comparable=3,
            exact_signatures=(_hx(0xB1),) * 3,
        )
    with pytest.raises(ContractError, match="matching_signature <= comparable"):
        _replay(
            outcome=ReplayOutcome.UNSTABLE,
            requested=2,
            completed=3,
            attempt_hashes=(_hx(0xA1), _hx(0xA2)),
        )


def test_replay_attempt_hashes_must_match_requested():
    with pytest.raises(ContractError, match="attempt_hashes length"):
        _replay(attempt_hashes=(_hx(0xA1), _hx(0xA2)))


def test_replay_exact_signatures_track_comparable():
    with pytest.raises(ContractError, match="exact_signatures length"):
        _replay(exact_signatures=(_hx(0xB1),) * 2)


def test_replay_reproduced_requires_three_matching_attempts():
    with pytest.raises(ContractError, match="REPRODUCED"):
        _replay(matching_signature=2)
    with pytest.raises(ContractError, match="REPRODUCED"):
        _replay(
            requested=2,
            completed=2,
            comparable=2,
            matching_signature=2,
            attempt_hashes=(_hx(0xA1), _hx(0xA2)),
            exact_signatures=(_hx(0xB1), _hx(0xB2)),
        )
    with pytest.raises(ContractError, match="operational"):
        _replay(operational_failure=True)


def test_replay_not_replayed_dispatches_nothing():
    result = _replay(
        attempt_hashes=(),
        requested=0,
        completed=0,
        comparable=0,
        matching_signature=0,
        exact_signatures=(),
        outcome=ReplayOutcome.NOT_REPLAYED,
        stop_reason=StopReason.NO_EXECUTOR,
    )
    assert result.attempt_hashes == () and result.requested == 0
    with pytest.raises(ContractError, match="NOT_REPLAYED"):
        _replay(
            outcome=ReplayOutcome.NOT_REPLAYED,
            stop_reason=StopReason.INVALID_CANDIDATE,
        )


def test_replay_unstable_partial_group_is_legal():
    result = _replay(
        attempt_hashes=(_hx(0xA1), _hx(0xA2)),
        requested=2,
        completed=2,
        comparable=1,
        matching_signature=1,
        exact_signatures=(_hx(0xB1),),
        outcome=ReplayOutcome.UNSTABLE,
        stop_reason=StopReason.TIME_BUDGET,
    )
    assert result.outcome is ReplayOutcome.UNSTABLE


def test_replay_field_validation():
    with pytest.raises(ContractError, match="requested"):
        _replay(requested=-1)
    with pytest.raises(ContractError, match="must be an int"):
        _replay(requested=True)
    with pytest.raises(ContractError, match="64-hex"):
        _replay(attempt_hashes=("zz",) * 3)
    with pytest.raises(ContractError, match="ReplayOutcome"):
        _replay(outcome="REPRODUCED")  # raw string, not the enum
    with pytest.raises(ContractError, match="does not match"):
        _replay(hash=_hx(0xEE))
    with pytest.raises(ContractError, match="unknown fields"):
        doc = _append_field(dump_replay_result(_replay()), b'"x":1')
        load_replay_result(doc)
    float_doc = dump_replay_result(_replay())
    assert b'"requested":3' in float_doc
    with pytest.raises(ContractError, match="float"):
        load_replay_result(float_doc.replace(b'"requested":3', b'"requested":3.0'))


# --------------------------------------------------------------------------
# ReductionResult
# --------------------------------------------------------------------------


def test_reduction_result_reduced_constructs_and_roundtrips():
    result = _reduction()
    assert result.has_reduction and result.best_case_id != result.original_case_id
    restored = load_reduction_result(dump_reduction_result(result))
    assert restored == result
    assert dump_reduction_result(restored) == dump_reduction_result(result)


def test_reduction_unchanged_constructs_and_roundtrips():
    result = _reduction(
        outcome=ReductionOutcome.UNCHANGED,
        stop_reason=StopReason.SEARCH_EXHAUSTED,
        original_fingerprint=None,
        best_case_id=_hx(0x01),
        best_comparison_hashes=(),
        has_reduction=False,
    )
    restored = load_reduction_result(dump_reduction_result(result))
    assert restored == result


def test_reduction_has_reduction_iff_best_differs_from_original():
    with pytest.raises(ContractError, match="if and only if"):
        _reduction(best_case_id=_hx(0x01))  # equal to original but has_reduction=True
    with pytest.raises(ContractError, match="if and only if"):
        _reduction(
            outcome=ReductionOutcome.FAILED,
            stop_reason=StopReason.ORIGINAL_NOT_REPRODUCED,
            best_case_id=_hx(0x02),
            has_reduction=False,
            search_complete=False,
        )


def test_reduction_outcome_and_has_reduction_agree():
    with pytest.raises(ContractError, match="REDUCED"):
        _reduction(has_reduction=False, best_case_id=_hx(0x01), best_comparison_hashes=())
    with pytest.raises(ContractError, match="UNCHANGED"):
        _reduction(outcome=ReductionOutcome.UNCHANGED, stop_reason=StopReason.SEARCH_EXHAUSTED)


def test_reduction_search_complete_only_for_reduced_or_unchanged():
    for outcome in (ReductionOutcome.FAILED, ReductionOutcome.BUDGET_EXHAUSTED):
        with pytest.raises(ContractError, match="search_complete"):
            _reduction(outcome=outcome, search_complete=True)
    _reduction(
        outcome=ReductionOutcome.FAILED,
        stop_reason=StopReason.ORIGINAL_NOT_REPRODUCED,
        has_reduction=False,
        best_case_id=_hx(0x01),
        best_comparison_hashes=(),
        search_complete=False,
    )
    _reduction(
        outcome=ReductionOutcome.BUDGET_EXHAUSTED,
        stop_reason=StopReason.PROPOSAL_BUDGET,
        has_reduction=False,
        best_case_id=_hx(0x01),
        best_comparison_hashes=(),
        search_complete=False,
    )


def test_reduction_best_comparison_hashes_match_has_reduction():
    with pytest.raises(ContractError, match="three child comparisons"):
        _reduction(best_comparison_hashes=(_hx(0x20), _hx(0x21)))
    with pytest.raises(ContractError, match="three child comparisons"):
        _reduction(
            outcome=ReductionOutcome.FAILED,
            stop_reason=StopReason.CANCELLED,
            has_reduction=False,
            best_case_id=_hx(0x01),
            best_comparison_hashes=(_hx(0x20),),
            search_complete=False,
        )


def test_reduction_field_validation():
    with pytest.raises(ContractError, match="proposals"):
        _reduction(proposals=-1)
    with pytest.raises(ContractError, match="must be an int"):
        _reduction(executions=True)
    with pytest.raises(ContractError, match="reduction_id"):
        _reduction(reduction_id="")
    with pytest.raises(ContractError, match="ReductionOutcome"):
        _reduction(outcome="REDUCED")
    with pytest.raises(ContractError, match="does not match"):
        _reduction(hash=_hx(0xEE))
    with pytest.raises(ContractError, match="unknown fields"):
        load_reduction_result(
            _append_field(dump_reduction_result(_reduction()), b'"x":1')
        )


# --------------------------------------------------------------------------
# Policies
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field, low, high",
    [
        ("deadline_ms", 1, COMPARISON_DEADLINE_MS),
        ("max_rows", 1, MAX_RESULT_ROWS),
        ("max_bytes", 1, MAX_RESULT_BYTES),
        ("max_columns", 1, MAX_RESULT_COLUMNS),
        ("witness_limit", 1, WITNESS_LIMIT),
    ],
)
def test_comparison_budget_bounds_are_hard_limits(field, low, high):
    with pytest.raises(ContractError, match=field):
        ComparisonBudget(**{field: low - 1})
    with pytest.raises(ContractError, match=field):
        ComparisonBudget(**{field: high + 1})
    ComparisonBudget(**{field: low})
    ComparisonBudget(**{field: high})


def test_comparison_budget_rejects_bool():
    with pytest.raises(ContractError, match="must be an int"):
        ComparisonBudget(deadline_ms=True)


def test_replay_policy_attempts_is_frozen_to_three():
    with pytest.raises(ContractError, match="frozen"):
        ReplayPolicy(attempts=2)
    with pytest.raises(ContractError, match="frozen"):
        ReplayPolicy(attempts=4)
    with pytest.raises(ContractError, match="total_budget_ms"):
        ReplayPolicy(total_budget_ms=0)
    with pytest.raises(ContractError, match="total_budget_ms"):
        ReplayPolicy(total_budget_ms=REPLAY_TOTAL_BUDGET_MS + 1)
    with pytest.raises(ContractError, match="attempt_budget_ms"):
        ReplayPolicy(attempt_budget_ms=ATTEMPT_BUDGET_MS + 1)
    with pytest.raises(ContractError, match="cancel_grace_ms"):
        ReplayPolicy(cancel_grace_ms=CANCEL_GRACE_MS + 1)
    ReplayPolicy(cancel_grace_ms=0)  # zero grace is a legal lower bound


def test_reduction_policy_bounds_are_hard_limits():
    with pytest.raises(ContractError, match="max_proposals"):
        ReductionPolicy(max_proposals=REDUCTION_HARD_MAX_PROPOSALS + 1)
    with pytest.raises(ContractError, match="max_proposals"):
        ReductionPolicy(max_proposals=0)
    with pytest.raises(ContractError, match="max_executions"):
        ReductionPolicy(max_executions=REDUCTION_HARD_MAX_EXECUTIONS + 1)
    with pytest.raises(ContractError, match="max_executions"):
        ReductionPolicy(max_executions=0)
    with pytest.raises(ContractError, match="total_budget_ms"):
        ReductionPolicy(total_budget_ms=REDUCTION_HARD_TOTAL_BUDGET_MS + 1)
    with pytest.raises(ContractError, match="evidence_append_budget"):
        ReductionPolicy(evidence_append_budget=EVIDENCE_APPEND_HARD_CAP + 1)
    with pytest.raises(ContractError, match="evidence_append_budget"):
        ReductionPolicy(evidence_append_budget=0)
    assert ReductionPolicy().replay_policy() == ReplayPolicy(
        attempts=REPLAY_ATTEMPTS,
        total_budget_ms=REPLAY_TOTAL_BUDGET_MS,
        attempt_budget_ms=ATTEMPT_BUDGET_MS,
        cancel_grace_ms=CANCEL_GRACE_MS,
    )


def test_policy_hash_matches_frozen_golden_vectors():
    # Vectors computed once with plain hashlib + json.dumps over the canonical
    # default policy objects; independent of the code under test.
    assert (
        ReplayPolicy().policy_hash()
        == "8dbe4c8e57be42625c619da43055cdc43c0f297c88f626d2e5f2ed2630b5b3b5"
    )
    assert (
        ReductionPolicy().policy_hash()
        == "355697e3bfd679e2569847e50bfa539746ba1795d219e3959ae8b02f176a6b61"
    )
    # Distinct settings produce a distinct, still-stable hash.
    changed = ReplayPolicy(total_budget_ms=REPLAY_TOTAL_BUDGET_MS - 1)
    assert changed.policy_hash() != ReplayPolicy().policy_hash()
    assert changed.policy_hash() == ReplayPolicy(
        total_budget_ms=REPLAY_TOTAL_BUDGET_MS - 1
    ).policy_hash()
    assert REDUCTION_MAX_PROPOSALS == 200
    assert REDUCTION_MAX_EXECUTIONS == 120
    assert REDUCTION_TOTAL_BUDGET_MS == 600_000
    assert MAX_RESULT_SCALE == 65
    assert WITNESS_LIMIT == 20
    assert REPLAY_ATTEMPTS == 3


# --------------------------------------------------------------------------
# Trace records, artifact refs, receipts
# --------------------------------------------------------------------------


def test_trace_chain_constructs_from_seq_one():
    first, second = _chain()
    assert first.prev_hash == "0" * 64
    assert second.prev_hash == first.hash
    assert first.hash != second.hash
    # Hash covers content only: same content, same hash.
    assert first.hash == TraceRecord(seq=1, kind="START", inline={"run": "r1"}).hash


def test_trace_seq_one_requires_zero_prev_hash():
    with pytest.raises(ContractError, match="seq 1"):
        TraceRecord(seq=1, kind="START", prev_hash=_hx(0x41))
    with pytest.raises(ContractError, match="seq"):
        TraceRecord(seq=0, kind="START")


@pytest.mark.parametrize("kind", sorted(TRACE_RECORD_KINDS))
def test_trace_kind_whitelist(kind):
    assert TraceRecord(seq=1, kind=kind).kind == kind
    with pytest.raises(ContractError, match="kind"):
        TraceRecord(seq=1, kind="OTHER")
    with pytest.raises(ContractError, match="kind"):
        PersistedReceipt(seq=1, kind="OTHER", record_hash=_hx(0x42))


def test_trace_inline_size_and_shape_limits():
    TraceRecord(seq=1, kind="START", inline={"k": "v"})
    # {"pad":"X"*(N)} canonicalizes to 10 + N bytes; N = limit - 10 is exact.
    exact = {"pad": "x" * (MAX_TRACE_META_BYTES - 10)}
    assert TraceRecord(seq=1, kind="START", inline=exact) is not None
    with pytest.raises(ContractError, match="exceeds"):
        TraceRecord(seq=1, kind="START", inline={"pad": "x" * MAX_TRACE_META_BYTES})
    with pytest.raises(ContractError, match="dict"):
        TraceRecord(seq=1, kind="START", inline=["not", "a", "dict"])
    with pytest.raises(ContractError, match="float"):
        TraceRecord(seq=1, kind="START", inline={"k": 0.5})
    deep: dict = {"leaf": 1}
    for _ in range(40):
        deep = {"n": deep}
    with pytest.raises(ContractError, match="depth"):
        TraceRecord(seq=1, kind="START", inline=deep)


def test_trace_payload_ref_validation():
    with pytest.raises(ContractError, match="ArtifactRef"):
        TraceRecord(seq=1, kind="EVIDENCE", payload_ref="files/x.json")
    record = TraceRecord(
        seq=1,
        kind="EVIDENCE",
        payload_ref=ArtifactRef("files/abc.json", 1, _hx(0x43), 1),
    )
    restored = load_trace_record(dump_trace_record(record))
    assert restored == record


def test_trace_hash_tamper_is_rejected():
    record = TraceRecord(seq=1, kind="START", inline={"a": 1})
    assert record.hash == TraceRecord(seq=1, kind="START", inline={"a": 1}).hash
    changed = TraceRecord(seq=1, kind="START", inline={"a": 2})
    assert changed.hash != record.hash
    with pytest.raises(ContractError, match="does not match"):
        TraceRecord(seq=1, kind="START", inline={"a": 1}, hash=_hx(0xEE))


def test_trace_record_roundtrip_and_loader_rejections():
    first, second = _chain()
    for record in (first, second):
        doc = dump_trace_record(record)
        restored = load_trace_record(doc)
        assert restored == record
        assert dump_trace_record(restored) == doc
    doc = dump_trace_record(first)
    with pytest.raises(ContractError, match="unknown fields"):
        load_trace_record(_append_field(doc, b'"x":1'))
    with pytest.raises(ContractError, match="duplicate"):
        load_trace_record(_append_field(doc, b'"seq":1'))
    with pytest.raises(ContractError, match="JSON integer"):
        load_trace_record(doc.replace(b'"seq":1', b'"seq":true'))


@pytest.mark.parametrize(
    "path",
    [
        "/abs/path.json",
        "../escape.json",
        "a/../b.json",
        "a//b.json",
        "./x.json",
        "back\\slash.json",
        "",
    ],
)
def test_artifact_ref_path_rules(path):
    with pytest.raises(ContractError):
        ArtifactRef(path, 1, _hx(0x43), 1)


def test_artifact_ref_field_rules():
    ArtifactRef("files/abc.json", 0, _hx(0x43), 1)  # empty file is legal
    with pytest.raises(ContractError, match="size_bytes"):
        ArtifactRef("files/abc.json", -1, _hx(0x43), 1)
    with pytest.raises(ContractError, match="64-hex"):
        ArtifactRef("files/abc.json", 1, "nothex", 1)
    with pytest.raises(ContractError, match="schema_version"):
        ArtifactRef("files/abc.json", 1, _hx(0x43), 0)
    with pytest.raises(ContractError, match="must be an int"):
        ArtifactRef("files/abc.json", 1, _hx(0x43), True)


def test_persisted_receipt_validation():
    receipt = PersistedReceipt(seq=1, kind="ACCEPTED", record_hash=_hx(0x44))
    assert receipt.to_obj() == {"seq": 1, "kind": "ACCEPTED", "record_hash": _hx(0x44)}
    with pytest.raises(ContractError, match="seq"):
        PersistedReceipt(seq=0, kind="ACCEPTED", record_hash=_hx(0x44))
    with pytest.raises(ContractError, match="64-hex"):
        PersistedReceipt(seq=1, kind="ACCEPTED", record_hash="xyz")


# --------------------------------------------------------------------------
# CandidateInput
#
# The execution model types are resolved by a deferred import inside
# CandidateInput.__post_init__.  For the shape-validation tests we register a
# minimal stub module under the real module name; when contracts/execution.py
# lands, the separate real-construction test below exercises the actual types.
# --------------------------------------------------------------------------


class _StubAttemptRequest:
    pass


class _StubAttemptExpectation:
    pass


class _StubExecutionEvidence:
    pass


@pytest.fixture
def stub_execution_module(monkeypatch):
    import sys
    import types

    module = types.ModuleType("mtsql_typecheck.contracts.execution")
    module.AttemptRequest = _StubAttemptRequest
    module.AttemptExpectation = _StubAttemptExpectation
    module.ExecutionEvidence = _StubExecutionEvidence
    monkeypatch.setitem(sys.modules, "mtsql_typecheck.contracts.execution", module)
    return module


def _stub_candidate(**overrides):
    params = dict(
        payload=_minimal_payload(),
        request=_StubAttemptRequest(),
        expectation=_StubAttemptExpectation(),
        evidence=_StubExecutionEvidence(),
        comparison_hash=_hx(0x50),
        source="original",
    )
    params.update(overrides)
    return oracle.CandidateInput(**params)


def test_candidate_input_accepts_execution_shaped_models(stub_execution_module):
    bundle = _stub_candidate()
    assert bundle.source == "original"
    assert bundle.comparison_hash == _hx(0x50)


def test_candidate_input_rejects_non_execution_models(stub_execution_module):
    with pytest.raises(ContractError, match="request"):
        _stub_candidate(request=object())
    with pytest.raises(ContractError, match="expectation"):
        _stub_candidate(expectation=object())
    with pytest.raises(ContractError, match="evidence"):
        _stub_candidate(evidence=object())


def test_candidate_input_rejects_bad_reference_and_source(stub_execution_module):
    with pytest.raises(ContractError, match="comparison_hash"):
        _stub_candidate(comparison_hash="nothex")
    with pytest.raises(ContractError, match="source"):
        _stub_candidate(source="")
    with pytest.raises(ContractError, match="payload"):
        _stub_candidate(payload="not-a-payload")


@requires_execution
def test_candidate_input_accepts_real_execution_models():
    try:
        bundle = _candidate()
    except (TypeError, AttributeError) as exc:  # pragma: no cover - moving API
        pytest.skip(f"execution model constructors not settled yet: {exc}")
    assert bundle.source == "original"
    assert bundle.request.payload == bundle.payload


# --------------------------------------------------------------------------
# Cross-module constant agreement with contracts/execution.py
# --------------------------------------------------------------------------


@pytest.mark.skipif(_execution is None, reason="contracts/execution.py not available yet")
def test_budget_constants_match_execution_module():
    # oracle.py duplicates the execution-side design 6.4.5 constants on
    # purpose; the two copies must never drift.  Replay/reduction/trace
    # budgets are oracle-side only and stay out of the shared set.
    shared = [
        "MAX_RESULT_ROWS",
        "MAX_RESULT_BYTES",
        "MAX_RESULT_COLUMNS",
        "MAX_EVIDENCE_BYTES",
        "ATTEMPT_BUDGET_MS",
        "CANCEL_GRACE_MS",
        "MAX_SCALAR_TEXT_CHARS",
        "MAX_RESULT_SCALE",
    ]
    for name in shared:
        assert getattr(_execution, name) == getattr(oracle, name), name


# --------------------------------------------------------------------------
# Shared helpers for execution-backed tests (defined lazily on purpose)
# --------------------------------------------------------------------------


def _minimal_payload():
    from mtsql_typecheck.contracts.case import (
        CasePayload,
        ColumnSpec,
        EnvironmentRequirements,
        IndexVariant,
        IntegerValue,
        QuerySpec,
        RelationMode,
        ResultColumnSpec,
        ResultRelationSpec,
        Row,
        Rows,
        RuleRef,
        SemverIdentity,
        SignedIntegerType,
        SignedIntName,
        TableSpec,
        TemplateId,
        TypeFamily,
        ValueEquivalence,
        NullPolicy,
        NullValue,
        REQUIRED_SQL_MODE_TOKENS,
    )

    return CasePayload(
        rule=RuleRef("mysql80.signed-widen", 1),
        a_type=SignedIntegerType(SignedIntName.TINYINT),
        b_type=SignedIntegerType(SignedIntName.SMALLINT),
        table=TableSpec(
            "t0",
            (
                ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
                ColumnSpec("v", SignedIntegerType(SignedIntName.TINYINT), True),
            ),
            ("rid",),
            IndexVariant.NONE,
        ),
        rows=Rows((Row(1, IntegerValue(1)), Row(2, NullValue()))),
        query=QuerySpec(TemplateId.Q1),
        relation=ResultRelationSpec(
            RelationMode.MULTISET_EXACT,
            (
                ResultColumnSpec(
                    "c0",
                    TypeFamily.SIGNED_INTEGER,
                    TypeFamily.SIGNED_INTEGER,
                    ValueEquivalence.EXACT_NUMERIC,
                    NullPolicy.PRESERVE,
                ),
            ),
        ),
        environment=EnvironmentRequirements(
            "mysql80",
            "innodb",
            "same-instance",
            REQUIRED_SQL_MODE_TOKENS,
            "utf8mb4",
            "utf8mb4_bin",
            "+00:00",
        ),
        generator=SemverIdentity("g1", "1"),
        renderer=SemverIdentity("r1", "1"),
    )


def _candidate():
    """Build a CandidateInput from real execution models (skips on drift).

    The exact constructor surface of contracts/execution.py is being finalized
    in parallel; if the keyword surface moved, this test skips instead of
    failing on an unrelated contract.
    """
    from mtsql_typecheck.contracts.case import (
        ExpectedBinding,
        NameMap,
        ObservedEnvironment,
    )

    payload = _minimal_payload()
    from mtsql_typecheck.contracts.codec import case_id_of

    name_map = NameMap("db_a", "db_b", "t_a", "t_b")
    environment = ObservedEnvironment(
        instance_identity="i1",
        version="8.0.0",
        vendor="mysql",
        build_id="b1",
        engine="innodb",
        sql_mode_tokens=("NO_ENGINE_SUBSTITUTION", "ONLY_FULL_GROUP_BY", "STRICT_ALL_TABLES"),
        character_set="utf8mb4",
        collation="utf8mb4_bin",
        time_zone="+00:00",
        optimizer_switch="",
    )
    binding = ExpectedBinding(
        run_id="run-1",
        case_id=case_id_of(payload),
        attempt_id="attempt-1",
        environment_hash=_hx(0x60),
        name_map_hash=_hx(0x61),
    )
    request = _execution.AttemptRequest(
        run_id="run-1",
        attempt_id="attempt-1",
        payload=payload,
        target_environment=environment,
        session_profile=_execution.SessionProfile(
            True, _execution.TransactionIsolation.REPEATABLE_READ
        ),
        execution_order=_execution.ExecutionOrder.AB,
        result_row_budget=MAX_RESULT_ROWS,
        result_byte_budget=MAX_RESULT_BYTES,
        time_budget_ms=ATTEMPT_BUDGET_MS,
        synthetic=True,
    )
    expectation = _execution.AttemptExpectation(
        binding=binding,
        request_hash=request.request_hash,
        codec_version="c1",
        execution_order=_execution.ExecutionOrder.AB,
        name_map=name_map,
    )
    evidence = _execution.ExecutionEvidence(
        request_hash=request.request_hash,
        expectation=expectation,
        runtime_facts=None,
        setup_diagnostics=(),
        actual_execution_order=_execution.ExecutionOrder.AB,
        a_context=None,
        b_context=None,
        a_query=None,
        b_query=None,
        isolation_receipt=None,
        terminal=None,
        failure=None,
        preflight_rejection=None,
        synthetic=True,
    )
    return oracle.CandidateInput(
        payload=payload,
        request=request,
        expectation=expectation,
        evidence=evidence,
        comparison_hash=_hx(0x50),
        source="original",
    )
