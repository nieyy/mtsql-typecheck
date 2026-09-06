"""B01: comparison budget, deadline and cancellation behaviour of the gates.

Budget limits are never clamped (contract 3.4): an over-budget result is an
INCONCLUSIVE RESULT_BUDGET_EXCEEDED for the whole pair — a differing prefix on
an over-budget side must never surface as an early mismatch candidate.
"""

from __future__ import annotations

from mtsql_typecheck.contracts.codec import canonical_json
from mtsql_typecheck.contracts.execution import (
    Control,
    load_attempt_expectation,
    load_attempt_request,
    load_execution_evidence,
)
from mtsql_typecheck.contracts.oracle import ComparisonStatus, MAX_RESULT_ROWS
from mtsql_typecheck.oracle.gates import compare_case, compare_case_document

from conftest import (
    bundle_from_docs,
    build_bundle,
    candidate_bundle,
    default_budget,
    match_bundle,
    IntegerValue,
    SignedIntName,
    SignedIntegerType,
)


def _wide_result_bundle(*, row_count: int, differing: bool = False):
    """A consistent bundle whose observed results carry ``row_count`` rows.

    The payload/readback stays minimal; result rows are observation content
    and are not cross-checked against the payload by the gates, so this
    isolates the result-budget gates at the model limit.  Returns a resealed
    :class:`Bundle`.
    """
    docs = build_bundle(
        rule_id="mysql80.signed-widen",
        a_type=SignedIntegerType(SignedIntName.TINYINT),
        b_type=SignedIntegerType(SignedIntName.SMALLINT),
        row_values=(IntegerValue(0),),
        a_readback=(IntegerValue(0),),
        b_readback=(IntegerValue(0),),
        a_result_rows=(IntegerValue(0),),
        b_result_rows=(IntegerValue(0),),
        result_row_budget=MAX_RESULT_ROWS,
    )
    rows_a = [[{"kind": "integer", "value": str(i)}] for i in range(row_count)]
    rows_b = [[{"kind": "integer", "value": str(i)}] for i in range(row_count)]
    if differing:
        rows_b[-1] = [{"kind": "integer", "value": "-1"}]
    for rows, side in ((rows_a, "a"), (rows_b, "b")):
        docs["evidence"][f"{side}_query"]["result"]["rows"] = rows
        docs["evidence"][f"{side}_query"]["result"]["observed_row_count"] = len(rows)
    bundle = bundle_from_docs(docs)
    bundle.reseal()
    return bundle


def _models(bundle):
    return (
        load_attempt_request(bundle.request),
        load_attempt_expectation(bundle.expectation),
        load_execution_evidence(bundle.evidence),
    )


def test_4096_rows_within_budget_compare_as_match() -> None:
    bundle = _wide_result_bundle(row_count=MAX_RESULT_ROWS)
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.MATCH
    assert outcome.counts.a_rows == MAX_RESULT_ROWS
    assert outcome.counts.matched_rows == MAX_RESULT_ROWS


def test_row_budget_exceeded_is_inconclusive_not_a_candidate() -> None:
    bundle = _wide_result_bundle(row_count=MAX_RESULT_ROWS, differing=True)
    budget = default_budget(max_rows=MAX_RESULT_ROWS - 1)
    outcome = bundle.compare(budget)
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("RESULT_BUDGET_EXCEEDED",)
    assert outcome.counts is None


def test_row_budget_exceeded_on_one_side_stops_the_pair() -> None:
    # Only side B breaches the budget; the whole pair still stops.
    bundle = _wide_result_bundle(row_count=MAX_RESULT_ROWS)
    bundle.evidence["b_query"]["result"]["rows"] = (
        bundle.evidence["b_query"]["result"]["rows"][:-1]
    )
    bundle.evidence["b_query"]["result"]["observed_row_count"] = MAX_RESULT_ROWS - 1
    bundle.reseal()
    budget = default_budget(max_rows=MAX_RESULT_ROWS - 1)
    outcome = bundle.compare(budget)
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("RESULT_BUDGET_EXCEEDED",)


def test_byte_budget_boundary_exactly_at_limit_matches() -> None:
    bundle = match_bundle()
    request, expectation, evidence = _models(bundle)
    sizes = [
        len(canonical_json(query.result.to_obj()))
        for query in (evidence.a_query, evidence.b_query)
    ]
    budget = default_budget(max_bytes=max(sizes))
    outcome = compare_case(request, expectation, evidence, budget)
    assert outcome.status is ComparisonStatus.MATCH


def test_byte_budget_exceeded_is_inconclusive() -> None:
    bundle = match_bundle()
    outcome = bundle.compare(default_budget(max_bytes=1))
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("RESULT_BUDGET_EXCEEDED",)


def test_column_budget_exceeded_is_inconclusive() -> None:
    bundle = match_bundle()
    result = bundle.evidence["a_query"]["result"]
    result["columns"] = [
        result["columns"][0],
        dict(result["columns"][0], ordinal=1, alias="c1"),
    ]
    for row in result["rows"]:
        row.append({"kind": "integer", "value": "0"})
    result["observed_row_count"] = len(result["rows"])
    bundle.reseal()
    outcome = bundle.compare(default_budget(max_columns=1))
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("RESULT_BUDGET_EXCEEDED",)


def test_column_shape_violation_surfaces_once_budget_allows() -> None:
    bundle = match_bundle()
    result = bundle.evidence["a_query"]["result"]
    result["columns"] = [
        result["columns"][0],
        dict(result["columns"][0], ordinal=1, alias="c1"),
    ]
    for row in result["rows"]:
        row.append({"kind": "integer", "value": "0"})
    result["observed_row_count"] = len(result["rows"])
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("RESULT_CONTRACT_VIOLATION",)


def test_expired_deadline_is_comparison_deadline_with_identity() -> None:
    bundle = match_bundle()
    request, expectation, evidence = _models(bundle)
    times = iter([0.0, 10.0])
    control = Control(
        clock=lambda: next(times, 10.0),
        deadline=5.0,
        cancelled=lambda: False,
    )
    outcome = compare_case(request, expectation, evidence, default_budget(), control)
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("COMPARISON_DEADLINE",)
    # Identity is still fully bound even when the deadline stopped the walk.
    assert outcome.case_id == request.case_id
    assert outcome.request_hash == request.request_hash
    assert outcome.execution_hash == evidence.evidence_hash


def test_cooperative_cancellation_is_cancelled() -> None:
    bundle = match_bundle()
    request, expectation, evidence = _models(bundle)
    control = Control(
        clock=lambda: 0.0,
        deadline=None,
        cancelled=lambda: True,
    )
    outcome = compare_case(request, expectation, evidence, default_budget(), control)
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("CANCELLED",)


def test_witness_limit_truncates_after_full_comparison() -> None:
    bundle = candidate_bundle()
    outcome = bundle.compare(default_budget(witness_limit=1))
    assert outcome.status is ComparisonStatus.MISMATCH_CANDIDATE
    # The comparison itself completed: counts cover every row.
    assert outcome.counts.a_rows == 2
    assert outcome.counts.b_rows == 2
    assert outcome.counts.matched_rows == 1
    assert len(outcome.witness) == 1
    assert outcome.witness_truncated is True


def test_witness_limit_at_exact_count_is_not_truncated() -> None:
    bundle = candidate_bundle()
    outcome = bundle.compare(default_budget(witness_limit=2))
    assert len(outcome.witness) == 2
    assert outcome.witness_truncated is False
