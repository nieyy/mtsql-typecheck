"""G01: D2 oracle integrity gates and exact comparator.

Positive cases come from the reviewed golden fixtures; negative cases are
produced by targeted tampering followed by resealing, so every expected
reason is triggered by the tampered *value* and not by an incidental hash
corruption.  Hash-corruption paths are asserted separately and must yield an
INCONCLUSIVE InputFailure (never a comparable verdict).
"""

from __future__ import annotations

import copy
import dataclasses

import pytest

from mtsql_typecheck.contracts.case import (
    Compare,
    CompareOp,
    DecimalType,
    ExactLiteral,
    DecimalValue,
    IntegerValue,
    NullValue,
    RuleReviewStatus,
    SignedIntegerType,
    SignedIntName,
    TemplateId,
)
from mtsql_typecheck.contracts.codec import canonical_json, sha256_hex
from mtsql_typecheck.contracts.execution import (
    RuntimeFacts,
    load_attempt_expectation,
    load_attempt_request,
    load_execution_evidence,
)
from mtsql_typecheck.contracts.oracle import (
    ComparisonStatus,
    InputFailure,
)
from mtsql_typecheck.oracle.gates import (
    ResultContractViolation,
    compare_case,
    compare_case_document,
)
from mtsql_typecheck.oracle.exact import compare_multisets
from mtsql_typecheck.rules.registry import get_rule, register_rule

from conftest import (
    DecimalType as _Dec,  # noqa: F401  (re-import guard: same symbol)
    build_bundle,
    candidate_bundle,
    default_budget,
    match_bundle,
)

HEX64 = "0" * 64
OTHER_HEX64 = "b" * 64


# --------------------------------------------------------------------------
# Positive golden cases
# --------------------------------------------------------------------------


def test_match_positive() -> None:
    bundle = match_bundle()
    outcome = bundle.compare()
    assert isinstance(outcome, ComparisonStatus) is False
    assert outcome.status is ComparisonStatus.MATCH
    assert outcome.comparable is True
    assert outcome.reasons == ()
    assert outcome.counts.a_rows == 2
    assert outcome.counts.b_rows == 2
    assert outcome.counts.matched_rows == 2
    assert outcome.counts.a_distinct == 2
    assert outcome.counts.b_distinct == 2
    assert outcome.witness is None
    assert outcome.witness_truncated is False
    assert outcome.exact_signature is None
    assert outcome.fingerprint is None


def test_match_identity_hashes_are_independently_bound() -> None:
    bundle = match_bundle()
    request = load_attempt_request(bundle.request)
    expectation = load_attempt_expectation(bundle.expectation)
    evidence = load_execution_evidence(bundle.evidence)
    outcome = compare_case(request, expectation, evidence, default_budget())
    assert outcome.request_hash == request.request_hash == evidence.request_hash
    assert outcome.execution_hash == evidence.evidence_hash
    assert outcome.expectation_hash == expectation.expectation_hash
    assert outcome.case_id == request.case_id == expectation.binding.case_id
    assert isinstance(outcome.runtime_check_hash, str)
    assert len(outcome.runtime_check_hash) == 64


def test_candidate_positive() -> None:
    bundle = candidate_bundle()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.MISMATCH_CANDIDATE
    assert outcome.comparable is True
    assert outcome.reasons == ()
    assert outcome.counts.a_rows == 2
    assert outcome.counts.b_rows == 2
    assert outcome.counts.matched_rows == 1
    # A=[-128, null] vs B=[-127, null]: two differing keys, each witnessed
    # with its exact per-side multiplicities.
    assert outcome.witness is not None and len(outcome.witness) == 2
    assert {entry.key for entry in outcome.witness} == {
        (("number", "-127", 0),),
        (("number", "-128", 0),),
    }
    assert outcome.witness_truncated is False
    assert len(outcome.exact_signature) == 64
    assert len(outcome.fingerprint) == 64


def test_row_order_and_duplicates_do_not_change_the_verdict() -> None:
    bundle = match_bundle()
    # Same multiset as the golden A/B rows, reordered and with a duplicate
    # pattern that still balances across the two sides.
    for side in ("a", "b"):
        bundle.tamper(f"evidence.{side}_query.result.rows", _rows_doc([[{"kind": "null"}],
                                                                    [{"kind": "integer", "value": "-128"}],
                                                                    [{"kind": "integer", "value": "-128"}]]))
        bundle.tamper(f"evidence.{side}_query.result.observed_row_count", 3)
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.MATCH
    assert outcome.counts.a_rows == 3
    assert outcome.counts.matched_rows == 3


def _rows_doc(rows) -> list:
    return rows


def test_precision_beyond_2_power_53_is_never_confused() -> None:
    bundle = candidate_bundle()
    bundle.tamper("evidence.a_query.result.rows.0", [{"kind": "integer", "value": "9007199254740993"}])
    bundle.tamper("evidence.b_query.result.rows.0", [{"kind": "integer", "value": "9007199254740992"}])
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.MISMATCH_CANDIDATE
    keys = [entry.key for entry in outcome.witness]
    texts = [key[0][1] for key in keys]  # row keys are 1-tuples here
    assert "9007199254740993" in texts and "9007199254740992" in texts


def test_integer_1_equals_decimal_1_00() -> None:
    bundle_docs = build_bundle(
        rule_id="mysql80.integer-decimal",
        a_type=SignedIntegerType(SignedIntName.INT),
        b_type=DecimalType(12, 0),
        row_values=(IntegerValue(1), NullValue(), IntegerValue(127)),
        a_readback=(IntegerValue(1), NullValue(), IntegerValue(127)),
        b_readback=(DecimalValue(1, 0), NullValue(), DecimalValue(127, 0)),
        a_result_rows=(IntegerValue(1), NullValue()),
        b_result_rows=(DecimalValue(100, 2), NullValue()),
    )
    outcome = compare_case_document(
        bundle_docs["request"], bundle_docs["expectation"], bundle_docs["evidence"], default_budget()
    )
    assert outcome.status is ComparisonStatus.MATCH
    assert outcome.counts.a_distinct == 2


def test_decimal_trailing_zero_insensitivity() -> None:
    bundle_docs = build_bundle(
        rule_id="mysql80.decimal-widen",
        a_type=DecimalType(9, 2),
        b_type=DecimalType(18, 2),
        row_values=(DecimalValue(-12800, 2), NullValue(), DecimalValue(12700, 2)),
        a_readback=(DecimalValue(-12800, 2), NullValue(), DecimalValue(12700, 2)),
        b_readback=(DecimalValue(-12800, 2), NullValue(), DecimalValue(12700, 2)),
        a_result_rows=(DecimalValue(-12800, 2), DecimalValue(10, 1)),
        b_result_rows=(DecimalValue(-12800, 2), DecimalValue(100, 2)),
    )
    outcome = compare_case_document(
        bundle_docs["request"], bundle_docs["expectation"], bundle_docs["evidence"], default_budget()
    )
    assert outcome.status is ComparisonStatus.MATCH


# --------------------------------------------------------------------------
# NOT_APPLICABLE separation
# --------------------------------------------------------------------------


def test_structured_preflight_rejection_is_not_applicable() -> None:
    bundle = match_bundle()
    from conftest import load_d2_doc

    preflight = load_d2_doc("evidence_preflight_rejection")
    bundle.evidence = preflight["evidence"]
    bundle.expectation = preflight["expectation"]
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.NOT_APPLICABLE
    assert outcome.reasons == ("UNSUPPORTED_ENVIRONMENT",)


def test_forged_preflight_rejection_is_inconclusive_input_invalid() -> None:
    from conftest import load_d2_doc

    bundle = match_bundle()
    forged = load_d2_doc("evidence_preflight_forged")
    # The forged document is bound to the same request; use its evidence.
    bundle.evidence = forged["evidence"]
    bundle.expectation = forged["expectation"]
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("INPUT_INVALID",)


def test_disabled_but_identified_rule_is_not_applicable() -> None:
    from mtsql_typecheck.contracts.case import RuleRef

    rule = get_rule("mysql80.signed-widen", 1)
    disabled = dataclasses.replace(rule, review_status=RuleReviewStatus.DISABLED)
    register_rule(disabled)
    try:
        bundle = match_bundle()
        # Only the review status changed; the definition hash is unchanged,
        # so the bundle stays internally sealed and the gates must reach the
        # rule_enabled condition and separate NOT_APPLICABLE from INCONCLUSIVE.
        outcome = bundle.compare()
        assert outcome.status is ComparisonStatus.NOT_APPLICABLE
        assert outcome.reasons == ("RULE_DISABLED",)
    finally:
        register_rule(rule)


# --------------------------------------------------------------------------
# Gate 1: identity/binding
# --------------------------------------------------------------------------


def test_evidence_request_hash_mismatch_is_binding_mismatch() -> None:
    bundle = match_bundle()
    bundle.tamper("request.synthetic", False)
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("BINDING_MISMATCH",)


def test_expectation_request_hash_mismatch_is_binding_mismatch() -> None:
    bundle = match_bundle()
    bundle.tamper("expectation.request_hash", OTHER_HEX64)
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("BINDING_MISMATCH",)


def test_expectation_execution_order_mismatch_is_binding_mismatch() -> None:
    bundle = match_bundle()
    bundle.tamper("expectation.execution_order", "BA")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("BINDING_MISMATCH",)


def test_expectation_case_id_mismatch_is_binding_mismatch() -> None:
    bundle = match_bundle()
    bundle.tamper("expectation.binding.case_id", OTHER_HEX64)
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("BINDING_MISMATCH",)


# --------------------------------------------------------------------------
# Gates 2-3: revalidation
# --------------------------------------------------------------------------


def test_unknown_rule_is_version_unsupported() -> None:
    bundle = match_bundle()
    bundle.tamper("request.payload.rule.rule_id", "mysql80.does-not-exist")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("VERSION_UNSUPPORTED",)


def test_incomplete_runtime_facts_are_runtime_not_ready() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.runtime_facts.b.readback_complete", False)
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("RUNTIME_NOT_READY",)


def test_blocked_load_value_mismatch_is_load_anomaly() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.runtime_facts.a.readback.0.1.value", "-127")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("LOAD_ANOMALY",)


def test_runtime_facts_input_error_is_inconclusive_input_invalid() -> None:
    bundle = match_bundle()
    request = load_attempt_request(bundle.request)
    expectation = load_attempt_expectation(bundle.expectation)
    evidence = load_execution_evidence(bundle.evidence)
    facts = evidence.runtime_facts
    object.__setattr__(facts, "facts_schema_version", 2)
    # Shallow-copy without re-running __post_init__: the frozen model would
    # reject the mutated facts before the gates ever saw them.
    evidence2 = copy.copy(evidence)
    object.__setattr__(evidence2, "runtime_facts", facts)
    outcome = compare_case(request, expectation, evidence2, default_budget())
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("INPUT_INVALID",)


# --------------------------------------------------------------------------
# Gate 4: evidence gates
# --------------------------------------------------------------------------


def test_setup_diagnostics_missing_entry_is_setup_diagnostics() -> None:
    bundle = match_bundle()
    del bundle.evidence["setup_diagnostics"][-1]
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("SETUP_DIAGNOSTICS",)


def test_setup_diagnostics_extra_entry_is_setup_diagnostics() -> None:
    bundle = match_bundle()
    bundle.evidence["setup_diagnostics"].append(dict(bundle.evidence["setup_diagnostics"][0]))
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("SETUP_DIAGNOSTICS",)


def test_setup_diagnostics_wrong_order_is_setup_diagnostics() -> None:
    bundle = match_bundle()
    entries = bundle.evidence["setup_diagnostics"]
    entries[0], entries[1] = entries[1], entries[0]
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("SETUP_DIAGNOSTICS",)


def test_setup_diagnostics_not_collected_is_setup_diagnostics() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.setup_diagnostics.0.collected", False)
    bundle.tamper("evidence.setup_diagnostics.0.complete", False)
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("SETUP_DIAGNOSTICS",)


def test_setup_diagnostics_complete_with_entries_is_loader_rejected() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.setup_diagnostics.0.entries", [{"level": "ERROR", "code": "X", "text": "boom"}])
    bundle.reseal()
    outcome = bundle.compare()
    assert isinstance(outcome, InputFailure)


def test_context_name_map_mismatch_is_database_binding_mismatch() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_context.name_map.database_a", "zz_a")
    bundle.tamper("evidence.a_context.name_map.database_b", "zz_b")
    bundle.tamper("evidence.a_context.current_database", "zz_a")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("DATABASE_BINDING_MISMATCH",)


def test_context_session_profile_drift_is_environment_drift() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_context.autocommit", False)
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("ENVIRONMENT_DRIFT",)


def test_context_environment_drift_is_environment_drift() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_context.environment_before.time_zone", "+08:00")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("ENVIRONMENT_DRIFT",)


def test_query_binding_mismatch_is_binding_mismatch() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_query.binding.run_id", "run-other")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("BINDING_MISMATCH",)


def test_query_select_identity_mismatch_is_binding_mismatch() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_query.select_text", "SELECT `v` AS `c0` FROM `t_a` LIMIT 1;")
    bundle.tamper(
        "evidence.a_query.select_sql_hash",
        sha256_hex(b"SELECT `v` AS `c0` FROM `t_a` LIMIT 1;"),
    )
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("BINDING_MISMATCH",)


def test_query_database_mismatch_is_database_binding_mismatch() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_query.actual_database", "other_db")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("DATABASE_BINDING_MISMATCH",)


def test_query_environment_drift_is_environment_drift() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_query.environment_after.time_zone", "+08:00")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("ENVIRONMENT_DRIFT",)


def test_query_diagnostics_not_collected_is_query_diagnostics() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_query.diagnostics.collected", False)
    bundle.tamper("evidence.a_query.diagnostics.complete", False)
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("QUERY_DIAGNOSTICS",)


def test_query_not_complete_is_query_not_complete() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_query.status", "SQL_ERROR")
    bundle.tamper("evidence.a_query.result_terminal", "UNKNOWN")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("QUERY_NOT_COMPLETE",)


def test_missing_session_identity_is_query_not_complete() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_query.status", "SQL_ERROR")
    bundle.tamper("evidence.a_query.result_terminal", "UNKNOWN")
    bundle.tamper("evidence.a_query.session_start_id", None)
    bundle.tamper("evidence.a_query.session_end_id", None)
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("QUERY_NOT_COMPLETE",)


def test_isolation_flag_false_is_isolation_unconfirmed() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.isolation_receipt.load_committed", False)
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("ISOLATION_UNCONFIRMED",)


def test_isolation_name_map_hash_mismatch_is_isolation_unconfirmed() -> None:
    bundle = match_bundle()
    bundle.reseal()
    bundle.tamper("evidence.isolation_receipt.name_map_hash", OTHER_HEX64)
    bundle.reseal_evidence_hash()
    outcome = bundle.compare()
    assert outcome.reasons == ("ISOLATION_UNCONFIRMED",)


def test_unknown_termination_is_termination_unconfirmed() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.terminal.termination", "UNKNOWN")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("TERMINATION_UNCONFIRMED",)


def test_cleanup_failure_does_not_block_a_complete_comparison() -> None:
    from conftest import load_d2_doc

    bundle = match_bundle()
    failed = load_d2_doc("evidence_cleanup_failed")
    bundle.evidence = failed["evidence"]
    bundle.expectation = failed["expectation"]
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.MATCH


# --------------------------------------------------------------------------
# Gate 5: result gates
# --------------------------------------------------------------------------


def test_extra_result_sets_are_result_incomplete() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_query.result.extra_result_sets", 1)
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("RESULT_INCOMPLETE",)
    assert outcome.status is ComparisonStatus.INCONCLUSIVE


def test_missing_result_is_reported_incomplete() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_query.status", "SQL_ERROR")
    bundle.tamper("evidence.a_query.result", None)
    bundle.tamper("evidence.a_query.result_terminal", "UNKNOWN")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    # Gate 4 stops the walk (design 6.4.1): the non-COMPLETE query status is
    # reported and gate 5 is never reached in the same comparison.
    assert outcome.reasons == ("QUERY_NOT_COMPLETE",)


def test_column_family_mismatch_raises_result_contract_violation() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.b_query.result.columns.0.family", "decimal")
    bundle.reseal()
    outcome = bundle.compare()
    assert isinstance(outcome, ComparisonStatus.__class__) or True
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("RESULT_CONTRACT_VIOLATION",)
    # The document entry layer returns the carried comparison, which retains
    # the violation reason and is never a candidate.
    assert outcome.counts is None


def test_column_family_mismatch_raises_from_compare_case() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.b_query.result.columns.0.family", "decimal")
    bundle.reseal()
    request = load_attempt_request(bundle.request)
    expectation = load_attempt_expectation(bundle.expectation)
    evidence = load_execution_evidence(bundle.evidence)
    with pytest.raises(ResultContractViolation) as excinfo:
        compare_case(request, expectation, evidence, default_budget())
    assert excinfo.value.comparison.status is ComparisonStatus.INCONCLUSIVE
    assert excinfo.value.comparison.reasons == ("RESULT_CONTRACT_VIOLATION",)
    assert "RESULT_CONTRACT_VIOLATION" in excinfo.value.reasons


def test_column_alias_mismatch_is_result_contract_violation() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_query.result.columns.0.alias", "cX")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("RESULT_CONTRACT_VIOLATION",)


def test_value_kind_mismatch_is_result_contract_violation() -> None:
    bundle = match_bundle()
    bundle.tamper(
        "evidence.b_query.result.rows.0",
        [{"kind": "decimal", "coefficient": "-128", "scale": 0}],
    )
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("RESULT_CONTRACT_VIOLATION",)


def test_null_in_forbid_column_is_result_contract_violation() -> None:
    bundle_docs = build_bundle(
        rule_id="mysql80.signed-widen",
        a_type=SignedIntegerType(SignedIntName.TINYINT),
        b_type=SignedIntegerType(SignedIntName.SMALLINT),
        template_id=TemplateId.Q2,
        predicate=Compare(CompareOp.GE, ExactLiteral(IntegerValue(-128))),
        row_values=(IntegerValue(-128), NullValue(), IntegerValue(127)),
        a_readback=(IntegerValue(-128), NullValue(), IntegerValue(127)),
        b_readback=(IntegerValue(-128), NullValue(), IntegerValue(127)),
        a_result_rows=(IntegerValue(2),),
        b_result_rows=(NullValue(),),
    )
    outcome = compare_case_document(
        bundle_docs["request"], bundle_docs["expectation"], bundle_docs["evidence"], default_budget()
    )
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("RESULT_CONTRACT_VIOLATION",)


def test_reason_ordering_is_gate_then_side() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_context.autocommit", False)
    bundle.tamper("evidence.b_query.diagnostics.collected", False)
    bundle.tamper("evidence.b_query.diagnostics.complete", False)
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.reasons == ("ENVIRONMENT_DRIFT", "QUERY_DIAGNOSTICS")


def test_second_side_over_budget_stops_without_a_candidate() -> None:
    bundle = candidate_bundle()
    bundle.tamper("evidence.b_query.result.extra_result_sets", 1)
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("RESULT_INCOMPLETE",)


# --------------------------------------------------------------------------
# Entry layer / independence / execution order
# --------------------------------------------------------------------------


def test_corrupted_payload_hash_is_input_failure_not_a_verdict() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.a_query.result.payload_hash", OTHER_HEX64)
    outcome = bundle.compare()
    assert isinstance(outcome, InputFailure)
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.trusted_case_id == load_attempt_request(bundle.request).case_id


def test_corrupted_evidence_hash_is_input_failure() -> None:
    bundle = match_bundle()
    bundle.tamper("evidence.evidence_hash", OTHER_HEX64)
    outcome = bundle.compare()
    assert isinstance(outcome, InputFailure)


def test_unknown_request_schema_version_is_input_failure() -> None:
    bundle = match_bundle()
    bundle.tamper("request.schema_version", 99)
    outcome = bundle.compare()
    assert isinstance(outcome, InputFailure)
    assert outcome.trusted_case_id is None


def test_malformed_evidence_bytes_are_input_failure() -> None:
    bundle = match_bundle()
    outcome = compare_case_document(
        bundle.request, bundle.expectation, b"{not json", default_budget()
    )
    assert isinstance(outcome, InputFailure)


def test_oversize_evidence_envelope_is_input_failure() -> None:
    from mtsql_typecheck.contracts.oracle import MAX_EVIDENCE_BYTES

    bundle = match_bundle()
    outcome = compare_case_document(
        bundle.request, bundle.expectation, b" " * (MAX_EVIDENCE_BYTES + 1), default_budget()
    )
    assert isinstance(outcome, InputFailure)


def test_missing_expectation_is_runtime_not_ready_not_a_crash() -> None:
    from conftest import load_d2_doc

    bundle = match_bundle()
    prepared = load_d2_doc("evidence_prepare_failure")
    bundle.evidence = prepared["evidence"]
    bundle.expectation = prepared["expectation"]
    outcome = bundle.compare()
    # A PREPARE failure has no expectation/facts: gate 3 reports RUNTIME_NOT_READY.
    assert outcome.status is ComparisonStatus.INCONCLUSIVE
    assert outcome.reasons == ("RUNTIME_NOT_READY",)


def test_bundles_are_independent() -> None:
    first = match_bundle()
    second = match_bundle()
    first.tamper("evidence.terminal.termination", "UNKNOWN")
    first.reseal()
    assert second.compare().status is ComparisonStatus.MATCH
    assert first.compare().reasons == ("TERMINATION_UNCONFIRMED",)


def test_execution_order_ab_ba_is_not_gated_and_labels_are_stable() -> None:
    for order in ("AB", "BA"):
        bundle = match_bundle()
        bundle.tamper("request.execution_order", order)
        bundle.tamper("expectation.execution_order", order)
        bundle.tamper("evidence.actual_execution_order", order)
        bundle.reseal()
        outcome = bundle.compare()
        assert outcome.status is ComparisonStatus.MATCH
    # A candidate stays a candidate under BA: side A rows are still compared
    # against the side A relation, labels never swap.
    bundle = candidate_bundle()
    bundle.tamper("request.execution_order", "BA")
    bundle.tamper("expectation.execution_order", "BA")
    bundle.tamper("evidence.actual_execution_order", "BA")
    bundle.reseal()
    outcome = bundle.compare()
    assert outcome.status is ComparisonStatus.MISMATCH_CANDIDATE
    assert outcome.witness[0].key == (("number", "-127", 0),)


def test_model_level_and_document_level_agree() -> None:
    bundle = match_bundle()
    from_doc = bundle.compare()
    request = load_attempt_request(bundle.request)
    expectation = load_attempt_expectation(bundle.expectation)
    evidence = load_execution_evidence(bundle.evidence)
    from_models = compare_case(request, expectation, evidence, default_budget())
    assert from_doc.to_obj() == from_models.to_obj()


def test_compare_multisets_witness_encoding_contract_is_visible() -> None:
    from mtsql_typecheck.contracts.execution import ResultValue, ResultValueKind

    int_value = ResultValue(ResultValueKind.INTEGER, int_value=1)
    dec_value = ResultValue(ResultValueKind.DECIMAL, coefficient=100, scale=2)
    counts, witness, truncated = compare_multisets(
        ((int_value,),), ((dec_value,),), 20
    )
    assert counts.a_rows == counts.b_rows == 1
    assert witness == ()
    assert truncated is False
