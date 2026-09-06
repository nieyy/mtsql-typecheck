"""G03: rejection, retry-exhaustion and tool-error tests (design 6.4.1).

Expectations are hand-written from the design constants (the 10^12 SUM
budget, the 8-attempt cap, the 1 MiB payload budget); none of them are
computed by calling the generator.
"""

from __future__ import annotations

import dataclasses

import pytest

from mtsql_typecheck.contracts.case import (
    CaseBundle,
    CheckStatus,
    ContractError,
    DecimalType,
    IndexVariant,
    IntegerValue,
    DecimalValue,
    NullValue,
    OrdinalReceipt,
    Profile,
    Rows,
    RuleSelector,
    TemplateId,
    TypeFamily,
    normalize_row_pairs,
)
from mtsql_typecheck.generation.generator import (
    GenerationRejection,
    GeneratorInvariantError,
    ProfileError,
    default_profile,
    generate_case,
    generate_cases,
    profile_hash,
    resolve_combinations,
    validate_profile,
)
from mtsql_typecheck.generation.validation import StaticValidationError
from mtsql_typecheck.rules.exact_numeric import check_q3_sum_budget
from mtsql_typecheck.rules.registry import UnknownRuleError

# Design 6.2.2 "SUM protection": hand-written frozen budget constant.
SUM_ABS_BUDGET = 10**12


def _profile(**overrides: object) -> Profile:
    values: dict[str, object] = {
        "rules": (RuleSelector("mysql80.decimal-widen", 1),),
        "templates": (TemplateId.Q3,),
        "index_variants": (IndexVariant.NONE,),
        "row_count": 1024,
        "predicate_atoms": 1,
        "attempts_per_ordinal": 8,
        "max_payload_bytes": 1024 * 1024,
        "max_bundle_bytes": 256 * 1024 * 1024,
    }
    values.update(overrides)
    return Profile(**values)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Q3: bounded construction then independent absolute-sum verification
# --------------------------------------------------------------------------


def test_q3_tight_budget_output_passes_handwritten_sum_check() -> None:
    """row_count=1024 makes the per-value budget share as tight as allowed.

    Every emitted payload must satisfy, checked by hand against the frozen
    10^12 constant: (a) the sum of absolute coefficients of all non-NULL
    rows is <= 10^12 * 10^scale, and (b) each row's |coefficient| stays
    within the construction share floor(10^12 * 10^scale / n) that the
    generator intersected its sampling domain with.
    """
    result = generate_cases(_profile(), 42, 60)  # N=3 combos x 20 visits
    assert result.status.value == "COMPLETE"
    assert result.rejected == 0
    assert result.emitted_occurrences == 60
    assert len(result.bundles) == result.unique_cases

    checked = 0
    for bundle in result.bundles:
        payload = bundle.payload
        assert payload.query.template_id is TemplateId.Q3
        scale = payload.b_type.scale
        limit = SUM_ABS_BUDGET * 10**scale
        rows = payload.rows.rows
        total = 0
        for row in rows:
            value = row.value
            if isinstance(value, NullValue):
                continue
            assert isinstance(value, DecimalValue)
            total += abs(value.coefficient)
        assert total <= limit, f"sum {total} exceeds handwritten budget {limit}"
        n = len(rows)
        if n:
            share = limit // n
            for row in rows:
                value = row.value
                if isinstance(value, DecimalValue):
                    assert abs(value.coefficient) <= share
        # Cross-check: the independent exact-numeric check agrees (SATISFIED),
        # and cancellation cannot evade the budget because absolute values are
        # summed -- a payload with the same total but signed values is still
        # measured by its absolute coefficients here.
        result_check = check_q3_sum_budget(payload.rows, scale, SUM_ABS_BUDGET)
        assert result_check.status is CheckStatus.SATISFIED
        checked += 1
    assert checked == len(result.bundles) == result.unique_cases


# --------------------------------------------------------------------------
# Retry exhaustion: foreseeable construction failures are final rejections
# --------------------------------------------------------------------------


def test_retry_exhaustion_rejects_ordinal_after_all_attempts() -> None:
    profile = default_profile()
    profile_hash_hex = profile_hash(profile)

    def hook(ordinal: int, retry_index: int, payload: object):
        if ordinal == 2:
            return None  # every attempt of this ordinal fails
        return payload

    rejected = generate_case(profile, profile_hash_hex, 42, 2, attempt_hook=hook)
    assert isinstance(rejected, OrdinalReceipt)
    assert rejected.outcome.value == "rejected"
    assert rejected.case_id is None
    assert rejected.retry_count == profile.attempts_per_ordinal == 8
    assert rejected.reason == "attempt_hook_injected_rejection"

    # Other ordinals are unaffected and still emitted.
    for ordinal in (0, 1, 3, 4):
        outcome = generate_case(profile, profile_hash_hex, 42, ordinal, attempt_hook=hook)
        assert isinstance(outcome, CaseBundle)
        assert outcome.provenance.retry == 0


def test_exhausted_ordinal_does_not_shift_other_ordinals() -> None:
    """Rejecting ordinal 2 after 8 attempts leaves every other ordinal
    byte-identical to its un-injected result: no combination swap, no
    schedule shift."""
    profile = default_profile()
    profile_hash_hex = profile_hash(profile)
    baseline = {}
    for ordinal in range(5):
        outcome = generate_case(profile, profile_hash_hex, 42, ordinal)
        assert isinstance(outcome, CaseBundle)
        baseline[ordinal] = outcome

    def hook(ordinal: int, retry_index: int, payload: object):
        return None if ordinal == 2 else payload

    for ordinal in range(5):
        outcome = generate_case(profile, profile_hash_hex, 42, ordinal, attempt_hook=hook)
        if ordinal == 2:
            assert isinstance(outcome, OrdinalReceipt)
            assert outcome.outcome.value == "rejected"
        else:
            assert isinstance(outcome, CaseBundle)
            assert outcome.to_obj() == baseline[ordinal].to_obj()


# --------------------------------------------------------------------------
# Invalid candidates are tool errors, never rejections
# --------------------------------------------------------------------------


def _relation_tamper_hook(target_ordinal: int):
    def hook(ordinal: int, retry_index: int, payload):
        if ordinal != target_ordinal:
            return payload
        # Declare a wrong per-column family relation: structurally legal
        # payload, but independent relation re-derivation must reject it.
        bad_relation = dataclasses.replace(
            payload.relation,
            columns=tuple(
                dataclasses.replace(column, a_family=TypeFamily.DECIMAL,
                                    b_family=TypeFamily.DECIMAL)
                for column in payload.relation.columns
            ),
        )
        return dataclasses.replace(payload, relation=bad_relation)

    return hook


def _rows_tamper_hook(target_ordinal: int):
    def hook(ordinal: int, retry_index: int, payload):
        if ordinal != target_ordinal:
            return payload
        # Kind-correct but out-of-every-domain value: construction-grade
        # payload that the independent value-domain check must reject.
        if isinstance(payload.a_type, DecimalType):
            value = DecimalValue(10**70, payload.a_type.scale)
        else:
            value = IntegerValue(10**70)
        rows = Rows(normalize_row_pairs([(1, value)]))
        return dataclasses.replace(payload, rows=rows)

    return hook


@pytest.mark.parametrize("hook_factory", [_relation_tamper_hook, _rows_tamper_hook])
def test_invalid_candidate_raises_generator_invariant_error(hook_factory) -> None:
    profile = default_profile()
    profile_hash_hex = profile_hash(profile)
    ordinal = 2
    with pytest.raises(GeneratorInvariantError) as excinfo:
        generate_case(
            profile, profile_hash_hex, 42, ordinal, attempt_hook=hook_factory(ordinal)
        )
    error = excinfo.value
    assert error.ordinal == ordinal
    assert error.check is not None
    assert error.check.status.value == "INVALID"
    # The tool error is not a retryable receipt: nothing was returned.
    # (generate_case raised instead of returning OrdinalReceipt.)


def test_static_validation_error_wraps_the_invalid_check() -> None:
    """The invariant error chain keeps the independent StaticValidationError."""
    profile = default_profile()
    profile_hash_hex = profile_hash(profile)
    with pytest.raises(GeneratorInvariantError) as excinfo:
        generate_case(
            profile,
            profile_hash_hex,
            42,
            2,
            attempt_hook=_relation_tamper_hook(2),
        )
    assert isinstance(excinfo.value.__cause__, StaticValidationError)


# --------------------------------------------------------------------------
# Payload budget exhaustion
# --------------------------------------------------------------------------


def test_payload_budget_exceeded_rejects_every_ordinal() -> None:
    profile = _profile(max_payload_bytes=64)  # hard-cap floor is 1; 64 is legal
    result = generate_cases(profile, 42, 4)
    assert result.status.value == "PARTIAL"
    assert result.emitted_occurrences == 0
    assert result.rejected == 4
    assert result.attempted_candidates == 4 * profile.attempts_per_ordinal
    assert len(result.receipts) == 4
    for receipt in result.receipts:
        assert receipt.outcome.value == "rejected"
        assert receipt.retry_count == profile.attempts_per_ordinal
        assert receipt.reason is not None
        assert receipt.reason.startswith("payload_budget_exceeded")
    # Conservation holds with zero successful cases (never a fake pass).
    assert result.requested == (
        result.emitted_occurrences
        + result.rejected
        + result.interrupted
        + result.not_attempted
    )
    assert len(result.rejections) == 4
    assert all(
        isinstance(rejection, GenerationRejection) for rejection in result.rejections
    )


# --------------------------------------------------------------------------
# Profile selection rejections
# --------------------------------------------------------------------------


def test_profile_rejects_zero_combination_selection() -> None:
    # Q4 is not allowed by the decimal-widen rule, so this selector yields
    # zero combinations and must be rejected, not silently emptied.
    profile = _profile(templates=(TemplateId.Q4,))
    with pytest.raises(ProfileError, match="zero combinations"):
        resolve_combinations(profile)
    with pytest.raises(ProfileError):
        validate_profile(profile)


def test_profile_rejects_unknown_rule_version() -> None:
    profile = _profile(rules=(RuleSelector("mysql80.decimal-widen", 2),))
    with pytest.raises(UnknownRuleError):
        resolve_combinations(profile)
    with pytest.raises((ProfileError, UnknownRuleError)):
        validate_profile(profile)


def test_profile_rejects_unknown_rule_id() -> None:
    profile = _profile(rules=(RuleSelector("mysql80.nope", 1),))
    with pytest.raises(UnknownRuleError):
        resolve_combinations(profile)


def test_profile_rejects_duplicate_selectors_and_over_cap_budgets() -> None:
    with pytest.raises(ContractError):
        Profile(
            rules=(
                RuleSelector("mysql80.decimal-widen", 1),
                RuleSelector("mysql80.decimal-widen", 1),
            ),
            templates=(TemplateId.Q3,),
            index_variants=(IndexVariant.NONE,),
            row_count=32,
            predicate_atoms=1,
            attempts_per_ordinal=8,
            max_payload_bytes=1024 * 1024,
            max_bundle_bytes=256 * 1024 * 1024,
        )
    with pytest.raises(ContractError):
        _profile(row_count=2000)  # hard cap is 1024
    with pytest.raises(ContractError):
        _profile(attempts_per_ordinal=9)  # hard cap is 8


def test_validate_profile_accepts_default_profile() -> None:
    validate_profile(default_profile())


# --------------------------------------------------------------------------
# Cancellation conserves attribution
# --------------------------------------------------------------------------


def test_cancellation_keeps_completed_ordinals_and_conserves_counts() -> None:
    profile = default_profile()
    calls = {"n": 0}

    def should_cancel() -> bool:
        calls["n"] += 1
        return calls["n"] > 4

    result = generate_cases(profile, 42, 50, should_cancel=should_cancel)
    assert result.status.value == "ABORTED"
    assert len(result.receipts) == 4
    assert result.not_attempted == 46
    assert result.interrupted == 0
    assert result.requested == (
        result.emitted_occurrences
        + result.rejected
        + result.interrupted
        + result.not_attempted
    )
