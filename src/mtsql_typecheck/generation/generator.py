"""Deterministic pure generator for D1 Phase 3 (design 6.4.1, 6.3.1, 6.6).

Implements the g1 generator: profile expansion/selection, combination
scheduling over ordinals, boundary-dictionary row construction, restricted
predicate/arithmetic generation, independent re-validation before acceptance
and per-ordinal receipts.  Pure functions only: no file, network or database
I/O, no ``random`` module, no clocks, no reliance on ``hash()`` or set
iteration order for anything output-relevant (all orderings come from sorted
ASCII keys or explicit tuples).  Importing this module performs no I/O.

Frozen g1 determinism decisions (design 6.4.1; locked by fixed vectors and
coverage tests, they do not participate in rule validity arguments):

- Combination order is the registry's ASCII ``combo_key`` order.  With
  ``N = len(combinations)``: ``combo_index = ordinal % N``,
  ``visit = ordinal // N`` and ``slot = (visit + combo_index) % 20``.
  Slot 18 emits an empty input (row_count=0), slot 19 an all-NULL input
  (only NULL values), every other slot a normal input.  An explicit
  ``profile.row_count == 0`` makes every ordinal empty.
- Normal rows are placed first from a fixed dictionary in the order
  zero, NULL, +1 unit, -1 unit, duplicate zero, common lower bound, common
  upper bound; inapplicable items are dropped but intentional duplicates are
  kept.  Positions run out -> only the prefix is placed, so a 1-row normal
  case always contains a non-NULL zero.  Q1/Q2 remaining positions then take
  the representable dedup boundaries 2^53-1 / 2^53 / 2^53+1 (when inside the
  common coefficient domain) and the decimal minimal unit (coefficient +/-1
  at the data scale, decimal data with scale > 0 only), then random fill from
  the ``rows`` substream.  Only values actually placed are recorded as
  coverage categories.
- Q3 normal construction intersects the common coefficient domain with
  ``[-floor(10^12 * 10^s / n), floor(10^12 * 10^s / n)]`` (``s`` = data
  scale, 0 for integer data; ``n`` = row count) before dictionary and random
  placement, then independently re-runs ``check_q3_sum_budget`` after the
  static validation: the construction limit never replaces the verification.
- Predicate constants use the full common value domain (not the Q3
  construction domain: constants are not SUM inputs), with the literal kind
  fixed by the rule (integer for signed/integer-decimal rules, same-scale
  decimal for decimal-widen); plain comparisons may use an explicit NULL.
  BETWEEN endpoints are non-NULL, same-kind and ordered lower <= upper.
  Q2 always carries a predicate, Q1 never; Q3/Q4 predicate presence is a
  predicate-substream draw.
- Q4 draws add/subtract and ``k`` from the ``arithmetic`` substream using the
  rule's registered k bounds, then re-checks ``check_bigint_intermediate``
  for every non-NULL value after static validation.

Injection seam: ``generate_case(..., attempt_hook=...)`` where the hook is
``callable(ordinal, retry_index, payload) -> payload | None``.  Returning
``None`` marks the attempt as a foreseeable construction rejection (consumes
one attempt, retryable).  Returning a payload hands the candidate to the
independent validator: a candidate the generator claims complete but whose
independent validation is INVALID is an internal invariant failure and raises
:class:`GeneratorInvariantError` -- it is never swallowed as a rejection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Optional

from mtsql_typecheck.contracts.case import (
    And,
    Arithmetic,
    ArithmeticOp,
    Between,
    CaseBundle,
    CasePayload,
    CheckStatus,
    ColumnSpec,
    Compare,
    CompareOp,
    CompatibilityCheck,
    ContractError,
    DecimalType,
    DecimalValue,
    ExactLiteral,
    ExactValue,
    GenerationManifest,
    GenerationStatus,
    IndexVariant,
    IntegerValue,
    IsNull,
    NullValue,
    Or,
    OrdinalOutcome,
    OrdinalReceipt,
    Profile,
    Projection,
    Provenance,
    Rows,
    RuleRef,
    RuleReviewStatus,
    RuleSelector,
    RuleSpec,
    SignedIntName,
    SignedIntegerType,
    TableSpec,
    TemplateId,
    TypeSpec,
    QuerySpec,
    normalize_row_pairs,
    signed_range,
)
from mtsql_typecheck.contracts.codec import (
    canonical_json,
    case_seed,
    dump_payload,
    sha256_hex,
    substream_block,
    take_from_list,
    take_in_range,
)
from mtsql_typecheck.rules.exact_numeric import (
    check_bigint_intermediate,
    check_q3_sum_budget,
    derive_relation,
)
from mtsql_typecheck.rules.registry import (
    RuleCombo,
    combo_key,
    get_rule,
)
from mtsql_typecheck.generation.render import RENDERER_IDENTITY, render_preview
from mtsql_typecheck.generation.validation import (
    GENERATOR_IDENTITY,
    StaticValidationError,
    static_check_or_raise,
)

__all__ = [
    "GENERATOR_IDENTITY",
    "SLOTS_PER_COMBO",
    "EMPTY_SLOT",
    "ALL_NULL_SLOT",
    "MAX_CASES",
    "AttemptHook",
    "ProfileError",
    "GeneratorInvariantError",
    "ConstructionRejection",
    "GenerationRejection",
    "OrdinalRecord",
    "CaseOccurrence",
    "GenerationResult",
    "default_profile",
    "profile_hash",
    "resolve_combinations",
    "validate_profile",
    "generate_case",
    "generate_cases",
]


class ProfileError(ContractError):
    """Raised when a profile selects an illegal or empty combination set."""


class GeneratorInvariantError(ContractError):
    """The generator built a candidate its independent validation rejected.

    This is a tool error (design 6.4.1 step 6), never a retryable rejection:
    the generator must not retry itself out of its own bugs.  Carries the
    failing ordinal and, when available, the INVALID check object.
    """

    def __init__(
        self,
        message: str,
        *,
        ordinal: int,
        check: Optional[CompatibilityCheck] = None,
    ) -> None:
        super().__init__(message)
        self.ordinal = ordinal
        self.check = check


class ConstructionRejection(Exception):
    """Internal signal: this attempt hit a foreseeable construction constraint.

    Consumes one attempt and is recorded as a GenerationRejection; the ordinal
    retries with the next retry_index up to ``attempts_per_ordinal`` and is
    then finally rejected -- the combination is never silently swapped.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------
# Frozen g1 scheduling and budget constants (design 6.4.1)
# --------------------------------------------------------------------------

SLOTS_PER_COMBO = 20
EMPTY_SLOT = 18
ALL_NULL_SLOT = 19
MAX_CASES = 10000

InputClass = Literal["normal", "empty", "all_null"]

# Callable[(ordinal, retry_index, payload), Optional[payload]].  Return None
# to inject a retryable construction rejection; return a payload to hand the
# candidate to independent validation (tampered payloads raise
# GeneratorInvariantError instead of being retried).
AttemptHook = Callable[[int, int, CasePayload], Optional[CasePayload]]


# --------------------------------------------------------------------------
# Profile expansion (design 6.3.3, 6.4.1 step 1)
# --------------------------------------------------------------------------


def default_profile() -> Profile:
    """The built-in ``mysql80-exact-v1`` profile (design 6.3.3).

    All four reviewed rules at version 1, templates Q1-Q4, both index
    variants, and the default budgets of design 6.4.1: 32 rows,
    predicate_atoms=1, 8 attempts per ordinal, 1 MiB payload and 256 MiB
    bundle caps.  ``rules``/``templates``/``index_variants`` are already
    sorted as the Profile contract requires.
    """
    return Profile(
        rules=(
            RuleSelector("mysql80.decimal-widen", 1),
            RuleSelector("mysql80.integer-decimal", 1),
            RuleSelector("mysql80.signed-add-sub", 1),
            RuleSelector("mysql80.signed-widen", 1),
        ),
        templates=(TemplateId.Q1, TemplateId.Q2, TemplateId.Q3, TemplateId.Q4),
        index_variants=(IndexVariant.IX_V, IndexVariant.NONE),
        row_count=32,
        predicate_atoms=1,
        attempts_per_ordinal=8,
        max_payload_bytes=1024 * 1024,
        max_bundle_bytes=256 * 1024 * 1024,
    )


def profile_hash(profile: Profile) -> str:
    """profile_hash = SHA256(canonical_json(Profile.to_obj())) (design 6.3.3)."""
    if not isinstance(profile, Profile):
        raise ProfileError("profile_hash needs a Profile")
    return sha256_hex(canonical_json(profile.to_obj()))


def resolve_combinations(profile: Profile) -> tuple[RuleCombo, ...]:
    """Expand a profile into its legal combinations, ASCII-sorted by combo key.

    The profile is a selector, not a license: only registered reviewed rule
    versions, their registered type pairs, the profile's template subset and
    the profile's index variants are combined.  Duplicate selectors, unknown
    enum values and over-cap budgets are already rejected by the Profile
    constructor (design 6.3.3: the loader sorts and the model re-checks);
    unknown or disabled rule versions and a zero-combination selection are
    rejected here.
    """
    if not isinstance(profile, Profile):
        raise ProfileError("resolve_combinations needs a Profile")
    combos: list[RuleCombo] = []
    for selector in profile.rules:
        # Unknown rule id/version raises UnknownRuleError explicitly; no
        # "latest version" substitute is resolved (design 6.3.1).
        rule = get_rule(selector.rule_id, selector.rule_version)
        if rule.review_status is not RuleReviewStatus.REVIEWED:
            raise ProfileError(
                f"rule {rule.rule_id}@{rule.rule_version} is "
                f"{str(rule.review_status.value)}; default generation rejects "
                "disabled rules"
            )
        for template in profile.templates:
            if template not in rule.templates:
                continue
            for a_type, b_type in rule.type_pairs:
                for variant in profile.index_variants:
                    combos.append(
                        RuleCombo(
                            rule.rule_id,
                            rule.rule_version,
                            a_type,
                            b_type,
                            template,
                            variant,
                            combo_key(
                                rule.rule_id,
                                rule.rule_version,
                                a_type,
                                b_type,
                                template,
                                variant,
                            ),
                        )
                    )
    combos.sort(key=lambda combo: combo.combo_key)
    if not combos:
        raise ProfileError(
            "profile selects zero combinations; a profile must keep at least "
            "one legal (rule, type pair, template, index variant) combination"
        )
    return tuple(combos)


def validate_profile(profile: Profile) -> None:
    """Validate an (external) profile selection; raises ProfileError.

    Duplicate selectors, unknown templates/variants and budgets beyond the
    hard caps are rejected by constructing the Profile itself (sorted/unique
    and cap checks in ``Profile.__post_init__``); this entry additionally
    rejects unknown/disabled rules and empty combination sets.
    """
    if not isinstance(profile, Profile):
        raise ProfileError("validate_profile needs a Profile")
    resolve_combinations(profile)


# --------------------------------------------------------------------------
# Deterministic substream (design 6.2.4)
# --------------------------------------------------------------------------


class _Substream:
    """Independent counter stream for one (case_seed, retry, domain) draw."""

    __slots__ = ("_case_seed", "_retry", "_domain", "_counter")

    def __init__(self, case_seed_hex: str, retry_index: int, domain: str) -> None:
        self._case_seed = case_seed_hex
        self._retry = retry_index
        self._domain = domain
        self._counter = 0

    def block(self) -> bytes:
        block = substream_block(self._case_seed, self._retry, self._domain, self._counter)
        self._counter += 1
        return block

    def below(self, bound: int) -> int:
        """Draw in [0, bound)."""
        return take_from_list(self.block(), bound)

    def in_range(self, lo: int, hi: int) -> int:
        """Draw in the closed range [lo, hi]."""
        return take_in_range(self.block(), lo, hi)


# --------------------------------------------------------------------------
# Value domains and the boundary dictionary (design 6.2.1, 6.4.1 step 4)
# --------------------------------------------------------------------------

_NULL = NullValue()

# Fixed operator vocabulary; index order is part of the frozen g1 behavior.
_PREDICATE_OP_VOCABULARY = (
    "=",
    "<>",
    "<",
    "<=",
    ">",
    ">=",
    "<=>",
    "BETWEEN",
    "IS NULL",
    "IS NOT NULL",
)

_POW53_BOUNDARIES: tuple[tuple[int, str], ...] = (
    (2**53 - 1, "pow53_minus1"),
    (2**53, "pow53"),
    (2**53 + 1, "pow53_plus1"),
)


def _data_scale_and_kind(a_type: TypeSpec, b_type: TypeSpec) -> tuple[int, str]:
    """Shared data scale and logical value kind for one type pair.

    Both sides decimal (decimal-widen): data is decimal at the shared scale.
    Otherwise (signed rules, integer-decimal) logical data is integer; the
    only mixed scale in the registry is 0, but the decimal side's scale is
    used generally so coefficient domains stay exact.
    """
    if isinstance(a_type, DecimalType) and isinstance(b_type, DecimalType):
        # equal-scale pairs only; the registry enforces the equality
        return a_type.scale, "decimal"
    if isinstance(b_type, DecimalType):
        return b_type.scale, "integer"
    if isinstance(a_type, DecimalType):
        return a_type.scale, "integer"
    return 0, "integer"


def _side_coefficient_domain(type_spec: TypeSpec, scale: int) -> tuple[int, int]:
    """Representable coefficient range of one side at the shared data scale."""
    if isinstance(type_spec, SignedIntegerType):
        lo, hi = signed_range(type_spec.name)
        return lo * 10**scale, hi * 10**scale
    limit = 10**type_spec.precision - 1
    return -limit, limit


def _common_coefficient_domain(a_type: TypeSpec, b_type: TypeSpec, scale: int) -> tuple[int, int]:
    lo_a, hi_a = _side_coefficient_domain(a_type, scale)
    lo_b, hi_b = _side_coefficient_domain(b_type, scale)
    return max(lo_a, lo_b), min(hi_a, hi_b)


def _make_value(kind: str, scale: int, coefficient: int) -> ExactValue:
    if kind == "integer":
        return IntegerValue(coefficient)
    return DecimalValue(coefficient, scale)


def _constant_kind(rule_kind: str, scale: int, coefficient: int) -> ExactValue:
    """Predicate constant literal kind is fixed by the rule, not by value."""
    if rule_kind == "decimal":
        return DecimalValue(coefficient, scale)
    return IntegerValue(coefficient)


def _boundary_dictionary(
    template: TemplateId,
    scale: int,
    kind: str,
    lo: int,
    hi: int,
) -> tuple[tuple[Optional[int], str], ...]:
    """The fixed boundary dictionary: (coefficient | None for NULL, category).

    Order is frozen g1 behavior: zero, NULL, +1, -1, duplicate zero, common
    lower bound, common upper bound, then (Q1/Q2 only) the 2^53 neighborhood
    and the decimal minimal unit when representable.  Inapplicable items are
    dropped; intentional duplicates (zero twice) are kept.
    """
    items: list[tuple[Optional[int], str]] = [(0, "zero"), (None, "null")]
    if hi >= 1:
        items.append((1, "unit_pos"))
    if lo <= -1:
        items.append((-1, "unit_neg"))
    items.append((0, "dup_zero"))
    items.append((lo, "lower_bound"))
    items.append((hi, "upper_bound"))
    if template in (TemplateId.Q1, TemplateId.Q2):
        for coefficient, category in _POW53_BOUNDARIES:
            if lo <= coefficient <= hi:
                items.append((coefficient, category))
        if kind == "decimal" and scale > 0:
            if hi >= 1:
                items.append((1, "decimal_min"))
            if lo <= -1:
                items.append((-1, "decimal_min_neg"))
    return tuple(items)


# --------------------------------------------------------------------------
# Per-attempt candidate construction
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _AttemptOutcome:
    bundle: CaseBundle
    categories: tuple[str, ...]
    row_count: int
    predicate_present: bool
    predicate_ops: tuple[str, ...]
    arithmetic_op: Optional[str]
    arithmetic_k: Optional[int]


def _normal_values(
    template: TemplateId,
    scale: int,
    kind: str,
    lo: int,
    hi: int,
    row_count: int,
    stream: _Substream,
) -> tuple[list[ExactValue], set[str]]:
    """Dictionary prefix plus substream random fill for one normal input."""
    items = _boundary_dictionary(template, scale, kind, lo, hi)
    coefficients: list[Optional[int]] = []
    categories: set[str] = set()
    for coefficient, category in items:
        if len(coefficients) == row_count:
            break
        coefficients.append(coefficient)
        categories.add(category)
    for _ in range(row_count - len(coefficients)):
        coefficients.append(stream.in_range(lo, hi))
        categories.add("random")
    values = [_NULL if c is None else _make_value(kind, scale, c) for c in coefficients]
    return values, categories


def _build_atom(
    rule_constant_kind: str,
    scale: int,
    lo: int,
    hi: int,
    stream: _Substream,
) -> tuple[Compare | Between | IsNull, str]:
    op = _PREDICATE_OP_VOCABULARY[stream.below(len(_PREDICATE_OP_VOCABULARY))]
    if op == "BETWEEN":
        first = stream.in_range(lo, hi)
        second = stream.in_range(lo, hi)
        lower, upper = (first, second) if first <= second else (second, first)
        return (
            Between(
                ExactLiteral(_constant_kind(rule_constant_kind, scale, lower)),
                ExactLiteral(_constant_kind(rule_constant_kind, scale, upper)),
            ),
            op,
        )
    if op == "IS NULL":
        return IsNull(False), op
    if op == "IS NOT NULL":
        return IsNull(True), op
    if stream.below(8) == 0:
        constant: ExactValue = _NULL
    else:
        constant = _constant_kind(rule_constant_kind, scale, stream.in_range(lo, hi))
    return Compare(CompareOp(op), ExactLiteral(constant)), op


def _build_predicate(
    rule_constant_kind: str,
    profile: Profile,
    template: TemplateId,
    scale: int,
    lo: int,
    hi: int,
    stream: _Substream,
) -> tuple[Optional[And | Or | Compare | Between | IsNull], tuple[str, ...]]:
    """Predicate for one candidate; Q1 never, Q2 always, Q3/Q4 substream draw.

    ``profile.predicate_atoms`` is the atom cap; a present predicate uses 1..cap
    atoms joined once by AND/OR.
    """
    if template is TemplateId.Q1:
        return None, ()
    if template is TemplateId.Q2:
        has_predicate = True
    else:
        has_predicate = stream.below(2) == 1
    if not has_predicate:
        return None, ()
    atom_count = 1 + stream.below(profile.predicate_atoms)
    atoms: list[Compare | Between | IsNull] = []
    ops: list[str] = []
    for _ in range(atom_count):
        atom, op = _build_atom(rule_constant_kind, scale, lo, hi, stream)
        atoms.append(atom)
        ops.append(op)
    if len(atoms) == 1:
        return atoms[0], tuple(ops)
    joined: And | Or = Or(atoms[0], atoms[1]) if stream.below(2) else And(atoms[0], atoms[1])
    return joined, tuple(ops)


def _build_arithmetic(
    k_lo: int, k_hi: int, stream: _Substream
) -> tuple[Arithmetic, str, int]:
    op = ArithmeticOp.ADD if stream.below(2) == 0 else ArithmeticOp.SUBTRACT
    k = stream.in_range(k_lo, k_hi)
    return Arithmetic(op, IntegerValue(k)), str(op.value), k


def _run_attempt(
    profile: Profile,
    profile_hash_hex: str,
    combo: RuleCombo,
    seed: int,
    ordinal: int,
    retry_index: int,
    input_class: InputClass,
    attempt_hook: Optional[AttemptHook],
) -> _AttemptOutcome:
    """One deterministic construction attempt for one ordinal."""
    rule = get_rule(combo.rule_id, combo.rule_version)
    case_seed_hex = case_seed(seed, ordinal)
    rows_stream = _Substream(case_seed_hex, retry_index, "rows")
    predicate_stream = _Substream(case_seed_hex, retry_index, "predicate")
    arithmetic_stream = _Substream(case_seed_hex, retry_index, "arithmetic")

    a_type = combo.a_type
    b_type = combo.b_type
    template = combo.template_id
    data_scale, data_kind = _data_scale_and_kind(a_type, b_type)
    common_lo, common_hi = _common_coefficient_domain(a_type, b_type, data_scale)

    row_count = 0 if input_class == "empty" else profile.row_count
    categories: set[str]
    if input_class == "all_null":
        values: list[ExactValue] = [_NULL] * row_count
        categories = {"null"}
    elif input_class == "empty":
        values = []
        categories = set()
    else:
        construction_lo, construction_hi = common_lo, common_hi
        if template is TemplateId.Q3:
            # Q3 construction limit (design 6.4.1 step 5): intersect the
            # common domain with the per-value budget share.  row_count > 0
            # here (row_count=0 profiles are empty); the registry budget is
            # positive so the share is >= 1 for every allowed row count.
            budget = rule.sum_abs_coefficient_budget
            if budget is None:  # registry invariant, defensive
                raise ConstructionRejection(
                    f"rule {rule.rule_id}@{rule.rule_version} allows Q3 without "
                    "a SUM budget"
                )
            share = (budget * 10**data_scale) // row_count
            construction_lo = max(common_lo, -share)
            construction_hi = min(common_hi, share)
            if construction_lo > construction_hi:
                raise ConstructionRejection(
                    f"q3 construction domain empty: common [{common_lo}, "
                    f"{common_hi}] disjoint from budget share "
                    f"[-{share}, {share}] for {row_count} rows"
                )
        values, categories = _normal_values(
            template,
            data_scale,
            data_kind,
            construction_lo,
            construction_hi,
            row_count,
            rows_stream,
        )

    # Predicate constants use the full common value domain; only Q3 row data
    # is narrowed by the SUM construction limit.
    rule_constant_kind = "decimal" if rule.requires_equal_scale else "integer"
    predicate, predicate_ops = _build_predicate(
        rule_constant_kind,
        profile,
        template,
        data_scale,
        common_lo,
        common_hi,
        predicate_stream,
    )
    arithmetic: Optional[Arithmetic] = None
    arithmetic_op: Optional[str] = None
    arithmetic_k: Optional[int] = None
    if template is TemplateId.Q4:
        assert rule.arithmetic_k_min is not None and rule.arithmetic_k_max is not None
        arithmetic, arithmetic_op, arithmetic_k = _build_arithmetic(
            rule.arithmetic_k_min, rule.arithmetic_k_max, arithmetic_stream
        )

    rule_ref = RuleRef(rule.rule_id, rule.rule_version)
    rows = Rows(
        normalize_row_pairs(
            [(rid, value) for rid, value in enumerate(values, start=1)]
        )
    )
    table = TableSpec(
        "t0",
        (
            ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
            ColumnSpec("v", a_type, True),
        ),
        ("rid",),
        combo.index_variant,
    )
    payload = CasePayload(
        rule=rule_ref,
        a_type=a_type,
        b_type=b_type,
        table=table,
        rows=rows,
        query=(
            QuerySpec(template, predicate, arithmetic)
            if template is not TemplateId.Q4
            else QuerySpec(
                template, predicate, arithmetic, (Projection("c0", arithmetic),)
            )
        ),
        relation=derive_relation(rule_ref, a_type, b_type, template),
        environment=rule.runtime_requirements,
        generator=GENERATOR_IDENTITY,
        renderer=RENDERER_IDENTITY,
    )

    if attempt_hook is not None:
        payload = attempt_hook(ordinal, retry_index, payload)
        if payload is None:
            raise ConstructionRejection("attempt_hook_injected_rejection")

    sealed = dump_payload(payload)
    if len(sealed) > profile.max_payload_bytes:
        raise ConstructionRejection(
            f"payload_budget_exceeded: {len(sealed)} bytes > limit "
            f"{profile.max_payload_bytes}"
        )

    try:
        check = static_check_or_raise(payload)
    except StaticValidationError as exc:
        raise GeneratorInvariantError(
            f"ordinal {ordinal} retry {retry_index}: the constructed candidate "
            "was rejected by independent static validation; this is a "
            "generator invariant failure, not a retryable rejection",
            ordinal=ordinal,
            check=exc.check,
        ) from exc

    # Independent re-verification after the static check (design 6.4.1 steps
    # 3/5: the construction limit never replaces the verification).  A
    # violation at this point is an internal invariant failure.
    _reverify_template_safety(rule, rows, template, data_scale, arithmetic, ordinal)

    preview_a, preview_b = render_preview(payload)
    bundle = CaseBundle(
        payload=payload,
        provenance=Provenance(
            seed=seed,
            ordinal=ordinal,
            profile_hash=profile_hash_hex,
            retry=retry_index,
        ),
        preview_a_sql=preview_a,
        preview_b_sql=preview_b,
        static_check=check,
    )
    return _AttemptOutcome(
        bundle=bundle,
        categories=tuple(sorted(categories)),
        row_count=len(rows.rows),
        predicate_present=predicate is not None,
        predicate_ops=predicate_ops,
        arithmetic_op=arithmetic_op,
        arithmetic_k=arithmetic_k,
    )


def _reverify_template_safety(
    rule: RuleSpec,
    rows: Rows,
    template: TemplateId,
    data_scale: int,
    arithmetic: Optional[Arithmetic],
    ordinal: int,
) -> None:
    if template is TemplateId.Q3:
        budget = rule.sum_abs_coefficient_budget
        result = check_q3_sum_budget(rows, data_scale, budget)
        if result.status is CheckStatus.VIOLATED:
            raise GeneratorInvariantError(
                f"ordinal {ordinal}: independently re-run Q3 SUM budget check "
                f"violated after construction: {result.detail}",
                ordinal=ordinal,
            )
    if template is TemplateId.Q4 and arithmetic is not None:
        k = arithmetic.constant.value
        for row in rows.rows:
            value = row.value
            if isinstance(value, IntegerValue):
                result = check_bigint_intermediate(value.value, k)
                if result.status is CheckStatus.VIOLATED:
                    raise GeneratorInvariantError(
                        f"ordinal {ordinal}: BIGINT intermediate check violated "
                        f"after construction: {result.detail}",
                        ordinal=ordinal,
                    )


# --------------------------------------------------------------------------
# Ordinal scheduling and records (design 6.4.1 step 2-3, 6.6)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class OrdinalRecord:
    """What one ordinal actually produced (coverage/observability data).

    Categories only cover values actually placed into an emitted payload;
    dictionary items that did not fit are never counted.  Rejected ordinals
    keep their slot-derived ``input_class`` but record no emitted content.
    """

    ordinal: int
    combo_index: int
    combo_key: str
    rule_id: str
    template_id: str
    index_variant: str
    input_class: InputClass
    value_categories: tuple[str, ...]
    row_count: int
    predicate_present: bool
    predicate_ops: tuple[str, ...]
    arithmetic_op: Optional[str]
    arithmetic_k: Optional[int]
    case_id: Optional[str]

    def to_obj(self) -> dict[str, object]:
        return {
            "ordinal": self.ordinal,
            "combo_index": self.combo_index,
            "combo_key": self.combo_key,
            "rule_id": self.rule_id,
            "template_id": self.template_id,
            "index_variant": self.index_variant,
            "input_class": self.input_class,
            "value_categories": list(self.value_categories),
            "row_count": self.row_count,
            "predicate_present": self.predicate_present,
            "predicate_ops": list(self.predicate_ops),
            "arithmetic_op": self.arithmetic_op,
            "arithmetic_k": self.arithmetic_k,
            "case_id": self.case_id,
        }


@dataclass(frozen=True)
class GenerationRejection:
    """Foreseeable construction failure of a finally rejected ordinal.

    Carries the ordinal, the retry index of its last failed attempt and that
    attempt's reason; the ordinal's full attempt count is on its
    ``OrdinalReceipt`` (``retry_count``).  Batch results surface one record
    per finally rejected ordinal (the last failure), never one per attempt.
    """

    ordinal: int
    retry_index: int
    reason: str


def _input_class_for_slot(profile: Profile, slot: int) -> InputClass:
    if profile.row_count == 0:
        # Explicit row_count=0: every ordinal is empty, never misreported as
        # normal or all-null coverage (design 6.4.1 step 3).
        return "empty"
    if slot == EMPTY_SLOT:
        return "empty"
    if slot == ALL_NULL_SLOT:
        return "all_null"
    return "normal"


def _generate_ordinal(
    profile: Profile,
    profile_hash_hex: str,
    combos: tuple[RuleCombo, ...],
    seed: int,
    ordinal: int,
    attempt_hook: Optional[AttemptHook],
) -> tuple[Optional[CaseBundle], OrdinalReceipt, OrdinalRecord, GenerationRejection | None]:
    """Run one ordinal to its final attribution: emitted or finally rejected."""
    combo_count = len(combos)
    combo_index = ordinal % combo_count
    visit = ordinal // combo_count
    slot = (visit + combo_index) % SLOTS_PER_COMBO
    input_class = _input_class_for_slot(profile, slot)
    combo = combos[combo_index]

    last_rejection: GenerationRejection | None = None
    for retry_index in range(profile.attempts_per_ordinal):
        try:
            outcome = _run_attempt(
                profile,
                profile_hash_hex,
                combo,
                seed,
                ordinal,
                retry_index,
                input_class,
                attempt_hook,
            )
        except ConstructionRejection as exc:
            # Foreseeable construction constraint failure: consume one
            # attempt, retry within the same ordinal substream, never swap
            # the combination (design 6.4.1 step 6).
            last_rejection = GenerationRejection(ordinal, retry_index, exc.reason)
            continue
        receipt = OrdinalReceipt(
            ordinal=ordinal,
            outcome=OrdinalOutcome.EMITTED,
            case_id=outcome.bundle.case_id,
            retry_count=retry_index,
        )
        record = OrdinalRecord(
            ordinal=ordinal,
            combo_index=combo_index,
            combo_key=combo.combo_key,
            rule_id=combo.rule_id,
            template_id=str(combo.template_id.value),
            index_variant=str(combo.index_variant.value),
            input_class=input_class,
            value_categories=outcome.categories,
            row_count=outcome.row_count,
            predicate_present=outcome.predicate_present,
            predicate_ops=outcome.predicate_ops,
            arithmetic_op=outcome.arithmetic_op,
            arithmetic_k=outcome.arithmetic_k,
            case_id=outcome.bundle.case_id,
        )
        return outcome.bundle, receipt, record, None

    final_reason = (
        last_rejection.reason if last_rejection is not None else "attempts exhausted"
    )
    receipt = OrdinalReceipt(
        ordinal=ordinal,
        outcome=OrdinalOutcome.REJECTED,
        retry_count=profile.attempts_per_ordinal,
        reason=final_reason,
    )
    record = OrdinalRecord(
        ordinal=ordinal,
        combo_index=combo_index,
        combo_key=combo.combo_key,
        rule_id=combo.rule_id,
        template_id=str(combo.template_id.value),
        index_variant=str(combo.index_variant.value),
        input_class=input_class,
        value_categories=(),
        row_count=0,
        predicate_present=False,
        predicate_ops=(),
        arithmetic_op=None,
        arithmetic_k=None,
        case_id=None,
    )
    return None, receipt, record, last_rejection


# --------------------------------------------------------------------------
# Batch entry points (design 6.3.1, 6.6)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseOccurrence:
    """Occurrence count of one case_id across the requested ordinals."""

    case_id: str
    count: int

    def to_obj(self) -> dict[str, object]:
        return {"case_id": self.case_id, "count": self.count}


@dataclass(frozen=True)
class GenerationResult:
    """Everything one generation request produced (design 6.6).

    ``bundles`` holds the first bundle per unique case_id; every emitted
    ordinal (including repeats of an already-seen case_id) is counted in
    ``emitted_occurrences`` and keeps its own receipt, so duplicate case_ids
    never discard provenance.  ``manifest`` is directly consumable by the
    bundle writer; ``case_files`` stay empty here because artifact hashes are
    over actual file bytes, which only exist once the bundle layer writes.
    """

    profile: Profile
    profile_hash: str
    seed: int
    bundles: tuple[CaseBundle, ...]
    occurrences: tuple[CaseOccurrence, ...]
    receipts: tuple[OrdinalReceipt, ...]
    records: tuple[OrdinalRecord, ...]
    rejections: tuple[GenerationRejection, ...]
    manifest: GenerationManifest

    @property
    def status(self) -> GenerationStatus:
        return self.manifest.status

    @property
    def requested(self) -> int:
        return self.manifest.requested_ordinals

    @property
    def attempted_candidates(self) -> int:
        return self.manifest.attempted_candidates

    @property
    def emitted_occurrences(self) -> int:
        return self.manifest.emitted_occurrences

    @property
    def unique_cases(self) -> int:
        return self.manifest.unique_cases

    @property
    def rejected(self) -> int:
        return self.manifest.rejected_ordinals

    @property
    def interrupted(self) -> int:
        return self.manifest.interrupted_ordinals

    @property
    def not_attempted(self) -> int:
        return self.manifest.not_attempted


def generate_case(
    profile: Profile,
    profile_hash_hex: str,
    seed: int,
    ordinal: int,
    attempt_hook: Optional[AttemptHook] = None,
) -> CaseBundle | OrdinalReceipt:
    """Generate one ordinal deterministically: bundle or final rejection.

    ``profile_hash_hex`` must be ``profile_hash(profile)``; it is sealed into
    the provenance verbatim (the generator does not re-encode the profile on
    every ordinal).  ``ordinal`` failures consume up to
    ``profile.attempts_per_ordinal`` attempts within this ordinal's own
    substreams; exhaustion returns ``OrdinalReceipt(REJECTED)`` without
    swapping the combination.  A constructed candidate whose independent
    validation is INVALID raises :class:`GeneratorInvariantError`.
    """
    if not isinstance(profile, Profile):
        raise ProfileError("generate_case needs a Profile")
    if not isinstance(profile_hash_hex, str) or len(profile_hash_hex) != 64:
        raise ProfileError(
            "generate_case needs the 64-hex profile_hash(profile) string"
        )
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
        raise ProfileError("generate_case ordinal must be a non-negative int")
    combos = resolve_combinations(profile)
    bundle, receipt, _record, _rejections = _generate_ordinal(
        profile, profile_hash_hex, combos, seed, ordinal, attempt_hook
    )
    return bundle if bundle is not None else receipt


def generate_cases(
    profile: Profile,
    seed: int,
    count: int,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> GenerationResult:
    """Generate ``count`` ordinals (design 6.4.1 budget: 1..10000).

    Cancellation is cooperative: ``should_cancel`` is consulted before each
    ordinal; when it fires the generator stops before starting that ordinal,
    so the pure generator never holds a half-finished ordinal -- all
    un-started ordinals are ``not_attempted`` and ``interrupted`` stays 0
    (mid-ordinal interruption attribution is the bundle layer's concern).
    Status is ABORTED on cancellation, PARTIAL when any ordinal was finally
    rejected, COMPLETE otherwise.
    """
    if not isinstance(profile, Profile):
        raise ProfileError("generate_cases needs a Profile")
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**64 - 1:
        raise ProfileError("generate_cases seed must be a uint64 int")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_CASES:
        raise ProfileError(f"generate_cases count must be in [1, {MAX_CASES}]")
    if should_cancel is not None and not callable(should_cancel):
        raise ProfileError("should_cancel must be callable")
    profile_hash_hex = profile_hash(profile)
    combos = resolve_combinations(profile)

    bundles: list[CaseBundle] = []
    occurrences: dict[str, int] = {}
    receipts: list[OrdinalReceipt] = []
    records: list[OrdinalRecord] = []
    rejections: list[GenerationRejection] = []
    attempted_candidates = 0
    emitted_occurrences = 0
    rejected_ordinals = 0
    cancelled = False

    for ordinal in range(count):
        if should_cancel is not None and should_cancel():
            cancelled = True
            break
        bundle, receipt, record, ordinal_rejections = _generate_ordinal(
            profile, profile_hash_hex, combos, seed, ordinal, None
        )
        receipts.append(receipt)
        records.append(record)
        if ordinal_rejections is not None:
            rejections.append(ordinal_rejections)
        if bundle is not None:
            # emitted: every failed retry plus the accepted attempt
            attempted_candidates += receipt.retry_count + 1
            emitted_occurrences += 1
            occurrences[bundle.case_id] = occurrences.get(bundle.case_id, 0) + 1
            if occurrences[bundle.case_id] == 1:
                bundles.append(bundle)
        else:
            # rejected: every attempt of this ordinal failed
            attempted_candidates += receipt.retry_count
            rejected_ordinals += 1

    processed = len(receipts)
    not_attempted = count - processed
    if cancelled:
        status = GenerationStatus.ABORTED
        reason: Optional[str] = "generation cancelled by should_cancel"
    elif rejected_ordinals:
        status = GenerationStatus.PARTIAL
        reason = None
    else:
        status = GenerationStatus.COMPLETE
        reason = None
    manifest = GenerationManifest(
        profile_hash=profile_hash_hex,
        seed=seed,
        requested_ordinals=count,
        attempted_candidates=attempted_candidates,
        emitted_occurrences=emitted_occurrences,
        unique_cases=len(bundles),
        rejected_ordinals=rejected_ordinals,
        interrupted_ordinals=0,
        not_attempted=not_attempted,
        status=status,
        generator=GENERATOR_IDENTITY,
        receipts=tuple(receipts),
        case_files=(),
        reason=reason,
    )
    return GenerationResult(
        profile=profile,
        profile_hash=profile_hash_hex,
        seed=seed,
        bundles=tuple(bundles),
        occurrences=tuple(
            CaseOccurrence(case_id, count_) for case_id, count_ in occurrences.items()
        ),
        receipts=tuple(receipts),
        records=tuple(records),
        rejections=tuple(rejections),
        manifest=manifest,
    )
