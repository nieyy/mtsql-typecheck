"""Reviewed rule registry for D1 (design 6.2.1, 6.4.1).

Holds the four reviewed v1.0 rule definitions and enumerates every legal
``(rule_id, rule_version, canonical_type_pair, template_id, index_variant)``
combination: 31 rule/type-pair/template combos (12 + 9 + 6 + 4), 62 with
both index variants.  Registration is explicit and conflict-checked: the
same (id, version) with a different definition is rejected, and unknown
ids/versions raise :class:`UnknownRuleError` instead of resolving to a
"latest" substitute.  Importing this module performs no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..contracts.case import (
    ContractError,
    DecimalType,
    EnvironmentRequirements,
    IndexVariant,
    REQUIRED_CHARACTER_SET,
    REQUIRED_COLLATION,
    REQUIRED_SQL_MODE_TOKENS,
    REQUIRED_TIME_ZONE,
    RuleReviewStatus,
    RuleSpec,
    SignedIntName,
    SignedIntegerType,
    TemplateId,
    TypeSpec,
)
from ..contracts.codec import canonical_json


class RuleRegistryError(ContractError):
    """Base error for registry misuse (also a ContractError/ValueError)."""


class UnknownRuleError(RuleRegistryError):
    """Raised for an unknown rule id or rule version; never resolved by approximation."""


class DuplicateDefinitionError(RuleRegistryError):
    """Raised when the same (rule_id, rule_version) is redefined semantically."""


def _int_type(name: SignedIntName) -> SignedIntegerType:
    return SignedIntegerType(name)


def _dec(precision: int, scale: int) -> DecimalType:
    return DecimalType(precision, scale)


# Canonical ASCII ordering of type pairs is fixed by canonical_json; the
# RuleSpec constructor re-checks sortedness from this same encoding.
def canonical_type_pair(a_type: TypeSpec, b_type: TypeSpec) -> str:
    """Canonical ASCII encoding of a (A TypeSpec, B TypeSpec) pair."""
    return canonical_json([a_type.to_obj(), b_type.to_obj()]).decode("ascii")


def combo_key(
    rule_id: str,
    rule_version: int,
    a_type: TypeSpec,
    b_type: TypeSpec,
    template_id: TemplateId,
    index_variant: IndexVariant,
) -> str:
    """Canonical ASCII combination key (design 6.4.1); sorted keys fix the order."""
    return canonical_json(
        [
            rule_id,
            rule_version,
            canonical_type_pair(a_type, b_type),
            str(template_id.value),
            str(index_variant.value),
        ]
    ).decode("ascii")


@dataclass(frozen=True)
class RuleCombo:
    """One legal (rule, type pair, template, index variant) combination."""

    rule_id: str
    rule_version: int
    a_type: TypeSpec
    b_type: TypeSpec
    template_id: TemplateId
    index_variant: IndexVariant
    combo_key: str


class RuleRegistry:
    """Explicit registry; the module-level default instance holds the four v1.0 rules."""

    def __init__(self) -> None:
        self._rules: dict[tuple[str, int], RuleSpec] = {}

    def register(self, spec: RuleSpec) -> None:
        key = (spec.rule_id, spec.rule_version)
        existing = self._rules.get(key)
        if existing is not None:
            if existing.definition_hash != spec.definition_hash:
                raise DuplicateDefinitionError(
                    f"rule {spec.rule_id!r} version {spec.rule_version} is already "
                    f"registered with a different definition "
                    f"({existing.definition_hash} != {spec.definition_hash}); bump "
                    "the rule version instead"
                )
            # Same semantic definition: re-registration only updates registry
            # management state (e.g. review status); semantics are immutable.
            self._rules[key] = spec
            return
        self._rules[key] = spec

    def get(self, rule_id: str, rule_version: int) -> RuleSpec:
        spec = self._rules.get((rule_id, rule_version))
        if spec is None:
            raise UnknownRuleError(
                f"unknown rule {rule_id!r} version {rule_version!r}; no approximate "
                "substitute is resolved"
            )
        return spec

    def rules(self) -> tuple[RuleSpec, ...]:
        return tuple(self._rules[key] for key in sorted(self._rules))

    def combinations(self) -> tuple[RuleCombo, ...]:
        combos: list[RuleCombo] = []
        for spec in self.rules():
            for a_type, b_type in spec.type_pairs:
                for template in spec.templates:
                    for variant in IndexVariant:
                        combos.append(
                            RuleCombo(
                                spec.rule_id,
                                spec.rule_version,
                                a_type,
                                b_type,
                                template,
                                variant,
                                combo_key(
                                    spec.rule_id,
                                    spec.rule_version,
                                    a_type,
                                    b_type,
                                    template,
                                    variant,
                                ),
                            )
                        )
        combos.sort(key=lambda combo: combo.combo_key)
        return tuple(combos)


# --------------------------------------------------------------------------
# The four reviewed v1.0 rule definitions (design 6.2.1)
# --------------------------------------------------------------------------

_MYSQL80_ENV = EnvironmentRequirements(
    database="mysql80",
    engine="innodb",
    scope="same-instance",
    sql_mode_tokens=REQUIRED_SQL_MODE_TOKENS,
    character_set=REQUIRED_CHARACTER_SET,
    collation=REQUIRED_COLLATION,
    time_zone=REQUIRED_TIME_ZONE,
)

# Sorted ASCII condition ids shared by every v1.0 rule.
_STATIC_CONDITIONS = (
    "arithmetic_safety",
    "common_value_domain",
    "predicate_constants",
    "structure_whitelist",
)

_SIGNED_WIDEN_PAIRS = (
    (_int_type(SignedIntName.TINYINT), _int_type(SignedIntName.SMALLINT)),
    (_int_type(SignedIntName.SMALLINT), _int_type(SignedIntName.MEDIUMINT)),
    (_int_type(SignedIntName.MEDIUMINT), _int_type(SignedIntName.INT)),
    (_int_type(SignedIntName.INT), _int_type(SignedIntName.BIGINT)),
)

_REVIEWED_RULES: tuple[RuleSpec, ...] = (
    RuleSpec(
        rule_id="mysql80.decimal-widen",
        rule_version=1,
        type_pairs=(
            (_dec(9, 2), _dec(18, 2)),
            (_dec(18, 6), _dec(30, 6)),
            (_dec(20, 0), _dec(30, 0)),
        ),
        templates=(TemplateId.Q1, TemplateId.Q2, TemplateId.Q3),
        requires_equal_scale=True,
        integer_only_values=False,
        sum_abs_coefficient_budget=10**12,
        arithmetic_k_min=None,
        arithmetic_k_max=None,
        static_conditions=_STATIC_CONDITIONS,
        runtime_requirements=_MYSQL80_ENV,
        rationale=(
            "https://dev.mysql.com/doc/refman/8.0/en/fixed-point-types.html [R3] "
            "DECIMAL precision/scale determine the exactly representable values",
            "project: widening precision with unchanged scale introduces no "
            "quantization; equal coefficients denote equal logical values; this "
            "does not license AVG, division or arbitrary decimal arithmetic",
        ),
        review_notes=(
            "reviewed 2026-09-05 against D1 design v1.0 section 6.2.1; reviewed "
            "means the offline definition is approved, not that a real MySQL "
            "build has been certified"
        ),
        review_status=RuleReviewStatus.REVIEWED,
    ),
    RuleSpec(
        rule_id="mysql80.integer-decimal",
        rule_version=1,
        type_pairs=(
            (_int_type(SignedIntName.BIGINT), _dec(20, 0)),
            (_int_type(SignedIntName.INT), _dec(12, 0)),
        ),
        templates=(TemplateId.Q1, TemplateId.Q2, TemplateId.Q3),
        requires_equal_scale=False,
        integer_only_values=True,
        sum_abs_coefficient_budget=10**12,
        arithmetic_k_min=None,
        arithmetic_k_max=None,
        static_conditions=_STATIC_CONDITIONS,
        runtime_requirements=_MYSQL80_ENV,
        rationale=(
            "https://dev.mysql.com/doc/refman/8.0/en/fixed-point-types.html [R3] "
            "scale=0 DECIMAL represents integers exactly",
            "https://dev.mysql.com/doc/refman/8.0/en/type-conversion.html [R4] "
            "integer vs DECIMAL comparison stays exact; no approximate "
            "intermediate is involved",
            "project: logical data stores integers only and side B is written as "
            "exact integers (scale 0); the declared relation permits the "
            "signed_integer/DECIMAL family mapping instead of masking it with CAST",
        ),
        review_notes=(
            "reviewed 2026-09-05 against D1 design v1.0 section 6.2.1; reviewed "
            "means the offline definition is approved, not that a real MySQL "
            "build has been certified"
        ),
        review_status=RuleReviewStatus.REVIEWED,
    ),
    RuleSpec(
        rule_id="mysql80.signed-add-sub",
        rule_version=1,
        type_pairs=_SIGNED_WIDEN_PAIRS,
        templates=(TemplateId.Q4,),
        requires_equal_scale=False,
        integer_only_values=True,
        sum_abs_coefficient_budget=None,
        arithmetic_k_min=-16,
        arithmetic_k_max=16,
        static_conditions=_STATIC_CONDITIONS,
        runtime_requirements=_MYSQL80_ENV,
        rationale=(
            "https://dev.mysql.com/doc/refman/8.0/en/arithmetic-functions.html "
            "[R6] integer addition/subtraction evaluates at BIGINT precision and "
            "signedness of intermediate results matters",
            "project: both operands are signed integers; only v +/- k with "
            "[-16, 16] integer k is allowed and every intermediate value is "
            "checked against the signed BIGINT domain; NULL stays NULL",
        ),
        review_notes=(
            "reviewed 2026-09-05 against D1 design v1.0 section 6.2.1; reviewed "
            "means the offline definition is approved, not that a real MySQL "
            "build has been certified"
        ),
        review_status=RuleReviewStatus.REVIEWED,
    ),
    RuleSpec(
        rule_id="mysql80.signed-widen",
        rule_version=1,
        type_pairs=_SIGNED_WIDEN_PAIRS,
        templates=(TemplateId.Q1, TemplateId.Q2, TemplateId.Q3),
        requires_equal_scale=False,
        integer_only_values=True,
        sum_abs_coefficient_budget=10**12,
        arithmetic_k_min=None,
        arithmetic_k_max=None,
        static_conditions=_STATIC_CONDITIONS,
        runtime_requirements=_MYSQL80_ENV,
        rationale=(
            "https://dev.mysql.com/doc/refman/8.0/en/integer-types.html [R2] "
            "signed integer value domains",
            "https://dev.mysql.com/doc/refman/8.0/en/type-conversion.html [R4] "
            "integer and integer/DECIMAL comparisons use exact numeric values",
            "project: widening one signed integer column keeps every shared "
            "value storable on both sides; projections, exact predicates and the "
            "allowed aggregates do not depend on the narrower storage width; "
            "type pairs are not transitive (no TINYINT->INT, no reverse pairs)",
        ),
        review_notes=(
            "reviewed 2026-09-05 against D1 design v1.0 section 6.2.1; reviewed "
            "means the offline definition is approved, not that a real MySQL "
            "build has been certified"
        ),
        review_status=RuleReviewStatus.REVIEWED,
    ),
)

DEFAULT_REGISTRY = RuleRegistry()
for _rule in _REVIEWED_RULES:
    DEFAULT_REGISTRY.register(_rule)


def get_rule(rule_id: str, rule_version: int) -> RuleSpec:
    """Look up one reviewed definition; unknown id/version raise explicitly."""
    return DEFAULT_REGISTRY.get(rule_id, rule_version)


def list_rules() -> tuple[RuleSpec, ...]:
    """All registered rule definitions, sorted by (rule_id, rule_version)."""
    return DEFAULT_REGISTRY.rules()


def iter_combinations() -> tuple[RuleCombo, ...]:
    """All legal combinations, ASCII-sorted by canonical combo key (31 pairs/templates x 2 variants = 62)."""
    return DEFAULT_REGISTRY.combinations()


def register_rule(spec: RuleSpec) -> None:
    """Register into the default registry; conflicting definitions are rejected."""
    DEFAULT_REGISTRY.register(spec)
