"""Static case validation for D1 (design 6.2.5, 6.3.1 ``validate_case``,
6.4.1 step 6; test IDs R02 and V01 static part).

``validate_case`` re-derives every static condition from the payload itself.
It never trusts any check conclusion carried by the payload or the caller:
``CasePayload`` carries no check field, no check can be passed in, and the
registered rule definition, the value domains, the declared relation and the
codec round trip are all recomputed here.

A static check never claims runtime readiness.  A ``VALID_STATIC`` result
always appends the runtime conditions as ``PENDING`` with reason
``missing_fact`` (design 6.2.5: environment/load facts and "独立对象/无写入"
cannot be proven offline and belong to D3); they are never SATISFIED and no
``READY`` status is ever produced by this module.  Full runtime-fact
validation is Phase 4 work.

Pure functions only: no file, network or database I/O, no randomness, no
clocks.  Importing this module performs no I/O.
"""

from __future__ import annotations

from mtsql_typecheck.contracts.case import (
    And,
    Between,
    CasePayload,
    CheckStage,
    CheckStatus,
    CompatibilityCheck,
    Compare,
    ConditionResult,
    ContractError,
    DecimalType,
    DecimalValue,
    EnvironmentRequirements,
    IntegerValue,
    IsNull,
    NullValue,
    Or,
    Predicate,
    Projection,
    QuerySpec,
    ReasonCode,
    REQUIRED_CHARACTER_SET,
    REQUIRED_COLLATION,
    REQUIRED_SQL_MODE_TOKENS,
    REQUIRED_TIME_ZONE,
    RuleRef,
    RuleReviewStatus,
    RuleSpec,
    SemverIdentity,
    StaticCheckStatus,
    TemplateId,
)
from mtsql_typecheck.contracts.codec import (
    canonical_json,
    case_id_of,
    dump_payload,
    load_payload,
    sha256_hex,
)
from mtsql_typecheck.generation.render import RENDERER_IDENTITY
from mtsql_typecheck.rules.exact_numeric import (
    ARITHMETIC_K_MAX,
    ARITHMETIC_K_MIN,
    check_predicate_constants,
    check_q3_sum_budget,
    check_q4_arithmetic,
    check_rows_domain,
    check_rule_binding,
    derive_relation,
)
from mtsql_typecheck.rules.registry import (
    UnknownRuleError,
    combo_key,
    get_rule,
    iter_combinations,
)

__all__ = [
    "VALIDATOR_IDENTITY",
    "GENERATOR_IDENTITY",
    "DEFAULT_PREDICATE_ATOM_LIMIT",
    "StaticValidationError",
    "validate_case",
    "static_check_or_raise",
]

# Validator semantic identity (design 6.2.4: re-validation always produces a
# new object stamped with the validator version).
VALIDATOR_IDENTITY = SemverIdentity("static-validate", "1")

# The only generator identity whose payloads this validator accepts.
GENERATOR_IDENTITY = SemverIdentity("g1", "1")

# Predicate atom cap with no profile context (design 6.4.1 budget table
# default: at most two atoms joined once by AND/OR).
DEFAULT_PREDICATE_ATOM_LIMIT = 2


class StaticValidationError(ContractError):
    """Raised by ``static_check_or_raise`` when a payload is INVALID."""

    def __init__(self, check: CompatibilityCheck) -> None:
        super().__init__(
            f"static validation returned {str(check.status.value)} for case "
            f"{check.case_id}"
        )
        self.check = check


_REQUIRED_ENVIRONMENT = EnvironmentRequirements(
    database="mysql80",
    engine="innodb",
    scope="same-instance",
    sql_mode_tokens=REQUIRED_SQL_MODE_TOKENS,
    character_set=REQUIRED_CHARACTER_SET,
    collation=REQUIRED_COLLATION,
    time_zone=REQUIRED_TIME_ZONE,
)

# Runtime conditions that stay PENDING on every VALID_STATIC result.  They
# are frozen here so the pending set itself is part of the stable contract.
_RUNTIME_PENDING_CONDITIONS = (
    ConditionResult(
        "runtime_environment",
        CheckStatus.PENDING,
        ReasonCode.MISSING_FACT,
        "server identity/version/vendor/build, engine and effective A/B "
        "session snapshot require D3 runtime facts",
    ),
    ConditionResult(
        "runtime_load",
        CheckStatus.PENDING,
        ReasonCode.MISSING_FACT,
        "DDL/INSERT statement receipts, complete diagnostics and full exact "
        "readback require D3 runtime facts",
    ),
    ConditionResult(
        "runtime_isolation",
        CheckStatus.PENDING,
        ReasonCode.MISSING_FACT,
        "attempt ownership, load commit and no-external-write isolation "
        "cannot be proven offline",
    ),
)


def _satisfied(condition_id: str, detail: str | None = None) -> ConditionResult:
    return ConditionResult(condition_id, CheckStatus.SATISFIED, None, detail)


def _violated(
    condition_id: str, reason: ReasonCode, detail: str
) -> ConditionResult:
    return ConditionResult(condition_id, CheckStatus.VIOLATED, reason, detail)


# --------------------------------------------------------------------------
# Individual checks
# --------------------------------------------------------------------------


def _check_codec_roundtrip(payload: CasePayload) -> ConditionResult:
    """Payload must survive dump -> strict load byte-identically (6.2.4).

    Catches construction bypasses: anything the strict loader would reject
    (floats, unknown fields, non-canonical text) fails here even if it was
    assembled directly in Python instead of decoded from JSON.
    """
    condition = "codec_roundtrip"
    try:
        sealed = dump_payload(payload)
    except ContractError as exc:
        return _violated(
            condition, ReasonCode.INVALID_STRUCTURE,
            f"payload cannot be canonically encoded: {exc}",
        )
    try:
        reloaded = load_payload(sealed)
    except ContractError as exc:
        return _violated(
            condition, ReasonCode.INVALID_STRUCTURE,
            f"payload does not survive the strict loader: {exc}",
        )
    if dump_payload(reloaded) != sealed:
        return _violated(
            condition, ReasonCode.INVALID_STRUCTURE,
            "payload is not byte-stable across the canonical dump/load round trip",
        )
    return _satisfied(condition, "canonical dump/load round trip is byte-identical")


def _check_rule_registered(rule_ref: RuleRef) -> tuple[ConditionResult, RuleSpec | None]:
    """get_rule must succeed, return the exact id/version, and the registered
    definition hash must still match a fresh re-derivation of its semantics
    (design 6.2.1: every read re-verifies the definition hash)."""
    condition = "rule_registered"
    try:
        rule = get_rule(rule_ref.rule_id, rule_ref.rule_version)
    except UnknownRuleError as exc:
        return _violated(condition, ReasonCode.UNKNOWN_VERSION, str(exc)), None
    if rule.rule_id != rule_ref.rule_id or rule.rule_version != rule_ref.rule_version:
        return (
            _violated(
                condition,
                ReasonCode.UNKNOWN_VERSION,
                f"registry returned {rule.rule_id}@{rule.rule_version} for a "
                f"payload referencing {rule_ref.rule_id}@{rule_ref.rule_version}",
            ),
            None,
        )
    recomputed = sha256_hex(canonical_json(rule.semantic_obj()))
    if recomputed != rule.definition_hash:
        return (
            _violated(
                condition,
                ReasonCode.INTERNAL_ERROR,
                f"registered definition_hash {rule.definition_hash!r} does not "
                "match the re-derived semantic content hash; the registered "
                "definition object was replaced",
            ),
            None,
        )
    return (
        _satisfied(
            condition, f"{rule.rule_id}@{rule.rule_version} registered and hash-consistent"
        ),
        rule,
    )


def _check_rule_enabled(rule: RuleSpec) -> ConditionResult:
    """Default generation/validation rejects disabled rules but must still
    report the rule as disabled instead of silently passing (design 6.2.1)."""
    condition = "rule_enabled"
    if rule.review_status is RuleReviewStatus.DISABLED:
        return _violated(
            condition,
            ReasonCode.RULE_DISABLED,
            f"rule {rule.rule_id}@{rule.rule_version} is disabled in the registry",
        )
    return _satisfied(condition, f"{rule.rule_id}@{rule.rule_version} is enabled")


def _check_rule_binding(rule: RuleSpec, payload: CasePayload) -> ConditionResult:
    """Type pair + template must be whitelisted by the rule AND the full
    (rule, version, pair, template, index_variant) combination must be one of
    the registered combinations (design 6.4.1: 62 combos, not a free product)."""
    result = check_rule_binding(
        rule, payload.a_type, payload.b_type, payload.query.template_id
    )
    if result.status is CheckStatus.VIOLATED:
        return result
    key = combo_key(
        payload.rule.rule_id,
        payload.rule.rule_version,
        payload.a_type,
        payload.b_type,
        payload.query.template_id,
        payload.table.index_variant,
    )
    legal_keys = {combo.combo_key for combo in iter_combinations()}
    if key not in legal_keys:
        return _violated(
            "rule_binding",
            ReasonCode.INVALID_STRUCTURE,
            "combination (rule_id, rule_version, type pair, template, "
            f"index_variant={str(payload.table.index_variant.value)}) is not in "
            "the reviewed combination whitelist",
        )
    return result


def _count_atoms(predicate: Predicate) -> int:
    if isinstance(predicate, (Compare, Between, IsNull)):
        return 1
    return _count_atoms(predicate.left) + _count_atoms(predicate.right)


def _atom_problems(predicate: Predicate) -> list[str]:
    """Structural re-checks of one predicate subtree (defensive; the contract
    models already reject most of these, but validate_case re-derives).

    - Compare keeps NULL only at the constant position, which is exactly where
      ``Compare.right`` lives; there is no other NULL position in the IR.
    - ``rid`` cannot appear as a predicate column: ``Compare``/``Between``
      carry no column field at all, their left/value side is fixed to ``v``.
    """
    if isinstance(predicate, (And, Or)):
        return _atom_problems(predicate.left) + _atom_problems(predicate.right)
    if isinstance(predicate, (Compare, IsNull)):
        return []
    if isinstance(predicate, Between):
        lower = predicate.lower.value
        upper = predicate.upper.value
        if isinstance(lower, NullValue) or isinstance(upper, NullValue):
            return ["BETWEEN endpoints must not be NULL"]
        if isinstance(lower, IntegerValue) and isinstance(upper, IntegerValue):
            if lower.value > upper.value:
                return [
                    f"BETWEEN endpoints reversed: lower {lower.value} > "
                    f"upper {upper.value}"
                ]
            return []
        if (
            isinstance(lower, DecimalValue)
            and isinstance(upper, DecimalValue)
            and lower.scale == upper.scale
        ):
            if lower.coefficient > upper.coefficient:
                return [
                    f"BETWEEN endpoints reversed: lower {lower.coefficient}e-"
                    f"{lower.scale} > upper {upper.coefficient}e-{upper.scale}"
                ]
            return []
        return [
            "BETWEEN endpoints must be same-kind, equal-scale non-NULL exact "
            "values; cross-kind or mixed-scale endpoints are illegal"
        ]
    return [f"unsupported predicate atom {type(predicate).__name__}"]


def _check_predicate_structure(query: QuerySpec) -> ConditionResult:
    """R02 template-shape whitelist, re-derived from the IR (design 6.2.2).

    Q1 carries no predicate and no arithmetic; Q2 requires a predicate and no
    arithmetic; Q3 never carries arithmetic; Q4 carries exactly one ``v +/- k``
    arithmetic node reused by the single projection, with k in [-16, 16].
    Between endpoints are non-NULL with lower <= upper compared exactly.
    """
    condition = "predicate_structure"
    problems: list[str] = []
    template = query.template_id
    if template is TemplateId.Q1:
        if query.predicate is not None:
            problems.append("Q1 must not carry a predicate")
        if query.arithmetic is not None:
            problems.append("Q1 must not carry arithmetic")
    elif template is TemplateId.Q2:
        if query.predicate is None:
            problems.append("Q2 requires a predicate")
        if query.arithmetic is not None:
            problems.append("Q2 must not carry arithmetic")
    elif template is TemplateId.Q3:
        if query.arithmetic is not None:
            problems.append("Q3 must not carry arithmetic")
    else:  # Q4
        if query.arithmetic is None:
            problems.append("Q4 requires exactly one v +/- k arithmetic node")
        else:
            if query.projections != (Projection("c0", query.arithmetic),):
                problems.append(
                    "Q4 projection must reuse the single arithmetic node"
                )
            k = query.arithmetic.constant.value
            if not ARITHMETIC_K_MIN <= k <= ARITHMETIC_K_MAX:
                problems.append(
                    f"arithmetic constant k={k} outside "
                    f"[{ARITHMETIC_K_MIN}, {ARITHMETIC_K_MAX}]"
                )
    if query.predicate is not None:
        if _count_atoms(query.predicate) > DEFAULT_PREDICATE_ATOM_LIMIT:
            problems.append(
                f"predicate joins more than {DEFAULT_PREDICATE_ATOM_LIMIT} atoms"
            )
        problems.extend(_atom_problems(query.predicate))
    if problems:
        return _violated(condition, ReasonCode.INVALID_STRUCTURE, "; ".join(problems))
    return _satisfied(condition, f"{str(template.value)} predicate/arithmetic shape is legal")


def _check_relation_declaration(payload: CasePayload) -> ConditionResult:
    """The declared relation must equal the relation derived from the rule
    binding, column by column (design 6.2.2)."""
    condition = "relation_declaration"
    derived = derive_relation(
        payload.rule, payload.a_type, payload.b_type, payload.query.template_id
    )
    declared = payload.relation
    if derived.mode != declared.mode:
        return _violated(
            condition,
            ReasonCode.INVALID_STRUCTURE,
            f"relation mode {str(declared.mode.value)} does not match the "
            f"derived mode {str(derived.mode.value)}",
        )
    if len(derived.columns) != len(declared.columns):
        return _violated(
            condition,
            ReasonCode.INVALID_STRUCTURE,
            f"relation declares {len(declared.columns)} columns, the derived "
            f"relation has {len(derived.columns)}",
        )
    for index, (expected, actual) in enumerate(zip(derived.columns, declared.columns)):
        for attribute in ("alias", "a_family", "b_family", "value_equivalence", "null_policy"):
            expected_value = getattr(expected, attribute)
            actual_value = getattr(actual, attribute)
            if expected_value != actual_value:
                return _violated(
                    condition,
                    ReasonCode.INVALID_STRUCTURE,
                    f"relation column {index} attribute {attribute} is "
                    f"{actual_value!r}, the derived relation requires {expected_value!r}",
                )
    return _satisfied(condition, "declared relation matches the derived relation")


def _check_environment(payload: CasePayload) -> ConditionResult:
    """Payload environment must be exactly the frozen mysql80/innodb/
    same-instance session contract (design 6.2.5)."""
    condition = "environment_requirements"
    if payload.environment != _REQUIRED_ENVIRONMENT:
        return _violated(
            condition,
            ReasonCode.UNSUPPORTED_ENVIRONMENT,
            "payload environment deviates from the frozen mysql80/innodb/"
            "same-instance session contract",
        )
    return _satisfied(condition, "environment matches the frozen session contract")


def _check_generation_identity(payload: CasePayload) -> ConditionResult:
    """Only payloads sealed by g1 and renderer r1/1 are accepted; unknown
    identities/versions are rejected as unknown_version (design 6.2.4)."""
    condition = "generation_identity"
    generator = payload.generator
    if generator.id != GENERATOR_IDENTITY.id or generator.version != GENERATOR_IDENTITY.version:
        return _violated(
            condition,
            ReasonCode.UNKNOWN_VERSION,
            f"generator identity {generator.id}/{generator.version} is not "
            f"{GENERATOR_IDENTITY.id}/{GENERATOR_IDENTITY.version}",
        )
    if payload.renderer != RENDERER_IDENTITY:
        return _violated(
            condition,
            ReasonCode.UNKNOWN_VERSION,
            f"renderer identity {payload.renderer.id}/{payload.renderer.version} "
            f"is not {RENDERER_IDENTITY.id}/{RENDERER_IDENTITY.version}",
        )
    return _satisfied(
        condition,
        f"generator {GENERATOR_IDENTITY.id}/{GENERATOR_IDENTITY.version}, "
        f"renderer {RENDERER_IDENTITY.id}/{RENDERER_IDENTITY.version}",
    )


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------


def validate_case(payload: CasePayload) -> CompatibilityCheck:
    """Independently re-derive every static condition for one payload.

    Returns a STATIC-stage :class:`CompatibilityCheck`: ``VALID_STATIC`` only
    when no condition is VIOLATED, and always carrying the three runtime
    conditions as PENDING/missing_fact in that case.  ``INVALID`` results keep
    only the conditions that were actually evaluable (e.g. with an unknown
    rule the rule-dependent domain checks cannot be re-derived and are not
    fabricated).  No input check conclusion is trusted and no READY/run-pass
    semantics is ever produced.
    """
    if not isinstance(payload, CasePayload):
        raise ContractError("validate_case needs a CasePayload")
    case_id = case_id_of(payload)
    conditions: list[ConditionResult] = [_check_codec_roundtrip(payload)]

    rule: RuleSpec | None
    registered, rule = _check_rule_registered(payload.rule)
    conditions.append(registered)
    if rule is not None:
        conditions.append(_check_rule_enabled(rule))
        conditions.append(_check_rule_binding(rule, payload))

    conditions.append(_check_predicate_structure(payload.query))

    if rule is not None:
        conditions.append(
            check_rows_domain(rule, payload.a_type, payload.b_type, payload.rows)
        )
        conditions.append(
            check_predicate_constants(rule, payload.a_type, payload.b_type, payload.query)
        )
        template = payload.query.template_id
        if template is TemplateId.Q3:
            budget = rule.sum_abs_coefficient_budget
            if budget is None:
                # Registry invariant: every Q3 rule declares a SUM budget.
                conditions.append(
                    _violated(
                        "q3_sum_abs_budget",
                        ReasonCode.INTERNAL_ERROR,
                        f"rule {rule.rule_id}@{rule.rule_version} allows Q3 "
                        "without a SUM budget; registry definition is inconsistent",
                    )
                )
            else:
                # Scale of the loaded logical data: the B-side decimal scale,
                # or 0 for integer logical data (design 6.4.1 step 5).
                b_type = payload.b_type
                scale = b_type.scale if isinstance(b_type, DecimalType) else 0
                conditions.append(check_q3_sum_budget(payload.rows, scale, budget))
        if template is TemplateId.Q4:
            conditions.append(
                check_q4_arithmetic(
                    payload.rows, payload.query.arithmetic, payload.a_type, payload.b_type
                )
            )

    conditions.append(_check_relation_declaration(payload))
    conditions.append(_check_environment(payload))
    conditions.append(_check_generation_identity(payload))

    if any(condition.status is CheckStatus.VIOLATED for condition in conditions):
        status = StaticCheckStatus.INVALID
    else:
        conditions.extend(_RUNTIME_PENDING_CONDITIONS)
        status = StaticCheckStatus.VALID_STATIC
    return CompatibilityCheck(
        stage=CheckStage.STATIC,
        case_id=case_id,
        validator_version=VALIDATOR_IDENTITY.version,
        conditions=tuple(conditions),
        status=status,
    )


def static_check_or_raise(payload: CasePayload) -> CompatibilityCheck:
    """Convenience entry for the generator/transforms: return the check for a
    statically valid payload, raise :class:`StaticValidationError` otherwise
    (design 6.4.1 step 6: a generator candidate rejected by independent
    validation is an internal invariant failure, not a retryable rejection)."""
    check = validate_case(payload)
    if check.status is StaticCheckStatus.INVALID:
        raise StaticValidationError(check)
    return check


# --------------------------------------------------------------------------
# Phase 4: runtime fact validation (design 6.2.5, 6.3.1; V01/V02/V03)
#
# Appended-only section: the imports below belong with this section and are
# kept here so the pre-existing static-validation part of this module stays
# byte-identical.
# --------------------------------------------------------------------------

import re  # noqa: E402  (append-only section import)
from dataclasses import replace as _dataclass_replace  # noqa: E402

from mtsql_typecheck.contracts.case import (  # noqa: E402
    ColumnSpec,
    FACTS_SCHEMA_VERSION,
    ExactValue,
    ExpectedBinding,
    NameMap,
    NullValue,
    ObservedEnvironment,
    RuntimeCheckStatus,
    RuntimeFacts,
    SideFacts,
    StatementPhase,
    TableSpec,
)
from mtsql_typecheck.generation.render import (  # noqa: E402
    RenderPhase,
    render_pair,
)

__all__.extend([
    "RUNTIME_VALIDATOR_IDENTITY",
    "RuntimeFactsError",
    "environment_content_hash",
    "name_map_content_hash",
    "parse_mysql_version_series",
    "validate_runtime_facts",
    "evaluate_observed_environment",
])

# Runtime validator semantic identity: re-validation always produces a new
# object stamped with this version (design 6.2.4).  Semantic changes to any
# condition below must bump it.
RUNTIME_VALIDATOR_IDENTITY = SemverIdentity("runtime-validate", "1")

# Content-hash specification (design 6.2.5: D1 recomputes the environment and
# name-map content hashes instead of comparing self-reported strings):
#
#   environment_hash = sha256_hex(canonical_json(ObservedEnvironment.to_obj()))
#   name_map_hash    = sha256_hex(canonical_json(NameMap.to_obj()))
#
# ``to_obj()`` is the canonical semantic content of each model (sorted keys,
# compact separators, ASCII).  The facts binding, the expected binding and the
# recomputed content hash must all agree; a binding whose
# ``environment_hash``/``name_map_hash`` disagrees with the hash of the
# attached content is rejected even though the two self-reported strings match.


class RuntimeFactsError(ContractError):
    """Malformed runtime-facts input (design 6.2.5: unknown facts versions and
    deformed structures are input errors, not BLOCKED conditions)."""


def environment_content_hash(environment: ObservedEnvironment) -> str:
    """SHA-256 over ``canonical_json(ObservedEnvironment.to_obj())``."""
    if not isinstance(environment, ObservedEnvironment):
        raise RuntimeFactsError("environment_content_hash needs an ObservedEnvironment")
    return sha256_hex(canonical_json(environment.to_obj()))


def name_map_content_hash(name_map: NameMap) -> str:
    """SHA-256 over ``canonical_json(NameMap.to_obj())``."""
    if not isinstance(name_map, NameMap):
        raise RuntimeFactsError("name_map_content_hash needs a NameMap")
    return sha256_hex(canonical_json(name_map.to_obj()))


def evaluate_observed_environment(
    payload: CasePayload, observed: ObservedEnvironment | None
) -> tuple[ConditionResult, ...]:
    """Re-evaluate the frozen environment conditions against one snapshot.

    Pure helper shared by the D2 oracle's preflight-rejection proof (design:
    a structured preflight rejection is NOT_APPLICABLE only when the observed
    snapshot itself proves the rejected requirement is violated).  Uses
    exactly the same condition logic as ``validate_runtime_facts``; the
    payload argument exists so a caller cannot evaluate conditions for
    something that is not a case payload.
    """
    if not isinstance(payload, CasePayload):
        raise RuntimeFactsError("evaluate_observed_environment needs a CasePayload")
    return tuple(_observed_environment_conditions(observed))


# MySQL version-series parsing: the leading dotted-numeric prefix of the
# server version string decides the series ("8.0.39", "8.0.39-log" and
# "8.0.39-1.el9" are all 8.0; "5.7.44", "10.11.6-MariaDB" and "8" are not).
_MYSQL_VERSION_SERIES_RE = re.compile(r"^\s*(\d+)\.(\d+)")


def parse_mysql_version_series(version: str) -> tuple[int, int] | None:
    """Leading ``(major, minor)`` series of a MySQL version string, or None."""
    if not isinstance(version, str):
        raise RuntimeFactsError("parse_mysql_version_series needs a version string")
    match = _MYSQL_VERSION_SERIES_RE.match(version)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)))


# Frozen target series for D1 v1.0 (design 6.2.5: MySQL 8.0 within one
# instance/engine; MariaDB compatibility version strings are not MySQL).
_REQUIRED_VERSION_SERIES = (8, 0)


def _rt_satisfied(condition_id: str, detail: str) -> ConditionResult:
    """Runtime-section SATISFIED with mandatory evidence detail.

    Deliberately not the static-section ``_satisfied``/``_violated`` helpers:
    distinct names keep the appended section from shadowing the functions the
    pre-existing static validator already resolves at call time."""
    return ConditionResult(condition_id, CheckStatus.SATISFIED, None, detail)


def _rt_pending(condition_id: str, detail: str) -> ConditionResult:
    return ConditionResult(condition_id, CheckStatus.PENDING, ReasonCode.MISSING_FACT, detail)


def _rt_violated(condition_id: str, reason: ReasonCode, detail: str) -> ConditionResult:
    return ConditionResult(condition_id, CheckStatus.VIOLATED, reason, detail)


def _aggregate_runtime(
    case_id: str, conditions: tuple[ConditionResult, ...]
) -> CompatibilityCheck:
    """Fixed priority (design 6.2.5): any VIOLATED -> BLOCKED, else any
    PENDING -> INCOMPLETE, else READY.  READY only states that the runtime
    preconditions hold; it never states a query MATCH and this module has no
    MATCH vocabulary at all."""
    if any(condition.status is CheckStatus.VIOLATED for condition in conditions):
        status: RuntimeCheckStatus = RuntimeCheckStatus.BLOCKED
    elif any(condition.status is CheckStatus.PENDING for condition in conditions):
        status = RuntimeCheckStatus.INCOMPLETE
    else:
        status = RuntimeCheckStatus.READY
    return CompatibilityCheck(
        stage=CheckStage.RUNTIME,
        case_id=case_id,
        validator_version=RUNTIME_VALIDATOR_IDENTITY.version,
        conditions=conditions,
        status=status,
    )


# --------------------------------------------------------------------------
# Binding conditions
# --------------------------------------------------------------------------


_BINDING_FIELDS = ("run_id", "case_id", "attempt_id", "environment_hash", "name_map_hash")


def _binding_conditions(
    payload: CasePayload, expected_binding: ExpectedBinding, facts: RuntimeFacts
) -> list[ConditionResult]:
    conditions: list[ConditionResult] = []
    payload_case_id = case_id_of(payload)
    if expected_binding.case_id == payload_case_id:
        conditions.append(
            _rt_satisfied(
                "binding_expected_case",
                f"expected binding case_id matches the payload case_id {payload_case_id}",
            )
        )
    else:
        conditions.append(
            _rt_violated(
                "binding_expected_case",
                ReasonCode.BINDING_MISMATCH,
                f"expected binding case_id {expected_binding.case_id} does not "
                f"match the payload case_id {payload_case_id}",
            )
        )
    facts_binding = facts.binding
    for field in _BINDING_FIELDS:
        condition_id = f"binding_{field}"
        expected_value = getattr(expected_binding, field)
        facts_value = getattr(facts_binding, field)
        if facts_value == expected_value:
            conditions.append(
                _rt_satisfied(condition_id, f"facts binding {field} matches the caller expectation")
            )
        else:
            conditions.append(
                _rt_violated(
                    condition_id,
                    ReasonCode.BINDING_MISMATCH,
                    f"facts binding {field} {facts_value!r} does not match the "
                    f"expected {expected_value!r}",
                )
            )
    environment = facts.observed_environment
    if environment is None:
        conditions.append(
            _rt_pending(
                "binding_content_environment",
                "observed environment not collected; its content hash cannot "
                "be recomputed against binding.environment_hash yet",
            )
        )
    else:
        recomputed = environment_content_hash(environment)
        if recomputed == facts_binding.environment_hash:
            conditions.append(
                _rt_satisfied(
                    "binding_content_environment",
                    "recomputed observed-environment content hash matches "
                    "binding.environment_hash",
                )
            )
        else:
            conditions.append(
                _rt_violated(
                    "binding_content_environment",
                    ReasonCode.BINDING_MISMATCH,
                    "recomputed observed-environment content hash "
                    f"{recomputed} does not match binding.environment_hash "
                    f"{facts_binding.environment_hash}; the environment content "
                    "and its self-reported hash disagree",
                )
            )
    name_map = facts.name_map
    if name_map is None:
        conditions.append(
            _rt_pending(
                "binding_content_name_map",
                "name map not collected; its content hash cannot be "
                "recomputed against binding.name_map_hash yet",
            )
        )
    else:
        recomputed = name_map_content_hash(name_map)
        if recomputed == facts_binding.name_map_hash:
            conditions.append(
                _rt_satisfied(
                    "binding_content_name_map",
                    "recomputed name-map content hash matches "
                    "binding.name_map_hash",
                )
            )
        else:
            conditions.append(
                _rt_violated(
                    "binding_content_name_map",
                    ReasonCode.BINDING_MISMATCH,
                    "recomputed name-map content hash "
                    f"{recomputed} does not match binding.name_map_hash "
                    f"{facts_binding.name_map_hash}; the name-map content and "
                    "its self-reported hash disagree",
                )
            )
    return conditions


# --------------------------------------------------------------------------
# Environment conditions
# --------------------------------------------------------------------------


_ENVIRONMENT_CONDITION_IDS = (
    "observed_environment",
    "version_series",
    "vendor_build",
    "engine",
    "session_snapshot",
    "optimizer_switch",
)


def _environment_conditions(facts: RuntimeFacts) -> list[ConditionResult]:
    return _observed_environment_conditions(facts.observed_environment)


def _observed_environment_conditions(
    environment: ObservedEnvironment | None,
) -> list[ConditionResult]:
    """Environment conditions evaluated against one observed snapshot."""
    if environment is None:
        return [
            _rt_pending(
                condition_id,
                "observed environment was not collected; this condition is "
                "not evaluable and no default environment is assumed",
            )
            for condition_id in _ENVIRONMENT_CONDITION_IDS
        ]
    conditions: list[ConditionResult] = [
        _rt_satisfied(
            "observed_environment",
            f"instance {environment.instance_identity!r} reported its "
            "identity and effective A/B session snapshot",
        )
    ]
    series = parse_mysql_version_series(environment.version)
    if "mariadb" in environment.vendor.lower():
        conditions.append(
            _rt_violated(
                "version_series",
                ReasonCode.UNSUPPORTED_ENVIRONMENT,
                f"vendor {environment.vendor!r} is MariaDB; MariaDB "
                "compatibility version strings are not MySQL 8.0",
            )
        )
    elif series == _REQUIRED_VERSION_SERIES:
        conditions.append(
            _rt_satisfied(
                "version_series",
                f"version {environment.version!r} resolves to the "
                f"{_REQUIRED_VERSION_SERIES[0]}.{_REQUIRED_VERSION_SERIES[1]} series",
            )
        )
    else:
        conditions.append(
            _rt_violated(
                "version_series",
                ReasonCode.UNSUPPORTED_ENVIRONMENT,
                f"version {environment.version!r} does not resolve to the "
                f"{_REQUIRED_VERSION_SERIES[0]}.{_REQUIRED_VERSION_SERIES[1]} series",
            )
        )
    if environment.vendor == "" or environment.build_id == "":
        conditions.append(
            _rt_pending(
                "vendor_build",
                "vendor/build identity is incomplete; a build cannot be "
                "recorded from empty fields",
            )
        )
    else:
        conditions.append(
            _rt_satisfied(
                "vendor_build",
                f"vendor {environment.vendor!r}, build {environment.build_id!r} recorded",
            )
        )
    if environment.engine == "innodb":
        conditions.append(_rt_satisfied("engine", "engine is innodb"))
    else:
        conditions.append(
            _rt_violated(
                "engine",
                ReasonCode.UNSUPPORTED_ENVIRONMENT,
                f"engine {environment.engine!r} is not innodb",
            )
        )
    session_problems: list[str] = []
    if tuple(environment.sql_mode_tokens) != REQUIRED_SQL_MODE_TOKENS:
        session_problems.append(
            f"sql_mode tokens {list(environment.sql_mode_tokens)} are not "
            f"exactly {list(REQUIRED_SQL_MODE_TOKENS)}"
        )
    if environment.character_set != REQUIRED_CHARACTER_SET:
        session_problems.append(
            f"character_set {environment.character_set!r} is not "
            f"{REQUIRED_CHARACTER_SET!r}"
        )
    if environment.collation != REQUIRED_COLLATION:
        session_problems.append(
            f"collation {environment.collation!r} is not {REQUIRED_COLLATION!r}"
        )
    if environment.time_zone != REQUIRED_TIME_ZONE:
        session_problems.append(
            f"time_zone {environment.time_zone!r} is not {REQUIRED_TIME_ZONE!r}"
        )
    if session_problems:
        conditions.append(
            _rt_violated(
                "session_snapshot",
                ReasonCode.UNSUPPORTED_ENVIRONMENT,
                "; ".join(session_problems),
            )
        )
    else:
        conditions.append(
            _rt_satisfied(
                "session_snapshot",
                "effective A/B session snapshot matches the frozen "
                "sql_mode/charset/collation/time_zone contract",
            )
        )
    # optimizer_switch is recorded, never pinned (design 6.2.5).  The
    # ObservedEnvironment model carries one shared A/B snapshot field, so an
    # empty value means the snapshot was not collected; a non-empty value is
    # the recorded common snapshot of both sessions.
    if environment.optimizer_switch == "":
        conditions.append(
            _rt_pending(
                "optimizer_switch",
                "optimizer_switch snapshot is empty; it must be recorded for "
                "both sessions before completeness",
            )
        )
    else:
        conditions.append(
            _rt_satisfied(
                "optimizer_switch",
                f"optimizer_switch recorded (common A/B snapshot): "
                f"{environment.optimizer_switch!r}",
            )
        )
    return conditions


# --------------------------------------------------------------------------
# Per-side conditions
# --------------------------------------------------------------------------


def _expected_side_table(payload: CasePayload, side: str) -> TableSpec:
    """Payload-declared physical schema for one side (rid BIGINT NOT NULL PK
    fixed by the TableSpec model; v column type is the side's declared type).
    D3 normalizes server metadata before it becomes ``actual_schema``, so the
    comparison is structural, not SHOW CREATE TABLE text."""
    v_type = payload.a_type if side == "a" else payload.b_type
    columns = (payload.table.columns[0], ColumnSpec("v", v_type, True))
    return TableSpec(
        payload.table.logical_id, columns, payload.table.primary_key, payload.table.index_variant
    )


def _expected_receipts(
    payload: CasePayload, name_map: NameMap, side: str
) -> tuple[tuple[StatementPhase, int, str], ...]:
    """Expected DDL/INSERT receipt sequence, computed live from render_pair.

    Ordinals are per-phase and 0-based in render_pair emission order: the DDL
    is ordinal 0 of phase ddl, INSERT batches are ordinals 0..n-1 of phase
    insert; the SELECT renders no receipt.  A zero-row case expects exactly
    one DDL receipt and no INSERT."""
    pair = render_pair(payload, name_map)
    expected: list[tuple[StatementPhase, int, str]] = []
    counters: dict[str, int] = {}
    for statement in getattr(pair, side):
        if statement.phase is RenderPhase.SELECT:
            continue
        phase = StatementPhase(str(statement.phase.value))
        ordinal = counters.get(str(phase.value), 0)
        counters[str(phase.value)] = ordinal + 1
        expected.append((phase, ordinal, statement.sql_hash))
    return tuple(expected)


def _receipt_conditions(
    payload: CasePayload,
    name_map: NameMap | None,
    side_facts: SideFacts | None,
    side: str,
) -> ConditionResult:
    condition_id = f"{side}_receipts"
    if name_map is None:
        return _rt_pending(
            condition_id,
            "name map not collected; the expected render_pair statement "
            "sequence cannot be computed yet",
        )
    if side_facts is None:
        return _rt_pending(condition_id, f"side {side} facts were not collected")
    receipts = side_facts.statement_receipts
    if not receipts:
        return _rt_pending(
            condition_id, f"side {side} has no statement receipts collected yet"
        )
    expected_receipts = _expected_receipts(payload, name_map, side)
    problems: list[str] = []
    if len(receipts) != len(expected_receipts):
        problems.append(
            f"side {side} reports {len(receipts)} receipts but render_pair "
            f"under the facts name map has {len(expected_receipts)} "
            "DDL/INSERT statements"
        )
    for index, (receipt, (phase, ordinal, sql_hash)) in enumerate(
        zip(receipts, expected_receipts)
    ):
        label = f"receipt[{index}]"
        if receipt.phase is not phase:
            problems.append(
                f"{label} phase {str(receipt.phase.value)} is not {str(phase.value)}"
            )
        elif receipt.ordinal != ordinal:
            problems.append(
                f"{label} ordinal {receipt.ordinal} is not {ordinal}"
            )
        elif receipt.sql_hash != sql_hash:
            problems.append(
                f"{label} sql_hash {receipt.sql_hash} does not match the "
                f"render_pair statement hash {sql_hash}"
            )
    if problems:
        return _rt_violated(
            condition_id, ReasonCode.MISSING_FACT, "; ".join(problems)
        )
    diagnostics_problems: list[str] = []
    for receipt in receipts:
        label = f"{str(receipt.phase.value)}#{receipt.ordinal}"
        if not receipt.success:
            diagnostics_problems.append(f"{label} success=false")
        if not receipt.diagnostics_complete:
            diagnostics_problems.append(f"{label} diagnostics_complete=false")
    if diagnostics_problems:
        return _rt_violated(
            condition_id, ReasonCode.LOAD_DIAGNOSTICS, "; ".join(diagnostics_problems)
        )
    return _rt_satisfied(
        condition_id,
        f"all {len(receipts)} expected DDL/INSERT receipts match render_pair "
        f"for side {side} with success and complete diagnostics",
    )


def _schema_condition(
    payload: CasePayload, side_facts: SideFacts | None, side: str
) -> ConditionResult:
    condition_id = f"{side}_schema"
    if side_facts is None:
        return _rt_pending(condition_id, f"side {side} facts were not collected")
    actual_schema = side_facts.actual_schema
    if actual_schema is None:
        return _rt_pending(condition_id, f"side {side} actual schema was not collected")
    expected_schema = _expected_side_table(payload, side)
    if actual_schema == expected_schema:
        return _rt_satisfied(
            condition_id,
            f"side {side} actual schema matches the payload-declared "
            "columns/nullability/order/PK/index variant",
        )
    return _rt_violated(
        condition_id,
        ReasonCode.SCHEMA_MISMATCH,
        f"side {side} actual schema {actual_schema.to_obj()} does not match "
        f"the declared schema {expected_schema.to_obj()}",
    )


def _value_fidelity_problem(expected: ExactValue, actual: ExactValue) -> str | None:
    """Exact readback fidelity for one shared value (design 6.2.5).

    - NULL must stay NULL; a zero or any other value in a NULL position is a
      mismatch (NULL becomes zero is never normalized away).
    - An integer value matches an exact integer or a scale-0 decimal with the
      same mathematical value (integer-decimal B side may report scale=0
      DECIMAL); any other scale or kind is a mismatch.
    - A decimal value matches only a decimal with the same scale and the same
      coefficient; a different coefficient (rounding/precision loss) or a
      scale drift is a mismatch even when the mathematical value would round
      back to the input.
    - Float and string readbacks cannot exist in the model: ExactValue has no
      such kind, so a driver that produced one fails at the contract/codec
      layer as an input error before this function can see it.
    """
    if isinstance(expected, NullValue):
        if isinstance(actual, NullValue):
            return None
        return f"expected NULL, read back {actual.to_obj()}"
    if isinstance(expected, IntegerValue):
        if isinstance(actual, IntegerValue):
            if actual.value == expected.value:
                return None
            return f"expected integer {expected.value}, read back {actual.value}"
        if isinstance(actual, NullValue):
            return f"expected integer {expected.value}, read back NULL"
        # DecimalValue readback of an integer expectation.
        if actual.scale == 0 and actual.coefficient == expected.value:
            return None
        return (
            f"expected integer {expected.value}, read back decimal "
            f"coefficient {actual.coefficient} scale {actual.scale}; only a "
            "scale-0 decimal with the same mathematical value is exact"
        )
    # DecimalValue expectation (decimal-widen: both sides share the scale).
    if isinstance(actual, NullValue):
        return f"expected decimal coefficient {expected.coefficient} scale {expected.scale}, read back NULL"
    if isinstance(actual, IntegerValue):
        return (
            f"expected decimal coefficient {expected.coefficient} scale "
            f"{expected.scale}, read back integer {actual.value}; a decimal "
            "expectation is never matched by an integer readback"
        )
    if actual.scale == expected.scale and actual.coefficient == expected.coefficient:
        return None
    return (
        f"expected decimal coefficient {expected.coefficient} scale "
        f"{expected.scale}, read back coefficient {actual.coefficient} scale "
        f"{actual.scale}; exact fidelity requires the same scale and coefficient"
    )


def _readback_problems(payload: CasePayload, readback) -> list[str]:
    expected_rows = payload.rows.rows
    actual_rows = readback.rows
    problems: list[str] = []
    if len(actual_rows) != len(expected_rows):
        problems.append(
            f"readback holds {len(actual_rows)} rows, the payload has "
            f"{len(expected_rows)} shared rows; the full-set readback must "
            "cover every rid exactly once"
        )
    for index, expected_row in enumerate(expected_rows):
        if index >= len(actual_rows):
            break
        actual_row = actual_rows[index]
        if actual_row.rid != expected_row.rid:
            problems.append(
                f"readback position {index} has rid {actual_row.rid}, expected "
                f"rid {expected_row.rid} (rid set/order must match the payload)"
            )
            continue
        problem = _value_fidelity_problem(expected_row.value, actual_row.value)
        if problem is not None:
            problems.append(f"rid {expected_row.rid}: {problem}")
    return problems


def _readback_condition(
    payload: CasePayload, side_facts: SideFacts | None, side: str
) -> ConditionResult:
    condition_id = f"{side}_readback"
    if side_facts is None:
        return _rt_pending(condition_id, f"side {side} facts were not collected")
    if not side_facts.readback_complete:
        return _rt_pending(
            condition_id,
            f"side {side} readback is not marked complete; a partial readback "
            "is never treated as a full-set match",
        )
    problems = _readback_problems(payload, side_facts.readback)
    if problems:
        return _rt_violated(
            condition_id, ReasonCode.LOAD_VALUE_MISMATCH, "; ".join(problems)
        )
    return _rt_satisfied(
        condition_id,
        f"side {side} complete readback matches all {len(payload.rows.rows)} "
        "shared rows exactly (NULL positions and exact values)",
    )


def _load_condition(side_facts: SideFacts | None, side: str) -> ConditionResult:
    condition_id = f"{side}_load"
    if side_facts is None:
        return _rt_pending(condition_id, f"side {side} facts were not collected")
    committed = side_facts.load_committed
    isolated = side_facts.isolation_confirmed
    if committed is True and isolated is True:
        return _rt_satisfied(
            condition_id,
            f"side {side} load committed and isolation confirmed for the "
            "current attempt",
        )
    # Optional fields absent (None) stay absent: no default is fabricated.
    # An explicit False is also not enough; D3 must positively confirm both.
    missing = [
        name
        for name, value in (("load_committed", committed), ("isolation_confirmed", isolated))
        if value is not True
    ]
    return _rt_pending(
        condition_id,
        f"side {side} has not positively confirmed {', '.join(missing)}; "
        "no default is assumed for absent or false confirmation flags",
    )


def _side_conditions(
    payload: CasePayload, facts: RuntimeFacts, side: str
) -> list[ConditionResult]:
    side_facts: SideFacts | None = getattr(facts, side)
    return [
        _schema_condition(payload, side_facts, side),
        _receipt_conditions(payload, facts.name_map, side_facts, side),
        _readback_condition(payload, side_facts, side),
        _load_condition(side_facts, side),
    ]


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def validate_runtime_facts(
    payload: CasePayload, expected_binding: ExpectedBinding, facts: RuntimeFacts
) -> CompatibilityCheck:
    """Validate D3 runtime facts against a payload and an independent binding
    expectation (design 6.2.5, 6.3.1; V01/V02/V03).

    Contract summary:

    - Static conditions are re-derived by calling :func:`validate_case`; the
      payload's own check conclusions are never trusted.  A static INVALID
      yields a BLOCKED runtime check whose only condition is the first
      VIOLATED static condition, kept verbatim.
    - Binding (V02): ``expected_binding.case_id`` must equal the payload
      case_id, and every facts-binding field (run/case/attempt/
      environment_hash/name_map_hash) must equal the caller expectation.
      Content hashes are recomputed, not compared as self-reported strings:
      ``environment_hash`` must equal
      ``sha256_hex(canonical_json(ObservedEnvironment.to_obj()))`` and
      ``name_map_hash`` must equal
      ``sha256_hex(canonical_json(NameMap.to_obj()))``.  Environment content
      that was tampered with while the binding hash stayed frozen is caught
      here, and replayed facts from a parent attempt are caught by the
      attempt_id field comparison.
    - Facts (V03), per side and per stable condition id (``a_schema``,
      ``a_receipts``, ``a_readback``, ``a_load``, and the ``b_`` twins):
      actual schema must structurally equal the payload-declared side table
      (D3 delivers already-normalized server metadata); statement receipts
      must equal the live render_pair DDL/INSERT sequence (per-phase 0-based
      ordinals, SELECT excluded, zero-row cases keep their DDL receipt) with
      success=true and diagnostics_complete=true; a complete readback must
      cover the shared rid set in order with exact values (NULL stays NULL,
      integers match exact integers or same-value scale-0 decimals, decimals
      match same-scale same-coefficient readbacks); load_committed and
      isolation_confirmed must be positively true.  Absent optional facts are
      PENDING/missing_fact, never fabricated defaults.
    - Environment: version must resolve to the MySQL 8.0 series (MariaDB
      vendors rejected), vendor/build must be non-empty and recorded, engine
      must be innodb, and the session snapshot must match the frozen
      sql_mode/charset/collation/time_zone contract; optimizer_switch is
      recorded and must be non-empty but is never pinned.
    - Priority (fixed): any VIOLATED -> BLOCKED, else any PENDING ->
      INCOMPLETE, else READY.  READY states only that the preconditions hold;
      no MATCH semantics exists in this module.
    - Unknown facts schema versions, missing bindings or non-contract objects
      raise :class:`RuntimeFactsError` (an input error, not a BLOCKED check).
    """
    if not isinstance(payload, CasePayload):
        raise RuntimeFactsError("validate_runtime_facts needs a CasePayload")
    if not isinstance(expected_binding, ExpectedBinding):
        raise RuntimeFactsError("validate_runtime_facts needs an ExpectedBinding")
    if not isinstance(facts, RuntimeFacts):
        raise RuntimeFactsError("validate_runtime_facts needs RuntimeFacts")
    if facts.facts_schema_version != FACTS_SCHEMA_VERSION:
        raise RuntimeFactsError(
            f"unsupported facts_schema_version {facts.facts_schema_version}"
        )
    if not isinstance(facts.binding, ExpectedBinding):
        raise RuntimeFactsError("RuntimeFacts.binding must be an ExpectedBinding")
    case_id = case_id_of(payload)

    static_check = validate_case(payload)
    if static_check.status is StaticCheckStatus.INVALID:
        first_violated = next(
            condition
            for condition in static_check.conditions
            if condition.status is CheckStatus.VIOLATED
        )
        return CompatibilityCheck(
            stage=CheckStage.RUNTIME,
            case_id=case_id,
            validator_version=RUNTIME_VALIDATOR_IDENTITY.version,
            conditions=(first_violated,),
            status=RuntimeCheckStatus.BLOCKED,
        )

    conditions: list[ConditionResult] = [
        _rt_satisfied(
            "static_revalidation",
            "independent validate_case re-run returned VALID_STATIC before "
            "the runtime facts were examined",
        )
    ]
    conditions.extend(_binding_conditions(payload, expected_binding, facts))
    conditions.extend(_environment_conditions(facts))
    conditions.extend(_side_conditions(payload, facts, "a"))
    conditions.extend(_side_conditions(payload, facts, "b"))
    return _aggregate_runtime(case_id, tuple(conditions))
