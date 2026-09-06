"""Strict canonical encoding, decoding and identity for D1 contracts.

Implements design 6.2.3/6.2.4: canonical JSON is exactly
``json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
allow_nan=False).encode("utf-8")`` with no trailing newline, applied only
after a strict type scan.  The loader rejects duplicate JSON keys, floats,
bools in integer positions, non-canonical integer/decimal text, depth > 32,
unknown fields, unknown kinds and unknown schema versions; it never fills in
default semantics.  Deterministic substream helpers (6.2.4) are provided here
for Phase 3.  Importing this module performs no I/O.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Optional

from .case import (
    MAX_JSON_DEPTH,
    MAX_NUMERIC_TEXT_CHARS,
    Arithmetic,
    ArithmeticOp,
    AggregateExpr,
    AggregateFunc,
    And,
    Between,
    CaseBundle,
    CasePayload,
    CaseFileEntry,
    ColumnName,
    ColumnRef,
    ColumnSpec,
    Compare,
    CompareOp,
    CompatibilityCheck,
    ConditionResult,
    ContractError,
    DecimalType,
    DecimalValue,
    EnvironmentRequirements,
    ExactLiteral,
    ExactValue,
    ExpectedBinding,
    GenerationManifest,
    GenerationStatus,
    IndexVariant,
    IntegerValue,
    IsNull,
    NameMap,
    NullValue,
    ObservedEnvironment,
    OrdinalOutcome,
    OrdinalReceipt,
    Or,
    PathNode,
    Predicate,
    Profile,
    Projection,
    QuerySpec,
    ReasonCode,
    ReplaceLiteral,
    RemoveRows,
    ReplaceValue,
    ResultColumnSpec,
    ResultRelationSpec,
    Row,
    Rows,
    RuleRef,
    RuleSelector,
    RuntimeFacts,
    SemverIdentity,
    SideFacts,
    SignedIntegerType,
    SignedIntName,
    StatementPhase,
    StatementReceipt,
    TableSpec,
    TemplateId,
    TransformResult,
    TransformStatus,
    TypeFamily,
    TypeSpec,
    NullPolicy,
    ValueEquivalence,
    RelationMode,
    CheckStage,
    CheckStatus,
    StaticCheckStatus,
    RuntimeCheckStatus,
    Transform,
    Provenance,
    SimplifyPredicate,
)

__all__ = [
    "ContractError",
    "canonical_json",
    "sha256_hex",
    "case_id_of",
    "preview_hash_of",
    "parse_strict_json",
    "load_payload",
    "dump_payload",
    "decode_case_payload",
    "case_seed",
    "substream_block",
    "digest_to_uint",
    "take_from_list",
    "take_in_range",
]

_CASE_SEED_DOMAIN = "typecheck-g1"
_BLOCK_DOMAIN = "typecheck-g1-block"
_SUBSTREAM_DOMAINS = ("rows", "predicate", "arithmetic")

# --------------------------------------------------------------------------
# Strict scanning for canonical encoding
# --------------------------------------------------------------------------


def _scan_strict(value: Any, depth: int) -> None:
    """Reject floats, non-finite values and bools-in-integer-positions.

    Bools are legal JSON values and are accepted only where a model field is
    declared bool; every typed field validator (model and loader paths)
    rejects bool wherever an integer or string is required, which is where
    "integer position" is knowable.  ``depth`` counts container levels, the
    outermost container being level 1.
    """
    if depth > MAX_JSON_DEPTH:
        raise ContractError("canonical_json input nesting exceeds depth 32")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise ContractError("canonical_json forbids float values")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError("canonical_json object keys must be strings")
            _scan_strict(item, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _scan_strict(item, depth + 1)
        return
    raise ContractError(f"canonical_json forbids value of type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, compact, ASCII, no trailing newline."""
    if isinstance(value, (dict, list, tuple)):
        _scan_strict(value, 1)
    else:
        _scan_strict(value, 0)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Lowercase SHA-256 hex of actual bytes."""
    return hashlib.sha256(data).hexdigest()


def case_id_of(payload: CasePayload) -> str:
    """case_id = SHA256(canonical_json(CasePayload))."""
    return sha256_hex(canonical_json(payload.to_obj()))


def preview_hash_of(preview_a_sql: str, preview_b_sql: str) -> str:
    """Hash binding the two logical preview SQL texts together."""
    return sha256_hex(canonical_json(["preview", preview_a_sql, preview_b_sql]))


def artifact_hash(data: bytes) -> str:
    """Artifact hash over the actual file bytes (trailing newline included)."""
    return sha256_hex(data)


# --------------------------------------------------------------------------
# Strict JSON parsing
# --------------------------------------------------------------------------


_CANONICAL_JSON_INT_RE = re.compile(r"^(0|-?[1-9][0-9]{0,79})$")


def _parse_int_hook(text: str) -> int:
    if not _CANONICAL_JSON_INT_RE.match(text) or len(text) > MAX_NUMERIC_TEXT_CHARS:
        raise ContractError(f"non-canonical JSON integer literal: {text!r}")
    return int(text)


def _parse_float_hook(text: str) -> float:
    raise ContractError(f"float literals are forbidden, got {text!r}")


def _parse_constant_hook(text: str) -> float:
    raise ContractError(f"non-finite JSON constant is forbidden: {text!r}")


def _object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _check_depth(value: Any, depth: int) -> None:
    """``depth`` counts container levels; the outermost container is level 1."""
    if depth > MAX_JSON_DEPTH:
        raise ContractError(f"JSON nesting depth exceeds {MAX_JSON_DEPTH}")
    if isinstance(value, dict):
        for item in value.values():
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)


def parse_strict_json(data: bytes | str) -> Any:
    """Parse untrusted JSON with every strictness rule of design 6.2.4."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError(f"input is not valid UTF-8: {exc}") from exc
    elif not isinstance(data, str):
        raise ContractError("parse_strict_json expects bytes or str")
    try:
        value = json.loads(
            data,
            parse_int=_parse_int_hook,
            parse_float=_parse_float_hook,
            parse_constant=_parse_constant_hook,
            object_pairs_hook=_object_pairs_hook,
        )
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid JSON: {exc}") from exc
    _check_depth(value, 1)
    return value


# --------------------------------------------------------------------------
# Deterministic substream primitives (design 6.2.4)
# --------------------------------------------------------------------------


def case_seed(seed: int, ordinal: int) -> str:
    """case_seed = SHA256(canonical_json(["typecheck-g1", seed, ordinal]))."""
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**64 - 1:
        raise ContractError("case_seed seed must be a uint64 int")
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
        raise ContractError("case_seed ordinal must be a non-negative int")
    return sha256_hex(canonical_json([_CASE_SEED_DOMAIN, seed, ordinal]))


def substream_block(
    case_seed_hex: str, retry_index: int, domain: str, counter: int
) -> bytes:
    """SHA256 block for one (retry, domain, counter) draw, as raw 32 bytes."""
    if not re.match(r"^[0-9a-f]{64}$", case_seed_hex):
        raise ContractError("substream_block needs a lowercase 64-hex case_seed")
    for name, value in (("retry_index", retry_index), ("counter", counter)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ContractError(f"substream_block {name} must be a non-negative int")
    if domain not in _SUBSTREAM_DOMAINS:
        raise ContractError(f"substream_block domain must be one of {_SUBSTREAM_DOMAINS}")
    return hashlib.sha256(
        canonical_json([_BLOCK_DOMAIN, case_seed_hex, retry_index, domain, counter])
    ).digest()


def digest_to_uint(digest: bytes) -> int:
    """Interpret a digest as an unsigned big-endian integer."""
    if not isinstance(digest, (bytes, bytearray)):
        raise ContractError("digest_to_uint expects bytes")
    return int.from_bytes(bytes(digest), "big", signed=False)


def take_from_list(digest: bytes, length: int) -> int:
    """Index into an ordered list of ``length`` items via modulo."""
    if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
        raise ContractError("take_from_list length must be a positive int")
    return digest_to_uint(digest) % length


def take_in_range(digest: bytes, lo: int, hi: int) -> int:
    """Closed-range integer draw: lo + digest % (hi - lo + 1)."""
    for name, value in (("lo", lo), ("hi", hi)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ContractError(f"take_in_range {name} must be an int")
    if hi < lo:
        raise ContractError("take_in_range requires hi >= lo")
    return lo + digest_to_uint(digest) % (hi - lo + 1)

# --------------------------------------------------------------------------
# Decoding helpers - strict, no defaults, no unknown fields
# --------------------------------------------------------------------------


def _expect_dict(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{what} must be a JSON object")
    return value


def _expect_kind(obj: dict[str, Any], kind: str, what: str) -> None:
    actual = obj.get("kind")
    if actual != kind:
        raise ContractError(f"{what} requires kind {kind!r}, got {actual!r}")


def _field(obj: dict[str, Any], key: str, what: str) -> Any:
    if key not in obj:
        raise ContractError(f"{what} is missing required field {key!r}")
    return obj[key]


def _no_extra(obj: dict[str, Any], allowed: set[str], what: str) -> None:
    extra = set(obj) - allowed
    if extra:
        raise ContractError(f"{what} has unknown fields: {sorted(extra)}")


def _as_int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{what} must be a JSON integer")
    return value


def _as_str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise ContractError(f"{what} must be a JSON string")
    return value


def _as_bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{what} must be a JSON boolean")
    return value


def _as_enum(enum_cls: type, value: Any, what: str) -> Any:
    if not isinstance(value, str):
        raise ContractError(f"{what} must be a JSON string")
    try:
        return enum_cls(value)
    except ValueError:
        raise ContractError(f"{what} has unknown value {value!r}") from None


def _as_opt(enum_cls: type, value: Any, what: str) -> Any:
    if value is None:
        return None
    return _as_enum(enum_cls, value, what)


def _as_list(value: Any, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError(f"{what} must be a JSON array")
    return value


# --------------------------------------------------------------------------
# Exact values and TypeSpec (design 6.2.3)
# --------------------------------------------------------------------------


def decode_exact_value(obj: Any, what: str = "exact value") -> ExactValue:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"kind", "value", "coefficient", "scale"}, what)
    kind = obj.get("kind")
    if kind == "null":
        _no_extra(obj, {"kind"}, what)
        return NullValue()
    if kind == "integer":
        text = _as_str(_field(obj, "value", what), f"{what}.value")
        if not _CANONICAL_JSON_INT_RE.match(text) or len(text) > MAX_NUMERIC_TEXT_CHARS:
            raise ContractError(f"{what}.value is not canonical decimal text: {text!r}")
        return IntegerValue(int(text))
    if kind == "decimal":
        coefficient_text = _as_str(_field(obj, "coefficient", what), f"{what}.coefficient")
        if (
            not _CANONICAL_JSON_INT_RE.match(coefficient_text)
            or len(coefficient_text) > MAX_NUMERIC_TEXT_CHARS
        ):
            raise ContractError(
                f"{what}.coefficient is not canonical decimal text: {coefficient_text!r}"
            )
        scale = _as_int(_field(obj, "scale", what), f"{what}.scale")
        return DecimalValue(int(coefficient_text), scale)
    raise ContractError(f"{what} has unknown kind {kind!r}")


def decode_type_spec(obj: Any, what: str = "type spec") -> TypeSpec:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"kind", "name", "precision", "scale"}, what)
    kind = obj.get("kind")
    if kind == "signed_integer":
        name = _as_enum(SignedIntName, _field(obj, "name", what), f"{what}.name")
        return SignedIntegerType(name)
    if kind == "decimal":
        precision = _as_int(_field(obj, "precision", what), f"{what}.precision")
        scale = _as_int(_field(obj, "scale", what), f"{what}.scale")
        return DecimalType(precision, scale)
    raise ContractError(f"{what} has unknown kind {kind!r}")


# --------------------------------------------------------------------------
# IR decoding (design 6.2.2, 6.2.3)
# --------------------------------------------------------------------------


def decode_column_ref(obj: Any, what: str = "column ref") -> ColumnRef:
    obj = _expect_dict(obj, what)
    _expect_kind(obj, "column_ref", what)
    _no_extra(obj, {"kind", "column"}, what)
    return ColumnRef(_as_enum(ColumnName, _field(obj, "column", what), f"{what}.column"))


def _decode_literal(obj: Any, what: str) -> ExactLiteral:
    obj = _expect_dict(obj, what)
    _expect_kind(obj, "literal", what)
    _no_extra(obj, {"kind", "value"}, what)
    return ExactLiteral(decode_exact_value(_field(obj, "value", what), f"{what}.value"))


def decode_arithmetic(obj: Any, what: str = "arithmetic") -> Arithmetic:
    obj = _expect_dict(obj, what)
    _expect_kind(obj, "arithmetic", what)
    _no_extra(obj, {"kind", "op", "constant"}, what)
    op = _as_enum(ArithmeticOp, _field(obj, "op", what), f"{what}.op")
    constant_obj = _field(obj, "constant", what)
    constant = decode_exact_value(constant_obj, f"{what}.constant")
    if not isinstance(constant, IntegerValue):
        raise ContractError(f"{what}.constant must be an integer literal")
    return Arithmetic(op, constant)


def decode_predicate(obj: Any, what: str = "predicate") -> Predicate:
    obj = _expect_dict(obj, what)
    kind = obj.get("kind")
    if kind == "compare":
        _no_extra(obj, {"kind", "op", "left", "right"}, what)
        op = _as_enum(CompareOp, _field(obj, "op", what), f"{what}.op")
        left = decode_column_ref(_field(obj, "left", what), f"{what}.left")
        if left.column is not ColumnName.V:
            raise ContractError(f"{what}.left must reference column 'v'")
        right = _decode_literal(_field(obj, "right", what), f"{what}.right")
        return Compare(op, right)
    if kind == "between":
        _no_extra(obj, {"kind", "value", "lower", "upper"}, what)
        value = decode_column_ref(_field(obj, "value", what), f"{what}.value")
        if value.column is not ColumnName.V:
            raise ContractError(f"{what}.value must reference column 'v'")
        lower = _decode_literal(_field(obj, "lower", what), f"{what}.lower")
        upper = _decode_literal(_field(obj, "upper", what), f"{what}.upper")
        return Between(lower, upper)
    if kind == "is_null":
        _no_extra(obj, {"kind", "negated"}, what)
        return IsNull(_as_bool(_field(obj, "negated", what), f"{what}.negated"))
    if kind in ("and", "or"):
        _no_extra(obj, {"kind", "left", "right"}, what)
        left = decode_predicate(_field(obj, "left", what), f"{what}.left")
        right = decode_predicate(_field(obj, "right", what), f"{what}.right")
        # Atoms are Compare/Between/IsNull; compounds arrive with their own kind.
        if isinstance(left, (And, Or)) or isinstance(right, (And, Or)):
            raise ContractError(f"{what} joins more than two atoms or nests compounds")
        return And(left, right) if kind == "and" else Or(left, right)
    raise ContractError(f"{what} has unknown predicate kind {kind!r}")


def decode_projection(obj: Any, what: str = "projection") -> Projection:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"alias", "expr"}, what)
    alias = _as_str(_field(obj, "alias", what), f"{what}.alias")
    expr_obj = _field(obj, "expr", what)
    expr_obj = _expect_dict(expr_obj, f"{what}.expr")
    kind = expr_obj.get("kind")
    if kind == "column_ref":
        expr: Any = decode_column_ref(expr_obj, f"{what}.expr")
    elif kind == "arithmetic":
        expr = decode_arithmetic(expr_obj, f"{what}.expr")
    elif kind == "aggregate":
        _no_extra(expr_obj, {"kind", "func", "column"}, f"{what}.expr")
        func = _as_enum(AggregateFunc, _field(expr_obj, "func", f"{what}.expr"), "func")
        column_obj = expr_obj.get("column")
        if func is AggregateFunc.COUNT_STAR:
            if column_obj is not None:
                raise ContractError("COUNT(*) projection takes no column")
            column = None
        else:
            if column_obj is None:
                raise ContractError(f"aggregate {func} requires a column")
            column = decode_column_ref(column_obj, f"{what}.expr.column")
        expr = AggregateExpr(func, column)
    else:
        raise ContractError(f"{what}.expr has unknown kind {kind!r}")
    return Projection(alias, expr)


def decode_query_spec(obj: Any, what: str = "query spec") -> QuerySpec:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"template_id", "predicate", "arithmetic", "projections"}, what)
    template = _as_enum(TemplateId, _field(obj, "template_id", what), f"{what}.template_id")
    predicate_obj = obj.get("predicate")
    predicate = None if predicate_obj is None else decode_predicate(predicate_obj, f"{what}.predicate")
    arithmetic_obj = obj.get("arithmetic")
    arithmetic = (
        None if arithmetic_obj is None else decode_arithmetic(arithmetic_obj, f"{what}.arithmetic")
    )
    projections = tuple(
        decode_projection(item, f"{what}.projections[{index}]")
        for index, item in enumerate(_as_list(_field(obj, "projections", what), f"{what}.projections"))
    )
    return QuerySpec(template, predicate, arithmetic, projections)


def decode_rows(obj: Any, what: str = "rows", max_rows: int = 1024) -> Rows:
    items = _as_list(obj, what)
    rows: list[Row] = []
    for index, item in enumerate(items):
        item = _as_list(item, f"{what}[{index}]")
        if len(item) != 2:
            raise ContractError(f"{what}[{index}] must be a [rid, value] pair")
        rid = _as_int(item[0], f"{what}[{index}].rid")
        rows.append(Row(rid, decode_exact_value(item[1], f"{what}[{index}].value")))
    return Rows(tuple(rows), max_rows=max_rows)


# --------------------------------------------------------------------------
# Schema, rule, relation, environment decoding
# --------------------------------------------------------------------------


def decode_column_spec(obj: Any, what: str = "column spec") -> ColumnSpec:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"name", "type", "nullable"}, what)
    return ColumnSpec(
        _as_str(_field(obj, "name", what), f"{what}.name"),
        decode_type_spec(_field(obj, "type", what), f"{what}.type"),
        _as_bool(_field(obj, "nullable", what), f"{what}.nullable"),
    )


def decode_table_spec(obj: Any, what: str = "table spec") -> TableSpec:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"logical_id", "columns", "primary_key", "index_variant"}, what)
    columns = tuple(
        decode_column_spec(item, f"{what}.columns[{index}]")
        for index, item in enumerate(_as_list(_field(obj, "columns", what), f"{what}.columns"))
    )
    primary_key = tuple(
        _as_str(item, f"{what}.primary_key[{index}]")
        for index, item in enumerate(
            _as_list(_field(obj, "primary_key", what), f"{what}.primary_key")
        )
    )
    return TableSpec(
        _as_str(_field(obj, "logical_id", what), f"{what}.logical_id"),
        columns,
        primary_key,
        _as_enum(IndexVariant, _field(obj, "index_variant", what), f"{what}.index_variant"),
    )


def decode_rule_ref(obj: Any, what: str = "rule ref") -> RuleRef:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"rule_id", "rule_version"}, what)
    return RuleRef(
        _as_str(_field(obj, "rule_id", what), f"{what}.rule_id"),
        _as_int(_field(obj, "rule_version", what), f"{what}.rule_version"),
    )


def decode_relation(obj: Any, what: str = "relation spec") -> ResultRelationSpec:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"mode", "columns"}, what)
    mode = _as_enum(RelationMode, _field(obj, "mode", what), f"{what}.mode")
    columns: list[ResultColumnSpec] = []
    for index, item in enumerate(_as_list(_field(obj, "columns", what), f"{what}.columns")):
        item = _expect_dict(item, f"{what}.columns[{index}]")
        _no_extra(
            item,
            {"alias", "a_family", "b_family", "value_equivalence", "null_policy"},
            f"{what}.columns[{index}]",
        )
        columns.append(
            ResultColumnSpec(
                _as_str(item["alias"], "alias"),
                _as_enum(TypeFamily, item["a_family"], "a_family"),
                _as_enum(TypeFamily, item["b_family"], "b_family"),
                _as_enum(ValueEquivalence, item["value_equivalence"], "value_equivalence"),
                _as_enum(NullPolicy, item["null_policy"], "null_policy"),
            )
        )
    return ResultRelationSpec(mode, tuple(columns))


def decode_environment(obj: Any, what: str = "environment") -> EnvironmentRequirements:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "database",
            "engine",
            "scope",
            "sql_mode_tokens",
            "character_set",
            "collation",
            "time_zone",
        },
        what,
    )
    tokens = tuple(
        _as_str(item, f"{what}.sql_mode_tokens[{index}]")
        for index, item in enumerate(
            _as_list(_field(obj, "sql_mode_tokens", what), f"{what}.sql_mode_tokens")
        )
    )
    return EnvironmentRequirements(
        database=_as_str(_field(obj, "database", what), f"{what}.database"),
        engine=_as_str(_field(obj, "engine", what), f"{what}.engine"),
        scope=_as_str(_field(obj, "scope", what), f"{what}.scope"),
        sql_mode_tokens=tokens,
        character_set=_as_str(_field(obj, "character_set", what), f"{what}.character_set"),
        collation=_as_str(_field(obj, "collation", what), f"{what}.collation"),
        time_zone=_as_str(_field(obj, "time_zone", what), f"{what}.time_zone"),
    )


def decode_semver_identity(obj: Any, what: str = "identity") -> SemverIdentity:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"id", "version"}, what)
    return SemverIdentity(
        _as_str(_field(obj, "id", what), f"{what}.id"),
        _as_str(_field(obj, "version", what), f"{what}.version"),
    )


# --------------------------------------------------------------------------
# Payload, bundle, checks, facts, manifest, transform, profile decoding
# --------------------------------------------------------------------------


def decode_case_payload(obj: Any, what: str = "case payload") -> CasePayload:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "case_schema_version",
            "rule",
            "a_type",
            "b_type",
            "table",
            "rows",
            "query",
            "relation",
            "environment",
            "generator",
            "renderer",
        },
        what,
    )
    version = _as_int(_field(obj, "case_schema_version", what), f"{what}.case_schema_version")
    if version != 1:
        raise ContractError(f"{what} has unsupported case_schema_version {version}")
    return CasePayload(
        rule=decode_rule_ref(_field(obj, "rule", what), f"{what}.rule"),
        a_type=decode_type_spec(_field(obj, "a_type", what), f"{what}.a_type"),
        b_type=decode_type_spec(_field(obj, "b_type", what), f"{what}.b_type"),
        table=decode_table_spec(_field(obj, "table", what), f"{what}.table"),
        rows=decode_rows(_field(obj, "rows", what), f"{what}.rows"),
        query=decode_query_spec(_field(obj, "query", what), f"{what}.query"),
        relation=decode_relation(_field(obj, "relation", what), f"{what}.relation"),
        environment=decode_environment(
            _field(obj, "environment", what), f"{what}.environment"
        ),
        generator=decode_semver_identity(_field(obj, "generator", what), f"{what}.generator"),
        renderer=decode_semver_identity(_field(obj, "renderer", what), f"{what}.renderer"),
        case_schema_version=version,
    )


def decode_provenance(obj: Any, what: str = "provenance") -> Provenance:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"seed", "ordinal", "profile_hash", "retry"}, what)
    return Provenance(
        seed=_as_int(_field(obj, "seed", what), f"{what}.seed"),
        ordinal=_as_int(_field(obj, "ordinal", what), f"{what}.ordinal"),
        profile_hash=_as_str(_field(obj, "profile_hash", what), f"{what}.profile_hash"),
        retry=_as_int(_field(obj, "retry", what), f"{what}.retry"),
    )


def decode_condition(obj: Any, what: str = "condition") -> ConditionResult:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"condition_id", "status", "reason", "detail"}, what)
    return ConditionResult(
        condition_id=_as_str(_field(obj, "condition_id", what), f"{what}.condition_id"),
        status=_as_enum(CheckStatus, _field(obj, "status", what), f"{what}.status"),
        reason=_as_opt(ReasonCode, obj.get("reason"), f"{what}.reason"),
        detail=obj.get("detail"),
    )


def decode_compatibility_check(obj: Any, what: str = "compatibility check") -> CompatibilityCheck:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {"stage", "case_id", "validator_version", "conditions", "status"},
        what,
    )
    stage = _as_enum(CheckStage, _field(obj, "stage", what), f"{what}.stage")
    status_value = _field(obj, "status", what)
    if stage is CheckStage.STATIC:
        status: Any = _as_enum(StaticCheckStatus, status_value, f"{what}.status")
    else:
        status = _as_enum(RuntimeCheckStatus, status_value, f"{what}.status")
    conditions = tuple(
        decode_condition(item, f"{what}.conditions[{index}]")
        for index, item in enumerate(
            _as_list(_field(obj, "conditions", what), f"{what}.conditions")
        )
    )
    return CompatibilityCheck(
        stage=stage,
        case_id=_as_str(_field(obj, "case_id", what), f"{what}.case_id"),
        validator_version=_as_str(
            _field(obj, "validator_version", what), f"{what}.validator_version"
        ),
        conditions=conditions,
        status=status,
    )


def decode_case_bundle(obj: Any, what: str = "case bundle") -> CaseBundle:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"payload", "case_id", "provenance", "preview", "static_check"}, what)
    payload = decode_case_payload(_field(obj, "payload", what), f"{what}.payload")
    preview = _expect_dict(_field(obj, "preview", what), f"{what}.preview")
    _no_extra(preview, {"a_sql", "b_sql", "hash"}, f"{what}.preview")
    static_check = decode_compatibility_check(
        _field(obj, "static_check", what), f"{what}.static_check"
    )
    # Construction re-derives case_id; a stored id that disagrees is rejected.
    return CaseBundle(
        payload=payload,
        provenance=decode_provenance(_field(obj, "provenance", what), f"{what}.provenance"),
        preview_a_sql=_as_str(preview["a_sql"], f"{what}.preview.a_sql"),
        preview_b_sql=_as_str(preview["b_sql"], f"{what}.preview.b_sql"),
        static_check=static_check,
        case_id=_as_str(_field(obj, "case_id", what), f"{what}.case_id"),
    )


def decode_expected_binding(obj: Any, what: str = "expected binding") -> ExpectedBinding:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {"run_id", "case_id", "attempt_id", "environment_hash", "name_map_hash"},
        what,
    )
    return ExpectedBinding(
        run_id=_as_str(_field(obj, "run_id", what), f"{what}.run_id"),
        case_id=_as_str(_field(obj, "case_id", what), f"{what}.case_id"),
        attempt_id=_as_str(_field(obj, "attempt_id", what), f"{what}.attempt_id"),
        environment_hash=_as_str(
            _field(obj, "environment_hash", what), f"{what}.environment_hash"
        ),
        name_map_hash=_as_str(_field(obj, "name_map_hash", what), f"{what}.name_map_hash"),
    )


def decode_statement_receipt(obj: Any, what: str = "statement receipt") -> StatementReceipt:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {"phase", "ordinal", "sql_hash", "success", "diagnostics_complete"},
        what,
    )
    return StatementReceipt(
        phase=_as_enum(StatementPhase, obj["phase"], f"{what}.phase"),
        ordinal=_as_int(obj["ordinal"], f"{what}.ordinal"),
        sql_hash=_as_str(obj["sql_hash"], f"{what}.sql_hash"),
        success=_as_bool(obj["success"], f"{what}.success"),
        diagnostics_complete=_as_bool(
            obj["diagnostics_complete"], f"{what}.diagnostics_complete"
        ),
    )


def decode_observed_environment(obj: Any, what: str = "observed environment") -> ObservedEnvironment:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "instance_identity",
            "version",
            "vendor",
            "build_id",
            "engine",
            "sql_mode_tokens",
            "character_set",
            "collation",
            "time_zone",
            "optimizer_switch",
        },
        what,
    )
    tokens = tuple(
        _as_str(item, f"{what}.sql_mode_tokens[{index}]")
        for index, item in enumerate(_as_list(obj["sql_mode_tokens"], f"{what}.sql_mode_tokens"))
    )
    return ObservedEnvironment(
        instance_identity=_as_str(obj["instance_identity"], "instance_identity"),
        version=_as_str(obj["version"], "version"),
        vendor=_as_str(obj["vendor"], "vendor"),
        build_id=_as_str(obj["build_id"], "build_id"),
        engine=_as_str(obj["engine"], "engine"),
        sql_mode_tokens=tokens,
        character_set=_as_str(obj["character_set"], "character_set"),
        collation=_as_str(obj["collation"], "collation"),
        time_zone=_as_str(obj["time_zone"], "time_zone"),
        optimizer_switch=_as_str(obj["optimizer_switch"], "optimizer_switch"),
    )


def decode_name_map(obj: Any, what: str = "name map") -> NameMap:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"database_a", "database_b", "table_a", "table_b"}, what)
    return NameMap(
        database_a=_as_str(obj["database_a"], f"{what}.database_a"),
        database_b=_as_str(obj["database_b"], f"{what}.database_b"),
        table_a=_as_str(obj["table_a"], f"{what}.table_a"),
        table_b=_as_str(obj["table_b"], f"{what}.table_b"),
    )


def decode_side_facts(obj: Any, what: str = "side facts") -> SideFacts:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "statement_receipts",
            "readback",
            "readback_complete",
            "actual_schema",
            "load_committed",
            "isolation_confirmed",
        },
        what,
    )
    receipts = tuple(
        decode_statement_receipt(item, f"{what}.statement_receipts[{index}]")
        for index, item in enumerate(
            _as_list(obj["statement_receipts"], f"{what}.statement_receipts")
        )
    )
    actual_schema = (
        None
        if obj["actual_schema"] is None
        else decode_table_spec(obj["actual_schema"], f"{what}.actual_schema")
    )
    load_committed = obj["load_committed"]
    if load_committed is not None:
        load_committed = _as_bool(load_committed, f"{what}.load_committed")
    isolation_confirmed = obj["isolation_confirmed"]
    if isolation_confirmed is not None:
        isolation_confirmed = _as_bool(isolation_confirmed, f"{what}.isolation_confirmed")
    return SideFacts(
        statement_receipts=receipts,
        readback=decode_rows(obj["readback"], f"{what}.readback", max_rows=1024),
        readback_complete=_as_bool(obj["readback_complete"], f"{what}.readback_complete"),
        actual_schema=actual_schema,
        load_committed=load_committed,
        isolation_confirmed=isolation_confirmed,
    )


def decode_runtime_facts(obj: Any, what: str = "runtime facts") -> RuntimeFacts:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "facts_schema_version",
            "binding",
            "observed_environment",
            "name_map",
            "a",
            "b",
        },
        what,
    )
    version = _as_int(obj["facts_schema_version"], f"{what}.facts_schema_version")
    if version != 1:
        raise ContractError(f"{what} has unsupported facts_schema_version {version}")
    return RuntimeFacts(
        binding=decode_expected_binding(obj["binding"], f"{what}.binding"),
        observed_environment=(
            None
            if obj["observed_environment"] is None
            else decode_observed_environment(obj["observed_environment"], f"{what}.observed_environment")
        ),
        name_map=(
            None if obj["name_map"] is None else decode_name_map(obj["name_map"], f"{what}.name_map")
        ),
        a=None if obj["a"] is None else decode_side_facts(obj["a"], f"{what}.a"),
        b=None if obj["b"] is None else decode_side_facts(obj["b"], f"{what}.b"),
        facts_schema_version=version,
    )


def decode_ordinal_receipt(obj: Any, what: str = "ordinal receipt") -> OrdinalReceipt:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"ordinal", "outcome", "case_id", "retry_count", "reason"}, what)
    return OrdinalReceipt(
        ordinal=_as_int(obj["ordinal"], f"{what}.ordinal"),
        outcome=_as_enum(OrdinalOutcome, obj["outcome"], f"{what}.outcome"),
        case_id=obj.get("case_id"),
        retry_count=_as_int(obj["retry_count"], f"{what}.retry_count"),
        reason=obj.get("reason"),
    )


def decode_case_file_entry(obj: Any, what: str = "case file entry") -> CaseFileEntry:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"case_id", "artifact_hash", "size_bytes"}, what)
    return CaseFileEntry(
        case_id=_as_str(obj["case_id"], f"{what}.case_id"),
        artifact_hash=_as_str(obj["artifact_hash"], f"{what}.artifact_hash"),
        size_bytes=_as_int(obj["size_bytes"], f"{what}.size_bytes"),
    )


def decode_generation_manifest(obj: Any, what: str = "generation manifest") -> GenerationManifest:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "generation_schema_version",
            "profile_hash",
            "seed",
            "generator",
            "status",
            "statistics",
            "receipts",
            "case_files",
            "reason",
        },
        what,
    )
    version = _as_int(obj["generation_schema_version"], f"{what}.generation_schema_version")
    if version != 1:
        raise ContractError(f"{what} has unsupported generation_schema_version {version}")
    stats = _expect_dict(obj["statistics"], f"{what}.statistics")
    _no_extra(
        stats,
        {
            "requested_ordinals",
            "attempted_candidates",
            "emitted_occurrences",
            "unique_cases",
            "rejected_ordinals",
            "interrupted_ordinals",
            "not_attempted",
        },
        f"{what}.statistics",
    )
    reason = obj.get("reason")
    return GenerationManifest(
        generation_schema_version=version,
        profile_hash=_as_str(obj["profile_hash"], f"{what}.profile_hash"),
        seed=_as_int(obj["seed"], f"{what}.seed"),
        generator=decode_semver_identity(obj["generator"], f"{what}.generator"),
        status=_as_enum(GenerationStatus, obj["status"], f"{what}.status"),
        requested_ordinals=_as_int(stats["requested_ordinals"], "requested_ordinals"),
        attempted_candidates=_as_int(stats["attempted_candidates"], "attempted_candidates"),
        emitted_occurrences=_as_int(stats["emitted_occurrences"], "emitted_occurrences"),
        unique_cases=_as_int(stats["unique_cases"], "unique_cases"),
        rejected_ordinals=_as_int(stats["rejected_ordinals"], "rejected_ordinals"),
        interrupted_ordinals=_as_int(stats["interrupted_ordinals"], "interrupted_ordinals"),
        not_attempted=_as_int(stats["not_attempted"], "not_attempted"),
        receipts=tuple(
            decode_ordinal_receipt(item, f"{what}.receipts[{index}]")
            for index, item in enumerate(_as_list(obj["receipts"], f"{what}.receipts"))
        ),
        case_files=tuple(
            decode_case_file_entry(item, f"{what}.case_files[{index}]")
            for index, item in enumerate(_as_list(obj["case_files"], f"{what}.case_files"))
        ),
        reason=reason,
    )


def decode_transform(obj: Any, what: str = "transform") -> Transform:
    obj = _expect_dict(obj, what)
    kind = obj.get("kind")
    if kind == "remove_rows":
        _no_extra(obj, {"kind", "rids"}, what)
        rids = tuple(
            _as_int(item, f"{what}.rids[{index}]")
            for index, item in enumerate(_as_list(obj["rids"], f"{what}.rids"))
        )
        return RemoveRows(rids)
    if kind == "replace_value":
        _no_extra(obj, {"kind", "rid", "value"}, what)
        return ReplaceValue(
            _as_int(obj["rid"], f"{what}.rid"),
            decode_exact_value(obj["value"], f"{what}.value"),
        )
    if kind == "simplify_predicate":
        _no_extra(obj, {"kind", "path"}, what)
        return SimplifyPredicate(_decode_path(obj["path"], what))
    if kind == "replace_literal":
        _no_extra(obj, {"kind", "path", "value"}, what)
        return ReplaceLiteral(
            _decode_path(obj["path"], what),
            decode_exact_value(obj["value"], f"{what}.value"),
        )
    raise ContractError(f"{what} has unknown transform kind {kind!r}")


def _decode_path(value: Any, what: str) -> tuple[PathNode, ...]:
    return tuple(
        _as_enum(PathNode, item, f"{what}.path[{index}]")
        for index, item in enumerate(_as_list(value, f"{what}.path"))
    )


def decode_transform_result(obj: Any, what: str = "transform result") -> TransformResult:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "parent_case_id",
            "transform",
            "status",
            "child",
            "static_check",
            "rejection_reason",
        },
        what,
    )
    child = None if obj["child"] is None else decode_case_bundle(obj["child"], f"{what}.child")
    static_check = (
        None
        if obj["static_check"] is None
        else decode_compatibility_check(obj["static_check"], f"{what}.static_check")
    )
    return TransformResult(
        parent_case_id=_as_str(obj["parent_case_id"], f"{what}.parent_case_id"),
        transform=decode_transform(obj["transform"], f"{what}.transform"),
        status=_as_enum(TransformStatus, obj["status"], f"{what}.status"),
        child=child,
        static_check=static_check,
        rejection_reason=_as_opt(ReasonCode, obj.get("rejection_reason"), f"{what}.rejection_reason"),
    )


def decode_rule_selector(obj: Any, what: str = "rule selector") -> RuleSelector:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"rule_id", "rule_version"}, what)
    return RuleSelector(
        _as_str(obj["rule_id"], f"{what}.rule_id"),
        _as_int(obj["rule_version"], f"{what}.rule_version"),
    )


def decode_profile(obj: Any, what: str = "profile") -> Profile:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "profile_schema_version",
            "rules",
            "templates",
            "index_variants",
            "row_count",
            "predicate_atoms",
            "attempts_per_ordinal",
            "max_payload_bytes",
            "max_bundle_bytes",
        },
        what,
    )
    version = _as_int(obj["profile_schema_version"], f"{what}.profile_schema_version")
    if version != 1:
        raise ContractError(f"{what} has unsupported profile_schema_version {version}")
    return Profile(
        profile_schema_version=version,
        rules=tuple(
            decode_rule_selector(item, f"{what}.rules[{index}]")
            for index, item in enumerate(_as_list(obj["rules"], f"{what}.rules"))
        ),
        templates=tuple(
            _as_enum(TemplateId, item, f"{what}.templates[{index}]")
            for index, item in enumerate(_as_list(obj["templates"], f"{what}.templates"))
        ),
        index_variants=tuple(
            _as_enum(IndexVariant, item, f"{what}.index_variants[{index}]")
            for index, item in enumerate(_as_list(obj["index_variants"], f"{what}.index_variants"))
        ),
        row_count=_as_int(obj["row_count"], f"{what}.row_count"),
        predicate_atoms=_as_int(obj["predicate_atoms"], f"{what}.predicate_atoms"),
        attempts_per_ordinal=_as_int(
            obj["attempts_per_ordinal"], f"{what}.attempts_per_ordinal"
        ),
        max_payload_bytes=_as_int(obj["max_payload_bytes"], f"{what}.max_payload_bytes"),
        max_bundle_bytes=_as_int(obj["max_bundle_bytes"], f"{what}.max_bundle_bytes"),
    )


# --------------------------------------------------------------------------
# Public load/dump entry points
# --------------------------------------------------------------------------


def dump_payload(payload: CasePayload) -> bytes:
    """Canonical payload bytes (no trailing newline)."""
    return canonical_json(payload.to_obj())


def load_payload(data: bytes | str) -> CasePayload:
    """Strict loader: untrusted bytes -> validated CasePayload."""
    return decode_case_payload(parse_strict_json(data))


def dump_json_document(value: Any) -> bytes:
    """Canonical bytes for any contract object with a to_obj()."""
    return canonical_json(value.to_obj())
