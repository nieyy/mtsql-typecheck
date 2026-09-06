"""Immutable contract models for TypeCheck D1 (design doc sections 6.2.2-6.2.6, 6.3).

Every model is a frozen dataclass built from Enums, tuples and exact numeric
values.  No float, no free SQL text, no unknown-field tolerance.  All semantic
validation runs in ``__post_init__`` so that both the Python construction path
and the strict loader (``mtsql_typecheck.contracts.codec``) enforce the same
invariants.  Importing this module performs no I/O.

Schema versions frozen by D1 v1.0: case=1, facts=1, profile=1, generation=1.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Literal, Optional, Union

# --------------------------------------------------------------------------
# Errors and frozen schema versions
# --------------------------------------------------------------------------


class ContractError(ValueError):
    """Raised when a model or decoded document violates a frozen contract."""


CASE_SCHEMA_VERSION = 1
FACTS_SCHEMA_VERSION = 1
PROFILE_SCHEMA_VERSION = 1
GENERATION_SCHEMA_VERSION = 1

# Loader/codec limits (design 6.4.1 budget table).
MAX_NUMERIC_TEXT_CHARS = 80
MAX_JSON_DEPTH = 32
MAX_READBACK_ROWS = 1024

RID_MIN = 1
RID_MAX = 2**63 - 1
SEED_MAX = 2**64 - 1

# Exact token set required by design 6.2.5; stored sorted.
REQUIRED_SQL_MODE_TOKENS = (
    "NO_ENGINE_SUBSTITUTION",
    "ONLY_FULL_GROUP_BY",
    "STRICT_ALL_TABLES",
)
REQUIRED_CHARACTER_SET = "utf8mb4"
REQUIRED_COLLATION = "utf8mb4_bin"
REQUIRED_TIME_ZONE = "+00:00"

MAX_PAYLOAD_BYTES_HARD_CAP = 1024 * 1024
MAX_BUNDLE_BYTES_HARD_CAP = 256 * 1024 * 1024

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_CONDITION_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SEMVER_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,15}$")
_SEMVER_VERSION_RE = re.compile(r"^[A-Za-z0-9._+-]{1,32}$")
_CANONICAL_INT_TEXT_RE = re.compile(r"^(0|-?[1-9][0-9]{0,79})$")


def _fail(msg: str) -> None:
    raise ContractError(msg)


def _check_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{name} must be an int, got {type(value).__name__}")
    return value


def _check_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        _fail(f"{name} must be a str, got {type(value).__name__}")
    return value


def _check_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{name} must be a bool, got {type(value).__name__}")
    return value


def _check_hex64(value: object, name: str) -> str:
    value = _check_str(value, name)
    if not _HEX64_RE.match(value):
        _fail(f"{name} must be lowercase 64-hex sha256, got {value!r}")
    return value


def _check_ident(value: object, name: str) -> str:
    value = _check_str(value, name)
    if not _IDENT_RE.match(value):
        _fail(f"{name} must match [a-z][a-z0-9_]{{0,47}}, got {value!r}")
    return value


def _check_enum(value: object, enum_cls: type, name: str):
    if not isinstance(value, enum_cls):
        _fail(f"{name} must be {enum_cls.__name__}, got {value!r}")
    return value


# --------------------------------------------------------------------------
# Stable reason codes (design 6.2.5, 6.5)
# --------------------------------------------------------------------------


class ReasonCode(enum.StrEnum):
    BINDING_MISMATCH = "binding_mismatch"
    UNSUPPORTED_ENVIRONMENT = "unsupported_environment"
    LOAD_VALUE_MISMATCH = "load_value_mismatch"
    LOAD_DIAGNOSTICS = "load_diagnostics"
    SCHEMA_MISMATCH = "schema_mismatch"
    MISSING_FACT = "missing_fact"
    RULE_DISABLED = "rule_disabled"
    INVALID_STRUCTURE = "invalid_structure"
    UNKNOWN_VERSION = "unknown_version"
    VALUE_OUT_OF_DOMAIN = "value_out_of_domain"
    BUDGET_EXCEEDED = "budget_exceeded"
    INTERNAL_ERROR = "internal_error"


# --------------------------------------------------------------------------
# Exact values (design 6.2.3)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class NullValue:
    """The single SQL NULL; encoded as {"kind":"null"}."""

    kind: Literal["null"] = "null"

    def to_obj(self) -> dict[str, object]:
        return {"kind": "null"}


@dataclass(frozen=True)
class IntegerValue:
    """Exact integer; canonical decimal text ``0`` or ``-?[1-9][0-9]*``."""

    value: int
    kind: Literal["integer"] = "integer"

    def __post_init__(self) -> None:
        _check_int(self.value, "IntegerValue.value")
        text = str(self.value)
        if not _CANONICAL_INT_TEXT_RE.match(text) or len(text) > MAX_NUMERIC_TEXT_CHARS:
            _fail(f"IntegerValue.value out of canonical text range: {self.value}")

    def to_obj(self) -> dict[str, object]:
        return {"kind": "integer", "value": str(self.value)}


@dataclass(frozen=True)
class DecimalValue:
    """Exact decimal ``coefficient * 10**-scale``; scale is non-negative."""

    coefficient: int
    scale: int
    kind: Literal["decimal"] = "decimal"

    def __post_init__(self) -> None:
        _check_int(self.coefficient, "DecimalValue.coefficient")
        _check_int(self.scale, "DecimalValue.scale")
        text = str(self.coefficient)
        if not _CANONICAL_INT_TEXT_RE.match(text) or len(text) > MAX_NUMERIC_TEXT_CHARS:
            _fail(f"DecimalValue.coefficient out of canonical text range: {self.coefficient}")
        if self.scale < 0:
            _fail(f"DecimalValue.scale must be non-negative, got {self.scale}")

    def to_obj(self) -> dict[str, object]:
        return {"kind": "decimal", "coefficient": str(self.coefficient), "scale": self.scale}


ExactValue = Union[NullValue, IntegerValue, DecimalValue]


# --------------------------------------------------------------------------
# TypeSpec tagged union (design 6.2.3)
# --------------------------------------------------------------------------


class SignedIntName(enum.StrEnum):
    TINYINT = "TINYINT"
    SMALLINT = "SMALLINT"
    MEDIUMINT = "MEDIUMINT"
    INT = "INT"
    BIGINT = "BIGINT"


# Signed n-bit range is [-2^(n-1), 2^(n-1)-1] (design 6.2.1).
SIGNED_BIT_WIDTHS: dict[SignedIntName, int] = {
    SignedIntName.TINYINT: 8,
    SignedIntName.SMALLINT: 16,
    SignedIntName.MEDIUMINT: 24,
    SignedIntName.INT: 32,
    SignedIntName.BIGINT: 64,
}


def signed_range(name: SignedIntName) -> tuple[int, int]:
    bits = SIGNED_BIT_WIDTHS[name]
    return (-(2 ** (bits - 1)), 2 ** (bits - 1) - 1)


@dataclass(frozen=True)
class SignedIntegerType:
    """{"kind":"signed_integer","name":"INT"}; no display width, no unsigned."""

    name: SignedIntName
    kind: Literal["signed_integer"] = "signed_integer"

    def __post_init__(self) -> None:
        _check_enum(self.name, SignedIntName, "SignedIntegerType.name")

    def to_obj(self) -> dict[str, object]:
        return {"kind": "signed_integer", "name": str(self.name.value)}


@dataclass(frozen=True)
class DecimalType:
    """{"kind":"decimal","precision":p,"scale":s}; MySQL DECIMAL(p,s) bounds."""

    precision: int
    scale: int
    kind: Literal["decimal"] = "decimal"

    def __post_init__(self) -> None:
        _check_int(self.precision, "DecimalType.precision")
        _check_int(self.scale, "DecimalType.scale")
        if not 1 <= self.precision <= 65:
            _fail(f"DecimalType.precision must be in [1,65], got {self.precision}")
        if not 0 <= self.scale <= 30:
            _fail(f"DecimalType.scale must be in [0,30], got {self.scale}")
        if self.scale > self.precision:
            _fail(f"DecimalType.scale {self.scale} exceeds precision {self.precision}")

    def to_obj(self) -> dict[str, object]:
        return {"kind": "decimal", "precision": self.precision, "scale": self.scale}


TypeSpec = Union[SignedIntegerType, DecimalType]


# --------------------------------------------------------------------------
# Restricted query IR (design 6.2.2, 6.2.3) - closed union, no free SQL text
# --------------------------------------------------------------------------


class ColumnName(enum.StrEnum):
    V = "v"
    RID = "rid"


@dataclass(frozen=True)
class ColumnRef:
    """{"kind":"column_ref","column":"v"|"rid"}."""

    column: ColumnName
    kind: Literal["column_ref"] = "column_ref"

    def __post_init__(self) -> None:
        _check_enum(self.column, ColumnName, "ColumnRef.column")

    def to_obj(self) -> dict[str, object]:
        return {"kind": "column_ref", "column": str(self.column.value)}


V_REF = ColumnRef(ColumnName.V)


@dataclass(frozen=True)
class ExactLiteral:
    """Exact constant; NULL allowed only where a consumer explicitly permits it."""

    value: ExactValue
    kind: Literal["literal"] = "literal"

    def __post_init__(self) -> None:
        if not isinstance(self.value, (NullValue, IntegerValue, DecimalValue)):
            _fail(f"ExactLiteral.value must be an exact value, got {type(self.value).__name__}")

    def to_obj(self) -> dict[str, object]:
        return {"kind": "literal", "value": self.value.to_obj()}


class CompareOp(enum.StrEnum):
    EQ = "="
    NE = "<>"
    LT = "<"
    LE = "<="
    GT = ">"
    GE = ">="
    NULL_SAFE_EQ = "<=>"


class ArithmeticOp(enum.StrEnum):
    ADD = "add"
    SUBTRACT = "subtract"


@dataclass(frozen=True)
class Arithmetic:
    """Q4-only ``v + k`` / ``v - k``; operand is fixed to ColumnRef("v").

    The [-16,16] constant bound and BIGINT intermediate-value checks are rule
    preconditions owned by the static validator, not structural invariants.
    """

    op: ArithmeticOp
    constant: IntegerValue
    kind: Literal["arithmetic"] = "arithmetic"

    def __post_init__(self) -> None:
        _check_enum(self.op, ArithmeticOp, "Arithmetic.op")
        if not isinstance(self.constant, IntegerValue):
            _fail("Arithmetic.constant must be an IntegerValue")

    def to_obj(self) -> dict[str, object]:
        return {"kind": "arithmetic", "op": str(self.op.value), "constant": self.constant.to_obj()}


@dataclass(frozen=True)
class Compare:
    """``v <op> constant``; left side fixed to ColumnRef("v") for determinism."""

    op: CompareOp
    right: ExactLiteral
    kind: Literal["compare"] = "compare"

    def __post_init__(self) -> None:
        _check_enum(self.op, CompareOp, "Compare.op")
        if not isinstance(self.right, ExactLiteral):
            _fail("Compare.right must be an ExactLiteral")

    def to_obj(self) -> dict[str, object]:
        return {
            "kind": "compare",
            "op": str(self.op.value),
            "left": V_REF.to_obj(),
            "right": self.right.to_obj(),
        }


@dataclass(frozen=True)
class Between:
    """``v BETWEEN lower AND upper``; endpoints must be non-NULL.

    lower <= upper ordering is a semantic precondition checked by the static
    validator (needs rule-level scale context), not a structural invariant.
    """

    lower: ExactLiteral
    upper: ExactLiteral
    kind: Literal["between"] = "between"

    def __post_init__(self) -> None:
        for name in ("lower", "upper"):
            operand = getattr(self, name)
            if not isinstance(operand, ExactLiteral):
                _fail(f"Between.{name} must be an ExactLiteral")
            if isinstance(operand.value, NullValue):
                _fail(f"Between.{name} must not be NULL")

    def to_obj(self) -> dict[str, object]:
        return {
            "kind": "between",
            "value": V_REF.to_obj(),
            "lower": self.lower.to_obj(),
            "upper": self.upper.to_obj(),
        }


@dataclass(frozen=True)
class IsNull:
    """``v IS NULL`` / ``v IS NOT NULL`` via explicit negated bool."""

    negated: bool
    kind: Literal["is_null"] = "is_null"

    def __post_init__(self) -> None:
        _check_bool(self.negated, "IsNull.negated")

    def to_obj(self) -> dict[str, object]:
        return {"kind": "is_null", "negated": self.negated}


PredicateAtom = Union[Compare, Between, IsNull]


@dataclass(frozen=True)
class And:
    """Exactly two atoms joined once; no nested And/Or (design 6.2.2)."""

    left: PredicateAtom
    right: PredicateAtom
    kind: Literal["and"] = "and"

    def __post_init__(self) -> None:
        for name in ("left", "right"):
            if not isinstance(getattr(self, name), (Compare, Between, IsNull)):
                _fail(f"And.{name} must be a predicate atom, not a compound predicate")

    def to_obj(self) -> dict[str, object]:
        return {"kind": "and", "left": self.left.to_obj(), "right": self.right.to_obj()}


@dataclass(frozen=True)
class Or:
    """Exactly two atoms joined once; no nested And/Or (design 6.2.2)."""

    left: PredicateAtom
    right: PredicateAtom
    kind: Literal["or"] = "or"

    def __post_init__(self) -> None:
        for name in ("left", "right"):
            if not isinstance(getattr(self, name), (Compare, Between, IsNull)):
                _fail(f"Or.{name} must be a predicate atom, not a compound predicate")

    def to_obj(self) -> dict[str, object]:
        return {"kind": "or", "left": self.left.to_obj(), "right": self.right.to_obj()}


Predicate = Union[PredicateAtom, And, Or]


class AggregateFunc(enum.StrEnum):
    COUNT_STAR = "count_star"
    COUNT = "count"
    MIN = "min"
    MAX = "max"
    SUM = "sum"


@dataclass(frozen=True)
class AggregateExpr:
    """Fixed aggregate shape for Q3; column is None only for COUNT(*)."""

    func: AggregateFunc
    column: Optional[ColumnRef] = None
    kind: Literal["aggregate"] = "aggregate"

    def __post_init__(self) -> None:
        _check_enum(self.func, AggregateFunc, "AggregateExpr.func")
        if self.func is AggregateFunc.COUNT_STAR:
            if self.column is not None:
                _fail("AggregateExpr COUNT(*) takes no column")
        else:
            if not isinstance(self.column, ColumnRef):
                _fail(f"AggregateExpr {self.func} requires a ColumnRef")

    def to_obj(self) -> dict[str, object]:
        obj: dict[str, object] = {"kind": "aggregate", "func": str(self.func.value)}
        if self.column is not None:
            obj["column"] = self.column.to_obj()
        return obj


ProjectionExpr = Union[ColumnRef, Arithmetic, AggregateExpr]


@dataclass(frozen=True)
class Projection:
    """Output column: fixed alias plus a closed expression node."""

    alias: str
    expr: ProjectionExpr

    def __post_init__(self) -> None:
        _check_ident(self.alias, "Projection.alias")
        if not isinstance(self.expr, (ColumnRef, Arithmetic, AggregateExpr)):
            _fail(f"Projection.expr has unsupported node {type(self.expr).__name__}")

    def to_obj(self) -> dict[str, object]:
        return {"alias": self.alias, "expr": self.expr.to_obj()}


class TemplateId(enum.StrEnum):
    Q1 = "Q1"
    Q2 = "Q2"
    Q3 = "Q3"
    Q4 = "Q4"


def _q3_projection(func: AggregateFunc, alias: str) -> Projection:
    column = None if func is AggregateFunc.COUNT_STAR else V_REF
    return Projection(alias, AggregateExpr(func, column))


# Projections are fully determined by the template (design 6.2.2).
_Q1_PROJECTIONS = (Projection("c0", V_REF),)
_Q2_PROJECTIONS = (Projection("c0", ColumnRef(ColumnName.RID)),)
_Q3_PROJECTIONS = (
    _q3_projection(AggregateFunc.COUNT_STAR, "c0"),
    _q3_projection(AggregateFunc.COUNT, "c1"),
    _q3_projection(AggregateFunc.MIN, "c2"),
    _q3_projection(AggregateFunc.MAX, "c3"),
    _q3_projection(AggregateFunc.SUM, "c4"),
)

_TEMPLATE_PROJECTIONS: dict[TemplateId, tuple[Projection, ...]] = {
    TemplateId.Q1: _Q1_PROJECTIONS,
    TemplateId.Q2: _Q2_PROJECTIONS,
    TemplateId.Q3: _Q3_PROJECTIONS,
}


@dataclass(frozen=True)
class QuerySpec:
    """template_id in Q1-Q4; predicate/arithmetic presence fixed per template.

    Q1: no predicate, no arithmetic.  Q2: predicate required, no arithmetic.
    Q3: no arithmetic, optional predicate.  Q4: exactly one arithmetic,
    optional predicate, and the projection re-uses the same arithmetic node.
    """

    template_id: TemplateId
    predicate: Optional[Predicate] = None
    arithmetic: Optional[Arithmetic] = None
    projections: tuple[Projection, ...] = ()

    def __post_init__(self) -> None:
        _check_enum(self.template_id, TemplateId, "QuerySpec.template_id")
        if self.projections == () and self.template_id in _TEMPLATE_PROJECTIONS:
            # Projections are fully determined by the template; deriving them
            # here is unambiguous and keeps every entry point validated.
            object.__setattr__(
                self, "projections", _TEMPLATE_PROJECTIONS[self.template_id]
            )
        if self.predicate is not None and not isinstance(
            self.predicate, (Compare, Between, IsNull, And, Or)
        ):
            _fail("QuerySpec.predicate must be a closed predicate node")
        if self.arithmetic is not None and not isinstance(self.arithmetic, Arithmetic):
            _fail("QuerySpec.arithmetic must be an Arithmetic node")
        for projection in self.projections:
            if not isinstance(projection, Projection):
                _fail("QuerySpec.projections must hold Projection items")
        template = self.template_id
        if template is TemplateId.Q1:
            expected = _Q1_PROJECTIONS
            ok = self.predicate is None and self.arithmetic is None
        elif template is TemplateId.Q2:
            expected = _Q2_PROJECTIONS
            ok = self.predicate is not None and self.arithmetic is None
        elif template is TemplateId.Q3:
            expected = _Q3_PROJECTIONS
            ok = self.arithmetic is None
        else:
            ok = self.arithmetic is not None and self.projections == (
                Projection("c0", self.arithmetic),
            )
            expected = None
        if not ok:
            _fail(f"QuerySpec {template} predicate/arithmetic combination is not allowed")
        if expected is not None and self.projections != expected:
            _fail(f"QuerySpec {template} projections must be exactly {expected!r}")

    def to_obj(self) -> dict[str, object]:
        obj: dict[str, object] = {
            "template_id": str(self.template_id.value),
            "projections": [projection.to_obj() for projection in self.projections],
        }
        if self.predicate is not None:
            obj["predicate"] = self.predicate.to_obj()
        if self.arithmetic is not None:
            obj["arithmetic"] = self.arithmetic.to_obj()
        return obj


# --------------------------------------------------------------------------
# Shared logical rows (design 6.2.2, 6.2.3)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Row:
    """One logical row: unique rid in [1, 2^63-1] plus the shared value."""

    rid: int
    value: ExactValue

    def __post_init__(self) -> None:
        _check_int(self.rid, "Row.rid")
        if not RID_MIN <= self.rid <= RID_MAX:
            _fail(f"Row.rid must be in [{RID_MIN}, {RID_MAX}], got {self.rid}")
        if not isinstance(self.value, (NullValue, IntegerValue, DecimalValue)):
            _fail(f"Row.value must be an exact value, got {type(self.value).__name__}")

    def to_obj(self) -> list[object]:
        return [self.rid, self.value.to_obj()]


def normalize_row_pairs(pairs: list[tuple[int, ExactValue]]) -> tuple[Row, ...]:
    """Sort and deduplicate-check raw (rid, value) pairs for generators.

    This is the explicit normalization entry point; the Rows constructor
    itself rejects unsorted or duplicate rids instead of repairing them.
    """
    seen: set[int] = set()
    rows: list[Row] = []
    for rid, value in pairs:
        if rid in seen:
            _fail(f"duplicate rid {rid} in row pairs")
        seen.add(rid)
        rows.append(Row(rid, value))
    rows.sort(key=lambda row: row.rid)
    return tuple(rows)


@dataclass(frozen=True)
class Rows:
    """Shared (rid, logical_value) sequence; rids strictly increasing.

    One sequence serves both A and B sides; there is no per-side copy that
    could drift.  ``rids`` are never renumbered downstream.
    """

    rows: tuple[Row, ...]
    max_rows: int = MAX_READBACK_ROWS

    def __post_init__(self) -> None:
        _check_int(self.max_rows, "Rows.max_rows")
        if self.max_rows < 0:
            _fail("Rows.max_rows must be non-negative")
        if len(self.rows) > self.max_rows:
            _fail(f"Rows holds {len(self.rows)} rows, over limit {self.max_rows}")
        previous: Optional[int] = None
        for row in self.rows:
            if not isinstance(row, Row):
                _fail("Rows.rows must hold Row items")
            if previous is not None and row.rid <= previous:
                _fail("Rows.rids must be strictly increasing (canonical order)")
            previous = row.rid

    def to_obj(self) -> list[object]:
        return [row.to_obj() for row in self.rows]


# --------------------------------------------------------------------------
# Logical schema (design 6.2.2)
# --------------------------------------------------------------------------


class IndexVariant(enum.StrEnum):
    NONE = "none"
    IX_V = "ix_v"


@dataclass(frozen=True)
class ColumnSpec:
    name: str
    type: TypeSpec
    nullable: bool

    def __post_init__(self) -> None:
        _check_ident(self.name, "ColumnSpec.name")
        if not isinstance(self.type, (SignedIntegerType, DecimalType)):
            _fail(f"ColumnSpec.type must be a TypeSpec, got {type(self.type).__name__}")
        _check_bool(self.nullable, "ColumnSpec.nullable")

    def to_obj(self) -> dict[str, object]:
        return {"name": self.name, "type": self.type.to_obj(), "nullable": self.nullable}


_RID_COLUMN = ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False)


@dataclass(frozen=True)
class TableSpec:
    """Logical table fixed to ``t0`` with ``rid BIGINT NOT NULL PK`` + ``v``.

    Exactly two columns; the ``v`` column carries the transformed type and is
    always NULL-able.  ``rid`` is never the transformed column.
    """

    logical_id: str
    columns: tuple[ColumnSpec, ...]
    primary_key: tuple[str, ...]
    index_variant: IndexVariant

    def __post_init__(self) -> None:
        _check_ident(self.logical_id, "TableSpec.logical_id")
        if self.logical_id != "t0":
            _fail("TableSpec.logical_id is fixed to 't0'")
        if not isinstance(self.columns, tuple) or len(self.columns) != 2:
            _fail("TableSpec.columns must be exactly (rid, v)")
        rid_col, v_col = self.columns
        if not isinstance(rid_col, ColumnSpec) or not isinstance(v_col, ColumnSpec):
            _fail("TableSpec.columns must hold ColumnSpec items")
        if rid_col != _RID_COLUMN:
            _fail("TableSpec first column must be rid BIGINT NOT NULL")
        if v_col.name != "v" or not v_col.nullable:
            _fail("TableSpec second column must be 'v' and nullable")
        if not isinstance(self.primary_key, tuple) or self.primary_key != ("rid",):
            _fail("TableSpec.primary_key must be ('rid',)")
        _check_enum(self.index_variant, IndexVariant, "TableSpec.index_variant")

    def to_obj(self) -> dict[str, object]:
        return {
            "logical_id": self.logical_id,
            "columns": [column.to_obj() for column in self.columns],
            "primary_key": list(self.primary_key),
            "index_variant": str(self.index_variant.value),
        }


# --------------------------------------------------------------------------
# Rule reference, result relation, environment (design 6.2.1, 6.2.2, 6.2.5)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleRef:
    """Reference to a reviewed rule definition; never a free type-pair string."""

    rule_id: str
    rule_version: int

    def __post_init__(self) -> None:
        _check_str(self.rule_id, "RuleRef.rule_id")
        if not _RULE_ID_RE.match(self.rule_id):
            _fail(f"RuleRef.rule_id has unsupported form: {self.rule_id!r}")
        _check_int(self.rule_version, "RuleRef.rule_version")
        if self.rule_version < 1:
            _fail("RuleRef.rule_version must be >= 1")

    def to_obj(self) -> dict[str, object]:
        return {"rule_id": self.rule_id, "rule_version": self.rule_version}


class TypeFamily(enum.StrEnum):
    SIGNED_INTEGER = "signed_integer"
    DECIMAL = "decimal"


class ValueEquivalence(enum.StrEnum):
    EXACT_NUMERIC = "exact_numeric"


class NullPolicy(enum.StrEnum):
    FORBID = "forbid"
    PRESERVE = "preserve"


class RelationMode(enum.StrEnum):
    MULTISET_EXACT = "multiset_exact"


@dataclass(frozen=True)
class ResultColumnSpec:
    """Per-column declared relation; families are frozen, never runtime-guessed."""

    alias: str
    a_family: TypeFamily
    b_family: TypeFamily
    value_equivalence: ValueEquivalence
    null_policy: NullPolicy

    def __post_init__(self) -> None:
        _check_ident(self.alias, "ResultColumnSpec.alias")
        _check_enum(self.a_family, TypeFamily, "ResultColumnSpec.a_family")
        _check_enum(self.b_family, TypeFamily, "ResultColumnSpec.b_family")
        _check_enum(
            self.value_equivalence, ValueEquivalence, "ResultColumnSpec.value_equivalence"
        )
        _check_enum(self.null_policy, NullPolicy, "ResultColumnSpec.null_policy")

    def to_obj(self) -> dict[str, object]:
        return {
            "alias": self.alias,
            "a_family": str(self.a_family.value),
            "b_family": str(self.b_family.value),
            "value_equivalence": str(self.value_equivalence.value),
            "null_policy": str(self.null_policy.value),
        }


@dataclass(frozen=True)
class ResultRelationSpec:
    mode: RelationMode
    columns: tuple[ResultColumnSpec, ...]

    def __post_init__(self) -> None:
        _check_enum(self.mode, RelationMode, "ResultRelationSpec.mode")
        if not isinstance(self.columns, tuple) or not self.columns:
            _fail("ResultRelationSpec.columns must be a non-empty tuple")
        for column in self.columns:
            if not isinstance(column, ResultColumnSpec):
                _fail("ResultRelationSpec.columns must hold ResultColumnSpec items")
        aliases = [column.alias for column in self.columns]
        if len(set(aliases)) != len(aliases):
            _fail("ResultRelationSpec aliases must be unique")

    def to_obj(self) -> dict[str, object]:
        return {
            "mode": str(self.mode.value),
            "columns": [column.to_obj() for column in self.columns],
        }


@dataclass(frozen=True)
class EnvironmentRequirements:
    """Frozen MySQL 8.0 / InnoDB / same-instance session contract (6.2.5)."""

    database: str
    engine: str
    scope: str
    sql_mode_tokens: tuple[str, ...]
    character_set: str
    collation: str
    time_zone: str

    def __post_init__(self) -> None:
        if (_check_str(self.database, "database"), _check_str(self.engine, "engine"),
                _check_str(self.scope, "scope")) != ("mysql80", "innodb", "same-instance"):
            _fail("EnvironmentRequirements must declare mysql80/innodb/same-instance")
        if not isinstance(self.sql_mode_tokens, tuple):
            _fail("EnvironmentRequirements.sql_mode_tokens must be a tuple")
        if self.sql_mode_tokens != REQUIRED_SQL_MODE_TOKENS:
            _fail(
                "EnvironmentRequirements.sql_mode_tokens must be exactly "
                f"{REQUIRED_SQL_MODE_TOKENS} (sorted, no duplicates), "
                f"got {self.sql_mode_tokens!r}"
            )
        if (_check_str(self.character_set, "character_set"),
                _check_str(self.collation, "collation"),
                _check_str(self.time_zone, "time_zone")) != (
            REQUIRED_CHARACTER_SET,
            REQUIRED_COLLATION,
            REQUIRED_TIME_ZONE,
        ):
            _fail(
                "EnvironmentRequirements session must be "
                f"{REQUIRED_CHARACTER_SET}/{REQUIRED_COLLATION}/time_zone={REQUIRED_TIME_ZONE}"
            )

    def to_obj(self) -> dict[str, object]:
        return {
            "database": self.database,
            "engine": self.engine,
            "scope": self.scope,
            "sql_mode_tokens": list(self.sql_mode_tokens),
            "character_set": self.character_set,
            "collation": self.collation,
            "time_zone": self.time_zone,
        }


@dataclass(frozen=True)
class SemverIdentity:
    """Semantic identity of a generator or renderer, e.g. g1/1 or r1/1."""

    id: str
    version: str

    def __post_init__(self) -> None:
        _check_str(self.id, "SemverIdentity.id")
        _check_str(self.version, "SemverIdentity.version")
        if not _SEMVER_ID_RE.match(self.id):
            _fail(f"SemverIdentity.id has unsupported form: {self.id!r}")
        if not _SEMVER_VERSION_RE.match(self.version):
            _fail(f"SemverIdentity.version has unsupported form: {self.version!r}")

    def to_obj(self) -> dict[str, object]:
        return {"id": self.id, "version": self.version}


class RuleReviewStatus(enum.StrEnum):
    """Registry management state (design 6.2.1): never part of the definition hash."""

    REVIEWED = "reviewed"
    DISABLED = "disabled"


@dataclass(frozen=True)
class RuleSpec:
    """Reviewed rule definition (design 6.2.1); published definitions are immutable.

    ``definition_hash`` covers only rule semantics (rule_id, type pairs,
    templates, precondition parameters); rationale links, review notes and
    the enablement state are registry management data that never enter the
    hash.  Output relations are a pure function of the semantic fields, so
    they are covered transitively; ``rules/exact_numeric.derive_relation``
    derives them per (rule, type pair, template).
    """

    rule_id: str
    rule_version: int
    type_pairs: tuple[tuple[TypeSpec, TypeSpec], ...]
    templates: tuple[TemplateId, ...]
    requires_equal_scale: bool
    integer_only_values: bool
    sum_abs_coefficient_budget: Optional[int]
    arithmetic_k_min: Optional[int]
    arithmetic_k_max: Optional[int]
    static_conditions: tuple[str, ...]
    runtime_requirements: EnvironmentRequirements
    rationale: tuple[str, ...]
    review_notes: str
    review_status: RuleReviewStatus
    definition_hash: str = ""

    def __post_init__(self) -> None:
        from .codec import canonical_json, sha256_hex  # deferred: codec imports case

        _check_str(self.rule_id, "RuleSpec.rule_id")
        if not _RULE_ID_RE.match(self.rule_id):
            _fail(f"RuleSpec.rule_id has unsupported form: {self.rule_id!r}")
        _check_int(self.rule_version, "RuleSpec.rule_version")
        if self.rule_version < 1:
            _fail("RuleSpec.rule_version must be >= 1")
        if not isinstance(self.type_pairs, tuple) or not self.type_pairs:
            _fail("RuleSpec.type_pairs must be a non-empty tuple")
        seen_keys: set[str] = set()
        for pair in self.type_pairs:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or not all(isinstance(t, (SignedIntegerType, DecimalType)) for t in pair)
            ):
                _fail("RuleSpec.type_pairs must hold (TypeSpec, TypeSpec) tuples")
            key = canonical_json([pair[0].to_obj(), pair[1].to_obj()]).decode("ascii")
            if key in seen_keys:
                _fail("RuleSpec.type_pairs must not repeat a type pair")
            seen_keys.add(key)
        if not isinstance(self.templates, tuple) or not self.templates:
            _fail("RuleSpec.templates must be a non-empty tuple")
        previous_template: Optional[TemplateId] = None
        for template in self.templates:
            _check_enum(template, TemplateId, "RuleSpec.templates item")
            if previous_template is not None and template <= previous_template:
                _fail("RuleSpec.templates must be sorted and unique")
            previous_template = template
        _check_bool(self.requires_equal_scale, "RuleSpec.requires_equal_scale")
        if self.requires_equal_scale:
            for pair in self.type_pairs:
                if not all(isinstance(t, DecimalType) for t in pair):
                    _fail("requires_equal_scale is only valid for decimal type pairs")
                if pair[0].scale != pair[1].scale:
                    _fail("equal-scale pairs must declare the same scale on both sides")
        _check_bool(self.integer_only_values, "RuleSpec.integer_only_values")
        if self.sum_abs_coefficient_budget is not None:
            _check_int(self.sum_abs_coefficient_budget, "RuleSpec.sum_abs_coefficient_budget")
            if self.sum_abs_coefficient_budget <= 0:
                _fail("RuleSpec.sum_abs_coefficient_budget must be positive")
        has_q3 = TemplateId.Q3 in self.templates
        has_q4 = TemplateId.Q4 in self.templates
        if has_q3 and self.sum_abs_coefficient_budget is None:
            _fail("rules allowing Q3 must declare sum_abs_coefficient_budget")
        if not has_q3 and self.sum_abs_coefficient_budget is not None:
            _fail("sum_abs_coefficient_budget requires template Q3")
        k_lo: Optional[int] = self.arithmetic_k_min
        k_hi: Optional[int] = self.arithmetic_k_max
        if k_lo is not None or k_hi is not None:
            _check_int(k_lo, "RuleSpec.arithmetic_k_min")
            _check_int(k_hi, "RuleSpec.arithmetic_k_max")
            if k_lo > k_hi:
                _fail("RuleSpec arithmetic k bounds are inverted")
        if has_q4 and k_lo is None:
            _fail("rules allowing Q4 must declare arithmetic k bounds")
        if not has_q4 and k_lo is not None:
            _fail("arithmetic k bounds require template Q4")
        if not isinstance(self.static_conditions, tuple) or not self.static_conditions:
            _fail("RuleSpec.static_conditions must be a non-empty tuple")
        previous_condition: Optional[str] = None
        for condition in self.static_conditions:
            _check_str(condition, "RuleSpec.static_conditions item")
            if not _CONDITION_ID_RE.match(condition):
                _fail(f"RuleSpec.static_conditions item has unsupported form: {condition!r}")
            if previous_condition is not None and condition <= previous_condition:
                _fail("RuleSpec.static_conditions must be sorted and unique")
            previous_condition = condition
        if not isinstance(self.runtime_requirements, EnvironmentRequirements):
            _fail("RuleSpec.runtime_requirements must be an EnvironmentRequirements")
        if not isinstance(self.rationale, tuple) or not self.rationale:
            _fail("RuleSpec.rationale must be a non-empty tuple")
        for item in self.rationale:
            _check_str(item, "RuleSpec.rationale item")
        _check_str(self.review_notes, "RuleSpec.review_notes")
        _check_enum(self.review_status, RuleReviewStatus, "RuleSpec.review_status")
        derived = sha256_hex(canonical_json(self.semantic_obj()))
        if self.definition_hash == "":
            object.__setattr__(self, "definition_hash", derived)
        elif self.definition_hash != derived:
            _fail(
                f"RuleSpec.definition_hash {self.definition_hash!r} does not match "
                f"the semantic content hash {derived}"
            )

    def semantic_obj(self) -> dict[str, object]:
        """Semantic content hashed into ``definition_hash`` (design 6.2.1)."""
        return {
            "definition_schema": 1,
            "rule_id": self.rule_id,
            "type_pairs": [[pair[0].to_obj(), pair[1].to_obj()] for pair in self.type_pairs],
            "templates": [str(template.value) for template in self.templates],
            "preconditions": {
                "arithmetic_k_max": self.arithmetic_k_max,
                "arithmetic_k_min": self.arithmetic_k_min,
                "integer_only_values": self.integer_only_values,
                "requires_equal_scale": self.requires_equal_scale,
                "sum_abs_coefficient_budget": self.sum_abs_coefficient_budget,
            },
        }

    def to_obj(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "definition_hash": self.definition_hash,
            "type_pairs": [[pair[0].to_obj(), pair[1].to_obj()] for pair in self.type_pairs],
            "templates": [str(template.value) for template in self.templates],
            "preconditions": {
                "arithmetic_k_max": self.arithmetic_k_max,
                "arithmetic_k_min": self.arithmetic_k_min,
                "integer_only_values": self.integer_only_values,
                "requires_equal_scale": self.requires_equal_scale,
                "sum_abs_coefficient_budget": self.sum_abs_coefficient_budget,
            },
            "static_conditions": list(self.static_conditions),
            "runtime_requirements": self.runtime_requirements.to_obj(),
            "rationale": list(self.rationale),
            "review_notes": self.review_notes,
            "review_status": str(self.review_status.value),
        }


# --------------------------------------------------------------------------
# CasePayload - the semantic, hashable core (design 6.2.4)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CasePayload:
    """Semantic case content; case_id = SHA256(canonical_json(to_obj()))."""

    rule: RuleRef
    a_type: TypeSpec
    b_type: TypeSpec
    table: TableSpec
    rows: Rows
    query: QuerySpec
    relation: ResultRelationSpec
    environment: EnvironmentRequirements
    generator: SemverIdentity
    renderer: SemverIdentity
    case_schema_version: int = CASE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.case_schema_version, "CasePayload.case_schema_version")
        if self.case_schema_version != CASE_SCHEMA_VERSION:
            _fail(f"unsupported case_schema_version {self.case_schema_version}")
        for name, expected in (
            ("rule", RuleRef),
            ("table", TableSpec),
            ("rows", Rows),
            ("query", QuerySpec),
            ("relation", ResultRelationSpec),
            ("environment", EnvironmentRequirements),
            ("generator", SemverIdentity),
            ("renderer", SemverIdentity),
        ):
            if not isinstance(getattr(self, name), expected):
                _fail(f"CasePayload.{name} must be {expected.__name__}")
        for name in ("a_type", "b_type"):
            if not isinstance(getattr(self, name), (SignedIntegerType, DecimalType)):
                _fail(f"CasePayload.{name} must be a TypeSpec")
        # A-side schema and the shared rows must agree with the declared types.
        if self.table.columns[1].type != self.a_type:
            _fail("CasePayload.table v-column type must equal a_type")
        self._check_row_domain()

    def _check_row_domain(self) -> None:
        """Structural value/type binding for the shared rows.

        Integer rows are accepted whenever at least one side is a signed
        integer type (signed rules and integer-decimal share integer logical
        data).  Decimal rows require both sides declared decimal; scale
        agreement is a rule precondition owned by the static validator.
        """
        both_decimal = isinstance(self.a_type, DecimalType) and isinstance(
            self.b_type, DecimalType
        )
        for row in self.rows.rows:
            value = row.value
            if isinstance(value, NullValue):
                continue
            if isinstance(value, DecimalValue):
                if not both_decimal:
                    _fail(
                        f"row rid={row.rid} is decimal data but not both sides "
                        "are declared decimal"
                    )
                continue
            if isinstance(value, IntegerValue):
                if both_decimal:
                    _fail(
                        f"row rid={row.rid} is integer data but decimal rules "
                        "require the fixed rule scale"
                    )
                continue
            _fail(f"row rid={row.rid} has unsupported value type")

    def to_obj(self) -> dict[str, object]:
        return {
            "case_schema_version": self.case_schema_version,
            "rule": self.rule.to_obj(),
            "a_type": self.a_type.to_obj(),
            "b_type": self.b_type.to_obj(),
            "table": self.table.to_obj(),
            "rows": self.rows.to_obj(),
            "query": self.query.to_obj(),
            "relation": self.relation.to_obj(),
            "environment": self.environment.to_obj(),
            "generator": self.generator.to_obj(),
            "renderer": self.renderer.to_obj(),
        }


# --------------------------------------------------------------------------
# Provenance and CaseBundle (design 6.2.4)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Provenance:
    """Ordinal receipt; never participates in case_id."""

    seed: int
    ordinal: int
    profile_hash: str
    retry: int

    def __post_init__(self) -> None:
        _check_int(self.seed, "Provenance.seed")
        if not 0 <= self.seed <= SEED_MAX:
            _fail("Provenance.seed must be a uint64")
        _check_int(self.ordinal, "Provenance.ordinal")
        if self.ordinal < 0:
            _fail("Provenance.ordinal must be >= 0")
        _check_hex64(self.profile_hash, "Provenance.profile_hash")
        _check_int(self.retry, "Provenance.retry")
        if self.retry < 0:
            _fail("Provenance.retry must be >= 0")

    def to_obj(self) -> dict[str, object]:
        return {
            "seed": self.seed,
            "ordinal": self.ordinal,
            "profile_hash": self.profile_hash,
            "retry": self.retry,
        }


@dataclass(frozen=True)
class CaseBundle:
    """payload + identity + provenance + preview + static check reference.

    Carries no DSN, no physical namespace and no run conclusions.  The
    constructor re-derives case_id from the payload, so a forged id cannot be
    stored.
    """

    payload: CasePayload
    provenance: Provenance
    preview_a_sql: str
    preview_b_sql: str
    static_check: "CompatibilityCheck"
    case_id: str = ""

    def __post_init__(self) -> None:
        from .codec import case_id_of, preview_hash_of  # deferred: codec imports case

        if not isinstance(self.payload, CasePayload):
            _fail("CaseBundle.payload must be a CasePayload")
        if not isinstance(self.provenance, Provenance):
            _fail("CaseBundle.provenance must be a Provenance")
        _check_str(self.preview_a_sql, "CaseBundle.preview_a_sql")
        _check_str(self.preview_b_sql, "CaseBundle.preview_b_sql")
        if not isinstance(self.static_check, CompatibilityCheck):
            _fail("CaseBundle.static_check must be a CompatibilityCheck")
        derived = case_id_of(self.payload)
        # case_id is a derived field: accept the default empty marker, reject
        # anything that disagrees with the payload.
        if self.case_id == "":
            object.__setattr__(self, "case_id", derived)
        elif self.case_id != derived:
            _fail(f"CaseBundle.case_id {self.case_id!r} does not match payload hash {derived}")
        _check_hex64(self.case_id, "CaseBundle.case_id")
        if self.static_check.case_id != derived:
            _fail("CaseBundle.static_check must reference the same case_id")

    def preview_hash(self) -> str:
        from .codec import preview_hash_of

        return preview_hash_of(self.preview_a_sql, self.preview_b_sql)

    def to_obj(self) -> dict[str, object]:
        return {
            "payload": self.payload.to_obj(),
            "case_id": self.case_id,
            "provenance": self.provenance.to_obj(),
            "preview": {
                "a_sql": self.preview_a_sql,
                "b_sql": self.preview_b_sql,
                "hash": self.preview_hash(),
            },
            "static_check": self.static_check.to_obj(),
        }


# --------------------------------------------------------------------------
# Compatibility checks (design 6.2.5)
# --------------------------------------------------------------------------


class CheckStage(enum.StrEnum):
    STATIC = "static"
    RUNTIME = "runtime"


class CheckStatus(enum.StrEnum):
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    PENDING = "PENDING"


class StaticCheckStatus(enum.StrEnum):
    VALID_STATIC = "VALID_STATIC"
    INVALID = "INVALID"


class RuntimeCheckStatus(enum.StrEnum):
    READY = "READY"
    BLOCKED = "BLOCKED"
    INCOMPLETE = "INCOMPLETE"


@dataclass(frozen=True)
class ConditionResult:
    """One check item with a stable condition id and reason code."""

    condition_id: str
    status: CheckStatus
    reason: Optional[ReasonCode] = None
    detail: Optional[str] = None

    def __post_init__(self) -> None:
        _check_str(self.condition_id, "ConditionResult.condition_id")
        if not _CONDITION_ID_RE.match(self.condition_id):
            _fail(f"ConditionResult.condition_id has unsupported form: {self.condition_id!r}")
        _check_enum(self.status, CheckStatus, "ConditionResult.status")
        if self.reason is not None:
            _check_enum(self.reason, ReasonCode, "ConditionResult.reason")
        if self.detail is not None:
            _check_str(self.detail, "ConditionResult.detail")
        if self.status is CheckStatus.VIOLATED and self.reason is None:
            _fail("a VIOLATED condition requires a reason code")

    def to_obj(self) -> dict[str, object]:
        obj: dict[str, object] = {
            "condition_id": self.condition_id,
            "status": str(self.status.value),
        }
        if self.reason is not None:
            obj["reason"] = str(self.reason.value)
        if self.detail is not None:
            obj["detail"] = self.detail
        return obj


@dataclass(frozen=True)
class CompatibilityCheck:
    """Stage-tagged check; re-validation always produces a new object."""

    stage: CheckStage
    case_id: str
    validator_version: str
    conditions: tuple[ConditionResult, ...]
    status: Union[StaticCheckStatus, RuntimeCheckStatus]

    def __post_init__(self) -> None:
        _check_enum(self.stage, CheckStage, "CompatibilityCheck.stage")
        _check_hex64(self.case_id, "CompatibilityCheck.case_id")
        _check_str(self.validator_version, "CompatibilityCheck.validator_version")
        if not _SEMVER_VERSION_RE.match(self.validator_version):
            _fail(f"CompatibilityCheck.validator_version has unsupported form: "
                  f"{self.validator_version!r}")
        if not isinstance(self.conditions, tuple):
            _fail("CompatibilityCheck.conditions must be a tuple")
        for condition in self.conditions:
            if not isinstance(condition, ConditionResult):
                _fail("CompatibilityCheck.conditions must hold ConditionResult items")
        if self.stage is CheckStage.STATIC:
            if not isinstance(self.status, StaticCheckStatus):
                _fail("static check status must be VALID_STATIC/INVALID")
        else:
            if not isinstance(self.status, RuntimeCheckStatus):
                _fail("runtime check status must be READY/BLOCKED/INCOMPLETE")

    def to_obj(self) -> dict[str, object]:
        return {
            "stage": str(self.stage.value),
            "case_id": self.case_id,
            "validator_version": self.validator_version,
            "status": str(self.status.value),
            "conditions": [condition.to_obj() for condition in self.conditions],
        }


@dataclass(frozen=True)
class ExpectedBinding:
    """Independent caller expectation; never copied out of the facts themselves."""

    run_id: str
    case_id: str
    attempt_id: str
    environment_hash: str
    name_map_hash: str

    def __post_init__(self) -> None:
        _check_str(self.run_id, "ExpectedBinding.run_id")
        _check_str(self.attempt_id, "ExpectedBinding.attempt_id")
        if not self.run_id or not self.attempt_id:
            _fail("ExpectedBinding.run_id/attempt_id must be non-empty")
        _check_hex64(self.case_id, "ExpectedBinding.case_id")
        _check_hex64(self.environment_hash, "ExpectedBinding.environment_hash")
        _check_hex64(self.name_map_hash, "ExpectedBinding.name_map_hash")

    def to_obj(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "attempt_id": self.attempt_id,
            "environment_hash": self.environment_hash,
            "name_map_hash": self.name_map_hash,
        }


# --------------------------------------------------------------------------
# Runtime facts (design 6.2.5) - models only; checking logic lives in Phase 4
# --------------------------------------------------------------------------


class StatementPhase(enum.StrEnum):
    DDL = "ddl"
    INSERT = "insert"


@dataclass(frozen=True)
class StatementReceipt:
    """One executed DDL/INSERT statement from render_pair, in order."""

    phase: StatementPhase
    ordinal: int
    sql_hash: str
    success: bool
    diagnostics_complete: bool

    def __post_init__(self) -> None:
        _check_enum(self.phase, StatementPhase, "StatementReceipt.phase")
        _check_int(self.ordinal, "StatementReceipt.ordinal")
        if self.ordinal < 0:
            _fail("StatementReceipt.ordinal must be >= 0")
        _check_hex64(self.sql_hash, "StatementReceipt.sql_hash")
        _check_bool(self.success, "StatementReceipt.success")
        _check_bool(self.diagnostics_complete, "StatementReceipt.diagnostics_complete")

    def to_obj(self) -> dict[str, object]:
        return {
            "phase": str(self.phase.value),
            "ordinal": self.ordinal,
            "sql_hash": self.sql_hash,
            "success": self.success,
            "diagnostics_complete": self.diagnostics_complete,
        }


@dataclass(frozen=True)
class ObservedEnvironment:
    """Server identity and effective A/B session snapshot, re-hashed by D1."""

    instance_identity: str
    version: str
    vendor: str
    build_id: str
    engine: str
    sql_mode_tokens: tuple[str, ...]
    character_set: str
    collation: str
    time_zone: str
    optimizer_switch: str

    def __post_init__(self) -> None:
        for name in (
            "instance_identity",
            "version",
            "vendor",
            "build_id",
            "engine",
            "character_set",
            "collation",
            "time_zone",
            "optimizer_switch",
        ):
            _check_str(getattr(self, name), f"ObservedEnvironment.{name}")
        if not isinstance(self.sql_mode_tokens, tuple) or not self.sql_mode_tokens:
            _fail("ObservedEnvironment.sql_mode_tokens must be a non-empty tuple")
        previous: Optional[str] = None
        for token in self.sql_mode_tokens:
            _check_str(token, "ObservedEnvironment.sql_mode token")
            if previous is not None and token <= previous:
                _fail("ObservedEnvironment.sql_mode_tokens must be sorted and unique")
            previous = token

    def to_obj(self) -> dict[str, object]:
        return {
            "instance_identity": self.instance_identity,
            "version": self.version,
            "vendor": self.vendor,
            "build_id": self.build_id,
            "engine": self.engine,
            "sql_mode_tokens": list(self.sql_mode_tokens),
            "character_set": self.character_set,
            "collation": self.collation,
            "time_zone": self.time_zone,
            "optimizer_switch": self.optimizer_switch,
        }


@dataclass(frozen=True)
class NameMap:
    """Controlled physical identifiers; A/B databases must differ (6.3.2)."""

    database_a: str
    database_b: str
    table_a: str
    table_b: str

    def __post_init__(self) -> None:
        for name in ("database_a", "database_b", "table_a", "table_b"):
            _check_ident(getattr(self, name), f"NameMap.{name}")
        if self.database_a == self.database_b:
            _fail("NameMap A/B databases must differ")

    def to_obj(self) -> dict[str, object]:
        return {
            "database_a": self.database_a,
            "database_b": self.database_b,
            "table_a": self.table_a,
            "table_b": self.table_b,
        }


@dataclass(frozen=True)
class SideFacts:
    """Per-side load/execution facts; absent pieces stay None (PENDING)."""

    statement_receipts: tuple[StatementReceipt, ...] = ()
    readback: Rows = Rows(())
    readback_complete: bool = False
    actual_schema: Optional[TableSpec] = None
    load_committed: Optional[bool] = None
    isolation_confirmed: Optional[bool] = None

    def __post_init__(self) -> None:
        if not isinstance(self.statement_receipts, tuple):
            _fail("SideFacts.statement_receipts must be a tuple")
        previous_phase_ordinal: dict[StatementPhase, int] = {}
        for receipt in self.statement_receipts:
            if not isinstance(receipt, StatementReceipt):
                _fail("SideFacts.statement_receipts must hold StatementReceipt items")
            last = previous_phase_ordinal.get(receipt.phase)
            if last is not None and receipt.ordinal <= last:
                _fail("SideFacts.statement_receipts must be ordered per phase")
            previous_phase_ordinal[receipt.phase] = receipt.ordinal
        if not isinstance(self.readback, Rows):
            _fail("SideFacts.readback must be Rows")
        _check_bool(self.readback_complete, "SideFacts.readback_complete")
        if self.actual_schema is not None and not isinstance(self.actual_schema, TableSpec):
            _fail("SideFacts.actual_schema must be a TableSpec")
        for name in ("load_committed", "isolation_confirmed"):
            value = getattr(self, name)
            if value is not None:
                _check_bool(value, f"SideFacts.{name}")

    def to_obj(self) -> dict[str, object]:
        obj: dict[str, object] = {
            "statement_receipts": [receipt.to_obj() for receipt in self.statement_receipts],
            "readback": self.readback.to_obj(),
            "readback_complete": self.readback_complete,
            "load_committed": self.load_committed,
            "isolation_confirmed": self.isolation_confirmed,
        }
        if self.actual_schema is not None:
            obj["actual_schema"] = self.actual_schema.to_obj()
        return obj


@dataclass(frozen=True)
class RuntimeFacts:
    """A/B execution facts provided by D3; checked, never trusted (6.2.5)."""

    binding: ExpectedBinding
    observed_environment: Optional[ObservedEnvironment] = None
    name_map: Optional[NameMap] = None
    a: Optional[SideFacts] = None
    b: Optional[SideFacts] = None
    facts_schema_version: int = FACTS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.facts_schema_version, "RuntimeFacts.facts_schema_version")
        if self.facts_schema_version != FACTS_SCHEMA_VERSION:
            _fail(f"unsupported facts_schema_version {self.facts_schema_version}")
        if not isinstance(self.binding, ExpectedBinding):
            _fail("RuntimeFacts.binding must be an ExpectedBinding")
        for name, cls in (
            ("observed_environment", ObservedEnvironment),
            ("name_map", NameMap),
            ("a", SideFacts),
            ("b", SideFacts),
        ):
            value = getattr(self, name)
            if value is not None and not isinstance(value, cls):
                _fail(f"RuntimeFacts.{name} must be {cls.__name__} or None")

    def to_obj(self) -> dict[str, object]:
        obj: dict[str, object] = {
            "facts_schema_version": self.facts_schema_version,
            "binding": self.binding.to_obj(),
        }
        for name in ("observed_environment", "name_map", "a", "b"):
            value = getattr(self, name)
            obj[name] = value.to_obj() if value is not None else None
        return obj


# --------------------------------------------------------------------------
# Generation manifest (design 6.6)
# --------------------------------------------------------------------------


class OrdinalOutcome(enum.StrEnum):
    EMITTED = "emitted"
    REJECTED = "rejected"
    INTERRUPTED = "interrupted"


class GenerationStatus(enum.StrEnum):
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    ABORTED = "ABORTED"


@dataclass(frozen=True)
class OrdinalReceipt:
    """Final per-ordinal attribution; every ordinal has exactly one outcome."""

    ordinal: int
    outcome: OrdinalOutcome
    case_id: Optional[str] = None
    retry_count: int = 0
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        _check_int(self.ordinal, "OrdinalReceipt.ordinal")
        if self.ordinal < 0:
            _fail("OrdinalReceipt.ordinal must be >= 0")
        _check_enum(self.outcome, OrdinalOutcome, "OrdinalReceipt.outcome")
        if self.case_id is not None:
            _check_hex64(self.case_id, "OrdinalReceipt.case_id")
            if self.outcome is not OrdinalOutcome.EMITTED:
                _fail("only EMITTED receipts carry a case_id")
        elif self.outcome is OrdinalOutcome.EMITTED:
            _fail("an EMITTED receipt requires a case_id")
        _check_int(self.retry_count, "OrdinalReceipt.retry_count")
        if self.retry_count < 0:
            _fail("OrdinalReceipt.retry_count must be >= 0")
        if self.reason is not None:
            _check_str(self.reason, "OrdinalReceipt.reason")

    def to_obj(self) -> dict[str, object]:
        obj: dict[str, object] = {
            "ordinal": self.ordinal,
            "outcome": str(self.outcome.value),
            "retry_count": self.retry_count,
        }
        if self.case_id is not None:
            obj["case_id"] = self.case_id
        if self.reason is not None:
            obj["reason"] = self.reason
        return obj


@dataclass(frozen=True)
class CaseFileEntry:
    """One published case file: case_id plus artifact hash of actual bytes."""

    case_id: str
    artifact_hash: str
    size_bytes: int

    def __post_init__(self) -> None:
        _check_hex64(self.case_id, "CaseFileEntry.case_id")
        _check_hex64(self.artifact_hash, "CaseFileEntry.artifact_hash")
        _check_int(self.size_bytes, "CaseFileEntry.size_bytes")
        if self.size_bytes < 0:
            _fail("CaseFileEntry.size_bytes must be >= 0")

    def to_obj(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "artifact_hash": self.artifact_hash,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class GenerationManifest:
    """Generation-only manifest; not the D0 run manifest (design 6.6)."""

    profile_hash: str
    seed: int
    requested_ordinals: int
    attempted_candidates: int
    emitted_occurrences: int
    unique_cases: int
    rejected_ordinals: int
    interrupted_ordinals: int
    not_attempted: int
    status: GenerationStatus
    generator: SemverIdentity
    receipts: tuple[OrdinalReceipt, ...] = ()
    case_files: tuple[CaseFileEntry, ...] = ()
    reason: Optional[str] = None
    generation_schema_version: int = GENERATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_hex64(self.profile_hash, "GenerationManifest.profile_hash")
        _check_int(self.seed, "GenerationManifest.seed")
        if not 0 <= self.seed <= SEED_MAX:
            _fail("GenerationManifest.seed must be a uint64")
        for name in (
            "requested_ordinals",
            "attempted_candidates",
            "emitted_occurrences",
            "unique_cases",
            "rejected_ordinals",
            "interrupted_ordinals",
            "not_attempted",
        ):
            _check_int(getattr(self, name), f"GenerationManifest.{name}")
            if getattr(self, name) < 0:
                _fail(f"GenerationManifest.{name} must be >= 0")
        _check_enum(self.status, GenerationStatus, "GenerationManifest.status")
        if not isinstance(self.generator, SemverIdentity):
            _fail("GenerationManifest.generator must be a SemverIdentity")
        _check_int(self.generation_schema_version, "GenerationManifest.generation_schema_version")
        if self.generation_schema_version != GENERATION_SCHEMA_VERSION:
            _fail(f"unsupported generation_schema_version {self.generation_schema_version}")
        if not isinstance(self.receipts, tuple) or not isinstance(self.case_files, tuple):
            _fail("GenerationManifest receipts/case_files must be tuples")
        previous_ordinal: Optional[int] = None
        for receipt in self.receipts:
            if not isinstance(receipt, OrdinalReceipt):
                _fail("GenerationManifest.receipts must hold OrdinalReceipt items")
            if previous_ordinal is not None and receipt.ordinal <= previous_ordinal:
                _fail("GenerationManifest.receipts must be sorted by unique ordinal")
            previous_ordinal = receipt.ordinal
        if self.unique_cases > self.emitted_occurrences:
            _fail("GenerationManifest.unique_cases cannot exceed emitted_occurrences")
        # Final states must conserve ordinals; RUNNING may still hold
        # in-flight ordinals that have no final attribution yet.
        if self.status is not GenerationStatus.RUNNING:
            attributed = (
                self.emitted_occurrences
                + self.rejected_ordinals
                + self.interrupted_ordinals
                + self.not_attempted
            )
            if attributed != self.requested_ordinals:
                _fail(
                    "GenerationManifest counts must conserve requested_ordinals for "
                    f"{self.status}, got {attributed} != {self.requested_ordinals}"
                )
        if self.reason is not None:
            _check_str(self.reason, "GenerationManifest.reason")

    def to_obj(self) -> dict[str, object]:
        obj: dict[str, object] = {
            "generation_schema_version": self.generation_schema_version,
            "profile_hash": self.profile_hash,
            "seed": self.seed,
            "generator": self.generator.to_obj(),
            "status": str(self.status.value),
            "statistics": {
                "requested_ordinals": self.requested_ordinals,
                "attempted_candidates": self.attempted_candidates,
                "emitted_occurrences": self.emitted_occurrences,
                "unique_cases": self.unique_cases,
                "rejected_ordinals": self.rejected_ordinals,
                "interrupted_ordinals": self.interrupted_ordinals,
                "not_attempted": self.not_attempted,
            },
            "receipts": [receipt.to_obj() for receipt in self.receipts],
            "case_files": [entry.to_obj() for entry in self.case_files],
        }
        if self.reason is not None:
            obj["reason"] = self.reason
        return obj


# --------------------------------------------------------------------------
# Transforms (design 6.4.3) - D2 proposes, D1 rebuilds and revalidates
# --------------------------------------------------------------------------


class TransformKind(enum.StrEnum):
    REMOVE_ROWS = "remove_rows"
    REPLACE_VALUE = "replace_value"
    SIMPLIFY_PREDICATE = "simplify_predicate"
    REPLACE_LITERAL = "replace_literal"


class PathNode(enum.StrEnum):
    """Closed path vocabulary for locating a predicate/literal/constant."""

    PREDICATE = "predicate"
    LEFT = "left"
    RIGHT = "right"
    LOWER = "lower"
    UPPER = "upper"
    ARITHMETIC = "arithmetic"
    CONSTANT = "constant"


@dataclass(frozen=True)
class RemoveRows:
    """Delete shared rows; rids are preserved, no renumbering."""

    rids: tuple[int, ...]
    kind: Literal["remove_rows"] = "remove_rows"

    def __post_init__(self) -> None:
        if not isinstance(self.rids, tuple):
            _fail("RemoveRows.rids must be a tuple")
        previous: Optional[int] = None
        for rid in self.rids:
            _check_int(rid, "RemoveRows.rid")
            if not RID_MIN <= rid <= RID_MAX:
                _fail(f"RemoveRows.rid out of range: {rid}")
            if previous is not None and rid <= previous:
                _fail("RemoveRows.rids must be sorted and unique")
            previous = rid

    def to_obj(self) -> dict[str, object]:
        return {"kind": "remove_rows", "rids": list(self.rids)}


@dataclass(frozen=True)
class ReplaceValue:
    """Replace the shared value of one row on both sides."""

    rid: int
    value: ExactValue
    kind: Literal["replace_value"] = "replace_value"

    def __post_init__(self) -> None:
        _check_int(self.rid, "ReplaceValue.rid")
        if not RID_MIN <= self.rid <= RID_MAX:
            _fail(f"ReplaceValue.rid out of range: {self.rid}")
        if not isinstance(self.value, (NullValue, IntegerValue, DecimalValue)):
            _fail("ReplaceValue.value must be an exact value")

    def to_obj(self) -> dict[str, object]:
        return {"kind": "replace_value", "rid": self.rid, "value": self.value.to_obj()}


@dataclass(frozen=True)
class SimplifyPredicate:
    """Replace an AND/OR node with one of its existing child atoms."""

    path: tuple[PathNode, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, tuple)
            or len(self.path) < 2
            or self.path[0] is not PathNode.PREDICATE
        ):
            _fail("SimplifyPredicate.path must start with 'predicate'")
        for step in self.path:
            _check_enum(step, PathNode, "SimplifyPredicate.path step")

    def to_obj(self) -> dict[str, object]:
        return {
            "kind": "simplify_predicate",
            "path": [str(step.value) for step in self.path],
        }


@dataclass(frozen=True)
class ReplaceLiteral:
    """Replace a predicate constant, BETWEEN endpoint, or the Q4 constant k."""

    path: tuple[PathNode, ...]
    value: ExactValue

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, tuple)
            or len(self.path) < 2
            or self.path[0] is not PathNode.PREDICATE
        ):
            _fail("ReplaceLiteral.path must start with 'predicate'")
        for step in self.path:
            _check_enum(step, PathNode, "ReplaceLiteral.path step")
        if not isinstance(self.value, (NullValue, IntegerValue, DecimalValue)):
            _fail("ReplaceLiteral.value must be an exact value")

    def to_obj(self) -> dict[str, object]:
        return {
            "kind": "replace_literal",
            "path": [str(step.value) for step in self.path],
            "value": self.value.to_obj(),
        }


Transform = Union[RemoveRows, ReplaceValue, SimplifyPredicate, ReplaceLiteral]


class TransformStatus(enum.StrEnum):
    APPLIED = "APPLIED"
    REJECTED = "REJECTED"
    NO_CHANGE = "NO_CHANGE"


@dataclass(frozen=True)
class TransformResult:
    """Parent/child pairing; a child never overwrites its parent."""

    parent_case_id: str
    transform: Transform
    status: TransformStatus
    child: Optional[CaseBundle] = None
    static_check: Optional[CompatibilityCheck] = None
    rejection_reason: Optional[ReasonCode] = None

    def __post_init__(self) -> None:
        _check_hex64(self.parent_case_id, "TransformResult.parent_case_id")
        if not isinstance(
            self.transform, (RemoveRows, ReplaceValue, SimplifyPredicate, ReplaceLiteral)
        ):
            _fail("TransformResult.transform must be a closed Transform node")
        _check_enum(self.status, TransformStatus, "TransformResult.status")
        if self.child is not None:
            if not isinstance(self.child, CaseBundle):
                _fail("TransformResult.child must be a CaseBundle")
            if self.child.case_id == self.parent_case_id:
                _fail("TransformResult.child equal to parent must be NO_CHANGE, not APPLIED")
            if self.status is not TransformStatus.APPLIED:
                _fail("only APPLIED results carry a child")
        if self.static_check is not None and not isinstance(
            self.static_check, CompatibilityCheck
        ):
            _fail("TransformResult.static_check must be a CompatibilityCheck")
        if self.rejection_reason is not None:
            _check_enum(self.rejection_reason, ReasonCode, "TransformResult.rejection_reason")
            if self.status is not TransformStatus.REJECTED:
                _fail("only REJECTED results carry a rejection reason")
        if self.status is TransformStatus.REJECTED and self.rejection_reason is None:
            _fail("a REJECTED TransformResult requires a rejection reason")
        if self.status is TransformStatus.APPLIED and self.static_check is None:
            _fail("an APPLIED TransformResult carries its child static check")

    def to_obj(self) -> dict[str, object]:
        obj: dict[str, object] = {
            "parent_case_id": self.parent_case_id,
            "transform": self.transform.to_obj(),
            "status": str(self.status.value),
        }
        if self.child is not None:
            obj["child"] = self.child.to_obj()
        if self.static_check is not None:
            obj["static_check"] = self.static_check.to_obj()
        if self.rejection_reason is not None:
            obj["rejection_reason"] = str(self.rejection_reason.value)
        return obj


# --------------------------------------------------------------------------
# Profile (design 6.3.3)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleSelector:
    rule_id: str
    rule_version: int

    def __post_init__(self) -> None:
        _check_str(self.rule_id, "RuleSelector.rule_id")
        if not _RULE_ID_RE.match(self.rule_id):
            _fail(f"RuleSelector.rule_id has unsupported form: {self.rule_id!r}")
        _check_int(self.rule_version, "RuleSelector.rule_version")
        if self.rule_version < 1:
            _fail("RuleSelector.rule_version must be >= 1")

    def to_obj(self) -> dict[str, object]:
        return {"rule_id": self.rule_id, "rule_version": self.rule_version}


@dataclass(frozen=True)
class Profile:
    """Frozen profile schema 1; hard caps come from design 6.4.1.

    ``rules``/``templates``/``index_variants`` must already be sorted and
    unique; loader-side normalization sorts explicitly before construction
    and is never applied silently to sealed payloads.
    """

    rules: tuple[RuleSelector, ...]
    templates: tuple[TemplateId, ...]
    index_variants: tuple[IndexVariant, ...]
    row_count: int
    predicate_atoms: int
    attempts_per_ordinal: int
    max_payload_bytes: int
    max_bundle_bytes: int
    profile_schema_version: int = PROFILE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.profile_schema_version, "Profile.profile_schema_version")
        if self.profile_schema_version != PROFILE_SCHEMA_VERSION:
            _fail(f"unsupported profile_schema_version {self.profile_schema_version}")
        if not isinstance(self.rules, tuple) or not self.rules:
            _fail("Profile.rules must be a non-empty tuple")
        previous: Optional[RuleSelector] = None
        for selector in self.rules:
            if not isinstance(selector, RuleSelector):
                _fail("Profile.rules must hold RuleSelector items")
            if previous is not None and (selector.rule_id, selector.rule_version) <= (
                previous.rule_id,
                previous.rule_version,
            ):
                _fail("Profile.rules must be sorted and unique")
            previous = selector
        if not isinstance(self.templates, tuple) or not self.templates:
            _fail("Profile.templates must be a non-empty tuple")
        previous_template: Optional[TemplateId] = None
        for template in self.templates:
            _check_enum(template, TemplateId, "Profile.templates item")
            if previous_template is not None and template <= previous_template:
                _fail("Profile.templates must be sorted and unique")
            previous_template = template
        if not isinstance(self.index_variants, tuple) or not self.index_variants:
            _fail("Profile.index_variants must be a non-empty tuple")
        previous_variant: Optional[IndexVariant] = None
        for variant in self.index_variants:
            _check_enum(variant, IndexVariant, "Profile.index_variants item")
            if previous_variant is not None and variant <= previous_variant:
                _fail("Profile.index_variants must be sorted and unique")
            previous_variant = variant
        self._check_budget("row_count", self.row_count, 0, 1024)
        self._check_budget("predicate_atoms", self.predicate_atoms, 1, 2)
        self._check_budget("attempts_per_ordinal", self.attempts_per_ordinal, 1, 8)
        self._check_budget("max_payload_bytes", self.max_payload_bytes, 1, MAX_PAYLOAD_BYTES_HARD_CAP)
        self._check_budget(
            "max_bundle_bytes", self.max_bundle_bytes, 1, MAX_BUNDLE_BYTES_HARD_CAP
        )

    @staticmethod
    def _check_budget(name: str, value: object, low: int, high: int) -> None:
        _check_int(value, f"Profile.{name}")
        if not low <= value <= high:
            _fail(f"Profile.{name} must be in [{low}, {high}], got {value}")

    def to_obj(self) -> dict[str, object]:
        return {
            "profile_schema_version": self.profile_schema_version,
            "rules": [selector.to_obj() for selector in self.rules],
            "templates": [str(template.value) for template in self.templates],
            "index_variants": [str(variant.value) for variant in self.index_variants],
            "row_count": self.row_count,
            "predicate_atoms": self.predicate_atoms,
            "attempts_per_ordinal": self.attempts_per_ordinal,
            "max_payload_bytes": self.max_payload_bytes,
            "max_bundle_bytes": self.max_bundle_bytes,
        }
