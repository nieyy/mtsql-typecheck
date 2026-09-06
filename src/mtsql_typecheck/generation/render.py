"""MySQL text-protocol SQL renderer for D1 (design 6.2.2, 6.3.2, 6.4.2; S01).

Pure rendering only: no file, network or database I/O, no SQL parsing, no
prepared-statement parameters, no CAST, no cleanup statements (no ``DROP``).
Every statement is emitted as exact text-protocol SQL with parameters=[] and a
per-statement SHA-256 over the UTF-8 statement text (``codec.sha256_hex``).

Renderer identity is ``r1``/``1`` (design 6.4.1 g1/r1); ``render_pair`` and
``render_preview`` reject payloads sealed with a different renderer identity.

Frozen text decisions locked by golden tests (``tests/unit/render``):

- DDL: ``CREATE TABLE `<table>` (`rid` BIGINT NOT NULL PRIMARY KEY, `v` <type> NULL[,
  KEY `ix_v` (`v`)])`` followed by a second line ``  ENGINE=InnoDB DEFAULT
  CHARSET=utf8mb4 COLLATE=utf8mb4_bin;`` exactly as in design 6.4.2.  ``ix_v``
  appends ``, KEY `ix_v` (`v`)`` inside the column list on both sides.
- INSERT: ``INSERT INTO `<table>` VALUES (rid,value),(rid,value),...;`` rows
  joined by a single comma, at most 64 rows per statement, shared rows in
  payload (rid) order; zero rows produce no INSERT statement.
- SELECT: fixed per template with backquoted columns/aliases; the Q4
  arithmetic expression is wrapped in one pair of parentheses.
- Predicates: Compare renders as ```v` <op> <literal>`` (NULL allowed at the
  constant position, ``<=>`` for NULL-safe equality), Between as
  ```v` BETWEEN <lo> AND <hi>``, IsNull as ```v` IS [NOT] NULL``; And/Or wrap
  the whole two-atom conjunction/disjunction in one pair of parentheses and
  their atoms stay unparenthesized: ``(P1 AND P2)``.
- Exact literals: integers as unquoted canonical decimal text (no exponent,
  no float; values beyond 2^53 pass through verbatim); decimals as fixed-point
  text built from coefficient/scale with the declared number of fraction
  digits (e.g. coefficient=-12345, scale=2 -> ``-123.45``; coefficient=5,
  scale=2 -> ``0.05``; scale=0 has no decimal point); NULL as ``NULL``.
- Identifiers: only a ``NameMap`` (contract charset ``[a-z][a-z0-9_]*``,
  length 1-48); every identifier is separately backquoted, never qualified
  with a dot and never accepted as free SQL text.  A/B tables must differ in
  addition to the A/B database rule enforced by ``NameMap`` itself.
- Preview: ``render_preview`` renders with the fixed logical names
  ``preview_a``/``preview_b`` and returns the two side texts (statements
  joined by ``\n``, no trailing newline); it uses the same statement sequence
  as ``render_pair``, so preview and actual SQL differ only in identifiers.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass

from mtsql_typecheck.contracts.case import (
    Arithmetic,
    ArithmeticOp,
    AggregateExpr,
    AggregateFunc,
    And,
    Between,
    CasePayload,
    ColumnRef,
    Compare,
    ContractError,
    DecimalValue,
    ExactLiteral,
    ExactValue,
    IndexVariant,
    IntegerValue,
    IsNull,
    NameMap,
    NullValue,
    Or,
    Projection,
    ReasonCode,
    Row,
    SemverIdentity,
    TypeSpec,
)
from mtsql_typecheck.contracts.codec import sha256_hex

__all__ = [
    "RenderError",
    "RenderPhase",
    "RenderedStatement",
    "RenderedPair",
    "RENDERER_IDENTITY",
    "PREVIEW_NAME_MAP",
    "MAX_INSERT_BATCH_ROWS",
    "render_pair",
    "render_preview",
]


class RenderError(ContractError):
    """Stable rejection of a rendering input; carries a ReasonCode."""

    def __init__(self, reason: ReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class RenderPhase(enum.StrEnum):
    """Phase of a rendered statement; SELECT is not a StatementReceipt phase."""

    DDL = "ddl"
    INSERT = "insert"
    SELECT = "select"


RENDERER_IDENTITY = SemverIdentity("r1", "1")
PREVIEW_NAME_MAP = NameMap(
    database_a="preview_a", database_b="preview_b", table_a="preview_a", table_b="preview_b"
)
MAX_INSERT_BATCH_ROWS = 64

_IDENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,47}$")

_AGGREGATE_TEXT = {
    AggregateFunc.COUNT: "COUNT",
    AggregateFunc.MIN: "MIN",
    AggregateFunc.MAX: "MAX",
    AggregateFunc.SUM: "SUM",
}


@dataclass(frozen=True)
class RenderedStatement:
    """One text-protocol statement; ``sql_hash`` covers the UTF-8 text."""

    phase: RenderPhase
    text: str
    sql_hash: str
    protocol: str = "text"
    parameters: Tuple[()] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.phase, RenderPhase):
            raise RenderError(
                ReasonCode.INVALID_STRUCTURE,
                f"statement phase must be RenderPhase, got {self.phase!r}",
            )
        if not isinstance(self.text, str) or not self.text:
            raise RenderError(ReasonCode.INVALID_STRUCTURE, "statement text must be non-empty")
        if self.sql_hash != sha256_hex(self.text.encode("utf-8")):
            raise RenderError(
                ReasonCode.INTERNAL_ERROR, "statement sql_hash does not match its text"
            )
        if self.protocol != "text" or self.parameters != ():
            raise RenderError(
                ReasonCode.INVALID_STRUCTURE,
                "text protocol forbids non-text protocol or non-empty parameters",
            )


@dataclass(frozen=True)
class RenderedPair:
    """A/B statement sequences rendered from one payload under one NameMap."""

    payload: CasePayload
    name_map: NameMap
    a: tuple[RenderedStatement, ...]
    b: tuple[RenderedStatement, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.payload, CasePayload):
            raise RenderError(ReasonCode.INVALID_STRUCTURE, "RenderedPair.payload must be a payload")
        if not isinstance(self.name_map, NameMap):
            raise RenderError(ReasonCode.INVALID_STRUCTURE, "RenderedPair.name_map must be a NameMap")
        for side in (self.a, self.b):
            if not isinstance(side, tuple) or not side:
                raise RenderError(ReasonCode.INVALID_STRUCTURE, "a rendered side is never empty")
            if not all(isinstance(item, RenderedStatement) for item in side):
                raise RenderError(
                    ReasonCode.INVALID_STRUCTURE, "rendered sides hold RenderedStatement items"
                )


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------


def _check_renderer_identity(payload: CasePayload) -> None:
    if payload.renderer != RENDERER_IDENTITY:
        raise RenderError(
            ReasonCode.UNKNOWN_VERSION,
            f"payload sealed for renderer {payload.renderer.id}/{payload.renderer.version}, "
            f"this module renders {RENDERER_IDENTITY.id}/{RENDERER_IDENTITY.version}",
        )


def _check_identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not _IDENT_RE.match(value):
        raise RenderError(
            ReasonCode.INVALID_STRUCTURE,
            f"{name} must match [a-z][a-z0-9_]{{0,47}}, got {value!r}",
        )
    return value


def _check_name_map(name_map: NameMap) -> None:
    for attribute in ("database_a", "database_b", "table_a", "table_b"):
        _check_identifier(getattr(name_map, attribute), f"NameMap.{attribute}")
    if name_map.table_a == name_map.table_b:
        raise RenderError(
            ReasonCode.INVALID_STRUCTURE,
            f"NameMap A/B tables must differ, got {name_map.table_a!r} on both sides",
        )


# --------------------------------------------------------------------------
# Text building blocks
# --------------------------------------------------------------------------


def _render_type(type_spec: TypeSpec) -> str:
    if type_spec.kind == "signed_integer":
        return str(type_spec.name.value)
    return f"DECIMAL({type_spec.precision},{type_spec.scale})"


def _render_exact_value(value: ExactValue) -> str:
    if isinstance(value, NullValue):
        return "NULL"
    if isinstance(value, IntegerValue):
        return str(value.value)
    if isinstance(value, DecimalValue):
        coefficient = value.coefficient
        scale = value.scale
        sign = "-" if coefficient < 0 else ""
        digits = str(abs(coefficient))
        if scale == 0:
            return sign + digits
        digits = digits.rjust(scale + 1, "0")
        return f"{sign}{digits[:-scale]}.{digits[-scale:]}"
    raise RenderError(
        ReasonCode.INTERNAL_ERROR,
        f"unsupported exact value {type(value).__name__}",
    )


def _render_literal(literal: ExactLiteral) -> str:
    return _render_exact_value(literal.value)


def _render_predicate(predicate: object) -> str:
    if isinstance(predicate, Compare):
        return f"`v` {predicate.op.value} {_render_literal(predicate.right)}"
    if isinstance(predicate, Between):
        return (
            f"`v` BETWEEN {_render_literal(predicate.lower)} "
            f"AND {_render_literal(predicate.upper)}"
        )
    if isinstance(predicate, IsNull):
        negation = "NOT " if predicate.negated else ""
        return f"`v` IS {negation}NULL"
    if isinstance(predicate, And):
        return f"({_render_predicate(predicate.left)} AND {_render_predicate(predicate.right)})"
    if isinstance(predicate, Or):
        return f"({_render_predicate(predicate.left)} OR {_render_predicate(predicate.right)})"
    raise RenderError(
        ReasonCode.INVALID_STRUCTURE,
        f"unsupported predicate node {type(predicate).__name__}",
    )


def _render_projection_expr(projection: Projection) -> str:
    expr = projection.expr
    if isinstance(expr, ColumnRef):
        return f"`{expr.column.value}`"
    if isinstance(expr, Arithmetic):
        operator = "+" if expr.op is ArithmeticOp.ADD else "-"
        return f"(`v` {operator} {expr.constant.value})"
    if isinstance(expr, AggregateExpr):
        if expr.func is AggregateFunc.COUNT_STAR:
            return "COUNT(*)"
        column = expr.column
        if not isinstance(column, ColumnRef):
            raise RenderError(ReasonCode.INTERNAL_ERROR, "aggregate without a column reference")
        return f"{_AGGREGATE_TEXT[expr.func]}(`{column.column.value}`)"
    raise RenderError(
        ReasonCode.INVALID_STRUCTURE, f"unsupported projection node {type(expr).__name__}"
    )


def _render_projection(projection: Projection) -> str:
    return f"{_render_projection_expr(projection)} AS `{projection.alias}`"


def _render_ddl(table: str, v_type: str, index_variant: IndexVariant) -> str:
    index_clause = ", KEY `ix_v` (`v`)" if index_variant is IndexVariant.IX_V else ""
    return (
        f"CREATE TABLE `{table}` (`rid` BIGINT NOT NULL PRIMARY KEY, `v` {v_type} NULL"
        f"{index_clause})\n"
        "  ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;"
    )


def _render_row(row: Row) -> str:
    return f"({row.rid},{_render_exact_value(row.value)})"


def _render_insert(table: str, batch: tuple[Row, ...]) -> str:
    values = ",".join(_render_row(row) for row in batch)
    return f"INSERT INTO `{table}` VALUES {values};"


def _render_select(table: str, payload: CasePayload) -> str:
    projections = ", ".join(_render_projection(item) for item in payload.query.projections)
    where = ""
    if payload.query.predicate is not None:
        where = f" WHERE {_render_predicate(payload.query.predicate)}"
    return f"SELECT {projections} FROM `{table}`{where};"


def _statement(phase: RenderPhase, text: str) -> RenderedStatement:
    return RenderedStatement(phase, text, sha256_hex(text.encode("utf-8")))


# --------------------------------------------------------------------------
# Public entry points
# --------------------------------------------------------------------------


def render_pair(payload: CasePayload, name_map: NameMap) -> RenderedPair:
    """Render the A/B statement sequences for D3 under the actual namespace.

    Pure function: no object is created, nothing is authorized for execution.
    The statement order is fixed: CREATE TABLE, then INSERT batches (at most
    64 rows each, omitted entirely for zero rows), then SELECT.
    """
    if not isinstance(payload, CasePayload):
        raise RenderError(ReasonCode.INVALID_STRUCTURE, "render_pair needs a CasePayload")
    if not isinstance(name_map, NameMap):
        raise RenderError(ReasonCode.INVALID_STRUCTURE, "render_pair needs a NameMap")
    _check_renderer_identity(payload)
    _check_name_map(name_map)
    index_variant = payload.table.index_variant
    statements_a = [
        _statement(RenderPhase.DDL, _render_ddl(name_map.table_a, _render_type(payload.a_type), index_variant))
    ]
    statements_b = [
        _statement(RenderPhase.DDL, _render_ddl(name_map.table_b, _render_type(payload.b_type), index_variant))
    ]
    rows = payload.rows.rows
    for start in range(0, len(rows), MAX_INSERT_BATCH_ROWS):
        batch = rows[start : start + MAX_INSERT_BATCH_ROWS]
        statements_a.append(_statement(RenderPhase.INSERT, _render_insert(name_map.table_a, batch)))
        statements_b.append(_statement(RenderPhase.INSERT, _render_insert(name_map.table_b, batch)))
    statements_a.append(_statement(RenderPhase.SELECT, _render_select(name_map.table_a, payload)))
    statements_b.append(_statement(RenderPhase.SELECT, _render_select(name_map.table_b, payload)))
    return RenderedPair(
        payload=payload,
        name_map=name_map,
        a=tuple(statements_a),
        b=tuple(statements_b),
    )


def render_preview(payload: CasePayload) -> tuple[str, str]:
    """Render the logical preview SQL under the fixed preview names.

    Returns ``(preview_a_sql, preview_b_sql)``; each text is the side's
    DDL/INSERT/SELECT statements joined by newlines with no trailing newline,
    ready to be sealed into the bundle as preview-a.sql/preview-b.sql content.
    The statement sequence matches ``render_pair``; only identifiers differ.
    """
    if not isinstance(payload, CasePayload):
        raise RenderError(ReasonCode.INVALID_STRUCTURE, "render_preview needs a CasePayload")
    _check_renderer_identity(payload)
    pair = render_pair(payload, PREVIEW_NAME_MAP)
    preview_a = "\n".join(statement.text for statement in pair.a)
    preview_b = "\n".join(statement.text for statement in pair.b)
    return preview_a, preview_b
