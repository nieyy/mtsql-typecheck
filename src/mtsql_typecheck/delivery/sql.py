"""Safe standalone-SQL packaging for D4 delivery (design 6.4.6).

D1 ``render_pair()`` only produces CREATE TABLE/INSERT/SELECT; wrapping with
database creation, ``USE`` and session ``SET`` statements is this module's job
(6.4.6).  The D1 renderer identity is untouched: the D1 statement texts are
embedded verbatim, in their original order, without re-rendering.

Safety invariants enforced here and locked by tests:

- Session ``SET`` statements are rendered ONLY from typed, validated
  ``SessionPreconditions`` fields.  Variable names come from a fixed module
  whitelist; every value passes through one controlled literal escaper
  (``_sql_literal``).  A malicious session value can never compose a second
  SQL statement: the field regexes forbid semicolons/quotes/backslashes where
  they would be dangerous, and the escaper escapes any residual quote or
  backslash inside a single-quoted literal.
- Package layout is exactly: comment header, session SETs, ``CREATE DATABASE``
  (no ``IF NOT EXISTS``), ``USE``, then the D1 statements verbatim.
- No ``DROP`` anywhere, no ``IF NOT EXISTS`` anywhere, no ``--force``: the
  composed text is re-checked before being returned and a violation raises.
- Physical names are derived deterministically from a validated export token
  plus the case_id prefix (``assign_name_map``); the logical case identity
  never depends on the token.
- Environment requirements come from the case payload (or supplied execution
  evidence) only; never from the local machine.  A generation-only export has
  ``optimizer_baseline == OPTIMIZER_BASELINE_UNKNOWN`` and must not fabricate
  a baseline from host defaults.  Provided values that cannot be expressed
  safely raise instead of being rendered (6.4.6).

Pure module: no file, network or database I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mtsql_typecheck.contracts.case import (
    CasePayload,
    ContractError,
    EnvironmentRequirements,
    ObservedEnvironment,
)
from mtsql_typecheck.contracts.codec import case_id_of
from mtsql_typecheck.generation.render import RenderedPair, RenderedStatement

__all__ = [
    "DeliverySqlError",
    "ExportNameMap",
    "SessionPreconditions",
    "EnvironmentRequirementsDoc",
    "EXPORTER_NOTE",
    "CANDIDATE_UNVERIFIED_MARKER",
    "NOT_RUN_INPUT_NOTE",
    "OPTIMIZER_BASELINE_UNKNOWN",
    "OPTIMIZER_BASELINE_UNKNOWN_NOTE",
    "SQL_VARIABLE_WHITELIST",
    "ISOLATION_LEVELS",
    "assign_name_map",
    "render_session_sql",
    "wrap_sql_package",
    "environment_requirements_document",
    "environment_requirements_document_with_observed",
    "decode_environment_requirements_document",
]


class DeliverySqlError(ContractError):
    """Stable rejection of an unsafe or malformed SQL packaging input."""


# --------------------------------------------------------------------------
# Header constants (design 6.4.6: the package is manual material, not a
# generation bundle; run --input must not accept it)
# --------------------------------------------------------------------------

EXPORTER_NOTE = "exported by mtsql-typecheck"
CANDIDATE_UNVERIFIED_MARKER = "candidate/unverified"
NOT_RUN_INPUT_NOTE = "manual execution material; not accepted by mt-typecheck run --input"

# Generation-only exports have no recorded optimizer baseline (6.4.6): the
# exported requirements flag UNKNOWN and demand a human check instead of
# substituting this host's or the target's defaults.
OPTIMIZER_BASELINE_UNKNOWN = "UNKNOWN"
OPTIMIZER_BASELINE_UNKNOWN_NOTE = (
    "optimizer_baseline is UNKNOWN: the source material recorded no "
    "optimizer_switch baseline (generation-only export). Do not assume the "
    "target session defaults match the original run; a human must check "
    "optimizer_switch before comparing results."
)

# Fixed SET variable whitelist (6.4.6: 变量名白名单).  optimizer_switch is
# rendered only when an optimizer_baseline was actually provided/observed.
SQL_VARIABLE_WHITELIST = frozenset(
    {
        "sql_mode",
        "character_set_client",
        "character_set_results",
        "character_set_connection",
        "collation_connection",
        "collation_database",
        "collation_server",
        "time_zone",
        "transaction_isolation",
        "optimizer_switch",
    }
)

# Fixed isolation whitelist (6.4.6 session preconditions: 隔离级别).
ISOLATION_LEVELS = frozenset(
    {
        "READ UNCOMMITTED",
        "READ COMMITTED",
        "REPEATABLE READ",
        "SERIALIZABLE",
    }
)

# --------------------------------------------------------------------------
# Field validators (whitelist regexes; quotes/semicolons/whitespace oddities
# are forbidden so a session value can never split into a second statement)
# --------------------------------------------------------------------------

_SQL_MODE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_,=!<>-]{1,128}$")
# Substrings/characters that must never appear inside a rendered session
# value, on top of the per-field whitelist regexes (no quotes, no statement
# separators, no whitespace oddities, no comment openers).
_FORBIDDEN_SUBSTRINGS = (";", "'", '"', "\\", "--", "/*", "*/", "`")
_FORBIDDEN_CHARS = re.compile(r"[\s\x00-\x1f\x7f]")
_NAME_VALUE_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_TIME_ZONE_OFFSET_RE = re.compile(r"^[+-][0-9]{2}:[0-9]{2}$")
_TIME_ZONE_NAMED_RE = re.compile(r"^[A-Za-z0-9_/+-]{1,64}$")
_OPTIMIZER_BASELINE_RE = re.compile(r"^[A-Za-z0-9_,=]{1,256}$")
_CASE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_EXPORT_TOKEN_RE = re.compile(r"^[a-z0-9]{8,32}$")
_EXPORT_IDENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_NOTE_RE = re.compile(r"^[^\x00-\x1f\x7f]+$")


def _fail(message: str) -> None:
    raise DeliverySqlError(message)


def _reject_unsafe_text(value: str, field: str) -> None:
    for forbidden in _FORBIDDEN_SUBSTRINGS:
        if forbidden in value:
            _fail(f"{field} must not contain {forbidden!r}: {value!r}")
    if _FORBIDDEN_CHARS.search(value):
        _fail(f"{field} must not contain whitespace or control characters: {value!r}")


def _validated_sql_mode_tokens(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        _fail("SessionPreconditions.sql_mode_tokens must be a tuple")
    seen: set[str] = set()
    for token in value:
        if not isinstance(token, str) or not _SQL_MODE_TOKEN_RE.match(token):
            _fail(f"sql_mode token has unsupported form: {token!r}")
        _reject_unsafe_text(token, "sql_mode token")
        if token in seen:
            _fail(f"sql_mode token repeated: {token!r}")
        seen.add(token)
    return value


def _validated_name_value(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _NAME_VALUE_RE.match(value):
        _fail(f"{field} must match [A-Za-z0-9_]{{1,64}}, got {value!r}")
    _reject_unsafe_text(value, field)
    return value


def _validated_time_zone(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not (
        _TIME_ZONE_OFFSET_RE.match(value) or _TIME_ZONE_NAMED_RE.match(value)
    ):
        _fail(
            "time_zone must be +HH:MM/-HH:MM or a named zone matching "
            f"[A-Za-z0-9_/+-]{{1,64}}, got {value!r}"
        )
    _reject_unsafe_text(value, "time_zone")
    return value


def _validated_isolation_level(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in ISOLATION_LEVELS:
        _fail(
            "isolation_level must be one of "
            f"{sorted(ISOLATION_LEVELS)}, got {value!r}"
        )
    return value


def _validated_optimizer_baseline(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _OPTIMIZER_BASELINE_RE.match(value):
        _fail(
            f"optimizer_baseline must match [A-Za-z0-9_,=]{{1,256}} or be None, "
            f"got {value!r}"
        )
    _reject_unsafe_text(value, "optimizer_baseline")
    return value


def _validated_notes(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        _fail("SessionPreconditions.unknown_fields_note must be a tuple")
    for note in value:
        if not isinstance(note, str) or not note or not _SAFE_NOTE_RE.match(note):
            _fail(f"unknown_fields_note entry must be a printable non-empty str: {note!r}")
    return value


# --------------------------------------------------------------------------
# Typed inputs (design 6.4.6: SET 只从已校验的 typed 环境字段渲染)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionPreconditions:
    """Recorded session preconditions of the ORIGINAL run environment.

    These describe what the original run observed/required; they are NOT the
    D1 generation token set (``REQUIRED_SQL_MODE_TOKENS`` stays a generation
    concern).  Every field is validated at construction: a value that cannot
    be rendered as exactly one safe ``SET`` statement is rejected here, before
    any SQL exists.  ``None`` fields are simply not rendered.  Notes are for
    the human README only and are never rendered into SQL.
    """

    sql_mode_tokens: tuple[str, ...] = ()
    character_set: str | None = None
    collation: str | None = None
    time_zone: str | None = None
    isolation_level: str | None = None
    optimizer_baseline: str | None = None
    unknown_fields_note: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validated_sql_mode_tokens(self.sql_mode_tokens)
        _validated_name_value(self.character_set, "character_set")
        _validated_name_value(self.collation, "collation")
        _validated_time_zone(self.time_zone)
        _validated_isolation_level(self.isolation_level)
        _validated_optimizer_baseline(self.optimizer_baseline)
        _validated_notes(self.unknown_fields_note)


@dataclass(frozen=True)
class ExportNameMap:
    """Physical A/B identifiers for one export package (6.4.6 export NameMap).

    Built only by ``assign_name_map`` from a validated token; the logical
    case_id never changes with the token.
    """

    database_a: str
    database_b: str
    table_a: str
    table_b: str

    def __post_init__(self) -> None:
        for attribute in ("database_a", "database_b", "table_a", "table_b"):
            value = getattr(self, attribute)
            if not isinstance(value, str) or not _EXPORT_IDENT_RE.match(value):
                _fail(f"ExportNameMap.{attribute} must match [a-z][a-z0-9_]{{0,63}}")
        if self.database_a == self.database_b:
            _fail("ExportNameMap A/B databases must differ")
        if self.table_a == self.table_b:
            _fail("ExportNameMap A/B tables must differ")


def assign_name_map(case_id: str, token: str) -> ExportNameMap:
    """Deterministic physical names from the case_id and an export token.

    Same (case_id, token) always yields the same names; a different token
    yields different physical names for the SAME logical case.  The token is
    chosen by the export package (6.4.6: 名称由导出包分配合法随机 token).
    """
    if not isinstance(case_id, str) or not _CASE_ID_RE.match(case_id):
        _fail(f"case_id must be lowercase 64-hex sha256, got {case_id!r}")
    if not isinstance(token, str) or not _EXPORT_TOKEN_RE.match(token):
        _fail(f"token must match [a-z0-9]{{8,32}}, got {token!r}")
    prefix = case_id[:8]
    return ExportNameMap(
        database_a=f"tc_a_{token}_{prefix}",
        database_b=f"tc_b_{token}_{prefix}",
        table_a=f"t_a_{token}_{prefix}",
        table_b=f"t_b_{token}_{prefix}",
    )


# --------------------------------------------------------------------------
# Session SET rendering (single controlled literal escaper)
# --------------------------------------------------------------------------


def _sql_literal(value: str) -> str:
    """Render one string as a single-quoted MySQL literal.

    Backslash and quote are escaped; everything else passes through.  The
    field validators already forbid semicolons/quotes/backslashes in the
    dangerous positions; this escaper is the residual defense, so a hostile
    value stays inside the one literal and can never terminate the statement.
    """
    if not isinstance(value, str):
        _fail(f"sql literal value must be a str, got {type(value).__name__}")
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def render_session_sql(pre: SessionPreconditions) -> tuple[str, ...]:
    """One complete ``SET`` statement per provided field, in fixed order.

    Unknown fields are never rendered (there is no free-text path into this
    function); a field left ``None`` produces no statement.  Each returned
    string is exactly one statement terminated by one semicolon.
    """
    statements: list[str] = []
    if pre.sql_mode_tokens:
        joined = ",".join(pre.sql_mode_tokens)
        statements.append(f"SET sql_mode = {_sql_literal(joined)};")
    if pre.character_set is not None:
        for variable in (
            "character_set_client",
            "character_set_results",
            "character_set_connection",
        ):
            statements.append(f"SET {variable} = {_sql_literal(pre.character_set)};")
    if pre.collation is not None:
        for variable in ("collation_connection", "collation_database", "collation_server"):
            statements.append(f"SET {variable} = {_sql_literal(pre.collation)};")
    if pre.time_zone is not None:
        statements.append(f"SET time_zone = {_sql_literal(pre.time_zone)};")
    if pre.isolation_level is not None:
        statements.append(f"SET transaction_isolation = {_sql_literal(pre.isolation_level)};")
    if pre.optimizer_baseline is not None:
        statements.append(f"SET optimizer_switch = {_sql_literal(pre.optimizer_baseline)};")
    for statement in statements:
        variable = statement.split(" ", 2)[1]
        if variable not in SQL_VARIABLE_WHITELIST:
            _fail(f"internal error: variable {variable!r} is not in the SET whitelist")
    return tuple(statements)


# --------------------------------------------------------------------------
# a.sql / b.sql composition
# --------------------------------------------------------------------------

_BANNED_SQL_RE = re.compile(r"\bDROP\b|IF\s+NOT\s+EXISTS|--force", re.IGNORECASE)


def _terminated(statement: str) -> str:
    """Return the statement with exactly one terminating semicolon.

    D1 statement texts already end with ``;``; they are kept byte-for-byte.
    Wrapper statements rendered here are terminated the same way, so the
    package is effectively statements joined by ``;\\n``.
    """
    stripped = statement.rstrip()
    if not stripped:
        _fail("refusing to render an empty statement")
    return stripped if stripped.endswith(";") else stripped + ";"


def _package_text(
    header: tuple[str, ...],
    session_statements: tuple[str, ...],
    database: str,
    statements: tuple[RenderedStatement, ...],
) -> str:
    lines = list(header)
    for statement in (*session_statements, f"CREATE DATABASE `{database}`", f"USE `{database}`"):
        lines.append(_terminated(statement))
    # D1 statements verbatim, original order, bytes preserved (6.4.6).
    lines.extend(_terminated(item.text) for item in statements)
    text = "\n".join(lines) + "\n"
    if _BANNED_SQL_RE.search(text):
        _fail("composed package contains DROP / IF NOT EXISTS / --force; refusing export")
    return text


def wrap_sql_package(
    rendered_pair: RenderedPair,
    pre: SessionPreconditions,
    names: ExportNameMap,
) -> tuple[str, str]:
    """Compose a.sql/b.sql for one rendered pair under one precondition set.

    Exact order (6.4.6, golden-checked): comment header lines, session SET
    statements, ``CREATE DATABASE`` (no IF NOT EXISTS), ``USE``, then the D1
    ``render_pair`` statements verbatim in their original order.  Statements
    are joined with a semicolon+newline and the file ends with a single
    trailing newline.
    """
    if not isinstance(rendered_pair, RenderedPair):
        _fail("wrap_sql_package needs a RenderedPair")
    if not isinstance(pre, SessionPreconditions):
        _fail("wrap_sql_package needs SessionPreconditions")
    if not isinstance(names, ExportNameMap):
        _fail("wrap_sql_package needs an ExportNameMap")
    name_map = rendered_pair.name_map
    if (
        names.database_a,
        names.database_b,
        names.table_a,
        names.table_b,
    ) != (
        name_map.database_a,
        name_map.database_b,
        name_map.table_a,
        name_map.table_b,
    ):
        _fail(
            "export names must match the rendered pair's NameMap; the D1 "
            "statements reference tables the package would not create"
        )
    case_id = case_id_of(rendered_pair.payload)
    header = (
        f"# {EXPORTER_NOTE} (D4 independent SQL delivery; design 6.4.6)",
        f"# case_id: {case_id}",
        f"# status: {CANDIDATE_UNVERIFIED_MARKER}; {NOT_RUN_INPUT_NOTE}",
    )
    session_statements = render_session_sql(pre)
    return (
        _package_text(header, session_statements, names.database_a, rendered_pair.a),
        _package_text(header, session_statements, names.database_b, rendered_pair.b),
    )


# --------------------------------------------------------------------------
# Environment requirements document (from case payload / evidence only)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class EnvironmentRequirementsDoc:
    """Exported environment-requirements record (6.4.6).

    Mirrors the case payload's ``EnvironmentRequirements`` plus the recorded
    optimizer baseline.  Values come only from the case payload or supplied
    execution evidence; a value that cannot be expressed safely raises at
    construction (拒绝导出) instead of being rendered unchecked.
    """

    database: str
    engine: str
    scope: str
    sql_mode_tokens: tuple[str, ...]
    character_set: str
    collation: str
    time_zone: str
    optimizer_baseline: str

    def __post_init__(self) -> None:
        for field in ("database", "engine", "scope"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value or not _SAFE_NOTE_RE.match(value):
                _fail(f"EnvironmentRequirementsDoc.{field} must be a safe non-empty str")
        _validated_sql_mode_tokens(self.sql_mode_tokens)
        if _validated_name_value(self.character_set, "character_set") is None:
            _fail("EnvironmentRequirementsDoc.character_set is required")
        if _validated_name_value(self.collation, "collation") is None:
            _fail("EnvironmentRequirementsDoc.collation is required")
        if _validated_time_zone(self.time_zone) is None:
            _fail("EnvironmentRequirementsDoc.time_zone is required")
        if self.optimizer_baseline != OPTIMIZER_BASELINE_UNKNOWN:
            _validated_optimizer_baseline(self.optimizer_baseline)
            if self.optimizer_baseline is None:
                _fail(
                    "EnvironmentRequirementsDoc.optimizer_baseline must be a value or "
                    f"the {OPTIMIZER_BASELINE_UNKNOWN!r} sentinel"
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
            "optimizer_baseline": self.optimizer_baseline,
        }


def _doc_from_environment(
    environment: EnvironmentRequirements, optimizer_baseline: str
) -> EnvironmentRequirementsDoc:
    if not isinstance(environment, EnvironmentRequirements):
        _fail("environment requirements need an EnvironmentRequirements")
    validated = _validated_optimizer_baseline(optimizer_baseline)
    if validated is None:
        _fail("optimizer_baseline must be a value or the UNKNOWN sentinel")
    return EnvironmentRequirementsDoc(
        database=environment.database,
        engine=environment.engine,
        scope=environment.scope,
        sql_mode_tokens=environment.sql_mode_tokens,
        character_set=environment.character_set,
        collation=environment.collation,
        time_zone=environment.time_zone,
        optimizer_baseline=validated,
    )


def environment_requirements_document(payload: CasePayload) -> EnvironmentRequirementsDoc:
    """Build the requirements doc from the CASE payload only.

    Generation-only material has no recorded optimizer baseline: the doc
    carries the ``UNKNOWN`` sentinel and the README note; nothing is read
    from the local machine and no baseline is fabricated (6.4.6).
    """
    if not isinstance(payload, CasePayload):
        _fail("environment_requirements_document needs a CasePayload")
    return _doc_from_environment(payload.environment, OPTIMIZER_BASELINE_UNKNOWN)


def environment_requirements_document_with_observed(
    environment: EnvironmentRequirements, observed: ObservedEnvironment
) -> EnvironmentRequirementsDoc:
    """Same doc, with the real baseline taken from execution evidence."""
    if not isinstance(observed, ObservedEnvironment):
        _fail("environment_requirements_document_with_observed needs an ObservedEnvironment")
    return _doc_from_environment(environment, observed.optimizer_switch)


def decode_environment_requirements_document(obj: object) -> EnvironmentRequirementsDoc:
    """Strict decode of a serialized environment-requirements document."""
    if not isinstance(obj, dict):
        _fail("environment requirements document must be a JSON object")
    expected_keys = {
        "database",
        "engine",
        "scope",
        "sql_mode_tokens",
        "character_set",
        "collation",
        "time_zone",
        "optimizer_baseline",
    }
    if set(obj) != expected_keys:
        _fail(f"environment requirements document keys must be exactly {sorted(expected_keys)}")
    tokens = obj["sql_mode_tokens"]
    if isinstance(tokens, list):
        tokens = tuple(tokens)
    return EnvironmentRequirementsDoc(
        database=obj["database"],
        engine=obj["engine"],
        scope=obj["scope"],
        sql_mode_tokens=tokens,
        character_set=obj["character_set"],
        collation=obj["collation"],
        time_zone=obj["time_zone"],
        optimizer_baseline=obj["optimizer_baseline"],
    )
