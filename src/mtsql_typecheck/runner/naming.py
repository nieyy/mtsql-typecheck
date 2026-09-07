"""Run/attempt object naming for D3 (design 6.2.3).

Database names are ``tc_<run-token>_<attempt-token>_a`` and
``..._b``; table names inside each attempt database are the distinct short
names ``case_a`` / ``case_b`` plus the fixed D3 ownership marker table.  The
total database name length never exceeds the D1 identifier limit of 48
characters (``contracts.case._IDENT_RE``: ``^[a-z][a-z0-9_]{0,47}$``).

Tokens are cryptographically random lowercase hex, drawn from
``secrets`` by default and always injectable: every generator accepts a
zero-argument ``token_source`` callable so tests can pin tokens without
weakening the production path.  Token generation never depends on
user-provided SQL; ``case_id`` does not change with the physical names.

The validator in this module is the single ownership guard used by cleanup:
a name that does not parse as a tool-generated attempt database name is
refused before any destructive statement is built (no prefix scans, design
6.4.5).  Importing this module performs no I/O.
"""

from __future__ import annotations

import re
import secrets
from typing import Callable, Optional, Tuple

from ..contracts.case import ContractError

__all__ = [
    "DATABASE_NAME_MAX_CHARS",
    "DATABASE_PREFIX",
    "RUN_TOKEN_HEX_CHARS",
    "ATTEMPT_TOKEN_HEX_CHARS",
    "TOKEN_MIN_HEX_CHARS",
    "TOKEN_MAX_HEX_CHARS",
    "TABLE_A",
    "TABLE_B",
    "NamingError",
    "TokenSource",
    "default_token_source",
    "new_run_token",
    "new_attempt_token",
    "validate_token",
    "attempt_database_names",
    "validate_database_name",
    "is_valid_database_name",
    "marker_table_name",
    "validate_marker_table_name",
]

# D1 identifier limit: [a-z][a-z0-9_]{0,47} -- 48 chars total.
DATABASE_NAME_MAX_CHARS = 48

DATABASE_PREFIX = "tc_"

# Production token lengths (hex chars).  3 + 16 + 1 + 16 + 2 = 38 <= 48.
RUN_TOKEN_HEX_CHARS = 16
ATTEMPT_TOKEN_HEX_CHARS = 16

# Validator bounds: short enough to keep the 48-char limit enforceable with
# margin, wide enough for the exactly-48-char boundary case (20 + 20 tokens).
TOKEN_MIN_HEX_CHARS = 8
TOKEN_MAX_HEX_CHARS = 24

# Short table names are shared across attempts (they live in distinct
# databases, design 6.2.2 NameMap uniqueness note).
TABLE_A = "case_a"
TABLE_B = "case_b"

_IDENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_NAME_RE = re.compile(
    rf"^{re.escape(DATABASE_PREFIX)}"
    rf"([0-9a-f]{{{TOKEN_MIN_HEX_CHARS},{TOKEN_MAX_HEX_CHARS}}})"
    rf"_([0-9a-f]{{{TOKEN_MIN_HEX_CHARS},{TOKEN_MAX_HEX_CHARS}}})"
    rf"_([ab])$"
)

TokenSource = Callable[[], str]


class NamingError(ContractError):
    """A name or token violates the frozen D3 naming grammar."""


def default_token_source() -> str:
    """Cryptographically random lowercase hex token (secrets-backed)."""
    return secrets.token_hex(RUN_TOKEN_HEX_CHARS // 2)


def _check_str(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise NamingError(f"{what} must be a str, got {type(value).__name__}")
    return value


def validate_token(token: object, what: str, *, exact_chars: Optional[int] = None) -> str:
    """Validate a lowercase-hex token and return it unchanged.

    ``exact_chars`` pins the length for the generation path; the validator
    used on stored names only enforces TOKEN_MIN_HEX_CHARS..TOKEN_MAX_HEX_CHARS.
    """
    token = _check_str(token, what)
    if not _HEX_RE.match(token):
        raise NamingError(f"{what} must be lowercase hex, got {token!r}")
    if exact_chars is not None:
        if len(token) != exact_chars:
            raise NamingError(
                f"{what} must be exactly {exact_chars} hex chars, got {len(token)}"
            )
        return token
    if not TOKEN_MIN_HEX_CHARS <= len(token) <= TOKEN_MAX_HEX_CHARS:
        raise NamingError(
            f"{what} must be {TOKEN_MIN_HEX_CHARS}..{TOKEN_MAX_HEX_CHARS} hex chars, "
            f"got {len(token)}"
        )
    return token


def new_run_token(token_source: Optional[TokenSource] = None) -> str:
    """Fresh run token; the source is injectable and its output is validated."""
    token = (token_source if token_source is not None else default_token_source)()
    return validate_token(token, "run token", exact_chars=RUN_TOKEN_HEX_CHARS)


def new_attempt_token(token_source: Optional[TokenSource] = None) -> str:
    """Fresh attempt token; the source is injectable and its output is validated."""
    token = (token_source if token_source is not None else default_token_source)()
    return validate_token(token, "attempt token", exact_chars=ATTEMPT_TOKEN_HEX_CHARS)


def attempt_database_names(run_token: object, attempt_token: object) -> Tuple[str, str]:
    """Return the ``(database_a, database_b)`` names for one attempt.

    Raises NamingError on malformed tokens or when the composed name would
    exceed DATABASE_NAME_MAX_CHARS (the length guard is an unconditional
    check, not a C-level assert, so it survives ``python -O``).
    """
    run_token = validate_token(run_token, "run token", exact_chars=RUN_TOKEN_HEX_CHARS)
    attempt_token = validate_token(
        attempt_token, "attempt token", exact_chars=ATTEMPT_TOKEN_HEX_CHARS
    )
    names = (
        f"{DATABASE_PREFIX}{run_token}_{attempt_token}_a",
        f"{DATABASE_PREFIX}{run_token}_{attempt_token}_b",
    )
    for name in names:
        if len(name) > DATABASE_NAME_MAX_CHARS:
            raise NamingError(
                f"database name {name!r} exceeds DATABASE_NAME_MAX_CHARS "
                f"({DATABASE_NAME_MAX_CHARS})"
            )
        validate_database_name(name, run_token=run_token)
    return names


def validate_database_name(name: object, *, run_token: Optional[str] = None) -> str:
    """Validate a tool-generated attempt database name; return it unchanged.

    The grammar is ``tc_<run-hex>_<attempt-hex>_[ab]`` with token lengths in
    TOKEN_MIN_HEX_CHARS..TOKEN_MAX_HEX_CHARS, the D1 identifier grammar, and
    the 48-character cap.  With ``run_token`` the run-token component must
    match it (cleanup binds deletion to the allocating run).
    """
    name = _check_str(name, "database name")
    match = _NAME_RE.match(name)
    if match is None:
        raise NamingError(f"database name {name!r} is not a tc_ attempt database name")
    if len(name) > DATABASE_NAME_MAX_CHARS:
        raise NamingError(
            f"database name {name!r} exceeds DATABASE_NAME_MAX_CHARS ({DATABASE_NAME_MAX_CHARS})"
        )
    if not _IDENT_RE.match(name):
        raise NamingError(f"database name {name!r} violates the D1 identifier grammar")
    if run_token is not None:
        run_token = validate_token(run_token, "run token")
        if match.group(1) != run_token:
            raise NamingError(
                f"database name {name!r} does not carry the expected run token {run_token!r}"
            )
    return name


def is_valid_database_name(name: object) -> bool:
    """Boolean form of :func:`validate_database_name` (no run-token binding)."""
    try:
        validate_database_name(name)
    except NamingError:
        return False
    return True


def marker_table_name() -> str:
    """Fixed D3 ownership marker table name (design 6.2.3)."""
    return "tc_ownership_marker"


def validate_marker_table_name(name: object) -> str:
    """Accept only the exact marker table name; anything else is refused."""
    name = _check_str(name, "marker table name")
    if name != marker_table_name():
        raise NamingError(f"marker table name must be {marker_table_name()!r}, got {name!r}")
    if not _IDENT_RE.match(name):
        raise NamingError(f"marker table name {name!r} violates the D1 identifier grammar")
    return name
