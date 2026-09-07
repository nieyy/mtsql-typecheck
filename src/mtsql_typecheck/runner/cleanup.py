"""Attempt cleanup against a narrow executor protocol (design 6.2.3/6.4.5).

The ``CleanupExecutor`` protocol is defined locally and deliberately narrow
(``execute_ddl`` + ``is_database_present``) so Phase 4/5 can bind the real
adapter without touching this module.  Nothing here imports the adapters
package or a driver.

Deletion rules (negative matrix S02/S03):

- The only deletable objects are the two attempt databases from
  ``runner.naming.attempt_database_names`` and, inside a still-present
  database, the short test table and the marker table.  Every name passes
  the ``tc_`` naming validator before a DDL string is built; there is no
  prefix scan, no wildcard, no DROP DATABASE with a prefix.
- A database that is already absent is a successful no-op (idempotent
  re-clean) and is recorded as CLEANUP_CONFIRMED.
- A database that is present but does not match the expected object set
  (e.g. the test table or marker is missing) fails the drop loudly and is
  reported: partial state inside a live database is ownership-uncertain,
  not silently claimed.
- Drops are confirmed by re-querying absence via ``is_database_present``.

Cleanup failures never raise past the caller: ``AttemptCleaner.clean``
returns a structured ``CleanupOutcome``; each failure also appends a
CLEANUP_FAILED ownership event.  A journal write failure is the one
exception that propagates: an unrecorded cleanup must not look successful
(design 6.2.3).

``ensure_marker`` runs the ownership marker DDL (constants live in
``runner.ownership``) through the executor.  Live-server verification of
marker creation/insert is NOT_RUN in Phase 3 (no MySQL in the unit suite).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, Tuple

from ..contracts.case import ContractError
from ..contracts.runner import OwnershipEventKind
from .naming import (
    TABLE_A,
    TABLE_B,
    NamingError,
    attempt_database_names,
    marker_table_name,
    validate_database_name,
    validate_marker_table_name,
    validate_token,
)
from .ownership import MARKER_TABLE_DDL, OwnershipJournal

__all__ = [
    "CleanupExecutor",
    "CleanupAction",
    "CleanupFailure",
    "CleanupOutcome",
    "CleanupRefusedError",
    "database_create_sql",
    "database_drop_sql",
    "table_drop_sql",
    "ensure_marker",
    "AttemptCleaner",
]


class CleanupExecutor(Protocol):
    """Narrow execution boundary; bound the real adapter in Phase 4/5."""

    def execute_ddl(self, sql: str) -> None: ...

    def is_database_present(self, name: str) -> bool: ...


class CleanupAction(Enum):
    DROP_TABLE = "DROP_TABLE"
    DROP_DATABASE = "DROP_DATABASE"
    VERIFY_ABSENT = "VERIFY_ABSENT"


@dataclass(frozen=True)
class CleanupFailure:
    object_name: str
    action: CleanupAction
    detail: str


@dataclass(frozen=True)
class CleanupOutcome:
    completed: bool
    failures: Tuple[CleanupFailure, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.failures, tuple):
            raise ContractError("CleanupOutcome.failures must be a tuple")
        for failure in self.failures:
            if not isinstance(failure, CleanupFailure):
                raise ContractError("CleanupOutcome.failures must hold CleanupFailure items")
        if self.completed != (not self.failures):
            raise ContractError("CleanupOutcome.completed must be exactly (not failures)")


class CleanupRefusedError(ContractError):
    """A requested cleanup names an object the naming validator does not own."""


_IDENTIFIER_LITERAL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _check_literal(value: object, what: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_LITERAL_RE.match(value):
        raise CleanupRefusedError(
            f"{what} must match [A-Za-z0-9._:-]{{1,128}}, got {value!r}"
        )
    return value


def _refuse(exc: NamingError) -> CleanupRefusedError:
    return CleanupRefusedError(f"object name refused: {exc}")


def database_create_sql(name: str) -> str:
    """CREATE DATABASE without IF NOT EXISTS; existing objects are conflicts."""
    try:
        validate_database_name(name)
    except NamingError as exc:
        raise _refuse(exc) from exc
    return f"CREATE DATABASE `{name}`"


def database_drop_sql(name: str) -> str:
    """DROP DATABASE for one validated attempt database name."""
    try:
        validate_database_name(name)
    except NamingError as exc:
        raise _refuse(exc) from exc
    return f"DROP DATABASE `{name}`"


def table_drop_sql(database: str, table: str) -> str:
    """DROP TABLE for one validated (database, table) pair."""
    try:
        validate_database_name(database)
        if table not in (TABLE_A, TABLE_B):
            validate_marker_table_name(table)
    except NamingError as exc:
        raise _refuse(exc) from exc
    return f"DROP TABLE `{database}`.`{table}`"


def ensure_marker(
    executor: CleanupExecutor, *, run_id: str, attempt_id: str, token: str
) -> None:
    """Create the D3 ownership marker table and stamp run/attempt/token.

    Called only on a freshly created attempt database (the CREATE has no
    IF NOT EXISTS on purpose: an existing marker is a hard conflict).
    """
    _check_literal(run_id, "run_id")
    _check_literal(attempt_id, "attempt_id")
    try:
        validate_token(token, "marker token")
    except NamingError as exc:
        raise _refuse(exc) from exc
    executor.execute_ddl(MARKER_TABLE_DDL)
    executor.execute_ddl(
        f"INSERT INTO `tc_ownership_marker` (run_id, attempt_id, token) "
        f"VALUES ('{run_id}', '{attempt_id}', '{token}')"
    )


class AttemptCleaner:
    """Drop one finished attempt's objects and journal every action."""

    def __init__(self, executor: CleanupExecutor, journal: OwnershipJournal) -> None:
        self._executor = executor
        self._journal = journal

    def clean(
        self,
        *,
        run_id: str,
        attempt_id: str,
        run_token: str,
        attempt_token: str,
    ) -> CleanupOutcome:
        """Clean both sides of one attempt; never raises for DDL failures.

        ``run_id``/``attempt_id`` label the journal events; the object set
        is derived only from the validated tokens.  A malformed token or an
        invalid composed name refuses before any DDL is executed.
        """
        run_id = _check_literal(run_id, "run_id")
        attempt_id = _check_literal(attempt_id, "attempt_id")
        try:
            validate_token(run_token, "run token")
            validate_token(attempt_token, "attempt token")
        except NamingError as exc:
            raise CleanupRefusedError(f"attempt tokens refused: {exc}") from exc
        try:
            database_a, database_b = attempt_database_names(run_token, attempt_token)
        except NamingError as exc:
            raise CleanupRefusedError(f"attempt names refused: {exc}") from exc

        failures: list[CleanupFailure] = []
        for database, test_table in ((database_a, TABLE_A), (database_b, TABLE_B)):
            failure = self._clean_side(
                database, test_table, run_id=run_id, attempt_id=attempt_id, token=run_token
            )
            if failure is not None:
                failures.append(failure)
        return CleanupOutcome(completed=not failures, failures=tuple(failures))

    def _clean_side(
        self,
        database: str,
        test_table: str,
        *,
        run_id: str,
        attempt_id: str,
        token: str,
    ) -> CleanupFailure | None:
        del run_id, token  # reserved for event labels once contracts carry a detail field
        action = CleanupAction.VERIFY_ABSENT
        try:
            if not self._executor.is_database_present(database):
                # Idempotent re-clean: already absent is success.
                self._journal.append(
                    OwnershipEventKind.CLEANUP_CONFIRMED,
                    attempt_id=attempt_id,
                    object_name=database,
                )
                return None
            for table in (test_table, marker_table_name()):
                action = CleanupAction.DROP_TABLE
                sql = table_drop_sql(database, table)
                self._executor.execute_ddl(sql)
                self._journal.append(
                    OwnershipEventKind.OBJECT_DROPPED,
                    attempt_id=attempt_id,
                    object_name=f"{database}.{table}",
                )
            action = CleanupAction.DROP_DATABASE
            self._executor.execute_ddl(database_drop_sql(database))
            if self._executor.is_database_present(database):
                raise ContractError(
                    f"database {database!r} still present after DROP DATABASE"
                )
            self._journal.append(
                OwnershipEventKind.OBJECT_DROPPED,
                attempt_id=attempt_id,
                object_name=database,
            )
            return None
        except Exception as exc:  # executor/verification failures become structured failures
            self._journal.append(
                OwnershipEventKind.CLEANUP_FAILED,
                attempt_id=attempt_id,
                object_name=database,
            )
            return CleanupFailure(
                object_name=database,
                action=action,
                detail=f"{type(exc).__name__}: {exc}",
            )
