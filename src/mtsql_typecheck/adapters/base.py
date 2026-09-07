"""Typed error types and the narrow adapter surface (D3 design 6.3.2).

This module is driver-free: importing it must not import PyMySQL or any other
database library, and must perform no I/O.  It defines

- the stable error-code constants and typed :class:`AdapterError` hierarchy,
- the frozen :class:`ConnectionParams` / :class:`FieldMetadata` data
  contracts, and
- the :class:`ProtocolAdapter` structural interface (design 6.3.2) that later
  D3 phases build on.

No business logic lives here; concrete behaviour is in the driver-specific
shim modules (``mysql_protocol``, later ``mysql80``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Protocol, runtime_checkable

from ..contracts.case import ContractError

__all__ = [
    "RESULT_ENCODING_UNSUPPORTED",
    "RESULT_CONTRACT_VIOLATION",
    "PROTOCOL_BUDGET_EXCEEDED",
    "AdapterError",
    "ResultEncodingError",
    "ResultContractViolation",
    "ProtocolBudgetError",
    "ConnectionParams",
    "FieldMetadata",
    "ProtocolAdapter",
]

# --------------------------------------------------------------------------
# Stable error codes (design 6.4.3; these strings are contract, not text)
# --------------------------------------------------------------------------

#: A column's wire type cannot be represented losslessly by the frozen
#: mapping (FLOAT/DOUBLE/string/unknown types); never silently coerced.
RESULT_ENCODING_UNSUPPORTED = "RESULT_ENCODING_UNSUPPORTED"

#: The server/driver produced a structure that violates the frozen protocol
#: contract (e.g. metadata disagreement, unexpected packet layout).
RESULT_CONTRACT_VIOLATION = "RESULT_CONTRACT_VIOLATION"

#: Packet/row/byte budget violation; the connection must be marked unusable.
PROTOCOL_BUDGET_EXCEEDED = "PROTOCOL_BUDGET_EXCEEDED"


class AdapterError(ContractError):
    """Base class for adapter refusals; carries a stable ``code`` string."""

    def __init__(self, message: str, *, code: str = RESULT_CONTRACT_VIOLATION) -> None:
        super().__init__(message)
        self.code = code


class ResultEncodingError(AdapterError):
    """A result value cannot be decoded losslessly under the frozen mapping.

    Raised (never silently coerced) for FLOAT/DOUBLE/string/JSON/date-time/
    unknown wire types.  Carries the raw protocol metadata so evidence can
    reference the original column without guessing a family.
    """

    def __init__(
        self,
        message: str,
        *,
        type_code: int,
        flags: int,
        column_ordinal: int,
        mapping_version: str,
    ) -> None:
        super().__init__(message, code=RESULT_ENCODING_UNSUPPORTED)
        self.type_code = type_code
        self.flags = flags
        self.column_ordinal = column_ordinal
        self.mapping_version = mapping_version


class ResultContractViolation(AdapterError):
    """A packet/metadata structure contradicts the frozen protocol contract."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code=RESULT_CONTRACT_VIOLATION)


class ProtocolBudgetError(AdapterError):
    """A packet/row/byte budget was exceeded; fail closed.

    The connection must be marked unusable afterwards: the shim never drains
    remaining results and never pretends a partial result is complete.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code=PROTOCOL_BUDGET_EXCEEDED)


# --------------------------------------------------------------------------
# Frozen parameter and metadata data contracts
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectionParams:
    """Connection endpoint parameters (design 6.3.1/6.3.2).

    TCP (``host``+``port``) and ``unix_socket`` are strictly mutually
    exclusive.  Passwords are supplied in memory by the caller (runner config
    resolves the environment variable); they are never serialized.

    ``server_public_key`` must stay ``False``: caching_sha2_password full
    authentication over an unverified channel (fetching the server RSA public
    key) is refused in Phase 2 scope with a clear error, not downgraded.
    """

    host: Optional[str] = None
    port: Optional[int] = None
    unix_socket: Optional[str] = None
    user: str = ""
    password: str = ""
    connect_timeout_s: int = 10
    read_timeout_s: int = 10
    write_timeout_s: int = 10
    tls_ca_file: Optional[str] = None
    tls_verify_identity: bool = False
    server_public_key: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.user, str) or not self.user:
            raise AdapterError("ConnectionParams.user must be a non-empty string")
        if not isinstance(self.password, str):
            raise AdapterError("ConnectionParams.password must be a string")
        has_tcp = self.host is not None
        has_socket = self.unix_socket is not None
        if has_tcp == has_socket:
            raise AdapterError(
                "ConnectionParams requires exactly one of host/port or unix_socket"
            )
        if has_tcp:
            if not isinstance(self.host, str) or not self.host:
                raise AdapterError("ConnectionParams.host must be a non-empty string")
            if isinstance(self.port, bool) or not isinstance(self.port, int):
                raise AdapterError("ConnectionParams.port must be an int")
            if not 1 <= self.port <= 65535:
                raise AdapterError(
                    f"ConnectionParams.port must be in [1, 65535], got {self.port}"
                )
        for name in ("connect_timeout_s", "read_timeout_s", "write_timeout_s"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise AdapterError(f"ConnectionParams.{name} must be an int")
            if not 1 <= value <= 600:
                raise AdapterError(
                    f"ConnectionParams.{name} must be in [1, 600], got {value}"
                )
        if self.tls_ca_file is not None and (
            not isinstance(self.tls_ca_file, str) or not self.tls_ca_file
        ):
            raise AdapterError("ConnectionParams.tls_ca_file must be a non-empty string or None")
        if not isinstance(self.tls_verify_identity, bool):
            raise AdapterError("ConnectionParams.tls_verify_identity must be a bool")
        if self.server_public_key is not False:
            raise AdapterError(
                "ConnectionParams.server_public_key must stay False: caching_sha2_password "
                "full auth over an unverified channel is refused in Phase 2 scope"
            )


@dataclass(frozen=True)
class FieldMetadata:
    """Raw protocol field metadata extracted by the driver shim.

    This is the metadata the shim extracts from PyMySQL's internal field
    packet structure (design 6.4.3) -- never the DB-API 7-field description
    alone, and no zero-filling of fields the driver does not provide.
    """

    ordinal: int
    type_code: int
    flags: int
    decimals: int
    length: int
    charset: int
    alias: str
    table_alias: str


# --------------------------------------------------------------------------
# Adapter surface (design 6.3.2); structural protocol, no logic here
# --------------------------------------------------------------------------


@runtime_checkable
class ProtocolAdapter(Protocol):
    """Narrow adapter operations (design 6.3.2 connect/probe .. cleanup).

    Signatures are intentionally minimal and typed loosely with ``object``;
    later D3 phases replace the object handles with concrete receipt types.
    Everything that would issue session/SET/probe SQL belongs to later phases.
    """

    def connect_and_probe(self) -> Mapping[str, object]: ...

    def apply_session(self, session_settings: Mapping[str, str]) -> Mapping[str, str]: ...

    def execute_statement(self, sql: str) -> object: ...

    def open_query(self, sql: str) -> object: ...

    def fetch_result(
        self, handle: object, *, row_budget: int, byte_budget: int
    ) -> object: ...

    def inspect_schema(self, database: str) -> object: ...

    def cancel_current(self) -> object: ...

    def close(self) -> None: ...
