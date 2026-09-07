"""Database adapter package (D3 design 6.3.2, Phase 2).

Importing this package performs no I/O, never opens a connection, and never
imports a database driver: ``base`` is driver-free and the PyMySQL-specific
shim lives in ``mysql_protocol``, which is imported only by the online runner
path (D3 design 6.4.4 [R8]).  Offline packages (``generation``, ``contracts``,
``oracle``, ``reduction``) must not import anything from this package.
"""

from .base import (
    AdapterError,
    ConnectionParams,
    FieldMetadata,
    ProtocolAdapter,
    ProtocolBudgetError,
    RESULT_CONTRACT_VIOLATION,
    RESULT_ENCODING_UNSUPPORTED,
    ResultContractViolation,
    ResultEncodingError,
)

__all__ = [
    "RESULT_CONTRACT_VIOLATION",
    "RESULT_ENCODING_UNSUPPORTED",
    "AdapterError",
    "ConnectionParams",
    "FieldMetadata",
    "ProtocolAdapter",
    "ProtocolBudgetError",
    "ResultContractViolation",
    "ResultEncodingError",
]
