"""Immutable contract models for the D2 oracle (oracle-d2-contract section 3).

Covers comparison results, input failures, replay/reduction results, the
in-memory candidate bundle, policy budgets and the append-only trace record
shape.  House rules are identical to D1 (`contracts/case.py`): frozen
dataclasses, closed enums, tuples in memory, strict ``__post_init__``
validation on both the construction and the loader path, unknown fields
rejected, ``bool`` never accepted as ``int``, no floats, canonical bytes via
``codec.canonical_json`` / ``codec.sha256_hex``.  Importing this module
performs no I/O and never imports a database driver.

The execution-side types (``AttemptRequest`` / ``AttemptExpectation``,
``ExecutionEvidence``) live in ``contracts/execution.py`` and are referenced
here only through string annotations plus a deferred import inside
``CandidateInput.__post_init__``; this module must stay importable while that
module is being implemented in parallel.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Any, Optional, Protocol

from .case import (
    MAX_NUMERIC_TEXT_CHARS,
    CasePayload,
    ContractError,
)
from .codec import canonical_json, parse_strict_json, sha256_hex

__all__ = [
    "ORACLE_VERSION",
    "COMPARISON_SCHEMA_VERSION",
    "REPLAY_SCHEMA_VERSION",
    "REDUCTION_SCHEMA_VERSION",
    "TRACE_SCHEMA_VERSION",
    "MAX_RESULT_ROWS",
    "MAX_RESULT_BYTES",
    "MAX_RESULT_COLUMNS",
    "MAX_EVIDENCE_BYTES",
    "MAX_TRACE_META_BYTES",
    "COMPARISON_DEADLINE_MS",
    "REPLAY_ATTEMPTS",
    "REPLAY_TOTAL_BUDGET_MS",
    "REDUCTION_MAX_PROPOSALS",
    "REDUCTION_MAX_EXECUTIONS",
    "REDUCTION_TOTAL_BUDGET_MS",
    "REDUCTION_HARD_MAX_PROPOSALS",
    "REDUCTION_HARD_MAX_EXECUTIONS",
    "REDUCTION_HARD_TOTAL_BUDGET_MS",
    "ATTEMPT_BUDGET_MS",
    "CANCEL_GRACE_MS",
    "EVIDENCE_APPEND_BUDGET",
    "EVIDENCE_APPEND_HARD_CAP",
    "EVIDENCE_RESERVE_BYTES",
    "WITNESS_LIMIT",
    "MAX_SCALAR_TEXT_CHARS",
    "MAX_RESULT_SCALE",
    "TRACE_RECORD_KINDS",
    "ComparisonStatus",
    "ReplayOutcome",
    "ReductionOutcome",
    "ComparisonReason",
    "StopReason",
    "WitnessEntry",
    "ComparisonCounts",
    "Comparison",
    "InputFailure",
    "ReplayResult",
    "ReductionResult",
    "CandidateInput",
    "ComparisonBudget",
    "ReplayPolicy",
    "ReductionPolicy",
    "ArtifactRef",
    "PersistedReceipt",
    "TraceSink",
    "TraceRecord",
    "decode_artifact_ref",
    "decode_comparison",
    "decode_input_failure",
    "decode_replay_result",
    "decode_reduction_result",
    "decode_trace_record",
    "load_comparison",
    "dump_comparison",
    "load_input_failure",
    "dump_input_failure",
    "load_replay_result",
    "dump_replay_result",
    "load_reduction_result",
    "dump_reduction_result",
    "load_trace_record",
    "dump_trace_record",
]

# --------------------------------------------------------------------------
# Frozen versions and constants (oracle-d2-contract section 1)
#
# The budget constants below are the oracle-side copy of the design 6.4.5
# limits.  They MUST stay identical to the constants in
# ``contracts/execution.py``; tests/contract/test_oracle_codec.py
# cross-asserts both modules when that module is present.
# --------------------------------------------------------------------------

ORACLE_VERSION = "o1"
COMPARISON_SCHEMA_VERSION = 1
REPLAY_SCHEMA_VERSION = 1
REDUCTION_SCHEMA_VERSION = 1
TRACE_SCHEMA_VERSION = 1

MAX_RESULT_ROWS = 4096                # per side
MAX_RESULT_BYTES = 8 * 1024 * 1024    # per side, canonical UTF-8 ResultSet incl. metadata
MAX_RESULT_COLUMNS = 5
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024  # single ExecutionEvidence envelope
MAX_TRACE_META_BYTES = 64 * 1024       # single trace record inline payload
COMPARISON_DEADLINE_MS = 5000
REPLAY_ATTEMPTS = 3                    # fixed, not configurable
REPLAY_TOTAL_BUDGET_MS = 120_000
REDUCTION_MAX_PROPOSALS = 200          # hard cap 2000
REDUCTION_MAX_EXECUTIONS = 120         # hard cap 1200
REDUCTION_TOTAL_BUDGET_MS = 600_000    # hard cap 3_600_000
REDUCTION_HARD_MAX_PROPOSALS = 2000
REDUCTION_HARD_MAX_EXECUTIONS = 1200
REDUCTION_HARD_TOTAL_BUDGET_MS = 3_600_000
ATTEMPT_BUDGET_MS = 30_000
CANCEL_GRACE_MS = 5000
EVIDENCE_APPEND_BUDGET = 256 * 1024 * 1024
EVIDENCE_APPEND_HARD_CAP = 1024 * 1024 * 1024
EVIDENCE_RESERVE_BYTES = 64 * 1024
WITNESS_LIMIT = 20                     # display cap only
MAX_SCALAR_TEXT_CHARS = 80             # == case.MAX_NUMERIC_TEXT_CHARS
MAX_RESULT_SCALE = 65

TRACE_RECORD_KINDS = frozenset(
    {
        "SNAPSHOT",
        "START",
        "REQUESTED",
        "EXPECTATION",
        "EVIDENCE",
        "RESULT",
        "COMPARISON",
        "REPLAY",
        "ACCEPTED",
        "FINISHED",
    }
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_DECIMAL_TEXT_RE = re.compile(r"^(0|-?[1-9][0-9]{0,79})$")
_TRACE_ROOT = "0" * 64


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


def _check_enum(value: object, enum_cls: type, name: str):
    if not isinstance(value, enum_cls):
        _fail(f"{name} must be {enum_cls.__name__}, got {value!r}")
    return value


def _check_nonempty(value: str, name: str, max_chars: int) -> str:
    if not value:
        _fail(f"{name} must be non-empty")
    if len(value) > max_chars:
        _fail(f"{name} must be at most {max_chars} chars, got {len(value)}")
    return value


def _content_hash(core: dict[str, object]) -> str:
    """SHA-256 over the canonical form of a record content minus its own hash."""
    return sha256_hex(canonical_json(core))


def _settle_hash(target: object, derived: str, attr: str, owner: str) -> None:
    """Accept the default empty marker, store the derived hash, reject mismatch."""
    current = getattr(target, attr)
    if current == "":
        object.__setattr__(target, attr, derived)
    elif current != derived:
        _fail(f"{owner}.{attr} {current!r} does not match the content hash {derived}")


# --------------------------------------------------------------------------
# Enumerations (oracle-d2-contract sections 3, 3.1, 3.2)
# --------------------------------------------------------------------------


class ComparisonStatus(enum.StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    MATCH = "MATCH"
    MISMATCH_CANDIDATE = "MISMATCH_CANDIDATE"


class ReplayOutcome(enum.StrEnum):
    REPRODUCED = "REPRODUCED"
    UNSTABLE = "UNSTABLE"
    NOT_REPLAYED = "NOT_REPLAYED"


class ReductionOutcome(enum.StrEnum):
    REDUCED = "REDUCED"
    UNCHANGED = "UNCHANGED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    FAILED = "FAILED"


class ComparisonReason(enum.StrEnum):
    """Fixed comparison reason codes; extend only with a design revision."""

    INPUT_INVALID = "INPUT_INVALID"
    VERSION_UNSUPPORTED = "VERSION_UNSUPPORTED"
    RULE_DISABLED = "RULE_DISABLED"
    UNSUPPORTED_ENVIRONMENT = "UNSUPPORTED_ENVIRONMENT"
    BINDING_MISMATCH = "BINDING_MISMATCH"
    RUNTIME_NOT_READY = "RUNTIME_NOT_READY"
    SETUP_DIAGNOSTICS = "SETUP_DIAGNOSTICS"
    LOAD_ANOMALY = "LOAD_ANOMALY"
    QUERY_NOT_COMPLETE = "QUERY_NOT_COMPLETE"
    QUERY_DIAGNOSTICS = "QUERY_DIAGNOSTICS"
    ENVIRONMENT_DRIFT = "ENVIRONMENT_DRIFT"
    DATABASE_BINDING_MISMATCH = "DATABASE_BINDING_MISMATCH"
    ISOLATION_UNCONFIRMED = "ISOLATION_UNCONFIRMED"
    RESULT_INCOMPLETE = "RESULT_INCOMPLETE"
    RESULT_CONTRACT_VIOLATION = "RESULT_CONTRACT_VIOLATION"
    RESULT_BUDGET_EXCEEDED = "RESULT_BUDGET_EXCEEDED"
    COMPARISON_DEADLINE = "COMPARISON_DEADLINE"
    CANCELLED = "CANCELLED"
    TERMINATION_UNCONFIRMED = "TERMINATION_UNCONFIRMED"


class StopReason(enum.StrEnum):
    """Fixed replay/reduction stop reasons; extend only with a design revision."""

    INVALID_CANDIDATE = "INVALID_CANDIDATE"
    NO_EXECUTOR = "NO_EXECUTOR"
    ORIGINAL_NOT_REPRODUCED = "ORIGINAL_NOT_REPRODUCED"
    SIGNATURE_CHANGED = "SIGNATURE_CHANGED"
    MATCH_OBSERVED = "MATCH_OBSERVED"
    EXECUTION_INCOMPLETE = "EXECUTION_INCOMPLETE"
    EXECUTOR_EXCEPTION = "EXECUTOR_EXCEPTION"
    EXECUTION_PROTOCOL_ERROR = "EXECUTION_PROTOCOL_ERROR"
    ENVIRONMENT_DRIFT = "ENVIRONMENT_DRIFT"
    TERMINATION_UNCONFIRMED = "TERMINATION_UNCONFIRMED"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    EVIDENCE_WRITE_FAILED = "EVIDENCE_WRITE_FAILED"
    TIME_BUDGET = "TIME_BUDGET"
    EXECUTION_BUDGET = "EXECUTION_BUDGET"
    PROPOSAL_BUDGET = "PROPOSAL_BUDGET"
    EVIDENCE_BUDGET = "EVIDENCE_BUDGET"
    CANCELLED = "CANCELLED"
    SEARCH_EXHAUSTED = "SEARCH_EXHAUSTED"
    REPLAY_COMPLETE = "REPLAY_COMPLETE"


# --------------------------------------------------------------------------
# Witness and counts (oracle-d2-contract sections 3.3, 4)
# --------------------------------------------------------------------------


def _check_witness_value_key(value: object, name: str) -> tuple[object, ...]:
    """Validate one value key: ("null",) or ("number", coeff_text, scale)."""
    if not isinstance(value, tuple) or not value:
        _fail(f"{name} must be a non-empty tuple")
    first = value[0]
    if not isinstance(first, str):
        _fail(f"{name}[0] must be a str, got {type(first).__name__}")
    if value == ("null",):
        return value
    if first == "number" and len(value) == 3:
        text = value[1]
        if not isinstance(text, str):
            _fail(f"{name}[1] must be canonical decimal text, got {type(text).__name__}")
        if (
            not _CANONICAL_DECIMAL_TEXT_RE.match(text)
            or len(text) > MAX_NUMERIC_TEXT_CHARS
        ):
            _fail(f"{name}[1] is not canonical decimal text: {text!r}")
        scale = _check_int(value[2], f"{name}[2]")
        if not 0 <= scale <= MAX_RESULT_SCALE:
            _fail(f"{name}[2] scale must be in [0, {MAX_RESULT_SCALE}], got {scale}")
        return value
    _fail(f"{name} must be ('null',) or ('number', coeff_text, scale), got {value!r}")


def _check_witness_key(key: object, name: str) -> tuple[object, ...]:
    """Validate a row-key: a non-empty ordered tuple of value keys.

    Design 6.2.2: the row key is the ordered array of per-column value keys,
    so a WitnessEntry always carries the full row key (a 1-tuple of value
    keys for single-column results, longer for multi-column ones).
    """
    if not isinstance(key, tuple) or not key:
        _fail(f"{name} must be a non-empty tuple of value keys")
    return tuple(
        _check_witness_value_key(value, f"{name}[{index}]")
        for index, value in enumerate(key)
    )


@dataclass(frozen=True)
class WitnessEntry:
    """One differing multiset key with per-side counts; diff is never zero.

    ``key`` is the full row key: the ordered tuple of per-column value keys
    (design 6.2.2), not a single flattened value key.
    """

    key: tuple[object, ...]
    a_count: int
    b_count: int
    diff: int

    def __post_init__(self) -> None:
        _check_witness_key(self.key, "WitnessEntry.key")
        a = _check_int(self.a_count, "WitnessEntry.a_count")
        b = _check_int(self.b_count, "WitnessEntry.b_count")
        if a < 0:
            _fail(f"WitnessEntry.a_count must be >= 0, got {a}")
        if b < 0:
            _fail(f"WitnessEntry.b_count must be >= 0, got {b}")
        diff = _check_int(self.diff, "WitnessEntry.diff")
        if diff != a - b:
            _fail(f"WitnessEntry.diff {diff} must equal a_count - b_count ({a - b})")
        if diff == 0:
            _fail("WitnessEntry.diff must be non-zero")

    def to_obj(self) -> dict[str, object]:
        # Persistent row-key encoding (design 6.2.2): the ordered list of
        # value-key arrays ["null"] / ["number", coeff_text, scale].
        key: list[object] = [
            ["null"] if value == ("null",) else ["number", value[1], value[2]]
            for value in self.key
        ]
        return {
            "key": key,
            "a_count": self.a_count,
            "b_count": self.b_count,
            "diff": self.diff,
        }


@dataclass(frozen=True)
class ComparisonCounts:
    """Observed row statistics; no fake zero-row counts for non-comparable results."""

    a_rows: int
    b_rows: int
    a_distinct: int
    b_distinct: int
    matched_rows: int

    def __post_init__(self) -> None:
        for name in ("a_rows", "b_rows", "a_distinct", "b_distinct", "matched_rows"):
            value = _check_int(getattr(self, name), f"ComparisonCounts.{name}")
            if value < 0:
                _fail(f"ComparisonCounts.{name} must be >= 0, got {value}")

    def to_obj(self) -> dict[str, object]:
        return {
            "a_rows": self.a_rows,
            "b_rows": self.b_rows,
            "a_distinct": self.a_distinct,
            "b_distinct": self.b_distinct,
            "matched_rows": self.matched_rows,
        }


# --------------------------------------------------------------------------
# Comparison result (oracle-d2-contract section 3.3)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Comparison:
    """Final comparison verdict for one case attempt pair; hash covers all
    content fields except ``hash`` itself.

    ``reasons`` are recorded in gate order (then side, then condition id) and
    deduplicated by the caller; the model validates membership and the
    non-comparable/non-empty rule but never reorders or deduplicates.
    """

    case_id: str
    request_hash: str
    expectation_hash: Optional[str]
    execution_hash: str
    runtime_check_hash: Optional[str]
    status: ComparisonStatus
    reasons: tuple[ComparisonReason, ...]
    comparable: bool
    counts: Optional[ComparisonCounts]
    witness: Optional[tuple[WitnessEntry, ...]]
    witness_truncated: bool
    exact_signature: Optional[str]
    fingerprint: Optional[str]
    schema_version: int = COMPARISON_SCHEMA_VERSION
    oracle_version: str = ORACLE_VERSION
    hash: str = ""

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "Comparison.schema_version")
        if self.schema_version != COMPARISON_SCHEMA_VERSION:
            _fail(f"unsupported comparison schema_version {self.schema_version}")
        oracle_version = _check_str(self.oracle_version, "Comparison.oracle_version")
        if oracle_version != ORACLE_VERSION:
            _fail(
                f"unsupported oracle_version {oracle_version!r}, "
                f"expected {ORACLE_VERSION!r}"
            )
        _check_hex64(self.case_id, "Comparison.case_id")
        _check_hex64(self.request_hash, "Comparison.request_hash")
        if self.expectation_hash is not None:
            _check_hex64(self.expectation_hash, "Comparison.expectation_hash")
        _check_hex64(self.execution_hash, "Comparison.execution_hash")
        if self.runtime_check_hash is not None:
            _check_hex64(self.runtime_check_hash, "Comparison.runtime_check_hash")
        _check_enum(self.status, ComparisonStatus, "Comparison.status")
        if not isinstance(self.reasons, tuple):
            _fail("Comparison.reasons must be a tuple")
        for reason in self.reasons:
            _check_enum(reason, ComparisonReason, "Comparison.reasons item")
        _check_bool(self.comparable, "Comparison.comparable")
        if self.counts is not None and not isinstance(self.counts, ComparisonCounts):
            _fail("Comparison.counts must be ComparisonCounts or None")
        if self.witness is not None:
            if not isinstance(self.witness, tuple):
                _fail("Comparison.witness must be a tuple")
            for entry in self.witness:
                if not isinstance(entry, WitnessEntry):
                    _fail("Comparison.witness must hold WitnessEntry items")
            if len(self.witness) > WITNESS_LIMIT:
                _fail(
                    f"Comparison.witness holds {len(self.witness)} entries, "
                    f"over limit {WITNESS_LIMIT}"
                )
        _check_bool(self.witness_truncated, "Comparison.witness_truncated")

        comparable_status = self.status in (
            ComparisonStatus.MATCH,
            ComparisonStatus.MISMATCH_CANDIDATE,
        )
        if self.comparable != comparable_status:
            _fail(
                f"Comparison.comparable must be {comparable_status} for status "
                f"{str(self.status.value)}"
            )
        if not comparable_status:
            for name in ("counts", "witness", "exact_signature", "fingerprint"):
                if getattr(self, name) is not None:
                    _fail(
                        f"Comparison.{name} must be None for status "
                        f"{str(self.status.value)}"
                    )
            if self.witness_truncated:
                _fail(
                    "Comparison.witness_truncated must be False for status "
                    f"{str(self.status.value)}"
                )
            if not self.reasons:
                _fail(
                    f"a non-comparable Comparison ({str(self.status.value)}) "
                    "requires at least one reason"
                )
        elif self.status is ComparisonStatus.MATCH:
            for name in ("exact_signature", "fingerprint", "witness"):
                if getattr(self, name) is not None:
                    _fail(f"Comparison.{name} must be None for a MATCH")
            if self.witness_truncated:
                _fail("Comparison.witness_truncated must be False for a MATCH")
        else:  # MISMATCH_CANDIDATE
            _check_hex64(self.exact_signature, "Comparison.exact_signature")
            _check_hex64(self.fingerprint, "Comparison.fingerprint")

        _settle_hash(
            self,
            _content_hash(self._content_obj()),
            "hash",
            "Comparison",
        )
        _check_hex64(self.hash, "Comparison.hash")

    def _content_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "oracle_version": self.oracle_version,
            "case_id": self.case_id,
            "request_hash": self.request_hash,
            "expectation_hash": self.expectation_hash,
            "execution_hash": self.execution_hash,
            "runtime_check_hash": self.runtime_check_hash,
            "status": str(self.status.value),
            "reasons": [str(reason.value) for reason in self.reasons],
            "comparable": self.comparable,
            "counts": self.counts.to_obj() if self.counts is not None else None,
            "witness": (
                [entry.to_obj() for entry in self.witness]
                if self.witness is not None
                else None
            ),
            "witness_truncated": self.witness_truncated,
            "exact_signature": self.exact_signature,
            "fingerprint": self.fingerprint,
        }

    def to_obj(self) -> dict[str, object]:
        obj = self._content_obj()
        obj["hash"] = self.hash
        return obj


# --------------------------------------------------------------------------
# Input failure (oracle-d2-contract section 3.3)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class InputFailure:
    """Entry-layer mapping of a ContractError onto the comparison status space.

    The status is frozen to INCONCLUSIVE: a failed input can never become a
    successful match or a mismatch candidate.  ``trusted_case_id`` is carried
    only when the id could be independently re-derived from intact input.
    """

    code: str
    input_ref: str
    detail: str
    trusted_case_id: Optional[str] = None
    schema_version: int = COMPARISON_SCHEMA_VERSION
    status: ComparisonStatus = ComparisonStatus.INCONCLUSIVE

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "InputFailure.schema_version")
        if self.schema_version != COMPARISON_SCHEMA_VERSION:
            _fail(f"unsupported input failure schema_version {self.schema_version}")
        _check_enum(self.status, ComparisonStatus, "InputFailure.status")
        if self.status is not ComparisonStatus.INCONCLUSIVE:
            _fail("InputFailure.status is frozen to INCONCLUSIVE")
        _check_nonempty(
            _check_str(self.code, "InputFailure.code"), "InputFailure.code", 128
        )
        _check_nonempty(
            _check_str(self.input_ref, "InputFailure.input_ref"),
            "InputFailure.input_ref",
            512,
        )
        _check_nonempty(
            _check_str(self.detail, "InputFailure.detail"), "InputFailure.detail", 512
        )
        if self.trusted_case_id is not None:
            _check_hex64(self.trusted_case_id, "InputFailure.trusted_case_id")

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "status": str(self.status.value),
            "code": self.code,
            "input_ref": self.input_ref,
            "detail": self.detail,
            "trusted_case_id": self.trusted_case_id,
        }


# --------------------------------------------------------------------------
# Replay result (oracle-d2-contract sections 3.3, 7)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ReplayResult:
    """Outcome of one 3-attempt replay group over a fixed candidate input."""

    comparison_hash: str
    policy_hash: str
    attempt_hashes: tuple[str, ...]
    requested: int
    completed: int
    comparable: int
    matching_signature: int
    exact_signatures: tuple[str, ...]
    outcome: ReplayOutcome
    stop_reason: Optional[StopReason]
    operational_failure: bool
    synthetic: bool
    hash: str = ""

    def __post_init__(self) -> None:
        _check_hex64(self.comparison_hash, "ReplayResult.comparison_hash")
        _check_hex64(self.policy_hash, "ReplayResult.policy_hash")
        if not isinstance(self.attempt_hashes, tuple):
            _fail("ReplayResult.attempt_hashes must be a tuple")
        for attempt_hash in self.attempt_hashes:
            _check_hex64(attempt_hash, "ReplayResult.attempt_hashes item")
        for name in ("requested", "completed", "comparable", "matching_signature"):
            value = _check_int(getattr(self, name), f"ReplayResult.{name}")
            if value < 0:
                _fail(f"ReplayResult.{name} must be >= 0, got {value}")
        if not self.matching_signature <= self.comparable <= self.completed <= self.requested:
            _fail(
                "ReplayResult counts must satisfy matching_signature <= comparable "
                f"<= completed <= requested, got {self.matching_signature} <= "
                f"{self.comparable} <= {self.completed} <= {self.requested}"
            )
        if not isinstance(self.exact_signatures, tuple):
            _fail("ReplayResult.exact_signatures must be a tuple")
        for signature in self.exact_signatures:
            _check_hex64(signature, "ReplayResult.exact_signatures item")
        if len(self.attempt_hashes) != self.requested:
            _fail(
                f"ReplayResult.attempt_hashes length {len(self.attempt_hashes)} "
                f"must equal requested {self.requested}"
            )
        if len(self.exact_signatures) != self.comparable:
            _fail(
                f"ReplayResult.exact_signatures length {len(self.exact_signatures)} "
                f"must equal comparable {self.comparable}"
            )
        _check_enum(self.outcome, ReplayOutcome, "ReplayResult.outcome")
        if self.stop_reason is not None:
            _check_enum(self.stop_reason, StopReason, "ReplayResult.stop_reason")
        _check_bool(self.operational_failure, "ReplayResult.operational_failure")
        _check_bool(self.synthetic, "ReplayResult.synthetic")
        if self.outcome is ReplayOutcome.REPRODUCED:
            if self.matching_signature != REPLAY_ATTEMPTS or self.requested != REPLAY_ATTEMPTS:
                _fail(
                    "a REPRODUCED ReplayResult requires all "
                    f"{REPLAY_ATTEMPTS} attempts comparable with the baseline "
                    f"signature, got requested={self.requested} "
                    f"matching_signature={self.matching_signature}"
                )
            if self.operational_failure:
                _fail("a REPRODUCED ReplayResult cannot carry an operational failure")
        if self.outcome is ReplayOutcome.NOT_REPLAYED and self.requested != 0:
            _fail(
                "a NOT_REPLAYED ReplayResult dispatches nothing, got "
                f"requested={self.requested}"
            )
        _settle_hash(
            self,
            _content_hash(self._content_obj()),
            "hash",
            "ReplayResult",
        )
        _check_hex64(self.hash, "ReplayResult.hash")

    def _content_obj(self) -> dict[str, object]:
        # The frozen field list for ReplayResult (section 3.3) carries no
        # schema_version field; REPLAY_SCHEMA_VERSION stays a module constant.
        return {
            "comparison_hash": self.comparison_hash,
            "policy_hash": self.policy_hash,
            "attempt_hashes": list(self.attempt_hashes),
            "requested": self.requested,
            "completed": self.completed,
            "comparable": self.comparable,
            "matching_signature": self.matching_signature,
            "exact_signatures": list(self.exact_signatures),
            "outcome": str(self.outcome.value),
            "stop_reason": (
                str(self.stop_reason.value) if self.stop_reason is not None else None
            ),
            "operational_failure": self.operational_failure,
            "synthetic": self.synthetic,
        }

    def to_obj(self) -> dict[str, object]:
        obj = self._content_obj()
        obj["hash"] = self.hash
        return obj


# --------------------------------------------------------------------------
# Reduction result (oracle-d2-contract sections 3.3, 9)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ReductionResult:
    """Final reduction verdict; never claims global minimality."""

    reduction_id: str
    outcome: ReductionOutcome
    stop_reason: Optional[StopReason]
    original_case_id: str
    original_comparison_hash: str
    original_fingerprint: Optional[str]
    best_case_id: str
    best_comparison_hashes: tuple[str, ...]
    has_reduction: bool
    search_complete: bool
    proposals: int
    executions: int
    accepted: int
    rejected_static: int
    inconclusive_candidates: int
    unstable_candidates: int
    synthetic: bool
    hash: str = ""

    def __post_init__(self) -> None:
        _check_nonempty(
            _check_str(self.reduction_id, "ReductionResult.reduction_id"),
            "ReductionResult.reduction_id",
            128,
        )
        _check_enum(self.outcome, ReductionOutcome, "ReductionResult.outcome")
        if self.stop_reason is not None:
            _check_enum(self.stop_reason, StopReason, "ReductionResult.stop_reason")
        _check_hex64(self.original_case_id, "ReductionResult.original_case_id")
        _check_hex64(
            self.original_comparison_hash, "ReductionResult.original_comparison_hash"
        )
        if self.original_fingerprint is not None:
            _check_hex64(
                self.original_fingerprint, "ReductionResult.original_fingerprint"
            )
        _check_hex64(self.best_case_id, "ReductionResult.best_case_id")
        if not isinstance(self.best_comparison_hashes, tuple):
            _fail("ReductionResult.best_comparison_hashes must be a tuple")
        for comparison_hash in self.best_comparison_hashes:
            _check_hex64(
                comparison_hash, "ReductionResult.best_comparison_hashes item"
            )
        _check_bool(self.has_reduction, "ReductionResult.has_reduction")
        _check_bool(self.search_complete, "ReductionResult.search_complete")
        for name in (
            "proposals",
            "executions",
            "accepted",
            "rejected_static",
            "inconclusive_candidates",
            "unstable_candidates",
        ):
            value = _check_int(getattr(self, name), f"ReductionResult.{name}")
            if value < 0:
                _fail(f"ReductionResult.{name} must be >= 0, got {value}")
        _check_bool(self.synthetic, "ReductionResult.synthetic")

        if self.has_reduction != (self.best_case_id != self.original_case_id):
            _fail(
                "ReductionResult.has_reduction must be true if and only if "
                "best_case_id differs from original_case_id"
            )
        if self.outcome is ReductionOutcome.REDUCED and not self.has_reduction:
            _fail("a REDUCED outcome requires an accepted child (has_reduction)")
        if self.outcome is ReductionOutcome.UNCHANGED and self.has_reduction:
            _fail("an UNCHANGED outcome cannot carry an accepted child")
        if self.search_complete and self.outcome not in (
            ReductionOutcome.REDUCED,
            ReductionOutcome.UNCHANGED,
        ):
            _fail(
                f"search_complete=True is only legal for REDUCED/UNCHANGED, "
                f"got {str(self.outcome.value)}"
            )
        expected_hashes = 3 if self.has_reduction else 0
        if len(self.best_comparison_hashes) != expected_hashes:
            _fail(
                "ReductionResult.best_comparison_hashes must hold the three child "
                f"comparisons of best when has_reduction, got "
                f"{len(self.best_comparison_hashes)} entries for "
                f"has_reduction={self.has_reduction}"
            )
        _settle_hash(
            self,
            _content_hash(self._content_obj()),
            "hash",
            "ReductionResult",
        )
        _check_hex64(self.hash, "ReductionResult.hash")

    def _content_obj(self) -> dict[str, object]:
        # The frozen field list for ReductionResult (section 3.3) carries no
        # schema_version field; REDUCTION_SCHEMA_VERSION stays a module constant.
        return {
            "reduction_id": self.reduction_id,
            "outcome": str(self.outcome.value),
            "stop_reason": (
                str(self.stop_reason.value) if self.stop_reason is not None else None
            ),
            "original_case_id": self.original_case_id,
            "original_comparison_hash": self.original_comparison_hash,
            "original_fingerprint": self.original_fingerprint,
            "best_case_id": self.best_case_id,
            "best_comparison_hashes": list(self.best_comparison_hashes),
            "has_reduction": self.has_reduction,
            "search_complete": self.search_complete,
            "proposals": self.proposals,
            "executions": self.executions,
            "accepted": self.accepted,
            "rejected_static": self.rejected_static,
            "inconclusive_candidates": self.inconclusive_candidates,
            "unstable_candidates": self.unstable_candidates,
            "synthetic": self.synthetic,
        }

    def to_obj(self) -> dict[str, object]:
        obj = self._content_obj()
        obj["hash"] = self.hash
        return obj


# --------------------------------------------------------------------------
# Candidate input bundle (oracle-d2-contract section 3.3)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CandidateInput:
    """In-memory bundle handed to replay/reduction.

    ``comparison_hash`` is a reference only; replay/reduction re-compare with
    ``compare_case`` and never trust the recorded status.
    """

    payload: CasePayload
    request: "mtsql_typecheck.contracts.execution.AttemptRequest"
    expectation: "mtsql_typecheck.contracts.execution.AttemptExpectation"
    evidence: "mtsql_typecheck.contracts.execution.ExecutionEvidence"
    comparison_hash: str
    source: str

    def __post_init__(self) -> None:
        # Deferred import: contracts/execution.py is implemented in parallel
        # and this module must stay importable without it.
        from .execution import AttemptExpectation, AttemptRequest, ExecutionEvidence

        if not isinstance(self.payload, CasePayload):
            _fail("CandidateInput.payload must be a CasePayload")
        for name, cls in (
            ("request", AttemptRequest),
            ("expectation", AttemptExpectation),
            ("evidence", ExecutionEvidence),
        ):
            if not isinstance(getattr(self, name), cls):
                _fail(f"CandidateInput.{name} must be {cls.__name__}")
        _check_hex64(self.comparison_hash, "CandidateInput.comparison_hash")
        _check_nonempty(
            _check_str(self.source, "CandidateInput.source"),
            "CandidateInput.source",
            128,
        )


# --------------------------------------------------------------------------
# Policy budgets (oracle-d2-contract section 3.4)
#
# Illegal values raise ContractError before any side effect; policies are
# never silently clamped.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ComparisonBudget:
    deadline_ms: int = COMPARISON_DEADLINE_MS
    max_rows: int = MAX_RESULT_ROWS
    max_bytes: int = MAX_RESULT_BYTES
    max_columns: int = MAX_RESULT_COLUMNS
    witness_limit: int = WITNESS_LIMIT

    def __post_init__(self) -> None:
        for name, value, low, high in (
            ("deadline_ms", self.deadline_ms, 1, COMPARISON_DEADLINE_MS),
            ("max_rows", self.max_rows, 1, MAX_RESULT_ROWS),
            ("max_bytes", self.max_bytes, 1, MAX_RESULT_BYTES),
            ("max_columns", self.max_columns, 1, MAX_RESULT_COLUMNS),
            ("witness_limit", self.witness_limit, 1, WITNESS_LIMIT),
        ):
            _check_int(value, f"ComparisonBudget.{name}")
            if not low <= value <= high:
                _fail(f"ComparisonBudget.{name} must be in [{low}, {high}], got {value}")

    def to_obj(self) -> dict[str, object]:
        return {
            "deadline_ms": self.deadline_ms,
            "max_rows": self.max_rows,
            "max_bytes": self.max_bytes,
            "max_columns": self.max_columns,
            "witness_limit": self.witness_limit,
        }


@dataclass(frozen=True)
class ReplayPolicy:
    attempts: int = REPLAY_ATTEMPTS
    total_budget_ms: int = REPLAY_TOTAL_BUDGET_MS
    attempt_budget_ms: int = ATTEMPT_BUDGET_MS
    cancel_grace_ms: int = CANCEL_GRACE_MS

    def __post_init__(self) -> None:
        _check_int(self.attempts, "ReplayPolicy.attempts")
        if self.attempts != REPLAY_ATTEMPTS:
            _fail(
                f"ReplayPolicy.attempts is frozen to {REPLAY_ATTEMPTS}, "
                f"got {self.attempts}"
            )
        _check_int(self.total_budget_ms, "ReplayPolicy.total_budget_ms")
        if not 1 <= self.total_budget_ms <= REPLAY_TOTAL_BUDGET_MS:
            _fail(
                f"ReplayPolicy.total_budget_ms must be in [1, {REPLAY_TOTAL_BUDGET_MS}], "
                f"got {self.total_budget_ms}"
            )
        _check_int(self.attempt_budget_ms, "ReplayPolicy.attempt_budget_ms")
        if not 1 <= self.attempt_budget_ms <= ATTEMPT_BUDGET_MS:
            _fail(
                f"ReplayPolicy.attempt_budget_ms must be in [1, {ATTEMPT_BUDGET_MS}], "
                f"got {self.attempt_budget_ms}"
            )
        _check_int(self.cancel_grace_ms, "ReplayPolicy.cancel_grace_ms")
        if not 0 <= self.cancel_grace_ms <= CANCEL_GRACE_MS:
            _fail(
                f"ReplayPolicy.cancel_grace_ms must be in [0, {CANCEL_GRACE_MS}], "
                f"got {self.cancel_grace_ms}"
            )

    def to_obj(self) -> dict[str, object]:
        return {
            "attempts": self.attempts,
            "total_budget_ms": self.total_budget_ms,
            "attempt_budget_ms": self.attempt_budget_ms,
            "cancel_grace_ms": self.cancel_grace_ms,
        }

    def policy_hash(self) -> str:
        """policy_hash = SHA256(canonical_json(to_obj()))."""
        return sha256_hex(canonical_json(self.to_obj()))


@dataclass(frozen=True)
class ReductionPolicy:
    max_proposals: int = REDUCTION_MAX_PROPOSALS
    max_executions: int = REDUCTION_MAX_EXECUTIONS
    total_budget_ms: int = REDUCTION_TOTAL_BUDGET_MS
    attempt_budget_ms: int = ATTEMPT_BUDGET_MS
    cancel_grace_ms: int = CANCEL_GRACE_MS
    evidence_append_budget: int = EVIDENCE_APPEND_BUDGET

    def __post_init__(self) -> None:
        for name, value, low, high in (
            ("max_proposals", self.max_proposals, 1, REDUCTION_HARD_MAX_PROPOSALS),
            ("max_executions", self.max_executions, 1, REDUCTION_HARD_MAX_EXECUTIONS),
            ("total_budget_ms", self.total_budget_ms, 1, REDUCTION_HARD_TOTAL_BUDGET_MS),
            ("attempt_budget_ms", self.attempt_budget_ms, 1, ATTEMPT_BUDGET_MS),
            ("cancel_grace_ms", self.cancel_grace_ms, 0, CANCEL_GRACE_MS),
            (
                "evidence_append_budget",
                self.evidence_append_budget,
                1,
                EVIDENCE_APPEND_HARD_CAP,
            ),
        ):
            _check_int(value, f"ReductionPolicy.{name}")
            if not low <= value <= high:
                _fail(f"ReductionPolicy.{name} must be in [{low}, {high}], got {value}")

    def to_obj(self) -> dict[str, object]:
        return {
            "max_proposals": self.max_proposals,
            "max_executions": self.max_executions,
            "total_budget_ms": self.total_budget_ms,
            "attempt_budget_ms": self.attempt_budget_ms,
            "cancel_grace_ms": self.cancel_grace_ms,
            "evidence_append_budget": self.evidence_append_budget,
        }

    def policy_hash(self) -> str:
        """policy_hash = SHA256(canonical_json(to_obj()))."""
        return sha256_hex(canonical_json(self.to_obj()))

    def replay_policy(self) -> ReplayPolicy:
        """Per-group replay policy derived from the shared attempt settings."""
        return ReplayPolicy(
            attempts=REPLAY_ATTEMPTS,
            total_budget_ms=REPLAY_TOTAL_BUDGET_MS,
            attempt_budget_ms=self.attempt_budget_ms,
            cancel_grace_ms=self.cancel_grace_ms,
        )


# --------------------------------------------------------------------------
# Trace record shape (oracle-d2-contract sections 3.5, 10)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ArtifactRef:
    """Reference to one published dependency file (atomic, exclusive)."""

    path: str
    size_bytes: int
    sha256: str
    schema_version: int

    def __post_init__(self) -> None:
        path = _check_str(self.path, "ArtifactRef.path")
        if not path:
            _fail("ArtifactRef.path must be non-empty")
        if len(path) > 512:
            _fail(f"ArtifactRef.path must be at most 512 chars, got {len(path)}")
        if "\x00" in path or "\\" in path or path.startswith("/"):
            _fail(f"ArtifactRef.path must be root-relative with POSIX separators: {path!r}")
        for component in path.split("/"):
            if component in ("", ".", ".."):
                _fail(f"ArtifactRef.path has an empty, '.' or '..' component: {path!r}")
        size = _check_int(self.size_bytes, "ArtifactRef.size_bytes")
        if size < 0:
            _fail(f"ArtifactRef.size_bytes must be >= 0, got {size}")
        _check_hex64(self.sha256, "ArtifactRef.sha256")
        version = _check_int(self.schema_version, "ArtifactRef.schema_version")
        if version < 1:
            _fail(f"ArtifactRef.schema_version must be >= 1, got {version}")

    def to_obj(self) -> dict[str, object]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class PersistedReceipt:
    """Receipt returned by TraceSink.append once bytes are flushed and fsynced."""

    seq: int
    kind: str
    record_hash: str

    def __post_init__(self) -> None:
        seq = _check_int(self.seq, "PersistedReceipt.seq")
        if seq < 1:
            _fail(f"PersistedReceipt.seq must be >= 1, got {seq}")
        kind = _check_str(self.kind, "PersistedReceipt.kind")
        if kind not in TRACE_RECORD_KINDS:
            _fail(f"PersistedReceipt.kind has unknown value {kind!r}")
        _check_hex64(self.record_hash, "PersistedReceipt.record_hash")

    def to_obj(self) -> dict[str, object]:
        return {"seq": self.seq, "kind": self.kind, "record_hash": self.record_hash}


class TraceSink(Protocol):
    """Append-only bounded JSONL sink (real implementation: reduction/trace.py)."""

    def reserve(self, size_hint: int) -> None:
        """Pre-flight budget check before dispatching work."""
        ...

    def append(self, record: TraceRecord) -> PersistedReceipt:
        """Persist one record; returns only after flush and fsync."""
        ...


@dataclass(frozen=True)
class TraceRecord:
    """One schema=1 JSONL record of the append-only reduction trace."""

    seq: int
    kind: str
    payload_ref: Optional[ArtifactRef] = None
    inline: Optional[dict] = None
    prev_hash: str = _TRACE_ROOT
    hash: str = ""

    def __post_init__(self) -> None:
        seq = _check_int(self.seq, "TraceRecord.seq")
        if seq < 1:
            _fail(f"TraceRecord.seq must be >= 1, got {seq}")
        kind = _check_str(self.kind, "TraceRecord.kind")
        if kind not in TRACE_RECORD_KINDS:
            _fail(f"TraceRecord.kind has unknown value {kind!r}")
        if self.payload_ref is not None and not isinstance(self.payload_ref, ArtifactRef):
            _fail("TraceRecord.payload_ref must be an ArtifactRef or None")
        if self.inline is not None:
            if not isinstance(self.inline, dict):
                _fail("TraceRecord.inline must be a dict or None")
            size = len(canonical_json(self.inline))
            if size > MAX_TRACE_META_BYTES:
                _fail(
                    f"TraceRecord.inline canonical size {size} exceeds "
                    f"{MAX_TRACE_META_BYTES} bytes"
                )
        prev_hash = _check_hex64(self.prev_hash, "TraceRecord.prev_hash")
        if seq == 1 and prev_hash != _TRACE_ROOT:
            _fail("TraceRecord.prev_hash must be 64 zeros for seq 1")
        _settle_hash(
            self,
            _content_hash(self._content_obj()),
            "hash",
            "TraceRecord",
        )
        _check_hex64(self.hash, "TraceRecord.hash")

    def _content_obj(self) -> dict[str, object]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "payload_ref": (
                self.payload_ref.to_obj() if self.payload_ref is not None else None
            ),
            "inline": self.inline,
            "prev_hash": self.prev_hash,
        }

    def to_obj(self) -> dict[str, object]:
        obj = self._content_obj()
        obj["hash"] = self.hash
        return obj


# --------------------------------------------------------------------------
# Decoding helpers - strict, no defaults, no unknown fields
# --------------------------------------------------------------------------


def _expect_dict(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{what} must be a JSON object")
    return value


def _field(obj: dict[str, Any], key: str, what: str) -> Any:
    if key not in obj:
        _fail(f"{what} is missing required field {key!r}")
    return obj[key]


def _no_extra(obj: dict[str, Any], allowed: set[str], what: str) -> None:
    extra = set(obj) - allowed
    if extra:
        _fail(f"{what} has unknown fields: {sorted(extra)}")


def _as_int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{what} must be a JSON integer")
    return value


def _as_str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        _fail(f"{what} must be a JSON string")
    return value


def _as_bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{what} must be a JSON boolean")
    return value


def _as_enum(enum_cls: type, value: Any, what: str) -> Any:
    if not isinstance(value, str):
        _fail(f"{what} must be a JSON string")
    try:
        return enum_cls(value)
    except ValueError:
        _fail(f"{what} has unknown value {value!r}")


def _as_opt_str(value: Any, what: str) -> Optional[str]:
    if value is None:
        return None
    return _as_str(value, what)


def _as_opt_enum(enum_cls: type, value: Any, what: str) -> Any:
    if value is None:
        return None
    return _as_enum(enum_cls, value, what)


def decode_witness_entry(obj: Any, what: str = "witness entry") -> WitnessEntry:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"key", "a_count", "b_count", "diff"}, what)
    key_items = _field(obj, "key", what)
    if not isinstance(key_items, list) or not key_items:
        _fail(f"{what}.key must be a non-empty JSON array of value keys")
    if any(not isinstance(item, list) for item in key_items):
        _fail(f"{what}.key must be an array of value-key arrays")
    return WitnessEntry(
        key=tuple(tuple(item) for item in key_items),
        a_count=_as_int(_field(obj, "a_count", what), f"{what}.a_count"),
        b_count=_as_int(_field(obj, "b_count", what), f"{what}.b_count"),
        diff=_as_int(_field(obj, "diff", what), f"{what}.diff"),
    )


def decode_comparison_counts(
    obj: Any, what: str = "comparison counts"
) -> ComparisonCounts:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {"a_rows", "b_rows", "a_distinct", "b_distinct", "matched_rows"},
        what,
    )
    return ComparisonCounts(
        a_rows=_as_int(_field(obj, "a_rows", what), f"{what}.a_rows"),
        b_rows=_as_int(_field(obj, "b_rows", what), f"{what}.b_rows"),
        a_distinct=_as_int(_field(obj, "a_distinct", what), f"{what}.a_distinct"),
        b_distinct=_as_int(_field(obj, "b_distinct", what), f"{what}.b_distinct"),
        matched_rows=_as_int(_field(obj, "matched_rows", what), f"{what}.matched_rows"),
    )


def decode_comparison(obj: Any, what: str = "comparison") -> Comparison:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "schema_version",
            "oracle_version",
            "case_id",
            "request_hash",
            "expectation_hash",
            "execution_hash",
            "runtime_check_hash",
            "status",
            "reasons",
            "comparable",
            "counts",
            "witness",
            "witness_truncated",
            "exact_signature",
            "fingerprint",
            "hash",
        },
        what,
    )
    schema_version = _as_int(
        _field(obj, "schema_version", what), f"{what}.schema_version"
    )
    if schema_version != COMPARISON_SCHEMA_VERSION:
        _fail(f"{what} has unsupported schema_version {schema_version}")
    oracle_version = _as_str(_field(obj, "oracle_version", what), f"{what}.oracle_version")
    if oracle_version != ORACLE_VERSION:
        _fail(f"{what} has unsupported oracle_version {oracle_version!r}")
    reasons_items = _field(obj, "reasons", what)
    if not isinstance(reasons_items, list):
        _fail(f"{what}.reasons must be a JSON array")
    witness_items = obj.get("witness")
    witness = None
    if witness_items is not None:
        if not isinstance(witness_items, list):
            _fail(f"{what}.witness must be a JSON array or null")
        witness = tuple(
            decode_witness_entry(item, f"{what}.witness[{index}]")
            for index, item in enumerate(witness_items)
        )
    counts_obj = obj.get("counts")
    counts = (
        None
        if counts_obj is None
        else decode_comparison_counts(counts_obj, f"{what}.counts")
    )
    return Comparison(
        case_id=_as_str(_field(obj, "case_id", what), f"{what}.case_id"),
        request_hash=_as_str(_field(obj, "request_hash", what), f"{what}.request_hash"),
        expectation_hash=_as_opt_str(
            obj.get("expectation_hash"), f"{what}.expectation_hash"
        ),
        execution_hash=_as_str(
            _field(obj, "execution_hash", what), f"{what}.execution_hash"
        ),
        runtime_check_hash=_as_opt_str(
            obj.get("runtime_check_hash"), f"{what}.runtime_check_hash"
        ),
        status=_as_enum(ComparisonStatus, _field(obj, "status", what), f"{what}.status"),
        reasons=tuple(
            _as_enum(ComparisonReason, item, f"{what}.reasons[{index}]")
            for index, item in enumerate(reasons_items)
        ),
        comparable=_as_bool(_field(obj, "comparable", what), f"{what}.comparable"),
        counts=counts,
        witness=witness,
        witness_truncated=_as_bool(
            _field(obj, "witness_truncated", what), f"{what}.witness_truncated"
        ),
        exact_signature=_as_opt_str(
            obj.get("exact_signature"), f"{what}.exact_signature"
        ),
        fingerprint=_as_opt_str(obj.get("fingerprint"), f"{what}.fingerprint"),
        schema_version=schema_version,
        oracle_version=oracle_version,
        hash=_as_str(_field(obj, "hash", what), f"{what}.hash"),
    )


def decode_input_failure(obj: Any, what: str = "input failure") -> InputFailure:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {"schema_version", "status", "code", "input_ref", "detail", "trusted_case_id"},
        what,
    )
    schema_version = _as_int(
        _field(obj, "schema_version", what), f"{what}.schema_version"
    )
    if schema_version != COMPARISON_SCHEMA_VERSION:
        _fail(f"{what} has unsupported schema_version {schema_version}")
    return InputFailure(
        code=_as_str(_field(obj, "code", what), f"{what}.code"),
        input_ref=_as_str(_field(obj, "input_ref", what), f"{what}.input_ref"),
        detail=_as_str(_field(obj, "detail", what), f"{what}.detail"),
        trusted_case_id=_as_opt_str(
            obj.get("trusted_case_id"), f"{what}.trusted_case_id"
        ),
        schema_version=schema_version,
        status=_as_enum(ComparisonStatus, _field(obj, "status", what), f"{what}.status"),
    )


def decode_replay_result(obj: Any, what: str = "replay result") -> ReplayResult:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "comparison_hash",
            "policy_hash",
            "attempt_hashes",
            "requested",
            "completed",
            "comparable",
            "matching_signature",
            "exact_signatures",
            "outcome",
            "stop_reason",
            "operational_failure",
            "synthetic",
            "hash",
        },
        what,
    )
    attempt_items = _field(obj, "attempt_hashes", what)
    if not isinstance(attempt_items, list):
        _fail(f"{what}.attempt_hashes must be a JSON array")
    signature_items = _field(obj, "exact_signatures", what)
    if not isinstance(signature_items, list):
        _fail(f"{what}.exact_signatures must be a JSON array")
    return ReplayResult(
        comparison_hash=_as_str(
            _field(obj, "comparison_hash", what), f"{what}.comparison_hash"
        ),
        policy_hash=_as_str(_field(obj, "policy_hash", what), f"{what}.policy_hash"),
        attempt_hashes=tuple(
            _as_str(item, f"{what}.attempt_hashes[{index}]")
            for index, item in enumerate(attempt_items)
        ),
        requested=_as_int(_field(obj, "requested", what), f"{what}.requested"),
        completed=_as_int(_field(obj, "completed", what), f"{what}.completed"),
        comparable=_as_int(_field(obj, "comparable", what), f"{what}.comparable"),
        matching_signature=_as_int(
            _field(obj, "matching_signature", what), f"{what}.matching_signature"
        ),
        exact_signatures=tuple(
            _as_str(item, f"{what}.exact_signatures[{index}]")
            for index, item in enumerate(signature_items)
        ),
        outcome=_as_enum(ReplayOutcome, _field(obj, "outcome", what), f"{what}.outcome"),
        stop_reason=_as_opt_enum(StopReason, obj.get("stop_reason"), f"{what}.stop_reason"),
        operational_failure=_as_bool(
            _field(obj, "operational_failure", what), f"{what}.operational_failure"
        ),
        synthetic=_as_bool(_field(obj, "synthetic", what), f"{what}.synthetic"),
        hash=_as_str(_field(obj, "hash", what), f"{what}.hash"),
    )


def decode_reduction_result(obj: Any, what: str = "reduction result") -> ReductionResult:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "reduction_id",
            "outcome",
            "stop_reason",
            "original_case_id",
            "original_comparison_hash",
            "original_fingerprint",
            "best_case_id",
            "best_comparison_hashes",
            "has_reduction",
            "search_complete",
            "proposals",
            "executions",
            "accepted",
            "rejected_static",
            "inconclusive_candidates",
            "unstable_candidates",
            "synthetic",
            "hash",
        },
        what,
    )
    hash_items = _field(obj, "best_comparison_hashes", what)
    if not isinstance(hash_items, list):
        _fail(f"{what}.best_comparison_hashes must be a JSON array")
    return ReductionResult(
        reduction_id=_as_str(
            _field(obj, "reduction_id", what), f"{what}.reduction_id"
        ),
        outcome=_as_enum(
            ReductionOutcome, _field(obj, "outcome", what), f"{what}.outcome"
        ),
        stop_reason=_as_opt_enum(StopReason, obj.get("stop_reason"), f"{what}.stop_reason"),
        original_case_id=_as_str(
            _field(obj, "original_case_id", what), f"{what}.original_case_id"
        ),
        original_comparison_hash=_as_str(
            _field(obj, "original_comparison_hash", what),
            f"{what}.original_comparison_hash",
        ),
        original_fingerprint=_as_opt_str(
            obj.get("original_fingerprint"), f"{what}.original_fingerprint"
        ),
        best_case_id=_as_str(_field(obj, "best_case_id", what), f"{what}.best_case_id"),
        best_comparison_hashes=tuple(
            _as_str(item, f"{what}.best_comparison_hashes[{index}]")
            for index, item in enumerate(hash_items)
        ),
        has_reduction=_as_bool(
            _field(obj, "has_reduction", what), f"{what}.has_reduction"
        ),
        search_complete=_as_bool(
            _field(obj, "search_complete", what), f"{what}.search_complete"
        ),
        proposals=_as_int(_field(obj, "proposals", what), f"{what}.proposals"),
        executions=_as_int(_field(obj, "executions", what), f"{what}.executions"),
        accepted=_as_int(_field(obj, "accepted", what), f"{what}.accepted"),
        rejected_static=_as_int(
            _field(obj, "rejected_static", what), f"{what}.rejected_static"
        ),
        inconclusive_candidates=_as_int(
            _field(obj, "inconclusive_candidates", what),
            f"{what}.inconclusive_candidates",
        ),
        unstable_candidates=_as_int(
            _field(obj, "unstable_candidates", what), f"{what}.unstable_candidates"
        ),
        synthetic=_as_bool(_field(obj, "synthetic", what), f"{what}.synthetic"),
        hash=_as_str(_field(obj, "hash", what), f"{what}.hash"),
    )


def decode_artifact_ref(obj: Any, what: str = "artifact ref") -> ArtifactRef:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"path", "size_bytes", "sha256", "schema_version"}, what)
    return ArtifactRef(
        path=_as_str(_field(obj, "path", what), f"{what}.path"),
        size_bytes=_as_int(_field(obj, "size_bytes", what), f"{what}.size_bytes"),
        sha256=_as_str(_field(obj, "sha256", what), f"{what}.sha256"),
        schema_version=_as_int(
            _field(obj, "schema_version", what), f"{what}.schema_version"
        ),
    )


def decode_trace_record(obj: Any, what: str = "trace record") -> TraceRecord:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {"seq", "kind", "payload_ref", "inline", "prev_hash", "hash"},
        what,
    )
    payload_ref_obj = obj.get("payload_ref")
    payload_ref = (
        None
        if payload_ref_obj is None
        else decode_artifact_ref(payload_ref_obj, f"{what}.payload_ref")
    )
    inline = obj.get("inline")
    if inline is not None and not isinstance(inline, dict):
        _fail(f"{what}.inline must be a JSON object or null")
    return TraceRecord(
        seq=_as_int(_field(obj, "seq", what), f"{what}.seq"),
        kind=_as_str(_field(obj, "kind", what), f"{what}.kind"),
        payload_ref=payload_ref,
        inline=inline,
        prev_hash=_as_str(_field(obj, "prev_hash", what), f"{what}.prev_hash"),
        hash=_as_str(_field(obj, "hash", what), f"{what}.hash"),
    )


# --------------------------------------------------------------------------
# Public load/dump entry points
# --------------------------------------------------------------------------


def dump_comparison(comparison: Comparison) -> bytes:
    """Canonical comparison bytes (no trailing newline)."""
    return canonical_json(comparison.to_obj())


def load_comparison(data: bytes | str) -> Comparison:
    """Strict loader: untrusted bytes -> validated Comparison."""
    return decode_comparison(parse_strict_json(data))


def dump_input_failure(failure: InputFailure) -> bytes:
    return canonical_json(failure.to_obj())


def load_input_failure(data: bytes | str) -> InputFailure:
    return decode_input_failure(parse_strict_json(data))


def dump_replay_result(result: ReplayResult) -> bytes:
    return canonical_json(result.to_obj())


def load_replay_result(data: bytes | str) -> ReplayResult:
    return decode_replay_result(parse_strict_json(data))


def dump_reduction_result(result: ReductionResult) -> bytes:
    return canonical_json(result.to_obj())


def load_reduction_result(data: bytes | str) -> ReductionResult:
    return decode_reduction_result(parse_strict_json(data))


def dump_trace_record(record: TraceRecord) -> bytes:
    return canonical_json(record.to_obj())


def load_trace_record(data: bytes | str) -> TraceRecord:
    return decode_trace_record(parse_strict_json(data))
