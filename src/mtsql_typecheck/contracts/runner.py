"""D3 runner contracts (design 6.2.1/6.3.1/6.4.6; docs/runner-d3-contract.md).

Frozen models for TargetConfig, EnvironmentManifest, StageObservation,
OwnershipEvent (append-only ownership journal) and RunnerManifest.  House
rules follow D1/D2 (``contracts/case.py``, ``contracts/codec.py``,
``contracts/execution.py``): frozen dataclasses, closed enums, tuples in
memory, full ``__post_init__`` validation on both the construction and the
loader path, unknown fields rejected, ``bool`` never accepted where an int is
required, no floats, optional fields only for genuinely absent facts.
Content hashes always exclude the record's own hash field.

Secrets never live in these models: TargetConfig carries a ``password_env``
environment-variable *name* and has no password field anywhere, so no secret
can serialize into evidence.  Importing this module performs no I/O and it
never imports a database driver.
"""

from __future__ import annotations

import enum
import uuid as _uuid
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from .case import (
    ContractError,
    ObservedEnvironment,
    _check_bool,
    _check_enum,
    _check_hex64,
    _check_int,
    _check_str,
)
from .codec import (
    _as_bool,
    _as_enum,
    _as_int,
    _as_list,
    _as_str,
    _expect_dict,
    _field,
    _no_extra,
    canonical_json,
    decode_observed_environment,
    parse_strict_json,
    sha256_hex,
)
from .execution import Side

__all__ = [
    "RUNNER_SCHEMA_VERSION",
    "RUNNER_ADAPTER_ID",
    "RUNNER_EVIDENCE_PROFILE",
    "TARGET_CONFIG_MAX_BYTES",
    "OWNERSHIP_GENESIS_HASH",
    "JOURNAL_MAX_EVENT_BYTES",
    "TlsMode",
    "TlsConfig",
    "TargetConfig",
    "BuildIdSource",
    "ProbeOutcome",
    "ProbeRecord",
    "EnvironmentManifest",
    "StageObservationKind",
    "StageObservation",
    "OwnershipEventKind",
    "OwnershipEvent",
    "RunnerCommand",
    "RunnerStatus",
    "RunnerManifest",
    "dump_ownership_journal",
    "load_ownership_journal",
    "decode_tls_config",
    "decode_target_config",
    "decode_probe_record",
    "decode_environment_manifest",
    "decode_stage_observation",
    "decode_ownership_event",
    "decode_runner_manifest",
    "load_tls_config",
    "load_target_config",
    "load_probe_record",
    "load_environment_manifest",
    "load_stage_observation",
    "load_ownership_event",
    "load_runner_manifest",
    "dump_tls_config",
    "dump_target_config",
    "dump_probe_record",
    "dump_environment_manifest",
    "dump_stage_observation",
    "dump_ownership_event",
    "dump_runner_manifest",
]

# --------------------------------------------------------------------------
# Frozen versions and budgets (docs/runner-d3-contract.md section 1)
# --------------------------------------------------------------------------

RUNNER_SCHEMA_VERSION = 1  # all D3 persistent models in this module

# TargetConfig.adapter is pinned to the one certified first-version adapter.
RUNNER_ADAPTER_ID = "mysql80-text-v1"

# Full-evidence profile bound into every RunnerManifest.  Keep in sync with
# contracts.oracle.EVIDENCE_PROFILE_FULL (D2 Phase 1); deliberately NOT
# imported from oracle.py so this module has no dependency on a file landing
# in a parallel change.
RUNNER_EVIDENCE_PROFILE = "typecheck-full-evidence-v1"

TARGET_CONFIG_MAX_BYTES = 64 * 1024  # raw envelope cap, design 6.3.1

# First event of an ownership journal links back to this all-zeros hash.
OWNERSHIP_GENESIS_HASH = "0" * 64

# Defensive per-line cap for journal loading (design 6.4.6: control records
# stay small); a longer line is rejected before parsing.
JOURNAL_MAX_EVENT_BYTES = 64 * 1024

_MAX_DETAIL_CHARS = 512
_MAX_RELPATH_CHARS = 512


def _fail(msg: str) -> None:
    raise ContractError(msg)


def _opt_int(value: object, what: str) -> Optional[int]:
    return None if value is None else _as_int(value, what)


def _opt_str(value: object, what: str) -> Optional[str]:
    return None if value is None else _as_str(value, what)


def _check_nonempty_str(value: object, name: str, max_chars: Optional[int] = None) -> str:
    value = _check_str(value, name)
    if not value:
        _fail(f"{name} must be non-empty")
    if max_chars is not None and len(value) > max_chars:
        _fail(f"{name} must be at most {max_chars} chars, got {len(value)}")
    return value


def _check_uuid(value: object, name: str) -> str:
    """Validate a UUID string and return the canonical lowercase hyphenated
    form (callers store it via ``object.__setattr__``)."""
    value = _check_str(value, name)
    try:
        parsed = _uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        _fail(f"{name} must parse as a UUID, got {value!r}")
    return str(parsed)


def _check_controlled_relpath(value: object, what: str) -> str:
    """Validate a controlled relative reference path (design 6.2.1).

    Must be a non-empty relative POSIX-style path: no leading ``/``, no
    backslash or NUL, no empty path component (``//``), no ``.`` or ``..``
    component, total length at most 512 chars.  Symlinks cannot be checked at
    the model layer; publishers and readers must enforce that separately.
    """
    value = _check_str(value, what)
    if not value:
        _fail(f"{what} must be a non-empty controlled relative path")
    if len(value) > _MAX_RELPATH_CHARS:
        _fail(f"{what} must be at most {_MAX_RELPATH_CHARS} chars, got {len(value)}")
    if value.startswith("/"):
        _fail(f"{what} must be a relative path, got {value!r}")
    if "\\" in value:
        _fail(f"{what} must not contain backslashes, got {value!r}")
    if "\0" in value:
        _fail(f"{what} must not contain NUL")
    for component in value.split("/"):
        if component == "":
            _fail(f"{what} must not contain empty path components, got {value!r}")
        if component in (".", ".."):
            _fail(f"{what} must not contain a {component!r} path component, got {value!r}")
    return value


# --------------------------------------------------------------------------
# TLS configuration (design 6.3.1)
# --------------------------------------------------------------------------


class TlsMode(enum.StrEnum):
    VERIFY_IDENTITY = "verify_identity"
    DISABLED = "disabled"


@dataclass(frozen=True)
class TlsConfig:
    """TLS selection for the target connection.

    VERIFY_IDENTITY requires a CA file; DISABLED is an explicit choice for an
    approved isolated network and must not carry a CA file.  No automatic
    downgrade exists at any layer (design 6.3.1).
    """

    mode: TlsMode
    ca_file: Optional[str]

    def __post_init__(self) -> None:
        _check_enum(self.mode, TlsMode, "TlsConfig.mode")
        if self.mode is TlsMode.VERIFY_IDENTITY:
            if self.ca_file is None:
                _fail("TlsConfig VERIFY_IDENTITY requires a ca_file")
            _check_nonempty_str(self.ca_file, "TlsConfig.ca_file")
        else:
            if self.ca_file is not None:
                _fail("TlsConfig DISABLED must not carry a ca_file")

    def to_obj(self) -> dict[str, object]:
        return {"mode": str(self.mode.value), "ca_file": self.ca_file}


def decode_tls_config(obj: object, what: str = "tls config") -> TlsConfig:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"mode", "ca_file"}, what)
    return TlsConfig(
        mode=_as_enum(TlsMode, _field(obj, "mode", what), f"{what}.mode"),
        ca_file=_opt_str(obj.get("ca_file"), f"{what}.ca_file"),
    )


# --------------------------------------------------------------------------
# TargetConfig (design 6.3.1)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetConfig:
    """Declarative target description; the password itself is read only from
    the ``password_env`` environment variable and never stored here.

    ``expected_server_uuid`` is normalized to the canonical lowercase
    hyphenated UUID form on both the construction and the loader path, so
    ``to_obj`` always emits the canonical form.  TCP (``host`` + ``port``) and
    ``unix_socket`` are strictly exclusive: exactly one transport.
    """

    adapter: str
    host: Optional[str]
    port: Optional[int]
    unix_socket: Optional[str]
    user: str
    password_env: str
    expected_server_uuid: str
    build_id: str
    database_prefix: str
    dedicated_test_instance: bool
    tls: TlsConfig
    schema_version: int = RUNNER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "TargetConfig.schema_version")
        if self.schema_version != RUNNER_SCHEMA_VERSION:
            _fail(f"unsupported runner schema_version {self.schema_version}")
        if self.adapter != RUNNER_ADAPTER_ID:
            _fail(f"TargetConfig.adapter must be {RUNNER_ADAPTER_ID!r}, got {self.adapter!r}")
        if self.unix_socket is not None:
            if self.host is not None or self.port is not None:
                _fail("TargetConfig unix_socket excludes host/port (exactly one transport)")
            _check_nonempty_str(self.unix_socket, "TargetConfig.unix_socket")
        else:
            if self.host is None or self.port is None:
                _fail("TargetConfig requires exactly one transport: host+port or unix_socket")
            _check_nonempty_str(self.host, "TargetConfig.host")
            _check_int(self.port, "TargetConfig.port")
            if not 1 <= self.port <= 65535:
                _fail(f"TargetConfig.port must be in [1, 65535], got {self.port}")
        _check_nonempty_str(self.user, "TargetConfig.user", max_chars=128)
        _check_nonempty_str(self.password_env, "TargetConfig.password_env", max_chars=128)
        if self.password_env == "password":
            _fail("TargetConfig.password_env must not be the literal \"password\"")
        if "\0" in self.password_env:
            _fail("TargetConfig.password_env must not contain NUL")
        object.__setattr__(
            self,
            "expected_server_uuid",
            _check_uuid(self.expected_server_uuid, "TargetConfig.expected_server_uuid"),
        )
        _check_nonempty_str(self.build_id, "TargetConfig.build_id", max_chars=256)
        if self.database_prefix != "tc_":
            _fail(f"TargetConfig.database_prefix must be \"tc_\", got {self.database_prefix!r}")
        _check_bool(self.dedicated_test_instance, "TargetConfig.dedicated_test_instance")
        if self.dedicated_test_instance is not True:
            _fail("TargetConfig.dedicated_test_instance must be true")
        if not isinstance(self.tls, TlsConfig):
            _fail("TargetConfig.tls must be a TlsConfig")

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "adapter": self.adapter,
            "host": self.host,
            "port": self.port,
            "unix_socket": self.unix_socket,
            "user": self.user,
            "password_env": self.password_env,
            "expected_server_uuid": self.expected_server_uuid,
            "build_id": self.build_id,
            "database_prefix": self.database_prefix,
            "dedicated_test_instance": self.dedicated_test_instance,
            "tls": self.tls.to_obj(),
        }


def decode_target_config(obj: object, what: str = "target config") -> TargetConfig:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "schema_version",
            "adapter",
            "host",
            "port",
            "unix_socket",
            "user",
            "password_env",
            "expected_server_uuid",
            "build_id",
            "database_prefix",
            "dedicated_test_instance",
            "tls",
        },
        what,
    )
    return TargetConfig(
        adapter=_as_str(_field(obj, "adapter", what), f"{what}.adapter"),
        host=_opt_str(_field(obj, "host", what), f"{what}.host"),
        port=_opt_int(_field(obj, "port", what), f"{what}.port"),
        unix_socket=_opt_str(_field(obj, "unix_socket", what), f"{what}.unix_socket"),
        user=_as_str(_field(obj, "user", what), f"{what}.user"),
        password_env=_as_str(_field(obj, "password_env", what), f"{what}.password_env"),
        expected_server_uuid=_as_str(
            _field(obj, "expected_server_uuid", what), f"{what}.expected_server_uuid"
        ),
        build_id=_as_str(_field(obj, "build_id", what), f"{what}.build_id"),
        database_prefix=_as_str(_field(obj, "database_prefix", what), f"{what}.database_prefix"),
        dedicated_test_instance=_as_bool(
            _field(obj, "dedicated_test_instance", what), f"{what}.dedicated_test_instance"
        ),
        tls=decode_tls_config(_field(obj, "tls", what), f"{what}.tls"),
        schema_version=_as_int(_field(obj, "schema_version", what), f"{what}.schema_version"),
    )


# --------------------------------------------------------------------------
# EnvironmentManifest (design 6.2.1)
# --------------------------------------------------------------------------


class BuildIdSource(enum.StrEnum):
    """Provenance of EnvironmentManifest.build_id.

    CONFIGURED means the build id is a configuration declaration and must
    never be presented as a server-measured value; OBSERVED means it was read
    from the live server during preflight.
    """

    CONFIGURED = "configured"
    OBSERVED = "observed"


class ProbeOutcome(enum.StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass(frozen=True)
class ProbeRecord:
    """One preflight probe result; probes are plain data and carry no
    special-casing here (e.g. the cancel-capability probe is just an entry).

    ``detail`` is bounded, sanitized text and may be empty; raw server output
    belongs in referenced evidence files, not in this field.
    """

    probe_id: str
    outcome: ProbeOutcome
    detail: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.probe_id, "ProbeRecord.probe_id", max_chars=128)
        _check_enum(self.outcome, ProbeOutcome, "ProbeRecord.outcome")
        detail = _check_str(self.detail, "ProbeRecord.detail")
        if len(detail) > _MAX_DETAIL_CHARS:
            _fail(f"ProbeRecord.detail must be at most {_MAX_DETAIL_CHARS} chars")
        object.__setattr__(self, "detail", detail)

    def to_obj(self) -> dict[str, object]:
        return {"probe_id": self.probe_id, "outcome": str(self.outcome.value), "detail": self.detail}


def decode_probe_record(obj: object, what: str = "probe record") -> ProbeRecord:
    obj = _expect_dict(obj, what)
    _no_extra(obj, {"probe_id", "outcome", "detail"}, what)
    return ProbeRecord(
        probe_id=_as_str(_field(obj, "probe_id", what), f"{what}.probe_id"),
        outcome=_as_enum(ProbeOutcome, _field(obj, "outcome", what), f"{what}.outcome"),
        detail=_as_str(_field(obj, "detail", what), f"{what}.detail"),
    )


@dataclass(frozen=True)
class EnvironmentManifest:
    """Preflight environment record (design 6.2.1): the D1 observed
    environment plus host-side identities, driver/adapter/mapping versions,
    build-id provenance, the sanitized config hash and raw probe outcomes.

    ``sanitized_config_hash`` is sha256 over the canonical
    ``TargetConfig.to_obj()`` bytes (contract, docs section 2.3); the model
    only checks the hex64 shape, consumers reconcile the derivation.
    """

    observed_environment: ObservedEnvironment
    server_uuid: str
    python_version: str
    os_platform: str
    driver_name: str
    driver_version: str
    adapter_version: str
    mapping_version: str
    build_id: str
    build_id_source: BuildIdSource
    sanitized_config_hash: str
    probes: Tuple[ProbeRecord, ...]
    schema_version: int = RUNNER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "EnvironmentManifest.schema_version")
        if self.schema_version != RUNNER_SCHEMA_VERSION:
            _fail(f"unsupported runner schema_version {self.schema_version}")
        if not isinstance(self.observed_environment, ObservedEnvironment):
            _fail("EnvironmentManifest.observed_environment must be an ObservedEnvironment")
        object.__setattr__(
            self, "server_uuid", _check_uuid(self.server_uuid, "EnvironmentManifest.server_uuid")
        )
        _check_nonempty_str(self.python_version, "EnvironmentManifest.python_version", max_chars=64)
        _check_nonempty_str(self.os_platform, "EnvironmentManifest.os_platform", max_chars=128)
        if self.driver_name != "pymysql":
            _fail(f"EnvironmentManifest.driver_name must be \"pymysql\", got {self.driver_name!r}")
        _check_nonempty_str(self.driver_version, "EnvironmentManifest.driver_version", max_chars=64)
        _check_nonempty_str(self.adapter_version, "EnvironmentManifest.adapter_version", max_chars=64)
        _check_nonempty_str(self.mapping_version, "EnvironmentManifest.mapping_version", max_chars=128)
        _check_nonempty_str(self.build_id, "EnvironmentManifest.build_id", max_chars=256)
        _check_enum(self.build_id_source, BuildIdSource, "EnvironmentManifest.build_id_source")
        _check_hex64(
            self.sanitized_config_hash, "EnvironmentManifest.sanitized_config_hash"
        )
        if not isinstance(self.probes, tuple):
            _fail("EnvironmentManifest.probes must be a tuple")
        for probe in self.probes:
            if not isinstance(probe, ProbeRecord):
                _fail("EnvironmentManifest.probes must hold ProbeRecord items")

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "observed_environment": self.observed_environment.to_obj(),
            "server_uuid": self.server_uuid,
            "python_version": self.python_version,
            "os_platform": self.os_platform,
            "driver_name": self.driver_name,
            "driver_version": self.driver_version,
            "adapter_version": self.adapter_version,
            "mapping_version": self.mapping_version,
            "build_id": self.build_id,
            "build_id_source": str(self.build_id_source.value),
            "sanitized_config_hash": self.sanitized_config_hash,
            "probes": [probe.to_obj() for probe in self.probes],
        }


def decode_environment_manifest(obj: object, what: str = "environment manifest") -> EnvironmentManifest:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "schema_version",
            "observed_environment",
            "server_uuid",
            "python_version",
            "os_platform",
            "driver_name",
            "driver_version",
            "adapter_version",
            "mapping_version",
            "build_id",
            "build_id_source",
            "sanitized_config_hash",
            "probes",
        },
        what,
    )
    return EnvironmentManifest(
        observed_environment=decode_observed_environment(
            _field(obj, "observed_environment", what), f"{what}.observed_environment"
        ),
        server_uuid=_as_str(_field(obj, "server_uuid", what), f"{what}.server_uuid"),
        python_version=_as_str(_field(obj, "python_version", what), f"{what}.python_version"),
        os_platform=_as_str(_field(obj, "os_platform", what), f"{what}.os_platform"),
        driver_name=_as_str(_field(obj, "driver_name", what), f"{what}.driver_name"),
        driver_version=_as_str(_field(obj, "driver_version", what), f"{what}.driver_version"),
        adapter_version=_as_str(_field(obj, "adapter_version", what), f"{what}.adapter_version"),
        mapping_version=_as_str(_field(obj, "mapping_version", what), f"{what}.mapping_version"),
        build_id=_as_str(_field(obj, "build_id", what), f"{what}.build_id"),
        build_id_source=_as_enum(
            BuildIdSource, _field(obj, "build_id_source", what), f"{what}.build_id_source"
        ),
        sanitized_config_hash=_as_str(
            _field(obj, "sanitized_config_hash", what), f"{what}.sanitized_config_hash"
        ),
        probes=tuple(
            decode_probe_record(item, f"{what}.probes[{index}]")
            for index, item in enumerate(_as_list(_field(obj, "probes", what), f"{what}.probes"))
        ),
        schema_version=_as_int(_field(obj, "schema_version", what), f"{what}.schema_version"),
    )


# --------------------------------------------------------------------------
# StageObservation (design 6.2.1)
# --------------------------------------------------------------------------


class StageObservationKind(enum.StrEnum):
    """Frozen stage vocabulary of raw collection observations."""

    PROBE = "PROBE"
    SESSION = "SESSION"
    DATABASE_CREATE = "DATABASE_CREATE"
    MARKER = "MARKER"
    DDL = "DDL"
    INSERT = "INSERT"
    READBACK = "READBACK"
    SELECT = "SELECT"
    FETCH = "FETCH"
    TERMINATION = "TERMINATION"
    CLEANUP = "CLEANUP"


@dataclass(frozen=True)
class StageObservation:
    """One raw collection observation (design 6.2.1): the Adapter records
    every observed stage fact here and later derives SideContext objects from
    the record; stage facts are never dropped or reconstructed.

    ``side`` is None for control-plane observations (probes, ownership,
    cleanup of unowned control connections).  Raw SQL text, diagnostics text
    and field metadata live in referenced evidence files via ``*_ref``
    controlled relative paths, never inline.
    """

    side: Optional[Side]
    stage: StageObservationKind
    ordinal: int
    connection_id: Optional[str]
    actual_database: Optional[str]
    session_id: Optional[str]
    sql_hash: Optional[str]
    sql_ref: Optional[str]
    diagnostics_ref: Optional[str]
    field_metadata_ref: Optional[str]
    detail: str = ""

    def __post_init__(self) -> None:
        if self.side is not None:
            _check_enum(self.side, Side, "StageObservation.side")
        _check_enum(self.stage, StageObservationKind, "StageObservation.stage")
        _check_int(self.ordinal, "StageObservation.ordinal")
        if self.ordinal < 0:
            _fail(f"StageObservation.ordinal must be >= 0, got {self.ordinal}")
        for name in ("connection_id", "actual_database", "session_id"):
            value = getattr(self, name)
            if value is not None:
                _check_nonempty_str(value, f"StageObservation.{name}")
        if self.sql_hash is not None:
            _check_hex64(self.sql_hash, "StageObservation.sql_hash")
        for name in ("sql_ref", "diagnostics_ref", "field_metadata_ref"):
            value = getattr(self, name)
            if value is not None:
                _check_controlled_relpath(value, f"StageObservation.{name}")
        detail = _check_str(self.detail, "StageObservation.detail")
        if len(detail) > _MAX_DETAIL_CHARS:
            _fail(f"StageObservation.detail must be at most {_MAX_DETAIL_CHARS} chars")
        object.__setattr__(self, "detail", detail)

    def to_obj(self) -> dict[str, object]:
        return {
            "side": None if self.side is None else str(self.side.value),
            "stage": str(self.stage.value),
            "ordinal": self.ordinal,
            "connection_id": self.connection_id,
            "actual_database": self.actual_database,
            "session_id": self.session_id,
            "sql_hash": self.sql_hash,
            "sql_ref": self.sql_ref,
            "diagnostics_ref": self.diagnostics_ref,
            "field_metadata_ref": self.field_metadata_ref,
            "detail": self.detail,
        }


def decode_stage_observation(obj: object, what: str = "stage observation") -> StageObservation:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "side",
            "stage",
            "ordinal",
            "connection_id",
            "actual_database",
            "session_id",
            "sql_hash",
            "sql_ref",
            "diagnostics_ref",
            "field_metadata_ref",
            "detail",
        },
        what,
    )
    return StageObservation(
        side=_as_opt_side(_field(obj, "side", what), f"{what}.side"),
        stage=_as_enum(StageObservationKind, _field(obj, "stage", what), f"{what}.stage"),
        ordinal=_as_int(_field(obj, "ordinal", what), f"{what}.ordinal"),
        connection_id=_opt_str(_field(obj, "connection_id", what), f"{what}.connection_id"),
        actual_database=_opt_str(_field(obj, "actual_database", what), f"{what}.actual_database"),
        session_id=_opt_str(_field(obj, "session_id", what), f"{what}.session_id"),
        sql_hash=_opt_str(_field(obj, "sql_hash", what), f"{what}.sql_hash"),
        sql_ref=_opt_str(_field(obj, "sql_ref", what), f"{what}.sql_ref"),
        diagnostics_ref=_opt_str(_field(obj, "diagnostics_ref", what), f"{what}.diagnostics_ref"),
        field_metadata_ref=_opt_str(
            _field(obj, "field_metadata_ref", what), f"{what}.field_metadata_ref"
        ),
        detail=_as_str(_field(obj, "detail", what), f"{what}.detail"),
    )


def _as_opt_side(value: object, what: str) -> Optional[Side]:
    if value is None:
        return None
    return _as_enum(Side, value, what)


# --------------------------------------------------------------------------
# OwnershipEvent and the append-only journal (design 6.2.1/6.2.3)
# --------------------------------------------------------------------------


class OwnershipEventKind(enum.StrEnum):
    """Frozen ownership vocabulary; every ledger transition is one of these."""

    RUN_LOCK_ACQUIRED = "RUN_LOCK_ACQUIRED"
    ATTEMPT_ALLOCATED = "ATTEMPT_ALLOCATED"
    OBJECT_ALLOCATED = "OBJECT_ALLOCATED"
    OBJECT_CREATED = "OBJECT_CREATED"
    MARKER_CREATED = "MARKER_CREATED"
    SESSION_REGISTERED = "SESSION_REGISTERED"
    GO_SENT = "GO_SENT"
    QUERY_STARTED = "QUERY_STARTED"
    QUERY_FINISHED = "QUERY_FINISHED"
    TERMINATION_CONFIRMED = "TERMINATION_CONFIRMED"
    TERMINATION_UNKNOWN = "TERMINATION_UNKNOWN"
    OBJECT_DROPPED = "OBJECT_DROPPED"
    CLEANUP_CONFIRMED = "CLEANUP_CONFIRMED"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    RUN_SEALED = "RUN_SEALED"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True)
class OwnershipEvent:
    """One append-only ownership journal event (design 6.2.3).

    ``content_hash`` is a derived field: constructed with the default empty
    marker it is computed over ``_content_obj()`` (the canonical event object
    minus the hash itself); a supplied value that disagrees is rejected.
    ``to_obj`` includes all fields including ``content_hash``.
    """

    seq: int
    prev_event_hash: str
    run_id: str
    event_kind: OwnershipEventKind
    attempt_id: Optional[str] = None
    server_uuid: Optional[str] = None
    object_name: Optional[str] = None
    token: Optional[str] = None
    session_generation: Optional[int] = None
    connection_id: Optional[str] = None
    content_hash: str = ""

    def __post_init__(self) -> None:
        _check_int(self.seq, "OwnershipEvent.seq")
        if self.seq < 1:
            _fail(f"OwnershipEvent.seq must be >= 1, got {self.seq}")
        _check_hex64(self.prev_event_hash, "OwnershipEvent.prev_event_hash")
        _check_nonempty_str(self.run_id, "OwnershipEvent.run_id", max_chars=128)
        _check_enum(self.event_kind, OwnershipEventKind, "OwnershipEvent.event_kind")
        if self.attempt_id is not None:
            _check_nonempty_str(self.attempt_id, "OwnershipEvent.attempt_id")
        if self.server_uuid is not None:
            object.__setattr__(
                self,
                "server_uuid",
                _check_uuid(self.server_uuid, "OwnershipEvent.server_uuid"),
            )
        if self.object_name is not None:
            _check_nonempty_str(self.object_name, "OwnershipEvent.object_name", max_chars=256)
        if self.token is not None:
            _check_nonempty_str(self.token, "OwnershipEvent.token", max_chars=128)
        if self.session_generation is not None:
            _check_int(self.session_generation, "OwnershipEvent.session_generation")
            if self.session_generation < 0:
                _fail(
                    f"OwnershipEvent.session_generation must be >= 0, "
                    f"got {self.session_generation}"
                )
        if self.connection_id is not None:
            _check_nonempty_str(self.connection_id, "OwnershipEvent.connection_id")
        derived = sha256_hex(canonical_json(self._content_obj()))
        if self.content_hash == "":
            object.__setattr__(self, "content_hash", derived)
        elif self.content_hash != derived:
            _fail(
                f"OwnershipEvent.content_hash {self.content_hash!r} does not match the "
                f"content hash {derived}"
            )
        _check_hex64(self.content_hash, "OwnershipEvent.content_hash")

    def _content_obj(self) -> dict[str, object]:
        """Hashed payload: the canonical event object minus content_hash."""
        return {
            "seq": self.seq,
            "prev_event_hash": self.prev_event_hash,
            "run_id": self.run_id,
            "event_kind": str(self.event_kind.value),
            "attempt_id": self.attempt_id,
            "server_uuid": self.server_uuid,
            "object_name": self.object_name,
            "token": self.token,
            "session_generation": self.session_generation,
            "connection_id": self.connection_id,
        }

    def to_obj(self) -> dict[str, object]:
        obj = self._content_obj()
        obj["content_hash"] = self.content_hash
        return obj


def decode_ownership_event(obj: object, what: str = "ownership event") -> OwnershipEvent:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "seq",
            "prev_event_hash",
            "run_id",
            "event_kind",
            "attempt_id",
            "server_uuid",
            "object_name",
            "token",
            "session_generation",
            "connection_id",
            "content_hash",
        },
        what,
    )
    return OwnershipEvent(
        seq=_as_int(_field(obj, "seq", what), f"{what}.seq"),
        prev_event_hash=_as_str(_field(obj, "prev_event_hash", what), f"{what}.prev_event_hash"),
        run_id=_as_str(_field(obj, "run_id", what), f"{what}.run_id"),
        event_kind=_as_enum(OwnershipEventKind, _field(obj, "event_kind", what), f"{what}.event_kind"),
        attempt_id=_opt_str(_field(obj, "attempt_id", what), f"{what}.attempt_id"),
        server_uuid=_opt_str(_field(obj, "server_uuid", what), f"{what}.server_uuid"),
        object_name=_opt_str(_field(obj, "object_name", what), f"{what}.object_name"),
        token=_opt_str(_field(obj, "token", what), f"{what}.token"),
        session_generation=_opt_int(
            _field(obj, "session_generation", what), f"{what}.session_generation"
        ),
        connection_id=_opt_str(_field(obj, "connection_id", what), f"{what}.connection_id"),
        content_hash=_as_str(_field(obj, "content_hash", what), f"{what}.content_hash"),
    )


def dump_ownership_journal(events: Tuple[OwnershipEvent, ...]) -> bytes:
    """Canonical JSONL: one canonical event object per line, ``"\\n"``
    terminated, with no trailing blank line beyond the final ``"\\n"``.

    The journal is data: callers own chain construction (seq and
    prev_event_hash); ``load_ownership_journal`` verifies it independently.
    """
    if not isinstance(events, tuple):
        _fail("dump_ownership_journal expects a tuple of OwnershipEvent")
    lines: list[bytes] = []
    for event in events:
        if not isinstance(event, OwnershipEvent):
            _fail("dump_ownership_journal expects a tuple of OwnershipEvent")
        lines.append(canonical_json(event.to_obj()))
    if not lines:
        return b""
    return b"\n".join(lines) + b"\n"


def load_ownership_journal(data: bytes | str) -> Tuple[OwnershipEvent, ...]:
    """Strict JSONL loader with full chain verification.

    Every line is parsed with ``parse_strict_json`` and decoded as an
    OwnershipEvent (which recomputes and verifies its content_hash).  The
    chain must start at seq 1 with ``prev_event_hash`` equal to
    ``OWNERSHIP_GENESIS_HASH`` and continue with strictly increasing seq
    (no gaps) where every ``prev_event_hash`` equals the previous event's
    ``content_hash``.  A zero-length or whitespace-only input loads as an
    empty tuple.  Any violation raises ContractError.
    """
    if isinstance(data, bytes):
        raw = data
    elif isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        _fail("load_ownership_journal expects bytes or str")
    events: list[OwnershipEvent] = []
    prev_hash = OWNERSHIP_GENESIS_HASH
    expected_seq = 1
    for line in raw.splitlines():
        if not line.strip():
            continue
        if len(line) > JOURNAL_MAX_EVENT_BYTES:
            _fail(
                f"ownership journal line exceeds JOURNAL_MAX_EVENT_BYTES "
                f"({JOURNAL_MAX_EVENT_BYTES})"
            )
        event = decode_ownership_event(parse_strict_json(line), "ownership journal event")
        if event.seq != expected_seq:
            _fail(
                f"ownership journal seq must be strictly 1..n with no gaps: expected "
                f"{expected_seq}, got {event.seq}"
            )
        if event.prev_event_hash != prev_hash:
            _fail(
                f"ownership journal event {event.seq} prev_event_hash {event.prev_event_hash!r} "
                f"does not link to the previous content hash {prev_hash!r}"
            )
        events.append(event)
        prev_hash = event.content_hash
        expected_seq += 1
    return tuple(events)


# --------------------------------------------------------------------------
# RunnerManifest (design 6.2.1/6.6)
# --------------------------------------------------------------------------


class RunnerCommand(enum.StrEnum):
    PREFLIGHT = "PREFLIGHT"
    RUN = "RUN"
    REPLAY = "REPLAY"
    REDUCE = "REDUCE"
    CLEANUP = "CLEANUP"


class RunnerStatus(enum.StrEnum):
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    ABORTED = "ABORTED"


# Contract versions declared by every manifest; all four are required exactly
# once.  "runner" is this contract (docs/runner-d3-contract.md).
RUNNER_CONTRACT_NAMES = ("case", "execution", "oracle", "runner")

# Manifest ref names outside the per-attempt namespace.
RUNNER_BASE_REF_NAMES = ("environment", "ownership", "runner_manifest", "trace")
_ATTEMPT_REF_PREFIX = "attempt:"

_COUNT_FIELDS = (
    "requested",
    "completed",
    "comparable",
    "match",
    "candidate",
    "inconclusive",
    "not_applicable",
)


def _check_contract_versions(value: object) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(value, tuple):
        _fail("RunnerManifest.contract_versions must be a tuple of (name, version) pairs")
    seen: dict[str, str] = {}
    for item in value:
        if not isinstance(item, tuple) or len(item) != 2:
            _fail("RunnerManifest.contract_versions must hold (name, version) pairs")
        name, version = item
        _check_str(name, "RunnerManifest.contract_versions name")
        if name not in RUNNER_CONTRACT_NAMES:
            _fail(f"RunnerManifest.contract_versions has unknown contract name {name!r}")
        if name in seen:
            _fail(f"RunnerManifest.contract_versions has duplicate contract name {name!r}")
        seen[name] = _check_nonempty_str(
            version, f"RunnerManifest.contract_versions[{name!r}]", max_chars=64
        )
    missing = [name for name in RUNNER_CONTRACT_NAMES if name not in seen]
    if missing:
        _fail(f"RunnerManifest.contract_versions is missing contract names {missing}")
    return tuple((name, seen[name]) for name in RUNNER_CONTRACT_NAMES)


def _check_ref_name(name: object) -> str:
    name = _check_str(name, "RunnerManifest.refs name")
    if name in RUNNER_BASE_REF_NAMES:
        return name
    if name.startswith(_ATTEMPT_REF_PREFIX):
        attempt_id = name[len(_ATTEMPT_REF_PREFIX):]
        if attempt_id and "\0" not in attempt_id:
            return name
    _fail(f"RunnerManifest.refs has unknown ref name {name!r}")


def _check_refs(value: object) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(value, tuple):
        _fail("RunnerManifest.refs must be a tuple of (name, path) pairs")
    seen: set[str] = set()
    pairs: list[tuple[str, str]] = []
    for item in value:
        if not isinstance(item, tuple) or len(item) != 2:
            _fail("RunnerManifest.refs must hold (name, path) pairs")
        name, path = item
        name = _check_ref_name(name)
        if name in seen:
            _fail(f"RunnerManifest.refs has duplicate ref name {name!r}")
        seen.add(name)
        pairs.append((name, _check_controlled_relpath(path, f"RunnerManifest.refs[{name!r}]")))
    # Normalized storage order keeps dump -> load round trips equal.
    return tuple(sorted(pairs))


@dataclass(frozen=True)
class RunnerManifest:
    """Run-level manifest sealed last in the output directory (design 6.6).

    Counters are per attempt: ``requested`` counts dispatches (prepare
    failures included), ``completed`` only full two-sided SELECT completions,
    ``comparable == match + candidate``.  ``stop_reason`` explains anything
    short of COMPLETE; it never hides a safety state.  ``refs`` are
    controlled relative paths inside the same output directory.
    """

    command: RunnerCommand
    run_id: str
    status: RunnerStatus
    requested: int
    completed: int
    comparable: int
    match: int
    candidate: int
    inconclusive: int
    not_applicable: int
    leftover_objects: int
    leftover_sessions: int
    synthetic: bool
    evidence_profile: str
    tool_version: str
    contract_versions: Tuple[Tuple[str, str], ...]
    refs: Tuple[Tuple[str, str], ...]
    sanitized_config_hash: str
    stop_reason: Optional[str] = None
    schema_version: int = RUNNER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_int(self.schema_version, "RunnerManifest.schema_version")
        if self.schema_version != RUNNER_SCHEMA_VERSION:
            _fail(f"unsupported runner schema_version {self.schema_version}")
        _check_enum(self.command, RunnerCommand, "RunnerManifest.command")
        _check_nonempty_str(self.run_id, "RunnerManifest.run_id", max_chars=128)
        _check_enum(self.status, RunnerStatus, "RunnerManifest.status")
        if self.stop_reason is not None:
            _check_nonempty_str(self.stop_reason, "RunnerManifest.stop_reason", max_chars=128)
        for name in _COUNT_FIELDS:
            value = getattr(self, name)
            _check_int(value, f"RunnerManifest.{name}")
            if value < 0:
                _fail(f"RunnerManifest.{name} must be >= 0, got {value}")
        if self.comparable != self.match + self.candidate:
            _fail(
                f"RunnerManifest.comparable {self.comparable} must equal match + candidate "
                f"({self.match} + {self.candidate})"
            )
        if self.completed > self.requested:
            _fail(
                f"RunnerManifest.completed {self.completed} must be <= requested "
                f"{self.requested}"
            )
        if self.comparable > self.completed:
            _fail(
                f"RunnerManifest.comparable {self.comparable} must be <= completed "
                f"{self.completed}"
            )
        for name in ("leftover_objects", "leftover_sessions"):
            value = getattr(self, name)
            _check_int(value, f"RunnerManifest.{name}")
            if value < 0:
                _fail(f"RunnerManifest.{name} must be >= 0, got {value}")
        _check_bool(self.synthetic, "RunnerManifest.synthetic")
        if self.evidence_profile != RUNNER_EVIDENCE_PROFILE:
            _fail(
                f"RunnerManifest.evidence_profile must be {RUNNER_EVIDENCE_PROFILE!r}, "
                f"got {self.evidence_profile!r}"
            )
        _check_nonempty_str(self.tool_version, "RunnerManifest.tool_version", max_chars=64)
        object.__setattr__(self, "contract_versions", _check_contract_versions(self.contract_versions))
        object.__setattr__(self, "refs", _check_refs(self.refs))
        _check_hex64(self.sanitized_config_hash, "RunnerManifest.sanitized_config_hash")

    def contract_version(self, name: str) -> str:
        """Version string for one declared contract; unknown names fail."""
        for pair_name, version in self.contract_versions:
            if pair_name == name:
                return version
        _fail(f"RunnerManifest has no contract version for {name!r}")

    def ref(self, name: str) -> Optional[str]:
        """Controlled relative path for one ref name; None when absent."""
        for ref_name, path in self.refs:
            if ref_name == name:
                return path
        return None

    def to_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "command": str(self.command.value),
            "run_id": self.run_id,
            "status": str(self.status.value),
            "stop_reason": self.stop_reason,
            "requested": self.requested,
            "completed": self.completed,
            "comparable": self.comparable,
            "match": self.match,
            "candidate": self.candidate,
            "inconclusive": self.inconclusive,
            "not_applicable": self.not_applicable,
            "leftover_objects": self.leftover_objects,
            "leftover_sessions": self.leftover_sessions,
            "synthetic": self.synthetic,
            "evidence_profile": self.evidence_profile,
            "tool_version": self.tool_version,
            "contract_versions": {name: version for name, version in self.contract_versions},
            "refs": {name: path for name, path in self.refs},
            "sanitized_config_hash": self.sanitized_config_hash,
        }


def decode_runner_manifest(obj: object, what: str = "runner manifest") -> RunnerManifest:
    obj = _expect_dict(obj, what)
    _no_extra(
        obj,
        {
            "schema_version",
            "command",
            "run_id",
            "status",
            "stop_reason",
            "requested",
            "completed",
            "comparable",
            "match",
            "candidate",
            "inconclusive",
            "not_applicable",
            "leftover_objects",
            "leftover_sessions",
            "synthetic",
            "evidence_profile",
            "tool_version",
            "contract_versions",
            "refs",
            "sanitized_config_hash",
        },
        what,
    )
    versions_obj = _expect_dict(
        _field(obj, "contract_versions", what), f"{what}.contract_versions"
    )
    _no_extra(versions_obj, set(RUNNER_CONTRACT_NAMES), f"{what}.contract_versions")
    contract_versions = tuple(
        (name, _as_str(_field(versions_obj, name, f"{what}.contract_versions"),
                       f"{what}.contract_versions[{name!r}]"))
        for name in RUNNER_CONTRACT_NAMES
    )
    refs_obj = _expect_dict(_field(obj, "refs", what), f"{what}.refs")
    refs = tuple(
        (_as_str(ref_name, f"{what}.refs name"),
         _as_str(ref_path, f"{what}.refs[{ref_name!r}]"))
        for ref_name, ref_path in refs_obj.items()
    )
    return RunnerManifest(
        command=_as_enum(RunnerCommand, _field(obj, "command", what), f"{what}.command"),
        run_id=_as_str(_field(obj, "run_id", what), f"{what}.run_id"),
        status=_as_enum(RunnerStatus, _field(obj, "status", what), f"{what}.status"),
        requested=_as_int(_field(obj, "requested", what), f"{what}.requested"),
        completed=_as_int(_field(obj, "completed", what), f"{what}.completed"),
        comparable=_as_int(_field(obj, "comparable", what), f"{what}.comparable"),
        match=_as_int(_field(obj, "match", what), f"{what}.match"),
        candidate=_as_int(_field(obj, "candidate", what), f"{what}.candidate"),
        inconclusive=_as_int(_field(obj, "inconclusive", what), f"{what}.inconclusive"),
        not_applicable=_as_int(_field(obj, "not_applicable", what), f"{what}.not_applicable"),
        leftover_objects=_as_int(_field(obj, "leftover_objects", what), f"{what}.leftover_objects"),
        leftover_sessions=_as_int(
            _field(obj, "leftover_sessions", what), f"{what}.leftover_sessions"
        ),
        synthetic=_as_bool(_field(obj, "synthetic", what), f"{what}.synthetic"),
        evidence_profile=_as_str(
            _field(obj, "evidence_profile", what), f"{what}.evidence_profile"
        ),
        tool_version=_as_str(_field(obj, "tool_version", what), f"{what}.tool_version"),
        contract_versions=contract_versions,
        refs=refs,
        sanitized_config_hash=_as_str(
            _field(obj, "sanitized_config_hash", what), f"{what}.sanitized_config_hash"
        ),
        stop_reason=_opt_str(_field(obj, "stop_reason", what), f"{what}.stop_reason"),
        schema_version=_as_int(_field(obj, "schema_version", what), f"{what}.schema_version"),
    )


# --------------------------------------------------------------------------
# Public load/dump entry points (execution.py pattern)
# --------------------------------------------------------------------------


def _load_document(decode: Callable[[object, str], object], data: object, what: str) -> object:
    if isinstance(data, dict):
        return decode(data, what)
    return decode(parse_strict_json(data), what)


def load_tls_config(data: bytes | str | dict) -> TlsConfig:
    """Strict loader: untrusted bytes/str/dict -> validated TlsConfig."""
    return _load_document(decode_tls_config, data, "tls config")  # type: ignore[return-value]


def load_target_config(data: bytes | str | dict) -> TargetConfig:
    """Strict loader; a raw envelope over TARGET_CONFIG_MAX_BYTES (64 KiB,
    design 6.3.1) is rejected before parsing."""
    if isinstance(data, (bytes, str)):
        raw = data.encode("utf-8") if isinstance(data, str) else data
        if len(raw) > TARGET_CONFIG_MAX_BYTES:
            _fail(
                f"target config exceeds TARGET_CONFIG_MAX_BYTES ({TARGET_CONFIG_MAX_BYTES})"
            )
    return _load_document(decode_target_config, data, "target config")  # type: ignore[return-value]


def load_probe_record(data: bytes | str | dict) -> ProbeRecord:
    return _load_document(decode_probe_record, data, "probe record")  # type: ignore[return-value]


def load_environment_manifest(data: bytes | str | dict) -> EnvironmentManifest:
    return _load_document(decode_environment_manifest, data, "environment manifest")  # type: ignore[return-value]


def load_stage_observation(data: bytes | str | dict) -> StageObservation:
    return _load_document(decode_stage_observation, data, "stage observation")  # type: ignore[return-value]


def load_ownership_event(data: bytes | str | dict) -> OwnershipEvent:
    return _load_document(decode_ownership_event, data, "ownership event")  # type: ignore[return-value]


def load_runner_manifest(data: bytes | str | dict) -> RunnerManifest:
    return _load_document(decode_runner_manifest, data, "runner manifest")  # type: ignore[return-value]


def dump_tls_config(model: TlsConfig) -> bytes:
    """Canonical config bytes (no trailing newline)."""
    return canonical_json(model.to_obj())


def dump_target_config(model: TargetConfig) -> bytes:
    return canonical_json(model.to_obj())


def dump_probe_record(model: ProbeRecord) -> bytes:
    return canonical_json(model.to_obj())


def dump_environment_manifest(model: EnvironmentManifest) -> bytes:
    return canonical_json(model.to_obj())


def dump_stage_observation(model: StageObservation) -> bytes:
    return canonical_json(model.to_obj())


def dump_ownership_event(model: OwnershipEvent) -> bytes:
    """Canonical event bytes including the ``content_hash`` field."""
    return canonical_json(model.to_obj())


def dump_runner_manifest(model: RunnerManifest) -> bytes:
    return canonical_json(model.to_obj())
