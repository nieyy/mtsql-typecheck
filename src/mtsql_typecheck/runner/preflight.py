"""Preflight environment probing (D3 design 6.3.1/6.4, Phase 2).

``run_preflight`` issues the read-only identity/environment probes against an
injected :class:`EnvironmentProbeSource` and assembles a schema=1
:class:`EnvironmentManifest` from ``contracts.runner``.  Preflight collects
facts only: it never raises for a failed *fact* (the probe record carries the
failure and the caller decides), and it never mutates session state -- the
probe protocol is read-only by construction.

Probe-source choice (documented decision): the design allows either a raw
``run_probe_query``-style executor or a fact-facing source.  A fact-facing
source is the cleaner boundary -- preflight must not know SQL text -- so the
protocol here is ``fetch_environment_facts()`` plus ``runtime_identity()``
and ``observed_build_id()``; ``MySQL80Adapter`` provides it (one round-trip
identity SELECT behind ``fetch_environment_facts``).

Fact vocabulary is identical to D1's environment facts
(``generation.validation`` / ``contracts.case``): the same variable names,
the same required value names, and the same MySQL version-series parser are
reused; preflight records observations and never claims a rule precondition
is satisfied (runtime-fact validation is Phase 4 / oracle-gate work).

NOT_APPLICABLE semantics (design P01/A02 boundary): a probe is NOT_APPLICABLE
only when a ``TargetConfig`` field opts out -- never to skip a probe whose
fact is required.  ``contracts.runner.ProbeOutcome`` has no NOT_APPLICABLE
member, so an opted-out probe emits *no* ProbeRecord at all.  In schema=1 no
``TargetConfig`` opt-out field exists (``build_id`` is mandatory), therefore
every declared probe below is marked REQUIRED and the skip branch is
unreachable; a future opt-out must add a config field and a non-required
spec, never a probe-failure shortcut.

Import discipline: importing this module imports neither PyMySQL nor the
adapters package.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Protocol, runtime_checkable

from ..contracts.case import ContractError, ObservedEnvironment
from ..contracts.codec import canonical_json, sha256_hex
from ..contracts.execution import Control
from ..contracts.runner import (
    BuildIdSource,
    EnvironmentManifest,
    ProbeOutcome,
    ProbeRecord,
    TargetConfig,
)
from ..generation.validation import parse_mysql_version_series

__all__ = [
    "PREFLIGHT_IDENTITY",
    "ProbeRuntimeIdentity",
    "EnvironmentProbeSource",
    "PreflightError",
    "run_preflight",
]

#: Semantic identity of this preflight implementation (probe set + mapping).
PREFLIGHT_IDENTITY = "runner-preflight-v1"

#: D1's frozen target series (``generation.validation``: MySQL 8.0 within one
#: instance/engine; MariaDB compatibility version strings are not admitted).
_REQUIRED_VERSION_SERIES = (8, 0)

_MAX_DETAIL_CHARS = 512


class PreflightError(ContractError):
    """Preflight cannot produce an honest manifest (contract misuse, probe
    source failure, or a fact the manifest schema cannot represent).  This is
    not a probe failure: per-fact failures become ``ProbeOutcome.FAIL``
    records on the manifest, and only unbuildable manifests raise."""


@dataclass(frozen=True)
class ProbeRuntimeIdentity:
    """Host-side runtime identities required by ``EnvironmentManifest``."""

    python_version: str
    os_platform: str
    driver_name: str
    driver_version: str
    adapter_version: str
    mapping_version: str


@runtime_checkable
class EnvironmentProbeSource(Protocol):
    """Narrow read-only probe boundary (implemented by ``MySQL80Adapter``).

    Implementations must issue read-only statements only (no SET, no session
    mutation) and must not cache stale facts across reconnects.
    """

    def fetch_environment_facts(self) -> Mapping[str, str]: ...

    def runtime_identity(self) -> ProbeRuntimeIdentity: ...

    def observed_build_id(self) -> Optional[str]: ...


# --------------------------------------------------------------------------
# Probe table (fixed order; probe records keep this order on the manifest)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _ProbeSpec:
    probe_id: str
    #: Key in the facts mapping; None for probes that compare facts against
    #: the configuration instead of reading one.
    fact_key: Optional[str]
    #: Check performed on the observed value.
    check: str  # "nonempty" | "uuid" | "version_series" | "uuid_match" | "build_id"
    #: REQUIRED probes can never be opted out (design P01/A02 boundary).
    required: bool = True


_PROBE_SPECS: tuple[_ProbeSpec, ...] = (
    _ProbeSpec("identity.server_uuid", "server_uuid", "uuid"),
    _ProbeSpec("identity.version", "version", "version_series"),
    _ProbeSpec("identity.version_comment", "version_comment", "nonempty"),
    _ProbeSpec("environment.sql_mode", "sql_mode", "nonempty"),
    _ProbeSpec("environment.character_set_server", "character_set_server", "nonempty"),
    _ProbeSpec("environment.character_set_connection", "character_set_connection", "nonempty"),
    _ProbeSpec("environment.collation_server", "collation_server", "nonempty"),
    _ProbeSpec("environment.collation_connection", "collation_connection", "nonempty"),
    _ProbeSpec("environment.time_zone", "time_zone", "nonempty"),
    _ProbeSpec("environment.system_time_zone", "system_time_zone", "nonempty"),
    _ProbeSpec("environment.innodb_version", "innodb_version", "nonempty"),
    _ProbeSpec("environment.optimizer_switch", "optimizer_switch", "nonempty"),
    _ProbeSpec("environment.sql_notes", "sql_notes", "nonempty"),
    # Server-measured build identity: PASSED only when the source can provide
    # one; the configured declaration is never presented as server-measured.
    _ProbeSpec("identity.build_id", None, "build_id"),
    # Same-instance proof (design 6.3.1): the observed server UUID must equal
    # the configured expectation; a proxy routing to another instance stops.
    _ProbeSpec("same_instance.server_uuid", None, "uuid_match"),
)


def _bounded_detail(text: str) -> str:
    text = text if isinstance(text, str) else repr(text)
    if len(text) <= _MAX_DETAIL_CHARS:
        return text
    return text[:_MAX_DETAIL_CHARS]


def _canonical_uuid(value: str) -> Optional[str]:
    import uuid as _uuid

    try:
        return str(_uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        return None


def _probe_outcome(spec: _ProbeSpec, facts: Mapping[str, str], config: TargetConfig) -> ProbeRecord:
    if spec.check == "build_id":
        # Handled by the caller (needs the probe source, not the fact map).
        raise PreflightError(f"probe {spec.probe_id} is source-backed, not fact-backed")
    if spec.check == "uuid_match":
        observed = facts.get("server_uuid")
        observed_canonical = _canonical_uuid(observed) if observed else None
        if observed_canonical is not None and observed_canonical == config.expected_server_uuid:
            return ProbeRecord(spec.probe_id, ProbeOutcome.PASS, "observed server_uuid matches")
        return ProbeRecord(
            spec.probe_id,
            ProbeOutcome.FAIL,
            _bounded_detail(
                f"expected server_uuid {config.expected_server_uuid}, observed "
                f"{observed!r}"
            ),
        )

    observed = facts.get(spec.fact_key or "")
    if observed is None:
        return ProbeRecord(spec.probe_id, ProbeOutcome.FAIL, "fact missing")
    if not isinstance(observed, str) or observed == "":
        return ProbeRecord(spec.probe_id, ProbeOutcome.FAIL, "fact empty")
    if spec.check == "uuid":
        canonical = _canonical_uuid(observed)
        if canonical is None:
            return ProbeRecord(
                spec.probe_id, ProbeOutcome.FAIL, _bounded_detail(f"not a UUID: {observed!r}")
            )
        return ProbeRecord(spec.probe_id, ProbeOutcome.PASS, _bounded_detail(f"observed {canonical}"))
    if spec.check == "version_series":
        series = parse_mysql_version_series(observed)
        if series is None:
            return ProbeRecord(
                spec.probe_id,
                ProbeOutcome.FAIL,
                _bounded_detail(f"no dotted-numeric version series in {observed!r}"),
            )
        if series != _REQUIRED_VERSION_SERIES:
            return ProbeRecord(
                spec.probe_id,
                ProbeOutcome.FAIL,
                _bounded_detail(
                    f"version series {series} is not the required {_REQUIRED_VERSION_SERIES}"
                ),
            )
        return ProbeRecord(spec.probe_id, ProbeOutcome.PASS, _bounded_detail(f"observed {observed!r}"))
    # "nonempty"
    return ProbeRecord(spec.probe_id, ProbeOutcome.PASS, _bounded_detail(f"observed {observed!r}"))


def _build_id_probe(
    probe_source: EnvironmentProbeSource, config: TargetConfig
) -> tuple[ProbeRecord, Optional[str]]:
    """Source-backed build identity probe (design: build_id provenance).

    ``BuildIdSource.OBSERVED`` only when the source itself provides a
    non-empty server-measured build id (returned as the second element);
    otherwise the probe FAILS and the manifest falls back to the configured
    declaration with ``BuildIdSource.CONFIGURED``.  A build id is never
    fabricated.
    """

    try:
        observed = probe_source.observed_build_id()
    except Exception as exc:  # noqa: BLE001 - probe failure is a fact, not a crash
        return (
            ProbeRecord(
                "identity.build_id",
                ProbeOutcome.FAIL,
                _bounded_detail(f"build id source raised {type(exc).__name__}"),
            ),
            None,
        )
    if observed is None:
        return (
            ProbeRecord(
                "identity.build_id",
                ProbeOutcome.FAIL,
                "source cannot provide a server-measured build id; the configured "
                "declaration is recorded with source CONFIGURED",
            ),
            None,
        )
    if not isinstance(observed, str) or not observed:
        return (
            ProbeRecord("identity.build_id", ProbeOutcome.FAIL, "build id empty"),
            None,
        )
    detail = (
        "matches the configured build_id"
        if observed == config.build_id
        else "differs from the configured build_id (both recorded)"
    )
    return (
        ProbeRecord("identity.build_id", ProbeOutcome.PASS, _bounded_detail(detail)),
        observed,
    )


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def run_preflight(
    config: TargetConfig,
    probe_source: EnvironmentProbeSource,
    control: Control,
) -> EnvironmentManifest:
    """Run the read-only preflight probes and assemble the manifest.

    Raises :class:`PreflightError` only when an honest schema=1 manifest
    cannot be produced (invalid arguments, probe-source failure, or a
    mandatory fact -- ``server_uuid`` / ``sql_mode`` -- missing or unusable).
    Per-probe fact failures are recorded as ``ProbeOutcome.FAIL`` records;
    the caller decides what a failed environment means.
    """

    if not isinstance(config, TargetConfig):
        raise PreflightError("run_preflight needs a TargetConfig")
    if not isinstance(control, Control):
        raise PreflightError("run_preflight needs a Control")
    try:
        identity = probe_source.runtime_identity()
    except Exception as exc:  # noqa: BLE001 - probe-source failure is typed
        raise PreflightError(
            f"probe source runtime_identity failed: {type(exc).__name__}: {exc}"
        ) from exc
    if identity.driver_name != "pymysql":
        raise PreflightError(
            f"EnvironmentManifest.driver_name is frozen to \"pymysql\", probe source "
            f"reports {identity.driver_name!r}"
        )

    control.raise_if_cancelled()
    try:
        facts = dict(probe_source.fetch_environment_facts())
    except Exception as exc:  # noqa: BLE001
        raise PreflightError(
            f"probe source fetch_environment_facts failed: {type(exc).__name__}: {exc}"
        ) from exc
    for key, value in facts.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise PreflightError(
                f"environment fact {key!r} is not a (str, str) pair (fail closed)"
            )

    probes: list[ProbeRecord] = []
    provided_build_id: Optional[str] = None
    for spec in _PROBE_SPECS:
        # NOT_APPLICABLE boundary: only a TargetConfig opt-out can skip a
        # probe, and no schema=1 field provides one (all specs are REQUIRED).
        if not spec.required:  # pragma: no cover - unreachable in schema=1
            continue
        if spec.check == "build_id":
            probe, provided_build_id = _build_id_probe(probe_source, config)
            probes.append(probe)
        else:
            probes.append(_probe_outcome(spec, facts, config))
    control.raise_if_cancelled()

    # Facts the manifest schema cannot represent as absent: fail closed.
    server_uuid_raw = facts.get("server_uuid")
    server_uuid = _canonical_uuid(server_uuid_raw) if server_uuid_raw else None
    if server_uuid is None:
        raise PreflightError(
            f"observed server_uuid {server_uuid_raw!r} is not a usable UUID; the "
            f"environment manifest cannot be produced (fail closed)"
        )
    sql_mode_raw = facts.get("sql_mode")
    sql_mode_tokens = tuple(
        sorted({token.strip() for token in (sql_mode_raw or "").split(",") if token.strip()})
    )
    if not sql_mode_tokens:
        raise PreflightError(
            f"observed sql_mode {sql_mode_raw!r} yields no mode tokens; the "
            f"environment manifest cannot be produced (fail closed)"
        )

    observed_environment = ObservedEnvironment(
        instance_identity=server_uuid,
        version=facts.get("version", ""),
        # Raw observed version_comment; never rewritten into a vendor guess.
        vendor=facts.get("version_comment", ""),
        # The configured declaration; never presented as server-measured
        # (BuildIdSource below records the provenance).
        build_id=config.build_id,
        engine="innodb" if facts.get("innodb_version") else "",
        sql_mode_tokens=sql_mode_tokens,
        character_set=facts.get("character_set_connection", ""),
        collation=facts.get("collation_connection", ""),
        time_zone=facts.get("time_zone", ""),
        optimizer_switch=facts.get("optimizer_switch", ""),
    )

    return EnvironmentManifest(
        observed_environment=observed_environment,
        server_uuid=server_uuid,
        python_version=identity.python_version,
        os_platform=identity.os_platform,
        driver_name=identity.driver_name,
        driver_version=identity.driver_version,
        adapter_version=identity.adapter_version,
        mapping_version=identity.mapping_version,
        build_id=provided_build_id if provided_build_id is not None else config.build_id,
        build_id_source=(
            BuildIdSource.OBSERVED if provided_build_id is not None else BuildIdSource.CONFIGURED
        ),
        sanitized_config_hash=sha256_hex(canonical_json(config.to_obj())),
        probes=tuple(probes),
    )
