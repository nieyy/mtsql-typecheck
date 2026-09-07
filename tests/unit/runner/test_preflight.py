"""Unit tests for runner.preflight (D3 Phase 2) -- no live server.

The probe source is a hand-written fake implementing the narrow
``EnvironmentProbeSource`` protocol; the adapter-side implementation is
exercised from ``tests/unit/adapters/test_mysql80.py``.  All probes are
read-only: the fake records every call and the tests assert no mutating
channel exists.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Mapping, Optional

import pytest

from mtsql_typecheck.contracts.codec import canonical_json, sha256_hex
from mtsql_typecheck.contracts.execution import Control, ControlCancelled, default_control
from mtsql_typecheck.contracts.runner import (
    RUNNER_ADAPTER_ID,
    BuildIdSource,
    EnvironmentManifest,
    ProbeOutcome,
    ProbeRecord,
    TlsConfig,
    TlsMode,
    TargetConfig,
    dump_environment_manifest,
    load_environment_manifest,
)
from mtsql_typecheck.runner.preflight import (
    PREFLIGHT_IDENTITY,
    _PROBE_SPECS,
    EnvironmentProbeSource,
    PreflightError,
    ProbeRuntimeIdentity,
    run_preflight,
)

TEST_UUID = "3f0a41c2-6b1e-11ef-9d3a-0242ac110002"
OTHER_UUID = "b1d2e3f4-6b1e-11ef-9d3a-0242ac110002"

IDENTITY = ProbeRuntimeIdentity(
    python_version="3.11.9",
    os_platform="Linux-6.1.0-x86_64",
    driver_name="pymysql",
    driver_version="1.1.2",
    adapter_version="mysql80-adapter-v1",
    mapping_version="mysql80-pymysql112-exact-v1",
)

GOOD_FACTS: dict[str, str] = {
    "server_uuid": TEST_UUID,
    "version": "8.0.39",
    "version_comment": "MySQL Community Server - GPL",
    "sql_mode": "NO_ENGINE_SUBSTITUTION,ONLY_FULL_GROUP_BY,STRICT_ALL_TABLES",
    "character_set_server": "utf8mb4",
    "character_set_connection": "utf8mb4",
    "collation_server": "utf8mb4_bin",
    "collation_connection": "utf8mb4_bin",
    "time_zone": "+00:00",
    "system_time_zone": "UTC",
    "innodb_version": "8.0.39",
    "sql_notes": "1",
    "optimizer_switch": "index_merge=on",
}


def make_target(**overrides) -> TargetConfig:
    fields = {
        "adapter": RUNNER_ADAPTER_ID,
        "host": "mysql-test.example.internal",
        "port": 3306,
        "unix_socket": None,
        "user": "typecheck",
        "password_env": "TYPECHECK_TEST_PASSWORD_ENV",
        "expected_server_uuid": TEST_UUID,
        "build_id": "certified-build-1",
        "database_prefix": "tc_",
        "dedicated_test_instance": True,
        "tls": TlsConfig(TlsMode.DISABLED, None),
    }
    fields.update(overrides)
    return TargetConfig(**fields)


class FakeProbeSource:
    """Fake EnvironmentProbeSource: read-only, records every access."""

    def __init__(
        self,
        facts: Mapping[str, str],
        *,
        identity: ProbeRuntimeIdentity = IDENTITY,
        build_id: Optional[str] = None,
        fetch_error: Optional[Exception] = None,
    ) -> None:
        self.facts = dict(facts)
        self._identity = identity
        self._build_id = build_id
        self._fetch_error = fetch_error
        self.fetch_calls = 0
        self.build_calls = 0

    def fetch_environment_facts(self) -> Mapping[str, str]:
        self.fetch_calls += 1
        if self._fetch_error is not None:
            raise self._fetch_error
        return dict(self.facts)

    def runtime_identity(self) -> ProbeRuntimeIdentity:
        return self._identity

    def observed_build_id(self) -> Optional[str]:
        self.build_calls += 1
        return self._build_id


def probe_by_id(manifest: EnvironmentManifest, probe_id: str) -> ProbeRecord:
    for probe in manifest.probes:
        if probe.probe_id == probe_id:
            return probe
    raise AssertionError(f"probe {probe_id} missing from manifest")


def test_happy_path_manifest_round_trip():
    source = FakeProbeSource(GOOD_FACTS, build_id="certified-build-1")
    manifest = run_preflight(make_target(), source, default_control())
    assert isinstance(manifest, EnvironmentManifest)
    assert manifest.server_uuid == TEST_UUID
    assert manifest.build_id_source is BuildIdSource.OBSERVED
    assert manifest.build_id == "certified-build-1"
    assert manifest.driver_name == "pymysql"
    assert manifest.observed_environment.version == "8.0.39"
    assert manifest.observed_environment.sql_mode_tokens == (
        "NO_ENGINE_SUBSTITUTION",
        "ONLY_FULL_GROUP_BY",
        "STRICT_ALL_TABLES",
    )
    assert manifest.observed_environment.character_set == "utf8mb4"
    assert manifest.observed_environment.collation == "utf8mb4_bin"
    assert manifest.observed_environment.time_zone == "+00:00"
    assert all(probe.outcome is ProbeOutcome.PASS for probe in manifest.probes)
    # Canonical dump -> strict load -> equality.
    loaded = load_environment_manifest(dump_environment_manifest(manifest))
    assert loaded == manifest


def test_probe_source_satisfies_the_local_protocol():
    assert isinstance(FakeProbeSource(GOOD_FACTS), EnvironmentProbeSource)


def test_preflight_identity_is_stable():
    assert PREFLIGHT_IDENTITY == "runner-preflight-v1"


def test_sanitized_config_hash_is_sha256_of_canonical_target_config():
    target = make_target()
    manifest = run_preflight(target, FakeProbeSource(GOOD_FACTS), default_control())
    assert manifest.sanitized_config_hash == sha256_hex(canonical_json(target.to_obj()))


def test_all_declared_probes_are_emitted_in_fixed_order():
    manifest = run_preflight(make_target(), FakeProbeSource(GOOD_FACTS), default_control())
    assert [probe.probe_id for probe in manifest.probes] == [
        spec.probe_id for spec in _PROBE_SPECS
    ]


def test_same_instance_uuid_mismatch_is_a_failed_probe_not_an_exception():
    target = make_target(expected_server_uuid=OTHER_UUID)
    manifest = run_preflight(target, FakeProbeSource(GOOD_FACTS), default_control())
    probe = probe_by_id(manifest, "same_instance.server_uuid")
    assert probe.outcome is ProbeOutcome.FAIL
    assert TEST_UUID in probe.detail
    # The manifest still records the observed instance honestly.
    assert manifest.server_uuid == TEST_UUID


def test_missing_fact_is_a_failed_probe():
    facts = {k: v for k, v in GOOD_FACTS.items() if k != "system_time_zone"}
    manifest = run_preflight(make_target(), FakeProbeSource(facts), default_control())
    probe = probe_by_id(manifest, "environment.system_time_zone")
    assert probe.outcome is ProbeOutcome.FAIL
    assert probe.detail == "fact missing"


def test_empty_fact_is_a_failed_probe():
    manifest = run_preflight(
        make_target(),
        FakeProbeSource({**GOOD_FACTS, "innodb_version": ""}),
        default_control(),
    )
    probe = probe_by_id(manifest, "environment.innodb_version")
    assert probe.outcome is ProbeOutcome.FAIL
    assert probe.detail == "fact empty"


def test_non_mysql_version_series_is_a_failed_probe():
    manifest = run_preflight(
        make_target(),
        FakeProbeSource({**GOOD_FACTS, "version": "10.11.6-MariaDB"}),
        default_control(),
    )
    probe = probe_by_id(manifest, "identity.version")
    assert probe.outcome is ProbeOutcome.FAIL
    assert manifest.observed_environment.version == "10.11.6-MariaDB"  # recorded, not judged


def test_unparseable_version_is_a_failed_probe():
    manifest = run_preflight(
        make_target(),
        FakeProbeSource({**GOOD_FACTS, "version": "not-a-version"}),
        default_control(),
    )
    assert probe_by_id(manifest, "identity.version").outcome is ProbeOutcome.FAIL


def test_non_uuid_server_uuid_fails_closed():
    with pytest.raises(PreflightError):
        run_preflight(
            make_target(),
            FakeProbeSource({**GOOD_FACTS, "server_uuid": "not-a-uuid"}),
            default_control(),
        )


def test_missing_server_uuid_fails_closed():
    facts = {k: v for k, v in GOOD_FACTS.items() if k != "server_uuid"}
    with pytest.raises(PreflightError):
        run_preflight(make_target(), FakeProbeSource(facts), default_control())


def test_missing_sql_mode_fails_closed():
    facts = {k: v for k, v in GOOD_FACTS.items() if k != "sql_mode"}
    with pytest.raises(PreflightError):
        run_preflight(make_target(), FakeProbeSource(facts), default_control())


def test_build_id_unavailable_is_a_failed_probe_with_configured_source():
    target = make_target()
    manifest = run_preflight(target, FakeProbeSource(GOOD_FACTS, build_id=None), default_control())
    probe = probe_by_id(manifest, "identity.build_id")
    assert probe.outcome is ProbeOutcome.FAIL
    # The configured declaration is recorded as configured, never fabricated.
    assert manifest.build_id == target.build_id
    assert manifest.build_id_source is BuildIdSource.CONFIGURED


def test_build_id_from_source_is_observed():
    target = make_target()
    manifest = run_preflight(
        make_target(),
        FakeProbeSource(GOOD_FACTS, build_id="server-measured-commit-abc"),
        default_control(),
    )
    assert probe_by_id(manifest, "identity.build_id").outcome is ProbeOutcome.PASS
    assert manifest.build_id == "server-measured-commit-abc"
    assert manifest.build_id_source is BuildIdSource.OBSERVED


def test_build_id_source_raising_is_a_failed_probe():
    class RaisingSource(FakeProbeSource):
        def observed_build_id(self) -> Optional[str]:
            raise RuntimeError("not available")

    manifest = run_preflight(make_target(), RaisingSource(GOOD_FACTS), default_control())
    assert probe_by_id(manifest, "identity.build_id").outcome is ProbeOutcome.FAIL
    assert manifest.build_id_source is BuildIdSource.CONFIGURED


def test_probe_source_fetch_failure_is_typed():
    source = FakeProbeSource({}, fetch_error=RuntimeError("connection gone"))
    with pytest.raises(PreflightError) as excinfo:
        run_preflight(make_target(), source, default_control())
    assert "connection gone" in str(excinfo.value)


def test_non_pymysql_driver_identity_is_refused():
    bad = ProbeRuntimeIdentity(
        python_version="3.11.9",
        os_platform="Linux",
        driver_name="mysqldb",
        driver_version="2.0.0",
        adapter_version="mysql80-adapter-v1",
        mapping_version="mysql80-pymysql112-exact-v1",
    )
    with pytest.raises(PreflightError):
        run_preflight(
            make_target(), FakeProbeSource(GOOD_FACTS, identity=bad), default_control()
        )


def test_non_target_config_argument_is_refused():
    with pytest.raises(PreflightError):
        run_preflight("not a target", FakeProbeSource(GOOD_FACTS), default_control())  # type: ignore[arg-type]


def test_cancelled_control_stops_before_probing():
    control = Control(clock=lambda: 0.0, deadline=None, cancelled=lambda: True)
    source = FakeProbeSource(GOOD_FACTS)
    with pytest.raises(ControlCancelled):
        run_preflight(make_target(), source, control)
    assert source.fetch_calls == 0  # nothing was issued after cancellation


def test_preflight_probes_are_read_only_and_schema1_has_no_opt_out():
    # NOT_APPLICABLE boundary (design P01/A02): every declared probe is
    # REQUIRED in schema=1; no probe can be skipped and no non-PASS/FAIL
    # outcome exists.
    assert all(spec.required for spec in _PROBE_SPECS)
    assert {outcome.value for outcome in ProbeOutcome} == {"PASS", "FAIL"}
    source = FakeProbeSource(GOOD_FACTS)
    manifest = run_preflight(make_target(), source, default_control())
    assert source.fetch_calls == 1
    assert source.build_calls == 1  # the only source channels are read-only


# ---------------------------------------------------------------------------
# Import hygiene: a fresh interpreter importing runner.preflight must not
# pull PyMySQL or the adapters package at module import time.
# ---------------------------------------------------------------------------


def test_fresh_import_of_runner_preflight_is_driver_and_adapter_free():
    code = (
        "import sys;"
        "import mtsql_typecheck.runner.preflight as p;"
        "assert 'pymysql' not in sys.modules, 'pymysql imported';"
        "adapter_mods = [m for m in sys.modules if m.startswith('mtsql_typecheck.adapters')];"
        "assert not adapter_mods, adapter_mods"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
