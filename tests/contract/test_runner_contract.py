"""D3 runner contract tests: TargetConfig, EnvironmentManifest,
StageObservation, OwnershipEvent/journal and RunnerManifest.

The golden canonical bytes and hashes below were produced once by an
independent script (plain ``json.dumps`` canonicalization hashed with
``hashlib`` and cross-checked with the external ``shasum -a 256`` tool) and
are frozen as literals; no assertion recomputes its own expectation through a
project hash helper.  Derived-hash tests (ownership content hash, sanitized
config hash) assert the documented derivation itself, which is the contract.
"""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from mtsql_typecheck.contracts.case import (
    ContractError,
    ObservedEnvironment,
)
from mtsql_typecheck.contracts.codec import parse_strict_json
from mtsql_typecheck.contracts.execution import Side
from mtsql_typecheck.contracts.runner import (
    JOURNAL_MAX_EVENT_BYTES,
    OWNERSHIP_GENESIS_HASH,
    RUNNER_ADAPTER_ID,
    RUNNER_EVIDENCE_PROFILE,
    TARGET_CONFIG_MAX_BYTES,
    BuildIdSource,
    EnvironmentManifest,
    OwnershipEvent,
    OwnershipEventKind,
    ProbeOutcome,
    ProbeRecord,
    RunnerCommand,
    RunnerManifest,
    RunnerStatus,
    StageObservation,
    StageObservationKind,
    TargetConfig,
    TlsConfig,
    TlsMode,
    decode_environment_manifest,
    decode_ownership_event,
    decode_probe_record,
    decode_runner_manifest,
    decode_stage_observation,
    decode_target_config,
    decode_tls_config,
    dump_environment_manifest,
    dump_ownership_event,
    dump_ownership_journal,
    dump_probe_record,
    dump_runner_manifest,
    dump_stage_observation,
    dump_target_config,
    dump_tls_config,
    load_environment_manifest,
    load_ownership_event,
    load_ownership_journal,
    load_probe_record,
    load_runner_manifest,
    load_stage_observation,
    load_target_config,
    load_tls_config,
)

# Frozen once with plain json.dumps + hashlib (cross-checked with shasum -a
# 256); the canonical bytes literals are hand-written, not produced by the
# code under test.
GOLDEN_TARGET_CONFIG_CANONICAL = (
    '{"adapter":"mysql80-text-v1","build_id":"8.0.39-certified-build-20250715",'
    '"database_prefix":"tc_","dedicated_test_instance":true,'
    '"expected_server_uuid":"1f0e3d2c-4b5a-4678-9abc-def012345678",'
    '"host":"mysql-test.example.internal","password_env":"TYPECHECK_MYSQL_PASSWORD",'
    '"port":3306,"schema_version":1,'
    '"tls":{"ca_file":"/etc/typecheck/ca.pem","mode":"verify_identity"},'
    '"unix_socket":null,"user":"typecheck"}'
).encode("utf-8")
GOLDEN_TARGET_CONFIG_HASH = "46560d8270b80482321142a0a91efba1fc72c0b9aea5f6124268aee31f7e4e3e"

GOLDEN_EVENT_CONTENT_CANONICAL = (
    '{"attempt_id":null,"connection_id":null,"event_kind":"RUN_LOCK_ACQUIRED",'
    '"object_name":null,"prev_event_hash":"' + OWNERSHIP_GENESIS_HASH + '",'
    '"run_id":"run-20260906-1","seq":1,"server_uuid":null,'
    '"session_generation":null,"token":null}'
).encode("utf-8")
GOLDEN_EVENT_CONTENT_HASH = "7a928872e04dd03417d5ae7a14f92d2dd9f0a1d9e2effe38115b3a17c528dfe1"

UUID = "1f0e3d2c-4b5a-4678-9abc-def012345678"
HEX64 = "ab" * 32
OTHER_HEX64 = "cd" * 32


def _canon_independent(obj) -> bytes:
    """Independent canonicalization used to derive hashes in tests."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


# --------------------------------------------------------------------------
# Hand-written golden documents (loader path does not rely on to_obj)
# --------------------------------------------------------------------------

TLS_DOC = {"mode": "verify_identity", "ca_file": "/etc/typecheck/ca.pem"}

TARGET_DOC = {
    "schema_version": 1,
    "adapter": "mysql80-text-v1",
    "host": "mysql-test.example.internal",
    "port": 3306,
    "unix_socket": None,
    "user": "typecheck",
    "password_env": "TYPECHECK_MYSQL_PASSWORD",
    "expected_server_uuid": UUID,
    "build_id": "8.0.39-certified-build-20250715",
    "database_prefix": "tc_",
    "dedicated_test_instance": True,
    "tls": dict(TLS_DOC),
}

PROBE_DOC = {
    "probe_id": "cancel-capability",
    "outcome": "PASS",
    "detail": "bounded SLEEP probe cancelled, own thread gone",
}

MANIFEST_DOC = {
    "schema_version": 1,
    "observed_environment": {
        "instance_identity": "mysql-8039-local",
        "version": "8.0.39",
        "vendor": "mysql",
        "build_id": "20250715",
        "engine": "innodb",
        "sql_mode_tokens": ["NO_ENGINE_SUBSTITUTION", "ONLY_FULL_GROUP_BY", "STRICT_ALL_TABLES"],
        "character_set": "utf8mb4",
        "collation": "utf8mb4_bin",
        "time_zone": "+00:00",
        "optimizer_switch": "index_merge=on,mrr=off",
    },
    "server_uuid": UUID,
    "python_version": "3.11.9",
    "os_platform": "Linux-5.15.0-x86_64",
    "driver_name": "pymysql",
    "driver_version": "1.1.2",
    "adapter_version": "mysql80-text-v1",
    "mapping_version": "mysql80-pymysql112-exact-v1",
    "build_id": "8.0.39-certified-build-20250715",
    "build_id_source": "configured",
    "sanitized_config_hash": GOLDEN_TARGET_CONFIG_HASH,
    "probes": [dict(PROBE_DOC)],
}

STAGE_DOC = {
    "side": "A",
    "stage": "INSERT",
    "ordinal": 0,
    "connection_id": "conn-1",
    "actual_database": "tc_a",
    "session_id": None,
    "sql_hash": HEX64,
    "sql_ref": "attempts/attempt-001/sql/insert-0.txt",
    "diagnostics_ref": "attempts/attempt-001/diagnostics/insert-0.txt",
    "field_metadata_ref": None,
    "detail": "",
}

EVENT_DOC = {
    "seq": 1,
    "prev_event_hash": OWNERSHIP_GENESIS_HASH,
    "run_id": "run-20260906-1",
    "event_kind": "RUN_LOCK_ACQUIRED",
    "attempt_id": None,
    "server_uuid": None,
    "object_name": None,
    "token": None,
    "session_generation": None,
    "connection_id": None,
    "content_hash": GOLDEN_EVENT_CONTENT_HASH,
}

RUNNER_MANIFEST_DOC = {
    "schema_version": 1,
    "command": "RUN",
    "run_id": "run-20260906-1",
    "status": "COMPLETE",
    "stop_reason": None,
    "requested": 10,
    "completed": 9,
    "comparable": 8,
    "match": 6,
    "candidate": 2,
    "inconclusive": 1,
    "not_applicable": 1,
    "leftover_objects": 0,
    "leftover_sessions": 0,
    "synthetic": True,
    "evidence_profile": "typecheck-full-evidence-v1",
    "tool_version": "0.1.0",
    "contract_versions": {"case": "1", "execution": "1", "oracle": "o1", "runner": "1"},
    "refs": {
        "environment": "environment.json",
        "ownership": "ownership.jsonl",
        "runner_manifest": "runner-manifest.json",
        "attempt:attempt-001": "attempts/attempt-001",
    },
    "sanitized_config_hash": GOLDEN_TARGET_CONFIG_HASH,
}


# --------------------------------------------------------------------------
# Shared builders (construction path)
# --------------------------------------------------------------------------


def _tls(**overrides) -> TlsConfig:
    kwargs = {"mode": TlsMode.VERIFY_IDENTITY, "ca_file": "/etc/typecheck/ca.pem"}
    kwargs.update(overrides)
    return TlsConfig(**kwargs)


def _target(**overrides) -> TargetConfig:
    kwargs = dict(
        adapter=RUNNER_ADAPTER_ID,
        host="mysql-test.example.internal",
        port=3306,
        unix_socket=None,
        user="typecheck",
        password_env="TYPECHECK_MYSQL_PASSWORD",
        expected_server_uuid=UUID,
        build_id="8.0.39-certified-build-20250715",
        database_prefix="tc_",
        dedicated_test_instance=True,
        tls=_tls(),
    )
    kwargs.update(overrides)
    return TargetConfig(**kwargs)


def _probe(**overrides) -> ProbeRecord:
    kwargs = {"probe_id": "cancel-capability", "outcome": ProbeOutcome.PASS, "detail": "ok"}
    kwargs.update(overrides)
    return ProbeRecord(**kwargs)


def _env_observed() -> ObservedEnvironment:
    return ObservedEnvironment(
        instance_identity="mysql-8039-local",
        version="8.0.39",
        vendor="mysql",
        build_id="20250715",
        engine="innodb",
        sql_mode_tokens=("NO_ENGINE_SUBSTITUTION", "ONLY_FULL_GROUP_BY", "STRICT_ALL_TABLES"),
        character_set="utf8mb4",
        collation="utf8mb4_bin",
        time_zone="+00:00",
        optimizer_switch="index_merge=on,mrr=off",
    )


def _manifest(**overrides) -> EnvironmentManifest:
    kwargs = dict(
        observed_environment=_env_observed(),
        server_uuid=UUID,
        python_version="3.11.9",
        os_platform="Linux-5.15.0-x86_64",
        driver_name="pymysql",
        driver_version="1.1.2",
        adapter_version="mysql80-text-v1",
        mapping_version="mysql80-pymysql112-exact-v1",
        build_id="8.0.39-certified-build-20250715",
        build_id_source=BuildIdSource.CONFIGURED,
        sanitized_config_hash=HEX64,
        probes=(_probe(),),
    )
    kwargs.update(overrides)
    return EnvironmentManifest(**kwargs)


def _stage(**overrides) -> StageObservation:
    kwargs = dict(
        side=Side.A,
        stage=StageObservationKind.INSERT,
        ordinal=0,
        connection_id="conn-1",
        actual_database="tc_a",
        session_id=None,
        sql_hash=HEX64,
        sql_ref="attempts/attempt-001/sql/insert-0.txt",
        diagnostics_ref=None,
        field_metadata_ref=None,
        detail="",
    )
    kwargs.update(overrides)
    return StageObservation(**kwargs)


def _event(**overrides) -> OwnershipEvent:
    kwargs = dict(
        seq=1,
        prev_event_hash=OWNERSHIP_GENESIS_HASH,
        run_id="run-20260906-1",
        event_kind=OwnershipEventKind.RUN_LOCK_ACQUIRED,
    )
    kwargs.update(overrides)
    return OwnershipEvent(**kwargs)


def _run_manifest(**overrides) -> RunnerManifest:
    kwargs = dict(
        command=RunnerCommand.RUN,
        run_id="run-20260906-1",
        status=RunnerStatus.COMPLETE,
        requested=10,
        completed=9,
        comparable=8,
        match=6,
        candidate=2,
        inconclusive=1,
        not_applicable=1,
        leftover_objects=0,
        leftover_sessions=0,
        synthetic=True,
        evidence_profile=RUNNER_EVIDENCE_PROFILE,
        tool_version="0.1.0",
        contract_versions=(("case", "1"), ("execution", "1"), ("oracle", "o1"), ("runner", "1")),
        refs=(
            ("environment", "environment.json"),
            ("ownership", "ownership.jsonl"),
            ("runner_manifest", "runner-manifest.json"),
            ("attempt:attempt-001", "attempts/attempt-001"),
        ),
        sanitized_config_hash=GOLDEN_TARGET_CONFIG_HASH,
    )
    kwargs.update(overrides)
    return RunnerManifest(**kwargs)


def _with_duplicate_key(doc: dict) -> bytes:
    """Raw bytes with the first top-level key emitted twice."""
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    first_colon = text.index(":")
    key = text[1:first_colon]  # includes its quotes
    return ("{" + key + ":null," + text[1:]).encode("utf-8")


# --------------------------------------------------------------------------
# Golden hashes against independent canonicalization
# --------------------------------------------------------------------------


def test_golden_target_config_canonical_bytes_and_hash():
    assert dump_target_config(_target()) == GOLDEN_TARGET_CONFIG_CANONICAL
    assert hashlib.sha256(GOLDEN_TARGET_CONFIG_CANONICAL).hexdigest() == GOLDEN_TARGET_CONFIG_HASH


def test_golden_ownership_event_content_hash():
    event = _event()
    assert event._content_obj() == json.loads(GOLDEN_EVENT_CONTENT_CANONICAL.decode())
    assert event.content_hash == GOLDEN_EVENT_CONTENT_HASH
    # The hash never covers itself.
    assert "content_hash" not in event._content_obj()
    assert "content_hash" in event.to_obj()


def test_sanitized_config_hash_derivation_documented_in_contract():
    # The contract defines sanitized_config_hash as sha256 over the canonical
    # TargetConfig.to_obj() bytes; derived here with independent tooling.
    assert hashlib.sha256(_canon_independent(_target().to_obj())).hexdigest() == (
        GOLDEN_TARGET_CONFIG_HASH
    )


# --------------------------------------------------------------------------
# Round trips through dump -> load for every model
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model,dump,load",
    [
        (_tls(), dump_tls_config, load_tls_config),
        (_target(), dump_target_config, load_target_config),
        (_probe(), dump_probe_record, load_probe_record),
    ],
)
def test_roundtrip_small_models(model, dump, load):
    assert load(dump(model)) == model


def test_roundtrip_target_config_from_hand_written_doc():
    target = decode_target_config(copy.deepcopy(TARGET_DOC))
    assert load_target_config(dump_target_config(target)) == target


def test_roundtrip_environment_manifest_from_hand_written_doc():
    manifest = decode_environment_manifest(copy.deepcopy(MANIFEST_DOC))
    assert load_environment_manifest(dump_environment_manifest(manifest)) == manifest


def test_roundtrip_stage_observation_from_hand_written_doc():
    stage = decode_stage_observation(copy.deepcopy(STAGE_DOC))
    assert load_stage_observation(dump_stage_observation(stage)) == stage


def test_roundtrip_ownership_event_from_hand_written_doc():
    event = decode_ownership_event(copy.deepcopy(EVENT_DOC))
    assert load_ownership_event(dump_ownership_event(event)) == event


def test_roundtrip_runner_manifest_from_hand_written_doc():
    manifest = decode_runner_manifest(copy.deepcopy(RUNNER_MANIFEST_DOC))
    assert load_runner_manifest(dump_runner_manifest(manifest)) == manifest
    # Normalized pair order keeps construction-order differences equal.
    reordered = _run_manifest(
        refs=(
            ("attempt:attempt-001", "attempts/attempt-001"),
            ("environment", "environment.json"),
            ("runner_manifest", "runner-manifest.json"),
            ("ownership", "ownership.jsonl"),
        ),
        contract_versions=(("runner", "1"), ("case", "1"), ("oracle", "o1"), ("execution", "1")),
    )
    assert reordered == manifest


def test_target_config_uuid_normalization_is_canonical_everywhere():
    target = _target(expected_server_uuid="1F0E3D2C-4B5A-4678-9ABC-DEF012345678")
    assert target.expected_server_uuid == UUID
    assert json.loads(dump_target_config(target))["expected_server_uuid"] == UUID
    doc = copy.deepcopy(TARGET_DOC)
    doc["expected_server_uuid"] = "1F0E3D2C-4B5A-4678-9ABC-DEF012345678"
    assert decode_target_config(doc).expected_server_uuid == UUID


# --------------------------------------------------------------------------
# Unknown-field, duplicate-key and scalar strictness rejections
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "decode,doc",
    [
        (decode_tls_config, TLS_DOC),
        (decode_target_config, TARGET_DOC),
        (decode_probe_record, PROBE_DOC),
        (decode_environment_manifest, MANIFEST_DOC),
        (decode_stage_observation, STAGE_DOC),
        (decode_ownership_event, EVENT_DOC),
        (decode_runner_manifest, RUNNER_MANIFEST_DOC),
    ],
)
def test_every_model_rejects_unknown_fields(decode, doc):
    bogus = copy.deepcopy(doc)
    bogus["bogus_field"] = 1
    with pytest.raises(ContractError, match="unknown fields"):
        decode(bogus)


@pytest.mark.parametrize(
    "load,doc",
    [
        (load_tls_config, TLS_DOC),
        (load_target_config, TARGET_DOC),
        (load_probe_record, PROBE_DOC),
        (load_environment_manifest, MANIFEST_DOC),
        (load_stage_observation, STAGE_DOC),
        (load_ownership_event, EVENT_DOC),
        (load_runner_manifest, RUNNER_MANIFEST_DOC),
    ],
)
def test_every_model_rejects_duplicate_json_keys_in_raw_bytes(load, doc):
    with pytest.raises(ContractError, match="duplicate"):
        load(_with_duplicate_key(doc))


def test_non_canonical_integer_rejected_in_raw_bytes():
    raw = json.dumps(TARGET_DOC).replace('"port": 3306', '"port": -0').encode("utf-8")
    with pytest.raises(ContractError, match="non-canonical"):
        load_target_config(raw)


def test_bool_in_int_position_rejected_by_loader_and_constructor():
    raw = json.dumps(TARGET_DOC).replace('"port": 3306', '"port": true').encode("utf-8")
    with pytest.raises(ContractError, match="integer"):
        load_target_config(raw)
    with pytest.raises(ContractError, match="int"):
        _target(port=True)
    raw = json.dumps(RUNNER_MANIFEST_DOC).replace('"requested": 10', '"requested": true')
    with pytest.raises(ContractError, match="integer"):
        load_runner_manifest(raw.encode("utf-8"))
    with pytest.raises(ContractError, match="int"):
        _run_manifest(requested=True)


def test_float_rejected_in_raw_bytes():
    raw = json.dumps(TARGET_DOC).replace('"port": 3306', '"port": 3306.5').encode("utf-8")
    with pytest.raises(ContractError, match="float"):
        load_target_config(raw)


# --------------------------------------------------------------------------
# TargetConfig (design 6.3.1)
# --------------------------------------------------------------------------


def test_target_config_tcp_and_unix_socket_are_exclusive():
    assert load_target_config(dump_target_config(_target())) == _target()
    unix = _target(host=None, port=None, unix_socket="/tmp/mysql-test.sock")
    assert load_target_config(dump_target_config(unix)) == unix
    with pytest.raises(ContractError, match="exactly one transport"):
        _target(unix_socket="/tmp/mysql-test.sock")
    with pytest.raises(ContractError, match="exactly one transport"):
        _target(host=None, port=None)
    with pytest.raises(ContractError, match="excludes host/port"):
        _target(port=None, unix_socket="/tmp/mysql-test.sock")
    with pytest.raises(ContractError, match="excludes host/port"):
        _target(host=None, unix_socket="/tmp/mysql-test.sock")


@pytest.mark.parametrize("port", [0, 65536, -1])
def test_target_config_port_range(port):
    with pytest.raises(ContractError, match="port"):
        _target(port=port)


def test_target_config_bad_uuid_rejected():
    for value in ("replace-with-test-server-uuid", "", "4b5a-4678-9abc-def012345678"):
        with pytest.raises(ContractError, match="UUID"):
            _target(expected_server_uuid=value)


def test_target_config_prefix_and_dedication_enforced():
    with pytest.raises(ContractError, match="database_prefix"):
        _target(database_prefix="test_")
    with pytest.raises(ContractError, match="dedicated_test_instance"):
        _target(dedicated_test_instance=False)


def test_target_config_tls_mode_rules():
    with pytest.raises(ContractError, match="VERIFY_IDENTITY requires"):
        _tls(mode=TlsMode.VERIFY_IDENTITY, ca_file=None)
    with pytest.raises(ContractError, match="DISABLED"):
        _tls(mode=TlsMode.DISABLED, ca_file="/etc/typecheck/ca.pem")
    disabled = _tls(mode=TlsMode.DISABLED, ca_file=None)
    assert decode_tls_config(disabled.to_obj()) == disabled


def test_target_config_adapter_value_enforced():
    with pytest.raises(ContractError, match="adapter"):
        _target(adapter="mysql80-text-v2")
    with pytest.raises(ContractError, match="adapter"):
        decode_target_config({**copy.deepcopy(TARGET_DOC), "adapter": "mysql57-text-v1"})


def test_target_config_password_env_rules():
    with pytest.raises(ContractError, match="password"):
        _target(password_env="password")
    with pytest.raises(ContractError, match="NUL"):
        _target(password_env="TYPECHECK\x00PASSWORD")
    with pytest.raises(ContractError, match="non-empty"):
        _target(password_env="")
    with pytest.raises(ContractError, match="128"):
        _target(user="u" * 129)


def test_target_config_has_no_password_field_and_secrets_never_serialize():
    secret = "opensesame-hunter2"
    dumped = dump_target_config(_target())
    assert b"opensesame" not in dumped
    keys = set(json.loads(dumped))
    assert "password" not in keys
    # A password injected into the document is an unknown field.
    with pytest.raises(ContractError, match="unknown fields"):
        decode_target_config({**copy.deepcopy(TARGET_DOC), "password": secret})
    # The model has no attribute that could carry a secret.
    assert not hasattr(_target(), "password")
    assert not hasattr(_target(), "dsn")


def test_target_config_64kib_envelope_cap_before_parsing():
    oversized = b" " * (TARGET_CONFIG_MAX_BYTES + 1)
    with pytest.raises(ContractError, match="TARGET_CONFIG_MAX_BYTES"):
        load_target_config(oversized)
    with pytest.raises(ContractError, match="TARGET_CONFIG_MAX_BYTES"):
        load_target_config(" " * (TARGET_CONFIG_MAX_BYTES + 1))


# --------------------------------------------------------------------------
# EnvironmentManifest (design 6.2.1)
# --------------------------------------------------------------------------


def test_environment_manifest_build_id_source_semantics():
    for source in (BuildIdSource.CONFIGURED, BuildIdSource.OBSERVED):
        manifest = _manifest(build_id_source=source)
        assert load_environment_manifest(dump_environment_manifest(manifest)) == manifest
        assert json.loads(dump_environment_manifest(manifest))["build_id_source"] == source.value
    with pytest.raises(ContractError, match="BuildIdSource"):
        _manifest(build_id_source="server-measured")
    with pytest.raises(ContractError, match="unknown value"):
        decode_environment_manifest({**copy.deepcopy(MANIFEST_DOC), "build_id_source": "observed!"})


def test_environment_manifest_driver_and_probes_validation():
    with pytest.raises(ContractError, match="driver_name"):
        _manifest(driver_name="psycopg")
    with pytest.raises(ContractError, match="tuple"):
        _manifest(probes=[_probe()])
    with pytest.raises(ContractError, match="ProbeRecord"):
        _manifest(probes=("cancel-capability",))
    with pytest.raises(ContractError, match="64-hex"):
        _manifest(sanitized_config_hash="ZZ" * 32)
    probes = (
        _probe(probe_id="cancel-capability", outcome=ProbeOutcome.PASS),
        _probe(probe_id="innodb-engine", outcome=ProbeOutcome.FAIL, detail="disabled"),
    )
    manifest = _manifest(probes=probes)
    restored = load_environment_manifest(dump_environment_manifest(manifest))
    assert restored == manifest
    assert restored.probes[1].outcome is ProbeOutcome.FAIL


def test_probe_record_validation():
    assert load_probe_record(dump_probe_record(_probe())) == _probe()
    with pytest.raises(ContractError, match="probe_id"):
        _probe(probe_id="")
    with pytest.raises(ContractError, match="ProbeOutcome"):
        _probe(outcome="MAYBE")
    with pytest.raises(ContractError, match="512"):
        _probe(detail="x" * 513)
    assert _probe(detail="").detail == ""
    assert decode_probe_record({**copy.deepcopy(PROBE_DOC), "detail": ""}).detail == ""


# --------------------------------------------------------------------------
# StageObservation (design 6.2.1)
# --------------------------------------------------------------------------


def test_stage_observation_control_plane_side_none_is_legal():
    control = _stage(side=None, stage=StageObservationKind.PROBE, actual_database=None)
    assert load_stage_observation(dump_stage_observation(control)) == control


def test_stage_observation_controlled_relpath_validation():
    for bad in (
        "/abs/environment.json",  # absolute path
        "a/../b.json",  # .. component
        "./relative.json",  # . component
        "back\\slash.json",  # backslash
        "attempts//x",  # empty component
        "x" * 513,  # too long
        "with\0nul.json",  # NUL
        "",  # empty
    ):
        with pytest.raises(ContractError):
            _stage(sql_ref=bad)
    with pytest.raises(ContractError, match="relative"):
        _stage(diagnostics_ref="/etc/passwd")
    with pytest.raises(ContractError, match="512"):
        _stage(field_metadata_ref="a/" + "x" * 512)
    good = _stage(
        sql_ref="attempts/attempt-001/sql/select-0.txt",
        diagnostics_ref="attempts/attempt-001/diagnostics/select-0.txt",
        field_metadata_ref="attempts/attempt-001/fields/select-0.json",
    )
    assert load_stage_observation(dump_stage_observation(good)) == good


def test_stage_observation_field_validation():
    with pytest.raises(ContractError, match="ordinal"):
        _stage(ordinal=-1)
    with pytest.raises(ContractError, match="StageObservationKind"):
        _stage(stage="MAYBE")
    with pytest.raises(ContractError, match="64-hex"):
        _stage(sql_hash="nothex")
    with pytest.raises(ContractError, match="non-empty"):
        _stage(connection_id="")
    with pytest.raises(ContractError, match="512"):
        _stage(detail="x" * 513)


# --------------------------------------------------------------------------
# OwnershipEvent and the append-only journal (design 6.2.1/6.2.3)
# --------------------------------------------------------------------------


def test_ownership_event_derived_content_hash_mismatch_rejected():
    with pytest.raises(ContractError, match="content_hash"):
        _event(content_hash=OTHER_HEX64)
    with pytest.raises(ContractError, match="content_hash"):
        decode_ownership_event({**copy.deepcopy(EVENT_DOC), "content_hash": OTHER_HEX64})
    # Tampered payload with a stale hash is rejected on both paths.
    with pytest.raises(ContractError, match="content_hash"):
        _event(run_id="run-other", content_hash=GOLDEN_EVENT_CONTENT_HASH)
    tampered = copy.deepcopy(EVENT_DOC)
    tampered["object_name"] = "tc_run1_att1_a"
    with pytest.raises(ContractError, match="content_hash"):
        decode_ownership_event(tampered)


def test_ownership_event_field_validation():
    with pytest.raises(ContractError, match="seq"):
        _event(seq=0)
    with pytest.raises(ContractError, match="64-hex"):
        _event(prev_event_hash="nothex")
    with pytest.raises(ContractError, match="UUID"):
        _event(server_uuid="not-a-uuid")
    assert _event(server_uuid="1F0E3D2C-4B5A-4678-9ABC-DEF012345678").server_uuid == UUID
    with pytest.raises(ContractError, match="256"):
        _event(object_name="x" * 257)
    with pytest.raises(ContractError, match="session_generation"):
        _event(session_generation=-1)
    assert _event(session_generation=0).session_generation == 0
    with pytest.raises(ContractError, match="OwnershipEventKind"):
        _event(event_kind="MAYBE")


def test_ownership_journal_honest_roundtrip_and_layout():
    first = _event()
    second = _event(
        seq=2,
        prev_event_hash=first.content_hash,
        event_kind=OwnershipEventKind.ATTEMPT_ALLOCATED,
        attempt_id="attempt-001",
        token="tok-123",
        session_generation=0,
    )
    journal = dump_ownership_journal((first, second))
    assert journal.endswith(b"\n")
    assert not journal.endswith(b"\n\n")
    assert journal.count(b"\n") == 2
    lines = journal.splitlines()
    assert json.loads(lines[0])["seq"] == 1
    restored = load_ownership_journal(journal)
    assert restored == (first, second)
    assert load_ownership_journal(journal.decode("utf-8")) == (first, second)
    # str input accepts the same content.


def test_ownership_journal_rejects_seq_gap_and_stale_prev_hash():
    first = _event()
    gap = _event(
        seq=3,
        prev_event_hash=first.content_hash,
        event_kind=OwnershipEventKind.ATTEMPT_ALLOCATED,
    )
    with pytest.raises(ContractError, match="seq"):
        load_ownership_journal(dump_ownership_journal((first, gap)))
    stale = _event(
        seq=2,
        prev_event_hash=OWNERSHIP_GENESIS_HASH,  # must link to first.content_hash
        event_kind=OwnershipEventKind.ATTEMPT_ALLOCATED,
    )
    with pytest.raises(ContractError, match="prev_event_hash"):
        load_ownership_journal(dump_ownership_journal((first, stale)))
    # A first event that does not use the genesis hash is rejected.
    orphan = _event(prev_event_hash=OTHER_HEX64)
    with pytest.raises(ContractError, match="prev_event_hash"):
        load_ownership_journal(dump_ownership_journal((orphan,)))


def test_ownership_journal_rejects_tampered_payload_with_stale_hash():
    first = _event()
    journal = dump_ownership_journal((first,))
    doc = json.loads(journal.decode("utf-8"))
    doc["run_id"] = "run-tampered"
    tampered = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with pytest.raises(ContractError, match="content_hash"):
        load_ownership_journal(tampered)


def test_ownership_journal_empty_and_defensive_limits():
    assert load_ownership_journal(b"") == ()
    assert load_ownership_journal("  \n\t ") == ()
    with pytest.raises(ContractError, match="invalid JSON"):
        load_ownership_journal(b"{not json}\n")
    first = _event()
    oversized = dump_ownership_journal((first,)).replace(
        b'"run_id":"run-20260906-1"', b'"run_id":"' + b"x" * (JOURNAL_MAX_EVENT_BYTES + 1) + b'"'
    )
    with pytest.raises(ContractError, match="JOURNAL_MAX_EVENT_BYTES"):
        load_ownership_journal(oversized)
    assert dump_ownership_journal(()) == b""


# --------------------------------------------------------------------------
# RunnerManifest (design 6.2.1/6.6)
# --------------------------------------------------------------------------


def test_runner_manifest_count_invariants():
    with pytest.raises(ContractError, match="match \\+ candidate"):
        _run_manifest(comparable=9)
    with pytest.raises(ContractError, match="requested"):
        _run_manifest(completed=11)
    with pytest.raises(ContractError, match="completed"):
        _run_manifest(comparable=10, match=8, candidate=2)
    for counts in (
        {"match": -1},
        {"candidate": -1},
        {"requested": -1},
        {"leftover_objects": -1},
        {"leftover_sessions": -1},
    ):
        with pytest.raises(ContractError, match=">= 0"):
            _run_manifest(**counts)
    # Boundary values are legal.
    zero = _run_manifest(
        requested=0,
        completed=0,
        comparable=0,
        match=0,
        candidate=0,
        inconclusive=0,
        not_applicable=0,
    )
    assert load_runner_manifest(dump_runner_manifest(zero)) == zero


def test_runner_manifest_evidence_profile_is_fixed():
    assert RUNNER_EVIDENCE_PROFILE == "typecheck-full-evidence-v1"
    with pytest.raises(ContractError, match="evidence_profile"):
        _run_manifest(evidence_profile="typecheck-full-evidence-v2")
    with pytest.raises(ContractError, match="evidence_profile"):
        decode_runner_manifest(
            {**copy.deepcopy(RUNNER_MANIFEST_DOC), "evidence_profile": "legacy"}
        )


def test_runner_manifest_ref_name_validation():
    with pytest.raises(ContractError, match="unknown ref name"):
        _run_manifest(refs=(("bogus", "bogus.json"),))
    with pytest.raises(ContractError, match="unknown ref name"):
        _run_manifest(refs=(("attempt:", "attempts/"),))
    assert _run_manifest().ref("attempt:attempt-001") == "attempts/attempt-001"
    assert _run_manifest().ref("environment") == "environment.json"
    assert _run_manifest().ref("trace") is None
    with pytest.raises(ContractError, match="duplicate ref name"):
        _run_manifest(
            refs=(
                ("environment", "environment.json"),
                ("environment", "environment-2.json"),
            )
        )
    # Ref values are controlled relative paths.
    with pytest.raises(ContractError, match="relative"):
        _run_manifest(refs=(("environment", "/etc/typecheck/environment.json"),))
    with pytest.raises(ContractError, match="\\.\\."):
        _run_manifest(refs=(("environment", "../escape/environment.json"),))


def test_runner_manifest_contract_versions_validation():
    manifest = _run_manifest()
    assert manifest.contract_versions == (
        ("case", "1"),
        ("execution", "1"),
        ("oracle", "o1"),
        ("runner", "1"),
    )
    assert manifest.contract_version("oracle") == "o1"
    assert json.loads(dump_runner_manifest(manifest))["contract_versions"] == {
        "case": "1",
        "execution": "1",
        "oracle": "o1",
        "runner": "1",
    }
    with pytest.raises(ContractError, match="unknown contract name"):
        _run_manifest(
            contract_versions=(("case", "1"), ("execution", "1"), ("oracle", "o1"), ("d1", "1"))
        )
    with pytest.raises(ContractError, match="missing contract names"):
        _run_manifest(
            contract_versions=(("case", "1"), ("execution", "1"), ("runner", "1"))
        )
    with pytest.raises(ContractError, match="duplicate contract name"):
        _run_manifest(
            contract_versions=(
                ("case", "1"),
                ("case", "2"),
                ("execution", "1"),
                ("oracle", "o1"),
                ("runner", "1"),
            )
        )
    with pytest.raises(ContractError, match="non-empty"):
        _run_manifest(
            contract_versions=(("case", ""), ("execution", "1"), ("oracle", "o1"), ("runner", "1"))
        )
    with pytest.raises(ContractError, match="missing required field"):
        decode_runner_manifest(
            {
                **copy.deepcopy(RUNNER_MANIFEST_DOC),
                "contract_versions": {"case": "1", "execution": "1", "oracle": "o1"},
            }
        )
    with pytest.raises(ContractError, match="unknown fields"):
        decode_runner_manifest(
            {
                **copy.deepcopy(RUNNER_MANIFEST_DOC),
                "contract_versions": {
                    "case": "1",
                    "execution": "1",
                    "oracle": "o1",
                    "runner": "1",
                    "d1": "1",
                },
            }
        )


def test_runner_manifest_status_command_stop_reason_and_hex64():
    with pytest.raises(ContractError, match="RunnerStatus"):
        _run_manifest(status="FINISHED")
    with pytest.raises(ContractError, match="RunnerCommand"):
        _run_manifest(command="DEPLOY")
    partial = _run_manifest(
        status=RunnerStatus.PARTIAL, stop_reason="cancel requested by user"
    )
    assert load_runner_manifest(dump_runner_manifest(partial)) == partial
    with pytest.raises(ContractError, match="128"):
        _run_manifest(stop_reason="x" * 129)
    with pytest.raises(ContractError, match="64-hex"):
        _run_manifest(sanitized_config_hash="nothex")


# --------------------------------------------------------------------------
# Import-time safety
# --------------------------------------------------------------------------


def test_module_import_performs_no_io_and_knows_no_driver():
    import subprocess
    import sys

    import mtsql_typecheck.contracts.runner as runner_module

    source = open(runner_module.__file__, "r", encoding="utf-8").read()
    assert "import pymysql" not in source
    # The sys.modules check must run in a fresh interpreter: the shared pytest
    # process legitimately imports pymysql elsewhere (adapters unit tests),
    # which would make an in-process assertion order-dependent.
    code = (
        "import sys; import mtsql_typecheck.contracts.runner; "
        "assert 'pymysql' not in sys.modules, 'contracts.runner pulled pymysql'"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_runner_evidence_profile_matches_oracle_full_profile():
    # The two constants must stay identical by value; this test makes the
    # keep-in-sync convention (comment in contracts/runner.py) enforceable.
    from mtsql_typecheck.contracts.oracle import EVIDENCE_PROFILE_FULL
    from mtsql_typecheck.contracts.runner import RUNNER_EVIDENCE_PROFILE

    assert RUNNER_EVIDENCE_PROFILE == EVIDENCE_PROFILE_FULL
