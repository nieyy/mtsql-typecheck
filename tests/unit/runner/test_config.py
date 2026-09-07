"""Unit tests for the TargetConfig -> ConnectionParams mapping (D3 Phase 2).

The environment is always a local mapping passed explicitly; the real process
environment is never mutated.  No server, no driver import at test-module
scope beyond the deferred import inside the function under test.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from mtsql_typecheck.adapters.base import ConnectionParams
from mtsql_typecheck.contracts.runner import RUNNER_ADAPTER_ID, TlsConfig, TlsMode, TargetConfig
from mtsql_typecheck.runner.config import ConfigError, connection_params_from_target

TEST_UUID = "3f0a41c2-6b1e-11ef-9d3a-0242ac110002"
PASSWORD_ENV = "TYPECHECK_TEST_PASSWORD_ENV"


def make_target(**overrides) -> TargetConfig:
    fields = {
        "adapter": RUNNER_ADAPTER_ID,
        "host": "mysql-test.example.internal",
        "port": 3306,
        "unix_socket": None,
        "user": "typecheck",
        "password_env": PASSWORD_ENV,
        "expected_server_uuid": TEST_UUID,
        "build_id": "certified-build-1",
        "database_prefix": "tc_",
        "dedicated_test_instance": True,
        "tls": TlsConfig(TlsMode.DISABLED, None),
    }
    fields.update(overrides)
    return TargetConfig(**fields)


TCP_ENV = {PASSWORD_ENV: "secret-value"}


def test_tcp_transport_maps_host_and_port():
    params = connection_params_from_target(make_target(), env=TCP_ENV)
    assert isinstance(params, ConnectionParams)
    assert params.host == "mysql-test.example.internal"
    assert params.port == 3306
    assert params.unix_socket is None


def test_socket_transport_maps_unix_socket():
    params = connection_params_from_target(
        make_target(host=None, port=None, unix_socket="/var/run/mysqld/mysqld.sock"),
        env=TCP_ENV,
    )
    assert params.unix_socket == "/var/run/mysqld/mysqld.sock"
    assert params.host is None
    assert params.port is None


def test_password_resolved_from_the_given_env_mapping():
    params = connection_params_from_target(make_target(), env=TCP_ENV)
    assert params.password == "secret-value"
    assert params.user == "typecheck"


def test_missing_password_env_names_the_variable_and_leaks_no_secret():
    with pytest.raises(ConfigError) as excinfo:
        connection_params_from_target(make_target(), env={})
    assert PASSWORD_ENV in str(excinfo.value)
    assert "secret-value" not in str(excinfo.value)


def test_missing_password_env_against_the_real_environment_errors():
    # A variable name that must not exist in the real process environment;
    # the default env source is os.environ and no mutation happens here.
    env_name = "TYPECHECK_DEFINITELY_UNSET_9f3a2b7c"
    target = make_target(password_env=env_name)
    with pytest.raises(ConfigError) as excinfo:
        connection_params_from_target(target)
    assert env_name in str(excinfo.value)


def test_tls_disabled_maps_to_no_ca_and_no_identity_check():
    params = connection_params_from_target(make_target(), env=TCP_ENV)
    assert params.tls_ca_file is None
    assert params.tls_verify_identity is False


def test_tls_verify_identity_maps_ca_file_and_identity_check():
    target = make_target(
        tls=TlsConfig(TlsMode.VERIFY_IDENTITY, "/etc/typecheck/ca.pem")
    )
    params = connection_params_from_target(target, env=TCP_ENV)
    assert params.tls_ca_file == "/etc/typecheck/ca.pem"
    assert params.tls_verify_identity is True


def test_server_public_key_stays_refused():
    params = connection_params_from_target(make_target(), env=TCP_ENV)
    assert params.server_public_key is False


def test_timeouts_default_to_connectionparams_defaults():
    # TargetConfig schema=1 carries no timeout fields; the frozen
    # ConnectionParams defaults apply (surfaced in the module docstring).
    params = connection_params_from_target(make_target(), env=TCP_ENV)
    assert params.connect_timeout_s == 10
    assert params.read_timeout_s == 10
    assert params.write_timeout_s == 10


def test_timeouts_can_be_overridden_explicitly():
    params = connection_params_from_target(
        make_target(), env=TCP_ENV, connect_timeout_s=3, read_timeout_s=7, write_timeout_s=9
    )
    assert (params.connect_timeout_s, params.read_timeout_s, params.write_timeout_s) == (3, 7, 9)


def test_non_target_config_is_refused():
    with pytest.raises(ConfigError):
        connection_params_from_target("not a target", env=TCP_ENV)  # type: ignore[arg-type]


def test_uuid_is_canonicalized_by_the_contract_before_mapping():
    target = make_target(expected_server_uuid=TEST_UUID.upper())
    assert target.expected_server_uuid == TEST_UUID  # canonical, lowercase


# ---------------------------------------------------------------------------
# Import hygiene: a fresh interpreter importing runner.config must not pull
# PyMySQL or the adapters package at module import time.
# ---------------------------------------------------------------------------


def test_fresh_import_of_runner_config_is_driver_and_adapter_free():
    code = (
        "import sys;"
        "import mtsql_typecheck.runner.config as c;"
        "assert 'pymysql' not in sys.modules, 'pymysql imported';"
        "adapter_mods = [m for m in sys.modules if m.startswith('mtsql_typecheck.adapters')];"
        "assert not adapter_mods, adapter_mods"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
