"""TargetConfig -> ConnectionParams mapping (D3 design 6.3.1, Phase 2).

Pure mapping layer: no I/O except reading the password from the caller
supplied environment mapping (default ``os.environ``).  Secrets never appear
in any serializable structure here; ``TargetConfig`` carries only the
environment-variable *name*.

Import discipline (D3 design: offline modules stay driver-free): importing
this module imports neither PyMySQL nor the adapters package.  The
``adapters.base`` import (driver-free by construction) happens inside
:func:`connection_params_from_target` so the module import itself performs no
adapter or driver import at all.

Schema=1 notes (surfaced, not improvised):

- ``TargetConfig`` carries no timeout fields, so the frozen
  ``ConnectionParams`` defaults (10s connect/read/write) apply; explicit
  keyword overrides exist for callers that own a timeout policy.  If a later
  schema adds timeout fields, this mapping must be extended rather than
  silently defaulted.
- The contract ``TlsMode`` vocabulary is ``VERIFY_IDENTITY``/``DISABLED``
  only.  The design text also mentions REQUIRED/VERIFY_CA modes; until the
  contract grows them, this mapping refuses anything but the two contract
  members (``TlsConfig`` validation already enforces that upstream) and there
  is no REQUIRED/VERIFY_CA branch here.
- ``server_public_key`` stays ``False``: caching_sha2_password full
  authentication over an unverified channel is refused in Phase 2 scope
  (design 6.3.1); ``ConnectionParams.__post_init__`` re-checks it.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Mapping, Optional

from ..contracts.runner import TlsMode, TargetConfig

if TYPE_CHECKING:  # pragma: no cover - annotation-only import
    from ..adapters.base import ConnectionParams

__all__ = ["ConfigError", "connection_params_from_target"]


class ConfigError(Exception):
    """Typed configuration-mapping refusal (missing password env var, missing
    TLS material, invalid transport).  Message text names the offending item;
    no secret value is ever included."""


def connection_params_from_target(
    config: TargetConfig,
    *,
    env: Optional[Mapping[str, str]] = None,
    connect_timeout_s: Optional[int] = None,
    read_timeout_s: Optional[int] = None,
    write_timeout_s: Optional[int] = None,
) -> "ConnectionParams":
    """Map a validated :class:`TargetConfig` to driver-free
    :class:`ConnectionParams`.

    - transport ``host``+``port`` -> TCP, ``unix_socket`` -> socket (mutual
      exclusivity is already enforced by ``TargetConfig``);
    - ``TlsMode.DISABLED`` -> no CA file, identity verification off;
      ``TlsMode.VERIFY_IDENTITY`` -> CA file required (``TlsConfig`` enforces
      it, re-checked here), identity verification on.  No automatic
      downgrade exists at any layer;
    - the password is read once from ``config.password_env`` in the given
      environment mapping (default ``os.environ``); a missing variable raises
      :class:`ConfigError` naming the variable;
    - timeouts use the ``ConnectionParams`` frozen defaults unless explicitly
      overridden (``TargetConfig`` schema=1 carries no timeout fields).
    """

    from ..adapters.base import ConnectionParams

    if not isinstance(config, TargetConfig):
        raise ConfigError("connection_params_from_target needs a TargetConfig")

    environment: Mapping[str, str] = os.environ if env is None else env
    if config.password_env not in environment:
        raise ConfigError(
            f"password environment variable {config.password_env!r} is not set; "
            f"the target password is only read from that variable"
        )
    password = environment[config.password_env]
    if not isinstance(password, str):
        raise ConfigError(
            f"password environment variable {config.password_env!r} did not "
            f"resolve to a string"
        )

    if config.tls.mode is TlsMode.DISABLED:
        tls_ca_file: Optional[str] = None
        tls_verify_identity = False
    elif config.tls.mode is TlsMode.VERIFY_IDENTITY:
        if config.tls.ca_file is None or not config.tls.ca_file:
            raise ConfigError(
                "TlsMode.VERIFY_IDENTITY requires a configured ca_file; "
                "refusing to connect without TLS material (no downgrade)"
            )
        tls_ca_file = config.tls.ca_file
        tls_verify_identity = True
    else:  # pragma: no cover - TlsConfig validation rejects other members
        raise ConfigError(f"unsupported TLS mode {config.tls.mode!r}")

    kwargs: dict = {
        "user": config.user,
        "password": password,
        "tls_ca_file": tls_ca_file,
        "tls_verify_identity": tls_verify_identity,
        # caching_sha2_password RSA public-key fetch stays refused (Phase 2).
        "server_public_key": False,
    }
    if config.unix_socket is not None:
        kwargs["unix_socket"] = config.unix_socket
    else:
        kwargs["host"] = config.host
        kwargs["port"] = config.port
    if connect_timeout_s is not None:
        kwargs["connect_timeout_s"] = connect_timeout_s
    if read_timeout_s is not None:
        kwargs["read_timeout_s"] = read_timeout_s
    if write_timeout_s is not None:
        kwargs["write_timeout_s"] = write_timeout_s

    return ConnectionParams(**kwargs)
