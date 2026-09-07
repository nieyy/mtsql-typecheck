"""Shared fakes for the Phase 5 controller/CLI tests (fakes only, no MySQL).

Independent of ``test_execution.py`` (that file is owned by the Phase 4
reconciliation work); everything here is built from the shared
``execution_fakes`` primitives.

- ``make_target_config`` / ``FakeProbeSource``: a driver-free preflight path
  (``run_preflight`` runs against the fake probe source).
- ``AttemptFakes``: one scripted ``MySQLExecutionPort`` per attempt (4 fake
  adapters: prepare A/B, query A/B) -- A answers the declared rows; B
  answers the declared rows too unless a canned mismatch result is given.
- ``InlineDispatcher``: ExecutionPort-shaped adapter so the controller loop
  runs against a real port without a subprocess.
- ``make_bundle``: a minimal D1 bundle directory (manifest + case.json).
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Mapping, Optional, Tuple

from execution_fakes import (
    BUILD_ID,
    DEFAULT_FACTS,
    FakeAdapter,
    FakeCatalog,
    FakeMappedColumn,
    InMemoryJournal,
    SERVER_UUID,
    StubClock,
    dec_value,
    int_value,
    make_payload,
    null_value,
    readback_rows_for,
)

from mtsql_typecheck.contracts.case import (
    CasePayload,
    DecimalValue,
    IntegerValue,
    NullValue,
)
from mtsql_typecheck.contracts.codec import case_id_of
from mtsql_typecheck.contracts.runner import (
    RUNNER_ADAPTER_ID,
    TlsConfig,
    TlsMode,
    TargetConfig,
)
from mtsql_typecheck.generation.bundle import case_doc_bytes
from mtsql_typecheck.runner.execution import MySQLExecutionPort
from mtsql_typecheck.runner.preflight import ProbeRuntimeIdentity

SELECT_COLUMN = FakeMappedColumn(ordinal=0, alias="c0", type_code=253, flags=0, scale=0)


def make_target_config(password_env: str = "MTTC_TEST_PW") -> TargetConfig:
    return TargetConfig(
        adapter=RUNNER_ADAPTER_ID,
        host="127.0.0.1",
        port=3306,
        unix_socket=None,
        user="tc-runner",
        password_env=password_env,
        expected_server_uuid=SERVER_UUID,
        build_id=BUILD_ID,
        database_prefix="tc_",
        dedicated_test_instance=True,
        tls=TlsConfig(TlsMode.DISABLED, None),
    )


class FakeProbeSource:
    """Read-only probe source answering the shared default facts."""

    def __init__(self, *, facts: Optional[Mapping[str, str]] = None) -> None:
        self._facts = dict(DEFAULT_FACTS)
        if facts is not None:
            self._facts.update(facts)

    def fetch_environment_facts(self) -> Mapping[str, str]:
        return dict(self._facts)

    def runtime_identity(self) -> ProbeRuntimeIdentity:
        return ProbeRuntimeIdentity(
            python_version="3.11.0",
            os_platform="test-platform",
            driver_name="pymysql",
            driver_version="1.1.2",
            adapter_version="test-adapter",
            mapping_version="mysql-text-1",
        )

    def observed_build_id(self) -> Optional[str]:
        return BUILD_ID


def result_rows_for(payload: CasePayload) -> Tuple[Tuple[object, ...], ...]:
    """Canned SELECT packets exactly representing the payload's rows."""
    rows: list = []
    for row in payload.rows.rows:
        value = row.value
        if isinstance(value, NullValue):
            rows.append((null_value(),))
        elif isinstance(value, IntegerValue):
            rows.append((int_value(value.value),))
        elif isinstance(value, DecimalValue):
            rows.append((dec_value(value.coefficient, value.scale),))
        else:  # pragma: no cover - unexpected exact-value kind
            raise AssertionError(f"unexpected exact value {type(value).__name__}")
    return tuple(rows)


class AttemptFakes:
    """One scripted port for one attempt (fresh adapters/catalog/journal)."""

    def __init__(self, payload: CasePayload, *, b_result: Optional[Tuple[Tuple[object, ...], ...]] = None) -> None:
        self.payload = payload
        self.catalog = FakeCatalog(readback_rows=readback_rows_for(payload))
        self.clock = StubClock()
        self.journal = InMemoryJournal("controller-test")
        rows = result_rows_for(payload)
        self.adapters = [
            self._adapter(0, column_type=b"tinyint", select_columns=(SELECT_COLUMN,)),
            self._adapter(1, column_type=b"smallint", select_columns=(SELECT_COLUMN,)),
            self._adapter(
                2,
                column_type=b"smallint",
                select_columns=(SELECT_COLUMN,),
                default_result=rows,
            ),
            self._adapter(
                3,
                column_type=b"smallint",
                select_columns=(SELECT_COLUMN,),
                default_result=b_result if b_result is not None else rows,
            ),
        ]

    def _adapter(self, slot: int, **kwargs) -> FakeAdapter:
        return FakeAdapter(
            catalog=self.catalog,
            connection_id=10 + slot,
            facts=dict(DEFAULT_FACTS),
            **kwargs,
        )

    def build(self) -> MySQLExecutionPort:
        pool = list(self.adapters)

        def factory():
            if not pool:
                raise AssertionError("adapter factory exhausted: unexpected connection")
            adapter = pool.pop(0)
            pool.append(adapter)
            return adapter

        return MySQLExecutionPort(
            adapter_factory=factory,
            journal=self.journal,
            clock=self.clock,
        )


class InlineDispatcher:
    """ExecutionPort-shaped adapter over a real in-process port.

    Also exposes the design-6.6 evidence streaming the controller pulls after
    an attempt is sealed (stage observations plus the raw payload side
    table), straight from the port's introspection surface.
    """

    def __init__(self, port) -> None:
        self._port = port

    def prepare(self, request, control):
        return self._port.prepare(request, control)

    def execute(self, request, expectation, control):
        return self._port.execute(request, expectation, control)

    def cancel_and_wait(self, attempt_id: str, grace_seconds: float):
        return self._port.cancel_and_wait(attempt_id, grace_seconds)

    def observations(self, attempt_id: str):
        return list(self._port.stage_observations(attempt_id))

    def payloads(self, attempt_id: str):
        return dict(self._port.payloads(attempt_id))

    def close(self) -> None:
        pass


class FailingDispatcher:
    """A dispatcher whose prepare always fails without salvage evidence."""

    def __init__(self, message: str = "simulated dispatcher failure") -> None:
        self.message = message

    def prepare(self, request, control):
        from mtsql_typecheck.runner.controller import DispatcherError

        raise DispatcherError(self.message)

    def execute(self, request, expectation, control):  # pragma: no cover
        raise AssertionError("execute must not be reached")

    def cancel_and_wait(self, attempt_id: str, grace_seconds: float):  # pragma: no cover
        return None  # the simulated worker cannot confirm termination

    def close(self) -> None:
        pass


def make_bundle(
    root: Path,
    payloads: Tuple[CasePayload, ...],
    *,
    manifest_bytes: bytes = b'{"schema_version": 1, "kind": "test-bundle"}\n',
) -> Path:
    """Write a minimal D1 bundle (manifest + one directory per case)."""
    (root / "cases").mkdir(parents=True)
    (root / "generation-manifest.json").write_bytes(manifest_bytes)
    for payload in payloads:
        case_id = case_id_of(payload)
        case_dir = root / "cases" / case_id
        case_dir.mkdir()
        (case_dir / "case.json").write_bytes(case_doc_bytes(payload, case_id))
    return root


def make_signed_payloads() -> Tuple[CasePayload, CasePayload]:
    """Two distinct single-row signed-widen payloads (match + candidate)."""
    return (
        make_payload(row_values=(IntegerValue(1),)),
        make_payload(row_values=(IntegerValue(7),)),
    )
