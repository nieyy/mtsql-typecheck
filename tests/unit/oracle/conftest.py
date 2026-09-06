"""Shared tooling for D2 oracle gate tests.

Fixtures are the reviewed golden bundles under ``tests/contract/fixtures/d2``;
they are loaded through the strict execution loaders after a deep copy, and a
tamper/reseal helper re-derives every affected hash so a negative test fails
for the intended "value differs" reason instead of an incidental hash
corruption.  Hash-corruption paths are tested separately and expect an
INCONCLUSIVE InputFailure from the entry layer.

The from-scratch builder constructs complete model bundles (payload, request,
expectation, runtime facts, evidence) without reusing any comparison logic, so
golden expectations never come from the code under test.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Optional

from mtsql_typecheck.contracts.case import (
    CasePayload,
    ColumnSpec,
    CompareOp,
    SideFacts,
    DecimalType,
    DecimalValue,
    EnvironmentRequirements,
    ExpectedBinding,
    IndexVariant,
    IntegerValue,
    NameMap,
    NullValue,
    ObservedEnvironment,
    QuerySpec,
    RuleRef,
    Rows,
    Row,
    SemverIdentity,
    SignedIntegerType,
    SignedIntName,
    StatementPhase,
    StatementReceipt,
    TableSpec,
    TemplateId,
    TypeFamily,
    REQUIRED_SQL_MODE_TOKENS,
)
from mtsql_typecheck.contracts.codec import canonical_json, case_id_of, decode_case_payload, sha256_hex
from mtsql_typecheck.contracts.execution import (
    ATTEMPT_BUDGET_MS,
    CleanupState,
    ExecutionOrder,
    ExecutionEvidence,
    AttemptExpectation,
    AttemptRequest,
    IsolationReceipt,
    QueryEvidence,
    QueryStatus,
    ResultColumn,
    ResultSet,
    ResultTerminal,
    ResultValue,
    ResultValueKind,
    RuntimeFacts,
    SelectPhase,
    SessionProfile,
    Side,
    SideContext,
    StatementDiagnostics,
    TerminalReceipt,
    TerminationState,
    TransactionIsolation,
    load_execution_evidence,
)
from mtsql_typecheck.contracts.oracle import ComparisonBudget, MAX_RESULT_BYTES, MAX_RESULT_ROWS
from mtsql_typecheck.generation.render import RenderPhase, render_pair
from mtsql_typecheck.rules.exact_numeric import derive_relation

D2_FIXTURES = Path(__file__).resolve().parents[2] / "contract" / "fixtures" / "d2"

_MATCH = "evidence_success_match"
_CANDIDATE = "evidence_success_candidate"


def load_d2_doc(name: str) -> dict:
    """Deep-copied fixture bundle without the ``_``-prefixed metadata keys."""
    doc = json.loads((D2_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    return {k: copy.deepcopy(v) for k, v in doc.items() if not k.startswith("_")}


def default_budget(**overrides) -> ComparisonBudget:
    fields = dict(
        deadline_ms=5000,
        max_rows=MAX_RESULT_ROWS,
        max_bytes=MAX_RESULT_BYTES,
        max_columns=5,
        witness_limit=20,
    )
    fields.update(overrides)
    return ComparisonBudget(**fields)


class Bundle:
    """A mutable request/expectation/evidence document triple.

    ``tamper`` addresses nested fields with dotted paths (list indices as
    plain integers).  ``reseal`` re-derives the affected content hashes
    (result payload hashes, binding hashes, request hash, evidence hash) so
    that a subsequent comparison fails for the tampered *value*, not because
    of a stale seal.
    """

    def __init__(self, name: str) -> None:
        doc = load_d2_doc(name)
        self.request: dict = doc["request"]
        self.expectation: Optional[dict] = doc.get("expectation")
        self.evidence: dict = doc["evidence"]

    # -- mutation ----------------------------------------------------------

    def tamper(self, path: str, value) -> None:
        roots = {
            "request": self.request,
            "expectation": self.expectation,
            "evidence": self.evidence,
        }
        parts = path.split(".")
        obj = roots[parts[0]]
        for part in parts[1:-1]:
            obj = obj[int(part)] if isinstance(obj, list) else obj[part]
        last = parts[-1]
        if isinstance(obj, list):
            obj[int(last)] = value
        else:
            obj[last] = value

    # -- resealing ---------------------------------------------------------

    def reseal(self) -> None:
        req, exp, ev = self.request, self.expectation, self.evidence
        # Result payload hashes and row counts.
        for side in ("a_query", "b_query"):
            query = ev.get(side)
            if isinstance(query, dict) and isinstance(query.get("result"), dict):
                result = query["result"]
                result["observed_row_count"] = len(result["rows"])
                result["payload_hash"] = sha256_hex(
                    canonical_json({"columns": result["columns"], "rows": result["rows"]})
                )
        if exp is not None:
            # The embedded expectation inside the evidence must stay identical.
            if isinstance(ev.get("expectation"), dict):
                ev["expectation"] = copy.deepcopy(exp)
            env_hash = sha256_hex(canonical_json(req["target_environment"]))
            nm_hash = sha256_hex(canonical_json(exp["name_map"]))
            case_id = case_id_of(decode_case_payload(req["payload"]))
            bindings = [exp["binding"]]
            for location in (ev.get("runtime_facts"), ev.get("a_query"), ev.get("b_query")):
                if isinstance(location, dict):
                    bindings.append(location["binding"])
            for binding in bindings:
                binding["case_id"] = case_id
                binding["environment_hash"] = env_hash
                binding["name_map_hash"] = nm_hash
            if isinstance(ev.get("isolation_receipt"), dict):
                ev["isolation_receipt"]["name_map_hash"] = nm_hash
            exp["request_hash"] = sha256_hex(canonical_json(req))
        ev["request_hash"] = sha256_hex(canonical_json(req))
        self.reseal_evidence_hash()

    def reseal_evidence_hash(self) -> None:
        """Re-derive only the evidence hash over the current content.

        A deliberately broken document stays broken (the loader rejects it
        downstream instead of resealing).
        """
        ev = self.evidence
        ev["evidence_hash"] = ""
        try:
            ev["evidence_hash"] = load_execution_evidence(ev).evidence_hash
        except Exception:
            pass

    # -- comparison entry --------------------------------------------------

    def compare(self, budget: Optional[ComparisonBudget] = None):
        from mtsql_typecheck.oracle.gates import compare_case_document

        return compare_case_document(
            self.request, self.expectation, self.evidence, budget or default_budget()
        )


def bundle_from_docs(docs: dict) -> Bundle:
    """Wrap already-built documents (e.g. from ``build_bundle``) in a Bundle."""
    bundle = Bundle.__new__(Bundle)
    bundle.request = docs["request"]
    bundle.expectation = docs.get("expectation")
    bundle.evidence = docs["evidence"]
    return bundle


def match_bundle() -> Bundle:
    return Bundle(_MATCH)


def candidate_bundle() -> Bundle:
    return Bundle(_CANDIDATE)


# --------------------------------------------------------------------------
# From-scratch bundle builder (no comparison logic reused)
# --------------------------------------------------------------------------

_ENV = ObservedEnvironment(
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

_PROFILE = SessionProfile(True, TransactionIsolation.REPEATABLE_READ)
_NAME_MAP = NameMap("tc_a", "tc_b", "t_a", "t_b")


def _family_of(type_spec) -> TypeFamily:
    if isinstance(type_spec, SignedIntegerType):
        return TypeFamily.SIGNED_INTEGER
    return TypeFamily.DECIMAL


def _result_value(value):
    """ExactValue (payload/readback) or ResultValue (observed) -> ResultValue."""
    if isinstance(value, ResultValue):
        return value
    if isinstance(value, NullValue):
        return ResultValue(ResultValueKind.NULL)
    if isinstance(value, IntegerValue):
        return ResultValue(ResultValueKind.INTEGER, int_value=value.value)
    return ResultValue(ResultValueKind.DECIMAL, coefficient=value.coefficient, scale=value.scale)


def _column_meta(type_spec):
    if isinstance(type_spec, SignedIntegerType):
        precision = {SignedIntName.TINYINT: 3, SignedIntName.SMALLINT: 5}.get(
            type_spec.name, 10
        )
        return (15, precision, 0)
    return (246, type_spec.precision, type_spec.scale)


def build_bundle(
    *,
    rule_id: str,
    rule_version: int = 1,
    a_type,
    b_type,
    template_id: TemplateId = TemplateId.Q1,
    predicate=None,
    row_values: tuple,
    a_readback: tuple,
    b_readback: tuple,
    a_result_rows: tuple,
    b_result_rows: tuple,
    run_id: str = "run-gates-1",
    attempt_id: str = "attempt-gates-1",
    result_row_budget: int = 1024,
    codec_version: str = "mysql-text-1",
):
    """Build a complete consistent bundle from first principles.

    ``row_values`` are ExactValue items (payload and side-A readback); side-B
    readbacks come from ``b_readback`` (e.g. scale-0 decimals for the
    integer-decimal rule).  Result rows are tuples of ExactValue per side.
    """
    rule_ref = RuleRef(rule_id, rule_version)
    payload_table = TableSpec(
        "t0",
        (
            ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
            ColumnSpec("v", a_type, True),
        ),
        ("rid",),
        IndexVariant.NONE,
    )
    payload_rows = Rows(tuple(Row(i + 1, value) for i, value in enumerate(row_values)))
    relation = derive_relation(rule_ref, a_type, b_type, template_id)
    from mtsql_typecheck.contracts.case import CasePayload

    payload = CasePayload(
        rule=rule_ref,
        a_type=a_type,
        b_type=b_type,
        table=payload_table,
        rows=payload_rows,
        query=(
            QuerySpec(template_id)
            if predicate is None
            else QuerySpec(template_id, predicate=predicate)
        ),
        relation=relation,
        environment=EnvironmentRequirements(
            "mysql80",
            "innodb",
            "same-instance",
            REQUIRED_SQL_MODE_TOKENS,
            "utf8mb4",
            "utf8mb4_bin",
            "+00:00",
        ),
        generator=SemverIdentity("g1", "1"),
        renderer=SemverIdentity("r1", "1"),
    )
    request = AttemptRequest(
        run_id=run_id,
        attempt_id=attempt_id,
        payload=payload,
        target_environment=_ENV,
        session_profile=_PROFILE,
        execution_order=ExecutionOrder.AB,
        result_row_budget=result_row_budget,
        result_byte_budget=MAX_RESULT_BYTES,
        time_budget_ms=ATTEMPT_BUDGET_MS,
        synthetic=True,
    )
    binding = ExpectedBinding(
        run_id=run_id,
        case_id=request.case_id,
        attempt_id=attempt_id,
        environment_hash=sha256_hex(canonical_json(_ENV.to_obj())),
        name_map_hash=sha256_hex(canonical_json(_NAME_MAP.to_obj())),
    )
    expectation = AttemptExpectation(
        binding=binding,
        request_hash=request.request_hash,
        codec_version=codec_version,
        execution_order=ExecutionOrder.AB,
        name_map=_NAME_MAP,
    )

    pair = render_pair(payload, _NAME_MAP)
    setup_diagnostics = []
    side_facts = {}
    side_queries = {}
    side_contexts = {}
    for side, side_type, readback_values, result_rows, statements in (
        (Side.A, a_type, a_readback, a_result_rows, pair.a),
        (Side.B, b_type, b_readback, b_result_rows, pair.b),
    ):
        label = str(side.value)
        database = _NAME_MAP.database_a if side is Side.A else _NAME_MAP.database_b
        select = None
        receipts = []
        counters: dict = {}
        for statement in statements:
            if statement.phase is RenderPhase.SELECT:
                select = statement
                continue
            phase = StatementPhase.DDL if statement.phase is RenderPhase.DDL else StatementPhase.INSERT
            ordinal = counters.get(phase, 0)
            counters[phase] = ordinal + 1
            receipts.append(
                StatementReceipt(phase, ordinal, statement.sql_hash, True, True)
            )
            setup_diagnostics.append(
                StatementDiagnostics(
                    side=side,
                    phase=phase,
                    ordinal=ordinal,
                    sql_hash=statement.sql_hash,
                    collected=True,
                    complete=True,
                    entries=(),
                )
            )
        actual_schema = TableSpec(
            "t0",
            (
                ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
                ColumnSpec("v", side_type, True),
            ),
            ("rid",),
            IndexVariant.NONE,
        )
        side_facts[label] = SideFacts(
            statement_receipts=tuple(receipts),
            readback=Rows(tuple(Row(i + 1, value) for i, value in enumerate(readback_values))),
            readback_complete=True,
            actual_schema=actual_schema,
            load_committed=True,
            isolation_confirmed=True,
        )
        type_code, precision, scale = _column_meta(side_type)
        result_set = ResultSet(
            columns=(
                ResultColumn(
                    0,
                    relation.columns[0].alias,
                    relation.columns[0].a_family if side is Side.A else relation.columns[0].b_family,
                    type_code,
                    0,
                    precision,
                    scale,
                    "d3-mapping-1",
                ),
            ),
            rows=tuple((_result_value(value),) for value in result_rows),
            observed_row_count=len(result_rows),
            fetch_complete=True,
            truncated=False,
            extra_result_sets=0,
            encoding_version="mysql-text-1",
        )
        side_queries[label] = QueryEvidence(
            side=side,
            binding=binding,
            select_text=select.text,
            select_sql_hash=select.sql_hash,
            protocol="text",
            parameters=(),
            status=QueryStatus.COMPLETE,
            result=result_set,
            session_start_id=f"sess-{label.lower()}-1",
            session_end_id=f"sess-{label.lower()}-1",
            actual_database=database,
            environment_before=_ENV,
            environment_after=_ENV,
            diagnostics=StatementDiagnostics(
                side=side,
                phase=SelectPhase.SELECT,
                ordinal=0,
                sql_hash=select.sql_hash,
                collected=True,
                complete=True,
                entries=(),
            ),
            duration_ms=1,
            result_terminal=ResultTerminal.CONFIRMED,
        )
        side_contexts[label] = SideContext(
            side=side,
            setup_connection_id=f"conn-{label.lower()}-1",
            readback_connection_id=f"conn-{label.lower()}-1",
            select_connection_id=f"conn-{label.lower()}-1",
            current_database=database,
            name_map=_NAME_MAP,
            autocommit=True,
            transaction_isolation=TransactionIsolation.REPEATABLE_READ,
            environment_before=_ENV,
            environment_after=_ENV,
        )

    facts = RuntimeFacts(
        binding=binding,
        observed_environment=_ENV,
        name_map=_NAME_MAP,
        a=side_facts["A"],
        b=side_facts["B"],
    )
    evidence = ExecutionEvidence(
        request_hash=request.request_hash,
        expectation=expectation,
        runtime_facts=facts,
        setup_diagnostics=tuple(setup_diagnostics),
        actual_execution_order=ExecutionOrder.AB,
        a_context=side_contexts["A"],
        b_context=side_contexts["B"],
        a_query=side_queries["A"],
        b_query=side_queries["B"],
        isolation_receipt=IsolationReceipt(
            attempt_id=attempt_id,
            name_map_hash=binding.name_map_hash,
            ownership_ref=f"{run_id}/objects/tc_a,tc_b",
            objects_created_confirmed=True,
            load_committed=True,
            no_concurrent_write_confirmed=True,
            method_version="d3-isolation-1",
        ),
        terminal=TerminalReceipt(
            attempt_id=attempt_id,
            termination=TerminationState.CONFIRMED,
            cleanup=CleanupState.DONE,
            owned_objects=(),
        ),
        failure=None,
        preflight_rejection=None,
        synthetic=True,
    )
    return {
        "request": request.to_obj(),
        "expectation": expectation.to_obj(),
        "evidence": {**evidence.to_obj(), "evidence_hash": evidence.evidence_hash},
    }
