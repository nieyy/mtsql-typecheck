"""G03: semantic audit over full-evidence traces (design 6.3, module
``reduction.audit``).

The honest trace is produced by a real engine run against the real
``JsonlTraceSink``; the forged trace is produced by tampering a published
evidence document AND rebuilding the record chain (new payload file, updated
payload_ref, recomputed record hashes), i.e. the strongest structural forgery
available at this layer.  Only the semantic audit — recomputing the oracle
verdict from the published documents — can catch it.
"""

from __future__ import annotations

import json
from pathlib import Path

from mtsql_typecheck.contracts.codec import canonical_json, sha256_hex
from mtsql_typecheck.contracts.execution import (
    dump_execution_evidence,
    load_execution_evidence,
)
from mtsql_typecheck.contracts.oracle import (
    ComparisonBudget,
    EVIDENCE_APPEND_BUDGET,
    decode_trace_record,
)
from mtsql_typecheck.reduction.audit import (
    EVIDENCE_PROFILE_FULL_MARKED,
    EVIDENCE_PROFILE_LEGACY,
    SEMANTIC_FULL_VERIFIED,
    SEMANTIC_MISMATCH,
    SEMANTIC_NOT_AUDITED,
    audit_trace,
)
from mtsql_typecheck.reduction.trace import (
    TRACE_FILE_NAME,
    TRACE_STATUS_COMPLETE,
    TRACE_STATUS_PARTIAL,
    JsonlTraceSink,
    read_trace,
)

import engine_fakes as ef
import replay_fakes as f

_GENESIS = "0" * 64


def _run_engine_trace(root: Path):
    """A real full-evidence engine run: children accepted, run REDUCED."""
    bundle = f.CandidateBundle()
    executor = ef.ReductionExecutor(bundle)
    with JsonlTraceSink(root, EVIDENCE_APPEND_BUDGET) as sink:
        result = ef.run_reduction(bundle, executor, sink)
    return result


def _load_records(root: Path) -> list[dict]:
    lines = [
        line
        for line in (root / TRACE_FILE_NAME).read_bytes().split(b"\n")
        if line
    ]
    return [json.loads(line) for line in lines]


def _write_records(root: Path, records: list[dict]) -> None:
    """Rewrite trace.jsonl, recomputing the entire record hash chain.

    ACCEPTED inline comparison_hashes are COMPARISON *record* hashes, so they
    must be fixed up to the recomputed hashes of the just-closed group (this
    is what a real forger rebuilding the chain would have to do, too)."""
    previous = _GENESIS
    lines = []
    group_hashes: list[str] = []
    last_kind = None
    for obj in records:
        kind = obj["kind"]
        if kind == "REQUESTED" and last_kind != "COMPARISON":
            group_hashes = []
        if kind == "ACCEPTED":
            obj["inline"]["comparison_hashes"] = list(group_hashes)
        obj["prev_hash"] = previous
        obj["hash"] = ""
        record = decode_trace_record(obj)
        previous = record.hash
        if kind == "COMPARISON":
            group_hashes.append(record.hash)
        last_kind = kind
        lines.append(canonical_json(record.to_obj()))
    (root / TRACE_FILE_NAME).write_bytes(b"\n".join(lines) + b"\n")


def test_honest_full_evidence_trace_is_fully_verified(tmp_path: Path) -> None:
    root = tmp_path / "honest"
    result = _run_engine_trace(root)
    assert result.outcome.value in ("REDUCED", "UNCHANGED")
    structural = read_trace(root)
    assert structural.trace_status == TRACE_STATUS_COMPLETE

    audit = audit_trace(root, ComparisonBudget())
    assert audit.structural_status == TRACE_STATUS_COMPLETE
    assert audit.evidence_profile == EVIDENCE_PROFILE_FULL_MARKED
    assert audit.semantic_status == SEMANTIC_FULL_VERIFIED
    assert audit.best_payload_ref == structural.best_payload_ref
    assert audit.records_verified == structural.records_verified


def test_legacy_trace_without_profile_marker_is_not_audited(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    _run_engine_trace(root)
    records = _load_records(root)
    for obj in records:
        if obj["kind"] == "START":
            del obj["inline"]["evidence_profile"]
    _write_records(root, records)
    assert read_trace(root).trace_status == TRACE_STATUS_COMPLETE

    audit = audit_trace(root, ComparisonBudget())
    assert audit.evidence_profile == EVIDENCE_PROFILE_LEGACY
    assert audit.semantic_status == SEMANTIC_NOT_AUDITED
    assert "legacy" in audit.detail


def test_tampered_result_row_with_rebuilt_chain_is_a_semantic_mismatch(
    tmp_path: Path,
) -> None:
    """Forge the strongest structurally valid trace: swap one observed result
    value inside a published EVIDENCE document, re-seal the evidence hash,
    publish a new payload file, point the record at it and rebuild the whole
    record hash chain.  The structural audit stays COMPLETE; only the
    semantic re-derivation catches it."""
    root = tmp_path / "forged"
    _run_engine_trace(root)

    records = _load_records(root)
    target = next(obj for obj in records if obj["kind"] == "EVIDENCE")
    ref = target["payload_ref"]
    document = json.loads((root / ref["path"]).read_bytes())

    # Change ONE observed result value on side B (count unchanged).
    row = document["b_query"]["result"]["rows"][0][0]
    assert row["kind"] == "integer"
    row["value"] = str(int(row["value"]) - 1)  # -127 -> -128: a different multiset
    result_doc = document["b_query"]["result"]
    result_doc["payload_hash"] = sha256_hex(
        canonical_json({"columns": result_doc["columns"], "rows": result_doc["rows"]})
    )
    # Re-seal the evidence hash over the tampered content.
    document["evidence_hash"] = ""
    sealed = load_execution_evidence(document)
    document["evidence_hash"] = sealed.evidence_hash
    payload = dump_execution_evidence(sealed)

    digest = sha256_hex(payload)
    (root / "files" / f"{digest}.json").write_bytes(payload)
    ref["path"] = f"files/{digest}.json"
    ref["size_bytes"] = len(payload)
    ref["sha256"] = digest
    # Make the forgery internally consistent: the inline evidence_hash must
    # match the tampered document too.
    target["inline"]["evidence_hash"] = document["evidence_hash"]
    _write_records(root, records)

    assert read_trace(root).trace_status == TRACE_STATUS_COMPLETE
    audit = audit_trace(root, ComparisonBudget())
    assert audit.evidence_profile == EVIDENCE_PROFILE_FULL_MARKED
    assert audit.semantic_status == SEMANTIC_MISMATCH
    assert "recomputed comparison hash" in audit.detail
    assert "group 1" in audit.detail


def test_partial_trace_is_never_semantically_audited(tmp_path: Path) -> None:
    root = tmp_path / "partial"
    _run_engine_trace(root)
    records = _load_records(root)
    # Drop the FINISHED record: the trace ends mid-run.
    records = [obj for obj in records if obj["kind"] != "FINISHED"]
    _write_records(root, records)
    assert read_trace(root).trace_status == TRACE_STATUS_PARTIAL

    audit = audit_trace(root, ComparisonBudget())
    assert audit.structural_status == TRACE_STATUS_PARTIAL
    assert audit.semantic_status == SEMANTIC_NOT_AUDITED
    assert audit.evidence_profile == "NONE"
