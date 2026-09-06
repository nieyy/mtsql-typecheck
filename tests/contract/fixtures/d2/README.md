# D2 execution-evidence contract fixtures (synthetic)

All files in this directory are **synthetic, hand-built execution evidence
samples** for the D2 Phase 1 contract
(`docs/oracle-d2-contract.md` sections 1, 2.1-2.5). They were **not** produced
by a real database run and they certify nothing about any MySQL/MTSQL build.
Each file carries a top-level `"synthetic": true` field on the request and
evidence documents and a `_note` documentation field (JSON has no comments, so
underscore-prefixed keys are documentation; the strict contract loaders reject
unknown fields, so the consuming test strips top-level `_`-prefixed keys
before decoding, exactly like the D1 fixtures).

## File shape

Each file is one scenario bundle:

```json
{
  "_synthetic": true,
  "_note": "...",
  "request":      { ... AttemptRequest document, schema_version 1 ... },
  "expectation":  { ... AttemptExpectation document ... } | null,
  "evidence":     { ... ExecutionEvidence document incl. evidence_hash ... }
}
```

The three documents are consistent with each other: `expectation.request_hash`
and `evidence.request_hash` equal `sha256(canonical_json(request))`, the
expectation binding carries the payload's `case_id`, and `evidence_hash`
covers the canonical evidence content. The referenced case is
`tests/contract/fixtures/payload_signed_widen_q1.json` (`mysql80.signed-widen`
Q1, TINYINT -> SMALLINT) under the name map `tc_a`/`tc_b`, tables `t_a`/`t_b`;
setup-diagnostic and SELECT `sql_hash` values are the real `render_pair`
hashes for that payload/name map, frozen at generation time.

## Files

| File | Scenario | What it exercises |
|---|---|---|
| `evidence_success_match.json` | Complete successful attempt; A and B each return the same 2 rows (`-128`, NULL). | The full happy-path evidence: setup diagnostics, SideContexts, query evidence with results, isolation receipt, terminal CONFIRMED/DONE. Oracle-gate expectation (hand-written): MATCH. Also the golden-hash fixture. |
| `evidence_success_candidate.json` | Complete successful attempt; B returns `-127` where A returns `-128`. | Same shape as above with differing results. Oracle-gate expectation (hand-written): MISMATCH_CANDIDATE. |
| `evidence_prepare_failure.json` | PREPARE-stage failure. | No expectation, no runtime facts, no setup diagnostics, no side evidence; `failure.stage = PREPARE` with a stable code; NOT_STARTED terminal. |
| `evidence_b_not_started.json` | Side A fully successful; side B never started. | `b_context`/`b_query` are null (an absence, not a success); runtime facts carry side A only. |
| `evidence_cleanup_failed.json` | Both queries complete and comparable; cleanup failed. | Terminal `termination=CONFIRMED`, `cleanup=FAILED`, one object still held. Cleanup failure must not block an already-complete comparison but is recorded downstream. |
| `evidence_termination_unknown.json` | Both queries complete; termination could not be confirmed. | Terminal `termination=UNKNOWN` must block any comparison (TERMINATION_UNCONFIRMED), never become a match. |
| `evidence_preflight_rejection.json` | Legitimate structured preflight rejection bound to the paired request. | No post-PREPARE content; `NOT_STARTED` terminal only; `preflight_rejection.request_hash` matches the request. |
| `evidence_preflight_forged.json` | Forged preflight rejection. | Structurally valid (the model cannot detect a forgery alone) but `preflight_rejection.request_hash` does **not** match the paired request; consumers must reconcile the hash and treat the rejection as unproven. |
| `evidence_stale_ready.json` | D1 READY-semantics runtime facts (rebound to this attempt) but no query evidence at all. | READY states load preconditions only; the missing `a_query`/`b_query` keep the attempt incomparable (RUNTIME_NOT_READY / QUERY_NOT_COMPLETE), never a match. |

## Producer responsibilities (D3 handover)

D3 owns producing these documents in real runs and must fill:

- `expectation` (from `ExecutionPort.prepare`) and the full `evidence`
  (from `ExecutionPort.execute`), including `setup_diagnostics` entries per
  DDL/INSERT statement, per-side `SideContext` session identity and
  pre/post environment snapshots, `QueryEvidence` result sets and SELECT
  diagnostics (phase serialized as `"select"`), `IsolationReceipt`
  (positively confirmed flags or absent), and `TerminalReceipt`
  (termination proof plus cleanup state).
- Missing facts stay genuinely absent (`null` + a failure record), never
  defaulted to true. `synthetic=true` marks fixture evidence only and
  propagates to every downstream Comparison/ReplayResult/ReductionResult; it
  never counts as real reproduction.

The fixtures were generated once with a one-off script that used the frozen
contract models so every hash is internally consistent; the golden hashes
asserted by `tests/contract/test_execution_evidence.py` were recomputed
independently (plain `json.dumps` + `hashlib`/`shasum -a 256`) and are frozen
as literals in the test.
