# Runtime-facts contract fixtures (synthetic)

All files with the `runtime_facts_` prefix in this directory are **synthetic,
hand-written evidence samples** for the D1 Phase 4 runtime-fact contract
(design `2026-09-05-mtsql-typecheck-type-compatibility-test-generation-design-zh.md`,
sections 6.2.5, 6.3.1, 7 Phase 4, test IDs V01/V02/V03). They were **not**
produced by a real database run and they certify nothing about any MySQL/MTSQL
build. Each JSON file repeats this in its `_synthetic: true` marker and its
`_note` field; every conclusion expected from `validate_runtime_facts` is
written by hand in the `_note` (JSON has no comments, so underscore-prefixed
keys are documentation). The strict contract loaders reject unknown fields, so
the test that consumes these fixtures strips top-level `_`-prefixed keys
before decoding.

## Files

| File | Content | Hand-written expected conclusion |
|---|---|---|
| `runtime_facts_expected_binding.json` | One `ExpectedBinding`: the independent caller expectation (run/case/attempt ids plus frozen environment/name-map content hashes). | Decodes as an `ExpectedBinding`; combined with `runtime_facts_ready.json` it yields READY. |
| `runtime_facts_pending.json` | `RuntimeFacts` with only the binding; environment, name map and both sides are `null` (nothing collected yet). | `INCOMPLETE`; every fact condition `PENDING`/`missing_fact`; no `VIOLATED`. |
| `runtime_facts_ready.json` | Complete `RuntimeFacts`: observed environment, name map, and full A/B schema, statement receipts, exact readback, commit and isolation facts. | `READY`; every condition `SATISFIED`. READY states preconditions only — it is never a query MATCH. |
| `runtime_facts_blocked.json` | Same as ready except side A read back rid 3 (a NULL row) as integer `0`. | `BLOCKED`; `a_readback` `VIOLATED`/`load_value_mismatch` (NULL must stay NULL). |
| `runtime_facts_incomplete.json` | Environment, name map and side A complete; side B `null`. | `INCOMPLETE`; `b_schema`/`b_receipts`/`b_readback`/`b_load` `PENDING`/`missing_fact`. |

## Referenced case

All facts bind to `tests/contract/fixtures/payload_signed_widen_q1.json`
(`mysql80.signed-widen` Q1, TINYINT -> SMALLINT, rids 1-4 with values -128, 0,
NULL, 127). The binding `case_id`
`bd3875f716326cd0c0e361fcc52f7db71967558e4113ab8be1bbb99109e6c305` is that
payload's case id (frozen in the contract tests).

## Field meanings

- `binding` / expected binding: `run_id`, `case_id`, `attempt_id` identify the
  execution request; `environment_hash` is `sha256(canonical_json(ObservedEnvironment.to_obj()))`
  and `name_map_hash` is `sha256(canonical_json(NameMap.to_obj()))` over the
  content carried in the facts. D1 recomputes both hashes from content; the
  values here were cross-checked once with `shasum -a 256`.
- `observed_environment`: server identity, version/vendor/build, engine and
  the effective A/B session snapshot (sql_mode tokens sorted, charset,
  collation, time_zone, optimizer_switch).
- `name_map`: the controlled physical identifiers A/B (`tc_a`/`tc_b`
  databases, `t_a`/`t_b` tables).
- Per side (`a`/`b`): `statement_receipts` (phase, per-phase 0-based ordinal,
  sql_hash, success, diagnostics_complete) covering exactly the DDL/INSERT
  statements of `render_pair` under the name map (SELECT has no receipt);
  `readback` + `readback_complete` (full-set exact readback of the shared
  rows, NULL positions preserved); `actual_schema` (server metadata already
  normalized by D3 into a `TableSpec`); `load_committed`,
  `isolation_confirmed`.

## Synthetic origin of the receipt hashes

The `sql_hash` values are SHA-256 over the exact `render_pair` statement text
for the referenced payload under the name map above (frozen once when the
fixture was written; `tests/unit/validation/test_runtime_facts.py` re-derives
them from the renderer to prove the linkage). They are content hashes of SQL
text, not evidence of execution.
