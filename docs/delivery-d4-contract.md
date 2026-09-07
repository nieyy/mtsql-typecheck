# D4 Evidence / Reporting / Regression Delivery Contract (delivery-d4-contract)

Status: frozen Phase 1 implementation baseline for D4 v1.0 (design
`2026-09-06-mtsql-typecheck-evidence-reporting-regression-delivery-design-zh.md`,
sections 6.2.1, 6.2.2, 6.2.3, 6.5, 6.5.1). This document fixes the field
names, schema versions, enumerations, identity formulas, producer convention
and budgets that `contracts/delivery.py` implements and that later D4 phases
(evidence reader/snapshot/manifest, assessment, reporting, export) must
consume. Where this file and prose differ, this file wins; changing anything
here requires a design revision, not a code default.

All models follow the D1/D2 house rules (`contracts/case.py`,
`contracts/codec.py`): frozen dataclasses, closed enums, tuples in memory,
strict `__post_init__` validation on **both** the construction and the loader
path, unknown fields rejected, duplicate JSON keys rejected, `bool` never
accepted where an int is required, no float literals in documents (the
seconds budget is the only numeric edge and is serialized as an int, see
`Limits`), optional fields only for genuinely absent facts (never a default
success). Canonical bytes come from `codec.canonical_json` /
`codec.sha256_hex`; strict parsing from `codec.parse_strict_json`. Importing
`contracts/delivery.py` performs no I/O and never imports a database driver.

## 1. Frozen schema versions and constants

```python
DELIVERY_SCHEMA_VERSION = 1   # EvidenceManifest / SourceDescriptor / EvidenceAssessment
REVIEW_SCHEMA_VERSION = 1     # FindingReview
EXPORT_SCHEMA_VERSION = 1     # RegressionCase / ExportManifest

MANIFEST_FILENAME = "evidence-manifest.json"    # never listed in its own files
EXPORT_MANIFEST_FILENAME = "delivery-manifest.json"
ASSESSMENT_FILENAME = "assessment.json"         # written by verify AND report

NATIVE_VERSION_KEYS = ("case_schema", "comparison_schema", "execution_schema",
                       "generation_schema", "reduction_schema", "replay_schema",
                       "runner_schema", "trace_format")   # sorted, closed set

MAX_PACKAGE_PATH_BYTES = 1024   # frozen; Limits.max_path_bytes must equal it
MAX_TIME_BUDGET_SECONDS = 600.0
DEFAULT_TIME_BUDGET_SECONDS = 120.0
```

## 2. Enumerations (closed; design 6.2.1-6.2.3 vocabulary)

| Enum | Values | Notes |
|---|---|---|
| `NativeKind` | generation / run / trace / attempt / delivery / unknown | native format family; `unknown` records restricted root metadata only |
| `DeliveryKind` | verification / report | evidence-package kind |
| `DeliveryCompletion` | COMPLETE / PARTIAL | whether the **derived delivery** was sealed; never test success |
| `SyntheticKind` | REAL / SYNTHETIC / UNKNOWN | UNKNOWN never counts into real findings |
| `CollectionStatus` | COLLECTED / SOURCE_CHANGED / PARTIALLY_READ / REFUSED | COLLECTED: closure read fully and unchanged; SOURCE_CHANGED: source changed during collection (diagnostic only); PARTIALLY_READ: declared closure partly unreadable; REFUSED: path-safety/limit refusal before any copy |
| `StructuralStatus` | COMPLETE / PARTIAL / CORRUPT / UNSUPPORTED | CORRUPT = proven contradiction/hash error; UNSUPPORTED = unknown version, not guessed |
| `SemanticStatus` | RECOMPUTED / NOT_RECOMPUTED / CONFLICT | Oracle/trace recompute over existing data only; never an SUT correctness proof |
| `ProvenanceStatus` | CORROBORATED / UNVERIFIED / CONFLICT | CORROBORATED is mutual consistency, never an authenticity certificate |
| `ExecutionSafetyStatus` | CONFIRMED / UNKNOWN / UNSAFE / NOT_APPLICABLE | per real terminal/ownership evidence; generation-only packages are NOT_APPLICABLE |
| `ReviewDecision` | CONFIRMED_DB_BUG / EXPECTED_BEHAVIOR / TOOL_OR_EVIDENCE_ISSUE / NEEDS_MORE_EVIDENCE | human decision, persisted independently of observations |
| `FileRole` | raw_native / assessment / report_json / report_md / report_html / review / export_readme / export_case / export_expected / export_environment_requirements / export_origin / export_sql_a / export_sql_b / export_regression_case | raw_native = original bytes; all others derived |
| `ExportFormat` | sql / regression | export manifest kind |
| `AssessmentDimension` | structural / semantic / provenance / execution_safety | the four audit dimensions |
| `RelationAssertionMode` | typed_multiset_exact | extended only with a design revision |

These D4 enums never overwrite D1/D2/D3 native enums.

## 3. Identity formulas (design 6.2.1; pure functions, hand-computed goldens in `tests/contract/test_delivery_contract.py`)

- `compute_snapshot_digest(native_kind, root_document, files, missing_paths)`
  = SHA-256 over canonical JSON of
  `{"native_kind", "root_document", "files", "missing_paths"}` where `files`
  is the list of `{"path", "size_bytes", "sha256"}` objects of the read
  native files **sorted by path**, and `missing_paths` is sorted and
  deduplicated. Excludes absolute paths, mtimes, wall-clock times, audit
  state, producer inference and the digest itself. `native_kind` must be a
  `NativeKind` value; paths are package-relative POSIX; duplicate file paths
  are rejected.
- `compute_source_id(snapshot_digest)` = `"s-" + snapshot_digest`. One
  native input has exactly one source; consuming a D4 delivery again keeps
  the original sources (a D4 report never becomes a new source).
- `compute_delivery_id(sources)` = SHA-256 over canonical JSON of the list
  of `{"source_id", "snapshot_digest"}` objects sorted by `source_id`
  (non-empty, unique). Moving, re-rendering or attaching reviews never
  changes it; changed raw bytes or a changed missing set always do.
- `compute_occurrence_id(source_id, attempt_id, case_id)` = SHA-256 over
  canonical JSON of `[source_id, attempt_id, case_id]`. `attempt_id` must be
  the real native attempt identifier; passing `None` raises (design: 缺失
  attempt 标识时不伪造 execution occurrence — callers whose native format
  lacks an attempt identifier do not create occurrences at all).

`EvidenceManifest.delivery_id` is re-derived and must equal
`compute_delivery_id(sources)`; `SourceDescriptor.source_id` must equal
`compute_source_id(snapshot_digest)`; `FindingOccurrence.occurrence_id` is
re-derived from (source_id, attempt_id, case_id). Forged identity is
therefore rejected on both the construction and the loader path.

## 4. ProducerInfo (design 6.5.1)

| Field | Type | Semantics |
|---|---|---|
| `name` | str, non-empty, <=128 | tool name, e.g. `mtsql-typecheck` |
| `version` | str or null | actual tool package version; null when unknown; never a substitute for `schema_version` |
| `revision` | str or null | full lowercase 40-hex git SHA recorded at build/package time; null when unverifiable; never read from the runtime cwd's HEAD |
| `dirty` | bool or null | whether the build contained uncommitted changes; **null stays null, never defaulted to false**; true means the revision cannot uniquely identify the built code |

`producer` describes the TypeCheck tool that wrote the native evidence (on
`SourceDescriptor`) or the offline delivery generator (on
`EvidenceManifest`); it is never the tested MySQL version. Missing producer
metadata is preserved as null; D4 never backfills unknown fields from its own
environment, and a present commit never upgrades provenance by itself.

## 5. Limits (design 6.5 budget table; no unlimited option exists)

| Field | Default | Meaning |
|---|---|---|
| `max_single_source_file_bytes` | 268435456 (256 MiB) | one source file |
| `max_total_source_bytes` | 1073741824 (1 GiB) | whole source closure |
| `max_json_document_bytes` | 33554432 (32 MiB) | single JSON document byte-reject limit (before parsing) |
| `max_files` | 10000 | files per snapshot |
| `max_jsonl_line_bytes` | 262144 (256 KiB) | one JSONL line |
| `max_dir_depth` | 16 | snapshot directory depth |
| `max_path_bytes` | 1024 | one package-relative path (frozen to `MAX_PACKAGE_PATH_BYTES`) |
| `max_output_single_file_bytes` | 268435456 (256 MiB) | one derived output file |
| `max_output_total_bytes` | 1073741824 (1 GiB) | whole output incl. raw, derived files and the final manifest |
| `max_html_bytes` | 8388608 (8 MiB) | report.html |
| `max_markdown_bytes` | 8388608 (8 MiB) | report.md |
| `min_diagnostic_reserve_bytes` | 2097152 (2 MiB) | diagnostic/manifest reserve kept free inside the output budget |
| `time_budget_seconds` | 120.0 (hard cap 600.0) | total wall clock |

Validation: every byte/count field is a positive int (`bool` rejected); the
single-file caps must not exceed their totals; the reserve must fit inside
the total output cap. `time_budget_seconds` is stored as a float but only
whole seconds are accepted (int or integral float, e.g. `120.0`, normalized
to float); the persistent document therefore carries an int and the strict
float-free canonical JSON rule stays intact. `Limits.default()` returns the
table above; `decode_limits` requires **all** fields present (no default
filling) and rejects zero/negative/bool/float values.

## 6. Files and sources

### EvidenceFile

| Field | Type | Semantics |
|---|---|---|
| `path` | str | package-relative POSIX path; no leading `/`, no `..`/`.`/empty components, no backslash, no NUL, <= 1024 bytes |
| `role` | FileRole | raw_native binds a source_id; all other roles are derived |
| `size_bytes` | int >= 0 | actual sealed byte size |
| `sha256` | 64-hex lowercase | hash over the actual sealed bytes |
| `source_id` | `s-`+64hex or null | required (non-null) for `raw_native`; allowed null only for derived files |

Verifying the hash against the stored bytes is the manifest validator's job;
the model validates format only.

### NativeVersionComponent

`kind_field` must be one of `NATIVE_VERSION_KEYS` (unknown keys rejected);
`value` is a non-empty version token (`[A-Za-z0-9._+-]{1,128}`). A
`SourceDescriptor.native_versions` tuple must be sorted and duplicate-free by
`kind_field`.

### SourceDescriptor

| Field | Type | Semantics |
|---|---|---|
| `source_id` | `s-`+64hex | must equal `s-` + snapshot_digest |
| `native_kind` | NativeKind | |
| `root_document` | package path | package-relative path of the root document inside `raw/<source-id>/` |
| `snapshot_digest` | 64-hex | `compute_snapshot_digest` over the frozen bytes |
| `synthetic` | SyntheticKind | |
| `collection_status` | CollectionStatus | SOURCE_CHANGED keeps the source diagnostic-only |
| `native_versions` | tuple of NativeVersionComponent | closed key set, sorted, unique |
| `observed_writer_version` | str or null | writer version actually observed in the native metadata |
| `source_commit` | 40-hex or null | null when the native writer recorded no commit; never filled from D4's own HEAD |
| `producer` | ProducerInfo or null | actually observed metadata (6.5.1) |
| `missing_files` | sorted tuple of package paths | sorted, unique |

### EvidenceManifest

| Field | Type | Semantics |
|---|---|---|
| `schema_version` | int == 1 | |
| `delivery_id` | 64-hex | re-derived from `sources`; mismatch rejected |
| `kind` | DeliveryKind | verification or report |
| `writer_version` | non-empty <=128 | D4 writer version of this delivery |
| `producer` | ProducerInfo or null | D4 delivery generator build info (separate from per-source producer) |
| `sources` | non-empty tuple of SourceDescriptor | sorted by source_id, unique |
| `files` | tuple of EvidenceFile | sorted by unique path; **must not list `evidence-manifest.json`** |
| `assessment_ref` | str == `"assessment.json"` | required for both kinds (verify and report both write assessment.json) |
| `completion` | DeliveryCompletion | delivery sealing only, never test success |

## 7. Assessment dimensions (design 6.2.2)

`DimensionObservation` (per-object input to the pure aggregation helpers):
`dimension` (AssessmentDimension), `applicable` (bool), `status` (must belong
to the dimension's enum), `object_ref` (optional short identifier, e.g. an
attempt id or file path). Non-applicable observations never change the
aggregate.

`DimensionResult` (persisted per dimension):
`dimension`, `applicable` (bool), `status` (dimension's enum),
`reason_codes` (sorted, unique, each matching `[a-z0-9_]{1,64}`),
`checked_objects` (int >= 0), `unchecked_objects` (int >= 0),
`detail` (str or null). `EvidenceAssessment` holds exactly one
`DimensionResult` per dimension slot (`structural`, `semantic`,
`provenance`, `execution_safety`) plus `schema_version == 1`; there is no
aggregate PASS field.

Aggregation rules (pure functions over tuples of `DimensionObservation`;
per-object records stay authoritative and are never overwritten):

| Helper | Rule |
|---|---|
| `aggregate_structural` | CORRUPT > UNSUPPORTED > PARTIAL > COMPLETE; nothing applicable is vacuously COMPLETE |
| `aggregate_semantic` | CONFLICT first; any applicable NOT_RECOMPUTED keeps NOT_RECOMPUTED; else RECOMPUTED; **zero applicable observations is NOT_RECOMPUTED, never RECOMPUTED** |
| `aggregate_provenance` | CONFLICT first; any applicable UNVERIFIED keeps UNVERIFIED; else CORROBORATED; **zero applicable observations is UNVERIFIED, never CORROBORATED** |
| `aggregate_safety` | UNSAFE > UNKNOWN > CONFIRMED; NOT_APPLICABLE only when every input is non-applicable or NOT_APPLICABLE (including the empty case) |

The empty-input defaults for semantic/provenance deviate deliberately from a
vacuous "everything checked": claiming RECOMPUTED/CORROBORATED with zero
observations would fabricate a conclusion. The overall applicability of a
dimension on an `EvidenceAssessment` is expressed by the DimensionResult's
own `applicable` flag (e.g. generation-only sources: semantic
NOT_RECOMPUTED/applicable=false, safety NOT_APPLICABLE).

## 8. Findings and reviews (design 6.2.1, 6.4.5)

### FindingOccurrence

| Field | Type | Semantics |
|---|---|---|
| `occurrence_id` | 64-hex | re-derived from (source_id, attempt_id, case_id) |
| `source_id` | `s-`+64hex | |
| `attempt_id` | non-empty str | real native attempt identifier; required (no occurrence without one) |
| `case_id` | 64-hex | logical input identity |
| `recompute_status` | SemanticStatus | D4 recompute outcome over existing data |
| `comparison_hash` | 64-hex or null | original recorded Comparison hash |
| `original_exact_signature` | 64-hex or null | D2 exact signature (reproduction identity, not a root-cause id) |
| `fingerprint` | 64-hex or null | D2 coarse fingerprint (browsing groups only, never a bug count) |
| `recomputed_comparison_hash` | 64-hex or null | required for RECOMPUTED/CONFLICT, forbidden for NOT_RECOMPUTED |
| `replay_ref` / `reduction_ref` | package path or null | references into the package raw tree |
| `synthetic` | SyntheticKind | UNKNOWN never counts into real findings |

There is deliberately **no `confirmed_bug` boolean**: confirmation exists
only as a `FindingReview`.

### FindingReview

| Field | Type | Semantics |
|---|---|---|
| `schema_version` | int == 1 | |
| `review_id` | non-empty, <=128 | caller-chosen stable id |
| `reviewer` | non-empty, <=128 | human declaration, not an authenticated identity |
| `reviewed_at` | ISO-8601 timestamp | `YYYY-MM-DDTHH:MM:SS(.ffffff)?(Z|±HH:MM)`; display only, never logical identity |
| `evidence_digest` | 64-hex | the delivery_id this review binds to; reviews facing another snapshot show as history only |
| `occurrence_ids` | sorted unique tuple of 64-hex | non-empty; precise binding to occurrences |
| `decision` | ReviewDecision | |
| `reason` | non-empty str | |
| `issue_url` | https URL or null | `https://` only; never fetched automatically |
| `supersedes` | review_id or null | must differ from `review_id`; cycle/dangling/cross-evidence checks belong to the review validator |

Reviews never overwrite observations; corrections are new reviews using
`supersedes` (acyclic), and the original record is preserved.

## 9. Export models (design 6.2.3, 6.4.6)

### RelationAssertion

| Field | Type | Semantics |
|---|---|---|
| `mode` | RelationAssertionMode | e.g. `typed_multiset_exact` |
| `columns` | sorted unique non-empty tuple of short names | result column aliases, order-insensitive here because `spec` carries the canonical serialized assertion |
| `spec` | non-empty str <= 2000 chars | serialized canonical assertion JSON; lossless and bounded |

The expected relation is the assertion; the historical mismatching database
output is never converted into expected truth here.

### RegressionCase (schema_version = 1)

| Field | Type | Semantics |
|---|---|---|
| `case_document_hash` | 64-hex | hash of the selected case document |
| `rule_definition_hash` | 64-hex or null | frozen rule semantics the payload was generated under |
| `renderer_id` / `renderer_version` | D1 semver form (`r1`/`1`) | render_pair identity |
| `codec_id` / `codec_version` | D1 semver form | value codec identity |
| `relation_assertion` | RelationAssertion | |
| `source_inventory_hash` | 64-hex | inventory the case came from |
| `review_ref` | review_id or null | |
| `synthetic` | SyntheticKind | SYNTHETIC regression may only be labelled TOOL_SELFTEST |
| `known_bad_build` / `fixed_build` | version token or null | saved only when explicitly provided; a historical mismatch is never a post-fix failure assertion |

### ExportManifest (schema_version = 1, format = sql / regression)

| Field | Type | Semantics |
|---|---|---|
| `export_id` | 64-hex | caller-chosen package identity |
| `format` | ExportFormat | sql or regression |
| `source_delivery_id` | 64-hex | the evidence delivery the material came from |
| `selected_case_id` | 64-hex | |
| `selected_occurrence_id` | 64-hex or null | disambiguates repeated cases |
| `review_ref` | review_id or null | **required for format=regression** (design: regression 必须有对应人工 review) |
| `name_map` | D1 `NameMap` | allocated random tokens (database_a/b, table_a/b); logical case_id unaffected |
| `files` | tuple of EvidenceFile | sorted by unique path; must not list `delivery-manifest.json` (or `evidence-manifest.json`) |
| `limitations` | sorted unique tuple of `[a-z0-9_]{1,64}` codes | e.g. `review_required` |
| `completion` | DeliveryCompletion | sealing only |

The export package is never a D1 generation bundle; it must not fabricate
seeds, ordinals or a generation manifest, and the README must state that it
is not directly consumable by the current `run --input`.

## 10. Delivery directory layout (design 6.2.3, informational)

```text
<new-output>/                    # verification: manifest + assessment + raw only
  evidence-manifest.json         # sealed last; never listed in its own files
  assessment.json
  report.json / report.md / report.html   # report kind must contain all three
  raw/<source-id>/...            # original relative tree and bytes
  reviews/<review-id>.json       # only user-supplied review copies
```

Export packages use `delivery-manifest.json` plus README.md, case.json,
expected.json, environment-requirements.json, a.sql, b.sql, origin.json and
(additionally for regression) regression-case.json and the review copy.

## 11. Non-goals encoded in the contract

- No `confirmed_bug` field on `FindingOccurrence`; confirmation is a
  `FindingReview` bound to `evidence_digest`.
- `DeliveryCompletion` (and `ExportManifest.completion`) never mean "tests
  passed"; they only state whether the derived package was sealed.
- Aggregation never produces a total PASS; every dimension keeps its own
  applicability, status, reason codes and checked/unchecked counts.
- `RECOMPUTED`/`CORROBORATED` are never claimed from zero observations;
  honesty defaults are NOT_RECOMPUTED / UNVERIFIED.
- No "unlimited" limits option; every budget is finite and positive.
- No float values in persistent D4 documents (whole-second time budget).
- No attempt-id fabrication: no native attempt identifier, no occurrence.
- `CORROBORATED`/`CONFIRMED` are evidence-consistency states, never
  authenticity certificates of the build or the database facts.
