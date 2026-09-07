# D3 Runner Contract (runner-d3-contract)

Status: frozen implementation baseline for D3 Phase 1 (design
`2026-09-06-mtsql-typecheck-runner-database-adapter-design-zh.md`, sections
6.2.1, 6.3.1, 6.4.6, 6.6 and 7 Phase 1). This document fixes the field names,
schema versions, enumerations and canonical-encoding rules that
`contracts/runner.py` must implement. Where this file and prose differ, this
file wins; changing anything here requires a design revision, not a code
default.

All models follow D1/D2 house rules (`contracts/case.py`,
`contracts/codec.py`, `contracts/execution.py`): frozen dataclasses, closed
enums, tuples (never lists) in memory, strict `__post_init__` validation on
**both** the construction and the loader path, unknown fields rejected,
`bool` never accepted as `int`, no floats, optional fields only for genuinely
absent facts (never a default success). Canonical bytes come from
`codec.canonical_json` / `codec.sha256_hex`. Importing the module performs no
I/O and never imports a database driver.

## 1. Frozen constants

```python
# contracts/runner.py
RUNNER_SCHEMA_VERSION = 1        # every D3 persistent model in the module
RUNNER_ADAPTER_ID = "mysql80-text-v1"
RUNNER_EVIDENCE_PROFILE = "typecheck-full-evidence-v1"
TARGET_CONFIG_MAX_BYTES = 64 * 1024   # raw envelope cap, before parsing
OWNERSHIP_GENESIS_HASH = "0" * 64     # prev_event_hash of the first event
JOURNAL_MAX_EVENT_BYTES = 64 * 1024   # defensive per-line cap on load
```

`RUNNER_EVIDENCE_PROFILE` must stay in sync with
`contracts.oracle.EVIDENCE_PROFILE_FULL`; it is deliberately re-declared, not
imported, so the contract module has no dependency on the oracle module.

## 2. Enumerations

All enums are `enum.StrEnum` and serialize as their value string.

```python
class TlsMode:               VERIFY_IDENTITY = "verify_identity"; DISABLED = "disabled"
class BuildIdSource:         CONFIGURED = "configured";          OBSERVED = "observed"
class ProbeOutcome:          PASS = "PASS";                      FAIL = "FAIL"
class StageObservationKind:  PROBE / SESSION / DATABASE_CREATE / MARKER / DDL / INSERT /
                             READBACK / SELECT / FETCH / TERMINATION / CLEANUP
class OwnershipEventKind:    RUN_LOCK_ACQUIRED / ATTEMPT_ALLOCATED / OBJECT_ALLOCATED /
                             OBJECT_CREATED / MARKER_CREATED / SESSION_REGISTERED / GO_SENT /
                             QUERY_STARTED / QUERY_FINISHED / TERMINATION_CONFIRMED /
                             TERMINATION_UNKNOWN / OBJECT_DROPPED / CLEANUP_CONFIRMED /
                             CLEANUP_FAILED / RUN_SEALED / QUARANTINED
class RunnerCommand:         PREFLIGHT / RUN / REPLAY / REDUCE / CLEANUP
class RunnerStatus:          RUNNING / COMPLETE / PARTIAL / ABORTED
```

`Side` (A/B) is imported from `contracts.execution`; the D3 models never
redefine it.

## 3. Canonical JSON and content hashes

Canonical JSON is exactly `codec.canonical_json`: sorted keys, compact
separators, `ensure_ascii=True`, no trailing newline, floats forbidden.
Every model has `to_obj()` (all fields, nulls preserved), a strict
`decode_<name>(obj, what)` loader, and public `load_<name>(bytes | str |
dict)` / `dump_<name>(model)` entry points following the `execution.py`
pattern. `load_*` parses with `codec.parse_strict_json` and therefore rejects
duplicate JSON keys, floats, bools in integer positions, non-canonical
integer literals and over-deep nesting before any model validation runs.

Content hashes always exclude the record's own hash field:

- `OwnershipEvent.content_hash` = sha256 over `canonical_json` of the event
  object minus `content_hash`. Constructed with the default empty marker the
  hash is computed; a supplied value that disagrees is rejected. `to_obj()`
  includes all fields including `content_hash`.
- `EnvironmentManifest.sanitized_config_hash` and
  `RunnerManifest.sanitized_config_hash` = sha256 over the canonical
  `TargetConfig.to_obj()` bytes of the run's target (the "sanitized"
  configuration: the model cannot contain a secret, so the hash itself is
  safe to publish). The models check the hex64 shape; consumers reconcile
  the derivation.

## 4. Controlled relative paths

`StageObservation.sql_ref` / `diagnostics_ref` /
`field_metadata_ref` and every `RunnerManifest.refs` value are controlled
relative paths inside the run's own output directory. The model-level rule
(`_check_controlled_relpath`): non-empty string, no leading `/`, no `\` and
no NUL, no empty path component (no `//`), no `.` or `..` component, total
length at most 512 characters. Symlinks cannot be checked at the model
layer; publishers and readers must enforce that separately (design 6.2.1).

## 5. Models

### 5.1 TlsConfig (design 6.3.1)

| field    | type            | constraints                                                            |
|----------|-----------------|------------------------------------------------------------------------|
| mode     | TlsMode         | closed enum                                                            |
| ca_file  | Optional[str]   | required non-empty when mode is VERIFY_IDENTITY; must be None when DISABLED |

Golden JSON:

```json
{"mode": "verify_identity", "ca_file": "/etc/typecheck/ca.pem"}
```

### 5.2 TargetConfig (design 6.3.1)

Declarative target description. Secrets never appear: there is no password
field anywhere; the password is read only from the `password_env`
environment variable at connection time and never serialized.

| field                    | type          | constraints                                                        |
|--------------------------|---------------|--------------------------------------------------------------------|
| schema_version           | int           | == 1                                                               |
| adapter                  | str           | exactly `"mysql80-text-v1"`                                        |
| host                     | Optional[str] | non-empty when present; host+port and unix_socket are exclusive (exactly one transport) |
| port                     | Optional[int] | int 1..65535, bool rejected; present iff host is present           |
| unix_socket              | Optional[str] | non-empty when present; excludes host/port                         |
| user                     | str           | non-empty, <= 128 chars                                            |
| password_env             | str           | non-empty, <= 128 chars, not the literal `"password"`, no NUL      |
| expected_server_uuid     | str           | must parse as a UUID; normalized to canonical lowercase hyphenated form on both construction and loader path |
| build_id                 | str           | non-empty, <= 256 chars                                            |
| database_prefix          | str           | exactly `"tc_"`                                                    |
| dedicated_test_instance  | bool          | must be `true`                                                     |
| tls                      | TlsConfig     | nested object                                                      |

Golden JSON (matches the design 6.3.1 target example: same field set and
shape; the design's placeholder values such as
`"replace-with-test-server-uuid"` are instantiated here with schema-valid
values — a placeholder string is not a valid UUID and the contract requires
one). Canonical single-line form and hash:

```
{"adapter":"mysql80-text-v1","build_id":"8.0.39-certified-build-20250715","database_prefix":"tc_","dedicated_test_instance":true,"expected_server_uuid":"1f0e3d2c-4b5a-4678-9abc-def012345678","host":"mysql-test.example.internal","password_env":"TYPECHECK_MYSQL_PASSWORD","port":3306,"schema_version":1,"tls":{"ca_file":"/etc/typecheck/ca.pem","mode":"verify_identity"},"unix_socket":null,"user":"typecheck"}
sha256 = 46560d8270b80482321142a0a91efba1fc72c0b9aea5f6124268aee31f7e4e3e
```

`load_target_config` rejects a raw envelope over `TARGET_CONFIG_MAX_BYTES`
(64 KiB) before parsing.

### 5.3 ProbeRecord and EnvironmentManifest (design 6.2.1)

ProbeRecord — one preflight probe outcome. Probes are plain data; the
mandatory cancel-capability probe is just an entry (usually
`probe_id: "cancel-capability"`), with no special-casing in the model.

| field    | type         | constraints                                  |
|----------|--------------|----------------------------------------------|
| probe_id | str          | non-empty, <= 128 chars                      |
| outcome  | ProbeOutcome | closed enum                                  |
| detail   | str          | <= 512 chars, may be empty, sanitized text   |

Golden JSON:

```json
{"probe_id": "cancel-capability", "outcome": "PASS", "detail": "bounded SLEEP probe cancelled, own thread gone"}
```

EnvironmentManifest — preflight environment record.

| field                 | type                | constraints                                     |
|-----------------------|---------------------|-------------------------------------------------|
| schema_version        | int                 | == 1                                            |
| observed_environment  | ObservedEnvironment | imported from `contracts.case`                  |
| server_uuid           | str                 | UUID; stored/serialized in canonical form       |
| python_version        | str                 | non-empty, <= 64 chars                          |
| os_platform           | str                 | non-empty, <= 128 chars                         |
| driver_name           | str                 | exactly `"pymysql"`                             |
| driver_version        | str                 | non-empty, <= 64 chars                          |
| adapter_version       | str                 | non-empty, <= 64 chars                          |
| mapping_version       | str                 | non-empty, <= 128 chars                         |
| build_id              | str                 | non-empty, <= 256 chars                         |
| build_id_source       | BuildIdSource       | CONFIGURED = a configuration declaration, never to be presented as server-measured; OBSERVED = read from the live server |
| sanitized_config_hash | str                 | hex64 (see section 3)                           |
| probes                | tuple[ProbeRecord]  | tuple in memory, JSON array on the wire         |

Golden JSON:

```json
{
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
    "optimizer_switch": "index_merge=on,mrr=off"
  },
  "server_uuid": "1f0e3d2c-4b5a-4678-9abc-def012345678",
  "python_version": "3.11.9",
  "os_platform": "Linux-5.15.0-x86_64",
  "driver_name": "pymysql",
  "driver_version": "1.1.2",
  "adapter_version": "mysql80-text-v1",
  "mapping_version": "mysql80-pymysql112-exact-v1",
  "build_id": "8.0.39-certified-build-20250715",
  "build_id_source": "configured",
  "sanitized_config_hash": "46560d8270b80482321142a0a91efba1fc72c0b9aea5f6124268aee31f7e4e3e",
  "probes": [
    {"probe_id": "cancel-capability", "outcome": "PASS",
     "detail": "bounded SLEEP probe cancelled, own thread gone"}
  ]
}
```

### 5.4 StageObservation (design 6.2.1)

One raw collection observation; the Adapter derives SideContext objects from
these records and never drops stage facts. `side` is None for control-plane
observations. Raw SQL text, diagnostics text and field metadata live in
referenced evidence files (section 4), never inline.

| field              | type                | constraints                                    |
|--------------------|---------------------|------------------------------------------------|
| side               | Optional[Side]      | A/B, or None for control-plane observations    |
| stage              | StageObservationKind| closed enum                                    |
| ordinal            | int                 | >= 0, collection order                         |
| connection_id      | Optional[str]       | non-empty when present                         |
| actual_database    | Optional[str]       | non-empty when present                         |
| session_id         | Optional[str]       | non-empty when present                         |
| sql_hash           | Optional[str]       | hex64 when present                             |
| sql_ref            | Optional[str]       | controlled relative path                       |
| diagnostics_ref    | Optional[str]       | controlled relative path                       |
| field_metadata_ref | Optional[str]       | controlled relative path                       |
| detail             | str                 | <= 512 chars, may be empty, default `""`       |

Golden JSON:

```json
{
  "side": "A",
  "stage": "INSERT",
  "ordinal": 0,
  "connection_id": "conn-1",
  "actual_database": "tc_a",
  "session_id": null,
  "sql_hash": "abababababababababababababababababababababababababababababababab",
  "sql_ref": "attempts/attempt-001/sql/insert-0.txt",
  "diagnostics_ref": "attempts/attempt-001/diagnostics/insert-0.txt",
  "field_metadata_ref": null,
  "detail": ""
}
```

### 5.5 OwnershipEvent and the append-only journal (design 6.2.1/6.2.3)

OwnershipEvent — one event of the append-only ownership ledger.

| field              | type               | constraints                                       |
|--------------------|--------------------|---------------------------------------------------|
| seq                | int                | >= 1, journal position                            |
| prev_event_hash    | str                | hex64; the first event uses `OWNERSHIP_GENESIS_HASH` (64 zeros) |
| run_id             | str                | non-empty, <= 128 chars                           |
| event_kind         | OwnershipEventKind | closed enum                                       |
| attempt_id         | Optional[str]      | non-empty when present                            |
| server_uuid        | Optional[str]      | UUID when present; stored/serialized canonically  |
| object_name        | Optional[str]      | full qualified name, non-empty, <= 256 chars      |
| token              | Optional[str]      | non-empty, <= 128 chars when present              |
| session_generation | Optional[int]      | >= 0 when present                                 |
| connection_id      | Optional[str]      | non-empty when present                            |
| content_hash       | str                | hex64, derived (section 3)                        |

Golden JSON (canonical single line, hash over the content minus
`content_hash`):

```
{"attempt_id":null,"connection_id":null,"content_hash":"7a928872e04dd03417d5ae7a14f92d2dd9f0a1d9e2effe38115b3a17c528dfe1","event_kind":"RUN_LOCK_ACQUIRED","object_name":null,"prev_event_hash":"0000000000000000000000000000000000000000000000000000000000000000","run_id":"run-20260906-1","seq":1,"server_uuid":null,"session_generation":null,"token":null}
```

Journal rules:

- `dump_ownership_journal(events)` produces JSONL: one canonical event
  object per line, `"\n"` terminated, no trailing blank line beyond the
  final `"\n"`; an empty tuple dumps to zero bytes.
- `load_ownership_journal(data)` parses every non-blank line with
  `parse_strict_json`, decodes each event (which recomputes and verifies
  `content_hash`), and verifies the append-only chain: `seq` must be exactly
  1..n with no gaps, the first `prev_event_hash` must equal
  `OWNERSHIP_GENESIS_HASH`, and every later `prev_event_hash` must equal the
  previous event's `content_hash`. Any violation raises `ContractError`.
  A zero-length or whitespace-only input loads as an empty tuple.
- A line longer than `JOURNAL_MAX_EVENT_BYTES` is rejected before parsing.

### 5.6 RunnerManifest (design 6.2.1/6.6)

Run-level manifest, sealed last in the output directory.

| field                 | type              | constraints                                                    |
|-----------------------|-------------------|----------------------------------------------------------------|
| schema_version        | int               | == 1                                                           |
| command               | RunnerCommand     | closed enum                                                    |
| run_id                | str               | non-empty, <= 128 chars                                        |
| status                | RunnerStatus      | closed enum; COMPLETE requires full references and no leftovers (consumer gate) |
| stop_reason           | Optional[str]     | non-empty, <= 128 chars when present; never hides a safety state |
| requested             | int               | >= 0; counts dispatches, prepare failures included             |
| completed             | int               | >= 0; completed <= requested; only full two-sided SELECT completions |
| comparable            | int               | >= 0; comparable == match + candidate and comparable <= completed |
| match                 | int               | >= 0                                                           |
| candidate             | int               | >= 0                                                           |
| inconclusive          | int               | >= 0                                                           |
| not_applicable        | int               | >= 0                                                           |
| leftover_objects      | int               | >= 0                                                           |
| leftover_sessions     | int               | >= 0                                                           |
| synthetic             | bool              | real/synthetic isolation marker                                |
| evidence_profile      | str               | exactly `"typecheck-full-evidence-v1"`                         |
| tool_version          | str               | non-empty, <= 64 chars                                         |
| contract_versions     | see below         | exactly the four names `case`/`execution`/`oracle`/`runner`, each once, values non-empty <= 64 chars |
| refs                  | see below         | logical name -> controlled relative path (section 4)           |
| sanitized_config_hash | str               | hex64 (section 3)                                              |

`contract_versions` is stored in memory as a tuple of `(name, version)`
pairs in the canonical name order, with accessor `contract_version(name)`.
`refs` is stored as a sorted tuple of `(name, path)` pairs with accessor
`ref(name)`; allowed names are the frozen set `environment`, `ownership`,
`runner_manifest`, `trace` plus per-attempt names of the form
`attempt:<attempt-id>` (non-empty attempt id after the prefix). Duplicate
names are rejected.

Golden JSON:

```json
{
  "schema_version": 1,
  "command": "RUN",
  "run_id": "run-20260906-1",
  "status": "COMPLETE",
  "stop_reason": null,
  "requested": 10,
  "completed": 9,
  "comparable": 8,
  "match": 6,
  "candidate": 2,
  "inconclusive": 1,
  "not_applicable": 1,
  "leftover_objects": 0,
  "leftover_sessions": 0,
  "synthetic": true,
  "evidence_profile": "typecheck-full-evidence-v1",
  "tool_version": "0.1.0",
  "contract_versions": {"case": "1", "execution": "1", "oracle": "o1", "runner": "1"},
  "refs": {
    "environment": "environment.json",
    "ownership": "ownership.jsonl",
    "runner_manifest": "runner-manifest.json",
    "attempt:attempt-001": "attempts/attempt-001"
  },
  "sanitized_config_hash": "46560d8270b80482321142a0a91efba1fc72c0b9aea5f6124268aee31f7e4e3e"
}
```

## 6. Non-goals

- No credentials in evidence: the models carry no password, DSN or token
  secret field. `password_env` is an environment-variable *name*; injecting a
  `password` key into a document is an unknown-field rejection.
- Schema 1 only: any other `schema_version` is rejected; no field of these
  models is optional-by-default or silently filled in.
- Unknown fields are rejected everywhere, on both the construction and the
  loader path; duplicate JSON keys, floats, bools in integer positions and
  non-canonical integer literals are rejected at parse time.
- No database driver, connection, I/O or filesystem access in this module;
  symlink/escape checks for controlled relative paths belong to the
  publisher and reader layers, not the model.
- The models validate structure and self-consistency only. Whether a run's
  counters, references and hashes describe a trustworthy execution is decided
  by the D2 oracle gates and the D3 controller, never by these records
  themselves.
