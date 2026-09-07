# MTSQL TypeCheck

A database correctness testing tool that detects type-related SQL logic bugs
through compatible schema and data transformations.

> Status: the D1 offline generation and validation core is implemented
> (deterministic case generation, bundle writing, and the offline CLI below).
> The D2 offline result-comparison and counterexample-reduction core is also
> implemented (typed exact multiset comparison gates, bounded 3-attempt
> replay, deterministic complexity-guided reduction, and an append-only
> trace) as importable Python protocol modules operating on execution
> evidence models. The D3 runner, MySQL 8.0 text-protocol adapter, and online
> CLI are implemented as well (see the online CLI section below), including a
> supervised subprocess executor, an append-only ownership journal, bounded
> cancellation/cleanup, and full evidence output. **No live-environment
> certification has been performed yet**: online behaviour is exercised in
> tests through hand-written fakes and protocol fixtures, never against a
> real database; the honest COVERED/NOT_RUN verification matrix is
> `docs/runner-d3-verification.md`. The D4 offline evidence-verification,
> reporting, and delivery CLI is also implemented (see the D4 offline CLI
> section below); its honest verification record is
> `docs/delivery-d4-verification.md`.

## Motivation

A query can execute successfully and still return an incorrect result. Instead
of requiring a hand-written answer for every query, this project constructs
related cases whose results should agree under explicit compatibility conditions.

The central idea is to preserve logical data values while changing selected
column types. Storage compatibility alone is not enough: operations,
intermediate values, and session semantics must also preserve the expected
relationship.

This project is inspired by *Detecting Data-Type-Related Logic Bugs in
Relational DBMSs via Compatible Database Construction* (VLDB 2026), listed on
[Wensheng Dou's publications page](https://wsdou.github.io/paper.html).
It is an independent implementation, not the authors' official TypeCheck tool
or a claim of full paper reproduction.

## Correctness Principles

- Use reviewed compatibility rules with explicit assumptions and exclusions.
- Compare only complete, comparable results; missing evidence is not a pass.
- Preserve exact values, NULLs, and duplicate rows during comparison.
- Treat a mismatch as a candidate finding, not a confirmed database bug.
- Recheck compatibility conditions whenever a counterexample is reduced.
- Preserve original inputs, environment details, and execution evidence so
  findings can be reproduced independently of the generator.
- Operate only on explicitly authorized, tool-owned test objects.

## Direction

The initial target is MySQL/MTSQL 8.0, comparing controlled datasets within the
same database instance and engine. Capability-aware adapters and versioned
rules can extend the approach to other versions and systems over time.

The project separates compatibility rules and generation, result checking and
counterexample reduction, database execution, and evidence reporting.
Database-specific behavior must not silently change the correctness contract.

## Runtime

The planned minimum is Python 3.11, with Linux as the initial validation
platform. On remote Linux machines, use a separately installed interpreter and
a project virtual environment; do not replace the operating system's Python.
Installation and execution commands will be documented when implemented.

### Implemented: offline generation and validation CLI

The `mt-typecheck` entry point (installed with `pip install .`) provides two
offline commands. They never accept a DSN, never connect to a database, and
make no network calls.

```console
$ mt-typecheck generate --profile mysql80-exact-v1 --seed 42 --cases 100 \
      --output /path/to/new-directory
$ mt-typecheck validate --input /path/to/new-directory
```

`generate` deterministically produces a case bundle (`generation-manifest.json`,
`profile.json`, and one directory per case under `cases/`) into a directory
that must not already exist; symlink path components are never followed and
nothing inside an output directory is deleted or overwritten. `validate`
re-derives every case identity, rule reference, static check, preview SQL, and
file hash from the stored bytes; it is read-only.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | `generate`: all requested ordinals emitted, manifest `COMPLETE`. `validate`: manifest `COMPLETE` and every offline check passed. This is an offline success only — it never means a database MATCH. |
| 2 | Illegal input (usage errors, unknown/disabled rule or version, existing output directory, symlink component); for `validate`: corrupt, illegal, or unverifiable evidence (corruption outranks incompleteness). |
| 3 | `generate`: a legal request that did not finish (retry/budget exhaustion, zero cases). `validate`: saved content is valid but the manifest is `PARTIAL`/`ABORTED`/legacy `RUNNING`. |
| 1 | Tool internal error or non-content I/O failure. |
| 130 | The process was cancelled by the user (SIGINT); completed evidence is preserved and the terminating manifest is written. |

The built-in profile `mysql80-exact-v1` (the only built-in name) selects the
four reviewed exact-numeric rules at version 1, templates Q1-Q4, both index
variants, and the default budgets of the D1 design. Alternatively,
`--profile-file PATH` loads a restricted JSON profile (schema 1) that may
filter these already-reviewed rule/template/index combinations and adjust
budgets within hard caps; unknown fields, duplicate selectors, unknown or
disabled rule versions, and over-cap budgets are rejected. Missing documented
fields are backfilled from the built-in defaults. `--profile` and
`--profile-file` are mutually exclusive; when neither is given the built-in
profile is used. `--seed` and `--cases` are per-request parameters and are not
part of the profile hash.

Scope: this is the D1 offline capability only. It does not include database
connection or execution, a result comparator, or counterexample reduction
(D3/D4 designs are not implemented). Successful generation or offline
validation is not database certification of any kind.

### Implemented: D2 offline comparison and reduction protocol (library)

The `mtsql_typecheck.oracle` and `mtsql_typecheck.reduction` packages provide
the D2 capability as a Python library; the online CLI below drives them
through the D3 runner, and the modules themselves still perform no database
access of any kind:

- `oracle.exact` — canonical value keys and full exact multiset comparison
  (integer arithmetic only; NULL never equals 0; duplicate rows preserved;
  bounded witness output).
- `oracle.gates` — `compare_case`, the ordered evidence gate pipeline that
  turns one execution-evidence bundle into a MATCH, a MISMATCH_CANDIDATE
  (with exact signature, fingerprint, and witness), or an explicit
  INCONCLUSIVE outcome with stable reason codes. Timeouts, SQL errors,
  truncated results, and missing evidence never become successful matches.
- `reduction.replay` — `replay_candidate`, a bounded 3-attempt replay group
  (AB, BA, AB) that re-comparisons the original observation and only labels
  it REPRODUCED when all three attempts agree on signature, fingerprint,
  environment, and terminal state.
- `reduction.strategy` — the deterministic reduction proposal order
  (remove rows, simplify predicates, replace values and literals) and the
  strictly decreasing complexity metric that guides the search.
- `reduction.engine` — `reduce_candidate`, the bounded reduction loop that
  re-verifies every child through a fresh replay group before accepting it
  and preserves the last verified best across budget exhaustion,
  cancellation, and faults.
- `reduction.trace` — an append-only, hash-chained JSONL trace with
  atomically published payload files and a read-only audit (PARTIAL/CORRUPT
  handling; the last verified ACCEPTED record is the only persistent best
  authority).

All comparison and reduction state is kept independent of database
connections: execution facts enter through the `ExecutionPort` protocol and
evidence models in `mtsql_typecheck.contracts`. A mismatch candidate is
never a confirmed bug, and reduced candidates are revalidated from scratch
in fresh test objects.

### Implemented: online execution CLI (D3 runner and MySQL adapter)

The `mt-typecheck` entry point additionally provides five online commands —
`preflight`, `run`, `replay`, `reduce`, and `cleanup` — that execute a
generated case bundle against a **dedicated, explicitly authorized**
MySQL/MTSQL 8.0 instance and produce D2-verifiable execution evidence.
These commands are covered by offline tests (fakes, protocol fixtures, and
fault injection) only; live-environment certification on real Linux +
MySQL/MTSQL 8.0 has **not** been performed and remains NOT_RUN — see
`docs/runner-d3-verification.md`.

Install with the certified driver extra:

```console
$ python3.11 -m venv .venv
$ .venv/bin/python -m pip install '.[mysql]'
$ export TYPECHECK_MYSQL_PASSWORD='...'
```

The `mysql` extra pins `PyMySQL==1.1.2` (see
`requirements/mysql-certified.txt`): only the narrow text-protocol shim
`adapters/mysql_protocol.py` may touch driver internals, it is version-gated
on exactly this release, and it fails closed on any other version. Without
the extra installed, `--help` for every command still works, but each online
command refuses to run (exit 2) instead of falling back to something less
faithful.

The target is described by a `target.json` file (schema 1; the frozen
field-by-field contract is `docs/runner-d3-contract.md`):

```json
{
  "schema_version": 1,
  "adapter": "mysql80-text-v1",
  "host": "mysql-test.example.internal",
  "port": 3306,
  "unix_socket": null,
  "user": "typecheck",
  "password_env": "TYPECHECK_MYSQL_PASSWORD",
  "expected_server_uuid": "1f0e3d2c-4b5a-4678-9abc-def012345678",
  "build_id": "replace-with-certified-build-or-commit",
  "database_prefix": "tc_",
  "dedicated_test_instance": true,
  "tls": {"mode": "disabled"}
}
```

`host`/`port` and `unix_socket` are mutually exclusive (exactly one transport;
both fields must be present). TCP targets must explicitly choose
`tls.mode: verify_identity` with a `ca_file`, or explicitly `disabled` for an
approved isolated network. The `expected_server_uuid` above instantiates the
design's placeholder: the D3 design's `target.json` example uses
`"replace-with-test-server-uuid"`, which is not a valid UUID and is rejected
by the contract, so a real UUID string is required. The password is read only
from the environment variable named by `password_env` and is never serialized
into evidence.

Commands (documented as implemented):

```console
$ mt-typecheck preflight --target target.json --output /data/typecheck/preflight-001
$ mt-typecheck run --input /data/typecheck/cases-001 --target target.json \
      --output /data/typecheck/run-001 [--cases N] [--evidence-budget-mib 256]
$ mt-typecheck replay --attempt /data/typecheck/run-001/attempts/attempt-001 \
      --output /data/typecheck/replay-001 [--target target.json]
$ mt-typecheck reduce --attempt /data/typecheck/run-001/attempts/attempt-001 \
      --output /data/typecheck/reduce-001 [--target target.json]
$ mt-typecheck cleanup --input /data/typecheck/run-001
$ mt-typecheck cleanup --input /data/typecheck/run-001 --apply --target target.json
```

Note: the D3 design's 6.3.1 example sketches `--input` for `replay`/`reduce`;
the implemented interface takes `--attempt ATTEMPT-DIRECTORY` (one recorded
candidate attempt). For `replay`/`reduce`, `--target` is optional: without it
the candidate is never re-executed and the command reports NOT_REPLAYED /
NO_EXECUTOR (exit 3) rather than claiming a reproduction. `preflight` is
read-only by default (it may run session `SET`/read-back probes); `cleanup`
without `--apply` only inventories leftover objects from the run's
`ownership.jsonl`.

Exit codes for the online commands (safety outranks differences, which
outrank incompleteness):

| Code | Meaning |
| --- | --- |
| 0 | The selected work completed with no candidate difference. Zero comparable cases is still shown explicitly and is not a pass. |
| 4 | The work completed and there is a trusted candidate (run), a fully reproduced counterexample (replay), or a still-valid reduced best (reduce). This is not a confirmed database bug. |
| 3 | Partial execution, inconclusive outcomes, budget-stopped work, unsatisfied environment with zero comparable cases, or unstable/not-replayed results. |
| 2 | Illegal input or configuration, corrupt evidence, or a target/authorization refusal — before any test execution started (missing certified driver included). |
| 1 | Tool, persistence, or infrastructure failure, or unsafe/unknown termination or cleanup. |
| 130 | Cancelled by the user (SIGINT); partial evidence is sealed and actual terminal/cleanup receipts must still be read. |

Output directory layout (exclusive creation, atomic publication, manifest
sealed last; plus a `run.lock` while the run is live):

```text
<output>/
  runner-manifest.json
  environment.json
  ownership.jsonl
  run.lock
  attempts/<attempt-id>/
    request.json
    expectation.json
    execution-evidence.json
    comparison.json
    observations.jsonl
    terminal.json
  payloads/<content-hash>.json
  trace.jsonl                 # replay/reduce outputs
```

Evidence budgets: `--evidence-budget-mib` bounds one run's total evidence
(default 256 MiB, hard cap 1024 MiB); a run stops dispatching rather than
overrunning it. Internally each attempt is bounded to 30 s of wall clock
under a 600 s run wall-clock default, each comparison to 5 s, each result
fetch to 4096 rows / 8 MiB / 5 columns per side (32 MiB per execution
evidence), and diagnostics to 128 statements / 2 KiB per message; exceeding
any of these is recorded as truncated/incomplete and never silently compared.

Safety model: the target must be declared a dedicated test instance
(`dedicated_test_instance: true`) and bound to the expected `server_uuid`.
Test objects are created only under fresh random names
(`tc_<run-token>_<attempt-token>_a/b`, prefix fixed to `tc_`) with an
append-only ownership journal; a fixed D3 ownership marker table is created
in each new database before any test table. Cleanup drops only the exact
object set this run recorded as created — never a prefix pattern — and any
missing marker, extra object, or unconfirmable termination quarantines the
run: no further dispatch, leftovers inventoried by `cleanup`, manual
resolution required.

### Implemented: D4 offline evidence verification, reporting, and delivery CLI

The `mt-typecheck` entry point additionally provides three offline commands —
`evidence-verify`, `report`, and `export` — that turn already-written
evidence into verifiable snapshots, reviewable reports, and standalone
SQL/regression packages. Like `generate`/`validate`, they never accept a DSN,
a target file, or a password, never import a database driver, and make no
network calls. Their exit codes are defined separately from both tables above
and computed by one shared mapping.

```console
$ mt-typecheck evidence-verify --input /data/typecheck/run-001 --output /data/typecheck/check-001
$ mt-typecheck report --input /data/typecheck/reduce-001 --output /data/typecheck/report-001 \
      [--review /data/typecheck/review.json ...]
$ mt-typecheck export --input /data/typecheck/report-001 --case-id <case-id> \
      --select original --format sql --output /data/typecheck/repro-001 \
      [--occurrence-id <occurrence-id>] [--review FILE ...]
$ mt-typecheck export --input /data/typecheck/report-002 --case-id <original-case-id> \
      --select best --format regression --review /data/typecheck/review.json \
      --output /data/typecheck/regression-001
```

Input is always a single directory whose native format is auto-detected: a
D1 generation bundle, a D3 run, a D2 `trace.jsonl` (its `replay-result.json`
/ `reduce-result.json` belong to the same format), a standalone attempt, or
an existing D4 delivery package. `--input-kind
generation|run|trace|attempt|delivery` is a diagnostic hint for a missing
root summary only; it cannot hide anything. Evidence that contradicts the
hint, roots carrying several mutually exclusive markers, and additional
orphan files (which are recorded, never dropped) are still detected and
reported. Reports never aggregate multiple runs — mixing builds or rule
versions silently is exactly what the design forbids; compare separate
`report.json` files explicitly instead.

`evidence-verify` writes a verification package (`evidence-manifest.json`,
`assessment.json`, and the immutable `raw/<source-id>/...` snapshot tree)
with no display pages. `report` additionally renders `report.json`,
`report.md`, and `report.html`; running `evidence-verify` first is not
required. `report.json` is the single structured record of facts — Markdown
and HTML are formatting of exactly the same content — and no report ever
shows an aggregate PASS: partial evidence, checks that were not recomputed,
UNVERIFIED provenance, UNKNOWN/UNSAFE execution safety, and review conflicts
stay visible in every rendering.

Exit codes (evaluated top-down; several causes keep every reason recorded):

| Code | Meaning |
| --- | --- |
| 0 | `evidence-verify`/`report` completed every applicable check and none of the conditions below applies; or `export` completed fully under the delivery gates. This is an offline outcome only — never a statement about database correctness. |
| 4 | `evidence-verify`/`report` completed every applicable check and the evidence contains a recomputable candidate. A candidate is not a confirmed bug. |
| 3 | Nothing was rejected, but work is PARTIAL, applicable checks were not recomputed, provenance is UNVERIFIED, execution safety is UNKNOWN/UNSAFE, a review conflict survives, or the audit budget expired. |
| 2 | Illegal, corrupt, or unknown-schema input; a structural/semantic/provenance CONFLICT; an illegal review file; or an ambiguous case/occurrence selection. |
| 1 | Tool-internal failure or output I/O failure (including ENOSPC). |
| 130 | Cancelled by the user (SIGINT); no COMPLETE manifest is published. |

`export` writes a standalone reproduction package into a new directory:
`delivery-manifest.json`, `README.md`, `case.json`, `expected.json`,
`environment-requirements.json`, `a.sql`, `b.sql`, `origin.json`; the
regression format adds `regression-case.json` and a copy of the accepted
review. `a.sql`/`b.sql` each contain the whitelisted session `SET`
statements, `CREATE DATABASE` (never `IF NOT EXISTS`), `USE`, the table DDL,
the exact `INSERT`s, and the `SELECT`. The case SQL is rendered by the D1
renderer with the database/USE/SET wrapping added — SQL is never extracted
from logs or string-rewritten, session values are rendered only from
validated typed fields against a variable whitelist (a hostile session value
cannot compose a second statement), and physical database/table names come
from a legal random token recorded in the export NameMap without changing
logical case identity. There is no `DROP`, no `mysql --force`, and no
automatic cleanup: a name collision stops the run and the operator exports
into a fresh directory with a fresh token.

Boundaries worth stating plainly:

- The export package is **not** a D1 generation bundle and cannot be fed to
  `run --input` (which only accepts generation bundles); this version also
  does not re-import an export package as `report` input.
- `expected.json` holds the relational assertion (for example "both sides'
  typed multisets are exactly equal", with a separate reference to the
  historical observation) — never the mismatching database output as a
  "correct" expectation.
- `--format regression` requires a valid human review with decision
  `CONFIRMED_DB_BUG` and a recomputable candidate; `--select best`
  additionally requires a verified `ACCEPTED` ancestor chain and a current
  best reference — without a valid best the command fails instead of
  silently falling back to `original`. A review conflict refuses the
  regression export.
- SQL debug export (`--select original --format sql`) is allowed without a
  review, but the package README then marks the case as an unverified
  candidate. Cases with broken identity/prerequisites are refused for any
  executable export.
- Each command creates its output directory exclusively (an existing
  directory is refused; nothing is ever overwritten) and exposes the limit
  flags `--time-budget-seconds`, `--max-input-mib`, and `--max-output-mib`;
  none of them can be set to unlimited.

## Testing

Three groups (D3 design section 7 and the D4 design Phase 5 regrouping):

- **Offline core** (default; no mysql extra installed, no PyMySQL
  importable):
  `python -m pytest --strict-markers -m 'not mysql and not integration'
  --ignore=tests/unit/adapters --ignore=tests/unit/runner
  --ignore=tests/unit/cli/test_installed_cli.py`
- **Protocol regression** (pinned `mysql` extra installed; still strictly
  offline, no target, no credentials):
  `python -m pytest --strict-markers -m 'not mysql and not integration'`
- **Online `mysql` group** (requires the certified driver and a live,
  authorized target): `TYPECHECK_TARGET_CONFIG=/secure/target.json python -m
  pytest --strict-markers -m mysql`

The first group runs the D4/core and offline D1/D2 suites in an environment
without the driver; the second runs the D3 protocol tests (which import
PyMySQL at collection time) with the pinned driver installed. Neither group
deletes or skips protocol tests for a missing driver — the split lives in
`.github/workflows/ci.yml` (`offline-core` and `protocol-offline` jobs).
The D4 offline closed-loop test `tests/integration/test_delivery_offline.py`
carries no online marker and is collected by the default offline runs.

The `mysql` and `integration` markers are registered in `pyproject.toml` and
deselected by the offline command. Selecting the `mysql` group without a
configured target must fail the job, not skip it green — that gating lives in
`.github/workflows/ci.yml`. No live-marked test exists yet; live
certification is NOT_RUN (see `docs/runner-d3-verification.md`).

## Design

The authoritative design is maintained in the `mtsql_helper` repository:

- [TypeCheck Overall Architecture and Correctness Contracts (D0, Chinese)](https://github.com/nieyy/mtsql_helper/blob/main/docs/designs/2026-09-04-mtsql-typecheck-overall-design-zh.md)
- [TypeCheck D2 Result Oracle and Counterexample Reduction (Chinese)](https://github.com/nieyy/mtsql_helper/blob/main/docs/designs/2026-09-05-mtsql-typecheck-result-oracle-counterexample-reduction-design-zh.md)
- [TypeCheck D3 Runner and Database Adapter (Chinese)](https://github.com/nieyy/mtsql_helper/blob/main/docs/designs/2026-09-06-mtsql-typecheck-runner-database-adapter-design-zh.md)
- [TypeCheck D4 Evidence, Reporting, and Regression Delivery (Chinese)](https://github.com/nieyy/mtsql_helper/blob/main/docs/designs/2026-09-06-mtsql-typecheck-evidence-reporting-regression-delivery-design-zh.md)

D0 provides the common contracts and index for focused D1-D4 designs covering
generation, checking and reduction, adapters, and reporting.

## Scope Boundaries

This project is independent of `mtsql_benchmark` and `mtsql-htap-benchmark`.
It does not initially aim to support arbitrary SQL, prove a database free of
bugs, test replication or concurrent transactions, or modify database internals.
Cross-engine differences are not automatically database bugs.

## License

This project is released under the MIT License; see `LICENSE` for the full
text. Third-party code must still not be imported until its license and
provenance have been reviewed.
