# MTSQL TypeCheck

A database correctness testing tool that detects type-related SQL logic bugs
through compatible schema and data transformations.

> Status: the D1 offline generation and validation core is implemented
> (deterministic case generation, bundle writing, and the offline CLI below).
> No database connection, execution, comparison, or reduction capability
> exists yet (D2-D4 are not implemented).

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
(D2/D3 designs are not implemented). Successful generation or offline
validation is not database certification of any kind.

## Design

The authoritative design is maintained in the `mtsql_helper` repository:

- [TypeCheck Overall Architecture and Correctness Contracts (D0, Chinese)](https://github.com/nieyy/mtsql_helper/blob/main/docs/designs/2026-09-04-mtsql-typecheck-overall-design-zh.md)

D0 provides the common contracts and index for focused D1-D4 designs covering
generation, checking and reduction, adapters, and reporting.

## Scope Boundaries

This project is independent of `mtsql_benchmark` and `mtsql-htap-benchmark`.
It does not initially aim to support arbitrary SQL, prove a database free of
bugs, test replication or concurrent transactions, or modify database internals.
Cross-engine differences are not automatically database bugs.

## License

The repository license has not been selected. Third-party code must not be
imported until its license and provenance have been reviewed.
