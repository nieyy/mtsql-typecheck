# MTSQL TypeCheck

A database correctness testing tool that detects type-related SQL logic bugs
through compatible schema and data transformations.

> Status: design in progress. No test engine, stable CLI, or result format is
> available yet.

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
