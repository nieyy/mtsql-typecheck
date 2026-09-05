# CLAUDE.md

Project rules for AI agents working in this repository.

## Project

`mtsql-typecheck` is an independent Python tool for detecting type-related SQL
logic errors through compatible database construction. The first target is
MySQL/MTSQL 8.0 within one instance and engine, not arbitrary cross-engine SQL.

This repository holds source, tests, and project documentation. Never commit
credentials, raw runs, generated evidence, or unrelated database product code.

## Sources of Truth

Read `README.md`, the current code and tests, and the designs linked from the
README. D0 owns common correctness contracts; D1-D4, once available and
approved, own generation, checking/reduction, execution, and reporting.
Do not implement unresolved design choices as hidden defaults. Surface code
and design disagreements with evidence.

## Core Invariants

- Storage-compatible types are not necessarily operation-compatible. Check
  value domains, intermediate values, session settings, and rule assumptions.
- Keep generation and comparison independent of database connections. Put
  database-specific behavior behind capability-aware adapters.
- Do not infer rule correctness merely because generated results agree.
- Preserve exact numbers, NULLs, duplicate rows, and declared ordering
  semantics. Never normalize all values to strings or floating point.
- A mismatch is a candidate finding, not a confirmed bug. Timeouts, SQL errors,
  truncated results, and missing evidence must not become successful matches.
- Revalidate assumptions after every reduction and rerun in fresh test objects.
- Preserve original cases and every attempt. Seeds alone are not reproduction
  evidence; freeze generated inputs, rule versions, and environment details.
- Modify or clean up only explicitly authorized objects with verified ownership.

## Workflow

Every change follows:

```text
understand -> research -> design -> implement -> test -> verify
```

### Understand

- Inspect branch state, recent commits, relevant code, tests, and configuration.
- Identify the affected contract and preserve unrelated work.

### Research

- Look for existing patterns before adding dependencies or abstractions.
- Ground compatibility claims in reviewed rules and authoritative semantics;
  distinguish paper facts from this project's independent decisions.

### Design

- Follow D0 and the applicable approved subdesign; D0 alone does not authorize
  implementing all D1-D4 behavior.
- Update the owning design before changing correctness semantics, public
  contracts, evidence formats, or safety boundaries.

### Implement

- Use Python 3.11 or newer; Linux/Python 3.11 is the required baseline.
- Use an independent interpreter and venv on remote Linux. Never replace the
  system Python or install project dependencies into it.
- Keep changes focused, use type hints at module boundaries, and prefer
  structured parsing and plain data contracts over speculative frameworks.
- Make randomness, clocks, and I/O injectable when determinism requires it.
- Keep resource budgets, cancellation, partial failures, and cleanup explicit.
- Never add credentials or silently enable unreviewed rules.

### Test

- Cover rule preconditions, exact comparison, reduction validity, serialization,
  cancellation, limits, ownership, and failure paths as applicable.
- Use independently reviewed golden cases and deliberately invalid cases;
  do not generate expected results using the same algorithm under test.
- Run focused tests first, then the configured broader suite. Never weaken
  assertions or discard mismatches merely to make tests pass.
- Use only authorized disposable targets for integration testing. Fake tests
  do not establish real-driver or remote-Linux compatibility.

### Verify

- Run `python -m pytest` when tests exist, using the project environment.
- Run the formatter, linter, type checker, and integration checks actually
  configured in the project. Do not invent successful check results.
- Review staged content for scope, secrets, raw evidence, and generated files.
- Report commands and outcomes, including skipped checks and their reasons.

### Cross-cutting

- Ask before expanding correctness semantics, destructive behavior, or license
  and security policy beyond the approved design.
- Preserve inconclusive and partial states; zero comparable cases is not a pass.
- Keep comments focused on invariants and non-obvious decisions.

## Git

Use focused subsystem commits, for example:

```text
rules: add a bounded integer compatibility rule
oracle: preserve duplicate result rows
runner: retain evidence after cancellation
docs: clarify reduction preconditions
```

Before committing or pushing, review the staged diff and actual verification
results. In Claude Code, run the configured `claude-md-auditor` audit and honor
the repository hooks. Other agents must review these rules and report their
checks without fabricating a Claude audit verdict. An optional review skill
does not replace required tests for Python changes.
