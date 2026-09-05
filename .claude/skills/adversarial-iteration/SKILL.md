---
name: adversarial-iteration
description: >
  Use for MTSQL diff-scoped static adversarial review after an implementation
  exists and review/fix iteration is needed. Each round starts with fresh
  `/codex:adversarial-review`, then a fresh round agent does scope review ->
  REFLECT -> plan -> fix -> static verify against the current diff. Focuses on
  source-grounded findings introduced, exposed, relied on, worsened, or blocked
  by the current change. It does not run remote UT/MTR and must not claim
  runtime verification. Do not use for formatting-only work, obvious one-line
  fixes, broad historical cleanup, or initial implementation before review.
---

# Adversarial Iteration

Work with adversarial review feedback instead of patching symptoms.

## Loop

```text
implement -> [/codex:adversarial-review -> spawn round agent -> scope review findings -> REFLECT -> plan -> fix -> static verify -> return summary] --+
               ^                                                                                                                                    |
               +-------- next round (fresh agent, clean context, re-reads files from disk) <--------------------------------------------------------+

  terminates when round agent reports ZERO_FINDINGS_STATIC.
```

For MTSQL, `verify` means **static verify**: source-grounded review, call-path
audit, invariant checks, and a concrete remote UT/MTR verification plan. This
skill does not run remote verification and must not report runtime correctness.

Do not commit during the loop. All changes stay in the working tree and commit
together after zero-finding termination.

Each round runs autonomously: do not ask the user questions or wait for user
gates. The user may interrupt, but otherwise pick the recommended path and
continue.

Every round MUST start by running `/codex:adversarial-review` in a fresh Codex
review agent against the current working tree. Do not reuse findings from a
previous round, and do not skip the Codex review because the orchestrator or
user already suspects the issue. If the fresh Codex review cannot run, stop the
loop as blocked rather than substituting stale or same-context review. The round
agent then validates the fresh Codex findings against the current diff,
classifies scope, and may add source-grounded findings found while re-reading
changed files.

Each round must re-read changed files from disk. Use a fresh round agent for
each round when available. If agents are unavailable, run inline but re-read
changed files, direct callers/callees, and relevant tests before reviewing.

## Diff Scope

Review the current diff, not the whole MTSQL codebase. Use one scope test:

```text
Would reverting this diff remove the bug, reachability, dependency, severity
increase, or correctness blockage?
```

If yes, classify it as `INTRODUCED_BY_DIFF`, `EXPOSED_BY_DIFF`,
`RELIED_ON_BY_DIFF`, `WORSENED_BY_DIFF`, or `BLOCKS_THIS_CHANGE`. If no, record
it briefly as `HISTORICAL_OUT_OF_SCOPE` and do not fix it. If unclear, mark
`UNCLEAR_NEEDS_CAUSALITY_CHECK` and keep it as `Question`, not `Blocking`, until
scope is clear.

Use `/codex:adversarial-review` as the adversarial reviewer for every round.
Ground all accepted findings in the current diff, changed files, direct
callers/callees, relevant MTR/gunit/result/baseline files, and nearby
comments/docs. Do not perform unbounded architecture review. Do not invent
MySQL/InnoDB semantics. Every accepted finding needs source evidence.

Accepted findings must include scope, severity, `file:line`, source evidence,
violated invariant, failure mode, and suggested fix or verification. Blocking
findings must be real current-change correctness risks: concurrency, lifecycle,
recovery, persistent format, transaction visibility, binlog/replication,
resource leak, or security.

## REFLECT

For each accepted in-scope finding, answer:

1. What did I do wrong? One sentence, no euphemisms.
2. Why did I miss it? Name the unverified assumption.
3. Which `CLAUDE.md` rule did I violate?
4. What static cheap check would have caught it?

Then name the unifying root-cause shape across findings.

Common MTSQL shapes:

- Solved the named case, not the invariant.
- Solved one mode, broke RO/RW parity.
- Assumed redo/recovery behavior without tracing it.
- Missed lock/latch ordering across layers.
- Relied on historical behavior without proving diff causality.
- Updated result files or helper usage without behavior evidence.

## Static Cheap Checks

Run the checks relevant to the finding before writing fix code:

1. **Diff causality** — Would reverting this diff remove the problem?
2. **Call-path contract** — Read direct callers/callees and producers.
3. **Concurrency / visibility** — Check lock/latch order, ReadView, and RO/RW.
4. **Redo / recovery / page lifecycle** — Trace changed state through recovery
   paths.
5. **Test oracle** — Name the remote MTR/gunit/manual verification.

## Plan, Fix, Verify

MTSQL UT/MTR usually requires a Linux dev environment. Before editing, make a
compact plan:

- REFLECT root-cause shape.
- Smallest fix that satisfies the violated invariant.
- Remote MTR/gunit/manual verification, expected signals, and runtime risk if
  not run.

Do not claim the verification passed unless it actually ran.

Fix only in-scope findings.

- Make the smallest change that satisfies the violated invariant.
- Do not refactor unrelated legacy code.
- Do not clean historical debt.
- Do not rename existing symbols for style-only reasons.
- Preserve nearby MySQL 8.0 / InnoDB style.

For MTSQL, verify means static verify. Before returning a round summary, re-read
changed files and check relevant callers/callees, tests/baselines,
error/cleanup paths, and MTSQL invariants touched by the diff: redo/recovery,
transaction visibility, binlog/replication, RO/RW behavior, page lifecycle,
lock/latch ordering, and persistence / on-disk format. List required remote
UT/MTR/manual verification.

If static verify discovers a new in-scope issue, convert it to a finding and do
not return `ZERO_FINDINGS_STATIC`.

Static verify does not prove runtime correctness.

## Round Handoff

After static verify, do these before the next round:

1. Audit changed files:
   `grep -rn 'round\|TODO.*round\|HACK\|FIXME\|debugging\|TEMP' <changed files>`
2. Remove round narrative, debugging scaffolding, and stale TODOs.
3. Build a short summary:

```text
### Round N complete
- Status: NEEDS_NEXT_ROUND | ZERO_FINDINGS_STATIC
- Findings: <in-scope findings or none>
- Historical out-of-scope: <optional, short>
- Root-cause shape: <if findings existed>
- Fixes: <2-3 sentences>
- Files changed: <paths>
- Static verification: <callers/callees/invariants checked>
- Required remote verification: <MTR/UT/manual plan or none>
- Remaining runtime risk: <if any>
```

Keep the summary concise. It is signal, not transcript.

4. Run fresh Codex review for the next round:

Run `/codex:adversarial-review` in a fresh Codex review agent against the
current working tree. If it cannot run, stop the loop and report the blocker.
Do not reuse previous findings.

5. Spawn a fresh round agent:

Read [references/round-agent-prompt.md](references/round-agent-prompt.md) and
populate it with:

- The round number.
- All accumulated prior round summaries.
- The list of changed files.
- Fresh findings from the next round's `/codex:adversarial-review`.

Spawn a **general-purpose agent** for the round. Do not spawn `codex:rescue`:
the round agent needs Read/Write/Edit/Bash for the full
scope-review -> REFLECT -> plan -> fix -> static-verify cycle. The fresh
context window is the compaction mechanism; no `/compact` is needed.

## Termination

Stop only when the latest round completes static verify and reports
`ZERO_FINDINGS_STATIC`: no source-grounded in-scope `Blocking` or unresolved
`Question` remains for the current diff, and required remote UT/MTR/manual
verification is listed or explicitly not needed.

`ZERO_FINDINGS_STATIC` is not runtime verified. Remote UT/MTR is a separate
verification step.

## This Project's Codebase

- Adversarial review: `/codex:adversarial-review`
- Loop runner: `/loop` when available
- Commit pattern: all changes commit together after zero-finding termination.
