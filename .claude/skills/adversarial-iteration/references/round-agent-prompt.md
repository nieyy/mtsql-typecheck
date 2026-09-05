# Round Agent Prompt Template

Fill in the bracketed sections before starting a fresh static review/fix round.

---

You are running round [N] of an MTSQL diff-scoped static adversarial iteration
loop.

MTSQL is a MySQL-derived database kernel evolving toward storage-compute
separation. Follow repository `CLAUDE.md`: current working tree is
authoritative, local MySQL 8.0 style wins, and redo/recovery/visibility/binlog/
replication/page lifecycle/persistence/locking changes are high risk.

This loop does not run remote UT/MTR. It performs static verification and must
not claim runtime correctness.

## Prior round summaries

[Paste accumulated round summaries here. If this is round 1, write:
"This is the first review round."]

## Files changed so far

[List all changed files.]

You MUST re-read every file in this list from disk. Also read direct
callers/callees and relevant MTR/gunit/result files when needed to verify
invariants. Do not rely on cached content.

## Codex findings for this round

[Paste findings from this round's fresh `/codex:adversarial-review` run here.
If there are none, write: "No findings."]

## Task

1. Re-read changed files from disk.
2. Validate the Codex findings against the current diff and directly relevant
   source/test context. You may add source-grounded findings found while
   re-reading changed files.
3. Classify findings with the scope test: would reverting the current diff
   remove the bug, reachability, dependency, severity increase, or correctness
   blockage? Use `INTRODUCED_BY_DIFF`, `EXPOSED_BY_DIFF`, `RELIED_ON_BY_DIFF`,
   `WORSENED_BY_DIFF`, `BLOCKS_THIS_CHANGE`, `HISTORICAL_OUT_OF_SCOPE`, or
   `UNCLEAR_NEEDS_CAUSALITY_CHECK`. Do not fix historical debt.
4. For each accepted in-scope finding, require:
   - Severity: Blocking | Question | Nit
   - Location: file:line
   - Evidence: diff hunk or nearby source fact
   - Violated invariant
   - Failure mode
   - Suggested fix or verification
5. If there are no in-scope findings, perform static verify and return:

   ```text
   ### Round [N] complete
   - Status: ZERO_FINDINGS_STATIC
   - Findings: none
   - Static verification: <files/callers/callees/invariants checked>
   - Required remote verification: <MTR/UT/manual plan or none>
   - Remaining runtime risk: <if any>
   ```

6. For valid in-scope findings, run REFLECT:
   - What did I do wrong?
   - Why did I miss it?
   - Which `CLAUDE.md` rule was violated?
   - Which static cheap check catches it?
   - What is the unifying root-cause shape?
7. Run relevant static cheap checks before editing:
   - Diff causality check.
   - Call-path / producer contract check.
   - Concurrency / visibility check.
   - Redo / recovery / page lifecycle check.
   - Test oracle check.
8. Draft a compact plan: root-cause shape, smallest fix, remote MTR/gunit/manual
   verification plan, expected fail/pass signals, and runtime risk if not run.
9. Fix only in-scope findings with the smallest change.
10. Perform static verify: re-read changed files; check relevant
    callers/callees, tests/baselines, MTSQL invariants, error/cleanup and
    crash-recovery implications; list remote verification plan.
    If static verify discovers a new in-scope issue, convert it to a finding and
    do not return `ZERO_FINDINGS_STATIC`.
11. Audit changed files for stale round/debug comments:
    `grep -rn 'round\|TODO.*round\|HACK\|FIXME\|debugging\|TEMP' <changed files>`
12. Return a concise summary:

   ```text
   ### Round [N] complete
   - Status: NEEDS_NEXT_ROUND
   - Findings: <in-scope findings>
   - Historical out-of-scope: <optional, short>
   - Root-cause shape: <shape>
   - Fixes: <2-3 sentences>
   - Files changed: <paths>
   - Static verification: <callers/callees/invariants checked>
   - Required remote verification: <MTR/UT/manual plan or none>
   - Remaining runtime risk: <if any>
   ```

## Rules

- Do NOT commit.
- Do NOT run or orchestrate remote UT/MTR.
- Do NOT claim runtime verification.
- Do NOT ask the user questions; pick the recommended path and continue.
- Do NOT skip REFLECT for accepted findings.
- Do NOT invent MySQL/InnoDB semantics.
- Every accepted finding needs `file:line` source evidence.
- Keep the returned summary concise and source-grounded.
