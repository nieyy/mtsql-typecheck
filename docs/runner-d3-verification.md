# D3 Runner Verification Matrix (runner-d3-verification)

Honest COVERED / NOT_RUN record for the D3 design
(`2026-09-06-mtsql-typecheck-runner-database-adapter-design-zh.md`, section 7,
Phases 1-6, and the 必要负例矩阵). Every COVERED row cites automated tests that
exist in this tree; every live requirement that has not been exercised against
a real, authorized MySQL/MTSQL 8.0 target is explicitly NOT_RUN. This document
does not upgrade offline (fake/fixture) evidence into live certification.

Recording rules (design section 7): 未运行保留 NOT_RUN；不能以“有明确阻塞说明”
替代退出标准. Report recorded: 2026-09-06, branch `nieyy/d3` (working tree,
commit hashes pending commit authorization).

## 0. Environment actually used

| Item | Value |
| --- | --- |
| Host OS | macOS (Darwin 24.6.0) — **not** the required Linux baseline |
| Python | 3.14.5 (local `.venv`) — the design baseline is Linux + Python 3.11/3.12 |
| Live MySQL/MTSQL 8.0 target | none authorized in this environment |
| Certified driver | PyMySQL==1.1.2 installed and version-gate tested offline; no live connection was made |
| Full offline suite | see section 4 for the recorded totals of the final run |

Because the platform is macOS and no live target exists, every gate marked
"real" in the design matrix is NOT_RUN, and the Linux/Python-3.11 regression
rows are NOT_RUN as well. The offline suite runs on the local interpreter as a
regression signal only.

## 1. Phase exit criteria

### Phase 1 — joint contract and D2 online-handover fixes (A01-A06)

| Criterion | Status | Evidence |
| --- | --- | --- |
| A01 independent expectation binding / replaced-binding refusal (G01) | COVERED (offline) | `tests/unit/reduction/test_online_handover.py` (G01 sections, 20 tests total), `tests/unit/oracle/test_gates.py` (gate-1 expectation-binding checks) |
| A02 preflight ordering + rejection proof, session-chain gate (G02) | COVERED (offline) | `tests/unit/oracle/test_gates.py` (structured/forged/pending-vendor-build rejection tests, `query_session_identity` mislink test), `tests/unit/runner/test_execution.py` (session mismatch stops before side B) |
| A03 full-evidence trace profile + semantic re-audit (G03) | COVERED (offline) | `tests/unit/reduction/test_audit.py` (4 tests), `tests/unit/reduction/test_trace.py`, `tests/contract/fixtures/d2/` |
| A04 comparison deadline + max-receipt reservation (G04) | COVERED (offline, fake clock) | `tests/unit/reduction/test_online_handover.py` (G04 section), `tests/unit/oracle/test_budgets.py` |
| A05 forced sink / NO_SINK semantics | COVERED (offline) | `tests/unit/reduction/test_online_handover.py` (R02/A05 section) |
| A06 `TraceSink.publish_payload` protocol | COVERED (offline) | `tests/unit/reduction/test_online_handover.py`, `tests/unit/reduction/test_trace.py` |
| Full vs partial/legacy read-side negatives; original offline suite no unexpected regression | COVERED (offline) | `tests/unit/reduction/test_audit.py`, full suite run (section 4) |

### Phase 2 — MySQL driver, configuration, probing

| Criterion | Status | Evidence |
| --- | --- | --- |
| Fixed patch dependency (`PyMySQL==1.1.2`), mysql extra, certified pin file | COVERED (offline) | `pyproject.toml` `[project.optional-dependencies].mysql`, `requirements/mysql-certified.txt`, wheel/extra resolution verified offline (section 3) |
| Driver/mapping version + packet/metadata golden fixtures | COVERED (offline) | `tests/contract/fixtures/mysql112/`, `tests/unit/adapters/test_mysql_protocol.py` (33 tests), `tests/unit/adapters/test_exact_codec.py`, `tests/unit/adapters/test_diagnostics.py` |
| 真实环境无损解码结果可复核 (live lossless decoding) | NOT_RUN | requires live MySQL/MTSQL 8.0 + certified driver |
| Protocol/decoder tests run without a live server; offline modules import with zero connections | COVERED (offline) | `tests/integration/test_d2_offline.py` (fresh-process import closed loop), `tests/unit/cli/test_online.py` (`--help`/import without the mysql extra), `tests/unit/runner/test_config.py` (fresh import is driver-free) |
| Config refusals (TLS modes, uuid, password env, transports) | COVERED (offline) | `tests/unit/runner/test_config.py` (13 tests), `tests/unit/adapters/test_mysql80.py` |

### Phase 3 — supervision, cancellation, safe cleanup

| Criterion | Status | Evidence |
| --- | --- | --- |
| Normal cancellation has server-side evidence; unconfirmable → UNKNOWN within the closing budget | COVERED at fake layer; **live NOT_RUN** | `tests/unit/runner/test_cancellation.py`, `tests/unit/runner/test_execution.py` (`TestCancelAndWait`); real KILL QUERY confirmation NOT_RUN |
| Leftover objects inventorable; control helper never blocks forever | COVERED at fake layer; **live NOT_RUN** | `tests/unit/runner/test_cleanup.py`, `tests/unit/runner/test_ipc.py`, `tests/unit/runner/test_worker.py` |
| Ownership journal / marker / naming invariants | COVERED (offline) | `tests/unit/runner/test_ownership.py`, `tests/unit/runner/test_naming.py`, `tests/unit/runner/test_cleanup_binding.py` |
| Quarantine paths stop all further dispatch | COVERED (offline) | `tests/unit/runner/test_cancellation.py` (UNKNOWN → QUARANTINED transitions), `tests/unit/runner/test_execution.py` (budget expiry without kill confirmation quarantines) |

### Phase 4 — isolated execution and runtime facts

| Criterion | Status | Evidence |
| --- | --- | --- |
| Real positive cases pass D1 runtime + D2 gates with AB/BA order and session identity intact | COVERED at fake layer; **live NOT_RUN** | `tests/unit/runner/test_execution.py` (48 tests, happy-path prepare/execute/compare), `tests/unit/runner/test_facts.py` (50 tests) |
| Fault execution stays inside the Phase 3 control channel; missing `after` → null side, never fabricated READY/MATCH | COVERED (offline fixtures) | `tests/unit/runner/test_execution.py` (`TestExecuteFailures`), `tests/contract/fixtures/d2/`, `tests/contract/test_runner_contract.py` |

### Phase 5 — online CLI, full evidence, D2 replay/reduce

| Criterion | Status | Evidence |
| --- | --- | --- |
| Installed-CLI behaviour (wheel build, fresh venv, offline commands, no-network runtime imports) | COVERED (offline) | `tests/unit/cli/test_installed_cli.py` (5 tests) + manual wheel verification (section 3) |
| Ordinary positive case real MATCH | NOT_RUN | requires live target |
| Synthetic deviation reproduced by the three rounds and reduced, kept out of real findings | COVERED (offline, synthetic) | `tests/integration/test_d2_offline.py` (replay → reduce → trace audit over the real JSONL sink), `tests/unit/reduction/test_replay.py` |
| Corrupted/incomplete evidence can never present as COMPLETE | COVERED (offline) | `tests/unit/runner/test_evidence.py`, `tests/unit/reduction/test_audit.py`, `tests/contract/test_runner_contract.py` |
| Exit codes 0/4/3/2/1/130 incl. safety outranking, auto-tested | COVERED (offline) | `tests/unit/cli/test_online.py` (25 tests), `tests/unit/runner/test_controller.py` (`exit_code_for` outranking) |
| Three rounds each carry request/expectation/evidence/comparison + before/after facts; original and best re-verifiable from files | COVERED (offline) | `tests/integration/test_d2_offline.py` (`test_replay_reduce_trace_closed_loop`), `tests/unit/reduction/test_audit.py` |
| Real initial execution through the installed CLI | NOT_RUN | requires live target |

### Phase 6 — Linux integration certification and delivery closeout

| Criterion | Status | Evidence |
| --- | --- | --- |
| CI offline/mysql grouping + wheel-install check | COVERED as configuration (not yet executed by CI) | `.github/workflows/ci.yml` created this phase; no CI run evidence exists yet — the first CI run is itself still to be observed |
| Linux + Python 3.11/3.12 offline regression and wheel install | NOT_RUN | requires remote Linux; macOS 3.14 regression is not a substitute |
| At least one fully documented real MySQL/MTSQL 8.0 dedicated-instance integration | NOT_RUN | requires authorized live instance with recorded build |
| 120-receipt memory acceptance / peak RSS recording | NOT_RUN | requires the synthetic subprocess fixture run on the target platform |
| D4 handover fixture set (eight categories) | COVERED (offline) | `tests/contract/fixtures/d2/` (complete match, candidate, not-started, prepare failure, structured preflight rejection, stale ready, termination unknown, cleanup failed); legacy-trace and corrupt-reference read-side negatives are covered by `tests/unit/reduction/test_trace.py` and `tests/unit/reduction/test_audit.py` |

## 2. Negative matrix (design section 7)

Layer split per design: "offline/contract" = automated tests in this tree;
"real" = live authorized database. A row is COVERED only when its whole
designated layer is offline (contract/protocol/fake/subprocess/synthetic); rows
with a `real` component are PARTIAL until the live half is executed.

| ID | Design layer | Offline/contract | Real/live |
| --- | --- | --- | --- |
| G01 | 1 / contract | COVERED — `tests/unit/reduction/test_online_handover.py`, `tests/unit/oracle/test_gates.py` | n/a |
| G02 | 1/4 / contract+real | COVERED — `tests/unit/reduction/test_online_handover.py` (fresh-name ledger), `tests/unit/oracle/test_gates.py` (`query_session_identity`), `tests/unit/runner/test_naming.py` (same short names across fresh databases are legal) | NOT_RUN (live round-reuse) |
| G03 | 1/5 / offline | COVERED — `tests/unit/reduction/test_audit.py`, `tests/unit/reduction/test_trace.py` | n/a |
| G04 | 1/5 / fake clock | COVERED — `tests/unit/reduction/test_online_handover.py` (G04), `tests/unit/oracle/test_budgets.py` | n/a |
| P01 | 2/4 / protocol+real | COVERED — `tests/unit/adapters/test_exact_codec.py` (P01), `tests/unit/adapters/test_mysql_protocol.py` | NOT_RUN (live field metadata) |
| P02 | 2 / protocol | COVERED — `tests/unit/adapters/test_diagnostics.py` (P02) | n/a |
| P03 | 2/4 / protocol+real | COVERED — `tests/unit/adapters/test_diagnostics.py` (P03) | NOT_RUN (live warning overflow) |
| P04 | 2/4 / protocol | COVERED — `tests/unit/adapters/test_mysql_protocol.py` (P04: exact row-limit EOF confirmation, one-over truncation, cumulative 16 MiB packet cap refused before body read) | n/a |
| S01 | 2/3 / unit+real | COVERED — `tests/unit/runner/test_config.py` (uuid/TLS/password-env refusals), `tests/unit/runner/test_preflight.py`, `tests/unit/adapters/test_mysql80.py` (server public key refused), sanitization tests | NOT_RUN (live auth/TLS refusal) |
| S02 | 3 / real+fault harness | COVERED at fake layer — `tests/unit/runner/test_cleanup.py` (S02/S03), `tests/unit/runner/test_cleanup_binding.py`, `tests/unit/runner/test_execution.py` (CREATE conflict) | NOT_RUN (real CREATE/ACK-loss harness) |
| S03 | 3/5 / unit+real | COVERED — `tests/unit/runner/test_cleanup.py`, `tests/unit/runner/test_evidence.py` (symlink/`..` path refusal) | NOT_RUN (live same-name/extra-object conflict) |
| C01 | 3/4 / real | COVERED at fake layer — `tests/unit/runner/test_cancellation.py`, `tests/unit/runner/test_execution.py` (`TestCancelAndWait`) | NOT_RUN (real own-SLEEP KILL, DDL wait, FETCH disconnect) |
| C02 | 3 / subprocess | COVERED — `tests/unit/runner/test_supervisor.py` (C02/C04), `tests/unit/runner/test_ipc.py`, `tests/unit/runner/test_worker.py` | n/a |
| C03 | 3 / real+synthetic | PARTIAL — repeated cancel never extends the deadline (`tests/unit/runner/test_cancellation.py`), unconfirmable unwind stays idempotent (`tests/unit/runner/test_execution.py`) | NOT_RUN (live control loss, real ID reuse, no false KILL) |
| C04 | 3/5 / subprocess | COVERED — `tests/unit/runner/test_supervisor.py` (C04), `tests/unit/cli/test_online.py` (SIGINT → 130, sealed partial evidence) | NOT_RUN (real parent SIGKILL on a live run) |
| E01 | 4 / real+fixture | COVERED — `tests/unit/runner/test_execution.py` (`test_missing_after_facts_leave_the_side_null_with_the_real_cause`), `tests/unit/runner/test_facts.py`, `tests/contract/fixtures/d2/` | NOT_RUN (live load drift / env change) |
| E02 | 4 / real+fixture | COVERED — `tests/unit/runner/test_execution.py` (`test_both_sides_erroring_before_any_fetch_still_seals`), `tests/unit/oracle/test_gates.py` (same-error INCONCLUSIVE) | NOT_RUN (live both-sides error) |
| R01 | 5 / synthetic E2E | COVERED — `tests/integration/test_d2_offline.py` (synthetic deviation replayed/reduced/audited), `tests/unit/reduction/test_replay.py` (R01 order/unstable) | n/a |
| R02 | 1/5 / fault sink | COVERED — `tests/unit/reduction/test_online_handover.py` (R02/A05: NO_SINK, unpersisted opt-out, cancel-on-sink-failure), `tests/unit/reduction/test_trace.py` (budget) | n/a |
| I01 | 5/6 / installed CLI | COVERED — `tests/unit/cli/test_installed_cli.py`, `tests/unit/cli/test_online.py` (`--help` without the mysql extra), manual wheel verification (section 3) | n/a (offline install is the point of the row; the live half of online certification is the Phase 6 row above) |

## 3. Manual packaging verification (this phase, 2026-09-06)

Performed outside the repo tree on macOS (Python 3.14); the Linux equivalent
remains NOT_RUN:

1. `.venv/bin/python -m pip wheel . --no-deps --no-build-isolation -w <scratch>/wheels`
   → built `mtsql_typecheck-0.1.0-py3-none-any.whl`.
2. Fresh venv outside the repo + `pip install --no-index --no-deps <wheel>`:
   `mt-typecheck --help` and all five online subcommand `--help` exited 0 with
   **no PyMySQL installed**; a valid target + password env made `preflight`
   refuse with exit 2 and the message "the certified MySQL driver is not
   installed (...); online commands refuse to run without it" (design I01).
3. `pip install PyMySQL==1.1.2` into that venv, then
   `import mtsql_typecheck.adapters.mysql_protocol` succeeded.
4. Second scratch venv: `pip install --no-index --find-links <scratch>/wheels '.[mysql]'`
   resolved the extra offline against the local `pymysql-1.1.2` wheel and the
   protocol module imported (extra/pin verified offline; no network install was
   relied on beyond seeding the local wheel directory).

All scratch venvs/wheels were removed afterwards; no `build/` or `dist/`
directory was left in the repository.

## 4. Final recorded run

`.venv/bin/python -m pytest` (full suite): **1523 passed, 0 failed, 0 skipped**
(2026-09-06, macOS worktree, Python 3.14 venv; baseline before D3 was 851
passed). Also green under the CI offline command
`pytest --strict-markers -m 'not mysql and not integration'`. Offline suite
totals are recorded per run and never carried over from earlier phases.

## 5. NOT_RUN registry (blocking live certification)

All of the following require remote Linux (Python 3.11/3.12) and a dedicated,
authorized MySQL/MTSQL 8.0 instance with the certified PyMySQL 1.1.2 driver:

- live preflight against the real target (uuid/TLS/caching_sha2 path,
  privilege and cancel-capability probes);
- live case execution (real positive MATCH, real metadata/diagnostics
  fidelity: P01/P03 real halves, E01/E02 real halves);
- real KILL QUERY cancellation and termination confirmation (C01, C03 real
  halves, C04 real parent SIGKILL);
- live cleanup with real ownership conflicts (S02/S03 real halves);
- remote-Linux offline regression + wheel install (Phase 6 rows);
- the first observed CI run of `.github/workflows/ci.yml`;
- 120-receipt memory acceptance and RSS recording on the target platform.

Until these are executed and recorded, the online capability is implemented
but **not certified**; zero failing offline tests is not a pass for the live
gates, and uncertified targets must not be presented as supported.
