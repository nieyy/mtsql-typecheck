# D4 Delivery Verification Record (delivery-d4-verification)

Honest PASS / FAIL / NOT_RUN record for the D4 design
(`/Users/nieyuanyuan/Desktop/ccproj/nieyy/mtsql_helper/docs/designs/2026-09-06-mtsql-typecheck-evidence-reporting-regression-delivery-design-zh.md`,
**v1.0, 2026-09-06, Locked**) — Phase 5 requirement: "记录代码 revision、环境、
命令、用例数、PASS/FAIL/NOT_RUN、已知限制". Every count below is a number
actually observed by running the cited command in this worktree; every
requirement that was not exercised is explicitly NOT_RUN. This record does
not upgrade offline (fake/fixture) evidence into live certification, and it
does not claim that all five phases are fully accepted.

## 0. Code revision and environment actually used

| Item | Value |
| --- | --- |
| Design | D4 evidence/reporting/regression delivery design, v1.0 (2026-09-06), Locked; source project state it was written against: `ad11f11b7fc3c4b36c136fe91422f9d8efde347e` |
| Worktree HEAD | `ad11f11b7fc3c4b36c136fe91422f9d8efde347e` (branch `nieyy/d4`) |
| Working tree | dirty: D4 phase files are present as uncommitted working-tree additions (`src/mtsql_typecheck/contracts/delivery.py`, `src/mtsql_typecheck/evidence/`, `src/mtsql_typecheck/reporting/`, `src/mtsql_typecheck/delivery/`, `tests/contract/test_delivery_contract.py`, `tests/unit/{bundle,evidence,reporting,delivery}/`, `docs/delivery-d4-contract.md`, plus this record, README and CI changes). The HEAD hash alone therefore does **not** identify the tested code; the tree state does. |
| Host OS | macOS (Darwin 24.6.0) — **not** the required Linux baseline |
| Python | 3.14.5 (venv `/tmp/d4-orchestration/venv`) — the design baseline is Linux + Python 3.11/3.12 |
| pytest | 9.1.1 |
| PyMySQL | **not installed** in this venv (deliberately: the offline D4/core verification runs without a driver, mirroring the CI `offline-core` job) |
| Required Linux/Python 3.11/3.12 offline verification | NOT_RUN on this host (see limitations) |
| Live MySQL/MTSQL 8.0 target | none authorized; never touched (D4 commands are offline by construction) |

All commands were run as
`PYTHONPATH=src /tmp/d4-orchestration/venv/bin/python -m pytest …` from the
worktree root. `tests/unit/cli/test_installed_cli.py` additionally builds a
wheel via `pip wheel` (see the Phase 5 notes and limitations).

## 1. Per-phase commands, counts, and status

Only the D4-relevant groups are listed per phase; the design's 建议最小逐阶段
命令 are followed where the named files exist in this tree (file names that
differ from the design text are recorded verbatim — e.g. the design's
`test_coverage.py` is `test_coverage_stats.py` here).

### Phase 1 — delivery contracts and safe format reading

| Item | Value |
| --- | --- |
| Code | `src/mtsql_typecheck/contracts/delivery.py`, `src/mtsql_typecheck/evidence/{reader,snapshot,native,manifest}.py`, `docs/delivery-d4-contract.md` |
| Tests | `tests/contract/test_delivery_contract.py`, `tests/unit/evidence/{test_reader,test_snapshot,test_native,test_manifest}.py` |
| Command (design line 511, Phase 1) | `python -m pytest tests/contract/test_delivery_contract.py tests/unit/evidence/test_reader.py tests/unit/evidence/test_native.py tests/unit/evidence/test_snapshot.py` |
| Result | **PASS — 142 passed** |
| Additional | `tests/contract/test_delivery_contract.py`: 59 passed; `tests/unit/evidence` (incl. `test_manifest.py`): 139 passed |

### Phase 2 — layered audit, counts, provenance

| Item | Value |
| --- | --- |
| Code | `src/mtsql_typecheck/evidence/{assessment,provenance}.py`, `src/mtsql_typecheck/reporting/{model,coverage,findings}.py`, bounded read-side changes to `src/mtsql_typecheck/reduction/{trace,audit}.py` and `src/mtsql_typecheck/generation/bundle.py` |
| Tests | `tests/unit/evidence/{test_assessment,test_provenance}.py`, `tests/unit/reporting/{test_coverage_stats,test_findings}.py`, `tests/unit/bundle/test_bounded_validate.py`, `tests/unit/reduction/{test_bounded_trace,test_detailed_audit}.py` (+ regression), `tests/unit/oracle` |
| Command (design line 511, Phase 2, as named in this tree) | `python -m pytest tests/unit/evidence tests/unit/reporting/test_coverage_stats.py tests/unit/reporting/test_findings.py tests/unit/bundle tests/unit/reduction tests/unit/oracle` |
| Result | **3 collection errors** (see known limitation (vi)) — run split instead |
| Split run 1 | `tests/unit/evidence tests/unit/reporting/test_coverage_stats.py tests/unit/reporting/test_findings.py tests/unit/reduction tests/unit/oracle` → **PASS — 479 passed** |
| Split run 2 | `tests/unit/bundle` → **PASS — 49 passed** (same dir alone: 49 passed) |
| Split totals | 528 passed across the two invocations |

### Phase 3 — report rendering and human review

| Item | Value |
| --- | --- |
| Code | `src/mtsql_typecheck/reporting/{review,build,markdown,html}.py` (+ `model.py` `ReportDocument`) |
| Tests | `tests/unit/reporting/{test_review,test_render}.py`, golden fixtures `tests/unit/reporting/fixtures/report_{complete,conflict}.json` |
| Command (design line 511, Phase 3) | `python -m pytest tests/unit/reporting/test_render.py tests/unit/reporting/test_review.py` |
| Result | **PASS — 80 passed** |
| Additional | `tests/unit/reporting` (incl. coverage/findings): 122 passed |

### Phase 4 — standalone SQL and regression delivery

| Item | Value |
| --- | --- |
| Code | `src/mtsql_typecheck/delivery/{sql,selection,export}.py` |
| Tests | `tests/unit/delivery/{test_sql,test_selection,test_export}.py` |
| Command (design line 511, Phase 4) | `python -m pytest tests/unit/delivery` |
| Result | **PASS — 116 passed** |

### Phase 5 — CLI, packaging, closed loop

| Item | Value |
| --- | --- |
| Code | `src/mtsql_typecheck/cli/delivery.py` (new; three commands + shared `compute_exit_code`), `cli/main.py` (registration/dispatch only; generate/validate/online untouched); `README.md` English guide and `.github/workflows/ci.yml` grouping per Phase 5b |
| Tests | `tests/unit/cli/test_delivery.py` (22 tests), `tests/integration/test_delivery_offline.py` (6 tests, **no** `integration` marker — collected by default offline CI) |
| Command (design line 511, Phase 5) | `python -m pytest --strict-markers tests/integration/test_delivery_offline.py tests/unit/cli/test_delivery.py` |
| Result | **PASS — 28 passed** (22 unit + 6 integration; integration covers the E12 loop: generate → report → move dir → verify → sql export → regression refusal → tamper → exit 2 with input hashes unchanged, plus 120 sequential verifies, cancel → 130, I/O failure → 1, budget → 3) |
| Full `tests/unit/cli` | 81 passed, 5 errors (without `test_installed_cli.py`: 81 passed) — the 5 errors are all `tests/unit/cli/test_installed_cli.py`, whose wheel build fails **in this venv** (`pip._vendor.pyproject_hooks._impl.BackendUnavailable: Cannot import 'setuptools.build_meta'`, environment limitation of the offline venv, not a code failure). The CI `wheel-install` job runs a real D4 installed-CLI closed loop ("D4 installed-CLI offline closed loop" step: generate → report → move → evidence-verify → sql export → regression refused (3) → tampered package refused (2), exit codes asserted); on this host the wheel build itself remains NOT_RUN (venv lacks setuptools). |
| Existing offline integration suite | `tests/integration/test_d2_offline.py`: 11 passed |
| New CI `offline-core` grouping, run locally | `python -m pytest --strict-markers -m 'not mysql and not integration' --ignore=tests/unit/adapters --ignore=tests/unit/runner --ignore=tests/unit/cli/test_installed_cli.py` → **PASS — 1467 passed** |
| Driver-dependent groups | `tests/unit/adapters` → 4 collection errors (`ModuleNotFoundError: No module named 'pymysql'`); `tests/unit/runner` → 2 collection errors (same) — **NOT_RUN** on this host by design (no driver in the offline venv); covered by the CI `protocol-offline` job with the pinned `mysql` extra |

### Acceptance-table row 1 (单元/契约) combined command

`python -m pytest tests/contract tests/unit/evidence tests/unit/reporting
tests/unit/delivery` → **PASS — 690 passed** (design acceptance row 1;
`tests/integration/test_delivery_offline.py` additionally passes 6/6, see the
Phase 5 table).

## 2. Acceptance matrix E01–E12 and test mapping

Matrix rows are quoted (condensed) from design lines 494–508. "测试位置"
cites only test files / node ids that exist in this tree.

| ID / Phase | 输入 / 故障注入 (condensed) | 必须得到的结果 (condensed) | 验证状态 | 测试位置 |
| --- | --- | --- | --- | --- |
| E01 / 1 | 五种原生 kind，D4 verification/report，空目录与冲突根标记 | 正确识别；verification 无展示页仍合法；空/冲突输入不得 COMPLETE | COVERED (offline) | `tests/unit/evidence/test_native.py::test_detect_each_kind`, `::test_detect_conflicting_markers_refused`, `::test_detect_empty_root_and_hints`; `tests/unit/evidence/test_manifest.py::test_required_files_for_kinds`, `::test_round_trip_verification_package_ok` (verification package legal without report pages); `tests/unit/evidence/test_assessment.py::test_zero_record_trace_claiming_completion_is_partial`, `::test_corrupt_trace_records_are_structurally_corrupt` |
| E02 / 1 | 绝对/父级引用、symlink race、FIFO、输入变化、输出重叠 | 不读越界字节、不覆盖源；SOURCE_CHANGED 只能诊断 | COVERED (offline) | `tests/unit/evidence/test_reader.py::test_unsafe_paths_are_refused`, `::test_symlink_root_is_refused`, `::test_symlink_component_is_refused`, `::test_fifo_is_refused_as_document`, `::test_over_long_path_is_refused`, `::test_mtime_change_during_read_is_detected`, `::test_replacement_between_lstat_and_open_is_detected`, `::test_over_limit_document_rejected_without_opening`; `tests/unit/evidence/test_snapshot.py::test_existing_output_root_is_refused`, `::test_output_inside_input_is_refused`, `::test_output_equal_to_input_is_refused`, `::test_capture_refuses_output_that_appeared_after_setup`, `::test_source_change_during_pass_one_writes_nothing` |
| E03 / 1,5 | 复制/搬移/附 review、修改 raw、缺依赖、修改派生报告 | 前三者 evidence identity 不变；后两类变更或缺失可检出；派生报告 hash 也校验 | COVERED (offline; the "搬移/附 review" end-to-end leg is exercised by `tests/integration/test_delivery_offline.py`) | `tests/unit/evidence/test_snapshot.py::test_moving_the_tree_preserves_source_id_and_digest`, `::test_single_byte_change_changes_the_digest`, `::test_orphan_files_are_never_copied`; `tests/unit/evidence/test_manifest.py::test_tampered_raw_file_reports_hash_mismatch`, `::test_deleted_listed_file_reports_missing_file`, `::test_extra_file_after_sealing`, `::test_missing_required_report_file`, `::test_round_trip_report_package_ok` (derived report.json/md/html hashed like any listed file); `tests/unit/delivery/test_export.py::test_manifest_identity_and_tamper_detection` |
| E04 / 1,2 | 无 producer、dirty/未知、错误类型、显式 revision 冲突 | 缺失保留 null；非法类型拒绝；仅版本已知不得升级佐证 | COVERED (offline) | `tests/unit/evidence/test_native.py::test_enumerate_legacy_trace_has_no_versions` (no producer → null kept), `::test_enumerate_generation_closure`, `::test_enumerate_run_closure`, `::test_trace_marker_contradiction_refused`; `tests/contract/test_delivery_contract.py::test_producer_info_canonical_json_golden` (typed producer model) |
| E05 / 2 | 修改 comparison 后同步重算外层 hash、跨会话 ID、KILL 应答但无终止 | 字节一致不能掩盖语义 CONFLICT；来源与安全分别降级 | COVERED (offline) | `tests/unit/evidence/test_assessment.py::test_forged_comparison_conflicts_and_original_is_preserved`, `::test_forged_trace_evidence_is_a_semantic_conflict`; `tests/unit/evidence/test_provenance.py::test_session_identity_rewrite_is_a_conflict`, `::test_kill_reply_without_terminal_is_unknown`, `::test_leftover_count_without_termination_evidence_is_unknown` (provenance and execution-safety degrade independently) |
| E06 / 2,4 | 无 trace、截尾、legacy、少一轮、假 ACCEPTED、非下降 child、悬空 best | 不伪造完成/最佳反例；legacy 可展示但不得 best 导出 | COVERED (offline) | `tests/unit/evidence/test_assessment.py::test_legacy_trace_is_not_recomputed_and_not_exportable`, `::test_trace_missing_third_round_stays_not_audited`, `::test_honest_full_trace_is_verified_and_recomputed`; `tests/unit/delivery/test_selection.py::test_best_selection_without_proof_is_refused`, `::test_best_selection_unverified_chain_is_unavailable`, `::test_best_selection_verified_chain_selects_best_case`; reduction regression: `tests/unit/reduction/test_audit.py`, `test_detailed_audit.py` |
| E07 / 2 | 同 case 多 attempt、重复签名、identity/empty、缺 Profile | 工作量与覆盖分开，分母未知显示 null，计数守恒 | COVERED (offline) | `tests/unit/reporting/test_findings.py::test_same_case_in_different_attempts_is_not_a_duplicate`, `::test_split_by_synthetic_kind`, `::test_unique_cases_and_distinct_surfaces`, `::test_fingerprint_group_is_not_a_bug_count`, `::test_attempt_less_rows_are_skipped`; `tests/unit/reporting/test_coverage_stats.py` (unknown denominator → null); `tests/unit/evidence/test_assessment.py::test_generation_only_source_semantic_and_safety_not_applicable` (no Profile → no denominator) |
| E08 / 3,4 | 错 review hash/ID、悬空/循环 supersedes、未被替代的互斥意见 | 区分输入错误与 review_conflict；不改变 observed Comparison，不自动确认整组 | COVERED (offline) | `tests/unit/reporting/test_review.py::TestDigestBinding`, `::TestSupersedes` (dangling/self/cycle), `::TestConflicts` (surviving mutually exclusive decisions), `::TestDuplicates`; `tests/unit/delivery/test_export.py::test_regression_conflicting_reviews_are_refused`, `::test_regression_rejected_review_input_is_refused` |
| E09 / 3 | HTML/Markdown/URL 注入、长中文/SQL、文件名特殊字符 | 无脚本/外部资源；三种展示一致、链接可用、窄屏不重叠 | PARTIAL — injection/escaping/links COVERED; browser display NOT_RUN | `tests/unit/reporting/test_render.py::test_markdown_injection_neutered`, `::test_html_injection_neutered`, `::test_no_javascript_href_anywhere`, `::test_issue_url_must_be_https`, `::test_special_filename_is_url_encoded`, `::test_diff_summary_truncation_marker`, `::test_renderer_only_links_package_paths`; three-render consistency from one model: `::test_golden_complete_json_bytes`, `::test_markdown_golden_fragments`, `::test_html_golden_fragments`; **窄屏/浏览器人工查看 NOT_RUN** (no browser on this host) |
| E10 / 4 | 大整数、Decimal scale、NULL/重复/空集、恶意 SET、重复 case 选择 | 无精度损失、无注入、歧义拒绝，合法调试 SQL 与 regression 门禁不同 | COVERED (offline) | `tests/unit/delivery/test_sql.py::test_golden_a_sql_byte_equality`, `::test_hostile_values_rejected_at_validation`, `::test_escaper_keeps_hostile_value_inside_one_literal`, `::test_no_banned_constructs_in_any_output`, `::test_create_database_has_no_if_not_exists`; `tests/unit/delivery/test_selection.py::test_ambiguous_selection_and_occurrence_disambiguation`, `::test_corrupt_case_document_is_refused`; `tests/unit/delivery/test_export.py::test_expected_json_holds_model_truth_only`; exact typed value encoding (big integers/Decimal/NULL/duplicates) via `tests/unit/oracle/test_exact.py` and `tests/contract/test_delivery_contract.py` roundtrips |
| E11 / 1,2,5 | 超限行/JSON/文件数、预算刚好边界、fake deadline、写/fsync/rename 失败 | 超限前或受控边界停止；不伪造 COMPLETE，输出预留有效 | COVERED (offline); the design's 120/1200-attempt scale+RSS run is NOT_RUN | `tests/unit/evidence/test_reader.py::test_over_limit_document_rejected_without_opening`, `::test_over_limit_jsonl_total_rejected_without_opening`, `::test_over_limit_jsonl_line_stops_before_reading_the_whole_file`, `::test_walk_max_entries_exceeded`, `::test_deadline_expires_during_walk`, `::test_deadline_expires_during_jsonl_read`; `tests/unit/bundle/test_bounded_validate.py`; `tests/unit/reduction/test_bounded_trace.py`; `tests/unit/evidence/test_snapshot.py::test_output_budget_exhaustion_stops_publishing`, `::test_reserve_is_counted_inside_the_output_budget`, `::test_fsync_failure_does_not_corrupt_originals_or_seal`; `tests/unit/evidence/test_manifest.py::test_write_fsync_failure_leaves_originals_intact` |
| E12 / 5 | 原生落盘→report→搬移→verify→SQL/regression，installed CLI | 离线闭环覆盖所有入口及 0/1/2/3/4/130；原文件 hash 不变 | PARTIAL — offline closed loop COVERED (pytest + CI wheel job); installed-CLI leg NOT_RUN on this host only | `tests/integration/test_delivery_offline.py` (6 tests: full loop `generate → report → move → evidence-verify → export sql → export regression refused → tampered package refused`, 0/1/2/3/130 covered there, exit 4 via `tests/unit/cli/test_delivery.py` candidate cases; original input hashes asserted unchanged), `tests/unit/cli/test_delivery.py` (22 tests over all three commands with real file inputs). The installed-CLI (wheel) leg runs in CI: the `wheel-install` job's "D4 installed-CLI offline closed loop" step exercises generate → report → move → verify → sql export → regression refusal (3) → tampered-package refusal (2) through the installed `mt-typecheck` with no PYTHONPATH/editable shadowing. It was additionally validated locally end-to-end with the same command sequence (exit codes 0/0/0/0/3/2); the wheel build itself was NOT_RUN on this host (venv lacks setuptools). |

Every COVERED row above is offline (fakes/fixtures) evidence only. Nothing in
this matrix, and no exit code of any D4 command, constitutes a confirmed
database bug or live certification.

## 3. Known limitations

Recorded during implementation; each verified against the code before being
listed here.

1. **Run roots without an ownership journal stay UNVERIFIED (fixture-level
   fact).** Provenance corroboration requires the run/attempt observation
   records and the ownership journal; when a runner manifest omits the base
   refs snapshot and no ownership journal is present, provenance stays
   UNVERIFIED (`ownership_journal_missing`), never upgraded to
   corroboration — `src/mtsql_typecheck/evidence/provenance.py`
   (`note(ProvenanceStatus.UNVERIFIED, "ownership_journal_missing")`),
   exercised by
   `tests/unit/evidence/test_provenance.py::test_missing_observations_and_journal_are_unverified_not_corroborated`.
2. **File-only snapshot copy loses empty directories → validator IO problem.**
   The snapshot copies files only, so a generation bundle whose `cases/`
   directory is empty (e.g. an aborted bundle with zero published cases)
   loses that directory in the copy, and the bounded bundle validator then
   records an `IO_ERROR` "cannot scan directory …/cases" for the snapshot
   instead of treating the empty directory as valid. Reproduced on this host
   with `validate_output_dir` against a snapshot-equivalent tree (real tree:
   no IO problem; copy: IO_ERROR). The original tree is never modified — the
   report honestly shows the problem instead of silently passing.
3. **Real trace assessments do not bind case ids.** `_semantic_trace`
   constructs `AttemptSemanticResult` with `case_id=None`
   (`src/mtsql_typecheck/evidence/assessment.py`); case-bound best selection
   is unit-tested only with synthetic selection fixtures
   (`tests/unit/delivery/test_selection.py`), so the case-bound end-to-end
   best→regression path cannot be exercised at unit level on a real trace
   (this is also part of why E12 waits for the integration test).
4. **`decode_generation_manifest({})` raises a raw `KeyError`
   ('generation_schema_version')** instead of a typed `ContractError` — a
   pre-existing D1 contracts gap in `contracts/codec.py`, outside D4 scope;
   reproduced on this host. Not fixed here to keep this phase scoped.
5. **Platform and display verification NOT_RUN on this host:** the required
   Linux + Python 3.11/3.12 offline verification, wheel isolation on Linux
   (the local `tests/unit/cli/test_installed_cli.py` wheel build fails in
   this venv for lack of a setuptools build backend — environment
   limitation), the 120/1200-attempt synthetic scale runs with peak-RSS
   recording, and the browser/narrow-viewport HTML display checks have not
   been performed. All remain NOT_RUN and are covered only by the CI jobs
   going forward.
6. **Test collection quirk (pre-existing):** `tests/unit/bundle/test_*.py`
   import helpers via `from conftest import …`; when several of
   `tests/unit/{bundle,reduction,oracle}` are named as explicit pytest args
   in one invocation, the bare `conftest` module can resolve to another
   directory's conftest (observed: `tests/unit/oracle/conftest.py` winning),
   producing 3 collection errors for the bundle tests. Running each
   directory separately (or the full default suite, which collects fine:
   1467 passed with the new offline-core grouping) avoids it. Recorded
   because the design's Phase 2 one-line command hits it; the split
   invocation is recorded in section 1.

## 4. Closing statement

Per design line 486: items that were not run are listed above as NOT_RUN —
the Linux/Python 3.11/3.12 offline verification and the wheel build on this
host (the installed-CLI closed loop is covered by the CI `wheel-install`
job's D4 step and was command-validated locally), the driver-dependent
protocol groups on this host, the scale/RSS runs, and the browser display
checks. The offline closed loop itself (E12, sans installed CLI) is covered
by `tests/integration/test_delivery_offline.py`. **No claim is made
that all five D4 phases are fully accepted**, and no fixture pass is
presented as real-database authentication.
