"""Markdown rendering of a :class:`ReportDocument` (design 6.4.5, Phase 3).

The renderer is a fixed program-built template over the typed report model —
no template engine, no dynamic HTML, no images, no network resources.  All
dynamic text is escaped twice over where the two syntaxes overlap: HTML
specials (``& < >``) so GFM inline HTML can never appear, and Markdown
specials (backslash, pipe, backtick) so table structure cannot be broken.
Newlines inside table cells become the visible two-character sequence
``\\n``; nothing dynamic is ever interpreted.

Section order follows design 6.4.5's first screen: 版本与来源、计数与覆盖、
候选与异常、Case 明细、人工 Review、文件清单与复现.  Links are built only
from package-relative paths through :func:`link_target` (URL-encoded,
scheme-bearing targets refused with :class:`UnsafeLinkError`); ``issue_url``
is displayed as plain text and never auto-visited (design 6.4.5).  The
result must fit the design 6.5 budget (8MiB default) or
:class:`LimitExceeded` is raised.

This module is pure: no file I/O, no clock, no database access.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from ..contracts.delivery import check_package_path
from .model import (
    DEFAULT_MAX_RENDER_BYTES,
    CoverageEntry,
    CoverageSummary,
    ExecutionCounts,
    FindingsSummary,
    GenerationCounts,
    LimitExceeded,
    ReportDocument,
    UnsafeLinkError,
)

__all__ = ["DEFAULT_MAX_MARKDOWN_BYTES", "link_target", "md_escape_cell", "render_markdown"]

DEFAULT_MAX_MARKDOWN_BYTES = DEFAULT_MAX_RENDER_BYTES

# A path whose first text run before any "/" ends with a colon parses as a
# URL scheme (javascript:, data:, file:, http:, C:) — never link one.
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")

_NONE = "（无）"
_UNKNOWN = "未知"
_UNRECORDED = "（未记录）"


def link_target(path: str) -> str:
    """Validate a package-relative path and URL-encode it for a link.

    Raises :class:`UnsafeLinkError` for anything that is not a
    package-relative POSIX path or that could parse as a URL scheme
    (design 6.4.5: 不接受 javascript/data/file URL).
    """
    try:
        check_package_path(path, "report link path")
    except Exception as exc:
        raise UnsafeLinkError(f"refusing to link non-package path {path!r}: {exc}") from exc
    if _SCHEME_RE.match(path):
        raise UnsafeLinkError(f"refusing to link scheme-bearing path {path!r}")
    return quote(path, safe="/-._~")


def md_escape_cell(value: str) -> str:
    """Escape one dynamic value for use inside a GFM table cell.

    HTML specials are entity-escaped (so no inline HTML can form), then
    Markdown specials are backslash-escaped (so pipes cannot break the
    table and backticks cannot open code spans).  Newlines become the
    visible two-character sequence ``\\n`` — content stays honest and
    single-line inside the cell.
    """
    text = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")
    return text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")


def _opt(value: str | None, none_text: str = _NONE) -> str:
    return value if value else none_text


def _int_or_unknown(value: int | None) -> str:
    return _UNKNOWN if value is None else str(value)


def _kv_table(rows: list[tuple[str, str]]) -> str:
    lines = ["| 字段 | 值 |", "| --- | --- |"]
    lines.extend(f"| {md_escape_cell(key)} | {md_escape_cell(value)} |" for key, value in rows)
    return "\n".join(lines)


def _dimension_cell(dimension) -> str:
    """One dimension row value: status, applicability, counts, reasons."""
    applicable = "适用" if dimension.applicable else "不适用"
    text = (
        f"{dimension.status.value}（{applicable}；"
        f"已查 {dimension.checked_objects}，未查 {dimension.unchecked_objects}）"
    )
    if dimension.reason_codes:
        text += "；原因: " + ", ".join(dimension.reason_codes)
    if dimension.detail:
        text += "；" + dimension.detail
    return text


# --------------------------------------------------------------------------
# Sections (design 6.4.5 first-screen order)
# --------------------------------------------------------------------------


def _section_header(doc: ReportDocument) -> str:
    header = doc.header
    limitations = (
        ", ".join(header.known_limitations) if header.known_limitations else _NONE
    )
    producer = _UNRECORDED
    if header.producer is not None:
        producer = header.producer.name
        if header.producer.version:
            producer += f" {header.producer.version}"
        if header.producer.revision:
            producer += f" (revision {header.producer.revision}"
            if header.producer.dirty is not None:
                producer += ", dirty" if header.producer.dirty else ", clean"
            producer += ")"
    rows = [
        ("工具", header.tool_name),
        ("报告写入器版本", header.writer_version),
        ("原生格式", header.native_kind.value),
        ("真实/合成", header.synthetic.value),
        ("原执行状态", _opt(header.original_run_status, _UNRECORDED)),
        ("结构审计", _dimension_cell(header.structural)),
        ("语义审计", _dimension_cell(header.semantic)),
        ("来源佐证", _dimension_cell(header.provenance)),
        ("执行安全", _dimension_cell(header.execution_safety)),
        ("生成工具信息", producer),
        ("源提交", _opt(header.source_commit, _UNRECORDED)),
        ("source_id", header.source_id),
        ("delivery_id", header.delivery_id),
        ("报告生成时间", _opt(header.generated_at, _UNRECORDED)),
        ("已知限制", limitations),
    ]
    return "# TypeCheck 证据报告\n\n## 版本与来源\n\n" + _kv_table(rows)


def _generation_section(counts: GenerationCounts | None) -> list[str]:
    if counts is None:
        return []
    rows = [
        ("请求序号", _int_or_unknown(counts.requested_ordinals)),
        ("尝试候选", _int_or_unknown(counts.attempted_candidates)),
        ("产出 occurrence", _int_or_unknown(counts.emitted_occurrences)),
        ("唯一 case", _int_or_unknown(counts.unique_cases)),
        ("拒绝序号", _int_or_unknown(counts.rejected_ordinals)),
        ("中断序号", _int_or_unknown(counts.interrupted_ordinals)),
        ("未尝试", _int_or_unknown(counts.not_attempted)),
        ("回执复核", counts.receipt_recheck),
        ("回执不一致原因", _opt(counts.receipt_mismatch_reason)),
        ("分母已知", "是" if counts.denominator_known else "否"),
    ]
    return ["### 生成计数", "", _kv_table(rows), ""]


def _execution_section(counts: ExecutionCounts | None) -> list[str]:
    if counts is None:
        return []
    rows = [
        ("请求执行", _int_or_unknown(counts.requested_attempts)),
        ("双侧完成", _int_or_unknown(counts.completed_both_selects)),
        ("match 候选", _int_or_unknown(counts.match_candidates)),
        ("不适用", _int_or_unknown(counts.not_applicable)),
        ("不可判定", _int_or_unknown(counts.undecidable)),
        ("预检失败", _int_or_unknown(counts.preflight_failures)),
        ("未派发", _int_or_unknown(counts.undispatched)),
    ]
    return ["### 执行计数", "", _kv_table(rows), ""]


def _coverage_entry_row(entry: CoverageEntry) -> str:
    denominator = _UNKNOWN if entry.denominator is None else str(entry.denominator)
    build = _opt(entry.build_key, "—")
    cells = [
        entry.rule_id,
        str(entry.rule_version),
        entry.type_pair,
        entry.template,
        entry.index_variant,
        build,
        str(entry.comparable_unique_cases),
        denominator,
    ]
    return "| " + " | ".join(md_escape_cell(cell) for cell in cells) + " |"


def _coverage_section(summary: CoverageSummary | None) -> list[str]:
    if summary is None:
        return []
    lines = ["### 唯一覆盖", ""]
    if summary.denominator_known:
        lines.append("覆盖分母：已知")
    else:
        lines.append(f"覆盖分母：未知（原因: {md_escape_cell(summary.unknown_reason or '')}）")
    lines.append("")
    if summary.entries:
        lines.append("| 规则 | 版本 | 类型对 | 模板 | 索引变体 | build | 唯一可比 case | 分母 |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        lines.extend(_coverage_entry_row(entry) for entry in summary.entries)
    else:
        lines.append("（无覆盖条目）")
    lines.append("")
    lines.append(
        f"控制组（不计入非平凡覆盖）：identity-only {summary.identity_only_cases} 个；"
        f"空结果 {summary.empty_result_cases} 个。"
    )
    lines.append("")
    return lines


def _section_counts(doc: ReportDocument) -> str:
    body: list[str] = []
    body.extend(_generation_section(doc.generation_counts))
    body.extend(_execution_section(doc.execution_counts))
    body.extend(_coverage_section(doc.coverage))
    if not body:
        body = ["（无计数数据）", ""]
    return "## 计数与覆盖\n\n" + "\n".join(body).rstrip("\n")


def _section_findings(doc: ReportDocument) -> str:
    findings = doc.findings
    summary_rows = _findings_summary_rows(findings)
    lines = ["## 候选与异常", "", "### 候选汇总", "", _kv_table(summary_rows), ""]
    if doc.occurrences:
        lines.extend(
            [
                "### 候选明细（按风险与稳定 ID 排序）",
                "",
                "| occurrence_id | case_id | attempt | 复算状态 | 合成 | 指纹 |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for occurrence in doc.occurrences:
            cells = [
                occurrence.occurrence_id,
                occurrence.case_id,
                occurrence.attempt_id,
                occurrence.recompute_status.value,
                occurrence.synthetic.value,
                _opt(occurrence.fingerprint, "—"),
            ]
            lines.append("| " + " | ".join(md_escape_cell(cell) for cell in cells) + " |")
        lines.append("")
    else:
        lines.extend(["### 候选明细（按风险与稳定 ID 排序）", "", "（无候选）", ""])
    return "\n".join(lines).rstrip("\n")


def _findings_summary_rows(findings: FindingsSummary) -> list[tuple[str, str]]:
    return [
        ("真实候选", str(findings.real_candidates)),
        ("合成候选", str(findings.synthetic_candidates)),
        ("合成未知候选", str(findings.unknown_synthetic_candidates)),
        ("语义冲突", str(findings.conflicts)),
        ("唯一 case 数", str(findings.unique_case_ids)),
        ("不同精确签名", str(findings.distinct_signatures)),
        ("不同粗指纹", str(findings.distinct_fingerprints)),
        ("已确认（review 绑定）", str(findings.reviewed_confirmed)),
    ]


def _section_case_details(doc: ReportDocument) -> str:
    lines = ["## Case 明细"]
    if not doc.case_details:
        lines.extend(["", "（无 case 明细）"])
        return "\n".join(lines)
    for detail in doc.case_details:
        def _ref_cell(value: str | None) -> str:
            if not value:
                return _NONE
            return f"[{md_escape_cell(value)}]({link_target(value)})"

        rows = [
            ("occurrence_id", detail.occurrence_id),
            ("case_id", detail.case_id),
            ("规则", f"{detail.rule_id} @ v{detail.rule_version}"),
            ("类型对", detail.type_pair),
            ("SELECT", _opt(detail.select_text)),
            ("差异摘要", _opt(detail.diff_summary)),
            ("原始引用", _ref_cell(detail.original_ref)),
            ("最佳引用", _ref_cell(detail.best_ref)),
            ("每轮轨迹", "; ".join(detail.round_outcomes) if detail.round_outcomes else _NONE),
            ("关联 review", ", ".join(detail.review_ids) if detail.review_ids else _NONE),
        ]
        lines.extend(["", f"### Case {detail.case_id}", "", _kv_table(rows)])
    return "\n".join(lines)


def _review_table(reviews) -> list[str]:
    lines = [
        "| review_id | 决策 | reviewer | 时间 | 证据摘要 | 关联 occurrence | 替代 | 意见 | issue |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for review in reviews:
        cells = [
            review.review_id,
            review.decision.value,
            review.reviewer,
            review.reviewed_at,
            review.evidence_digest,
            ", ".join(review.occurrence_ids),
            _opt(review.supersedes, "—"),
            review.reason,
            _opt(review.issue_url, "—"),
        ]
        lines.append("| " + " | ".join(md_escape_cell(cell) for cell in cells) + " |")
    return lines


def _section_reviews(doc: ReportDocument) -> str:
    reviews = doc.reviews
    lines = ["## 人工 Review"]
    if reviews.has_conflict:
        lines.append("")
        lines.append(
            "**警告：存在互斥的人工 review 冲突；以下全部意见并列保留，"
            "原始观察未被修改。**"
        )
    if reviews.accepted:
        lines.extend(["", "### 本次意见", ""])
        lines.extend(_review_table(reviews.accepted))
    if reviews.historical:
        lines.extend(["", "### 历史意见（绑定其他证据，仅展示，不自动应用）", ""])
        lines.extend(_review_table(item.review for item in reviews.historical))
        lines.append("")
        lines.append("历史说明：")
        for item in reviews.historical:
            lines.append(f"- {md_escape_cell(item.review.review_id)}: {md_escape_cell(item.detail)}")
    if reviews.conflicts:
        lines.extend(["", "### 互斥冲突", ""])
        lines.append("| occurrence | review | 说明 |")
        lines.append("| --- | --- | --- |")
        for conflict in reviews.conflicts:
            cells = [
                ", ".join(conflict.occurrence_ids),
                ", ".join(conflict.review_ids),
                conflict.detail,
            ]
            lines.append("| " + " | ".join(md_escape_cell(cell) for cell in cells) + " |")
    if reviews.duplicates_ignored:
        lines.extend(["", "### 同 ID 重复忽略", ""])
        lines.append(
            ", ".join(md_escape_cell(item) for item in reviews.duplicates_ignored)
        )
    if not (
        reviews.accepted
        or reviews.historical
        or reviews.conflicts
        or reviews.duplicates_ignored
        or reviews.has_conflict
    ):
        lines.extend(["", _NONE])
    return "\n".join(lines)


def _section_inventory(doc: ReportDocument) -> str:
    lines = ["## 文件清单与复现", "", "### 文件清单"]
    if doc.inventory.files:
        lines.extend(["", "| 路径 | 角色 | 字节数 | sha256 |", "| --- | --- | --- | --- |"])
        for item in doc.inventory.files:
            target = link_target(item.path)
            cells = [
                f"[{md_escape_cell(item.path)}]({target})",
                item.role.value,
                str(item.size_bytes),
                item.sha256,
            ]
            lines.append("| " + " | ".join(cells) + " |")
    else:
        lines.extend(["", _NONE])
    lines.extend(["", "### 审计问题"])
    if doc.inventory.problems:
        lines.extend(["", "| 代码 | 路径 | 说明 |", "| --- | --- | --- |"])
        for problem in doc.inventory.problems:
            cells = [problem.code, _opt(problem.path, "—"), problem.detail]
            lines.append("| " + " | ".join(md_escape_cell(cell) for cell in cells) + " |")
    else:
        lines.extend(["", _NONE])
    lines.extend(["", "### 复现说明"])
    if doc.inventory.reproduction_notes:
        lines.append("")
        for index, note in enumerate(doc.inventory.reproduction_notes, start=1):
            escaped = md_escape_cell(note)
            if escaped.startswith("#"):
                escaped = "\\" + escaped
            lines.append(f"{index}. {escaped}")
    else:
        lines.extend(["", _NONE])
    lines.extend(
        [
            "",
            "---",
            "",
            "本报告是证据展示：报告生成不等于测试通过，也不证明被测数据库正确性。"
            "诊断与 SQL 仅作文本展示，不会被执行。",
            "",
        ]
    )
    return "\n".join(lines).rstrip("\n") + "\n"


_SECTIONS = (
    _section_header,
    _section_counts,
    _section_findings,
    _section_case_details,
    _section_reviews,
    _section_inventory,
)


def render_markdown(
    doc: ReportDocument, *, max_bytes: int = DEFAULT_MAX_MARKDOWN_BYTES
) -> str:
    """Render the report as Chinese Markdown (design 6.4.5, 6.5).

    Raises :class:`LimitExceeded` when the UTF-8 encoding exceeds
    ``max_bytes`` (default 8MiB, design 6.5: HTML/MD 各 8MiB).
    """
    if not isinstance(doc, ReportDocument):
        raise TypeError("render_markdown expects a ReportDocument")
    text = "\n\n".join(section(doc) for section in _SECTIONS)
    data = text.encode("utf-8")
    if len(data) > max_bytes:
        raise LimitExceeded(
            f"markdown rendering is {len(data)} bytes, exceeding the "
            f"{max_bytes}-byte budget (design 6.5)"
        )
    return text
