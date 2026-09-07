"""Static self-contained HTML rendering of a :class:`ReportDocument`.

Fixed program-built template (design 5, Phase 3): no template engine, no
JavaScript, no external resources (no CDN, fonts, images or network fetches),
one inline ``<style>`` block, dark/light through ``prefers-color-scheme``.
Every dynamic string passes through :func:`html.escape`; the only ``href``
values ever emitted come from :func:`render_markdown.link_target`, which
accepts package-relative paths only and URL-encodes them — ``javascript:``,
``data:``, ``file:`` and absolute paths are refused with
:class:`~mtsql_typecheck.reporting.model.UnsafeLinkError`.  ``issue_url`` is
plain text and never auto-visited (design 6.4.5).

The headline is derived strictly from the four dimension statuses plus the
review-conflict flag (design 6.2.2: 聚合不生成一个总 PASS；Phase 3 退出标准：
partial 仍可阅读但无绿色全通过标题): any conflict / corruption / unsafe
verdict gets an explicit red badge, any applicable-but-unfinished dimension
gets an explicit amber 部分证据 badge, and only a fully finished audit gets
the neutral completion wording — which is never phrased as 全部通过 because
a semantic recompute is not a SUT correctness proof.

Tables sit in ``overflow-x: auto`` containers and long SQL/ids use
word-break so desktop and narrow screens stay readable.  Same 8MiB byte
budget as Markdown; :class:`LimitExceeded` is raised past it.  Pure module:
no file I/O, no clock.
"""

from __future__ import annotations

import html as _html
from typing import Iterable, Optional, Sequence

from ..contracts.delivery import (
    ExecutionSafetyStatus,
    FindingReview,
    ProvenanceStatus,
    SemanticStatus,
    StructuralStatus,
)
from .markdown import link_target
from .model import (
    DEFAULT_MAX_RENDER_BYTES,
    CoverageSummary,
    ExecutionCounts,
    GenerationCounts,
    LimitExceeded,
    ReportDocument,
)

__all__ = ["DEFAULT_MAX_HTML_BYTES", "headline_for", "render_html"]

DEFAULT_MAX_HTML_BYTES = DEFAULT_MAX_RENDER_BYTES

_NONE = "（无）"
_UNKNOWN = "未知"
_UNRECORDED = "（未记录）"

_CSS = """
:root{color-scheme:light dark;--bg:#ffffff;--fg:#202124;--muted:#5f6368;
--border:#dadce0;--head:#f1f3f4;--link:#0b57d0;
--ok-bg:#e6f4ea;--ok-fg:#137333;--warn-bg:#fef7e0;--warn-fg:#8a6d00;
--bad-bg:#fce8e6;--bad-fg:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#1f2023;--fg:#e8eaed;
--muted:#9aa0a6;--border:#3c4043;--head:#2a2c30;--link:#8ab4f8;
--ok-bg:#1e3326;--ok-fg:#81c995;--warn-bg:#3a3116;--warn-fg:#fdd663;
--bad-bg:#442f2e;--bad-fg:#f28b82}}
*{box-sizing:border-box}
body{margin:0 auto;max-width:960px;padding:16px;background:var(--bg);
color:var(--fg);font:14px/1.6 system-ui,-apple-system,"Segoe UI",
"PingFang SC","Microsoft YaHei",sans-serif}
h1{font-size:20px;line-height:1.4}
h2{font-size:17px;border-bottom:1px solid var(--border);padding-bottom:4px;
margin-top:28px}
h3{font-size:15px;margin:18px 0 6px}
.tablewrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid var(--border);padding:4px 8px;text-align:left;
vertical-align:top}
th{background:var(--head)}
.long{word-break:break-all;overflow-wrap:anywhere;font-family:ui-monospace,
SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.sql{white-space:pre-wrap;word-break:break-all;overflow-wrap:anywhere;
background:var(--head);border:1px solid var(--border);padding:8px;
font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:12.5px;margin:6px 0}
.badge{display:inline-block;font-size:13px;padding:2px 10px;
border-radius:10px;margin-left:8px;vertical-align:middle;white-space:nowrap}
.badge.ok{background:var(--ok-bg);color:var(--ok-fg)}
.badge.warn{background:var(--warn-bg);color:var(--warn-fg)}
.badge.bad{background:var(--bad-bg);color:var(--bad-fg)}
.muted{color:var(--muted)}
a{color:var(--link)}
.disclaimer{color:var(--muted);border-top:1px solid var(--border);
margin-top:32px;padding-top:12px}
"""


def _h(value: str) -> str:
    """Escape one dynamic value for HTML text or attribute context."""
    return _html.escape(value, quote=True)


def _int_or_unknown(value: Optional[int]) -> str:
    return _UNKNOWN if value is None else str(value)


def _opt(value: Optional[str], none_text: str = _NONE) -> str:
    return value if value else none_text


def _table(headers: list[str], rows: Iterable[Sequence[str]]) -> str:
    """Build a wrapped table; each row is a sequence of pre-escaped cells."""
    parts = ['<div class="tablewrap"><table>', "<thead><tr>"]
    parts.extend(f"<th>{_h(cell)}</th>" for cell in headers)
    parts.append("</tr></thead><tbody>")
    for row in rows:
        parts.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
    parts.append("</tbody></table></div>")
    return "".join(parts)


def _plain_cell(value: str) -> str:
    return _h(value)


def _link_cell(relpath: str) -> str:
    target = link_target(relpath)
    return f'<a class="long" href="{_h(target)}">{_h(relpath)}</a>'


def _kv_table(rows: list[tuple[str, str]]) -> str:
    """Two-column table; keys are fixed program text, values pre-escaped."""
    return _table(
        ["字段", "值"],
        [[_h(key), f'<span class="long">{value}</span>'] for key, value in rows],
    )


def _dimension_cell(dimension) -> str:
    applicable = "适用" if dimension.applicable else "不适用"
    text = (
        f"{dimension.status.value}（{applicable}；"
        f"已查 {dimension.checked_objects}，未查 {dimension.unchecked_objects}）"
    )
    if dimension.reason_codes:
        text += "；原因: " + ", ".join(dimension.reason_codes)
    if dimension.detail:
        text += "；" + dimension.detail
    return _h(text)


# --------------------------------------------------------------------------
# Headline derived from the four dimension statuses (design 6.2.2)
# --------------------------------------------------------------------------


def headline_for(doc: ReportDocument) -> tuple[str, str]:
    """Return ``(badge_text, badge_class)`` for the report headline.

    The wording always derives from the four dimension statuses and the
    review-conflict flag; a partially audited source never shows a green
    completion badge and no wording ever claims an overall PASS.
    """
    header = doc.header
    structural = header.structural.status
    semantic = header.semantic.status
    provenance = header.provenance.status
    safety = header.execution_safety.status
    if doc.reviews.has_conflict:
        return ("人工意见冲突 — 全部意见并列保留，需人工处理", "bad")
    if (
        structural in (StructuralStatus.CORRUPT, StructuralStatus.UNSUPPORTED)
        or semantic is SemanticStatus.CONFLICT
        or provenance is ProvenanceStatus.CONFLICT
        or safety is ExecutionSafetyStatus.UNSAFE
    ):
        return ("证据冲突或不可信 — 需人工处理", "bad")
    partial = (
        structural is StructuralStatus.PARTIAL
        or (header.semantic.applicable and semantic is SemanticStatus.NOT_RECOMPUTED)
        or (header.provenance.applicable and provenance is ProvenanceStatus.UNVERIFIED)
        or safety is ExecutionSafetyStatus.UNKNOWN
    )
    if partial:
        return ("部分证据 — 非完整通过", "warn")
    finished = (
        structural is StructuralStatus.COMPLETE
        and (not header.semantic.applicable or semantic is SemanticStatus.RECOMPUTED)
        and (
            not header.provenance.applicable
            or provenance is ProvenanceStatus.CORROBORATED
        )
        and (
            safety is ExecutionSafetyStatus.CONFIRMED
            or safety is ExecutionSafetyStatus.NOT_APPLICABLE
        )
    )
    if finished:
        return ("四维审计完成（非正确性证明）", "ok")
    return ("部分证据 — 非完整通过", "warn")


# --------------------------------------------------------------------------
# Sections
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
        ("工具", _plain_cell(header.tool_name)),
        ("报告写入器版本", _plain_cell(header.writer_version)),
        ("原生格式", _plain_cell(header.native_kind.value)),
        ("真实/合成", _plain_cell(header.synthetic.value)),
        ("原执行状态", _h(_opt(header.original_run_status, _UNRECORDED))),
        ("结构审计", _dimension_cell(header.structural)),
        ("语义审计", _dimension_cell(header.semantic)),
        ("来源佐证", _dimension_cell(header.provenance)),
        ("执行安全", _dimension_cell(header.execution_safety)),
        ("生成工具信息", _h(producer)),
        ("源提交", _h(_opt(header.source_commit, _UNRECORDED))),
        ("source_id", _plain_cell(header.source_id)),
        ("delivery_id", _plain_cell(header.delivery_id)),
        ("报告生成时间", _h(_opt(header.generated_at, _UNRECORDED))),
        ("已知限制", _h(limitations)),
    ]
    return _kv_table(rows)


def _generation_section(counts: Optional[GenerationCounts]) -> str:
    if counts is None:
        return ""
    rows = [
        ("请求序号", _h(_int_or_unknown(counts.requested_ordinals))),
        ("尝试候选", _h(_int_or_unknown(counts.attempted_candidates))),
        ("产出 occurrence", _h(_int_or_unknown(counts.emitted_occurrences))),
        ("唯一 case", _h(_int_or_unknown(counts.unique_cases))),
        ("拒绝序号", _h(_int_or_unknown(counts.rejected_ordinals))),
        ("中断序号", _h(_int_or_unknown(counts.interrupted_ordinals))),
        ("未尝试", _h(_int_or_unknown(counts.not_attempted))),
        ("回执复核", _plain_cell(counts.receipt_recheck)),
        ("回执不一致原因", _h(_opt(counts.receipt_mismatch_reason))),
        ("分母已知", _h("是" if counts.denominator_known else "否")),
    ]
    return "<h3>生成计数</h3>" + _kv_table(rows)


def _execution_section(counts: Optional[ExecutionCounts]) -> str:
    if counts is None:
        return ""
    rows = [
        ("请求执行", _h(_int_or_unknown(counts.requested_attempts))),
        ("双侧完成", _h(_int_or_unknown(counts.completed_both_selects))),
        ("match 候选", _h(_int_or_unknown(counts.match_candidates))),
        ("不适用", _h(_int_or_unknown(counts.not_applicable))),
        ("不可判定", _h(_int_or_unknown(counts.undecidable))),
        ("预检失败", _h(_int_or_unknown(counts.preflight_failures))),
        ("未派发", _h(_int_or_unknown(counts.undispatched))),
    ]
    return "<h3>执行计数</h3>" + _kv_table(rows)


def _coverage_section(summary: Optional[CoverageSummary]) -> str:
    if summary is None:
        return ""
    if summary.denominator_known:
        denominator_line = "<p>覆盖分母：已知</p>"
    else:
        denominator_line = (
            "<p>覆盖分母：未知（原因: "
            + _h(summary.unknown_reason or "")
            + "）</p>"
        )
    if summary.entries:
        rows = []
        for entry in summary.entries:
            rows.append(
                [
                    _h(entry.rule_id),
                    _h(str(entry.rule_version)),
                    _h(entry.type_pair),
                    _h(entry.template),
                    _h(entry.index_variant),
                    _h(_opt(entry.build_key, "—")),
                    _h(str(entry.comparable_unique_cases)),
                    _h(_UNKNOWN if entry.denominator is None else str(entry.denominator)),
                ]
            )
        table = _table(
            [
                "规则",
                "版本",
                "类型对",
                "模板",
                "索引变体",
                "build",
                "唯一可比 case",
                "分母",
            ],
            rows,
        )
    else:
        table = f"<p>{_h(_NONE)}</p>"
    controls = (
        "<p>控制组（不计入非平凡覆盖）：identity-only "
        + str(summary.identity_only_cases)
        + " 个；空结果 "
        + str(summary.empty_result_cases)
        + " 个。</p>"
    )
    return f"<h3>唯一覆盖</h3>{denominator_line}{table}{controls}"


def _section_counts(doc: ReportDocument) -> str:
    body = (
        _generation_section(doc.generation_counts)
        + _execution_section(doc.execution_counts)
        + _coverage_section(doc.coverage)
    )
    if not body:
        body = f"<p>{_h(_NONE)}</p>"
    return body


def _section_findings(doc: ReportDocument) -> str:
    findings = doc.findings
    summary_rows = [
        ("真实候选", _h(str(findings.real_candidates))),
        ("合成候选", _h(str(findings.synthetic_candidates))),
        ("合成未知候选", _h(str(findings.unknown_synthetic_candidates))),
        ("语义冲突", _h(str(findings.conflicts))),
        ("唯一 case 数", _h(str(findings.unique_case_ids))),
        ("不同精确签名", _h(str(findings.distinct_signatures))),
        ("不同粗指纹", _h(str(findings.distinct_fingerprints))),
        ("已确认（review 绑定）", _h(str(findings.reviewed_confirmed))),
    ]
    parts = ["<h3>候选汇总</h3>", _kv_table(summary_rows), "<h3>候选明细（按风险与稳定 ID 排序）</h3>"]
    if doc.occurrences:
        rows = []
        for occurrence in doc.occurrences:
            rows.append(
                [
                    _plain_cell(occurrence.occurrence_id),
                    _plain_cell(occurrence.case_id),
                    _h(occurrence.attempt_id),
                    _h(occurrence.recompute_status.value),
                    _h(occurrence.synthetic.value),
                    _h(_opt(occurrence.fingerprint, "—")),
                ]
            )
        parts.append(
            _table(
                ["occurrence_id", "case_id", "attempt", "复算状态", "合成", "指纹"],
                rows,
            )
        )
    else:
        parts.append(f"<p>{_h(_NONE)}</p>")
    return "".join(parts)


def _section_case_details(doc: ReportDocument) -> str:
    if not doc.case_details:
        return f"<p>{_h(_NONE)}</p>"
    parts: list[str] = []
    for detail in doc.case_details:
        rows = [
            ("occurrence_id", _plain_cell(detail.occurrence_id)),
            ("case_id", _plain_cell(detail.case_id)),
            ("规则", _h(f"{detail.rule_id} @ v{detail.rule_version}")),
            ("类型对", _h(detail.type_pair)),
            ("原始引用", _link_cell(detail.original_ref) if detail.original_ref else _h(_NONE)),
            ("最佳引用", _link_cell(detail.best_ref) if detail.best_ref else _h(_NONE)),
            (
                "每轮轨迹",
                _h("; ".join(detail.round_outcomes) if detail.round_outcomes else _NONE),
            ),
            (
                "关联 review",
                _h(", ".join(detail.review_ids) if detail.review_ids else _NONE),
            ),
        ]
        blocks = [f"<h3>Case {_h(detail.case_id)}</h3>", _kv_table(rows)]
        if detail.select_text is not None:
            blocks.append("<p class=\"muted\">SELECT</p>")
            blocks.append(f'<div class="sql">{_h(detail.select_text)}</div>')
        if detail.diff_summary is not None:
            blocks.append("<p class=\"muted\">差异摘要</p>")
            blocks.append(f'<div class="sql">{_h(detail.diff_summary)}</div>')
        parts.append("".join(blocks))
    return "".join(parts)


def _review_table(reviews: Iterable[FindingReview]) -> str:
    rows = []
    for review in reviews:
        rows.append(
            [
                _plain_cell(review.review_id),
                _h(review.decision.value),
                _h(review.reviewer),
                _h(review.reviewed_at),
                _plain_cell(review.evidence_digest),
                _h(", ".join(review.occurrence_ids)),
                _h(_opt(review.supersedes, "—")),
                _h(review.reason),
                _h(_opt(review.issue_url, "—")),
            ]
        )
    return _table(
        [
            "review_id",
            "决策",
            "reviewer",
            "时间",
            "证据摘要",
            "关联 occurrence",
            "替代",
            "意见",
            "issue",
        ],
        rows,
    )


def _section_reviews(doc: ReportDocument) -> str:
    reviews = doc.reviews
    parts: list[str] = []
    if reviews.has_conflict:
        parts.append(
            "<p><strong>警告：存在互斥的人工 review 冲突；以下全部意见并列保留，"
            "原始观察未被修改。</strong></p>"
        )
    if reviews.accepted:
        parts.append("<h3>本次意见</h3>")
        parts.append(_review_table(reviews.accepted))
    if reviews.historical:
        parts.append("<h3>历史意见（绑定其他证据，仅展示，不自动应用）</h3>")
        parts.append(_review_table(item.review for item in reviews.historical))
        parts.append("<ul>")
        for item in reviews.historical:
            parts.append(
                f"<li>{_h(item.review.review_id)}: {_h(item.detail)}</li>"
            )
        parts.append("</ul>")
    if reviews.conflicts:
        parts.append("<h3>互斥冲突</h3>")
        rows = []
        for conflict in reviews.conflicts:
            rows.append(
                [
                    _h(", ".join(conflict.occurrence_ids)),
                    _h(", ".join(conflict.review_ids)),
                    _h(conflict.detail),
                ]
            )
        parts.append(_table(["occurrence", "review", "说明"], rows))
    if reviews.duplicates_ignored:
        parts.append("<h3>同 ID 重复忽略</h3>")
        parts.append("<p>" + _h(", ".join(reviews.duplicates_ignored)) + "</p>")
    if not parts:
        parts.append(f"<p>{_h(_NONE)}</p>")
    return "".join(parts)


def _section_inventory(doc: ReportDocument) -> str:
    parts: list[str] = ["<h3>文件清单</h3>"]
    if doc.inventory.files:
        rows = []
        for item in doc.inventory.files:
            rows.append(
                [
                    _link_cell(item.path),
                    _h(item.role.value),
                    _h(str(item.size_bytes)),
                    f'<span class="long">{_h(item.sha256)}</span>',
                ]
            )
        parts.append(_table(["路径", "角色", "字节数", "sha256"], rows))
    else:
        parts.append(f"<p>{_h(_NONE)}</p>")
    parts.append("<h3>审计问题</h3>")
    if doc.inventory.problems:
        rows = []
        for problem in doc.inventory.problems:
            rows.append(
                [
                    _h(problem.code),
                    _h(_opt(problem.path, "—")),
                    _h(problem.detail),
                ]
            )
        parts.append(_table(["代码", "路径", "说明"], rows))
    else:
        parts.append(f"<p>{_h(_NONE)}</p>")
    parts.append("<h3>复现说明</h3>")
    if doc.inventory.reproduction_notes:
        parts.append("<ol>")
        for note in doc.inventory.reproduction_notes:
            parts.append(f"<li>{_h(note)}</li>")
        parts.append("</ol>")
    else:
        parts.append(f"<p>{_h(_NONE)}</p>")
    return "".join(parts)


_SECTIONS = (
    ("版本与来源", _section_header),
    ("计数与覆盖", _section_counts),
    ("候选与异常", _section_findings),
    ("Case 明细", _section_case_details),
    ("人工 Review", _section_reviews),
    ("文件清单与复现", _section_inventory),
)


def render_html(doc: ReportDocument, *, max_bytes: int = DEFAULT_MAX_HTML_BYTES) -> str:
    """Render the report as a static self-contained HTML page (6.4.5, 6.5).

    Raises :class:`LimitExceeded` when the UTF-8 encoding exceeds
    ``max_bytes`` (default 8MiB) and :class:`UnsafeLinkError` when the
    inventory contains a path the controlled link builder refuses.
    """
    if not isinstance(doc, ReportDocument):
        raise TypeError("render_html expects a ReportDocument")
    badge_text, badge_class = headline_for(doc)
    parts = [
        "<!doctype html>",
        '<html lang="zh-CN">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>TypeCheck 证据报告</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        "<main>",
        f'<h1>TypeCheck 证据报告 <span class="badge {badge_class}">{_h(badge_text)}</span></h1>',
    ]
    for title, builder in _SECTIONS:
        parts.append(f"<h2>{_h(title)}</h2>")
        parts.append(builder(doc))
    parts.append(
        '<p class="disclaimer">本报告是证据展示：报告生成不等于测试通过，'
        "也不证明被测数据库正确性。诊断与 SQL 仅作文本展示，不会被执行；"
        "页面无脚本、无外部资源，issue 链接不会被自动访问。</p>"
    )
    parts.append("</main>")
    parts.append("</body>")
    parts.append("</html>")
    text = "\n".join(parts) + "\n"
    data = text.encode("utf-8")
    if len(data) > max_bytes:
        raise LimitExceeded(
            f"html rendering is {len(data)} bytes, exceeding the "
            f"{max_bytes}-byte budget (design 6.5)"
        )
    return text
