"""报告生成：把流水线结果渲染成可归档、可入报告的文本。

输出两种形态：
    render_markdown()     —— 完整的 Markdown 报告，可直接粘进应急报告或归档
    render_text_summary()  —— 终端友好的简短摘要，现场看一眼就知道重点

报告刻意保留了三段"看起来不讨喜"的内容：能力边界、未解析文件、已知盲区。
因为一份声称全覆盖的应急报告是不可信的；说清楚"我没查什么"，
比多说一句"我很强"更能让复核者放心。
"""
from __future__ import annotations

from typing import Any, Dict, List

from .schema import severity_rank

_SEV_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}

# 与 windows/windows-detection-validation.md 声明一致的能力盲区。
# 报告里必须显式列出，避免读者把"没报出来"误读为"没问题"。
KNOWN_BLIND_SPOTS = [
    "内核级 Rootkit（本流水线在用户态运行，不读取内核内存）",
    "BYOVD（利用合法签名驱动关停防护）——需结合驱动加载日志与签名链分析",
    "内存马 / 无文件注入（需内存取证与 pe-sieve 类工具配合）",
    "业务调度平台后门（如 XXL-JOB glue 脚本）——需针对中间件单独核查",
    "云身份滥用（AK/SK 泄露、控制台异常登录）——不在主机产物范围内",
]


def _fmt_attack(attack: Any) -> str:
    if not isinstance(attack, dict) or not attack:
        return "-"
    tech = attack.get("technique", "")
    name = attack.get("name", "")
    tactic = attack.get("tactic", "")
    parts = [p for p in (tech, name, tactic) if p]
    return " / ".join(parts) if parts else "-"


def render_text_summary(result: Any) -> str:
    """终端摘要：10 行内看完，现场快速判断要不要深入。"""
    if not result.ok:
        return "采集产物解析失败: {0}".format(result.error)

    c = result.collection
    counts = result.severity_counts()
    lines = [
        "=" * 58,
        " 应急采集产物研判结果（本地规则，未联网）",
        "=" * 58,
        " 主机        : {0}".format(c.host or "(未识别)"),
        " 采集时间    : {0}".format(c.collected_at or "(未识别)"),
        " 数据来源    : {0} (置信度 {1})".format(result.adapter, result.probe_score),
        " 归一化记录  : {0} 条".format(c.total_records),
        " 命中线索    : {0} 条  {1}".format(
            len(result.findings),
            " ".join("{0}={1}".format(_SEV_LABEL.get(k, k), v)
                     for k, v in sorted(counts.items(), key=lambda x: severity_rank(x[0])))
            or ""
        ),
        " 解析耗时    : {0} ms".format(result.stats.get("elapsed_ms", 0)),
        "-" * 58,
        " 结论需人工确认；本工具不做任何处置动作。",
        "=" * 58,
    ]
    return "\n".join(lines)


def render_markdown(result: Any, top_n: int = 50, verbose: bool = False) -> str:
    """渲染完整 Markdown 报告。top_n 控制线索明细最多展示多少条。"""
    if not result.ok:
        return "# 采集产物研判报告\n\n**解析失败**：{0}\n".format(result.error)

    c = result.collection
    counts = result.severity_counts()
    out: List[str] = []

    out.append("# 主机应急采集 · 产物研判报告")
    out.append("")
    out.append("> 本报告由本地规则引擎生成，**全程不联网、不调用任何大模型**。")
    out.append("> 所有结论均为规则初筛结果，**必须经人工确认**后才能作为处置依据。")
    out.append("")

    # ---------------- 1 采集概览
    out.append("## 1. 采集概览")
    out.append("")
    out.append("| 项目 | 值 |")
    out.append("|---|---|")
    out.append("| 主机名 | {0} |".format(c.host or "(未识别)"))
    out.append("| 采集时间 | {0} |".format(c.collected_at or "(未识别)"))
    out.append("| 平台 | {0} |".format(c.platform))
    out.append("| 适配器 | `{0}`（探测置信度 {1}） |".format(result.adapter, result.probe_score))
    out.append("| 产物目录 | `{0}` |".format(c.root))
    out.append("| 归一化记录 | {0} 条 |".format(c.total_records))
    out.append("| 命中线索 | {0} 条 |".format(len(result.findings)))
    out.append("| 解析耗时 | {0} ms |".format(result.stats.get("elapsed_ms", 0)))
    out.append("")

    # ---------------- 2 记录分布
    out.append("## 2. 数据分布（按记录种类）")
    out.append("")
    out.append("| 种类 | 条数 |")
    out.append("|---|---|")
    for k, v in sorted((c.records_by_kind or {}).items(), key=lambda x: -x[1]):
        out.append("| {0} | {1} |".format(k, v))
    out.append("")

    # ---------------- 3 线索清单
    out.append("## 3. 线索清单")
    out.append("")
    if not result.findings:
        out.append("本次规则库**未命中任何线索**。")
        out.append("")
        out.append("> ⚠️ 这不等于「主机干净」。规则库覆盖的是已知手法特征，"
                   "未命中的原因可能是：① 确实无异常；② 数据源缺失导致证据不足；"
                   "③ 手法不在当前规则库覆盖范围内（见第 4 节盲区）。")
        out.append("")
    else:
        out.append("严重级别分布：")
        out.append("")
        for sev in ("critical", "high", "medium", "low", "info"):
            if counts.get(sev):
                out.append("- **{0}**（{1}）：{2} 条".format(
                    _SEV_LABEL.get(sev, sev), sev, counts[sev]))
        out.append("")

        for idx, f in enumerate(result.findings[:top_n], 1):
            rec = f.get("record") or {}
            fields = rec.get("fields") or {}
            rule = f.get("top_rule") or {}

            # 标题用「规则名 + 命中对象」而不是整句 summary，便于快速扫读
            label = rule.get("name") or "疑似异常"
            obj = (fields.get("name") or fields.get("detail")
                   or fields.get("display") or "")
            obj = str(obj)[:60]
            out.append("### {0}. [{1}] {2}{3}".format(
                idx,
                _SEV_LABEL.get(f.get("severity", "info"), f.get("severity", "")),
                label,
                " — `{0}`".format(obj) if obj else "",
            ))
            out.append("")
            out.append("- 来源产物：`{0}`".format(rec.get("source", "-")))
            out.append("- 记录种类：`{0}`".format(rec.get("kind", "-")))
            key_fields = [k for k in ("name", "path", "cmd", "cmdline", "mech",
                                      "remote_addr", "remote_port", "pid", "user",
                                      "hidden", "detail", "display") if fields.get(k)]
            if key_fields:
                out.append("- 关键字段：")
                for k in key_fields:
                    out.append("    - `{0}` = `{1}`".format(k, str(fields[k])[:300]))
            out.append("- 命中规则：`{0}` {1}".format(rule.get("rule_id", "-"),
                                                    rule.get("name", "")))
            out.append("- 研判摘要：{0}".format(f.get("summary", "")))
            out.append("- ATT&CK：{0}".format(_fmt_attack(rule.get("attack"))))
            if rule.get("matched_keywords"):
                out.append("- 命中关键词：{0}".format(
                    ", ".join("`{0}`".format(x) for x in rule["matched_keywords"])))
            if rule.get("matched_predicates"):
                out.append("- 命中条件：{0}".format(
                    "; ".join("`{0}`".format(x) for x in rule["matched_predicates"])))

            fph = rule.get("false_positive_hints") or []
            if fph:
                out.append("- **可能的误报**（先排除这些再定性）：")
                for h in fph:
                    out.append("    - {0}".format(h))
            ns = rule.get("next_steps") or []
            if ns:
                out.append("- **建议人工验证步骤**（本工具不代为执行）：")
                for s in ns:
                    out.append("    - {0}".format(s))
            if verbose and rec.get("raw"):
                out.append("- 原始行：")
                out.append("")
                out.append("```")
                out.append(str(rec["raw"])[:800])
                out.append("```")
            out.append("")

        if len(result.findings) > top_n:
            out.append("> 另有 {0} 条线索未展开，见 JSON 结果文件。".format(
                len(result.findings) - top_n))
            out.append("")

    # ---------------- 4 能力边界
    out.append("## 4. 能力边界（必读）")
    out.append("")
    out.append("### 4.1 已知盲区")
    out.append("")
    out.append("以下场景本流水线**无法覆盖**，若怀疑涉及，须切换到对应专项手段：")
    out.append("")
    for b in KNOWN_BLIND_SPOTS:
        out.append("- {0}".format(b))
    out.append("")

    out.append("### 4.2 产物清单（供核对采集完整性）")
    out.append("")
    artifacts = result.stats.get("artifact_files") or []
    if artifacts:
        out.append("目录内共 {0} 个采集产物文件：".format(len(artifacts)))
        out.append("")
        for s in artifacts[:40]:
            out.append("- `{0}`".format(s))
        if len(artifacts) > 40:
            out.append("- …等共 {0} 个".format(len(artifacts)))
        out.append("")
        out.append("> 若某类关键证据（如事件日志导出、计划任务列表）不在此清单中，")
        out.append("> 说明采集时该项未取到或未开启，**此时「未命中线索」不能作为排查结论**。")
    else:
        out.append("目录内未发现已知类型的采集产物文件，请确认传入的是采集输出根目录。")
    out.append("")

    # ---------------- 5 声明
    out.append("## 5. 声明")
    out.append("")
    out.append("- 本报告由 `mcp/irflow` 本地规则流水线生成，未联网、未调用大模型。")
    out.append("- 字段 `human_review_required` 恒为 `true`、`auto_action_allowed` 恒为 `false`，")
    out.append("  该约束硬编码在代码中，不受调用方式与提示词影响。")
    out.append("- 报告不含真实客户环境数据；规则关键词均取自公开威胁情报与 ATT&CK 技术描述。")
    out.append("")
    return "\n".join(out)
