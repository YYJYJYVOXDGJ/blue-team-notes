# -*- coding: utf-8 -*-
"""blue-team-notes MCP Server —— 只读应急能力封装（最小可用版）。

安全底线（对齐 windows/windows-forensics-toolchain.md §5.3）：

| 约束         | 本实现的做法                                                     |
|--------------|------------------------------------------------------------------|
| 只读默认     | 只暴露查询/研判类工具, 不提供任何命令执行或写操作接口             |
| 白名单查询   | 入参用 Literal / 枚举约束, 非白名单值直接拒绝                     |
| 参数校验     | 长度、字符、类型在 guard 层统一校验                               |
| 审计日志     | 每次调用落盘 audit/YYYYMMDD.jsonl                                 |
| 最小权限     | 不需管理员权限即可运行                                            |
| 结果留痕     | 结果写入审计日志摘要, 不只存在于会话中                            |
| 人在回路     | 返回值硬编码 human_review_required=True / auto_action_allowed=False |
| 数据边界     | **本 Server 不发起任何外部网络请求, 不调用任何大模型 API**        |

模型在 MCP 客户端侧（Claude Desktop / Inspector / 自研 Agent），
本 Server 只提供**确定性的、只读的**能力。这个分层是刻意设计的：
判定环节不放进模型，避免幻觉导致的误处置。
"""

from __future__ import annotations

import json
import os
import time
from typing import Literal, Optional

from mcp.server.fastmcp import FastMCP

from guard import audit, sanitize_text, safe_path
import triage as triage_engine

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)
AUDIT_DIR = os.path.join(_HERE, "audit")
RULES_PATH = os.path.join(_HERE, "rules", "triage-rules.yaml")

SERVER_INSTRUCTIONS = (
    "你是主机应急响应分诊助手。约束如下：\n"
    "1. 你只能调用本 Server 提供的只读工具（规则研判、采集产物分析、查看规则库与能力边界）。\n"
    "2. 工具返回的结论一律标注'待人工确认'，你必须原样传达这个标记，不得省略。\n"
    "3. 禁止输出删除文件、结束进程、隔离主机等处置动作作为最终建议；"
    "只能给出'建议人工执行的验证命令'。\n"
    "4. 规则未命中时，如实说明未命中，不要凭常识编造结论；"
    "报告'未命中'时必须同时说明已知盲区（可调用 list_sources 获取）。\n"
    "5. 分析采集产物前，先确认 result_dir 是采集脚本的输出根目录；"
    "无法识别来源时要如实说明，不要猜测。"
)

_RULES_CACHE: Optional[list] = None


def _rules() -> list:
    global _RULES_CACHE
    if _RULES_CACHE is None:
        _RULES_CACHE = triage_engine.load_rules(RULES_PATH)
    return _RULES_CACHE


def _build_server() -> FastMCP:
    try:
        return FastMCP("blue-team-ir", instructions=SERVER_INSTRUCTIONS)
    except TypeError:
        # 部分 SDK 版本的 FastMCP 不支持 instructions 参数，降级后约束仍写在
        # 工具 docstring 与返回值里。
        return FastMCP("blue-team-ir")


mcp = _build_server()


# --------------------------------------------------------------------------
# Tool 1（主）：本地规则研判
# --------------------------------------------------------------------------
@mcp.tool()
def triage_alert(
    alert: str,
    top_k: Literal[1, 2, 3, 5, 10] = 3,
) -> dict:
    """按本地规则库对一条告警或一段日志做初筛研判。

    返回命中的规则、ATT&CK 映射、置信度、误报提示与建议的人工验证步骤。

    重要：本工具不做任何自动处置。返回结果的 human_review_required 恒为 true、
    auto_action_allowed 恒为 false —— 这是硬编码的，不随调用方式改变。

    Args:
        alert: 告警原文或日志片段（≤20000 字符）。
        top_k: 返回前 N 条命中规则。
    """
    ok, text, err = sanitize_text(alert, max_len=20000)
    if not ok:
        audit("triage_alert", {"error": err}, False, err)
        return {"ok": False, "error": err,
                "human_review_required": True, "auto_action_allowed": False}

    result = triage_engine.triage(text, rules=_rules(), top_k=int(top_k))
    result["human_review_required"] = True     # 硬编码：人在回路
    result["auto_action_allowed"] = False      # 硬编码：禁止自动处置

    audit("triage_alert",
          {"input_length": len(text), "top_k": top_k},
          bool(result.get("ok")),
          str(result.get("summary", "")))
    return result


# --------------------------------------------------------------------------
# Tool 2（辅）：查看规则库覆盖范围
# --------------------------------------------------------------------------
@mcp.tool()
def list_rules(severity: Optional[Literal["critical", "high", "medium", "low"]] = None) -> dict:
    """列出当前规则库的规则清单（id / 名称 / ATT&CK 编号 / 严重级别）。

    用于让调用方了解本 Server 的能力边界：只覆盖清单内的场景，
    清单外的告警不会被误判为正常。

    Args:
        severity: 仅返回该严重级别的规则；不传则返回全部。
    """
    rules = _rules()
    items = []
    for r in rules:
        sev = str(r.get("severity", "")).lower()
        if severity and sev != severity:
            continue
        items.append({
            "id": r.get("id"),
            "name": r.get("name"),
            "severity": sev,
            "attack": r.get("attack") or {},
        })
    out = {
        "ok": True,
        "rules_version": triage_engine.RULES_VERSION,
        "count": len(items),
        "rules": items,
        "human_review_required": True,
        "auto_action_allowed": False,
    }
    audit("list_rules", {"severity": severity}, True, "count=%d" % len(items))
    return out


# --------------------------------------------------------------------------
# Tool 3（v0.2 新增）：对采集产物目录做完整研判
# --------------------------------------------------------------------------
@mcp.tool()
def analyze_collection(
    result_dir: str,
    top_k: Literal[3, 5, 10] = 5,
    out_report: Optional[str] = None,
) -> dict:
    """对一次主机采集的产物目录做完整研判，返回按严重级别排序的可疑项清单。

    支持 Windows 与 Linux 两套采集脚本的产物目录（自动探测），
    内部执行：目录探测 → 异构产物归一化 → 规则研判 → 报告生成。

    本工具**只读采集产物**，不修改、不删除、不移动其中的任何文件。
    若提供 out_report，报告会写到该路径（Markdown），用于归档与跨时间比对。

    重要：返回值中 human_review_required 恒为 true、auto_action_allowed 恒为 false。

    Args:
        result_dir: 采集脚本的输出根目录（不是它的上级目录）。
        top_k: 每条可疑项最多附带的候选规则数。
        out_report: 可选，Markdown 报告的落盘路径。
    """
    ok, path, err = safe_path(result_dir)
    if not ok:
        audit("analyze_collection", {"result_dir": result_dir}, False, err)
        return {"ok": False, "error": err,
                "human_review_required": True, "auto_action_allowed": False}

    if not os.path.isdir(path):
        msg = "目录不存在: {0}".format(path)
        audit("analyze_collection", {"result_dir": path}, False, msg)
        return {"ok": False, "error": msg,
                "human_review_required": True, "auto_action_allowed": False}

    try:
        from irflow import run_pipeline, render_markdown, render_text_summary
    except ImportError as exc:
        msg = ("irflow 模块不可用: {0}（请确认 mcp/ 目录完整，"
               "并以 mcp 为工作目录启动本 Server）").format(exc)
        audit("analyze_collection", {"result_dir": path}, False, msg)
        return {"ok": False, "error": msg,
                "human_review_required": True, "auto_action_allowed": False}

    result = run_pipeline(path, top_k=int(top_k))

    payload = {
        "ok": result.ok,
        "error": result.error,
        "adapter": result.adapter,
        "probe_score": result.probe_score,
        "collection": result.collection.to_dict() if result.collection else None,
        "stats": result.stats,
        "findings": result.findings[:200],          # 会话内只回传前 200 条
        "finding_count": len(result.findings),
        "severity_counts": result.severity_counts(),
        "summary": render_text_summary(result),
        "human_review_required": True,
        "auto_action_allowed": False,
        "note": ("本结果为本地规则初筛，未经人工确认不得作为处置依据；"
                 "Agent 应如实转述'待人工确认'，并引导用户按 next_steps 逐条核实。"),
    }

    if result.ok and result.findings:
        payload["top_findings"] = [
            {
                "severity": f.get("severity"),
                "rule": (f.get("top_rule") or {}).get("rule_id"),
                "attack": (f.get("top_rule") or {}).get("attack"),
                "summary": f.get("summary"),
                "source": (f.get("record") or {}).get("source"),
            }
            for f in result.findings[:10]
        ]

    if out_report and result.ok:
        ok2, out_path, err2 = safe_path(out_report)
        if not ok2:
            payload["report_error"] = err2
        else:
            try:
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(render_markdown(result))
                payload["report_written"] = out_path
            except OSError as exc:
                payload["report_error"] = str(exc)

    audit("analyze_collection",
          {"result_dir": path, "top_k": top_k, "out_report": out_report},
          bool(result.ok),
          "records=%s findings=%s" % (
              result.collection.total_records if result.collection else 0,
              len(result.findings)))

    return payload


# --------------------------------------------------------------------------
# Tool 4（v0.2 新增）：能力边界自述
# --------------------------------------------------------------------------
@mcp.tool()
def list_sources() -> dict:
    """列出本 Server 当前支持的采集来源（适配器）与已知盲区。

    用途：让 Agent 在回答"这台机器有没有问题"之前，先知道本工具**能看什么、
    不能看什么**。未命中线索时不得直接下"主机正常"的结论。
    """
    try:
        from irflow.adapters import registered
        from irflow.report import KNOWN_BLIND_SPOTS
    except ImportError as exc:
        return {"ok": False, "error": "irflow 模块不可用: {0}".format(exc),
                "human_review_required": True, "auto_action_allowed": False}

    sources = [
        {"name": a.name, "platform": a.platform,
         "expects": getattr(a, "_SIGNATURES", [])}
        for a in registered()
    ]
    out = {
        "ok": True,
        "sources": sources,
        "known_blind_spots": KNOWN_BLIND_SPOTS,
        "human_review_required": True,
        "auto_action_allowed": False,
        "note": ("规则未命中不等于主机正常；未覆盖的场景需按对应专项手段排查。"),
    }
    audit("list_sources", {}, True, "sources=%d" % len(sources))
    return out


if __name__ == "__main__":
    os.makedirs(AUDIT_DIR, exist_ok=True)
    mcp.run()          # 默认 stdio —— MCP 最通用、排坑成本最低的传输方式
