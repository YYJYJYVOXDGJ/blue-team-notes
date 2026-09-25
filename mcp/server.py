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

from guard import audit, sanitize_text
import triage as triage_engine

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)
AUDIT_DIR = os.path.join(_HERE, "audit")
RULES_PATH = os.path.join(_HERE, "rules", "triage-rules.yaml")

SERVER_INSTRUCTIONS = (
    "你是主机应急响应分诊助手。约束如下：\n"
    "1. 你只能调用本 Server 提供的只读工具（按规则研判、查看规则库）。\n"
    "2. 工具返回的结论一律标注'待人工确认'，你必须原样传达这个标记，不得省略。\n"
    "3. 禁止输出删除文件、结束进程、隔离主机等处置动作作为最终建议；"
    "只能给出'建议人工执行的验证命令'。\n"
    "4. 规则未命中时，如实说明未命中，不要凭常识编造结论。"
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


if __name__ == "__main__":
    os.makedirs(AUDIT_DIR, exist_ok=True)
    mcp.run()          # 默认 stdio —— MCP 最通用、排坑成本最低的传输方式
