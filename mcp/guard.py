# -*- coding: utf-8 -*-
"""安全护栏 —— 把 windows-forensics-toolchain.md §5.3 的约束变成可执行检查。

本模块零第三方依赖，可在离线环境直接使用。
"""

from __future__ import annotations

import json
import os
import re
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
AUDIT_DIR = os.path.join(_HERE, "audit")

# Windows / Linux 绝对路径；不含 shell 元字符
SAFE_DIR_RE = re.compile(r"^(?:[A-Za-z]:[\\/][\w\-\.\\/ ]{1,200}|/(?:[\w\-\.]+/)*[\w\-\.]+/?)$")

# 明确拒绝的字符：路径穿越与 shell 注入
DANGEROUS_TOKENS = ("..", "|", ";", "&", "`", "$(", "\n", "\r", "'", '"', "<", ">")

# 研判类输入的软性清洗目标：控制字符一律剔除
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def safe_path(p: str) -> tuple:
    """路径参数校验。返回 (是否通过, 错误信息)。

    拒绝路径穿越（..）与所有 shell 元字符，防止参数被拼进命令行后造成注入。
    """
    if not p or not isinstance(p, str):
        return False, "路径为空或类型错误"
    if not SAFE_DIR_RE.match(p):
        return False, "路径不合法：必须是本地绝对路径，仅允许字母数字与 -_. 及路径分隔符"
    if any(t in p for t in DANGEROUS_TOKENS):
        return False, "路径含危险字符（.. 或 shell 元字符），已拒绝"
    return True, ""


def sanitize_text(s: str, max_len: int = 20000) -> tuple:
    """文本入参清洗。返回 (是否通过, 清洗后的文本, 错误信息)。"""
    if not s or not isinstance(s, str):
        return False, "", "输入为空或类型错误"
    if len(s) > max_len:
        return False, "", "输入长度 %d 超过上限 %d，已拒绝" % (len(s), max_len)
    cleaned = _CONTROL_RE.sub("", s)
    return True, cleaned, ""


def audit(tool: str, params: dict, ok: bool, summary: str = "") -> None:
    """审计日志：每次工具调用落盘 audit/YYYYMMDD.jsonl。

    记录时间、工具名、参数、是否成功、结果摘要（截断 500 字符）。
    """
    try:
        os.makedirs(AUDIT_DIR, exist_ok=True)
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "tool": tool,
            "params": params,
            "ok": bool(ok),
            "summary": (summary or "")[:500],
        }
        path = os.path.join(AUDIT_DIR, "%s.jsonl" % time.strftime("%Y%m%d"))
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        # 审计失败不应影响主流程，但要在 stderr 留痕
        import sys
        print("[guard] 审计日志写入失败", file=sys.stderr)


# 供调用方强制附加的安全标记（防止被上游覆盖）
SAFETY_FLAGS = {
    "human_review_required": True,
    "auto_action_allowed": False,
}
