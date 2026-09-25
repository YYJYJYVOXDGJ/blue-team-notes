# -*- coding: utf-8 -*-
"""告警分诊规则引擎 —— 本地确定性研判。

设计要点（与 windows/windows-forensics-toolchain.md §5.3 安全底线对齐）:

1. **不调用任何大模型或外部 API**。判定完全由本地规则库决定, 结果是确定性的、
   可复现的、可审计的。模型的价值在于"把人话翻译成查询、把结构化结果讲成人话",
   中间的判定环节不让模型参与。
2. **人在回路是代码写死的**: 返回值恒定带 ``human_review_required=True`` 与
   ``auto_action_allowed=False``, 不依赖提示词约束, 也不会因为模型输出而改变。
3. **零第三方依赖**: 有 PyYAML 时用 PyYAML, 没有时回退内置的最小解析器,
   保证在离线应急环境(便携 Python / U 盘)里也能直接跑。
4. **数据边界**: 本模块不发起任何网络请求, 告警文本只在本机内存中处理。

规则文件: rules/triage-rules.yaml
"""

from __future__ import annotations

import os
from typing import Any

RULES_VERSION = "0.1.0"

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RULES_PATH = os.path.join(_HERE, "rules", "triage-rules.yaml")

# 严重级别基础分
_SEVERITY_BASE = {"critical": 45, "high": 30, "medium": 15, "low": 8, "info": 3}


# --------------------------------------------------------------------------
# 最小 YAML 解析器（仅支持本仓库规则文件用到的子集）
#   - 2 空格缩进
#   - "key: value" 标量 / "key:" 后接子块 / "- item" 列表 / "- key: value" 字典项
#   - 内联列表 ["a", "b"] 与 []
# 有 PyYAML 时不会用到它, 它只是为了离线环境兜底。
# --------------------------------------------------------------------------

def _scalar(v: str) -> Any:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [_scalar(x) for x in inner.split(",")]
    if v in ("null", "~", "None"):
        return None
    return v


def _parse_dict(rows: list, pos: list, indent: int) -> dict:
    out: dict = {}
    while pos[0] < len(rows):
        ind, content = rows[pos[0]]
        if ind != indent or content.startswith("- "):
            break
        if ":" not in content:
            pos[0] += 1
            continue
        key, _, val = content.partition(":")
        key, val = key.strip(), val.strip()
        pos[0] += 1
        if val == "":
            if pos[0] < len(rows) and rows[pos[0]][0] > ind:
                nind = rows[pos[0]][0]
                if rows[pos[0]][1].startswith("- "):
                    out[key] = _parse_list(rows, pos, nind)
                else:
                    out[key] = _parse_dict(rows, pos, nind)
            else:
                out[key] = None
        else:
            out[key] = _scalar(val)
    return out


def _parse_list(rows: list, pos: list, indent: int) -> list:
    out: list = []
    while pos[0] < len(rows):
        ind, content = rows[pos[0]]
        if ind != indent or not content.startswith("- "):
            break
        item = content[2:].strip()
        if ":" in item:                       # "- id: MINING-001" → 字典项
            sub = [(ind + 2, item)]
            pos[0] += 1
            while pos[0] < len(rows) and rows[pos[0]][0] > ind:
                sub.append(rows[pos[0]])
                pos[0] += 1
            out.append(_parse_dict(sub, [0], ind + 2))
        else:                                  # "- xmrig" → 标量项
            out.append(_scalar(item))
            pos[0] += 1
    return out


def _mini_yaml_load(text: str) -> Any:
    rows: list = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        rows.append((indent, line.strip()))
    if not rows:
        return []
    pos = [0]
    if rows[0][1].startswith("- "):
        return _parse_list(rows, pos, rows[0][0])
    return _parse_dict(rows, pos, rows[0][0])


def _load_yaml(path: str) -> Any:
    try:
        import yaml  # type: ignore
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        with open(path, "r", encoding="utf-8") as f:
            return _mini_yaml_load(f.read())


# --------------------------------------------------------------------------
# 规则加载与匹配
# --------------------------------------------------------------------------

def load_rules(path: str = DEFAULT_RULES_PATH) -> list:
    """加载规则库。返回规则字典列表。"""
    data = _load_yaml(path)
    if not isinstance(data, list):
        raise ValueError("规则文件格式错误: 顶层应为列表")
    rules = []
    for r in data:
        if not isinstance(r, dict) or "id" not in r:
            continue
        kw = r.get("keywords") or {}
        r["_any"] = [str(x).lower() for x in (kw.get("any") or []) if x]
        r["_all"] = [str(x).lower() for x in (kw.get("all") or []) if x]
        rules.append(r)
    return rules


def _match_one(text_lc: str, rule: dict) -> dict | None:
    any_kw, all_kw = rule.get("_any") or [], rule.get("_all") or []
    hits = [k for k in any_kw if k in text_lc]
    if all_kw and not all(k in text_lc for k in all_kw):
        return None
    if not hits:
        return None
    sev = str(rule.get("severity", "low")).lower()
    score = _SEVERITY_BASE.get(sev, 8) + min(len(hits), 6) * 5
    score = min(score, 100)
    return {
        "rule_id": rule.get("id"),
        "name": rule.get("name"),
        "severity": sev,
        "attack": rule.get("attack") or {},
        "score": score,
        "matched_keywords": hits,
        "false_positive_hints": rule.get("false_positive_hints") or [],
        "next_steps": rule.get("next_steps") or [],
    }


def triage(alert: str, rules: list | None = None, top_k: int = 3,
           rules_path: str = DEFAULT_RULES_PATH) -> dict:
    """对一条告警文本做本地规则研判。

    返回结构中 ``human_review_required`` 恒为 True、``auto_action_allowed`` 恒为
    False —— 这是硬编码的, 不随调用方式改变。
    """
    if rules is None:
        rules = load_rules(rules_path)

    result: dict = {
        "ok": True,
        "engine": "local-rules",
        "rules_version": RULES_VERSION,
        "rules_loaded": len(rules),
        "input_length": len(alert or ""),
        "matched": [],
        "top_rule": None,
        "confidence": "none",
        "summary": "未命中任何规则, 需人工研判。",
        "human_review_required": True,
        "auto_action_allowed": False,
        "note": "本结果为规则初筛, 仅供参考; 处置动作必须经人工确认后执行。",
    }

    if not alert or not alert.strip():
        result["ok"] = False
        result["summary"] = "输入为空"
        return result
    if len(alert) > 20000:
        result["ok"] = False
        result["summary"] = "输入超过 20000 字符, 已拒绝(防止资源滥用)"
        return result

    text_lc = alert.lower()
    matched = [m for m in (_match_one(text_lc, r) for r in rules) if m]
    matched.sort(key=lambda x: -x["score"])
    top = matched[: max(1, min(int(top_k), 10))]

    result["matched"] = top
    if top:
        result["top_rule"] = top[0]
        s = top[0]["score"]
        result["confidence"] = "high" if s >= 70 else ("medium" if s >= 40 else "low")
        tech = (top[0].get("attack") or {}).get("technique", "-")
        result["summary"] = (
            "命中 %d 条规则, 最高置信: %s(%s, %s, ATT&CK %s)。该结论需人工确认。"
            % (len(matched), top[0]["name"], top[0]["severity"],
               result["confidence"], tech)
        )
    return result
