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
import re
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


def _split_kv(content: str):
    """在「引号之外」的第一个冒号处切分 key / value。

    必须跳过引号内的冒号，否则 'C:\\Windows\\' 这类 Windows 路径
    会被误判成 "key: value"（key='C、value=\\Windows\\'）。
    这是离线兜底解析器最容易踩的坑，PyYAML 本身不会犯，
    所以这里对齐 PyYAML 的行为，保证两种解析路径结果一致。
    """
    in_single = False
    in_double = False
    for i, ch in enumerate(content):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ":" and not in_single and not in_double:
            return content[:i], content[i + 1:]
    return None


def _parse_dict(rows: list, pos: list, indent: int) -> dict:
    out: dict = {}
    while pos[0] < len(rows):
        ind, content = rows[pos[0]]
        if ind != indent or content.startswith("- "):
            break
        kv = _split_kv(content)
        if kv is None:
            pos[0] += 1
            continue
        key, val = kv[0].strip(), kv[1].strip()
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
        kv = _split_kv(item)
        if kv is not None:                     # "- id: MINING-001" → 字典项
            sub = [(ind + 2, item)]
            pos[0] += 1
            while pos[0] < len(rows) and rows[pos[0]][0] > ind:
                sub.append(rows[pos[0]])
                pos[0] += 1
            out.append(_parse_dict(sub, [0], ind + 2))
        else:                                  # "- 'C:\\Windows\\'" → 标量项
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
    """加载规则库。返回规则字典列表。

    每条规则会被编译出三个内部字段（下划线开头，不参与序列化输出）：
        _any / _all  —— 关键词匹配（面向纯文本告警，v0.1 起的原有能力）
        _match       —— 结构化谓词（面向采集产物的字段，v0.2 新增）

    两类条件同时存在时**必须都满足**，便于写出「机制是计划任务 且 命令行含编码
    PowerShell」这种精确规则，而不是靠关键词堆叠碰运气。
    """
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
        r["_match"] = _compile_match(r.get("match"))
        # 规则作用域：
        #   both（默认）—— 文本告警与采集产物两条入口都适用
        #   alert       —— 只用于文本告警。这类规则靠宽泛关键词匹配，套到结构化产物上
        #                 噪声很大（正常 cron 行、正常服务名都可能撞上），必须排除
        #   record      —— 只用于采集产物
        r["_scope"] = str(r.get("scope") or "both").strip().lower()
        rules.append(r)
    return rules


# --------------------------------------------------------------------------
# 结构化谓词（v0.2 新增）——让规则能匹配采集产物的字段，而不只是文本
# --------------------------------------------------------------------------

# 支持的比较算子。命名与直觉一致，写规则时不需要记忆额外语法。
_OPERATORS = (
    "equals", "not_equals",
    "in", "not_in",
    "contains", "not_contains",
    "startswith", "not_startswith",
    "endswith", "not_endswith",
    "regex", "not_regex",
    "exists", "not_exists",
    "gt", "lt",
)


def _compile_match(match: Any) -> dict | None:
    """把规则里的 match 段编译成可执行谓词结构。

    支持两种形态：
        match:
          kind: persistence          # 直接限定，等价于 kind 谓词
          platform: windows
          all: [...]                 # 全部满足
          any: [...]                 # 至少一个满足
    """
    if not isinstance(match, dict):
        return None

    compiled: dict = {
        "kind": match.get("kind"),
        "platform": match.get("platform"),
        "all": [],
        "any": [],
    }

    def _norm(entry: Any) -> dict | None:
        if not isinstance(entry, dict):
            return None
        field = entry.get("field")
        if not field:
            return None
        ops = {k: v for k, v in entry.items() if k in _OPERATORS}
        if not ops:
            return None
        return {"field": str(field), "ops": ops}

    for group in ("all", "any"):
        raw = match.get(group) or []
        if isinstance(raw, dict):
            raw = [raw]
        for entry in raw:
            n = _norm(entry)
            if n:
                compiled[group].append(n)

    if not (compiled["kind"] or compiled["platform"] or compiled["all"] or compiled["any"]):
        return None
    return compiled


def _as_bool_str(v: Any) -> str:
    """把 PowerShell 导出的布尔值统一成小写字符串，便于规则书写。

    PowerShell 的 Boolean 经 Export-Csv 会是 True/False，
    而某些来源是 true/false 或 1/0，这里统一成 "true"/"false"/"1"/"0"。
    """
    s = str(v).strip().lower()
    if s in ("true", "yes", "1"):
        return "true"
    if s in ("false", "no", "0"):
        return "false"
    return s


def _op_holds(value: Any, op: str, expected: Any) -> bool:
    """判定单个算子是否成立。value 来自记录字段，expected 来自规则。"""
    v = "" if value is None else str(value)
    v_lc = _as_bool_str(v)
    v_low = v.lower()

    if op == "exists":
        return bool(v) is bool(expected)
    if op == "not_exists":
        return (not bool(v)) is bool(expected)

    if not v:
        # 字段缺失时，否定类算子视为成立（"没有这个痕迹"也是一种结论），
        # 但肯定类算子一律不成立，避免用缺失字段把规则误命中。
        return op.startswith("not_")

    exp_list = expected if isinstance(expected, list) else [expected]

    def _norm_list(items):
        return [str(x).lower() for x in items]

    if op == "equals":
        return v_lc == _as_bool_str(expected) or v_low == str(expected).lower()
    if op == "not_equals":
        return not (v_lc == _as_bool_str(expected) or v_low == str(expected).lower())
    if op == "in":
        return v_low in _norm_list(exp_list)
    if op == "not_in":
        return v_low not in _norm_list(exp_list)
    if op == "contains":
        return any(str(x).lower() in v_low for x in exp_list)
    if op == "not_contains":
        return not any(str(x).lower() in v_low for x in exp_list)
    if op == "startswith":
        return any(v_low.startswith(str(x).lower()) for x in exp_list)
    if op == "not_startswith":
        return not any(v_low.startswith(str(x).lower()) for x in exp_list)
    if op == "endswith":
        return any(v_low.endswith(str(x).lower()) for x in exp_list)
    if op == "not_endswith":
        return not any(v_low.endswith(str(x).lower()) for x in exp_list)
    if op == "regex":
        try:
            return re.search(str(expected), v, re.IGNORECASE) is not None
        except re.error:
            return False
    if op == "not_regex":
        try:
            return re.search(str(expected), v, re.IGNORECASE) is None
        except re.error:
            return True
    if op == "gt":
        try:
            return float(v) > float(expected)
        except (TypeError, ValueError):
            return False
    if op == "lt":
        try:
            return float(v) < float(expected)
        except (TypeError, ValueError):
            return False
    return False


def match_predicates(record: Any, compiled: dict) -> tuple:
    """对一条记录执行结构化谓词匹配。

    返回 (是否命中, 命中的谓词描述列表)。描述会进入报告，便于人工复核
    「为什么这条被标可疑」。
    """
    if not compiled:
        return False, []

    fields = getattr(record, "fields", None)
    kind = getattr(record, "kind", None)
    platform = getattr(record, "platform", None)
    if fields is None:
        return False, []

    evidence: list = []

    if compiled.get("kind"):
        if str(kind or "").lower() != str(compiled["kind"]).lower():
            return False, []
    if compiled.get("platform"):
        if str(platform or "").lower() != str(compiled["platform"]).lower():
            return False, []

    for entry in compiled.get("all", []):
        field = entry["field"]
        value = fields.get(field, "")
        for op, expected in entry["ops"].items():
            if not _op_holds(value, op, expected):
                return False, []
            evidence.append("{0} {1} {2}".format(field, op, expected))

    if compiled.get("any"):
        any_hit = False
        any_evidence: list = []
        for entry in compiled["any"]:
            field = entry["field"]
            value = fields.get(field, "")
            ok = True
            local_ev: list = []
            for op, expected in entry["ops"].items():
                if not _op_holds(value, op, expected):
                    ok = False
                    break
                local_ev.append("{0} {1} {2}".format(field, op, expected))
            if ok:
                any_hit = True
                any_evidence.extend(local_ev)
        if not any_hit:
            return False, []
        evidence.extend(any_evidence)

    return True, evidence


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
    eligible = [r for r in rules if r.get("_scope", "both") != "record"]
    matched = [m for m in (_match_one(text_lc, r) for r in eligible) if m]
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


# --------------------------------------------------------------------------
# 结构化记录研判（v0.2 新增）
# 让规则引擎直接消费「采集产物归一化后的记录」，
# 而不需要先把记录人工拼成一段文本再喂进来。
# --------------------------------------------------------------------------

def triage_record(record: Any, rules: list | None = None, top_k: int = 3,
                  rules_path: str = DEFAULT_RULES_PATH) -> dict:
    """对一条归一化记录（irflow.schema.Record）做研判。

    双通道匹配：
        结构化通道 —— 规则里的 match 段，直接比字段，精确且不易误报
        文本通道   —— 规则里的 keywords 段，匹配原始行，兜住非结构化残留

    两条通道都写的规则，要求同时成立。
    """
    if rules is None:
        rules = load_rules(rules_path)

    text = ""
    if hasattr(record, "text_for_rules"):
        text = record.text_for_rules() or ""
    elif isinstance(record, dict):
        text = " ".join(str(v) for v in record.values() if v)
    else:
        text = str(record)
    text_lc = text.lower()

    matched: list = []
    for rule in rules:
        # 作用域过滤：仅面向文本告警的规则不参与采集产物研判
        if rule.get("_scope", "both") == "alert":
            continue

        compiled = rule.get("_match")

        pred_ok, pred_evidence = (True, [])
        if compiled:
            pred_ok, pred_evidence = match_predicates(record, compiled)
            if not pred_ok:
                continue

        kw_hit = _match_one(text_lc, rule)
        if compiled and not kw_hit:
            # 只有结构化条件，命中即可
            if not (rule.get("_any") or rule.get("_all")):
                sev = str(rule.get("severity", "low")).lower()
                kw_hit = {
                    "rule_id": rule.get("id"),
                    "name": rule.get("name"),
                    "severity": sev,
                    "attack": rule.get("attack") or {},
                    "score": _SEVERITY_BASE.get(sev, 8) + 5 * min(len(pred_evidence), 4),
                    "matched_keywords": [],
                    "false_positive_hints": rule.get("false_positive_hints") or [],
                    "next_steps": rule.get("next_steps") or [],
                }

        if not kw_hit:
            continue

        kw_hit["matched_predicates"] = pred_evidence
        matched.append(kw_hit)

    matched.sort(key=lambda x: -x["score"])
    top = matched[: max(1, min(int(top_k), 10))]

    out: dict = {
        "ok": True,
        "engine": "local-rules",
        "rules_version": RULES_VERSION,
        "rules_loaded": len(rules),
        "input_length": len(text),
        "matched": top,
        "top_rule": top[0] if top else None,
        "confidence": "none",
        "summary": "未命中任何规则, 不构成可疑线索。",
        "human_review_required": True,
        "auto_action_allowed": False,
        "note": "本结果为规则初筛, 仅供参考; 处置动作必须经人工确认后执行。",
    }

    if top:
        s = top[0]["score"]
        out["confidence"] = "high" if s >= 70 else ("medium" if s >= 40 else "low")
        tech = (top[0].get("attack") or {}).get("technique", "-")
        out["summary"] = (
            "命中 %d 条规则, 最高置信: %s(%s, %s, ATT&CK %s)。该结论需人工确认。"
            % (len(matched), top[0]["name"], top[0]["severity"],
               out["confidence"], tech)
        )
    return out


def triage_records(records, rules: list | None = None, top_k: int = 3,
                   rules_path: str = DEFAULT_RULES_PATH, min_score: int = 1) -> list:
    """批量研判记录流，返回命中列表。

    入参 records 可以是任意可迭代对象（含生成器），本函数逐条处理、
    不把全量记录读进内存 —— 这是能处理几十万行采集产物的前提。
    """
    if rules is None:
        rules = load_rules(rules_path)

    hits: list = []
    for rec in records:
        try:
            res = triage_record(rec, rules=rules, top_k=top_k)
        except Exception as exc:            # 单条异常不应中断整批
            hits.append({
                "ok": False,
                "error": str(exc),
                "record": rec.to_dict() if hasattr(rec, "to_dict") else str(rec),
                "human_review_required": True,
                "auto_action_allowed": False,
            })
            continue
        if res.get("top_rule") and res["top_rule"]["score"] >= min_score:
            hits.append({
                "ok": True,
                "record": rec.to_dict() if hasattr(rec, "to_dict") else str(rec),
                "severity": res["top_rule"]["severity"],
                "score": res["top_rule"]["score"],
                "confidence": res["confidence"],
                "summary": res["summary"],
                "top_rule": res["top_rule"],
                "all_rules": res["matched"],
                "human_review_required": True,
                "auto_action_allowed": False,
            })
    hits.sort(key=lambda x: -x.get("score", 0))
    return hits
