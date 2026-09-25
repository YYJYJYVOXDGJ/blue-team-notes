#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
敏感信息自查脚本（仓库提交前门禁）

用途：扫描仓库内的 Markdown / 脚本文件，找出可能泄露涉事主机、人员或组织的信息。
本仓库是公开仓库，任何案例与文档在入库前应跑一遍本脚本。

用法：
    python scripts/check-sensitive.py                 # 扫描整个仓库
    python scripts/check-sensitive.py ir/cases/       # 只扫指定目录

退出码：0 = 未发现；1 = 发现待确认项

说明：
- 部分命中是**文档保留地址**（RFC 5737：192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）
  与示例域名（RFC 2606：example.com/.local），脚本会自动识别并降为 INFO。
- 脚本只做模式匹配，不替代人工判断。拿不准就删。
"""

from __future__ import annotations

import os
import re
import sys

# ---------------------------------------------------------------- 规则定义
# (规则名, 正则, 严重级别, 说明)
RULES = [
    ("内网IPv4-私有段", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                        r"|192\.168\.\d{1,3}\.\d{1,3}"
                        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
     "WARN", "RFC1918 私有地址：作通用示例无害，需确认不是真实内网地址"),
    ("公网IPv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
     "WARN", "公网地址，需确认是否为涉事资产"),
    ("用户名路径", r"[A-Za-z]:\\+(?:Users|Documents and Settings)\\+[A-Za-z0-9_.\-]+"
                   r"|/(?:home|Users)/[a-z][a-z0-9_.\-]{2,}",
     "ERROR", "含具体用户名，应泛化为 <用户>"),
    ("Windows主机名", r"\bWIN(?:-[A-Z0-9]{4,}|DOWS-[A-Z0-9]+)\b",
     "ERROR", "主机名应泛化为 HOST-A 之类"),
    ("邮箱地址", r"\b[\w.\-]+@[\w\-]+\.(?:com|cn|net|org|edu|local|gov)\b",
     "ERROR", "真实邮箱必须删除"),
    ("手机号", r"\b1[3-9]\d{9}\b",
     "ERROR", "真实手机号必须删除"),
    ("域名-内网", r"\b(?!rc\.)(?:[\w\-]+)\.(?:local|internal|corp|lan)\b",
     "WARN", "内网域名应替换为 example.local"),
    ("SSH公钥", r"\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/]{20,}",
     "ERROR", "真实密钥材料必须删除"),
    ("个人姓名", r"杨竣烨",
     "ERROR", "真实姓名不得出现在公开仓库"),
]

# 豁免：文档保留段与示例域名（RFC 5737 / RFC 2606 / RFC 6761）
EXEMPT_PATTERNS = [
    re.compile(r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b"),
    re.compile(r"\b(?:example|test|invalid|localhost)\b", re.I),
    re.compile(r"\b(?:1\.2\.3\.4|8\.8\.8\.8|114\.114\.114\.114)\b"),   # 惯用示例 DNS/地址
]

# IPv4 中无需告警的地址：回环、链路本地、未指定、广播、组播、私有段、文档段
_IP_SKIP_RE = re.compile(
    r"^(?:"
    r"127\.|0\.|169\.254\.|255\."
    r"|10\."
    r"|192\.168\."
    r"|172\.(?:1[6-9]|2\d|3[01])\."
    r"|192\.0\.2\.|198\.51\.100\.|203\.0\.113\."
    r"|22[4-9]\.|23\d\."          # 组播与保留
    r")"
)


def is_safe_ip(val: str) -> bool:
    """IPv4 是否属于无需告警的保留/私有地址。"""
    return bool(_IP_SKIP_RE.match(val))

# 明显的示例值：命中即不告警（demo / example / test / 中文示例人名 / 系统公共目录等）
EXEMPT_VALUE_RE = re.compile(
    r"(?:demo|example|test|sample|foo|bar|zhangsan|lisi|deploy|public"
    r"|demokey|win-demo|host-a|<用户>|<oem>|<component>)",
    re.I,
)

# 合成测试数据目录：整体不告警（这些是刻意构造的评估样本与示例报告）
EXEMPT_PATH_RE = re.compile(
    r"(?:mcp/eval/samples/|mcp/docs/demo|ir/cases/README\.md)"
)

SKIP_DIRS = {".git", ".github", "node_modules", "__pycache__", ".venv", "venv"}
SKIP_FILES = {"check-sensitive.py"}
SCAN_EXT = {".md", ".py", ".sh", ".ps1", ".yaml", ".yml", ".json", ".txt", ".bat"}


def is_exempt(line: str) -> bool:
    return any(p.search(line) for p in EXEMPT_PATTERNS)


def scan_file(path: str, rel: str) -> list:
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError:
        return []

    hits = []
    for no, line in enumerate(lines, 1):
        stripped = line.strip()
        # 跳过本脚本自身的规则定义与说明行
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for name, pattern, level, note in RULES:
            for m in re.finditer(pattern, line):
                val = m.group(0)
                # IP 类规则：先排除保留/私有地址，剩下的才可能是真实公网资产
                if name.endswith("IPv4") and is_safe_ip(val):
                    continue
                if is_exempt(val) or is_exempt(line):
                    continue
                # 示例值 / 合成测试数据
                if EXEMPT_VALUE_RE.search(val) or EXEMPT_PATH_RE.search(rel):
                    continue
                hits.append((level, rel, no, name, val, note))
    return hits


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    root = os.path.abspath(root)

    all_hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn in SKIP_FILES:
                continue
            if os.path.splitext(fn)[1].lower() not in SCAN_EXT:
                continue
            fp = os.path.join(dirpath, fn)
            rel = os.path.relpath(fp, root).replace("\\", "/")
            all_hits.extend(scan_file(fp, rel))

    errs = [h for h in all_hits if h[0] == "ERROR"]
    warns = [h for h in all_hits if h[0] == "WARN"]

    print("=" * 74)
    print("敏感信息自查 —— 扫描根目录: %s" % root)
    print("=" * 74)

    if not errs and not warns:
        print("\n✓ 未发现敏感信息。\n")
        return 0

    for level, group in (("ERROR", errs), ("WARN", warns)):
        if not group:
            continue
        print("\n【%s】%d 项" % (level, len(group)))
        print("-" * 74)
        for level, rel, no, name, val, note in group[:40]:
            print("  %s:%d  [%s] %s" % (rel, no, name, val[:60]))
            print("         └ %s" % note)
        if len(group) > 40:
            print("  …等共 %d 项" % len(group))

    print("\n" + "=" * 74)
    print("说明：ERROR 必须处理；WARN 需人工确认是否为涉事资产。")
    print("      文档保留段（192.0.2.x / 198.51.100.x / 203.0.113.x）与 example.local 已自动豁免。")
    print("=" * 74 + "\n")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
