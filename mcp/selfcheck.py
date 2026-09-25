# -*- coding: utf-8 -*-
"""零依赖自检脚本 —— 不安装 mcp / pyyaml 也能验证规则引擎可用。

用法：
    python selfcheck.py

作用：
    1. 验证规则文件能被正确解析（YAML 解析器兜底逻辑是否生效）
    2. 用 4 条示例告警跑一遍研判，肉眼确认结果合理
    3. 确认"人在回路"标记确实恒为 True

跑通这个脚本，说明核心能力是好的；剩下的只是 MCP 协议那一层包装。
"""

from __future__ import annotations

import json
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    # 不强制 UTF-8：Windows 控制台默认 GBK，强转会导致中文乱码。
    # 只把错误处理设为 replace，避免在窄编码环境下抛异常中断输出。
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import triage  # noqa: E402

SAMPLES = [
    (
        "挖矿迹象（EDR 告警）",
        "EDR 检测到进程 sysupdate.exe 持续占用 CPU 98%，"
        "该进程对外发起 stratum+tcp 协议连接至 45.xx.xx.xx:3333，"
        "进程路径 C:\\Windows\\Temp\\sysupdate.exe，无有效数字签名。",
    ),
    (
        "WebShell 访问（WAF 告警）",
        "WAF 拦截到对 /uploads/cmd.aspx 的 POST 请求，请求体含 eval( 与 base64_decode，"
        "响应中包含 whoami 执行结果，来源 IP 位于境外。",
    ),
    (
        "可疑计划任务（Sysmon 告警）",
        "检测到 schtasks /create 创建计划任务 OfficeUpdate，"
        "ImagePath 指向 C:\\Users\\Public\\update.exe，创建者账号为普通域用户，"
        "同时间段该主机有大量 4625 登录失败记录。",
    ),
    (
        "正常业务日志（预期不命中）",
        "应用服务正常启动，数据库连接池初始化完成，健康检查返回 200。",
    ),
]


def show(title: str, text: str, rules: list) -> None:
    res = triage.triage(text, rules=rules, top_k=3)
    print("=" * 72)
    print("【%s】" % title)
    print("  输入: %s..." % text[:56])
    print("  结论: %s" % res["summary"])
    print("  置信度: %s" % res["confidence"])
    for m in res["matched"]:
        atk = m.get("attack") or {}
        print("    - [%s] %s | ATT&CK %s (%s) | 命中: %s"
              % (m["severity"], m["name"], atk.get("technique", "-"),
                 atk.get("tactic", "-"), "、".join(m["matched_keywords"][:4])))
        if m["next_steps"]:
            print("        建议人工验证: %s" % m["next_steps"][0])
    print("  安全标记: human_review_required=%s, auto_action_allowed=%s"
          % (res["human_review_required"], res["auto_action_allowed"]))


def main() -> int:
    path = triage.DEFAULT_RULES_PATH
    print("blue-team-notes MCP —— 本地规则引擎自检")
    print("规则文件: %s" % path)
    print("引擎版本: %s" % triage.RULES_VERSION)

    try:
        import yaml  # noqa: F401
        print("YAML 解析: PyYAML（已安装）")
    except ImportError:
        print("YAML 解析: 内置最小解析器（未安装 PyYAML，离线兜底生效）")

    try:
        rules = triage.load_rules(path)
    except Exception as e:
        print("加载规则失败: %s" % e)
        return 1

    print("已加载规则: %d 条\n" % len(rules))

    for title, text in SAMPLES:
        show(title, text, rules)

    print("\n" + "=" * 72)
    ok = all(
        triage.triage(t, rules=rules)["human_review_required"] is True
        and triage.triage(t, rules=rules)["auto_action_allowed"] is False
        for _, t in SAMPLES
    )
    print("安全底线校验（人在回路标记恒定）: %s" % ("通过" if ok else "失败"))
    print("结论: 规则引擎工作正常。安装 mcp 包后即可通过 MCP 协议对外提供能力。")
    print("      pip install \"mcp[cli]\"  →  python server.py")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
