# -*- coding: utf-8 -*-
"""一键演示脚本 —— 面试现场用，全程离线、零第三方依赖。

用法：
    python demo.py            # 逐步演示，每步暂停等你讲解（推荐现场用）
    python demo.py --auto     # 一口气跑完，不暂停

为什么单独有这么一个脚本：
    面试官说"你演示一下"的时候，现场敲 python -c "from irflow import ..."
    这种长命令既容易打错、又不好讲。这个脚本把 4 个演示点串成一条线，
    每步先打印"这一步在证明什么"，再打印实际输出，你照着念就行。

演示覆盖的 4 件事：
    [1] 规则引擎     —— 一条告警进来，出规则 + ATT&CK + 误报提示 + 人工验证步骤
    [2] 数据流水线   —— 一整个采集产物目录进来，出按严重度排序的可疑项清单
    [3] 研判报告     —— 生成 Markdown 报告（含"能力边界"专节）
    [4] 效果与性能   —— 召回率/精确率可量化 + 50 万行日志的吞吐与内存

不涉及任何真实数据：样本在 eval/samples/ 下，全部为合成数据。
"""

from __future__ import annotations

import os
import subprocess
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(errors="replace")   # 不强制 UTF-8，避免控制台乱码
    except Exception:
        pass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

AUTO = "--auto" in sys.argv
OUT_DIR = os.path.join(_HERE, "demo-output")


def hr(ch="=", n=74):
    print(ch * n)


def pause(msg="  ▶ 按回车继续下一步 ..."):
    if AUTO:
        return
    try:
        input(msg)
    except (EOFError, KeyboardInterrupt):
        pass


def banner(idx, total, title, proves):
    hr()
    print("  [%d/%d] %s" % (idx, total, title))
    print("  这一步证明：%s" % proves)
    hr()


# --------------------------------------------------------------------------
# 步骤 1：规则引擎
# --------------------------------------------------------------------------
def step1_rules():
    banner(1, 4, "规则引擎：把一条告警变成可执行的分诊结论",
           "输入是自然语言的告警，输出的不是'我猜这是挖矿'，而是带 ATT&CK 编号、"
           "误报提示和人工验证步骤的确定性结论。")

    import triage

    try:
        import yaml  # noqa: F401
        yaml_mode = "PyYAML（已安装）"
    except ImportError:
        yaml_mode = "内置最小解析器（未装 PyYAML，离线兜底生效）"

    print("  规则库     : %s" % os.path.relpath(triage.DEFAULT_RULES_PATH, _HERE))
    print("  引擎版本   : %s" % triage.RULES_VERSION)
    print("  YAML 解析  : %s" % yaml_mode)

    rules = triage.load_rules(triage.DEFAULT_RULES_PATH)
    print("  已加载规则 : %d 条" % len(rules))

    samples = [
        ("挖矿迹象（EDR 告警）",
         "EDR 检测到进程 sysupdate.exe 持续占用 CPU 98%，该进程对外发起 "
         "stratum+tcp 协议连接至 45.xx.xx.xx:3333，进程路径 "
         "C:\\Windows\\Temp\\sysupdate.exe，无有效数字签名。"),
        ("WebShell 访问（WAF 告警）",
         "WAF 拦截到对 /uploads/cmd.aspx 的 POST 请求，请求体含 eval( 与 "
         "base64_decode，响应中包含 whoami 执行结果，来源 IP 位于境外。"),
        ("正常业务日志（预期不命中）",
         "应用服务正常启动，数据库连接池初始化完成，健康检查返回 200。"),
    ]

    for title, text in samples:
        res = triage.triage(text, rules=rules, top_k=3)
        print()
        print("  ┌─ %s" % title)
        print("  │  结论   : %s" % res["summary"])
        print("  │  置信度 : %s" % res["confidence"])
        for m in res["matched"]:
            atk = m.get("attack") or {}
            print("  │  命中   : [%s] %s" % (m["severity"], m["name"]))
            print("  │           ATT&CK %s (%s)" % (atk.get("technique", "-"),
                                                    atk.get("tactic", "-")))
            if m.get("next_steps"):
                print("  │  人工验证: %s" % m["next_steps"][0])
            if m.get("false_positive_hints"):
                print("  │  误报提示: %s" % m["false_positive_hints"][0])
        print("  └─ 安全标记: human_review_required=%s, auto_action_allowed=%s"
              % (res["human_review_required"], res["auto_action_allowed"]))

    print()
    print("  要点：返回值里 human_review_required / auto_action_allowed 是"
          "硬编码的，")
    print("        任何输入都不会变成'可以自动处置'。判定环节不进模型。")


# --------------------------------------------------------------------------
# 步骤 2 & 3：数据流水线 + 报告
# --------------------------------------------------------------------------
def step2_pipeline():
    banner(2, 4, "数据流水线：一整个采集产物目录 → 可疑项清单",
           "真实应急的输入不是手打的文本，而是采集脚本吐出来的几十个异构 "
           "CSV/txt。这一步证明采集与研判之间的断层被接上了。")

    from irflow import run_pipeline
    from irflow.report import render_text_summary

    sample = os.path.join(_HERE, "eval", "samples", "linux-demo")
    print("  样本目录 : %s" % os.path.relpath(sample, _HERE))
    print("  （合成数据，非真实环境）")
    print()

    res = run_pipeline(sample)
    if not res.ok:
        print("  [失败] %s" % res.error)
        return None
    print(render_text_summary(res))

    print("  按种类记录数：")
    for k, v in sorted(res.collection.records_by_kind.items(), key=lambda x: -x[1]):
        print("    %-14s %d" % (k, v))
    print("  命中的规则：")
    seen = set()
    for f in res.findings:
        rid = (f.get("top_rule") or {}).get("rule_id")
        if rid and rid not in seen:
            seen.add(rid)
            print("    - [%s] %s" % (f.get("severity"), rid))
    return res


def step3_report():
    banner(3, 4, "研判报告：把结果变成可以归档、可以复核的文档",
           "报告里专门有一节写明「我没查什么」—— 一份声称全覆盖的应急报告是不可信的。")

    from irflow import run_pipeline, render_markdown

    os.makedirs(OUT_DIR, exist_ok=True)
    for name in ("windows-demo", "linux-demo"):
        sample = os.path.join(_HERE, "eval", "samples", name)
        if not os.path.isdir(sample):
            continue
        res = run_pipeline(sample)
        if not res.ok:
            print("  [跳过] %s: %s" % (name, res.error))
            continue
        out = os.path.join(OUT_DIR, "报告-%s.md" % name)
        with open(out, "w", encoding="utf-8") as f:
            f.write(render_markdown(res))
        print("  已生成: %s  (%d 条线索)" % (os.path.relpath(out, _HERE),
                                            len(res.findings)))

    print()
    print("  现场可打开报告，重点翻到这两节：")
    print("    · 「线索清单」—— 每条线索带来源产物文件名、关键字段、命中规则")
    print("    · 「能力边界」—— 已知盲区 + 本次产物清单，声明我没覆盖什么")


# --------------------------------------------------------------------------
# 步骤 4：效果评估 + 性能基准
# --------------------------------------------------------------------------
def step4_eval_bench():
    banner(4, 4, "效果与性能：规则准不准、能不能扛住大日志",
           "规则写完不能凭感觉说「应该挺准的」。有度量才有优化。")

    def run(rel, title):
        print()
        hr("-")
        print("  ▶ %s" % title)
        hr("-")
        try:
            r = subprocess.run([sys.executable, rel], cwd=_HERE,
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=600)
            out = (r.stdout or "").rstrip()
            print(out if out else "  （无输出，stderr: %s）" % (r.stderr or "")[:300])
        except Exception as e:
            print("  [失败] %s" % e)

    run(os.path.join("eval", "run_eval.py"), "规则库效果评估（召回 / 精确）")
    run(os.path.join("bench", "bench_parse.py"), "流水线性能基准（吞吐 / 内存）")

    print()
    print("  现场一定要补一句：")
    print("    「这两个数字只在合成样本上成立，不能外推到真实环境。")
    print("      它的价值是提供一条可复现的回归基线 —— 改规则跑一遍，")
    print("      指标掉了就说明改坏了。」")


# --------------------------------------------------------------------------
def main():
    print()
    hr()
    print("  blue-team-notes  ·  现场演示（全程离线，不装任何包）")
    print("  仓库：github.com/YYJYJYVOXDGJ/blue-team-notes")
    hr()
    print("  说明：本演示不联网、不调用任何大模型、不接触任何真实数据。")
    print("        4 步之间会暂停，方便你讲解；想一口气跑完用 --auto。")
    pause()

    step1_rules();     pause()
    step2_pipeline();  pause()
    step3_report();    pause()
    step4_eval_bench()

    print()
    hr()
    print("  演示结束。")
    print("  收口话术：现在的状态是最小可用版 —— 规则是关键词 + 字段匹配的初筛器，")
    print("            不是检测引擎，不解决免杀绕过和未知攻击。")
    print("            下一步是接入真实日志源，并把人工研判结论回流做效果闭环。")
    hr()
    if not AUTO:
        pause("  ▶ 按回车退出 ...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
