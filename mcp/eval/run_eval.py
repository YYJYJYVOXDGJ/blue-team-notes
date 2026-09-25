# -*- coding: utf-8 -*-
"""效果评估：用带标注的样本量化规则库的命中率与误报率。

为什么需要这个：
    规则库写完之后，"准不准"不能靠感觉。做法是准备一批**带标注的样本**
    （每份样本标明：应该命中哪些规则、不应该命中哪些），跑一遍流水线，
    统计召回率 / 精确率 / 误报，改规则后再跑一遍，看指标是变好还是变坏。
    这就是「效果优化」的可复现形式，而不是改完规则凭印象说"应该更准了"。

用法：
    python eval/run_eval.py                 # 跑全部样本
    python eval/run_eval.py --sample windows-demo
    python eval/run_eval.py --verbose       # 打印每条命中的明细
    python eval/run_eval.py --json out.json # 结果落盘

零第三方依赖。
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_MCP = os.path.dirname(_HERE)
if _MCP not in sys.path:
    sys.path.insert(0, _MCP)

from irflow import run_pipeline                     # noqa: E402
from irflow.report import render_markdown, render_text_summary   # noqa: E402


def _force_utf8() -> None:
    """Windows 控制台默认 GBK，中文输出会炸。统一改 UTF-8。"""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def load_labels(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def matched_rule_ids(result) -> set:
    """从流水线结果里抽出命中的全部规则 ID。"""
    ids = set()
    for finding in result.findings:
        for r in finding.get("all_rules") or []:
            rid = r.get("rule_id")
            if rid:
                ids.add(rid)
        top = finding.get("top_rule") or {}
        if top.get("rule_id"):
            ids.add(top["rule_id"])
    return ids


def evaluate_sample(name: str, spec: dict, samples_dir: str, verbose: bool = False) -> dict:
    root = os.path.join(samples_dir, name)
    expected = set(spec.get("expected_rules") or [])
    forbidden = set(spec.get("must_not_match") or [])

    t0 = time.perf_counter()
    result = run_pipeline(root)
    elapsed = (time.perf_counter() - t0) * 1000.0

    if not result.ok:
        return {
            "sample": name,
            "ok": False,
            "error": result.error,
            "expected": sorted(expected),
            "hit": [],
            "missed": sorted(expected),
            "false_positive": [],
            "precision": 0.0,
            "recall": 0.0,
            "elapsed_ms": round(elapsed, 1),
        }

    hit = matched_rule_ids(result)
    hit_expected = hit & expected
    missed = expected - hit
    false_positive = (hit - expected) | (hit & forbidden)

    precision = (len(hit_expected) / len(hit)) if hit else 0.0
    recall = (len(hit_expected) / len(expected)) if expected else 1.0

    detail = []
    if verbose:
        for f in result.findings:
            rec = f.get("record") or {}
            fields = rec.get("fields") or {}
            top = f.get("top_rule") or {}
            detail.append({
                "rule": top.get("rule_id"),
                "severity": f.get("severity"),
                "kind": rec.get("kind"),
                "source": rec.get("source"),
                "key": (fields.get("name") or fields.get("detail")
                        or fields.get("display") or "")[:120],
            })

    return {
        "sample": name,
        "ok": True,
        "description": spec.get("description", ""),
        "adapter": result.adapter,
        "probe_score": result.probe_score,
        "records": result.collection.total_records if result.collection else 0,
        "findings": len(result.findings),
        "detail": detail,
        "expected": sorted(expected),
        "hit": sorted(hit_expected),
        "missed": sorted(missed),
        "false_positive": sorted(false_positive),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "elapsed_ms": round(elapsed, 1),
        "stats": result.stats,
    }


def main() -> int:
    _force_utf8()
    parser = argparse.ArgumentParser(description="规则库效果评估")
    parser.add_argument("--sample", help="只跑指定样本")
    parser.add_argument("--verbose", action="store_true", help="打印命中明细")
    parser.add_argument("--json", help="结果落盘路径")
    parser.add_argument("--md", help="渲染某一份样本的完整报告到文件")
    args = parser.parse_args()

    labels_path = os.path.join(_HERE, "labels.json")
    samples_dir = os.path.join(_HERE, "samples")
    raw_labels = load_labels(labels_path)
    # 下划线开头的键是说明性元数据，不是样本
    labels = {k: v for k, v in raw_labels.items()
              if not k.startswith("_") and isinstance(v, dict)}

    names = [args.sample] if args.sample else sorted(labels.keys())
    results = []
    for name in names:
        if name not in labels:
            print("未知样本: {0}".format(name))
            continue
        results.append(evaluate_sample(name, labels[name], samples_dir, args.verbose))

    print("=" * 66)
    print(" 规则库效果评估")
    print("=" * 66)
    print("")

    total_exp = total_hit = total_pred = total_fp = 0
    for r in results:
        print("样本: {0}".format(r["sample"]))
        if r.get("description"):
            print("  说明    : {0}".format(r["description"]))
        if not r["ok"]:
            print("  ✗ 解析失败: {0}".format(r["error"]))
            print("")
            continue
        print("  适配器  : {0} (置信度 {1})".format(r["adapter"], r["probe_score"]))
        print("  归一化  : {0} 条记录 → {1} 条线索".format(r["records"], r["findings"]))
        print("  召回率  : {0:.1%}  ({1}/{2})".format(
            r["recall"], len(r["hit"]), len(r["expected"])))
        print("  精确率  : {0:.1%}".format(r["precision"]))
        if r["missed"]:
            print("  漏报    : {0}".format(", ".join(r["missed"])))
        if r["false_positive"]:
            print("  意外命中: {0}".format(", ".join(r["false_positive"])))
        print("  耗时    : {0} ms".format(r["elapsed_ms"]))
        if args.verbose:
            print("  命中规则: {0}".format(", ".join(r["hit"]) or "(无)"))
            print("  线索明细:")
            for d in r.get("detail") or []:
                print("    - [{0}] {1}  <{2}>  {3}".format(
                    d.get("rule"), d.get("kind"), d.get("source"), d.get("key")))
        print("")

        total_exp += len(r["expected"])
        total_hit += len(r["hit"])
        total_pred += len(r["hit"]) + len(r["false_positive"])
        total_fp += len(r["false_positive"])

    if total_exp:
        micro_recall = total_hit / total_exp
        micro_precision = (total_hit / total_pred) if total_pred else 0.0
        print("-" * 66)
        print(" 汇总: 召回 {0:.1%}  精确 {1:.1%}  误报 {2} 项".format(
            micro_recall, micro_precision, total_fp))
        print("-" * 66)

    if args.md:
        target = names[0] if names else None
        if target:
            res = run_pipeline(os.path.join(samples_dir, target))
            with open(args.md, "w", encoding="utf-8") as f:
                f.write(render_markdown(res, verbose=False))
            print("\n报告已写入: {0}".format(args.md))

    if args.json:
        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "samples": results,
            "summary": {
                "expected_total": total_exp,
                "hit_total": total_hit,
                "false_positive_total": total_fp,
                "micro_recall": round(total_hit / total_exp, 4) if total_exp else 0.0,
                "micro_precision": round(total_hit / total_pred, 4) if total_pred else 0.0,
            },
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print("结果已写入: {0}".format(args.json))

    # 有漏报即视为需要关注（返回非零便于 CI 使用）
    return 0 if all(r.get("recall", 0) >= 0.5 for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
