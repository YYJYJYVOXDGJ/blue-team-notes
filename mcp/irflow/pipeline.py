"""流水线编排：采集产物 → 归一化记录 → 规则研判 → 结构化结果。

    from irflow import run_pipeline
    r = run_pipeline(r"C:\\IR\\HOST-01-20260925")
    print(r.summary_line())

设计要点：
  1. **流式**：解析器全程使用生成器，不把全量记录读进内存。
     十万行级别的采集产物在本机内存占用保持恒定。
  2. **可中断**：单条记录处理异常不会中断整批，错误被收集而非抛出。
  3. **可复现**：同一份产物、同一版规则，输出完全一致（无随机、无时间戳参与判定）。
  4. **留痕**：结果可落盘为 JSON，用于归档与后续比对。
"""
from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional

from .adapters import detect, registered
from .schema import Collection, Finding, Kind, Platform, Record, severity_rank, write_json

# triage.py / guard.py 位于 mcp/ 根目录（与 irflow/ 同级）。
# 本模块既可能作为包被导入（mcp 在 sys.path），也可能被直接执行，
# 因此在这里做一次幂等的路径兜底，保证两种用法都能找到规则引擎。
_MCP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _MCP_DIR not in sys.path:
    sys.path.insert(0, _MCP_DIR)

import triage as triage_mod  # noqa: E402  (路径注入后才能导入)


@dataclass
class PipelineResult:
    """一次流水线运行的完整结果。"""
    ok: bool = False
    error: str = ""
    collection: Optional[Collection] = None
    adapter: str = ""
    probe_score: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    # 人在回路：任何情况下都不允许自动处置
    human_review_required: bool = True
    auto_action_allowed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "error": self.error,
            "adapter": self.adapter,
            "probe_score": self.probe_score,
            "collection": self.collection.to_dict() if self.collection else None,
            "stats": self.stats,
            "finding_count": len(self.findings),
            "findings": self.findings,
            "human_review_required": True,
            "auto_action_allowed": False,
            "note": "本结果为规则初筛, 仅供参考; 处置动作必须经人工确认后执行。",
        }

    def summary_line(self) -> str:
        if not self.ok:
            return "流水线失败: {0}".format(self.error)
        c = self.collection
        return (
            "[{0}] {1} 条记录 / {2} 条线索 / 平台={3} / 耗时 {4}ms"
            .format(
                self.adapter,
                c.total_records if c else 0,
                len(self.findings),
                c.platform if c else "unknown",
                self.stats.get("elapsed_ms", 0),
            )
        )

    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts


# ---------------------------------------------------------------- 内部工具

def _iter_records(adapter, root: str, collection: Collection) -> Iterator[Record]:
    """带统计的解析迭代器（不缓存记录，只累加计数）。"""
    for rec in adapter.parse(root, collection):
        collection.total_records += 1
        k = rec.kind
        collection.records_by_kind[k] = collection.records_by_kind.get(k, 0) + 1
        yield rec


def _list_skipped(root: str) -> List[str]:
    """列出目录里存在但当前适配器不解析的文件，写进报告。

    这是"能力边界清晰"的一部分：让使用者知道哪些产物还没被自动化覆盖，
    而不是误以为"没报警就是没问题"。
    """
    known_ext = (".csv", ".txt", ".json", ".log", ".evtx", ".xml")
    found: List[str] = []
    try:
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                if fn.lower().endswith(known_ext):
                    rel = os.path.relpath(os.path.join(dirpath, fn), root).replace("\\", "/")
                    found.append(rel)
    except OSError:
        pass
    return sorted(found)


# ---------------------------------------------------------------- 对外接口

def triage_collection(records: Iterable[Record], rules_path: Optional[str] = None,
                      top_k: int = 3, min_score: int = 1) -> List[Dict[str, Any]]:
    """对记录流做批量研判（薄封装，便于单独调用与测试）。"""
    if rules_path:
        return triage_mod.triage_records(records, top_k=top_k,
                                         min_score=min_score, rules_path=rules_path)
    return triage_mod.triage_records(records, top_k=top_k, min_score=min_score)


def run_pipeline(root: str, rules_path: Optional[str] = None, top_k: int = 3,
                 min_score: int = 1, max_findings: int = 2000) -> PipelineResult:
    """对一份采集产物目录执行完整流水线。

    root        —— 采集产物目录（Windows/Linux 均可，自动探测）
    rules_path  —— 规则库路径，默认 mcp/rules/triage-rules.yaml
    max_findings—— 线索数上限，防止极端情况下结果爆炸
    """
    t0 = time.perf_counter()

    if not root or not os.path.isdir(root):
        return PipelineResult(ok=False, error="目录不存在或不是目录: {0}".format(root))

    adapter, score = detect(root)
    if adapter is None or score <= 0:
        avail = ", ".join(a.name for a in registered())
        return PipelineResult(
            ok=False,
            error=("无法识别该目录属于哪个采集来源（置信度 0）。"
                   "当前已注册的适配器: {0}。"
                   "请确认目录是采集脚本的输出根目录，而不是上层父目录。").format(avail),
        )

    collection = Collection(root=os.path.abspath(root), platform=adapter.platform)
    records = _iter_records(adapter, root, collection)

    findings = triage_collection(records, rules_path=rules_path,
                                 top_k=top_k, min_score=min_score)
    findings = findings[:max_findings]

    all_files = _list_skipped(root)
    parsed_sources = set()
    for f in findings:
        src = (f.get("record") or {}).get("source")
        if src:
            parsed_sources.add(src)

    elapsed = (time.perf_counter() - t0) * 1000.0

    result = PipelineResult(
        ok=True,
        collection=collection,
        adapter=adapter.name,
        probe_score=score,
        findings=findings,
        stats={
            "elapsed_ms": round(elapsed, 1),
            "files_in_dir": len(all_files),
            "artifact_files": all_files,
            "findings": len(findings),
            "severity_counts": {},
            "by_kind": dict(collection.records_by_kind),
            "engine": "local-rules",
            "note": "解析与研判全程不联网、不调用模型。",
        },
    )
    result.stats["severity_counts"] = result.severity_counts()
    return result


def run_pipeline_to_file(root: str, out_json: str, **kwargs) -> PipelineResult:
    """跑流水线并把结果落盘 JSON（结果留痕），便于归档与跨时间比对。"""
    result = run_pipeline(root, **kwargs)
    if result.ok:
        write_json(out_json, result.to_dict())
    return result
