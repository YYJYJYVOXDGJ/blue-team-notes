"""irflow —— 主机应急响应数据处理流水线。

把「采集 → 解析 → 归一化 → 研判 → 报告」串成一条可复用的链路。

    from irflow import run_pipeline
    result = run_pipeline("C:/IR/HOST-01-20260925")

设计原则：
  1. 采集侧不动（脚本保持只读、离线可用）
  2. 解析侧适配（异构来源统一成一套 schema）
  3. 研判侧确定（规则匹配，不调模型）
  4. 结论侧留痕（每次运行产出 JSON + Markdown，可归档比对）

零第三方依赖。
"""
from __future__ import annotations

from .schema import Collection, Finding, Kind, Platform, Record, dumps, severity_rank, write_json
from .pipeline import PipelineResult, run_pipeline, triage_collection
from .report import render_markdown, render_text_summary

__version__ = "0.1.0"

__all__ = [
    "Collection", "Finding", "Kind", "Platform", "Record",
    "dumps", "severity_rank", "write_json",
    "PipelineResult", "run_pipeline", "triage_collection",
    "render_markdown", "render_text_summary",
    "__version__",
]
