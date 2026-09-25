"""统一数据模型（Normalized Schema）。

设计目标：把 Windows / Linux 两个平台、CSV / 纯文本两种格式的采集产物，
归一化成同一套字段，使得下游的规则研判、报告生成、效果评估都不用关心来源差异。

这是本流水线的"数据打通"层——对应岗位要求中的
「异构系统接入、接口封装、数据打通和流程集成」。

零第三方依赖：只用标准库。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------- 枚举常量
# 用常量字符串而非 Enum，降低适配器编写成本，同时保持可读性

class Kind:
    """记录种类。跨平台统一，不区分来源。"""
    PROCESS = "process"            # 进程
    CONNECTION = "connection"      # 网络连接 / 监听
    PERSISTENCE = "persistence"    # 持久化机制（启动项/计划任务/服务/cron/systemd…）
    ACCOUNT = "account"            # 账号
    LOG = "log"                    # 日志
    FILE = "file"                  # 文件系统痕迹
    MODULE = "module"              # 内核模块 / 驱动
    CONFIG = "config"              # 配置项（审计策略、防火墙、代理等）
    NOTE = "note"                  # 采集过程中的说明性内容

    ALL = (PROCESS, CONNECTION, PERSISTENCE, ACCOUNT, LOG, FILE, MODULE, CONFIG, NOTE)


class Platform:
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------- 数据模型

@dataclass
class Record:
    """一条归一化记录。

    fields 里的键名遵循跨平台统一命名（见各适配器文档），例如：
        进程：pid / ppid / name / path / cmdline / user / signer
        连接：proto / local_addr / local_port / remote_addr / remote_port / state / pid
        持久化：mech / name / path / cmd / user
        账号：name / enabled / admin / last_login
    """
    kind: str
    source: str                       # 来源产物相对路径，如 "03-process.csv"
    platform: str
    fields: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""                     # 原始行文本（截断后），便于人工核对

    def __post_init__(self) -> None:
        if self.kind not in Kind.ALL:
            raise ValueError("未知记录种类: {0}".format(self.kind))
        # 原始文本截断，避免大文件把内存吃满
        if self.raw and len(self.raw) > 2000:
            self.raw = self.raw[:2000] + "…[truncated]"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def text_for_rules(self) -> str:
        """拼出一段用于关键词规则匹配的文本。

        结构化字段优先（更准），原始行兜底（防漏）。
        """
        parts: List[str] = []
        for k in ("name", "path", "cmdline", "cmd", "mech", "user",
                  "remote_addr", "local_addr", "state", "proto", "display"):
            v = self.fields.get(k)
            if v:
                parts.append(str(v))
        if self.raw:
            parts.append(self.raw)
        return " ".join(parts)


@dataclass
class Finding:
    """研判结果：一条疑似可疑记录 + 命中的规则 + 建议的下一步。"""
    record: Record
    matched_rules: List[Dict[str, Any]] = field(default_factory=list)
    severity: str = "info"            # critical / high / medium / low / info
    score: int = 0
    summary: str = ""

    # 这两个标记永久为真/假，不允许被上层改写（人在回路，见 README 安全底线）
    human_review_required: bool = True
    auto_action_allowed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.record.kind,
            "source": self.record.source,
            "platform": self.record.platform,
            "severity": self.severity,
            "score": self.score,
            "summary": self.summary,
            "matched_rules": self.matched_rules,
            "fields": self.record.fields,
            "human_review_required": self.human_review_required,
            "auto_action_allowed": self.auto_action_allowed,
        }


@dataclass
class Collection:
    """一次采集产物的集合（一个 output 目录）。"""
    root: str = ""
    platform: str = Platform.UNKNOWN
    host: str = ""
    collected_at: str = ""
    total_records: int = 0
    records_by_kind: Dict[str, int] = field(default_factory=dict)
    skipped_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------- 输出工具

def dumps(obj: Any, indent: int = 2) -> str:
    """统一 JSON 输出：中文不转义，便于人工阅读中文路径与命令。"""
    if hasattr(obj, "to_dict"):
        obj = obj.to_dict()
    return json.dumps(obj, ensure_ascii=False, indent=indent, default=str)


def write_json(path, obj) -> None:
    """落盘 JSON（结果留痕，见安全底线）。"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(dumps(obj))


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def severity_rank(sev: Optional[str]) -> int:
    return SEVERITY_ORDER.get(sev or "info", 9)
