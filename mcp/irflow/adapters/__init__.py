"""适配器注册表。

新增数据源只需两步：
    1. 在本目录写一个 Adapter 子类
    2. 在本文件 import 并 register()

流水线代码完全不需要改动。

当前已接入：
    - windows-quickcheck  : scripts/windows-ir-quickcheck.ps1 的产物
    - linux-quickcheck    : scripts/linux-ir-quickcheck.sh 的产物

规划接入（接口已就绪，只差实现）：
    - evtx-export         : Windows 事件日志导出（evtx → csv/json）
    - auditd              : Linux auditd 原始日志
    - sigma-json          : Sigma 规则的 JSON 输出
    - edr-export          : 客户侧 EDR / 态势感知的告警导出
"""
from __future__ import annotations

from .base import (
    Adapter,
    clean,
    detect,
    iter_csv_dicts,
    read_text_lines,
    register,
    registered,
    to_int,
)
from .windows_quickcheck import WindowsQuickCheckAdapter
from .linux_quickcheck import LinuxQuickCheckAdapter

__all__ = [
    "Adapter", "clean", "detect", "iter_csv_dicts", "read_text_lines",
    "register", "registered", "to_int",
    "WindowsQuickCheckAdapter", "LinuxQuickCheckAdapter",
]

# 注册内置适配器（Windows 优先：同名文件冲突时 Windows 特征更强）
register(WindowsQuickCheckAdapter())
register(LinuxQuickCheckAdapter())
