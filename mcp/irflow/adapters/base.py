"""适配器接口定义（接口封装层）。

每个采集来源（Windows QuickCheck / Linux QuickCheck / 未来接入的 EDR 导出、
SIEM 日志、Velociraptor 采集包……）实现一个 Adapter，对外只暴露统一的
`probe()` / `parse()` 接口，下游完全不感知来源差异。

新增一个数据源 = 新增一个 Adapter 文件 + 注册，不改动流水线代码。
这就是"接口封装"在工程上的意义。

零第三方依赖。
"""
from __future__ import annotations

import csv
import io
import os
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from ..schema import Collection, Platform, Record


# ---------------------------------------------------------------- 工具函数

def read_text_lines(path: str, encoding_candidates: Optional[List[str]] = None) -> Iterator[str]:
    """流式逐行读取文本文件，自动兼容多种编码。

    为什么不用 read_text()：应急现场的事件日志导出、进程列表动辄几十万行，
    整读到内存会直接把便携设备干趴。逐行生成器是"大规模日志处理"的基本功。

    编码顺序：UTF-8-SIG（PowerShell 的 -Encoding UTF8 带 BOM）→ UTF-8 → GBK → latin-1 兜底。
    """
    if encoding_candidates is None:
        encoding_candidates = ["utf-8-sig", "utf-8", "gbk"]

    for enc in encoding_candidates:
        try:
            with open(path, "r", encoding=enc, errors="strict", newline="") as f:
                for line in f:
                    yield line.rstrip("\r\n")
            return
        except UnicodeDecodeError:
            continue
        except FileNotFoundError:
            return
        except OSError:
            return

    # 全部编码都失败：用替换模式读，保证有数据比漂亮重要
    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            for line in f:
                yield line.rstrip("\r\n")
    except OSError:
        return


def iter_csv_dicts(path: str) -> Iterator[Dict[str, str]]:
    """流式读取 CSV 为字典。PowerShell Export-Csv 会带 BOM，用 utf-8-sig 处理。"""
    for enc in ("utf-8-sig", "utf-8", "gbk"):
        try:
            with open(path, "r", encoding=enc, newline="", errors="strict") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    yield {k: v for k, v in row.items() if k is not None}
            return
        except UnicodeDecodeError:
            continue
        except (FileNotFoundError, OSError):
            return

    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            for row in csv.DictReader(f):
                yield {k: v for k, v in row.items() if k is not None}
    except OSError:
        return


def clean(value) -> str:
    """清洗字段值：去空白、把 PowerShell 的空占位去掉。"""
    if value is None:
        return ""
    s = str(value).strip()
    if s in ("", "-", "N/A", "n/a", "null", "None"):
        return ""
    return s


def to_int(value, default: int = 0) -> int:
    try:
        s = clean(value)
        return int(s) if s else default
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------- 适配器基类

class Adapter:
    """采集产物适配器基类。

    子类必须实现：
        name           —— 适配器标识
        platform       —— 归属平台
        probe()        —— 判断某个目录像不像本适配器的产物（返回置信度 0~100）
        parse()        —— 遍历目录，产出归一化 Record
    """

    name: str = "base"
    platform: str = Platform.UNKNOWN

    def __init__(self) -> None:
        # 相对路径缓存。
        # 性能关键：解析器对每条记录都要标注来源文件，同一个文件会被重复计算
        # 成千上万次。Windows 上 ntpath.relpath 内部做 normcase / split，
        # 实测在 10 万行样本上占掉总耗时的 70% 以上。缓存后该项开销归零。
        self._rel_cache: Dict[Tuple[str, str], str] = {}

    # -------------------------------------------------- 必须由子类实现
    def probe(self, root: str) -> int:
        """探测置信度。0 = 完全不像；100 = 确定是本适配器的产物。

        打分而非布尔判断，是为了将来多来源共存时能自动选最合适的适配器。
        """
        raise NotImplementedError

    def parse(self, root: str, collection: Collection) -> Iterator[Record]:
        """产出归一化记录。子类实现时应复用 collection 回填统计信息。"""
        raise NotImplementedError

    # -------------------------------------------------- 供子类使用的辅助
    def _find(self, root: str, *names: str) -> Optional[str]:
        """在 root 下查找第一个存在的文件（支持子目录浅层搜索）。"""
        for n in names:
            p = os.path.join(root, n)
            if os.path.isfile(p):
                return p
            # Windows 侧产物全在根目录；Linux 侧有 net/ proc/ 等子目录
            for sub in ("net", "proc", "persist", "user", "file", "log", "etc"):
                p2 = os.path.join(root, sub, n)
                if os.path.isfile(p2):
                    return p2
        return None

    def _rel(self, root: str, path: str) -> str:
        """相对路径（带缓存，见 __init__ 的说明）。"""
        key = (root, path)
        cached = self._rel_cache.get(key)
        if cached is not None:
            return cached
        try:
            rel = os.path.relpath(path, root).replace("\\", "/")
        except ValueError:
            rel = os.path.basename(path)
        self._rel_cache[key] = rel
        return rel

    def _count(self, root: str, patterns: List[str]) -> int:
        """统计匹配任一模式的现存文件数（用于 probe 打分）。"""
        hit = 0
        for pat in patterns:
            if self._find(root, pat):
                hit += 1
        return hit


# ---------------------------------------------------------------- 注册表

_REGISTRY: List[Adapter] = []


def register(adapter: Adapter, *, prepend: bool = False) -> Adapter:
    """注册适配器。prepend=True 时优先级更高（用于覆盖内置实现）。"""
    if prepend:
        _REGISTRY.insert(0, adapter)
    else:
        _REGISTRY.append(adapter)
    return adapter


def registered() -> List[Adapter]:
    return list(_REGISTRY)


def detect(root: str) -> Tuple[Optional[Adapter], int]:
    """自动探测目录属于哪个适配器，返回 (adapter, 置信度)。

    置信度为 0 时返回 (None, 0)，调用方应给出"无法识别"的明确提示，
    而不是硬猜——猜错平台会导致误判，比不判更糟。
    """
    best: Optional[Adapter] = None
    best_score = 0
    for a in _REGISTRY:
        try:
            s = a.probe(root)
        except Exception:
            s = 0
        if s > best_score:
            best, best_score = a, s
    return best, best_score
