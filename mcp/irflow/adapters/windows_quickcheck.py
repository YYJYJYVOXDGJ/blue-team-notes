"""Windows IR QuickCheck 采集产物适配器。

对应 scripts/windows-ir-quickcheck.ps1 的输出：
  - 根目录 40 个左右的 CSV（Export-Csv，UTF-8 BOM）
  - 23 个辅助 txt（Out-File / Format-List）

解析策略：**不改动采集脚本**。
理由是采集脚本必须在目标机上保持只读、可离线、零依赖；为了解析方便去改脚本，
会让"已采集的历史证据"失效，也会引入在目标机上重跑的需要。
在分析侧做适配，是取证工作流的正确分层。

字段名来自脚本实际输出（已逐项核对），同时保留多候选键名兜底，
便于将来脚本字段微调时不至于整体失效。
"""
from __future__ import annotations

import os
from typing import Any, Dict, Iterator, List, Optional

from ..schema import Collection, Kind, Platform, Record
from .base import Adapter, clean, iter_csv_dicts, read_text_lines, to_int


def _pick(row: Dict[str, str], *keys: str) -> str:
    """按候选键名顺序取值，兼容字段重命名。"""
    for k in keys:
        if k in row:
            v = clean(row.get(k))
            if v:
                return v
    return ""


class WindowsQuickCheckAdapter(Adapter):
    name = "windows-quickcheck"
    platform = Platform.WINDOWS

    # 探针特征文件（存在即为强信号）
    _SIGNATURES = [
        "01-system.csv",
        "03-process.csv",
        "02-listen.csv",
        "03-process-tree.txt",
        "07-auditpol.txt",
    ]

    def probe(self, root: str) -> int:
        hit = self._count(root, self._SIGNATURES)
        score = min(100, hit * 20)
        # 反向排除：Linux 侧特征文件存在则大幅降分
        if self._find(root, "ps-full.txt") or self._find(root, "ss-summary.txt"):
            score = max(0, score - 60)
        return score

    # ------------------------------------------------------------ 主流程
    def parse(self, root: str, collection: Collection) -> Iterator[Record]:
        # 先从系统信息里拿主机名与采集时间
        sysinfo = self._find(root, "01-system.csv")
        if sysinfo:
            for row in iter_csv_dicts(sysinfo):
                collection.host = _pick(row, "Hostname") or collection.host
                collection.collected_at = _pick(row, "ComputedAt") or collection.collected_at
                yield Record(
                    kind=Kind.CONFIG,
                    source=self._rel(root, sysinfo),
                    platform=self.platform,
                    fields={
                        "host": _pick(row, "Hostname"),
                        "domain": _pick(row, "Domain"),
                        "part_of_domain": _pick(row, "PartOfDomain"),
                        "os_name": _pick(row, "OSName"),
                        "os_version": _pick(row, "OSVersion"),
                        "build": _pick(row, "BuildNumber"),
                        "arch": _pick(row, "Architecture"),
                        "is_admin": _pick(row, "IsAdmin"),
                    },
                    raw=str(row),
                )
                break

        for rec in self._parse_network(root):
            yield rec
        for rec in self._parse_processes(root):
            yield rec
        for rec in self._parse_accounts(root):
            yield rec
        for rec in self._parse_persistence(root):
            yield rec
        for rec in self._parse_logs_and_config(root):
            yield rec

    # ------------------------------------------------------------ 网络
    def _parse_network(self, root: str) -> Iterator[Record]:
        spec = [
            ("02-listen.csv", "tcp-listen"),
            ("02-udp.csv", "udp-listen"),
            ("02-established.csv", "tcp-established"),
        ]
        for fname, proto in spec:
            p = self._find(root, fname)
            if not p:
                continue
            for row in iter_csv_dicts(p):
                yield Record(
                    kind=Kind.CONNECTION,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "proto": proto,
                        "local_addr": _pick(row, "LocalAddress"),
                        "local_port": to_int(_pick(row, "LocalPort")),
                        "remote_addr": _pick(row, "RemoteAddress"),
                        "remote_port": to_int(_pick(row, "RemotePort")),
                        "state": _pick(row, "State"),
                        "pid": to_int(_pick(row, "OwningProcess", "ProcessId")),
                        "name": _pick(row, "Process", "Name"),
                        "path": _pick(row, "Path", "ExecutablePath"),
                    },
                    raw=str(row),
                )

        # portproxy 是横向移动的常见通道，以文本形式产出，单独抽
        p = self._find(root, "02-portproxy.txt")
        if p:
            for line in read_text_lines(p):
                if not clean(line) or "---" in line:
                    continue
                yield Record(
                    kind=Kind.CONFIG,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={"display": "portproxy", "detail": clean(line)},
                    raw=line,
                )

    # ------------------------------------------------------------ 进程
    def _parse_processes(self, root: str) -> Iterator[Record]:
        # 进程快照按 PID 建索引，用于给"无签名/路径异常"两类结论补充上下文
        procs: Dict[int, Dict[str, Any]] = {}

        p = self._find(root, "03-process.csv")
        if p:
            for row in iter_csv_dicts(p):
                pid = to_int(_pick(row, "ProcessId"))
                rec = Record(
                    kind=Kind.PROCESS,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "pid": pid,
                        "ppid": to_int(_pick(row, "ParentProcessId")),
                        "name": _pick(row, "Name"),
                        "path": _pick(row, "ExecutablePath"),
                        "cmdline": _pick(row, "CommandLine"),
                        "created": _pick(row, "CreationDate"),
                        "user": _pick(row, "User", "Owner"),
                        "signer": _pick(row, "Signer", "Company"),
                        "sign": _pick(row, "Sign"),
                    },
                    raw=str(row),
                )
                if pid:
                    procs[pid] = rec.fields
                yield rec

        # 脚本已做的三维初筛结果，同样归一化，保留其判定结论
        for fname, tag, fieldname in [
            ("03-suspicious-cmdline.csv", "suspicious-cmdline", "cmdline"),
            ("03-process-outside-sysdir.csv", "outside-system-dir", "path"),
            ("03-process-non-ms-signed.csv", "non-microsoft-signed", "signer"),
        ]:
            p = self._find(root, fname)
            if not p:
                continue
            for row in iter_csv_dicts(p):
                pid = to_int(_pick(row, "ProcessId", "Id"))
                ctx = procs.get(pid, {})
                yield Record(
                    kind=Kind.PROCESS,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "pid": pid,
                        "ppid": to_int(_pick(row, "ParentProcessId")) or ctx.get("ppid", 0),
                        "name": _pick(row, "Name") or ctx.get("name", ""),
                        "path": _pick(row, "Path") or _pick(row, "ExecutablePath") or ctx.get("path", ""),
                        "cmdline": _pick(row, "CommandLine") or ctx.get("cmdline", ""),
                        "created": _pick(row, "CreationDate") or ctx.get("created", ""),
                        "sign": _pick(row, "Sign") or ctx.get("sign", ""),
                        "signer": _pick(row, "Signer") or _pick(row, "Company") or ctx.get("signer", ""),
                        "prescreen": tag,
                    },
                    raw=str(row),
                )

        # 内核驱动（BYOVD 攻击面）
        p = self._find(root, "04-drivers.csv")
        if p:
            for row in iter_csv_dicts(p):
                yield Record(
                    kind=Kind.MODULE,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "name": _pick(row, "Name"),
                        "display": _pick(row, "DisplayName"),
                        "state": _pick(row, "State"),
                        "start_mode": _pick(row, "StartMode"),
                        "path": _pick(row, "PathName"),
                    },
                    raw=str(row),
                )

    # ------------------------------------------------------------ 账号
    def _parse_accounts(self, root: str) -> Iterator[Record]:
        p = self._find(root, "06-specialaccounts.txt")
        if p:
            for line in read_text_lines(p):
                s = clean(line)
                if not s or s.startswith("==="):
                    continue
                yield Record(
                    kind=Kind.ACCOUNT,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={"detail": s},
                    raw=line,
                )
        # net accounts 的策略输出按原样保留，供人工核对口令策略
        p = self._find(root, "06-netaccounts.txt")
        if p:
            buf: List[str] = []
            for line in read_text_lines(p):
                if clean(line):
                    buf.append(clean(line))
            if buf:
                yield Record(
                    kind=Kind.CONFIG,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={"display": "password-policy", "detail": " | ".join(buf[:12])},
                    raw="\n".join(buf[:12]),
                )

    # ------------------------------------------------------------ 持久化
    def _parse_persistence(self, root: str) -> Iterator[Record]:
        # Run 系列
        p = self._find(root, "05-run-keys.csv")
        if p:
            for row in iter_csv_dicts(p):
                yield Record(
                    kind=Kind.PERSISTENCE,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "mech": "run-key",
                        "name": _pick(row, "Name"),
                        "reg_key": _pick(row, "Key"),
                        "cmd": _pick(row, "Value"),
                        "path": _pick(row, "Value"),
                    },
                    raw=str(row),
                )

        # 计划任务
        p = self._find(root, "05-scheduled-tasks.csv")
        if p:
            for row in iter_csv_dicts(p):
                yield Record(
                    kind=Kind.PERSISTENCE,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "mech": "scheduled-task",
                        "name": _pick(row, "TaskName"),
                        "task_path": _pick(row, "TaskPath"),
                        "state": _pick(row, "State"),
                        "author": _pick(row, "Author"),
                        "user": _pick(row, "RunAs"),
                        "run_level": _pick(row, "RunLevel"),
                        "hidden": _pick(row, "Hidden"),
                        "path": _pick(row, "Execute"),
                        "cmd": "{0} {1}".format(_pick(row, "Execute"), _pick(row, "Arguments")).strip(),
                    },
                    raw=str(row),
                )

        # 服务
        p = self._find(root, "04-services.csv")
        if p:
            for row in iter_csv_dicts(p):
                yield Record(
                    kind=Kind.PERSISTENCE,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "mech": "service",
                        "name": _pick(row, "Name"),
                        "display": _pick(row, "DisplayName"),
                        "state": _pick(row, "State"),
                        "start_mode": _pick(row, "StartMode"),
                        "user": _pick(row, "StartName"),
                        "path": _pick(row, "PathName"),
                        "cmd": _pick(row, "PathName"),
                        "pid": to_int(_pick(row, "ProcessId")),
                    },
                    raw=str(row),
                )

        # ServiceDll 劫持 / 服务失败命令 / IFEO / SilentProcessExit —— 四类冷门持久化
        for fname, mech, builder in [
            ("04-servicedll.csv", "servicedll",
             lambda r: {"mech": "servicedll", "name": _pick(r, "Service", "Name"),
                        "path": _pick(r, "ServiceDll", "Path", "Value")}),
            ("04-service-failurecommand.csv", "service-failure-command",
             lambda r: {"mech": "service-failure-command", "name": _pick(r, "Service"),
                        "cmd": _pick(r, "FailureCommand"), "path": _pick(r, "FailureCommand")}),
            ("05-ifeo.csv", "ifeo",
             lambda r: {"mech": "ifeo", "name": _pick(r, "Target"),
                        "reg_key": _pick(r, "Root"), "cmd": _pick(r, "Debugger"),
                        "path": _pick(r, "Debugger")}),
            ("05-silentprocessexit.csv", "silent-process-exit",
             lambda r: {"mech": "silent-process-exit", "name": _pick(r, "Target"),
                        "cmd": _pick(r, "MonitorProcess"), "path": _pick(r, "MonitorProcess")}),
        ]:
            p = self._find(root, fname)
            if not p:
                continue
            for row in iter_csv_dicts(p):
                fields = builder(row)
                fields["source_file"] = self._rel(root, p)
                yield Record(
                    kind=Kind.PERSISTENCE,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields=fields,
                    raw=str(row),
                )

        # WMI 事件订阅：无文件持久化的典型手法，三条链要合起来看
        p = self._find(root, "05-wmi-filters.csv")
        if p:
            for row in iter_csv_dicts(p):
                yield Record(
                    kind=Kind.PERSISTENCE,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "mech": "wmi-subscription",
                        "name": _pick(row, "Name"),
                        "cmd": _pick(row, "Query"),
                        "namespace": _pick(row, "EventNamespace"),
                    },
                    raw=str(row),
                )
        p = self._find(root, "05-wmi-consumers.csv")
        if p:
            for row in iter_csv_dicts(p):
                yield Record(
                    kind=Kind.PERSISTENCE,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "mech": "wmi-subscription",
                        "name": _pick(row, "Name"),
                        "consumer_class": _pick(row, "__CLASS", "Class"),
                    },
                    raw=str(row),
                )
        p = self._find(root, "05-wmi-bindings.csv")
        if p:
            for row in iter_csv_dicts(p):
                yield Record(
                    kind=Kind.PERSISTENCE,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "mech": "wmi-subscription",
                        "name": "{0} -> {1}".format(_pick(row, "Filter"), _pick(row, "Consumer")),
                        "filter": _pick(row, "Filter"),
                        "consumer": _pick(row, "Consumer"),
                    },
                    raw=str(row),
                )

        # 其余持久化位以文本形式产出，整段保留交给人工与规则双重判读
        for fname in ("05-misc-persistence.txt", "05-winlogon.txt", "05-lsa.txt",
                      "05-wsl.txt", "02-hosts.txt"):
            p = self._find(root, fname)
            if not p:
                continue
            for line in read_text_lines(p):
                s = clean(line)
                if not s or s.startswith("==="):
                    continue
                yield Record(
                    kind=Kind.PERSISTENCE,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={"mech": "misc", "detail": s, "display": fname},
                    raw=line,
                )

    # ------------------------------------------------------------ 日志与配置
    def _parse_logs_and_config(self, root: str) -> Iterator[Record]:
        config_files = [
            "07-auditpol.txt", "07-audit-config.txt", "07-sysmon.txt",
            "07-defender-status.txt", "07-defender-exclusions.txt",
            "07-wef-subscriptions.txt", "02-firewall-profiles.csv",
        ]
        for fname in config_files:
            p = self._find(root, fname)
            if not p:
                continue
            if p.lower().endswith(".csv"):
                for row in iter_csv_dicts(p):
                    yield Record(
                        kind=Kind.CONFIG,
                        source=self._rel(root, p),
                        platform=self.platform,
                        fields={"display": fname, "detail": str(row)},
                        raw=str(row),
                    )
            else:
                for line in read_text_lines(p):
                    s = clean(line)
                    if not s or s.startswith("==="):
                        continue
                    yield Record(
                        kind=Kind.CONFIG,
                        source=self._rel(root, p),
                        platform=self.platform,
                        fields={"display": fname, "detail": s, "category": "audit-or-defense"},
                        raw=line,
                    )

        # 采集日志与摘要保留为 NOTE，便于报告里呈现采集完整性
        p = self._find(root, "00-collect-log.txt")
        if p:
            count = 0
            for line in read_text_lines(p):
                count += 1
            yield Record(
                kind=Kind.NOTE,
                source=self._rel(root, p),
                platform=self.platform,
                fields={"display": "collect-log", "lines": count},
                raw="采集日志共 {0} 行".format(count),
            )
