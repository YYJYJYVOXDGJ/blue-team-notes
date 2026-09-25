"""Linux IR QuickCheck 采集产物适配器。

对应 scripts/linux-ir-quickcheck.sh 的输出（子目录结构）：
    etc/     系统信息
    net/     ss / ip / 防火墙 / DNS
    proc/    ps / /proc 直读 / 隐藏进程差集 / 内核模块 / eBPF
    persist/ cron / systemd / ssh 公钥 / 自启动
    user/    账号与登录
    file/    SUID / 能力位 / 无主文件 / 3 日内变动文件
    log/     完整性校验

难点在于 ss 与 ps 的输出是**定宽列 + 自由文本 tail**，且列内容可能为空（用 ? 占位）。
这里用「正则精确匹配 + 降级按空白切分」双路径，保证同一份产物在
不同发行版 / 不同 util-linux 版本下都能解析出可用结果。
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterator, List

from ..schema import Collection, Kind, Platform, Record
from .base import Adapter, clean, read_text_lines, to_int

# ss -tulwnp 一行：Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
_SS_RE = re.compile(
    r"^(tcp|udp|tcp6|udp6|raw|raw6|netlink)\s+"
    r"(\S+)\s+(\d+)\s+(\d+)\s+"
    r"(\S+)\s+(\S+)"
    r"(?:\s+(.*))?$",
    re.IGNORECASE,
)

# users:(("sshd",pid=1234,fd=3),("x",pid=5678,fd=4))
_SS_PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')

# ps -eo pid,ppid,user,tty,stat,lstart,etime,cmd
# 注意 lstart 的日期段可能带前导空格（如 "Sep  5"），故用 \s* 兼容
_PS_RE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+"
    r"((?:\w{3}\s+){2}\s*\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+"
    r"(\S+)\s+(.*)$"
)

# ip:port（兼容 0.0.0.0:22 / [::]:22 / *:22 / 127.0.0.1:631 / ::1:22）
_ADDR_RE = re.compile(r"^(.*):(\d+|\*)$")


def _split_addr(s: str) -> tuple:
    m = _ADDR_RE.match(s)
    if not m:
        return s, 0
    return m.group(1), to_int(m.group(2))


# ---------------------------------------------------------------- 行级判定
# 采集脚本把命令原文整段重定向进产物文件，文件里混着段标题、归属行、
# 环境变量声明、工具表头。逐行照收 = 大量误报，所以必须做行级语义判定。

# cron 时间字段：* / 5 / */10 / 1-5 / 1,3,5 / 1-5/2
_CRON_FIELD_RE = re.compile(r"^(\*|\d+|\*/\d+|\d+-\d+|\d+(?:,\d+)*)(?:/\d+)?$")
_CRON_SPECIAL = ("@reboot", "@daily", "@hourly", "@weekly", "@monthly",
                 "@yearly", "@annually", "@midnight")

_PUBKEY_PREFIXES = ("ssh-rsa", "ssh-ed25519", "ecdsa-sha2-", "ssh-dss",
                    "sk-ssh-", "ssh-xmss", "rsa-sha2-")


def _is_cron_line(s: str) -> bool:
    """判断一行是不是真正的 cron 任务行（而不是 SHELL=/PATH= 或段标题）。"""
    if s.startswith(_CRON_SPECIAL):
        return True
    parts = s.split()
    if len(parts) < 6:
        return False
    return all(_CRON_FIELD_RE.match(p) for p in parts[:5])


def _split_cron(s: str) -> tuple:
    """拆出 (时间表达式, 命令)。"""
    for sp in _CRON_SPECIAL:
        if s.startswith(sp):
            rest = s[len(sp):].strip()
            return sp, rest
    parts = s.split(None, 5)
    return " ".join(parts[:5]), (parts[5] if len(parts) > 5 else "")


def _is_pubkey_line(s: str) -> bool:
    parts = s.split()
    if len(parts) < 2:
        return False
    return parts[0].lower().startswith(_PUBKEY_PREFIXES)


def _is_table_header(s: str) -> bool:
    """过滤工具输出表头（lsmod / ss / ps 等）。"""
    low = s.lower()
    return (("module" in low and "size" in low and "used by" in low)
            or low.startswith("netid")
            or low.startswith("state ")
            or low.startswith("pid ")
            or low.startswith("filesystem")
            or low.startswith("active connections"))


class LinuxQuickCheckAdapter(Adapter):
    name = "linux-quickcheck"
    platform = Platform.LINUX

    _SIGNATURES = [
        "ps-full.txt",
        "ss-summary.txt",
        "HIDDEN-pids.txt",
        "exe-links.txt",
        "system-info.txt",
    ]

    def probe(self, root: str) -> int:
        hit = self._count(root, self._SIGNATURES)
        score = min(100, hit * 20)
        if self._find(root, "03-process.csv") or self._find(root, "01-system.csv"):
            score = max(0, score - 60)
        return score

    # ------------------------------------------------------------ 主流程
    def parse(self, root: str, collection: Collection) -> Iterator[Record]:
        p = self._find(root, "system-info.txt")
        if p:
            buf: List[str] = []
            for line in read_text_lines(p):
                s = clean(line)
                if not s or s.startswith("==="):
                    continue
                buf.append(s)
            if buf:
                collection.collected_at = self._guess_collected_at(buf)
                collection.host = self._guess_hostname(buf)
                yield Record(
                    kind=Kind.CONFIG,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "host": collection.host,
                        "detail": " | ".join(buf[:20]),
                        "display": "system-info",
                    },
                    raw="\n".join(buf[:20]),
                )

        for rec in self._parse_network(root):
            yield rec
        for rec in self._parse_processes(root):
            yield rec
        for rec in self._parse_accounts(root):
            yield rec
        for rec in self._parse_persistence(root):
            yield rec
        for rec in self._parse_files_and_logs(root):
            yield rec

    @staticmethod
    def _guess_collected_at(lines: List[str]) -> str:
        for s in lines:
            if "采集时间" in s:
                return s.split("：")[-1].split(":")[-1].strip() if "：" in s else s
        return lines[0] if lines else ""

    @staticmethod
    def _guess_hostname(lines: List[str]) -> str:
        for s in lines:
            if s.lower().startswith("hostname") or "主机名" in s:
                parts = s.replace("：", ":").split(":")
                if len(parts) > 1:
                    return parts[-1].strip()
        return ""

    # ------------------------------------------------------------ 网络
    def _parse_network(self, root: str) -> Iterator[Record]:
        for fname, proto in (("listen.txt", "listen"), ("established.txt", "established"),
                             ("tcp.txt", "tcp-all")):
            p = self._find(root, fname)
            if not p:
                continue
            header_seen = False
            for line in read_text_lines(p):
                s = line.strip()
                if not s:
                    continue
                if s.startswith("Netid") or s.startswith("State"):
                    header_seen = True
                    continue
                m = _SS_RE.match(s)
                if not m:
                    continue
                netid, state, _recv, _send, local, peer, procinfo = m.groups()
                laddr, lport = _split_addr(local)
                raddr, rport = _split_addr(peer or "")

                procs = _SS_PROC_RE.findall(procinfo or "")
                first_name, first_pid = (procs[0][0], to_int(procs[0][1])) if procs else ("", 0)

                yield Record(
                    kind=Kind.CONNECTION,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "proto": "{0}-{1}".format(netid.lower(), proto),
                        "state": state,
                        "local_addr": laddr,
                        "local_port": lport,
                        "remote_addr": raddr,
                        "remote_port": rport,
                        "name": first_name,
                        "pid": first_pid,
                        "cmd": ",".join("{0}({1})".format(n, pi) for n, pi in procs),
                    },
                    raw=s,
                )

        # 防火墙与 DNS 配置：无文件攻击常改 resolv.conf / hosts 做流量劫持
        for fname, display in (("firewall.txt", "firewall"), ("dns.txt", "dns"),
                               ("basic.txt", "net-basic")):
            p = self._find(root, fname)
            if not p:
                continue
            for line in read_text_lines(p):
                s = clean(line)
                if not s or s.startswith("==="):
                    continue
                yield Record(
                    kind=Kind.CONFIG,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={"display": display, "detail": s, "category": "network-config"},
                    raw=line,
                )

    # ------------------------------------------------------------ 进程
    def _parse_processes(self, root: str) -> Iterator[Record]:
        p = self._find(root, "ps-full.txt")
        if p:
            for line in read_text_lines(p):
                s = line.rstrip()
                if not s or s.strip().startswith("PID"):
                    continue
                m = _PS_RE.match(s)
                if m:
                    pid, ppid, user, tty, stat, started, etime, cmd = m.groups()
                    yield Record(
                        kind=Kind.PROCESS,
                        source=self._rel(root, p),
                        platform=self.platform,
                        fields={
                            "pid": to_int(pid),
                            "ppid": to_int(ppid),
                            "user": user,
                            "tty": tty,
                            "stat": stat,
                            "created": started,
                            "etime": etime,
                            "cmdline": cmd.strip(),
                            "name": self._basename_of(cmd),
                            "path": self._first_path_of(cmd),
                        },
                        raw=s,
                    )
                    continue
                # 降级路径：按空白切分，尽量救回关键字段
                parts = s.split()
                if len(parts) >= 8 and parts[0].isdigit():
                    yield Record(
                        kind=Kind.PROCESS,
                        source=self._rel(root, p),
                        platform=self.platform,
                        fields={
                            "pid": to_int(parts[0]),
                            "ppid": to_int(parts[1]),
                            "user": parts[2],
                            "cmdline": " ".join(parts[5:]),
                            "name": self._basename_of(" ".join(parts[5:])),
                        },
                        raw=s,
                    )

        # /proc 直读的 exe / cwd 链接：被删除的可执行文件会显示 (deleted)
        for fname, key in (("exe-links.txt", "exe"), ("cwd-links.txt", "cwd")):
            p = self._find(root, fname)
            if not p:
                continue
            for line in read_text_lines(p):
                s = clean(line)
                if not s:
                    continue
                m = re.search(r"/proc/(\d+)/", s)
                pid = to_int(m.group(1)) if m else 0
                target = s.split("->")[-1].strip() if "->" in s else ""
                yield Record(
                    kind=Kind.PROCESS,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "pid": pid,
                        "path": target,
                        "name": os.path.basename(target.split(" (deleted)")[0]) if target else "",
                        "deleted": "yes" if "(deleted)" in target else "",
                        "sourcetype": key,
                    },
                    raw=line,
                )

        # 隐藏进程差集：这是绕过被替换的 ps/netstat 的关键证据
        p = self._find(root, "HIDDEN-pids.txt")
        if p:
            for line in read_text_lines(p):
                s = clean(line)
                if not s:
                    continue
                yield Record(
                    kind=Kind.PROCESS,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "pid": to_int(s),
                        "name": "(hidden)",
                        "hidden": "yes",
                        "detail": "存在于 /proc 但 ps 不可见，疑似内核级隐藏或 ps 被替换",
                    },
                    raw=line,
                )

        # 内核模块与 eBPF 程序：rootkit / 无文件后门的落点
        for fname, display in (("lsmod.txt", "lsmod"), ("modules.txt", "proc-modules"),
                               ("bpf-progs.txt", "bpf-programs"),
                               ("injection.txt", "ptrace-injection"),
                               ("dmesg.txt", "dmesg")):
            p = self._find(root, fname)
            if not p:
                continue
            for line in read_text_lines(p):
                s = clean(line)
                if not s or s.startswith("==="):
                    continue
                if _is_table_header(s):
                    continue
                yield Record(
                    kind=Kind.MODULE if fname in ("lsmod.txt", "modules.txt", "bpf-progs.txt")
                    else Kind.CONFIG,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={"display": display, "detail": s, "name": s.split()[0] if s.split() else ""},
                    raw=line,
                )

    # ------------------------------------------------------------ 账号
    def _parse_accounts(self, root: str) -> Iterator[Record]:
        for fname in ("accounts.txt", "logins.txt"):
            p = self._find(root, fname)
            if not p:
                continue
            for line in read_text_lines(p):
                s = clean(line)
                if not s or s.startswith("==="):
                    continue
                rec = {
                    "detail": s,
                    "display": fname,
                }
                # /etc/passwd 行：user:x:uid:gid:gecos:home:shell
                if fname == "accounts.txt" and s.count(":") >= 6 and not s.startswith(" "):
                    f = s.split(":")
                    rec.update({
                        "name": f[0],
                        "uid": to_int(f[2]),
                        "gid": to_int(f[3]),
                        "home": f[5],
                        "shell": f[6],
                        # UID 0 但非 root = 后门账号，这是最硬的判据
                        "admin": "yes" if to_int(f[2]) == 0 else "",
                    })
                yield Record(
                    kind=Kind.ACCOUNT,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields=rec,
                    raw=line,
                )

        p = self._find(root, "login.defs")
        if p:
            for line in read_text_lines(p):
                s = clean(line)
                if not s or s.startswith("#"):
                    continue
                yield Record(
                    kind=Kind.CONFIG,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={"display": "login.defs", "detail": s, "category": "password-policy"},
                    raw=line,
                )

    # ------------------------------------------------------------ 持久化
    def _parse_persistence(self, root: str) -> Iterator[Record]:
        # cron：**只挑真正的 cron 行**。
        # 脚本把 crontab 原文整段重定向进 cron.txt，其中混有 SHELL=/PATH= 环境变量行、
        # "-- user: root" 归属行、"===== 段标题 ====="。逐行照收会造成大量误报，
        # 因此这里用「前 5 个字段是不是合法 cron 时间字段」做行级判定。
        p = self._find(root, "cron.txt")
        if p:
            owner = ""
            for line in read_text_lines(p):
                s = line.strip()
                if not s or s.startswith("==="):
                    continue
                m_owner = re.match(r"^--\s*(?:user:\s*)?(.+)$", s)
                if m_owner and not _is_cron_line(s):
                    owner = m_owner.group(1).strip()
                    continue
                if not _is_cron_line(s):
                    continue
                sched, cmd = _split_cron(s)
                yield Record(
                    kind=Kind.PERSISTENCE,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "mech": "cron",
                        "name": sched,
                        "schedule": sched,
                        "cmd": cmd,
                        "path": self._first_path_of(cmd),
                        "user": owner,
                        "detail": s,
                    },
                    raw=line,
                )

        # SSH authorized_keys：脚本输出形如
        #     ===== authorized_keys =====
        #     -rw------- 1 root root 96 Sep 25 14:00 /root/.ssh/authorized_keys
        #     -- content --
        #     ssh-ed25519 AAAA... user@host
        # 只有真公钥行才算持久化项；sshd_config 段另归配置类。
        p = self._find(root, "ssh.txt")
        if p:
            cur_path = ""
            section = ""
            for line in read_text_lines(p):
                s = line.strip()
                if not s:
                    continue
                if s.startswith("====="):
                    section = s.strip("= ").lower()
                    continue
                # ls -l 行：拿它作为后续公钥的归属文件
                if s.startswith("-") and "authorized_keys" in s:
                    parts = s.split()
                    if parts:
                        cur_path = parts[-1]
                    continue
                if s in ("-- content --", "-", "--"):
                    continue

                if _is_pubkey_line(s):
                    parts = s.split()
                    yield Record(
                        kind=Kind.PERSISTENCE,
                        source=self._rel(root, p),
                        platform=self.platform,
                        fields={
                            "mech": "ssh-authorized-keys",
                            "name": cur_path or "authorized_keys",
                            "key_type": parts[0],
                            "comment": parts[2] if len(parts) > 2 else "",
                            "cmd": s,
                            "path": cur_path,
                            "detail": s,
                        },
                        raw=line,
                    )
                    continue

                # 高危授权选项（command= / from= / permitopen= 等）
                if section and "高危" in section and ":" in s:
                    yield Record(
                        kind=Kind.PERSISTENCE,
                        source=self._rel(root, p),
                        platform=self.platform,
                        fields={
                            "mech": "ssh-authorized-keys-option",
                            "name": s.split(":", 1)[0],
                            "cmd": s,
                            "path": s.split(":", 1)[0],
                            "detail": s,
                        },
                        raw=line,
                    )
                    continue

                # sshd_config 关键项属于配置，不是持久化后门
                if "sshd_config" in section or re.match(r"^(PermitRootLogin|PasswordAuthentication|"
                                                        r"PubkeyAuthentication|Port|AllowUsers|"
                                                        r"ForceCommand|PermitUserEnvironment)",
                                                        s, re.IGNORECASE):
                    yield Record(
                        kind=Kind.CONFIG,
                        source=self._rel(root, p),
                        platform=self.platform,
                        fields={"display": "sshd_config", "detail": s,
                                "category": "ssh-config"},
                        raw=line,
                    )

        # autostart / systemd
        p = self._find(root, "autostart.txt")
        if p:
            for line in read_text_lines(p):
                s = clean(line)
                if not s or s.startswith("==="):
                    continue
                yield Record(
                    kind=Kind.PERSISTENCE,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={"mech": "autostart", "name": s, "cmd": s,
                            "path": self._first_path_of(s), "detail": s},
                    raw=line,
                )

        p = self._find(root, "systemd.txt")
        if p:
            section = ""
            for line in read_text_lines(p):
                s = line.strip()
                if not s:
                    continue
                if s.startswith("====="):
                    section = s.strip("= ")
                    continue
                # Exec*= 行：`/path/unit.service:ExecStart=/tmp/x.sh -a`
                if re.search(r"Exec(Start|Stop|Reload)(Pre|Post)?=", s):
                    unit, _, val = s.partition(":")
                    yield Record(
                        kind=Kind.PERSISTENCE,
                        source=self._rel(root, p),
                        platform=self.platform,
                        fields={
                            "mech": "systemd",
                            "name": unit or "systemd-unit",
                            "unit": unit,
                            "cmd": val or s,
                            "path": self._first_path_of(val or s),
                            "detail": s,
                        },
                        raw=line,
                    )
                    continue
                # 启用中的服务条目（`sshd.service enabled enabled`）不含路径，
                # 单列出来，避免被"路径含 /tmp"类规则误命中。
                if re.search(r"\b(enabled|disabled)\b", s, re.IGNORECASE) and " " in s:
                    yield Record(
                        kind=Kind.PERSISTENCE,
                        source=self._rel(root, p),
                        platform=self.platform,
                        fields={"mech": "systemd-unit", "name": s.split()[0],
                                "state": s.split()[1] if len(s.split()) > 1 else "",
                                "detail": s, "section": section},
                        raw=line,
                    )

    # ------------------------------------------------------------ 文件与日志
    def _parse_files_and_logs(self, root: str) -> Iterator[Record]:
        spec = [
            ("suid.txt", "suid"),
            ("sgid.txt", "sgid"),
            ("capabilities.txt", "capabilities"),
            ("no-owner.txt", "no-owner"),
            ("recent-3d.txt", "recent-modified"),
            ("traces.txt", "deleted-but-open"),
            ("tmpdirs.txt", "tmp-executables"),
            ("world-writable-dirs.txt", "world-writable-dir"),
            ("bash-history-list.txt", "bash-history"),
            ("integrity.txt", "integrity"),
        ]
        for fname, display in spec:
            p = self._find(root, fname)
            if not p:
                continue
            kind = Kind.LOG if fname == "integrity.txt" else Kind.FILE
            if fname == "bash-history-list.txt":
                kind = Kind.FILE
            for line in read_text_lines(p):
                s = clean(line)
                if not s or s.startswith("==="):
                    continue
                yield Record(
                    kind=kind,
                    source=self._rel(root, p),
                    platform=self.platform,
                    fields={
                        "display": display,
                        "detail": s,
                        "path": self._first_path_of(s) or (s if s.startswith("/") else ""),
                        "name": os.path.basename(s.split()[-1]) if s.split() else "",
                    },
                    raw=line,
                )

    # ------------------------------------------------------------ 小工具
    @staticmethod
    def _basename_of(cmd: str) -> str:
        if not cmd:
            return ""
        first = cmd.strip().split()[0]
        return os.path.basename(first)

    @staticmethod
    def _first_path_of(cmd: str) -> str:
        """从命令行里抽出第一个看起来像绝对路径的 token。"""
        if not cmd:
            return ""
        for tok in cmd.replace("\t", " ").split():
            t = tok.strip("\"'`,;()")
            if t.startswith("/") and len(t) > 1:
                return t
        return ""
