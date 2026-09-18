# Linux 主机应急排查手册（蓝队）

> 适用场景：主机入侵事件应急响应、攻防演习保障、主机安全基线巡检
>
> 三条原则：
> 1. **先取证，后处置** —— 杀进程、删文件之前先固定证据。现场一旦被破坏，攻击路径就再也还原不了。
> 2. **先外围，后核心** —— 网络连接 → 进程 → 持久化 → 日志/文件，由外向内收敛，不要一上来就 `find /`。
> 3. **不迷信系统命令** —— `ps` / `ls` / `netstat` / `ss` 都可能被替换或被 `LD_PRELOAD` hook。凡是结论性判断，都要用 `/proc` 直读、软件包校验、外部可信二进制做交叉验证。

## 目录

- [0. 排查前置：现场保护与取证](#0-排查前置现场保护与取证)
- [1. 网络连接与端口排查](#1-网络连接与端口排查)
- [2. 进程与内存排查](#2-进程与内存排查)
- [3. 持久化后门排查（核心）](#3-持久化后门排查核心)
- [4. 用户账号与登录审计](#4-用户账号与登录审计)
- [5. 命令历史与操作痕迹](#5-命令历史与操作痕迹)
- [6. 文件系统与恶意文件排查](#6-文件系统与恶意文件排查)
- [7. 日志审计](#7-日志审计)
- [8. 应用与中间件专项](#8-应用与中间件专项)
- [9. 处置与加固](#9-处置与加固)
- [10. 一键排查脚本](#10-一键排查脚本)
- [附录 A：现场排查 Checklist](#附录-a现场排查-checklist)

**配套文档**

- [Linux 攻击手法与排查点映射](linux-attack-mapping.md) —— 从攻击者视角反查：每种手法在本机留下什么痕迹、对应的排查命令、ATT&CK 对照
- [Linux 主机安全基线核查与加固](linux-hardening.md) —— 排查之后的收口，面向安全评估与常态化基线巡检

---

## 0. 排查前置：现场保护与取证

排查的第一步不是敲命令，是**决定要不要动这个系统**。

### 0.1 建立时间基准

```bash
date                      # 当前系统时间（注意是否被篡改）
date -u                   # UTC 时间
uptime                    # 运行时长 + 平均负载
uptime -s                 # 系统启动时间点
who -b                    # 最近一次启动时间
last reboot | head -10    # 历史重启记录
timedatectl               # 时区/NTP 同步状态（时间被改会毁掉整条时间线）
```

### 0.2 选择处置策略（先想清楚，再断网）

| 策略 | 适用 | 风险 |
|---|---|---|
| 保持观察，不打草惊蛇 | 攻击者仍在活动、要抓溯源线索 | 攻击可能继续 |
| 拔网线 / `ip link set eth0 down` | 已确认失陷，需立即止损 | 攻击者会察觉，可能触发自毁 |
| `iptables` 精准封禁指定 IP | 只封 C2 信道，保留主机可控 | 需先确认 IP 准确 |
| 只挂起进程 `kill -STOP PID` | 想保留内存现场 | 需尽快取证 |

### 0.3 固定证据

```bash
# 1) 内存取证（有条件的场景，工具需提前准备）
avml /tmp/evidence/mem.lime                 # Linux 内存镜像
# 或 insmod LiME；后续用 volatility3 分析

# 2) 磁盘镜像（只在需要离线分析时做）
dd if=/dev/sda of=/mnt/usb/disk.img bs=4M status=progress

# 3) 最小证据包：日志 + 账号 + 进程 + 网络 + 历史命令
mkdir -p /tmp/evidence/{proc,log,etc,hist}
ps auxf > /tmp/evidence/proc/ps.txt
ss -tulnp > /tmp/evidence/proc/ss.txt
cp -a /var/log/secure* /var/log/messages* /var/log/wtmp /var/log/btmp /tmp/evidence/log/ 2>/dev/null
cp -a /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/crontab /etc/fstab /tmp/evidence/etc/
cp -a /root/.bash_history /tmp/evidence/hist/ 2>/dev/null

# 4) 所有排查命令统一落盘，方便回溯
#    用 script 录制整个会话，或在脚本里 tee -a
```

### 0.4 准备可信工具（不要用被污染的机器上的二进制）

- **BusyBox 静态版**：`./busybox ps`、`./busybox netstat`，绕过被替换的系统命令
- 从 U 盘或另一台干净主机带入：`chkrootkit`、`rkhunter`、`unhide`、`ClamAV`、`sysdig`、`osquery`、`auditd`
- 交叉验证思路：**同一条信息用两种不同来源取两次，结果不一致就是线索**

```bash
# 检查系统关键命令是否被替换（时间戳异常 / 大小异常 / 权限异常）
ls -l --time-style=full-iso /usr/bin/ps /usr/bin/ls /usr/bin/netstat /usr/bin/ss /usr/bin/find
rpm -Vf /usr/bin/ps /usr/bin/ls /usr/bin/netstat 2>/dev/null    # RHEL 系
dpkg -V procps coreutils net-tools 2>/dev/null                  # Debian 系
lsattr /usr/bin/ps /usr/bin/ls 2>/dev/null                      # 是否被人为加了 i 属性
which ps; type -a ps; echo $PATH                                # 是否有路径劫持
alias                                                           # 是否有 alias 劫持（如 alias ls='ls -a' 藏文件）
```

### 0.5 排查优先级与时间分配

现场时间有限，别平均用力。按「失陷确认度」决定排查深度：

| 触发场景 | 优先做 | 可暂缓 |
|---|---|---|
| 告警疑似（EDR / 流量告警，主机未见异常） | 第 1 节网络 + 3.1 SSH 公钥 + 3.4 定时任务 | 全盘 `find` |
| 已确认失陷，攻击者可能仍在活动 | 第 2 节隐藏进程 + 1.3 `/proc` 直读 + 第 0 节取证 | 应用层深挖 |
| 失陷已阻断，转做溯源 | 第 5 节时间线 + 第 7 节日志 + 第 4 节账号 | 反复复检端口 |
| 攻防演习 / 基线巡检 | 第 3 节持久化全量 + 第 9 节加固 | 深度取证 |
| 挖矿 / 勒索（资源型事件） | `ps aux --sort=-%cpu` + 攻击手法映射专项 | 历史日志 |

**10 分钟快速定位（第一轮，只读不改）**

```bash
ss -tulwnp | grep -vE "127\.0\.0\.1|::1"                                     # 1 异常监听
ss -tanp state established | grep -vE "127\.0\.0\.1|::1"                      # 2 异常外连
ps -eo pid,ppid,user,etime,cmd | grep -E "/tmp/|/var/tmp/|/dev/shm/|/dev/tcp|bash -i|socat|ncat"   # 3 可疑进程
find / -name authorized_keys -exec ls -l {} \; 2>/dev/null                    # 4 SSH 公钥后门
for u in $(cut -d: -f1 /etc/passwd); do echo "-- $u"; crontab -l -u "$u" 2>/dev/null; done   # 5 用户级定时任务
cat /etc/ld.so.preload 2>/dev/null; ls -l /proc/[0-9]*/exe 2>/dev/null | grep -i memfd        # 6 注入 / 无文件
```

> 六条都「干净」只代表**表层**干净。对手上了 rootkit 时，第 6 条与 `/proc` 直读才是分水岭。

---

## 1. 网络连接与端口排查

### 1.1 监听端口

```bash
ss -tulnp                 # 推荐：TCP+UDP 监听 + 进程（-n 不解析域名，-p 显示进程）
ss -tulwnp                # 加上 -w，含 raw socket（ICMP 隧道会出现在这里）
ss -tulp                  # UDP 监听单独看
netstat -tulnp            # 传统方式（部分系统需 net-tools）
lsof -i -P -n             # 以「进程」为视角看所有网络文件
lsof -i -P -n | grep LISTEN
netstat -antp | grep java # XXL-JOB / 中间件场景下按进程过滤
```

### 1.2 外连与 C2 信道

```bash
ss -tanp state established                # 已建立连接（重点看外连公网 IP）
ss -tnp | grep -vE "127\.0\.0\.1|::1"     # 排除本地回环
lsof -i -n -P | grep ESTABLISHED
netstat -anp | grep ESTABLISHED | grep -v 127.0.0.1

# 按目标 IP 聚合，快速识别异常外连（谁连得最多）
ss -tn state established | awk 'NR>1{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20
```

### 1.3 绕过被替换的 netstat/ss（直读 /proc）

这是**判断有无隐藏连接**的关键手段。

```bash
# 原始 /proc 输出：地址是十六进制小端序，需转换
cat /proc/net/tcp
cat /proc/net/tcp6
cat /proc/net/udp
cat /proc/net/raw            # raw socket，ICMP/自定义协议隧道
cat /proc/net/unix           # unix socket，本地后门通信

# 十六进制转可读（需 gawk，RHEL 系默认 awk 即 gawk）
awk 'NR>1{split($2,a,":");split($3,b,":");
  printf "%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d st=%s inode=%s\n",
  strtonum("0x" substr(a[1],7,2)),strtonum("0x" substr(a[1],5,2)),
  strtonum("0x" substr(a[1],3,2)),strtonum("0x" substr(a[1],1,2)),strtonum("0x" a[2]),
  strtonum("0x" substr(b[1],7,2)),strtonum("0x" substr(b[1],5,2)),
  strtonum("0x" substr(b[1],3,2)),strtonum("0x" substr(b[1],1,2)),strtonum("0x" b[2]),
  $4,$10}' /proc/net/tcp

# 数量对比：ss 与 /proc 数量不一致 → 强信号存在隐藏连接/隐藏进程
echo "ss:    $(ss -tan | tail -n +2 | wc -l)"
echo "proc:  $(tail -n +2 /proc/net/tcp | wc -l)"

# 用 inode 反查持有该连接的进程（ss 不显示进程时用）
INODE=1234567
ls -l /proc/[0-9]*/fd 2>/dev/null | grep "socket:\[$INODE\]"
```

### 1.4 路由 / ARP / 网卡

```bash
ip route; route -n                    # 异常路由 = 可能被配成跳板/中转
ip neigh; arp -a                      # ARP 表：内网横向痕迹、ARP 欺骗
ip -br addr                           # 网卡地址总览
ip link | grep -i promisc             # 混杂模式（攻击者抓包）
cat /proc/sys/net/ipv4/ip_forward     # =1 且不该转发 → 可能做跳板
sysctl -a 2>/dev/null | grep -E "ip_forward|accept_redirects|send_redirects"
cat /proc/sys/net/ipv4/conf/all/rp_filter
```

### 1.5 防火墙与 NAT（攻击者常留的转发规则）

```bash
iptables -L -n -v --line-numbers
iptables -t nat -L -n -v              # DNAT/SNAT 端口转发、隧道
iptables -t mangle -L -n -v
iptables-save                         # 完整规则快照
nft list ruleset
firewall-cmd --list-all
# 关注：非运维添加的 DROP/ACCEPT、陌生的 DNAT/SNAT、REDIRECT
```

### 1.6 DNS 与 hosts（外带/隧道）

```bash
cat /etc/resolv.conf        # 陌生的 DNS 可能是数据外带通道
cat /etc/hosts              # 域名劫持、隐藏解析
cat /etc/nsswitch.conf      # 解析顺序被改
cat /etc/services           # 端口名混淆
```

### 1.7 连接跟踪与抓包

```bash
conntrack -L                                  # 连接跟踪全表
cat /proc/net/nf_conntrack | head -50
tcpdump -i any -nn -c 200 'not port 22'       # 快速看流量特征
tcpdump -i any -nn icmp                       # ICMP 隧道
tcpdump -i any -nn port 53                    # DNS 隧道
tcpdump -i any -nn -w /tmp/evidence/cap.pcap  # 抓包留证
```

### 1.8 内核层网络取证与流量分析

```bash
# AF_PACKET 套接字：抓包嗅探器（tcpdump / 后门嗅探模块）会在这里现形
cat /proc/net/packet
ss -0 -a                                     # -0 即 AF_PACKET
ss -tulnp | grep -i packet

# 协议栈统计异常（大量 SYN/RST、ICMP 异常 → 扫描或隧道）
ss -s
netstat -s | head -40
nstat -az | head -40                         # 更全的协议计数器
cat /proc/net/snmp

# 连接状态异常
ss -tanp state syn-sent                      # 半开连接：扫描器 / 隧道客户端
ss -tan state time-wait | wc -l              # TIME_WAIT 暴增 → 端口扫描或连接风暴

# 实时流量（需额外安装，按需）
iftop -nNP                                   # 按连接看带宽，快速定位外传
nethogs                                      # 按进程看带宽
iptraf-ng; vnstat; bmon

# conntrack 全量（含 NAT 转发后的连接）
conntrack -L -o extended
conntrack -L | grep -v ESTABLISHED | head -50

# iptables 是否被内核层 hook
cat /proc/net/ip_tables_names
lsmod | grep -E "ip_tables|nf_|xt_"
# 提示：iptables -L 的规则数与 iptables-save 的 -A 行数对不上，说明存在 hook 层
```

### 1.9 隧道、代理与隐蔽信道检测

```bash
# 进程特征：主流隧道 / 代理工具
ps aux | grep -Ei "frpc|frps|ngrok|chisel|gost|regeorg|ew_for|venom|nps|lcx|socat|stowaway|iox|tun2socks|sshuttle"

# 落地文件特征（配置里往往直接写着 C2 地址）
ls -la /tmp /var/tmp /dev/shm /run 2>/dev/null | grep -Ei "frp|ngrok|chisel|gost|nps|ew_|venom|\.conf|\.ini|\.toml"

# 监听端口人工过一遍，关注点：
#   1) 非业务端口
#   2) 1xxxx-6xxxx 的高端口
#   3) 本该只监听 127.0.0.1 的管理服务监听在 0.0.0.0
ss -tulnp

# SSH 隧道（-L 本地转发 / -R 远程转发 / -D 动态 socks / -N 不执行命令）
ps -eo pid,user,tty,etime,cmd | grep -E "ssh .*(-L|-R|-D|-N|-f|ProxyCommand)"
grep -rEi "socks|proxycommand|localforward|remoteforward|dynamicforward" \
  /etc/ssh/ssh_config ~/.ssh/config /home/*/.ssh/config 2>/dev/null

# 内核层隧道设备
ip tunnel show
ip -d link show | grep -E "tun|tap|wireguard|gre|sit|ipip|vxlan"
cat /proc/net/ip_tunnels 2>/dev/null
ls -la /dev/net/tun
wg show 2>/dev/null

# 抓包识别隧道：长连接 + 小包 + 固定间隔 + 无明显协议特征
tcpdump -i any -nn -c 100 'tcp and len < 100' -w /tmp/evidence/tunnel.pcap
tcpdump -i any -nn -c 50 icmp            # ICMP 隧道
tcpdump -i any -nn -c 50 port 53         # DNS 隧道
```

---

## 2. 进程与内存排查

### 2.1 进程枚举（多源交叉验证，防隐藏进程）

```bash
ps aux                       # 全量进程（原表格命令）
ps auxf                      # 树形 + 全格式
ps -ef
ps -eo pid,ppid,user,tty,stat,lstart,etime,cmd --sort=start_time
pstree -p
pstree -aps 1234             # 只看某进程的完整祖先链（溯源父进程）
top -c; htop; atop
```

**隐藏进程检测（关键）**：`ps` 被 hook 时会漏进程，用 `/proc` 目录做基准。

```bash
ls -d /proc/[0-9]* | sed 's#/proc/##' | sort -n > /tmp/p_proc.txt
ps -eo pid --no-headers | tr -d ' ' | sort -n > /tmp/p_ps.txt
echo "== 只在 /proc 中，ps 看不到的进程 =="
comm -23 /tmp/p_proc.txt /tmp/p_ps.txt
echo "== 只在 ps 中，/proc 里没有的进程 =="
comm -13 /tmp/p_proc.txt /tmp/p_ps.txt

# 专业工具（需外部带入）
./unhide proc          # 检测隐藏进程
./unhide sys           # 检测被 hook 的系统调用
```

### 2.2 可疑进程特征识别

```bash
# 反弹 shell 特征
ps aux | grep -E "bash -i|sh -i|/dev/tcp|/dev/udp|nc |ncat |socat |openssl s_client|perl -e|python -c|php -r"

# 长时间运行的「一句话命令」（挖矿/隧道常用）
ps -eo pid,etime,cmd --sort=-etime | head -30

# 资源异常
ps aux --sort=-%cpu | head -15
ps aux --sort=-%mem | head -15

# 进程名与可执行路径不符（伪装成 kernel 线程、systemd 等）
ps -eo pid,comm,args | awk '$2!=$3'

# 可执行文件位于异常目录或在 tmp / 已删除
ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/|/run/|\(deleted\)"

# 内核线程伪装检测：真实内核线程 [kworker] 无 cmdline
for p in /proc/[0-9]*; do
  n=$(cat $p/comm 2>/dev/null)
  c=$(tr -d '\0' < $p/cmdline 2>/dev/null)
  case "$n" in \[*\]*) [ -n "$c" ] && echo "可疑内核线程伪装: $p name=$n cmd=$c";; esac
done
```

### 2.3 无文件攻击 / 内存马

```bash
# memfd 无文件落地（文件不在磁盘上，只存在于内存）
ls -l /proc/[0-9]*/exe 2>/dev/null | grep -i memfd

# 异常的 rwx 匿名内存映射（注入的 shellcode）
grep -E "rwxp|rwx" /proc/[0-9]*/maps 2>/dev/null | head

# 打开着「已删除」文件的进程（loader 常驻的典型特征）
lsof 2>/dev/null | grep -i deleted
ls -l /proc/[0-9]*/fd 2>/dev/null | grep -i deleted
```

### 2.4 单进程深挖

```bash
PID=1234
ls -l /proc/$PID/exe                    # 可执行文件真实路径（进程删了文件也能看到）
ls -l /proc/$PID/cwd                    # 工作目录
ls -l /proc/$PID/root                   # 根目录视图
tr '\0' ' ' < /proc/$PID/cmdline; echo  # 完整启动参数
tr '\0' '\n' < /proc/$PID/environ       # 环境变量（查 LD_PRELOAD 注入）
cat /proc/$PID/maps                     # 内存映射（看加载的库和被注入的段）
cat /proc/$PID/status                   # 状态、父亲 PID、能力位
cat /proc/$PID/limits
cat /proc/$PID/mountinfo                # 挂载视图（容器逃逸痕迹）
ls -l /proc/$PID/fd                     # 打开的文件与 socket
lsof -p $PID
strace -f -p $PID                       # 系统调用跟踪（需先装 strace）
ltrace -p $PID
```

### 2.5 内核层与驱动

```bash
lsmod                                   # 内核模块列表
cat /proc/modules
modinfo 模块名
dmesg -T | tail -50                     # 模块加载报错、OOM killer
dmesg -T | grep -iE "taint|module|segfault"
cat /proc/kallsyms | wc -l              # 与已知基线对比

# eBPF 后门（现代 rootkit 新宠）
bpftool prog show 2>/dev/null
bpftool map show 2>/dev/null
cat /proc/sys/kernel/unprivileged_bpf_disabled

# 动态链接器劫持（最经典的 rootkit 手法）
cat /etc/ld.so.preload                  # 正常应为空或不存在！
env | grep -i LD_
cat /proc/1/environ | tr '\0' '\n' | grep -i LD_
ls -la /etc/ld.so.conf.d/ && cat /etc/ld.so.conf.d/*
ldd /usr/bin/ps
```

### 2.6 会话与终端

```bash
w                 # 在线用户 + 来源 IP + 当前执行的命令
who; who -a
users
ps -eo pid,ppid,user,tty,stat,lstart,cmd | grep -E "pts/|tty[0-9]"
ss -tnp | grep ":22"                    # 当前 SSH 连接
# 踢掉可疑会话：杀对应的 shell 进程，而不是杀 sshd 主进程
```

### 2.7 `/proc/PID` 全量取证字段速查

| 路径 | 作用 |
|---|---|
| `/proc/PID/exe` | 可执行文件真实路径。指向 `(deleted)` = 文件已删但进程仍活着 |
| `/proc/PID/cmdline` | 原始启动参数（`tr '\0' ' '` 后可读） |
| `/proc/PID/environ` | 环境变量（`LD_PRELOAD` / `LD_LIBRARY_PATH` 注入点） |
| `/proc/PID/cwd` | 工作目录 |
| `/proc/PID/root` | 进程视角的根目录（与 `/` 不一致 → 容器 / 挂载逃逸） |
| `/proc/PID/maps` | 内存映射（`rwx` 段、`memfd`、陌生 `.so`） |
| `/proc/PID/smaps` | maps 的详细版，含权限与共享情况 |
| `/proc/PID/status` | Uid / Gid / PPid / Threads / CapEff（能力位异常 = 提权痕迹） |
| `/proc/PID/syscall` | 当前正在执行的系统调用（多采几次能看出行为） |
| `/proc/PID/stack` | 内核态调用栈 |
| `/proc/PID/wchan` | 阻塞在哪个内核函数 |
| `/proc/PID/io` | 读写字节数（判断是否在扫盘 / 外传） |
| `/proc/PID/fd` | 打开的文件与 socket（`socket:[inode]` 用于反查连接） |
| `/proc/PID/ns/*` | 命名空间（与 PID 1 不一致 → 容器） |
| `/proc/PID/cgroup` | cgroup 归属 |
| `/proc/PID/attr/current` | SELinux / AppArmor 上下文 |
| `/proc/PID/mountinfo` | 挂载视图 |
| `/proc/PID/task/` | 线程列表（隐藏线程检测） |
| `/proc/PID/limits` | 资源限制 |

```bash
# 一次性抓全可疑进程的现场
PID=1234; D=/tmp/evidence/proc-$PID; mkdir -p "$D"
for f in status cmdline environ maps smaps syscall stack wchan io limits cgroup mountinfo "attr/current"; do
  cp "/proc/$PID/$f" "$D/$(echo "$f" | tr '/' '_')" 2>/dev/null
done
ls -l /proc/$PID/exe /proc/$PID/cwd /proc/$PID/root > "$D/links.txt" 2>&1
cp -a /proc/$PID/fd "$D/fd" 2>/dev/null
cat /proc/$PID/task/*/comm 2>/dev/null > "$D/threads.txt"

# 能力位异常：普通进程不该有 CAP_SYS_ADMIN / CAP_SYS_MODULE
grep -E "CapEff|CapBnd|CapPrm" /proc/$PID/status

# 判断是否运行在容器内
cat /proc/1/cgroup | head -3
ls -la /.dockerenv /run/.containerenv 2>/dev/null
```

### 2.8 会话工具与实时行为监控

```bash
# 攻击者常用的「抗断线」会话工具，是很常见的驻留形式
screen -ls; tmux ls
ls -la /tmp/.screen /tmp/tmux-* /run/screen /root/.tmux 2>/dev/null
ps aux | grep -E "screen|tmux|nohup|setsid"
find / -name "nohup.out" -ls 2>/dev/null          # 守护化残留

# 脱离终端的进程（tty 为 ?，且不是内核线程）
ps -eo pid,ppid,user,tty,stat,cmd | awk '$4=="?" && $6!~/^\[/'

# 实时行为监控（工具需提前准备）
sysdig -c topfiles_bytes                          # 谁在疯狂写盘
sysdig -c topconns                                # 谁在疯狂外连
sysdig -c spy_users                               # 谁在敲命令
sysdig "proc.name=sh and evt.type=execve"
osqueryi "select * from processes where on_disk=0;"    # 无文件进程
osqueryi "select * from listening_ports;"
osqueryi "select * from crontab;"

# auditd 命令执行审计（事后回溯最有力）
auditctl -a always,exit -F arch=b64 -S execve -k exec_track
aureport -x --summary
```

### 2.9 内存取证

```bash
# 完整内存镜像
avml /tmp/evidence/mem.lime                                 # 推荐：体积小、兼容性好
insmod lime.ko "path=/tmp/evidence/mem.lime format=lime"     # 传统方式
dd if=/dev/mem of=/tmp/evidence/mem.raw bs=1M 2>/dev/null    # 不可靠，仅备用

# 单进程内存 dump（快速初判）
gcore -o /tmp/evidence/core 1234                             # 依赖 gdb
cat /proc/1234/maps > /tmp/evidence/maps.txt
dd if=/proc/1234/mem of=/tmp/evidence/proc-mem.raw bs=1M 2>/dev/null

# 分析（volatility3）
vol -f mem.lime linux.pslist
vol -f mem.lime linux.pstree
vol -f mem.lime linux.netstat
vol -f mem.lime linux.bash            # 还原 bash 命令历史，即使文件已被删
vol -f mem.lime linux.malfind         # 直接定位注入的内存段
vol -f mem.lime linux.lsmod
vol -f mem.lime linux.check_syscall   # 系统调用表 hook 检测
```

> 内存是**唯一能还原「已删除文件」和「只在内存里运行的恶意代码」**的证据源。确认是高级威胁时，内存镜像优先级最高，务必在重启前做。

### 2.10 样本初判（轻量静态分析，先不上沙箱）

```bash
F=/tmp/evidence/sample

file $F                                    # 真实文件类型（识破改扩展名）
sha256sum $F                               # 先算哈希拿去情报平台比对，再决定是否深挖
strings -n 8 $F | head -100                # 提取可读字符串
strings -n 8 $F | grep -Ei "http|https|/dev/tcp|base64|chmod|curl|wget|\.onion|ssh-rsa"
readelf -h $F                              # ELF 头（架构、是否被 strip）
readelf -d $F | grep NEEDED                # 依赖库，异常依赖 = 可疑
objdump -d -M intel $F | head -80          # 反汇编入口
xxd $F | head -20                          # 十六进制头，判断是否加壳
upx -l $F 2>/dev/null                      # UPX 加壳检测
binwalk $F                                 # 内嵌文件 / 固件识别
yara -r /tmp/rules/malware_index.yar $F     # YARA 规则匹配
clamscan --infected $F
# 静态看不够就上沙箱：微步 / VirusTotal / ANY.RUN / 本地 CAPE
```

---

## 3. 持久化后门排查（核心）

> 攻防对抗里 80% 的驻留手段集中在这一节。原始手册只覆盖了 cron 和 systemd，遗漏了最高频的 **SSH 公钥后门**。

### 3.1 SSH 后门（最高频，必查）

```bash
# 所有用户的公钥，一把梭
find / -name "authorized_keys" -exec ls -l {} \; -exec echo "--- content ---" \; -exec cat {} \; 2>/dev/null

# 按 /etc/passwd 逐个用户家目录取
awk -F: '{print $6"/.ssh/authorized_keys"}' /etc/passwd | while read f; do
  [ -f "$f" ] && { echo "== $f ($(stat -c '%y' "$f"))"; cat "$f"; }
done

cat /root/.ssh/authorized_keys
cat /root/.ssh/known_hosts           # 出向连接的痕迹
ls -la ~/.ssh/ /home/*/.ssh/

# sshd 配置后门（ForceCommand / AuthorizedKeysCommand 是经典后门位）
grep -vE "^\s*#|^\s*$" /etc/ssh/sshd_config | grep -iE "Port|PermitRootLogin|AuthorizedKeys|ForceCommand|PermitUserEnvironment|AllowUsers|AllowGroups|Match|Subsystem|Banner|UsePAM"
ls -l --time-style=full-iso /etc/ssh/sshd_config
rpm -Vf /usr/sbin/sshd 2>/dev/null   # sshd 二进制是否被替换
```

### 3.2 账号后门

```bash
cat /etc/passwd
cat /etc/shadow                      # 需 root
awk -F: '$3==0{print $1}' /etc/passwd            # UID=0 的超级用户（应只有 root）
awk -F: '($3=="")||($3==0){print}' /etc/passwd   # UID 为空或 0
awk -F: '($2==""){print $1}' /etc/shadow         # 空密码账号（严重）
grep -vE "/sbin/nologin|/bin/false" /etc/passwd  # 有登录 shell 的账号
grep "^+" /etc/passwd                            # NIS 后门（+ 开头）
sort -t: -k3n /etc/passwd | awk -F: '{if($3==p)print prev"\n"$0;p=$3;prev=$0}'  # UID 重复
ls -l --time-style=full-iso /etc/passwd /etc/shadow /etc/group   # 修改时间是否异常

passwd -S 用户名        # 账号状态：L=锁定 P=正常 NP=空密码
chage -l 用户名         # 密码策略
lastlog                 # 每个账号最后一次登录（长期未登录却有活动 = 可疑）
lastlog -u 用户名
```

### 3.3 提权面（sudo / SUID / capabilities）

```bash
cat /etc/sudoers
ls -la /etc/sudoers.d/ && cat /etc/sudoers.d/*
sudo -l
grep -E "^(wheel|sudo|admin)" /etc/group

find / -xdev -perm -4000 -type f 2>/dev/null      # SUID
find / -xdev -perm -2000 -type f 2>/dev/null      # SGID
find / -xdev -perm -g=s -o -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null                            # capabilities（cap_setuid 等）
find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null   # 无主文件
```

### 3.4 计划任务

```bash
crontab -l                                        # 当前用户
crontab -l -u 用户名
# 遍历所有用户
for u in $(cut -d: -f1 /etc/passwd); do
  echo "===== $u ====="; crontab -l -u "$u" 2>/dev/null
done

cat /etc/crontab
ls -la /etc/cron.d/ && cat /etc/cron.d/*
ls -la /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/
cat /etc/anacrontab
ls -laR /var/spool/cron/                          # RHEL
ls -laR /var/spool/cron/crontabs/                 # Debian

atq; at -l                                        # 一次性任务（很隐蔽）
cat /etc/at.allow /etc/at.deny 2>/dev/null

grep -i cron /var/log/cron* | tail -50            # cron 执行日志
# 关注内容：curl|wget|base64|/dev/tcp|bash -i|python -c|nohup|/tmp 路径
```

### 3.5 开机自启与服务

```bash
systemctl list-unit-files --type=service --state=enabled
systemctl list-units --type=service --all
systemctl list-dependencies --reverse multi-user.target
systemctl get-default

# 重点：查看 unit 文件里的执行命令（后门藏在 ExecStart/ExecStopPost 等）
grep -rE "Exec(Start|Stop|Reload)(Pre|Post)?=" /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null \
  | grep -E "/tmp|/dev/shm|/var/tmp|/home|curl|wget|bash -c|nc |ncat|socat|base64"

# 最近新增/改动的 unit 文件 = 强线索
find /etc/systemd/system /usr/lib/systemd/system -type f -mtime -30 -printf "%T+ %p\n" 2>/dev/null | sort
ls -la /etc/systemd/system/multi-user.target.wants/
ls -la /etc/systemd/system/*.wants/
systemctl cat 服务名                              # 查看最终生效的 unit 内容

ls -l /etc/init.d/ /etc/rc.d/ /etc/rc*.d/
cat /etc/rc.local
systemctl status rc-local 2>/dev/null
ls -la /etc/init/                                 # Upstart（老系统）

# udev 规则后门（触发式执行，极隐蔽）
ls -la /etc/udev/rules.d/ && cat /etc/udev/rules.d/*.rules

# 用户级自启
ls -la ~/.config/autostart/ /home/*/.config/autostart/ 2>/dev/null
ls -laR ~/.config/systemd/user/ 2>/dev/null
```

### 3.6 Shell 配置文件后门

```bash
# 全量扫描登录脚本中的可疑内容
grep -rEn "curl|wget|base64|/dev/tcp|nc |socat|LD_PRELOAD|export PATH=|alias (ls|ps|netstat|ss|find|grep)" \
  /etc/profile /etc/profile.d/ /etc/bashrc /etc/bash.bashrc /etc/environment \
  /root/.bashrc /root/.bash_profile /root/.profile /home/*/.[a-z]*rc 2>/dev/null

cat /etc/profile.d/*.sh
ls -la /etc/profile.d/
cat /etc/motd /etc/issue                          # 横幅后门
ls -la /etc/update-motd.d/                        # 登录即执行的脚本
cat /etc/environment
lsattr -R /etc/profile.d/ 2>/dev/null | grep -i "i-"   # 被加不可变属性的文件
```

### 3.7 动态链接库劫持

```bash
cat /etc/ld.so.preload            # 正常为空！任何内容都高度可疑
ls -la /etc/ld.so.conf.d/ && cat /etc/ld.so.conf.d/*
find /lib /usr/lib /usr/local/lib -name "*.so*" -mtime -30 -ls 2>/dev/null
ldd /usr/bin/ls /usr/bin/ps
objdump -p /usr/bin/ls | grep NEEDED
```

### 3.8 PAM 后门（万能密码）

```bash
rpm -V pam 2>/dev/null            # RHEL：校验 PAM 模块完整性
dpkg -V libpam-modules 2>/dev/null
ls -l --time-style=full-iso /lib*/security/ /usr/lib*/security/
cat /etc/pam.d/sshd /etc/pam.d/system-auth /etc/pam.d/common-auth
# 辅助判断（特征字符串）
strings /lib*/security/pam_unix.so 2>/dev/null | grep -iE "backdoor|magic|hack|pam_passwd" 
```

### 3.9 其他驻留点

```bash
# 容器 / 编排
docker ps -a; docker images; ls -la /var/lib/docker 2>/dev/null
kubectl get pods -A 2>/dev/null
ls -la /var/run/docker.sock

# 版本控制 hooks（CI/CD 供应链投毒）
find / -path "*/.git/hooks/*" -type f ! -name "*.sample" -ls 2>/dev/null
ls -la /var/spool/at /var/spool/mail /var/spool/lpd 2>/dev/null

# 邮件别名 / 命令转发后门
cat /etc/aliases /etc/aliases.db 2>/dev/null
cat ~/.forward /root/.forward 2>/dev/null

# SSH 免密横向（拿到别的机器的钥匙）
find /home /root -name "id_rsa" -o -name "*.pem" -o -name "id_ed25519" 2>/dev/null
```

### 3.10 冷门启动位（最容易漏）

```bash
# XDG 自启（桌面环境、运维跳板机常见）
ls -la /etc/xdg/autostart/ /root/.config/autostart/ /home/*/.config/autostart/ 2>/dev/null
grep -h "^Exec=" /etc/xdg/autostart/*.desktop 2>/dev/null

# Bash 补全脚本（加载即执行，几乎没人查）
ls -la /etc/bash_completion.d/ /usr/share/bash-completion/completions/ 2>/dev/null
find /etc/bash_completion.d/ -type f -mtime -30 -exec ls -l {} \; 2>/dev/null

# SSH 登录即执行 —— 比 authorized_keys 更隐蔽
ls -la /root/.ssh/rc /home/*/.ssh/rc 2>/dev/null        # 登录时由 sshd 执行
grep -i "PermitUserRC" /etc/ssh/sshd_config
ls -la /root/.ssh/environment /home/*/.ssh/environment 2>/dev/null   # 配合 PermitUserEnvironment

# rc / profile 的延伸位置
ls -la /etc/bash.bashrc /etc/zsh/zshrc /etc/csh.cshrc /etc/csh.login 2>/dev/null
cat /etc/zsh/zshenv /etc/zsh/zprofile 2>/dev/null
ls -la ~/.bash_logout ~/.zlogout 2>/dev/null            # 注销时执行，反弹 shell 好位置

# cron 的 @reboot 与 deny 文件
grep -r "@reboot" /etc/crontab /etc/cron.d/ /var/spool/cron/ 2>/dev/null
cat /etc/cron.deny /etc/at.deny 2>/dev/null

# systemd 的其他触发方式（不只在开机时跑）
systemctl list-timers --all                             # 定时器，等价 cron，常被忽略
ls -la /etc/systemd/system/*.timer 2>/dev/null
grep -rhE "OnCalendar|OnBootSec|OnUnitActiveSec" /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null | sort -u | head -30
systemctl list-units --type=path                        # 路径触发：文件被访问时执行
systemctl list-units --type=socket                      # socket 激活
ls -la /etc/systemd/system/*.path /etc/systemd/system/*.socket 2>/dev/null

# 内核模块自动加载
cat /etc/modules /etc/modules-load.d/*.conf /etc/modprobe.d/*.conf 2>/dev/null

# 邮件到达触发（机器在收信时）
cat ~/.procmailrc /etc/procmailrc 2>/dev/null
cat /etc/aliases 2>/dev/null

# udev 触发（插入设备即执行）
grep -rhE "RUN\+?=|PROGRAM" /etc/udev/rules.d/ /lib/udev/rules.d/ 2>/dev/null | grep -E "/tmp|/dev/shm|bash|sh -c|curl|wget"
```

---

## 4. 用户账号与登录审计

### 4.1 在线与历史登录

```bash
w                       # 在线用户 + 正在做什么
who; who -a; who -b
last -a -i -F | head -50        # 登录成功记录（-i 显示来源 IP，-F 完整时间）
lastb -a -i -F | head -50       # 登录失败记录（暴力破解）
lastlog                         # 每个账号最后一次登录
```

### 4.2 登录日志

```bash
# RHEL/CentOS → /var/log/secure    Debian/Ubuntu → /var/log/auth.log
cat /var/log/secure | grep Accepted
cat /var/log/secure | grep Failed
grep -Ei "Accepted|Failed|Invalid user|Connection closed|maximum authentication" /var/log/secure*

# 按来源 IP 统计失败次数（识别爆破源）
grep "Failed password" /var/log/secure | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# 按成功登录来源统计（识别异常 IP 成功登录）
grep "Accepted" /var/log/secure | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn

# 公钥登录记录（配合 3.1 定位是哪个 key 进来的）
grep "Accepted publickey" /var/log/secure

# 账号变更操作（攻击者建号常用）
grep -E "useradd|usermod|userdel|groupadd|passwd|chpasswd" /var/log/secure*
grep -i sudo /var/log/secure*

# systemd 系统
journalctl -u sshd --since "7 days ago" --no-pager
journalctl _COMM=sshd --since today
journalctl -p err -b --no-pager          # 本次启动的所有错误

# auditd（有开启审计的情况，信息最全）
ausearch -m USER_LOGIN,USER_AUTH,USER_ACCT -ts recent
ausearch -m EXECVE -ts today | head -100
aureport -au --summary
aureport -l --summary
```

### 4.3 日志被清理的痕迹

```bash
ls -l --time-style=full-iso /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/secure
ls -la /var/log/ | awk '$5==0'                     # 0 字节的日志文件
journalctl --list-boots                            # 与文件日志对比，对不上就是被删过
grep -iE "history|logrotate|> /var/log|rm .*log" /*/.bash_history 2>/dev/null
cat /etc/logrotate.conf; cat /etc/logrotate.d/*    # 轮转配置被改 → 日志被定点清除
grep -vE "^\s*#|^\s*$" /etc/rsyslog.conf | grep -iE "^\*\.\*|@@|@"   # 日志被转发到外部
```

### 4.4 账号侧补充检查

```bash
# 历史密码哈希（改过密码会留痕）
cat /etc/security/opasswd 2>/dev/null

# 密码策略被改（爆破的前提条件）
grep -vE "^\s*#|^\s*$" /etc/login.defs
grep -E "pam_pwquality|pam_cracklib|minlen|remember|retry" /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null

# 失败锁定机制被关掉 = 为爆破铺路
faillock 2>/dev/null; faillock --user root 2>/dev/null
pam_tally2 --user root 2>/dev/null
cat /var/log/faillog 2>/dev/null

# 访问控制与信任关系
cat /etc/security/access.conf 2>/dev/null
cat /etc/security/limits.conf 2>/dev/null
cat /etc/security/time.conf 2>/dev/null
cat /etc/hosts.equiv ~/.rhosts /root/.rhosts /etc/ssh/shosts.equiv 2>/dev/null   # 信任关系后门

# sudo 痕迹：免密 sudo 是重点
grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
cat /var/log/sudo.log 2>/dev/null
journalctl _COMM=sudo --since "7 days ago" --no-pager
grep -i "sudo" /var/log/secure* 2>/dev/null

# su 使用记录
grep -i "su:" /var/log/secure* /var/log/auth.log* 2>/dev/null

# 账号 / 组变更的强证据：文件 mtime 与日志双验证
ls -l --time-style=full-iso /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers
grep -E "useradd|usermod|userdel|groupadd|groupmod|gpasswd|chpasswd|passwd" /var/log/secure* 2>/dev/null
```

### 4.5 SSH 公钥后门的高级特征

```bash
# 不只看「有没有陌生 key」，还要看选项滥用
for f in $(find / -name authorized_keys 2>/dev/null); do
  echo "===== $f ($(stat -c '%y %U:%G %a' "$f" 2>/dev/null)) ====="
  grep -vE "^\s*#|^\s*$" "$f"
done

# 高危选项：限定命令 = 后门专属 key，只能跑指定命令
for f in $(find / -name authorized_keys 2>/dev/null); do
  grep -HE 'command=|from=|no-pty|environment=|permitopen=' "$f" 2>/dev/null
done
# from="..."     限定来源 IP → 攻击者给自己留的专属通道
# command="..."  该 key 只能执行一条命令，常配合反弹 shell

# SSH CA 信任（一把钥匙开所有锁，极隐蔽）
grep -iE "TrustedUserCAKeys|AuthorizedPrincipalsFile|AuthorizedKeysCommand" /etc/ssh/sshd_config

# 客户端侧：出向免密（横向移动用的钥匙）
ls -la /root/.ssh/ /home/*/.ssh/ 2>/dev/null
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.key" 2>/dev/null | grep -vE "^/(usr|etc/ssl|opt/certs)"
cat ~/.ssh/config 2>/dev/null
wc -l < ~/.ssh/known_hosts 2>/dev/null      # 记录的内网主机数量，判断横向范围
```

---

## 5. 命令历史与操作痕迹

```bash
history                    # 注意：只有当前 shell 会话，且可能被 history -c 清过
cat /root/.bash_history
cat ~/.bash_history
find / -name ".bash_history" -exec ls -l --time-style=full-iso {} \; 2>/dev/null
find / -name ".bash_history" -exec sh -c 'echo "== {}"; tail -50 "{}"' \; 2>/dev/null

# 其他历史文件（攻击者常忘）
ls -la ~/ /root/ | grep -E "\.(bash_history|bash_sessions|zsh_history|sh_history|python_history|mysql_history|psql_history|viminfo|lesshst|wget-hsts)"
cat ~/.viminfo ~/.lesshst 2>/dev/null

# 历史记录是否被刻意关闭
grep -rE "HISTFILE|HISTSIZE|history -c|unset HIST" /etc/profile /etc/bashrc /root/.bashrc /home/*/.bashrc 2>/dev/null
cat /proc/$$/environ | tr '\0' '\n' | grep -i hist

# 若已配置 HISTTIMEFORMAT，history 才带时间，否则要靠 .bash_history 的 mtime 推断
echo 'export HISTTIMEFORMAT="%F %T "'   # 加固建议（事后）
```

**时间线构建**（应急分析的灵魂，别只靠 `find -mtime`）

```bash
# 文件系统时间线：指定时间窗口内被改动的文件，按时间排序
find / -xdev -newermt "2026-09-01" ! -newermt "2026-09-18" -type f -printf "%T+ %p\n" 2>/dev/null | sort | tail -200

# 基于 ctime（属性/权限变更）与 mtime 的差集，能抓到「时间戳伪造」
find / -xdev -type f \( -newerct "2026-09-17" \) ! \( -newermt "2026-09-17" \) 2>/dev/null | head -50

# 单文件三时间戳 + birth time
stat 文件名
stat -c '%n  mtime=%y  ctime=%z  birth=%w' 文件名

# 关键目录时间线（持久化点位最集中）
find /etc /var/spool/cron /etc/systemd /root /tmp /var/tmp -newermt "-7 days" -printf "%T+ %p\n" 2>/dev/null | sort
```

---

## 6. 文件系统与恶意文件排查

### 6.1 时间维度

```bash
find / -mtime -1 -type f 2>/dev/null                                  # 最近 24h 修改（原表格命令）
find / -xdev -mmin -60 -type f -ls 2>/dev/null                        # 最近 1h（应急时更快）
find / -xdev -type f -perm -u+x -mtime -7 -printf "%T+ %p\n" 2>/dev/null | sort   # 最近新增可执行
find / -mtime -1 -type f \( -name "*.sh" -o -name "*.elf" \)          # 原表格：近期脚本/ELF
```

### 6.2 位置维度（攻击者偏好目录）

```bash
ls -lat /tmp /var/tmp /dev/shm /run /run/lock
ls -lt /tmp /var/tmp
find /tmp /var/tmp /dev/shm /run -type f -mtime -7 -ls 2>/dev/null
find / -xdev -type f -name ".*" -mtime -30 -printf "%T+ %p\n" 2>/dev/null   # 近期出现的隐藏文件
find / -xdev -type d -name ".*" 2>/dev/null                                  # 隐藏目录
find / -name ".. *" 2>/dev/null                                              # 名字带空格伪装
```

### 6.3 权限维度

```bash
find / -perm -u+s -type f 2>/dev/null                # SUID（原表格命令）
find / -xdev -type f -perm -0002 2>/dev/null         # 全局可写文件
find / -xdev -type d -perm -0002 2>/dev/null         # 全局可写目录
getcap -r / 2>/dev/null
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null
lsattr -R /tmp /var/tmp /dev/shm 2>/dev/null | grep -i "i-"   # 被加不可变属性保护的恶意文件
```

### 6.4 完整性与 Rootkit 检测

```bash
# 软件包完整性校验 —— 判断系统二进制/配置是否被篡改的核心手段
rpm -Va 2>/dev/null | grep -vE "^\.{9}|/etc/(ssh|pam|sudoers|cron)"     # RHEL 全量
rpm -Va 2>/dev/null | grep -E "^..5|^S"                                  # 只看内容/大小变化的
rpm -Vf /usr/bin/ps /usr/bin/ls /usr/bin/netstat /usr/sbin/sshd          # 定向校验
debsums -c 2>/dev/null; dpkg -V 2>/dev/null                              # Debian
rpm -qf /usr/bin/ps                                                      # 反查文件属于哪个包

# Rootkit 专项扫描
chkrootkit -q
rkhunter --check --sk --nocolors
./unhide proc; ./unhide sys

# 恶意样本扫描
freshclam && clamscan -r -i /tmp /var/tmp /dev/shm /home /var/www
```

### 6.5 Web 目录与 Webshell

```bash
find /var/www /usr/share/nginx /usr/share/tomcat /home/*/public_html -type f -mtime -30 \
  \( -name "*.php" -o -name "*.jsp" -o -name "*.jspx" -o -name "*.war" -o -name "*.jar" \) -ls 2>/dev/null

grep -rEn "eval\(|assert\(|base64_decode|system\(|passthru|shell_exec|popen\(|Runtime\.getRuntime|ProcessBuilder" \
  --include="*.php" --include="*.jsp" --include="*.jspx" /var/www 2>/dev/null | head -50

ls -lat /var/www/html/uploads/ /var/www/html/upload/ 2>/dev/null    # 上传目录
find / -name "*.php" -newermt "-30 days" -ls 2>/dev/null
# 关注：文件名随机（1.php / a1b2c3.jsp）、内容极短、时间戳与站点发布节奏不符
```

### 6.6 数据库与中间件落地文件

```bash
# MySQL UDF 提权
ls -la /usr/lib/mysql/plugin/ /usr/lib64/mysql/plugin/
mysql -e "select * from mysql.func"
mysql -e "select * from information_schema.triggers"
mysql -e "select user,host,authentication_string from mysql.user"
cat /etc/my.cnf ~/.my.cnf 2>/dev/null

# Redis 未授权利用痕迹
ls -la /var/lib/redis/ /root/.ssh/authorized_keys /var/spool/cron/
redis-cli -h 127.0.0.1 info 2>/dev/null | head -20
```

### 6.7 磁盘与挂载

```bash
mount; cat /etc/fstab; cat /proc/mounts      # 异常挂载点 / 隐藏分区
lsblk; blkid; losetup -a                     # 异常回环设备
df -h; du -sh /tmp /var/tmp /dev/shm 2>/dev/null
```

### 6.8 文件真实类型与内容初判

```bash
# 改扩展名 / 无扩展名的恶意文件
find /tmp /var/tmp /dev/shm -type f -exec file {} \; 2>/dev/null | grep -iE "ELF|executable|shell script"
find / -xdev -type f -mtime -7 -size +100k -exec file {} \; 2>/dev/null | grep -i ELF | head -30

# 按内容特征全盘搜索（比按扩展名可靠）
grep -rlE "^#!/(bin|usr/bin)/(ba)?sh" /tmp /var/tmp /dev/shm 2>/dev/null
strings -n 10 /path/to/file | grep -Ei "http://|https://|/dev/tcp|base64|ssh-rsa|eval\("

# 大文件与近期大文件（隐藏数据 / 日志外带打包常用）
find / -xdev -type f -size +100M -ls 2>/dev/null | head -20
du -ah /tmp /var/tmp /dev/shm 2>/dev/null | sort -rh | head -20

# 短小但可执行的文件（dropper 典型特征）
find / -xdev -type f -perm -u+x -size -100k -mtime -7 -ls 2>/dev/null

# 硬链接异常（后门用硬链接做到「删了还在」）
find / -xdev -type f -links +1 -ls 2>/dev/null | head -30
```

### 6.9 被删文件与数据恢复

```bash
# 已删除但仍被进程占用（恶意 loader 的典型状态）
lsof +L1 2>/dev/null
lsof 2>/dev/null | grep -i deleted
find /proc/[0-9]*/fd -lname "*deleted*" -ls 2>/dev/null

# 从 /proc 拿回被删的二进制（黄金操作，先做）
cp /proc/PID/exe /tmp/evidence/recovered_binary 2>/dev/null

# ext 系列文件系统：恢复被删文件
debugfs -R "lsdel" /dev/sda1                        # 列出已删除 inode
debugfs -R "dump <inode> /tmp/evidence/recovered" /dev/sda1
extundelete /dev/sda1 --restore-all -o /tmp/evidence/
ext4magic /dev/sda1 -M -d /tmp/evidence/

# XFS / Btrfs
xfs_db -r -c "sb 0" -c "p uuid" /dev/sda1
btrfs restore /dev/sda1 /tmp/evidence/

# 提示：取证场景下，恢复操作要在镜像副本上做，别直接操作原盘
```

### 6.10 文件完整性监控（长期运营）

```bash
# 软件包基线比对：最实用的两条
rpm -Va 2>/dev/null | grep -v "^\.\{9\}"       # RHEL：只看有变化的
debsums -c 2>/dev/null                          # Debian

# AIDE：先建基线，之后定期比对，能发现静默篡改
aideinit && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check

# Tripwire
tripwire --init && tripwire --check

# osquery：把主机当数据库查，适合批量巡检
osqueryi "select * from file where path like '/tmp/%' and mtime > strftime('%s','now') - 86400;"
osqueryi "select * from suid_bin;"
osqueryi "select * from crontab;"
osqueryi "select * from authorized_keys;"
```

---

## 7. 日志审计

### 7.1 系统与 Web 日志基础检查

```bash
ls -la /var/log/
tail -100 /var/log/messages        # RHEL 系统日志
tail -100 /var/log/syslog          # Debian 系统日志
tail -100 /var/log/cron
tail -100 /var/log/maillog
journalctl --since today --no-pager
journalctl -p err --no-pager | tail -50

# Web 访问日志（攻击者打点入口）
tail -100 /var/log/nginx/access.log
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20
grep -iE "\.\./|%2e%2e|union.*select|<script|eval\(|/etc/passwd|cmd=|exec=" /var/log/nginx/access.log* | tail -30
grep -iE "sqlmap|nikto|nmap|masscan|gobuster|dirsearch|wpscan|curl/|python-requests" /var/log/nginx/access.log* | tail -30

# 内核与硬件
dmesg -T | tail -50
cat /var/log/dmesg 2>/dev/null

# 时间同步（时间被改 = 整条时间线失真）
timedatectl; chronyc tracking 2>/dev/null; ntpq -p 2>/dev/null
```

### 7.2 wtmp / btmp 原始解析（识别篡改）

```bash
utmpdump /var/log/wtmp          # 原始结构，能把记录被删/改的断裂看出来
utmpdump /var/log/btmp
utmpdump /var/log/lastlog       # 二进制 lastlog，附带可读时间

# 与 last / lastb 输出交叉验证，条数对不上 = 被动过
last -a -i -F | wc -l
utmpdump /var/log/wtmp | grep -c "USER_PROCESS"
```

### 7.3 journald 与日志完整性

```bash
journalctl --disk-usage
journalctl --list-boots                     # 启动次数，被人为 vacuum 过会出现缺口
journalctl -o json-pretty -n 20             # 含 _PID/_COMM/_EXE/_CMDLINE，比文本日志信息多
journalctl _PID=1234
journalctl -k -b -1                         # 上一次启动的内核日志

# journal 持久化是否被关（关掉后一重启就查不到历史）
grep -E "^\s*Storage=" /etc/systemd/journald.conf
ls -la /var/log/journal/ 2>/dev/null

# 日志被悄悄清理的迹象
ls -la /var/log/ | head -30
find /var/log -type f -size 0 2>/dev/null
ls -l --time-style=full-iso /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/secure /var/log/messages 2>/dev/null
```

### 7.4 auditd 配置与停用检测

```bash
systemctl status auditd                     # 被停掉本身就是高危信号
auditctl -s                                 # 审计系统运行状态
auditctl -l                                 # 当前生效规则（空 = 从未配置）
cat /etc/audit/audit.rules
cat /etc/audit/rules.d/*.rules 2>/dev/null
grep -vE "^\s*#|^\s*$" /etc/audit/auditd.conf
augenrules --check                          # 规则是否已持久化（重启后会丢的常见坑）

# 命令执行与账号变更的回溯
ausearch -i -m EXECVE -ts today | head -100 # -i 解释字段，可读性大幅提升
aureport -x --summary                       # 执行过的命令汇总（攻击者视角）
aureport -au --summary                      # 认证事件汇总
ausearch -i -k exec_track 2>/dev/null | head
```

### 7.5 日志转发与日志可信性

```bash
# 日志被转发到攻击者主机 → 你手里的日志就是假的
grep -vE "^\s*#|^\s*$" /etc/rsyslog.conf | grep -E "@|@@|omfwd"
ls -la /etc/rsyslog.d/ && cat /etc/rsyslog.d/*.conf 2>/dev/null
grep -rn "filesystem\|/dev/tcp\|@@" /etc/rsyslog.d/ 2>/dev/null
grep -rEi "logrotate" /etc/cron.d/ /etc/cron.daily/ 2>/dev/null   # 轮转被改 → 日志定点清除
```

---

## 8. 应用与中间件专项

> 主机侧应急不能只看系统层，绝大多数打点都发生在应用层。以下为高频入口的落地排查点。

### 8.1 XXL-JOB（Java 分布式任务调度，常见驻留点）

> XXL-JOB 若管理接口未授权或弱口令，攻击者可新增执行任务实现命令执行、后门驻留，是红蓝对抗常见打点驻留点位。

```bash
# 定位进程与部署目录
ps aux | grep -i xxl-job
find / -name "*xxl-job*.jar" 2>/dev/null

# 日志（默认路径，按实际部署调整）
ls -l /data/applogs/xxl-job/
tail -n 50 /data/applogs/xxl-job/xxl-job-admin.log

# 配置文件（获取数据库连接）
find / -name "application*.properties" 2>/dev/null | xargs grep -l "xxl.job" 2>/dev/null

# 拿到数据库权限后，查任务定义 / 执行历史 / 后台账号
mysql -e "select * from xxl_job_info;"      # 所有定时任务（找可疑的 GLUE 模式任务）
mysql -e "select * from xxl_job_log;"       # 任务执行历史
mysql -e "select * from xxl_job_user;"      # 后台账号（是否新增/弱口令）
mysql -e "select * from xxl_job_group;"     # 执行器（是否新增陌生机器）

# 检测管理端口（默认 8080/8081）
netstat -antp | grep java
ss -tlnp | grep java
```

### 8.2 其他高频入口速查

| 入口 | 排查点 |
|---|---|
| Redis 未授权 | `redis-cli info`、写 crontab/authorized_keys、`config get dir`、`keys *` |
| Nacos 未授权 | `/nacos/v1/auth/users` 新增用户、配置中植入脚本 |
| Spring Boot Actuator | `/actuator/env`、`/actuator/heapdump`、`/actuator/gateway` |
| Tomcat | `webapps/` 下新增 war、`conf/server.xml` 被改、manager 弱口令 |
| Jenkins | 脚本命令行痕迹、`/var/lib/jenkins/` 凭据、新增 job |
| WebLogic / JBoss | 反序列化 gadget 落地文件、`tmp/` 下上传 payload |
| Shiro / Fastjson / Log4j2 | 反序列化/JNDI 回连日志、`LDAP` 出向连接 |
| Docker API 未授权(2375) | `docker ps -a`、陌生容器挂载 `/`、`--privileged` |
| Kubernetes | 异常 Pod、`hostPath` 挂载 `/`、ServiceAccount token 窃取 |
| 文件上传 | upload 目录新增 `.jsp/.php/.sh`、大小与站点发布节奏不符 |

---

## 9. 处置与加固

> 处置前请确保证据已固定（见第 0 节）。

### 9.1 网络隔离

```bash
# 精准封禁来源 IP（-I 插到最前面，确保生效）
iptables -I INPUT -s 攻击IP -j DROP
iptables -A INPUT -s IP地址 -j DROP                 # 原表格命令
iptables -I OUTPUT -d C2_IP -j DROP                 # 封出向，切断回连
iptables -I INPUT -p tcp --dport 端口 -j DROP        # 封端口

# 持久化规则前先确认不会把自己锁在外面
iptables-save > /tmp/evidence/iptables.rules

# firewalld
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=攻击IP reject'
firewall-cmd --reload

# 断网（最彻底）
ip link set eth0 down

# 干掉已建立的异常连接（不用重启服务）
ss -K dst 攻击IP
fuser -k 8080/tcp
```

### 9.2 进程处置

```bash
# 顺序：取证 → 挂起 → 确认 → 结束
mkdir -p /tmp/evidence/proc_body
cp /proc/PID/exe /tmp/evidence/proc_body/ 2>/dev/null    # 留样本（可能因 deleted 失败）
cp /proc/PID/maps /tmp/evidence/proc_body/ 2>/dev/null
cat /proc/PID/cmdline | tr '\0' ' ' > /tmp/evidence/proc_body/cmdline.txt

kill -STOP 进程PID          # 先挂起，保留内存现场
kill -9 进程PID             # 原表格命令：强制结束
pkill -9 -f "特征字符串"     # 批量
```

### 9.3 账号处置

```bash
passwd -l 用户名                       # 原表格命令：锁定密码
usermod -L 用户名                       # 锁定
usermod -e 1 用户名                     # 设过期日期为 1970，彻底失效
usermod -s /sbin/nologin 用户名         # 禁用登录 shell
passwd 用户名                           # 改密码
# 清理后门公钥：编辑 ~/.ssh/authorized_keys，删除陌生 key
# 清理后门账号：删除 passwd/shadow/group 中对应行，并清理家目录
```

### 9.4 服务与启动项清理

```bash
systemctl stop 服务名 && systemctl disable 服务名
systemctl mask 服务名
rm -f /etc/systemd/system/恶意.service && systemctl daemon-reload
crontab -r -u 用户名                    # 慎用！先备份 crontab -l
rm -f /etc/cron.d/恶意任务
ipcrm -a                                # 清共享内存（如涉及）
```

### 9.5 文件处置

```bash
# 先打包留证，再删除
tar czf /tmp/evidence/malware.tar.gz /path/to/恶意文件
sha256sum 恶意文件 >> /tmp/evidence/hash.txt
# 冻结（防止攻击者回来改回去 / 保护关键配置）
chattr +i /etc/sudoers 2>/dev/null
# 删除
rm -f 恶意文件
```

### 9.6 加固与收尾

```bash
getenforce; sestatus 2>/dev/null; aa-status 2>/dev/null   # SELinux / AppArmor 是否被关
grep -vE "^\s*#|^\s*$" /etc/sysctl.conf                   # 内核参数是否被改
ss -tulnp                                                  # 复检端口
ls -la /etc/passwd /etc/shadow                             # 复检账号
find / -mtime -1 -type f 2>/dev/null | head               # 复检是否还有新文件落地
```

### 9.7 加固措施（处置后落地）

```bash
# SSH 加固 —— 先看当前生效值，再改配置
sshd -T | grep -E "permitrootlogin|passwordauthentication|maxauthtries|logingrace|allowusers|authorizedkeysfile"
# 建议项：
#   PermitRootLogin no
#   PasswordAuthentication no          （改用密钥）
#   MaxAuthTries 3
#   LoginGraceTime 30
#   AllowUsers 指定账号                 （白名单）
#   AuthorizedKeysFile 指向受控路径

# 爆破自动封禁
dnf install -y fail2ban 2>/dev/null || apt install -y fail2ban
systemctl enable --now fail2ban
fail2ban-client status sshd

# 命令执行审计（一旦再次驻留，回溯有据）
cat > /etc/audit/rules.d/blue-team.rules <<'EOF'
-a always,exit -F arch=b64 -S execve -k exec_track
-w /etc/passwd -p wa -k account_change
-w /etc/shadow -p wa -k account_change
-w /etc/sudoers -p wa -k sudo_change
-w /etc/ssh/sshd_config -p wa -k sshd_change
-w /etc/ld.so.preload -p wa -k ld_preload
-w /etc/cron.d -p wa -k cron_change
-w /var/spool/cron -p wa -k cron_change
-w /etc/systemd/system -p wa -k systemd_change
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_load
EOF
augenrules --load && auditctl -l | head

# 文件完整性基线
aideinit 2>/dev/null && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 内核参数加固（对照修改 /etc/sysctl.conf）
#   net.ipv4.ip_forward = 0
#   net.ipv4.conf.all.rp_filter = 1
#   fs.suid_dumpable = 0
#   kernel.dmesg_restrict = 1
#   kernel.kptr_restrict = 2
#   kernel.modules_disabled 慎用（开启后无法再加载任何模块）
sysctl -p

# 基线核查
lynis audit system --quick
```

**收尾清单**
1. 确认所有后门点位已清理（对照第 3 节逐项复核，不要只清发现的那一个）
2. 全量更新补丁，重置所有账号密码与密钥
3. 评估是否需要重装（内核级 rootkit 或数据已被完全掌控时，重装是唯一可靠选择）
4. 输出应急报告：时间线、攻击路径、影响范围、处置动作、加固建议

---

## 10. 一键排查脚本

```bash
#!/bin/bash
# linux-ir-quickcheck.sh —— 只读采集，不做任何处置动作
OUT="/tmp/ir-$(date +%Y%m%d%H%M%S)"
mkdir -p "$OUT"/{net,proc,persist,user,file,log}

echo "[*] 输出目录: $OUT"

# 1 网络
{ date; uptime; ip -br addr; ip route; ip neigh; cat /proc/sys/net/ipv4/ip_forward; } > "$OUT/net/basic.txt" 2>&1
ss -tulwnp > "$OUT/net/listen.txt" 2>&1
ss -tanp   > "$OUT/net/tcp.txt"    2>&1
{ iptables -L -n -v; iptables -t nat -L -n -v; } > "$OUT/net/iptables.txt" 2>&1
cp /proc/net/tcp /proc/net/udp /proc/net/raw "$OUT/net/" 2>/dev/null

# 2 进程
ps auxf > "$OUT/proc/ps.txt" 2>&1
ls -d /proc/[0-9]* | sed 's#/proc/##' | sort -n > "$OUT/proc/proc_pids.txt"
ps -eo pid --no-headers | tr -d ' ' | sort -n > "$OUT/proc/ps_pids.txt"
comm -23 "$OUT/proc/proc_pids.txt" "$OUT/proc/ps_pids.txt" > "$OUT/proc/HIDDEN_pids.txt"
ls -l /proc/[0-9]*/exe > "$OUT/proc/exe_links.txt" 2>/dev/null
lsmod > "$OUT/proc/lsmod.txt" 2>&1

# 3 持久化
systemctl list-unit-files --state=enabled > "$OUT/persist/systemd_enabled.txt" 2>&1
for u in $(cut -d: -f1 /etc/passwd); do echo "== $u"; crontab -l -u "$u" 2>/dev/null; done > "$OUT/persist/crontabs.txt"
cp /etc/crontab /etc/anacrontab "$OUT/persist/" 2>/dev/null
cp -a /etc/cron.d "$OUT/persist/" 2>/dev/null
find / -name "authorized_keys" -exec ls -l {} \; -exec cat {} \; > "$OUT/persist/authorized_keys.txt" 2>/dev/null
cp /etc/ssh/sshd_config "$OUT/persist/" 2>/dev/null
cat /etc/ld.so.preload > "$OUT/persist/ld_so_preload.txt" 2>&1

# 4 用户
cp /etc/passwd /etc/shadow /etc/group /etc/sudoers "$OUT/user/" 2>/dev/null
{ w; last -a -i -F | head -50; lastb -a -i -F | head -50; lastlog; } > "$OUT/user/logins.txt" 2>&1

# 5 文件
find / -xdev -perm -4000 -type f > "$OUT/file/suid.txt" 2>/dev/null
find / -xdev -mtime -3 -type f -printf "%T+ %p\n" 2>/dev/null | sort > "$OUT/file/recent.txt"
find /tmp /var/tmp /dev/shm -type f -ls > "$OUT/file/tmpdirs.txt" 2>/dev/null
getcap -r / > "$OUT/file/caps.txt" 2>/dev/null

# 6 日志
cp -a /var/log/secure* /var/log/auth.log* /var/log/messages* "$OUT/log/" 2>/dev/null

echo "[+] 采集完成: $OUT"
echo "[+] 重点检查: $OUT/proc/HIDDEN_pids.txt  (非空 = 存在隐藏进程)"
```

用法：`chmod +x linux-ir-quickcheck.sh && sudo ./linux-ir-quickcheck.sh`

---

## 附录 A：现场排查 Checklist

**0. 现场保护**
- [ ] 记录系统时间、运行时长、时区
- [ ] 确认处置策略（观察 / 断网 / 精准封禁）
- [ ] 固定最小证据包（进程、网络、账号、日志、历史命令）
- [ ] 准备 BusyBox 静态版等可信工具

**1. 网络**
- [ ] `ss -tulwnp` 监听端口逐条过一遍
- [ ] 外连公网 IP 聚合统计，确认无异常 C2
- [ ] `/proc/net/tcp` 与 `ss` 数量比对
- [ ] 路由 / ARP / 混杂模式 / ip_forward
- [ ] iptables 全表（含 nat 表）
- [ ] resolv.conf / hosts 是否被改

**2. 进程**
- [ ] `ps` 与 `/proc` 做隐藏进程差集
- [ ] 反弹 shell 特征串扫描
- [ ] tmp / dev/shm 路径的进程、deleted、memfd
- [ ] 内核模块 + eBPF + `ld.so.preload`

**3. 持久化（逐项过，不要跳）**
- [ ] 所有用户 `authorized_keys`
- [ ] `sshd_config` 异常项（ForceCommand / AuthorizedKeysCommand）
- [ ] UID=0、空密码、UID 重复账号
- [ ] sudoers / SUID / capabilities
- [ ] 全用户 crontab + cron.d/hourly/daily + anacron + at
- [ ] systemd unit 的 ExecStart / ExecStopPost
- [ ] profile / bashrc / motd / udev 规则
- [ ] PAM 模块完整性

**4. 账号与登录**
- [ ] `last` / `lastb` / `lastlog` 逐条看
- [ ] secure/auth.log 中 Accepted 与 Failed 的来源 IP
- [ ] 账号增删改记录
- [ ] 日志文件大小与时间是否正常

**5. 痕迹与文件**
- [ ] bash_history（含被清空/关闭的迹象）
- [ ] 文件三时间戳时间线，反查伪造
- [ ] SUID / 全局可写 / 无主文件
- [ ] `rpm -Va` / `debsums -c` 完整性
- [ ] Web 目录新增文件 + webshell 特征

**6. 处置**
- [ ] 证据已固定
- [ ] 后门点位已逐项复核（不只清发现的那一处）
- [ ] 隔离规则与账号处置已生效
- [ ] 复检：端口、账号、新增文件
- [ ] 输出应急报告

---

> 本项目仅用于授权环境下的安全学习与合规审计，禁止用于未授权的系统检测。
