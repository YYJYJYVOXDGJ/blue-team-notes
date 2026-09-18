# Linux 攻击手法与排查点映射（蓝队）

> 用法：现场拿到线索后，先在这里定位「这属于哪类手法、应该看哪里」，再跳到 [linux-host-audit.md](linux-host-audit.md) 对应章节精查。
>
> 核心思路：**不要从命令出发，要从攻击行为出发**。攻击者要落地，必然在系统里留下可观测的痕迹——找到痕迹与手法的对应关系，排查就有方向了。

## 目录

- [一、攻击链阶段与排查切入点](#一攻击链阶段与排查切入点)
- [二、ATT&CK for Linux 映射表](#二attck-for-linux-映射表)
- [三、权限维持手法一览（15 类）](#三权限维持手法一览15-类)
- [四、专项：挖矿](#四专项挖矿)
- [五、专项：勒索](#五专项勒索)
- [六、专项：反弹 Shell 与隧道代理](#六专项反弹-shell-与隧道代理)
- [七、专项：Web 应用打点](#七专项web-应用打点)
- [八、专项：横向移动](#八专项横向移动)
- [九、专项：痕迹清理与防御削弱](#九专项痕迹清理与防御削弱)
- [十、现象 → 手法 → 下一步 速查](#十现象--手法--下一步-速查)

---

## 一、攻击链阶段与排查切入点

| 阶段 | 攻击者做的事 | 本机留下的痕迹 | 主手册章节 |
|---|---|---|---|
| 侦察 | 端口扫描、服务识别 | `ss -tanp state syn-sent`、`/var/log/` 中大量连接、Web 日志中的扫描器 UA | 1.8、7 |
| 打点 | 利用 Web 漏洞 / 弱口令 / 未授权 | Web 日志中的恶意请求、上传目录新增文件、webshell | 6.5、7 |
| 执行 | 落地并运行 payload | `/tmp`、`/dev/shm` 下新文件、`bash -i`、`/dev/tcp`、`curl\|sh` | 2.2、6.2 |
| 提权 | SUID / sudo / 内核漏洞 / 配置错误 | SUID 新文件、`NOPASSWD`、内核模块、能力位异常 | 3.3、2.5 |
| 驻留 | 装后门、留持久化 | authorized_keys、cron、systemd、ld.so.preload、PAM | **第 3 节全节** |
| 横移 | 窃取凭据、横向连接 | `known_hosts` 增长、`id_rsa`、`sshpkt`、内网扫描、Ansible 等被滥用 | 4.5、1.2 |
| 外传 | 打包数据回传 | `tar`/`zip` 大文件、`/tmp` 中压缩包、异常外连大流量 | 1.2、6.8 |
| 清痕 | 删日志、清历史、改时间戳 | 0 字节日志、`history -c`、ctime 与 mtime 矛盾 | 5、7.1 |

**关键判据**：攻击链是**单向推进**的——发现后段痕迹（如驻留）时，前段（打点入口）一定存在。反过来，只清理驻留而不找到入口，攻击者会原路再进来。

---

## 二、ATT&CK for Linux 映射表

### 初始访问

| 技术 | 编号 | 本机落地痕迹 | 排查命令 |
|---|---|---|---|
| 利用公开应用 | T1190 | Web 日志异常请求、上传文件、中间件漏洞特征 | `grep -iE "union.*select\|\.\./\|cmd=" access.log` |
| 外部远程服务 | T1133 | VPN/SSH/RDP 端口的异常登录 | `grep "Accepted" /var/log/secure` |
| 有效账户 | T1078 | 合法账号在异常时间/来源登录 | `last -a -i -F`、`lastlog` |
| 暴力破解 | T1110 | `Failed password` 大量记录、faillock | `grep "Failed password" secure \| awk '{print $(NF-3)}' \| sort \| uniq -c \| sort -rn` |

### 执行

| 技术 | 编号 | 本机落地痕迹 | 排查命令 |
|---|---|---|---|
| 命令与脚本解释器 | T1059.004 | `bash -i`、`sh -c`、`python -c` 进程 | `ps aux \| grep -E "bash -i\|python -c\|perl -e"` |
| 计划任务 | T1053.003 | crontab 中的 `curl\|sh`、`@reboot` | 主手册 3.4 |
| at 任务 | T1053.002 | `atq` 输出 | `atq` |
| systemd 定时器 | T1053.006 | `.timer` unit 的 `OnCalendar` | `systemctl list-timers --all` |
| 事件触发执行 | T1546 | `~/.ssh/rc`、`bashrc`、`udev`、`motd` | 主手册 3.6、3.10 |
| 无文件执行 | T1620 | `memfd:`、`rwx` 匿名内存段、`deleted` | `ls -l /proc/*/exe \| grep memfd` |

### 持久化

| 技术 | 编号 | 本机落地痕迹 | 排查命令 |
|---|---|---|---|
| 创建/修改系统进程 | T1543.002 | 新增 systemd unit、`ExecStart` 指向 tmp | 主手册 3.5 |
| 开机自启 | T1547 | `/etc/rc.local`、`init.d`、XDG autostart | 主手册 3.5、3.10 |
| 内核模块 | T1547.006 | `lsmod` 中陌生模块 | `lsmod`、`/proc/modules` |
| 账户操纵 | T1098 | `authorized_keys` 被改、`sshd_config` 被改 | 主手册 3.1、4.5 |
| 创建账户 | T1136 | `/etc/passwd` 新增行、UID=0 | 主手册 3.2 |
| 服务器软件组件 | T1505.003 | Web 目录新增 php/jsp | 主手册 6.5 |

### 提权

| 技术 | 编号 | 本机落地痕迹 | 排查命令 |
|---|---|---|---|
| Setuid / Setgid | T1548.001 | 新增 SUID 文件、SUID 指向脚本 | `find / -perm -4000 -type f` |
| Sudo 滥用 | T1548.003 | `NOPASSWD` 条目 | `grep -rn NOPASSWD /etc/sudoers*` |
| 漏洞提权 | T1068 | 内核版本对应 EXP、`dmesg` 中 segfault | `uname -a`、`dmesg -T \| grep -i segfault` |
| 动态链接器劫持 | T1574.006 | `/etc/ld.so.preload` 非空、异常 `.so` | `cat /etc/ld.so.preload` |
| Rootkit | T1014 | `ps` 与 `/proc` 不一致、`rpm -Va` 报错 | 主手册 2.1、6.4 |
| 窃取凭据 | T1003.008 | `/etc/shadow` 被读取（audit 日志） | `ausearch -f /etc/shadow` |

### 防御规避与 C2

| 技术 | 编号 | 本机落地痕迹 | 排查命令 |
|---|---|---|---|
| 隐藏文件/目录 | T1564.001 | `.` 开头的近期文件、名字带空格 | 主手册 6.2 |
| 削弱防御 | T1562 | auditd / SELinux / 防火墙被停 | `systemctl status auditd`、`getenforce` |
| 清除日志 | T1070.002 | 日志 0 字节、journal 缺 boot | 主手册 7.1、7.2 |
| 清除命令历史 | T1070.003 | `HISTFILE=/dev/null`、`history -c` | 主手册第 5 节 |
| 时间戳伪造 | T1070.006 | ctime 与 mtime 矛盾 | `find / -newerct ... ! -newermt ...` |
| 非标准端口 | T1571 | 高端口监听 | `ss -tulnp` |
| 协议隧道 | T1572 | frp/ngrok/chisel/socat 进程 | 主手册 1.9 |
| 非应用层协议 | T1095 | `/proc/net/raw` 有连接、`tcpdump icmp` | `cat /proc/net/raw` |
| 代理 | T1090.003 | SSH `-D` socks、多级跳板 | `ps -eo cmd \| grep "ssh .*-D"` |
| 流量信令 | T1205 | 端口敲门、`nft`/`iptables` 中的 connlimit 规则 | `iptables-save` |

### 影响

| 技术 | 编号 | 本机落地痕迹 | 排查命令 |
|---|---|---|---|
| 资源劫持（挖矿） | T1496 | CPU 打满、矿池连接、`xmrig` | 见 [第四节](#四专项挖矿) |
| 数据加密（勒索） | T1486 | 文件批量改名、勒索信 | 见 [第五节](#五专项勒索) |
| 归档收集 | T1560 | `/tmp` 下的 `tar.gz`/`zip` | `find /tmp /var/tmp -name "*.tar*" -o -name "*.zip"` |

---

## 三、权限维持手法一览（15 类）

> 这一节是应急排查的**核对清单**。清后门最忌讳「只清发现的那一个」——必须逐类过一遍。

| # | 手法 | 落地点 | 一句话排查 |
|---|---|---|---|
| 1 | SSH 公钥后门 | 各用户 `~/.ssh/authorized_keys` | `find / -name authorized_keys -exec cat {} \;` |
| 2 | SSH 配置后门 | `sshd_config` 的 `ForceCommand`/`AuthorizedKeysCommand`；`~/.ssh/rc` | `grep -iE "ForceCommand\|AuthorizedKeysCommand" /etc/ssh/sshd_config` |
| 3 | cron 定时任务 | 全用户 crontab、`/etc/cron.d`、`@reboot` | `for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u; done` |
| 4 | at 一次性任务 | `atq` 队列、`/var/spool/at` | `atq` |
| 5 | systemd service | `/etc/systemd/system/*.service` 的 `ExecStart` | `grep -rE "Exec(Start\|Stop)(Pre\|Post)?=" /etc/systemd/system/` |
| 6 | systemd timer/path/socket | `*.timer`、`*.path`、`*.socket` | `systemctl list-timers --all`、`list-units --type=path` |
| 7 | init 脚本 | `/etc/init.d`、`/etc/rc.local`、`/etc/rc*.d` | `cat /etc/rc.local`、`ls -la /etc/rc*.d` |
| 8 | Shell 配置 | `/etc/profile.d`、`bashrc`、`bash_logout`、`bash_completion.d` | `grep -rE "curl\|wget\|/dev/tcp\|LD_PRELOAD" /etc/profile* /root/.bash*` |
| 9 | motd / 登录横幅 | `/etc/motd`、`/etc/update-motd.d/` | `ls -la /etc/update-motd.d/` |
| 10 | udev 规则 | `/etc/udev/rules.d/*.rules` 的 `RUN+=` | `grep -rE "RUN\+?=" /etc/udev/rules.d/` |
| 11 | PAM 后门 | `/lib*/security/pam_*.so` 被替换 | `rpm -V pam`、`dpkg -V libpam-modules` |
| 12 | 动态链接库劫持 | `/etc/ld.so.preload`、`/etc/ld.so.conf.d/` | `cat /etc/ld.so.preload` |
| 13 | 内核模块 / eBPF | `lsmod`、`bpftool prog show` | `lsmod`、`bpftool prog show` |
| 14 | 账号与提权面 | UID=0、空密码、`sudoers`、SUID、capabilities | `awk -F: '$3==0' /etc/passwd`、`getcap -r /` |
| 15 | 容器 / K8s 驻留 | DaemonSet、static Pod、kubelet 配置 | `kubectl get ds -A`、`ls /etc/kubernetes/manifests` |

---

## 四、专项：挖矿

### 落地痕迹

- **资源**：CPU 长期 100%（单核或全核），负载远高于业务基线
- **进程**：名字伪装成 `kworker`、`[kthreadd]`、`rsyslogd`、`systemd-*`、随机字符串；父进程常是 `sh`、`cron`、`nginx`
- **文件**：`/tmp`、`/dev/shm`、`/var/tmp` 下的 `xmrig`、`kdevtmpfsi`、`kinsing`、`systemd-*`
- **网络**：连矿池，常见端口 3333 / 4444 / 5555 / 7777 / 8888 / 14444 / 45700
- **持久化**：cron `@reboot`、`/etc/rc.local`、`ld.so.preload`（劫持 `top`/`ps` 隐藏自身）

### 排查命令

```bash
# 1) 谁在吃 CPU
ps aux --sort=-%cpu | head -15
top -b -n1 | head -20
pidstat 1 3 2>/dev/null

# 2) 可疑路径下的进程与文件
ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E "/tmp/|/dev/shm/|/var/tmp/(deleted)"
find /tmp /var/tmp /dev/shm -type f -mtime -30 -ls 2>/dev/null

# 3) 矿池连接
ss -tanp | grep -E ":(3333|4444|5555|7777|8888|14444|45700)\b"
ss -tanp state established | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head

# 4) 持久化四件套（挖矿必查这几处）
grep -r "@reboot" /etc/crontab /etc/cron.d/ /var/spool/cron/ 2>/dev/null
cat /etc/rc.local 2>/dev/null
cat /etc/ld.so.preload 2>/dev/null
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | grep -E "curl|wget|/dev/tcp"; done

# 5) 已知家族特征（YARA / 文件名 / 挖矿域名）
grep -rl "stratum+tcp\|xmrig\|kdevtmpfsi\|kinsing" /tmp /var/tmp /dev/shm /etc 2>/dev/null

# 6) 处置：先取证，再按依赖顺序清理
#    进程 → cron → 文件（chattr -i 解锁再删）→ 复检
```

### 常见误区

- 只 `kill` 进程 → cron 一分钟后拉起来
- 只清 cron → `ld.so.preload` 还在劫持 `ps`，你以为干净了
- 忘了 `/etc/rc.local` 和 `.so` 劫持 → 重启后复活

---

## 五、专项：勒索

### 落地痕迹

- **文件**：批量改扩展名（`.locked`、`.encrypted`、随机后缀）、目录下出现勒索信（`README.txt`、`HOW_TO_DECRYPT`）
- **资源**：加密阶段磁盘 IO 暴涨、CPU 高
- **行为**：删除快照/备份、`vssadmin` 类操作（Linux 上是 `rm` 备份目录）、停数据库服务
- **清痕**：日志被清空、`/var/log` 下文件 0 字节、历史命令被清

### 排查命令

```bash
# 1) 找勒索信与加密后缀
find / -xdev -maxdepth 4 -iname "*README*" -o -iname "*DECRYPT*" -o -iname "*RECOVER*" 2>/dev/null
find / -xdev -newermt "-24 hours" -type f -name "*.*" 2>/dev/null | \
  sed 's/.*\.//' | sort | uniq -c | sort -rn | head -20     # 后缀分布突变 = 被批量改名

# 2) 加密进程与 IO
ps aux --sort=-%cpu | head -10
iotop -oP 2>/dev/null | head -20
cat /proc/PID/io

# 3) 日志与备份是否被清
find /var/log -type f -size 0 2>/dev/null
ls -l --time-style=full-iso /var/log/ | head -30
ls -la /var/backups /backup /opt/backup 2>/dev/null
crontab -l | grep -i backup; ls /etc/cron.daily/

# 4) 定位加密开始时间点（决定恢复窗口）
find / -xdev -newermt "-48 hours" -type f -printf "%T@ %p\n" 2>/dev/null | sort -n | head -20

# 5) 判断是否还有进程持有未加密文件句柄（少数能救回文件的情况）
lsof 2>/dev/null | grep -i deleted
```

**处置原则**：勒索场景**优先止损与取证，不要急着删**。加密进程的内存里可能有密钥；日志是唯一能还原时间线的证据。先做内存镜像和日志备份，再谈阻断。

---

## 六、专项：反弹 Shell 与隧道代理

### 落地痕迹

| 特征 | 说明 |
|---|---|
| `/dev/tcp/`、`/dev/udp/` | bash 原生反弹，无外部工具 |
| `bash -i`、`sh -i` | 交互式 shell |
| `nc -e`、`ncat`、`socat` | 经典反弹工具 |
| `python -c "...socket..."`、`perl -e`、`php -r` | 脚本语言一句话反弹 |
| `mkfifo /tmp/f` | 命名管道构造双向通信 |
| `openssl s_client` | 加密反弹 |
| `-L`/`-R`/`-D`/`-N` 的 ssh 进程 | SSH 隧道 |

```bash
# 一句话扫全（反弹 shell 全家族）
ps aux | grep -Ei "bash -i|sh -i|/dev/tcp|/dev/udp|nc -e|ncat|socat|mkfifo|openssl s_client|python -c|perl -e|ruby -e|php -r|telnet"

# 父进程溯源：谁拉起的这个 shell
pstree -aps $(pgrep -f "bash -i")
cat /proc/PID/status | grep PPid

# 配对分析：一个 shell 进程必然对应一条网络连接
ls -l /proc/PID/fd | grep socket
```

### 隧道 / 代理工具家族

```bash
# 主流工具进程名
ps aux | grep -Ei "frpc|frps|ngrok|chisel|gost|regeorg|ew_for_linux|venom|nps|lcx|stowaway|iox|tun2socks|sshuttle|goproxy"

# 落地文件特征
find / -xdev -type f -size -20M -mtime -30 \( -name "*.conf" -o -name "*.ini" -o -name "*.toml" -o -name "*.json" \) \
  -exec grep -lE "server_addr|remote_port|token|tunnel|socks5" {} \; 2>/dev/null | head

# 内网扫描痕迹
ps aux | grep -Ei "nmap|masscan|fscan|gobuster|dirsearch|hydra|medusa|nc -zv"

# SOCKS 代理端口（动态转发）
ss -tlnp | grep -E ":1080|:1081|:7890|:7891|:10808|:10809"
```

---

## 七、专项：Web 应用打点

> 主机侧应急必须结合应用层。80% 的 Linux 失陷入口在 Web。

```bash
# 1) Web 根目录近期新增文件（webshell 主战场）
find /var/www /usr/share/nginx /usr/share/tomcat /home/*/public_html /opt/*/webapps \
  -type f -mtime -30 \( -name "*.php" -o -name "*.jsp" -o -name "*.jspx" -o -name "*.war" -o -name "*.py" -o -name "*.sh" \) -ls 2>/dev/null

# 2) 上传目录（时间戳与站点发布节奏不符）
ls -lat /var/www/html/uploads/ /var/www/html/upload/ /opt/tomcat/webapps/ROOT/ 2>/dev/null | head -30

# 3) 内容特征匹配
grep -rEn "eval\(|assert\(|base64_decode|system\(|passthru|shell_exec|popen\(|Runtime\.getRuntime|ProcessBuilder|define\(" \
  --include="*.php" --include="*.jsp" --include="*.jspx" /var/www 2>/dev/null | head -50

# 4) 中间件配置被改（Tomcat manager / php.ini auto_prepend_file）
grep -iE "auto_prepend_file|auto_append_file" /etc/php.ini /etc/php/*/php.ini 2>/dev/null
ls -la /opt/tomcat/conf/ 2>/dev/null

# 5) 访问日志里的攻击证据
grep -iE "\.\./|%2e%2e|union.*select|<script|eval\(|/etc/passwd|cmd=|exec=|base64" /var/log/nginx/access.log* 2>/dev/null | tail -30
grep -iE "sqlmap|nikto|nmap|gobuster|dirsearch|wpscan|python-requests|curl/" /var/log/nginx/access.log* 2>/dev/null | tail -30

# 6) 反序列化 / JNDI 回连（Log4j2、Fastjson、Shiro）
grep -rEi "ldap://|rmi://|jndi:" /var/log/**/*.log 2>/dev/null | head
ss -tanp | grep -E ":389|:1389|:1099"
```

---

## 八、专项：横向移动

```bash
# 1) 出向凭据与信任关系
ls -la /root/.ssh/ /home/*/.ssh/ 2>/dev/null
cat ~/.ssh/config 2>/dev/null
wc -l < ~/.ssh/known_hosts 2>/dev/null               # 内网主机数量的代理指标
find / -name "id_rsa" -o -name "*.pem" -o -name "*.key" 2>/dev/null | grep -vE "^/(usr|etc/ssl)"

# 2) 非交互式登录痕迹（脚本化横移）
grep -E "Accepted (publickey|password)" /var/log/secure* | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn

# 3) 运维工具被滥用（Ansible / Salt / SSH 批量）
ps aux | grep -Ei "ansible|ansible-playbook|salt-call|salt-minion|pssh|clush|pdsh|sshpass"
find / -name "*.yml" -path "*ansible*" -mtime -7 -ls 2>/dev/null

# 4) 数据库 / 中间件横向（Redis 写 key 到别的主机）
grep -rn "ssh-rsa\|crontab" /var/lib/redis/ /var/spool/cron/ 2>/dev/null | head
redis-cli -h 127.0.0.1 config get dir 2>/dev/null
redis-cli -h 127.0.0.1 config get dbfilename 2>/dev/null

# 5) 内网扫描痕迹
ss -tanp state syn-sent | head
conntrack -L 2>/dev/null | awk '{print $5}' | cut -d= -f2 | cut -d: -f1 | sort | uniq -c | sort -rn | head
```

---

## 九、专项：痕迹清理与防御削弱

### 痕证清理手法

| 手法 | 编号 | 痕迹 |
|---|---|---|
| 清系统日志 | T1070.002 | `/var/log` 下文件 0 字节、journal 缺 boot、wtmp 被 truncate |
| 清命令历史 | T1070.003 | `history -c`、`HISTFILE=/dev/null`、`unset HISTFILE`、`.bash_history` 为空但文件 mtime 新 |
| 删文件 | T1070.004 | `(deleted)` 句柄、`/proc/PID/exe` 指向已删文件 |
| 时间戳伪造 | T1070.006 | `ctime` 比 `mtime` 新很多；`touch -r` 会把 atime/mtime 改成参考文件的值 |
| 安全擦除 | — | `shred`、`dd if=/dev/zero` 的使用记录 |

```bash
# 历史文件被清但 mtime 很新 → 强烈可疑
find / -name ".bash_history" -newermt "-3 days" -size -1k -ls 2>/dev/null

# 时间戳矛盾检测（ctime 晚于 mtime 说明属性被人为改过）
find / -xdev -type f -newerct "2026-09-01" ! -newermt "2026-09-01" -printf "%p ctime=%Tc\n" 2>/dev/null | head -30

# 日志被清的证据
find /var/log -type f -size 0 -ls 2>/dev/null
journalctl --list-boots        # boot 序列出现缺口 = 被人为 vacuum
```

### 防御削弱手法

```bash
# 安全组件被关停
systemctl is-active auditd fail2ban firewalld 2>/dev/null
systemctl is-enabled auditd fail2ban firewalld 2>/dev/null
getenforce; aa-status 2>/dev/null | head -3

# EDR / 云镜 / 安全 agent 被停或卸载
ps aux | grep -Ei "edr|hids|aegis|barad|qcloud|aliyun-service|falcon|osquery|wazuh" | grep -v grep
systemctl list-units --all | grep -Ei "edr|hids|aegis|barad|falcon"

# 防火墙被清空
iptables -L -n | head -5
iptables -t nat -L -n | head -5
nft list ruleset 2>/dev/null | head

# auditd 规则被删
auditctl -l
ls -la /etc/audit/rules.d/ 2>/dev/null
```

> 安全组件被关停本身就是**高危信号**——正常运维不会静默停掉 auditd 和防火墙。发现即视为已失陷。

---

## 十、现象 → 手法 → 下一步 速查

| 你看到的现象 | 最可能的手法 | 下一步 |
|---|---|---|
| CPU 打满、负载异常 | 挖矿（T1496） | [第四节](#四专项挖矿) |
| 文件被批量改名 + 勒索信 | 勒索（T1486） | [第五节](#五专项勒索) |
| `ps` 结果与 `/proc` 数量不符 | Rootkit（T1014） | 主手册 2.1、6.4 |
| 某进程指向 `(deleted)` | 无文件/loader（T1620） | 主手册 2.3、6.9 |
| 高端口监听 + 非业务进程 | 隧道/代理（T1572） | 主手册 1.9 |
| 新建 UID=0 账号 | 账户操纵（T1098） | 主手册 3.2、4.4 |
| `authorized_keys` 出现陌生 key | SSH 公钥后门（T1098） | 主手册 3.1、4.5 |
| cron 里有 `curl \| sh` | 计划任务驻留（T1053.003） | 主手册 3.4 |
| `/etc/ld.so.preload` 非空 | 链接器劫持（T1574.006） | 主手册 2.5、3.7 |
| `sshd_config` 有 `ForceCommand` | SSH 配置后门（T1546） | 主手册 3.1 |
| 日志 0 字节 / journal 缺 boot | 清痕（T1070.002） | 主手册 7.1、7.2 |
| auditd / SELinux 被停 | 削弱防御（T1562） | [第九节](#九专项痕迹清理与防御削弱) |
| Web 目录新增随机名文件 | Webshell（T1505.003） | [第七节](#七专项web-应用打点) |
| 内网出现大量短连接 | 横向扫描 | [第八节](#八专项横向移动) |
| 无扩展名 ELF 在 `/dev/shm` | 无文件植入 | 主手册 2.3、6.8 |
| 时间戳 ctime 与 mtime 矛盾 | 时间戳伪造（T1070.006） | 主手册第 5 节 |

---

> 本项目仅用于授权环境下的安全学习与合规审计，禁止用于未授权的系统检测。
