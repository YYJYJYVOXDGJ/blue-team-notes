# Linux 主机安全基线核查与加固

> 定位：与 [linux-host-audit.md](linux-host-audit.md)（应急排查）互补。排查是「已经出事了，找痕迹」；基线核查是「还没出事，找可被利用的面」。
>
> 适用场景：主机安全评估、攻防演习赛前基线巡检、常态化安全运营、应急处置后的加固收口。
>
> 风险等级：**高** = 可直接导致失陷或提权；**中** = 显著扩大攻击面；**低** = 纵深防御项。

---

## 一、账号与认证

| 检查项 | 核查命令 | 合格标准 | 风险 |
|---|---|---|---|
| 除 root 外无 UID=0 账号 | `awk -F: '$3==0{print $1}' /etc/passwd` | 仅输出 `root` | 高 |
| 无空密码账号 | `awk -F: '($2==""){print $1}' /etc/shadow` | 无输出 | 高 |
| 无 UID 重复 | `cut -d: -f3 /etc/passwd \| sort \| uniq -d` | 无输出 | 高 |
| 服务账号不可登录 | `grep -vE "/sbin/nologin\|/bin/false" /etc/passwd` | 仅有人工账号 | 中 |
| 敏感文件权限 | `stat -c '%a %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers` | passwd/group 644；shadow/gshadow 000；sudoers 440 | 高 |
| 密码策略 | `grep -E "PASS_MAX_DAYS\|PASS_MIN_LEN\|PASS_WARN_AGE" /etc/login.defs` | MAX≤90、MIN_LEN≥10、WARN≥7 | 中 |
| 密码复杂度 | `grep -E "minlen\|dcredit\|ucredit\|ocredit\|lcredit" /etc/pam.d/system-auth /etc/pam.d/common-password` | 已启用 pwquality/cracklib | 中 |
| 历史密码限制 | `grep remember /etc/pam.d/system-auth /etc/pam.d/common-password` | remember≥5 | 低 |
| 失败锁定 | `grep -E "deny\|unlock_time" /etc/pam.d/system-auth /etc/pam.d/common-auth` | deny≤5，unlock_time≥300 | 中 |
| 上次登录提示 | `grep pam_lastlog /etc/pam.d/system-auth /etc/pam.d/login` | 已启用 | 低 |
| 无多余账号 | `lastlog \| awk 'NR>1 && $2=="**Never"'` | 无长期空置账号 | 低 |
| 信任关系文件 | `ls -la /etc/hosts.equiv ~/.rhosts /root/.rhosts 2>/dev/null` | 均不存在 | 高 |
| su 限制 | `grep -E "^auth\|^account" /etc/pam.d/su \| grep pam_wheel` | 仅 wheel 组可 su | 中 |

```bash
# 一键核查账号面
echo "== UID=0 账号 ==";      awk -F: '$3==0{print $1}' /etc/passwd
echo "== 空密码账号 ==";      awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null
echo "== 可登录账号 ==";      grep -vE "/sbin/nologin|/bin/false" /etc/passwd
echo "== sudo 权限 ==";       grep -rnE "NOPASSWD|ALL=\(ALL\)" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
echo "== 关键文件权限 ==";    stat -c '%a %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers 2>/dev/null
```

---

## 二、SSH 服务

| 检查项 | 核查命令 | 合格标准 | 风险 |
|---|---|---|---|
| root 禁止登录 | `sshd -T \| grep permitrootlogin` | `no` | 高 |
| 禁用密码认证 | `sshd -T \| grep passwordauthentication` | `no`（全量密钥） | 高 |
| 禁止空密码 | `sshd -T \| grep permitemptypasswords` | `no` | 高 |
| 认证尝试次数 | `sshd -T \| grep maxauthtries` | ≤4 | 中 |
| 登录宽限期 | `sshd -T \| grep logingrace` | ≤60 | 低 |
| 账号白名单 | `sshd -T \| grep -E "allowusers\|allowgroups"` | 已配置 | 中 |
| X11 转发关闭 | `sshd -T \| grep x11forwarding` | `no` | 低 |
| TCP 转发限制 | `sshd -T \| grep -E "allowtcpforwarding\|allowagentforwarding"` | 非必需则 `no` | 中 |
| 认证密钥路径受控 | `sshd -T \| grep authorizedkeysfile` | 非 `/tmp` 等可写目录 | 高 |
| 会话超时 | `sshd -T \| grep -E "clientalive"` | interval>0 且 countmax≤3 | 低 |
| 日志级别 | `sshd -T \| grep loglevel` | `VERBOSE` 或 `INFO` | 低 |
| 无后门指令 | `grep -iE "ForceCommand\|AuthorizedKeysCommand\|PermitUserRC\|TrustedUserCAKeys" /etc/ssh/sshd_config` | 无（除非业务必需） | 高 |
| 配置与密钥权限 | `stat -c '%a %n' /etc/ssh/sshd_config /etc/ssh/ssh_host_*_key` | 配置 600，私钥 600 | 中 |
| 端口非默认（可选） | `sshd -T \| grep "^port"` | 非 22 可降低扫描噪音 | 低 |

```bash
# 核查当前生效的 SSH 配置（比读配置文件可靠，包含默认值与 Include）
sshd -T | grep -E "permitrootlogin|passwordauthentication|permitemptypasswords|maxauthtries|x11forwarding|authorizedkeysfile|allowtcpforwarding|clientalive"
```

---

## 三、日志与审计

| 检查项 | 核查命令 | 合格标准 | 风险 |
|---|---|---|---|
| rsyslog 运行 | `systemctl is-active rsyslog` | active | 中 |
| auditd 运行 | `systemctl is-active auditd` | active | 高 |
| auditd 有规则 | `auditctl -l \| wc -l` | >0，且含关键文件监控 | 高 |
| audit 规则已持久化 | `augenrules --check` | 已加载 | 中 |
| journald 持久化 | `grep "^Storage" /etc/systemd/journald.conf` | `persistent` | 中 |
| 日志文件权限 | `stat -c '%a %n' /var/log/secure /var/log/messages /var/log/audit/audit.log` | 600 或 640 | 中 |
| 日志轮转配置 | `ls -la /etc/logrotate.d/` | 关键日志均有配置 | 低 |
| 日志远程备份 | `grep -E "@\|@@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf` | 已转发到独立日志服务器 | 中 |
| 无异常转发 | `grep -rnE "omfwd\|/dev/tcp" /etc/rsyslog*` | 无指向陌生地址的规则 | 高 |
| 日志无空文件 | `find /var/log -type f -size 0` | 无异常空文件 | 中 |
| 时间同步 | `timedatectl \| grep -i "synchronized"` | yes | 中 |

```bash
# 推荐的审计规则（与主手册 9.7 一致）
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
```

---

## 四、文件权限与完整性

| 检查项 | 核查命令 | 合格标准 | 风险 |
|---|---|---|---|
| SUID/SGID 基线 | `find / -xdev -perm -4000 -type f` | 与基线清单一致，无新增 | 高 |
| 无全局可写文件 | `find / -xdev -type f -perm -0002 ! -path "/proc/*"` | 无（或极少且合理） | 高 |
| 无全局可写目录 | `find / -xdev -type d -perm -0002 ! -type l` | 仅 `/tmp` `/var/tmp` 且带 sticky | 高 |
| /tmp 带 sticky bit | `stat -c '%a %n' /tmp /var/tmp` | 1777 | 中 |
| 无主/无组文件 | `find / -xdev \( -nouser -o -nogroup \)` | 无输出 | 中 |
| 默认 umask | `grep -r umask /etc/profile /etc/bashrc /etc/login.defs` | 027 或 022 | 低 |
| capabilities | `getcap -r / 2>/dev/null` | 与基线一致，无 `cap_setuid+ep` 类异常 | 高 |
| 软硬链接异常 | `find / -xdev -type l -mtime -30 -ls` | 无指向敏感路径的新链接 | 中 |
| 关键目录不可写 | `ls -ld /etc /bin /sbin /usr/bin` | root 所有，其他无写权限 | 高 |
| 完整性基线 | `aide --check` / `rpm -Va` / `debsums -c` | 无异常变更 | 高 |
| 隐藏属性滥用 | `lsattr -R /tmp /var/tmp 2>/dev/null \| grep "i-"` | 无恶意不可变文件 | 中 |

```bash
# SUID/SGID 基线留存（后续比对用）
find / -xdev -perm -4000 -type f -exec ls -l {} \; 2>/dev/null | sort > /var/lib/blue-team/suid-baseline.txt
find / -xdev -perm -2000 -type f -exec ls -l {} \; 2>/dev/null | sort > /var/lib/blue-team/sgid-baseline.txt
getcap -r / 2>/dev/null | sort > /var/lib/blue-team/caps-baseline.txt

# 后续比对
diff <(find / -xdev -perm -4000 -type f -exec ls -l {} \; 2>/dev/null | sort) /var/lib/blue-team/suid-baseline.txt
```

---

## 五、服务、端口与网络

| 检查项 | 核查命令 | 合格标准 | 风险 |
|---|---|---|---|
| 最小化监听 | `ss -tulnp` | 仅业务必需端口 | 高 |
| 管理端口不对外 | `ss -tuln \| grep -E "0\.0\.0\.0:(3306\|6379\|9200\|27017\|2375\|8080)"` | 无输出 | 高 |
| 防火墙启用 | `systemctl is-active firewalld \|\| systemctl is-active ufw \|\| iptables -L -n \| wc -l` | 已启用且有规则 | 高 |
| 无明文协议服务 | `systemctl list-unit-files \| grep -E "telnet\|rsh\|rlogin\|vsftpd\|tftp"` | 均未启用 | 高 |
| 不必要服务已关 | `systemctl list-unit-files --state=enabled` | 无 legacy/无用服务 | 中 |
| IP 转发关闭 | `sysctl net.ipv4.ip_forward` | 0（非路由/容器主机） | 中 |
| 无异常路由 | `ip route` | 仅默认网关与内网段 | 中 |
| NTP 已同步 | `timedatectl`、`chronyc tracking` | 已同步 | 中 |
| DNS 配置可信 | `cat /etc/resolv.conf` | 仅内网/可信 DNS | 中 |
| hosts 无异常 | `cat /etc/hosts` | 无陌生解析 | 中 |
| 混杂模式关闭 | `ip link \| grep -i promisc` | 无输出 | 中 |
| Docker API 未暴露 | `ss -tuln \| grep 2375` | 无输出 | 高 |

---

## 六、内核参数

```bash
# 逐项核查（对照右侧合格值）
sysctl -n net.ipv4.ip_forward                    # 0
sysctl -n net.ipv4.conf.all.rp_filter            # 1
sysctl -n net.ipv4.conf.all.accept_source_route  # 0
sysctl -n net.ipv4.conf.all.accept_redirects     # 0
sysctl -n net.ipv4.conf.all.send_redirects       # 0
sysctl -n net.ipv4.icmp_echo_ignore_broadcasts   # 1
sysctl -n net.ipv4.conf.all.log_martians         # 1
sysctl -n net.ipv4.tcp_syncookies                # 1
sysctl -n kernel.randomize_va_space              # 2
sysctl -n kernel.dmesg_restrict                  # 1
sysctl -n kernel.kptr_restrict                   # 2
sysctl -n fs.suid_dumpable                       # 0
sysctl -n kernel.core_pattern                    # 非可写目录中的管道
sysctl -n kernel.yama.ptrace_scope               # 1 或 2
sysctl -a 2>/dev/null | grep -c "bpf"            # 关注 unprivileged_bpf_disabled
```

```bash
# 加固模板，写入 /etc/sysctl.d/99-blue-team.conf 后 sysctl --system
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
kernel.yama.ptrace_scope = 1
```

> `kernel.modules_disabled = 1` 能彻底封死 LKM rootkit，但开启后**无法再加载任何内核模块**（含新硬件驱动、容器相关模块）。只在明确不需要动态加载模块的专用主机上使用，且必须先确认现有模块已全部加载。

---

## 七、SELinux / AppArmor

```bash
# SELinux
getenforce                                  # 合格：Enforcing
sestatus                                    # 详细状态
grep "^SELINUX=" /etc/selinux/config         # 合格：enforcing（不是 permissive/disabled）
semanage login -l 2>/dev/null
ls -Z /tmp /var/www 2>/dev/null | head       # 上下文是否正确
ausearch -m AVC -ts recent 2>/dev/null | head    # 近期拒绝记录

# AppArmor
aa-status 2>/dev/null
systemctl is-active apparmor
```

> `getenforce` 返回 `Disabled` 且 `/etc/selinux/config` 里也是 `disabled`，要么是安装时就没开，要么是**被人为关掉的**——后者是高危信号，结合 `ausearch` 或命令历史确认。

---

## 八、补丁与软件

```bash
uname -a; cat /etc/os-release
rpm -q kernel --last | head          # 当前内核与已装内核
yum check-update 2>/dev/null | tail -20
apt list --upgradable 2>/dev/null | head -20

# 关键组件版本
openssh-server --version 2>/dev/null || rpm -q openssh-server
nginx -v 2>&1; httpd -v 2>&1; java -version 2>&1 | head -1
docker version 2>/dev/null | head -3
openssl version
```

**关注点**：内核提权漏洞（Dirty Pipe / PwnKit / Looney Tunables 等）取决于内核与 `polkit`/`glibc` 版本；对外开放服务的中间件版本（Log4j2、Fastjson、Spring、Shiro、Weblogic）是打点主入口。

---

## 九、定时任务与自启

| 检查项 | 核查命令 | 合格标准 | 风险 |
|---|---|---|---|
| 全用户 crontab 已知 | `for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u; done` | 与基线一致，无 `curl\|sh` | 高 |
| 系统 cron 已知 | `cat /etc/crontab; ls -la /etc/cron.d/` | 与基线一致 | 高 |
| systemd 自启已知 | `systemctl list-unit-files --state=enabled` | 与基线一致 | 高 |
| unit 执行路径可信 | `grep -rE "ExecStart=" /etc/systemd/system/ \| grep -E "/tmp\|/dev/shm\|/var/tmp"` | 无输出 | 高 |
| 定时器已知 | `systemctl list-timers --all` | 与基线一致 | 中 |
| rc.local 已知 | `cat /etc/rc.local 2>/dev/null` | 空或仅业务必需 | 中 |
| profile 脚本干净 | `grep -rE "curl\|wget\|/dev/tcp\|LD_PRELOAD" /etc/profile.d/ /etc/bashrc` | 无输出 | 高 |
| udev 规则干净 | `grep -rE "RUN\+?=" /etc/udev/rules.d/` | 与基线一致 | 中 |
| ld.so.preload 为空 | `cat /etc/ld.so.preload` | 空或不存在 | 高 |

---

## 十、容器与虚拟化

```bash
# Docker
docker version 2>/dev/null | head -3
ss -tuln | grep 2375                                  # 未认证 API 暴露 = 高危
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}'
docker ps -q | xargs -r docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}}' 2>/dev/null
ls -la /var/run/docker.sock                            # 权限是否为 docker 组

# Kubernetes
kubectl get nodes 2>/dev/null
kubectl get pods -A -o wide 2>/dev/null | head -20
kubectl get ds -A 2>/dev/null                          # DaemonSet 是容器驻留首选
ls -la /etc/kubernetes/manifests/                      # static Pod 后门
grep -E "anonymous-auth|authorization-mode" /var/lib/kubelet/config.yaml 2>/dev/null
# 期望：anonymous-auth: false，authorization-mode 含 Webhook 或 RBAC

# 是否运行在容器中
cat /proc/1/cgroup | head -3
ls -la /.dockerenv /run/.containerenv 2>/dev/null
capsh --print 2>/dev/null | head -5
```

**重点**：`--privileged`、`-v /:/host`、`hostPID`/`hostNetwork`、`hostPath` 挂载 `/` 的 Pod 都等于给攻击者一条逃逸路径。

---

## 附：一键基线核查脚本

```bash
#!/bin/bash
# linux-baseline-check.sh —— 只读核查，输出问题清单
OUT="/tmp/baseline-$(date +%Y%m%d%H%M%S).txt"
exec > >(tee "$OUT") 2>&1

echo "===== Linux 基线核查 $(date) ====="

echo; echo "## 1 账号与认证"
echo "-- 非 root 的 UID=0 账号（应为空）:"
awk -F: '$3==0 && $1!="root"{print "  [!] "$1}' /etc/passwd
echo "-- 空密码账号（应为空）:"
awk -F: '($2==""){print "  [!] "$1}' /etc/shadow 2>/dev/null
echo "-- UID 重复（应为空）:"
cut -d: -f3 /etc/passwd | sort | uniq -d | sed 's/^/  [!] UID /'
echo "-- 可登录账号:"
grep -vE "/sbin/nologin|/bin/false" /etc/passwd | awk -F: '{print "  "$1" shell="$7}'
echo "-- 关键文件权限:"
stat -c '  %a %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null
echo "-- NOPASSWD sudo（关注）:"
grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | sed 's/^/  [!] /'

echo; echo "## 2 SSH"
sshd -T 2>/dev/null | grep -E "permitrootlogin|passwordauthentication|permitemptypasswords|maxauthtries|authorizedkeysfile" | sed 's/^/  /'
echo "-- 后门指令（应为空）:"
grep -iE "ForceCommand|AuthorizedKeysCommand|TrustedUserCAKeys|PermitUserRC" /etc/ssh/sshd_config 2>/dev/null | sed 's/^/  [!] /'

echo; echo "## 3 日志与审计"
echo "  rsyslog: $(systemctl is-active rsyslog 2>/dev/null)"
echo "  auditd:  $(systemctl is-active auditd 2>/dev/null)"
echo "  audit 规则数: $(auditctl -l 2>/dev/null | wc -l)"
echo "  空日志文件:"
find /var/log -type f -size 0 2>/dev/null | sed 's/^/  [!] /'

echo; echo "## 4 文件权限"
echo "-- SUID 数量: $(find / -xdev -perm -4000 -type f 2>/dev/null | wc -l)"
echo "-- 全局可写目录:"
find / -xdev -type d -perm -0002 ! -type l 2>/dev/null | grep -vE "^/tmp$|^/var/tmp$|^/proc|^/sys|^/dev" | sed 's/^/  [!] /'
echo "-- 无主文件:"
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -10 | sed 's/^/  [!] /'
echo "-- capabilities（关注 cap_setuid/cap_sys_admin）:"
getcap -r / 2>/dev/null | sed 's/^/  /'

echo; echo "## 5 端口与服务"
ss -tulnp 2>/dev/null | tail -n +2 | awk '{print "  "$5"  "$7}'
echo "-- 高危暴露端口:"
ss -tuln 2>/dev/null | grep -E "0\.0\.0\.0:(3306|6379|9200|27017|2375|11211|8080)" | sed 's/^/  [!] /'

echo; echo "## 6 内核参数"
for k in net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_source_route \
         kernel.randomize_va_space kernel.dmesg_restrict kernel.kptr_restrict fs.suid_dumpable; do
  echo "  $k = $(sysctl -n $k 2>/dev/null)"
done

echo; echo "## 7 SELinux"
echo "  getenforce: $(getenforce 2>/dev/null || echo N/A)"

echo; echo "## 8 持久化位"
echo "-- ld.so.preload（应为空）:"; cat /etc/ld.so.preload 2>/dev/null | sed 's/^/  [!] /'
echo "-- unit 指向 tmp 的自启项（应为空）:"
grep -rE "ExecStart=" /etc/systemd/system/ 2>/dev/null | grep -E "/tmp|/dev/shm|/var/tmp" | sed 's/^/  [!] /'
echo "-- 含 curl/wget 的 profile 脚本（应为空）:"
grep -rE "curl|wget|/dev/tcp" /etc/profile.d/ /etc/bashrc 2>/dev/null | sed 's/^/  [!] /'

echo; echo "===== 核查完成，输出：$OUT ====="
```

用法：`chmod +x linux-baseline-check.sh && sudo ./linux-baseline-check.sh`

---

> 本项目仅用于授权环境下的安全学习与合规审计，禁止用于未授权的系统检测。
