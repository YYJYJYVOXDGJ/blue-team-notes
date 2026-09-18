#!/bin/bash
#===============================================================================
# linux-ir-quickcheck.sh —— Linux 主机应急响应快速采集（只读，不做任何处置）
#
# 用途：应急现场第一轮证据固定，把所有排查命令的输出统一落盘，便于回溯与交接。
# 用法：chmod +x linux-ir-quickcheck.sh && sudo ./linux-ir-quickcheck.sh
# 说明：脚本本身不修改系统任何配置，不会杀进程、不会改防火墙。
#===============================================================================

set -u

OUT="/tmp/ir-$(date +%Y%m%d%H%M%S)"
mkdir -p "$OUT"/{net,proc,persist,user,file,log,etc}
LOG="$OUT/summary.txt"

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] 建议以 root 运行，否则部分检查会因权限不足而缺失。"
fi

echo "[*] 采集开始：$(date)"
echo "[*] 输出目录：$OUT"
echo

{
  echo "===== 采集时间 ====="
  date; date -u; uptime; uptime -s 2>/dev/null; who -b 2>/dev/null
  echo
  echo "===== 系统信息 ====="
  uname -a
  cat /etc/os-release 2>/dev/null | head -5
  echo
} > "$OUT/etc/system-info.txt" 2>&1

#--------------------------------------------------------------- 1 网络
echo "[*] 1/6 网络连接与端口"
{
  ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null
  echo "--- route ---"; ip route 2>/dev/null || route -n 2>/dev/null
  echo "--- neigh/arp ---"; ip neigh 2>/dev/null || arp -a 2>/dev/null
  echo "--- ip_forward ---"; cat /proc/sys/net/ipv4/ip_forward 2>/dev/null
  echo "--- promisc ---"; ip link 2>/dev/null | grep -i promisc
} > "$OUT/net/basic.txt" 2>&1

ss -tulwnp   > "$OUT/net/listen.txt"   2>&1
ss -tanp     > "$OUT/net/tcp.txt"      2>&1
ss -tanp state established > "$OUT/net/established.txt" 2>&1
ss -s        > "$OUT/net/ss-summary.txt" 2>&1
{
  echo "--- filter ---"
  iptables -L -n -v 2>/dev/null
  echo "--- nat ---"
  iptables -t nat -L -n -v 2>/dev/null
  echo "--- save ---"
  iptables-save 2>/dev/null
  echo "--- nft ---"
  nft list ruleset 2>/dev/null
} > "$OUT/net/firewall.txt" 2>&1
cp /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/raw /proc/net/packet "$OUT/net/" 2>/dev/null
{
  echo "--- resolv.conf ---"; cat /etc/resolv.conf 2>/dev/null
  echo "--- hosts ---";       cat /etc/hosts 2>/dev/null
} > "$OUT/net/dns.txt" 2>&1

#--------------------------------------------------------------- 2 进程
echo "[*] 2/6 进程与隐藏进程"
ps auxf > "$OUT/proc/ps-auxf.txt" 2>&1
ps -eo pid,ppid,user,tty,stat,lstart,etime,cmd --sort=start_time > "$OUT/proc/ps-full.txt" 2>&1
ls -d /proc/[0-9]* 2>/dev/null | sed 's#/proc/##' | sort -n > "$OUT/proc/pids-in-proc.txt"
ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n > "$OUT/proc/pids-in-ps.txt"
comm -23 "$OUT/proc/pids-in-proc.txt" "$OUT/proc/pids-in-ps.txt" > "$OUT/proc/HIDDEN-pids.txt" 2>/dev/null
ls -l /proc/[0-9]*/exe  > "$OUT/proc/exe-links.txt" 2>&1
ls -l /proc/[0-9]*/cwd  > "$OUT/proc/cwd-links.txt" 2>&1
lsmod  > "$OUT/proc/lsmod.txt" 2>&1
cat /proc/modules > "$OUT/proc/modules.txt" 2>&1
dmesg -T 2>/dev/null | tail -100 > "$OUT/proc/dmesg.txt" 2>&1
bpftool prog show > "$OUT/proc/bpf-progs.txt" 2>&1
{
  echo "--- LD_PRELOAD in env ---"
  env | grep -i "^LD_"
  echo "--- ld.so.preload ---"
  cat /etc/ld.so.preload 2>/dev/null
} > "$OUT/proc/injection.txt" 2>&1
pstree -p > "$OUT/proc/pstree.txt" 2>&1

#--------------------------------------------------------------- 3 持久化
echo "[*] 3/6 持久化后门点位"
{
  echo "===== 全用户 crontab ====="
  for u in $(cut -d: -f1 /etc/passwd); do
    echo "-- user: $u"; crontab -l -u "$u" 2>/dev/null
  done
  echo; echo "===== /etc/crontab =====";   cat /etc/crontab 2>/dev/null
  echo; echo "===== /etc/anacrontab ====="; cat /etc/anacrontab 2>/dev/null
  echo; echo "===== /etc/cron.d =====";    for f in /etc/cron.d/*; do [ -f "$f" ] && { echo "-- $f"; cat "$f"; }; done 2>/dev/null
  echo; echo "===== cron.hourly/daily/weekly/monthly ====="
  ls -la /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null
  echo; echo "===== at 任务 ====="; atq 2>/dev/null
  echo; echo "===== @reboot ====="
  grep -r "@reboot" /etc/crontab /etc/cron.d/ /var/spool/cron/ 2>/dev/null
} > "$OUT/persist/cron.txt" 2>&1

{
  echo "===== enabled services ====="
  systemctl list-unit-files --type=service --state=enabled 2>/dev/null
  echo; echo "===== timers ====="
  systemctl list-timers --all 2>/dev/null
  echo; echo "===== path units ====="
  systemctl list-units --type=path 2>/dev/null
  echo; echo "===== socket units ====="
  systemctl list-units --type=socket 2>/dev/null
  echo; echo "===== ExecStart 指向可疑路径 ====="
  grep -rE "Exec(Start|Stop|Reload)(Pre|Post)?=" /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null \
    | grep -E "/tmp|/dev/shm|/var/tmp|/home|curl|wget|bash -c|nc |ncat|socat|base64"
  echo; echo "===== 近期变动的 unit ====="
  find /etc/systemd/system /usr/lib/systemd/system -type f -mtime -30 -printf "%T+ %p\n" 2>/dev/null | sort
} > "$OUT/persist/systemd.txt" 2>&1

{
  echo "===== authorized_keys ====="
  find / -name "authorized_keys" -exec ls -l {} \; -exec echo "-- content --" \; -exec cat {} \; 2>/dev/null
  echo; echo "===== 高危 authorized_keys 选项 ====="
  for f in $(find / -name authorized_keys 2>/dev/null); do
    grep -HE 'command=|from=|no-pty|environment=|permitopen=' "$f" 2>/dev/null
  done
  echo; echo "===== sshd_config 关键项 ====="
  grep -vE "^\s*#|^\s*$" /etc/ssh/sshd_config 2>/dev/null \
    | grep -iE "Port|PermitRootLogin|AuthorizedKeys|ForceCommand|PermitUserEnvironment|AllowUsers|PermitUserRC|TrustedUserCAKeys"
  echo; echo "===== ~/.ssh/rc ====="
  ls -la /root/.ssh/rc /home/*/.ssh/rc 2>/dev/null
} > "$OUT/persist/ssh.txt" 2>&1

{
  echo "===== rc / init ====="
  ls -la /etc/init.d/ /etc/rc.local /etc/rc*.d/ 2>/dev/null
  cat /etc/rc.local 2>/dev/null
  echo; echo "===== 登录脚本中的可疑内容 ====="
  grep -rEn "curl|wget|base64|/dev/tcp|socat|LD_PRELOAD|alias (ls|ps|netstat|ss|find|grep)" \
    /etc/profile /etc/profile.d/ /etc/bashrc /etc/bash.bashrc /etc/environment \
    /root/.bashrc /root/.bash_profile /root/.profile 2>/dev/null
  echo; echo "===== udev 规则 ====="
  grep -rhE "RUN\+?=|PROGRAM" /etc/udev/rules.d/ /lib/udev/rules.d/ 2>/dev/null \
    | grep -E "/tmp|/dev/shm|bash|sh -c|curl|wget"
  echo; echo "===== XDG autostart ====="
  ls -la /etc/xdg/autostart/ /root/.config/autostart/ 2>/dev/null
  echo; echo "===== bash_completion ====="
  ls -la /etc/bash_completion.d/ 2>/dev/null
  echo; echo "===== ld.so.conf.d ====="
  ls -la /etc/ld.so.conf.d/ 2>/dev/null && cat /etc/ld.so.conf.d/* 2>/dev/null
} > "$OUT/persist/autostart.txt" 2>&1

#--------------------------------------------------------------- 4 用户与登录
echo "[*] 4/6 用户与登录审计"
cp -a /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers "$OUT/user/" 2>/dev/null
cp -a /etc/sudoers.d "$OUT/user/" 2>/dev/null
{
  echo "===== UID=0 账号 =====";     awk -F: '$3==0{print $1}' /etc/passwd
  echo; echo "===== 空密码账号 ====="; awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null
  echo; echo "===== UID 重复 =====";   cut -d: -f3 /etc/passwd | sort | uniq -d
  echo; echo "===== 可登录账号 ====="; grep -vE "/sbin/nologin|/bin/false" /etc/passwd
  echo; echo "===== passwd/shadow mtime ====="
  ls -l --time-style=full-iso /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null
  echo; echo "===== NOPASSWD sudo ====="; grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
} > "$OUT/user/accounts.txt" 2>&1

{
  echo "===== w =====";       w 2>/dev/null
  echo; echo "===== last =====";  last -a -i -F 2>/dev/null | head -50
  echo; echo "===== lastb ====="; lastb -a -i -F 2>/dev/null | head -50
  echo; echo "===== lastlog ====="; lastlog 2>/dev/null
  echo; echo "===== 在线会话 ====="; who -a 2>/dev/null
  echo; echo "===== 失败登录来源 TOP ====="
  grep "Failed password" /var/log/secure* /var/log/auth.log* 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20
  echo; echo "===== 成功登录来源 TOP ====="
  grep "Accepted" /var/log/secure* /var/log/auth.log* 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20
  echo; echo "===== 账号变更记录 ====="
  grep -E "useradd|usermod|userdel|groupadd|groupmod|chpasswd" /var/log/secure* /var/log/auth.log* 2>/dev/null | tail -30
} > "$OUT/user/logins.txt" 2>&1

cp -a /etc/security/opasswd "$OUT/user/" 2>/dev/null
grep -vE "^\s*#|^\s*$" /etc/login.defs > "$OUT/user/login.defs" 2>&1

#--------------------------------------------------------------- 5 文件
echo "[*] 5/6 文件系统与痕迹"
find / -xdev -perm -4000 -type f -exec ls -l {} \; 2>/dev/null | sort > "$OUT/file/suid.txt"
find / -xdev -perm -2000 -type f -exec ls -l {} \; 2>/dev/null | sort > "$OUT/file/sgid.txt"
getcap -r / 2>/dev/null | sort > "$OUT/file/capabilities.txt"
find / -xdev -mtime -3 -type f -printf "%T+ %p\n" 2>/dev/null | sort > "$OUT/file/recent-3d.txt"
find /tmp /var/tmp /dev/shm /run -type f -ls 2>/dev/null > "$OUT/file/tmpdirs.txt"
find / -xdev -type d -perm -0002 ! -type l 2>/dev/null > "$OUT/file/world-writable-dirs.txt"
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -50 > "$OUT/file/no-owner.txt"
find / -name ".bash_history" -exec ls -l --time-style=full-iso {} \; 2>/dev/null > "$OUT/file/bash-history-list.txt"
{
  echo "===== root 历史命令（尾部） ====="
  tail -200 /root/.bash_history 2>/dev/null
  echo; echo "===== nohup.out ====="
  find / -name "nohup.out" -ls 2>/dev/null | head
  echo; echo "===== 会话工具 ====="
  ps aux 2>/dev/null | grep -E "screen|tmux|nohup|setsid" | grep -v grep
  echo; echo "===== 已删除但仍被占用的文件 ====="
  ls -l /proc/[0-9]*/fd 2>/dev/null | grep -i deleted | head -30
  echo; echo "===== memfd 无文件 ====="
  ls -l /proc/[0-9]*/exe 2>/dev/null | grep -i memfd
} > "$OUT/file/traces.txt" 2>&1

#--------------------------------------------------------------- 6 日志
echo "[*] 6/6 日志完整性"
cp -a /var/log/secure* /var/log/auth.log* /var/log/messages* /var/log/cron* "$OUT/log/" 2>/dev/null
{
  echo "===== 0 字节日志（异常） ====="
  find /var/log -type f -size 0 2>/dev/null
  echo; echo "===== 关键日志时间戳 ====="
  ls -l --time-style=full-iso /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/secure /var/log/messages 2>/dev/null
  echo; echo "===== journal boots ====="
  journalctl --list-boots 2>/dev/null | tail -20
  echo; echo "===== journal 持久化配置 ====="
  grep -E "^\s*Storage=" /etc/systemd/journald.conf 2>/dev/null
  echo; echo "===== journal 用量 ====="
  journalctl --disk-usage 2>/dev/null
  echo; echo "===== auditd 状态 ====="
  systemctl is-active auditd 2>/dev/null
  auditctl -l 2>/dev/null | head -20
  echo; echo "===== 日志转发配置 ====="
  grep -vE "^\s*#|^\s*$" /etc/rsyslog.conf 2>/dev/null | grep -E "@|omfwd"
  echo; echo "===== 安全组件状态 ====="
  for s in auditd rsyslog firewalld fail2ban; do
    echo "  $s: $(systemctl is-active $s 2>/dev/null)"
  done
  echo "  SELinux: $(getenforce 2>/dev/null || echo N/A)"
} > "$OUT/log/integrity.txt" 2>&1

#--------------------------------------------------------------- 汇总
{
  echo "===== 采集汇总 $(date) ====="
  echo "输出目录: $OUT"
  echo
  echo "!! 隐藏进程（ps 看不到但 /proc 里存在）:"
  if [ -s "$OUT/proc/HIDDEN-pids.txt" ]; then
    cat "$OUT/proc/HIDDEN-pids.txt" | sed 's/^/   [!] PID /'
  else
    echo "   无"
  fi
  echo
  echo "!! ld.so.preload（应为空）:"
  if [ -s /etc/ld.so.preload ] 2>/dev/null; then cat /etc/ld.so.preload | sed 's/^/   [!] /'; else echo "   空"; fi
  echo
  echo "!! memfd 无文件进程:"
  M=$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep -ci memfd); echo "   数量: $M"
  echo
  echo "!! SSH 高危公钥选项:"
  for f in $(find / -name authorized_keys 2>/dev/null); do
    grep -HE 'command=|from=' "$f" 2>/dev/null | sed 's/^/   [!] /'
  done
  echo
  echo "!! 空日志文件:"
  find /var/log -type f -size 0 2>/dev/null | sed 's/^/   [!] /'
  echo
  echo "文件清单:"
  find "$OUT" -type f | sed 's/^/   /'
} > "$LOG" 2>&1

cat "$LOG"
echo
echo "[+] 采集完成。汇总：$LOG"
echo "[+] 建议打包留证：tar czf ${OUT}.tar.gz $OUT && sha256sum ${OUT}.tar.gz"
