#!/bin/bash
#===============================================================================
# linux-baseline-check.sh —— Linux 主机安全基线核查（只读）
#
# 用途：安全评估 / 基线巡检 / 应急处置后的加固复核。
#       逐项核查账号、SSH、日志审计、文件权限、端口服务、内核参数、SELinux、持久化位，
#       输出问题清单（带 [!] 标记），可直接写入评估报告。
# 用法：chmod +x linux-baseline-check.sh && sudo ./linux-baseline-check.sh
#===============================================================================

set -u

OUT="/tmp/baseline-$(date +%Y%m%d%H%M%S).txt"
FINDINGS=0

hr() { echo "------------------------------------------------------------------"; }

# report: 传入一段可能为空的输出，空则打 OK，非空则标记为问题并计数
report() {
  if [ -n "${1:-}" ]; then
    echo "$1" | sed 's/^/  [!] /'
    FINDINGS=$((FINDINGS + 1))
  else
    echo "  OK"
  fi
}

check_sysctl() {
  local k="$1" want="$2" got
  got=$(sysctl -n "$k" 2>/dev/null)
  if [ "$got" = "$want" ]; then
    printf "  %-44s = %-4s OK\n" "$k" "$got"
  else
    printf "  %-44s = %-4s   [!] 建议 %s\n" "$k" "${got:-N/A}" "$want"
    FINDINGS=$((FINDINGS + 1))
  fi
}

main() {
  echo "=================================================================="
  echo " Linux 主机安全基线核查"
  echo " 时间：$(date)    主机：$(hostname 2>/dev/null)    内核：$(uname -r)"
  echo "=================================================================="

  hr; echo "## 1 账号与认证"; hr
  echo "-- 非 root 的 UID=0 账号:"
  report "$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)"
  echo "-- 空密码账号:"
  report "$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)"
  echo "-- UID 重复:"
  report "$(cut -d: -f3 /etc/passwd | sort | uniq -d | sed 's/^/UID /')"
  echo "-- 可登录账号:"
  grep -vE "/sbin/nologin|/bin/false" /etc/passwd 2>/dev/null | awk -F: '{print "     "$1"  shell="$7}'
  echo "-- 关键文件权限:"
  stat -c '     %a %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers 2>/dev/null
  report "$(for f in /etc/shadow /etc/gshadow; do
              p=$(stat -c '%a' "$f" 2>/dev/null)
              [ -n "$p" ] && [ "$p" != "0" ] && [ "$p" != "000" ] && echo "$f 权限为 $p，建议 000"
            done)"
  echo "-- NOPASSWD sudo:"
  report "$(grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null)"
  echo "-- 信任关系文件（应不存在）:"
  report "$(ls /etc/hosts.equiv /root/.rhosts /etc/ssh/shosts.equiv 2>/dev/null)"

  hr; echo "## 2 SSH 服务"; hr
  if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null | grep -E "permitrootlogin|passwordauthentication|permitemptypasswords|maxauthtries|authorizedkeysfile|x11forwarding|allowtcpforwarding" | sed 's/^/  /'
    echo "-- 逐项对照:"
    for kv in "permitrootlogin:no" "permitemptypasswords:no" "passwordauthentication:no" "x11forwarding:no"; do
      k=${kv%%:*}; v=${kv##*:}
      got=$(sshd -T 2>/dev/null | awk -v k="$k" '$1==k{print $2}')
      if [ "$got" = "$v" ]; then printf "     %-28s = %-4s OK\n" "$k" "$got"
      else printf "     %-28s = %-4s   [!] 建议 %s\n" "$k" "${got:-未设置}" "$v"; FINDINGS=$((FINDINGS + 1)); fi
    done
  else
    echo "  sshd 未安装"
  fi
  echo "-- sshd_config 后门指令:"
  report "$(grep -iE "ForceCommand|AuthorizedKeysCommand|TrustedUserCAKeys|PermitUserRC" /etc/ssh/sshd_config 2>/dev/null)"
  echo "-- 配置与私钥权限:"
  stat -c '     %a %U:%G %n' /etc/ssh/sshd_config /etc/ssh/ssh_host_*_key 2>/dev/null

  hr; echo "## 3 日志与审计"; hr
  for s in rsyslog auditd firewalld fail2ban; do
    printf "  %-10s %s\n" "$s" "$(systemctl is-active "$s" 2>/dev/null)"
  done
  RULES=$(auditctl -l 2>/dev/null | wc -l)
  echo "  audit 规则数: $RULES"
  [ "$RULES" -eq 0 ] && { echo "  [!] auditd 无任何规则，审计形同虚设"; FINDINGS=$((FINDINGS + 1)); }
  [ "$(systemctl is-active auditd 2>/dev/null)" != "active" ] && { echo "  [!] auditd 未运行"; FINDINGS=$((FINDINGS + 1)); }
  echo "-- 空日志文件:"
  report "$(find /var/log -type f -size 0 2>/dev/null)"
  echo "-- journal 持久化配置:"
  grep -E "^\s*Storage=" /etc/systemd/journald.conf 2>/dev/null | sed 's/^/     /' || echo "     未显式配置（默认 auto，重启可能丢失）"
  echo "-- 日志外发配置:"
  grep -vE "^\s*#|^\s*$" /etc/rsyslog.conf 2>/dev/null | grep -E "@|omfwd" | sed 's/^/     /' || echo "     未配置远程日志"

  hr; echo "## 4 文件权限与完整性"; hr
  echo "  SUID 文件数: $(find / -xdev -perm -4000 -type f 2>/dev/null | wc -l)"
  echo "  SGID 文件数: $(find / -xdev -perm -2000 -type f 2>/dev/null | wc -l)"
  echo "-- 全局可写目录（排除 /tmp /var/tmp）:"
  report "$(find / -xdev -type d -perm -0002 ! -type l 2>/dev/null | grep -vE "^/tmp$|^/var/tmp$|^/proc|^/sys|^/dev")"
  echo "-- 无主 / 无组文件:"
  report "$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -10)"
  echo "-- /tmp /var/tmp sticky bit:"
  stat -c '     %a %n' /tmp /var/tmp 2>/dev/null
  echo "-- capabilities:"
  report "$(getcap -r / 2>/dev/null)"
  echo "-- /etc/ld.so.preload（应为空）:"
  report "$(cat /etc/ld.so.preload 2>/dev/null)"

  hr; echo "## 5 端口与服务"; hr
  ss -tulnp 2>/dev/null | tail -n +2 | awk '{print "     "$5"  "$7}'
  echo "-- 高危暴露端口（0.0.0.0 上的管理 / 数据服务）:"
  report "$(ss -tuln 2>/dev/null | grep -E "0\.0\.0\.0:(3306|6379|9200|27017|2375|11211|8080|15672|5601)")"
  echo "-- 明文 / 不必要服务:"
  report "$(systemctl list-unit-files 2>/dev/null | grep -E "^(telnet|rsh|rlogin|vsftpd|tftp)")"

  hr; echo "## 6 内核参数"; hr
  check_sysctl net.ipv4.ip_forward 0
  check_sysctl net.ipv4.conf.all.rp_filter 1
  check_sysctl net.ipv4.conf.all.accept_source_route 0
  check_sysctl net.ipv4.conf.all.accept_redirects 0
  check_sysctl net.ipv4.conf.all.send_redirects 0
  check_sysctl net.ipv4.tcp_syncookies 1
  check_sysctl kernel.randomize_va_space 2
  check_sysctl kernel.dmesg_restrict 1
  check_sysctl kernel.kptr_restrict 2
  check_sysctl fs.suid_dumpable 0

  hr; echo "## 7 SELinux / AppArmor"; hr
  SE=$(getenforce 2>/dev/null)
  echo "  SELinux: ${SE:-N/A}"
  if [ -n "$SE" ] && [ "$SE" != "Enforcing" ]; then
    echo "  [!] SELinux 未处于 Enforcing 模式"; FINDINGS=$((FINDINGS + 1))
  fi
  grep "^SELINUX=" /etc/selinux/config 2>/dev/null | sed 's/^/     /'
  aa-status 2>/dev/null | head -3 | sed 's/^/     /'

  hr; echo "## 8 持久化位"; hr
  echo "-- unit 指向可疑路径的自启项:"
  report "$(grep -rE "ExecStart=" /etc/systemd/system/ 2>/dev/null | grep -E "/tmp|/dev/shm|/var/tmp")"
  echo "-- 含 curl/wget 的登录脚本:"
  report "$(grep -rE "curl|wget|/dev/tcp" /etc/profile.d/ /etc/bashrc 2>/dev/null)"
  echo "-- crontab 中的下载执行行为:"
  report "$(for u in $(cut -d: -f1 /etc/passwd); do
              crontab -l -u "$u" 2>/dev/null | grep -E "curl|wget|/dev/tcp|base64" | sed "s/^/[$u] /"
            done)"
  echo "-- SSH 公钥高危选项:"
  report "$(for f in $(find / -name authorized_keys 2>/dev/null); do
              grep -HE 'command=|from=' "$f" 2>/dev/null
            done)"
  echo "-- rc.local 有效内容:"
  grep -vE "^\s*#|^\s*$" /etc/rc.local 2>/dev/null | sed 's/^/     /' || echo "     空或不存在"

  hr
  echo " 核查完成：发现问题 $FINDINGS 项"
  echo " 输出文件：$OUT"
  hr
}

main > "$OUT" 2>&1
cat "$OUT"

exit 0
