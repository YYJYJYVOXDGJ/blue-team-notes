# 主机应急采集 · 产物研判报告

> 本报告由本地规则引擎生成，**全程不联网、不调用任何大模型**。
> 所有结论均为规则初筛结果，**必须经人工确认**后才能作为处置依据。

## 1. 采集概览

| 项目 | 值 |
|---|---|
| 主机名 | linux-demo-01 |
| 采集时间 | 2026-09-25T14:30:02+08:00 |
| 平台 | linux |
| 适配器 | `linux-quickcheck`（探测置信度 80） |
| 产物目录 | `F:\bluenotes\blue-team-notes\mcp\eval\samples\linux-demo` |
| 归一化记录 | 55 条 |
| 命中线索 | 18 条 |
| 解析耗时 | 25.7 ms |

## 2. 数据分布（按记录种类）

| 种类 | 条数 |
|---|---|
| process | 13 |
| persistence | 11 |
| log | 7 |
| connection | 6 |
| account | 6 |
| config | 5 |
| file | 4 |
| module | 3 |

## 3. 线索清单

严重级别分布：

- **严重**（critical）：6 条
- **高危**（high）：9 条
- **中危**（medium）：3 条

### 1. [严重] UID 0 的非 root 账号 — `support`

- 来源产物：`user/accounts.txt`
- 记录种类：`account`
- 关键字段：
    - `name` = `support`
    - `detail` = `support:x:0:0:support:/tmp/:/bin/bash`
    - `display` = `accounts.txt`
- 命中规则：`ACCT-001` UID 0 的非 root 账号
- 研判摘要：命中 2 条规则, 最高置信: UID 0 的非 root 账号(critical, medium, ATT&CK T1136)。该结论需人工确认。
- ATT&CK：T1136 / Create Account / Persistence
- 命中条件：`uid equals 0`; `name not_equals root`
- **可能的误报**（先排除这些再定性）：
    - 极少有合法场景；部分发行版的 systemd 兼容账号需人工确认
- **建议人工验证步骤**（本工具不代为执行）：
    - 按 P0 处理：UID 0 的非 root 账号是典型的后门账号
    - 查该账号的创建时间（/etc/passwd 文件 mtime、审计日志）
    - 检查其家目录、authorized_keys 与最近登录记录

### 2. [严重] 临时目录下的 SUID 可执行文件 — `suhelper`

- 来源产物：`file/suid.txt`
- 记录种类：`file`
- 关键字段：
    - `name` = `suhelper`
    - `path` = `/tmp/.hidden/suhelper`
    - `detail` = `/tmp/.hidden/suhelper`
    - `display` = `suid`
- 命中规则：`FILE-001` 临时目录下的 SUID 可执行文件
- 研判摘要：命中 1 条规则, 最高置信: 临时目录下的 SUID 可执行文件(critical, medium, ATT&CK T1548.001)。该结论需人工确认。
- ATT&CK：T1548.001 / Setuid and Setgid / Privilege Escalation
- 命中条件：`display in ['suid', 'capabilities']`; `path regex ^(/tmp|/var/tmp|/dev/shm|/home)`
- **可能的误报**（先排除这些再定性）：
    - 极少有合法场景
- **建议人工验证步骤**（本工具不代为执行）：
    - 按 P0 处理：这是提权后门的典型形态
    - 记录文件哈希与 mtime，保留副本后再处理
    - 检查同目录下的其他文件是否同期出现

### 3. [严重] 日志完整性校验失败（疑似被篡改） — `天`

- 来源产物：`log/integrity.txt`
- 记录种类：`log`
- 关键字段：
    - `name` = `天`
    - `path` = `/etc/sudoers`
    - `detail` = `/etc/sudoers FAILED - 文件 mtime 早于当前时间 3 天`
    - `display` = `integrity`
- 命中规则：`DEFENSE-002` 日志完整性校验失败（疑似被篡改）
- 研判摘要：命中 1 条规则, 最高置信: 日志完整性校验失败（疑似被篡改）(critical, medium, ATT&CK T1070.001)。该结论需人工确认。
- ATT&CK：T1070.001 / Clear Windows Event Logs / Defense Evasion
- 命中条件：`display equals integrity`; `detail regex (?i)(FAILED|不匹配|mismatch|missing|缺失|no such|无法打开)`
- **可能的误报**（先排除这些再定性）：
    - 日志轮转导致的正常缺失（应有轮转策略记录）
- **建议人工验证步骤**（本工具不代为执行）：
    - 按 P0 升级：日志缺失/被清通常是反取证行为
    - 从远端日志服务器或 SIEM 找回同期日志
    - 核对日志文件的 mtime 与 size 是否被改动

### 4. [严重] 日志完整性校验失败（疑似被篡改） — `无该文件或无法打开`

- 来源产物：`log/integrity.txt`
- 记录种类：`log`
- 关键字段：
    - `name` = `无该文件或无法打开`
    - `path` = `/var/log/auth.log`
    - `detail` = `/var/log/auth.log missing - 无该文件或无法打开`
    - `display` = `integrity`
- 命中规则：`DEFENSE-002` 日志完整性校验失败（疑似被篡改）
- 研判摘要：命中 1 条规则, 最高置信: 日志完整性校验失败（疑似被篡改）(critical, medium, ATT&CK T1070.001)。该结论需人工确认。
- ATT&CK：T1070.001 / Clear Windows Event Logs / Defense Evasion
- 命中条件：`display equals integrity`; `detail regex (?i)(FAILED|不匹配|mismatch|missing|缺失|no such|无法打开)`
- **可能的误报**（先排除这些再定性）：
    - 日志轮转导致的正常缺失（应有轮转策略记录）
- **建议人工验证步骤**（本工具不代为执行）：
    - 按 P0 升级：日志缺失/被清通常是反取证行为
    - 从远端日志服务器或 SIEM 找回同期日志
    - 核对日志文件的 mtime 与 size 是否被改动

### 5. [严重] 日志完整性校验失败（疑似被篡改） — `哈希与包管理记录不匹配`

- 来源产物：`log/integrity.txt`
- 记录种类：`log`
- 关键字段：
    - `name` = `哈希与包管理记录不匹配`
    - `path` = `/usr/bin/ps`
    - `detail` = `/usr/bin/ps FAILED - 哈希与包管理记录不匹配`
    - `display` = `integrity`
- 命中规则：`DEFENSE-002` 日志完整性校验失败（疑似被篡改）
- 研判摘要：命中 1 条规则, 最高置信: 日志完整性校验失败（疑似被篡改）(critical, medium, ATT&CK T1070.001)。该结论需人工确认。
- ATT&CK：T1070.001 / Clear Windows Event Logs / Defense Evasion
- 命中条件：`display equals integrity`; `detail regex (?i)(FAILED|不匹配|mismatch|missing|缺失|no such|无法打开)`
- **可能的误报**（先排除这些再定性）：
    - 日志轮转导致的正常缺失（应有轮转策略记录）
- **建议人工验证步骤**（本工具不代为执行）：
    - 按 P0 升级：日志缺失/被清通常是反取证行为
    - 从远端日志服务器或 SIEM 找回同期日志
    - 核对日志文件的 mtime 与 size 是否被改动

### 6. [严重] 隐藏进程（/proc 与 ps 结果不一致） — `(hidden)`

- 来源产物：`proc/HIDDEN-pids.txt`
- 记录种类：`process`
- 关键字段：
    - `name` = `(hidden)`
    - `pid` = `7777`
    - `hidden` = `yes`
    - `detail` = `存在于 /proc 但 ps 不可见，疑似内核级隐藏或 ps 被替换`
- 命中规则：`PROC-004` 隐藏进程（/proc 与 ps 结果不一致）
- 研判摘要：命中 1 条规则, 最高置信: 隐藏进程（/proc 与 ps 结果不一致）(critical, medium, ATT&CK T1014)。该结论需人工确认。
- ATT&CK：T1014 / Rootkit / Defense Evasion
- 命中条件：`hidden equals yes`
- **可能的误报**（先排除这些再定性）：
    - ps 使用了非标准的 /proc 挂载视图（极少见）
    - 采集脚本在容器内核命名空间下运行造成的视图差异
- **建议人工验证步骤**（本工具不代为执行）：
    - 视同 Rootkit 嫌疑，按 P0 升级并考虑隔离主机
    - 用 /proc/<pid>/ 直读方式独立核对（不要依赖 ps、netstat、ls）
    - 检查内核模块、bpf 程序与 ld.so.preload 是否有异常加载项

### 7. [高危] 对外地址上的高危端口监听 — `.kworkerd`

- 来源产物：`net/listen.txt`
- 记录种类：`connection`
- 关键字段：
    - `name` = `.kworkerd`
    - `cmd` = `.kworkerd(3390)`
    - `remote_addr` = `*`
    - `pid` = `3390`
- 命中规则：`NET-001` 对外地址上的高危端口监听
- 研判摘要：命中 1 条规则, 最高置信: 对外地址上的高危端口监听(high, medium, ATT&CK T1571)。该结论需人工确认。
- ATT&CK：T1571 / Non-Standard Port / Command and Control
- 命中条件：`local_addr not_in ['127.0.0.1', '::1', '[::1]']`; `local_port in ['4444', '4445', '5555', '6666', '7777', '8888', '9999', '12345', '31337', '50050']`; `state in ['LISTEN', 'UNCONN']`
- **可能的误报**（先排除这些再定性）：
    - 内部服务恰好使用了这些端口（如 8888 常见于 Jupyter）
    - 开发测试用的临时监听
    - {'注意 0.0.0.0 与': ': 表示绑定全部网卡，对外暴露面最大，属重点关注对象'}
    - Windows 侧 02-listen.csv 无 State 列（采集时已按监听过滤），故本规则对缺失 state 的情况放行
- **建议人工验证步骤**（本工具不代为执行）：
    - 反查该端口的进程名、路径与签名（这是判定的决定性证据）
    - 用 `netstat -ano` 与 `Get-NetTCPConnection` 交叉验证，防止 netstat 被替换
    - 确认该监听是否在基线快照中存在，不在则重点怀疑

### 8. [高危] cron 任务指向临时目录 — `*/10 * * * *`

- 来源产物：`persist/cron.txt`
- 记录种类：`persistence`
- 关键字段：
    - `name` = `*/10 * * * *`
    - `path` = `/tmp/.hidden/run.sh`
    - `cmd` = `/tmp/.hidden/run.sh >/dev/null 2>&1`
    - `mech` = `cron`
    - `user` = `root`
    - `detail` = `*/10 * * * * /tmp/.hidden/run.sh >/dev/null 2>&1`
- 命中规则：`PERSIST-011` cron 任务指向临时目录
- 研判摘要：命中 1 条规则, 最高置信: cron 任务指向临时目录(high, medium, ATT&CK T1053.003)。该结论需人工确认。
- ATT&CK：T1053.003 / Cron / Persistence
- 命中条件：`mech equals cron`; `cmd regex (/tmp/|/var/tmp/|/dev/shm/|/run/shm/)`
- **可能的误报**（先排除这些再定性）：
    - 临时维护脚本（通常生命周期很短）
- **建议人工验证步骤**（本工具不代为执行）：
    - 定位 cron 文件的修改时间与属主
    - 检查所指脚本的实际内容
    - 注意 /dev/shm 与 /run/shm 内存目录，重启即失但极隐蔽

### 9. [高危] cron 任务指向临时目录 — `@reboot`

- 来源产物：`persist/cron.txt`
- 记录种类：`persistence`
- 关键字段：
    - `name` = `@reboot`
    - `path` = `/tmp/.hidden/.kworkerd`
    - `cmd` = `root /tmp/.hidden/.kworkerd --boot`
    - `mech` = `cron`
    - `user` = `/etc/cron.d/sysstat`
    - `detail` = `@reboot root /tmp/.hidden/.kworkerd --boot`
- 命中规则：`PERSIST-011` cron 任务指向临时目录
- 研判摘要：命中 1 条规则, 最高置信: cron 任务指向临时目录(high, medium, ATT&CK T1053.003)。该结论需人工确认。
- ATT&CK：T1053.003 / Cron / Persistence
- 命中条件：`mech equals cron`; `cmd regex (/tmp/|/var/tmp/|/dev/shm/|/run/shm/)`
- **可能的误报**（先排除这些再定性）：
    - 临时维护脚本（通常生命周期很短）
- **建议人工验证步骤**（本工具不代为执行）：
    - 定位 cron 文件的修改时间与属主
    - 检查所指脚本的实际内容
    - 注意 /dev/shm 与 /run/shm 内存目录，重启即失但极隐蔽

### 10. [高危] systemd 单元指向临时目录 — `/etc/systemd/system/syshealth.service`

- 来源产物：`persist/systemd.txt`
- 记录种类：`persistence`
- 关键字段：
    - `name` = `/etc/systemd/system/syshealth.service`
    - `cmd` = `ExecStart=/tmp/.hidden/.kworkerd --daemon`
    - `mech` = `systemd`
    - `detail` = `/etc/systemd/system/syshealth.service:ExecStart=/tmp/.hidden/.kworkerd --daemon`
- 命中规则：`PERSIST-012` systemd 单元指向临时目录
- 研判摘要：命中 1 条规则, 最高置信: systemd 单元指向临时目录(high, medium, ATT&CK T1543.002)。该结论需人工确认。
- ATT&CK：T1543.002 / Systemd Service / Persistence
- 命中条件：`mech equals systemd`; `cmd regex (/tmp/|/var/tmp/|/dev/shm/|/run/shm/)`
- **可能的误报**（先排除这些再定性）：
    - 开发调试用的临时 unit
- **建议人工验证步骤**（本工具不代为执行）：
    - 核对 unit 文件的 mtime 与创建来源
    - 检查 ExecStart 指向的可执行文件
    - 与 cron 一并核对，恶意程序常双写持久化

### 11. [高危] 矿池端口通信迹象 — `.kworkerd`

- 来源产物：`net/listen.txt`
- 记录种类：`connection`
- 关键字段：
    - `name` = `.kworkerd`
    - `cmd` = `.kworkerd(3390)`
    - `remote_addr` = `198.51.100.77`
    - `remote_port` = `3333`
    - `pid` = `3390`
- 命中规则：`NET-003` 矿池端口通信迹象
- 研判摘要：命中 1 条规则, 最高置信: 矿池端口通信迹象(high, low, ATT&CK T1496)。该结论需人工确认。
- ATT&CK：T1496 / Resource Hijacking / Impact
- 命中条件：`remote_port in ['3333', '4444', '5555', '7777', '8888', '9999', '14444', '45700']`
- **可能的误报**（先排除这些再定性）：
    - 开发环境的本地服务端口
- **建议人工验证步骤**（本工具不代为执行）：
    - 反查进程并核对是否为已知挖矿程序名
    - 检查 CPU 占用与父进程链
    - 按持久化全量清单核对清除彻底性

### 12. [高危] 进程可执行文件已被删除（Linux） — `.kworkerd`

- 来源产物：`proc/exe-links.txt`
- 记录种类：`process`
- 关键字段：
    - `name` = `.kworkerd`
    - `path` = `/tmp/.hidden/.kworkerd (deleted)`
    - `pid` = `3390`
- 命中规则：`PROC-003` 进程可执行文件已被删除（Linux）
- 研判摘要：命中 1 条规则, 最高置信: 进程可执行文件已被删除（Linux）(high, low, ATT&CK T1070)。该结论需人工确认。
- ATT&CK：T1070 / Indicator Removal / Defense Evasion
- 命中条件：`deleted equals yes`
- **可能的误报**（先排除这些再定性）：
    - 正常升级过程中的短暂窗口（服务重启后即消失）
    - 容器内进程引用了已卸载的层
- **建议人工验证步骤**（本工具不代为执行）：
    - 立即固定证据：从 /proc/<pid>/exe 复制出文件副本（进程退出后证据即消失）
    - 记录 pid、启动时间与父进程，判断是否为长期驻留
    - 这是无文件落地类恶意程序的典型特征，按高优先级处理

### 13. [高危] 进程可执行文件已被删除（Linux） — `.x`

- 来源产物：`proc/exe-links.txt`
- 记录种类：`process`
- 关键字段：
    - `name` = `.x`
    - `path` = `/dev/shm/.x (deleted)`
    - `pid` = `7777`
- 命中规则：`PROC-003` 进程可执行文件已被删除（Linux）
- 研判摘要：命中 1 条规则, 最高置信: 进程可执行文件已被删除（Linux）(high, low, ATT&CK T1070)。该结论需人工确认。
- ATT&CK：T1070 / Indicator Removal / Defense Evasion
- 命中条件：`deleted equals yes`
- **可能的误报**（先排除这些再定性）：
    - 正常升级过程中的短暂窗口（服务重启后即消失）
    - 容器内进程引用了已卸载的层
- **建议人工验证步骤**（本工具不代为执行）：
    - 立即固定证据：从 /proc/<pid>/exe 复制出文件副本（进程退出后证据即消失）
    - 记录 pid、启动时间与父进程，判断是否为长期驻留
    - 这是无文件落地类恶意程序的典型特征，按高优先级处理

### 14. [高危] SSH 公钥认证项（Linux） — `/root/.ssh/authorized_keys`

- 来源产物：`persist/ssh.txt`
- 记录种类：`persistence`
- 关键字段：
    - `name` = `/root/.ssh/authorized_keys`
    - `path` = `/root/.ssh/authorized_keys`
    - `cmd` = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoKeyForEvaluationOnly000000000000 attacker@example`
    - `mech` = `ssh-authorized-keys`
    - `detail` = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoKeyForEvaluationOnly000000000000 attacker@example`
- 命中规则：`PERSIST-010` SSH 公钥认证项（Linux）
- 研判摘要：命中 1 条规则, 最高置信: SSH 公钥认证项（Linux）(high, low, ATT&CK T1098.004)。该结论需人工确认。
- ATT&CK：T1098.004 / SSH Authorized Keys / Persistence
- 命中条件：`mech equals ssh-authorized-keys`
- **可能的误报**（先排除这些再定性）：
    - 运维配置的自动化部署密钥（应有台账）
    - 用户自己的登录密钥
- **建议人工验证步骤**（本工具不代为执行）：
    - 逐个核对公钥指纹与所属账号，与运维台账比对
    - 重点看 root 与高权限账号，以及 mtime 较新的条目
    - 公钥后门是 Linux 侧最高频的持久化手法之一

### 15. [高危] SSH 公钥认证项（Linux） — `/home/deploy/.ssh/authorized_keys`

- 来源产物：`persist/ssh.txt`
- 记录种类：`persistence`
- 关键字段：
    - `name` = `/home/deploy/.ssh/authorized_keys`
    - `path` = `/home/deploy/.ssh/authorized_keys`
    - `cmd` = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDemoKeyForEvaluationOnly000 deploy@build-server`
    - `mech` = `ssh-authorized-keys`
    - `detail` = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDemoKeyForEvaluationOnly000 deploy@build-server`
- 命中规则：`PERSIST-010` SSH 公钥认证项（Linux）
- 研判摘要：命中 1 条规则, 最高置信: SSH 公钥认证项（Linux）(high, low, ATT&CK T1098.004)。该结论需人工确认。
- ATT&CK：T1098.004 / SSH Authorized Keys / Persistence
- 命中条件：`mech equals ssh-authorized-keys`
- **可能的误报**（先排除这些再定性）：
    - 运维配置的自动化部署密钥（应有台账）
    - 用户自己的登录密钥
- **建议人工验证步骤**（本工具不代为执行）：
    - 逐个核对公钥指纹与所属账号，与运维台账比对
    - 重点看 root 与高权限账号，以及 mtime 较新的条目
    - 公钥后门是 Linux 侧最高频的持久化手法之一

### 16. [中危] 内核模块加载项待核对 — `nvidia`

- 来源产物：`proc/lsmod.txt`
- 记录种类：`module`
- 关键字段：
    - `name` = `nvidia`
    - `detail` = `nvidia              55746560  12`
    - `display` = `lsmod`
- 命中规则：`MOD-001` 内核模块加载项待核对
- 研判摘要：命中 1 条规则, 最高置信: 内核模块加载项待核对(medium, low, ATT&CK T1547.006)。该结论需人工确认。
- ATT&CK：T1547.006 / Kernel Modules and Extensions / Persistence
- 命中条件：`display in ['lsmod', 'proc-modules']`
- **可能的误报**（先排除这些再定性）：
    - 绝大多数模块都是系统正常组件
    - 虚拟化、容器、存储驱动的加载项
- **建议人工验证步骤**（本工具不代为执行）：
    - 与同版本系统的基线模块清单做差集，只看新增项
    - 新增模块用 `modinfo` 查来源与签名（Linux 内核模块签名）
    - Windows 侧核对驱动的签名主体是否为已知厂商

### 17. [中危] 内核模块加载项待核对 — `kvm_intel`

- 来源产物：`proc/lsmod.txt`
- 记录种类：`module`
- 关键字段：
    - `name` = `kvm_intel`
    - `detail` = `kvm_intel            372736  0`
    - `display` = `lsmod`
- 命中规则：`MOD-001` 内核模块加载项待核对
- 研判摘要：命中 1 条规则, 最高置信: 内核模块加载项待核对(medium, low, ATT&CK T1547.006)。该结论需人工确认。
- ATT&CK：T1547.006 / Kernel Modules and Extensions / Persistence
- 命中条件：`display in ['lsmod', 'proc-modules']`
- **可能的误报**（先排除这些再定性）：
    - 绝大多数模块都是系统正常组件
    - 虚拟化、容器、存储驱动的加载项
- **建议人工验证步骤**（本工具不代为执行）：
    - 与同版本系统的基线模块清单做差集，只看新增项
    - 新增模块用 `modinfo` 查来源与签名（Linux 内核模块签名）
    - Windows 侧核对驱动的签名主体是否为已知厂商

### 18. [中危] 内核模块加载项待核对 — `rootkit_hide`

- 来源产物：`proc/lsmod.txt`
- 记录种类：`module`
- 关键字段：
    - `name` = `rootkit_hide`
    - `detail` = `rootkit_hide           20480  0`
    - `display` = `lsmod`
- 命中规则：`MOD-001` 内核模块加载项待核对
- 研判摘要：命中 1 条规则, 最高置信: 内核模块加载项待核对(medium, low, ATT&CK T1547.006)。该结论需人工确认。
- ATT&CK：T1547.006 / Kernel Modules and Extensions / Persistence
- 命中条件：`display in ['lsmod', 'proc-modules']`
- **可能的误报**（先排除这些再定性）：
    - 绝大多数模块都是系统正常组件
    - 虚拟化、容器、存储驱动的加载项
- **建议人工验证步骤**（本工具不代为执行）：
    - 与同版本系统的基线模块清单做差集，只看新增项
    - 新增模块用 `modinfo` 查来源与签名（Linux 内核模块签名）
    - Windows 侧核对驱动的签名主体是否为已知厂商

## 4. 能力边界（必读）

### 4.1 已知盲区

以下场景本流水线**无法覆盖**，若怀疑涉及，须切换到对应专项手段：

- 内核级 Rootkit（本流水线在用户态运行，不读取内核内存）
- BYOVD（利用合法签名驱动关停防护）——需结合驱动加载日志与签名链分析
- 内存马 / 无文件注入（需内存取证与 pe-sieve 类工具配合）
- 业务调度平台后门（如 XXL-JOB glue 脚本）——需针对中间件单独核查
- 云身份滥用（AK/SK 泄露、控制台异常登录）——不在主机产物范围内

### 4.2 产物清单（供核对采集完整性）

目录内共 12 个采集产物文件：

- `etc/system-info.txt`
- `file/suid.txt`
- `log/integrity.txt`
- `net/listen.txt`
- `persist/cron.txt`
- `persist/ssh.txt`
- `persist/systemd.txt`
- `proc/HIDDEN-pids.txt`
- `proc/exe-links.txt`
- `proc/lsmod.txt`
- `proc/ps-full.txt`
- `user/accounts.txt`

> 若某类关键证据（如事件日志导出、计划任务列表）不在此清单中，
> 说明采集时该项未取到或未开启，**此时「未命中线索」不能作为排查结论**。

## 5. 声明

- 本报告由 `mcp/irflow` 本地规则流水线生成，未联网、未调用大模型。
- 字段 `human_review_required` 恒为 `true`、`auto_action_allowed` 恒为 `false`，
  该约束硬编码在代码中，不受调用方式与提示词影响。
- 报告不含真实客户环境数据；规则关键词均取自公开威胁情报与 ATT&CK 技术描述。
