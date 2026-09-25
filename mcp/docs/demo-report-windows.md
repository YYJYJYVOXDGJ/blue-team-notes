# 主机应急采集 · 产物研判报告

> 本报告由本地规则引擎生成，**全程不联网、不调用任何大模型**。
> 所有结论均为规则初筛结果，**必须经人工确认**后才能作为处置依据。

## 1. 采集概览

| 项目 | 值 |
|---|---|
| 主机名 | WIN-DEMO-01 |
| 采集时间 | 2026-09-25T14:22:07 |
| 平台 | windows |
| 适配器 | `windows-quickcheck`（探测置信度 60） |
| 产物目录 | `F:\bluenotes\blue-team-notes\mcp\eval\samples\windows-demo` |
| 归一化记录 | 35 条 |
| 命中线索 | 14 条 |
| 解析耗时 | 15.1 ms |

## 2. 数据分布（按记录种类）

| 种类 | 条数 |
|---|---|
| persistence | 13 |
| process | 9 |
| connection | 7 |
| config | 6 |

## 3. 线索清单

严重级别分布：

- **严重**（critical）：3 条
- **高危**（high）：7 条
- **中危**（medium）：4 条

### 1. [严重] 服务路径包含命令行解释器 — `SysHealthSvc`

- 来源产物：`04-services.csv`
- 记录种类：`persistence`
- 关键字段：
    - `name` = `SysHealthSvc`
    - `path` = `C:\Windows\System32\cmd.exe /c start /b C:\Users\demo\AppData\Local\Temp\svhost32.exe -svc`
    - `cmd` = `C:\Windows\System32\cmd.exe /c start /b C:\Users\demo\AppData\Local\Temp\svhost32.exe -svc`
    - `mech` = `service`
    - `pid` = `4460`
    - `user` = `LocalSystem`
    - `display` = `Windows System Health Service`
- 命中规则：`PERSIST-006` 服务路径包含命令行解释器
- 研判摘要：命中 1 条规则, 最高置信: 服务路径包含命令行解释器(critical, medium, ATT&CK T1543.003)。该结论需人工确认。
- ATT&CK：T1543.003 / Windows Service / Persistence
- 命中条件：`mech equals service`; `path regex (?i)(cmd\.exe|powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|/c\s|base64)`
- **可能的误报**（先排除这些再定性）：
    - 部分老旧软件确实用 cmd /c 启动（应能说清用途）
- **建议人工验证步骤**（本工具不代为执行）：
    - 高优先级核查：正常服务极少以命令行解释器作为映像路径
    - 查服务的创建时间与 Source（SCM 事件日志 7045）
    - 检查该服务当前是否在运行（State / StartMode）

### 2. [严重] WMI 事件订阅持久化 — `SCM Event Log Consumer`

- 来源产物：`05-wmi-consumers.csv`
- 记录种类：`persistence`
- 关键字段：
    - `name` = `SCM Event Log Consumer`
    - `mech` = `wmi-subscription`
- 命中规则：`PERSIST-009` WMI 事件订阅持久化
- 研判摘要：命中 1 条规则, 最高置信: WMI 事件订阅持久化(critical, medium, ATT&CK T1546.003)。该结论需人工确认。
- ATT&CK：T1546.003 / WMI Event Subscription / Persistence
- 命中条件：`mech equals wmi-subscription`; `consumer_class in ['CommandLineEventConsumer', 'ActiveScriptEventConsumer']`
- **可能的误报**（先排除这些再定性）：
    - 极少数监控软件会用到 WMI 订阅（应在基线中存在）
- **建议人工验证步骤**（本工具不代为执行）：
    - 无文件持久化的典型手法，杀软覆盖差，按 P0/P1 升级
    - 三条链（Filter / Consumer / Binding）必须一起看，缺一不成立
    - 重点看 Consumer 里的脚本内容与执行命令

### 3. [严重] IFEO 调试器劫持 — `sethc.exe`

- 来源产物：`05-ifeo.csv`
- 记录种类：`persistence`
- 关键字段：
    - `name` = `sethc.exe`
    - `path` = `C:\Windows\System32\cmd.exe`
    - `cmd` = `C:\Windows\System32\cmd.exe`
    - `mech` = `ifeo`
- 命中规则：`PERSIST-007` IFEO 调试器劫持
- 研判摘要：命中 1 条规则, 最高置信: IFEO 调试器劫持(critical, medium, ATT&CK T1546.012)。该结论需人工确认。
- ATT&CK：T1546.012 / Image File Execution Options Injection / Persistence
- 命中条件：`mech equals ifeo`
- **可能的误报**（先排除这些再定性）：
    - 开发机上的调试器注册（如 windbg、Visual Studio）
    - 无障碍功能替换（辅助技术的正规配置）
- **建议人工验证步骤**（本工具不代为执行）：
    - 调试器指向非调试工具路径时按恶意处理
    - 核对注册表键的写入时间
    - 常规杀软极易漏掉此项，属高频遗漏点

### 4. [高危] 对外地址上的高危端口监听 — `svhost32.exe`

- 来源产物：`02-listen.csv`
- 记录种类：`connection`
- 关键字段：
    - `name` = `svhost32.exe`
    - `path` = `C:\Users\demo\AppData\Local\Temp\svhost32.exe`
    - `pid` = `4460`
- 命中规则：`NET-001` 对外地址上的高危端口监听
- 研判摘要：命中 1 条规则, 最高置信: 对外地址上的高危端口监听(high, medium, ATT&CK T1571)。该结论需人工确认。
- ATT&CK：T1571 / Non-Standard Port / Command and Control
- 命中条件：`local_addr not_in ['127.0.0.1', '::1', '[::1]']`; `local_port in ['4444', '4445', '5555', '6666', '7777', '8888', '9999', '12345', '31337', '50050']`; `state not_exists true`
- **可能的误报**（先排除这些再定性）：
    - 内部服务恰好使用了这些端口（如 8888 常见于 Jupyter）
    - 开发测试用的临时监听
    - {'注意 0.0.0.0 与': ': 表示绑定全部网卡，对外暴露面最大，属重点关注对象'}
    - Windows 侧 02-listen.csv 无 State 列（采集时已按监听过滤），故本规则对缺失 state 的情况放行
- **建议人工验证步骤**（本工具不代为执行）：
    - 反查该端口的进程名、路径与签名（这是判定的决定性证据）
    - 用 `netstat -ano` 与 `Get-NetTCPConnection` 交叉验证，防止 netstat 被替换
    - 确认该监听是否在基线快照中存在，不在则重点怀疑

### 5. [高危] 进程可执行文件位于用户可写目录 — `svhost32.exe`

- 来源产物：`03-process.csv`
- 记录种类：`process`
- 关键字段：
    - `name` = `svhost32.exe`
    - `path` = `C:\Users\demo\AppData\Local\Temp\svhost32.exe`
    - `cmdline` = `"C:\Users\demo\AppData\Local\Temp\svhost32.exe" -c cfg.dat`
    - `pid` = `4460`
- 命中规则：`PROC-001` 进程可执行文件位于用户可写目录
- 研判摘要：命中 1 条规则, 最高置信: 进程可执行文件位于用户可写目录(high, medium, ATT&CK T1036)。该结论需人工确认。
- ATT&CK：T1036 / Masquerading / Defense Evasion
- 命中条件：`path regex \\(Temp|AppData|ProgramData|Users\\Public|Windows\\Temp|PerfLogs|Recycle)\\`; `path not_startswith ['C:\\Windows\\', 'C:\\Program Files\\', 'C:\\Program Files (x86)\\']`
- **可能的误报**（先排除这些再定性）：
    - 便携版软件、绿色软件、自解压更新器
    - 企业内部自研工具未走标准安装路径
    - 安装过程中的临时解包进程
- **建议人工验证步骤**（本工具不代为执行）：
    - 核对文件数字签名与签名主体（无签名或签名主体陌生的优先级最高）
    - 比对文件哈希与基线快照，确认是否为已知合法程序
    - 查父进程与创建时间，判断是用户主动运行还是被拉起

### 6. [高危] 可疑 PowerShell 执行（含编码命令） — `powershell.exe`

- 来源产物：`03-process.csv`
- 记录种类：`process`
- 关键字段：
    - `name` = `powershell.exe`
    - `path` = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
    - `cmdline` = `powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA`
    - `pid` = `4512`
- 命中规则：`EXEC-001` 可疑 PowerShell 执行（含编码命令）
- 研判摘要：命中 1 条规则, 最高置信: 可疑 PowerShell 执行（含编码命令）(high, medium, ATT&CK T1059.001)。该结论需人工确认。
- ATT&CK：T1059.001 / PowerShell / Execution
- 命中关键词：`-enc`, `-nop -w hidden`
- **可能的误报**（先排除这些再定性）：
    - 管理员正常的自动化运维脚本（应有日志留痕）
- **建议人工验证步骤**（本工具不代为执行）：
    - 确认 4104 脚本块日志与 4688 命令行日志是否已开启，未开启则无法还原内容
    - 解码后查看实际执行的命令内容
    - 检查是否存在 AMSI 绕过或日志清除的伴随行为

### 7. [高危] 进程可执行文件位于用户可写目录 — `svhost32.exe`

- 来源产物：`03-process-outside-sysdir.csv`
- 记录种类：`process`
- 关键字段：
    - `name` = `svhost32.exe`
    - `path` = `C:\Users\demo\AppData\Local\Temp\svhost32.exe`
    - `cmdline` = `"C:\Users\demo\AppData\Local\Temp\svhost32.exe" -c cfg.dat`
    - `pid` = `4460`
- 命中规则：`PROC-001` 进程可执行文件位于用户可写目录
- 研判摘要：命中 2 条规则, 最高置信: 进程可执行文件位于用户可写目录(high, medium, ATT&CK T1036)。该结论需人工确认。
- ATT&CK：T1036 / Masquerading / Defense Evasion
- 命中条件：`path regex \\(Temp|AppData|ProgramData|Users\\Public|Windows\\Temp|PerfLogs|Recycle)\\`; `path not_startswith ['C:\\Windows\\', 'C:\\Program Files\\', 'C:\\Program Files (x86)\\']`
- **可能的误报**（先排除这些再定性）：
    - 便携版软件、绿色软件、自解压更新器
    - 企业内部自研工具未走标准安装路径
    - 安装过程中的临时解包进程
- **建议人工验证步骤**（本工具不代为执行）：
    - 核对文件数字签名与签名主体（无签名或签名主体陌生的优先级最高）
    - 比对文件哈希与基线快照，确认是否为已知合法程序
    - 查父进程与创建时间，判断是用户主动运行还是被拉起

### 8. [高危] Run 键指向临时目录或脚本宿主 — `Updater`

- 来源产物：`05-run-keys.csv`
- 记录种类：`persistence`
- 关键字段：
    - `name` = `Updater`
    - `path` = `C:\Users\demo\AppData\Roaming\updater.exe --silent`
    - `cmd` = `C:\Users\demo\AppData\Roaming\updater.exe --silent`
    - `mech` = `run-key`
- 命中规则：`PERSIST-005` Run 键指向临时目录或脚本宿主
- 研判摘要：命中 1 条规则, 最高置信: Run 键指向临时目录或脚本宿主(high, medium, ATT&CK T1547.001)。该结论需人工确认。
- ATT&CK：T1547.001 / Registry Run Keys / Persistence
- 命中条件：`mech in ['run-key', 'autostart']`; `cmd regex (?i)(\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|powershell|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript)`
- **可能的误报**（先排除这些再定性）：
    - 部分输入法、驱动更新器的正常自启动
    - 企业统一推送的合规客户端
- **建议人工验证步骤**（本工具不代为执行）：
    - 核对所指文件的签名、路径与文件创建时间
    - 检查注册表项的最后写入时间是否与可疑活动时间吻合
    - 同时核对 HKCU 与 HKLM 两个分支

### 9. [高危] 隐藏的计划任务 — `SysHealthCheck`

- 来源产物：`05-scheduled-tasks.csv`
- 记录种类：`persistence`
- 关键字段：
    - `name` = `SysHealthCheck`
    - `path` = `C:\Users\demo\AppData\Local\Temp\svhost32.exe`
    - `cmd` = `C:\Users\demo\AppData\Local\Temp\svhost32.exe -task`
    - `mech` = `scheduled-task`
    - `user` = `demo`
    - `hidden` = `True`
- 命中规则：`PERSIST-003` 隐藏的计划任务
- 研判摘要：命中 2 条规则, 最高置信: 隐藏的计划任务(high, medium, ATT&CK T1053.005)。该结论需人工确认。
- ATT&CK：T1053.005 / Scheduled Task / Persistence
- 命中条件：`mech equals scheduled-task`; `hidden equals true`
- **可能的误报**（先排除这些再定性）：
    - 部分企业软件会创建隐藏任务做静默更新
- **建议人工验证步骤**（本工具不代为执行）：
    - 核对任务的 Author 与创建时间，是否与可疑登录时间吻合
    - 检查 Execute 指向的文件签名与哈希
    - 用 `schtasks /query /v` 与注册表 TaskCache 交叉验证

### 10. [高危] 外连到 C2 常用端口 — `svhost32.exe`

- 来源产物：`02-established.csv`
- 记录种类：`connection`
- 关键字段：
    - `name` = `svhost32.exe`
    - `path` = `C:\Users\demo\AppData\Local\Temp\svhost32.exe`
    - `remote_addr` = `198.51.100.77`
    - `remote_port` = `4444`
    - `pid` = `4460`
- 命中规则：`NET-002` 外连到 C2 常用端口
- 研判摘要：命中 2 条规则, 最高置信: 外连到 C2 常用端口(high, low, ATT&CK T1571)。该结论需人工确认。
- ATT&CK：T1571 / Non-Standard Port / Command and Control
- 命中条件：`remote_port in ['4444', '4445', '5555', '6666', '7777', '9999', '12345', '31337', '50050', '14444', '45560']`
- **可能的误报**（先排除这些再定性）：
    - 企业自研系统的内部端口恰好撞上这些值
    - 云服务商的自定义端口
    - 注意：Windows 侧 02-established.csv 本身只含已建立连接，故本规则不再校验 state
- **建议人工验证步骤**（本工具不代为执行）：
    - 查 remote_addr 的 ASN 归属与备案信息（不要只凭 IP 首段猜国家）
    - 反查发起连接的进程，核对签名与路径
    - 结合 DNS 缓存记录判断域名来源

### 11. [中危] 杀软排除项覆盖面过大 — `PathExclusions : C:\`

- 来源产物：`07-defender-exclusions.txt`
- 记录种类：`config`
- 关键字段：
    - `detail` = `PathExclusions : C:\`
    - `display` = `07-defender-exclusions.txt`
- 命中规则：`CFG-002` 杀软排除项覆盖面过大
- 研判摘要：命中 1 条规则, 最高置信: 杀软排除项覆盖面过大(medium, low, ATT&CK T1562.001)。该结论需人工确认。
- ATT&CK：T1562.001 / Disable or Modify Tools / Defense Evasion
- 命中条件：`display equals 07-defender-exclusions.txt`; `detail regex (?i)(C:\\|\\\\|Process|Extension)`
- **可能的误报**（先排除这些再定性）：
    - 运维为解决误杀加的临时排除（应有变更记录与回收计划）
- **建议人工验证步骤**（本工具不代为执行）：
    - 核对排除项的来源与登记记录
    - 整盘或整目录排除是攻击者常用的"合法绕杀"手法
    - 检查排除目录下是否存在异常可执行文件

### 12. [中危] 杀软排除项覆盖面过大 — `PathExclusions : C:\Users\demo\AppData\Local\Temp`

- 来源产物：`07-defender-exclusions.txt`
- 记录种类：`config`
- 关键字段：
    - `detail` = `PathExclusions : C:\Users\demo\AppData\Local\Temp`
    - `display` = `07-defender-exclusions.txt`
- 命中规则：`CFG-002` 杀软排除项覆盖面过大
- 研判摘要：命中 1 条规则, 最高置信: 杀软排除项覆盖面过大(medium, low, ATT&CK T1562.001)。该结论需人工确认。
- ATT&CK：T1562.001 / Disable or Modify Tools / Defense Evasion
- 命中条件：`display equals 07-defender-exclusions.txt`; `detail regex (?i)(C:\\|\\\\|Process|Extension)`
- **可能的误报**（先排除这些再定性）：
    - 运维为解决误杀加的临时排除（应有变更记录与回收计划）
- **建议人工验证步骤**（本工具不代为执行）：
    - 核对排除项的来源与登记记录
    - 整盘或整目录排除是攻击者常用的"合法绕杀"手法
    - 检查排除目录下是否存在异常可执行文件

### 13. [中危] 杀软排除项覆盖面过大 — `ProcessExclusions : svhost32.exe`

- 来源产物：`07-defender-exclusions.txt`
- 记录种类：`config`
- 关键字段：
    - `detail` = `ProcessExclusions : svhost32.exe`
    - `display` = `07-defender-exclusions.txt`
- 命中规则：`CFG-002` 杀软排除项覆盖面过大
- 研判摘要：命中 1 条规则, 最高置信: 杀软排除项覆盖面过大(medium, low, ATT&CK T1562.001)。该结论需人工确认。
- ATT&CK：T1562.001 / Disable or Modify Tools / Defense Evasion
- 命中条件：`display equals 07-defender-exclusions.txt`; `detail regex (?i)(C:\\|\\\\|Process|Extension)`
- **可能的误报**（先排除这些再定性）：
    - 运维为解决误杀加的临时排除（应有变更记录与回收计划）
- **建议人工验证步骤**（本工具不代为执行）：
    - 核对排除项的来源与登记记录
    - 整盘或整目录排除是攻击者常用的"合法绕杀"手法
    - 检查排除目录下是否存在异常可执行文件

### 14. [中危] 杀软排除项覆盖面过大 — `ExtensionExclusions : .dat`

- 来源产物：`07-defender-exclusions.txt`
- 记录种类：`config`
- 关键字段：
    - `detail` = `ExtensionExclusions : .dat`
    - `display` = `07-defender-exclusions.txt`
- 命中规则：`CFG-002` 杀软排除项覆盖面过大
- 研判摘要：命中 1 条规则, 最高置信: 杀软排除项覆盖面过大(medium, low, ATT&CK T1562.001)。该结论需人工确认。
- ATT&CK：T1562.001 / Disable or Modify Tools / Defense Evasion
- 命中条件：`display equals 07-defender-exclusions.txt`; `detail regex (?i)(C:\\|\\\\|Process|Extension)`
- **可能的误报**（先排除这些再定性）：
    - 运维为解决误杀加的临时排除（应有变更记录与回收计划）
- **建议人工验证步骤**（本工具不代为执行）：
    - 核对排除项的来源与登记记录
    - 整盘或整目录排除是攻击者常用的"合法绕杀"手法
    - 检查排除目录下是否存在异常可执行文件

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

- `01-system.csv`
- `02-established.csv`
- `02-listen.csv`
- `03-process-outside-sysdir.csv`
- `03-process.csv`
- `04-services.csv`
- `05-ifeo.csv`
- `05-run-keys.csv`
- `05-scheduled-tasks.csv`
- `05-wmi-bindings.csv`
- `05-wmi-consumers.csv`
- `07-defender-exclusions.txt`

> 若某类关键证据（如事件日志导出、计划任务列表）不在此清单中，
> 说明采集时该项未取到或未开启，**此时「未命中线索」不能作为排查结论**。

## 5. 声明

- 本报告由 `mcp/irflow` 本地规则流水线生成，未联网、未调用大模型。
- 字段 `human_review_required` 恒为 `true`、`auto_action_allowed` 恒为 `false`，
  该约束硬编码在代码中，不受调用方式与提示词影响。
- 报告不含真实客户环境数据；规则关键词均取自公开威胁情报与 ATT&CK 技术描述。
