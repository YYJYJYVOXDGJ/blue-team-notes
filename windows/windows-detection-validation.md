# Windows 检测能力验证清单（Detection Validation Checklist）

> `windows-host-audit.md` 回答「查什么」，本文回答另一个更要命的问题：**这些检测点在真实环境里到底抓不抓得到。**

- [0. 为什么需要验证](#0-为什么需要验证)
- [1. 三条验证路径](#1-三条验证路径)
- [2. 前置：日志源与工具基线](#2-前置日志源与工具基线)
- [3. Atomic Red Team 的正确用法](#3-atomic-red-team-的正确用法)
- [4. 验证主表（按手册章节）](#4-验证主表按手册章节)
- [5. 判定口径与记录](#5-判定口径与记录)
- [6. 覆盖矩阵：哪些能回放、哪些必须真跑](#6-覆盖矩阵哪些能回放哪些必须真跑)
- [7. 已知盲区](#7-已知盲区)
- [8. 静态验证：Sigma 规则](#8-静态验证sigma-规则)
- [9. 与 MCP + AI Agent 规划的衔接](#9-与-mcp--ai-agent-规划的衔接)
- [附录 A：受控执行 Checklist](#附录-a受控执行-checklist)
- [附录 B：日志导出与分析命令](#附录-b日志导出与分析命令)

---

## 0. 为什么需要验证

应急现场最常见的失败不是「不知道查什么」，而是这三件事：

| 失败模式 | 表现 | 根因 |
|---|---|---|
| 有检测点，无数据 | 手册写着「查 4104 脚本块日志」，实际日志里一条 4104 都没有 | 日志源从未开启 |
| 有数据，无字段 | 4688 有事件，但 `CommandLine` 为空 | `ProcessCreationIncludeCmdLine_Enabled` 未开 |
| 有字段，规则不响 | 事件都在，规则/查询筛不出来 | 字段名写错、过度依赖单一事件、被白名单吃掉 |

所以验证要回答三个层次的问题，**只做前两层是自欺欺人**：

1. **数据可得性**（Data Availability）——日志源开了吗？有数据吗？
2. **检测命中**（Detection Coverage）——这条逻辑对这类行为有没有反应？
3. **告警链路**（Alerting Path）——命中的东西有没有进入告警/工单？还是只躺在日志里没人看？

本文的定位：把手册里的每条检测逻辑，变成**可执行、可判定、可记录、可回归**的用例集。

---

## 1. 三条验证路径

| 路径 | 做法 | 风险 | 能验证什么 | 不能验证什么 |
|---|---|---|---|---|
| **A. 静态规则验证** | `sigma-cli` 检查规则语法与字段映射 | 无 | 规则写法、字段名、逻辑分支 | 真实日志、真实命中率 |
| **B. 日志回放**（推荐主力） | 用公开的攻击样本 EVTX / 数据集喂给 Chainsaw / Hayabusa / Sigma | ≈ 0 | 检测逻辑对真实攻击日志的命中率、误报情况 | 本机日志源是否开启 |
| **C. 受控真跑**（少量必需） | 隔离 VM 中执行 Atomic Red Team 用例 | 可控，但需授权与快照 | 端到端：行为 → 日志 → 检测 → 告警 | 无（但代价与风险最高） |

**决策顺序：A → B → C**。不要一上来就跑 ART。绝大多数人真正缺的是 B——拿真实攻击日志验证规则，比在自己机器上打一遍安全得多，而且更接近「对手真来的时候日志长什么样」。

只有**行为依赖运行态、无法从日志样本体现**的少数几项（进程注入、WMI 订阅三连、LSASS 访问）才值得走 C。这些项在第 4 节统一标了 ★。

### 公开可用的回放数据源

| 数据源 | 内容 | 说明 |
|---|---|---|
| `sbousseaden/EVTX-ATTACK-SAMPLES` | 按 ATT&CK 技术分类的 Windows EVTX 样本 | 最贴合本清单，直接对应技术编号 |
| `OTRF/Security-Datasets` | Mordor 项目数据，含主机/网络数据集与元数据 | 带 `metadata.json`，可用字典批量回放 |
| `splunk/attack_data` | Splunk 攻击数据集，含原子测试配套日志 | 覆盖范围广，含云与容器 |
| `SigmaHQ/sigma` | 规则库 + 官方 test 数据 | 用于 A 路径与规则回归 |

---

## 2. 前置：日志源与工具基线

**这一节必须先跑。** 不满足的话，第 4 节所有用例都会「未命中」，你会误判成规则有问题。

### 2.1 日志源核查表

| # | 日志源 | 核查命令 | 合格标准 | 缺失后果 |
|---|---|---|---|---|
| 1 | Sysmon 服务 | `Get-CimInstance Win32_SystemDriver \| Where-Object Name -match sysmon \| Select Name,State,PathName` | `State=Running`，路径非临时目录 | 第 4 节大部分用例直接失效 |
| 2 | Sysmon 版本与配置 | `Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1`；检索 Event ID 16（配置变更） | 有近期 16 事件，配置非极简 | 配置过简会丢 ImageLoaded / ProcessAccess |
| 3 | **脚本块日志 4104** | `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'` | `EnableScriptBlockLogging=1` | 无文件攻击、编码命令**彻底失明** |
| 4 | 模块日志 4103 | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging` | `EnableModuleLogging=1` | 管道细节丢失 |
| 5 | PowerShell 转录 | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription` | 按需（注意转录文件可被攻击者读取） | 无 |
| 6 | 4688 命令行 | `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled` | `=1` | 4688 只有进程名，没有命令行，等于废掉一半 |
| 7 | 审核子类别 | `auditpol /get /category:*` | Process Creation、Logon/Logoff、Account Management、Object Access(Handle/Registry/File System)、Policy Change、System 全部为 Success and Failure | 关键事件根本不产生 |
| 8 | Sysmon DNS 查询 | 检索 Event ID 22 | 有数据 | 无法用 DNS 侧检测 C2 |
| 9 | **任务计划日志** | `Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational'` | `IsEnabled=True` | 计划任务只有 4698（创建），**看不到执行**——很常见的坑 |
| 10 | **BITS 客户端日志** | `Get-WinEvent -ListLog 'Microsoft-Windows-Bits-Client/Operational'` | `IsEnabled=True` | BITS 持久化不可见 |
| 11 | WMI 活动日志 | `Get-WinEvent -ListLog 'Microsoft-Windows-WMI-Activity/Operational'` | 有 5857/5860/5861 | WMI 执行与订阅证据不足 |
| 12 | 终端服务 1149 | 检索 `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | 有数据 | RDP 源 IP 拿不到（4624 只有主机名） |
| 13 | Defender 日志 | 检索 `Microsoft-Windows-Windows Defender/Operational` 的 1116/1117/5001/5007 | 有数据 | 无法验证「关防护」类行为 |
| 14 | 日志容量与覆盖 | `Get-WinEvent -ListLog * -MaxEvents 0 \| Where-Object LogName -match 'Sysmon\|Security\|PowerShell' \| Select LogName,MaximumSizeInBytes,RecordCount,FileSize` | 容量足够撑过事件处置周期，无「最早记录 = 今天」 | 日志被滚动覆盖，时间线断裂 |

> **一句话机检**：先跑 `windows-ir-quickcheck.ps1`，它已把上述 14 项的采集与判定内置；本文节 2.1 是它的判定口径来源。

### 2.2 签名与完整性（附加一条：日志源本身是否可信）

对手的第一反应常是**让日志源闭嘴**。验证前先确认：

```powershell
# Sysmon 二进制与驱动签名
Get-AuthenticodeSignature "$env:SystemRoot\Sysmon64.exe" | Select Status,SignerCertificate
Get-CimInstance Win32_SystemDriver | Where-Object Name -match sysmon |
  Select Name,State,PathName

# 审核策略是否被改回去（对比基线）
auditpol /get /category:* > C:\IR\auditpol-now.txt
# 与 windows-hardening.md 基线逐项比对

# 服务是否是「改了配置但没重启」的僵尸状态
Get-Service WinDefend,Sysmon64,EventLog,Schedule,Tasks | Select Name,Status,StartType
```

### 2.3 工具链

| 工具 | 用途 | 获取 |
|---|---|---|
| Sysmon（v15+）+ 社区配置 | 行为日志基座 | SwiftOnSecurity `sysmon-config`、`olafhartong/sysmon-modular` |
| Chainsaw | 基于 Sigma 的快速狩猎 | WithSecure（Rust 单文件） |
| Hayabusa | 全量 EVTX 时间线与检测 | Yamato-Security |
| Zircolite | Sigma 规则批处理（含 EVTX/SQLite） | wagga40 |
| EvtxECmd | EVTX → CSV/JSON 精解 | Eric Zimmerman |
| Velociraptor | 端点实时狩猎与采集 | Velocidex |
| sigma-cli | 规则语法检查与格式转换 | `pip install sigma-cli` |

### 2.4 受控执行的底线（走 C 路径才需要）

> **⚠️ 此操作具有风险，可能对被测主机造成不可逆的业务影响或数据丢失。**以下四条缺任意一条，就不要执行 C 路径：

1. **书面授权**：明确主机范围、时间窗口、允许的技术编号。无授权即未授权渗透。
2. **隔离环境**：独立 VM（非生产、不加入生产域），执行前打**快照**——回滚比 ART 自带的 `-Cleanup` 可靠。
3. **网络收敛**：断网或 NAT 限制出口，避免外联类用例打真实 C2，也避免被 SOC 误判为真实事件。
4. **逐条取证**：一条一跑、跑完立刻导出 EVTX、再跑 `-Cleanup`；异常则停止并回滚。

**禁止在这些主机上执行**：生产服务器、域控、办公机（包括你现在这台）、任何你在用的机器。

**⚠️ 高危用例**（第 4 节标 ⚠️）不建议真跑：`T1003.001`（会产生真实凭据文件）、`T1070.001`（会真删事件日志，毁掉取证能力）、`T1562.001`（会真关防护）。这三类请用回放或人工评审替代。

---

## 3. Atomic Red Team 的正确用法

### 3.1 安装（在隔离 VM 内）

```powershell
# 官方安装脚本：装到 C:\AtomicRedTeam
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

# 每次使用前加载
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
$PSDefaultParameterValues = @{ "Invoke-AtomicTest:PathToAtomicsFolder" = "C:\AtomicRedTeam\atomics" }
```

### 3.2 执行姿势（**别背用例编号**）

ART 的用例编号会随版本变化，任何写死编号的清单都会过期。正确做法是先枚举、再筛选：

```powershell
# 1) 枚举该技术下的所有用例（看编号、名称、支持平台、依赖）
Invoke-AtomicTest T1546.003 -ShowDetailsBrief

# 2) 查依赖与前置条件
Invoke-AtomicTest T1546.003 -CheckPrereqs

# 3) 按需自动补齐依赖（可能触发下载，隔离环境才做）
Invoke-AtomicTest T1546.003 -GetPrereqs

# 4) 执行单条用例（加超时避免挂死）
Invoke-AtomicTest T1546.003 -TestNumbers 1 -TimeoutSeconds 120

# 5) 立刻清理（不依赖它，但必须做）
Invoke-AtomicTest T1546.003 -TestNumbers 1 -Cleanup
```

因此本文表格给的是「**技术编号 + 行为描述 + 在 `-ShowDetailsBrief` 输出里按什么关键词挑用例**」，编号以你的 ART 版本实际输出为准。

### 3.3 逐条取证

```powershell
New-Item -ItemType Directory -Force D:\ir | Out-Null
wevtutil epl Microsoft-Windows-Sysmon/Operational          D:\ir\sysmon.evtx
wevtutil epl Security                                       D:\ir\security.evtx
wevtutil epl System                                         D:\ir\system.evtx
wevtutil epl Microsoft-Windows-PowerShell/Operational       D:\ir\ps-op.evtx
wevtutil epl Microsoft-Windows-TaskScheduler/Operational    D:\ir\taskschd.evtx
wevtutil epl Microsoft-Windows-WMI-Activity/Operational     D:\ir\wmi.evtx
```

---

## 4. 验证主表（按手册章节）

列说明：**期望日志**给出 Channel / EventID / 关键字段；**判定标准**给出「命中 / 半命中」的分界线，这是本文最该被抄走的部分。

### 4.1 执行与脚本（对应手册 §2、§附录 C）

| 编号 | 技术 | 触发动作（ART 定位关键词） | 期望日志 | 判定标准 | 手册 | 风险 |
|---|---|---|---|---|---|---|
| V-01 | T1059.001 | PowerShell 编码命令（`-EncodedCommand` / `-enc`；关键词 `encoded`、`base64`） | Sysmon 1（`Image=powershell.exe`，`CommandLine` 含 `-enc`）+ **4104**（`ScriptBlockText` 为解码后明文） | 1 与 4104 **都有**才算命中；只有 1 无 4104 = 半命中（脚本块日志未开） | §2.6、§5.6 | 低 |
| V-02 | T1059.001 | 内存下载执行（`IEX(IWR ...)`、`DownloadString`、`FromBase64String`） | 4104 全文；磁盘**无**落地文件 | 4104 有明文 + Sysmon 无对应 11 事件 = 验证「无文件可见性」 | §5.6 | 低 |
| V-03 | T1059.003 | `cmd.exe /c` 子进程链（`ParentImage` 异常） | Sysmon 1 + 4688（`CommandLine` 非空） | 4688 的 `CommandLine` 为空 = 事件 6 未开 | §5.6 | 低 |
| V-04 | T1047 | WMI 本地/远程执行（`wmic process call create`、CIM 方法调用） | Sysmon 1（`ParentImage=WmiPrvSE.exe`）+ WMI-Activity 5857/5860 | 有 1 无 5857 = 只够「看见父进程异常」，不够定性 | §2.4 | 低 |
| V-05 | T1218.011 | `rundll32` 执行远程脚本（JavaScript/VBScript） | Sysmon 1 + 7（`ImageLoaded` 路径非常规）+ 3（外联） | 三条齐 = 完整链路 | §附录 C | 低 |
| V-06 | T1218.005 | `mshta` 执行远程 HTA | 同 V-05 | 同上 | §附录 C | 低 |
| V-07 | T1218.010 | `regsvr32` SCT 回调（Squiblydoo） | Sysmon 1 + 3（外联目标非业务） | 有网络连接 = 可定性 | §附录 C | 低 |
| V-08 | T1059.005 | VBScript / WSH（`wscript`/`cscript`） | Sysmon 1（进程链）+ 4688 | 与日常登录脚本能否区分（白名单是否过宽） | §附录 C | 低 |

### 4.2 持久化 ★核心（对应手册 §3）

| 编号 | 技术 | 触发动作（关键词） | 期望日志 | 判定标准 | 手册 | 风险 |
|---|---|---|---|---|---|---|
| V-10 | T1547.001 | Run / RunOnce 键写入 | **Sysmon 13**（`TargetObject` 含 `\CurrentVersion\Run`） | 必须是 **13**（值设置）；只有 12 说明规则写歪了 | §3.1 | 低-中 |
| V-11 | T1543.003 | 服务创建 | **System 7045**（`ImagePath`、`ServiceType`）+ Sysmon 13 | 7045 与 13 能互相印证；7045 单独出现也可判定 | §3.3 | 中 |
| V-12 | T1543.003 | `ServiceDll` 劫持 | Sysmon 13（`TargetObject` 以 `\Parameters\ServiceDll` 结尾） | 写入路径非 `System32`/`SysWOW64` = 高危 | §3.3 | 中 |
| V-13 | T1543.003 | `FailureCommand` 后门 | Sysmon 13（`FailureCommand`） | 该键正常情况下**不应存在**，出现即查 | §3.3 | 中 |
| V-14 | T1053.005 | 计划任务创建 | Security 4698 + **TaskScheduler 106**（执行） | 若 106 拿不到 = §2.1 第 9 项未开，需先补日志源 | §3.4 | 中 |
| V-15 | T1546.003 | **WMI 事件订阅**（永久订阅） | **Sysmon 19 + 20 + 21** 三连 | **三件齐全**才算命中：只有 20（消费者）说明订阅未完成，或规则只抓了单一事件 | §3.5 | 中 |
| V-16 | T1546.012 | IFEO `Debugger` 劫持 | Sysmon 13（`Image File Execution Options`） | 该键指向非调试器 = 劫持 | §3.7 | 中 |
| V-17 | T1574.010 | `SilentProcessExit` `MonitorProcess` | Sysmon 13 | 该键**正常应为空**，有值即后门 | §3.7 | 中 |
| V-18 | T1546.002 | 屏保后门（`SCRNSAVE.EXE` 指向可执行文件） | Sysmon 13 + 进程创建 | `.scr` 路径异常 | §3.10 | 低 |
| V-19 | T1197 | BITS 任务持久化 | `Microsoft-Windows-Bits-Client/Operational` 3 | 该日志默认可能关闭，先验 §2.1 第 10 项 | §3.10 | 低 |
| V-20 | T1546.007 | Netsh Helper DLL | Sysmon 13（`Netsh\AddHelpers`） | 非系统 DLL = 可疑 | §3.10 | 低 |
| V-21 | T1547.014 | 网络提供程序劫持（Winsock2 命名空间） | Sysmon 13（`winsock2\...\Namespace_Catalog_Entries`） | 与 `netsh winsock show catalog` 交叉验证 | §3.10 | 中 |

### 4.3 进程注入与凭据（对应手册 §2.4、§4.4）

| 编号 | 技术 | 触发动作（关键词） | 期望日志 | 判定标准 | 手册 | 风险 |
|---|---|---|---|---|---|---|
| V-30 ★ | T1055 | 远程进程注入（`CreateRemoteThread`、`QueueUserAPC`） | **Sysmon 8** + **Sysmon 10**（`GrantedAccess` 如 `0x1F0FFF`/`0x143A`） | 关键在**源-目标配对**：`SourceImage` 非 `csrss`/`lsass`/`MpCmdRun` 而 `TargetImage` 为常见宿主 = 命中 | §2.4 | 中（可能致目标进程崩溃） |
| V-31 ★ | T1003.001 | LSASS 内存转储（comsvcs、procdump、直接读句柄） | Sysmon 10（`TargetImage=lsass.exe`）/ Sysmon 11（`.dmp` 落地）+ Security 4656 + Defender 1116/1117 | 三层中至少命中两层。**⚠️ 会产生真实凭据文件**，仅隔离环境，跑完立即安全删除（含可能同步到云端的副本） | §4.4 | **高** |
| V-32 | T1134 | 令牌窃取 / 复制 | Security 4672 + 4624 Type 9 + Sysmon 10 | Type 9 登录类型在正常环境极罕见，是强信号 | §4.4 | 中 |
| V-33 | T1555 | 浏览器 / 凭据文件读取 | 4663 或 Sysmon 11（`Login Data`、`Cookies` 路径） | 非浏览器进程读这些文件 = 命中 | §4.4 | 低 |

### 4.4 防御规避与痕迹（对应手册 §6、§7）

| 编号 | 技术 | 触发动作（关键词） | 期望日志 | 判定标准 | 手册 | 风险 |
|---|---|---|---|---|---|---|
| V-40 | T1562.001 | 关闭 Defender 实时保护 | System **5001/5007**（值 `1→0`） | 必须能看到「改之前 + 改之后」两条；只有一条说明日志级别不足 | §7.3 | **高**（会真降防护，请用回放替代） |
| V-41 | T1070.001 | 清除事件日志 | Security **1102** / System **104** | 清日志动作本身必须触发告警，否则最致命的反取证无人知晓 | §7.1 | **高**（毁证据，用回放替代） |
| V-42 | T1070.004 | 文件删除 | Sysmon **23/26** + USN Journal（`fsutil usn readjournal`） | 有 23/26 = 可追溯；无则靠 `$MFT` + USN 恢复 | §6.9 | 低 |
| V-43 | T1112 | 注册表修改（隐藏配置） | Sysmon 12/13 | 与基线快照比对 | §3 | 低 |
| V-44 ★ | T1070.006 | **文件时间戳篡改** | Sysmon **2**（`FileCreateTime changed`） | 这条最常被漏配：`FileCreateTime` 事件在默认配置里往往被关；无 2 = 时间线不可信且不自知 | §5.5 | 低 |
| V-45 | T1564.004 | ADS 备用数据流写入 | Sysmon **15**（`FileCreateStreamHash`） | 与文件扫描脚本交叉验证 | §6.2 | 低 |
| V-46 | T1218.* | LOLBins 批量（附录 C 的 20+ 项） | Sysmon 1 + 4688 | 逐条过，标出「本环境白名单是否放得太宽」 | §附录 C | 低 |

### 4.5 横向移动（对应手册 §1.4、§4）

| 编号 | 技术 | 触发动作（关键词） | 期望日志 | 判定标准 | 手册 | 风险 |
|---|---|---|---|---|---|---|
| V-50 | T1021.001 | RDP 登录 | **1149（含源 IP）** + 4624 Type 10 + 4625（失败） | 只有 4624 拿不到源 IP = §2.1 第 12 项未开 | §4.2 | 低 |
| V-51 | T1021.002 | SMB 管理共享访问 | 5140 / 5145（`ADMIN$`、`C$`）+ 4624 Type 3 | 对象访问审核未开会全哑 | §1.4 | 低 |
| V-52 | T1021.006 | WinRM 远程执行 | `WinRM/Operational` + 4624 Type 3 + 4688 | 与正常运维脚本的区分度 | §1.4 | 低 |
| V-53 | T1569.002 | PsExec 型服务横向 | 7045（随机名服务）+ 4624 Type 3 + 5145 | 7045 服务名随机 + `ImagePath` 指向 `ADMIN$` = 命中 | §3.3 | 中 |
| V-54 | T1550.002 | 哈希传递 | 4624 Type 3（`NTLM`、无失败登录）+ 4672 | 无 4625 却有高权限登录 = 可疑 | §4.4 | 中 |

### 4.6 业务中间件（**ART 不覆盖，需自造用例**）

这一类是本项目相对通用检测清单的差异化价值所在——**没有任何社区原子测试覆盖 XXL-JOB 这类业务调度平台后门**。

| 编号 | 对象 | 自造验证动作 | 期望痕迹 | 判定标准 | 手册 | 风险 |
|---|---|---|---|---|---|---|
| V-60 ★ | XXL-JOB | 在测试库改 `xxl_job_info.glue_type` / `glue_source`，触发一次调度 | 调度中心日志（登录/任务变更）、执行器 `gluesource` 目录 mtime 变化、进程链 `java → sh -c → 落地产物` | 「任务变更 → 执行器拉取 → 命令执行」三者时间相邻 = 命中；只有数据库变更无执行痕迹 = 检测深度不足 | §8.2 | 中（需独立测试实例） |
| V-61 | IIS / .NET | 投放模块化后门 / 内存马（测试站点） | `w3wp.exe` 模块列表（`Get-Process -Id <pid> -Module`）、AppDomain 程序集、`wwwroot` 文件 mtime | 模块路径不在 `Microsoft.NET` / `System32` 下 = 命中 | §8.3 | 中 |
| V-62 | SQL Server | 自启动存储过程 / SQL Agent 作业 / CLR 程序集 | `sys.sp_configure`、`msdb.dbo.sysjobs`、`sys.assemblies` | 新增 CLR 程序集且 `permission_set=UNSAFE` = 高危 | §8.4 | 低 |
| V-63 | Jenkins | 凭据读取 + 流水线脚本执行 | Jenkins 审计日志 + 构建日志 + 子进程链 | 构建任务的子进程异常外联 = 命中 | §8.4 | 中 |

---

## 5. 判定口径与记录

### 5.1 三态判定

| 判定 | 含义 | 后续动作 |
|---|---|---|
| **命中** | 预期事件出现、关键字段完整、且能被规则/查询自动筛出 | 记录证据文件名，纳入「已验证」清单 |
| **半命中** | 事件在，但字段缺失（如 4688 无 `CommandLine`）或规则不触发 | 补日志源或改规则，**然后重跑**——不许记成「已验证」 |
| **未命中** | 没有预期事件 | 按 5.2 排查根因 |

### 5.2 未命中的根因排查顺序（按实际概率排序）

1. **日志源未开**（占绝大多数）→ 返回 §2.1 逐项核对
2. **字段被裁剪**（Sysmon 配置 `Exclude`、4688 命令行未开、规则依赖的字段被过滤）→ 比对 Sysmon 配置版本
3. **基础设施差异**（日志被滚动覆盖、`wevtutil` 导出时使用了过滤）→ 核对日志容量
4. **规则逻辑错**（字段名写错、过度依赖单一事件、白名单过宽）→ 走 A 路径静态复核

### 5.3 记录表模板

| 编号 | 技术 | 执行方式（回放/真跑） | 时间 | 判定 | 证据文件 | 根因 | 修复动作 | 复查 |
|---|---|---|---|---|---|---|---|---|
| V-15 | T1546.003 | 真跑 | 2026-09-18 22:40 | 半命中（缺 21） | `sysmon.evtx` | 规则只匹配 19/20 | 补 21 分支 | 待复查 |

### 5.4 回归机制

- 用例集纳入版本控制（本文即用例源），**规则变更即触发回归**
- 建议把「已验证清单」与 `windows-hardening.md` 的整改项合并成一张台账，避免两处维护
- 每次系统大版本升级（尤其 Windows 累积更新 / Sysmon 升级）后重跑 §2.1

---

## 6. 覆盖矩阵：哪些能回放、哪些必须真跑

| 手册检测点 | 建议路径 | 理由 |
|---|---|---|
| 执行与脚本类（V-01～V-08） | **B 回放** | EVTX-ATTACK-SAMPLES 覆盖完整，无需真跑 |
| Run 键 / 服务 / 任务（V-10、V-11、V-14） | **B 回放** | 有现成样本日志 |
| **WMI 事件订阅三连**（V-15） | **C 真跑** | 三件事件的**关联关系**是检测核心，样本日志常缺其一 |
| IFEO / SilentProcessExit（V-16、V-17） | C 真跑 | 需要真实注册表写入序列 |
| **进程注入**（V-30） | **C 真跑** | 依赖运行态，Sysmon 8/10 的 `GrantedAccess` 值必须实测 |
| **时间戳篡改**（V-44） | C 真跑 | 验证「Sysmon 2 是否被配置关掉」只能实测 |
| **LSASS 访问**（V-31） | 回放 + 人工评审 | ⚠️ 真跑会产生真实凭据文件，风险不可接受 |
| 清日志 / 关防护（V-40、V-41） | **回放**（禁止真跑） | 破坏取证能力与主机态势 |
| 横向移动类（V-50～V-54） | B 回放 | 需多机环境，回放成本更低 |
| **业务中间件类**（V-60～V-63） | **自造用例** | 无社区覆盖，必须自建 |

---

## 7. 已知盲区

诚实列出来，比假装「全覆盖」有价值——这也是评估一个检测方案是否专业的标志。

| # | 盲区 | 为什么验证不了 | 需要什么补充 |
|---|---|---|---|
| 1 | 内核态 Rootkit | Sysmon 6 只能看到驱动加载，看不到驱动**行为** | 驱动签名核查 + 内存镜像分析 + 完整性基线 |
| 2 | BYOVD 卸载 EDR 之后的行为窗口 | 采集通道本身可能已被摘除，日志出现静默空洞 | 独立采集通道（WEF/远端 syslog）+ 心跳缺口检测 |
| 3 | 固件 / 引导区持久化 | 操作系统层面不可见 | SPI 闪存校验、UEFI 变量审计（`Get-SecureBootUEFI`） |
| 4 | 内存马（.NET / Java / PHP 无文件 WebShell） | 磁盘无落地文件，日志只有 HTTP 请求 | pe-sieve / HollowsHunter 扫进程 + 内存镜像 + 中间件侧字节码审计 |
| 5 | 业务调度平台后门（XXL-JOB 等） | 无社区原子测试，行为与正常任务高度相似 | 自造用例（V-60）+ 数据库变更审计 |
| 6 | 加密 C2 流量 | 主机侧只剩连接元数据（Sysmon 3/22） | 网络侧（JA3/JA4、流量行为基线）— 超出主机排查范围 |
| 7 | 云身份滥用（AAD Token、OAuth 应用、条件访问绕过） | 主机日志完全覆盖不到 | 云审计日志（Entra ID 登录日志、应用授权变更） |
| 8 | 供应链植入（签名合法） | 签名有效、路径正常，静态特征全过 | 软件物料清单（SBOM）+ 文件哈希基线 + 行为监控 |

---

## 8. 静态验证：Sigma 规则

### 8.1 检查与转换

```bash
pip install sigma-cli

# 语法与字段检查（对应路径 A）
sigma check rules/

# 转换成本地可用格式
sigma convert -t splunk -p splunk_windows rules/windows/registry/registry_set/xxx.yml
sigma convert -t microsoft365defender rules/windows/process_creation/xxx.yml
```

### 8.2 对应本手册检测点的基线规则示例

> 以下为**基线示例**，直接使用前必须按环境白名单收敛，否则误报会淹掉真事件。

**① ServiceDll 注册（手册 §3.3）**

```yaml
title: ServiceDll 指向非系统目录（服务宿主型后门）
logsource:
  product: windows
  category: registry_set
detection:
  selection_key:
    TargetObject|endswith: '\Parameters\ServiceDll'
  filter_legit:
    Details|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
      - 'C:\Program Files\'
  condition: selection_key and not filter_legit
level: high
```

**② WMI 事件订阅三连（手册 §3.5）**

```yaml
title: WMI 事件订阅创建（Filter / Consumer / Binding）
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 19   # WmiEventFilter
      - 20   # WmiEventConsumer
      - 21   # WmiEventConsumerToFilter
  condition: selection
level: high
```

**③ 脚本块中的下载执行（手册 §5.6）**

```yaml
title: PowerShell 脚本块中的可疑下载执行
logsource:
  product: windows
  service: powershell
  definition: 需启用 ScriptBlockLogging（事件 4104）
detection:
  selection:
    EventID: 4104
  keywords:
    - 'FromBase64String'
    - 'Invoke-Expression'
    - 'IEX'
    - 'DownloadString'
    - 'Net.WebClient'
    - 'AmsiUtils'
  condition: selection and keywords
level: high
```

**④ 文件时间戳篡改（手册 §5.5）**

```yaml
title: 文件创建时间被修改（时间戳伪造）
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 2
  filter_system:
    Image|startswith: 'C:\Windows\'
  condition: selection and not filter_system
level: medium
```

**⑤ LSASS 进程访问（手册 §4.4）**

```yaml
title: 对 LSASS 的进程访问（疑似凭据转储）
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
  filter_legit:
    SourceImage|endswith:
      - '\MsMpEng.exe'
      - '\csrss.exe'
      - '\svchost.exe'
      - '\MpCmdRun.exe'
  condition: selection and not filter_legit
level: critical
```

---

## 9. 与 MCP + AI Agent 规划的衔接

本清单天然适合作为 Agent 的**检测能力回归测试集**，这是「自动化巡检」落地时最先要解决的问题。

| 层次 | 用例表提供什么 | Agent 侧动作 |
|---|---|---|
| 巡检前置自检 | §2.1 的 14 项日志源核查 | 每次巡检**先跑自查**，日志源缺失直接告警，避免「查了但没数据」的假阴性 |
| 机器可读用例 | 编号 / 技术 / 期望 Channel+EventID / 判定表达式 | 输出 JSON 用例集，Agent 自动执行查询并判定命中 |
| 结论汇总 | §5.3 记录表 | Agent 生成 `detection-validation-report.md`：命中率、缺口清单、修复建议，直接对接 `windows-hardening.md` 整改 |
| 人在回路 | ⚠️ 高危用例标记 | 高危项必须人工确认，Agent 只做只读查询、不执行攻击动作 |

**设计约束**（与 `windows-forensics-toolchain.md` 第 5 节一致）：只读、白名单查询、参数校验、不执行任何攻击性动作。Agent 的职责是**验证检测能力**，不是**发起攻击**。

---

## 附录 A：受控执行 Checklist

执行 C 路径前逐项打勾，任一不满足即停止：

- [ ] 书面授权已获取，含主机清单、时间窗口、允许技术编号
- [ ] 被测主机为独立 VM，**未加入生产域**
- [ ] 已打 VM 快照，且已验证可回滚
- [ ] 网络已断或出口已限制（防止打到真实 C2）
- [ ] Sysmon + 4104 + 4688 命令行 + 审核策略均已开启并验证有数据
- [ ] 已确认 ⚠️ 高危用例（T1003.001 / T1070.001 / T1562.001）改为回放
- [ ] 准备逐条取证脚本（`wevtutil epl`）
- [ ] 执行后 24h 内回滚快照，并复核残留（服务、任务、注册表键、WMI 订阅）

**清残留复核命令**（防止测试本身留下后门）：

```powershell
# ART 残留复核：服务 / 任务 / 注册表 Run / WMI 订阅
Get-Service | Where-Object { $_.Name -match 'art|atomic|test' }
Get-ScheduledTask | Where-Object { $_.TaskName -match 'art|atomic|test' }
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' |
  Select-Object -Property * -ExcludeProperty PS*
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding
```

---

## 附录 B：日志导出与分析命令

```powershell
# 导出（逐条取证用）
wevtutil epl Microsoft-Windows-Sysmon/Operational D:\ir\sysmon.evtx
wevtutil epl Security D:\ir\security.evtx

# 快速确认某个事件到底有没有
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=19,20,21} -MaxEvents 5 |
  Format-List TimeCreated, Id, Message

# 确认日志源是否有数据（返回空 = 日志源没开，不是没有攻击）
Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 1
```

```powershell
# Hayabusa：全量 EVTX → 时间线
.\hayabusa.exe csv-timeline -d D:\ir\evtx -o D:\ir\timeline.csv

# Chainsaw：用 Sigma 规则批量狩猎
.\chainsaw.exe hunt D:\ir\evtx -s .\sigma\rules --mapping .\mappings\sigma-event-logs-all.yml -o D:\ir\hunt.json
```

> 日志源核查项与判定口径同时内置于 `scripts/windows-ir-quickcheck.ps1`，现场可直接用它跑第 2.1 节。

---

**相关文档**

- `windows-host-audit.md` —— 手册主体，本清单的技术编号与章节引用来源
- `windows-attack-mapping.md` —— 攻击手法与落地痕迹对照
- `windows-hardening.md` —— 验证发现的缺口在此落地整改
- `windows-forensics-toolchain.md` —— 工具获取与 MCP + AI Agent 设计
