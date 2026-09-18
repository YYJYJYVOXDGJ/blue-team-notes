# Windows 加固基线与核查项（蓝队）

> 定位：**排查之后的收口**。用于安全评估、攻防演习前的主机基线巡检、以及应急响应结束后的加固落地。
> 与主手册的关系：主手册第 9.6 节是"应急后立刻要做的 10 件事"，本文是完整的基线核查表。
> 与行业标准的关系：核查项对齐 **CIS Microsoft Windows 11 / Server 2022 Benchmark**、**Microsoft Security Baselines**、**等保 2.0 主机安全要求**。

## 目录

- [1. 基线核查的定位与方法](#1-基线核查的定位与方法)
- [2. 核查项清单](#2-核查项清单)
- [3. 基线核查流程](#3-基线核查流程)
- [4. 自动化核查与加固](#4-自动化核查与加固)
- [5. 加固的风险控制](#5-加固的风险控制)
- [6. 高价值加固优先级（先做这些）](#6-高价值加固优先级先做这些)

---

## 1. 基线核查的定位与方法

### 1.1 基线核查真正在解决的问题

很多人把基线核查做成"对着表格打勾"。它其实要回答三个问题：

| 问题 | 对应核查内容 |
|---|---|
| **如果现在被打，我能不能查到？** | 日志、审计、Sysmon、EDR、日志外发（第 2.5 节） |
| **如果现在被打，我能不能挡住？** | ASR、WDAC、Defender、补丁、攻击面（第 2.6/2.9 节） |
| **如果已经被打，我还有没有底牌？** | 备份、卷影、凭据保护、最小权限（第 2.1/2.10 节） |

**只做"合规项"而不做前三项的基线，等于给自己制造虚假安全感。**

### 1.2 核查方法与判定原则

```powershell
# 所有核查命令都是只读的。统一以管理员身份运行。
# 建议先建立核查输出目录
New-Item -ItemType Directory -Path "C:\Baseline\<主机名>-<日期>" -Force
```

**判定原则**

- **可验证**：每条都要有"能跑的命令 + 明确的合格标准"，不做"应加强管理"这类不可验证的表述；
- **分级**：按风险等级排序，先修高危；不做"全部整改"这种无法执行的结论；
- **留痕**：核查结果落盘存档，加时间戳，便于下次对比；
- **闭环**：加固后必须**重跑同一条命令验证**，而不是"改完就算"。

### 1.3 风险等级定义

| 等级 | 含义 | 处置时限建议 |
|---|---|---|
| **P0 高危** | 直接导致失陷、失陷后无法发现、或凭据大规模泄露 | 立即（24 小时内） |
| **P1 中危** | 显著扩大攻击面或降低检测能力 | 1–2 周 |
| **P2 低危** | 纵深防御层面的改进项 | 1 个月内或结合版本迭代 |

---

## 2. 核查项清单

### 2.1 账号与认证（P0 集中区）

| # | 核查项 | 核查命令 | 合格标准 | 等级 |
|---|---|---|---|---|
| 1 | 本地管理员组人数受控 | `Get-LocalGroupMember Administrators` | 仅必要的管理员账号，无未知账号 | P0 |
| 2 | 内置 Administrator 状态 | `Get-LocalUser Administrator \| Select Name,Enabled` | 已禁用或已改名 + 强密码 | P0 |
| 3 | Guest 账号 | `Get-LocalUser Guest \| Select Enabled` | 禁用 | P0 |
| 4 | 无多余本地账号 | `Get-LocalUser` | 每个账号有明确用途与责任人 | P0 |
| 5 | 无空口令 / 口令永不过期账号 | `Get-LocalUser \| Where { -not $_.PasswordRequired }` | 无空口令账号 | P0 |
| 6 | 无 `$` 结尾隐藏账号 | `Get-LocalUser \| Where Name -match '\$$'` | 无计划外账号 | P0 |
| 7 | 密码策略合规 | `net accounts` | 长度 ≥ 14；启用复杂度；最长使用期 ≤ 90 天 | P1 |
| 8 | 账户锁定策略 | `net accounts` | 阈值 ≤ 10 次，锁定时长 ≥ 15 分钟 | P1 |
| 9 | 本地管理员密码唯一化 | `Get-LapsADPassword` / LAPS 配置 | 已启用 Windows LAPS | P0 |
| 10 | WDigest 明文缓存 | `Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"` | `UseLogonCredential = 0` 或不存在 | P0 |
| 11 | Credential Guard | `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard` | 状态 = 运行中 | P1 |
| 12 | LSASS 保护 | `Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" \| Select RunAsPPL` | `RunAsPPL = 1` | P0 |
| 13 | 特权组成员最小化 | `Get-LocalGroupMember` 各特权组 | 无业务无关成员 | P1 |
| 14 | 免密自动登录 | `Get-ItemProperty "...\Winlogon" \| Select AutoAdminLogon,DefaultPassword` | 未启用；无明文密码 | P0 |
| 15 | SAM 隐藏账号 | SYSTEM 权限读 SAM；`SpecialAccounts\UserList` | 无隐藏账号 | P0 |

### 2.2 权限与访问控制

| # | 核查项 | 核查命令 | 合格标准 | 等级 |
|---|---|---|---|---|
| 16 | UAC 启用 | `Get-ItemProperty "HKLM:\...\Policies\System" \| Select EnableLUA` | `EnableLUA = 1` | P0 |
| 17 | UAC 提示级别 | 同上，`ConsentPromptBehaviorAdmin` | = 2 或 4（不明显降低） | P1 |
| 18 | 危险用户权限受控 | `secedit /export /cfg secpol.cfg /areas USER_RIGHTS` | `SeDebugPrivilege`/`SeBackupPrivilege`/`SeImpersonatePrivilege` 仅限必要账号 | P0 |
| 19 | 匿名枚举被禁用 | 同上，`LSAAnonymousNameLookup` | = 0 | P1 |
| 20 | 匿名 SID/名称转换 | `RestrictAnonymous` / `RestrictAnonymousSAM` | = 1 | P1 |
| 21 | AlwaysInstallElevated | 检查 HKLM + HKCU 两处 | 均为 0 / 不存在 | P0 |
| 22 | 文件系统权限 | `icacls` 检查敏感目录 | 无 `Everyone:F` / `Users:W` 于系统目录 | P1 |
| 23 | 未加引号的服务路径 | 见主手册 3.2 | 无未加引号且含空格的服务路径 | P0 |
| 24 | 服务账户最小权限 | `Get-CimInstance Win32_Service \| Select Name,StartName` | 非必要不使用 LocalSystem | P1 |

### 2.3 网络与远程访问

| # | 核查项 | 核查命令 | 合格标准 | 等级 |
|---|---|---|---|---|
| 25 | 监听端口最小化 | `Get-NetTCPConnection -State Listen` | 无非法暴露端口 | P0 |
| 26 | 防火墙启用（三配置文件） | `Get-NetFirewallProfile \| Select Name,Enabled` | 全部 Enabled | P0 |
| 27 | 入向默认阻断 | 同上，`DefaultInboundAction` | = Block | P0 |
| 28 | 无异常入向放行规则 | `Get-NetFirewallRule -Direction Inbound -Action Allow` | 逐条有业务依据 | P1 |
| 29 | 无端口转发后门 | `netsh interface portproxy show all` | 无条目（除业务明确需要） | P0 |
| 30 | 无代理劫持 | `netsh winhttp show proxy`；Internet Settings | 无未授权的代理 / PAC | P0 |
| 31 | RDP 状态 | `Get-ItemProperty "...\Terminal Server" \| Select fDenyTSConnections` | 非必要则 = 1（禁用） | P0 |
| 32 | RDP 使用 NLA | `...\WinStations\RDP-Tcp` 的 `UserAuthentication` | = 1 | P0 |
| 33 | RDP 安全层 | 同上 `SecurityLayer` | = 2（SSL/TLS） | P1 |
| 34 | RDP 端口未改 + 来源受限 | 防火墙规则 | 仅允许跳板/VPN 访问 | P1 |
| 35 | RDP Wrapper 未安装 | `Test-Path "C:\Program Files\RDP Wrapper"` | 不存在 | P0 |
| 36 | SMBv1 已禁用 | `Get-SmbServerConfiguration \| Select EnableSMB1Protocol` | = False | P0 |
| 37 | SMB 签名强制 | `Get-SmbServerConfiguration \| Select RequireSecuritySignature` | = True | P1 |
| 38 | 管理共享受控 | `net share` / `Get-SmbShare` | 无额外共享；IPC$/ADMIN$ 按需 | P1 |
| 39 | WinRM 状态 | `Get-Service WinRM`；`winrm enumerate winrm/config/listener` | 非必要则禁用 | P1 |
| 40 | 远程注册表服务 | `Get-Service RemoteRegistry` | 已禁用 | P1 |
| 41 | 网络协议最小化 | `Get-NetAdapterBinding`、`Get-WindowsOptionalFeature` | 禁用 NetBIOS/TFTP/SNMP 等非必要协议 | P1 |
| 42 | LLMNR / NetBIOS 名称解析 | 组策略或注册表 | 禁用（防投毒） | P1 |
| 43 | 无线与蓝牙 | `Get-NetAdapter` | 服务器无必要则禁用 | P2 |

### 2.4 服务、驱动与计划任务

| # | 核查项 | 核查命令 | 合格标准 | 等级 |
|---|---|---|---|---|
| 44 | 无多余服务 | `Get-Service \| Where StartType -eq Automatic` | 每个服务有业务依据 | P1 |
| 45 | 服务路径规范 | 见主手册 3.2 | 无指向用户目录 / TEMP 的服务 | P0 |
| 46 | ServiceDll 指向正常 | 见主手册 3.2 | svchost 服务的 ServiceDll 均为微软路径 | P0 |
| 47 | 无 FailureCommand 后门 | 见主手册 3.2 | 无异常失败恢复命令 | P0 |
| 48 | 驱动签名合规 | `Get-CimInstance Win32_SystemDriver` + 签名校验 | 全部有效签名 | P0 |
| 49 | 无恶意 minifilter | `fltmc filters` | 无未授权过滤驱动 | P0 |
| 50 | 无高危易受攻击驱动 | 对照 LOLDrivers 清单 | 无已知 BYOVD 驱动 | P0 |
| 51 | 计划任务规范 | 见主手册 3.3 | 无隐藏任务、无指向 LOLBin 的可疑任务 | P0 |
| 52 | 无 WMI 持久化 | 见主手册 3.4 | `__EventFilter` 等表为空 | P0 |
| 53 | 无 BITS 异常任务 | `Get-BitsTransfer -AllUsers` | 无未知任务 | P1 |

### 2.5 日志与审计（**最容易被跳过，也最致命**）

| # | 核查项 | 核查命令 | 合格标准 | 等级 |
|---|---|---|---|---|
| 54 | 命令行审计开启 | `Get-ItemProperty "HKLM:\...\Policies\System\Audit"` | `ProcessCreationIncludeCmdLine_Enabled = 1` | P0 |
| 55 | 进程创建审计 | `auditpol /get /subcategory:"Process Creation"` | 成功 + 失败 | P0 |
| 56 | 登录审计 | `auditpol /get /category:*` | 登录/注销、账户管理、策略更改、特权使用均开启 | P0 |
| 57 | PowerShell 脚本块日志 | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` | `EnableScriptBlockLogging = 1` | P0 |
| 58 | PowerShell 模块日志 | 同上 `ModuleLogging` | = 1 | P1 |
| 59 | PowerShell 转录 | 同上 `Transcription` | = 1 | P1 |
| 60 | Security 日志容量 | `wevtutil gl Security` | ≥ 512 MB，LogMode 为 AutoBackup | P0 |
| 61 | 关键日志未禁用 | `Get-WinEvent -ListLog * \| Where IsEnabled -eq $false` | 关键通道全部启用 | P0 |
| 62 | 日志外发（WEF/SIEM） | `wecutil gs`、Agent 服务 | 已配置集中收集 | P0 |
| 63 | Sysmon 已部署 | `Get-Service Sysmon64` | 运行中 + 有配置 | P0 |
| 64 | Sysmon 配置完整 | `sysmon64 -c` | 覆盖进程/网络/注册表/镜像加载 | P1 |
| 65 | 系统时间同步 | `w32tm /query /status` | 已同步且与实际一致 | P1 |
| 66 | 事件日志被清痕迹 | `Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102}` | 无异常记录 | P0 |

> **关于第 54–63 项的重要性**：这些是"失陷时能不能查"的前提。基线评估里如果只报"密码策略不达标"，而不报"命令行审计未开启"，那是**评估方向错了**。

### 2.6 端点防护

| # | 核查项 | 核查命令 | 合格标准 | 等级 |
|---|---|---|---|---|
| 67 | Defender 实时保护 | `Get-MpComputerStatus` | `RealTimeProtectionEnabled = True` | P0 |
| 68 | 行为监控 | 同上 | `BehaviorMonitorEnabled = True` | P0 |
| 69 | 云保护 | `Get-MpPreference \| Select MAPSReporting,SubmitSamplesConsent` | 已启用 | P1 |
| 70 | 特征库时效 | `Get-MpComputerStatus \| Select AntivirusSignatureLastUpdated` | ≤ 1 天 | P1 |
| 71 | **排除项审计** | `Get-MpPreference \| Select Exclusion*` | 排除项有明确依据（**攻击者最爱的入口**） | P0 |
| 72 | Defender 策略未被削弱 | `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender` | 无 `DisableAntiSpyware` 等 | P0 |
| 73 | ASR 规则状态 | `Get-MpPreference \| Select AttackSurfaceReductionRules_*` | 关键规则为 Block（见 2.9） | P0 |
| 74 | 受控文件夹访问 | `Get-MpPreference \| Select EnableControlledFolderAccess` | = 1（Enabled）或 2（Audit） | P1 |
| 75 | 篡改保护 | `Get-MpComputerStatus \| Select IsTamperProtected` | = True | P1 |
| 76 | 网络保护 | `Get-MpPreference \| Select EnableNetworkProtection` | ≥ 1 | P1 |
| 77 | EDR / XDR Agent 在线 | 对应服务与进程 | 运行中且未被卸载 | P0 |
| 78 | 应用白名单（WDAC/AppLocker） | `Get-AppLockerPolicy`；WDAC 策略 | 已部署或已规划 | P1 |
| 79 | 设备控制（USB） | 组策略 / 注册表 | 非必要禁用大容量存储 | P2 |

### 2.7 凭据保护

| # | 核查项 | 核查命令 | 合格标准 | 等级 |
|---|---|---|---|---|
| 80 | LAPS 启用 | LAPS 策略注册表 + 事件 | 已启用并轮换 | P0 |
| 81 | Credential Guard | `Win32_DeviceGuard` | 运行中 | P1 |
| 82 | LSASS RunAsPPL | 注册表 | = 1 | P0 |
| 83 | 无明文凭据落盘 | 搜 `.aws`/`.git-credentials`/脚本内密码 | 无明文凭据 | P0 |
| 84 | 无人值守远控密码 | 远控软件配置 | 无固定密码；非业务远控已卸载 | P0 |
| 85 | 浏览器保存密码策略 | 组策略 | 按需禁用或结合密码管理器 | P2 |
| 86 | 证书私钥保护 | `Get-ChildItem Cert:\LocalMachine\My` | 私钥不可导出或已标记 | P1 |
| 87 | Kerberos 相关（域） | krbtgt 密码年龄、AES 强制 | 符合域安全基线 | P1 |
| 88 | NTLM 使用审计/限制 | 组策略 `LmCompatibilityLevel` | ≥ 3，理想为 5 | P1 |

### 2.8 Office、脚本与浏览器（攻击面）

| # | 核查项 | 核查命令 | 合格标准 | 等级 |
|---|---|---|---|---|
| 89 | Office 宏策略 | 组策略 / `HKCU:\Software\Policies\Microsoft\Office\*\*\Security` | 阻止来自 Internet 的宏 | P0 |
| 90 | 受信任位置最小化 | 同上 `Trusted Locations` | 无用户可写的宽泛目录 | P1 |
| 91 | 无人值守 Office 加载项 | `HKCU:\...\Office\*\*\Addins` | 仅业务必需 | P1 |
| 92 | `VbaProject.OTM` | 文件是否存在 | 不存在（宏后门高频位置） | P0 |
| 93 | WSH 脚本策略 | 组策略 | 按需限制 `wscript/cscript` | P2 |
| 94 | PowerShell 执行策略 | `Get-ExecutionPolicy -List` | 企业由组策略统一（非 AllSigned 也可，但需配合日志） | P2 |
| 95 | PowerShell 约束语言模式 | 组策略 | 高价值服务器启用 ConstrainedLanguage | P1 |
| 96 | 浏览器强制扩展 | `ExtensionInstallForcelist` | 无未知强制扩展 | P0 |
| 97 | 浏览器自动更新 | 版本检查 | 最新稳定版 | P1 |
| 98 | 危险文件类型关联 | `assoc` / `ftype` | 未被改指向脚本解释器 | P1 |
| 99 | LNK 显示扩展名 | 资源管理器选项 | 已显示已知扩展名 | P2 |
| 100 | AutoRun/AutoPlay 禁用 | 组策略 / `NoDriveTypeAutoRun` | = 255 | P1 |

### 2.9 补丁、更新与基线一致性

| # | 核查项 | 核查命令 | 合格标准 | 等级 |
|---|---|---|---|---|
| 101 | 操作系统补丁 | `Get-HotFix \| Sort InstalledOn -Desc` | 无超过 60 天的关键补丁缺口 | P0 |
| 102 | 应用补丁（Exchange/IIS/SQL/浏览器/Java） | 各应用版本核对 | 无已知在野利用漏洞 | P0 |
| 103 | 更新服务配置 | `Get-Service wuauserv`；WSUS/Intune 配置 | 受统一管理 | P1 |
| 104 | 安全启动与固件 | `Confirm-SecureBootUEFI`；`Get-Tpm` | 安全启动开启、TPM 可用 | P1 |
| 105 | 系统完整性 | `sfc /verifyonly`；`DISM /ScanHealth` | 无完整性错误 | P1 |
| 106 | 基线一致性（关键注册表） | 与基线导出 diff | 无差异或差异有依据 | P1 |
| 107 | 未安装非必要软件 | `Get-ItemProperty "...\Uninstall\*"` | 无远控/破解/非授权工具 | P1 |
| 108 | 时间同步与审计合规 | `w32tm`、日志留存周期 | 满足等保/内控要求的留存期 | P1 |

### 2.10 备份与恢复（对抗勒索的底线）

| # | 核查项 | 核查命令 | 合格标准 | 等级 |
|---|---|---|---|---|
| 109 | 备份存在且可读 | 备份系统控制台 / `wbadmin get versions` | 有近期成功备份 | P0 |
| 110 | 离线/不可变备份 | 备份架构评审 | 至少一份离线或不可变（防勒索删备份） | P0 |
| 111 | 卷影副本 | `vssadmin list shadows` | 按需开启且保留合理 | P1 |
| 112 | 备份凭据隔离 | 凭据管理评审 | 备份账号与主机本地账号不同 | P0 |
| 113 | 恢复演练记录 | 演练文档 | 近 6 个月内有成功恢复演练 | P1 |
| 114 | 恢复环境可用 | `reagentc /info` | WinRE 可用且未被禁用 | P1 |

---

## 3. 基线核查流程

```
0. 准备
   └─ 获取授权（书面）→ 明确范围 → 确定核查时间窗（避开业务高峰）
       └─ 建输出目录、确认管理员权限

1. 只读核查（本阶段不改任何配置）
   └─ 按第 2 节逐类执行 → 结果落盘
       └─ 关键：先导出"现状快照"，便于加固后对比

2. 分级与定责
   └─ 按 P0/P1/P2 分类 → 每项标注：影响、依据、建议动作、责任方
       └─ P0 立即上报，不等到报告写完

3. 加固（按优先级执行）
   └─ 先做"提升可见性"的（日志/Sysmon/ASR）——它们不改变业务行为，风险最低
       └─ 再做"收敛攻击面"的（RDP/SMB/服务/账号）
           └─ 最后做"限制性"的（WDAC/约束语言模式）——需先审计模式验证

4. 验证
   └─ 重跑同一条核查命令 → 贴到报告里作为证据
       └─ 对无法立即整改的，登记为"接受的风险"并写明缓解措施

5. 复核与运营
   └─ 季度复核 P1/P2；关键项纳入变更管理
       └─ 把核查项做成脚本，纳入日常巡检（见第 4 节）
```

**现场执行建议**

```powershell
# 一次性建立基线快照（只读，可作为"核查前"存档与后续 diff 的基线）
$out = "C:\Baseline\$(hostname)-$(Get-Date -f yyyyMMdd-HHmm)"
New-Item -ItemType Directory $out -Force | Out-Null

# 账号
Get-LocalUser | Export-Csv "$out\users.csv" -NoTypeInformation -Encoding UTF8
Get-LocalGroup | ForEach-Object {
  Get-LocalGroupMember $_.Name -EA SilentlyContinue |
    Select-Object @{n='Group';e={$_.Name}},Name,PrincipalSource,ObjectClass
} | Export-Csv "$out\groupmembers.csv" -NoTypeInformation -Encoding UTF8

# 安全策略
secedit /export /cfg "$out\secpol.cfg"
auditpol /get /category:* > "$out\auditpol.txt"
net accounts > "$out\netaccounts.txt"

# 网络
Get-NetTCPConnection -State Listen | Export-Csv "$out\listen.csv" -NoTypeInformation -Encoding UTF8
Get-NetFirewallProfile | Export-Csv "$out\fwprofile.csv" -NoTypeInformation -Encoding UTF8
Get-NetFirewallRule | Export-Csv "$out\fwrules.csv" -NoTypeInformation -Encoding UTF8
netsh interface portproxy show all > "$out\portproxy.txt"
netsh winhttp show proxy > "$out\winhttp.txt"

# 服务与驱动
Get-CimInstance Win32_Service | Select Name,DisplayName,State,StartMode,StartName,PathName |
  Export-Csv "$out\services.csv" -NoTypeInformation -Encoding UTF8
Get-CimInstance Win32_SystemDriver | Select Name,State,StartMode,PathName |
  Export-Csv "$out\drivers.csv" -NoTypeInformation -Encoding UTF8
fltmc filters > "$out\fltmc.txt"

# 持久化
autorunsc64.exe -accepteula -a * -c -h -s -t -nobanner -o "$out\autoruns.csv"

# 日志配置
Get-WinEvent -ListLog * | Select LogName,IsEnabled,RecordCount,FileSize,MaximumSizeInBytes,LogMode |
  Export-Csv "$out\logs.csv" -NoTypeInformation -Encoding UTF8

# 端点防护
Get-MpComputerStatus  | Export-Csv "$out\mpstatus.csv" -NoTypeInformation -Encoding UTF8
Get-MpPreference      | Export-Csv "$out\mppref.csv" -NoTypeInformation -Encoding UTF8

# 补丁
Get-HotFix | Export-Csv "$out\hotfix.csv" -NoTypeInformation -Encoding UTF8

# 注册表基线
reg export "HKLM\SYSTEM\CurrentControlSet\Services" "$out\services.reg" /y
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "$out\run.reg" /y
reg export "HKLM\SOFTWARE\Policies" "$out\policies.reg" /y

Write-Host "基线快照已输出到 $out"
```

---

## 4. 自动化核查与加固

### 4.1 HardeningKitty（推荐，开源）

基于 CIS Benchmark，用 PowerShell 批量核查 + 可选自动加固。

```powershell
# 项目地址：https://github.com/scipag/HardeningKitty
# 1) 只做核查，输出 CSV 报告（推荐先跑这个）
.\HardeningKitty.ps1 -Mode Audit -FileFindingList .\lists\finding_list_cis_machine_2.0.0.csv -Report -ReportFile C:\Baseline\hkitty_audit.csv

# 2) 按风险等级过滤（只看高危）
Import-Csv C:\Baseline\hkitty_audit.csv | Where-Object { $_.RecommendedValue -ne $_.Value } |
  Sort-Object CVSS -Descending | Select-Object -First 40

# 3) 加固（危险！必须先测试）
# .\HardeningKitty.ps1 -Mode HailMary -FileFindingList .\lists\finding_list_cis_machine_2.0.0.csv
#    - 强烈建议：先在测试机跑 → 用虚拟化快照 → 分批（一次改一类）

# 4) 回滚（脚本会生成回滚脚本）
# .\rollback.ps1
```

**注意事项**：HardeningKitty 会修改大量注册表与策略，**在生产环境直接跑 `HailMary` 是运维事故的常见来源**。正确用法是"Audit → 人工筛选 → 分批加固 → 验证"。

### 4.2 Microsoft Security Compliance Toolkit

- 官方基线（GPO 包）：`Windows 11 Security Baseline`、`Windows Server 2022 Security Baseline`
- 获取：https://www.microsoft.com/en-us/download/details.aspx?id=55319
- 用法：用 **LGPO.exe** 应用，或用 **Policy Analyzer** 对比本地策略与基线差异
- 优势：微软官方、有 GPO 形式，适合域环境批量下发

```powershell
# Policy Analyzer 对比本地策略与基线（图形化差异报告）
# LGPO.exe /g <GPO目录>     # 应用
# LGPO.exe /parse /m <GPO目录>\Machine\Registry.pol > out.txt   # 解析查看
```

### 4.3 CIS-CAT Pro

- 官方合规扫描工具，输出 CIS Benchmark 得分
- 适合需要"对外可交付的合规评分"场景（等保、ISO 27001 审计）
- 免费版 CIS-CAT Lite 可做基础核查

### 4.4 自建核查脚本

仓库提供 `../scripts/windows-baseline-check.sh`（Linux）与本文配套的
`../scripts/windows-baseline-check.ps1`（Windows），实现第 2 节中**最高价值的 30 项**自动核查，输出问题清单与问题计数。

```powershell
# 运行（只读，不修改任何配置）
powershell -ExecutionPolicy Bypass -File .\scripts\windows-baseline-check.ps1
# 输出：控制台摘要 + C:\Baseline\<主机名>-<时间戳>\baseline-report.csv
```

### 4.5 持续运营

| 手段 | 说明 |
|---|---|
| 定期快照 + diff | 每周导出第 3 节的基线快照，与上周 diff，发现漂移 |
| 纳入配置管理 | 用 Intune / SCCM / Ansible / DSC 把基线固化为代码 |
| 关键项监控 | 把"日志被清 1102""Defender 被关 5001""新服务 7045"做成 SIEM 告警 |
| 演练验证 | 用 Atomic Red Team 跑攻击模拟，验证检测与阻断是否真的生效（见工具链文档） |

---

## 5. 加固的风险控制

**加固动作本身可能造成业务中断。** 必须遵守：

| 原则 | 说明 |
|---|---|
| **先审计后强制** | ASR、WDAC、约束语言模式、网络保护等，先以 Audit 模式跑 2–4 周，看命中情况再切 Block |
| **分批复核** | 一次只改一类（如只改日志类），不要一次改 100 项 |
| **快照先行** | 虚拟机先做快照；物理机先导出注册表/策略备份 |
| **保留回滚** | HardeningKitty/LGPO 都提供回滚，务必验证回滚可用 |
| **变更窗口** | 生产环境在变更窗口执行，并通知业务方 |
| **验证闭环** | 加固后重跑核查命令 + 做业务功能验证（应用能启动、能登录、能访问） |

**典型踩坑**

- 强制 SMB 签名后，老设备/扫描仪连不上共享；
- 禁用 NTLM 后，部分老应用认证失败；
- WDAC 强制模式后，业务自研程序被拦；
- 关闭 PowerShell v2 后，某些老脚本失效；
- 启用约束语言模式后，运维脚本报错；
- 改 RDP 端口/强制 NLA 后，运维人员无法连接。

**一句话**：加固的目标是"降低被攻破的概率"，不是"制造运维事故"。任何可能影响业务的项，**先审计、再灰度、后强制**。

---

## 6. 高价值加固优先级（先做这些）

如果只能做 10 件事，按这个顺序做（投入产出比最高）：

| 顺序 | 动作 | 收益 | 主手册落点 |
|---|---|---|---|
| 1 | **开启命令行审计 + PowerShell 脚本块日志** | 让未来所有排查都"有据可查"；这是检测能力的地基 | 7.2 / 5.6 |
| 2 | **部署 Sysmon + 成熟配置** | 进程/网络/注册表/注入全维度遥测，免费 | 7.4 / 附录 B |
| 3 | **配置日志外发（WEF 或采集 Agent）** | 本机日志被清也能追 | 7.3 |
| 4 | **开启 ASR 规则（Office/WMI/脚本/勒索相关）** | 直接在行为层拦住最常见的攻击链 | 6.10 |
| 5 | **启用 LAPS + RunAsPPL + 关 WDigest** | 切断凭据窃取的主要路径 | 4.4 / 9.6 |
| 6 | **审计并清理 Defender 排除项** | 封堵"自己给自己开的洞" | 6.10 |
| 7 | **收敛 RDP / SMB / 管理共享暴露面** | 断绝暴破与横向移动的主要通道 | 2.3 节 31–38 |
| 8 | **清理服务/计划任务/注册表持久化面** | 减少攻击者可用的持久化位置 | 第 3 章 |
| 9 | **补丁管理（OS + 应用）** | 消灭已知在野利用漏洞 | 2.9 节 101–102 |
| 10 | **离线/不可变备份 + 恢复演练** | 对抗勒索的最后底牌 | 2.10 节 |

**这 10 项做完，主机的"可检测性"与"抗打击能力"会有质的提升**——远高于把 100 项合规项打勾带来的实际安全收益。

---

> **配套文档**：
> - `windows-host-audit.md` —— 现场排查命令手册
> - `windows-attack-mapping.md` —— 攻击手法映射与持久化核对清单
> - `windows-forensics-toolchain.md` —— 工具链（用于落实第 1.1 节的"能不能查到"）
> - `../linux/linux-hardening.md` —— 对应的 Linux 基线
