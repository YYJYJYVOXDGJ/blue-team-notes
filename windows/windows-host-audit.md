# Windows 主机应急排查手册（蓝队）

> 适用：Windows Server 2012 R2 / 2016 / 2019 / 2022、Windows 10 / 11
> 定位：**现场可执行**。每条命令都标注了「查什么」和「判读要点」，不是命令清单。
> 配套：`windows-attack-mapping.md`（攻击手法 → 痕迹映射）、`windows-hardening.md`（加固基线）、`windows-forensics-toolchain.md`（现代工具链）、`../scripts/windows-ir-quickcheck.ps1`（一键只读采集）

## 目录

- [0. 排查前置：现场保护与证据固定](#0-排查前置现场保护与证据固定)
- [1. 网络连接与端口排查](#1-网络连接与端口排查)
- [2. 进程与内存排查](#2-进程与内存排查)
- [3. 持久化后门排查（核心）](#3-持久化后门排查核心)
- [4. 账号与身份认证审计](#4-账号与身份认证审计)
- [5. 执行痕迹与时间线](#5-执行痕迹与时间线)
- [6. 文件系统与恶意文件排查](#6-文件系统与恶意文件排查)
- [7. 事件日志审计](#7-事件日志审计)
- [8. 应用与中间件专项](#8-应用与中间件专项)
- [9. 处置与加固](#9-处置与加固)
- [10. 一键排查脚本](#10-一键排查脚本)
- [附录 A：现场排查 Checklist](#附录-a现场排查-checklist)
- [附录 B：应急工具箱（离线 U 盘必带）](#附录-b应急工具箱离线-u-盘必带)
- [附录 C：LOLBins 与无文件攻击速查](#附录-clolbins-与无文件攻击速查)

**约定**

- 标注 `[管理员]` 的命令需要**提升权限**的 PowerShell / CMD，否则结果不完整或直接失败。
- 标注 `[SYSTEM]` 的需要 SYSTEM 权限（如读 SAM 注册表），可用 `psexec -s -i powershell` 提权。
- 优先用 `Get-CimInstance` 而非 `Get-WmiObject`：后者在 PowerShell 7 中已被移除，且性能更差。
- 排查**只读优先**。任何删除、终止动作前，先确认证据已固定。

---

## 0. 排查前置：现场保护与证据固定

### 0.1 先搞清楚一件事：你到底有多少时间

Windows 的易失性数据比 Linux 更"娇贵"：

| 数据 | 存活周期 | 丢失后果 |
|---|---|---|
| 内存（含注入代码、明文凭据、解密密钥） | 断电即失 | **无法追查无文件攻击、无法提取 C2 配置** |
| 网络连接、DNS 缓存 | 分钟级 | 丢失 C2 地址，无法做阻断与同源排查 |
| 进程、句柄 | 进程退出即失（或重启） | 丢失父子关系、内存马 |
| 事件日志、注册表 | 一般留存 | 可恢复，但可能被攻击者删过 |
| 磁盘文件 | 持久 | 相对安全 |

**结论：内存和网络必须先抓，再谈其他。** 拔电源 = 销毁证据，这是现场最常见也最不可逆的错误。

### 0.2 选择处置策略（先想清楚，再断网）

| 场景 | 建议动作 | 理由 |
|---|---|---|
| 已确认失陷、攻击者仍在线 | **隔离网络但保持通电**（防火墙封锁，不拔网线/不断电） | 保留内存；断网后攻击者失去控制，可能触发 wiper |
| 疑似失陷、业务关键不可停 | 先只读采集 + 全流量镜像，不动主机 | 取证与业务平衡 |
| 确认失陷、正在横向 | 立即网络隔离 + 收集相邻主机日志 | 止血优先级 > 取证完整性 |
| 勒索已加密 | **立刻保内存、保 VSS 快照、保加密器样本**，再考虑重启 | 解密器可能还在内存里；重启会丢密钥 |

**网络隔离的 Windows 做法**（比拔网线优雅，且不丢内存）：

```powershell
# [管理员] 保留与取证服务器的通信，阻断其余出入向
New-NetFirewallRule -DisplayName "IR-Block-Outbound" -Direction Outbound -Action Block -Profile Any
New-NetFirewallRule -DisplayName "IR-Block-Inbound"  -Direction Inbound  -Action Block -Profile Any
# 放行到取证服务器（按需）
New-NetFirewallRule -DisplayName "IR-Allow-Forensic" -Direction Outbound -Action Allow -RemoteAddress 10.0.0.100
# 处置结束后清理
# Remove-NetFirewallRule -DisplayName "IR-Block-*","IR-Allow-Forensic"

# 禁用网卡（会断掉取证通道，谨慎）
# Disable-NetAdapter -Name "以太网" -Confirm:$false
```

### 0.3 内存采集（第一优先级）

```powershell
# 方式一：WinPmem（推荐，开源，Win10/11 内核可用）
# 先加载驱动再 dump，输出 raw 格式，Volatility3 可直接吃
winpmem_mini_x64.exe C:\IR\mem.raw

# 方式二：Magnet RAM Capture / Belkasoft RAM Capturer（带 GUI，现场好用）
# 方式三：FTK Imager -> Capture Memory

# 方式四：仅对单进程 dump（不推荐用于取证，但适合快速看某个可疑进程）
procdump64.exe -ma <PID> C:\IR\proc_<PID>.dmp

# 注意：下面这条 comsvcs.dll 命令是攻击者最常用的 LSASS dump 手法之一，
# 在排查中它是"痕迹"而不是"工具"——看到它出现在命令行审计里就该警觉
# rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_PID> C:\temp\lsass.dmp full
```

采集后**立刻校验哈希**，防止后续被质疑完整性：

```powershell
Get-FileHash C:\IR\mem.raw -Algorithm SHA256 | Format-List
```

### 0.4 网络流量与连接快照

```powershell
# 内置抓包（Windows 10 1809+ / Server 2019+，不需要装 Wireshark）
pktmon start --capture --pkt-size 0 --file-name C:\IR\traffic.etl
# ... 采集一段时间后 ...
pktmon stop
pktmon etl2pcap C:\IR\traffic.etl --out C:\IR\traffic.pcap

# 老系统用 netsh trace（ETL 格式，可用 Microsoft Network Monitor 打开）
netsh trace start capture=yes tracefile=C:\IR\nettrace.etl maxsize=512
netsh trace stop

# 有 Wireshark 环境时直接抓
# tshark -i 1 -w C:\IR\cap.pcap -b filesize:51200
```

### 0.5 时间基准与可信工具

```powershell
# 时间是第一位的：时间错会导致整个时间线错位
Get-Date
w32tm /query /status
w32tm /query /configuration
Get-TimeZone
# 注册表里 sysprep 遗留的时区设置也会影响日志解析

# 检查系统启动时间（判断是否被重启过、失陷窗口）
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Get-CimInstance Win32_OperatingSystem | Select LastBootUpTime, InstallDate, Version, BuildNumber

# 版本与补丁（判断是否命中已知漏洞）
systeminfo
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20
Get-CimInstance Win32_QuickFixEngineering | Where-Object { $_.HotFixID -like "KB*" } | Measure-Object
```

**可信工具原则**：不要用失陷主机上的 `tasklist.exe`、`netstat.exe`、`ipconfig.exe` 做结论——这些是攻击者最常替换/劫持的对象。至少做两件事：

1. 用**多源交叉**（`Get-CimInstance` + `Get-Process` + `tasklist` 三者比对）；
2. 优先用**自带运行时的静态工具**：Sysinternals 全套、`Velociraptor`、`KAPE`、`Chainsaw`（Rust 编译，无外部依赖）。

```powershell
# 用 Sysinternals 的签名版本覆盖系统工具（从 U 盘运行，不落地）
# 建议准备：Autoruns64.exe、ProcessExplorer、TCPView、Sigcheck、Sysmon、Strings、ProcDump、
#          handle64.exe、ListDlls64.exe、streams.exe、sdelete、PsExec、PsLogList

# 校验系统关键二进制是否被替换（对比 WinSxS 中的原始版本）
Get-FileHash C:\Windows\System32\tasklist.exe
sfc /verifyonly
DISM /Online /Cleanup-Image /ScanHealth
```

### 0.6 排查优先级与时间分配

| 失陷确认度 | 首轮重点 | 建议时间 |
|---|---|---|
| 仅告警，未确认 | 网络外连（1 章）+ 持久化（3 章）+ 事件日志 4624/4688（7 章） | 30 分钟 |
| 确认 Webshell/入口点 | 应用专项（8 章）+ 持久化全量 + 账号（4 章） | 2 小时 |
| 确认内网横向 | 账号与认证（4 章）+ 横向移动痕迹 + 相邻主机日志 | 1 天 |
| 勒索/挖矿已发作 | 内存 + 勒索专项（6.7）+ 备份完整性 + VSS | 优先止血 |

**10 分钟快速定位（首轮组合拳）**

```powershell
# 1. 外连了谁（含进程名）
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } |
  Select-Object RemoteAddress,RemotePort,State,OwningProcess,
    @{n='Proc';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} |
  Sort-Object RemoteAddress

# 2. 有没有身份不对的进程（不在系统目录 / 未签名）
Get-Process | Where-Object { $_.Path -and $_.Path -notlike "$env:SystemRoot*" } |
  Select-Object Name,Id,Path,Company

# 3. 最近的持久化改动
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
  ForEach-Object { Get-ItemProperty $_.PSPath }

# 4. 最近 24 小时创建的可执行文件
Get-ChildItem C:\ -Recurse -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.js -ErrorAction SilentlyContinue |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-1) } |
  Select-Object FullName,CreationTime,Length

# 5. 最近的登录（含来源 IP）
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 50 |
  Where-Object { $_.Properties[8].Value -in 3,10 } |
  Select-Object TimeCreated,@{n='User';e={$_.Properties[5].Value}},@{n='SrcIP';e={$_.Properties[18].Value}},@{n='LogonType';e={$_.Properties[8].Value}}

# 6. 新装的服务（持久化最高频落点之一）
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 30 |
  Select-Object TimeCreated,@{n='Service';e={$_.Properties[0].Value}},@{n='Path';e={$_.Properties[1].Value}}
```

---

## 1. 网络连接与端口排查

### 1.1 监听端口与连接枚举

```powershell
# 基础：所有 TCP/UDP 端口 + PID（不解析域名，速度最快）
netstat -ano

# 带可执行文件名（需管理员，攻击者最爱替换/劫持的就是这个功能）
netstat -anob

# 只看监听
netstat -ano | findstr LISTENING

# PowerShell 原生（推荐，可直接与进程对象联动）
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
Get-NetTCPConnection -State Listen
Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess

# 只查看监听状态的端口（按 PID 排序，方便找异常高位端口）
Get-NetTCPConnection -State Listen | Sort-Object OwningProcess | Format-Table -AutoSize

# PID -> 进程
tasklist | findstr "PID号"
Get-Process -Id <PID> | Select-Object Id,Name,Path,Company,Description,StartTime
Get-CimInstance Win32_Process -Filter "ProcessId=<PID>" | Select-Object ProcessId,Name,ExecutablePath,CommandLine,CreationDate
```

**判读要点**

| 现象 | 含义 |
|---|---|
| 高位端口（如 4444/5555/1080/8080/8888）监听且进程在 `%TEMP%` | 高度可疑，C2 或代理 |
| 监听进程为 `svchost.exe` 但不在 `C:\Windows\System32\` | 伪装，正常 svchost 只会从 System32 启动 |
| `netstat` 显示端口但 `Get-NetTCPConnection` 不显示（或反之） | **用户态 API 被 hook**，立即转 2.6 节做内核级交叉验证 |
| 监听在 `0.0.0.0` 的数据库/中间件端口（1433/3306/6379/8080） | 暴露面，结合 8 章判断是否被当作入口 |
| 端口相同但 PID 与上一轮快照不一致 | 进程重生（看门狗），杀之前先找守护者 |

### 1.2 外连与 C2 信道

```powershell
# 所有已建立的外连（排除本地回环）
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemoteAddress -notin @('127.0.0.1','::1','0.0.0.0','::') -and $_.RemoteAddress -notmatch '^fe80' } |
  Select-Object RemoteAddress,RemotePort,LocalAddress,LocalPort,
    @{n='PID';e={$_.OwningProcess}},
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}},
    @{n='Path';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Path}} |
  Sort-Object RemoteAddress | Format-Table -AutoSize

# 按远端端口聚合，快速发现"同一 C2 多台主机"
Get-NetTCPConnection -State Established | Group-Object RemoteAddress,RemotePort |
  Sort-Object Count -Descending | Select-Object Count,Name -First 20

# 哪个进程连得最多（挖矿/扫描器通常连接数异常）
Get-NetTCPConnection -State Established | Group-Object OwningProcess |
  Sort-Object Count -Descending | ForEach-Object {
    $p = Get-Process -Id $_.Name -EA SilentlyContinue
    [PSCustomObject]@{PID=$_.Name; Count=$_.Count; Process=$p.Name; Path=$p.Path}
  } | Format-Table -AutoSize
```

**常见 C2 / 后门端口特征**（仅作线索，不能当结论）

| 端口 | 常见来源 |
|---|---|
| 4444 / 4445 | Metasploit 默认 handler |
| 50050 | Cobalt Strike Team Server 默认 |
| 8080 / 8443 / 443 / 80 | 流量伪装成 Web，需结合 JA3/TLS 指纹判断 |
| 1080 / 7890 / 10808 | SOCKS 代理（frp/Clash/SSR 等） |
| 3389 | RDP，横向移动主力 |
| 5985 / 5986 | WinRM，横向移动 |
| 445 | SMB，横向移动 + 数据窃取 |

### 1.3 DNS 缓存与 hosts（外带/隧道必查）

```powershell
# DNS 客户端缓存：能还原"刚访问过什么域名"，即使连接已关闭
Get-DnsClientCache | Select-Object Entry,Data,Type,TimeToLive | Sort-Object Entry
ipconfig /displaydns

# 缓存中只查出来的可疑特征：长随机子域、超长 TXT、非常规 TLD
Get-DnsClientCache | Where-Object { $_.Entry.Length -gt 40 -or $_.Entry -match '\.(top|xyz|cc|tk|pw|ru|su|gq|ml|cf)$' } |
  Select-Object Entry,Data

# hosts 文件（劫持或屏蔽）
Get-Content C:\Windows\System32\drivers\etc\hosts
Get-Item C:\Windows\System32\drivers\etc\hosts | Select-Object LastWriteTime,Length

# DNS 服务器配置（是否被改成攻击者的解析器）
Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses }
Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.DNSServerSearchOrder } |
  Select-Object Description,DNSServerSearchOrder,DNSDomain

# 清理缓存（采集完成后再执行）
# Clear-DnsClientCache
```

### 1.4 路由、ARP、网卡

```powershell
Get-NetRoute | Sort-Object RouteMetric | Format-Table -AutoSize
route print
arp -a
Get-NetNeighbor | Where-Object { $_.State -ne 'Unreachable' } | Select-Object IPAddress,LinkLayerAddress,State

# 网卡与 IP 配置（找异常的第二 IP、混杂模式、可疑虚拟网卡）
Get-NetIPConfiguration -Detailed
Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed
Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } |
  Select-Object Description,IPAddress,DefaultIPGateway,MACAddress

# 混杂模式检测（嗅探器/中间人）
Get-NetAdapterAdvancedProperty -DisplayName "Promiscuous*" -ErrorAction SilentlyContinue
```

### 1.5 防火墙、代理与端口转发（攻击者最爱留的通道）

```powershell
# 防火墙全部规则（含新增的放行规则）
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } |
  Select-Object DisplayName,Direction,Action,Profile | Sort-Object Direction
netsh advfirewall firewall show rule name=all
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction

# 只看"入向放行"的规则（攻击者为长期访问开的洞）
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
  ForEach-Object {
    $pf = $_ | Get-NetFirewallPortFilter
    [PSCustomObject]@{Name=$_.DisplayName;Proto=$pf.Protocol;Port=$pf.LocalPort;Program=$_.Program}
  } | Format-Table -AutoSize

# 端口转发（netsh portproxy 是 Windows 上最隐蔽的隧道之一，默认不显示在任何 GUI 里）
netsh interface portproxy show all
netsh interface portproxy show v4tov4
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp\*" -ErrorAction SilentlyContinue

# 系统代理配置（外带数据常用）
netsh winhttp show proxy
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" |
  Select-Object ProxyEnable,ProxyServer,ProxyOverride,AutoConfigURL
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" |
  Select-Object ProxyEnable,ProxyServer,AutoConfigURL

# PAC 自动配置脚本（AutoConfigURL 是高频后门点，指向攻击者服务器）
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Recurse -EA SilentlyContinue |
  Select-Object PSPath
```

**特别关注 `netsh interface portproxy`**：它能把外部连接转发到内网任意主机，隐藏真实监听进程；`portproxy` 配置存在注册表 `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy`，常规排查极易漏掉。同理还有 `netsh add helper` 注册的 DLL（见 3.9）。

### 1.6 WMI / WinRM / RDP 等横向通道监听

```powershell
# RDP 是否开启、端口是否被改
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" | Select-Object fDenyTSConnections
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" |
  Select-Object PortNumber,UserAuthentication,SecurityLayer,MinEncryptionLevel
netsh advfirewall firewall show rule name=all | findstr /i "3389"

# RDP 影子会话（攻击者可静默旁观）
Get-Process -Name mstsc,RDPClip -EA SilentlyContinue | Select-Object Id,Name,Path
qwinsta
query user

# WinRM
Get-Service WinRM | Select-Object Status,StartType
winrm enumerate winrm/config/listener
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -EA SilentlyContinue

# SMB 共享与配置（横向窃取与投毒）
Get-SmbShare | Select-Object Name,Path,Description
Get-SmbSession | Select-Object ClientComputerName,ClientUserName,NumOpens
Get-SmbOpenFile | Select-Object ClientUserName,Path
net share
# SMBv1 若开启，是永恒之蓝等漏洞的基础（应关闭）
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature

# WMI 远程连接痕迹
Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" -MaxEvents 50 -EA SilentlyContinue |
  Where-Object { $_.Id -in 5857,5858,5859,5860,5861 } |
  Select-Object TimeCreated,Id,Message -First 20
```

### 1.7 连接的进程级深挖

```powershell
# 某个进程持有的所有连接
Get-NetTCPConnection -OwningProcess <PID> | Format-Table -AutoSize

# 进程打开的网络句柄（进程"隐藏"连接时的出路）
handle64.exe -p <PID> -a | findstr /i "TCP UDP"

# 按连接找出进程的加载模块（判断是否被注入）
Get-Process -Id <PID> | Select-Object -ExpandProperty Modules |
  Select-Object ModuleName,FileName,@{n='Company';e={$_.FileVersionInfo.CompanyName}}

# 实时观察新建连接（RDP/WinRM 横向时特别有效）
while ($true) {
  Get-NetTCPConnection -State Established |
    Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' } |
    Select-Object @{n='T';e={Get-Date -f 'HH:mm:ss'}},RemoteAddress,RemotePort,OwningProcess
  Start-Sleep 5
}
```

---
## 2. 进程与内存排查

### 2.1 进程枚举（多源交叉，防隐藏进程）

```powershell
# 源一：PowerShell（走 .NET / Win32 API）
Get-Process | Select-Object Id,Name,Path,Company,Description,StartTime | Format-Table -AutoSize

# 源二：CIM/WMI（走 WMI Provider，可能被不同方式 hook）
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate

# 源三：系统自带 tasklist
tasklist /v /fo csv

# 源四：WMI 原生（PS 5.1）
Get-WmiObject Win32_Process | Select-Object ProcessId,Name,CommandLine

# 多源差集：任何一源独有 / 缺失的 PID 都值得深挖
$ps  = (Get-Process).Id | Sort-Object
$cim = (Get-CimInstance Win32_Process).ProcessId | Sort-Object
$tl  = (tasklist /fo csv | ConvertFrom-Csv).PID | ForEach-Object { [int]$_ } | Sort-Object
Write-Host "PowerShell 独有:" (Compare-Object $ps  $cim | Where-Object SideIndicator -eq '<=' | ForEach-Object InputObject)
Write-Host "CIM 独有:      " (Compare-Object $ps  $cim | Where-Object SideIndicator -eq '=>' | ForEach-Object InputObject)
Write-Host "tasklist 独有: " (Compare-Object $cim $tl  | Where-Object SideIndicator -eq '=>' | ForEach-Object InputObject)
```

**判读**：三源数量差 1–2 个属正常（受保护进程、刚创建/退出的进程）。差集里出现**普通名字**（如 `svchost.exe`、`explorer.exe`）才是强信号。

### 2.2 进程树与父子关系异常

攻击链的本质是"谁启动了谁"，**父子关系是 Windows 上最强的检测信号**。

```powershell
# 导出完整进程树
Get-CimInstance Win32_Process |
  Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath |
  Sort-Object ParentProcessId | Format-Table -AutoSize -Wrap

# 生成缩进树状视图
$procs = Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine
function Show-Tree($parent, $indent) {
  foreach ($p in $procs | Where-Object ParentProcessId -eq $parent) {
    "{0}{1} ({2})" -f $indent, $p.Name, $p.ProcessId
    if ($p.CommandLine) { "{0}   └─ {1}" -f $indent, $p.CommandLine.Substring(0,[Math]::Min(180,$p.CommandLine.Length)) }
    Show-Tree $p.ProcessId ($indent + "  ")
  }
}
Show-Tree 0 ""

# 孤儿进程：父进程已退出（常见于进程注入、服务拉起的一次性 payload）
$all = Get-CimInstance Win32_Process
$all | Where-Object { $_.ParentProcessId -notin $all.ProcessId -and $_.ParentProcessId -ne 0 } |
  Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine

# 父进程比自己还新（时间倒挂 = 注入或伪造）
$all | ForEach-Object {
  $pp = $all | Where-Object ProcessId -eq $_.ParentProcessId
  if ($pp -and $_.CreationDate -lt $pp.CreationDate) {
    [PSCustomObject]@{Child=$_.Name;ChildPID=$_.ProcessId;ChildTime=$_.CreationDate;
                      Parent=$pp.Name;ParentPID=$_.ParentProcessId;ParentTime=$pp.CreationDate}
  }
}
```

**必须警觉的父子组合**（Office / 浏览器 / Web 服务不该拉起命令行）：

| 父进程 | 子进程 | 含义 |
|---|---|---|
| `winword.exe` / `excel.exe` / `outlook.exe` | `powershell.exe` / `cmd.exe` / `mshta.exe` / `wscript.exe` / `rundll32.exe` | 宏钓鱼载荷执行 |
| `w3wp.exe` / `httpd.exe` / `java.exe` / `nginx.exe` | `cmd.exe` / `powershell.exe` / `whoami.exe` | Webshell / 中间件被利用 |
| `services.exe` | `cmd.exe` / `powershell.exe` | 服务被替换或异常 ServiceDll |
| `svchost.exe` | `powershell.exe` / `mshta.exe` / `certutil.exe` | 计划任务或服务后门 |
| `explorer.exe` | `certutil.exe` / `bitsadmin.exe` / `mshta.exe` | 用户态下载执行 |
| `cmd.exe` | `net.exe` / `net1.exe` / `sc.exe` / `schtasks.exe` / `wmic.exe` | 手工侦察/持久化 |
| `lsass.exe` | 任意 | 极不正常，凭据窃取痕迹 |

```powershell
# 一次性扫出上述高危组合
$risky = @{
  'winword|excel|powerpoint|outlook|msaccess' = 'powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|msiexec|installutil'
  'w3wp|httpd|java|nginx|tomcat|node|python'  = 'cmd|powershell|pwsh|whoami|net|net1|curl|bitsadmin|certutil'
  'services'                                   = 'cmd|powershell|pwsh|mshta'
  'svchost'                                    = 'powershell|pwsh|mshta|certutil|bitsadmin|curl'
  'explorer'                                   = 'certutil|bitsadmin|mshta|regsvr32|rundll32'
  'lsass'                                      = '.'
}
$all = Get-CimInstance Win32_Process
foreach ($k in $risky.Keys) {
  $all | Where-Object { $_.Name -match "^($k)\.exe$" } | ForEach-Object {
    $pp = $_
    $all | Where-Object {
      $_.ParentProcessId -eq $pp.ProcessId -and $_.Name -match "^($($risky[$k]))"
    } | Select-Object @{n='Parent';e={$pp.Name}},@{n='ParentPID';e={$pp.ProcessId}},
                      Name,ProcessId,CreationDate,CommandLine
  }
} | Format-Table -AutoSize -Wrap
```

### 2.3 路径、签名、版本信息三重校验

**这是识别伪装进程最快的方法**：正常系统进程一定在 `System32`、有微软签名、有完整版本信息。

```powershell
# 1) 路径不在系统目录的进程（首要过滤器）
Get-Process | Where-Object { $_.Path -and $_.Path -notlike "$env:SystemRoot*" } |
  Select-Object Name,Id,Path,Company,@{n='Signed';e={(Get-AuthenticodeSignature $_.Path).Status}} |
  Sort-Object Signed | Format-Table -AutoSize

# 2) 未签名 / 签名无效的可执行进程（重点怀疑对象）
Get-Process | Where-Object { $_.Path } | ForEach-Object {
  $sig = Get-AuthenticodeSignature $_.Path -EA SilentlyContinue
  if ($sig.Status -ne 'Valid') {
    [PSCustomObject]@{Name=$_.Name;PID=$_.Id;Path=$_.Path;Sign=$sig.Status;Signer=$sig.SignerCertificate.Subject}
  }
} | Format-Table -AutoSize -Wrap

# 3) 系统进程被冒充：名字对但路径/签名不对
$sysNames = 'svchost','lsass','services','winlogon','csrss','smss','wininit','taskhostw','dllhost','explorer','conhost'
Get-Process | Where-Object { $_.Name -in $sysNames } | ForEach-Object {
  $ok = $_.Path -like "$env:SystemRoot\System32\*"
  $sig = (Get-AuthenticodeSignature $_.Path -EA SilentlyContinue).Status
  if (-not $ok -or $sig -ne 'Valid') {
    "[!] {0} ({1}) Path={2} Sign={3}" -f $_.Name,$_.Id,$_.Path,$sig
  }
}

# 4) 用 Sysinternals sigcheck 做全盘签名审计（比 PowerShell 快得多，支持 VirusTotal）
# sigcheck64.exe -a -h -nobanner -e -s C:\Windows\System32
# sigcheck64.exe -u -nobanner -e -s C:\Windows        # 只看未签名文件
# sigcheck64.exe -vt -nobanner -e -s C:\Windows       # 提交 VirusTotal 查询（外发，需授权）
# sigcheck64.exe -c -h -nobanner -s C:\ > C:\IR\sigcheck.csv

# 5) 版本信息缺失/伪造
Get-Process | Where-Object { $_.Path } | Select-Object Name,Id,
  @{n='Company';e={$_.Company}},@{n='Product';e={$_.Product}},
  @{n='Version';e={$_.FileVersion}},@{n='Desc';e={$_.Description}} |
  Where-Object { -not $_.Company -or -not $_.Version } | Format-Table -AutoSize
```

### 2.4 命令行中的恶意特征（无文件攻击核心）

**Windows 上的攻击 90% 能从命令行里看出来**——前提是你开了命令行审计（见 7.2）。

```powershell
# 当前所有进程的完整命令行
Get-CimInstance Win32_Process |
  Select-Object ProcessId,Name,CommandLine |
  Where-Object CommandLine | Format-List

# 按可疑关键字过滤
$bad = 'enc|EncodedCommand|FromBase64String|DownloadString|DownloadFile|IEX|Invoke-Expression|' +
       'Invoke-WebRequest|iwr|curl|wget|WebClient|Net\.WebClient|Reflection\.Assembly|' +
       'Bypass|-w hidden|-WindowStyle Hidden|nop|NoProfile|-sta|-noni|AMSI|' +
       'mimikatz|sekurlsa|lsadump|comsvcs|procdump|MiniDump|' +
       'certutil.*-urlcache|bitsadmin|mshta|regsvr32.*scrobj|rundll32.*javascript|' +
       'vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled|' +
       'net user.*\/add|net localgroup.*administrators|schtasks.*\/create|' +
       'New-Object.*Net\.Sockets|TCPClient|Invoke-Shellcode|Marshal|VirtualAlloc'
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match $bad } |
  Select-Object ProcessId,ParentProcessId,Name,CreationDate,CommandLine | Format-List
```

**高频恶意命令行模式（背下来）**

| 模式 | 用途 |
|---|---|
| `powershell -EncodedCommand <base64>` / `-enc` | 隐藏脚本内容，最常见的初始载荷 |
| `powershell -w hidden -nop -exec bypass` | 静默 + 免策略执行 |
| `IEX (New-Object Net.WebClient).DownloadString('http://...')` | 内存加载，不落地 |
| `[Reflection.Assembly]::Load($bytes)` | 内存加载 .NET 程序集（Cobalt Strike、内存马） |
| `mshta http://...` / `mshta vbscript:...` | 无文件执行 |
| `regsvr32 /s /n /u /i:http://... scrobj.dll` | Squiblydoo，绕过 AppLocker |
| `rundll32 javascript:"\..\mshtml,..."` | 无文件执行 |
| `certutil -urlcache -split -f http://... a.exe` | 下载文件（卡巴/Defender 都会报，但依然常用） |
| `bitsadmin /transfer` / `Start-BitsTransfer` | BITS 下载，可跨重启续传 |
| `wmic process call create "..."` | 远程/本地执行 |
| `vssadmin delete shadows /all` | 删除卷影（勒索前置） |
| `bcdedit /set {default} recoveryenabled No` | 禁用恢复（勒索前置） |
| `wevtutil cl <log>` | 清除事件日志 |
| `net user guest /active:yes` / `net localgroup administrators X /add` | 账号后门 |
| `schtasks /create /sc onlogon /tn X /tr ...` | 计划任务持久化 |
| `netsh interface portproxy add v4tov4 ...` | 端口转发隧道 |
| `sc create X binPath= C:\...` | 服务持久化 |

### 2.5 进程注入与内存马检测

```powershell
# 进程加载了哪些模块（找"不该出现的 DLL"）
Get-Process -Name <进程名> | Select-Object -ExpandProperty Modules |
  Select-Object ModuleName,FileName,@{n='Company';e={$_.FileVersionInfo.CompanyName}},
                @{n='Size';e={$_.ModuleMemorySize}} |
  Sort-Object Company | Format-Table -AutoSize

# 跨进程加载异常：系统进程加载了第三方 DLL
Get-Process | Where-Object { $_.Name -in $sysNames } | ForEach-Object {
  $proc = $_
  $_.Modules | Where-Object {
    $_.FileName -notlike "$env:SystemRoot*" -and $_.FileName -notlike "$env:ProgramFiles*"
  } | Select-Object @{n='Proc';e={$proc.Name}},@{n='PID';e={$proc.Id}},
                    ModuleName,FileName
} | Format-Table -AutoSize

# Sysinternals ListDlls：能显示未在 PE 导出表中登记的模块（更接近注入真相）
# listdlls64.exe -u <PID>
# listdlls64.exe -v svchost.exe

# 内存区域审计：找 RWX 权限 / 无文件映射的私有内存
# Sysinternals VMMap -> 关注 "Private Data" 段中的 RWX

# PE-Sieve：检测进程内的"被篡改代码"，是内存马/注入的首选工具
# pe-sieve64.exe /pid <PID> /out C:\IR\pesieve /shellc /data 3 /min 1024
# hollows_hunter64.exe /out C:\IR\hollows /shellc /data 3   # 全量扫描所有进程

# Sysmon 事件直接看注入行为（必须部署 Sysmon，见工具链文档）
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -EA SilentlyContinue |
  Where-Object { $_.Id -in 8,10,25 } | Select-Object -First 40 TimeCreated,Id,Message

#  .NET 程序集注入 / 内存马的痕迹：进程里出现 Assembly.Load 加载的无文件模块
#  结合 Sysmon Event 7（ImageLoad）+ 模块路径为空/异常判断
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -EA SilentlyContinue |
  Where-Object { $_.Id -eq 7 -and $_.Message -match 'UNKNOWN|\.tmp|Temp|AppData' } |
  Select-Object -First 30 TimeCreated,Message
```

**关键事件对照**

| Sysmon ID | 含义 | 排查价值 |
|---|---|---|
| 1 | Process Create | 命令行 + 父进程 + 哈希，**最高价值** |
| 2 | File Creation Time Changed（时间戳篡改） | 反取证 |
| 3 | Network Connection | C2 通信 |
| 5 | Process Terminated | 短命进程（一次性载荷） |
| 7 | Image Loaded | DLL 注入、侧载 |
| 8 | CreateRemoteThread | **远程线程注入** |
| 10 | ProcessAccess | **LSASS 读取**（凭据窃取） |
| 11 | FileCreate | 落地文件 |
| 12/13/14 | 注册表创建/设置/重命名 | 持久化 |
| 15 | FileCreateStreamHash（ADS） | **备用数据流** |
| 17/18 | Pipe Created/Connected | C2 命名管道（Cobalt Strike 特征） |
| 19/20/21 | WMI Filter/Consumer/Binding | **WMI 持久化** |
| 22 | DNS Query | 域名外联 |
| 23/26 | FileDelete（归档） | 删证 |
| 25 | ProcessTampering | 进程镂空 |

### 2.6 隐藏进程与 Rootkit

```powershell
# 1) 句柄法：找出"能打开但枚举不到"的进程（经典隐藏进程检测）
#    遍历 PID 0..65535，OpenProcess 成功但不在进程列表 = 隐藏
$visible = (Get-Process).Id
1..65535 | Where-Object { $_ -notin $visible } | ForEach-Object {
  $p = Get-Process -Id $_ -EA SilentlyContinue
  if ($p) { "隐藏? PID=$_ Name=$($p.Name)" }
}

# 2) 用户态工具与内核对象比对
Get-CimInstance Win32_Process | Measure-Object | Select-Object Count
Get-Process | Measure-Object | Select-Object Count
# 数量不一致且反复复现 -> 疑似 rootkit

# 3) 驱动与内核模块（rootkit 必有一席）
Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,State,StartMode,PathName |
  Sort-Object State | Format-Table -AutoSize
driverquery /v /fo csv > C:\IR\drivers.csv
Get-ChildItem C:\Windows\System32\drivers\*.sys | ForEach-Object {
  $s = Get-AuthenticodeSignature $_.FullName -EA SilentlyContinue
  if ($s.Status -ne 'Valid') { [PSCustomObject]@{File=$_.Name;Sign=$s.Status;Time=$_.CreationTime} }
} | Format-Table -AutoSize

# 4) 文件系统过滤驱动（minifilter，勒索/监控/隐藏文件常用）
fltmc filters
fltmc instances
fltmc volumes

# 5) 内核回调（Sysinternals 之外的免费方案：Volatility3 的 windows.callbacks）
#    内核回调被恶意驱动注册 = 隐蔽 hook

# 6) 系统完整性
sfc /verifyonly
DISM /Online /Cleanup-Image /ScanHealth
Get-CimInstance Win32_OperatingSystem | Select-Object SystemDirectory,WindowsDirectory

# 7) 专业工具（对已知 rootkit 效果最好）
#    GMER、TDSSKiller、Malwarebytes Anti-Rootkit、PCHunter/System Informer（原 Process Hacker）
```

### 2.7 进程内存与镜像取证

```powershell
# 单进程 dump（保留现场，用于后续分析）
procdump64.exe -ma <PID> C:\IR\proc_<PID>.dmp
# 或者用系统自带（也是攻击者手法，反过来是痕迹）：
#   rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\IR\out.dmp full

# 内存镜像（全量，见 0.3）
# winpmem_mini_x64.exe C:\IR\mem.raw
```

**Volatility 3 常用插件清单（Windows）**

```bash
# 基础信息与版本
vol -f mem.raw windows.info
vol -f mem.raw windows.verinfo

# 进程（pslist 依赖 EPROCESS 链表，psscan 扫描结构体 —— 两者差集 = 隐藏进程）
vol -f mem.raw windows.pslist
vol -f mem.raw windows.psscan
vol -f mem.raw windows.pstree
vol -f mem.raw windows.cmdline          # 命令行
vol -f mem.raw windows.envars           # 环境变量
vol -f mem.raw windows.getsids
vol -f mem.raw windows.privileges

# 模块与注入
vol -f mem.raw windows.dlllist
vol -f mem.raw windows.ldrmodules       # 对比 PEB 链表 / 内存映射 / VAD —— 找隐藏 DLL
vol -f mem.raw windows.malfind          # 找 RWX + PE 头内存段（注入/无文件）
vol -f mem.raw windows.vadyarascan --yara-file rules.yar
vol -f mem.raw windows.yarascan --yara-file rules.yar

# 网络
vol -f mem.raw windows.netscan
vol -f mem.raw windows.netstat

# 服务、计划任务、注册表
vol -f mem.raw windows.svcscan
vol -f mem.raw windows.scheduled_tasks
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -f mem.raw windows.registry.hivelist
vol -f mem.raw windows.registry.hivedump

# 凭据（用于判断是否已被窃取）
vol -f mem.raw windows.hashdump
vol -f mem.raw windows.lsadump
vol -f mem.raw windows.cachedump

# 内核级 rootkit 检测
vol -f mem.raw windows.callbacks        # 内核回调
vol -f mem.raw windows.ssdt             # SSDT hook
vol -f mem.raw windows.modscan          # 驱动扫描
vol -f mem.raw windows.driverscan
vol -f mem.raw windows.driverirp

# 文件与提取
vol -f mem.raw windows.filescan
vol -f mem.raw windows.dumpfiles --virtaddr <addr>
vol -f mem.raw windows.procdump --pid <PID>
vol -f mem.raw windows.memmap --pid <PID> --dump
vol -f mem.raw windows.strings --pid <PID>
```

**MemProcFS（新工具，强烈推荐）**：把内存镜像**挂载成文件系统**，直接用资源管理器浏览进程、句柄、注册表、网络，比命令行快得多。

```powershell
# 挂载为盘符（只读，forensic 模式）
MemProcFS.exe -device C:\IR\mem.raw -forensic 1 -mount C:\IR\mnt
# 之后可直接浏览：
#   C:\IR\mnt\pid\        进程与模块
#   C:\IR\mnt\registry\   注册表 hive
#   C:\IR\mnt\net\        连接
#   C:\IR\mnt\files\      文件系统
```

### 2.8 样本初判（轻量静态分析）

```powershell
$f = "C:\IR\sample.exe"

Get-FileHash $f -Algorithm SHA256,MD5,SSDEEP   # 多哈希，便于情报比对
Get-Item $f | Select-Object Length,CreationTime,LastWriteTime,LastAccessTime,Attributes
Get-AuthenticodeSignature $f
(Get-Item $f).VersionInfo | Format-List *       # 版本信息（常被伪造或为空）
Get-Item $f -Stream *                            # 备用数据流（ADS）

# 字符串提取（Sysinternals strings，支持 ASCII/UTF-16）
strings64.exe -accepteula -n 8 $f > C:\IR\strings.txt
strings64.exe -accepteula -n 8 -u $f >> C:\IR\strings.txt   # Unicode
# 重点搜：URL、IP、域名、注册表路径、互斥体名、加密算法名、C2 端口

# 壳与编译器识别
#   Detect It Easy (DIE) —— 支持几百种壳/编译器特征
#   PEStudio             —— 静态行为画像（导入表/资源/熵值）
#   CFF Explorer         —— PE 结构细看
#   exiftool -a -u $f    —— 元数据

# 能力识别（Mandiant CAPA）—— 自动给出"这个样本会做什么"
# capa.exe -v sample.exe
# capa.exe --format json -o capa.json sample.exe

# 字符串去混淆（Mandiant FLOSS）—— 自动解出栈字符串与编码字符串
# floss.exe sample.exe > floss.txt

# YARA 扫描
# yara64.exe -r rules\ sample.exe
# yara64.exe -r -s rules\ C:\Users\   # 全盘扫描

# 行为动态分析（沙箱，注意联网风险）
#   Microsoft Defender 沙箱 / ANY.RUN / Joe Sandbox / Cuckoo
```

### 2.9 实时行为监控（排查期间同步跑）

```powershell
# PowerShell 原生：按 CPU / 内存排序找异常消耗
Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name,Id,CPU,WS,Path
Get-Process | Sort-Object WS  -Descending | Select-Object -First 15 Name,Id,CPU,WS,Path

# 实时跟踪新建进程（排查期间守株待兔）
while ($true) {
  Get-CimInstance Win32_Process |
    Where-Object { $_.CreationDate -gt (Get-Date).AddSeconds(-20) } |
    Select-Object @{n='T';e={$_.CreationDate}},Name,ProcessId,ParentProcessId,CommandLine
  Start-Sleep 5
}

# Sysinternals 组合拳（现场最有效）
#   Process Monitor (Procmon)：Filter -> Operation is Process Create / RegSetValue / WriteFile
#   Process Explorer：VirusTotal 集成、进程树、句柄、线程栈
#   TCPView：实时连接 + 进程
#   Autoruns：持久化全量（见 3.13）
#   System Informer（原 Process Hacker）：内核级对象查看、隐藏进程

# 内置 ETW 实时追踪（不需要装任何东西）
#   事件查看器 -> Microsoft-Windows-Sysmon/Operational（若已部署）
#   or: wevtutil qe Microsoft-Windows-Sysmon/Operational /f:text /c:50 /rd:true

# Sysinternals Sysmon 未部署时的替代：开启 PowerShell 日志 + 命令行审计
# （详见 7.2，通过组策略或注册表开启，开启后仍需等事件产生）
```

---
## 3. 持久化后门排查（核心）

> **本章是全篇最重要的部分。** Windows 有 40+ 个可持久化位置，攻击者只需一个没被清掉就能重新回来。
> 清理原则：**不做全量核对就不要说"清理完成"**。参考 `windows-attack-mapping.md` 的持久化核对清单。

### 3.1 注册表自启项（Run 系列全集）

```powershell
# 系统级（所有用户生效）—— 原手册命令
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
# 当前用户级
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# 完整清单（含 32 位视图、RunOnce、Policies、老式 RunServices）
$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
  'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
  'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($k in $runKeys) {
  if (Test-Path $k) {
    $props = Get-ItemProperty $k
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      [PSCustomObject]@{Key=$k;Name=$_.Name;Value=$_.Value}
    }
  }
} | Format-Table -AutoSize -Wrap

# 每个自启项指向的文件是否存在、是否签名、创建时间
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
  Select-Object * -ExcludeProperty PS* | ForEach-Object {
    $_.PSObject.Properties | ForEach-Object {
      $p = ($_.Value -replace '^"([^"]+)".*','$1') -replace '\s+-.*$',''
      [PSCustomObject]@{
        Name=$_.Name; Cmd=$_.Value; Exists=(Test-Path $p -EA SilentlyContinue)
        Sign=(Get-AuthenticodeSignature $p -EA SilentlyContinue).Status
        Created=(Get-Item $p -EA SilentlyContinue).CreationTime
      }
    }
  } | Format-Table -AutoSize -Wrap
```

**判读**：Run 项指向 `%TEMP%` / `%APPDATA%` / `%PUBLIC%` / `ProgramData`、文件名随机、无签名 —— 基本可直接定性。

### 3.2 服务持久化（含最隐蔽的 ServiceDll 与 FailureCommand）

```powershell
# 所有服务 + 可执行路径（原手册命令的增强版）
Get-Service | Where-Object { $_.Status -eq "Running" }
Get-Service | Where-Object { $_.StartType -eq "Automatic" }
Get-WmiObject Win32_Service | Select-Object Name,State,StartMode,PathName
Get-CimInstance Win32_Service |
  Select-Object Name,DisplayName,State,StartMode,StartName,PathName,ProcessId |
  Sort-Object StartMode | Format-Table -AutoSize -Wrap

# 【关键】PathName 未加引号 + 路径含空格 = DLL/EXE 劫持（T1574.009）
Get-CimInstance Win32_Service | Where-Object {
  $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.PathName -notmatch '^[A-Za-z]:\\Windows\\(System32|SysWOW64)\\'
} | Select-Object Name,State,StartMode,PathName

# 【关键】svchost 服务的 ServiceDll 被指向恶意 DLL —— 最高频的服务型后门
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
  $p = Join-Path $_.PSPath "Parameters"
  if (Test-Path $p) {
    $dll = (Get-ItemProperty $p -EA SilentlyContinue).ServiceDll
    if ($dll) {
      $clean = $dll -replace '^\\\?\?\\','' -replace '^\\SystemRoot\\',"$env:SystemRoot\"
      [PSCustomObject]@{
        Service=$_.PSChildName; ServiceDll=$clean
        Exists=(Test-Path $clean -EA SilentlyContinue)
        Sign=(Get-AuthenticodeSignature $clean -EA SilentlyContinue).Status
        Created=(Get-Item $clean -EA SilentlyContinue).CreationTime
      }
    }
  }
} | Where-Object { $_.Exists -eq $false -or $_.Sign -ne 'Valid' } | Format-Table -AutoSize

# 【关键】服务失败恢复命令：sc failure 可挂载任意命令，触发时机隐蔽
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
  $f = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).FailureCommand
  if ($f) { [PSCustomObject]@{Service=$_.PSChildName; FailureCommand=$f} }
} | Format-Table -AutoSize -Wrap
# 等价命令：
sc qfailure <服务名>

# 非微软签名的服务（最快收敛）
Get-CimInstance Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
  $exe = ($_.PathName -replace '^"([^"]+)".*','$1')
  $sig = Get-AuthenticodeSignature $exe -EA SilentlyContinue
  if ($sig.SignerCertificate.Subject -notmatch 'Microsoft') {
    [PSCustomObject]@{Name=$_.Name;Path=$exe;Signer=$sig.SignerCertificate.Subject;State=$_.State}
  }
} | Format-Table -AutoSize -Wrap

# 服务账户异常（后门服务常用 LocalSystem 或空口令域账户）
Get-CimInstance Win32_Service |
  Where-Object { $_.StartName -and $_.StartName -notmatch '^(LocalSystem|LocalService|NetworkService|NT AUTHORITY)' } |
  Select-Object Name,StartName,PathName

# 驱动型服务（Type=1/2）
Get-CimInstance Win32_SystemDriver | Select-Object Name,State,StartMode,PathName
```

### 3.3 计划任务（含隐藏任务）

```powershell
# 基础（原手册命令）
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" }
Get-ScheduledTaskInfo -TaskName 任务名
schtasks /query /fo LIST /v

# 完整枚举 + 执行体路径 + 作者
Get-ScheduledTask | ForEach-Object {
  $t = $_
  $act = $t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
  [PSCustomObject]@{
    Path=$t.TaskPath; Name=$t.TaskName; State=$t.State; Author=$t.Author
    RunAs=$t.Principal.UserId; RunLevel=$t.Principal.RunLevel
    Action=($act -join ' | ')
    Trigger=($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ','
  }
} | Sort-Object Path | Format-Table -AutoSize -Wrap

# 【关键】隐藏任务（<Hidden>true</Hidden>，在 GUI 里看不见）
[cim]$ns = "root/Microsoft/Windows/TaskScheduler"
Get-CimInstance -Namespace $ns -ClassName MSFT_TaskHidden | Out-Null  # 探测能力
Get-ScheduledTask | Where-Object { $_.Settings.Hidden -eq $true } |
  Select-Object TaskPath,TaskName,Author,@{n='Action';e={$_.Actions.Execute}}

# 【关键】任务 XML 原文（暴露 GUI 隐藏信息与混淆参数）
Get-ScheduledTask | ForEach-Object {
  Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath
} | Select-String -Pattern '<Hidden>true</Hidden>|<Command>|ComHandler|<Arguments>' -Context 0,0

# 【关键】注册表里的任务定义（防止 XML 被删但注册表残留，或反之）
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath -EA SilentlyContinue
    [PSCustomObject]@{ID=$_.PSChildName;Path=$p.Path;Hash=$p.Hash}
  } | Format-Table -AutoSize

# 任务文件系统层（直接看落地文件与时间）
Get-ChildItem "C:\Windows\System32\Tasks" -Recurse -File |
  Sort-Object LastWriteTime -Descending | Select-Object -First 40 FullName,LastWriteTime,Length

# 任务动作指向非系统目录 / 缺签名（最高效的过滤）
Get-ScheduledTask | ForEach-Object {
  foreach ($a in $_.Actions) {
    $exe = $a.Execute
    if (-not $exe) { continue }
    $exe = $exe.Trim('"')
    if ($exe -notlike "$env:SystemRoot*" -and $exe -notlike "$env:ProgramFiles*") {
      [PSCustomObject]@{
        Task="$($_.TaskPath)$($_.TaskName)"; State=$_.State; RunAs=$_.Principal.UserId
        Exe=$exe; Sign=(Get-AuthenticodeSignature $exe -EA SilentlyContinue).Status
      }
    }
  }
} | Format-Table -AutoSize -Wrap

# 常见被滥用为"任务"的 LOLBin
Get-ScheduledTask | Where-Object {
  $_.Actions.Execute -match 'powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|msiexec|conhost|forfiles|curl'
} | Select-Object TaskPath,TaskName,State,@{n='Exe';e={$_.Actions.Execute}},@{n='Args';e={$_.Actions.Arguments}} |
  Format-Table -AutoSize -Wrap
```

### 3.4 WMI 事件订阅（最隐蔽的持久化之一）

WMI 持久化由三部分组成：**事件过滤器（__EventFilter）→ 事件消费者（__EventConsumer）→ 绑定（__FilterToConsumerBinding）**。它是无文件、存活于 WMI 仓库、几乎不被杀软监控的经典后门。

```powershell
# 三个组件必须一起看，缺一不能成立
Get-WmiObject -Namespace root\subscription -Class __EventFilter    | Format-List *
Get-WmiObject -Namespace root\subscription -Class __EventConsumer  | Format-List *
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Format-List *

# 精简视图（推荐，方便快速扫）
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
  Select-Object Name,Query,EventNamespace
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
  Select-Object Filter,Consumer
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer |
  Select-Object Name,__CLASS,
    @{n='CommandLine';e={$_.CommandLineTemplate}},
    @{n='ScriptText';e={$_.ScriptText}},
    @{n='ScriptFileName';e={$_.ScriptFileName}}

# 只看 CommandLineEventConsumer（最常用，直接跑命令）
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
  Select-Object Name,CommandLineTemplate,ExecutablePath,WorkingDirectory

# 【重要】正常 Windows 系统这几张表应为空 —— 有任何条目都要逐个确认业务来源
# 同类隐蔽位置：其他命名空间也可能被用（较少见）
Get-ChildItem -Path (Get-WmiObject -Namespace root -Class __Namespace).Name
```

**判读**：`__EventFilter` 的 Query 常见形式为 `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'`（定时触发），配合 `CommandLineEventConsumer` 执行 `powershell -enc ...`。**只要消费者是 CommandLineEventConsumer 且命令行含编码/网络特征，即可定性。**

### 3.5 Winlogon 与认证层后门

这一层直接决定"攻击者能不能用你的账号密码登录回来"，也是清后门最容易被绕过的地方。

```powershell
# Winlogon：Shell / Userinit 被改 = 每次登录都执行
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
  Select-Object Shell,Userinit,Taskman,VmApplet,AppSetup,GinaDLL
# 正常值：
#   Shell     = explorer.exe
#   Userinit  = C:\Windows\system32\userinit.exe,
#   GinaDLL   = (不存在)

# Winlogon\Notify（老式，DLL 加载点）
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" -EA SilentlyContinue

# 【关键】AppInit_DLLs：所有加载 user32.dll 的进程都会加载它
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" |
  Select-Object AppInit_DLLs,LoadAppInit_DLLs,RequireSignedAppInit_DLLs
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -EA SilentlyContinue |
  Select-Object AppInit_DLLs,LoadAppInit_DLLs
# 正常：AppInit_DLLs 为空、LoadAppInit_DLLs = 0

# LSA 认证包 / 安全包（SSP 后门 = 明文抓密码）
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" |
  Select-Object "Authentication Packages","Security Packages","Notification Packages"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" -EA SilentlyContinue |
  Select-Object "Security Packages"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -EA SilentlyContinue |
  Select-Object "Authentication Packages","Security Packages"
# 正常 Notification Packages 仅含 scecli（密码过滤器位置，被替换即万能改密）

# 安全检查提供程序列表
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders" | Select-Object SecurityProviders

# 凭据提供程序（登录界面劫持，伪装成登录框窃取密码）
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" -EA SilentlyContinue |
  ForEach-Object { [PSCustomObject]@{CLSID=$_.PSChildName;Name=(Get-ItemProperty $_.PSPath).'(default)'} }

# 免密登录后门（注册表存明文密码！）
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -EA SilentlyContinue |
  Select-Object AutoAdminLogon,DefaultUserName,DefaultPassword,DefaultDomainName
# DefaultPassword 存在 = 明文凭据泄露

# 【重要】隐藏账号：SpecialAccounts\UserList 里值为 0 的用户会从登录界面消失
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -EA SilentlyContinue

# 密码策略与锁定
net accounts
```

### 3.6 IFEO 与辅助功能劫持（经典且高频）

```powershell
# IFEO Debugger：为任意程序挂"调试器"，等于劫持其启动
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
  ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).Debugger
    if ($dbg) { [PSCustomObject]@{Target=$_.PSChildName; Debugger=$dbg} }
  } | Format-Table -AutoSize -Wrap
Get-ChildItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -EA SilentlyContinue |
  ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).Debugger
    if ($dbg) { [PSCustomObject]@{Target=$_.PSChildName; Debugger=$dbg} }
  } | Format-Table -AutoSize -Wrap

# 【重点】辅助功能程序被劫持 = 锁屏界面按 5 次 Shift 直接出 SYSTEM 命令行
# 目标清单：sethc.exe(粘滞键) utilman.exe(轻松访问) osk.exe(屏幕键盘)
#          magnify.exe(放大镜) narrator.exe(讲述人) DisplaySwitch.exe AtBroker.exe
$acc = 'sethc','utilman','osk','magnify','narrator','DisplaySwitch','AtBroker','mstsc'
foreach ($a in $acc) {
  $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$a.exe"
  $d = (Get-ItemProperty $k -EA SilentlyContinue).Debugger
  if ($d) { "[!] $a.exe 被 IFEO 劫持 -> $d" }
  $f = "$env:SystemRoot\System32\$a.exe"
  if (Test-Path $f) {
    $sig = Get-AuthenticodeSignature $f -EA SilentlyContinue
    if ($sig.Status -ne 'Valid') { "[!] $f 签名异常: $($sig.Status)" }
  }
}

# 文件替换型（不是 IFEO，是直接换了 exe）：比对大小与签名
foreach ($a in $acc) {
  $f = "$env:SystemRoot\System32\$a.exe"
  if (Test-Path $f) {
    Get-Item $f | Select-Object Name,Length,CreationTime,LastWriteTime,
      @{n='Sign';e={(Get-AuthenticodeSignature $f).Status}}
  }
} | Format-Table -AutoSize

# 【冷门但极隐蔽】SilentProcessExit：进程退出时触发 MonitorProcess（T1546.012）
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" -EA SilentlyContinue |
  ForEach-Object {
    $mp = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).MonitorProcess
    if ($mp) { [PSCustomObject]@{Target=$_.PSChildName; MonitorProcess=$mp} }
  } | Format-Table -AutoSize -Wrap
```

### 3.7 COM 劫持、BHO、Office 与浏览器插件

```powershell
# COM 劫持：HKCU 覆盖 HKLM 的 CLSID 指向（不需要管理员即可持久化）
Get-ChildItem "HKCU:\Software\Classes\CLSID" -EA SilentlyContinue | ForEach-Object {
  $ip = Join-Path $_.PSPath "InprocServer32"
  if (Test-Path $ip) {
    $dll = (Get-ItemProperty $ip -EA SilentlyContinue).'(default)'
    if ($dll) { [PSCustomObject]@{CLSID=$_.PSChildName; DLL=$dll; Sign=(Get-AuthenticodeSignature ($dll -replace '^"','' -replace '"$','') -EA SilentlyContinue).Status} }
  }
} | Where-Object { $_.Sign -ne 'Valid' } | Format-Table -AutoSize -Wrap

# 常见被劫持的 COM 目标（微软自带但可被覆盖）
$comTargets = 'LocalServer32','InprocServer32','TreatAs','ScriptletURL','ProgID'
Get-ChildItem "HKCU:\Software\Classes\CLSID" -Recurse -Depth 2 -EA SilentlyContinue |
  Where-Object { $_.PSChildName -in $comTargets } | Select-Object PSPath

# TreatAs：把一个 CLSID 指向另一个（劫持 .NET 组件）
Get-ChildItem "HKCU:\Software\Classes\CLSID" -EA SilentlyContinue |
  ForEach-Object {
    $t = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).TreatAs
    if ($t) { [PSCustomObject]@{CLSID=$_.PSChildName; TreatAs=$t} }
  }

# 浏览器辅助对象（BHO）与 Shell 扩展
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" -EA SilentlyContinue |
  Select-Object PSChildName
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" -EA SilentlyContinue |
  Select-Object PSChildName
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers" -EA SilentlyContinue
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved" -EA SilentlyContinue

# Office 加载项（WLL/XLL/DLL 型后门，随 Office 启动）
foreach ($v in '16.0','15.0','14.0') {
  foreach ($app in 'Word','Excel','PowerPoint','Outlook') {
    $k = "HKCU:\Software\Microsoft\Office\$v\$app\Addins"
    if (Test-Path $k) { Get-ChildItem $k | ForEach-Object { [PSCustomObject]@{App="$app $v"; Addin=$_.PSChildName; Load=(Get-ItemProperty $_.PSPath).LoadBehavior} } }
  }
}
# Office 启动目录（放进去就执行）
#   %APPDATA%\Microsoft\Excel\XLSTART\
#   %APPDATA%\Microsoft\Word\STARTUP\
#   %APPDATA%\Microsoft\Outlook\VbaProject.OTM     <- 宏后门，非常高频
Get-ChildItem "$env:APPDATA\Microsoft\Excel\XLSTART","$env:APPDATA\Microsoft\Word\STARTUP" -EA SilentlyContinue
Get-Item "$env:APPDATA\Microsoft\Outlook\VbaProject.OTM" -EA SilentlyContinue |
  Select-Object FullName,Length,CreationTime,LastWriteTime
# Office 受信任位置（攻击者把恶意文档目录加白）
Get-ChildItem "HKCU:\Software\Microsoft\Office\*\*\Security\Trusted Locations" -EA SilentlyContinue -Recurse |
  Select-Object PSPath

# 输入法（IME）DLL 劫持：通过 CTF 注册恶意 IME
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\CTF\TIP" -Recurse -Depth 3 -EA SilentlyContinue |
  Where-Object { $_.PSChildName -eq 'LanguageProfile' } | Select-Object -First 10 PSPath
```

### 3.8 启动文件夹、快捷方式、Active Setup、登录脚本

```powershell
# 启动文件夹（按用户 + 全局）
$startups = @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($s in $startups) {
  if (Test-Path $s) {
    Get-ChildItem $s -Force | Select-Object @{n='Dir';e={$s}},Name,Length,CreationTime,LastWriteTime
  }
}
# 启动文件夹位置被重定向（同时看注册表指向）
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" |
  Select-Object Startup,StartupApproved

# .lnk 快捷方式的目标（后门常伪装成快捷方式，目标指向 powershell/mshta）
$sh = New-Object -ComObject WScript.Shell
Get-ChildItem $startups -Filter *.lnk -Force -EA SilentlyContinue | ForEach-Object {
  $l = $sh.CreateShortcut($_.FullName)
  [PSCustomObject]@{Lnk=$_.Name;Target=$l.TargetPath;Args=$l.Arguments;WorkDir=$l.WorkingDirectory}
} | Format-Table -AutoSize -Wrap

# Active Setup：首次登录执行的组件（用户级持久化的隐蔽手法）
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components" -EA SilentlyContinue |
  ForEach-Object {
    $stub = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).StubPath
    if ($stub) { [PSCustomObject]@{Component=$_.PSChildName; StubPath=$stub} }
  } | Format-Table -AutoSize -Wrap

# 登录脚本（本地策略 + 用户属性）
Get-ItemProperty "HKCU:\Environment" -EA SilentlyContinue | Select-Object UserInitMprLogonScript
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts" -Recurse -EA SilentlyContinue |
  Select-Object PSPath
Get-ChildItem "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup","C:\Windows\System32\GroupPolicy\User\Scripts\Logon" -EA SilentlyContinue |
  Select-Object FullName,Length,LastWriteTime

# 组策略脚本配置（GPT.INI 与 scripts.ini 时间戳）
Get-ChildItem "C:\Windows\System32\GroupPolicy" -Recurse -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 20 FullName,LastWriteTime

# 域环境：域登录脚本 / 组策略首选项（需在 DC 侧核查）
# net group /domain / Get-GPOReport
```

### 3.9 冷门启动位（最容易漏，逐项过一遍）

```powershell
Write-Host "`n=== 1) NetSh Helper DLL（网络组件后门，极隐蔽）==="
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NetSh" -EA SilentlyContinue

Write-Host "`n=== 2) Winsock LSP / Namespace Providers ==="
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries" -EA SilentlyContinue |
  ForEach-Object { (Get-ItemProperty $_.PSPath).PackedCatalogItem }
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries" -EA SilentlyContinue |
  Select-Object PSPath

Write-Host "`n=== 3) AppCertDlls（证书 API hook，进程级注入）==="
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" -EA SilentlyContinue

Write-Host "`n=== 4) Session Manager：BootExecute / SetupExecute / S0InitialCommand ==="
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -EA SilentlyContinue |
  Select-Object BootExecute,SetupExecute,S0InitialCommand,Execute,PendingFileRenameOperations

Write-Host "`n=== 5) Shell 延迟加载 / 共享任务 / 打印监视器 / 时间提供程序 ==="
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad" -EA SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler" -EA SilentlyContinue
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors" -EA SilentlyContinue |
  ForEach-Object { $d=(Get-ItemProperty $_.PSPath -EA SilentlyContinue).Driver; [PSCustomObject]@{Monitor=$_.PSChildName;Driver=$d} }
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders" -EA SilentlyContinue |
  ForEach-Object { $d=(Get-ItemProperty $_.PSPath -EA SilentlyContinue).DllName; [PSCustomObject]@{Provider=$_.PSChildName;Dll=$d} }

Write-Host "`n=== 6) 屏幕保护程序 / SCRNSAVE ==="
Get-ItemProperty "HKCU:\Control Panel\Desktop" -EA SilentlyContinue | Select-Object SCRNSAVE.EXE,ScreenSaveActive,ScreenSaveTimeOut

Write-Host "`n=== 7) 环境变量中的执行点 ==="
Get-ItemProperty "HKCU:\Environment" -EA SilentlyContinue
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -EA SilentlyContinue

Write-Host "`n=== 8) 打印处理器 / 端口监视器 / LSA 扩展 ==="
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Print\PrintProcessors" -EA SilentlyContinue
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\*\Print Processors" -EA SilentlyContinue

Write-Host "`n=== 9) Store / UWP 应用持久化 & AppX 启动 ==="
Get-AppxPackage | Where-Object { -not $_.SignatureKind -eq 'System' } | Select-Object Name,PackageFullName,InstallLocation
Get-ChildItem "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData" -EA SilentlyContinue |
  Select-Object -First 20 PSPath

Write-Host "`n=== 10) 备份/恢复与 WinRE（持久化到恢复环境）==="
Get-ChildItem "C:\Recovery" -Recurse -EA SilentlyContinue | Select-Object -First 20 FullName,LastWriteTime
Get-ChildItem "C:\Windows\System32\Recovery" -EA SilentlyContinue
Get-CimInstance Win32_ShadowCopy -EA SilentlyContinue | Select-Object ID,InstallDate,DeviceObject

Write-Host "`n=== 11) 安全模式配置被篡改 ==="
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot" -Recurse -EA SilentlyContinue |
  Where-Object { $_.PSChildName -match '\.(exe|dll|sys)$' -and $_.PSChildName -notmatch '^(sys|svc)$' } |
  Select-Object -First 30 PSPath

Write-Host "`n=== 12) 被禁用的 Defender / 审计策略（常作为后门前置）==="
Get-MpPreference | Select-Object DisableRealtimeMonitoring,ExclusionPath,ExclusionProcess,ExclusionExtension
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -EA SilentlyContinue
```

### 3.10 RDP 与远程访问后门

```powershell
# RDP 配置（是否被远程开启、认证被降级）
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" | Select-Object fDenyTSConnections
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" |
  Select-Object PortNumber,UserAuthentication,SecurityLayer,fEnableWinStation,MaxInstanceCount
# 正常：UserAuthentication=1, SecurityLayer=2（SSL）

# RDP Wrapper（把单用户 Windows 变成多会话，常被用作后门）
Get-ChildItem "C:\Program Files\RDP Wrapper","C:\Program Files\RDP Wrapper\rdpwrap.ini" -EA SilentlyContinue
Get-Service TermService | Select-Object Status,StartType
# 检查 termsrv.dll 是否被改（RDP Wrapper 会打补丁）
Get-Item "$env:SystemRoot\System32\termsrv.dll" | Select-Object Length,LastWriteTime
(Get-FileHash "$env:SystemRoot\System32\termsrv.dll" -Algorithm SHA256).Hash

# 影子会话（攻击者无需登录即可旁观/控制）
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow
qwinsta

# 远程桌面客户端记录：连过谁（横向移动的自证）
Get-ChildItem "HKCU:\Software\Microsoft\Terminal Server Client\Servers" -EA SilentlyContinue |
  Select-Object PSChildName
Get-ChildItem "HKCU:\Software\Microsoft\Terminal Server Client\Default" -EA SilentlyContinue
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Filter "*.rdp" -EA SilentlyContinue
Get-Content "$env:USERPROFILE\Documents\Default.rdp" -EA SilentlyContinue

# 三条"远程访问类"后门全家桶（合法工具被滥用，需要业务确认）
$rc = 'TeamViewer','AnyDesk','ToDesk','SunloginClient','RustDesk','AweSun','GotoHTTP','VNC','todesk'
Get-Process | Where-Object { $rc -contains $_.Name -or $_.Path -match ($rc -join '|') } |
  Select-Object Name,Id,Path,StartTime
Get-Service | Where-Object { $rc -contains $_.Name -or $_.DisplayName -match ($rc -join '|') } |
  Select-Object Name,Status,StartType
Get-ChildItem "$env:ProgramData","$env:ProgramFiles","${env:ProgramFiles(x86)}" -Directory -EA SilentlyContinue |
  Where-Object { $_.Name -match ($rc -join '|') } | Select-Object FullName,LastWriteTime
# 远控软件常用端口
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 5938,6568,7070,8000,4000,21118,21116 } |
  Select-Object LocalAddress,LocalPort,OwningProcess

# SSH 服务（Windows 版 OpenSSH，常被二进制替换 + authorized_keys 后门）
Get-Service sshd,ssh-agent -EA SilentlyContinue | Select-Object Name,Status,StartType
Get-Item "$env:ProgramData\ssh\administrators_authorized_keys","$env:USERPROFILE\.ssh\authorized_keys" -EA SilentlyContinue |
  Select-Object FullName,Length,LastWriteTime
Get-Content "$env:ProgramData\ssh\administrators_authorized_keys" -EA SilentlyContinue
Get-Content "$env:ProgramData\ssh\sshd_config" -EA SilentlyContinue | Select-String -Pattern 'AuthorizedKeysFile|ForceCommand|PermitUserEnvironment|AllowUsers|Port'
```

### 3.11 WSL、容器与虚拟化层

这是近几年新增的攻击面：**Windows 主机被查干净了，后门在 WSL 里**。

```powershell
# WSL 发行版与其中的 Linux 侧持久化
wsl --list --verbose
wsl --list --all
# 直接进 WSL 查 Linux 侧持久化（cron / systemd / authorized_keys / rc.local）
wsl -d <DistroName> -- bash -c "crontab -l; ls -la /etc/cron.d/ /root/.ssh/ 2>/dev/null; cat /etc/rc.local 2>/dev/null"
# WSL 文件从 Windows 侧可见（UNC 路径）
Get-ChildItem "\\wsl$\<DistroName>\root" -Force -EA SilentlyContinue

# WSL 配置与开机启动
Get-Content "$env:USERPROFILE\.wslconfig" -EA SilentlyContinue
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*" -EA SilentlyContinue |
  Select-Object DistributionName,BasePath,Flags

# Docker Desktop / 容器
Get-Process -Name "com.docker*","dockerd","Docker Desktop" -EA SilentlyContinue
docker ps -a
docker images
# 容器内异常镜像与挂载宿主机目录
docker inspect $(docker ps -q) --format '{{.Name}} {{.Config.Image}} {{.Mounts}}'

# Hyper-V / 虚拟机（攻击者可能藏在 VM 里做跳板）
Get-VM -EA SilentlyContinue | Select-Object Name,State,Uptime
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Hyper-V" -EA SilentlyContinue
```

### 3.12 BITS 与其他"任务型"持久化

```powershell
# BITS 传输任务：跨重启存活、以 SYSTEM 运行、可从 HTTP 拉文件
Get-BitsTransfer -AllUsers -EA SilentlyContinue | Select-Object DisplayName,JobState,OwnerAccount,FileList
bitsadmin /list /allusers /verbose
# BITS 任务注册表
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\BITS" -Recurse -EA SilentlyContinue |
  Select-Object -First 20 PSPath

# 事件订阅之外的"通知型"后门：任务计划 + 事件触发器（XML 里 <Subscription>）
Get-ScheduledTask | Where-Object {
  $_.Triggers | Where-Object { $_.CimClass.CimClassName -match 'Event|Logon|Boot|Registration' }
} | Select-Object TaskPath,TaskName,State,@{n='Trigger';e={($_.Triggers.CimClass.CimClassName) -join ','}}

# 服务恢复动作（重新串联一次，因为极隐蔽）
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
  $ra = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).FailureCommand
  if ($ra) { "服务 $($_.PSChildName) 的失败命令: $ra" }
}

# .NET 相关的机器级启动：NGEN / x86 兼容层
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\.NETFramework" -EA SilentlyContinue | Select-Object PSPath

# PowerShell 配置后门（所有 PS 会话都会加载）
Get-ChildItem $PROFILE,$PROFILE.AllUsersAllHosts,$PROFILE.AllUsersCurrentHost -EA SilentlyContinue |
  Select-Object FullName,Length,LastWriteTime
# 正常的 $PROFILE 往往不存在；存在且含网络调用 = 后门
Microsoft.PowerShell_profile.ps1 2>$null
Get-ChildItem "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1" -EA SilentlyContinue |
  Select-Object FullName,Length,LastWriteTime
```

### 3.13 一键全量枚举：Autoruns（**不要跳过这一步**）

手工查完上面 12 节，仍可能有遗漏。**Autoruns 是持久化排查的最终兜底**，覆盖 50+ 个自启位置，且能校验签名、查 VirusTotal。

```powershell
# 全量导出 CSV（含哈希 + 签名校验 + 时间戳）
autorunsc64.exe -accepteula -a * -c -h -s -t -nobanner -o C:\IR\autoruns_all.csv

# 只看非微软项（最实用的一张表）
autorunsc64.exe -accepteula -a * -c -h -s -t -nobanner -m -o C:\IR\autoruns_nonms.csv

# 只看未签名项
autorunsc64.exe -accepteula -a * -c -h -u -nobanner -o C:\IR\autoruns_unsigned.csv

# 查 VirusTotal（会外发哈希，需授权）
# autorunsc64.exe -accepteula -a * -c -h -s -vt -nobanner -m -o C:\IR\autoruns_vt.csv

# GUI 版现场核对
# autoruns64.exe  ->  Options: Hide Microsoft / Verify Code Signatures / Check VirusTotal
#                    Everything 勾选后看黄色（未签名）与红色（VT 命中）条目

# 参数速查：
#   -a *  所有类别（b boot, d drv, e 计划任务, g 侧边栏, h 已知DLL, i IE, k 登录项,
#         l 服务, m 用户自启, o 系统自启, p 打印机, r 驱动, s 安全包, w Winlogon）
#   -c    CSV 输出    -h 计算哈希    -s 校验签名    -t 显示时间戳
#   -m    隐藏微软项  -u 只显示未签名  -vt 查 VirusTotal  -o 输出文件
```

**Autoruns 结果的处理顺序**

1. 先看 `-m`（非微软）结果中的 **未签名 + 指向用户可写目录** 项 —— 这撮基本就是后门；
2. 再看 `Task Scheduler` 与 `Services` 类别的**创建时间**是否与失陷窗口吻合；
3. 对每个可疑条目，回到前面 3.1–3.12 对应小节做确认（Autoruns 只给"存在"，不给"为什么"）。

---
## 4. 账号与身份认证审计

### 4.1 本地账号枚举（含隐藏账号）

```powershell
# 基础枚举（原手册命令）
Get-LocalUser
net user
Get-LocalGroupMember Administrators

# 增强视图：账号状态、最后登录、密码更新时间、说明字段
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordExpires,
  Description,UserMayChangePassword,PrincipalSource | Format-Table -AutoSize

Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
  Select-Object Name,SID,Disabled,Lockout,PasswordRequired,Description |
  Sort-Object Name | Format-Table -AutoSize

# net user 全量（含内置描述，$ 结尾的隐藏账号在这里才看得到）
net user
# 单个账号详情（含登录脚本、上次登录、组成员）
net user <用户名>

# 【关键】$ 结尾账号：net user 不显示但可以被登录
Get-LocalUser | Where-Object { $_.Name -match '\$$' } | Select-Object Name,Enabled,Description

# 【关键】SAM 注册表直读：能看到 GUI/Get-LocalUser 隐藏的账号（需 SYSTEM 权限）
# 通过 PsExec 以 SYSTEM 身份读
# psexec -s -i regedit
# 或者：
# reg save HKLM\SAM C:\IR\SAM.hive
# reg save HKLM\SYSTEM C:\IR\SYSTEM.hive
# reg save HKLM\SECURITY C:\IR\SECURITY.hive
# 然后用 RegistryExplorer / impacket-secretsdump 离线解析
# impacket-secretsdump -sam SAM.hive -system SYSTEM.hive LOCAL

# Winlogon\SpecialAccounts 里被隐藏的账号（值=0 时登录界面不显示）
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -EA SilentlyContinue

# RID 500/501/502 之外的高 RID 且无描述账号 = 可疑
Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
  Where-Object { $_.Name -notin 'Administrator','Guest','DefaultAccount','WDAGUtilityAccount' } |
  Select-Object Name,SID,Description,Disabled
```

**判读要点**

| 现象 | 含义 |
|---|---|
| 账号名以 `$` 结尾 | 计划任务的默认命名习惯，也可能是后门账号（`net user` 隐藏） |
| `Description` 与其他账号风格一致但账号名陌生 | 攻击者刻意融入环境（T1036.004） |
| `PasswordLastSet` 与失陷窗口吻合、且账号平时不活跃 | 新建/改密后门账号 |
| 账号在 `Administrators` 或 `Remote Desktop Users` 组但业务方不认识 | 直接定性 |
| 同名账号但 SID 不同（克隆账号） | 极隐蔽，需比对 SAM 中的 F/V 值 |

### 4.2 特权组与提权面

```powershell
# 所有特权组的成员（不止 Administrators）
$privileged = 'Administrators','Remote Desktop Users','Remote Management Users',
              'Backup Operators','Hyper-V Administrators','Account Operators',
              'Server Operators','Print Operators','Distributed COM Users','Network Configuration Operators'
foreach ($g in $privileged) {
  Get-LocalGroupMember -Group $g -EA SilentlyContinue |
    Select-Object @{n='Group';e={$g}},Name,PrincipalSource,ObjectClass
}

# 完整组成员关系导出（原生模块）
Get-LocalGroup | ForEach-Object {
  $g = $_
  Get-LocalGroupMember $g.Name -EA SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{Group=$g.Name;Member=$_.Name;Source=$_.PrincipalSource;Type=$_.ObjectClass}
  }
} | Format-Table -AutoSize

# 【重要】User Rights Assignment：谁拥有"调试程序/以操作系统方式操作/备份文件"等高危权限
secedit /export /cfg C:\IR\secpol.cfg /areas USER_RIGHTS
Get-Content C:\IR\secpol.cfg
# 重点看：SeDebugPrivilege（可 dump LSASS）、SeBackupPrivilege（可读 SAM/NTDS）、
#         SeImpersonatePrivilege（Potato 提权）、SeTcbPrivilege、SeLoadDriverPrivilege

# 本地安全策略中的其他关键项
secedit /export /cfg C:\IR\secpol_full.cfg
Select-String -Path C:\IR\secpol_full.cfg -Pattern 'EnableAdmin|LSAAnonymousNameLookup|RestrictAnonymous|NewAdministratorName'
# NewAdministratorName 表示 Administrator 被改名（合法运维或攻击者隐藏）

# UAC 配置被改（降低防御以保证后门可用）
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
  Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop,FilterAdministratorToken
# EnableLUA=0 = UAC 被关闭（危险）

# AlwaysInstallElevated（任意用户可提权安装 MSI）
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -EA SilentlyContinue |
  Select-Object AlwaysInstallElevated
Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -EA SilentlyContinue |
  Select-Object AlwaysInstallElevated

# 计划任务/服务中使用了高权限账户的（横向线索）
Get-CimInstance Win32_Service | Where-Object {
  $_.StartName -in 'LocalSystem','.\Administrator' -or $_.StartName -match 'SYSTEM'
} | Select-Object Name,StartName,PathName | Format-Table -AutoSize
```

### 4.3 登录事件解读（这是判断"谁进来过"的核心）

```powershell
# 成功登录（4624）—— 看 LogonType 与来源 IP
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 100 |
  Select-Object TimeCreated,
    @{n='User';e={$_.Properties[5].Value}},
    @{n='Domain';e={$_.Properties[6].Value}},
    @{n='Type';e={$_.Properties[8].Value}},
    @{n='AuthPkg';e={$_.Properties[10].Value}},
    @{n='Workstation';e={$_.Properties[11].Value}},
    @{n='SrcIP';e={$_.Properties[18].Value}},
    @{n='Proc';e={$_.Properties[17].Value}} | Format-Table -AutoSize

# 只看远程交互（RDP = 10）与网络登录（3），过滤掉本地噪声
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 500 |
  Where-Object { $_.Properties[8].Value -in 3,8,10 } |
  Select-Object TimeCreated,@{n='User';e={$_.Properties[5].Value}},
    @{n='Type';e={$_.Properties[8].Value}},@{n='SrcIP';e={$_.Properties[18].Value}},
    @{n='User';e={$_.Properties[5].Value}} | Sort-Object TimeCreated

# 登录失败（4625）—— 暴破与密码喷洒
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 50
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 1000 |
  Group-Object { $_.Properties[5].Value } | Sort-Object Count -Descending |
  Select-Object Count,Name -First 20
# 按来源 IP 聚合（找暴破源头）
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 1000 |
  Group-Object { $_.Properties[18].Value } | Sort-Object Count -Descending |
  Select-Object Count,Name -First 20

# 特权分配（4672）—— 每次带管理员权限登录都会记录
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672} -MaxEvents 50 |
  Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='Privileges';e={$_.Properties[4].Value}}

# 显式凭据使用（4648）—— 横向移动最直接的证据
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4648} -MaxEvents 50 |
  Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},
    @{n='Target';e={$_.Properties[5].Value}},@{n='TargetServer';e={$_.Properties[8].Value}},
    @{n='Proc';e={$_.Properties[11].Value}}

# 账号与组的变更
foreach ($id in 4720,4722,4723,4724,4726,4738,4740) {   # 创建/启用/改密/重置/删除/变更/锁定
  Get-WinEvent -FilterHashtable @{LogName='Security';ID=$id} -MaxEvents 20 -EA SilentlyContinue |
    Select-Object @{n='ID';e={$id}},TimeCreated,Message
}
foreach ($id in 4728,4732,4756,4735,4737) {   # 加入全局/本地/通用组
  Get-WinEvent -FilterHashtable @{LogName='Security';ID=$id} -MaxEvents 20 -EA SilentlyContinue |
    Select-Object @{n='ID';e={$id}},TimeCreated,Message
}

# 审计策略被改（攻击者常关审计）
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4719} -MaxEvents 20
auditpol /get /category:*

# Kerberos / NTLM
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4768,4769,4771,4776} -MaxEvents 50 |
  Select-Object TimeCreated,Id,@{n='User';e={$_.Properties[0].Value}}

# 【RDP 最好的来源】连接管理器 1149：含源 IP 与用户名
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -MaxEvents 50 -EA SilentlyContinue |
  Where-Object { $_.Id -eq 1149 } | Select-Object TimeCreated,Message

# 本地会话管理器：21 登录 / 22 Shell 启动 / 23 注销 / 24 断开 / 25 重连
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -MaxEvents 80 -EA SilentlyContinue |
  Where-Object { $_.Id -in 21,22,23,24,25 } |
  Select-Object TimeCreated,Id,@{n='Msg';e={($_.Message -split "`n")[0]}}

# 共享访问（横向取数据）
Get-WinEvent -FilterHashtable @{LogName='Security';ID=5140,5145} -MaxEvents 50 |
  Select-Object TimeCreated,Id,Message
```

**LogonType 速查**

| 值 | 含义 | 排查价值 |
|---|---|---|
| 2 | 交互式（本地键鼠） | 有人坐在机器前 |
| 3 | 网络（SMB/共享/WMI/WinRM） | **横向移动主战场** |
| 4 | 批处理 | 计划任务 |
| 5 | 服务 | 服务账户 |
| 7 | 解锁 | 有人解锁了被锁定会话 |
| 8 | 网络明文 | 明文凭据（危险） |
| 9 | NewCredentials（runas /netonly） | **凭据伪造迹象** |
| 10 | 远程交互（RDP） | 有人远程登录 |
| 11 | 缓存交互 | 域账号离线登录 |

### 4.4 凭据窃取痕迹（Windows 特有，必查）

```powershell
# 【1】WDigest 明文缓存（老系统被开启后，LSASS 里存明文密码）
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -EA SilentlyContinue |
  Select-Object UseLogonCredential
# 应为 0 或不存在。=1 说明被开启了明文缓存

# 【2】LSASS 被读取的痕迹（Sysmon Event 10 是最直接的证据）
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -EA SilentlyContinue |
  Where-Object { $_.Id -eq 10 -and $_.Message -match 'lsass' } |
  Select-Object TimeCreated,Message -First 20

# 【3】LSASS dump 文件的痕迹（常见落地位置）
Get-ChildItem C:\ -Recurse -Include *.dmp,lsass*,*lsass*.zip,*.tar.gz -EA SilentlyContinue -Force |
  Where-Object { $_.Name -match 'lsass|dump|dmp' } |
  Select-Object FullName,Length,CreationTime,LastWriteTime

# 【4】mimikatz / 类似工具的落盘痕迹
Get-ChildItem C:\ -Recurse -Include mimikatz*,*sekurlsa*,*lsadump*,*kerberoast*,pwdump*,procdump* -EA SilentlyContinue -Force |
  Select-Object FullName,Length,CreationTime

# 【5】DPAPI 凭据与主密钥被访问（浏览器密码、RDP 密码破解）
Get-ChildItem "$env:APPDATA\Microsoft\Credentials","$env:LOCALAPPDATA\Microsoft\Credentials" -Force -EA SilentlyContinue |
  Select-Object FullName,Length,LastWriteTime
Get-ChildItem "$env:APPDATA\Microsoft\Protect" -Recurse -Force -EA SilentlyContinue |
  Select-Object FullName,LastWriteTime

# 【6】DCSync（域控）：4662 + 复制权限 GUID
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4662} -MaxEvents 200 -EA SilentlyContinue |
  Where-Object { $_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |
  Select-Object TimeCreated,Message
# 这两个 GUID 分别是 DS-Replication-Get-Changes / -All，非 DC 主机出现即高危

# 【7】NTDS.dit 被窃取的痕迹（域控）
Get-Item "$env:SystemRoot\NTDS\ntds.dit" | Select-Object Length,LastWriteTime
Get-ChildItem C:\ -Recurse -Include *.dit -EA SilentlyContinue -Force | Select-Object FullName,Length,CreationTime
# 常见手法：vssadmin 创建快照 -> 从快照复制 -> 删除快照
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 500 -EA SilentlyContinue |
  Where-Object { $_.Message -match 'ntdsutil|vssadmin|esentutl|diskshadow' } | Select-Object TimeCreated,Message

# 【8】GPP 密码（cpassword）被读取：组策略 Preferences XML
Get-ChildItem "\\<DOMAIN>\SYSVOL" -Recurse -Include Groups.xml,Services.xml,ScheduledTasks.xml -EA SilentlyContinue

# 【9】浏览器保存的凭据被导出
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
              "$env:APPDATA\Mozilla\Firefox\Profiles" -Recurse -Force -EA SilentlyContinue |
  Select-Object FullName,LastWriteTime
# 浏览器进程被非用户启动（浏览器凭据窃取）
Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'chrome|firefox|msedge' -and $_.CommandLine -match 'headless|remote-debugging|--type=' } |
  Select-Object ProcessId,CommandLine
```

### 4.5 会话、域环境与横向移动

```powershell
# 当前会话与登录用户
query user
qwinsta
Get-CimInstance Win32_LogonSession | Select-Object LogonId,LogonType,StartTime,AuthenticationPackage
Get-CimInstance Win32_LoggedOnUser | Select-Object Antecedent,Dependent

# 已建立的管理员文件连接（谁连着我）
net session
Get-SmbSession | Select-Object ClientComputerName,ClientUserName,NumOpens
net use
Get-PSDrive | Where-Object { $_.Provider.Name -eq 'FileSystem' -and $_.Name -ne '' }

# 域信息（判断是否在域内、定位 DC）
systeminfo | findstr /i "domain"
nltest /dsgetdc:<你的域名>
Get-CimInstance Win32_ComputerSystem | Select-Object Domain,PartOfDomain,UserName
whoami /all
whoami /groups
whoami /priv

# 域相关持久化（域环境必查）
# - AdminSDHolder ACL 被改（自动提权）
# - 组策略下发脚本/计划任务
# - SID History 注入（需域管工具核查）
# - 黄金票据（krbtgt 哈希被窃，通常伴随 4769 异常）
# Get-ADUser -Filter * -Properties SIDHistory | Where-Object SIDHistory
# Get-ADTrust -Filter *
# Get-ADGroupMember "Domain Admins"
# AD 攻击路径评估（蓝队自查也很有用）
# BloodHound / SharpHound 采集 + BloodHound 分析
# Purple Knight / PingCastle 做 AD 安全评估

# 横向移动工具痕迹（本机侧）
# PsExec：会创建 PSEXESVC 服务与共享
Get-Service PSEXESVC -EA SilentlyContinue | Select-Object Name,Status,StartType
Get-ChildItem "$env:SystemRoot\PSEXESVC.exe" -EA SilentlyContinue
# WMI 远程执行痕迹
Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" -MaxEvents 100 -EA SilentlyContinue |
  Where-Object { $_.Id -in 5857,5858 } | Select-Object TimeCreated,Message -First 30
# WinRM 远程
Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -MaxEvents 50 -EA SilentlyContinue |
  Where-Object { $_.Id -in 6,15,91,142,145 } | Select-Object TimeCreated,Id,Message -First 30

# 出站管理连接（我倒着连别人 = 我可能已是跳板）
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemotePort -in 445,135,139,5985,5986,3389,22 } |
  Select-Object RemoteAddress,RemotePort,OwningProcess,
    @{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}}
```

### 4.6 账号侧补充检查

```powershell
# 密码策略与锁定策略
net accounts
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -EA SilentlyContinue |
  Select-Object MaximumPasswordAge,MinimumPasswordAge,MinimumPasswordLength,RequireSignOrSeal

# 【关键】空口令账号 / 口令永不过期
Get-LocalUser | Where-Object { -not $_.PasswordRequired -or $_.PasswordExpires -eq $null } |
  Select-Object Name,Enabled,PasswordRequired,PasswordExpires,PasswordLastSet

# 来宾与内置管理员状态
Get-LocalUser Administrator,Guest,DefaultAccount -EA SilentlyContinue | Select-Object Name,Enabled,LastLogon
net user guest

# Windows LAPS（本地管理员密码集中管理，现代基线要求启用）
Get-LapsADPassword  -Identity <计算机名> -EA SilentlyContinue   # 域内
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Policies\LAPS" -EA SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" -EA SilentlyContinue

# Credential Guard / Device Guard 状态（保护凭据不被 dump）
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -EA SilentlyContinue |
  Select-Object VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning

# 证书与智能卡（攻击者可能导入证书做持久化认证）
Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject,Thumbprint,NotAfter,HasPrivateKey
certutil -store -v My
# 被信任的根证书（中间人）
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -notmatch 'Microsoft|VeriSign|DigiCert|GlobalSign|Entrust|Baltimore|Sectigo|USERTrust|COMODO|Go Daddy|Thawte|Symantec' } |
  Select-Object Subject,Thumbprint,NotBefore,NotAfter

# 本地账号的登录脚本与主目录（可被改指向）
Get-CimInstance Win32_UserProfile | Select-Object LocalPath,SID,LastUseTime,Special
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -EA SilentlyContinue |
  Select-Object PSChildName,ProfileImagePath
```

---

## 5. 执行痕迹与时间线

> Windows 相比 Linux 的最大优势：**有大量"用户活动与程序执行"的遗迹**，即使攻击者删除了日志也常常残留。这一层决定了你能不能说清"他到底干了什么"。

### 5.1 Prefetch（程序执行证据）

```powershell
# Prefetch 目录：程序执行的直接证据（含首次/末次运行时间与运行次数）
Get-ChildItem "$env:SystemRoot\Prefetch" -Filter "*.pf" |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 50 Name,Length,CreationTime,LastWriteTime

# 只看最近 24 小时执行过的程序
Get-ChildItem "$env:SystemRoot\Prefetch" -Filter "*.pf" |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
  Select-Object Name,CreationTime,LastWriteTime | Sort-Object LastWriteTime -Descending

# 【注意】Prefetch 是否被禁用（攻击者常关掉它反取证）
$pf = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -EA SilentlyContinue
$pf | Select-Object EnablePrefetcher,EnableSuperfetch
# EnablePrefetcher: 0=禁用 1=仅应用 2=仅启动 3=全开。=0 需警惕

# 专业解析（PECmd，Eric Zimmerman 出品，能解出运行次数与 8 个最近运行时间）
# 用法一：直接解析目录
# PECmd.exe -d C:\Windows\Prefetch --csv C:\IR\prefetch --csvf pf.csv
# 用法二：解析单个文件（-k 保留原文件时间戳，-q 静默）
# PECmd.exe -f C:\Windows\Prefetch\POWERSHELL.EXE-XXXX.pf -k

# 关注这些 Prefetch 条目（攻击者常用）
$lol = 'POWERSHELL','PWSH','CMD','MSHTA','WSCRIPT','CSCRIPT','RUNDLL32','REGSVR32',
       'CERTUTIL','BITSADMIN','MSBUILD','INSTALLUTIL','WMIC','CURL','FTP','TELNET',
       'MIMIKATZ','PROCDUMP','PSEXEC','NET','NET1','SC','SCHTASKS','REG','VSSADMIN'
foreach ($l in $lol) {
  Get-ChildItem "$env:SystemRoot\Prefetch" -Filter "$l*.pf" -EA SilentlyContinue |
    Select-Object @{n='Tool';e={$l}},Name,CreationTime,LastWriteTime
} | Sort-Object LastWriteTime -Descending | Format-Table -AutoSize
```

### 5.2 Amcache 与 ShimCache（程序存在与执行痕迹）

即使文件被删除，**Amcache / ShimCache 往往还留着它的哈希和路径**。

```powershell
# ShimCache（AppCompatCache）：存在于注册表，记录"系统见过"的可执行文件
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -EA SilentlyContinue |
  Select-Object AppCompatCache -ExpandProperty AppCompatCache | Out-Null
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache

# Amcache.hve：记录执行过的程序 + SHA1 + 首次/末次运行时间
Get-Item "$env:SystemRoot\AppCompat\Programs\Amcache.hve" |
  Select-Object FullName,Length,LastWriteTime

# 专业解析（推荐）
#   AmcacheParser -f C:\Windows\AppCompat\Programs\Amcache.hve --csv C:\IR\amcache
#   AppCompatCacheParser -f C:\Windows\System32\config\SYSTEM --csv C:\IR\shimcache
#   注意：解析 Amcache 需要先复制 hive（正在被使用无法直接读）
Copy-Item "$env:SystemRoot\AppCompat\Programs\Amcache.hve" C:\IR\Amcache.hve -Force -EA SilentlyContinue
#   若被占用，用 reg save 或 Volume Shadow Copy 提取

# 结果里重点看：路径在 Temp/AppData/ProgramData、SHA1 在威胁情报中命中、
#              首次运行时间落在失陷窗口、名称与合法程序相似（仿冒）
```

### 5.3 UserAssist、BAM/DAM、SRUM（用户行为画像）

```powershell
# UserAssist：GUI 程序执行记录（ROT13 编码的键名，需解码）
$k = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
Get-ChildItem $k -EA SilentlyContinue | ForEach-Object {
  $sub = $_
  Get-ChildItem $sub.PSPath -EA SilentlyContinue | ForEach-Object {
    $name = $_.PSChildName
    # ROT13 解码
    $decoded = -join ($name.ToCharArray() | ForEach-Object {
      $c = [int][char]$_
      if ($c -ge 65 -and $c -le 90)      { [char](65 + (($c - 65 + 13) % 26)) }
      elseif ($c -ge 97 -and $c -le 122) { [char](97 + (($c - 97 + 13) % 26)) }
      else { [char]$c }
    })
    [PSCustomObject]@{Program=$decoded}
  }
} | Where-Object { $_.Program -match '\.exe|powershell|cmd|mshta|rundll32|Temp|AppData' } |
  Sort-Object Program -Unique

# 也可以用专业工具（自动解时间戳与运行次数）
#   UserAssistParser / Registry Explorer

# BAM/DAM：每个用户的"后台活动管理"，记录程序最后执行时间（服务级，无编码）
$sid = (Get-CimInstance Win32_UserAccount -Filter "Name='$env:USERNAME'" -EA SilentlyContinue).SID
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$sid" -EA SilentlyContinue |
  Select-Object * -ExcludeProperty PS*
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*" -EA SilentlyContinue |
  Select-Object PSChildName,*

# SRUM（System Resource Usage Monitor）：应用使用 + 网络流量（含字节数！）
# 数据库位置
Get-Item "$env:SystemRoot\System32\sru\SRUDB.dat" | Select-Object FullName,Length,LastWriteTime
# 解析工具：SrumECmd / SrumDump
#   SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat --csv C:\IR\srum
#   （SRUDB.dat 需配合 SOFTWARE hive 解析应用名）
# 价值：能还原"某进程在某时刻消耗了多少网络流量"，是挖矿/外带的关键佐证

# RecentApps 与 Jump Lists（用户近期访问的对象）
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations" -Force -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 20 Name,LastWriteTime
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations" -Force -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 20 Name,LastWriteTime
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps" -Recurse -EA SilentlyContinue |
  Select-Object -First 20 PSPath
```

### 5.4 最近文件、临时目录与回收站

```powershell
# 最近打开的文件（原手册命令的增强版）
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Force |
  Sort-Object LastWriteTime -Descending | Select-Object -First 30 Name,LastWriteTime,Length

# 用户临时目录（原手册命令）
Get-ChildItem $env:TEMP -File | Sort-Object LastWriteTime -Descending

# 所有用户的临时目录 + 系统临时目录（后门落地主场）
Get-ChildItem "$env:SystemRoot\Temp","$env:ProgramData","$env:PUBLIC" -File -EA SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 40 FullName,Length,LastWriteTime

# 下载目录与浏览器下载记录
Get-ChildItem "$env:USERPROFILE\Downloads" -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 20 Name,Length,LastWriteTime
Get-ChildItem "C:\Users" -Directory | ForEach-Object {
  Get-ChildItem (Join-Path $_.FullName "Downloads") -File -EA SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) } |
    Select-Object @{n='User';e={$_.Directory.Parent.Name}},Name,Length,LastWriteTime
}

# 回收站：$I 元数据（原路径 + 删除时间）+ $R 实际文件
Get-ChildItem "C:\$Recycle.Bin" -Recurse -Force -File -EA SilentlyContinue |
  Where-Object { $_.Name -like '$I*' } |
  Select-Object FullName,CreationTime,Length
# 用工具解析原路径：
#   RBCmd.exe --csv C:\IR\rb -d 'C:\$Recycle.Bin'
# 或用 PowerShell 解析 $I 文件头（前 8 字节是版本，之后是文件大小与删除时间）
# rifiuti2 也是好工具

# 卷影副本（攻击者删快照是勒索前置，保留快照可恢复文件）
vssadmin list shadows
Get-CimInstance Win32_ShadowCopy | Select-Object ID,InstallDate,DeviceObject,Volume
# 快照被删除的痕迹（事件日志）
Get-WinEvent -FilterHashtable @{LogName='System';ID=8222} -MaxEvents 20 -EA SilentlyContinue
```

### 5.5 MFT、USN Journal 与时间戳篡改

```powershell
# MFT：文件系统的"主索引"，含创建/修改/MFT 改动/访问时间（即使文件被删，$MFT 仍有记录）
# 提取 $MFT
#   FTK Imager / MFTECmd / rawcopy
# 解析
#   MFTECmd.exe -f "$MFT" --csv C:\IR\mft --csvf mft.csv
# 从镜像中解析
#   MFTECmd.exe -f "D:\case\C\`$MFT" --csv C:\IR\mft

# USN Journal：记录所有文件系统变更（创建/删除/改名），是"删除痕迹"的最佳来源
# 提取
fsutil usn queryjournal C:\
fsutil usn enumdata 1 0 1 C:\ | Out-File C:\IR\usn.txt   # 前 1000 条
# 解析 $UsnJrnl:$J（用 MFTECmd）
#   MFTECmd.exe -f "D:\case\C\`$Extend\`$UsnJrnl`$\`$J" --csv C:\IR\usn --csvf usn.csv

# 【关键】时间戳篡改检测：$STANDARD_INFORMATION（可被改）与 $FILE_NAME（难以伪造）不一致
# MFTECmd 输出中对比 "Created0x10 / LastModified0x10"(SI) 与
# "Created0x30 / LastModified0x30"(FN)，差值异常（如 FN 比 SI 晚很多）= 篡改
# Sysmon Event 2 直接记录"文件创建时间被修改"

# 用 PowerShell 快速查"创建时间早于写入时间"的异常（粗筛）
Get-ChildItem C:\Windows\Temp,C:\ProgramData -Recurse -File -EA SilentlyContinue |
  Where-Object { $_.CreationTime -gt $_.LastWriteTime } |
  Select-Object FullName,CreationTime,LastWriteTime

# 时间线重建（推荐组合）
#   1) MFTECmd 解 $MFT + $UsnJrnl
#   2) EvtxECmd 解全部事件日志
#   3) PECmd 解 Prefetch、AmcacheParser 解 Amcache、JLECmd 解 JumpList、RBCmd 解回收站
#   4) Timeline Explorer 载入全部 CSV 统一排序过滤（免费，Eric Zimmerman）
#      或 Plaso：log2timeline.py --storage-file case.plaso <image>；psort.py -o l2tcsv
#      或 Timesketch（团队协作、可视化时间线）

# 时间线分析的核心方法：
#   a. 定"失陷起点"：Web 日志第一条异常请求 / 首次恶意进程创建（Sysmon 1 / 4688）
#   b. 拉"攻击者操作链"：按 5 分钟粒度切片，看进程创建 → 网络连接 → 文件落地 → 注册表修改
#   c. 找"清理动作"：日志清除（1102/104）、文件删除（USN）、时间戳篡改（Sysmon 2）
#   d. 交叉验证：同一动作在 3 个独立来源出现 = 可信；只在一个来源出现 = 需要解释
```

### 5.6 PowerShell 与脚本执行痕迹（无文件攻击必查）

```powershell
# PowerShell 操作日志（4104 = ScriptBlock，能还原脚本内容！）
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 -EA SilentlyContinue |
  Where-Object { $_.Id -eq 4104 } |
  Select-Object TimeCreated,@{n='Script';e={$_.Message}} -First 30

# 在所有 4104 里搜可疑关键字（这是抓无文件攻击的杀招）
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Id -eq 4104 } |
  Where-Object { $_.Message -match 'FromBase64String|DownloadString|DownloadFile|IEX|Invoke-Expression|WebClient|Reflection\.Assembly|Add-Type|VirtualAlloc|CreateThread|AMSI|AmsiUtils|Invoke-Mimikatz|Invoke-Shellcode|Net\.Sockets|TCPClient|Set-MpPreference|Add-MpPreference|New-Object IO\.MemoryStream' } |
  Select-Object TimeCreated,Message | Format-List

# 模块日志（4103）
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 200 -EA SilentlyContinue |
  Where-Object { $_.Id -eq 4103 } | Select-Object TimeCreated,Message -First 20

# 引擎状态（400/403/600 = 引擎启动/停止；脚本被阻止）
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 -EA SilentlyContinue |
  Where-Object { $_.Id -in 400,403,600,800 } | Select-Object TimeCreated,Id,Message -First 20

# 转录日志（若开启了 Transcription，所有会话的输入输出都在这里）
Get-ChildItem "$env:USERPROFILE\Documents\PowerShell_transcript*","C:\Transcripts" -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 10 FullName,LastWriteTime,Length
Get-Content "C:\Transcripts\*.txt" -EA SilentlyContinue | Select-String -Pattern 'IEX|DownloadString|Invoke-' -Context 2,5

# 【重要】这些日志是否被关掉（攻击者销毁证据的常见手法）
$psLog = Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational"
$psLog | Select-Object LogName,IsEnabled,MaximumSizeInBytes,FileSize,RecordCount
$sb = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -EA SilentlyContinue
$sb | Select-Object EnableScriptBlockLogging,EnableScriptBlockInvocationLogging
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -EA SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -EA SilentlyContinue
# EnableScriptBlockLogging 缺失或 =0 => 你无法还原脚本内容，属于重大举证缺陷

# 命令行审计是否开启（4688 是否含命令行）
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -EA SilentlyContinue |
  Select-Object ProcessCreationIncludeCmdLine_Enabled
# 也可通过组策略：管理模板 -> 系统 -> 审核进程创建 -> 包含命令行
# 未开启时，4688 只有进程名，没有参数 —— 排查能力大幅下降

# WMI 相关的脚本执行（无文件）
Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" -MaxEvents 100 -EA SilentlyContinue |
  Where-Object { $_.Id -in 5857,5860,5861 } | Select-Object TimeCreated,Message -First 20

# Office 宏执行痕迹
Get-ChildItem "$env:APPDATA\Microsoft\Templates\Normal.dotm" -EA SilentlyContinue
Get-WinEvent -LogName "Microsoft-Office-*" -MaxEvents 50 -EA SilentlyContinue |
  Select-Object TimeCreated,Id,Message -First 20
# 更可靠：看 Sysmon 1 里 winword.exe -> powershell/cmd 的父子关系（见 2.2）

# 计划任务与 AT 命令的执行结果
Get-ScheduledTaskInfo -TaskName * -EA SilentlyContinue | Select-Object TaskName,LastRunTime,LastTaskResult,NextRunTime
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 100 -EA SilentlyContinue |
  Where-Object { $_.Id -in 129,200,201,203 } | Select-Object TimeCreated,Id,Message -First 30
# 200 = 任务动作启动、201 = 完成、203 = 动作失败。能直接看到"谁在什么时候跑了什么"
```

---
## 6. 文件系统与恶意文件排查

### 6.1 时间维度：最近落地的文件

```powershell
# 最近 7 天新增/修改的可执行文件（全盘，耗时较长，建议限定目录）
$ext = '*.exe','*.dll','*.sys','*.ps1','*.bat','*.cmd','*.vbs','*.js','*.jse','*.wsf',
       '*.hta','*.jar','*.scr','*.pif','*.com','*.msi','*.lnk','*.aspx','*.jsp','*.php'
$roots = 'C:\Users','C:\ProgramData','C:\Windows\Temp','C:\Temp','C:\inetpub','C:\Program Files','C:\Program Files (x86)'
Get-ChildItem $roots -Recurse -Include $ext -File -Force -EA SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
  Select-Object FullName,Length,CreationTime,LastWriteTime |
  Sort-Object LastWriteTime -Descending | Format-Table -AutoSize

# 最近 24 小时新增文件（更快、更聚焦）
Get-ChildItem C:\ -Recurse -File -Force -EA SilentlyContinue |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-1) } |
  Select-Object FullName,Length,CreationTime | Sort-Object CreationTime -Descending

# 按"创建时间与修改时间倒挂"筛（常见于时间戳伪造）
Get-ChildItem C:\Windows\Temp,C:\ProgramData,"C:\Users" -Recurse -File -EA SilentlyContinue |
  Where-Object { $_.CreationTime -gt $_.LastWriteTime.AddSeconds(1) } |
  Select-Object FullName,CreationTime,LastWriteTime

# 记录"末次访问"（注意：Windows 默认可能关闭 last access 更新，需确认）
fsutil behavior query disablelastaccess
# 2 = 禁用（默认），0 = 启用。禁用时 LastAccessTime 不可用于取证
# 启用（会带来性能影响，取证环境可临时开）：
# fsutil behavior set disablelastaccess 0
```

### 6.2 位置维度：攻击者偏好目录

| 目录 | 为什么是热点 |
|---|---|
| `C:\Windows\Temp` | 权限宽松，几乎所有用户可写 |
| `C:\Users\<用户>\AppData\Local\Temp` | 用户态可写，常见初始载荷落地 |
| `%APPDATA%` / `%LOCALAPPDATA%` | 用户态可写且不在常规扫描范围 |
| `C:\ProgramData` | 所有用户可写，服务后门常用 |
| `C:\Users\Public` | 权限宽松，共享给所有用户 |
| `C:\Windows\Tasks` / `C:\Windows\System32\Tasks` | 计划任务定义 |
| `C:\$Recycle.Bin` | 删除文件的藏身处 |
| `C:\Windows\System32\spool\drivers` | 打印机驱动后门（PrintNightmare 类） |
| `C:\Windows\System32\com` / `wbem` | COM/WMI 组件替换 |
| `C:\inetpub\wwwroot` | IIS Webshell |
| `C:\Windows\Fonts` | 极少被动，隐蔽落地点 |

```powershell
# 逐个目录扫可疑文件（含隐藏与系统属性）
$hot = 'C:\Windows\Temp','C:\ProgramData','C:\Users\Public','C:\Temp',
       "$env:LOCALAPPDATA\Temp","$env:APPDATA","$env:LOCALAPPDATA",
       'C:\Windows\System32\spool\drivers','C:\Windows\Fonts','C:\Windows\Tasks'
foreach ($d in $hot) {
  if (Test-Path $d) {
    Get-ChildItem $d -Recurse -File -Force -EA SilentlyContinue |
      Where-Object { $_.Extension -in '.exe','.dll','.sys','.ps1','.bat','.vbs','.js','.hta','.scr','.jar','.py' } |
      Select-Object @{n='Dir';e={$d}},FullName,Length,CreationTime,
        @{n='Sign';e={(Get-AuthenticodeSignature $_.FullName -EA SilentlyContinue).Status}}
  }
} | Where-Object { $_.Sign -ne 'Valid' } | Sort-Object CreationTime -Descending | Format-Table -AutoSize

# 隐藏的文件与目录（Attributes 含 Hidden）
Get-ChildItem C:\ -Recurse -Force -EA SilentlyContinue |
  Where-Object { $_.Attributes -match 'Hidden' -and $_.Extension -in '.exe','.dll','.bat','.vbs','.ps1' } |
  Select-Object FullName,Attributes,CreationTime

# 系统目录下的异常文件（不属于任何系统组件）
Get-ChildItem $env:SystemRoot -File -EA SilentlyContinue |
  Where-Object { $_.Extension -in '.exe','.dll' } |
  ForEach-Object {
    $s = Get-AuthenticodeSignature $_.FullName -EA SilentlyContinue
    if ($s.SignerCertificate.Subject -notmatch 'Microsoft') {
      [PSCustomObject]@{File=$_.Name;Time=$_.CreationTime;Signer=$s.SignerCertificate.Subject}
    }
  } | Format-Table -AutoSize
```

### 6.3 备用数据流（ADS）与 Zone.Identifier

**ADS 是 NTFS 特有、Linux 没有的隐藏层**：`file.txt:secret.exe` 在资源管理器里完全不可见。

```powershell
# 列出文件的所有数据流（含隐藏流）
Get-Item <文件路径> -Stream *
# 示例
Get-Item C:\Windows\Temp\test.txt -Stream *

# 目录级全量扫描（PowerShell）
Get-ChildItem <目录> -Recurse -File -Force -EA SilentlyContinue | ForEach-Object {
  $streams = Get-Item $_.FullName -Stream * -EA SilentlyContinue |
    Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
  if ($streams) {
    [PSCustomObject]@{File=$_.FullName; Streams=($streams.Stream -join ','); Size=($streams.Length -join ',')}
  }
}

# CMD 下更直观（/r 显示 ADS）
dir /r C:\Windows\Temp

# Sysinternals streams（支持递归，最快）
# streams64.exe -accepteula -s -h C:\ > C:\IR\ads.txt
# streams64.exe -accepteula -s -h -d C:\Users   # -d 删除所有 ADS（谨慎！会破坏证据）

# 读取 ADS 内容
Get-Content <文件> -Stream <流名>
# 或
Get-Content "C:\Windows\Temp\test.txt:secret.ps1"

# 【重要】Zone.Identifier：标记"文件来自互联网"（Mark of the Web）
# 这是判断"文件是否从网络下载"的直接证据！
Get-Item <文件> -Stream Zone.Identifier -EA SilentlyContinue | Select-Object Stream,Length
Get-Content <文件> -Stream Zone.Identifier -EA SilentlyContinue
# 输出示例：
#   [ZoneTransfer]
#   ZoneId=3              <- 3 = Internet（从网上下载）
#   ReferrerUrl=https://evil.example.com/a.exe
#   HostUrl=https://evil.example.com/a.exe
# ZoneId: 0=本地 1=内网 2=可信 3=Internet 4=受限
# 【注意】攻击者常删除此流来伪装成本地文件 —— 缺失 Zone.Identifier 的下载文件本身也可疑

# 批量找出"从 Internet 下载"的可执行文件（高价值线索）
Get-ChildItem C:\Users,C:\ProgramData,C:\Windows\Temp -Recurse -File -Force -EA SilentlyContinue |
  ForEach-Object {
    $z = Get-Item $_.FullName -Stream Zone.Identifier -EA SilentlyContinue
    if ($z) {
      $c = Get-Content $_.FullName -Stream Zone.Identifier -EA SilentlyContinue
      if ($c -match 'ZoneId=3') {
        [PSCustomObject]@{File=$_.FullName;Time=$_.CreationTime;Referrer=($c | Select-String 'ReferrerUrl').Line}
      }
    }
  } | Format-Table -AutoSize -Wrap
```

### 6.4 文件真实类型与伪装

```powershell
# 用文件头（Magic Number）判断真实类型，而不是看扩展名
function Get-RealType($path) {
  $b = [System.IO.File]::ReadAllBytes($path)[0..7]
  $hex = ($b | ForEach-Object { $_.ToString('X2') }) -join ''
  switch -Regex ($hex) {
    '^4D5A'         { 'PE/EXE/DLL（Windows 可执行）' }
    '^504B0304'     { 'ZIP（含 docx/xlsx/jar/apk）' }
    '^25504446'     { 'PDF' }
    '^7F454C46'     { 'ELF（Linux 可执行）' }
    '^D0CF11E0'     { 'OLE（老式 doc/xls/msi）' }
    '^52617221'     { 'RAR' }
    '^377ABCAF'     { '7-Zip' }
    '^1F8B'         { 'GZIP' }
    '^CDFF'         { 'MS Compound（.doc/.xls 等）' }
    '^3C3F786D6C'   { 'XML' }
    '^3C25'         { '文本/脚本（如 ASP/JSP）' }
    '^2321'         { '脚本（#! shebang）' }
    default         { "未知: $hex" }
  }
}

# 批量找出"扩展名与真实类型不符"的文件（伪装是高频手法）
Get-ChildItem C:\Users,C:\ProgramData,C:\Windows\Temp -Recurse -File -Force -EA SilentlyContinue |
  Where-Object { $_.Extension -in '.jpg','.png','.gif','.txt','.log','.dat','.tmp','.pdf','.doc','.docx','.xls','.css','.js' } |
  ForEach-Object {
    $rt = Get-RealType $_.FullName
    if ($rt -match 'PE/EXE|ELF|ZIP') {
      [PSCustomObject]@{File=$_.FullName;Ext=$_.Extension;RealType=$rt;Size=$_.Length;Time=$_.CreationTime}
    }
  } | Format-Table -AutoSize -Wrap

# 双扩展名（invoice.pdf.exe）
Get-ChildItem C:\ -Recurse -File -Force -EA SilentlyContinue |
  Where-Object { $_.Name -match '\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip)\.(exe|scr|com|pif|bat|cmd|js|vbs)$' } |
  Select-Object FullName,CreationTime

# 使用 file 命令（WSL/Git Bash 环境）
# file suspicious.doc
# 或用 TrID / Detect It Easy 做概率化类型判断（更专业）
# trid.exe -v suspicious.doc
```

### 6.5 哈希、签名、YARA 与情报比对

```powershell
# 计算哈希并与情报比对（VirusTotal / 内部威胁情报库）
$f = "C:\IR\sample.exe"
Get-FileHash $f -Algorithm MD5,SHA1,SHA256,SHA512
Get-FileHash $f -Algorithm SHA256 | Select-Object -ExpandProperty Hash

# Authenticode 签名验证（含证书链与吊销）
Get-AuthenticodeSignature $f | Format-List *
# Status 取值：Valid / NotSigned / HashMismatch / UnknownError / NotTrusted

# 证书是否被吊销（重要：签名有效不代表可信）
# sigcheck -a -h -i -nobanner $f   # -i 显示证书链与吊销状态

# YARA 扫描（自定义规则或开源规则集）
# yara64.exe -r -s -w rules\ C:\Users\Public
# yara64.exe -r rules\index.yar C:\IR\samples\
# 推荐规则集：Neo23x0/signature-base、Yara-Rules/rules、Elastic/protections-artifacts

# 与 Sigma 规则配合的事件层检测见第 7 章

# 快速判断是否是已知恶意软件家族（不联网时的启发式）
#   - 文件熵值高（>7.0）= 加密/压缩（可能加壳）
#   - 导入表极少 = 加壳/手工构造
#   - 节区名非标准（如 UPX0/UPX1、.themida、随机名）
#   - 无版本信息、无图标、时间戳为 0 或未来时间
# 用 Detect It Easy 或 PEStudio 一眼看出
```

### 6.6 Web 目录与 Webshell（IIS / 应用侧）

```powershell
# IIS 站点与物理路径
Import-Module WebAdministration -EA SilentlyContinue
Get-Website | Select-Object Name,State,PhysicalPath,Bindings
Get-WebApplication | Select-Object Path,PhysicalPath
# 或（不依赖模块）
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" list sites
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" list vdirs
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" list apps

# 【关键】IIS 配置被植入后门（模块、处理程序、虚拟目录指向别处）
Get-Content "$env:SystemRoot\System32\inetsrv\config\applicationHost.config" |
  Select-String -Pattern 'physicalPath|modules|handlers|ManagedPipelineHandler'
Get-Content "$env:SystemRoot\System32\inetsrv\config\applicationHost.config" | Select-String -Pattern 'allowSubDirConfig'
# 恶意 IIS 模块（DLL 型后门）
Get-Item "$env:SystemRoot\System32\inetsrv\*.dll" |
  ForEach-Object {
    $s = Get-AuthenticodeSignature $_.FullName -EA SilentlyContinue
    if ($s.SignerCertificate.Subject -notmatch 'Microsoft') {
      [PSCustomObject]@{Dll=$_.Name;Time=$_.LastWriteTime;Signer=$s.SignerCertificate.Subject}
    }
  } | Format-Table -AutoSize

# 全盘搜 Webshell 文件（按扩展名 + 时间）
$webExt = '*.aspx','*.asp','*.ashx','*.asmx','*.asax','*.ascx','*.cshtml','*.jsp','*.jspx','*.php','*.php3','*.php5','*.phtml','*.war'
Get-ChildItem C:\inetpub,C:\wwwroot,D:\wwwroot,D:\inetpub,E:\wwwroot -Recurse -Include $webExt -File -EA SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-60) } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 60 FullName,Length,LastWriteTime

# 【核心方法】用内容特征筛 Webshell（比按时间靠谱得多）
$wshSig = @(
  'eval\(', 'Execute\(', 'ExecuteGlobal', 'CreateObject\("WScript', 'Server\.CreateObject',
  'Request\.(Item|Form|QueryString)\[', 'Request\["', 'System\.Text\.Encoding',
  'FromBase64String', 'Assembly\.Load', 'ProcessStartInfo', 'cmd\.exe', '/c ',
  'Response\.Write', 'RunTime\.GetRuntime', 'Class\.forName', 'getRuntime\(\)\.exec',
  'Runtime\.getRuntime', 'ProcessBuilder', 'cmd\.exe', 'assert\(', 'base64_decode',
  'system\(', 'passthru\(', 'shell_exec', 'popen\(', 'GzipStream', 'DeflateStream'
)
Get-ChildItem C:\inetpub,C:\wwwroot,D:\wwwroot -Recurse -Include $webExt -File -EA SilentlyContinue |
  ForEach-Object {
    $m = Select-String -Path $_.FullName -Pattern $wshSig -EA SilentlyContinue
    if ($m) {
      [PSCustomObject]@{
        File=$_.FullName; Time=$_.LastWriteTime; Size=$_.Length
        Matches=(($m | Select-Object -ExpandProperty Pattern -Unique) -join ',')
        Line=$m[0].LineNumber
      }
    }
  } | Sort-Object Time -Descending | Format-Table -AutoSize -Wrap

# 已知 Webshell 工具特征文件名（需配合人工确认，避免误报）
Get-ChildItem C:\ -Recurse -Include *.aspx,*.jsp,*.php -File -Force -EA SilentlyContinue |
  Where-Object { $_.Name -match 'shell|cmd|exec|upload|bypass|1\.(aspx|jsp|php)|a\.(aspx|jsp|php)|test\.(aspx|jsp|php)|tmp\d*\.[a-z]+' } |
  Select-Object FullName,Length,LastWriteTime

# IIS/W3SVC 日志：Web 攻击的第一现场
Get-ChildItem "C:\inetpub\logs\LogFiles" -Recurse -File -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 10 FullName,Length,LastWriteTime
# 在日志里找攻击特征（SQLi / 上传 / 命令注入）
Get-ChildItem "C:\inetpub\logs\LogFiles\W3SVC*" -Filter *.log -EA SilentlyContinue |
  Select-String -Pattern '(?i)(union\s+select|select\s+.*\s+from|\.\./|\.\.\\|cmd\.exe|/bin/sh|whoami|script>|\.\.%2f|%00|\.aspx|\.jsp|\.php|upload|eval|base64)' |
  Select-Object -First 100 Path,LineNumber,Line
# 用 Log Parser / LogParser Studio 或 Excel 做聚合更高效
# 也推荐 PowerShell: 按 c-ip 聚合高频请求（找扫描器/暴破）
Get-Content "C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log" -EA SilentlyContinue |
  Where-Object { $_ -notmatch '^#' } |
  ForEach-Object { ($_ -split ' ')[8] } |
  Group-Object | Sort-Object Count -Descending | Select-Object -First 20 Count,Name
```

### 6.7 勒索与挖矿专项

```powershell
# === 勒索软件 ===
# 1) 加密文件扩展名特征（批量出现的高熵新扩展名）
Get-ChildItem C:\ -Recurse -File -EA SilentlyContinue |
  Group-Object Extension | Sort-Object Count -Descending | Select-Object -First 40 Count,Name
# 典型：.lockbit .conti .revil .ryuk .phobos .makop .basta .blackcat .hive .akira .mallox .devos
# 或随机 6-10 位扩展名

# 2) 勒索信（常见文件名）
Get-ChildItem C:\ -Recurse -File -EA SilentlyContinue |
  Where-Object { $_.Name -match '(?i)readme|how_to_decrypt|decrypt_instruction|restore_files|RECOVER|_readme\.txt|!!!|HELP_DECRYPT|#Decrypt#' } |
  Select-Object FullName,Length,CreationTime | Sort-Object CreationTime

# 3) 勒索前置动作（必查这些事件）
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 1000 -EA SilentlyContinue |
  Where-Object { $_.Message -match 'vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled|cipher /w|wevtutil cl|wmic shadowcopy delete|diskshadow' } |
  Select-Object TimeCreated,Message
# 相关事件日志
Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='VSS'} -MaxEvents 30 -EA SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='System';ID=8222} -MaxEvents 20 -EA SilentlyContinue  # VSS 快照删除

# 4) 备份是否还完好（决定能否恢复）
vssadmin list shadows
vssadmin list shadowstorage
Get-CimInstance Win32_ShadowCopy | Measure-Object
wbadmin get versions
Get-WindowsBackupStatus -EA SilentlyContinue

# 5) 恢复被删的卷影（若只是被 vssadmin 删除，有时可重建）
#    更可靠：从备份恢复；或从磁盘镜像用 PhotoRec/R-Studio 恢复加密前文件（成功率取决于覆写）

# 6) 勒索软件自身样本（优先保存，用于家族识别与解密工具匹配）
Get-ChildItem C:\Users,C:\ProgramData,C:\Windows\Temp -Recurse -Include *.exe -File -Force -EA SilentlyContinue |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-2) } |
  Select-Object FullName,Length,CreationTime
# 家族识别：ID Ransomware (id-ransomware.malwarehunterteam.com) / NoMoreRansom.org

# === 挖矿 ===
# 1) 高 CPU 进程
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,Id,CPU,WS,Path
# 采样 10 秒更准
1..2 | ForEach-Object { Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,Id,CPU; Start-Sleep 5 }

# 2) 挖矿特征字符串与命令行
Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -match 'stratum|--donate-level|xmrig|minerd|cpuminer|--coin|--url|pool\.|nanopool|minexmr|supportxmr|--background|--cpu-priority'
} | Select-Object ProcessId,Name,CommandLine

# 3) 落地文件与配置
Get-ChildItem C:\ -Recurse -File -Force -EA SilentlyContinue |
  Where-Object { $_.Name -match '(?i)xmrig|miner|cpuminer|config\.json|pool\.txt|start\.(bat|sh|ps1|vbs)' } |
  Select-Object FullName,Length,CreationTime
# 挖矿钱包地址（在脚本/配置里搜）
Get-ChildItem C:\ProgramData,C:\Users -Recurse -Include *.json,*.txt,*.bat,*.ps1,*.vbs,*.ini -File -Force -EA SilentlyContinue |
  Select-String -Pattern '(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})' |
  Select-Object Path,LineNumber,Line -First 30

# 4) 挖矿常配合的持久化：计划任务 + WMI + 服务（回到第 3 章核对）

# 5) 网络特征：连接矿池端口
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemotePort -in 3333,4444,5555,7777,8080,8888,9999,14444,45560,45700 } |
  Select-Object RemoteAddress,RemotePort,OwningProcess

# 6) Defender 是否被关（挖矿木马常先关杀软）
Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled,
  BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,AntispywareEnabled
Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,
  DisableIOAVProtection,DisableScriptScanning,ExclusionPath,ExclusionProcess,ExclusionExtension
```

### 6.8 数据外带痕迹

```powershell
# 1) 压缩打包工具（外带前置）
Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -match 'rar\.exe a|7z\.exe a|winrar|makecab|compress-archive|tar\.exe|zip\.exe'
} | Select-Object ProcessId,Name,CommandLine

# 2) 云同步/网盘工具（rclone、OneDrive、Google Drive 被滥用）
Get-Process | Where-Object { $_.Name -match 'rclone|megasync|dropbox|onedrive|googledrive|pcloud|nutstore' } |
  Select-Object Name,Id,Path
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'rclone|--transfers|copy .* :' } |
  Select-Object ProcessId,CommandLine

# 3) 上传行为的网络痕迹（大流量上行）
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemotePort -in 21,22,443,80,8080,8443 } |
  Select-Object RemoteAddress,RemotePort,OwningProcess,
    @{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}}

# 4) 命令行的外发证据
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 2000 -EA SilentlyContinue |
  Where-Object { $_.Message -match 'curl .*-F|Invoke-WebRequest.*-Method Post|Invoke-RestMethod|ftp -s:|tftp |bitsadmin /transfer|Invoke-Sqlcmd.*xp_cmdshell' } |
  Select-Object TimeCreated,Message

# 5) DNS 外带（大量异常 DNS 查询）
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -EA SilentlyContinue |
  Where-Object { $_.Id -eq 22 } |
  Group-Object { ($_.Message -split "QueryName: ")[1] -split "`n" | Select-Object -First 1 } |
  Sort-Object Count -Descending | Select-Object Count,Name -First 20

# 6) SRUM（见 5.3）能给出精确的"哪个进程发了多少字节"

# 7) 邮件外发（Outlook 痕迹、SMTP 连接）
Get-NetTCPConnection -State Established | Where-Object { $_.RemotePort -in 25,465,587,110,143,993,995 } |
  Select-Object RemoteAddress,RemotePort,OwningProcess
```

### 6.9 文件与数据恢复

```powershell
# 1) 卷影副本挂载（可直接访问历史版本文件）
vssadmin list shadows
# 挂载为符号链接（示例）
# mklink /d C:\vs C:\@GMT-2026.09.18-01.00.00  （或使用 ShadowExplorer / vssadmin 输出中的 device path）

# 2) 从卷影复制文件
Get-CimInstance Win32_ShadowCopy | ForEach-Object {
  # DeviceObject 形如 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
  "快照: $($_.DeviceObject)  时间: $($_.InstallDate)"
}

# 3) 被彻底删除的文件恢复（需停写磁盘）
#   PhotoRec / TestDisk      —— 免费，按文件头恢复
#   R-Studio / GetDataBack   —— 商业，NTFS 恢复能力强
#   Recuva                   —— 轻量恢复
#   FTK Imager               —— 取证镜像与挂载
#   重要：恢复前不要往目标磁盘写任何东西；优先对镜像操作

# 4) 从 $MFT / $UsnJrnl 恢复"存在过的证据"（即使文件内容已不可恢复）
#   见 5.5，MFTECmd 解析后可列出被删除文件的原路径与删除时间

# 5) 回收站内容解析
#   RBCmd.exe --csv C:\IR\rb -d "C:\$Recycle.Bin"
```

### 6.10 完整性监控与长期运营

```powershell
# 1) Sysmon（Windows 上最重要的免费检测能力，见工具链文档）
Get-Service Sysmon,Sysmon64 -EA SilentlyContinue | Select-Object Name,Status,StartType
Get-Process sysmon,Sysmon64 -EA SilentlyContinue | Select-Object Id,Name,Path,StartTime
# 配置是否被篡改（换配置会改变检测能力）
# sysmon64.exe -c
# sysmon64.exe -c current-config.xml

# 2) Windows Defender：受控文件夹访问 + ASR 规则（阻止勒索）
Get-MpPreference | Select-Object EnableControlledFolderAccess,AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions
# 检查关键 ASR 规则是否被关闭（尤其勒索相关）
$asr = Get-MpPreference
$asr.AttackSurfaceReductionRules_Ids -join ',' ; $asr.AttackSurfaceReductionRules_Actions -join ','
# 推荐启用的规则（GUID -> 说明）：
#   D4F940AB-401B-4EFC-AADC-AD5F3C50688A  阻止 Office 子进程创建可执行内容
#   3B576869-A4EC-4529-8536-B80A7769E899  阻止 Office 创建可执行内容
#   75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84  阻止 Office 注入其他进程
#   26190899-1602-49E8-8B27-EB1D0A1CE869  阻止 Office 通信程序创建子进程
#   7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C  阻止 Adobe Reader 创建子进程
#   D3E037E1-3EB8-44C8-A917-57927947596D  阻止 JS/VBS 下载可执行内容
#   5BEB7EFE-FD9A-4556-801D-275E5FFC04CC  阻止执行可能混淆的脚本
#   BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550  阻止执行可执行文件（除非满足流行度/年龄/受信任条件）
#   9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2  阻止从 WMI 事件订阅创建进程（**直接防 3.4 的 WMI 后门**）
#   56A863A9-875E-4185-98A7-B882C64B5CE5  阻止滥用易受攻击的签名驱动（BYOVD）
#   C1DB55AB-C21A-4637-BB3F-A12568109D35  阻止勒索软件行为（需审计模式先行）
#   01443614-CD74-433A-B99E-2ECDC07BFC25  阻止来源不受信任的可执行文件运行

# 3) 文件完整性监控方案
#   - Windows Server FSRM（文件服务器资源管理器）：文件组 + 筛选器 + 勒索文件阻断
#   - AIDE 对应物：Tripwire / OSSEC / Wazuh（Windows Agent）
#   - 微软自带：Get-FileHash 定时基线比对（小范围）
#   - 企业级：CrowdStrike / Defender for Endpoint / Elastic Defend / Velociraptor

# 4) 建立基线（首次干净快照，供后续比对）
$baseline = 'C:\Windows\System32','C:\Program Files'
Get-ChildItem $baseline -Recurse -File -EA SilentlyContinue |
  Where-Object { $_.Extension -in '.exe','.dll','.sys' } |
  Select-Object FullName,Length,LastWriteTime,@{n='SHA256';e={(Get-FileHash $_.FullName -Algorithm SHA256).Hash}} |
  Export-Csv C:\IR\baseline.csv -NoTypeInformation -Encoding UTF8

# 5) 关键注册表与配置的定期导出（便于差分）
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" C:\IR\run.reg /y
reg export "HKLM\SYSTEM\CurrentControlSet\Services" C:\IR\services.reg /y

# 6) 现代平台（若已有，直接用它们的检索能力，速度远超手工）
#   Microsoft Defender for Endpoint: Advanced Hunting (KQL) 查询
#   Velociraptor: VQL 查询所有端点
#   Elastic / Splunk / Sentinel: 统一检索
```

---

## 7. 事件日志审计

### 7.1 日志清单与基础检索

```powershell
# 读取最近事件（原手册命令）
Get-WinEvent -LogName Security -MaxEvents 30 | Select-Object TimeCreated,Id,Message
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 20

# 列出所有日志及其状态（哪些被禁用、哪些被清空）
Get-WinEvent -ListLog * -EA SilentlyContinue |
  Select-Object LogName,IsEnabled,RecordCount,FileSize,MaximumSizeInBytes,LogMode |
  Sort-Object RecordCount -Descending | Format-Table -AutoSize
# 重点：关键日志 IsEnabled=False 或 RecordCount=0 => 被动了手脚

# 只看有内容的日志（快速定位证据来源）
Get-WinEvent -ListLog * -EA SilentlyContinue |
  Where-Object { $_.RecordCount -gt 0 } |
  Select-Object LogName,RecordCount,FileSize | Sort-Object RecordCount -Descending
# 默认上限 1000 条，如需全量：
# Get-WinEvent -ListLog * | Select-Object LogName,RecordCount

# 事件日志文件位置（可离线拷贝分析）
Get-ChildItem "$env:SystemRoot\System32\winevt\Logs" |
  Sort-Object LastWriteTime -Descending | Select-Object Name,Length,LastWriteTime
# 关键文件：Security.evtx, System.evtx, Application.evtx,
#          Microsoft-Windows-PowerShell%4Operational.evtx,
#          Microsoft-Windows-Sysmon%4Operational.evtx,
#          Microsoft-Windows-TaskScheduler%4Operational.evtx,
#          Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx

# 日志配置（大小不足以留存事件 = 重大缺陷）
wevtutil gl Security
wevtutil gl System
Get-WinEvent -ListLog Security | Select-Object MaximumSizeInBytes,LogMode
# 建议：Security >= 512MB，LogMode=AutoBackup，并外发到 SIEM

# 命令行检索（等价 Get-WinEvent，适合远程）
wevtutil qe Security /c:50 /rd:true /f:text
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:20 /f:text

# 导出日志备查
wevtutil epl Security C:\IR\Security.evtx
Get-WinEvent -LogName Security | Export-Clixml C:\IR\security.xml
```

### 7.2 日志被清除与篡改的痕迹

```powershell
# 【1】审计日志被清除（1102）—— 最高优先级告警
Get-WinEvent -FilterHashtable @{LogName='Security';ID=1102} -MaxEvents 20
# 1102 里有"执行清除的用户名与域"，能直接定位是谁清空的

# 【2】System 日志被清除（104）
Get-WinEvent -FilterHashtable @{LogName='System';ID=104} -MaxEvents 20

# 【3】其他日志通道的清除记录
Get-WinEvent -LogName "Microsoft-Windows-Eventlog/Operational" -MaxEvents 200 -EA SilentlyContinue |
  Where-Object { $_.Id -in 104,1102,1100,1101 } | Select-Object TimeCreated,Id,Message

# 【4】命令行清除动作（即使日志被清，若已转发到 SIEM 仍可查）
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 3000 -EA SilentlyContinue |
  Where-Object { $_.Message -match 'wevtutil cl|Clear-EventLog|Remove-EventLog|auditpol /clear' }

# 【5】日志文件本身被删（文件系统层痕迹）
Get-ChildItem "$env:SystemRoot\System32\winevt\Logs" |
  Sort-Object LastWriteTime | Select-Object Name,Length,CreationTime,LastWriteTime
# 现象：文件大小为 0、CreationTime 很新但系统已运行很久、RecordCount 突然很小

# 【6】EventRecordID 跳号（说明事件被选择性删除/插入）
$ids = (Get-WinEvent -LogName Security -MaxEvents 2000 |
        Sort-Object RecordId | Select-Object -ExpandProperty RecordId)
for ($i=1; $i -lt $ids.Count; $i++) {
  $gap = $ids[$i] - $ids[$i-1]
  if ($gap -gt 1) { "RecordId 缺口: $($ids[$i-1]) -> $($ids[$i])  跳过 $($gap-1) 条" }
}
# 说明：正常日志会因滚动覆盖产生缺口，需结合时间判断；短时间大量缺口 = 可疑

# 【7】审计策略被关闭（4719）
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4719} -MaxEvents 20 |
  Select-Object TimeCreated,Message
auditpol /get /category:*
# 关键子类别应为"成功和失败"：
#   登录/注销、账户管理、策略更改、特权使用、对象访问、进程跟踪

# 【8】Sysmon 被卸载或停止（攻击者常先干掉它）
Get-Service Sysmon,Sysmon64 -EA SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=4,16} -MaxEvents 20 -EA SilentlyContinue
# 4 = Sysmon 服务状态改变（含被卸载）；16 = Sysmon 配置变更

# 【9】Defender 被关闭/排除项被添加
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 200 -EA SilentlyContinue |
  Where-Object { $_.Id -in 5001,5007,5004,5010,5012 } | Select-Object TimeCreated,Id,Message
# 5001 = 实时保护被关闭；5007 = 配置被更改（含添加排除项）
# 1116/1117 = 检测到威胁与处置结果
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 300 -EA SilentlyContinue |
  Where-Object { $_.Id -in 1116,1117,1015,1006,1007 } | Select-Object TimeCreated,Id,Message -First 40

# 【10】时间被改动（影响整个时间线可信度）
Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-General';ID=1} -MaxEvents 20
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4616} -MaxEvents 20   # 系统时间被修改
```

### 7.3 日志转发与可信性（决定能否依赖本机日志）

```powershell
# Windows Event Forwarding（WEF）：判断本机日志是否已外发（外发后本机被清也无所谓）
wecutil gs <SubscriptionName> -EA SilentlyContinue
Get-Service Wecsvc | Select-Object Name,Status,StartType
Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding" -Recurse -EA SilentlyContinue
# 配置位置
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" -EA SilentlyContinue

# 第三方 Agent（EDR / SIEM 采集器）
Get-Service | Where-Object { $_.DisplayName -match 'Splunk|Elastic|CrowdStrike|SentinelOne|Carbon Black|Qualys|Wazuh|NXLog|Filebeat|Winlogbeat|osquery|Carbon' } |
  Select-Object Name,DisplayName,Status,StartType
Get-Process | Where-Object { $_.Name -match 'splunk|winlogbeat|filebeat|nxlog|osquery|sentineld|csagent' } |
  Select-Object Name,Id,Path,StartTime

# Defender for Endpoint 上载状态
Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated

# 【结论性判断】
# 若本机日志被清 + 无外发 + 无 EDR => 本机日志不可作为唯一证据，
# 必须转向：内存镜像、MFT/USN、Prefetch/Amcache、相邻主机与网络设备日志
```

### 7.4 用现代工具批量分析（强烈推荐）

手工 `Get-WinEvent` 适合精准查询，**不适合海量筛查**。当你有整个 `winevt\Logs` 目录或上百台主机的日志时，用下列工具：

```powershell
# === Chainsaw（WithSecure，Rust）—— Sigma 规则驱动的事件日志猎杀 ===
# 先建立 Sigma 规则索引（首次使用）
# chainsaw sigma index --rules sigma/rules --output rules/index
# 快速时间线
# chainsaw hunt C:\IR\evtx --mapping mappings/sigma-event-logs-all.yml -s sigma/rules --csv --output C:\IR\chainsaw
# 应用 Sigma 规则
# chainsaw hunt C:\IR\evtx -s sigma/rules --sigma "mappings/sigma-event-logs-all.yml" --output C:\IR\chainsaw
# 导出全部事件为 JSON 供进一步分析
# chainsaw dump C:\IR\evtx --output C:\IR\dump.json

# === Hayabusa（Yamato Security，Rust）—— Windows 事件日志时间线 + 检测 ===
# 生成时间线（默认使用内置 Sigma 规则）
# hayabusa.exe csv-timeline -d C:\IR\evtx -o C:\IR\timeline.csv
# 只看高危
# hayabusa.exe csv-timeline -d C:\IR\evtx -m high -o C:\IR\high.csv
# 登录摘要（谁从哪登录）
# hayabusa.exe logon-summary -d C:\IR\evtx
# 事件 ID 统计（快速定位异常通道）
# hayabusa.exe eid-metrics -d C:\IR\evtx
# 扫描单个文件
# hayabusa.exe csv-timeline -f C:\IR\Security.evtx -o C:\IR\sec.csv

# === EvtxECmd（Eric Zimmerman）—— evtx 转 CSV，喂给时间线工具 ===
# EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv C:\IR\evtx --csvf all.csv
# 单文件
# EvtxECmd.exe -f C:\IR\Security.evtx --csv C:\IR\evtx --csvf security.csv

# === Zircolite（Sigma 规则 + SQLite，适合超大数据集）===
# zircolite.py --evtx C:\IR\evtx --ruleset rules/rules_windows_generic.json --outdir C:\IR\zircolite

# === DeepBlueCLI（PowerShell，零依赖，适合应急现场）===
# .\DeepBlue.ps1 C:\IR\Security.evtx
# .\DeepBlue.ps1 -log C:\IR\System.evtx

# === APT-Hunter（Python，针对 APT 场景的事件日志分析）===
# python APT-Hunter.py -evtx C:\IR\evtx -o C:\IR\apt
```

**这些工具的价值**：把 Sigma 社区数千条检测规则应用到你的日志上，等价于请了几百个分析师同时看日志。**在没有任何 EDR 的环境里，这是性价比最高的检测手段。**

### 7.5 关键事件 ID 速查（排查时的抓手）

| 事件 ID | 通道 | 含义 | 排查价值 |
|---|---|---|---|
| 4624 | Security | 登录成功 | 谁、从哪、用什么方式 |
| 4625 | Security | 登录失败 | 暴破、密码喷洒 |
| 4634 / 4647 | Security | 注销 | 会话结束 |
| 4648 | Security | 显式凭据登录 | **横向移动直接证据** |
| 4672 | Security | 分配特殊权限 | 管理员活动 |
| 4688 | Security | 进程创建 | **需开启命令行审计** |
| 4689 | Security | 进程退出 | 短命进程 |
| 4697 | Security | 服务安装 | **服务后门** |
| 4698 / 4699 / 4700 / 4701 / 4702 | Security | 计划任务创建/删除/启用/禁用/修改 | **任务后门** |
| 4719 | Security | 审计策略变更 | 关审计 |
| 4720 / 4722 / 4723 / 4724 / 4726 | Security | 账号创建/启用/改密/重置/删除 | 账号后门 |
| 4728 / 4732 / 4756 | Security | 加入特权组 | 提权 |
| 4738 | Security | 账号属性变更 | 改描述/改脚本 |
| 4740 | Security | 账号锁定 | 暴破后果 |
| 4768 / 4769 / 4771 | Security | Kerberos TGT/TGS/预认证失败 | Kerberoasting、黄金票据 |
| 4776 | Security | NTLM 认证 | 哈希传递 |
| 1102 | Security | **审计日志被清除** | 反取证 |
| 104 | System | 日志被清除 | 反取证 |
| 4616 | Security | 系统时间被修改 | 时间线污染 |
| 7045 | System | **新服务安装** | 服务后门 |
| 7034 / 7036 | System | 服务崩溃/状态变化 | 服务异常 |
| 8222 | System | VSS 快照删除 | 勒索前置 |
| 4688 | Security | 进程创建 | 见上 |
| 4103 / 4104 | PowerShell/Operational | 模块日志 / **脚本块日志** | **还原无文件脚本** |
| 400 / 403 / 600 | PowerShell/Operational | 引擎启动/停止 | 会话边界 |
| 1116 / 1117 | Defender | 检测到威胁/已处置 | 杀软命中 |
| 5001 / 5007 | Defender | 实时保护被关闭 / 配置被改 | **杀软被关** |
| 5857 / 5858 / 5859 / 5860 / 5861 | WMI-Activity/Operational | WMI 提供程序加载与操作 | **WMI 后门** |
| 21 / 22 / 23 / 24 / 25 | TerminalServices-LocalSessionManager | RDP 会话事件 | 远程登录 |
| 1149 | TerminalServices-RemoteConnectionManager | **RDP 认证成功（含源 IP）** | 远程登录 |
| 200 / 201 / 203 | TaskScheduler/Operational | 任务动作启动/完成/失败 | 任务执行 |
| 5156 / 5157 | Security | 网络连接允许/阻止（需开启筛选平台审计） | 网络行为 |
| 5140 / 5145 | Security | 网络共享访问 | 横向取数据 |
| 1 / 3 / 7 / 8 / 10 / 11 / 12-14 / 15 / 17-22 / 25 | Sysmon/Operational | 见 2.5 的 Sysmon 表 | **最高价值** |

---
## 8. 应用与中间件专项

> 企业环境里，**主机被攻破的入口 90% 在应用层**（Web 漏洞、中间件弱口令、任务调度平台）。
> 主机排查跑完后，如果没查应用层，等于没找到"人是怎么进来的"。

### 8.1 XXL-JOB（分布式任务调度平台，高价值驻留点）

XXL-JOB 的 **GLUE 模式**本质是"可控的任务调度器 + 脚本执行器"，一旦被攻破，攻击者可以：
新增一个"定时任务"，脚本内容写反弹 Shell 或持久化命令，**执行记录看起来像正常业务调度**。

**Windows 侧排查要点**

```powershell
# 1) 进程与部署位置（确认实例、jar 路径、启动参数、日志目录）
Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'java.exe' -and $_.CommandLine -match 'xxl-job' } |
  Select-Object ProcessId,CommandLine | Format-List

# 从命令行提取关键参数：--xxl.job.admin.addresses / --xxl.job.executor.appname
#                        --xxl.job.executor.logpath / --spring.datasource.url
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'xxl' } |
  ForEach-Object {
    $cmd = $_.CommandLine
    [PSCustomObject]@{
      PID = $_.ProcessId
      AdminAddr = ([regex]::Match($cmd,'--xxl\.job\.admin\.addresses=(\S+)')).Groups[1].Value
      Executor  = ([regex]::Match($cmd,'--xxl\.job\.executor\.appname=(\S+)')).Groups[1].Value
      LogPath   = ([regex]::Match($cmd,'--xxl\.job\.executor\.logpath=(\S+)')).Groups[1].Value
      Jar       = ([regex]::Match($cmd,'-jar\s+(\S+)')).Groups[1].Value
    }
  }

# 2) 【核心】查数据库中的任务定义（调度中心库：xxl_job）
#    GLUE 模式任务的脚本内容就存在 xxl_job_info.glue_source
#    正常业务任务多用 BEAN 模式（glue_type 为空/NULL），GLUE 模式需要重点核对
# 用 sqlcmd 直查（把 <DBHOST>/<DB>/<USER>/<PWD> 换成实际值）
$sql = @"
SELECT id, job_desc, job_group, executor_handler, glue_type,
       CAST(glue_source AS NVARCHAR(MAX)) AS glue_source,
       schedule_conf, add_time, update_time, trigger_last_time, trigger_status
FROM xxl_job_info
ORDER BY update_time DESC;
"@
# sqlcmd -S <DBHOST> -d <DB> -U <USER> -P <PWD> -Q "$sql" -o C:\IR\xxl_job_info.txt -W -s "|"

# 3) 执行记录（哪些任务最近真的跑过、结果如何）
# SELECT * FROM xxl_job_log ORDER BY trigger_time DESC LIMIT 200;
# SELECT * FROM xxl_job_log_report;

# 4) 脚本型任务（php/python/shell/nodejs）的执行器在 Windows 上如何落地
#    Windows 执行器通常调用 cmd/powershell 或对应解释器；在 Sysmon/4688 里看进程链
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 2000 -EA SilentlyContinue |
  Where-Object { $_.Message -match 'xxl-job|glue|executor' } | Select-Object TimeCreated,Message -First 30

# 5) 执行器日志目录（记录每个任务的调度与输出）
Get-ChildItem "C:\" -Directory -Recurse -Depth 3 -EA SilentlyContinue |
  Where-Object { $_.Name -match 'xxl-job' -or $_.FullName -match 'xxl-job\\log' } |
  Select-Object FullName
# 典型结构：xxl-job/jobhandler/gluesource/<jobId>.glue        <- 脚本实体，必看
#          xxl-job/jobhandler/gluesource/<jobId>-<时间戳>.glue
#          xxl-job/jobhandler/<日期>/<jobId>.log
Get-ChildItem <EXECUTOR_LOG_PATH> -Recurse -File -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 40 FullName,Length,LastWriteTime
Get-Content <EXECUTOR_LOG_PATH>\gluesource\*.glue -EA SilentlyContinue

# 6) 调度中心（admin）侧的 Web 访问日志：找"新增/修改任务"的异常操作来源
#    Tomcat: <admin_deploy>\logs\localhost_access_log.*.txt
#    在日志里搜 /jobinfo/add、/jobinfo/update、/jobcode/save
Get-ChildItem <ADMIN_DEPLOY>\logs -Filter "*.txt" -EA SilentlyContinue |
  Select-String -Pattern 'jobinfo/(add|update)|jobcode/save|joblog/query' |
  Select-Object -First 60 Path,LineNumber,Line

# 7) 调度中心自身被拿下的痕迹（xxl-job-admin 历史漏洞：默认口令、未授权、反序列化）
#    数据库连接串与账号密码（配置文件里）
Get-ChildItem <ADMIN_DEPLOY> -Recurse -Include application.properties,application.yml,*.yml -EA SilentlyContinue |
  Select-String -Pattern 'spring.datasource|username|password|xxl.job.accessToken'
#    默认口令 admin/123456 是否还在用 —— 从数据库 auth 用户表核查
#    accessToken 为空 = 执行器可被任意调用（严重）
```

**XXL-JOB 排查清单（结论用）**

- [ ] `xxl_job_info` 中 `glue_type` 非空（GLUE 模式）的任务条目，逐个核对业务归属
- [ ] `glue_source` 内容里有网络请求、编码字符串、反弹 Shell、下载行为 → 定性为后门
- [ ] 任务 `update_time` 落在失陷窗口内
- [ ] 执行器 `gluesource` 目录下的 `.glue` 文件新建/修改时间
- [ ] `job_desc` 填写得"很像业务"（如 `data_sync_task`）但内容是恶意的（T1036）
- [ ] 调度中心 `accessToken` 是否为空、默认口令是否修改
- [ ] 任务被触发后的进程链（cmd/powershell/curl）出现在 4688 / Sysmon 1 中

**同类平台（排查思路完全一致：它们都是"可控执行器"）**

| 平台 | 排查落点 |
|---|---|
| Jenkins | `JENKINS_HOME\jobs\*\config.xml`、`C:\Program Files (x86)\Jenkins\`、脚本化流水线（Groovy）、凭据 `credentials.xml` |
| GitLab Runner | `config.toml`、`builds\` 目录、`gitlab-runner.exe` 命令行 |
| Apache Airflow | `dags\*.py`、`airflow.cfg`、`airflow.db` |
| Nacos | `nacos_config` 表 `content` 字段（配置型后门）、`derby-data\` |
| Tomcat | `webapps\` 下的 war、`conf\server.xml`、`conf\tomcat-users.xml`（manager 弱口令）、`work\` 编译产物 |
| Zookeeper / Kafka / RocketMQ | `bin\windows\*.bat` 是否被改、`config\` 被改、启动脚本追加命令 |
| Spring Boot 应用 | `application.properties/yml` 被改、`BOOT-INF\classes` 被替换、`lib\` 里新增 jar |
| Redis / MySQL / MSSQL | 服务配置与 `my.ini`、`postgresql.conf`，暴露端口与弱口令 |

```powershell
# 通用：中间件配置被改动的排查（按时间筛）
Get-ChildItem "C:\Program Files","C:\Program Files (x86)","C:\ProgramData","D:\" -Recurse -Include *.xml,*.yml,*.yaml,*.properties,*.conf,*.ini,*.json,*.toml -File -EA SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) } |
  Select-Object FullName,Length,LastWriteTime | Sort-Object LastWriteTime -Descending

# 通用的"中间件被当作执行器"的进程链检测
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 3000 -EA SilentlyContinue |
  Where-Object { $_.Message -match '\\w3wp\.exe|\\java\.exe|\\sqlservr\.exe|\\node\.exe|\\python\.exe' -and
                          $_.Message -match 'cmd\.exe|powershell|pwsh|whoami|net\.exe|net1\.exe|certutil|curl' } |
  Select-Object TimeCreated,Message -First 40
```

### 8.2 IIS / ASP.NET 专项

```powershell
# 进程侧：w3wp 的命令行与工作进程
Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'" | Select-Object ProcessId,CommandLine
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" list wp    # 工作进程与应用程序池对应

# 应用池身份被改（提权到高权限账户）
Import-Module WebAdministration -EA SilentlyContinue
Get-ChildItem IIS:\AppPools | ForEach-Object {
  [PSCustomObject]@{Pool=$_.Name;Identity=(Get-ItemProperty "$($_.PSPath)\processModel").identityType;
                    User=(Get-ItemProperty "$($_.PSPath)\processModel").userName}
}

# 站点/虚拟目录被新增（指向攻击者目录）、URL 重写规则被植入
Get-Content "$env:SystemRoot\System32\inetsrv\config\applicationHost.config" |
  Select-String -Pattern 'rewrite|rules|physicalPath' -Context 1,3

# ASP.NET 机器密钥泄露（可伪造 ViewState/身份票据）
Get-Content "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" -EA SilentlyContinue |
  Select-String -Pattern 'machineKey|validationKey|decryptionKey'
# 检查 web.config 是否被植入 httpModules / httpHandlers
Get-ChildItem C:\inetpub -Recurse -Include web.config -EA SilentlyContinue |
  Select-String -Pattern 'httpModules|httpHandlers|modules runAllManagedModulesForAllRequests|assembly=' |
  Select-Object Path,LineNumber,Line

# IIS 日志里找攻击者 IP 与请求模式
Get-ChildItem "C:\inetpub\logs\LogFiles\W3SVC*" -Filter *.log -EA SilentlyContinue |
  Get-Content | Where-Object { $_ -notmatch '^#' } |
  ForEach-Object {
    $p = $_ -split ' '
    [PSCustomObject]@{IP=$p[8];Method=$p[3];Uri=$p[4];Status=$p[11];UA=$p[9]}
  } | Where-Object { $_.Status -in 200,500 -and $_.Uri -match '\.(aspx|ashx|asmx|asp)' } |
  Group-Object IP | Sort-Object Count -Descending | Select-Object -First 20 Count,Name
```

### 8.3 SQL Server 专项

```sql
-- 1) 危险配置是否被打开
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell';                     -- 应为 0
EXEC sp_configure 'Ole Automation Procedures';       -- 应为 0
EXEC sp_configure 'clr enabled';                     -- 按业务定，需留意
EXEC sp_configure 'Ad Hoc Distributed Queries';
SELECT name, value_in_use FROM sys.configurations ORDER BY name;

-- 2) 自动执行存储过程（持久化后门，每次实例启动即执行）
SELECT name, is_auto_executed
FROM sys.procedures WHERE is_auto_executed = 1;
-- 或
EXEC sp_procoption @ProcName = N'<过程名>', @OptionName = 'startup', @OptionValue = 'off';

-- 3) 扩展存储过程（可调用系统命令）
EXEC sp_helpextendedproc;

-- 4) SQL Agent 作业（最常用的"定时后门"）
SELECT j.name, j.enabled, j.date_created, j.date_modified,
       s.step_id, s.subsystem, s.command, s.database_name
FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobsteps s ON j.job_id = s.job_id
ORDER BY j.date_modified DESC;

-- 5) 存储过程/触发器里含命令执行关键字的
SELECT OBJECT_NAME(m.object_id) AS obj, m.definition
FROM sys.sql_modules m
WHERE m.definition LIKE '%xp_cmdshell%' OR m.definition LIKE '%sp_OACreate%'
   OR m.definition LIKE '%powershell%'  OR m.definition LIKE '%cmd.exe%'
   OR m.definition LIKE '%certutil%'    OR m.definition LIKE '%bitsadmin%';

-- 6) CLR 程序集（可执行任意 .NET 代码）
SELECT name, permission_set_desc, create_date, modify_date FROM sys.assemblies WHERE is_user_defined = 1;
SELECT * FROM sys.assembly_files;

-- 7) 服务器触发器与链接服务器
SELECT name, is_disabled FROM sys.server_triggers;
SELECT name, product, provider, data_source FROM sys.servers WHERE is_linked = 1;

-- 8) 登录与权限（新增 sysadmin 账号）
SELECT name, type_desc, create_date, is_disabled FROM sys.server_principals WHERE type IN ('S','U','G');
SELECT p.name FROM sys.server_role_members rm
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id
WHERE r.name = 'sysadmin';

-- 9) 相关错误日志与审计
EXEC sp_readerrorlog 0, 1, 'xp_cmdshell';
EXEC sp_readerrorlog 0, 1, 'login';
```

```powershell
# SQL Server 相关文件与进程（Windows 侧）
Get-Service | Where-Object { $_.Name -match 'MSSQL|SQLAgent|SQLBrowser' } | Select-Object Name,Status,StartType
Get-CimInstance Win32_Process -Filter "Name='sqlservr.exe'" | Select-Object ProcessId,CommandLine
Get-ChildItem "C:\Program Files\Microsoft SQL Server" -Recurse -Include *.dll -EA SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
  Select-Object FullName,LastWriteTime
# SQL 错误日志位置
Get-ChildItem "C:\Program Files\Microsoft SQL Server\*\MSSQL\Log\ERRORLOG*" -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 5 FullName,Length,LastWriteTime
```

**MySQL / PostgreSQL（Windows 部署时同理）**

```powershell
# MySQL：UDF 提权与后门
#   检查 plugin 目录新增 DLL（lib_mysqludf_sys 等）
Get-ChildItem "C:\Program Files\MySQL","C:\ProgramData\MySQL" -Recurse -Include *.dll -EA SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } | Select-Object FullName,LastWriteTime
#   检查 my.ini 的 secure_file_priv 与 plugin_dir 被改
Get-ChildItem "C:\ProgramData\MySQL" -Recurse -Include my.ini -EA SilentlyContinue |
  Select-String -Pattern 'secure_file_priv|plugin_dir|general_log|log-bin'
#   SQL 侧：
#   SELECT * FROM mysql.func;                         -- 自定义函数
#   SELECT user,host,authentication_string FROM mysql.user;
#   SELECT * FROM mysql.event;                        -- 定时事件（持久化）
#   SELECT * FROM information_schema.triggers;

# PostgreSQL：扩展与启动钩子
#   SELECT * FROM pg_available_extensions;  /  \dx
#   postgresql.conf 的 shared_preload_libraries 是否被加料
Get-ChildItem "C:\Program Files\PostgreSQL" -Recurse -Include postgresql.conf -EA SilentlyContinue |
  Select-String -Pattern 'shared_preload_libraries|session_preload_libraries'
```

### 8.4 远程控制软件与"合法工具被滥用"

攻击者用合法远控软件（**Living off the Land 的现代变体**）的好处是：进程有签名、有公司名、杀软不报。

```powershell
# 1) 已安装的远控/远程管理软件清单
$rc = 'TeamViewer','AnyDesk','ToDesk','SunloginClient','向日葵','RustDesk','AweSun','GoToHTTP',
      'VNC','TightVNC','UltraVNC','tvnserver','WinVNC','Ammyy','Splashtop','Zoom','ScreenConnect','Atera','SSH'
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                 "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue |
  Where-Object { $_.DisplayName -match ($rc -join '|') } |
  Select-Object DisplayName,DisplayVersion,InstallDate,InstallLocation,Publisher

# 2) 服务的可执行路径与配置（判断是否"新装/被改"）
Get-CimInstance Win32_Service | Where-Object { $_.Name -match ($rc -join '|') -or $_.PathName -match ($rc -join '|') } |
  Select-Object Name,State,StartType,StartName,PathName

# 3) 配置文件（TeamViewer 的 ID/密码、AnyDesk 的密码哈希）
Get-ChildItem "$env:ProgramData\TeamViewer" -Recurse -Include *.ini,*.txt -EA SilentlyContinue |
  Select-String -Pattern 'ClientID|Version|SecurityPasswordAES'
Get-ChildItem "$env:ProgramData\AnyDesk" -Recurse -EA SilentlyContinue | Select-Object Name,LastWriteTime
Get-Content "$env:APPDATA\AnyDesk\user.conf" -EA SilentlyContinue |
  Select-String -Pattern 'ad.anynet.token|ad.anynet.id'
# 向日葵：配置文件与日志
Get-ChildItem "$env:ProgramData\Oray","$env:ProgramFiles\Oray" -Recurse -EA SilentlyContinue |
  Select-Object FullName,LastWriteTime -First 30
# ToDesk
Get-ChildItem "$env:ProgramData\ToDesk","$env:ProgramFiles\ToDesk" -Recurse -EA SilentlyContinue |
  Select-Object FullName,LastWriteTime -First 30

# 4) 远控的连接记录（这是最有力的证据）
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemotePort -in 5938,443,80,4000,6568,7070,8000,21115,21116,21118 } |
  Select-Object RemoteAddress,RemotePort,OwningProcess,
    @{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}}
# TeamViewer: 5938 | AnyDesk: 443/80/6568 | RustDesk: 21115-21119

# 5) 无人值守访问是否被开启（= 攻击者不用密码就能连）
Get-ItemProperty "HKLM:\SOFTWARE\TeamViewer" -EA SilentlyContinue |
  Select-Object ClientID,Version,SecurityPasswordAES,LocalPasswordAES
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\TeamViewer" -EA SilentlyContinue |
  Select-Object ClientID,SecurityPasswordAES

# 6) 远控软件的日志（含连接者 IP）
Get-ChildItem "$env:ProgramData\TeamViewer\Connections_incoming.txt" -EA SilentlyContinue |
  Get-Content
Get-ChildItem "$env:ProgramData\AnyDesk" -Recurse -Filter "*.trace" -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 5 |
  ForEach-Object { Select-String -Path $_.FullName -Pattern 'Connection|Login|Remote' | Select-Object -First 20 }
```

**判读**：如果这些软件**不是业务方要求的**，且安装时间在失陷窗口内、配置为"无人值守、固定密码"，基本可定性为攻击者安装的后门通道。

### 8.5 云、CI/CD 与开发凭据泄露面

攻击者拿到主机后，下一步常常是**横向到云和代码仓库**。

```powershell
# AWS
Get-ChildItem "$env:USERPROFILE\.aws" -Recurse -File -EA SilentlyContinue |
  Select-Object FullName,LastWriteTime
Get-Content "$env:USERPROFILE\.aws\credentials" -EA SilentlyContinue
# Azure
Get-ChildItem "$env:USERPROFILE\.azure","$env:USERPROFILE\.IdentityService" -Recurse -File -EA SilentlyContinue |
  Select-Object FullName,LastWriteTime
# GCP
Get-ChildItem "$env:APPDATA\gcloud" -Recurse -File -EA SilentlyContinue | Select-Object FullName,LastWriteTime
# Kubernetes
Get-Content "$env:USERPROFILE\.kube\config" -EA SilentlyContinue | Select-String 'server:|token:|client-certificate'
# Docker
Get-Content "$env:USERPROFILE\.docker\config.json" -EA SilentlyContinue
# Git 凭据
Get-Content "$env:USERPROFILE\.git-credentials" -EA SilentlyContinue
Get-Content "$env:USERPROFILE\.gitconfig" -EA SilentlyContinue
# npm / pip / nuget token
Get-Content "$env:USERPROFILE\.npmrc","$env:APPDATA\npm\etc\npmrc" -EA SilentlyContinue
Get-Content "$env:APPDATA\pip\pip.ini" -EA SilentlyContinue
# Terraform state（含明文密钥）
Get-ChildItem C:\ -Recurse -Filter "terraform.tfstate*" -File -EA SilentlyContinue | Select-Object FullName,LastWriteTime
# CI/CD runner 配置
Get-Content "C:\gitlab-runner\config.toml" -EA SilentlyContinue
Get-ChildItem "C:\Program Files (x86)\Jenkins" -Recurse -Include credentials.xml,config.xml -EA SilentlyContinue |
  Select-Object FullName,LastWriteTime
# Git 钩子后门（提交时执行）
Get-ChildItem C:\ -Recurse -Directory -Filter "hooks" -EA SilentlyContinue |
  Where-Object { $_.FullName -match '\\\.git\\hooks$' } |
  ForEach-Object { Get-ChildItem $_.FullName -File | Where-Object { $_.Name -notmatch '\.sample$' } |
    Select-Object @{n='Repo';e={$_.Directory.Parent.Parent.FullName}},Name,LastWriteTime }
# 私有密钥（SSH/PGP/证书）
Get-ChildItem "$env:USERPROFILE\.ssh","C:\Users" -Recurse -File -Include id_rsa,id_ed25519,*.pem,*.pfx,*.key -EA SilentlyContinue |
  Select-Object FullName,LastWriteTime

# 浏览器：扩展后门、保存的密码、下载记录
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" -Directory -EA SilentlyContinue |
  Select-Object Name,LastWriteTime
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" -Directory -EA SilentlyContinue |
  Select-Object Name,LastWriteTime
# 强制安装的扩展（策略下发，攻击者可用）
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" -EA SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist" -EA SilentlyContinue

# 邮件凭据与 Outlook 配置
Get-Content "$env:APPDATA\Microsoft\Outlook\*.xml" -EA SilentlyContinue
Get-ChildItem "$env:USERPROFILE\AppData\Local\Microsoft\OneAuth" -Recurse -EA SilentlyContinue
```

### 8.6 高频入口与对应 PowerShell 排查起点

| 入口类型 | 主机侧第一手证据 | 起始命令 |
|---|---|---|
| IIS/PHP/Java Web 漏洞 | w3wp 子进程、web 访问日志、新增 aspx/jsp | 6.6、8.2 |
| 中间件/调度平台 | 配置改动、任务新增、脚本目录 | 8.1 |
| RDP 弱口令/暴破 | 4625 集中 + 4624 Type10 + 1149 | 4.3 |
| SMB/共享弱口令 | 5140/5145、SmbSession | 4.5 |
| 远程管理软件 | 新装远控、无人值守配置 | 8.4 |
| 钓鱼附件/宏 | winword 子进程、Zone.Identifier、Prefetch | 5.1、6.3 |
| 供应链（软件更新） | 已签名程序被替换、DLL 侧载 | 6.5、3.9 |
| VPN/边界设备 | 本机侧无直接证据，需查设备日志 | 转网络侧 |
| 暴露的服务（1433/3306/6379/3389） | 监听 + 登录失败事件 | 1.1、8.3 |

---

## 9. 处置与加固

### 9.1 网络隔离

```powershell
# 先界定：隔离目标主机，不影响取证通道
# 方案一：主机防火墙（推荐，保留内存）
New-NetFirewallRule -DisplayName "IR-Block-All-Out" -Direction Outbound -Action Block -Profile Any
New-NetFirewallRule -DisplayName "IR-Block-All-In"  -Direction Inbound  -Action Block -Profile Any
# 放行取证服务器
New-NetFirewallRule -DisplayName "IR-Allow-Forensic" -Direction Outbound -Action Allow -RemoteAddress <取证服务器IP>

# 方案二：交换机端口关闭 / VLAN 隔离（需网络组配合）
# 方案三：拔网线（仅在内存已固定且需要绝对隔离时使用）

# 阻断已知 C2（应急止血，注意攻击者会换）
New-NetFirewallRule -DisplayName "IR-Block-C2" -Direction Outbound -Action Block -RemoteAddress 1.2.3.4
# 清理
# Remove-NetFirewallRule -DisplayName "IR-*"

# 清理攻击者留下的转发与代理
netsh interface portproxy show all
# netsh interface portproxy delete v4tov4 listenport=<端口> listenaddress=0.0.0.0
# netsh winhttp reset proxy
# netsh winhttp set proxy <合法代理>
```

### 9.2 进程处置

```powershell
# 强制结束进程（原手册命令）
taskkill /F /PID 进程PID
# 结束进程树（含子进程）
taskkill /F /T /PID 进程PID
# PowerShell
Stop-Process -Id <PID> -Force
Get-CimInstance Win32_Process -Filter "ParentProcessId=<PID>" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

# 【重要】处置前的正确顺序
# 1) 先固定证据（内存/句柄/连接/命令行）—— 进程一杀，证据就没了
Get-CimInstance Win32_Process -Filter "ProcessId=<PID>" | Select-Object * | Export-Clixml C:\IR\proc_<PID>.xml
Get-NetTCPConnection -OwningProcess <PID> | Export-Csv C:\IR\conn_<PID>.csv -NoTypeInformation

# 2) 需要考虑"挂起"而非"终止"（保留内存供分析）
#    Sysinternals Process Explorer 右键 -> Suspend；或：
#    pssuspend64.exe <PID>
#    恢复：pssuspend64.exe -r <PID>

# 3) 若进程有守护/看门狗（杀了就重生），先找守护者
#    方法：记录 PID -> 杀掉 -> 立即看是否有同名新 PID -> 溯源父进程
#    查计划任务/服务中引用该 exe 的条目

# 4) 处置后必须验证：同名进程不再出现、端口不再监听、连接不再建立
Get-Process -Name <名字> -EA SilentlyContinue
Get-NetTCPConnection -LocalPort <端口> -EA SilentlyContinue
```

### 9.3 服务与自启项清理

```powershell
# 禁用计划任务（原手册命令）
Disable-ScheduledTask -TaskName "任务名"
Unregister-ScheduledTask -TaskName "任务名" -Confirm:$false   # 删除

# 停止并禁用服务（原手册命令）
Stop-Service -Name 服务名; Set-Service -Name 服务名 -StartupType Disabled
# 删除服务
sc.exe stop <服务名>
sc.exe delete <服务名>
# 注意：删除前先导出配置作为证据
sc.exe qc <服务名> > C:\IR\svc_<服务名>.txt

# 清理注册表 Run 项（先导出！）
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" C:\IR\run_before.reg /y
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "<值名>"
# 或
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "<值名>" /f

# 清理 WMI 持久化（三个组件都要删！）
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
  Where-Object { $_.Consumer -match '<恶意消费者名>' } | Remove-CimInstance
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
  Where-Object { $_.Name -eq '<恶意消费者名>' } | Remove-CimInstance
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
  Where-Object { $_.Name -eq '<恶意过滤器名>' } | Remove-CimInstance

# 停用并移除 Autoruns 发现的项（GUI 操作最不易出错）
# autoruns64.exe -> 定位条目 -> Delete（先 Export 备份）

# 处置后验证：重跑 3.13 的 Autoruns 导出，对比清理前后差异
autorunsc64.exe -accepteula -a * -c -h -s -t -nobanner -m -o C:\IR\autoruns_after.csv
```

### 9.4 账号处置

```powershell
# 禁用账号
Disable-LocalUser -Name "<用户名>"
net user <用户名> /active:no
# 删除账号
Remove-LocalUser -Name "<用户名>"
net user <用户名> /delete

# 重置密码（若账号必须保留）
net user <用户名> <新密码>
# 强制下次登录改密
Set-LocalUser -Name "<用户名>" -PasswordNeverExpires $false
net user <用户名> /logonpasswordchg:yes

# 从特权组移除
Remove-LocalGroupMember -Group "Administrators" -Member "<用户名或组>"
Remove-LocalGroupMember -Group "Remote Desktop Users" -Member "<用户名>"

# 【必做】改所有可能已泄露的凭据
#   - 本地管理员密码（本机）
#   - 域账号密码（尤其域管，需评估是否已黄金票据，可能需重置 krbtgt 两次）
#   - 服务账户密码
#   - 应用连接串中的数据库账号
#   - API Key / Token（云、CI/CD、监控平台）
#   - SSH 私钥重新生成（Windows OpenSSH）
#   - 证书吊销与重签

# 【必做】清理攻击者的凭据驻留
#   - 删除可疑的 DPAPI 凭据文件
#   - 检查并移除新增的证书
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.NotBefore -gt (Get-Date).AddDays(-30) }
#   - 关闭 WDigest 明文缓存
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 0

# 踢掉活动会话（改密后老会话可能仍有效）
logoff <会话ID>
# 远程注销
# query user / logoff <ID>

# 域环境额外动作
#   - 重置 krbtgt 密码（两次，间隔 > 10 小时）
#   - 检查并清理 AdminSDHolder ACL
#   - 检查 SID History
#   - 检查 GPO 是否被改
```

### 9.5 文件处置

```powershell
# 【先隔离，后删除】—— 隔离到取证目录并保留哈希，不要直接删
$quarantine = "C:\IR\quarantine"
New-Item -ItemType Directory -Path $quarantine -Force
$target = "C:\Windows\Temp\evil.exe"
Move-Item $target (Join-Path $quarantine (Split-Path $target -Leaf)) -Force
Get-FileHash (Join-Path $quarantine (Split-Path $target -Leaf)) -Algorithm SHA256

# 删除恶意文件（确认已取证后）
Remove-Item <路径> -Force
# 若被占用/权限拒绝
takeown /F <路径> /A
icacls <路径> /grant Administrators:F
Remove-Item <路径> -Force

# 删除前记录"删除痕迹"（时间、操作者、哈希、大小），写入事件报告
# 删除后从 USN Journal / MFT 仍可追溯（见 5.5）

# 清理临时落地与下载物
Get-ChildItem C:\Windows\Temp,$env:TEMP -File -EA SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt <失陷起始时间> } | Select-Object FullName,LastWriteTime

# 清理 ADS（谨慎：-d 会删除所有数据流，含 Zone.Identifier）
# streams64.exe -d -s <目录>

# 恢复被篡改的系统文件
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth
```

### 9.6 加固措施（处置后落地）

> 完整基线见 `windows-hardening.md`。这里是"应急响应结束后必须立刻做"的最小集。

```powershell
# === 1) 打开关键日志（现在不开，下次还是查不到）===
# 命令行审计（4688 带命令行）
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
# 也可用 auditpol 打开进程创建审计
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
# PowerShell 脚本块日志（还原无文件攻击的前提）
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
# 增大日志容量（Security 建议 >= 512MB）
wevtutil sl Security /ms:536870912
wevtutil sl System /ms:134217728
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:134217728

# === 2) 部署 Sysmon（Windows 上性价比最高的检测手段）===
# 下载 Sysmon + 使用成熟配置（SwiftOnSecurity / olafhartong/sysmon-modular）
# sysmon64.exe -accepteula -i sysmonconfig.xml
Get-Service Sysmon64 -EA SilentlyContinue | Select-Object Name,Status,StartType

# === 3) 打开 Defender 攻击面缩减规则（ASR）===
# 见 6.10，至少启用与 Office/WMI/脚本/勒索相关的 8 条

# === 4) 关闭不必要的高危面 ===
# SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
# 关闭 SMB 签名要求改为强制
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
# 禁用 WDigest 明文
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 0
# 禁用 AutoRun/AutoPlay（U 盘传播）
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -Value 255
# 禁用远程注册表、Telnet、不必要服务
Get-Service RemoteRegistry,Telnet,SNMP,FTPSVC -EA SilentlyContinue | Set-Service -StartupType Disabled

# === 5) RDP 加固 ===
# 限制来源、启用 NLA、启用网络级认证、关闭驱动器重定向
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name SecurityLayer -Value 2
# 更彻底：RDP 只允许经跳板/堡垒机（防火墙限制源 IP 或经 VPN）

# === 6) PowerShell 约束语言模式 / 应用白名单 ===
# WDAC 或 AppLocker，把 PowerShell 限制为 ConstrainedLanguage
# （需先在审计模式验证，避免影响业务脚本）

# === 7) 凭据保护 ===
# 开启 Credential Guard（需 UEFI + VBS 支持，先评估兼容性）
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus,SecurityServicesRunning
# 启用 Windows LAPS 管理本地管理员密码
# 启用 LSASS 保护（RunAsPPL）
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
# 限制调试权限（只有管理员可 dump LSASS）
# 见 4.2 的 User Rights Assignment

# === 8) 建立日志外发（本机被清也能查）===
# 配置 WEF 或在主机上部署采集 Agent（Winlogbeat/Filebeat/Splunk UF）
Get-Service Winlogbeat,filebeat,splunkd,nxlog -EA SilentlyContinue | Select-Object Name,Status

# === 9) 补丁与漏洞收敛 ===
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
# 关注：Exchange/IIS/SQL 等应用补丁、以及被利用的 0day
# 用 Windows Update / WSUS / SCCM / Intune 统一推进

# === 10) 备份与恢复验证（对抗勒索的最后一道线）===
# - 3-2-1 备份策略（3 份、2 种介质、1 份离线）
# - 离线备份不可被网络访问（勒索最爱打备份服务器）
# - 定期演练恢复，不是"有备份就行"
```

**收尾清单**

- [ ] 所有已发现后门已清理，且 **Autoruns 二次导出对比无残留**
- [ ] 新增/可疑账号已禁用或删除，相关凭据已全部更换
- [ ] C2 地址已封禁，且确认主机不再发起连接
- [ ] 事件日志已导出留档（含 Security / System / Application / PowerShell / Sysmon）
- [ ] 内存镜像、样本、导出报告归档，附 SHA256
- [ ] 应急处置报告已完成（含时间线、入口、影响范围、处置动作、遗留风险）
- [ ] 加固措施已落地（至少完成 9.6 的 1–4 项）
- [ ] 同源排查：其他主机是否有相同 IOC / 相同入口
- [ ] 已向上汇报，并给出"同类风险系统"的收敛计划

---

## 10. 一键排查脚本

仓库提供了两个只读脚本，用于快速建立现场基线：

```powershell
# 应急响应快速采集（只读，输出到 C:\IR\<主机名>-<时间戳>\）
# 以管理员身份运行 PowerShell
powershell -ExecutionPolicy Bypass -File .\scripts\windows-ir-quickcheck.ps1

# 基线核查（只读，输出问题清单与问题计数）
powershell -ExecutionPolicy Bypass -File .\scripts\windows-baseline-check.ps1
```

**`windows-ir-quickcheck.ps1` 采集内容**

| 模块 | 内容 |
|---|---|
| 系统信息 | 主机名、系统版本、启动时间、补丁、时区 |
| 网络 | 监听端口、外连、DNS 缓存、ARP、路由、防火墙规则、portproxy、代理 |
| 进程 | 完整进程列表、命令行、路径、签名、父子关系、可疑进程判定 |
| 服务与驱动 | 服务路径、ServiceDll、FailureCommand、驱动 |
| 持久化 | Run 系列、计划任务（含隐藏）、WMI 订阅、IFEO、启动文件夹、Winlogon、LSA |
| 账号 | 本地用户、特权组、Guest/Administrator 状态、登录事件摘要 |
| 事件日志 | 关键事件 ID 摘要、日志清除痕迹、日志配置 |
| 文件痕迹 | 近期可执行文件、Prefetch、ADS、Zone.Identifier（Internet 来源） |
| 可疑项汇总 | 末尾自动输出"需要人工确认"的清单 |

**使用建议**

1. **先跑采集，再动手清理**——脚本只读，不会破坏证据；
2. 输出目录连同主机名一起打包，作为案件存档；
3. 汇总结论是**线索而非结论**，每条都要人工确认（脚本会标注判定依据）；
4. 在有 EDR 的环境里，脚本用于补齐 EDR 覆盖不到的细节（如 ServiceDll、WMI 订阅）。

---

## 附录 A：现场排查 Checklist

**第一阶段：保护与固定（15 分钟内）**

- [ ] 记录时间基准（系统时间、时区、启动时间）
- [ ] 采集内存镜像（WinPmem）
- [ ] 采集网络连接快照与 DNS 缓存
- [ ] 若需要，启动流量抓包（pktmon）
- [ ] 确认是否已开启日志转发/EDR（决定后续能否依赖本机日志）

**第二阶段：快速定位（30–60 分钟）**

- [ ] 外连清单（含进程、路径）
- [ ] 可疑进程（路径异常 / 未签名 / 父子关系异常 / 命令行可疑）
- [ ] 持久化快速扫（Run 系列、计划任务、服务、WMI 订阅、启动文件夹）
- [ ] 账号（新增账号、隐藏账号、特权组成员变化）
- [ ] 登录事件（4624 Type10、4625 集中、4648）
- [ ] 最近落地文件（24–72 小时）

**第三阶段：深挖（按需，数小时）**

- [ ] Autoruns 全量导出 + 逐条确认
- [ ] Sysmon / PowerShell 4104 检索无文件攻击
- [ ] Prefetch / Amcache / SRUM / USN Journal 时间线
- [ ] 内存分析（Volatility3 / MemProcFS）
- [ ] Webshell / 中间件专项（IIS、SQL、XXL-JOB、Jenkins）
- [ ] 凭据窃取痕迹（LSASS、DPAPI、NTDS）
- [ ] 横向移动痕迹（4648、PsExec、WMI、WinRM、RDP 出站）
- [ ] 数据外带痕迹（压缩、云同步、大流量上行）
- [ ] 日志篡改与清除痕迹

**第四阶段：处置与收口**

- [ ] 网络隔离 / C2 阻断
- [ ] 后门清理（服务、任务、注册表、WMI、文件）
- [ ] 账号处置与凭据轮换
- [ ] 加固落地（日志、Sysmon、ASR、补丁）
- [ ] 二次验证（Autoruns 对比、端口/连接复查）
- [ ] 报告与同源排查

---

## 附录 B：应急工具箱（离线 U 盘必带）

| 类别 | 工具 | 用途 |
|---|---|---|
| 内存采集 | WinPmem、Magnet RAM Capture、Belkasoft RAM Capturer、DumpIt | 内存镜像 |
| 内存分析 | Volatility 3、MemProcFS、WinDbg | 进程/注入/凭据/rootkit |
| 持久化 | **Autoruns**、AutoRuns CLI | 50+ 自启位置全量 |
| 进程/句柄 | Process Explorer、System Informer、ListDlls、handle、ProcDump、pssuspend | 实时分析与挂起 |
| 网络 | TCPView、CurrPorts、Wireshark、pktmon（内置）、Nmap | 连接与流量 |
| 签名/哈希 | Sigcheck、Get-AuthenticodeSignature、HashMyFiles | 签名与情报比对 |
| 文件痕迹 | **PECmd**、**AmcacheParser**、**AppCompatCacheParser**、**MFTECmd**、**JLECmd**、**RBCmd**、**SrumECmd**、**EvtxECmd**、**Registry Explorer**、**Timeline Explorer**（Eric Zimmerman 全家桶） | 时间线与痕迹解析 |
| 日志检测 | **Chainsaw**、**Hayabusa**、**Zircolite**、**DeepBlueCLI**、APT-Hunter、Sigma 规则库 | 规则驱动的日志猎杀 |
| 采集打包 | **KAPE**、Velociraptor、CyLR、FastIR Collector、IREC | 批量取证采集 |
| 静态分析 | Detect It Easy、PEStudio、CFF Explorer、**CAPA**、**FLOSS**、strings、YARA、exiftool | 样本初判 |
| 内存马检测 | **pe-sieve**、**HollowsHunter**、Moneta | 注入与内存马 |
| 反 rootkit | GMER、TDSSKiller、Malwarebytes Anti-Rootkit、System Informer | 内核级后门 |
| 基线核查 | **HardeningKitty**、Microsoft Security Compliance Toolkit、CIS-CAT、Lynis(WSL) | 基线评估 |
| AD 评估 | **BloodHound**、**PingCastle**、**Purple Knight**、ADAudit Plus | 域环境风险 |
| 恢复 | PhotoRec、TestDisk、R-Studio、FTK Imager、ShadowExplorer | 文件恢复 |
| 脚本运行时 | PowerShell 7、Python 3、.NET Runtime | 保证工具能跑 |

> 完整说明与获取方式见 `windows-forensics-toolchain.md`。

---

## 附录 C：LOLBins 与无文件攻击速查

**"离地攻击"（Living off the Land）**：用系统自带的合法程序做恶意事，绕过应用白名单与部分杀软。

| 二进制 | 常见滥用方式 |
|---|---|
| `powershell.exe` / `pwsh.exe` | `-enc`、`-nop -w hidden -exec bypass`、IEX 下载执行、内存加载 .NET |
| `cmd.exe` | `/c` 串联命令、`start` 派生、管道下载 |
| `mshta.exe` | `mshta http://...`、`mshta vbscript:` / `javascript:` |
| `rundll32.exe` | `javascript:`、导出函数调用、`comsvcs.dll MiniDump`（dump LSASS） |
| `regsvr32.exe` | `/s /n /u /i:http://... scrobj.dll`（Squiblydoo，绕 AppLocker） |
| `certutil.exe` | `-urlcache -split -f` 下载、`-decode` 解码 Base64、`-encode` |
| `bitsadmin.exe` | `/transfer` 下载（跨重启、低检测） |
| `msiexec.exe` | `/q /i http://...` 远程 MSI 执行 |
| `wmic.exe` | `process call create` 执行、`/node:` 远程 |
| `msbuild.exe` / `csc.exe` | 编译并内联执行 C# 代码（无文件） |
| `installutil.exe` | .NET 程序集绕过白名单执行 |
| `regasm.exe` / `regsvcs.exe` | .NET DLL 注册并执行 |
| `cscript.exe` / `wscript.exe` | `.vbs` / `.js` 脚本执行 |
| `forfiles.exe` | `/c` 参数执行命令 |
| `pcalua.exe` | `-a` 启动任意程序 |
| `conhost.exe` | 可承载命令执行 |
| `xwizard.exe` | 加载自定义 COM 执行代码 |
| `runonce.exe` | `/AlternateShellStartup` 执行 |
| `expand.exe` / `extrac32.exe` | 解压/复制任意文件 |
| `esentutl.exe` | `/y` 复制被占用文件（如 NTDS.dit、SAM） |
| `netsh.exe` | `add helper` 加载 DLL、`portproxy` 建代理 |
| `sc.exe` | `create` / `config` 建服务 |
| `schtasks.exe` | `/create` 建任务 |
| `regsvr32.exe`（再次） | 侧载任意 DLL |
| `wsl.exe` | 通过 WSL 执行 Linux 载荷 |
| `ssh.exe` | 内网跳板与隧道 |
| `curl.exe`（Win10+ 内置） | 下载（原本就合法，检测困难） |
| `tar.exe`（Win10+ 内置） | 打包外带 |
| `mpcmdrun.exe` | Defender 命令行，可被用于下载文件 |

**配套检测思路**

```powershell
# 一次性扫出"LOLBin 被非正常父进程调用"的情况
$lolbins = 'powershell','pwsh','cmd','mshta','rundll32','regsvr32','certutil','bitsadmin',
           'msiexec','wmic','msbuild','csc','installutil','regasm','regsvcs','cscript','wscript',
           'forfiles','pcalua','xwizard','runonce','expand','extrac32','esentutl','netsh','sc',
           'schtasks','wsl','curl','tar','mpcmdrun','conhost'
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Message -match ('\\\\(' + ($lolbins -join '|') + ')\.exe') -and
                          $_.Message -match 'Office|EXCEL|WINWORD|OUTLOOK|w3wp|httpd|nginx|java|node' } |
  Select-Object TimeCreated,Message -First 50
```

**无文件攻击的四个落点**

1. **进程内存**：`pe-sieve` / `HollowsHunter` 扫描；Volatility3 `malfind`
2. **脚本块日志**：PowerShell 4104（前提是已开启）
3. **WMI 仓库**：`__EventFilter` + `CommandLineEventConsumer`（见 3.4）
4. **注册表**：把脚本/Base64 存在注册表值里，运行时读取（见 3.9）

---

> **文档维护**：本手册随攻击手法演进持续更新。发现新手法时，请同时更新
> `windows-attack-mapping.md`（手法映射）与 `scripts/windows-ir-quickcheck.ps1`（自动采集）。

