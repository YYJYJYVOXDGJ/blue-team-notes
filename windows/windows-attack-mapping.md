# Windows 攻击手法映射（蓝队知识层）

> 定位：**回答"看到这个现象，最可能是什么手法，下一步查什么"**。
> 与 `windows-host-audit.md` 的关系：主手册是"工具书"（怎么做），本文是"对照表"（为什么）。
> 所有章节号（如 3.4）均指主手册章节。

## 目录

- [1. 攻击链阶段 → 落地痕迹 → 排查落点](#1-攻击链阶段--落地痕迹--排查落点)
- [2. ATT&CK for Windows 映射表](#2-attck-for-windows-映射表)
- [3. 权限维持手法全量核对清单（清后门必查）](#3-权限维持手法全量核对清单清后门必查)
- [4. 专项分析](#4-专项分析)
- [5. 现象 → 最可能手法 → 下一步 速查表](#5-现象--最可能手法--下一步-速查表)
- [6. 常见攻击工具与框架特征速查](#6-常见攻击工具与框架特征速查)
- [7. 现代攻防趋势与新技术（2024–2026）](#7-现代攻防趋势与新技术20242026)

---

## 1. 攻击链阶段 → 落地痕迹 → 排查落点

| 阶段 | 攻击者动作 | Windows 上留下的痕迹 | 主手册落点 |
|---|---|---|---|
| **初始访问** | 钓鱼宏 / 漏洞利用 / 弱口令 RDP / 暴露面 | `winword.exe`→`powershell.exe` 父子链；`Zone.Identifier` 标记 ZoneId=3；4625 暴破集中；Web 日志异常请求 | 2.2 / 6.3 / 4.3 / 8.2 |
| **执行** | 脚本、LOLBin、内存加载 | 4688（含命令行）、Sysmon 1、Prefetch、PowerShell 4104、Amcache | 5.1 / 5.2 / 5.6 / 7.5 |
| **持久化** | 服务、任务、注册表、WMI | 7045、4697、4698、Sysmon 12/13/19/20/21、Autoruns 条目 | 第 3 章 |
| **提权** | UAC 绕过、Potato、服务权限、驱动 | 4672、4673、事件 4688 中的 `fodhelper`/`sdclt`/`computerdefaults`、AlwaysInstallElevated=1 | 4.2 / 6.10 |
| **防御规避** | 关杀软、加排除、关日志、清日志 | Defender 5001/5007、1102、104、Sysmon 服务停止、4719 | 7.2 / 6.10 |
| **凭据访问** | LSASS dump、mimikatz、DPAPI、Kerberoast | Sysmon 10 访问 lsass、`comsvcs.dll MiniDump` 命令行、4769 异常、4662 复制 GUID、`mimilib.dll` 出现在 LSA | 4.4 |
| **发现** | 侦察（net/whoami/nltest/BloodHound） | 4688 中 `net`/`net1`/`whoami`/`nltest`/`ping`/`arp` 短时间密集执行；LDAP 查询激增 | 2.4 / 4.5 |
| **横向移动** | RDP / SMB / WMI / WinRM / PsExec | 4648、4624 Type3/10、5140/5145、PSEXESVC 服务、WMI-Activity 5857、出站 445/135/3389 | 4.5 |
| **凭证复用与伪装** | runas /netonly、Pass-the-Hash | 4624 Type9、4776 NTLM、同账号异地登录 | 4.3 |
| **收集** | 打包敏感文件、截图、键盘记录 | `rar`/`7z`/`makecab` 命令行、`Compress-Archive`、截图工具、新建大文件 | 6.8 |
| **C2** | Beacon 回连、隧道、端口转发 | 外连高位端口、命名管道（Sysmon 17/18）、`netsh portproxy`、代理配置被改 | 1.2 / 1.5 |
| **外带** | 上传到网盘、HTTP POST、DNS 隧道 | rclone/curl 命令行、上行大流量（SRUM）、Sysmon 22 异常 DNS | 6.8 |
| **影响** | 勒索、擦除、挖矿 | `vssadmin delete shadows`、`bcdedit recoveryenabled No`、高熵新扩展名、CPU 满载 | 6.7 |

**时间线的读法**：把上面的阶段按 5 分钟粒度切片，**阶段之间的间隔通常很短**（自动化程度高的攻击在几分钟内完成整个链条）。如果你看到"执行"和"外带"间隔 3 天，说明中间有大量人工操作——这段时间的 4688 和 Sysmon 1 是关键。

---

## 2. ATT&CK for Windows 映射表

> 下表按战术分组。每项给出**技术 ID → Windows 落地痕迹 → 排查命令所在的章节**。
> 完整列表见 MITRE ATT&CK 官网，这里只保留**蓝队现场高频且可验证**的部分。

### TA0001 初始访问（Initial Access）

| ID | 技术 | Windows 落地痕迹 | 落点 |
|---|---|---|---|
| T1566.001 | 钓鱼附件 | `winword/excel/outlook` → 子进程；`Zone.Identifier`；`%TEMP%` 下的 RTF/DOC | 2.2 / 6.3 |
| T1566.002 | 钓鱼链接 | 浏览器进程 → `rundll32/mshta`；下载目录新增可执行 | 2.2 / 5.4 |
| T1190 | 利用面向公众的应用 | `w3wp.exe` → `cmd/powershell`；IIS 日志异常请求；新增 `.aspx` | 6.6 / 8.2 |
| T1133 | 外部远程服务 | RDP 1149/4624 Type10；VPN 软件；远控软件新装 | 4.3 / 8.4 |
| T1078 | 有效账户 | 4624 Type3/10 使用合法账号；陌生来源 IP | 4.3 |
| T1195.002 | 供应链：软件依赖 | 签名程序被替换；DLL 侧载；更新包被篡改 | 6.5 / 3.9 |
| T1199 | 信任关系 | 域内横向；AD FS 令牌伪造 | 4.5 |

### TA0002 执行（Execution）

| ID | 技术 | Windows 落地痕迹 | 落点 |
|---|---|---|---|
| T1059.001 | PowerShell | 4104 脚本块；`-enc` 命令行；Prefetch `POWERSHELL.EXE-*.pf` | 5.6 / 2.4 |
| T1059.003 | Windows CMD | 4688 中 `cmd.exe /c`；父进程为 Office/Web 服务 | 2.4 |
| T1059.005 | Visual Basic | `cscript/wscript` + `.vbs`；Office 宏 | 2.4 |
| T1059.007 | JavaScript | `mshta`、`.js` 文件、`wscript` | 附录 C |
| T1047 | WMI | `wmic process call create`；WMI-Activity 5857/5858 | 3.4 / 4.5 |
| T1204.002 | 用户执行：恶意文件 | `Zone.Identifier`；回收站/下载目录新增；Prefetch | 5.1 / 6.3 |
| T1203 | 客户端漏洞利用 | Office/浏览器异常崩溃（Application 日志 1000/1001） | 7.5 |
| T1569.002 | 服务执行 | 7045 新服务；`sc create` 命令行 | 3.2 |
| T1053.005 | 计划任务 | 4698；TaskScheduler 200/201；`schtasks /create` | 3.3 |
| T1106 | 原生 API | 反射加载 / .NET 内存加载；无落地文件 | 2.5 |
| T1047 / T1218.* | LOLBins | 见附录 C 的二进制清单 | 附录 C |

### TA0003 持久化（Persistence）

| ID | 技术 | Windows 落地痕迹 | 落点 |
|---|---|---|---|
| T1547.001 | 注册表 Run 键 | Run/RunOnce 值 | 3.1 |
| T1547.004 | Winlogon Helper DLL | Winlogon\Shell / Userinit / Notify | 3.5 |
| T1547.005 | 安全支持提供程序（SSP） | LSA Security Packages 含非微软项（如 `mimilib`） | 3.5 / 4.4 |
| T1547.006 | 内核模块与扩展 | 恶意驱动 `.sys`；`driverquery` | 2.6 / 3.2 |
| T1547.008 | LSASS 驱动 | LSA 相关驱动注册 | 3.5 |
| T1547.009 | 快捷方式修改 | 启动文件夹 `.lnk` 指向异常 | 3.8 |
| T1547.010 | 端口监视器 | Print\Monitors 新增项 | 3.9 |
| T1547.012 | 打印处理器 | PrintProcessors 新增 | 3.9 |
| T1547.014 | Active Setup | StubPath | 3.8 |
| T1547.015 | 登录脚本 | `UserInitMprLogonScript` | 3.8 |
| T1136.001 | 创建本地账户 | 4720；`$` 结尾账号；SpecialAccounts | 4.1 |
| T1136.002 | 创建域账户 | 4720（DC）；域内新增账号 | 4.5 |
| T1543.003 | Windows 服务 | 7045；ServiceDll；FailureCommand | 3.2 |
| T1543.002 | 系统服务/守护进程 | 驱动型服务 | 3.2 |
| T1546.003 | WMI 事件订阅 | `__EventFilter` + `CommandLineEventConsumer` | 3.4 |
| T1546.007 | Netsh Helper DLL | `HKLM\SOFTWARE\Microsoft\NetSh` | 3.9 |
| T1546.008 | 辅助功能程序 | sethc/utilman 的 IFEO Debugger | 3.6 |
| T1546.009 | AppCert DLLs | `AppCertDlls` | 3.9 |
| T1546.010 | AppInit DLLs | `AppInit_DLLs` | 3.5 |
| T1546.011 | 应用填充（COM 劫持） | HKCU 覆盖 CLSID | 3.7 |
| T1546.012 | IFEO 注入 | IFEO Debugger | 3.6 |
| T1546.015 | COM 劫持 | InprocServer32 / TreatAs | 3.7 |
| T1547.002 | 认证包 | LSA Authentication Packages | 3.5 |
| T1547.003 | 时间提供程序 | W32Time\TimeProviders | 3.9 |
| T1505.003 | Web Shell | IIS 目录新增 aspx | 6.6 |
| T1505.001 | SQL 存储过程 | 自启动存储过程 / SQL Agent 作业 | 8.3 |
| T1053.005 | 计划任务 | 4698；隐藏任务 | 3.3 |
| T1037.001 | 登录脚本 | UserInitMprLogonScript / 组策略脚本 | 3.8 |
| T1078.001 | 默认账户 | Administrator/Guest 被启用 | 4.6 |
| T1098 | 账户操作 | 加入特权组 4728/4732 | 4.1 |
| **T1547.014 / T1546.012 之外** | BITS 任务 | `Get-BitsTransfer` | 3.12 |

### TA0004 提权（Privilege Escalation）

| ID | 技术 | Windows 落地痕迹 | 落点 |
|---|---|---|---|
| T1548.002 | UAC 绕过 | `fodhelper.exe` / `sdclt.exe` / `eventvwr.exe` 异常启动；`ms-settings` 协议劫持 | 4.2 |
| T1068 | 漏洞利用提权 | 系统补丁缺失；驱动漏洞（BYOVD） | 9.6 / 6.10 |
| T1134 | 访问令牌操作 | `SeDebugPrivilege` 异常使用；令牌伪造 | 4.2 |
| T1134.002 | 创建令牌 | `runas /netonly`（Type9 登录） | 4.3 |
| T1484 | 域策略修改 | GPO 被改、AdminSDHolder ACL | 4.5 |
| T1574.001/002/008/009 | 劫持执行流 | DLL 侧载、未加引号服务路径、PATH 劫持 | 3.2 / 3.9 |

### TA0005 防御规避（Defense Evasion）

| ID | 技术 | Windows 落地痕迹 | 落点 |
|---|---|---|---|
| T1562.001 | 关闭或修改工具 | Defender 5001/5007；排除项被加 | 6.10 / 7.2 |
| T1562.002 | 关闭日志 | 4719；日志 IsEnabled=False；日志被清 1102 | 7.2 |
| T1562.006 | 禁用遥测 | Sysmon 服务停止（Sysmon 4）；ETW 被改 | 7.2 |
| T1562.008 | 关闭云端保护 | `Get-MpPreference` 中各项被关 | 6.10 |
| T1070.001 | 清除 Windows 事件日志 | 1102、104 | 7.2 |
| T1070.004 | 文件删除 | USN Journal `$J` 记录 | 5.5 |
| T1070.006 | 时间戳篡改 | Sysmon 2；MFT 中 SI 与 FN 时间不一致 | 5.5 |
| T1036.003 | 重命名系统实用程序 | 伪装成 svchost/explorer 的进程 | 2.3 |
| T1036.005 | 匹配合法名称或位置 | 放在 `C:\Windows\` 下的仿冒 DLL | 6.2 |
| T1027 | 混淆文件或信息 | `-enc`、Base64、字符串加密 | 2.4 / 5.6 |
| T1027.002 | 软件打包 | 加壳（UPX 等），熵值高 | 6.5 |
| T1140 | 反混淆/解码 | `certutil -decode`、`[Convert]::FromBase64String` | 2.4 |
| T1218.005 | Mshta | 见附录 C | 附录 C |
| T1218.010 | Regsvr32 | Squiblydoo | 附录 C |
| T1218.011 | Rundll32 | `comsvcs.dll MiniDump` | 4.4 |
| T1197 | BITS 作业 | `bitsadmin /transfer` | 3.12 |
| T1222 | 文件权限修改 | `takeown` + `icacls` 命令 | 9.5 |
| T1553.002 | 代码签名滥用 | 签名有效但被吊销 / 正规证书签恶意程序 | 6.5 |
| T1553.006 | 降级攻击 | 卸载补丁、禁用 AMSI | 5.6 |
| T1574.001 | DLL 搜索顺序劫持 | 系统目录被植入同名 DLL | 6.2 |

### TA0006 凭据访问（Credential Access）

| ID | 技术 | Windows 落地痕迹 | 落点 |
|---|---|---|---|
| T1003.001 | LSASS 内存 | Sysmon 10；`comsvcs.dll` / procdump / mimikatz | 4.4 |
| T1003.002 | SAM | `reg save HKLM\SAM`；`esentutl` 复制 | 4.1 / 4.4 |
| T1003.003 | NTDS | `ntdsutil` + VSS；`esentutl /y` | 4.4 |
| T1003.004 | LSA Secrets | 注册表 SECURITY hive 被导出 | 4.4 |
| T1003.005 | 缓存域凭据 | `cachedump`；mscash | 4.4 |
| T1003.006 | DCSync | 4662 + 复制 GUID | 4.4 |
| T1056.001 | 键盘记录 | 异常钩子进程；`SetWindowsHookEx` | 2.5 |
| T1110 | 暴力破解 | 4625 集中；4740 锁定 | 4.3 |
| T1110.003 | 密码喷洒 | 多账号 4625，次数少但分散 | 4.3 |
| T1552.001 | 文件中凭据 | `.aws\credentials`、`.git-credentials`、配置文件明文 | 8.5 |
| T1552.002 | 注册表凭据 | `DefaultPassword`、Putty 会话、VNC 密码 | 3.5 / 8.4 |
| T1555 | 密码管理器 | KeePass/Keeper 进程被异常读取 | 8.5 |
| T1555.003 | 浏览器凭据 | Chrome `Login Data` 被复制；浏览器 headless 启动 | 4.4 |
| T1558.003 | Kerberoasting | 4769 大量 RC4 请求 | 4.5 |
| T1558.001 | 黄金票据 | krbtgt 哈希被窃；4769 异常加密类型 | 4.5 |
| T1606 | 伪造凭据 | AD FS / 令牌签名证书 | 4.5 |
| T1550.002 | 哈希传递 | 4776 NTLM；4624 Type3 无密码验证过程 | 4.3 |

### TA0007 发现（Discovery）

| ID | 技术 | Windows 落地痕迹 | 落点 |
|---|---|---|---|
| T1087.001 | 本地账户发现 | 4688 中 `net user`、`Get-LocalUser` | 2.4 |
| T1087.002 | 域账户发现 | LDAP 查询激增；`net group /domain` | 4.5 |
| T1018 | 远程系统发现 | `ping`/`arp` 扫描；`net view` | 4.5 |
| T1082 | 系统信息发现 | `systeminfo`、`whoami /all` | 2.4 |
| T1057 | 进程发现 | `tasklist`、`Get-Process` | 2.4 |
| T1012 | 查询注册表 | `reg query` 命令；Sysmon 12/13 | 3.1 |
| T1083 | 文件与目录发现 | 大量 `dir` / `Get-ChildItem`；`where` | 2.4 |
| T1046 | 网络服务扫描 | 大量出站连接尝试；防火墙 5157 阻止日志 | 1.2 |
| T1135 | 网络共享发现 | `net share`、`net view` | 4.5 |
| T1518.001 | 安全软件发现 | 查询 Defender 状态的命令 | 6.10 |

### TA0008 横向移动（Lateral Movement）

| ID | 技术 | Windows 落地痕迹 | 落点 |
|---|---|---|---|
| T1021.001 | RDP | 4624 Type10；1149 含源 IP；`Default.rdp` | 4.3 / 4.5 |
| T1021.002 | SMB / 管理共享 | 5140/5145；`Get-SmbSession`；`net use` | 4.5 |
| T1021.003 | DCOM | `MMC20.Application` 等 COM 对象的远程调用 | 4.5 |
| T1021.006 | WinRM | WinRM/Operational 6/15/91；5985/5986 连接 | 4.5 |
| T1047 | WMI 远程执行 | WMI-Activity 5857/5858；`wmic /node:` | 4.5 |
| T1569.002 | 服务执行（PsExec） | PSEXESVC 服务与管道 | 4.5 |
| T1570 | 横向工具传输 | 出站 445 + 大文件写入 | 4.5 / 6.8 |
| T1550.002 | 哈希传递 | 4776；Type3 登录 | 4.3 |
| T1080 | 共享内容投毒 | 共享目录新增恶意文件 | 6.2 |

### TA0011 命令与控制（Command and Control）

| ID | 技术 | Windows 落地痕迹 | 落点 |
|---|---|---|---|
| T1071.001 | Web 协议 | 长连接 443/80；固定 UA；规律心跳 | 1.2 |
| T1071.004 | DNS | Sysmon 22；超长/高熵子域；DNS 缓存 | 1.3 |
| T1573 | 加密信道 | JA3 指纹异常；非浏览器进程发 TLS | 1.2 |
| T1090 | 代理 | `netsh portproxy`；系统代理被改；SOCKS 进程 | 1.5 |
| T1090.001 | 内部代理 | 内网主机做跳板 | 1.5 |
| T1572 | 协议隧道 | ICMP/DNS 隧道；`iodine`/`dnscat` | 1.2 |
| T1095 | 非应用层协议 | 自定义协议端口 | 1.2 |
| T1105 | 工具传输 | `certutil`/`bitsadmin`/`curl` 下载 | 附录 C |
| T1219 | 远程访问软件 | 见 8.4 | 8.4 |
| T1102 | Web 服务（合法站点） | 用 GitHub/Pastebin/Telegram 做 C2 | 1.2 |
| T1568 | 动态解析 | 域名快速切换（DGA/Fast Flux） | 1.3 |

### TA0010 外带（Exfiltration）与 TA0040 影响（Impact）

| ID | 技术 | Windows 落地痕迹 | 落点 |
|---|---|---|---|
| T1567 | 通过 Web 服务外带 | rclone/curl 上传；网盘客户端 | 6.8 |
| T1041 | 通过 C2 信道外带 | 上行流量异常（SRUM 可量化） | 5.3 / 6.8 |
| T1048.003 | 非 C2 协议外带 | FTP/TFTP/邮件外发 | 6.8 |
| T1052.001 | 物理介质外带 | USB 设备接入（注册表 USBSTOR） | 6.2 |
| T1486 | 加密数据以影响 | 高熵新扩展名；勒索信；`vssadmin delete` | 6.7 |
| T1490 | 阻止系统恢复 | `bcdedit /set recoveryenabled No`；删除快照；`wbadmin delete` | 6.7 |
| T1489 | 停止服务 | 关键服务被停（7034/7036） | 7.5 |
| T1485 | 数据销毁 | `cipher /w`、`sdelete`、格式化命令 | 6.7 |
| T1496 | 资源劫持（挖矿） | 高 CPU；`stratum` 连接；矿池端口 | 6.7 |
| T1491 | 篡改 | 桌面背景/网站内容被改 | 6.7 |

---

## 3. 权限维持手法全量核对清单（清后门必查）

> **这是本文最有实用价值的一节。**
> 排查时最危险的错误是"只清掉发现的那一个后门"。攻击者通常**同时布 3–5 个**，你清掉 1 个，他 10 分钟后回来。

**用法**：逐项打勾。任何一项"未核查"就代表清理未完成。

### A. 注册表类（14 项）

- [ ] `HKLM\...\CurrentVersion\Run` / `RunOnce` / `RunOnceEx` / `RunServices`
- [ ] `HKCU\...\CurrentVersion\Run` / `RunOnce`
- [ ] `HKLM\SOFTWARE\Wow6432Node\...\Run`（32 位视图，最容易漏）
- [ ] `HKLM/HKCU\...\Policies\Explorer\Run`
- [ ] `Winlogon\Shell`、`Userinit`、`Notify`、`Taskman`、`GinaDLL`
- [ ] `AppInit_DLLs`（含 Wow6432Node）+ `LoadAppInit_DLLs`
- [ ] `AppCertDlls`
- [ ] `Image File Execution Options\*\Debugger`（含 32 位视图）
- [ ] `SilentProcessExit\*\MonitorProcess`
- [ ] `Explorer\ShellServiceObjectDelayLoad`、`SharedTaskScheduler`
- [ ] `Active Setup\Installed Components\*\StubPath`
- [ ] `HKCU\Environment\UserInitMprLogonScript`
- [ ] `HKCU\Control Panel\Desktop\SCRNSAVE.EXE`
- [ ] `User Shell Folders\Startup` 被重定向

### B. 认证与安全组件类（8 项）

- [ ] `Lsa\Authentication Packages`
- [ ] `Lsa\Security Packages` / `Lsa\OSConfig\Security Packages` / `Lsa\MSV1_0`
- [ ] `Lsa\Notification Packages`（密码过滤器）
- [ ] `Control\SecurityProviders\SecurityProviders`
- [ ] Credential Providers 新增项
- [ ] SPP / SSP 相关 DLL 签名核查
- [ ] 新增的受信任根证书
- [ ] `Winlogon\SpecialAccounts\UserList` 隐藏账号

### C. 服务与驱动类（5 项）

- [ ] 非微软签名的服务
- [ ] `svchost` 服务的 `Parameters\ServiceDll` 指向异常
- [ ] `FailureCommand`（失败恢复命令）
- [ ] 服务 `PathName` 未加引号 + 含空格
- [ ] 恶意驱动 `.sys`（含 minifilter：`fltmc filters`）

### D. 计划任务类（5 项）

- [ ] 所有任务的 XML（导出后按时间排序）
- [ ] `<Hidden>true</Hidden>` 隐藏任务
- [ ] 动作指向 `powershell`/`mshta`/`cmd`/`rundll32` 等 LOLBin
- [ ] `TaskCache\Tasks` 注册表残留（XML 已删但注册表还在）
- [ ] `C:\Windows\System32\Tasks` 文件时间戳

### E. WMI 与 COM 类（4 项）

- [ ] `__EventFilter`
- [ ] `__EventConsumer`（尤其 `CommandLineEventConsumer`、`ActiveScriptEventConsumer`）
- [ ] `__FilterToConsumerBinding`
- [ ] HKCU 下的 CLSID 覆盖（InprocServer32 / LocalServer32 / TreatAs）

### F. 启动位置类（6 项）

- [ ] 用户启动文件夹 + 全局启动文件夹
- [ ] 启动文件夹内 `.lnk` 的目标与参数
- [ ] Office 启动目录（XLSTART、STARTUP、VbaProject.OTM）
- [ ] Office/浏览器加载项注册表
- [ ] 组策略脚本目录（`System32\GroupPolicy`）
- [ ] 第三方软件的自启（Autoruns 的 Logon/Explorer 类别）

### G. 网络与远程访问类（6 项）

- [ ] `netsh interface portproxy` 转发规则
- [ ] `HKLM\SOFTWARE\Microsoft\NetSh` Helper DLL
- [ ] Winsock LSP / Namespace Provider
- [ ] 系统/用户代理设置与 PAC 脚本
- [ ] RDP 配置（含 RDP Wrapper、termsrv.dll 改动）
- [ ] SSH 服务与 `administrators_authorized_keys`（Windows OpenSSH）
- [ ] 远控软件（TeamViewer/AnyDesk/ToDesk/向日葵）无人值守配置

### H. 其他（5 项）

- [ ] BITS 传输任务（`Get-BitsTransfer -AllUsers`）
- [ ] PowerShell `$PROFILE` 与机器级 profile
- [ ] WSL 发行版内的 Linux 侧持久化
- [ ] 容器与虚拟机
- [ ] `BootExecute` / `SetupExecute` / `S0InitialCommand`（Session Manager）

### 核对完成度自评

| 打勾数 | 结论 |
|---|---|
| < 40 | **清理未完成**，不可下结论 |
| 40–50 | 基本覆盖，需补做 Autoruns 交叉验证 |
| 全部 + Autoruns 二次导出无差异 | 可以认为持久化已清干净 |

---

## 4. 专项分析

### 4.1 勒索软件（Ransomware）

**现代勒索的攻击链**（2024–2026 主流）：

```
初始访问（VPN 漏洞 / RDP 弱口令 / 钓鱼 / 供应链）
  → 建立 C2（Cobalt Strike / Brute Ratel / Sliver / Havoc）
  → 侦察与提权（BloodHound、AD 信息收集）
  → 凭据窃取（LSASS dump、DCSync、NTDS）
  → 横向移动（PsExec / WMI / RDP 到多台主机）
  → 关闭杀软与日志（BYOVD 卸载 EDR、清日志）
  → 删除备份与卷影（vssadmin / wbadmin / ESXi 侧）
  → 数据外带（双重勒索，先偷后加密）
  → 批量加密（GPO 下发、PsExec 全网执行加密器）
```

**关键排查点**

```powershell
# 1) 加密前置命令（一条都不能漏）
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Message -match 'vssadmin.*delete shadows|wmic shadowcopy delete|wbadmin.*delete|bcdedit.*recoveryenabled.*No|bcdedit.*bootstatuspolicy|diskshadow|cipher /w|wevtutil cl|fsutil usn deletejournal' } |
  Select-Object TimeCreated,Message

# 2) EDR/杀软被卸载或驱动被利用（BYOVD）
Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} -MaxEvents 50 |
  Where-Object { $_.Message -match '\.sys|driver' } | Select-Object TimeCreated,Message

# 3) GPO 被用于批量下发（域环境）
Get-WinEvent -FilterHashtable @{LogName='Security';ID=5136} -MaxEvents 100 -EA SilentlyContinue |
  Where-Object { $_.Message -match 'gPCFileSysPath|ScheduledTasks|Scripts' } | Select-Object TimeCreated,Message

# 4) 备份系统是否被攻击（备份服务器、NAS、云存储）
#    - 备份软件账号是否被用于登录
#    - 备份目录是否有异常删除
#    - 云备份凭据是否等于主机上的凭据（重大风险）
```

**蓝队最重要的两件事**

1. **看备份还在不在**：`vssadmin list shadows`、`wbadmin get versions`、NAS 快照。备份是唯一能让"恢复"取代"付赎金"的东西。
2. **看数据是否已被外带**：现代勒索是"以披露为威胁"。即使用备份恢复，也需要评估数据泄露风险（`6.8` 的外带痕迹、上行流量）。

### 4.2 挖矿（Cryptomining）

| 维度 | 特征 |
|---|---|
| 进程 | 高 CPU/GPU 占用；进程名伪装成 `svchost`/`system`；父进程为服务或计划任务 |
| 命令行 | `--donate-level`、`stratum+tcp://`、`--url`、`--coin`、`--cpu-priority` |
| 文件 | `xmrig.exe`、`config.json`、`start.bat`、`pool.txt`、随机目录名 |
| 网络 | 连接矿池端口 3333/4444/5555/7777/9999/14444/45560 |
| 持久化 | 计划任务（每 5–30 分钟检查）、WMI 订阅、注册表 Run、服务 |
| 前置动作 | 关闭 Defender、添加排除项、卸载安全软件 |
| 常见载体 | Redis 未授权、Spring Boot Actuator、Weblogic、Log4j2、永恒之蓝、Web 漏洞 |

```powershell
# 快速定性（三个维度交叉）
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name,Id,CPU,Path
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'stratum|xmrig|--donate' } | Select-Object CommandLine
Get-NetTCPConnection -State Established | Where-Object { $_.RemotePort -in 3333,4444,5555,7777,9999,14444 } |
  Select-Object RemoteAddress,RemotePort,OwningProcess
```

### 4.3 无文件攻击（Fileless）

**核心特征**：磁盘上没有恶意可执行文件，载荷只存在于内存。

| 载体 | 痕迹 | 检测手段 |
|---|---|---|
| PowerShell 内存加载 | 4104 中的 `IEX`/`FromBase64String`/`Reflection.Assembly` | PowerShell 脚本块日志 |
| WMI 订阅执行 | `__EventFilter` + `CommandLineEventConsumer` | WMI 订阅枚举（3.4） |
| .NET 反射加载 | 进程模块列表中有无路径模块 | pe-sieve / HollowsHunter |
| 注册表存储载荷 | 大体积的 Base64 注册表值 | Sysmon 13 + 值长度异常 |
| 进程注入 / 镂空 | RWX 内存段、无映像文件的内存 | Volatility `malfind`、Sysmon 8/10/25 |
| 脚本宿主（mshta/regsvr32） | 命令行中的远程 URL | 4688 命令行 |
| 计划任务中的脚本 | Task XML 里内联脚本 | 任务 XML 导出 |
| WSL/Linux 侧 | WSL 里的进程与文件 | `wsl --list` + 进 WSL 查 |

**检测前提**（如果这些没开，无文件攻击基本无法还原）：

```powershell
# 检查这些开关（缺一个，检测能力就断一层）
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" |
  Select-Object EnableScriptBlockLogging                                    # 脚本块日志
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" |
  Select-Object ProcessCreationIncludeCmdLine_Enabled                       # 4688 带命令行
Get-Service Sysmon64,Sysmon -EA SilentlyContinue                           # Sysmon
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,BehaviorMonitorEnabled,AMSIProviderVersion
```

### 4.4 横向移动（Lateral Movement）

**判定"这台是不是跳板"的三个问题**

1. **它连出去了吗？** → 出站 445/135/3389/5985/22（4.5）
2. **它用谁的凭据连的？** → 4648 显式凭据、4624 Type3/Type9（4.3）
3. **留下的工具是什么？** → PSEXESVC、WMI 远程、Impacket 特征服务名

```powershell
# 横向移动工具特征一网打尽
# PsExec
Get-Service PSEXESVC -EA SilentlyContinue
Get-ChildItem "$env:SystemRoot\PSEXESVC.exe" -EA SilentlyContinue
Get-ChildItem "\\.\pipe\" -EA SilentlyContinue | Where-Object { $_.Name -match 'psexesvc|remcom' }

# Impacket（wmiexec / smbexec / atexec）：随机 8 位大写服务名
Get-CimInstance Win32_Service | Where-Object { $_.Name -match '^[A-Z0-9]{8}$' } |
  Select-Object Name,PathName,StartName,State

# 命名管道（Cobalt Strike 特征，Sysmon 17/18）
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -EA SilentlyContinue |
  Where-Object { $_.Id -in 17,18 } | Select-Object TimeCreated,Message -First 30

# 出站管理端口
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemotePort -in 445,135,139,3389,5985,5986,22,1433 } |
  Select-Object RemoteAddress,RemotePort,OwningProcess,
    @{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}}
```

### 4.5 凭据窃取手势速查

| 手法 | 命令行 / 行为特征 | 事件痕迹 |
|---|---|---|
| comsvcs MiniDump | `rundll32 comsvcs.dll, MiniDump <pid>` | Sysmon 10、4688 |
| procdump | `procdump -ma lsass.exe out.dmp` | Sysmon 10、文件落地 .dmp |
| 任务管理器 dump | `taskmgr` 对 lsass 右键创建转储 | 文件落地、Sysmon 10 |
| mimikatz | `sekurlsa::logonpasswords`、`privilege::debug` | 4104、Sysmon 11（mimikatz 落地） |
| Cobalt Strike | `mimikatz` 命令、`lsass` 的 `MiniDump` | 命名管道、Sysmon 10 |
| SSP 后门 | `mimilib.dll` 被写入 System32 并注册到 LSA | 3.5 的 Security Packages 变化 |
| DPAPI | 访问 `%APPDATA%\Microsoft\Protect` | 文件访问 |
| 浏览器 | 复制 `Login Data`、headless 启动浏览器 | 4688、文件写入 |
| 域控 | `ntdsutil` + `vssadmin`、`esentutl /y` | 4688、4662 |

```powershell
# 一条命令覆盖主要 dump 手法
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Message -match 'comsvcs|MiniDump|procdump|rundll32.*lsass|ntdsutil|esentutl /y|reg save.*SAM|reg save.*SECURITY|vssadmin create' } |
  Select-Object TimeCreated,Message
```

### 4.6 Webshell（IIS / ASP.NET 为主）

| 类型 | 特征 |
|---|---|
| 一句话式 | 极短文件，含 `Request["x"]` + `eval`/`Execute` |
| 大马 | 文件管理、命令执行、提权的完整功能界面 |
| 内存马（.NET Filter/Module） | **磁盘上没有文件**，通过 `Assembly.Load` 注入 w3wp |
| 反向代理型 | 转发流量到内网（`System.Net.Http` 相关） |
| 加密型 | 参数 Base64/AES 加密，`FromBase64String` + `AesManaged` |

**内存马排查（磁盘查不到，这是关键）**

```powershell
# w3wp 进程的模块 / 内存
Get-Process w3wp | Select-Object -ExpandProperty Modules |
  Where-Object { $_.FileName -notlike "$env:SystemRoot\Microsoft.NET*" -and
                 $_.FileName -notlike "$env:SystemRoot\Microsoft.NET\Framework*" }
# 用 pe-sieve 扫 w3wp（能发现内存中的 .NET 程序集）
# pe-sieve64.exe /pid <w3wp_PID> /out C:\IR\w3wp_sieve /shellc /data 3
# 用 HollowsHunter 全量
# hollows_hunter64.exe /out C:\IR\hollows /shellc /data 3

# 检查 IIS 全局模块（内存马常通过 httpModules 注入）
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" list modules
Get-Content "$env:SystemRoot\System32\inetsrv\config\applicationHost.config" |
  Select-String -Pattern '<add name=' -Context 0,1 | Select-String -Pattern 'type='

# 会话中仍然存在的异常上传（Web 日志）
Get-ChildItem "C:\inetpub\logs\LogFiles\W3SVC*" -Filter *.log -EA SilentlyContinue |
  Select-String -Pattern 'POST .*(\.aspx|\.ashx|\.asmx)' | Select-Object -First 30 Line
```

### 4.7 数据外带（Exfiltration）

| 手法 | 痕迹 |
|---|---|
| 打包外发 | `rar a -hp`、`7z a -p`、`makecab`、`Compress-Archive`、`tar` |
| 云盘/对象存储 | rclone、MEGAsync、OneDrive 的异常上传；`aws s3 cp`、`azcopy` |
| HTTP POST | `curl -F`、`Invoke-WebRequest -Method Post`、`Invoke-RestMethod` |
| 邮件 | SMTP 连接（25/465/587）；Outlook 发件箱异常 |
| DNS 隧道 | 高熵子域、大量 TXT/A 查询；Sysmon 22 |
| C2 信道 | 上行流量远大于下行（SRUM 可量化） |
| 物理 | USB 设备接入（注册表 `USBSTOR`） |

```powershell
# 量化外带：SRUM 让"某进程发了多少字节"可查
# SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat --csv C:\IR\srum
# 关注 NetworkUsages 表的 BytesSent（按应用/时间聚合）

# USB 使用记录（常被忽略的外带渠道）
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -EA SilentlyContinue |
  Select-Object PSChildName,FriendlyName
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational';ID=2003} -MaxEvents 20 -EA SilentlyContinue
```

### 4.8 痕迹清理与反取证（Anti-Forensics）

| 手法 | 痕迹（反过来说明攻击者成熟度高） |
|---|---|
| 清事件日志 | 1102、104；日志文件大小为 0 |
| 关日志/降日志大小 | 4719；`wevtutil sl /ms:` 改小 |
| 关 Prefetch / 清 Prefetch | `EnablePrefetcher=0`；Prefetch 目录为空 |
| 时间戳篡改 | Sysmon 2；MFT 中 SI/FN 时间不一致 |
| 删文件并覆写 | `sdelete`、`cipher /w`、`fsutil usn deletejournal` |
| 停用/卸载 Sysmon | Sysmon 事件 4；服务不存在 |
| 加 Defender 排除项 | 5007 |
| 删除卷影 | 8222；`vssadmin delete shadows` |
| 清理 WMI 仓库 | `__EventFilter` 被删但残留 `__Namespace` 痕迹 |
| 禁用恢复环境 | `bcdedit /set recoveryenabled No` |

```powershell
# 反取证行为的集中检测
$anti = 'wevtutil cl|Clear-EventLog|Remove-EventLog|auditpol /clear|wevtutil sl .* /ms:|fsutil usn deletejournal|vssadmin delete shadows|sdelete|cipher /w|bcdedit .* recoveryenabled|sc stop Sysmon|sc delete Sysmon|Set-MpPreference -Disable'
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 5000 -EA SilentlyContinue |
  Where-Object { $_.Message -match $anti } | Select-Object TimeCreated,Message
```

### 4.9 远控软件被滥用（Remote Monitoring & Management Abuse）

**这是近几年增长最快的"合法工具型"后门**，因为它：
- 有正规数字签名 → 杀软不报
- 是正常软件 → 白名单放行
- 自带完整远控功能 → 不需要写恶意代码

```powershell
# 判断"是业务在用还是攻击者装的"
# 1) 安装时间是否落在失陷窗口
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA SilentlyContinue |
  Where-Object { $_.DisplayName -match 'TeamViewer|AnyDesk|ToDesk|Sunlogin|RustDesk|Atera|ScreenConnect|Splashtop' } |
  Select-Object DisplayName,InstallDate,InstallLocation,Publisher

# 2) 是否配置为无人值守 / 固定密码（攻击者核心诉求）
Get-ItemProperty "HKLM:\SOFTWARE\TeamViewer" -EA SilentlyContinue |
  Select-Object ClientID,SecurityPasswordAES,LocalPasswordAES

# 3) 连接记录（谁在什么时候连过）
Get-Content "$env:ProgramData\TeamViewer\Connections_incoming.txt" -EA SilentlyContinue
Get-ChildItem "$env:ProgramData\AnyDesk\*.trace" -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 3 |
  ForEach-Object { Select-String $_.FullName -Pattern 'login|connection' | Select-Object -First 10 }

# 4) 是否被加到防火墙 / 开机自启
Get-NetFirewallRule | Where-Object { $_.DisplayName -match 'TeamViewer|AnyDesk|ToDesk|Sunlogin' }
```

---

## 5. 现象 → 最可能手法 → 下一步 速查表

| 你看到的现象 | 最可能的手法 | 下一步必查 |
|---|---|---|
| 有监听端口但 `netstat -ano` 里找不到进程 | 内核级 hook / rootkit | 2.6 多源比对 + Volatility `callbacks`/`ssdt` |
| `Get-Process` 和 `tasklist` 数量对不上 | 隐藏进程 | 2.1 差集 + 2.6 |
| 端口占用但没有进程持有 | 驱动级后门 / 端口转发 | 1.5 `netsh portproxy` |
| 系统里出现不明 DLL 加载到 svchost | ServiceDll 后门 | 3.2 |
| 每次登录都有命令行一闪而过 | Winlogon Shell/Userinit 或 Run 项 | 3.5 / 3.1 |
| 锁屏按 Shift 出命令行 | sethc 后门 | 3.6 |
| 杀软自动关闭 / 排除项莫名增加 | 攻击者前置动作，木马已到位 | 6.10 / 7.2 |
| 事件日志被清空但事务日志说明有活动 | 1102 | 7.2，转向内存与 MFT |
| 大量 4625 + 少量 4624 Type10 | RDP 暴破成功 | 4.3，查后续动作 |
| 4648 频繁出现在非管理时段 | 横向移动 | 4.5 |
| 4769 大量且加密类型为 RC4 | Kerberoasting | 4.5 |
| 4662 出现复制 GUID | DCSync，域已失陷 | 4.4 |
| 4688 里出现 `-enc` 长 Base64 | PowerShell 内存加载 | 2.4 / 5.6 |
| 4104 里有 `FromBase64String` + `Assembly.Load` | .NET 内存马 / C2 | 5.6 |
| `winword.exe` 起了 `powershell.exe` | 钓鱼宏 | 2.2 |
| `w3wp.exe` 起了 `cmd.exe` | Webshell | 6.6 / 8.2 |
| 高 CPU + 矿池端口连接 | 挖矿 | 6.7 |
| 文件扩展名被批量改写 + 勒索信 | 勒索 | 6.7，先看备份 |
| 卷影被删、恢复被禁用 | 勒索前置 | 6.7 |
| 主机 CPU 正常但外网流量大 | 数据外带 | 6.8 |
| 新增服务在 `%TEMP%` 路径 | 服务后门 | 3.2 |
| 计划任务在 GUI 里看不到但存在 | 隐藏任务 | 3.3 |
| `__EventFilter` 有条目 | WMI 后门 | 3.4 |
| 启动后自动连某 IP 且无进程对应 | 驱动或 WMI 订阅 | 3.4 / 2.6 |
| 主机上有 rclone / 云盘客户端且非业务需求 | 数据外带准备 | 6.8 |
| WSL 里有 cron / 未知进程 | 跨子系统持久化 | 3.11 |
| 时间戳早于系统安装时间 | 时间戳伪造 | 5.5 |
| `$Recycle.Bin` 里有大量刚删除的敏感文件 | 攻击者清理现场但留了回收站 | 5.4 |
| Prefetch 被清空但系统正常运行 | 反取证 | 5.1 / 4.8 |
| 远控软件无人值守 + 安装时间可疑 | 合法工具后门 | 8.4 / 4.9 |

---

## 6. 常见攻击工具与框架特征速查

> 用途：在主机上看到这些特征时，快速判断攻击者用的是什么，进而推断其能力等级与后续动作。

### 6.1 Cobalt Strike（商业 C2，使用最广）

| 维度 | 特征 |
|---|---|
| 默认端口 | Team Server 50050；Beacon 常用 80/443/8080/53/4444 |
| 命名管道 | `\\.\pipe\MSSE-<随机>`、`msagent_<随机>`、`postex_<随机>`、`status_<pid>`、`\<随机 4 字符>` |
| 进程注入 | 反射加载 beacon.dll（无文件）；常见注入目标 `rundll32`/`svchost`/`dllhost` |
| 命令行 | `powershell -nop -w hidden -enc <base64>`（默认 artifact） |
| 内存特征 | `beacon.x64.dll`、`ReflectiveLoader`、`MZ` 头在非映像内存 |
| Malleable C2 | 可通过 profile 伪装成正常流量（JA3/JA3S 指纹仍可识别） |
| 检测 | Sysmon 8/10/25、命名管道事件 17/18、内存扫 `malfind` |

```powershell
# 命名管道检测（最有效的 CS 识别手段）
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -EA SilentlyContinue |
  Where-Object { $_.Id -eq 17 -and $_.Message -match 'MSSE-|msagent_|postex_|status_' } |
  Select-Object TimeCreated,Message
# 也看 net 命名管道枚举
[System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match 'MSSE|msagent|postex|status_' }
```

### 6.2 mimikatz / 凭据窃取工具

| 特征 | 说明 |
|---|---|
| 文件名 | `mimikatz.exe`、`mimi.exe`、`Invoke-Mimikatz.ps1`、`kiwi.exe` |
| 模块名 | `mimilib.dll`（作为 SSP 持久化时会写入 System32 并注册到 LSA） |
| 命令行 | `sekurlsa::logonpasswords`、`privilege::debug`、`lsadump::dcsync`、`kerberos::golden` |
| 内存 | LSASS 内 `wdigest` / `kiwi` 特征字符串 |
| 变体 | SafetyKatz、SharpKatz、dumpert、Pypykatz、nanodump（现代免杀变体） |
| 检测 | Sysmon 10 访问 lsass + 4104 + 文件落地 |

### 6.3 其他高频工具

| 工具 | 类型 | 主机侧特征 |
|---|---|---|
| Impacket（wmiexec/smbexec/atexec/psexec.py） | 横向移动 | 随机 8 位大写服务名；`cmd.exe /Q /c echo` 包裹命令；命名管道 |
| PsExec | 横向移动 | `PSEXESVC` 服务、`C:\Windows\PSEXESVC.exe`、`\\.\pipe\psexesvc` |
| Meterpreter | C2 / 后门 | `met.dll`、`metsvc` 服务、端口 4444/443、`stdapi` 字符串 |
| Rubeus / Kerberoast 工具 | 凭据 | 4769 大量 RC4；`kerberoast` 字符串；`rubeus.exe` |
| SharpHound / BloodHound | 侦察 | 密集 LDAP 查询；`<日期>_BloodHound.zip`、`*.json` 采集文件 |
| Seatbelt / WinPEAS / SharpUp | 本地侦察 | 短时间大量系统查询命令 |
| Advanced IP Scanner / Nmap | 扫描 | 大量 ARP/连接尝试；防火墙 5157 阻止日志 |
| PsInfo / kPortScan | 扫描 | 同上网 |
| AdvancedRun / NSudo | 提权执行 | 以 SYSTEM 启动任意进程 |
| Process Hacker / System Informer | 工具滥用 | 被用于终止安全进程 |
| AnyDesk/TeamViewer | 远控 | 见 8.4 |
| WinSCP / FileZilla / PuTTY | 外带/跳板 | 保存的会话凭据；SCP/FTP 出站连接 |
| ngrok / frp / chisel / gost | 隧道 | 进程名与配置文件；出站长连接 |
| Sliver / Havoc / Brute Ratel / Nighthawk | 新一代 C2 | 命名管道、mTLS、伪装成合法进程 |
| BYOVD 驱动（如 `RTCore64.sys`、`dbutil_2_3.sys`） | 关 EDR | 已知易受攻击驱动被加载到 System32\drivers |

---

## 7. 现代攻防趋势与新技术（2024–2026）

> 这一节的意义：**让排查清单跟上攻击者的演进**。以下是近年最值得关注的变化。

### 7.1 攻击侧的新变化

| 趋势 | 具体表现 | 对排查的影响 |
|---|---|---|
| **Ransomware-as-a-Service 工业化** | 勒索团伙分工（初始访问代理 → 提权 → 谈判）；双重/三重勒索 | 加密前必然有长时间潜伏与数据外带，早期痕迹（初始访问 2–30 天前）是重点 |
| **EDR 规避成为标配** | BYOVD 加载易受攻击驱动卸载 EDR；直接内核回调篡改；ETW 补丁 | 主机上看不到 EDR 进程 = 强信号；需查 `driverquery`、`fltmc`、内核回调 |
| **LOLBins + 无文件组合** | 避开落盘，只用系统自带组件 | 没有 Sysmon/4104/4688 命令行 = 几乎无法还原 |
| **合法远程管理工具滥用** | AnyDesk/TeamViewer/Atera/ScreenConnect | 白名单策略失效，必须结合"业务是否申请过"判断 |
| **Cobalt Strike 替代品兴起** | Sliver（开源）、Havoc、Brute Ratel、Nighthawk | 传统 CS 特征（命名管道/默认端口）失效，需靠行为检测 |
| **供应链与身份攻击** | 签名的恶意更新包；云身份（Entra ID）被顶替；OAuth 应用后门 | 主机排查之外要查云侧登录日志与 OAuth 授权 |
| **WSL / 容器成为新藏身处** | 后门放在 WSL 发行版内，Windows 侧看不到 | 必须 `wsl --list` 并进 Linux 侧查（3.11） |
| **AI 辅助攻击** | AI 生成钓鱼文本/深伪语音；自动生成免杀代码 | 社工识别难度上升；检测重心后移到"行为"而非"内容" |
| **Hypervisor / UEFI 层攻击** | Bootkit、固件级持久化 | 常规重装无效，需查固件与安全启动状态 |

### 7.2 检测侧的新技术（蓝队该用的）

| 技术 | 说明 | 落地建议 |
|---|---|---|
| **Sysmon + 社区配置** | Windows 上最高性价比的端点遥测 | 部署 `olafhartong/sysmon-modular` 或 SwiftOnSecurity 配置，并按业务裁剪 |
| **Sigma 规则（社区检测规则标准）** | 跨 SIEM 通用的检测规则格式 | 用 Chainsaw / Hayabusa / Zircolite 直接跑，等于自带数千条检测逻辑 |
| **EDR / XDR 遥测** | 进程树、内存、内核回调级别的可见性 | 排查时优先从 EDR 控制台取时间线，比手工快一个数量级 |
| **ETW（事件追踪）** | 内核与用户态的统一遥测总线 | 高级检测使用；注意攻击者会 patch ETW |
| **AMSI 日志** | 脚本内容在内存中被扫描的记录 | Defender 1116/1117 + AMSI 提供商事件 |
| **Windows Defender ASR** | 行为层的攻击阻断规则 | 见主手册 6.10 的 15 条规则清单 |
| **WDAC / AppLocker** | 应用白名单，从源头阻止未授权执行 | 先审计模式运行 2–4 周再强制 |
| **WEF + 集中日志** | 本机日志被清仍可追 | 关键：**必须在失陷前就配好** |
| **威胁情报 + IOC 匹配** | 哈希/域名/IP/证书指纹 | 与内存镜像、Prefetch、DNS 缓存批量比对 |
| **威胁狩猎（Threat Hunting）** | 主动假设已被入侵，用假设驱动查询 | 用上面的检测工具 + ATT&CK 覆盖度自评 |
| **Velociraptor / osquery** | 跨端点批量查询（VQL / SQL） | 一台命令查全网同类痕迹 |
| **日志时间线工具** | Chainsaw / Hayabusa / Timeline Explorer / Timesketch | 把海量日志变成可读的攻击叙事 |
| **基线即代码** | HardeningKitty、Microsoft Security Compliance Toolkit、Intune 基线 | 把加固从"人工检查"变成"可重复执行的检查" |

### 7.3 蓝队能力自评（用 ATT&CK 覆盖度）

排查结束后，用下表自评"这台主机我到底能看见多少"：

| 能力层 | 有 = 能查 | 无 = 查不到 |
|---|---|---|
| 进程创建（含命令行） | 4688 带命令行 / Sysmon 1 | 只能看到进程名 |
| 脚本内容 | PowerShell 4104 + Transcription | 无文件攻击完全无法还原 |
| 网络连接 | Sysmon 3/22 + 防火墙日志 | 只能看当前连接快照 |
| 注册表持久化 | Sysmon 12/13/14 | 只能看当前状态，看不到"何时被改" |
| 凭据访问 | Sysmon 10 | 只能靠事后推断 |
| 日志外发 | WEF / SIEM | 本机日志被清 = 证据归零 |
| 内存取证 | 有采集工具 + 流程 | 无文件攻击与内存马无法验证 |
| 端点（EDR） | 有且未被卸载 | 排查效率与覆盖面大幅下降 |

**结论**：主机应急排查的上限，由**失陷前**的可见性配置决定。响应阶段能做的是"把已有数据用到极致"，但补不上"数据从来没被记录"的缺口。这也是为什么每次响应结束都要回到加固（主手册 9.6）。

---

> **配套文档**：
> - `windows-host-audit.md` —— 现场排查命令手册（主手册）
> - `windows-hardening.md` —— 加固基线与核查项
> - `windows-forensics-toolchain.md` —— 现代工具链与获取方式
> - `../scripts/windows-ir-quickcheck.ps1` —— 一键只读采集
