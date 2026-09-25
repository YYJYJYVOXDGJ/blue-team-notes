# Windows 手工排查分步手册

> 与 `scripts/windows-ir-quickcheck.ps1` 的关系：脚本用于**批量取证留证**，本文用于**现场逐条研判**。
> 两者不是替代关系。

## 为什么还要手工敲命令

一键脚本会批量调用几十条系统查询命令——**这和木马（信息窃取类）的行为特征几乎一模一样**，
因此杀软 / 浏览器按启发式规则直接查杀。那不是脚本有毒，是它"长得像"。

手工敲命令的价值在于：**每条命令你都看得见它在干什么，没有黑盒**。
在已失陷或高度可疑的主机上，这条性质比效率更重要。

## 三条总则

1. **看不懂的先别删。** 删错系统文件比留着可疑文件麻烦十倍。可疑项先记录，再隔离或上报。
2. **发现可疑 ≠ 已经中招。** Windows 上"看起来奇怪但正常"的东西非常多，本文每步都给出判据，对照着看。
3. **任何一步结果拿不准，就把输出提交给分析人员。** 不要凭感觉处置。

## 准备工作

- **CMD**：开始菜单搜 `cmd` → 右键 → **以管理员身份运行**
- **PowerShell**：开始菜单搜 `PowerShell` → 右键 → **以管理员身份运行**

命令行窗口里右键即为粘贴。**大部分步骤用 CMD，只有第 3 步必须用 PowerShell。**

---

## 第 1 步 · 看网络有没有在偷偷外连（CMD）

```cmd
netstat -ano
```

看四列：本地地址、外部地址、状态、PID（进程号）。只看"已建立连接"可大幅缩短输出：

```cmd
netstat -ano | findstr ESTABLISHED
```

| 正常 | 可疑 |
|---|---|
| 外部端口是 443（HTTPS）或 80，来自常见服务 | 端口是 4444、5555、6666、8080、9001 这类，或纯 IP 无域名 |
| 外部 IP 属于已知大型厂商 ASN | 连到陌生境外 IP，或端口是远控常用端口 |
| 关掉所有程序后连接数明显下降 | 什么都关了还有稳定外连 |

快速统计哪个外部 IP 连得最多（PowerShell）：

```powershell
powershell -NoProfile -Command "Get-NetTCPConnection | Where-Object State -eq Established | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 15 Count,Name | Format-Table -AutoSize"
```

## 第 2 步 · 用 PID 反查是哪个程序（CMD）

把第 1 步记下的可疑 PID（如 `4820`）填进去：

```cmd
tasklist | findstr 4820
tasklist /svc | findstr 4820
```

- **正常**：`chrome.exe`、`msedge.exe`、`SearchApp.exe`、`OneDrive.exe` 这类认识的进程
- **可疑**：随机字符串名（`a8f3c2.exe`）、伪装系统名（`WinUpdater.exe`）

看到可疑名字先别删，记下完整路径（下一步能拿到）。

## 第 3 步 · 看命令行和父进程（**必须用 PowerShell**，最关键）

CMD 的 `tasklist` 看不到命令行，而 `wmic` 在新版 Windows 上已被移除，因此这一步只能走 PowerShell。

```powershell
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Format-List"
```

| 检查项 | 正常 | 可疑 |
|---|---|---|
| 父进程 | `explorer.exe` 父进程是自身或 `wininit.exe`；`cmd.exe` 是自己打开的 | `cmd.exe` / `powershell.exe` 的父进程是 `winword.exe`、`excel.exe`、`outlook.exe` —— 说明由附件触发 |
| 路径 | 系统进程在 `C:\Windows\System32\` 下 | `svchost.exe`、`conhost.exe`、`lsass.exe` 出现在 `C:\Users\<用户>\AppData\` 或 `C:\ProgramData\` 下 —— 一定是假的 |
| 命令行 | 清晰的程序路径与参数 | 一大串乱码 / base64（结尾常带 `==`），或 `-enc`、`-e` 参数 —— 典型无文件攻击 |

输出会很长，重点扫这几类名字（木马惯用的 LOLBins）：
`cmd`、`powershell`、`wscript`、`cscript`、`rundll32`、`regsvr32`、`mshta`、`installutil`。

## 第 4 步 · 查启动项（CMD）

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
```

- **正常**：路径在 `C:\Program Files\` 或 `C:\Program Files (x86)\` 下
- **可疑**：路径指向 `AppData`、`Temp`、`ProgramData`、`Public`

再看两个启动文件夹：

```cmd
dir /a /b "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
dir /a /b "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"
```

正常情况下应为空或只有一两个认识的快捷方式。出现陌生 `.exe` / `.vbs` / `.js` 需重点核查。

## 第 5 步 · 查计划任务（木马最爱藏这里，CMD）

```cmd
schtasks /query /fo TABLE /nh
```

重点找两类：**名字是随机串**，或**故意模仿系统名**（如 `WindowsUpdateCheck`、`AdobeFlashUpdate`）。

找到可疑名字后看详情：

```cmd
schtasks /query /fo LIST /v | findstr /i "TaskName 任务名"
```

也可在「任务计划程序」中展开"任务计划程序库"，直接看"任务要执行的操作"里跑的是什么程序——
**路径在 `AppData` / `Temp` 下的一律可疑**。

## 第 6 步 · 查服务（PowerShell）

只看非微软的，输出短：

```powershell
powershell -NoProfile -Command "Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch 'Windows|Microsoft|svchost' } | Select-Object Name,DisplayName,State,StartMode,PathName | Format-List"
```

判据：服务对应 exe 应在 `Program Files` 下。
**路径在 `AppData`、`Temp`、`Public` 下，或文件名是随机串 → 可疑。**
显示名、描述、制造商均为空的"三无服务"也要留意。

## 第 7 步 · 查最近有没有掉东西进来（CMD）

```cmd
:: 最近下载，按时间倒序
dir /a /b /o-d "%USERPROFILE%\Downloads"
:: 临时目录里的可执行文件
dir /a /b "%TEMP%\*.exe"
dir /a /b "%TEMP%\*.dll"
dir /a /b "%windir%\Temp\*.exe"
```

- **高度可疑**：随机字符串名（`ms5Xk2.exe`）、伪装系统名（`svchost.exe` 出现在 Temp）
- **高度可疑**：图标看似 PDF/Word，实际后缀是 `.exe`、`.scr`、`.js`
  （需先在文件夹选项中打开"显示文件扩展名"）

## 第 8 步 · 查有没有被新建后门账号（CMD）

```cmd
net user
net localgroup administrators
net localgroup "Remote Desktop Users"
```

- 默认应存在的账号：`Administrator`、`Guest`（通常禁用）、`DefaultAccount`、`WDAGUtilityAccount`，加上自己的账号
- 管理员组里应只有自己（和 `Administrator`）
- 出现陌生账号（尤其是非 `$` 结尾的英文名）→ 可疑

查看某账号最近是否被改过密码：

```cmd
net user 用户名
```

看"密码上次设置时间"，不是自己改的就要警惕。

## 第 9 步 · 查远程通道有没有被打开（CMD）

```cmd
:: fDenyTSConnections = 1 表示关闭远程桌面，这是安全的
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
netstat -ano | findstr :3389
net share
```

- `fDenyTSConnections` 为 `0x1` 才是关闭状态
- `net share` 除默认 `IPC$`、`ADMIN$`、`C$` 外多出来的共享目录，要问一句是谁开的

再手动确认有没有被装远控软件：「设置 → 应用 → 已安装的应用」，搜索
`AnyDesk`、`TeamViewer`、`ToDesk`、`向日葵`、`RustDesk`、`Ammyy`。**不记得装过的，就是问题。**

## 第 10 步 · 查流量有没有被劫持（CMD）

```cmd
type %windir%\System32\drivers\etc\hosts
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | findstr /i Proxy
netsh winhttp show proxy
```

- hosts 文件正常情况下全是 `#` 开头的注释行。**任何把金融 / 邮箱 / 招聘类站点指向某个 IP 的记录，都是恶意的**
- `ProxyEnable` 应为 `0x0`；`ProxyServer` 有值但从未配置过代理 → 可疑（流量经过别人的服务器）

## 第 11 步 · 查登录日志（CMD）

```cmd
wevtutil qe Security /rd:true /c:40 /f:text /q:"*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4732)]]"
```

| 事件 ID | 含义 | 什么情况要警惕 |
|---|---|---|
| 4624 | 登录成功 | 深夜时段、陌生用户名、来源 IP 非本机 |
| 4625 | 登录失败 | 短时间内大量失败 = 有人在撞密码 |
| 4720 | 新建账号 | **任何非预期的创建都要立刻重视** |
| 4732 | 被加入管理员组 | **同上，这是提权动作** |

输出中 `Account Name` 是账号，`Logon Type` 里 3 和 10 代表远程登录（10 是远程桌面）。

## 第 12 步 · 杀毒和系统修复（CMD，管理员）

前面 11 步都是"看"，这一步才动手。

```cmd
:: 快速扫描（几分钟）
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 1
:: 全盘扫描（1–3 小时）
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 2

sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth
```

装了第三方杀软就用它的全盘扫。**扫出的威胁让它"隔离"，不要直接删除**——隔离还能还原，删错了就没了。

---

## 附 A · 常见正常进程白名单（别自己吓自己）

| 进程名 | 是什么 |
|---|---|
| `svchost.exe` | Windows 服务宿主，会有十几个，**路径必须在 System32 下** |
| `csrss.exe` / `wininit.exe` / `winlogon.exe` / `lsass.exe` | 系统核心进程，路径必须在 System32 下 |
| `MsMpEng.exe` / `NisSrv.exe` | Windows Defender 本体 |
| `SearchApp.exe` / `SearchIndexer.exe` | Windows 搜索与索引 |
| `OneDrive.exe` / `PhoneExperienceHost.exe` | 微软云盘、手机连接 |
| `YourPhone.exe` / `Widgets.exe` / `TextInputHost.exe` | 系统自带功能组件 |
| `chrome.exe` / `msedge.exe` / `firefox.exe` | 浏览器，进程多、连接多，正常 |
| `WUDFHost.exe` / `RuntimeBroker.exe` / `ShellExperienceHost.exe` | 系统框架进程 |
| `DLLHost.exe` / `Taskmgr.exe` / `ctfmon.exe` | COM 宿主、任务管理器、输入法 |
| `spoolsv.exe` | 打印服务（不用打印机也可能开着） |

> **唯一铁律：看路径。** 这些名字出现在 `C:\Windows\System32\` 下就是正常的；
> 同样的名字出现在 `AppData`、`Temp`、`ProgramData` 下，一律是伪装。

## 附 B · 发现可疑之后怎么办

1. **不要直接删。** 先截图 / 复制完整路径记录下来
2. **先断网**（拔网线或关 WiFi），防止继续通信
3. **查文件底细**：把文件哈希提交 VirusTotal 检索（只算哈希即可，不必上传整文件）
4. **算哈希**（CMD）：`certutil -hashfile "完整路径\文件名.exe" SHA256`
5. **让杀软处理**而不是手动删。手动删容易删不干净，还有自启动项会把它拉回来
6. **确认中招**：用手机改所有密码，再考虑重装系统（重要文件先备份，备份文件也要先杀毒）

## 附 C · 十分钟极简版

1. 可疑邮件删除 / 拉黑，**不点任何东西**
2. **用手机**改邮箱密码 + 开二次验证
3. 邮箱设置里检查**自动转发和收信规则**（钓鱼最常见的后手）
4. 梳理同密码的其他账号并全部改掉
5. 跑 `netstat -ano | findstr ESTABLISHED`，看有无陌生外连
6. 跑一次杀软全盘扫描

---

> 本文所有命令均为系统自带工具，只读为主；第 12 步涉及扫描与修复，执行前建议先备份重要数据。
> 拿不准的结果不要自行处置，把输出提交给分析人员研判。
