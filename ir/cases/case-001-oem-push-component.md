# 案例 001 · OEM 预装推送组件被误判为反向连接

> **案例类型**：误报排除（False Positive Elimination）
> **平台**：Windows 10/11
> **关联**：`windows/windows-manual-steps.md` 第 1–3 步、第 6 步；`mcp/rules/triage-rules.yaml` 的 `NET-002`
>
> **本案例的价值不在于结论，而在于它记录了一次判断被推翻的过程。**
> 初始判断依据「103 段属亚太、常见于港新」+「非标准端口」得出"疑似境外 C2"，
> 最终被 RDAP 归属与数字签名推翻。**把"猜错了"连同纠正过程一起记下来，才是有用的案例。**

---

## 1. 初始发现与误判

受检主机在例行出向连接排查中，发现一个进程与某公网 IP 的非标准端口存在间歇性连接。

**初始怀疑**的三条依据：

1. 连接形态是**客户端主动连出、服务器可反向下发内容** —— 与反弹连接外观一致
2. 目标端口 `3000` 非标准服务端口
3. 目标 IP 首段为 `103`，凭经验归入"亚太境外地址段"

**这三条里，第 3 条是错的**，而且是最致命的一条。见 §5 的方法论教训。

## 2. 定性：六维对比表

「连境外」「端口奇怪」只是**线索**，不是**证据**。定性必须落到硬证据上。
下表是本例与真实反向连接 / 反弹 Shell 的逐项对照：

| 判据 | 真正的反连 / 反弹 Shell | 本例实际情况 |
|---|---|---|
| 文件位置 | 藏在 `Temp`、`AppData`、用户目录 | `C:\Program Files (x86)\<OEM>\<Component>\`，规范安装目录 |
| 数字签名 | 无签名或伪造签名 | **有效签名**，签名者 CN 为该 OEM 法人主体，DigiCert 颁发 |
| 目标 IP | 陌生境外 IP、VPS、家庭宽带 | **厂商自有 ASN**，RDAP 可查，段名与厂商对应 |
| 端口 | 4444 / 6666 / 8080 等典型远控端口 | `3000`，MQTT 自定义 broker 端口 |
| 父进程 | Word / Excel / WPS / 脚本宿主 | Windows 服务宿主（由服务拉起） |
| 子进程行为 | 拉起 `cmd` / `powershell`，无文件落地执行 | 只派生自身组件，无 shell 派生 |

六项全部落在"正常"侧 → 结案。

## 3. 它到底是什么：整目录拆解

**看一个组件不能只看主程序，要看它同目录下带了哪些"同伴"——同伴决定了它的能力边界。**
该目录内 10 个文件的分工：

> 为便于理解，以下使用真实文件命名模式但隐去厂商前缀（统一记为 `<OEM>` / `<Component>`）。

| 文件 | 作用 |
|---|---|
| `<Component>Service.exe` | 服务本体，注册为 Windows 服务，负责开机拉起主程序 |
| `<Component>.exe` | 主程序，消息推送中间件——服务器向客户端下发消息的通道 |
| `<Log>.dll` | 日志记录模块，把程序自身运行状态与心跳回报服务器 |
| `<Component>Prot.exe` | 驱动保护组件的安装 / 卸载程序 |
| `ProtectDrvSDK.dll` | 应用层（R3）与内核层（R0）通信模块 |
| `<drv>.sys` | **内核驱动（R0）**，实现进程 / 文件 / 注册表保护——这是它难以卸载的根源 |
| `*Sdk.dll` + `<Account>.exe` | 厂商账号管理 SDK 与账号管理组件 |
| `ipc.dll`、`<Component>DB.db`、`uninstall.exe` | 进程间通信、本地数据库、卸载程序 |

> **关键观察**：出现 `.sys` 驱动文件要特别留意——那意味着该组件具备内核权限，也能自我保护。
> 主程序名字无害，**不代表它带的驱动无害**。

## 4. 为什么会去连那个 IP：三条原因

1. **推送通道需要长连接。** 同厂商目录下存在 `mqtt-ca.pem` 与 `MessagingPlugin.exe`（示例名） —— 标准的
   **MQTT over TLS** 消息推送客户端。MQTT 客户端主动连出并保持在线，服务器随时可下发消息。
   `3000` 只是自定义的非标准 broker 端口。
2. **周期性心跳 + 运行日志。** 日志模块定时回报运行状态，因此连接**间歇出现、时连时断**，
   不是 24 小时常连（复查时该连接不存在）。
3. **账号相关连通性检查。** 账号组件在用户未登录厂商账号时也会做基础连通性检查。

## 5. 方法论教训（本案例最该看的一节）

### 教训一：IP 归属必须查，不能猜

`103` 段既可能分给中国香港、新加坡，也可能分给北京的厂商自有机房。
**凭 IP 首段数字猜归属地，是本次误判的直接原因。**

正确做法——至少两个源交叉验证：

```bash
curl https://ipinfo.io/<IP>/json
curl https://rdap.apnic.net/ip/<IP>      # 亚太地址段，最权威
curl https://rdap.arin.net/ip/<IP>       # 美洲段
curl https://rdap.ripe.net/ip/<IP>       # 欧洲段
```

看三个字段：`org`（归属组织）、`country`（注册国）、`name`（段名）。

### 教训二：端口指纹只能当线索

同一次排查中还出现过「某端口 = BT 下载软件」的误判。端口是可自定义的，**指纹价值远低于常识想象**。
定性的三样硬东西是：**文件路径、数字签名、IP 的 ASN 归属**。

### 教训三：「像反连」不等于「是反连」

推送、升级、遥测都会做长连接外连。区分点在**父进程、签名、文件位置、IP 归属**这四项硬证据上，
而不是连接形态。

## 6. 通用排查九步（可复用）

以下每条均可直接执行。以可疑 PID 为例（此处记为 `<PID>`）：

```powershell
# 1. 由 PID 定位进程和路径
Get-Process -Id <PID> | Select-Object Id,ProcessName,Path | Format-List

# 2. 看版本信息里的厂商和用途
(Get-Item "进程完整路径").VersionInfo |
  Select-Object CompanyName,FileDescription,ProductName,FileVersion | Format-List

# 3. 验数字签名（最关键的一步）
Get-AuthenticodeSignature "进程完整路径" |
  Select-Object Status,@{n='签名者';e={$_.SignerCertificate.Subject}} | Format-List
# Status = Valid 且签名者为知名厂商 → 基本可排除伪装

# 4. 看同目录同伴（找驱动、找 DLL、找服务）
Get-ChildItem "进程所在目录" -Recurse | Select-Object Name,Length | Format-Table -AutoSize

# 5. 看服务与计划任务
Get-CimInstance Win32_Service |
  Where-Object {$_.PathName -like "*关键字*"} |
  Select-Object Name,State,StartMode,PathName | Format-List
Get-ScheduledTask | Where-Object {$_.TaskPath -like "*关键字*"} | Select-Object TaskName,State

# 6. 看父进程和命令行（木马最常在这里露馅）
Get-CimInstance Win32_Process -Filter "ProcessId=<PID>" |
  Select-Object ProcessId,ParentProcessId,CommandLine | Format-List
# 重点：父进程是不是 Office / 浏览器 / 脚本宿主

# 7. 看当前连接
Get-NetTCPConnection -OwningProcess <PID> |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | Format-Table -AutoSize

# 8. 查 IP 归属（见 §5 教训一，至少两个源）

# 9. 哈希复核（可选）
Get-FileHash "进程完整路径" -Algorithm SHA256
# 提交 VirusTotal 看多引擎结果。注意：厂商自家组件也可能有个别引擎误报，
# 看的是整体比例而非单引擎。
```

## 7. 处置结论

**安全上无需处置**：官方签名组件，无隐私窃取行为（该结论与公开逆向分析一致，见 §8）。

若因资产治理需要移除，注意两点：

- 该组件带**内核驱动做自我保护**，普通模式下直接删除易触发系统异常，**不要硬删驱动文件**
- 卸载主程序时该组件**不会跟随删除**，属卸载残留，需单独处理

推荐顺序：先在「应用和功能」中正常卸载主程序 → 重启 → 安全模式下重命名残留目录 → 重启后删除。

## 8. 结论可复现性说明

本案例关于「无隐私窃取、无云控、无自动更新」的判断，与公开技术分析结论一致
（该分析通过逆向定位代码并解密了上报内容）。**这不是基于组件名称的推测，而是有逆向证据的公开结论。**

---

## 附 · 本案例的脱敏处理

本文由真实排查记录改写为教学案例，遵循 `README.md` 的案例脱敏规范：

| 原文信息 | 处理方式 | 理由 |
|---|---|---|
| 涉事主机名、用户名、内网地址 | 原文未涉及，无需处理 | 排查记录本身未采集 |
| 外连目标 IP | 原文为厂商自有公网服务器地址，**非涉事主机资产**，RDAP 可公开验证 | 保留其 ASN 归属结论，隐去具体数值 |
| PID、版本号等运行时细节 | 保留（PID）／泛化（版本号） | PID 无身份关联性；版本号非分析必需 |
| 第一人称叙事（"你当时""上一轮我"） | 全部改为中性案例体 | 去除对话语境，转为可复用文档 |
| 厂商与产品名 | 泛化为 `<OEM>` / `<Component>` | **避免对特定厂商作公开定性表述**，同时保留分析结构 |

> 判断一个组件是否为恶意，**依据的是路径、签名、ASN 三项硬证据，而不是它的名字**。
> 名字可以伪造，这三项不能。
