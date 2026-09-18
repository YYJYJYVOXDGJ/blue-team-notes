# Windows 应急与取证工具链（现代工具）

> 定位：**主手册第 10 章与附录 B 的展开**。回答"用什么工具、从哪拿、怎么用、离线能不能跑"。
> 选型原则：**优先开源自带运行时的、优先单文件便携的、优先社区验证过的、优先离线可用的**。

## 目录

- [1. 工具选型原则](#1-工具选型原则)
- [2. 工具清单（按用途分类）](#2-工具清单按用途分类)
- [3. 典型工作流](#3-典型工作流)
- [4. 离线应急 U 盘准备清单](#4-离线应急-u-盘准备清单)
- [5. 与 AI Agent / MCP 结合的自动化巡检](#5-与-ai-agent--mcp-结合的自动化巡检)
- [6. 值得关注的检测新技术](#6-值得关注的检测新技术)

---

## 1. 工具选型原则

| 原则 | 原因 |
|---|---|
| **自带运行时 / 单文件便携** | 失陷主机上装不了东西；不能依赖目标机的 .NET/Python 版本；避免落地依赖被篡改 |
| **静态编译（Go / Rust）** | Chainsaw、Hayabusa、Velociraptor 都是这类，无外部依赖，抗 DLL 劫持 |
| **只读优先** | 采集阶段绝不应修改目标系统状态（写入会污染时间戳与日志） |
| **多源交叉** | 不用单一工具下结论；系统自带工具可能被劫持（用 Velociraptor/静态工具交叉验证） |
| **可校验** | 每个工具都要能核对哈希与签名（工具本身也可能被替换） |
| **授权明确** | 涉及外发数据的工具（VirusTotal、云沙箱）必须先获得数据外发授权 |

**风险提示**：本清单中标注 ⚠️ 的工具**会把数据发送到互联网**（VirusTotal、沙箱等）。在涉密或受合规约束的环境中使用前，必须有书面授权。

---

## 2. 工具清单（按用途分类）

### 2.1 实时响应与批量采集

| 工具 | 用途 | 获取 | 备注 |
|---|---|---|---|
| **Velociraptor** | 端点活体取证与查询（VQL），支持全网批量 | github.com/Velocidex/velociraptor | 单文件；可做 Offline Collector 一键打包；**首选** |
| **KAPE** | 采集 + 解析一体化（Kroll Artifact Parser and Extractor） | kroll.com（搜索 KAPE） | 有 GUI 与 CLI；自带目标文件清单 |
| **CyLR** | .NET 单文件快速采集（含 $MFT、$UsnJrnl、事件日志） | github.com/orlikoski/CyLR | 单文件；适合 U 盘即插即用 |
| **FastIR Collector** | 轻量主机信息采集 | github.com/SekoiaLab/Fastir_Collector | 脚本化，产物结构化 |
| **LiveResponseCollection** | 批处理采集脚本集 | github.com/ArsenalRecon/LiveResponseCollection-Cedarpelta | 老牌，覆盖面广 |
| **osquery** | 用 SQL 查询系统状态 | osquery.io | 适合长期巡检而非单次应急 |
| **psr.exe**（内置） | 操作录制（问题步骤记录器） | Windows 自带 | 现场记录操作过程 |

### 2.2 内存取证

| 工具 | 用途 | 获取 | 备注 |
|---|---|---|---|
| **WinPmem** | 内存采集（驱动 + raw 格式） | github.com/Velocidex/WinPmem | Volatility3 直接可解析 |
| **Magnet RAM Capture** | 内存采集（GUI，现场友好） | magnetforensics.com（免费工具） | 适合非技术人员操作 |
| **Volatility 3** | 内存分析（进程/注入/凭据/内核） | github.com/volatilityfoundation/volatility3 | Python；插件见主手册 2.7 |
| **MemProcFS** | **把内存镜像挂载成文件系统** | github.com/ufrisk/MemProcFS | 极大提升分析效率；同时提供 API |
| **WinDbg** | 内核调试与内存深挖 | Microsoft Store / SDK | 高级分析 |
| **DumpIt / Belkasoft RAM Capturer** | 一键内存镜像 | 各自官网（Belkasoft 免费） | 现场快速固定内存 |

### 2.3 Sysinternals 全家桶（微软官方，必带）

获取：https://learn.microsoft.com/sysinternals/ （单个 exe，可离线拷贝）

| 工具 | 用途 | 应急必备度 |
|---|---|---|
| **Autoruns / autorunsc** | 持久化全量（50+ 位置） | ★★★★★ |
| **Process Explorer** | 进程树、句柄、VirusTotal 集成 | ★★★★★ |
| **Process Monitor (Procmon)** | 实时监控文件/注册表/网络行为 | ★★★★★ |
| **TCPView** | 实时连接与进程对应 | ★★★★☆ |
| **Sigcheck** | 签名校验、VirusTotal 查询 ⚠️ | ★★★★★ |
| **PsExec** | 远程执行、以 SYSTEM 运行 | ★★★★☆ |
| **ProcDump** | 进程转储 | ★★★★☆ |
| **PsSuspend** | 挂起进程（保留内存） | ★★★☆☆ |
| **handle64** | 句柄查看（网络、文件、互斥体） | ★★★★☆ |
| **ListDlls** | 进程模块列表（含未登记模块） | ★★★★☆ |
| **Strings** | ASCII/Unicode 字符串提取 | ★★★★☆ |
| **streams** | 备用数据流（ADS）扫描 | ★★★★☆ |
| **pipelist** | 命名管道枚举（C2 特征） | ★★★☆☆ |
| **LogonSessions** | 登录会话枚举 | ★★★☆☆ |
| **PsLogList / PsGetsid** | 日志与会话信息 | ★★★☆☆ |
| **RAMMap / VMMap** | 内存占用与虚拟内存地图 | ★★★☆☆ |
| **AccessChk / AccessEnum / ShareEnum** | 权限与共享审计 | ★★★☆☆ |
| **SDelete** ⚠️ | 安全删除（**处置阶段用；取证阶段禁用**） | ★★☆☆☆ |

### 2.4 Eric Zimmerman 工具集（EZ Tools，时间线分析核心）

获取：https://ericzimmerman.github.io/ （有安装器，支持批量下载）

| 工具 | 解析对象 | 输出价值 |
|---|---|---|
| **MFTECmd** | `$MFT`、`$UsnJrnl:$J`、`$Boot` | 文件系统时间线 + 删除痕迹 |
| **PECmd** | Prefetch `.pf` | 程序执行时间与运行次数 |
| **AmcacheParser** | `Amcache.hve` | 执行过的程序 + SHA1 |
| **AppCompatCacheParser** | ShimCache（SYSTEM hive） | "见过"的可执行文件 |
| **EvtxECmd** | `.evtx` 事件日志 | 统一事件 CSV（喂给时间线工具） |
| **JLECmd / LECmd** | Jump List / LNK | 用户访问痕迹（含打开过的文件） |
| **RBCmd** | 回收站 `$I` 文件 | 删除的原路径与时间 |
| **SrumECmd** | `SRUDB.dat` | 应用使用 + 网络流量字节数 |
| **SBECmd** | ShellBags | 目录浏览痕迹（含已删除目录） |
| **WxTCmd** | Windows 时间线 | 用户活动轨迹 |
| **Registry Explorer** | 注册表 hive 离线浏览 | 替代 regedit，支持事务日志回放 |
| **Timeline Explorer** | CSV 时间线**浏览与过滤** | 把上述所有 CSV 统一排序查看 |
| **ShellBagsExplorer** | ShellBags 图形化 | 更直观 |

**这一套是"还原攻击者操作时间线"的最强组合**，且全部免费、可离线。

### 2.5 日志检测与威胁狩猎（Sigma 生态）

| 工具 | 用途 | 获取 | 备注 |
|---|---|---|---|
| **Sigma** | 社区检测规则标准（数千条规则） | github.com/SigmaHQ/sigma | 生态核心 |
| **Chainsaw** | Sigma 规则驱动的事件日志猎杀（Rust） | github.com/WithSecureLabs/chainsaw | 单文件；速度快 |
| **Hayabusa** | 事件日志时间线 + 检测（Rust） | github.com/Yamato-Security/hayabusa | 单文件；内置规则；输出美观 |
| **Zircolite** | 基于 Sigma + SQLite 的大数据量检测 | github.com/wagga40/Zircolite | 适合几十 GB 日志 |
| **DeepBlueCLI** | PowerShell 轻量日志分析 | github.com/sans-blue-team/DeepBlueCLI | 零依赖，现场应急好用 |
| **APT-Hunter** | 面向 APT 场景的日志分析 | github.com/ahmedkhlief/APT-Hunter | Python |
| **Aurora** | 基于 Sigma 的实时日志扫描 | github.com/NextronSystems/aurora | Nextron 出品 |
| **Log Parser / Log Parser Lizard** | 类 SQL 查询各类日志 | Microsoft / lizard-labs.com | 老牌但强 |

**典型用法**

```powershell
# Hayabusa：一条命令得到带威胁评分的时间线
hayabusa.exe csv-timeline -d C:\IR\evtx -o C:\IR\timeline.csv -p super-verbose
hayabusa.exe logon-summary -d C:\IR\evtx          # 登录摘要（含来源 IP）
hayabusa.exe eid-metrics   -d C:\IR\evtx          # 事件 ID 分布，快速定位异常通道

# Chainsaw：Sigma 规则猎杀
chainsaw hunt C:\IR\evtx -s sigma/rules --mapping mappings/sigma-event-logs-all.yml --output C:\IR\chainsaw

# Zircolite：超大数据集
zircolite.py --evtx C:\IR\evtx --ruleset rules/rules_windows_generic.json --outdir C:\IR\zircolite
```

### 2.6 样本静态分析

| 工具 | 用途 | 获取 | 备注 |
|---|---|---|---|
| **Detect It Easy (DIE)** | 壳/编译器/保护识别 | github.com/horsicq/Detect-It-Easy | 比 PEiD 现代 |
| **PEStudio** | PE 静态画像（导入表/资源/熵/字符串） | winitor.com | 商业但有免费版 |
| **CFF Explorer** | PE 结构编辑与查看 | 网上流传（NTCore 出品） | 老牌 |
| **capa** | **自动识别样本能力**（基于规则匹配） | github.com/mandiant/capa | 输出"这样本会做什么" |
| **FLOSS** | 字符串去混淆（自动解栈/编码字符串） | github.com/mandiant/flare-floss | 对抗混淆利器 |
| **YARA** | 规则匹配扫描 | github.com/VirusTotal/yara | 配合规则集使用 |
| **binwalk** | 固件/嵌套文件提取 | github.com/ReFirmLabs/binwalk | 分析打包载荷 |
| **exiftool** | 元数据 | exiftool.org | 文档/图片元数据 |
| **Hindsight** | Chrome 浏览器取证 | github.com/obsidianforensics/hindsight | 浏览历史/下载/凭据痕迹 |
| **Nirsoft 工具集** | USB、浏览历史、凭据等 200+ 小工具 | nirsoft.net | 覆盖面极广，单文件 |

### 2.7 内存马与代码注入检测

| 工具 | 用途 | 获取 | 备注 |
|---|---|---|---|
| **pe-sieve** | 扫描单个进程内的篡改代码 | github.com/hasherezade/pe-sieve | **内存马首选** |
| **HollowsHunter** | 全量扫描所有进程 | github.com/hasherezade/hollows_hunter | pe-sieve 的批量封装 |
| **Moneta** | 内存区域异常检测 | github.com/forrest-orr/moneta | 侧重 RWX/无映像内存 |
| **Volatility3 `malfind`** | 内存镜像中的注入痕迹 | 见 2.2 | 离线分析用 |

```powershell
# 现场用法：先定位可疑进程，再逐个扫
hollows_hunter64.exe /out C:\IR\hollows /shellc /data 3
pe-sieve64.exe /pid <PID> /out C:\IR\pesieve /shellc /data 3 /min 1024
```

### 2.8 反 Rootkit 与内核级检查

| 工具 | 用途 | 获取 | 备注 |
|---|---|---|---|
| **GMER** | Rootkit 扫描（SSDT/IDT/驱动） | gmer.net | 老但有效 |
| **TDSSKiller** | 卡巴斯基 Rootkit 专杀 | kaspersky.com | 针对已知家族 |
| **System Informer**（原 Process Hacker） | 内核对象、句柄、隐藏进程 | systeminformer.sourceforge.io | 功能强于 ProcExp |
| **Volatility3 `callbacks` / `ssdt`** | 内核回调与 SSDT hook 检测 | 见 2.2 | 离线分析 |
| **LOLDrivers** | 已知易受攻击驱动清单（BYOVD 检测） | loldrivers.io | **排查 EDR 被卸载的关键参考** |

### 2.9 网络取证

| 工具 | 用途 | 获取 | 备注 |
|---|---|---|---|
| **Wireshark / tshark** | 流量分析 | wireshark.org | 配合解密与协议解析 |
| **Nmap** | 端口与服务扫描 | nmap.org | 内网资产与暴露面 |
| **pktmon**（内置） | Windows 内置抓包（Win10 1809+） | 系统自带 | 不需要装东西 |
| **Zeek** | 网络流量分析框架 | zeek.org | 生成连接日志（conn/dns/http） |
| **RITA** | 流量中的 C2/Beacon 检测 | github.com/activecm/rita | 配合 Zeek 输出使用 |
| **Netsh trace** | 内置 ETW 抓包 | 系统自带 | 老系统替代 pktmon |

### 2.10 域环境与 AD 安全

| 工具 | 用途 | 获取 | 备注 |
|---|---|---|---|
| **BloodHound + SharpHound** | AD 攻击路径可视化 | github.com/SpecterOps/BloodHound | 蓝队自查也极有价值 |
| **PingCastle** | AD 安全评估（评分报告） | pingcastle.com | 免费版够用 |
| **Purple Knight** | AD 暴露面评估 | semperis.com/purple-knight | 免费 |
| **ADAudit Plus / Netwrix** | AD 审计（商业） | 各自官网 | 持续审计 |
| **Impacket** ⚠️ | 凭据导出与分析（secretsdump） | github.com/fortra/impacket | 离线解析 SAM/NTDS 产出 |

### 2.11 基线与合规核查

| 工具 | 用途 | 获取 | 备注 |
|---|---|---|---|
| **HardeningKitty** | 基于 CIS 的自动化核查与加固 | github.com/scipag/HardeningKitty | **强烈推荐**；支持 Audit/加固/回滚 |
| **Microsoft SCT** | 官方安全基线与 LGPO | microsoft.com（Security Compliance Toolkit） | 域环境下发基线 |
| **Policy Analyzer** | 本地策略 vs 基线差异 | 随 SCT 提供 | 生成差异报告 |
| **CIS-CAT Lite / Pro** | CIS Benchmark 评分扫描 | cisecurity.org | 合规交付用 |
| **Lynis**（WSL 内） | Linux 侧基线（跨平台统一时使用） | cisofy.com | 对应 Linux 文档 |

### 2.12 攻击模拟与检测验证

> **验证"我的检测到底能不能生效"** —— 这是从"配了 Sysmon"升级到"确认检测有效"的关键一步。

| 工具 | 用途 | 获取 | 备注 |
|---|---|---|---|
| **Atomic Red Team** | 按 ATT&CK 技术执行原子测试 | github.com/redcanaryco/atomic-red-team | 验证每条技术的可检测性 |
| **Caldera** | 自动化对手模拟 | github.com/mitre/caldera | MITRE 出品 |
| **Stratus Red Team** | 云环境攻击模拟 | github.com/DataDog/stratus-red-team | 云侧对应物 |
| **LOLBAS Project** | LOLBin 用法数据库 | lolbas-project.github.io | 检测逻辑参考 |
| **MITRE ATT&CK** | 技术知识库 | attack.mitre.org | 覆盖度自评基准 |

### 2.13 威胁情报与在线资源

> ⚠️ **以下均涉及数据外发（上传哈希/样本/文件名），使用前必须获得授权。**

| 资源 | 用途 | 地址 |
|---|---|---|
| VirusTotal | 哈希/域名/IP/样本查询 | virustotal.com |
| MalwareBazaar | 恶意样本库（下载样本） | bazaar.abuse.ch |
| URLhaus | 恶意 URL 库 | urlhaus.abuse.ch |
| ThreatFox | IOC 共享平台 | threatfox.abuse.ch |
| ANY.RUN | 交互式在线沙箱 | any.run |
| Hybrid Analysis | 免费沙箱 | hybrid-analysis.com |
| ID Ransomware | 勒索家族识别 | id-ransomware.malwarehunterteam.com |
| NoMoreRansom | 解密工具（含免费解密器） | nomoreransom.org |
| MISP | 开源威胁情报平台（自建） | misp-project.org |
| OpenCTI | 开源情报平台（自建） | github.com/OpenCTI-Platform/opencti |

### 2.14 磁盘与数据恢复

| 工具 | 用途 | 获取 |
|---|---|---|
| **FTK Imager** | 磁盘/内存镜像与挂载（免费） | exterro.com/ftk-imager |
| **Autopsy** | 开源取证分析平台 | autopsy.com |
| **PhotoRec / TestDisk** | 数据恢复与分区恢复（免费） | cgsecurity.org |
| **R-Studio / GetDataBack** | 商业 NTFS 恢复 | 各自官网 |
| **ShadowExplorer** | 卷影副本浏览 | shadowexplorer.com |

---

## 3. 典型工作流

### 3.1 单机应急（最常用）

```
① 固定易失数据（15 分钟）
   WinPmem → mem.raw
   Get-NetTCPConnection / DNS 缓存 / 进程列表 → 文本快照
   pktmon start（若需要流量）

② 一键只读采集（30 分钟）
   scripts\windows-ir-quickcheck.ps1  → C:\IR\<主机>-<时间>\
   CyLR 或 KAPE 采集 $MFT、$UsnJrnl、事件日志、注册表 hive

③ 快速定性（30 分钟）
   Autoruns（-m 非微软）→ 持久化清单
   Hayabusa 或 Chainsaw → 日志时间线 + Sigma 命中
   人工确认可疑项（回到主手册第 3 章对应小节）

④ 深挖（数小时，按需）
   Volatility3 / MemProcFS → 内存中的注入与 C2
   pe-sieve / HollowsHunter → 内存马
   PECmd / AmcacheParser / MFTECmd → 执行痕迹时间线

⑤ 处置与加固
   隔离 → 清理 → 改凭据 → 加固（主手册第 9 章）
```

### 3.2 批量排查（企业环境）

```
① Velociraptor 部署到全端点（或已有 EDR）
② 用 VQL 查询全网同类痕迹，例如：
   - 哪些主机有 TeamViewer 且非业务授权
   - 哪些主机存在 __EventFilter
   - 哪些主机在最近 7 天执行过 certutil -urlcache
③ 命中主机进入"单机应急"流程
④ 用 Sigma 规则在集中日志平台回溯全网历史
```

```sql
-- Velociraptor VQL 示例（查询所有主机的异常服务路径）
SELECT * FROM Artifact.Windows.System.Services()
WHERE PathName =~ "Temp|AppData|ProgramData"
```

### 3.3 深度取证（有镜像/有完整日志）

```
① 建立时间线
   MFTECmd   → $MFT 与 $UsnJrnl
   EvtxECmd  → 全部事件日志
   PECmd     → Prefetch
   AmcacheParser / AppCompatCacheParser
   JLECmd / LECmd / RBCmd / SBECmd
   SrumECmd  → 网络流量
② Timeline Explorer 载入全部 CSV，统一按时间排序
③ 按 ATT&CK 阶段切片，还原攻击叙事
④ Plaso + Timesketch（团队协作与可视化）
```

---

## 4. 离线应急 U 盘准备清单

**目录结构建议**

```
IR-USB\
├── 00-说明与授权\
│   ├── 授权书模板.docx
│   ├── 应急处置流程.md
│   └── 现场记录表.xlsx
├── 01-采集\
│   ├── winpmem_mini_x64.exe
│   ├── Velociraptor\
│   ├── CyLR\
│   ├── KAPE\
│   ├── MagnetRAMCapture\
│   └── ir-quickcheck\  (放本仓库的脚本)
├── 02-分析\Sysinternals\   (autoruns, procexp, procmon, tcpview, sigcheck,
│                            procdump, handle, listdlls, strings, streams, pipelist,
│                            pssuspend, logonsessions, rammap)
├── 03-分析\EZTools\        (MFTECmd, PECmd, AmcacheParser, AppCompatCacheParser,
│                            EvtxECmd, JLECmd, LECmd, RBCmd, SrumECmd, SBECmd,
│                            RegistryExplorer, TimelineExplorer)
├── 04-分析\日志检测\       (Chainsaw + sigma规则, Hayabusa, Zircolite, DeepBlueCLI)
├── 05-分析\内存\           (Volatility3 + 依赖, MemProcFS)
├── 06-分析\样本\           (DIE, PEStudio, capa, FLOSS, yara + 规则集, CFF Explorer)
├── 07-分析\内存马\         (pe-sieve, hollows_hunter, moneta)
├── 08-分析\反Rootkit\      (GMER, TDSSKiller, System Informer)
├── 09-网络\                (Wireshark, Nmap, Zeek)
├── 10-基线\                (HardeningKitty + CIS 清单, SCT, LGPO)
├── 11-恢复\                (PhotoRec, TestDisk, FTK Imager)
└── 99-运行时\              (PowerShell 7, Python 3 便携版, .NET Runtime, VC++ 运行库)
```

**准备要点**

- [ ] 所有工具**预下载并核对哈希**（应急现场没有网、也不该有网）
- [ ] 工具的**版本号与签名**做成清单，每次更新记录
- [ ] 脚本类工具**预先测试**过（至少语法与运行环境验证）
- [ ] U 盘本身**写保护**（避免被失陷主机感染）
- [ ] 准备一个**干净的 U 盘**用于把证据拷出（不要用同一个盘双向用）
- [ ] 准备**静态编译版**的 bash/curl 等（应对系统工具被替换）
- [ ] Sigma 规则、YARA 规则**预先更新**到较新版本

---

## 5. 与 AI Agent / MCP 结合的自动化巡检

> 这一节对应项目规划中"结合 MCP 协议接入 AI Agent，实现自动化巡检与异常研判"。

### 5.1 架构思路

```
自然语言指令
    ↓
AI Agent（编排与研判）
    ↓  MCP（Model Context Protocol）
MCP Server（本地，只读能力封装）
    ↓
┌─────────────────────────────────────────┐
│ Tool 1: run_ir_quickcheck   → 执行采集脚本
│ Tool 2: query_autoruns      → 解析 Autoruns CSV
│ Tool 3: query_events        → Get-WinEvent 封装
│ Tool 4: scan_with_yara      → 规则扫描
│ Tool 5: hunt_sigma          → Chainsaw/Hayabusa 封装
│ Tool 6: query_velociraptor  → VQL 查询
└─────────────────────────────────────────┘
    ↓
结构化结果 → Agent 研判 → 报告 / 告警 / 建议
```

### 5.2 三个层次的落地

| 层次 | 能力 | 实现方式 |
|---|---|---|
| **L1 采集自动化** | 把只读采集脚本封装为工具，Agent 按需调用 | 直接包装 PowerShell 脚本，返回 JSON |
| **L2 查询自动化** | Agent 能按自然语言查事件日志、注册表、持久化项 | 封装 `Get-WinEvent` / `Get-ItemProperty` 为参数化查询（**必须白名单**） |
| **L3 研判自动化** | Agent 结合规则与情报给结论 | 接入 Sigma/YARA 输出 + 威胁情报查询 + ATT&CK 映射表 |

### 5.3 关键设计约束（**安全底线**）

| 约束 | 说明 |
|---|---|
| **只读默认** | 默认只暴露只读工具；写操作（清理/删除）必须单独授权且二次确认 |
| **白名单查询** | 不对 Agent 暴露任意命令执行；每个工具是固定目的的封装 |
| **参数校验** | 所有输入做严格校验，防注入（尤其拼接到命令行的参数） |
| **审计日志** | 每次工具调用记录：时间、调用方、参数、结果摘要 |
| **最小权限** | MCP Server 以专用低权限账户运行；需要 SYSTEM 的操作单独隔离 |
| **结果留痕** | 所有采集结果落盘存档，不只在会话里 |
| **人在回路** | L3 的结论必须标注"待人工确认"，不可直接用于处置动作 |
| **数据边界** | 调用外部情报服务前必须经授权与脱敏 |

### 5.4 可以立刻做的第一步

把仓库里的 `scripts\windows-ir-quickcheck.ps1` 封装成一个只读 MCP 工具：

```jsonc
// 概念示例：MCP Server 侧的工具定义
{
  "name": "run_ir_quickcheck",
  "description": "在本地主机执行只读应急采集，输出结构化结果摘要。不会修改任何系统状态。",
  "inputSchema": {
    "type": "object",
    "properties": {
      "outputDir": {
        "type": "string",
        "description": "采集结果输出目录（绝对路径，需已存在或可创建）"
      },
      "modules": {
        "type": "array",
        "items": { "enum": ["network","process","persistence","account","log","file"] },
        "description": "要采集的模块；不传则全部采集"
      }
    },
    "required": ["outputDir"]
  }
}
```

**Agent 侧的使用体验**：

> **用户**：帮我查一下这台机器有没有可疑的持久化后门。
> **Agent**：调用 `run_ir_quickcheck(modules=["persistence"])` → 解析结果 → 结合
> `windows-attack-mapping.md` 的持久化核对清单逐项比对 → 输出可疑项与判定依据、
> 并给出下一步验证命令。

**这样做的好处**：把"知识"（本仓库的手册）与"能力"（脚本）都变成 Agent 可调用的资源，
从"我查手册"变成"Agent 按手册帮我查"。这也是这套笔记从"文档"演进到"工具"的路径。

---

## 6. 值得关注的检测新技术

| 技术 | 价值 | 落地难度 |
|---|---|---|
| **Sigma 规则生态** | 一次编写，多 SIEM 复用；社区持续更新 | 低（用 Chainsaw/Hayabusa 直接跑） |
| **Velociraptor VQL** | 跨端点任意维度查询，无需部署 Agent 到每台 | 中 |
| **MemProcFS 式内存挂载** | 把内存分析从"命令行考古"变成"浏览文件" | 低 |
| **内核回调监控** | 检测内核级 rootkit 与 EDR 篡改 | 高 |
| **ETW 全量遥测** | 覆盖进程/网络/文件/注册表的内核级可见性 | 高（且可能被 patch） |
| **WDAC + 受管安装程序** | 从"检测"前移到"阻止" | 中（需规划） |
| **不可变备份 / 离线备份** | 唯一真正对抗勒索的手段 | 中 |
| **不可变日志（WORM 存储）** | 攻击者清不掉日志 | 中 |
| **Threat Hunting as Code** | 把狩猎查询写成代码，纳入版本管理与定时执行 | 中 |
| **Attack Simulation（Atomic/Caldera）** | 用攻击验证检测，形成"检测-验证"闭环 | 中 |
| **AI 辅助研判** | 把海量告警与制品做初筛与关联 | 中（需人在回路） |

---

> **配套文档**：
> - `windows-host-audit.md` —— 现场排查命令手册
> - `windows-attack-mapping.md` —— 攻击手法映射
> - `windows-hardening.md` —— 加固基线
> - `../scripts/windows-ir-quickcheck.ps1` / `windows-baseline-check.ps1` —— 自动化脚本
