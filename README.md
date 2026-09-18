# blue-team-notes

**蓝队主机应急响应与安全审计工具集** — Windows / Linux 双平台的主机排查手册、防御基线、检测验证与应急响应体系

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)](#-仓库结构)
[![Docs](https://img.shields.io/badge/Docs-12-blue.svg)](#-仓库结构)

---

### 🎯 项目定位

面向主机侧**入侵排查、应急响应、安全基线与检测能力建设**的方法论与工具集合，沉淀攻防实战与安全服务中的主机排查经验。

项目不停留在「一堆排查命令」，而是按应急响应的真实工作流组织成三层能力：**预防（基线加固）→ 检测（日志与规则验证）→ 响应（流程、场景预案、文书）**，并显式标注尚未覆盖的部分——**能力边界清晰，比宣称全覆盖更有价值**。

可用于安全事件处置、攻防演习保障、主机安全评估、检测能力验证与日常安全运营。

### 🧭 体系总览

```text
              ┌──────────── 治理支撑（Govern）────────────┐
              │ 授权与合规 · 制度与流程 · 职责与考核 · 度量  │
              └───────────────────────────────────────────┘
                                    │
   ┌────────────────┬────────────────┬────────────────┐
   │   预防 Prevent  │   检测 Detect   │   响应 Respond   │
   ├────────────────┼────────────────┼────────────────┤
   │ 资产与暴露面     │ 日志基建         │ 流程 SOP         │
   │ 身份与权限       │ 检测规则         │ 场景预案         │
   │ 配置基线         │ 主动狩猎         │ 工具与模板       │
   │ 补丁与漏洞       │ 情报驱动         │ 演练与复盘       │
   │ 数据与备份       │ 覆盖度度量       │ 恢复与加固       │
   └────────────────┴────────────────┴────────────────┘
```

体系框架、能力地图（含覆盖度自评与缺口）、组织角色 RACI、事件分级与度量指标见 **[`ir/ir-framework.md`](ir/ir-framework.md)**。

### 📂 仓库结构

```text
blue-team-notes/
├── ir/                                  # 应急响应体系（流程层，跨平台）
│   ├── ir-framework.md                  # 体系框架、能力地图、分级与度量、路线图
│   ├── ir-playbook.md                   # 应急响应标准流程 SOP（七阶段）
│   ├── ir-scenarios.md                  # 8 类场景化处置预案
│   └── ir-templates.md                  # 授权书 / 记录表 / 报告等模板
├── linux/
│   ├── linux-host-audit.md              # Linux 主机全量应急排查手册（10 章 + 附录）
│   ├── linux-attack-mapping.md          # Linux 攻击手法与排查点映射（ATT&CK 对照）
│   └── linux-hardening.md               # Linux 主机安全基线核查与加固
├── windows/
│   ├── windows-host-audit.md            # Windows 主机全量应急排查手册（10 章 + 附录）
│   ├── windows-attack-mapping.md        # Windows 攻击手法映射（ATT&CK for Windows）
│   ├── windows-hardening.md             # Windows 安全基线核查（CIS / 微软基线对照）
│   ├── windows-forensics-toolchain.md   # 现代应急取证工具链与获取方式
│   └── windows-detection-validation.md  # 检测能力验证清单（用例集 + 回归）
├── scripts/
│   ├── linux-ir-quickcheck.sh           # Linux 应急响应一键采集（只读）
│   ├── linux-baseline-check.sh          # Linux 安全基线一键核查（只读）
│   ├── windows-ir-quickcheck.ps1        # Windows 应急响应一键采集（只读）
│   ├── windows-baseline-check.ps1       # Windows 安全基线一键核查（只读）
│   ├── port-check.ps1                   # PowerShell 监听端口自动审计脚本
│   └── run.bat                          # 一键启动脚本
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── DISCLAIMER.md                        # 使用限制与免责声明（务必阅读）
└── LICENSE
```

### ✅ 核心能力

1. **应急响应体系与流程（`ir/`）**
   - **标准流程 SOP**：准备 → 识别与分诊 → 遏制 → 取证与溯源 → 消除 → 恢复 → 复盘。含**首访 15 分钟标准动作**、失陷判定三档结论、**短遏制/长遏制策略矩阵**（什么情况下不要一刀切）、打蛇风险评估、**清除 vs 重装决策树**、恢复验证清单、加严监控期
   - **8 类场景化预案**：勒索与双重勒索、挖矿、Web 打点/Webshell/内存马、凭据泄露与横向移动、数据外带与泄露、APT 长期潜伏、供应链与 CI-CD、云主机与容器 K8s。每个场景给出「识别信号 → 10 分钟确认 → 遏制（含**禁忌清单**）→ 清除 → 恢复 → 复盘要点」
   - **文书模板**：应急响应授权书、事件信息记录表、证据交接单（chain of custody）、处置动作记录表、初报/续报/结报、复盘报告、应急联系人表、对内对外通知话术
   - **分级与上报**：P0–P3 定级判据与响应 SLA、升级/降级规则、法定上报义务与时限对照

2. **双平台主机入侵排查（10 章手册）**
   - 覆盖端口进程、启动项、计划任务、服务、用户账号、登录日志、恶意文件等全维度检查点
   - 标准化检查清单，适配应急现场快速定位攻击路径
   - 原生命令优先、标注权限要求、每条都说明「查什么」与「判读要点」

3. **深度分层：不止于表层命令**
   - **对抗隐藏**：`/proc` 直读绕过被替换的 `netstat`/`ss`、隐藏进程差集、inode 反查；Windows 侧多源进程交叉验证、内核对象比对
   - **高频遗漏项**：Linux 的 SSH 公钥后门、`ld.so.preload`、PAM 后门、冷门启动位；Windows 的 `ServiceDll`、`FailureCommand`、WMI 事件订阅、IFEO、`SilentProcessExit`、Netsh Helper、LSA 认证包
   - **证据链视角**：取证顺序与易失性数据优先级、时间线重建与时间戳伪造识别、`rpm -Va` 完整性校验、日志清痕检测、内存取证

4. **攻击手法 → 排查点映射（知识层）**
   - 按 ATT&CK 组织（Linux 与 Windows 各一套），每项技术的落地痕迹与排查命令一一对应
   - **权限维持全量核对清单**（Linux 15 类 / Windows 8 大类 50+ 项），避免「只清掉发现的那一个」
   - 挖矿 / 勒索 / 无文件攻击 / 横向移动 / 凭据窃取 / Webshell / 数据外带 / 反取证 / 合法远控滥用等专项
   - 「现象 → 最可能手法 → 下一步」速查表，现场不用现想

5. **检测能力验证（把「写了」变成「验过」）**
   - `windows-detection-validation.md`：把手册的每条检测逻辑转成**可执行、可判定、可回归**的用例（V-01 ~ V-63），逐条给出期望日志（Channel / EventID / 关键字段）、命中判定标准与风险等级
   - **14 项日志源自查表**：先排除「日志源未开导致假阴性」这一最常见误判
   - 三条验证路径分级：静态规则验证 → **日志回放**（推荐主力，风险≈0）→ 隔离 VM 受控真跑；高危用例明确禁止真跑
   - **8 项已知盲区**（内核 Rootkit、BYOVD、内存马、业务调度平台后门、云身份滥用等）显式声明

6. **自动化审计脚本（全部只读）**
   - `linux-ir-quickcheck.sh`：采集网络、进程、持久化、账号、文件、日志证据，自动标出隐藏进程、`ld.so.preload`、memfd 无文件进程
   - `linux-baseline-check.sh`：逐项核查账号、SSH、日志审计、文件权限、端口、内核参数、SELinux、持久化位，输出带 `[!]` 的问题清单
   - `windows-ir-quickcheck.ps1`：自动汇总跨进程链异常、无签名进程、`ServiceDll` 异常、WMI 订阅、隐藏任务、ADS、Internet 来源文件
   - `windows-baseline-check.ps1`：10 组 70+ 项核查，输出 P0/P1/P2 分级报告
   - `port-check.ps1`：一键输出监听端口、进程名与 PID，替代 `netstat` + `tasklist` 两步操作
   - **所有脚本均不修改系统配置、不杀进程、不改防火墙**

7. **业务中间件专项**
   - **XXL-JOB 定时任务排查**：进程与启动参数、调度中心库 `xxl_job_info`（`glue_type` / `glue_source`）、执行器 `gluesource` 目录、accessToken 与默认口令；并给出**自造验证用例**（社区无覆盖）
   - 扩展覆盖 Jenkins / GitLab Runner / Airflow / Nacos / Tomcat / Zookeeper / RocketMQ、IIS 与 ASP.NET（含内存马）、SQL Server（自启动存储过程、SQL Agent 作业、CLR 程序集）、MySQL / PostgreSQL
   - 识别「任务调度平台 / 中间件被当作可控执行器」类的后门持久化攻击

8. **现代工具链与新技术**
   - 采集与分析：Velociraptor / KAPE / CyLR、WinPmem + Volatility 3 + **MemProcFS**、Sysinternals 全集、**Eric Zimmerman 工具集**（MFTECmd / PECmd / AmcacheParser / EvtxECmd / SrumECmd）、Linux 侧 avml / LiME
   - 检测与狩猎：**Sigma 规则生态** + Chainsaw / Hayabusa / Zircolite / DeepBlueCLI；Linux 侧 **eBPF 检测**（Falco / Tetragon）、auditd
   - 内存马与注入：pe-sieve / HollowsHunter；静态分析：capa / FLOSS / DIE / YARA
   - 基线与验证：HardeningKitty（CIS 自动化）、Microsoft Security Compliance Toolkit、Atomic Red Team

9. **项目治理**
   - 明确的 `DISCLAIMER.md`（用途限定、授权要求、禁止事项、风险提示）、`CONTRIBUTING.md`（文档与脚本规范、自检清单）、`CHANGELOG.md`（版本演进）

### 🗺️ 文档地图

**按角色**

| 我是谁 | 优先看 |
|---|---|
| 团队负责人 / 安全建设者 | `ir-framework.md`（体系、能力地图、分级、度量、路线图） |
| 值班一线（L1） | `ir-playbook.md` 附录 A 速查卡、`scripts/` 采集脚本、`ir-templates.md` T2 |
| 应急响应工程师（L2） | `ir-playbook.md` → `ir-scenarios.md` → `*-host-audit.md` |
| 深度分析与取证（L3） | `*-host-audit.md` 内存/取证章节、`windows-forensics-toolchain.md` |
| 检测工程师 | `windows-detection-validation.md`、`*-attack-mapping.md` |
| 运维 / 系统管理员 | `*-hardening.md`、`scripts/*-baseline-check.*` |
| 贡献者 | `CONTRIBUTING.md` |

**按场景**

| 我现在要做什么 | 看哪份 |
|---|---|
| 主机报警了，先固定证据 | `scripts/*-ir-quickcheck.*` |
| 确认是入侵，需要按流程走 | `ir-playbook.md` |
| 已确认事件类型（勒索/挖矿/Webshell…） | `ir-scenarios.md` 对应场景 |
| 不知道该查什么层 | `*-host-audit.md` 第 0 章与目录 |
| 现象已知，想知道是什么手法 | `*-attack-mapping.md` 现象速查表 |
| 想知道后门清干净了没有 | `*-attack-mapping.md` 权限维持全量核对清单 |
| 要写事件报告 / 找授权书 | `ir-templates.md` |
| 验证检测规则有没有效 | `windows-detection-validation.md` |
| 要做基线巡检与整改 | `*-hardening.md` |
| 事件结束了要复盘 | `ir-playbook.md` §7、`ir-templates.md` T6 |

### 🚀 快速开始

```bash
# Linux 应急响应：先固定证据（只读采集，输出到 /tmp/ir-<时间戳>/）
chmod +x scripts/linux-ir-quickcheck.sh && sudo ./scripts/linux-ir-quickcheck.sh

# Linux 基线巡检：输出问题清单
chmod +x scripts/linux-baseline-check.sh && sudo ./scripts/linux-baseline-check.sh
```

```powershell
# Windows 应急响应：只读采集（输出到 C:\IR\<主机名>-<时间戳>\）
powershell -ExecutionPolicy Bypass -File .\scripts\windows-ir-quickcheck.ps1

# Windows 基线核查：输出 P0/P1/P2 分级问题清单
powershell -ExecutionPolicy Bypass -File .\scripts\windows-baseline-check.ps1

# 加 -IncludeFileScan 可额外扫描 ADS 与 Internet 来源文件（较慢）
powershell -ExecutionPolicy Bypass -File .\scripts\windows-ir-quickcheck.ps1 -IncludeFileScan
```

```bat
:: Windows 端口审计（管理员权限运行）
cd scripts && run.bat
```

### 建议使用顺序

| 场景 | 顺序 |
|---|---|
| **主机失陷应急响应** | `scripts/*-ir-quickcheck.*` 固定证据 → `ir-playbook.md` 按阶段执行 → `ir-scenarios.md` 套用具体打法 → `*-host-audit.md` 逐层深入 → `ir-templates.md` 记录与上报 |
| **主机安全评估 / 基线巡检** | `scripts/*-baseline-check.*` 出问题清单 → `*-hardening.md` 分级整改 → 复跑确认 |
| **溯源分析** | `*-attack-mapping.md` 用现象定位手法 → 回 `*-host-audit.md` 对应章节取证 → `*-attack-mapping.md` 持久化清单核对清除彻底性 |
| **检测能力建设 / 规则回归** | `windows-detection-validation.md` §2.1 日志源自查 → 日志回放验证规则 → 仅对 ★ 项在隔离环境真跑 → 按 §5.3 归档 |
| **安全体系建设规划** | `ir-framework.md` 能力地图找缺口 → §7 路线图排优先级 → §6 度量指标落地 |
| **Windows 深度取证** | `windows-forensics-toolchain.md` 选工具 → Hayabusa/Chainsaw 出日志时间线 → EZ Tools 出文件系统时间线 |

### 🛠️ 技术栈

- **系统**：Windows / Linux（含容器与 K8s 场景延伸）
- **脚本**：PowerShell / Batch / Shell
- **检测**：Sigma 规则、Sysmon、ETW、auditd、eBPF、ATT&CK 映射
- **验证**：Atomic Red Team、日志回放（Chainsaw / Hayabusa）、日志源基线自查
- **方法论**：NIST CSF 2.0、NIST SP 800-61r3、ISO 27035、等保 2.0、PICERL
- **方向**：主机安全审计、入侵检测、应急响应、安全运营、蓝队攻防
- **规划**：结合 MCP 协议接入 AI Agent，实现自动化巡检与异常研判（设计见 `windows/windows-forensics-toolchain.md` §5，验证用例集见 `windows/windows-detection-validation.md` §9）

### 📖 使用场景

1. **安全事件应急响应**：主机入侵后按流程快速定位、遏制、清除与恢复
2. **攻防演习保障**：赛前基线巡检、赛中异常定位、赛后复盘与改进
3. **安全评估服务**：主机配置核查、风险识别与加固建议
4. **日常安全运营**：常态化端口、进程、基线巡检与告警治理
5. **检测能力建设**：验证自建与社区检测规则的有效性，形成可回归的用例集
6. **体系建设与汇报**：用能力地图与度量指标量化现状、规划改进、向上汇报

### 🗓️ 版本与路线图

当前版本 **v0.3.0**，变更历史见 [`CHANGELOG.md`](CHANGELOG.md)。

近期计划：

- [ ] Linux 侧检测能力验证清单（验证介质：auditd / eBPF / journald）
- [ ] 数据与备份策略文档（3-2-1、离线与不可变备份、恢复演练）——**勒索场景的生死线**
- [ ] 应急演练脚本与评分表
- [ ] 验证用例集机器可读化（JSON），供 MCP + AI Agent 自动执行与判定

### ⚖️ 授权与免责

- 本项目依据 [`LICENSE`](LICENSE)（MIT License）开源。
- **使用前请务必阅读 [`DISCLAIMER.md`](DISCLAIMER.md)**：本项目仅限用于**已获合法授权**的系统自查、应急响应、安全评估与学习研究，禁止用于任何未授权系统或非法用途。
- `windows-detection-validation.md` 中标注为高危的验证用例**会真实执行攻击行为**，严禁在生产系统、办公机或任何你在使用的主机上执行；必须在隔离环境并满足该文档 §2.4 与附录 A 的全部前置条件。
