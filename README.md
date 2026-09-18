# blue-team-notes
## 蓝队主机应急响应与安全审计工具集

### 🎯 项目定位
面向主机侧入侵排查、应急响应、安全基线巡检的工具与手册集合，沉淀攻防实战与安全服务中的主机排查方法论，通过自动化脚本提升现场排查效率，可用于安全事件处置、攻防演习保障、主机安全评估等场景。

### 📂 仓库结构
```text
blue-team-notes/
├── linux/
│   ├── linux-host-audit.md             # Linux 主机全量应急排查手册（10 章 + 附录）
│   ├── linux-attack-mapping.md         # Linux 攻击手法与排查点映射（ATT&CK 对照）
│   └── linux-hardening.md              # Linux 主机安全基线核查与加固
├── windows/
│   ├── windows-host-audit.md           # Windows 主机全量应急排查手册（10 章 + 附录）
│   ├── windows-attack-mapping.md       # Windows 攻击手法映射（ATT&CK for Windows）
│   ├── windows-hardening.md            # Windows 安全基线核查（CIS / 微软基线对照）
│   └── windows-forensics-toolchain.md  # 现代应急取证工具链与获取方式
├── scripts/
│   ├── linux-ir-quickcheck.sh          # Linux 应急响应一键采集（只读）
│   ├── linux-baseline-check.sh         # Linux 安全基线一键核查（只读）
│   ├── windows-ir-quickcheck.ps1       # Windows 应急响应一键采集（只读）
│   ├── windows-baseline-check.ps1      # Windows 安全基线一键核查（只读）
│   ├── port-check.ps1                  # PowerShell 监听端口自动审计脚本
│   └── run.bat                         # 一键启动脚本
└── README.md
```

### ✅ 核心能力

1. **双平台主机入侵排查**
   - 覆盖 Windows / Linux 全维度检查点：端口进程、启动项、计划任务、服务、用户账号、登录日志、恶意文件
   - 标准化检查清单，适配应急响应现场快速定位攻击路径
   - 原生命令优先、标注权限要求、每条都说明「查什么」与「判读要点」

2. **深度分层：不止于表层命令**
   - **对抗隐藏**：`/proc` 直读绕过被替换的 `netstat`/`ss`、隐藏进程差集、inode 反查；Windows 侧多源进程交叉验证、`/proc` 等价的内核对象比对
   - **高频遗漏项**：Linux 的 SSH 公钥后门、`ld.so.preload`、PAM 后门、冷门启动位；Windows 的 `ServiceDll`、`FailureCommand`、WMI 事件订阅、IFEO、`SilentProcessExit`、Netsh Helper、LSA 认证包
   - **证据链视角**：现场取证顺序与易失性数据优先级、时间线重建、包/文件完整性校验、日志清痕检测、内存取证

3. **攻击手法 → 排查点映射（知识层）**
   - 按 ATT&CK 组织（Linux 与 Windows 各一套），每项技术在主机上的落地痕迹与对应排查命令一一对应
   - **权限维持全量核对清单**（Linux 15 类 / Windows 8 大类 50+ 项），避免「只清掉发现的那一个」
   - 挖矿 / 勒索 / 无文件攻击 / 横向移动 / 凭据窃取 / Webshell / 数据外带 / 反取证 / 合法远控滥用等专项分析
   - 「现象 → 最可能手法 → 下一步」速查表，现场不用现想

4. **自动化审计脚本（全部只读）**
   - `linux-ir-quickcheck.sh`：采集网络、进程、持久化、账号、文件、日志证据；自动标出隐藏进程、`ld.so.preload`、memfd 无文件进程等关键项
   - `linux-baseline-check.sh`：逐项核查账号、SSH、日志审计、文件权限、端口、内核参数、SELinux、持久化位，输出带 `[!]` 的问题清单
   - `windows-ir-quickcheck.ps1`：采集系统/网络/进程/服务驱动/持久化/账号/日志/文件痕迹，自动汇总跨进程链异常、无签名进程、`ServiceDll` 异常、WMI 订阅、隐藏任务、ADS、Internet 来源文件等可疑项
   - `windows-baseline-check.ps1`：分组核查账号、权限、网络、服务、日志审计、端点防护、凭据保护、攻击面、补丁、备份，输出 P0/P1/P2 分级问题清单
   - `port-check.ps1`：一键输出所有监听端口、对应进程名与 PID，替代手动 `netstat` + `tasklist` 两步操作
   - **所有脚本均不修改系统配置、不杀进程、不改防火墙**

5. **业务中间件专项**
   - XXL-JOB 分布式定时任务排查：进程与启动参数、调度中心库 `xxl_job_info`（`glue_type` / `glue_source`）、执行器 `gluesource` 目录、任务执行记录、accessToken 与默认口令
   - 扩展覆盖 Jenkins / GitLab Runner / Airflow / Nacos / Tomcat / Zookeeper / RocketMQ、IIS 与 ASP.NET、SQL Server（自启动存储过程、SQL Agent 作业、CLR 程序集）、MySQL / PostgreSQL
   - 识别「任务调度平台 / 中间件被当作可控执行器」类的后门持久化攻击

6. **现代工具链与新技术（Windows）**
   - 采集与分析：Velociraptor / KAPE / CyLR、WinPmem + Volatility 3 + **MemProcFS**、Sysinternals 全集、**Eric Zimmerman 工具集**（MFTECmd / PECmd / AmcacheParser / EvtxECmd / SrumECmd 等）
   - 检测与狩猎：**Sigma 规则生态** + Chainsaw / Hayabusa / Zircolite / DeepBlueCLI，把社区数千条检测逻辑应用到本地日志
   - 内存马与注入：pe-sieve / HollowsHunter；静态分析：capa / FLOSS / DIE / YARA
   - 基线与验证：HardeningKitty（CIS 自动化）、Microsoft Security Compliance Toolkit、Atomic Red Team（检测有效性验证）

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

**建议使用顺序**

| 场景 | 顺序 |
|---|---|
| Windows 应急响应 | `windows-ir-quickcheck.ps1` 采集 → 按 `windows-host-audit.md` 逐层深入 → 用 `windows-attack-mapping.md` 定性手法并核对持久化清单 |
| Windows 基线巡检 | `windows-baseline-check.ps1` 出问题清单 → 按 `windows-hardening.md` 分级整改 → 复跑确认 |
| Windows 深度取证 | `windows-forensics-toolchain.md` 选工具 → Hayabusa/Chainsaw 出日志时间线 → EZ Tools 出文件系统时间线 |
| Linux 应急响应 | `linux-ir-quickcheck.sh` 采集 → 按 `linux-host-audit.md` 逐层深入 → 用 `linux-attack-mapping.md` 定性手法 |
| Linux 基线巡检 | `linux-baseline-check.sh` 出问题清单 → 按 `linux-hardening.md` 整改 → 复跑确认 |
| 溯源分析 | `*-attack-mapping.md` 先用现象定位手法 → 回 `*-host-audit.md` 对应章节取证 |

### 🛠️ 技术栈
- 系统：Windows / Linux
- 脚本：PowerShell / Batch / Shell
- 检测：Sigma 规则、Sysmon、ETW、ATT&CK 映射
- 方向：主机安全审计、入侵检测、应急响应、蓝队攻防
- 规划：结合 MCP 协议接入 AI Agent，实现自动化巡检与异常研判（设计思路见 `windows/windows-forensics-toolchain.md` 第 5 节）

### 📖 使用场景
1. 安全事件应急响应：主机入侵后快速排查攻击痕迹
2. 攻防演习保障：赛前主机基线巡检、赛中异常定位
3. 安全评估服务：主机安全配置核查、风险识别
4. 日常安全运营：常态化主机端口、进程、基线巡检

### ⚠️ 说明
本项目仅用于授权环境下的安全学习与合规审计，禁止用于未授权的系统检测。
