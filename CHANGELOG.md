# 更新日志

本文件记录本项目面向使用者的重要变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 计划中
- Linux 侧检测能力验证清单（`linux/linux-detection-validation.md`），验证介质为 auditd / eBPF / journald
- 数据与备份策略文档（3-2-1、离线与不可变备份、恢复演练）
- 应急演练脚本与评分表
- 验证用例集机器可读化（JSON），供 MCP + AI Agent 自动执行与判定

---

## [0.3.0] - 2026-09-18

### 新增
- **应急响应体系（`ir/`）**——补齐从「会查」到「会处置」的流程层
  - `ir/ir-framework.md`：三层能力模型（预防 / 检测 / 响应）+ 治理支撑，对齐 NIST CSF 2.0 与 SP 800-61r3；**能力地图与覆盖度自评**（逐项标注已覆盖 / 部分 / 待建设）；组织角色 RACI；事件分级 P0–P3 与响应 SLA；度量指标（MTTD / MTTA / MTTR / Dwell Time / 覆盖率）；分阶段建设路线图；全仓文档索引
  - `ir/ir-playbook.md`：应急响应标准流程 SOP（准备 → 识别与分诊 → 遏制 → 取证与溯源 → 消除 → 恢复 → 复盘）。含首访 15 分钟标准动作、起获三档失陷判定、短遏制/长遏制策略矩阵、打蛇风险评估、清除 vs 重装决策树、恢复验证清单、加严监控期、沟通与上报的法定时限对照
  - `ir/ir-scenarios.md`：8 类场景化处置预案（勒索与双重勒索、挖矿、Web 打点/Webshell/内存马、凭据泄露与横向移动、数据外带与泄露、APT 长期潜伏、供应链与 CI-CD、云主机与容器 K8s）。统一结构：识别信号 → 10 分钟确认 → 遏制（含禁忌）→ 清除与根因 → 恢复与加固 → 复盘要点
  - `ir/ir-templates.md`：可直接填写的文书模板——应急响应授权书、事件信息记录表、证据交接单（chain of custody）、处置动作记录表、事件报告（初报/续报/结报）、复盘报告、应急联系人表、对内与对外通知模板
- 项目治理文件：`LICENSE`（MIT）、`DISCLAIMER.md`（用途限定、授权要求、禁止事项、风险提示与责任免除）、`CONTRIBUTING.md`（文档与脚本规范、提交前自检清单、提交信息规范）、`CHANGELOG.md`

### 变更
- `README.md` 重构为体系视角：新增体系总览与**按角色/场景索引的文档地图**，补充版本与路线图、授权与免责入口

---

## [0.2.1] - 2026-09-18

### 新增
- `.gitignore`：忽略备份文件、编辑器目录，以及排查脚本的采集产物（`ir-*/`、`*.evtx`、`*.dmp`、`*.mem` 等）

### 变更
- `.gitattributes`：由 `* text=auto` 调整为 `* text=auto eol=lf`，消除 Windows 检出/提交导致的全文件行尾噪音；`.sh`/`.bash` 固定 LF，`.ps1`/`.bat`/`.cmd` 固定 CRLF
- 移除冗余的手工备份文件（原始版本保留在 `ae84729` 提交中，可用 `git show HEAD:<path>` 取回）

### 移除
- `linux/linux-host-audit.md.bak`、`windows/windows-host-audit.md.bak`

---

## [0.2.0] - 2026-09-18

### 新增
- 双平台主排查手册重写为 10 章结构，各含附录
  - `linux/linux-host-audit.md`：取证前置与排查优先级、网络与内核层取证、`/proc` 全量字段与隐藏进程差集、持久化全量核对、账号与 SSH 公钥后门、执行痕迹、文件系统与时间线、日志篡改识别、应用中间件专项、处置加固
  - `windows/windows-host-audit.md`：取证前置与四源进程交叉验证、`portproxy`/PAC 与多源连接比对、进程注入与内存马、持久化 13 小节（含 WMI 事件订阅、IFEO、SilentProcessExit、Netsh Helper、WSL 侧持久化）、账号认证与凭据窃取、执行痕迹（Prefetch/Amcache/ShimCache/UserAssist/BAM/SRUM/MFT/USN）、ADS 与 Zone.Identifier、事件日志与 Sigma 分析、应用中间件、LOLBins 速查
- 知识层文档
  - `linux/linux-attack-mapping.md`、`windows/windows-attack-mapping.md`：ATT&CK 映射表、**权限维持全量核对清单**（Linux 15 类 / Windows 8 大类 50+ 项）、挖矿/勒索/无文件/横向/凭据/Webshell/外带/反取证等专项、现象速查表、2024–2026 攻击趋势
  - `linux/linux-hardening.md`（十类基线检查项）、`windows/windows-hardening.md`（114 项核查表，含 P0/P1/P2 分级）
  - `windows/windows-forensics-toolchain.md`：14 类取证工具、离线工具盘结构、MCP + AI Agent 自动化巡检设计
- 只读自动化脚本：`scripts/linux-ir-quickcheck.sh`、`scripts/linux-baseline-check.sh`、`scripts/windows-ir-quickcheck.ps1`、`scripts/windows-baseline-check.ps1`
  - 采集脚本自动汇总隐藏进程差集、`ld.so.preload`、无文件进程、跨进程链异常、无签名进程、`ServiceDll` 异常、WMI 订阅、隐藏任务、ADS、Internet 来源文件等
  - 基线脚本输出 `[!]` 问题清单与 P0/P1/P2 分级报告

### 变更
- `README.md`：修正仓库结构树缩进，核心能力扩充，新增快速开始与「场景 → 使用顺序」表

---

## [0.1.0] - 2026-09-17

### 新增
- 初始版本：Windows / Linux 主机排查命令清单（端口进程、启动项、计划任务、账号审计、系统日志、恶意文件）
- XXL-JOB 分布式定时任务排查要点
- `scripts/port-check.ps1`：监听端口自动审计，一键输出端口、进程与 PID；`scripts/run.bat` 启动脚本
- `README.md`：项目定位与使用场景
