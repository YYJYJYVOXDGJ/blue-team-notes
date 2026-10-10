# 更新日志

本文件记录本项目面向使用者的重要变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 修正
- **依赖版本约束修正（重要）**：`mcp[cli]` 由 `>=1.28.1` 收紧为 `>=1.28.1,<2`。
  mcp 2.x 已将 `FastMCP` 更名为 `MCPServer`（导入路径由 `mcp.server.fastmcp`
  变为 `mcp.server.mcpserver`），本 Server 基于 1.x API 编写，未锁版本时装到 2.x
  会直接 `ModuleNotFoundError`，Server 无法启动。`requirements.txt`、
  `mcp/README.md` 快速开始、`selfcheck.py` 末尾提示三处同步修正。
- **文档口径与实现对齐**：规则库实际为 **37 条**（10 条关键词 + 27 条结构化），
  此前 `README.md` 与 `mcp/README.md` 中的「40 条」「30 条结构化」为过时口径，已更正。
- `README.md` 当前版本号由 v0.4.0 更正为 v0.4.1（与 CHANGELOG 一致）。

### 新增
- `mcp/demo.py` + `mcp/演示.bat`：现场演示一键脚本。
  串起「规则引擎 → 数据流水线 → 研判报告 → 效果与性能」四个演示点，
  全程离线、零第三方依赖、不接触真实数据。

### 计划中
- 数据与备份策略文档（3-2-1、离线与不可变备份、恢复演练）——勒索场景的生死线
- Linux 侧检测能力验证清单（`linux/linux-detection-validation.md`），验证介质为 auditd / eBPF / journald
- 应急演练脚本与评分表
- `mcp/` v0.3.0：接入真实日志源（Windows 安全日志 4624/4625/4688/4104、Linux auditd / journald）
- 案例集补充：误报排除类（正常组件被误判）、检测盲区类各 1–2 例

---

## [0.4.1] - 2026-09-25

本版主题：**把散落的实战记录沉淀为脱敏后的可复用文档**，并补上仓库此前缺的两块——
「手工排查线」与「钓鱼场景」。

### 新增

- **S9 钓鱼邮件与社交工程**（`ir/ir-scenario-phishing.md`）
  - 补上原 8 类场景中的缺失项。核心是纠正三个常见误判：
    收到邮件 ≠ 中毒、先杀毒后改密码是反的、删掉文件就安全
  - 邮件头判读对照表（Return-Path / Received / X-Mailer 三行的「像营销」vs「像定向」）
  - 点开链接后的 5 步止损，**顺序是关键**：断网 → 换干净设备改密码 → 查邮件转发规则 → 查登录记录 → 主机排查
  - 本机 A–G 七项排查清单与红线禁忌（含"别下专杀工具""别格式化逃避"）
- **Windows 12 步手工排查**（`windows/windows-manual-steps.md`）
  - 与一键采集脚本互补而非替代：脚本用于批量取证留证，手工线用于现场逐条研判
  - **为什么需要手工线**：一键脚本批量调用几十条系统查询，行为特征与信息窃取类木马几乎一致，
    会被启发式规则查杀；手工敲命令则没有黑盒
  - 每步给出「正常 / 可疑」对照判据；第 3 步（父进程与命令行）单列，这是抓邮件触发型木马最有效的一招
  - 附常见正常进程白名单，避免自查时自己吓自己
- **敏感信息自查门禁**（`scripts/check-sensitive.py`）
  - 本仓库公开，把"人工记得检查"变成"提交前自动跑"：扫描私有地址、用户名路径、主机名、
    邮箱、手机号、SSH 密钥材料、真实姓名等，ERROR 退出码阻断提交
  - 文档保留段（RFC 5737）与示例域名（RFC 2606）自动豁免，避免噪音淹没真问题
  - 已接入 `CONTRIBUTING.md` §4 提交前自检清单
- **脱敏实战案例集 `ir/cases/`**
  - `case-001-oem-push-component.md`：OEM 预装推送组件被误判为反向连接
    ——完整记录从「疑似境外 C2」到「厂商自有推送中间件」的**判断被推翻的过程**
  - 六维对比表（文件位置 / 数字签名 / 目标 IP / 端口 / 父进程 / 子进程行为）给出"像反连 ≠ 是反连"的切开方式
  - 三条方法论教训：IP 归属必须查不能猜（凭 IP 首段猜归属地是本次误判的直接原因）、
    端口指纹只能当线索、"看组件要看整目录而非主程序"
  - **`README.md` 案例脱敏规范**：红线清单（内网 IP 换 RFC 5737 文档段、用户名/主机名/设备画像泛化、
    第一人称叙事改中性案例体）、可保留清单、判断原则（"这条信息能否反定位到具体的人或组织？"）、
    厂商名泛化为 `<OEM>` / `<Component>` 的约定，以及新增案例模板

### 变更

- `ir/ir-scenarios.md` 索引表新增 S9 条目
- `README.md`：文档计数 11 → 14 份、新增 Cases 徽标、核心能力与仓库结构同步
- `CONTRIBUTING.md`：提交前自检清单新增「敏感信息自查」条目与 §4.1 说明

### 修复（安全）

自查脚本上线首轮即抓出两处**此前已入库的真实用户名泄露**，均已修复：

- `mcp/一键自检.bat`：Python 路径硬编码为 `C:\Users\<用户名>\...`，改为 `%LOCALAPPDATA%` 环境变量展开
- `mcp/docs/demo-output.txt`：示例输出中遗留 `C:\Users\<用户名>\Desktop\...`，改为 `<repo>` 相对路径

另将 `windows/windows-host-audit.md` 中的示例内网地址 `10.0.0.100` 换为 RFC 5737 文档段 `192.0.2.100`。

### 说明

- 本版三份文档均由真实排查记录**脱敏改写**而来，脱敏项逐条记录在案例文末的「附 · 本案例的脱敏处理」中
- 案例对厂商与产品名作泛化处理，避免对特定厂商作公开定性表述；
  这不影响推理结构的可复用性——**判定组件是否恶意依据的是路径、签名、ASN，而不是名字**

---

## [0.4.0] - 2026-09-25

本版主题：**打通「采集 → 解析 → 研判 → 报告」的数据链路**。
在此之前，`scripts/` 产出的采集结果没有任何程序能读，`mcp/` 的规则引擎只能吃手打文本——
采集与研判之间是断开的。本版补上了中间那一层。

### 新增

- **数据流水线 `mcp/irflow/`**（零第三方依赖）
  - `schema.py`：跨平台统一数据模型（Record / Finding / Collection），9 类记录种类
  - `pipeline.py`：编排「探测 → 解析 → 归一化 → 研判」，全程生成器流式处理，内存与数据量解耦
  - `report.py`：Markdown 报告与终端摘要生成，报告含能力边界与产物清单
  - `adapters/base.py`：适配器接口 + 注册表（新增数据源只需实现一个类并注册）
  - `adapters/windows_quickcheck.py`：解析 Windows 采集脚本的 40 个 CSV + 23 个 txt
  - `adapters/linux_quickcheck.py`：解析 Linux 采集脚本的 30+ 个产物，含 `ss`/`ps` 定宽列解析与行级语义识别
  - **设计取舍**：不改动采集脚本（保持只读、离线、零依赖，且已采集的历史证据仍可用），
    在分析侧做适配——这是"异构系统接入"在取证工作流中的正确分层
- **结构化规则引擎能力扩展**（`mcp/triage.py`）
  - 新增 `match` 段与 16 个比较算子（`equals` / `in` / `regex` / `not_startswith` / `exists` …），
    规则可直接比对采集产物的字段，不必先拼成文本
  - 新增 `triage_record()` / `triage_records()`：单条与批量记录研判
  - 新增规则作用域 `scope`（`both` / `alert` / `record`）：
    宽泛的关键词规则标记 `scope: alert` 后不再参与采集产物研判，消除大批误报
- **结构化规则 30 条**（`mcp/rules/triage-rules.yaml`，规则库总数 10 → 40 条）
  - `PROC-*` 进程类 5 条、`NET-*` 网络类 4 条、`PERSIST-*` 持久化类 10 条、
    `ACCT-*` 账号类 2 条、`FILE-*` 文件类 2 条、`MOD-*` 内核模块 1 条、
    `CFG-*` 配置类 2 条、`DEFENSE-*` 反取证 1 条
  - 每条都带 ATT&CK 映射、误报提示与建议的人工验证步骤
- **效果评估体系 `mcp/eval/`**
  - `labels.json`：带标注的合成样本集（Windows / Linux 各一套）
  - `run_eval.py`：量化召回率 / 精确率 / 误报，支持 `--verbose` 明细与 `--json` 落盘
  - 合成样本 `samples/`：模拟「远控 + 多重持久化」与「挖矿 + 后门 + 提权」两类典型失陷场景
- **性能基准 `mcp/bench/bench_parse.py`**
  - 测吞吐与峰值内存，并与「全量读入内存」的朴素实现对照
- **MCP Tool 扩展**：2 个 → 4 个
  - `analyze_collection(result_dir, top_k, out_report)`：对采集产物目录跑完整研判
  - `list_sources()`：列出支持的采集来源与已知盲区，让 Agent 知道能力边界
- 示例报告 `mcp/docs/demo-report-windows.md` / `demo-report-linux.md`

### 变更

- `mcp/selfcheck.py`：自检范围从"规则引擎"扩展到"规则引擎 + 完整流水线"，
  仍保持零第三方依赖，不装任何包即可运行
- `mcp/server.py`：`SERVER_INSTRUCTIONS` 增加两条约束——
  报告"未命中"时必须同时说明已知盲区；分析产物前需确认目录类型，无法识别时如实说明
- `mcp/README.md`：按 v0.2 的实际实现重写，补充架构图、评估指标、性能数据与能力边界

### 修复

评估集在上线当天就抓出三个真实缺陷，均已修复：

- **规则 `NET-001` 判定逻辑写反**：把 `0.0.0.0` 放进了 `not_in` 白名单，
  导致"绑定全部网卡的高危端口监听"被排除——而这类监听恰恰是暴露面最大的
- **Linux 适配器逐行照收**：`cron.txt` / `ssh.txt` / `lsmod.txt` 中的
  `SHELL=/bin/sh`、`ls -l` 输出行、段标题、工具表头都被当成了持久化项，噪声巨大。
  改为按行语义识别（cron 时间字段校验、公钥行前缀校验、表头过滤）
- **自研 YAML 兜底解析器的引号 bug**：`'C:\Windows\'` 中引号内的冒号被误判为
  key/value 分隔符，导致所有含冒号的 Windows 路径规则**在离线环境下静默失效**
  （装了 PyYAML 时正常，而这恰恰掩盖了问题——离线才是应急现场的主要形态）。
  修复后已验证两条解析路径结果完全一致

### 性能

对解析热路径做了一次实测调优：

| 规模 | 优化前 | 优化后 | 提速 |
|---|---|---|---|
| 1 万行 | 1.16 s | 0.40 s | 2.9× |
| 10 万行 | 12.07 s | 3.20 s | 3.8× |
| 50 万行 | 64.50 s | 15.10 s | 4.3× |

- 用 `cProfile` 定位到 `ntpath.relpath` 占总耗时 **72%**：解析器对每条记录都重算
  一次来源文件的相对路径，同一文件被重复计算十万次
- 加一层 `(root, path) → relpath` 缓存后，该项开销归零，吞吐 8,600 → 31,267 行/秒
- 优化后回归验证：评估指标完全不变（召回 100%、精确 100%）
- 内存与数据量解耦：流式解析峰值内存恒定在几十 KB，不随文件增长；
  对照的"全量读入"实现在 50 万行时峰值 80 MB 且线性增长

### 说明

- `mcp/eval/samples/` 全部为**合成数据**，不含任何真实环境信息；
  样本中的 IP 使用 RFC 5737 文档保留段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）
- 评估指标（召回 100% / 精确 100%）**只在合成样本上成立**，不可外推到真实环境。
  它的价值是提供可复现的回归基线，而非宣称检测能力

---

## [0.3.1] - 2026-09-20

### 新增
- `.github/REPO-METADATA.md`：仓库 Description / Topics / Social preview 设置建议与检查清单，修复仓库 About 区描述与项目实际定位不符的问题

### 变更
- `README.md` 与截图/简历描述对齐：
  - 双平台手册明确归纳为**六大维度**（网络与端口 / 进程与内存 / 自启动与计划任务 / 账号与权限 / 登录与系统日志 / 恶意文件与执行痕迹），并给出各维度到 Linux / Windows 手册章节的映射表
  - 脚本章节按实际作用重排，`port-check.ps1` 明确为**项目起点脚本**，说明其「多条命令串联 → 一次执行」的压缩价值
  - 路线图调整优先级（数据与备份策略提为第一优先），并指向 `ir-framework.md` §7 完整路线图
  - badge 计数修正（Docs 11 / Scripts 6），仓库结构树补充 `.github/`

### 修复
- **消除重复内容**：
  - README「体系总览」原为与 `ir-framework.md` §1 逐字相同的 ASCII 图（同图两份，改一处必漏一处）→ 改为三层能力对照表 + 指向来源文档，仅保留一句核心结论
  - README「按场景」表原与 `ir-framework.md` §8「按场景找文档」表大面积重合 → README 收敛为高频入口，完整对照统一由 §8 维护

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
