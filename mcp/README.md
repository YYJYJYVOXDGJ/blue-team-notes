# blue-team-notes-mcp

> 把「主机应急响应工具集」的排查经验封装成**可被 AI Agent 调用的确定性能力**。
>
> 一句话定位：**不造一个会乱说的 AI 分析师，只造一条能跑通的数据流水线 + 一组只读工具，让模型负责翻译和表达。**

本目录是 [blue-team-notes](https://github.com/YYJYJYVOXDGJ/blue-team-notes) 仓库
`windows/windows-forensics-toolchain.md` §5「MCP / Agent 设计」章节的**可运行实现**。

当前版本 **v0.2.0**：在 v0.1 的规则引擎之上，补齐了「采集产物 → 结构化研判」的数据链路。

---

## 这个目录解决什么问题

v0.1 只做了"喂一段告警文本 → 返回命中的规则"。但真实应急场景的输入不是手打的文本，
而是**采集脚本吐出来的一整个目录**（Windows 侧 60+ 个 CSV/txt，Linux 侧 30+ 个文件）。
这批产物没有任何程序能读，只能人工翻——**采集与研判之间是断开的**。

v0.2 补上了中间那一层：

```
采集脚本             异构产物                   归一化               规则研判          报告
─────────      ─────────────────      ──────────────      ──────────      ─────────
windows-  ──→  40 个 CSV + 23 txt  ──→  Adapter 适配  ──→  结构化谓词  ──→  Markdown
ir-...ps1           Linux 30+ txt         统一 Schema        确定性匹配        可疑项清单
linux-ir-...sh                          （流式，不整读）
     ↑                                        ↑                  ↑
  采集侧不动                          本目录新增的核心        复用 v0.1 引擎
```

**为什么不去改采集脚本让它直接输出 JSON？**
因为脚本要在目标机上保持只读、离线、零依赖，且**已采集的历史证据也要能用**。
在分析侧做适配，是取证工作流的正确分层——这也是"异构系统接入"在工程上的含义。

---

## 目录结构

```
mcp/
├── README.md                  # 本文件
├── requirements.txt           # 运行 MCP Server 所需（核心引擎不需要）
│
├── triage.py                  # 规则研判引擎（零依赖，v0.2 扩展了结构化谓词）
├── guard.py                   # 安全护栏：入参校验 + 审计日志（零依赖）
├── server.py                  # MCP Server（fastmcp），4 个只读 Tool
├── selfcheck.py               # 零依赖自检：规则引擎 + 完整流水线，不装任何包也能跑
│
├── irflow/                    # ★ v0.2 新增：数据流水线
│   ├── schema.py              # 统一数据模型（Record / Finding / Collection）
│   ├── pipeline.py            # 编排：探测 → 解析 → 归一 → 研判
│   ├── report.py              # 报告生成（Markdown / 终端摘要）
│   └── adapters/
│       ├── base.py            # 适配器接口 + 注册表（新增数据源只改这里的两行）
│       ├── windows_quickcheck.py   # Windows 采集产物适配器
│       └── linux_quickcheck.py     # Linux 采集产物适配器
│
├── rules/
│   └── triage-rules.yaml      # 规则库（37 条：10 条关键词规则 + 27 条结构化规则）
│
├── eval/                      # ★ v0.2 新增：效果评估
│   ├── run_eval.py            # 评估脚本：量化命中率与误报率
│   ├── labels.json            # 带标注的评估集
│   └── samples/               # 合成样本（Windows / Linux 各一套）
│
├── bench/
│   └── bench_parse.py         # ★ v0.2 新增：性能基准（吞吐 + 内存）
│
├── docs/
│   ├── demo-report-windows.md # 示例研判报告（Windows 样本）
│   ├── demo-report-linux.md   # 示例研判报告（Linux 样本）
│   └── 面试讲解稿.md           # 三句话 / 五分钟 / 诚实边界
│
├── audit/                     # 审计日志目录（运行时生成，已 gitignore）
└── 一键自检.bat                # Windows 双击运行自检
```

---

## 快速开始

### 第一步：零依赖自检（**现在就能跑，不用装任何包**）

```bash
cd mcp
python selfcheck.py
```

会依次验证：
1. 规则文件能否被正确解析（含 PyYAML 缺失时的离线兜底解析器）
2. 4 条示例告警的研判结果是否合理
3. **完整流水线**能否跑通（对 `eval/samples/` 的两套合成样本）
4. 「人在回路」标记是否恒定

### 第二步：对一份采集产物跑流水线

```bash
# 直接看终端摘要
python -c "from irflow import run_pipeline; from irflow.report import render_text_summary; print(render_text_summary(run_pipeline(r'C:\IR\HOST-01-20260925')))"

# 生成 Markdown 报告
python -c "from irflow import run_pipeline, render_markdown; r=run_pipeline(r'C:\IR\HOST-01-20260925'); open('report.md','w',encoding='utf-8').write(render_markdown(r))"
```

示例输出见 [`docs/demo-report-windows.md`](docs/demo-report-windows.md)。

### 第三步：跑效果评估与性能基准

```bash
python eval/run_eval.py --verbose      # 规则库效果评估
python bench/bench_parse.py            # 性能基准
```

### 第四步：启动 MCP Server（需安装 mcp 包）

```bash
pip install "mcp[cli]>=1.28.1,<2"
mcp dev server.py                      # 用 Inspector 验证
```

> ⚠️ **必须锁 `mcp<2`**：mcp 2.x 把 `FastMCP` 改名为 `MCPServer`
> （导入路径由 `mcp.server.fastmcp` 变为 `mcp.server.mcpserver`），
> 本 Server 基于 1.x API 编写，未锁版本时装到 2.x 会直接
> `ModuleNotFoundError: No module named 'mcp.server.fastmcp'`，Server 起不来。
> 该版本约束已写入 `requirements.txt`。

---

## 四个 MCP Tool

| Tool | 作用 | 入参约束 |
|---|---|---|
| `triage_alert` | 对一段告警/日志文本做规则初筛 | `alert` ≤ 20000 字符；`top_k` 用 `Literal[1,2,3,5,10]` |
| `analyze_collection` | **对采集产物目录做完整研判**，返回按严重级别排序的可疑项清单，可选输出 Markdown 报告 | `result_dir` 经路径校验；`out_report` 可选 |
| `list_rules` | 列出规则库覆盖范围 | `severity` 用 `Literal` 枚举 |
| `list_sources` | 列出支持的采集来源与**已知盲区** | 无 |

后两个工具的存在意义是**让 Agent 知道边界**：回答"这台机器有没有问题"之前，
先知道自己能看什么、不能看什么。

---

## 效果评估：规则库到底准不准

规则写完不能凭感觉说"应该挺准的"。做法是准备**带标注的合成样本**——
每份样本标明「应该命中哪些规则」，跑一遍统计指标，改规则后再跑，看指标变好还是变坏。

```bash
python eval/run_eval.py
```

当前基准（合成样本，非真实环境指标）：

| 样本 | 归一化记录 | 命中线索 | 召回率 | 精确率 |
|---|---|---|---|---|
| windows-demo | 35 条 | 14 条 | **100%** (13/13) | **100%** |
| linux-demo | 55 条 | 18 条 | **100%** (12/12) | **100%** |

> 这两个数字**只在合成样本上成立**，不能外推到真实环境。它的价值在于
> 提供了一条可复现的回归基线：改规则跑一遍，指标掉了就说明改坏了。

**这套评估集实际抓出了三个真实缺陷**（不是摆设）：

1. 规则 `NET-001` 把 `0.0.0.0` 放进 `not_in` 白名单——**绑定全部网卡的监听才是最该关注的**，写反了
2. Linux 适配器对 `cron.txt` / `ssh.txt` **逐行照收**，把 `SHELL=/bin/sh`、`ls -l` 行、段标题都当成了持久化项，噪声巨大 → 改为按行语义识别
3. **自研 YAML 兜底解析器**的 bug：`'C:\Windows\'` 里的冒号在引号内，却被当成 key/value 分隔符，导致所有含冒号的 Windows 路径规则静默失效

第 3 个尤其典型：装了 PyYAML 的机器上一切正常，**只有离线环境才出错**——
而离线恰恰是应急现场的主要形态。已修复并验证两条解析路径结果完全一致。

---

## 性能：能不能处理大规模日志

应急现场一台跑过半年的服务器，进程快照几万行、事件日志上百万行。
**"能跑小样本"不等于"能用"**，所以做了基准测试：

```bash
python bench/bench_parse.py
```

| 规模 | 文件大小 | 优化前 | 优化后 | 提速 |
|---|---|---|---|---|
| 1 万行 | 1.1 MB | 1.16 s | 0.40 s | 2.9× |
| 10 万行 | 11.3 MB | 12.07 s | 3.20 s | 3.8× |
| **50 万行** | **56.5 MB** | **64.50 s** | **15.10 s** | **4.3×** |

吞吐从 8,600 行/秒提升到 **31,267 行/秒**。

**优化的过程**（这是比结果更值得讲的部分）：

1. 先测基线，不猜
2. 用 `cProfile` 定位，发现 `ntpath.relpath` 占总耗时 **72%**——因为解析器对**每条记录**
   都重算一次来源文件的相对路径，同一个文件被算了 10 万次，内部还触发大量 `normcase`
   （Windows 上 160 万次调用）
3. 加一层 `(root, path) → relpath` 缓存，该项开销归零
4. 回归验证：优化后评估指标必须**完全不变**（召回 100%、精确 100%）

同时验证了**内存与数据量解耦**：流水线全程用生成器，峰值内存恒定在几十 KB 量级，
不随文件增长；对照的"全量读入"实现在 50 万行时峰值内存达 80 MB 并线性增长。

---

## 规则库

`rules/triage-rules.yaml` 共 **37 条**，分两类：

**关键词规则（10 条，v0.1）** —— 匹配文本，用于人工粘贴的告警
`MINING-001` `WEBSHELL-001` `PERSIST-001` `PERSIST-002` `EXEC-001` `CRED-001`
`C2-001` `EXEC-002` `COLLECT-001` `DEFENSE-001`

**结构化规则（27 条，v0.2）** —— 直接比对采集产物的字段，用于自动化研判

| 前缀 | 覆盖 | 示例 |
|---|---|---|
| `PROC-*` | 进程 | 可执行文件落在临时目录、无签名、已删除可执行文件、`/proc` 与 `ps` 差集隐藏进程 |
| `NET-*` | 网络 | 对外地址高危端口监听、C2 常用端口外连、矿池端口、端口转发配置 |
| `PERSIST-*` | 持久化 | 隐藏计划任务、Run 键指向临时目录、服务路径含命令行解释器、IFEO、SilentProcessExit、WMI 事件订阅、SSH 公钥、cron 与 systemd 指向临时目录 |
| `ACCT-*` | 账号 | UID 0 的非 root 账号、可登录 shell + 家目录在临时目录 |
| `FILE-*` | 文件 | 临时目录下的 SUID 文件、无主文件 |
| `MOD-*` | 内核模块 | 模块加载项待核对 |
| `CFG-*` | 配置 | 审计策略被削弱、杀软排除项覆盖面过大 |
| `DEFENSE-*` | 反取证 | 日志完整性校验失败 |

### 结构化规则怎么写

```yaml
- id: PERSIST-006
  name: 服务路径包含命令行解释器
  attack: { technique: T1543.003, tactic: Persistence, name: Windows Service }
  severity: critical
  match:
    kind: persistence          # 限定记录种类
    platform: windows          # 限定平台
    all:                       # 以下谓词必须全部成立
      - field: mech
        equals: service
      - field: path
        regex: '(?i)(cmd\.exe|powershell|/c\s|base64)'
  false_positive_hints: [...]  # 误报提示 → 进报告
  next_steps: [...]            # 建议的人工验证步骤 → 进报告
```

支持的算子：`equals` / `not_equals` / `in` / `not_in` / `contains` / `not_contains` /
`startswith` / `not_startswith` / `endswith` / `not_endswith` / `regex` / `not_regex` /
`exists` / `not_exists` / `gt` / `lt`

**规则作用域**：宽泛的关键词规则可以标 `scope: alert`，表示"仅用于文本告警"。
这类规则套到结构化产物上噪声很大（正常 cron 行、正常服务名都会撞上），
必须排除——这是评估集量化后发现的，不是拍脑袋加的。

---

## 设计决策（面试最该讲的部分）

### 1. 判定环节不放进模型

`triage_alert` 与 `analyze_collection` **完全不调用大模型，也不发起任何网络请求**。
命中与否由本地 YAML 规则做确定性匹配，同样的输入永远得到同样的输出，可复现、可审计。

模型的价值被限定在两个位置：
- **入口**：把人话（"这台机器好像在挖矿"）翻译成工具调用
- **出口**：把结构化的 JSON 结果讲成人话

中间的"是不是攻击、属于哪一类、该不该处置"——**不让模型参与**。
原因很直接：应急现场判定错一次，代价是误处置（业务中断）或漏处置（失陷扩大），
而幻觉是概率性的，靠提示词约束压不到零。

### 2. 人在回路是**代码写死的**

```python
result["human_review_required"] = True     # 硬编码
result["auto_action_allowed"]   = False    # 硬编码
```

这两行在 `server.py`、`triage.py`、`irflow/pipeline.py` 的返回值里都显式赋值，
**任何调用路径都不会改变它**。无论客户端的提示词怎么写、模型怎么输出，
返回值里这两个标记都不变。

### 3. 零第三方依赖（离线可用）

`triage.py` / `guard.py` / `irflow/` 全部只用标准库：
- 有 PyYAML 时用 PyYAML 解析规则
- 没有时回退到内置的最小 YAML 子集解析器

这不是炫技。应急现场经常是离线的、只带一个 U 盘和便携 Python 的环境，
装不了包就跑不了的工具，在真实场景下没有价值。

### 4. 只暴露只读能力

四个工具全是查询/研判类，**没有任何命令执行、文件写入、主机隔离接口**。
`analyze_collection` 只读采集产物目录，不改动其中任何文件；
需要落盘报告时必须由调用方显式提供 `out_report` 路径。

### 5. 每次调用留痕

`guard.audit()` 把每次工具调用落盘到 `audit/YYYYMMDD.jsonl`，
记录时间、工具名、参数、是否成功、结果摘要。

### 6. 报告必须写清楚"我没查什么"

生成的 Markdown 报告里有专门一节「能力边界」，列出：
- 已知盲区（内核 Rootkit、BYOVD、内存马、业务调度平台后门、云身份滥用）
- 本次产物清单（用于核对采集完整性）

因为一份声称全覆盖的应急报告是不可信的。**说清楚"我没查什么"，
比多说一句"我很强"更能让复核者放心**——尤其是"未命中线索"时，
必须同时说明"可能是采集缺项导致假阴性"。

---

## 与仓库其他文档的关系

| 文档 | 关系 |
|---|---|
| `windows/windows-forensics-toolchain.md` §5 | 本实现的**设计来源**：MCP/Agent 架构、工具清单、八条安全底线 |
| `scripts/*-ir-quickcheck.*` | 采集侧产出，本目录的**输入**；不改动它们 |
| `ir/ir-framework.md` | 研判流程与分级标准的设计依据 |
| `windows/windows-detection-validation.md` | 已知盲区清单的来源，与本目录报告中的盲区声明一致 |
| `*-attack-mapping.md` | 规则关键词、ATT&CK 映射与 `next_steps` 的取材来源 |

---

## 能力边界（如实说明）

**能做的**：把两套采集脚本的产物归一化，按 37 条规则做确定性初筛，
输出带 ATT&CK 映射、误报提示、人工验证步骤的可疑项清单，并可量化效果与性能。

**不能做的**：
- 不做内网横向、流量分析、日志关联（这是 SIEM/SOAR 的活）
- 不覆盖内核级 Rootkit / BYOVD / 内存马（需内存取证工具配合）
- 规则是"关键词 + 字段匹配"的初筛器，**不是检测引擎**，
  不解决免杀绕过与未知攻击
- 目前只接了 2 个数据源适配器（双平台采集脚本），接口已就绪但
  EDR 导出、auditd、Sigma JSON 等尚未实现

---

## 路线图

- [x] **v0.1.0**：规则引擎 + 护栏 + 2 个只读 Tool + 自检脚本
- [x] **v0.2.0**：数据流水线（双平台适配器）+ 结构化规则 30 条 + 效果评估集 + 性能基准 + 4 个 Tool
- [ ] v0.3.0：接入真实日志源（Windows 安全日志 4624/4625/4688/4104、Linux auditd / journald）
- [ ] v0.4.0：扩评估集到 100+ 标注样本（含真实脱敏样例），把召回/精确量化到分场景
- [ ] v0.5.0：HTML 报告与时间线视图；多主机产物横向比对（同一攻击者在多台机器上的痕迹聚类）
- [ ] v1.0.0：效果评估体系闭环（人工研判结论回流 → 规则迭代 → 复测）

---

## 声明

本项目不含任何来自真实客户环境的数据。`eval/samples/` 全部为合成数据，
IP 使用 RFC 5737 文档保留段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24），
主机名与账号均为虚构。规则关键词来自公开威胁情报、ATT&CK 技术描述与开源社区公开样本。
