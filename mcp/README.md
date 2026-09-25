# blue-team-notes-mcp

> 把「主机应急响应工具集」的排查经验封装成**可被 AI Agent 调用的只读 MCP 能力**。
>
> 一句话定位：**不造一个会乱说的 AI 分析师，只造一个确定性的研判工具，让模型负责翻译和表达。**

本目录是 [blue-team-notes](https://github.com/YYJYJYVOXDGJ/blue-team-notes) 仓库 `windows/windows-forensics-toolchain.md` §5 中
「MCP / Agent 设计」章节的**第一个可运行实现**（A 档最小可用版，v0.1.0）。

---

## 目录结构

```
blue-team-notes-mcp/
├── README.md                  # 本文件
├── requirements.txt           # 运行 MCP Server 所需的依赖（核心引擎不需要）
├── triage.py                  # 【核心】本地规则研判引擎，零第三方依赖
├── guard.py                   # 【核心】安全护栏：入参校验 + 审计日志，零第三方依赖
├── server.py                  # MCP Server（fastmcp），把上面两个能力暴露成 MCP Tool
├── selfcheck.py               # 零依赖自检脚本：不装任何包也能跑通验证
├── rules/
│   └── triage-rules.yaml      # 研判规则库（10 条，带 ATT&CK 映射 / 误报提示 / 人工验证步骤）
├── audit/                     # 审计日志目录（运行时自动生成，已在 .gitignore 中排除）
└── docs/
    └── 面试讲解稿.md           # 三句话 / 五分钟 / 诚实边界，讲这个项目时照着说
```

---

## 设计决策（面试最该讲的部分）

### 1. 判定环节不放进模型

`triage_alert` 这个工具**完全不调用大模型，也不发起任何网络请求**。
命中与否由本地 yaml 规则库做确定性匹配，同样的输入永远得到同样的输出，可复现、可审计。

模型的价值被限定在两个位置：

- **入口**：把人话（"这台机器好像在挖矿"）翻译成工具调用
- **出口**：把结构化的 JSON 结果讲成人话

中间的"是不是攻击、属于哪一类、该不该处置"——**不让模型参与**。
原因很直接：应急现场判定错一次，代价是误处置（业务中断）或漏处置（失陷扩大），
而幻觉是概率性的，靠提示词约束压不到零。

### 2. 人在回路是**代码写死的**，不是提示词约束的

```python
result["human_review_required"] = True     # 硬编码
result["auto_action_allowed"]   = False    # 硬编码
```

这两行在 `server.py` 的返回值里显式赋值，在 `triage.py` 的结果结构里也是默认值。
无论客户端的提示词怎么写、模型怎么输出，返回值里这两个标记都不会变。

同时 `SERVER_INSTRUCTIONS` 里写了四条约束，要求模型：

1. 只调用本 Server 提供的只读工具
2. 必须原样传达"待人工确认"标记，不得省略
3. 禁止输出删除文件、结束进程、隔离主机等处置动作作为最终建议，只能给"建议人工执行的验证命令"
4. 规则未命中时如实说明，不得凭常识编造结论

### 3. 零第三方依赖（离线可用）

`triage.py` 与 `guard.py` **不依赖任何第三方包**：

- 有 PyYAML 时用 PyYAML 解析规则
- 没有 PyYAML 时回退到内置的最小 YAML 子集解析器（`_mini_yaml_load`）

这不是炫技。应急现场经常是离线的、只带一个 U 盘和便携 Python 的环境，
装不了包就跑不了的工具，在真实场景下没有价值。

### 4. 只暴露只读能力

当前只提供两个工具，都是查询/研判类，**没有任何命令执行、文件写入、主机隔离接口**：

| Tool | 作用 | 入参约束 |
|---|---|---|
| `triage_alert` | 对一条告警/日志片段做规则初筛，返回命中规则、ATT&CK 映射、置信度、误报提示、建议的人工验证步骤 | `alert` 文本 ≤ 20000 字符；`top_k` 用 `Literal[1,2,3,5,10]` 约束 |
| `list_rules` | 列出规则库覆盖范围，让调用方知道能力边界 | `severity` 用 `Literal` 枚举约束 |

`guard.py` 的 `safe_path()` 拒绝路径穿越（`..`）与全部 shell 元字符（`| ; & \` $() ' " < >` 等），
防止参数被拼进命令行造成注入。当前版本没有暴露路径类工具，`safe_path` 是为后续 B 档（日志采集类工具）预留的护栏。

### 5. 每次调用留痕

`guard.audit()` 把每次工具调用落盘到 `audit/YYYYMMDD.jsonl`，记录时间、工具名、参数、是否成功、结果摘要（截断 500 字符）。
审计失败不影响主流程，但会在 stderr 留痕。

---

## 快速开始

### 第一步：零依赖自检（**现在就能跑，不用装任何包**）

```bash
python selfcheck.py
```

预期输出：加载 10 条规则，跑 4 条示例告警（挖矿 / WebShell / 可疑计划任务 / 正常日志），
最后打印「安全底线校验（人在回路标记恒定）：通过」。

这一步通过，说明核心能力没问题；剩下的只是 MCP 协议那一层包装。

示例输出见 `docs/demo-output.txt`。

### 第二步：安装 MCP 依赖并启动 Server

```bash
pip install "mcp[cli]"
python server.py          # 默认 stdio 传输
```

### 第三步：用 MCP Inspector 验证

```bash
mcp dev server.py
```

打开 Inspector 后调用 `triage_alert`，传入一段告警文本，即可看到结构化结果。

### 第四步：接入 MCP 客户端（可选）

Claude Desktop 的 `claude_desktop_config.json` 中加入：

```json
{
  "mcpServers": {
    "blue-team-ir": {
      "command": "python",
      "args": ["C:/path/to/blue-team-notes-mcp/server.py"]
    }
  }
}
```

---

## 规则库现状

`rules/triage-rules.yaml` 共 10 条，每条包含：`id` / `name` / `attack`（ATT&CK 编号、战术、技术名）/ `severity` /
`keywords` / `false_positive_hints`（误报提示）/ `next_steps`（建议人工验证步骤）。

| ID | 场景 | ATT&CK | 级别 |
|---|---|---|---|
| MINING-001 | 挖矿进程与矿池通信 | T1496 Resource Hijacking | high |
| WEBSHELL-001 | WebShell 落地或访问 | T1505.003 Web Shell | critical |
| EXEC-002 | 可疑子进程（应用进程起命令行） | T1059 Command and Scripting Interpreter | critical |
| DEFENSE-001 | 日志清除与防御规避 | T1070.001 Clear Windows Event Logs | critical |
| EXEC-001 | 可疑 PowerShell（含编码命令） | T1059.001 PowerShell | high |
| CRED-001 | 可疑登录与凭据攻击 | T1110 Brute Force | high |
| C2-001 | 可疑外连与远控通信 | T1071 Application Layer Protocol | high |
| COLLECT-001 | 数据打包与外带 | T1560 Archive Collected Data | high |
| PERSIST-001 | 可疑计划任务创建 | T1053.005 Scheduled Task | medium |
| PERSIST-002 | 可疑服务创建或服务替换 | T1543.003 Windows Service | medium |

规则来源：`ir-framework.md` 的排查清单 + `windows-attack-mapping.md` / `linux-attack-mapping.md` 的持久化项，
关键词取自真实告警文本里出现过的特征（矿池协议、WebShell 文件名与函数、日志清除命令等）。

**当前局限（如实说明）**：这是关键词匹配 + 严重级别打分的初筛器，不是检测引擎。
它解决的是"告警太多、人看不过来、需要先把明显的一类归拢出来"这个分诊问题，
不解决免杀绕过、未知攻击这类需要行为分析与情报支撑的问题。

---

## 路线图

- [x] **v0.1.0（本版）**：规则引擎 + 护栏 + 2 个只读 Tool + 自检脚本
- [ ] v0.2.0：接入真实日志源（Windows 安全日志 4624/4625/4688/4104，Linux auth.log / auditd），规则库扩到 30+
- [ ] v0.3.0：B 档工具集（进程/端口/启动项快照、日志时间窗提取），全部只读
- [ ] v0.4.0：用本仓库沉淀的排查清单做回归测试集，量化规则的命中率与误报率
- [ ] v1.0.0：效果评估体系（人工研判结论回流 → 规则迭代 → 复测），对应 JD 中「Agent 效果优化」

---

## 与仓库其他文档的关系

| 文档 | 关系 |
|---|---|
| `windows/windows-forensics-toolchain.md` §5 | 本实现的**设计来源**：MCP/Agent 架构、工具清单、八条安全底线 |
| `ir/ir-framework.md` | 研判流程与分级标准的设计依据 |
| `windows/windows-attack-mapping.md` / `linux/linux-attack-mapping.md` | 规则关键词与 `next_steps` 的取材来源 |
| `scripts/` | 已有的采集类脚本；B 档计划把它们封装成只读 Tool |

---

## 声明

本项目不含任何来自真实客户环境的数据。规则关键词全部来自公开威胁情报、
ATT&CK 技术描述与开源社区公开样本，示例告警为构造数据。
