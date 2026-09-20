# GitHub 仓库元信息设置建议

> 本文件是**给仓库维护者的操作说明**，不是给访客看的内容。
> 仓库设置项（Description / Topics / Social preview）无法通过 git 提交生效，需要在 GitHub 网页端手动填写。本文件提供可直接复制的文案。

## 为什么需要单独维护这两项

`About` 区的 Description 与 Topics 是**访客看到的第一句话**，也是 GitHub 搜索与推荐的主要依据。当前仓库的 Description 仍是早期版本（写于仓库只有两份命令清单时），与项目现状严重不符——它会让人误判项目水平。

## 一、Description（About 区，最多 350 字符）

在仓库首页右侧 **About → ⚙️ → Description** 中填写。

### 推荐文案（英文优先，便于检索）

```text
Blue team host incident response & security audit toolkit for Windows/Linux: standardized host triage playbooks, hardening baselines, ATT&CK attack-to-artifact mapping, detection validation, plus read-only PowerShell/Shell collection scripts. Covers XXL-JOB / middleware backdoor persistence.
```

### 备选（中文，如希望访客一眼看到中文定位）

```text
蓝队主机应急响应与安全审计工具集（Windows/Linux）：双平台主机入侵排查手册、安全加固基线、ATT&CK 攻击手法映射、检测能力验证，配套只读采集与基线核查脚本；含 XXL-JOB 等中间件后门持久化专项排查。
```

> ⚠️ **务必替换掉旧描述**：`蓝队学习笔记，包含Windows/Linux应急排查、端口进程分析、系统日志审计、简单应急响应脚本，用于网络安全蓝队学习。`
> 问题在于「学习笔记」「简单」——这两个词会把项目定位拉低一档，且与实际的应急响应体系（流程 SOP / 场景预案 / 文书模板 / 检测验证）完全不符。

## 二、Topics（仓库标签，最多 20 个）

在 **About → ⚙️ → Topics** 中逐个添加。Topics 影响 GitHub 站内搜索与推荐，建议全部填满。

```text
blue-team
incident-response
dfir
digital-forensics
threat-hunting
security-audit
edr
windows-security
linux-security
attack-mapping
mitre-attack
sigma
sysmon
powershell
detection-engineering
hardening
cybersecurity
infosec
soc
malware-analysis
```

## 三、About 区其他建议

| 项 | 建议值 |
|---|---|
| **Website** | 可留空；若有博客或其他介绍页再填 |
| **Releases** | 建议在 `main` 上打 `v0.3.0` tag，About 区会显示版本入口 |
| **Packages** | 不适用 |
| **Include in the home page** | 勾选 **Releases**、**Packages** 中的 Releases；**Topics** 自动显示 |

## 四、Social preview（分享卡片图）

**Settings → General → Social preview → Upload an image**，建议尺寸 **1280 × 640**。

若暂无设计图，可用项目名称文字排版：深色底 + `blue-team-notes` 主标题 + 副标题「Windows/Linux 主机应急响应与安全审计工具集」，可显著提升在社交平台与技术社区的传播观感。

## 五、检查清单

- [ ] Description 已替换为上方推荐文案
- [ ] Topics 已填满 20 个
- [ ] 已在 `main` 打 `v0.3.0` tag
- [ ] Social preview 图片已上传
- [ ] About 区勾选了 Releases
