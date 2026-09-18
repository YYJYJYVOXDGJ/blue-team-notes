# 场景化处置预案

> 本文是 `ir-playbook.md` 的**场景分支**：确定事件类型后直接翻到对应章节照做。每个场景采用统一结构——**识别信号 → 10 分钟确认 → 遏制（含禁忌）→ 清除与根因 → 恢复与加固 → 复盘要点**。

| 编号 | 场景 | 典型触发 |
|---|---|---|
| S1 | [勒索软件与双重勒索](#s1-勒索软件与双重勒索) | 文件被加密、勒索信、卷影副本被删 |
| S2 | [挖矿](#s2-挖矿) | CPU/GPU 长期打满、异常出向到矿池 |
| S3 | [Web 打点 / Webshell / 内存马](#s3-web-打点--webshell--内存马) | Web 进程异常子进程、目录异常文件 |
| S4 | [凭据泄露与横向移动](#s4-凭据泄露与横向移动) | 异常登录类型、多主机同时认证、DCSync |
| S5 | [数据外带与数据泄露](#s5-数据外带与数据泄露) | 大流量出向、网盘/对象存储上传 |
| S6 | [APT 长期潜伏](#s6-apt-长期潜伏) | 低频 C2、合法工具滥用、日志被选择性清理 |
| S7 | [供应链与 CI-CD](#s7-供应链与-ci-cd) | 构建产物异常、流水线被改、发布凭据新增 |
| S8 | [云主机与容器 / K8s](#s8-云主机与容器--k8s) | AK 泄露、元数据服务滥用、K8s 审计异常 |

**通用前置**：任何场景的第 0 步都是「固定证据」——跑 `scripts/linux-ir-quickcheck.sh` 或 `scripts/windows-ir-quickcheck.ps1`，导出日志、算哈希、存独立证据盘。详见 `ir-playbook.md` §4.1。

---

## S1 勒索软件与双重勒索

> 定位：**P0**。这是唯一一个「时间就是损失」的场景——每分钟都有新数据被加密。

### 识别信号

- 文件扩展名被批量追加（`.encrypted` / `.locked` / 随机后缀），目录出现勒索信（`README.txt` / `HOW_TO_DECRYPT`）
- **卷影副本被删除**（`vssadmin delete shadows` / `wbadmin delete catalog`）——清备份是勒索的标准前置动作
- 备份服务器、NAS、虚拟化平台（ESXi/vCenter）出现异常访问或加密
- 大量 SMB 写操作、磁盘 IO 与 CPU 异常升高
- Defender/EDR 被关闭（5001/5007），大量文件被重命名

### 10 分钟确认

```powershell
# Windows：卷影副本是否还在（这是能否快速恢复的关键）
vssadmin list shadows
wmic shadowcopy list brief
# 勒索信与加密文件样本
Get-ChildItem C:\ -Include *.txt,*.html -Recurse -Depth 2 -EA SilentlyContinue |
  Where-Object { $_.Name -match 'README|DECRYPT|RESTORE|HOW_TO' }
# 加密进程与来源
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=11} -MaxEvents 50
# 谁在写（横向加密的判断）
Get-SmbSession | Select-Object ClientComputerName,ClientUserName,NumOpens
```

```bash
# Linux：加密文件与最近变更
find / -xdev -newermt '-2 hours' -type f 2>/dev/null | head -50
ls -lt / | head            # 找勒索信
# 快照/备份是否被动过
ls -la /.snapshot 2>/dev/null; lvs 2>/dev/null
```

### 遏制（含禁忌）

**立即做**

1. **切断网络，保留供电**——物理拔网线或封交换机端口，**不要关机、不要重启**
2. 断开共享存储与 NAS 挂载点，**暂停备份任务**（防止离线备份也被加密）
3. 隔离虚拟化层：检查并保护 ESXi/vCenter、快照存储
4. 定位加密源头主机（写操作最集中的那台），优先隔离
5. 冻结被用于横向的账号（尤其是域管、备份账号）

**⚠️ 禁忌**

| 禁忌 | 原因 |
|---|---|
| 关机 / 重启 | 丢失内存中的密钥与配置线索；部分勒索在重启后进入引导加密阶段 |
| 直接删除勒索信与加密样本 | 失去家族与解密可能性判断依据 |
| 盲目使用网上的解密工具 | 部分工具会二次破坏文件结构，且可能夹带恶意代码 |
| 从**可能已被加密**的备份恢复 | 会把加密状态带回生产 |
| 自行决定是否支付赎金 | 涉及法律、保险与监管，必须由 IMT + 法务决定（多数情形不建议，且不保证解密） |
| 加密还在进行时做大规模文件操作 | 加剧 IO 压力，且干扰取证 |

### 清除与根因

- 常见入口：**RDP 暴露 + 弱口令**、VPN 无 MFA、对外服务漏洞（如中间件/虚拟化平台）、钓鱼附件、第三方运维通道
- 按持久化全量核对清单清除（`*-attack-mapping.md`），勒索团伙普遍使用「服务 + 计划任务 + 共享账号」多点维持
- **全量凭据重置**：域管、本地管理员、备份账号、服务账号、云 AK

### 恢复与加固

- [ ] 恢复来源必须**早于入侵时间**（确认入口时间点，否则恢复即二次投毒）
- [ ] 优先使用**离线/不可变备份**；在线备份需先验证未被污染
- [ ] 分阶段恢复：外围 → 中间件/数据库 → 应用 → 核心业务
- [ ] 加固：关闭 RDP 对公网暴露（改跳板 + MFA）、备份隔离化与不可变、开启受控文件夹访问、EDR 全量覆盖

### 复盘要点

- 备份为什么被影响？是**离线/不可变**的吗？恢复实际耗时多少（有没有实测过）？
- 从加密开始到被发现的时长（MTTD）是多少？为什么监控没在加密**之前**告警？
- 是否构成数据泄露（双重勒索常伴随数据外带）→ 若涉及**个人信息**，按 `ir-playbook.md` §8.2 判定上报义务

**关联**：`windows/windows-attack-mapping.md`（勒索专项）· `linux/linux-attack-mapping.md`（勒索专项）· `ir-playbook.md` §3、§6

---

## S2 挖矿

> 定位：**P2**（若已影响业务性能或伴随横向，升 P1）。挖矿本身破坏性有限，但**它证明主机已被完全控制**，且攻击者常同时留有后门。

### 识别信号

- CPU / GPU 长期接近满载，进程名伪装成系统进程（`kdevtmpfsi` / `xmrig` / `sysupdate` / 随机 12 位字母）
- 出向连接到常见矿池端口：`3333` `4444` `5555` `7777` `14444` `45700`，或指向矿池域名
- 异常守护：两个进程互相拉起（杀一个另一个立刻重启）
- 容器内出现挖矿（K8s 被利用挖矿的典型特征）

### 10 分钟确认

```bash
# Linux：高 CPU + 网络落点
ps -eo pid,ppid,pcpu,etime,cmd --sort=-pcpu | head -20
ss -tnp | grep -E 'ESTAB' | head -30
# 守护与自启
crontab -l; ls -la /etc/cron.* /var/spool/cron/* 2>/dev/null
systemctl list-units --type=service --state=running | grep -vE 'ssh|systemd'
ls -la /etc/ld.so.preload; cat /etc/ld.so.preload 2>/dev/null
```

```powershell
# Windows：高占用与外连
Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name,Id,CPU,Path
Get-NetTCPConnection -State Established |
  Where-Object { $_.RemotePort -in 3333,4444,5555,7777,14444,45700 } |
  Select-Object LocalAddress,RemoteAddress,RemotePort,OwningProcess
Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch 'C:\\Windows' } | Select Name,PathName,State
```

### 遏制（含禁忌）

1. **先记录后处置**：截图/导出进程树与网络连接（挖矿进程常带自毁或加密配置）
2. 封堵矿池出口（IP + 域名 + 端口），阻断收益通道
3. **同时处理互拉的两个进程**（只杀一个会被立刻拉起，是常见的「杀不干净」原因）
4. 禁用被利用账号，改密并踢会话
5. 容器场景：先 `docker inspect` / `kubectl describe` 留证，再隔离节点

**禁忌**：只杀进程不清自启（几分钟后复活）；只清当前用户 crontab 而漏掉其他用户与 systemd；直接删除挖矿程序而不留样本（无法判断是否有其他后门）。

### 清除与根因

清除顺序：**先断自启 → 再杀进程 → 最后删文件**（顺序反了就是反复复活）

- [ ] 清理 cron（含 `/var/spool/cron/` 所有用户）、systemd unit、`rc.local`、`profile.d`
- [ ] 检查 `ld.so.preload`、可疑内核模块、SUID 异常（挖矿常带 rootkit 组件）
- [ ] 检查是否存在**未授权访问类入口**：Redis/MongoDB/Elasticsearch 未授权、Docker API 暴露、Web 漏洞、SSH 弱口令、K8s API 未授权
- [ ] 检查是否同时被用作**跳板或代理**（挖矿宿主常兼职做代理池）

### 恢复与加固

- [ ] 关闭未授权访问（绑内网 + 认证 + 最小权限）
- [ ] 补齐资源监控与出向流量告警（挖矿之所以能长期存在，通常是**没人看 CPU 和出向流量**）
- [ ] 若为容器场景：清异常镜像与 Deployment/DaemonSet/CronJob，加固 K8s RBAC 与准入

### 复盘要点

- 为什么长期没发现？主机资源监控与出向告警是否存在？
- 除挖矿外是否还有其他后门？（**挖矿是表象，控制权才是实质**）
- 是否会因算力占用与对外攻击行为影响合规（被举报为攻击源）

**关联**：`linux/linux-attack-mapping.md`（挖矿专项）· `windows/windows-attack-mapping.md`（挖矿专项）· `ir-scenarios.md` S8

---

## S3 Web 打点 / Webshell / 内存马

> 定位：**P1**（对外服务被控制）。核心难点是**内存马**——磁盘上什么都查不到。

### 识别信号

- Web 目录、上传目录、临时目录出现近期新增的异常文件（`.jsp` `.php` `.aspx` `.ashx`，或伪装成图片/日志的双扩展名）
- Web 进程出现异常子进程链：`w3wp.exe → cmd.exe`、`java → sh -c`、`nginx → /bin/sh`
- Web 进程异常外连（反弹 shell、下载后续载荷）
- 中间件日志中异常请求：超大 POST、可疑 UA、非常规路径、单 IP 高频

### 10 分钟确认

```bash
# Linux：Web 目录近 30 天变更 + 可疑内容
find /var/www /usr/share/nginx /opt/tomcat -type f -newermt '-30 days' -ls 2>/dev/null | head -40
grep -rlE 'eval\(|Runtime\.getRuntime|ProcessBuilder|base64_decode|assert\(' \
  /var/www /opt/tomcat/webapps 2>/dev/null | head -20
# 进程链异常
ps -ef --forest | grep -iE 'java|php|nginx|tomcat'
```

```powershell
# Windows：IIS 目录 + 进程模块
Get-ChildItem C:\inetpub\wwwroot -Recurse -File |
  Where-Object LastWriteTime -gt (Get-Date).AddDays(-30) |
  Select-Object FullName,LastWriteTime,Length
# w3wp 加载的非标准模块（内存马的重要线索）
Get-Process w3wp -EA SilentlyContinue | ForEach-Object {
  $p=$_; $p.Modules | Where-Object { $_.FileName -notmatch 'Microsoft\.NET|System32|WinSxS|Program Files' } |
    Select-Object @{n='PID';e={$p.Id}},FileName
}
# 应用日志里的可疑请求
Select-String -Path C:\inetpub\logs\LogFiles\*\*.log -Pattern 'POST' |
  Select-Object -Last 40
```

**内存马确认**（磁盘无痕时）：
- Java：`jcmd <pid> GC.class_histogram` / heap dump 后用 MAT 或专用工具搜 `Filter`/`Servlet` 异常注册、`jsp` 类名异常
- .NET：`pe-sieve` / HollowsHunter 扫进程内存中的可疑模块
- 通用：内存镜像 + Volatility 的 `malfind` 插件

### 遏制（含禁忌）

1. **保全请求日志与样本**（Web 日志常被滚动覆盖，先复制出来）
2. 从负载均衡下线该节点（摘流量），而不是直接关机
3. 若无法立即下线：在 WAF 层阻断攻击者 IP 与利用路径，同时保持日志采集
4. 隔离同应用的其他节点（同一镜像/同版本可能存在相同漏洞）

**禁忌**：直接删除 Webshell 文件（丢掉样本与入口分析依据，且对手可能已上传多个）；只处理单节点而忽略同集群；重启应用进程（内存马会随之消失，证据一并消失——**先 dump 内存再重启**）。

### 清除与根因

- [ ] 清除所有 Webshell（**逐个确认**，含图片马、双扩展名、隐藏目录）
- [ ] 处理内存马：在取证后重启服务/重建容器；若为 IIS 模块后门，需检查 `applicationHost.config` 与全局程序集
- [ ] 修复入口：上传校验、反序列化、目录执行权限、框架/组件漏洞补丁
- [ ] 轮换应用与运维凭据：数据库、Redis、对象存储 AK、CI-CD Token（Web 应用常内嵌这些凭据）
- [ ] 检查是否被植入**持久化**（Web 打点后通常立刻建立持久化，见 `*-attack-mapping.md`）

### 恢复与加固

- [ ] 回归流量前先复测原入口（漏洞是否真的堵了）
- [ ] Web 目录设为不可执行（上传目录尤其）、上传类型白名单
- [ ] WAF 规则补充并验证生效
- [ ] 中间件日志留存期与告警（POST 大小、异常路径、异常 UA、单 IP 频率）

### 复盘要点

- WAF/防护为什么没拦住？规则是「记录模式」还是「拦截模式」？
- 从打点到发现间隔多久？Web 日志有没有告警？
- 应用内嵌凭据的管理方式是否合理？（硬编码凭据是横向的重灾区）

**关联**：`windows/windows-host-audit.md` §6.3（IIS 与内存马）· `windows/windows-attack-mapping.md`（Webshell 专项）· `linux/linux-attack-mapping.md`（Web 打点专项）

---

## S4 凭据泄露与横向移动

> 定位：**P1**（涉域控/堡垒机升 **P0**）。这是「主机失陷」升级为「全网失陷」的转折点。

### 识别信号

- 登录类型异常：Type 3（网络）、Type 9（NewCredentials）、Type 10（RDP）在非工作时段/异常源 IP
- 大量失败登录后出现成功登录（爆破成功）
- 同一账号短时间内在多台主机认证
- `4648`（显式凭据登录）、`4672`（授予特权）、`4728/4732`（加入特权组）
- 域环境：`4769` 异常（Kerberoasting 的 RC4 票据请求）、`4662` 含复制 GUID（DCSync 特征）
- LSASS 被访问、`mimikatz`/`procdump` 特征命令、SAM/SYSTEM 注册表被导出

### 10 分钟确认

```powershell
# 登录全景（按类型与来源 IP 聚合）
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625,4648} -MaxEvents 300 |
  Select-Object TimeCreated,Id,@{n='User';e={$_.Properties[5].Value}},
                @{n='Type';e={$_.Properties[8].Value}},@{n='IP';e={$_.Properties[18].Value}} |
  Group-Object Id,Type,IP | Sort-Object Count -Descending | Select-Object -First 20 Count,Name
# 特权组变更
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4728,4732,4756,4720,4726} -MaxEvents 50
# LSASS 访问（Sysmon 10）
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} -MaxEvents 50 |
  Where-Object { $_.Message -match 'lsass' } | Select-Object TimeCreated,Message
```

```bash
# Linux：认证成功/失败来源分布
grep -Ei 'Accepted|Failed' /var/log/secure /var/log/auth.log 2>/dev/null |
  awk '{print $1,$2,$9,$11}' | sort | uniq -c | sort -rn | head -20
lastb | head -20; last -aiF | head -20
# 凭据文件被动过
ls -la /etc/shadow /etc/gshadow /root/.ssh/ /home/*/.ssh/authorized_keys
```

### 遏制（含禁忌）

1. **先摸范围，再动凭据**——顺序错了会打草惊蛇且造成大面积业务中断
2. 隔离受影响主机、限制域控入向连接
3. 禁用可疑账号并**踢出会话、吊销 token/证书**（只改密码不够）
4. 建立「凭据污染清单」：哪些账号的密码/哈希可能已被窃取 → 全部纳入轮换计划

**禁忌**：只改密码不踢会话；在范围未明时全网统一改密（业务中断 + 惊动对手）；只处理业务账号而忽略**服务账号、备份账号、域管、云 AK**（这些才是对手真正想要的）。

### 清除与根因

- [ ] 重置**全部**受影响凭据：域管、特权账号、本地管理员、服务账号、SSH 公钥、云 AK
- [ ] 域环境专项：`krbtgt` 密码**连续重置两次**（清除黄金票据）；清理委派；审计 GPO 启动脚本与登录脚本
- [ ] 清理对手建立的账号与组关系，检查是否有隐藏的本地管理员
- [ ] 清除持久化（横向成功后必然建据点）
- [ ] 根因：入口是弱口令 / MFA 缺失 / 凭据硬编码 / LSASS 未保护 / 委派配置不当？

### 恢复与加固

- [ ] 强制 MFA 覆盖：VPN、RDP、堡垒机、云控制台、CI-CD
- [ ] 开启 LSASS 保护（Credential Guard / RunAsPPL）、限制调试权限
- [ ] 特权账号隔离：域管账号仅用于域控登录，日常运维用分级管理账号
- [ ] 加固：禁止 NTLM 降级、限制 RDP 暴露、最小化委派、LAPS 管理本地管理员口令

### 复盘要点

- 黑客用了多少时间完成横向？我们的检测在哪一环缺席？
- 特权账号体系是否「一人多权」？堡垒机是否被绕过？
- MFA 覆盖率的真实数字是多少（不是「要求了」，是「强制了」）？

**关联**：`windows/windows-host-audit.md` §4 · `windows/windows-attack-mapping.md`（凭据窃取/横向移动专项）· `ir-playbook.md` §5.3

---

## S5 数据外带与数据泄露

> 定位：**P1/P0**。**法律风险最高**的场景——一旦涉及个人信息或重要数据，立刻触发上报义务。

### 识别信号

- 出向流量异常（大流量、非工作时段、指向云存储/网盘/代码托管/匿名文件中转）
- 打包行为：`rar`/`7z`/`tar`/`zip` 对数据库目录或业务数据目录操作
- 数据库批量导出：`mysqldump`、`bcp`、`SELECT ... INTO OUTFILE`、大量查询单个账号
- 通过合法通道外带：企业邮箱发大附件、企业网盘、IM 文件传输、云盘同步客户端
- DLP / 代理 / 防火墙出现敏感数据特征告警

### 10 分钟确认

```bash
# Linux：外连 + 大文件 + 打包进程
ss -tnp | grep ESTAB
ps -ef | grep -Ei 'tar|zip|7z|rar|mysqldump|pg_dump|scp|rsync|curl -F|rclone'
find / -xdev -size +100M -newermt '-3 days' -type f 2>/dev/null | head -20
grep -rEi 'SELECT .* INTO OUTFILE|INTO DUMPFILE' /var/log/mysql/ 2>/dev/null | tail
```

```powershell
# Windows：出向 + 压缩 + 云盘进程
Get-NetTCPConnection -State Established | Select-Object RemoteAddress,RemotePort,OwningProcess
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'rar|7z|Makecab|Compress-Archive|rclone' } |
  Select-Object ProcessId,Name,CommandLine
Get-ChildItem $env:USERPROFILE,C:\Windows\Temp -Recurse -File -EA SilentlyContinue |
  Where-Object { $_.Length -gt 100MB } | Select-Object FullName,Length,LastWriteTime
# 邮件与网盘（外部外带通道）
Get-Process | Where-Object { $_.Name -match 'OneDrive|BaiduNetdisk|WeChat|DingTalk|Feishu' }
```

### 遏制（含禁忌）

1. **精准切断出向通道**——断出向，保留入向以便继续取证
2. 冻结相关账号、暂停同步类客户端
3. **保全证据**：代理/防火墙/DLP/邮件网关日志优先导出（这些日志留存期往往很短）
4. **立即法务前置**：判定数据类型与规模 → 是否构成个人信息/重要数据泄露 → 是否触发上报

**禁忌**：在取证前清理外带中转文件；只处理主机不管通道（对手还有别的通道）；技术团队自行判断「没有泄露」——数据是否外带需要证据，不是推测。

### 清除与根因

- [ ] 清除持久化与通道（隧道、代理、云 AK）
- [ ] 轮换所有可能被读取的凭据
- [ ] 定位数据导出方式（SQL 导出 / 应用接口越权 / 文件系统打包 / 备份文件窃取）
- [ ] 评估是否涉及**数据库备份文件被窃**（这是最容易被忽略的外带方式）

### 恢复与加固

- [ ] 数据已经外带无法收回，止损点是**阻止持续外带 + 履行告知义务**
- [ ] 出向白名单化、限制云盘/网盘/个人邮箱通道
- [ ] 数据分类分级 + 敏感数据访问审计（谁在什么时候读了什么）
- [ ] 数据库导出操作审计与告警（异常时间、异常账号、大批量）

### 复盘要点

- 外带通道为什么可用？出向是否默认放行？
- 从外带开始到发现的时长（可能以天/周计）——**这是 MTTD 最差的场景**
- 上报义务判定是否及时？是否满足时限要求（见 `ir-playbook.md` §8.2）？
- 是否已有数据分类分级？没有分级就无法判断严重性

**关联**：`windows/windows-attack-mapping.md`（数据外带专项）· `linux/linux-attack-mapping.md`（数据外带专项）· `ir-playbook.md` §8

---

## S6 APT 长期潜伏

> 定位：**P0**。特征是「不明显、周期长、目标明确」，往往不是靠告警发现，而是靠**主动狩猎**或外部通报。

### 识别信号

- 低频 C2：固定周期或固定抖动的心跳（每 30 分钟 / 每小时），流量小而规律
- 合法工具滥用：系统自带工具做反常动作（`certutil` 下载、`bitsadmin` 传输、`netsh` 隧道、远程管理工具）
- 凭据长期可用：异常账号在数月内偶尔使用，来源 IP 固定
- 日志被**选择性**清理：只删特定时间段、特定主机
- 多台不相关主机存在同一细微特征（同一证书指纹、同一 User-Agent、同一命名管道）

### 10 分钟确认（狩猎思路，非等待告警）

```powershell
# 周期性连接聚类（找心跳）
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=3} -MaxEvents 2000 |
  Group-Object RemoteIp,RemotePort | Sort-Object Count -Descending | Select-Object -First 20
# 合法工具的异常使用
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 1000 |
  Where-Object { $_.Message -match 'certutil|bitsadmin|mshta|rundll32|regsvr32|wmic' } |
  Select-Object TimeCreated,@{n='Cmd';e={($_.Message -split "`n" | Select-String 'CommandLine')}}
# 日志空洞检测（跳号 = 被删过）
Get-WinEvent -LogName Security -MaxEvents 200 | Select-Object RecordId,TimeCreated | Sort-Object TimeCreated
```

```bash
# Linux：长时间跨度内的低频连接与异常账号
grep -hE 'ESTAB|SYN' /var/log/* 2>/dev/null | awk '{print $5}' | sort | uniq -c | sort -rn | head -20
# 审计日志缺口（对比 journald boot 与文件日志）
journalctl --list-boots | tail -20
ls -la /var/log/ | grep -E 'secure|auth|messages|syslog'
# 隐藏账号与 sudo 异常
awk -F: '($3>=1000||$3==0){print}' /etc/passwd
```

### 遏制（**长遏制**优先）

APT 场景的核心权衡是**打草惊蛇**：

1. **默认先观察**：仅加强监控，暂不动手；目标是摸清范围（哪些主机、哪些凭据、哪些通道）
2. 如需干预，优先**静默取证**（不改变主机可见状态）
3. 待范围清晰后，**全域一次性清除**（同时动作，避免漏网触发对手反制）
4. 保护信任锚点：域控、堡垒机、CA、KMS、备份、CI-CD、云控制台账号

**禁忌**：发现一处就立刻清理（对手立刻换据点）；只在单机做动作而不摸全网；在未掌握 C2 通道的情况下贸然切断（对手可能启用备用通道并进入破坏阶段）。

### 清除与根因

- [ ] 全域持久化核对（`*-attack-mapping.md` 全量清单逐项打勾）
- [ ] 全部凭据轮换，包括证书与令牌（APT 常用证书做长期认证）
- [ ] 清除 C2 通道并监控其再次出现
- [ ] 根因：入口是钓鱼、供应链、0day、还是第三方运维通道？

### 恢复与加固

- [ ] 加严监控期延长至 **30 天以上**（普通事件 14 天）
- [ ] 引入情报（IOC/基础设施指纹）到检测规则，形成长期监控
- [ ] 简化信任链：减少长期有效凭据、强制短周期令牌、收敛运维通道
- [ ] 补齐日志留存期（APT 常驻留数月，**30 天留存根本不够**——这是最常见的硬伤）

### 复盘要点

- 我们的日志留存期能覆盖多久？如果对手驻留 6 个月，我们的证据还剩多少？
- 为什么告警没发现？检测规则是否只覆盖「高噪声」技术，而漏掉低调手法？
- 是否有能力做**主动狩猎**，还是只能等告警？

**关联**：`windows/windows-attack-mapping.md`（ATT&CK 全战术表与 2024–2026 趋势）· `linux/linux-attack-mapping.md` · `windows/windows-detection-validation.md` §7（已知盲区）

---

## S7 供应链与 CI-CD

> 定位：**P0**。影响面是「所有由该流水线交付的系统」，且往往涉及对外产品。

### 识别信号

- 构建产物与历史版本哈希不一致，或产物中出现非常规文件
- 依赖包版本突变 / 引入未知源 / 依赖投毒
- 流水线配置被修改：新增构建步骤、新增 secrets 引用、改为向外部地址上传
- 发布凭据新增：仓库 SSH Key、访问令牌、服务账号
- 代码仓库出现来源不明的提交、`postinstall` 脚本、构建脚本被改
- 镜像仓库出现重新推送的旧 tag（**最隐蔽的一种**）

### 10 分钟确认

```bash
# 代码与配置变更审计
git log --since='90 days ago' --stat --author-date-order | head -100
git log -p --since='90 days ago' -- .github/ .gitlab-ci.yml Jenkinsfile Dockerfile | head -200
# 依赖与锁文件是否被改
git log --oneline --since='90 days ago' -- package-lock.json requirements.txt go.sum pom.xml
# 凭据与密钥
grep -rInE 'AKIA|BEGIN (RSA|OPENSSH) PRIVATE KEY|password\s*=' --include='*.yml' --include='*.yaml' . | head
```

```bash
# 产物一致性（与制品库对比）
sha256sum dist/*.tar.gz
# 镜像层审计
docker history --no-trunc <image>:<tag> | head -40
```

### 遏制（含禁忌）

1. **冻结发布**：暂停所有流水线，避免继续向生产扩散
2. 轮换全部 CI-CD 凭据：仓库 Token、流水线 secrets、签名密钥、制品库账号、云部署凭据
3. 回滚生产到**已验证可信**的版本
4. 排查已发布产物是否被下载/使用（涉及对外分发时，可能需要通知下游用户）

**禁忌**：只清理代码仓库而不检查**制品库与镜像仓库**；只轮换部分凭据；在未确认哪些产物受影响前恢复发布。

### 清除与根因

- [ ] 清除恶意提交、恶意依赖、恶意流水线步骤
- [ ] 清理制品库中的污染产物（含已推送的旧 tag）
- [ ] 重建流水线环境（构建机常被植入持久化）
- [ ] 检查构建机是否有持久化（构建机是「高信任」主机，值得重点核对）

### 恢复与加固

- [ ] 发布链路最小权限：流水线按需授权，不与生产长期凭据共用
- [ ] 引入**产物签名与验证**、SBOM（软件物料清单）、依赖来源锁定
- [ ] 关键发布双人复核；敏感变更告警
- [ ] 外部依赖入私库（避免上游投毒）、定期审计依赖

### 复盘要点

- 发布链路是否有凭据硬编码？是否有审计日志且留存足够？
- 产物是否可验证来源（签名/哈希）？没有的话，如何证明当前生产运行的是什么？
- 是否能快速回答「哪些客户受影响了」？（涉及对外通知时这是必答项）

**关联**：`windows/windows-attack-mapping.md`（供应链专项）· `windows/windows-host-audit.md` §8.4（Jenkins/CI 凭据）

---

## S8 云主机与容器 / K8s

> 定位：**P1**（涉云控制台账号或大规模数据升 **P0**）。云环境的响应顺序与传统主机**相反**：先控云侧身份，再进主机处置。

### 识别信号

- **AK/SK 泄露**：代码仓库、镜像层、日志、前端 JS、错误堆栈中出现 AccessKey
- 访问实例元数据服务：进程连接 `169.254.169.254`（凭据窃取的经典手法，IMDSv1 未禁用时尤其危险）
- 云审计异常调用：`CreateAccessKey`、`AttachUserPolicy`、`CreateUser`、`RunInstances`、`ModifySecurityGroup`
- K8s 审计异常：`exec` 进入 Pod、创建 `clusterrolebinding`、创建特权 Pod、`hostPath` 挂载 `/`
- 容器逃逸特征：容器内看到宿主机进程、`/proc/1/root` 访问、Docker Socket 被挂载
- 异常工作负载：新出现的 Deployment/DaemonSet/CronJob，镜像来自未知仓库

### 10 分钟确认

```bash
# 元数据服务被访问（AWS/阿里云等）
grep -r '169.254.169.254' /var/log/ 2>/dev/null | tail
# 云审计（示例：AWS CloudTrail / 阿里云 ActionTrail 控制台或 CLI 查询）
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --max-results 20
# K8s 审计与异常工作负载
kubectl get events -A --sort-by=.lastTimestamp | tail -40
kubectl get pods -A -o wide | grep -vE 'kube-|coredns|calico|flannel'
kubectl get clusterrolebinding -o json | jq -r '.items[] | select(.subjects[]?.kind=="ServiceAccount") | .metadata.name' | head
# 容器内逃逸迹象（在容器中执行）
ls -la /var/run/docker.sock 2>/dev/null; cat /proc/1/cgroup | head
```

### 遏制（含禁忌）

**顺序关键：先云侧身份，再主机**

1. **禁用泄露的 AK/SK**、撤销已发放的临时凭据、使会话失效
2. 收回安全组/网络 ACL 中的异常放行规则
3. 隔离受影响实例（安全组收紧而非直接关机，便于取证）
4. K8s：撤销 ServiceAccount token、隔离节点、暂停受影响工作负载
5. 保全云审计日志（**云日志留存期与覆盖范围要提前确认**）

**禁忌**：只处理容器内进程而不管**云侧身份**（AK 仍然可用，随时重建环境）；直接删除实例（云审计与元数据证据随之消失，正确做法是先打快照/镜像）；只删 Pod 不删 Deployment/DaemonSet（会自动重建）。

### 清除与根因

- [ ] 清除恶意工作负载（Deployment / DaemonSet / CronJob / 特权 Pod / 恶意镜像）
- [ ] 吊销全部 token，重建受影响节点（容器节点重建比清理更可靠）
- [ ] 轮换云凭据、IAM 策略回滚到最小权限
- [ ] 根因：AK 硬编码？IMDSv1 未禁用？K8s API 未授权？RBAC 过宽？镜像来源不可信？

### 恢复与加固

- [ ] **禁用 IMDSv1**（强制 IMDSv2）或启用实例元数据服务屏蔽
- [ ] 使用短期凭据（IRSA / OIDC / 实例角色）替代长期 AK
- [ ] K8s：准入控制（禁止特权 Pod、禁止 hostPath、镜像白名单）、审计日志开启并集中收集
- [ ] 镜像扫描与签名验证；CI-CD 与生产凭据彻底隔离
- [ ] 云侧启用异常 API 调用告警（尤其是 IAM 类操作），加严监控期 14–30 天

### 复盘要点

- AK 为什么会在代码/镜像/日志里？是否有密钥扫描机制？
- 云审计日志是否完整、留存多久？能否支撑「攻击者做过什么」的完整还原？
- K8s RBAC 与准入控制的实际强度，是否验证过（而不是默认配置）？

**关联**：`ir-playbook.md` §9（多平台协同）· `windows/windows-host-audit.md` §8（云与 CI-CD 凭据）· `linux/linux-host-audit.md` §8（容器与 K8s 专项）

---

## 附：场景决策速查

| 现象 | 最可能场景 | 第一动作 | 关键禁忌 |
|---|---|---|---|
| 文件被批量加密 + 卷影副本消失 | S1 勒索 | **断网但不关机** | 不要重启/删样本/盲目解密 |
| CPU 打满 + 连矿池 | S2 挖矿 | 记录后同时清互拉进程 | 只杀进程不清自启 |
| `w3wp`/`java` 拉起 shell | S3 Web 打点 | 保全日志 + 摘流量 | 重启服务前先 dump 内存 |
| 多主机同一账号异常登录 | S4 横向 | 摸范围后再动凭据 | 未弄清范围就全网改密 |
| 出向大流量 + 打包进程 | S5 数据外带 | 精准断出向 + 法务前置 | 自行断言「没泄露」 |
| 规律性心跳 + 合法工具滥用 | S6 APT | **长遏制**，先摸清范围 | 发现一处就立即清理 |
| 产物哈希不一致 + 流水线被改 | S7 供应链 | 冻结发布 + 轮换发布凭据 | 只顾代码不管制品库 |
| 元数据服务被访问 + IAM 异常调用 | S8 云/容器 | **先禁用 AK**，再进主机 | 只处理容器不管云身份 |

---

**相关文档**：`ir-playbook.md`（流程）· `ir-framework.md`（体系与分级）· `ir-templates.md`（文书）· `linux/linux-host-audit.md` · `windows/windows-host-audit.md` · `linux/linux-attack-mapping.md` · `windows/windows-attack-mapping.md`
