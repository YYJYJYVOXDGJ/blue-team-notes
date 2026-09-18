Windows 主机应急排查手册（蓝队）

1\. 端口与进程排查

基础命令行查询

cmd

列出所有TCP/UDP端口、对应PID，数字形式不解析域名（最常用）

netstat -ano



列出所有TCP连接，包含本地地址、端口、状态、所属进程ID

Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,State,OwningProcess

只查看监听状态的端口

Get-NetTCPConnection -State Listen



tasklist | findstr "PID号"

示例：tasklist | findstr 1234



taskkill /F /PID 进程PID



查看系统级开机自启（HKLM，所有用户生效）

Get-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

查看当前用户级开机自启（HKCU，仅当前用户生效）

Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"



列出所有就绪状态的计划任务

Get-ScheduledTask | Where-Object {$\_.State -eq "Ready"}

查看任务详细信息与执行程序路径

Get-ScheduledTaskInfo -TaskName 任务名



列出本地所有用户账号

Get-LocalUser

列出管理员组所有成员

Get-LocalGroupMember Administrators

命令行查看所有用户，识别$结尾隐藏账号

net user



读取最近30条安全日志

Get-WinEvent -LogName Security -MaxEvents 30 | Select-Object TimeCreated,Id,Message

筛选所有登录失败事件

Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20



列出所有运行中的服务

Get-Service | Where-Object {$\_.Status -eq "Running"}

筛选自动启动的服务（持久化排查重点）

Get-Service | Where-Object {$\_.StartType -eq "Automatic"}



