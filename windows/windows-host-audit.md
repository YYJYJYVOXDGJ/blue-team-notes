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



2、启动项与计划任务排查

注册表开机自启

查看所有用户开机启动项

Get-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

查看当前用户开机启动项

Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"



计划任务

列出所有计划任务

schtasks /query /fo LIST /v

Get-ScheduledTask | Select-Object TaskName,State,Author



系统服务

查看所有运行中的服务

Get-Service | Where-Object {$\_.Status -eq "Running"}

按启动类型筛选

Get-WmiObject Win32\_Service | Select-Object Name,State,StartMode,PathName



3、用户与登录日志排查

本地用户枚举

Get-LocalUser

net user



登录事件日志

查看成功登录事件（ID 4624）

Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 20

查看登录失败事件（ID 4625）

Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 20



4、恶意文件与痕迹排查

临时目录与下载目录

检查用户临时目录

Get-ChildItem $env:TEMP -File | Sort-Object LastWriteTime -Descending



最近打开文件

Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Recent" | Sort-Object LastWriteTime -Descending



5、应急响应处置命令

强制结束进程

taskkill /F /PID 进程PID

禁用计划任务

Disable-ScheduledTask -TaskName "任务名"

停止并禁用服务

Stop-Service -Name 服务名; Set-Service -Name 服务名 -StartupType Disabled



