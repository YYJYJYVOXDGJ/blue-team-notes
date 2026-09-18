Linux 主机应急排查速查表（蓝队）

1\. 端口与网络连接

bash

查看所有监听端口与对应进程（推荐，比netstat速度快）

ss -tulnp

传统netstat查询方式

netstat -tulnp

查看所有TCP连接状态（排查外连C2信道）

ss -tan



列出所有运行进程，全格式显示用户、PID、CPU、内存

ps aux

树形显示进程父子关系，溯源恶意进程父进程

pstree -p

实时监控进程资源占用

top

强制结束可疑进程

kill -9 进程PID



查看当前在线登录用户

w

查看历史登录成功记录

last

查看登录失败记录（暴力破解排查）

lastb

列出系统所有用户账号

cat /etc/passwd

列出所有UID=0的超级管理员账号

awk -F: '$3==0{print $1}' /etc/passwd



查看开机自启服务（Systemd系统）

systemctl list-unit-files --type=service | grep enabled

查看当前用户定时任务

crontab -l

查看系统级定时任务目录

ls -la /etc/cron.d/

ls -la /var/spool/cron/



查找最近24小时内修改过的文件

find / -mtime -1 -type f 2>/dev/null

查看临时目录可疑文件

ls -la /tmp/

查找SUID提权权限文件

find / -perm -u+s -type f 2>/dev/null



2、启动项与服务排查

开机自启项

ls -l /etc/init.d/

cat /etc/rc.local

systemctl list-unit-files | grep enabled



cron计划任务

crontab -l

cat /etc/crontab

ls -l /etc/cron.\*



XXL‑JOB 定时任务排查（Java分布式任务调度，常见入侵利用点）

> XXL‑JOB如果配置管理接口未授权、弱口令，攻击者可新增执行任务实现命令执行、后门驻留，是红蓝对抗常见打点驻留点位

bash

查找xxl‑job相关进程

ps aux | grep -i xxl‑job



查找xxl‑job部署jar包，寻找安装目录

find / -name "\*xxl‑job\*.jar" 2>/dev/null



查看xxl‑job日志目录（默认日志路径，根据实际部署路径调整）

ls -l /data/applogs/xxl-job/

tail -n 50 /data/applogs/xxl-job/xxl-job-admin.log



查看配置文件，获取数据库连接信息，任务数据存储在MySQL

find / -name "application\*.properties" 2>/dev/null | xargs grep -l "xxl.job" 2>/dev/null



如果拿到数据库权限，可查询任务定义、执行器、任务日志

select \* from xxl\_job\_info;       # 查看所有定时任务

select \* from xxl\_job\_log;        # 查看任务执行历史记录

select \* from xxl\_job\_user;       # 查看后台账号



检测xxl‑job‑admin管理端口，默认8080/8081

netstat -antp | grep java





3、用户与登录日志

用户账号排查

cat /etc/passwd

cat /etc/shadow

查看具有root权限的用户

awk -F: '$3==0{print $1}' /etc/passwd



登录日志

最近登录记录

last

lastb

正在登录用户

w

who

登录日志全文

cat /var/log/secure | grep Accepted

cat /var/log/secure | grep Failed



4、进程与恶意文件排查

可疑进程详细信息

ps auxf

查看进程打开的文件

lsof -p 进程PID



可疑文件排查

最近24小时修改的可执行文件

find / -mtime -1 -type f \\( -name "\*.sh" -o -name "\*.elf" \\)

检查tmp目录可疑文件

ls -lt /tmp /var/tmp



5、应急响应处置

结束进程

kill -9 进程PID

锁定用户

passwd -l 用户名

禁止IP

iptables -A INPUT -s IP地址 -j DROP

