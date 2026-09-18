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









