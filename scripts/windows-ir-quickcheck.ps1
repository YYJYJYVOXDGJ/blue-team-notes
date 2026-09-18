#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 主机应急响应快速采集（只读）

.DESCRIPTION
    用于蓝队应急现场建立第一手基线。本脚本【完全只读】：
    不修改注册表、不删除文件、不终止进程、不改变任何系统配置。

    采集内容：系统信息 / 网络 / 进程 / 服务驱动 / 持久化 / 账号 / 日志 / 文件痕迹，
    并在结尾自动汇总"需要人工确认"的可疑项。

.PARAMETER OutputDir
    结果输出目录。默认 C:\IR\<主机名>-<时间戳>

.PARAMETER IncludeFileScan
    启用较慢的文件扫描（近期可执行文件、ADS、Zone.Identifier）。
    默认关闭；大磁盘上可能耗时较长。

.PARAMETER StaleHours
    "最近文件"的时间窗口（小时），默认 72。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\windows-ir-quickcheck.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\windows-ir-quickcheck.ps1 -IncludeFileScan -StaleHours 168

.NOTES
    必须以管理员身份运行，否则部分模块结果不完整。
    输出结果是"线索"而非"结论"，每条都需人工确认。
    配套手册：windows/windows-host-audit.md
#>
[CmdletBinding()]
param(
    [string]$OutputDir,
    [switch]$IncludeFileScan,
    [int]$StaleHours = 72
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# ============================================================
# 0. 初始化
# ============================================================

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $OutputDir) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputDir = Join-Path 'C:\IR' ("{0}-{1}" -f $env:COMPUTERNAME, $stamp)
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:LogLines = New-Object System.Collections.Generic.List[string]

function Write-Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message
    $script:LogLines.Add($line)
    Write-Host $line
}

function Add-Finding {
    param(
        [ValidateSet('High','Medium','Low')][string]$Severity,
        [string]$Category,
        [string]$Detail,
        [string]$Evidence = ''
    )
    $script:Findings.Add([PSCustomObject]@{
        Severity = $Severity
        Category = $Category
        Detail   = $Detail
        Evidence = $Evidence
    })
}

function Save-Csv {
    param($Data, [string]$Name)
    if ($null -eq $Data) { return }
    $arr = @($Data)
    if ($arr.Count -eq 0) { return }
    $path = Join-Path $OutputDir ("{0}.csv" -f $Name)
    $arr | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Windows IR QuickCheck (Read-Only)"        -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " 主机: $env:COMPUTERNAME"
Write-Host " 用户: $env:USERNAME"
Write-Host " 管理员权限: $IsAdmin"
Write-Host " 输出目录: $OutputDir"
Write-Host ""

if (-not $IsAdmin) {
    Write-Host "[!] 未以管理员身份运行，部分结果将不完整（服务/驱动/安全日志）。" -ForegroundColor Yellow
}

# ============================================================
# 1. 系统信息
# ============================================================
Write-Log "采集系统信息..."

try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bi = Get-CimInstance Win32_BIOS

    $sysInfo = [PSCustomObject]@{
        ComputedAt        = (Get-Date).ToString('s')
        Hostname          = $env:COMPUTERNAME
        Domain            = $cs.Domain
        PartOfDomain      = $cs.PartOfDomain
        OSName            = $os.Caption
        OSVersion         = $os.Version
        BuildNumber       = $os.BuildNumber
        Architecture      = $os.OSArchitecture
        InstallDate       = $os.InstallDate
        LastBootUpTime    = $os.LastBootUpTime
        UptimeHours       = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
        SystemDrive       = $os.SystemDrive
        WindowsDirectory  = $os.WindowsDirectory
        Manufacturer      = $cs.Manufacturer
        Model             = $cs.Model
        SerialNumber      = $bi.SerialNumber
        TimeZone          = (Get-TimeZone).Id
        LocalTime         = (Get-Date).ToString('s')
        UtcOffsetMinutes  = [int][TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IsAdmin           = $IsAdmin
    }
    $sysInfo | Format-List | Out-File (Join-Path $OutputDir '01-system.txt') -Encoding UTF8
    Save-Csv $sysInfo '01-system'

    # 时间同步状态（时间不准会导致整个时间线错位）
    $w32 = (& w32tm /query /status) 2>&1
    $w32 | Out-File (Join-Path $OutputDir '01-timesync.txt') -Encoding UTF8

    # 补丁
    $hotfix = Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy
    Save-Csv $hotfix '01-hotfix'

    $recentPatch = $hotfix | Sort-Object InstalledOn -Descending |
        Select-Object -First 1
    if ($recentPatch -and $recentPatch.InstalledOn) {
        $days = ((Get-Date) - $recentPatch.InstalledOn).Days
        if ($days -gt 90) {
            Add-Finding 'Medium' 'Patch' "最近补丁安装于 $days 天前，可能存在补丁缺口" `
                ($recentPatch | Out-String).Trim()
        }
    }
} catch {
    Write-Log "系统信息采集出错: $_"
}

# ============================================================
# 2. 网络
# ============================================================
Write-Log "采集网络信息..."

try {
    # 2.1 监听端口
    $listen = Get-NetTCPConnection -State Listen |
        Select-Object LocalAddress, LocalPort, OwningProcess,
            @{n='Process';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}},
            @{n='Path';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Path}}
    Save-Csv $listen '02-listen'

    # UDP
    $udp = Get-NetUDPEndpoint |
        Select-Object LocalAddress, LocalPort, OwningProcess,
            @{n='Process';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}}
    Save-Csv $udp '02-udp'

    # 2.2 外连
    $conn = Get-NetTCPConnection -State Established |
        Where-Object {
            $_.RemoteAddress -notin @('127.0.0.1','::1','0.0.0.0','::') -and
            $_.RemoteAddress -notmatch '^fe80'
        } |
        Select-Object RemoteAddress, RemotePort, LocalAddress, LocalPort,
            OwningProcess,
            @{n='Process';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}},
            @{n='Path';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Path}}
    Save-Csv $conn '02-established'

    # 高危端口线索
    $riskyPort = 4444,4445,50050,1080,7890,3333,5555,7777,9999,14444,45560,31337,12345
    foreach ($c in @($conn)) {
        if ($riskyPort -contains [int]$c.RemotePort) {
            Add-Finding 'High' 'Network' "连接到高危端口 $($c.RemotePort)（进程 $($c.Process)）" `
                "Remote=$($c.RemoteAddress):$($c.RemotePort) Path=$($c.Path)"
        }
    }

    # 2.3 DNS 缓存
    $dns = Get-DnsClientCache | Select-Object Entry, Data, Type, TimeToLive
    Save-Csv $dns '02-dnscache'
    foreach ($d in @($dns)) {
        if ($d.Entry -and $d.Entry.Length -gt 40) {
            Add-Finding 'Medium' 'Network' "超长域名（疑似 DNS 隧道/外带）: $($d.Entry)" ''
        }
    }

    # 2.4 hosts
    $hosts = 'C:\Windows\System32\drivers\etc\hosts'
    if (Test-Path $hosts) {
        $h = Get-Content $hosts
        $h | Out-File (Join-Path $OutputDir '02-hosts.txt') -Encoding UTF8
        $active = $h | Where-Object { $_ -and $_ -notmatch '^\s*#' }
        if ($active) {
            Add-Finding 'Medium' 'Network' "hosts 文件存在非注释条目" (($active -join ' | '))
        }
    }

    # 2.5 路由 / ARP / 网卡
    Save-Csv (Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric) '02-route'
    Save-Csv (Get-NetNeighbor | Where-Object { $_.State -ne 'Unreachable' } |
        Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias) '02-arp'
    Save-Csv (Get-NetIPConfiguration -Detailed | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer) '02-ipconfig'

    # 2.6 防火墙
    $fwProfile = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    Save-Csv $fwProfile '02-firewall-profiles'
    foreach ($p in @($fwProfile)) {
        if (-not $p.Enabled) {
            Add-Finding 'High' 'Network' "防火墙配置文件 $($p.Name) 未启用" ''
        }
    }
    Save-Csv (Get-NetFirewallRule -Enabled True |
        Select-Object DisplayName, Direction, Action, Profile) '02-firewall-rules'

    # 2.7 端口转发（极隐蔽的后门通道）
    $pp = (& netsh interface portproxy show all) 2>&1
    $pp | Out-File (Join-Path $OutputDir '02-portproxy.txt') -Encoding UTF8
    $ppText = ($pp | Out-String)
    if ($ppText -match '\d+\.\d+\.\d+\.\d+') {
        Add-Finding 'High' 'Network' "存在 netsh portproxy 端口转发规则" $ppText.Trim()
    }

    # 2.8 代理
    $winhttp = (& netsh winhttp show proxy) 2>&1
    $winhttp | Out-File (Join-Path $OutputDir '02-proxy.txt') -Encoding UTF8
    $ieProxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -EA SilentlyContinue
    $ieProxy | Select-Object ProxyEnable, ProxyServer, AutoConfigURL |
        Format-List | Out-File (Join-Path $OutputDir '02-proxy.txt') -Encoding UTF8 -Append
    if ($ieProxy.AutoConfigURL) {
        Add-Finding 'High' 'Network' "检测到 PAC 自动代理脚本（AutoConfigURL）" $ieProxy.AutoConfigURL
    }

    # 2.9 RDP 与其他远程访问
    $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -EA SilentlyContinue
    if ($ts -and $ts.fDenyTSConnections -eq 0) {
        Add-Finding 'Medium' 'Network' "RDP 已启用（fDenyTSConnections=0）" ''
    }
    $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -EA SilentlyContinue
    if ($rdp) {
        $rdp | Select-Object PortNumber, UserAuthentication, SecurityLayer |
            Format-List | Out-File (Join-Path $OutputDir '02-rdp.txt') -Encoding UTF8
        if ($rdp.UserAuthentication -eq 0) {
            Add-Finding 'Medium' 'Network' "RDP 未启用 NLA 网络级认证" ''
        }
    }
    if (Test-Path 'C:\Program Files\RDP Wrapper') {
        Add-Finding 'High' 'Network' "检测到 RDP Wrapper（可能被用作多会话后门）" 'C:\Program Files\RDP Wrapper'
    }

    # 2.10 SMB
    Save-Csv (Get-SmbShare | Select-Object Name, Path, Description) '02-smbshare'
    $smb = Get-SmbServerConfiguration -EA SilentlyContinue
    if ($smb) {
        $smb | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature |
            Format-List | Out-File (Join-Path $OutputDir '02-smb.txt') -Encoding UTF8
        if ($smb.EnableSMB1Protocol) {
            Add-Finding 'High' 'Network' "SMBv1 已启用（高危，应关闭）" ''
        }
    }
    Save-Csv (Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens) '02-smbsession'
} catch {
    Write-Log "网络采集出错: $_"
}

# ============================================================
# 3. 进程
# ============================================================
Write-Log "采集进程..."

try {
    $procs = Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
    Save-Csv $procs '03-process'

    # 进程树文本
    ($procs | Sort-Object ParentProcessId |
        Format-Table -AutoSize -Wrap | Out-String -Width 400) |
        Out-File (Join-Path $OutputDir '03-process-tree.txt') -Encoding UTF8

    # 3.1 多源一致性（隐藏进程线索）
    $psIds  = @((Get-Process).Id | Sort-Object -Unique)
    $cimIds = @((Get-CimInstance Win32_Process).ProcessId | Sort-Object -Unique)
    $onlyCim = @($cimIds | Where-Object { $_ -notin $psIds })
    $onlyPs  = @($psIds  | Where-Object { $_ -notin $cimIds })
    @(
        "PowerShell 可见进程数: $($psIds.Count)"
        "CIM 可见进程数:        $($cimIds.Count)"
        "仅 CIM 可见(可疑):     $($onlyCim -join ', ')"
        "仅 PowerShell 可见:    $($onlyPs -join ', ')"
    ) | Out-File (Join-Path $OutputDir '03-process-crosscheck.txt') -Encoding UTF8
    if ($onlyCim.Count -gt 0) {
        Add-Finding 'High' 'Process' "存在仅 CIM 可见的进程（疑似隐藏进程）" ($onlyCim -join ', ')
    }

    # 3.2 可疑父进程链
    $badParent = @{
        'winword|excel|powerpoint|outlook|msaccess' = 'powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|msiexec|installutil|certutil|bitsadmin'
        'w3wp|httpd|nginx|java|node|python|tomcat'  = 'cmd|powershell|pwsh|whoami|net|net1|curl|bitsadmin|certutil'
        'services|svchost'                          = 'powershell|pwsh|mshta|certutil|bitsadmin|curl|cmd'
        'explorer'                                  = 'certutil|bitsadmin|mshta|regsvr32|rundll32|wscript|cscript'
    }
    foreach ($k in $badParent.Keys) {
        $parents = @($procs | Where-Object { $_.Name -match "^($k)\.exe$" })
        foreach ($p in $parents) {
            $kids = @($procs | Where-Object {
                $_.ParentProcessId -eq $p.ProcessId -and $_.Name -match "^($($badParent[$k]))"
            })
            foreach ($c in $kids) {
                Add-Finding 'High' 'Process' "异常父子进程链: $($p.Name) -> $($c.Name)" `
                    ("PID $($p.ProcessId) -> $($c.ProcessId) | " + $c.CommandLine)
            }
        }
    }

    # 3.3 命令行可疑特征
    $badCmd = 'EncodedCommand|-enc |FromBase64String|DownloadString|DownloadFile|IEX|Invoke-Expression|' +
              'Invoke-WebRequest|-w hidden|-WindowStyle Hidden|nop|Bypass|AMSI|Reflection\.Assembly|' +
              'mimikatz|sekurlsa|lsadump|comsvcs.*MiniDump|procdump|' +
              'certutil.*-urlcache|bitsadmin|mshta |regsvr32.*scrobj|rundll32.*javascript|' +
              'vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled|wevtutil cl|' +
              'net user .*/add|net localgroup .*administrators|schtasks .*/create|' +
              'netsh interface portproxy add|sc\.exe create|New-Object Net\.Sockets|TCPClient'
    $suspCmd = @($procs | Where-Object { $_.CommandLine -and $_.CommandLine -match $badCmd })
    Save-Csv ($suspCmd | Select-Object ProcessId, ParentProcessId, Name, CreationDate, CommandLine) '03-suspicious-cmdline'
    foreach ($s in $suspCmd) {
        Add-Finding 'High' 'Process' "可疑命令行（$($s.Name), PID $($s.ProcessId)）" $s.CommandLine
    }

    # 3.4 路径与签名
    $sysRoot = $env:SystemRoot
    $outside = @(Get-Process | Where-Object {
        $_.Path -and $_.Path -notlike "$sysRoot*" -and $_.Path -notlike "${env:ProgramFiles}*" -and
        $_.Path -notlike "${env:ProgramFiles(x86)}*"
    } | Select-Object Name, Id, Path, Company, @{n='Sign';e={(Get-AuthenticodeSignature $_.Path -EA SilentlyContinue).Status}})
    Save-Csv $outside '03-process-outside-sysdir'
    foreach ($o in $outside) {
        if ($o.Sign -ne 'Valid') {
            Add-Finding 'Medium' 'Process' "进程在非标准目录且签名无效: $($o.Name) -> $($o.Path)" "Sign=$($o.Sign)"
        }
    }

    # 3.5 系统进程被冒充
    $sysNames = 'svchost','lsass','services','winlogon','csrss','smss','wininit','taskhostw','dllhost','explorer','conhost'
    foreach ($p in @(Get-Process | Where-Object { $_.Name -in $sysNames })) {
        if (-not $p.Path) { continue }
        $okPath = $p.Path -like "$sysRoot\System32\*"
        $sig = (Get-AuthenticodeSignature $p.Path -EA SilentlyContinue).Status
        if (-not $okPath -or $sig -ne 'Valid') {
            Add-Finding 'High' 'Process' "系统进程路径/签名异常: $($p.Name) (PID $($p.Id))" "Path=$($p.Path) Sign=$sig"
        }
    }

    # 3.6 非微软签名的运行中进程（信息性，量可能较大）
    $nonMs = @(Get-Process | Where-Object { $_.Path } | ForEach-Object {
        $sig = Get-AuthenticodeSignature $_.Path -EA SilentlyContinue
        $subj = ''
        if ($sig.SignerCertificate) { $subj = $sig.SignerCertificate.Subject }
        if ($subj -notmatch 'Microsoft') {
            [PSCustomObject]@{ Name=$_.Name; Id=$_.Id; Path=$_.Path; Sign=$sig.Status; Signer=$subj }
        }
    })
    Save-Csv $nonMs '03-process-non-ms-signed'
} catch {
    Write-Log "进程采集出错: $_"
}

# ============================================================
# 4. 服务与驱动
# ============================================================
Write-Log "采集服务与驱动..."

try {
    $svc = Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId
    Save-Csv $svc '04-services'

    foreach ($s in @($svc)) {
        $p = $s.PathName
        if (-not $p) { continue }

        # 路径指向用户可写目录
        if ($p -match '(?i)(\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Windows\\Temp\\)') {
            Add-Finding 'High' 'Service' "服务路径位于用户可写目录: $($s.Name)" $p
        }

        # 未加引号且含空格
        if ($p -notmatch '^"' -and $p -match ' ' -and $p -match '^[A-Za-z]:\\' -and
            $p -notmatch '(?i)^[A-Za-z]:\\Windows\\(System32|SysWOW64)\\') {
            Add-Finding 'Medium' 'Service' "服务路径未加引号且含空格（DLL/EXE 劫持风险）: $($s.Name)" $p
        }

        # 签名核查
        $exe = ($p -replace '^"([^"]+)".*','$1') -replace '^([A-Za-z]:\\[^ ]*\.exe).*','$1'
        if (Test-Path $exe) {
            $sig = Get-AuthenticodeSignature $exe -EA SilentlyContinue
            if ($sig.Status -ne 'Valid') {
                Add-Finding 'Medium' 'Service' "服务可执行文件签名无效: $($s.Name)" "$exe (Sign=$($sig.Status))"
            }
        }
    }

    # svchost 服务的 ServiceDll
    $svcDll = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
        $p = Join-Path $_.PSPath 'Parameters'
        if (Test-Path $p) {
            $dll = (Get-ItemProperty $p -EA SilentlyContinue).ServiceDll
            if ($dll) {
                $clean = $dll -replace '^\\\?\?\\','' -replace '^\\SystemRoot\\', "$env:SystemRoot\"
                [PSCustomObject]@{
                    Service    = $_.PSChildName
                    ServiceDll = $clean
                    Exists     = (Test-Path $clean -EA SilentlyContinue)
                    Sign       = (Get-AuthenticodeSignature $clean -EA SilentlyContinue).Status
                }
            }
        }
    })
    Save-Csv $svcDll '04-servicedll'
    foreach ($d in $svcDll) {
        if (-not $d.Exists -or $d.Sign -ne 'Valid') {
            Add-Finding 'High' 'Service' "ServiceDll 异常: $($d.Service)" "$($d.ServiceDll) Exists=$($d.Exists) Sign=$($d.Sign)"
        }
    }

    # 失败恢复命令（隐蔽后门点）
    $failCmd = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
        $f = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).FailureCommand
        if ($f) { [PSCustomObject]@{ Service = $_.PSChildName; FailureCommand = $f } }
    })
    Save-Csv $failCmd '04-service-failurecommand'
    foreach ($f in $failCmd) {
        Add-Finding 'High' 'Service' "服务配置了失败恢复命令: $($f.Service)" $f.FailureCommand
    }

    # 驱动
    Save-Csv (Get-CimInstance Win32_SystemDriver |
        Select-Object Name, DisplayName, State, StartMode, PathName) '04-drivers'
    Save-Csv ((& driverquery /v /fo csv | ConvertFrom-Csv) ) '04-driverquery'

    # minifilter
    (& fltmc filters) | Out-File (Join-Path $OutputDir '04-fltmc.txt') -Encoding UTF8
} catch {
    Write-Log "服务驱动采集出错: $_"
}

# ============================================================
# 5. 持久化
# ============================================================
Write-Log "采集持久化项..."

try {
    # 5.1 Run 系列全集
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    $runItems = New-Object System.Collections.Generic.List[object]
    foreach ($k in $runKeys) {
        if (Test-Path $k) {
            $props = Get-ItemProperty $k -EA SilentlyContinue
            if ($props) {
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -match '^PS') { continue }
                    $runItems.Add([PSCustomObject]@{ Key = $k; Name = $p.Name; Value = [string]$p.Value })
                }
            }
        }
    }
    Save-Csv $runItems '05-run-keys'
    foreach ($r in $runItems) {
        if ($r.Value -match '(?i)(\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|powershell|mshta|rundll32|regsvr32|certutil|bitsadmin|\\Windows\\Temp\\)') {
            Add-Finding 'High' 'Persistence' "Run 项指向可疑路径或 LOLBin: $($r.Name)" "$($r.Key) = $($r.Value)"
        }
    }

    # 5.2 计划任务
    $tasks = @(Get-ScheduledTask | ForEach-Object {
        $t = $_
        foreach ($a in $t.Actions) {
            [PSCustomObject]@{
                TaskPath  = $t.TaskPath
                TaskName  = $t.TaskName
                State     = $t.State
                Author    = $t.Author
                RunAs     = $t.Principal.UserId
                RunLevel  = $t.Principal.RunLevel
                Hidden    = $t.Settings.Hidden
                Execute   = $a.Execute
                Arguments = $a.Arguments
            }
        }
    })
    Save-Csv $tasks '05-scheduled-tasks'

    foreach ($t in $tasks) {
        if ($t.Hidden) {
            Add-Finding 'High' 'Persistence' "隐藏计划任务: $($t.TaskPath)$($t.TaskName)" $t.Execute
        }
        if ($t.Execute -match '(?i)(powershell|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|cmd\.exe|conhost|forfiles)') {
            Add-Finding 'High' 'Persistence' "计划任务调用脚本解释器/LOLBin: $($t.TaskPath)$($t.TaskName)" "$($t.Execute) $($t.Arguments)"
        }
        elseif ($t.Execute -and $t.Execute -notmatch '(?i)^("?)([A-Za-z]:\\(Windows|Program Files))') {
            Add-Finding 'Medium' 'Persistence' "计划任务动作位于非系统目录: $($t.TaskPath)$($t.TaskName)" $t.Execute
        }
    }

    # 5.3 WMI 事件订阅
    $wmiFilters   = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -EA SilentlyContinue)
    $wmiConsumers = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -EA SilentlyContinue)
    $wmiBindings  = @(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -EA SilentlyContinue)
    Save-Csv ($wmiFilters   | Select-Object Name, Query, EventNamespace) '05-wmi-filters'
    Save-Csv ($wmiConsumers | Select-Object Name, __CLASS) '05-wmi-consumers'
    Save-Csv ($wmiBindings  | Select-Object Filter, Consumer) '05-wmi-bindings'
    Save-Csv (@(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -EA SilentlyContinue) |
        Select-Object Name, CommandLineTemplate, ExecutablePath) '05-wmi-cmdline-consumers'

    if ($wmiFilters.Count -gt 0 -or $wmiConsumers.Count -gt 0) {
        Add-Finding 'High' 'Persistence' `
            "存在 WMI 事件订阅（过滤器 $($wmiFilters.Count) / 消费者 $($wmiConsumers.Count) / 绑定 $($wmiBindings.Count)）" `
            (($wmiConsumers | ForEach-Object { $_.Name }) -join ', ')
    }

    # 5.4 IFEO
    $ifeo = @()
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                       'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        $ifeo += @(Get-ChildItem $root -EA SilentlyContinue | ForEach-Object {
            $d = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).Debugger
            if ($d) { [PSCustomObject]@{ Root = $root; Target = $_.PSChildName; Debugger = $d } }
        })
    }
    Save-Csv $ifeo '05-ifeo'
    foreach ($i in $ifeo) {
        Add-Finding 'High' 'Persistence' "IFEO Debugger 劫持: $($i.Target)" "$($i.Debugger) [$($i.Root)]"
    }

    # SilentProcessExit
    $spe = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -EA SilentlyContinue |
        ForEach-Object {
            $m = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).MonitorProcess
            if ($m) { [PSCustomObject]@{ Target = $_.PSChildName; MonitorProcess = $m } }
        })
    Save-Csv $spe '05-silentprocessexit'
    foreach ($s in $spe) {
        Add-Finding 'High' 'Persistence' "SilentProcessExit 劫持: $($s.Target)" $s.MonitorProcess
    }

    # 5.5 Winlogon / AppInit / LSA
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -EA SilentlyContinue
    $wl | Select-Object Shell, Userinit, Taskman, VmApplet, AppSetup, GinaDLL, AutoAdminLogon, DefaultUserName, DefaultPassword |
        Format-List | Out-File (Join-Path $OutputDir '05-winlogon.txt') -Encoding UTF8
    if ($wl) {
        if ($wl.Shell -and $wl.Shell -ne 'explorer.exe') {
            Add-Finding 'High' 'Persistence' "Winlogon Shell 被修改" $wl.Shell
        }
        if ($wl.Userinit -and $wl.Userinit -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe,?$') {
            Add-Finding 'High' 'Persistence' "Winlogon Userinit 被修改" $wl.Userinit
        }
        if ($wl.DefaultPassword) {
            Add-Finding 'High' 'Account' "Winlogon 存储了明文密码（DefaultPassword）" ''
        }
    }

    $appinit = @()
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                     'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $a = Get-ItemProperty $k -EA SilentlyContinue
        if ($a -and ($a.AppInit_DLLs -or $a.LoadAppInit_DLLs -eq 1)) {
            $appinit += [PSCustomObject]@{ Key=$k; AppInit_DLLs=$a.AppInit_DLLs; LoadAppInit_DLLs=$a.LoadAppInit_DLLs }
        }
    }
    Save-Csv $appinit '05-appinit'
    foreach ($a in $appinit) {
        if ($a.AppInit_DLLs) {
            Add-Finding 'High' 'Persistence' "AppInit_DLLs 非空" "$($a.Key): $($a.AppInit_DLLs)"
        }
    }

    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA SilentlyContinue
    $lsa | Select-Object 'Authentication Packages','Security Packages','Notification Packages' |
        Format-List | Out-File (Join-Path $OutputDir '05-lsa.txt') -Encoding UTF8
    if ($lsa) {
        $np = $lsa.'Notification Packages'
        if ($np -and ($np -join ',') -notmatch '(?i)^scecli$') {
            Add-Finding 'High' 'Persistence' "LSA Notification Packages 异常（可能是密码过滤器后门）" ($np -join ',')
        }
        $sp = $lsa.'Security Packages'
        if ($sp -and ($sp -join ',') -match '(?i)mimilib|kiwi|evil|hook') {
            Add-Finding 'High' 'Persistence' "LSA Security Packages 含可疑项" ($sp -join ',')
        }
    }

    # WDigest
    $wd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -EA SilentlyContinue
    if ($wd -and $wd.UseLogonCredential -eq 1) {
        Add-Finding 'High' 'Account' "WDigest 明文密码缓存已启用（UseLogonCredential=1）" ''
    }

    # 5.6 启动文件夹
    $startups = @(
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    $startupItems = New-Object System.Collections.Generic.List[object]
    foreach ($s in $startups) {
        if (Test-Path $s) {
            Get-ChildItem $s -Force | ForEach-Object {
                $startupItems.Add([PSCustomObject]@{
                    Dir = $s; Name = $_.Name; Length = $_.Length
                    Created = $_.CreationTime; Modified = $_.LastWriteTime
                })
            }
        }
    }
    Save-Csv $startupItems '05-startup-folder'
    if ($startupItems.Count -gt 0) {
        Add-Finding 'Low' 'Persistence' "启动文件夹存在 $($startupItems.Count) 个条目，需人工核对" `
            (($startupItems | ForEach-Object { $_.Name }) -join ', ')
    }

    # 5.7 冷门位置
    $misc = [PSCustomObject]@{
        NetshHelpers        = ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NetSh' -EA SilentlyContinue |
                                Select-Object * -ExcludeProperty PS* | Out-String).Trim())
        AppCertDlls         = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -EA SilentlyContinue |
                                Select-Object * -ExcludeProperty PS* | Out-String).Trim())
        BootExecute         = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -EA SilentlyContinue).BootExecute -join '; ')
        LsaAuthPackages     = ($lsa.'Authentication Packages' -join ',')
        ActiveSetupCount    = (@(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' -EA SilentlyContinue).Count)
        TimeProviders       = ((Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' -EA SilentlyContinue |
                                Select-Object -ExpandProperty PSChildName) -join ',')
        PrintMonitors       = ((Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -EA SilentlyContinue |
                                Select-Object -ExpandProperty PSChildName) -join ',')
        EnvironmentUser     = ((Get-ItemProperty 'HKCU:\Environment' -EA SilentlyContinue | Select-Object * -ExcludeProperty PS* | Out-String).Trim())
    }
    $misc | Format-List | Out-File (Join-Path $OutputDir '05-misc-persistence.txt') -Encoding UTF8

    $netsh = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NetSh' -EA SilentlyContinue
    if ($netsh) {
        $netshProps = @($netsh.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })
        if ($netshProps.Count -gt 0) {
            Add-Finding 'High' 'Persistence' "存在 Netsh Helper DLL 注册（隐蔽后门点）" `
                (($netshProps | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ')
        }
    }

    # WSL
    $wsl = (& wsl --list --verbose) 2>&1
    if ($LASTEXITCODE -eq 0 -and ($wsl | Out-String) -notmatch '没有已安装|no installed') {
        $wsl | Out-File (Join-Path $OutputDir '05-wsl.txt') -Encoding UTF8
        Add-Finding 'Medium' 'Persistence' "检测到 WSL 发行版，Linux 侧持久化无法从 Windows 侧查看" `
            (($wsl | Out-String).Trim())
    }
} catch {
    Write-Log "持久化采集出错: $_"
}

# ============================================================
# 6. 账号
# ============================================================
Write-Log "采集账号..."

try {
    Save-Csv (Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
        PasswordExpires, Description, PrincipalSource) '06-localuser'
    Save-Csv ((& net user) | Out-String | ForEach-Object { [PSCustomObject]@{ Output = $_ } }) '06-netuser-raw'

    $defaults = 'Administrator','Guest','DefaultAccount','WDAGUtilityAccount'
    $extra = @(Get-LocalUser | Where-Object { $_.Name -notin $defaults })
    foreach ($u in $extra) {
        if ($u.Name -match '\$$') {
            Add-Finding 'High' 'Account' "存在 `$ 结尾账号（net user 不显示）: $($u.Name)" "Enabled=$($u.Enabled)"
        }
        if (-not $u.PasswordRequired) {
            Add-Finding 'High' 'Account' "账号允许空密码: $($u.Name)" ''
        }
    }

    $guest = Get-LocalUser Guest -EA SilentlyContinue
    if ($guest -and $guest.Enabled) {
        Add-Finding 'High' 'Account' "Guest 账号已启用" ''
    }

    # 特权组
    $privGroups = 'Administrators','Remote Desktop Users','Remote Management Users',
                  'Backup Operators','Hyper-V Administrators','Account Operators',
                  'Server Operators','Print Operators','Distributed COM Users',
                  'Network Configuration Operators'
    $members = New-Object System.Collections.Generic.List[object]
    foreach ($g in $privGroups) {
        Get-LocalGroupMember -Group $g -EA SilentlyContinue | ForEach-Object {
            $members.Add([PSCustomObject]@{ Group = $g; Member = $_.Name; Source = $_.PrincipalSource; Type = $_.ObjectClass })
        }
    }
    Save-Csv $members '06-privgroup-members'

    # 隐藏账号
    $sa = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' -EA SilentlyContinue
    if ($sa) {
        ($sa | Select-Object * -ExcludeProperty PS* | Out-String) |
            Out-File (Join-Path $OutputDir '06-specialaccounts.txt') -Encoding UTF8
        Add-Finding 'High' 'Account' "存在 Winlogon SpecialAccounts 条目（可能有隐藏账号）" `
            (($sa.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
              ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ')
    }

    # 密码策略
    (& net accounts) | Out-File (Join-Path $OutputDir '06-netaccounts.txt') -Encoding UTF8

    # 登录与账号变更事件
    foreach ($id in 4624,4625,4648,4672,4720,4726,4728,4732,4738,4740,4719,1102) {
        $ev = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=$id } -MaxEvents 50 -EA SilentlyContinue
        if ($ev) {
            Save-Csv ($ev | Select-Object TimeCreated, Id, @{n='Summary';e={
                ($_.Message -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -First 3) -join ' ' }}) "06-event-$id"
        }
    }
} catch {
    Write-Log "账号采集出错: $_"
}

# ============================================================
# 7. 日志与端点防护状态
# ============================================================
Write-Log "采集日志与防护状态..."

try {
    # 7.1 日志通道状态
    $logs = Get-WinEvent -ListLog * -EA SilentlyContinue |
        Select-Object LogName, IsEnabled, RecordCount, FileSize, MaximumSizeInBytes, LogMode
    Save-Csv $logs '07-logs'

    foreach ($l in @($logs)) {
        if (-not $l.IsEnabled -and $l.LogName -match '(?i)Security|System|PowerShell|Sysmon|TerminalServices') {
            Add-Finding 'High' 'Log' "关键日志通道被禁用: $($l.LogName)" ''
        }
    }
    $secLog = $logs | Where-Object { $_.LogName -eq 'Security' }
    if ($secLog -and $secLog.MaximumSizeInBytes -lt 268435456) {
        Add-Finding 'Medium' 'Log' "Security 日志容量偏小（$([math]::Round($secLog.MaximumSizeInBytes/1MB,0)) MB），建议 >= 512 MB" ''
    }

    # 7.2 日志清除痕迹
    $cleared = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=1102 } -MaxEvents 20 -EA SilentlyContinue
    if ($cleared) {
        Save-Csv ($cleared | Select-Object TimeCreated, Id, Message) '07-log-cleared'
        Add-Finding 'High' 'Log' "检测到审计日志被清除（事件 1102）" `
            (($cleared | Select-Object -First 3 | ForEach-Object { $_.TimeCreated.ToString('s') }) -join ', ')
    }
    $clearedSys = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=104 } -MaxEvents 20 -EA SilentlyContinue
    if ($clearedSys) {
        Save-Csv ($clearedSys | Select-Object TimeCreated, Id, Message) '07-log-cleared-system'
        Add-Finding 'High' 'Log' "检测到 System 日志被清除（事件 104）" `
            (($clearedSys | Select-Object -First 3 | ForEach-Object { $_.TimeCreated.ToString('s') }) -join ', ')
    }

    # 7.3 审计与脚本日志配置
    $auditCfg = [PSCustomObject]@{
        CmdLineAudit = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -EA SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
        ScriptBlock  = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA SilentlyContinue).EnableScriptBlockLogging
        ModuleLog    = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -EA SilentlyContinue).EnableModuleLogging
        Transcription= (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -EA SilentlyContinue).EnableTranscripting
    }
    $auditCfg | Format-List | Out-File (Join-Path $OutputDir '07-audit-config.txt') -Encoding UTF8

    if ($auditCfg.CmdLineAudit -ne 1) {
        Add-Finding 'High' 'Log' "命令行审计未开启（4688 将不含命令行），排查能力严重受限" ''
    }
    if ($auditCfg.ScriptBlock -ne 1) {
        Add-Finding 'High' 'Log' "PowerShell 脚本块日志未开启（无法还原无文件攻击脚本）" ''
    }

    (& auditpol /get /category:*) | Out-File (Join-Path $OutputDir '07-auditpol.txt') -Encoding UTF8

    # 7.4 服务安装 / 计划任务事件
    foreach ($id in 7045,7036,4697,4698,4702,8222) {
        $ev = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=$id } -MaxEvents 30 -EA SilentlyContinue
        if (-not $ev) {
            $ev = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=$id } -MaxEvents 30 -EA SilentlyContinue
        }
        if ($ev) {
            Save-Csv ($ev | Select-Object TimeCreated, Id, @{n='Summary';e={
                ($_.Message -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -First 3) -join ' ' }}) "07-event-$id"
        }
    }

    # 7.5 Defender 状态
    $mp = Get-MpComputerStatus -EA SilentlyContinue
    if ($mp) {
        $mp | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled,
            BehaviorMonitorEnabled, IoavProtectionEnabled, IsTamperProtected,
            AntivirusSignatureLastUpdated, AMRunningMode |
            Format-List | Out-File (Join-Path $OutputDir '07-defender-status.txt') -Encoding UTF8
        if (-not $mp.RealTimeProtectionEnabled) {
            Add-Finding 'High' 'Defense' "Defender 实时保护未启用" ''
        }
        if (-not $mp.AntivirusEnabled) {
            Add-Finding 'High' 'Defense' "Defender 杀毒功能未启用" ''
        }
    }
    $mpp = Get-MpPreference -EA SilentlyContinue
    if ($mpp) {
        $mpp | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension, ExclusionIpAddress |
            Format-List | Out-File (Join-Path $OutputDir '07-defender-exclusions.txt') -Encoding UTF8
        if ($mpp.ExclusionPath -or $mpp.ExclusionProcess -or $mpp.ExclusionExtension) {
            Add-Finding 'High' 'Defense' "Defender 存在排除项（需核对业务依据）" `
                ("Path: " + ($mpp.ExclusionPath -join ', ') +
                 " | Process: " + ($mpp.ExclusionProcess -join ', ') +
                 " | Ext: " + ($mpp.ExclusionExtension -join ', '))
        }
        if ($mpp.DisableRealtimeMonitoring) {
            Add-Finding 'High' 'Defense' "Defender 实时监控被策略禁用" ''
        }
    }

    # 7.6 Sysmon 状态
    $sysmon = Get-Service Sysmon,Sysmon64 -EA SilentlyContinue
    if ($sysmon) {
        $sysmon | Select-Object Name, Status, StartType |
            Format-List | Out-File (Join-Path $OutputDir '07-sysmon.txt') -Encoding UTF8
        foreach ($s in @($sysmon)) {
            if ($s.Status -ne 'Running') {
                Add-Finding 'High' 'Defense' "Sysmon 服务未运行: $($s.Name)" ''
            }
        }
        $se = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=4 } -MaxEvents 5 -EA SilentlyContinue
        if ($se) {
            Save-Csv ($se | Select-Object TimeCreated, Id, Message) '07-sysmon-state-events'
            Add-Finding 'Medium' 'Defense' "Sysmon 服务状态变更有记录（事件 4），需核对" ''
        }
    } else {
        Add-Finding 'Medium' 'Defense' "未检测到 Sysmon（建议部署以提升可见性）" ''
    }

    # 7.7 日志转发 / EDR
    $agents = @(Get-Service | Where-Object {
        $_.DisplayName -match '(?i)Splunk|Elastic|CrowdStrike|SentinelOne|Carbon Black|Qualys|Wazuh|NXLog|Filebeat|Winlogbeat|osquery|Tanium' -or
        $_.Name -match '(?i)winlogbeat|filebeat|csagent|splunkd'
    } | Select-Object Name, DisplayName, Status, StartType)
    Save-Csv $agents '07-agents'
    $wec = (& wecutil gs *) 2>&1
    $wec | Out-File (Join-Path $OutputDir '07-wef-subscriptions.txt') -Encoding UTF8
} catch {
    Write-Log "日志采集出错: $_"
}

# ============================================================
# 8. 文件痕迹（可选，较慢）
# ============================================================
Write-Log "采集文件痕迹..."

try {
    # 8.1 Prefetch
    $pfDir = Join-Path $env:SystemRoot 'Prefetch'
    if (Test-Path $pfDir) {
        $pf = Get-ChildItem $pfDir -Filter *.pf |
            Sort-Object LastWriteTime -Descending |
            Select-Object Name, Length, CreationTime, LastWriteTime
        Save-Csv ($pf | Select-Object -First 300) '08-prefetch'
        $pfCfg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -EA SilentlyContinue
        if ($pfCfg -and $pfCfg.EnablePrefetcher -eq 0) {
            Add-Finding 'Medium' 'AntiForensics' "Prefetch 已被禁用（EnablePrefetcher=0）" ''
        }
        if (@($pf).Count -eq 0) {
            Add-Finding 'Medium' 'AntiForensics' "Prefetch 目录为空（可能被清理）" ''
        }
    }

    # 8.2 最近执行的可疑工具
    $lol = 'POWERSHELL','PWSH','CMD','MSHTA','WSCRIPT','CSCRIPT','RUNDLL32','REGSVR32',
           'CERTUTIL','BITSADMIN','MSBUILD','INSTALLUTIL','WMIC','CURL','FTP','TELNET',
           'MIMIKATZ','PROCDUMP','PSEXEC','VSSADMIN','ESENTUTL','NETSH','SC','SCHTASKS'
    $lolPf = @(Get-ChildItem $pfDir -Filter *.pf -EA SilentlyContinue | Where-Object {
        $n = $_.Name
        ($lol | Where-Object { $n -like "$_*" }).Count -gt 0
    } | Select-Object Name, LastWriteTime | Sort-Object LastWriteTime -Descending)
    Save-Csv $lolPf '08-prefetch-lolbin'

    # 8.3 临时目录与热点目录
    $hot = @(
        (Join-Path $env:SystemRoot 'Temp'),
        $env:TEMP,
        (Join-Path $env:ProgramData ''),
        'C:\Users\Public',
        'C:\Temp'
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    $recentExe = @()
    foreach ($d in $hot) {
        $recentExe += @(Get-ChildItem $d -Recurse -File -Force -EA SilentlyContinue |
            Where-Object {
                $_.Extension -in '.exe','.dll','.sys','.ps1','.bat','.cmd','.vbs','.js','.hta','.scr','.jar' -and
                $_.LastWriteTime -gt (Get-Date).AddHours(-$StaleHours)
            } | Select-Object @{n='Dir';e={$d}}, FullName, Length, CreationTime, LastWriteTime)
    }
    Save-Csv ($recentExe | Sort-Object LastWriteTime -Descending | Select-Object -First 500) '08-recent-executables'

    # 8.4 回收站
    $rb = @(Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -File -EA SilentlyContinue |
        Where-Object { $_.Name -like '$I*' } |
        Select-Object FullName, CreationTime, Length)
    Save-Csv ($rb | Sort-Object CreationTime -Descending | Select-Object -First 200) '08-recyclebin'

    if ($IncludeFileScan) {
        Write-Log "执行扩展文件扫描（可能较慢）..."

        # ADS 扫描（仅热点目录）
        $ads = New-Object System.Collections.Generic.List[object]
        foreach ($d in $hot) {
            Get-ChildItem $d -Recurse -File -Force -EA SilentlyContinue | ForEach-Object {
                $streams = Get-Item $_.FullName -Stream * -EA SilentlyContinue |
                    Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
                if ($streams) {
                    $ads.Add([PSCustomObject]@{
                        File    = $_.FullName
                        Streams = ($streams.Stream -join ',')
                        Sizes   = ($streams.Length -join ',')
                    })
                }
            }
        }
        Save-Csv $ads '08-ads'
        foreach ($a in $ads) {
            Add-Finding 'High' 'File' "文件包含备用数据流（ADS）: $($a.File)" $a.Streams
        }

        # Zone.Identifier：来自 Internet 的可执行文件
        $mzw = New-Object System.Collections.Generic.List[object]
        foreach ($d in $hot) {
            Get-ChildItem $d -Recurse -File -Force -EA SilentlyContinue |
                Where-Object { $_.Extension -in '.exe','.dll','.ps1','.bat','.vbs','.js','.hta','.scr','.zip','.rar' } |
                ForEach-Object {
                    $z = Get-Item $_.FullName -Stream Zone.Identifier -EA SilentlyContinue
                    if ($z) {
                        $c = Get-Content $_.FullName -Stream Zone.Identifier -EA SilentlyContinue
                        if ($c -match 'ZoneId=3') {
                            $mzw.Add([PSCustomObject]@{
                                File    = $_.FullName
                                Created = $_.CreationTime
                                Referrer= (($c | Select-String 'ReferrerUrl').Line -join ' ')
                                Host    = (($c | Select-String 'HostUrl').Line -join ' ')
                            })
                        }
                    }
                }
        }
        Save-Csv $mzw '08-mark-of-the-web'
        foreach ($m in $mzw) {
            Add-Finding 'Medium' 'File' "可执行文件标记来自 Internet: $($m.File)" "$($m.Referrer) $($m.Host)"
        }
    }
} catch {
    Write-Log "文件痕迹采集出错: $_"
}

# ============================================================
# 9. 汇总
# ============================================================
Write-Log "生成汇总..."

$high   = @($script:Findings | Where-Object Severity -eq 'High')
$medium = @($script:Findings | Where-Object Severity -eq 'Medium')
$low    = @($script:Findings | Where-Object Severity -eq 'Low')

$summaryPath = Join-Path $OutputDir '00-SUMMARY.txt'
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("==============================================================")
[void]$sb.AppendLine(" Windows IR QuickCheck - 采集汇总")
[void]$sb.AppendLine("==============================================================")
[void]$sb.AppendLine("主机      : $env:COMPUTERNAME")
[void]$sb.AppendLine("域        : $((Get-CimInstance Win32_ComputerSystem).Domain)")
[void]$sb.AppendLine("采集时间  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$sb.AppendLine("管理员    : $IsAdmin")
[void]$sb.AppendLine("文件扫描  : $IncludeFileScan (窗口 ${StaleHours}h)")
[void]$sb.AppendLine("输出目录  : $OutputDir")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("发现项统计: 高危 $($high.Count) / 中危 $($medium.Count) / 低危 $($low.Count)")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("--------------------------------------------------------------")
[void]$sb.AppendLine("【高危】需优先人工确认")
[void]$sb.AppendLine("--------------------------------------------------------------")
if ($high.Count -eq 0) {
    [void]$sb.AppendLine("  (无)")
} else {
    foreach ($f in $high) {
        [void]$sb.AppendLine("  [High][$($f.Category)] $($f.Detail)")
        if ($f.Evidence) {
            $ev = $f.Evidence
            if ($ev.Length -gt 220) { $ev = $ev.Substring(0, 220) + ' ...' }
            [void]$sb.AppendLine("        证据: $ev")
        }
    }
}
[void]$sb.AppendLine("")
[void]$sb.AppendLine("--------------------------------------------------------------")
[void]$sb.AppendLine("【中危】")
[void]$sb.AppendLine("--------------------------------------------------------------")
if ($medium.Count -eq 0) {
    [void]$sb.AppendLine("  (无)")
} else {
    foreach ($f in $medium) {
        [void]$sb.AppendLine("  [Med ][$($f.Category)] $($f.Detail)")
        if ($f.Evidence) {
            $ev = $f.Evidence
            if ($ev.Length -gt 180) { $ev = $ev.Substring(0, 180) + ' ...' }
            [void]$sb.AppendLine("        证据: $ev")
        }
    }
}
[void]$sb.AppendLine("")
[void]$sb.AppendLine("--------------------------------------------------------------")
[void]$sb.AppendLine("【低危 / 信息】")
[void]$sb.AppendLine("--------------------------------------------------------------")
if ($low.Count -eq 0) {
    [void]$sb.AppendLine("  (无)")
} else {
    foreach ($f in $low) {
        [void]$sb.AppendLine("  [Low ][$($f.Category)] $($f.Detail)")
    }
}
[void]$sb.AppendLine("")
[void]$sb.AppendLine("--------------------------------------------------------------")
[void]$sb.AppendLine("【重要提示】")
[void]$sb.AppendLine("--------------------------------------------------------------")
[void]$sb.AppendLine("  1. 本结果是【线索】而非结论，每一项都需人工确认。")
[void]$sb.AppendLine("  2. 若检测到持久化项，请按 windows-attack-mapping.md 的")
[void]$sb.AppendLine("     '权限维持手法全量核对清单' 逐项核对，不要只清掉发现的那一个。")
[void]$sb.AppendLine("  3. 清理任何项之前，先导出备份并记录证据（哈希、时间、路径）。")
[void]$sb.AppendLine("  4. 清理完成后，重跑本脚本对比前后差异以验证。")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("==============================================================")

$sb.ToString() | Out-File $summaryPath -Encoding UTF8
Save-Csv ($script:Findings) '00-findings'
($script:LogLines -join "`r`n") | Out-File (Join-Path $OutputDir '00-collect-log.txt') -Encoding UTF8

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " 采集完成"                                -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host " 输出目录: $OutputDir"
Write-Host " 高危 $($high.Count) / 中危 $($medium.Count) / 低危 $($low.Count)"
Write-Host ""
if ($high.Count -gt 0) {
    Write-Host " 高危项摘要：" -ForegroundColor Yellow
    foreach ($f in $high | Select-Object -First 15) {
        Write-Host ("   - [{0}] {1}" -f $f.Category, $f.Detail) -ForegroundColor Yellow
    }
    if ($high.Count -gt 15) { Write-Host "   ...（完整清单见 00-SUMMARY.txt）" }
}
Write-Host ""
Write-Host " 汇总文件: $summaryPath"
Write-Host ""
