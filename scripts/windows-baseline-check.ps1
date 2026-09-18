#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 主机安全基线核查（只读）

.DESCRIPTION
    对照 CIS Microsoft Windows Benchmark / Microsoft Security Baselines 的
    高价值核查项做自动化检查。本脚本【完全只读】，不修改任何系统配置。

    核查维度（每项给出：核查项 / 实测值 / 期望值 / 结论 / 风险等级）：
      账号与认证 / 权限与访问控制 / 网络与远程访问 / 服务与驱动
      日志与审计 / 端点防护 / 凭据保护 / 攻击面 / 补丁 / 备份

    重点不在"打勾"，而在于回答三个问题：
      1) 如果现在被打，我能不能查到？（日志与审计）
      2) 如果现在被打，我能不能挡住？（防护与攻击面）
      3) 如果已经被打，我还有没有底牌？（凭据保护与备份）

.PARAMETER OutputDir
    报告输出目录。默认 C:\Baseline\<主机名>-<时间戳>

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\windows-baseline-check.ps1

.NOTES
    必须以管理员身份运行。
    加固前请阅读 windows/windows-hardening.md 第 5 节"加固的风险控制"：
    先审计、再灰度、后强制。
#>
[CmdletBinding()]
param(
    [string]$OutputDir
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
    $OutputDir = Join-Path 'C:\Baseline' ("{0}-{1}" -f $env:COMPUTERNAME, $stamp)
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$script:Results = New-Object System.Collections.Generic.List[object]
$script:TotalChecks = 0

function Test-Item {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [string]$Actual = '',
        [string]$Expected = '',
        [ValidateSet('P0','P1','P2')][string]$Risk = 'P1',
        [bool]$Pass = $true,
        [string]$Note = ''
    )
    $script:TotalChecks++
    $status = if ($Pass) { 'PASS' } else { 'FAIL' }
    $script:Results.Add([PSCustomObject]@{
        Category = $Category
        Item     = $Name
        Status   = $status
        Risk     = $Risk
        Actual   = $Actual
        Expected = $Expected
        Note     = $Note
    })
    if (-not $Pass) {
        $color = switch ($Risk) { 'P0' { 'Red' } 'P1' { 'Yellow' } default { 'Gray' } }
        Write-Host ("  [{0}] {1}" -f $Risk, $Name) -ForegroundColor $color
        if ($Actual) { Write-Host ("        实测: {0}" -f $Actual) -ForegroundColor Gray }
        if ($Expected) { Write-Host ("        期望: {0}" -f $Expected) -ForegroundColor Gray }
    }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    $v = (Get-ItemProperty -Path $Path -Name $Name -EA SilentlyContinue).$Name
    return $v
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Windows Security Baseline Check (RO)"     -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " 主机: $env:COMPUTERNAME"
Write-Host " 管理员权限: $IsAdmin"
Write-Host " 输出目录: $OutputDir"
Write-Host ""

if (-not $IsAdmin) {
    Write-Host "[!] 未以管理员身份运行，部分检查结果将不准确。" -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================
# 1. 账号与认证
# ============================================================
Write-Host "[1/10] 账号与认证" -ForegroundColor Cyan

# 1.1 内置 Administrator
$adm = Get-LocalUser -Name 'Administrator' -EA SilentlyContinue
if ($adm) {
    Test-Item -Category 'Account' -Name '内置 Administrator 已禁用' `
        -Actual ("Enabled=" + $adm.Enabled) -Expected 'Enabled=False' -Risk 'P0' -Pass (-not $adm.Enabled)
} else {
    Test-Item -Category 'Account' -Name '内置 Administrator 已禁用' `
        -Actual 'Administrator 账号不存在（可能已改名）' -Expected 'Disabled 或 已改名' -Risk 'P0' -Pass $true `
        -Note '需确认是否被改名，以及管理员组是否有其他成员'
}

# 1.2 Guest
$guest = Get-LocalUser -Name 'Guest' -EA SilentlyContinue
if ($guest) {
    Test-Item -Category 'Account' -Name 'Guest 账号已禁用' `
        -Actual ("Enabled=" + $guest.Enabled) -Expected 'Enabled=False' -Risk 'P0' -Pass (-not $guest.Enabled)
}

# 1.3 空密码 / 不需要密码的账号
$noPwd = @(Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordRequired })
Test-Item -Category 'Account' -Name '无空密码账号' `
    -Actual (($noPwd | ForEach-Object { $_.Name }) -join ', ') -Expected '无' -Risk 'P0' `
    -Pass ($noPwd.Count -eq 0)

# 1.4 $ 结尾隐藏账号
$dollar = @(Get-LocalUser | Where-Object { $_.Name -match '\$$' })
Test-Item -Category 'Account' -Name '无 $ 结尾隐藏账号' `
    -Actual (($dollar | ForEach-Object { $_.Name }) -join ', ') -Expected '无（除非业务明确需要）' -Risk 'P0' `
    -Pass ($dollar.Count -eq 0) -Note '这类账号 net user 不显示，但可以登录'

# 1.5 密码策略
$netAccounts = (& net accounts) 2>&1 | Out-String
$minLen = 0
if ($netAccounts -match '(?i)Minimum password length:\s*(\d+)') { $minLen = [int]$Matches[1] }
Test-Item -Category 'Account' -Name '密码最小长度 >= 14' `
    -Actual "长度=$minLen" -Expected '>= 14' -Risk 'P1' -Pass ($minLen -ge 14)

$maxAge = 0
if ($netAccounts -match '(?i)Maximum password age \(days\):\s*(\d+)') { $maxAge = [int]$Matches[1] }
if ($maxAge -gt 0) {
    Test-Item -Category 'Account' -Name '密码最长使用期 <= 90 天' `
        -Actual "天数=$maxAge" -Expected '<= 90' -Risk 'P1' -Pass ($maxAge -le 90)
} else {
    Test-Item -Category 'Account' -Name '密码最长使用期 <= 90 天' `
        -Actual '未设置过期或解析失败（可能是"从不"）' -Expected '<= 90' -Risk 'P1' -Pass $false
}

# 1.6 账号锁定策略
$lockThreshold = 0
if ($netAccounts -match '(?i)Lockout threshold:\s*(\d+)') { $lockThreshold = [int]$Matches[1] }
Test-Item -Category 'Account' -Name '账号锁定阈值已配置（<= 10）' `
    -Actual "阈值=$lockThreshold" -Expected '1-10' -Risk 'P1' `
    -Pass ($lockThreshold -gt 0 -and $lockThreshold -le 10)

# 1.7 特权组成员核查（列出，需人工核对）
$privGroups = 'Administrators','Backup Operators','Remote Desktop Users','Remote Management Users'
$memberLines = @()
foreach ($g in $privGroups) {
    $m = Get-LocalGroupMember -Group $g -EA SilentlyContinue
    if ($m) { $memberLines += ("{0}: {1}" -f $g, (($m | ForEach-Object { $_.Name }) -join ', ')) }
}
Test-Item -Category 'Account' -Name '特权组成员需人工核对业务依据' `
    -Actual ($memberLines -join ' | ') -Expected '仅必要成员' -Risk 'P1' -Pass $true `
    -Note '此项为信息项，请逐个人工确认'

# 1.8 WDigest 明文缓存
$wdigest = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
Test-Item -Category 'Account' -Name 'WDigest 明文密码缓存已关闭' `
    -Actual ("UseLogonCredential=" + $(if ($null -eq $wdigest) { '(不存在)' } else { $wdigest })) `
    -Expected '0 或 不存在' -Risk 'P0' `
    -Pass ($null -eq $wdigest -or $wdigest -eq 0) `
    -Note '开启后 LSASS 中会存明文密码，攻击者 dump 后可直接用'

# 1.9 LSASS RunAsPPL
$ppl = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
Test-Item -Category 'Account' -Name 'LSASS 保护（RunAsPPL）已启用' `
    -Actual ("RunAsPPL=" + $(if ($null -eq $ppl) { '(不存在)' } else { $ppl })) `
    -Expected '1' -Risk 'P0' -Pass ($ppl -eq 1) `
    -Note '未启用时 mimikatz 类工具可直接 dump LSASS'

# 1.10 LAPS
$lapsPath = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'
$lapsBackup = Get-RegValue $lapsPath 'BackupDirectory'
$lapsEnabled = ($null -ne $lapsBackup)
Test-Item -Category 'Account' -Name 'Windows LAPS 已配置' `
    -Actual $(if ($lapsEnabled) { "BackupDirectory=$lapsBackup" } else { '未检测到 LAPS 策略' }) `
    -Expected '已配置本地管理员密码轮换' -Risk 'P0' -Pass $lapsEnabled `
    -Note '本地管理员密码不唯一 = 一处泄露全网失守'

# ============================================================
# 2. 权限与访问控制
# ============================================================
Write-Host "[2/10] 权限与访问控制" -ForegroundColor Cyan

# 2.1 UAC
$enableLUA = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
Test-Item -Category 'Privilege' -Name 'UAC 已启用' `
    -Actual ("EnableLUA=" + $(if ($null -eq $enableLUA) { '(不存在)' } else { $enableLUA })) `
    -Expected '1' -Risk 'P0' -Pass ($enableLUA -eq 1)

# 2.2 UAC 提示级别
$consent = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
Test-Item -Category 'Privilege' -Name 'UAC 管理员提示级别合规' `
    -Actual ("ConsentPromptBehaviorAdmin=" + $(if ($null -eq $consent) { '(不存在)' } else { $consent })) `
    -Expected '2 或 4' -Risk 'P1' -Pass ($consent -eq 2 -or $consent -eq 4)

# 2.3 AlwaysInstallElevated
$aieHklm = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
$aieHkcu = Get-RegValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
$aie = ($aieHklm -eq 1) -and ($aieHkcu -eq 1)
Test-Item -Category 'Privilege' -Name 'AlwaysInstallElevated 已禁用' `
    -Actual ("HKLM=$aieHklm HKCU=$aieHkcu") -Expected '均为 0 或 不存在' -Risk 'P0' -Pass (-not $aie) `
    -Note '两项同时为 1 时任意用户可提权安装 MSI'

# 2.4 用户权限分配（导出供人工核对）
$secpolPath = Join-Path $OutputDir 'secpol.cfg'
(& secedit /export /cfg $secpolPath /areas USER_RIGHTS) | Out-Null
$secpol = Get-Content $secpolPath -EA SilentlyContinue
$debugPriv = ($secpol | Select-String '^SeDebugPrivilege').Line
Test-Item -Category 'Privilege' -Name 'SeDebugPrivilege 授予范围需人工核对' `
    -Actual $(if ($debugPriv) { $debugPriv } else { '未解析到' }) `
    -Expected '仅管理员（该权限可用于 dump LSASS）' -Risk 'P0' -Pass $true `
    -Note '信息项：请在 secpol.cfg 中核对 SeDebugPrivilege / SeBackupPrivilege / SeImpersonatePrivilege'

# 2.5 未加引号的服务路径
$unquoted = @(Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and
    $_.PathName -match '^[A-Za-z]:\\' -and
    $_.PathName -notmatch '(?i)^[A-Za-z]:\\Windows\\(System32|SysWOW64)\\'
})
Test-Item -Category 'Privilege' -Name '无未加引号的服务路径' `
    -Actual (($unquoted | ForEach-Object { $_.Name }) -join ', ') -Expected '无' -Risk 'P0' `
    -Pass ($unquoted.Count -eq 0) -Note '未加引号 + 含空格 = 可被 DLL/EXE 劫持'

# 2.6 服务路径指向用户可写目录
$badSvcPath = @(Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -match '(?i)(\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\)'
})
Test-Item -Category 'Privilege' -Name '服务路径不在用户可写目录' `
    -Actual (($badSvcPath | ForEach-Object { $_.Name }) -join ', ') -Expected '无' -Risk 'P0' `
    -Pass ($badSvcPath.Count -eq 0)

# ============================================================
# 3. 网络与远程访问
# ============================================================
Write-Host "[3/10] 网络与远程访问" -ForegroundColor Cyan

# 3.1 防火墙
$fwOff = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled })
Test-Item -Category 'Network' -Name '所有防火墙配置文件已启用' `
    -Actual (($fwOff | ForEach-Object { $_.Name }) -join ', ') -Expected 'Domain/Private/Public 全部启用' `
    -Risk 'P0' -Pass ($fwOff.Count -eq 0)

# 3.2 入向默认阻断
$fwIn = @(Get-NetFirewallProfile | Where-Object { $_.DefaultInboundAction -ne 'Block' })
Test-Item -Category 'Network' -Name '入向默认动作 = Block' `
    -Actual (($fwIn | ForEach-Object { "$($_.Name)=$($_.DefaultInboundAction)" }) -join ', ') `
    -Expected 'Block' -Risk 'P0' -Pass ($fwIn.Count -eq 0)

# 3.3 portproxy
$ppText = ((& netsh interface portproxy show all) 2>&1 | Out-String)
$hasPp = $ppText -match '\d+\.\d+\.\d+\.\d+'
Test-Item -Category 'Network' -Name '无 netsh portproxy 端口转发' `
    -Actual $(if ($hasPp) { $ppText.Trim() } else { '无规则' }) -Expected '无规则' -Risk 'P0' -Pass (-not $hasPp) `
    -Note '这是 Windows 上最隐蔽的隧道手法之一，不显示在任何 GUI'

# 3.4 系统代理
$winhttpProxy = ((& netsh winhttp show proxy) 2>&1 | Out-String)
$hasWinhttpProxy = $winhttpProxy -match '(?i)Proxy Server\(s\)\s*:\s*\S+'
$pacUrl = Get-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 'AutoConfigURL'
Test-Item -Category 'Network' -Name '无未授权的系统代理 / PAC' `
    -Actual ("winhttp=" + $(if ($hasWinhttpProxy) { '已配置' } else { '直连' }) + " PAC=" + $(if ($pacUrl) { $pacUrl } else { '无' })) `
    -Expected '直连 且 无 PAC（除非业务明确需要）' -Risk 'P0' -Pass (-not $hasWinhttpProxy -and -not $pacUrl)

# 3.5 RDP
$ts = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$rdpDenied = ($ts -eq 1)
Test-Item -Category 'Network' -Name 'RDP 已禁用（非必要场景）' `
    -Actual ("fDenyTSConnections=" + $(if ($null -eq $ts) { '(不存在)' } else { $ts })) `
    -Expected '1（若必须开启，需配合 NLA + 来源限制）' -Risk 'P0' -Pass $rdpDenied `
    -Note '此项为业务权衡项：若 RDP 必须开启，请确认 3.6/3.7 项'

# 3.6 RDP NLA
$rdpNla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
if (-not $rdpDenied) {
    Test-Item -Category 'Network' -Name 'RDP 已启用 NLA' `
        -Actual ("UserAuthentication=" + $(if ($null -eq $rdpNla) { '(不存在)' } else { $rdpNla })) `
        -Expected '1' -Risk 'P0' -Pass ($rdpNla -eq 1)
}

# 3.7 RDP 安全层
$rdpSec = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'SecurityLayer'
if (-not $rdpDenied) {
    Test-Item -Category 'Network' -Name 'RDP 安全层 = SSL/TLS(2)' `
        -Actual ("SecurityLayer=" + $(if ($null -eq $rdpSec) { '(不存在)' } else { $rdpSec })) `
        -Expected '2' -Risk 'P1' -Pass ($rdpSec -eq 2)
}

# 3.8 RDP Wrapper
$rdpWrap = Test-Path 'C:\Program Files\RDP Wrapper'
Test-Item -Category 'Network' -Name '未安装 RDP Wrapper' `
    -Actual $(if ($rdpWrap) { '已安装' } else { '未安装' }) -Expected '未安装' -Risk 'P0' -Pass (-not $rdpWrap)

# 3.9 SMBv1
$smb1 = (Get-SmbServerConfiguration -EA SilentlyContinue).EnableSMB1Protocol
Test-Item -Category 'Network' -Name 'SMBv1 已禁用' `
    -Actual ("EnableSMB1Protocol=" + $(if ($null -eq $smb1) { '(读取失败)' } else { $smb1 })) `
    -Expected 'False' -Risk 'P0' -Pass ($smb1 -eq $false)

# 3.10 SMB 签名
$smbSig = (Get-SmbServerConfiguration -EA SilentlyContinue).RequireSecuritySignature
Test-Item -Category 'Network' -Name 'SMB 签名强制' `
    -Actual ("RequireSecuritySignature=" + $(if ($null -eq $smbSig) { '(读取失败)' } else { $smbSig })) `
    -Expected 'True' -Risk 'P1' -Pass ($smbSig -eq $true) `
    -Note '强制前请确认老设备/扫描仪兼容性'

# 3.11 远程注册表
$remReg = Get-Service RemoteRegistry -EA SilentlyContinue
if ($remReg) {
    Test-Item -Category 'Network' -Name '远程注册表服务已禁用' `
        -Actual ("Status=$($remReg.Status) StartType=$($remReg.StartType)") `
        -Expected 'Disabled' -Risk 'P1' -Pass ($remReg.StartType -eq 'Disabled')
}

# 3.12 WinRM
$winrm = Get-Service WinRM -EA SilentlyContinue
if ($winrm -and $winrm.Status -eq 'Running') {
    Test-Item -Category 'Network' -Name 'WinRM 运行状态需业务确认' `
        -Actual ("Status=$($winrm.Status) StartType=$($winrm.StartType)") `
        -Expected '非必要则禁用' -Risk 'P1' -Pass $false `
        -Note 'WinRM 是横向移动的重要通道（5985/5986）'
} else {
    Test-Item -Category 'Network' -Name 'WinRM 未运行' -Actual '未运行' -Expected '未运行或受控' -Risk 'P1' -Pass $true
}

# 3.13 管理共享
$shares = @(Get-SmbShare | Where-Object { $_.Name -notin 'IPC$','C$','ADMIN$','print$' -and -not $_.Name.EndsWith('$') })
Test-Item -Category 'Network' -Name '无额外非管理共享（需业务确认）' `
    -Actual (($shares | ForEach-Object { $_.Name }) -join ', ') -Expected '无额外共享' -Risk 'P1' `
    -Pass ($shares.Count -eq 0)

# 3.14 LLMNR（防投毒）
$llmnr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
Test-Item -Category 'Network' -Name 'LLMNR 已禁用' `
    -Actual ("EnableMulticast=" + $(if ($null -eq $llmnr) { '(未配置)' } else { $llmnr })) `
    -Expected '0' -Risk 'P1' -Pass ($llmnr -eq 0) -Note '未禁用时可被 Responder 类工具投毒'

# ============================================================
# 4. 服务与驱动
# ============================================================
Write-Host "[4/10] 服务与驱动" -ForegroundColor Cyan

# 4.1 ServiceDll 异常
$svcDllBad = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue | ForEach-Object {
    $p = Join-Path $_.PSPath 'Parameters'
    if (Test-Path $p) {
        $dll = (Get-ItemProperty $p -EA SilentlyContinue).ServiceDll
        if ($dll) {
            $clean = $dll -replace '^\\\?\?\\','' -replace '^\\SystemRoot\\', "$env:SystemRoot\"
            $exists = Test-Path $clean -EA SilentlyContinue
            $sig = (Get-AuthenticodeSignature $clean -EA SilentlyContinue).Status
            if (-not $exists -or $sig -ne 'Valid') {
                [PSCustomObject]@{ Service = $_.PSChildName; Dll = $clean; Exists = $exists; Sign = $sig }
            }
        }
    }
})
Test-Item -Category 'Service' -Name 'ServiceDll 指向合法文件' `
    -Actual (($svcDllBad | ForEach-Object { "$($_.Service)->$($_.Dll)" }) -join ' | ') `
    -Expected '全部存在且签名有效' -Risk 'P0' -Pass ($svcDllBad.Count -eq 0)

# 4.2 FailureCommand
$failCmd = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue | ForEach-Object {
    $f = (Get-ItemProperty $_.PSPath -EA SilentlyContinue).FailureCommand
    if ($f) { [PSCustomObject]@{ Service = $_.PSChildName; Command = $f } }
})
Test-Item -Category 'Service' -Name '无服务失败恢复命令后门' `
    -Actual (($failCmd | ForEach-Object { "$($_.Service)=$($_.Command)" }) -join ' | ') `
    -Expected '无' -Risk 'P0' -Pass ($failCmd.Count -eq 0)

# 4.3 非微软签名服务
$nonMsSvc = @(Get-CimInstance Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
    $exe = ($_.PathName -replace '^"([^"]+)".*','$1')
    if ($exe -match '^(.*\.exe)') { $exe = $Matches[1] }
    if (Test-Path $exe) {
        $sig = Get-AuthenticodeSignature $exe -EA SilentlyContinue
        if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
            [PSCustomObject]@{ Name = $_.Name; Path = $exe; Signer = $sig.SignerCertificate.Subject }
        }
    }
})
Test-Item -Category 'Service' -Name '非微软签名服务需人工核对' `
    -Actual ("共 " + $nonMsSvc.Count + " 个：" + (($nonMsSvc | Select-Object -First 8 | ForEach-Object { $_.Name }) -join ', ')) `
    -Expected '每个有业务依据' -Risk 'P1' -Pass $true -Note '信息项，请逐个核对'

# 4.4 minifilter（文件系统过滤驱动）
$flt = ((& fltmc filters) 2>&1 | Out-String)
($flt.Trim()) | Out-File (Join-Path $OutputDir 'fltmc-filters.txt') -Encoding UTF8
Test-Item -Category 'Service' -Name 'minifilter 驱动需人工核对' `
    -Actual (($flt -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -Skip 1 -First 6) -join ' / ') `
    -Expected '无未知过滤驱动' -Risk 'P1' -Pass $true -Note '信息项，勒索与监控软件常用 minifilter'

# 4.5 驱动签名
$badDrv = @(Get-ChildItem "$env:SystemRoot\System32\drivers\*.sys" -EA SilentlyContinue | ForEach-Object {
    $s = Get-AuthenticodeSignature $_.FullName -EA SilentlyContinue
    if ($s.Status -ne 'Valid') { [PSCustomObject]@{ File = $_.Name; Sign = $s.Status } }
})
Test-Item -Category 'Service' -Name '系统驱动签名全部有效' `
    -Actual (($badDrv | ForEach-Object { "$($_.File)($($_.Sign))" }) -join ', ') `
    -Expected '全部 Valid' -Risk 'P0' -Pass ($badDrv.Count -eq 0)

# ============================================================
# 5. 日志与审计（最关键的一类）
# ============================================================
Write-Host "[5/10] 日志与审计" -ForegroundColor Cyan

# 5.1 命令行审计
$cmdAudit = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
Test-Item -Category 'Log' -Name '命令行审计已开启（4688 含命令行）' `
    -Actual ("ProcessCreationIncludeCmdLine_Enabled=" + $(if ($null -eq $cmdAudit) { '(不存在)' } else { $cmdAudit })) `
    -Expected '1' -Risk 'P0' -Pass ($cmdAudit -eq 1) `
    -Note '未开启时 4688 只有进程名，几乎所有命令级排查都会失效'

# 5.2 PowerShell 脚本块日志
$sbLog = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
Test-Item -Category 'Log' -Name 'PowerShell 脚本块日志已开启' `
    -Actual ("EnableScriptBlockLogging=" + $(if ($null -eq $sbLog) { '(不存在)' } else { $sbLog })) `
    -Expected '1' -Risk 'P0' -Pass ($sbLog -eq 1) `
    -Note '这是还原无文件攻击脚本的唯一可靠手段'

# 5.3 模块日志
$moLog = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
Test-Item -Category 'Log' -Name 'PowerShell 模块日志已开启' `
    -Actual ("EnableModuleLogging=" + $(if ($null -eq $moLog) { '(不存在)' } else { $moLog })) `
    -Expected '1' -Risk 'P1' -Pass ($moLog -eq 1)

# 5.4 转录
$trLog = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
Test-Item -Category 'Log' -Name 'PowerShell 转录已开启' `
    -Actual ("EnableTranscripting=" + $(if ($null -eq $trLog) { '(不存在)' } else { $trLog })) `
    -Expected '1' -Risk 'P1' -Pass ($trLog -eq 1)

# 5.5 Security 日志容量
$secLog = Get-WinEvent -ListLog Security -EA SilentlyContinue
if ($secLog) {
    $sizeMB = [math]::Round($secLog.MaximumSizeInBytes / 1MB, 0)
    Test-Item -Category 'Log' -Name 'Security 日志容量 >= 512 MB' `
        -Actual ("容量=" + $sizeMB + " MB，记录数=" + $secLog.RecordCount) `
        -Expected '>= 512 MB' -Risk 'P0' -Pass ($sizeMB -ge 512) `
        -Note '容量太小会在攻击发生时把关键事件覆盖掉'
}

# 5.6 关键日志通道启用
$criticalLogs = 'Security','System','Application',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-Windows Defender/Operational'
$disabledLogs = @()
foreach ($n in $criticalLogs) {
    $l = Get-WinEvent -ListLog $n -EA SilentlyContinue
    if ($l -and -not $l.IsEnabled) { $disabledLogs += $n }
}
Test-Item -Category 'Log' -Name '关键日志通道均启用' `
    -Actual (($disabledLogs) -join ', ') -Expected '全部启用' -Risk 'P0' -Pass ($disabledLogs.Count -eq 0)

# 5.7 日志被清除痕迹
$cleared = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=1102 } -MaxEvents 5 -EA SilentlyContinue
Test-Item -Category 'Log' -Name '无审计日志被清除痕迹（1102）' `
    -Actual $(if ($cleared) { (($cleared | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') }) -join ', ') } else { '无' }) `
    -Expected '无' -Risk 'P0' -Pass (-not $cleared)

# 5.8 Sysmon
$sysmon = Get-Service Sysmon,Sysmon64 -EA SilentlyContinue
if ($sysmon) {
    $notRunning = @($sysmon | Where-Object { $_.Status -ne 'Running' })
    Test-Item -Category 'Log' -Name 'Sysmon 服务运行中' `
        -Actual (($sysmon | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join ', ') `
        -Expected 'Running' -Risk 'P0' -Pass ($notRunning.Count -eq 0)
} else {
    Test-Item -Category 'Log' -Name 'Sysmon 已部署' `
        -Actual '未检测到' -Expected '已部署并运行' -Risk 'P0' -Pass $false `
        -Note 'Sysmon 是 Windows 上性价比最高的端点遥测，建议用社区配置部署'
}

# 5.9 日志外发
$agents = @(Get-Service | Where-Object {
    $_.DisplayName -match '(?i)Splunk|Elastic|CrowdStrike|SentinelOne|Carbon Black|Qualys|Wazuh|NXLog|Filebeat|Winlogbeat|osquery|Tanium' -or
    $_.Name -match '(?i)winlogbeat|filebeat|csagent|splunkd'
})
$wef = (((& wecutil gs *) 2>&1 | Out-String).Trim())
$hasWef = $wef.Length -gt 0 -and $wef -notmatch '(?i)error|不存在|No subscription'
Test-Item -Category 'Log' -Name '日志已外发到集中平台（WEF / Agent）' `
    -Actual ("Agent: " + $(if ($agents.Count -gt 0) { (($agents | ForEach-Object { $_.Name }) -join ', ') } else { '无' }) +
             " | WEF: " + $(if ($hasWef) { '有订阅' } else { '无' })) `
    -Expected '至少一种' -Risk 'P0' -Pass ($agents.Count -gt 0 -or $hasWef) `
    -Note '本机日志被清后，外发日志是唯一证据来源'

# 5.10 审计子类别
$auditpol = ((& auditpol /get /category:*) 2>&1 | Out-String)
$loginAuditOn = $auditpol -match '(?i)Logon\s+(Success|Success and Failure|失败和成功|成功)'
Test-Item -Category 'Log' -Name '登录审计已开启' `
    -Actual $(if ($loginAuditOn) { '已开启' } else { '未确认' }) -Expected '成功与失败均开启' -Risk 'P0' `
    -Pass $loginAuditOn -Note '详见输出的 auditpol.txt'

# 5.11 系统时间同步
$w32 = ((& w32tm /query /source) 2>&1 | Out-String).Trim()
Test-Item -Category 'Log' -Name '系统时间已同步' `
    -Actual ("时间源: " + $(if ($w32) { $w32 } else { '未知' })) -Expected '有有效时间源' -Risk 'P1' `
    -Pass ($w32 -and $w32 -notmatch '(?i)error|失败|拒绝')

# ============================================================
# 6. 端点防护
# ============================================================
Write-Host "[6/10] 端点防护" -ForegroundColor Cyan

$mp = Get-MpComputerStatus -EA SilentlyContinue
$mpp = Get-MpPreference -EA SilentlyContinue

if ($mp) {
    Test-Item -Category 'Defense' -Name 'Defender 实时保护已启用' `
        -Actual ("RealTimeProtectionEnabled=" + $mp.RealTimeProtectionEnabled) `
        -Expected 'True' -Risk 'P0' -Pass ($mp.RealTimeProtectionEnabled -eq $true)

    Test-Item -Category 'Defense' -Name 'Defender 行为监控已启用' `
        -Actual ("BehaviorMonitorEnabled=" + $mp.BehaviorMonitorEnabled) `
        -Expected 'True' -Risk 'P0' -Pass ($mp.BehaviorMonitorEnabled -eq $true)

    Test-Item -Category 'Defense' -Name 'Defender 篡改保护已启用' `
        -Actual ("IsTamperProtected=" + $mp.IsTamperProtected) `
        -Expected 'True' -Risk 'P1' -Pass ($mp.IsTamperProtected -eq $true)

    if ($mp.AntivirusSignatureLastUpdated) {
        $sigDays = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days
        Test-Item -Category 'Defense' -Name 'Defender 特征库更新及时（<= 3 天）' `
            -Actual ("上次更新 " + $sigDays + " 天前") -Expected '<= 3 天' -Risk 'P1' -Pass ($sigDays -le 3)
    }
} else {
    Test-Item -Category 'Defense' -Name 'Defender 可用性' `
        -Actual '无法获取 Defender 状态（可能被第三方杀软接管或已被禁用）' `
        -Expected '启用或被合规 EDR 接管' -Risk 'P0' -Pass $false
}

if ($mpp) {
    $exPaths = @($mpp.ExclusionPath | Where-Object { $_ })
    $exProcs = @($mpp.ExclusionProcess | Where-Object { $_ })
    $exExts  = @($mpp.ExclusionExtension | Where-Object { $_ })
    $exTotal = $exPaths.Count + $exProcs.Count + $exExts.Count
    Test-Item -Category 'Defense' -Name 'Defender 排除项需逐条核对' `
        -Actual ("路径: " + ($exPaths -join ', ') + " | 进程: " + ($exProcs -join ', ') + " | 扩展名: " + ($exExts -join ', ')) `
        -Expected '无 或 每条有书面依据' -Risk 'P0' -Pass ($exTotal -eq 0) `
        -Note '攻击者最常用的手法之一就是给自己加排除项'

    if ($mpp.DisableRealtimeMonitoring) {
        Test-Item -Category 'Defense' -Name '未通过策略禁用实时监控' `
            -Actual 'DisableRealtimeMonitoring=True' -Expected 'False / 未设置' -Risk 'P0' -Pass $false
    }

    $asrIds = @($mpp.AttackSurfaceReductionRules_Ids)
    $asrAct = @($mpp.AttackSurfaceReductionRules_Actions)
    $asrBlock = 0
    for ($i = 0; $i -lt $asrIds.Count; $i++) {
        if ($asrAct[$i] -eq 1) { $asrBlock++ }
    }
    Test-Item -Category 'Defense' -Name 'ASR 攻击面缩减规则已启用' `
        -Actual ("共 " + $asrIds.Count + " 条，其中 Block " + $asrBlock + " 条") `
        -Expected 'Office/WMI/脚本/勒索相关规则至少 8 条为 Block' -Risk 'P0' `
        -Pass ($asrBlock -ge 8) -Note '完整规则清单见 windows-host-audit.md 6.10'

    if ($null -ne $mpp.EnableNetworkProtection) {
        Test-Item -Category 'Defense' -Name '网络保护已启用' `
            -Actual ("EnableNetworkProtection=" + $mpp.EnableNetworkProtection) `
            -Expected '>= 1（1=Block, 2=Audit）' -Risk 'P1' -Pass ([int]$mpp.EnableNetworkProtection -ge 1)
    }

    if ($null -ne $mpp.EnableControlledFolderAccess) {
        Test-Item -Category 'Defense' -Name '受控文件夹访问已启用（防勒索）' `
            -Actual ("EnableControlledFolderAccess=" + $mpp.EnableControlledFolderAccess) `
            -Expected '1（Enabled）或 2（Audit）' -Risk 'P1' `
            -Pass ($mpp.EnableControlledFolderAccess -eq 1 -or $mpp.EnableControlledFolderAccess -eq 2)
    }
}

# EDR / 第三方 Agent
$edr = @(Get-Service | Where-Object {
    $_.DisplayName -match '(?i)CrowdStrike|SentinelOne|Carbon Black|Cortex|Trellix|McAfee|Symantec|Sophos|Trend Micro|Kaspersky|Tanium|Elastic Endpoint'
})
Test-Item -Category 'Defense' -Name 'EDR / 杀软 Agent（需业务确认）' `
    -Actual $(if ($edr.Count -gt 0) { (($edr | ForEach-Object { $_.DisplayName }) -join ', ') } else { '未检测到第三方 EDR' }) `
    -Expected '运行中且未被卸载' -Risk 'P0' -Pass ($edr.Count -gt 0 -or $null -ne $mp) `
    -Note '若原本有 EDR 现在没有，是强失陷信号（BYOVD 卸载）'

# ============================================================
# 7. 凭据保护
# ============================================================
Write-Host "[7/10] 凭据保护" -ForegroundColor Cyan

# 7.1 Credential Guard
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -EA SilentlyContinue
if ($dg) {
    Test-Item -Category 'Credential' -Name 'Credential Guard / VBS 运行中' `
        -Actual ("VBS=" + $dg.VirtualizationBasedSecurityStatus + " 服务=" + ($dg.SecurityServicesRunning -join ',')) `
        -Expected 'VBS=2 且含 1(Credential Guard)' -Risk 'P1' `
        -Pass ($dg.VirtualizationBasedSecurityStatus -eq 2)
}

# 7.2 明文凭据落盘检查
$credFiles = @()
foreach ($p in @("$env:USERPROFILE\.aws\credentials",
                 "$env:USERPROFILE\.git-credentials",
                 "$env:USERPROFILE\.kube\config",
                 "$env:USERPROFILE\.docker\config.json")) {
    if (Test-Path $p) { $credFiles += $p }
}
Test-Item -Category 'Credential' -Name '主机上无明文的云/开发凭据文件' `
    -Actual ($credFiles -join ', ') -Expected '无（若有，说明主机可能成为云横向跳板）' -Risk 'P0' `
    -Pass ($credFiles.Count -eq 0)

# 7.3 远控软件无人值守
$rcPattern = 'TeamViewer|AnyDesk|ToDesk|Sunlogin|RustDesk|AweSun|Splashtop|ScreenConnect|Atera|GotoHTTP'
$rcSvc = @(Get-CimInstance Win32_Service | Where-Object {
    $_.Name -match $rcPattern -or $_.PathName -match $rcPattern -or $_.DisplayName -match $rcPattern
})
Test-Item -Category 'Credential' -Name '无未授权的远程控制软件' `
    -Actual (($rcSvc | ForEach-Object { $_.Name }) -join ', ') -Expected '无 或 有业务授权' -Risk 'P0' `
    -Pass ($rcSvc.Count -eq 0) -Note '合法远控被滥用是近年增长最快的后门方式'

# 7.4 证书（可疑根证书）
$suspectCerts = @(Get-ChildItem Cert:\LocalMachine\Root -EA SilentlyContinue | Where-Object {
    $_.Subject -notmatch '(?i)Microsoft|VeriSign|DigiCert|GlobalSign|Entrust|Baltimore|Sectigo|USERTrust|COMODO|Go Daddy|Thawte|Symantec|DigiCert|Amazon|Google|Apple|ISRG|Let''s Encrypt|Certum|QuoVadis|SwissSign|T-Systems|Buypass|ACCV|Firmaprofesional|CFCA|GDCA|SecureTrust|Network Solutions|Starfield'
})
Test-Item -Category 'Credential' -Name '受信任根证书无异常项' `
    -Actual ("可疑 " + $suspectCerts.Count + " 个：" + (($suspectCerts | Select-Object -First 5 | ForEach-Object { $_.Subject }) -join ' | ')) `
    -Expected '仅标准的公共 CA 与内部合法 CA' -Risk 'P1' -Pass ($suspectCerts.Count -eq 0) `
    -Note '新增根证书 = 可中间人劫持 HTTPS'

# ============================================================
# 8. 攻击面
# ============================================================
Write-Host "[8/10] 攻击面" -ForegroundColor Cyan

# 8.1 Office 宏策略
$macroBlock = Get-RegValue 'HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security' 'blockcontentexecutionfrominternet'
if ($null -eq $macroBlock) {
    $macroBlock = Get-RegValue 'HKCU:\Software\Microsoft\Office\16.0\Word\Security' 'blockcontentexecutionfrominternet'
}
Test-Item -Category 'AttackSurface' -Name 'Office 阻止来自 Internet 的宏' `
    -Actual ("blockcontentexecutionfrominternet=" + $(if ($null -eq $macroBlock) { '(未配置)' } else { $macroBlock })) `
    -Expected '1' -Risk 'P0' -Pass ($macroBlock -eq 1) `
    -Note '未配置时钓鱼宏可直接执行'

# 8.2 VbaProject.OTM
$otm = Join-Path $env:APPDATA 'Microsoft\Outlook\VbaProject.OTM'
Test-Item -Category 'AttackSurface' -Name '不存在 VbaProject.OTM（宏后门高频位置）' `
    -Actual $(if (Test-Path $otm) { "存在: $otm" } else { '不存在' }) -Expected '不存在' -Risk 'P0' `
    -Pass (-not (Test-Path $otm))

# 8.3 浏览器强制安装扩展
$forcedExt = @()
foreach ($k in @('HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist',
                 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist')) {
    if (Test-Path $k) {
        $p = Get-ItemProperty $k -EA SilentlyContinue
        if ($p) { $forcedExt += @($p.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object { $_.Value }) }
    }
}
Test-Item -Category 'AttackSurface' -Name '浏览器无未知强制扩展' `
    -Actual ($forcedExt -join ', ') -Expected '无 或 均为企业管控扩展' -Risk 'P0' -Pass ($forcedExt.Count -eq 0)

# 8.4 AutoRun
$noAutoRun = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
Test-Item -Category 'AttackSurface' -Name 'AutoRun 已禁用' `
    -Actual ("NoDriveTypeAutoRun=" + $(if ($null -eq $noAutoRun) { '(未配置)' } else { $noAutoRun })) `
    -Expected '255 (0xFF)' -Risk 'P1' -Pass ($noAutoRun -eq 255)

# 8.5 PowerShell 执行策略
$execPol = Get-ExecutionPolicy -List | ForEach-Object { "$($_.Scope)=$($_.ExecutionPolicy)" }
Test-Item -Category 'AttackSurface' -Name 'PowerShell 执行策略受控' `
    -Actual ($execPol -join ', ') -Expected '由组策略统一管理（非 Undefined）' -Risk 'P2' -Pass $true `
    -Note '信息项：执行策略不是安全边界，但可提高攻击成本'

# 8.6 非必要软件
$riskySw = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                              'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue |
    Where-Object { $_.DisplayName -match '(?i)TeamViewer|AnyDesk|ToDesk|Sunlogin|RustDesk|Nmap|Wireshark|Cain|psexec|Mimikatz|keygen|crack|hack|破解' })
Test-Item -Category 'AttackSurface' -Name '无高危/非授权工具软件' `
    -Actual (($riskySw | ForEach-Object { $_.DisplayName }) -join ', ') `
    -Expected '无（安全工具应按流程管控）' -Risk 'P1' -Pass ($riskySw.Count -eq 0)

# ============================================================
# 9. 补丁与完整性
# ============================================================
Write-Host "[9/10] 补丁与完整性" -ForegroundColor Cyan

# 9.1 最近补丁
$lastPatch = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($lastPatch -and $lastPatch.InstalledOn) {
    $pDays = ((Get-Date) - $lastPatch.InstalledOn).Days
    Test-Item -Category 'Patch' -Name '最近 90 天内有补丁更新' `
        -Actual ("最近补丁 " + $lastPatch.HotFixID + " 于 " + $pDays + " 天前") `
        -Expected '<= 90 天' -Risk 'P0' -Pass ($pDays -le 90)
}

# 9.2 系统完整性
$sfc = ((& sfc /verifyonly) 2>&1 | Out-String)
$sfcOk = $sfc -match '(?i)differences|完整性违反|found no integrity'
($sfc.Trim()) | Out-File (Join-Path $OutputDir 'sfc-verifyonly.txt') -Encoding UTF8
Test-Item -Category 'Patch' -Name '系统文件完整性无异常' `
    -Actual $(if ($sfc -match '(?i)Windows Resource Protection did not find any integrity violations|未找到完整性冲突') { '无完整性违反' } else { '存在差异或未能判定，见 sfc-verifyonly.txt' }) `
    -Expected '无完整性违反' -Risk 'P1' `
    -Pass ($sfc -match '(?i)did not find any integrity violations|未找到完整性冲突')

# 9.3 安全启动
$sb = $null
try { $sb = Confirm-SecureBootUEFI } catch { $sb = $null }
if ($null -ne $sb) {
    Test-Item -Category 'Patch' -Name '安全启动（Secure Boot）已启用' `
        -Actual ("SecureBoot=" + $sb) -Expected 'True' -Risk 'P1' -Pass ($sb -eq $true)
} else {
    Test-Item -Category 'Patch' -Name '安全启动状态' `
        -Actual '无法查询（可能为传统 BIOS 或不支持）' -Expected '支持并启用' -Risk 'P2' -Pass $true `
        -Note '信息项'
}

# 9.4 非微软签名驱动（BYOVD 线索）
$lolDrv = @(Get-ChildItem "$env:SystemRoot\System32\drivers\*.sys" -EA SilentlyContinue | Where-Object {
    $_.Name -match '(?i)dbutil|rtcore|gdrv|iqvw64|speedfan|winring0|msio|cpuz|ene\.sys|asio|ntiolib|physmem|pmxdrv|atszios'
})
Test-Item -Category 'Patch' -Name '无已知易受攻击驱动（BYOVD）' `
    -Actual (($lolDrv | ForEach-Object { $_.Name }) -join ', ') -Expected '无（对照 LOLDrivers 清单）' -Risk 'P0' `
    -Pass ($lolDrv.Count -eq 0) -Note '这类驱动可被用于卸载 EDR、内核读写'

# ============================================================
# 10. 备份与恢复
# ============================================================
Write-Host "[10/10] 备份与恢复" -ForegroundColor Cyan

# 10.1 卷影副本
$vss = @(Get-CimInstance Win32_ShadowCopy -EA SilentlyContinue)
Test-Item -Category 'Backup' -Name '卷影副本可用（防勒索的本地底线）' `
    -Actual ("快照数: " + $vss.Count) -Expected '>= 1（或已有独立备份体系）' -Risk 'P1' -Pass ($vss.Count -gt 0) `
    -Note '若已有独立不可变备份，此项可豁免'

# 10.2 WinRE
$reagent = ((& reagentc /info) 2>&1 | Out-String)
$reEnabled = $reagent -match '(?i)Enabled|已启用'
($reagent.Trim()) | Out-File (Join-Path $OutputDir 'winre-info.txt') -Encoding UTF8
Test-Item -Category 'Backup' -Name 'Windows 恢复环境（WinRE）已启用' `
    -Actual $(if ($reEnabled) { 'Enabled' } else { 'Disabled 或未知' }) -Expected 'Enabled' -Risk 'P1' -Pass $reEnabled `
    -Note '勒索软件常通过 bcdedit 禁用它'

# 10.3 备份介质分离（信息项）
Test-Item -Category 'Backup' -Name '离线/不可变备份需人工确认' `
    -Actual '需人工核查（本脚本无法判定）' -Expected '至少一份离线或不可变备份，且凭据隔离' -Risk 'P0' `
    -Pass $true -Note '这是对抗勒索唯一真正有效的手段，务必人工确认'

# ============================================================
# 汇总报告
# ============================================================
$failP0 = @($script:Results | Where-Object { $_.Status -eq 'FAIL' -and $_.Risk -eq 'P0' })
$failP1 = @($script:Results | Where-Object { $_.Status -eq 'FAIL' -and $_.Risk -eq 'P1' })
$failP2 = @($script:Results | Where-Object { $_.Status -eq 'FAIL' -and $_.Risk -eq 'P2' })
$pass   = @($script:Results | Where-Object { $_.Status -eq 'PASS' })

Save-Csv ($script:Results) 'baseline-report'

# 文本报告
$reportPath = Join-Path $OutputDir '00-BASELINE-SUMMARY.txt'
$sb2 = New-Object System.Text.StringBuilder
[void]$sb2.AppendLine("==============================================================")
[void]$sb2.AppendLine(" Windows 安全基线核查报告")
[void]$sb2.AppendLine("==============================================================")
[void]$sb2.AppendLine("主机        : $env:COMPUTERNAME")
[void]$sb2.AppendLine("域          : $((Get-CimInstance Win32_ComputerSystem).Domain)")
[void]$sb2.AppendLine("操作系统    : $((Get-CimInstance Win32_OperatingSystem).Caption)")
[void]$sb2.AppendLine("核查时间    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$sb2.AppendLine("管理员权限  : $IsAdmin")
[void]$sb2.AppendLine("")
[void]$sb2.AppendLine("核查项总数  : $($script:TotalChecks)")
[void]$sb2.AppendLine("  通过      : $($pass.Count)")
[void]$sb2.AppendLine("  不通过 P0 : $($failP0.Count)   <- 24 小时内处置")
[void]$sb2.AppendLine("  不通过 P1 : $($failP1.Count)   <- 1-2 周内处置")
[void]$sb2.AppendLine("  不通过 P2 : $($failP2.Count)   <- 1 个月内处置")
[void]$sb2.AppendLine("")

if ($failP0.Count -gt 0) {
    [void]$sb2.AppendLine("--------------------------------------------------------------")
    [void]$sb2.AppendLine(" 【P0 高危】必须优先处置")
    [void]$sb2.AppendLine("--------------------------------------------------------------")
    foreach ($r in $failP0) {
        [void]$sb2.AppendLine("  [$($r.Category)] $($r.Item)")
        [void]$sb2.AppendLine("      实测: $($r.Actual)")
        if ($r.Expected) { [void]$sb2.AppendLine("      期望: $($r.Expected)") }
        if ($r.Note)     { [void]$sb2.AppendLine("      说明: $($r.Note)") }
        [void]$sb2.AppendLine("")
    }
}

if ($failP1.Count -gt 0) {
    [void]$sb2.AppendLine("--------------------------------------------------------------")
    [void]$sb2.AppendLine(" 【P1 中危】")
    [void]$sb2.AppendLine("--------------------------------------------------------------")
    foreach ($r in $failP1) {
        [void]$sb2.AppendLine("  [$($r.Category)] $($r.Item)")
        [void]$sb2.AppendLine("      实测: $($r.Actual)")
        if ($r.Expected) { [void]$sb2.AppendLine("      期望: $($r.Expected)") }
        [void]$sb2.AppendLine("")
    }
}

if ($failP2.Count -gt 0) {
    [void]$sb2.AppendLine("--------------------------------------------------------------")
    [void]$sb2.AppendLine(" 【P2 低危】")
    [void]$sb2.AppendLine("--------------------------------------------------------------")
    foreach ($r in $failP2) {
        [void]$sb2.AppendLine("  [$($r.Category)] $($r.Item) -> $($r.Actual)")
    }
    [void]$sb2.AppendLine("")
}

[void]$sb2.AppendLine("--------------------------------------------------------------")
[void]$sb2.AppendLine(" 【加固提示】")
[void]$sb2.AppendLine("--------------------------------------------------------------")
[void]$sb2.AppendLine("  1. 先做'提升可见性'的项（日志/Sysmon/审计），它们不改变业务行为，风险最低。")
[void]$sb2.AppendLine("  2. 再做'收敛攻击面'的项（RDP/SMB/服务/账号）。")
[void]$sb2.AppendLine("  3. 最后做'限制性'的项（WDAC/约束语言模式），必须先在审计模式验证。")
[void]$sb2.AppendLine("  4. 详细方法与风险控制见 windows/windows-hardening.md 第 5 节。")
[void]$sb2.AppendLine("  5. 加固后请重跑本脚本，验证处置结果。")
[void]$sb2.AppendLine("")
[void]$sb2.AppendLine("==============================================================")

$sb2.ToString() | Out-File $reportPath -Encoding UTF8

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " 核查完成"                                -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host " 核查项: $($script:TotalChecks)  通过: $($pass.Count)"
Write-Host " 不通过: P0=$($failP0.Count)  P1=$($failP1.Count)  P2=$($failP2.Count)" `
    -ForegroundColor $(if ($failP0.Count -gt 0) { 'Red' } else { 'Yellow' })
Write-Host ""
Write-Host " 报告: $reportPath"
Write-Host " 明细: $(Join-Path $OutputDir 'baseline-report.csv')"
Write-Host ""
