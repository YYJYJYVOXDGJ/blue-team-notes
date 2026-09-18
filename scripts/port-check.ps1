[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
<#
.SYNOPSIS
Windows port listener scanner, list all listening tcp ports and related process
.DESCRIPTION
BlueTeam host inspection tool. Get listening TCP ports, match PID and process name automatically.
Replace manual netstat + tasklist operations, improve on-site emergency response efficiency.
#>

Write-Host "===== Windows Listening Port Scan =====" -ForegroundColor Cyan
Write-Host "LocalAddr`t`tPort`t`tProcName`t`tPID" -ForegroundColor Gray

$ports = Get-NetTCPConnection -State Listen

$result = foreach ($port in $ports) {
    $process = Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue
    $procName = if ($process) { $process.ProcessName } else { "UnknownProcess" }
    
    [PSCustomObject]@{
        LocalAddr = $port.LocalAddress
        Port      = $port.LocalPort
        ProcName  = $procName
        PID       = $port.OwningProcess
    }
}

$result | Format-Table -AutoSize
Write-Host "`nScan finished. Total $($ports.Count) listening ports." -ForegroundColor Green
