<#
    04-Install-ADMonitor.ps1
    Da eseguire sul DC come Amministratore. Installa:
      - i collector in C:\ProgramData\ADMonitor
      - task pianificati (Collect ogni 60s, Serve all'avvio)
      - regola firewall 9182
#>
[CmdletBinding()]
param(
    [string]$SourceDir = $PSScriptRoot,
    [string]$InstallDir = 'C:\ProgramData\ADMonitor',
    [int]$Port = 9182,
    [int]$IntervalSeconds = 60
)

$ErrorActionPreference = 'Stop'
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    [OK]   $m" -ForegroundColor Green }
function Err($m)  { Write-Host "    [ERR]  $m" -ForegroundColor Red }

Step "Creazione directory $InstallDir"
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

Step "Copia script"
foreach ($f in @('02-Collect-ADMetrics.ps1', '03-Serve-Metrics.ps1')) {
    $src = Join-Path $SourceDir $f
    if (Test-Path $src) {
        Copy-Item $src -Destination (Join-Path $InstallDir $f) -Force
        Ok "$f copiato"
    } else {
        Err "$f non trovato in $SourceDir"
    }
}

Step "Firewall porta $Port"
if (-not (Get-NetFirewallRule -DisplayName 'AD-Monitor-In' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'AD-Monitor-In' -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $Port -Profile Any -Enabled True | Out-Null
    Ok "Regola AD-Monitor-In creata"
} else { Ok "Regola gia' presente" }

function Register-Task($name, $script, $args, $trigger) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $args
    $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
    if ($trigger -eq 'Startup') { $t = New-ScheduledTaskTrigger -AtStartup }
    else { $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                -RepetitionInterval (New-TimeSpan -Seconds $IntervalSeconds) `
                -RepetitionDuration ([TimeSpan]::MaxValue) }
    Register-ScheduledTask -TaskName $name -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
    Ok "Task '$name' registrato"
}

Step "Task pianificati"
Register-Task 'ADMonitor-Collect' (Join-Path $InstallDir '02-Collect-ADMetrics.ps1') `
    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir '02-Collect-ADMetrics.ps1')`"" 'Repeat'
Register-Task 'ADMonitor-Serve' (Join-Path $InstallDir '03-Serve-Metrics.ps1') `
    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir '03-Serve-Metrics.ps1')`" -Port $Port" 'Startup'

Step "Avvio immediato"
Start-ScheduledTask -TaskName 'ADMonitor-Collect'
Start-ScheduledTask -TaskName 'ADMonitor-Serve'
Start-Sleep -Seconds 12
Ok "Task avviati"

Step "Verifica endpoint"
try {
    $r = Invoke-WebRequest "http://localhost:$Port/metrics" -UseBasicParsing -TimeoutSec 10
    Ok "HTTP $($r.StatusCode) - $($r.Content.Length) byte"
    ($r.Content -split "`n" | Where-Object { $_ -notmatch '^#' -and $_.Trim() -ne '' } | Select-Object -First 12) | ForEach-Object { "      $_" }
} catch {
    Err "Test endpoint: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "=== PROSSIMO PASSO ===" -ForegroundColor Green
Write-Host "Aggiungi al prometheus.yml sul DC:"
Write-Host @"
  - job_name: 'ad-dc'
    scrape_interval: 60s
    scrape_timeout: 20s
    static_configs:
      - targets: ['192.168.1.10:$Port']
        labels:
          instance_name: 'HOMELAB'
"@ -ForegroundColor Green
