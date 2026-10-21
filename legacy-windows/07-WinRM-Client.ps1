<#
    07-WinRM-Client.ps1
    Da eseguire da STAGE3 (o da qualsiasi client) per verificare e usare WinRM verso il DC.
#>
[CmdletBinding()]
param(
    [string]$DC = '192.168.1.10',
    [string]$Domain = 'example.lan',
    [switch]$UseHttps,
    [switch]$Setup
)

$ErrorActionPreference = 'Continue'
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    [OK]   $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    [WARN] $m" -ForegroundColor Yellow }
function Err($m)  { Write-Host "    [ERR]  $m" -ForegroundColor Red }

# ---------------------------------------------------------------- 1. TrustedHosts
Step "TrustedHosts su questo client"
$cur = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
Ok "Valore attuale: '$cur'"
if ($Setup) {
    $hosts = @($cur -split ',' | Where-Object { $_ }) + $DC + 'homelab.example.lan'
    $hosts = $hosts | Select-Object -Unique
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value ($hosts -join ',') -Force
    Ok "TrustedHosts impostato su: $($hosts -join ', ')"
}

# ---------------------------------------------------------------- 2. Test rete
Step "Test porte WinRM"
foreach ($p in @(5985, 5986)) {
    $ok = Test-NetConnection -ComputerName $DC -Port $p -WarningAction SilentlyContinue
    if ($ok.TcpTestSucceeded) { Ok "porta $p aperta" } else { Warn "porta $p chiusa" }
}

# ---------------------------------------------------------------- 3. Sessione
Step "Apertura sessione remota"
$cred = $null
if (-not $UseHttps) {
    $cred = Get-Credential -Message "Credenziali per $Domain (es. example.lan\utente o utente@example.lan)"
}

$sessOpt = New-PSSessionOption -SkipCACheck -SkipCNCheck -OpenTimeout 15000 -OperationTimeout 60000
$target = if ($UseHttps) { 'https://192.168.1.10:5986' } else { $DC }

try {
    if ($cred) {
        $s = New-PSSession -ComputerName $target -Authentication Negotiate -Credential $cred -SessionOption $sessOpt -ErrorAction Stop
    } else {
        $s = New-PSSession -ComputerName $target -Authentication Negotiate -SessionOption $sessOpt -ErrorAction Stop
    }
    Ok "Sessione aperta: $target"
} catch {
    Err "Sessione non riuscita: $($_.Exception.Message)"
    Warn "Suggerimento: -UseHttps se il DC ha il listener HTTPS (porta 5986) con certificato."
    Write-Host @"
  Comandi manuali alternativi:
    Enter-PSSession -ComputerName $target -Authentication Negotiate -Credential (Get-Credential $Domain\utente)
    winrs -r:$DC -u:$Domain\utente -p:Password hostname
"@ -ForegroundColor Yellow
    exit 1
}

# ---------------------------------------------------------------- 4. Comandi diagnostici
function Run([string]$title, [scriptblock]$sb) {
    Write-Host ""
    Write-Host "--- $title ---" -ForegroundColor Magenta
    try { Invoke-Command -Session $s -ScriptBlock $sb | Out-String | Write-Host } catch { Err "$($_.Exception.Message)" }
}

Run 'Identita' { whoami; hostname; Get-Date }

Run 'Domain controller' {
    Get-ADDomainController | Select-Object HostName, Site, IPv4Address, IsGlobalCatalog, IsGlobalCatalogEnabled, Enabled, Status |
        Format-Table -AutoSize | Out-String
}

Run 'Stato replica (repadmin /replsummary)' { & repadmin /replsummary 2>&1 | Out-String }

Run 'Partner di replica in dettaglio' {
    & repadmin /repl /csv 2>$null | ConvertFrom-Csv |
        Select-Object 'Source DC','Destination DC',Partition,'Replication Status','Last Successful Replication Time','Consecutive Failures' |
        Format-Table -AutoSize | Out-String
}

Run 'Errori di replica' { Get-ADReplicationFailure -ErrorAction SilentlyContinue | Format-List | Out-String }

Run 'FSMO' {
    Get-ADDomainController | Select-Object HostName, PDCEmulator, RIDMaster, InfrastructureMaster, DomainNamingMaster | Format-List | Out-String
}

Run 'dcdiag (sintesi)' { & dcdiag /e /c /q 2>&1 | Select-Object -Last 40 | Out-String }

Run 'Servizi critici' {
    Get-Service NTDS, DNS, Kerberos, Netlogon, DFSR, WinRM, ADWS -ErrorAction SilentlyContinue |
        Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String
}

Run 'DNS zone' { Get-DnsServerZone -ErrorAction SilentlyContinue | Select-Object ZoneName, DnsServerZoneSerial | Format-Table -AutoSize | Out-String }

Run 'Ultimi eventi Directory Service' {
    Get-WinEvent -FilterHashtable @{ LogName='Directory Service'; Level=1,2,3 } -MaxEvents 15 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List | Out-String
}

Run 'Logon falliti (ultima ora)' {
    Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-1) } -MaxEvents 20 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Message | Format-List | Out-String
}

Remove-PSSession $s
Write-Host ""
Ok "Sessione chiusa."
