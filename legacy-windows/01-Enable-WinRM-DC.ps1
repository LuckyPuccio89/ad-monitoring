<#
    01-Enable-WinRM-DC.ps1
    Va eseguito sul DC (HOMELAB.example.lan / 192.168.1.10) come Amministratore.
    Abilita WinRM (HTTP listener + HTTPS listener) e apre il firewall.
#>
[CmdletBinding()]
param(
    [string]$Domain          = 'example.lan',
    [string]$SubnetAllowed   = '192.168.1.0/24,172.17.0.0/16,172.19.0.0/16,127.0.0.1',
    [switch]$HttpsOnly
)

$ErrorActionPreference = 'Continue'
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    [OK]   $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    [WARN] $m" -ForegroundColor Yellow }
function Err($m)  { Write-Host "    [ERR]  $m" -ForegroundColor Red }

Step "Contesto"
Ok "Host: $env:COMPUTERNAME.$Domain"
Ok "User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

# ---------------------------------------------------------------- WinRM service
Step "Servizio WinRM"
Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
if ((Get-Service WinRM).Status -ne 'Running') { Start-Service WinRM }
Ok "WinRM = $((Get-Service WinRM).Status)"

# ---------------------------------------------------------------- HTTPS listener
# Il listener HTTPS e' preferibile: niente TrustedHosts, niente NTLM in chiaro su rete.
Step "Listener HTTPS (porta 5986)"
try {
    $thumb = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
              Select-Object -First 1).Thumbprint

    if (-not $thumb) {
        Warn "Nessun certificato con chiave privata trovata in Cert:\LocalMachine\My"
        Warn "Creazione certificato self-signed per WinRM..."
        $cert = New-SelfSignedCertificate -Subject "CN=$env:COMPUTERNAME.$Domain" `
                    -DnsName "localhost","$env:COMPUTERNAME","$env:COMPUTERNAME.$Domain" `
                    -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(2)
        $thumb = $cert.Thumbprint
        Ok "Certificato creato: $thumb"
    } else {
        Ok "Certificato esistente: $thumb"
    }

    $existing = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' }
    if (-not $existing) {
        New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $thumb -Force | Out-Null
        Ok "Listener HTTPS creato"
    } else {
        Ok "Listener HTTPS gia' presente"
    }
} catch {
    Err "Listener HTTPS: $($_.Exception.Message)"
}

# ---------------------------------------------------------------- HTTP listener
if (-not $HttpsOnly) {
    Step "Listener HTTP (porta 5985) - solo per host Prometheus/collector"
    try {
        $existing = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTP' }
        if (-not $existing) {
            New-Item -Path WSMan:\localhost\Listener -Transport HTTP -Address * -Force | Out-Null
            Ok "Listener HTTP creato"
        } else {
            Ok "Listener HTTP gia' presente"
        }
    } catch {
        Err "Listener HTTP: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------- WinRM hardening
Step "Hardening sessione WinRM"
try {
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
    Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
    Set-Item WSMan:\localhost\MaxMemoryPerShellMB -Value 512
    Set-Item WSMan:\localhost\Service\MaxTimeoutms -Value 1800000
    Ok "Auth: Basic=off, Negotiate=on, Unencrypted=off"
} catch {
    Warn "Hardening parziale: $($_.Exception.Message)"
}

# ---------------------------------------------------------------- Firewall
Step "Firewall Windows"
foreach ($rule in @(
    @{ N = 'WinRM-HTTPS-In'; P = 5986 },
    @{ N = 'WinRM-HTTP-In';  P = 5985 }
)) {
    if (-not (Get-NetFirewallRule -DisplayName $rule.N -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule.N -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $rule.P -Profile Any -Enabled True | Out-Null
        Ok "Regola $($rule.N) (porta $($rule.P)) creata"
    } else {
        Ok "Regola $($rule.N) gia' presente"
    }
}

# ------------------------------------------------------------- ADWS (porta 9389)
Step "Active Directory Web Services (9389) - per Lync/DPAPI/ADWS query"
try {
    if ((Get-Service ADWS).Status -ne 'Running') { Start-Service ADWS }
    Set-Service ADWS -StartupType Automatic
    if (-not (Get-NetFirewallRule -DisplayName 'ADWS-In' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'ADWS-In' -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort 9389 -Profile Any -Enabled True | Out-Null
    }
    Ok "ADWS = $((Get-Service ADWS).Status)"
} catch {
    Warn "ADWS: $($_.Exception.Message)"
}

# ------------------------------------------------- Endpoint di monitoring locale
Step "Endpoint HTTP metriche AD (9182) per Prometheus"
if (-not (Get-NetFirewallRule -DisplayName 'AD-Monitor-In' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'AD-Monitor-In' -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 9182 -Profile Any -Enabled True | Out-Null
    Ok "Regola AD-Monitor-In creata"
} else {
    Ok "Regola AD-Monitor-In gia' presente"
}

# ---------------------------------------------------------------- Verifica
Step "Verifica listener attivi"
Get-ChildItem WSMan:\localhost\Listener | ForEach-Object { Ok ("Listener: " + ($_.Keys -join ', ')) }

Step "Verifica connettivita' locale"
try {
    $s = New-PSSession -ComputerName localhost -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck -OpenTimeout 10000) -ErrorAction Stop
    Ok "Test-PSSession localhost: OK"
    Remove-PSSession $s
} catch {
    Warn "Test-PSSession localhost: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "=== COMANDI PER IL CLIENT (STAGE3 / container Prometheus) ===" -ForegroundColor Green
Write-Host @"
  # Da STAGE3 (PS 5.1) - per usare l'IP serve TrustedHosts:
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value '192.168.1.10' -Force
  \$s = New-PSSession -ComputerName 192.168.1.10 -Authentication Negotiate -Credential (Get-Credential example.lan\utente) -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck)
  Invoke-Command -Session \$s -ScriptBlock { Get-ADDomainController | Select-Object HostName,Site,IPv4Address,IsGlobalCatalog,Status }

  # Oppure, se il client e' in dominio example.lan, Kerberos funziona senza TrustedHosts:
  Invoke-Command -ComputerName homelab.example.lan -ScriptBlock { hostname }
"@ -ForegroundColor Green
