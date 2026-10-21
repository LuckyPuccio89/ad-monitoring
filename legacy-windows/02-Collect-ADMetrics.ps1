<#
    02-Collect-ADMetrics.ps1
    Raccoglie lo stato di Active Directory e lo esporta in formato Prometheus (text exposition).
    Girare come SYSTEM ogni 60 secondi (vedi 04-Install-ADMonitor.ps1).
    Output: C:\ProgramData\ADMonitor\metrics.prom  (scrittura atomica)
#>
[CmdletBinding()]
param(
    [string]$Domain      = 'example.lan',
    [string]$OutputPath  = 'C:\ProgramData\ADMonitor\metrics.prom'
)

$ErrorActionPreference = 'Stop'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$out = New-Object System.Collections.Generic.List[string]

function M([string]$name, $value, [string]$type = 'gauge', [string]$help = '') {
    if ($help) { $script:out.Add("# HELP $name $help") }
    $script:out.Add("# TYPE $name $type")
    $script:out.Add("$name $value")
}
function Esc([string]$v) {
    if ($null -eq $v) { return '' }
    $v -replace '\\', '\\' -replace '"', '\"' -replace "`n", '\n' -replace "`r", ''
}
function Safe([scriptblock]$b, $default = $null) {
    try { & $b } catch { $script:out.Add("# ERROR in: $($_.Exception.Message)"); $default }
}

# ---------------------------------------------------------------------------
# 0. Identita' DC
# ---------------------------------------------------------------------------
$dcName       = $env:COMPUTERNAME
$dcFqdn       = try { (Get-ADDomainController -Identity $dcName).HostName } catch { "$dcName.$Domain" }
$siteName     = Safe { (Get-ADDomainController -Identity $dcName).Site } 'Unknown'
$dcLabels     = "instance=`"$dcName`",fqdn=`"$dcFqdn`",domain=`"$Domain`",site=`"$siteName`""

M 'ad_dc_up' 1 'gauge' 'Always 1 if the AD collector can query this domain controller.'

# ---------------------------------------------------------------------------
# 1. Servizi critici
# ---------------------------------------------------------------------------
$crit = @{
    NTDS    = 'NTDS'
    DNS     = 'DNS'
    KDC     = 'Kerberos Key Distribution Center'
    Netlogon = 'Netlogon'
    DFSR    = 'DFS Replication'
    WinRM   = 'WinRM'
}
foreach ($k in $crit.Keys) {
    $svc = Safe { Get-Service -Name $k -ErrorAction Stop } $null
    if ($svc) {
        $st = if ($svc.Status -eq 'Running') { 1 } else { 0 }
        M "ad_dc_service_state{service=`"$k`",instance=`"$dcName`"}" $st 'gauge' "1 if the Windows service is running."
    }
}

# ---------------------------------------------------------------------------
# 2. Bind LDAP + DNS resolution
# ---------------------------------------------------------------------------
$bindOk = 0; $bindMs = 0
try {
    $b = [System.Diagnostics.Stopwatch]::StartNew()
    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($dcFqdn)
    $conn.SessionOptions.ProtocolVersion = 3
    $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    $conn.Bind()
    $b.Stop(); $bindMs = [math]::Round($b.Elapsed.TotalMilliseconds, 3)
    $bindOk = 1
    $conn.Dispose()
} catch { }
M "ad_dc_ldap_bind_success$dcLabels" $bindOk 'gauge' '1 if the LDAP (Negotiate/Kerberos) bind succeeds.'
M "ad_dc_ldap_bind_duration_seconds$dcLabels" $bindMs 'gauge' 'LDAP bind latency in seconds.'

$dnsOk = 0
try { if ([System.Net.Dns]::GetHostEntry($dcFqdn)) { $dnsOk = 1 } } catch { }
M "ad_dc_dns_resolve_success$dcLabels" $dnsOk 'gauge' '1 if the DC FQDN resolves via DNS.'

# ---------------------------------------------------------------------------
# 3. Replicazione
# ---------------------------------------------------------------------------
try {
    $repl = & repadmin /repl /csv 2>$null | ConvertFrom-Csv
    foreach ($r in $repl) {
        $src = Esc $r.'Source DC'
        $dst = Esc $r.'Destination DC'
        $part = Esc $r.Partition
        $lbl  = "source=`"$src`",destination=`"$dst`",partition=`"$part`""
        $ok   = if ($r.'Replication Status' -eq '0') { 1 } else { 0 }
        M "ad_replication_failed{$lbl}" $ok 'gauge' '1 if the last replication attempt failed.'
        $cf = 0; [void][int]::TryParse($r.'Consecutive Failures', [ref]$cf)
        M "ad_replication_consecutive_failures{$lbl}" $cf 'gauge' 'Consecutive failed replication attempts.'
        $lag = -1
        if ($r.'Last Successful Replication Time') {
            $t = [datetime]::Parse($r.'Last Successful Replication Time')
            $lag = [math]::Round(((Get-Date) - $t).TotalSeconds, 0)
        }
        M "ad_replication_lag_seconds{$lbl}" $lag 'gauge' 'Seconds since the last successful replication (lag).'
        $ts = 0
        if ($r.'Last Successful Replication Time') { $ts = [datetime]::Parse($r.'Last Successful Replication Time').ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds }
        M "ad_replication_last_sync_timestamp_seconds{$lbl}" $ts 'gauge' 'Unix timestamp of the last successful replication.'
    }
} catch { $out.Add("# ERROR replication: $($_.Exception.Message)") }

try {
    $fails = Get-ADReplicationFailure -Server $dcName -ErrorAction Stop
    foreach ($f in $fails) {
        $lbl = "reason=`"$(Esc $f.Reason)`",object=`"$(Esc $f.ObjectDN)`""
        M "ad_replication_failure{$lbl}" 1 'gauge' '1 for each replication failure reported by Get-ADReplicationFailure.'
    }
} catch { }

# ---------------------------------------------------------------------------
# 4. Domain controller, FSMO, sito
# ---------------------------------------------------------------------------
try {
    $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
    foreach ($d in $dcs) {
        $lbl = "instance=`"$(Esc $d.HostName)`",site=`"$(Esc $d.Site)`",global_catalog=`"$($d.IsGlobalCatalog)`",enabled=`"$($d.Enabled)`""
        M "ad_domain_controller{$lbl}" 1 'gauge' '1 for each domain controller discovered in the forest.'
        $st = 0
        if ($d.Status -match 'Up') { $st = 1 }
        M "ad_domain_controller_status{$lbl}" $st 'gauge' '1 if the DC status is Up.'
        $since = [math]::Round(((Get-Date) - $d.OperatingSystem.CreationDate).TotalSeconds, 0)
        M "ad_domain_controller_uptime_seconds{$lbl}" $since 'gauge' 'Seconds since the DC OS was created.'
    }
    M 'ad_domain_controller_count' @($dcs).Count 'gauge' 'Number of domain controllers in the forest.'
    $sites = @($dcs | Select-Object -ExpandProperty Site -Unique)
    M 'ad_site_count' $sites.Count 'gauge' 'Number of AD sites.'
} catch { }

try {
    $dc = Get-ADDomainController -Identity $dcName -ErrorAction Stop
    foreach ($r in @(
        @{ n = 'PDCEmulator';        v = $dc.PDCEmulator },
        @{ n = 'RIDMaster';          v = $dc.RIDMaster },
        @{ n = 'InfrastructureMaster'; v = $dc.InfrastructureMaster },
        @{ n = 'DomainNamingMaster'; v = $dc.DomainNamingMaster }
    )) {
        if ($r.v) { M "ad_fsmo_role_holder{role=`"$($r.n)`",instance=`"$dcName`"}" 1 'gauge' '1 on the DC holding the given FSMO role.' }
    }
} catch { }

# ---------------------------------------------------------------------------
# 5.Oggetti di directory
# ---------------------------------------------------------------------------
function CountLdap($filter) {
    try { (Get-ADObject -LDAPFilter $filter -ErrorAction Stop | Measure-Object).Count } catch { -1 }
}
M 'ad_directory_users'      (CountLdap '(objectClass=user)')                                    'gauge' 'User objects in the domain.'
M 'ad_directory_computers'  (CountLdap '(objectClass=computer)')                                'gauge' 'Computer objects in the domain.'
M 'ad_directory_groups'     (CountLdap '(objectClass=group)')                                   'gauge' 'Group objects in the domain.'
M 'ad_directory_ous'        (CountLdap '(objectClass=organizationalUnit)')                      'gauge' 'Organizational units.'
M 'ad_directory_privileged_users' (CountLdap '(userAccountControl:1.2.840.113556.1.4.803:=2)') 'gauge' 'Users with adminCount=1 (privileged).'
M 'ad_directory_locked_users' (CountLdap '(objectClass=user)(lockoutTime>=1)')                  'gauge' 'Users currently locked out.'
M 'ad_directory_disabled_users' (CountLdap '(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)') 'gauge' 'Disabled user accounts.'

# ---------------------------------------------------------------------------
# 6. DNS
# ---------------------------------------------------------------------------
try {
    $zones = Get-DnsServerZone -ErrorAction Stop
    foreach ($z in $zones) {
        M "ad_dns_zone_serial{zone=`"$(Esc $z.ZoneName)`"}" $z.DnsServerZoneSerial 'gauge' 'SOA serial of the DNS zone.'
    }
    M 'ad_dns_zone_count' @($zones).Count 'gauge' 'Number of DNS zones hosted on this DC.'
} catch { }

# ---------------------------------------------------------------------------
# 7. Eventi (ultima ora)
# ---------------------------------------------------------------------------
function CountEvents($log, $ids, $hours = 1) {
    try {
        $start = (Get-Date).AddHours(-$hours)
        $f = @{ LogName = $log; StartTime = $start; ErrorAction = 'Stop' }
        if ($ids) { $f['Id'] = $ids }
        @(Get-WinEvent -FilterHashtable $f -ErrorAction Stop).Count
    } catch { 0 }
}

$failedLogon = CountEvents 'Security' 4625
M 'ad_events_failed_logon_1h'      $failedLogon 'gauge' 'Event 4625 (failed logon) in the last hour.'
M 'ad_events_privileged_1h'        (CountEvents 'Security' 4672)  'gauge' 'Event 4672 (special privileges) in the last hour.'
M 'ad_events_admin_1h'             (CountEvents 'Security' 4672,4732) 'gauge' 'Admin-equivalent logons in the last hour.'
M 'ad_events_group_add_1h'         (CountEvents 'Security' 4728)  'gauge' 'Event 4728 (member added to global group) in the last hour.'
M 'ad_events_account_lockout_1h'   (CountEvents 'Security' 4740)  'gauge' 'Event 4740 (account lockout) in the last hour.'
M 'ad_events_ticket_1h'            (CountEvents 'Security' 4767,4768,4771) 'gauge' 'Kerberos ticket errors in the last hour.'
M 'ad_events_kerberos_service_1h'  (CountEvents 'Security' 4768,4769,4770) 'gauge' 'Kerberos service ticket errors in the last hour.'
M 'ad_events_ds_error_1h'          (CountEvents 'Directory Service' @(135,1450,2159,2201,2300,2600)) 'gauge' 'Directory Service errors in the last hour.'
M 'ad_events_replication_error_1h' (CountEvents 'Directory Service' @(135,136,1450,2159)) 'gauge' 'Replication-related errors in the last hour.'
M 'ad_events_system_critical_1h'   (CountEvents 'System' @(7031,7034,7036)) 'gauge' 'System log service errors in the last hour.'
M 'ad_events_dns_error_1h'         (CountEvents 'DNS Server' @(4000,4001,4002,4003,4005,4010,4012,4013)) 'gauge' 'DNS Server errors in the last hour.'
M 'ad_events_efs_1h'               (CountEvents 'Security' 4656,4658,4663,4681) 'gauge' 'Effective access errors in the last hour.'

# Eventi di sicurezza specifici aggregati per top-source (utili al pannello brute force)
try {
    $start = (Get-Date).AddHours(-1)
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $start } -ErrorAction Stop |
          Select-Object -First 5000
    $ev | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -First 1).'#text'
        $user = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -First 1).'#text'
        if ($ip) { M "ad_failed_logon_source_total{ip=`"$(Esc $ip)`",user=`"$(Esc $user)`"}" 1 'counter' 'Failed logons per source IP in the last hour.' }
    }
} catch { }

# ---------------------------------------------------------------------------
# 8. dcdiag
# ---------------------------------------------------------------------------
$dcFail = -1
try {
    $txt = & dcdiag /e /c /q /v 2>&1 | Out-String
    $dcFail = ([regex]::Matches($txt, '(?im)^.*\bfailed\b.*$')).Count
} catch { }
M "ad_dcdiag_failures{instance=`"$dcName`"}" $dcFail 'gauge' 'Number of failed dcdiag checks (>=0 when dcdiag ran).'

# ---------------------------------------------------------------------------
# 9. Storage
# ---------------------------------------------------------------------------
try {
    $ntds = Join-Path $env:SystemRoot 'NTDS\ntds.dit'
    if (Test-Path $ntds) {
        M "ad_ntds_dit_size_bytes{instance=`"$dcName`"}" (Get-Item $ntds).Length 'gauge' 'Size of ntds.dit in bytes.'
    }
    $sysvol = Get-SmbShare -Name 'SYSVOL' -ErrorAction Stop
    M 'ad_sysvol_share_present' 1 'gauge' '1 if the SYSVOL share is present.'
} catch { M 'ad_sysvol_share_present' 0 'gauge' '1 if the SYSVOL share is present.' }

foreach ($d in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
    $used = $d.Used; $free = $d.Free
    if (($used + $free) -gt 0) {
        M "ad_volume_free_bytes{volume=`"$(Esc $d.Name)`"}" $free 'gauge' 'Free bytes per volume.'
        M "ad_volume_free_ratio{volume=`"$(Esc $d.Name)`"}" ([math]::Round($free / ($used + $free), 4)) 'gauge' 'Free ratio per volume.'
    }
}

# ---------------------------------------------------------------------------
# 10. Metadata collector
# ---------------------------------------------------------------------------
$sw.Stop()
M 'ad_collector_success' 1 'gauge' '1 if the last collection run completed.'
M 'ad_collector_duration_seconds' [math]::Round($sw.Elapsed.TotalSeconds, 3) 'gauge' 'Duration of the last collection run.'
M 'ad_collector_last_run_timestamp_seconds' ([datetime]::UtcNow - [datetime]'1970-01-01').TotalSeconds 'gauge' 'Unix timestamp of the last collection run.'

# ---------------------------------------------------------------------------
# Scrittura atomica
# ---------------------------------------------------------------------------
$dir = Split-Path $OutputPath -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$tmp = "$OutputPath.tmp"
[System.IO.File]::WriteAllLines($tmp, $out, (New-Object System.Text.UTF8Encoding($false)))
Move-Item -LiteralPath $tmp -Destination $OutputPath -Force
Write-Host ("AD metrics written: {0} ({1} lines, {2}s)" -f $OutputPath, $out.Count, [math]::Round($sw.Elapsed.TotalSeconds, 2))
