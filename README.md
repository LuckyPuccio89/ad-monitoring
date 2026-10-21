# Monitoraggio Active Directory — Samba AD DC (Zentyal)

Dominio `example.lan` · DC unico `HOMELAB.example.lan` · **Samba 4.19.5 su Ubuntu 24.04**
Stack: Prometheus 3.15.0 + Grafana 13.0.2 (Docker) sullo stesso host, dashboard uid `active-directory`.

> Il contenuto originale di questa cartella era scritto per un DC **Windows** (WinRM, `Get-AD*`,
> `repadmin`, `dcdiag`, `Get-WinEvent`). Su questo host quelle API non esistono: WinRM/ADWS sono
> chiusi e il DC è Samba. Il materiale è archiviato in `legacy-windows/` e **non va eseguito**.
> Piano completo e motivazioni: [`PLAN.md`](PLAN.md).

## Stato

| Fase | Stato |
|---|---|
| 0 — backup e struttura | fatto (`/opt/ad-monitoring/backup/`) |
| 1 — exporter nativo Samba | fatto e attivo (`ad-monitor.service`, `172.19.0.1:9182`) |
| 2 — sicurezza/autenticazione/salute | parziale: metriche auth e `dbcheck` settimanale attivi; mancano probe `kinit` e account LDAP dedicato |
| 3 — dashboard Grafana | fatto (38 pannelli, provisioning persistente) |
| 4 — alert Grafana-managed | fatto: 16 regole, notifica email, test end-to-end passato |
| 5 — consolidamento/hardening | parziale: README e runbook fatti; accesso anonimo Grafana da valutare |

## Architettura

```
samba-ad-dc + named
      │  ldbsearch · samba-tool · systemctl · rndc/dig · log auth JSON
      ▼
ad-monitor.service (Python, 172.19.0.1:9182)
      ▲ scrape 60s
monitoring-prometheus-1 ──► monitoring-grafana-1 (dashboard AD)
```

Nessuna porta AD aggiuntiva, nessun WinRM, nessuna credenziale. L'exporter è in sola lettura.

## File

| File | Dove va | Scopo |
|---|---|---|
| `exporter/ad-monitor.py` | `/opt/ad-monitoring/` | exporter metriche (systemd) |
| `exporter/ad-dbcheck.py` | `/opt/ad-monitoring/` | `samba-tool dbcheck` settimanale |
| `deploy/ad-monitor.service` | `/etc/systemd/system/` | unit del collector |
| `deploy/ad-dbcheck.service` / `.timer` | `/etc/systemd/system/` | dbcheck periodico |
| `deploy/logrotate-ad-monitoring-samba` | `/etc/logrotate.d/ad-monitoring-samba` | rotazione `samba.log` |
| `prometheus.yml` | `/opt/monitoring/prometheus.yml` | job `ad-dc` + blackbox corretto |
| `grafana/ad.json` | `/var/lib/grafana/dashboards-ad/ad.json` | dashboard (generata) |
| `grafana/ad.yml` | `/etc/grafana/provisioning/dashboards/ad.yml` | provider |
| `grafana/alerting/rules.yaml` | `/etc/grafana/provisioning/alerting/` | 16 regole (generato) |
| `grafana/alerting/notification-policies.yaml` | idem | policy verso `email-ad` |
| `grafana/alerting/contact-points.yaml.tmpl` | idem (renderizzato) | contact point email |
| `tools/gen_dashboard.py` | `/opt/ad-monitoring/tools/` | generatore dashboard (fonte unica) |
| `tools/gen_alert_rules.py` | `/opt/ad-monitoring/tools/` | generatore regole (fonte unica) |
| `tools/apply-smtp.py` | `/opt/ad-monitoring/tools/` | scrive `[smtp]` in grafana.ini |
| `tools/deploy-alerting.sh` | `/opt/ad-monitoring/tools/` | deploy SMTP + alerting |
| `deploy/smtp.env.example` | `/etc/ad-monitoring/smtp.env` | modello credenziali SMTP |
| `deploy/apply.sh` | `/opt/monitoring/grafana/apply.sh` | persistenza provisioning dopo recreate |
| `tools/site-poll.py` | `/opt/ad-monitoring/tools/` | snapshot `api/ad.json` per il sito (60 s) |
| `deploy/ad-site-poll.service` | `/etc/systemd/system/` | unit del poller sito |
| `deploy/ad-site-poll.timer` | `/etc/systemd/system/` | timer 60 s del poller sito |
| `RUNBOOK.md` | `/opt/ad-monitoring/docs/` | operatività, troubleshooting, rollback |
| `legacy-windows/` | — | kit Windows archiviato, non eseguibile qui |

## Verifica rapida

```bash
curl -s http://172.19.0.1:9182/healthz
curl -s http://172.19.0.1:9182/metrics | grep '^ad_collector'
curl -s http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22ad-dc%22%7D
open http://192.168.1.10:3000/grafana/d/active-directory
```

## Metriche principali (`ad_*`)

Directory: `ad_directory_users{,_enabled,_disabled,_locked,_password_never_expires,_password_expired,_stale_logon}`,
`ad_directory_computers{,_enabled,_stale}`, `ad_directory_groups`, `ad_directory_ous`,
`ad_privileged_accounts`, `ad_group_members{group}`, `ad_domain_controllers`.

Servizi e collector: `ad_dc_service_active`, `ad_dc_service_restarts_total`, `ad_dc_uptime_seconds`,
`ad_collector_success`, `ad_collector_partial_errors`, `ad_collector_section_ok{section}`,
`ad_collector_duration_seconds`, `ad_collector_last_run_timestamp_seconds`, `ad_dc_info`.

Sicurezza: `ad_auth_success_1h`, `ad_auth_failures_1h`, `ad_auth_lockouts_1h`,
`ad_auth_failures_by_status_1h`, `ad_auth_failures_by_source_1h` (top 10 IP).

DNS/Kerberos: `ad_dns_zones`, `ad_dns_zone_serial{zone}`, `ad_dns_srv_ok{record}`,
`ad_dns_xfer_deferred`, `ad_dns_xfer_running`.

Salute: `ad_sysvol_share_ok`, `ad_replication_partners`, `ad_dbcheck_errors`,
`ad_dbcheck_last_run_timestamp_seconds`.

## Alert

16 regole Grafana-managed (7 gruppi: availability, services, directory, auth, dns, health,
structural), notifica via email `admin@example.com` con SMTP Gmail 587/TLS.

Soglie principali: target/collector down 3–5 min; Samba/named down 2–5 min; SRV/SYSVOL 5 min;
oltre 20 auth fallite/h; oltre 2 account bloccati; modifiche ai gruppi privilegiati;
serial DNS non leggibile (non il serial semplicemente fermo, normale in un dominio statico);
`dbcheck` errori o fermo da 8 giorni; single-DC a severità `info` (1 notifica/24h).

Per modificare le regole: `tools/gen_alert_rules.py`, poi `tools/deploy-alerting.sh`.
Credenziali SMTP in `/etc/ad-monitoring/smtp.env` (0600, mai nel repo);
modello in `deploy/smtp.env.example`.

## Pagina pubblica sul sito

La dashboard AD e' pubblicata come progetto su `https://pucci-homelab.duckdns.org/ad-monitoring.html`
(card in `projects.html`). Non e' un iframe di Grafana: la pagina legge `api/ad.json`, uno snapshot
sanitizzato generato ogni 60 secondi da `tools/site-poll.py` via Prometheus.

- Pubblicati: conteggi utenti/computer/gruppi/OU, stato servizi, uptime, DNS/SRV, dbcheck, conteggi alert.
- **Mai pubblicati**: nomi account, gruppi, IP sorgente, configurazioni, credenziali.
- La dashboard Grafana completa resta fuori dal sito.
- Se il poller non aggiorna, il file precedente resta servito e la pagina mostra il badge
  `DATI NON AGGIORNATI` (soglia 180 s).
- File sito: `ad-monitoring.html`, `js/ad-monitoring.js`, `js/ad-i18n.js`, card in `projects.html`,
  voce in `sitemap.xml`.

## Note operative

- L'exporter ascolta **solo** su `172.19.0.1:9182` (bridge Docker), non sulla LAN.
- `samba.log` non era ruotato (41 MB): ora c'è logrotate settimanale con `copytruncate`.
- `smb.conf` non è stato modificato: `log level = 3` emetteva già gli eventi `Authentication` JSON.
- Grafana è in accesso anonimo viewer (configurato da `apply.sh`): valutare se restringerlo.
- Prometheus conserva 7 giorni / 2 GB: sufficiente per questa dashboard, da rivedere se servono trend lunghi.
