#!/usr/bin/env python3
"""Genera la dashboard Grafana v2 per l'exporter Samba AD.

Uso: python3 gen_dashboard.py [output.json]
Sorgente unica: le metriche definite in /opt/ad-monitoring/ad-monitor.py.
"""

import json
import sys

DS = {"type": "prometheus", "uid": "dg13jav59r8cgd"}
OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/ad-monitoring/grafana/ad.json"
panels: list[dict] = []
_id = [0]


def nid() -> int:
    _id[0] += 1
    return _id[0]


def target(expr: str, legend: str = "", instant: bool = False, ref: str = "A") -> dict:
    return {
        "datasource": DS,
        "expr": expr,
        "legendFormat": legend,
        "refId": ref,
        "instant": instant,
        "range": not instant,
    }


def pos(x: int, y: int, w: int, h: int) -> dict:
    return {"h": h, "w": w, "x": x, "y": y}


def row(title: str, y: int) -> None:
    panels.append({
        "id": nid(), "type": "row", "title": title, "collapsed": False,
        "gridPos": pos(0, y, 24, 1), "panels": [],
    })


def stat(title: str, expr: str, x: int, y: int, w: int = 4, h: int = 4,
         unit: str = "short", mappings: list | None = None,
         thresholds: list | None = None, desc: str = "",
         legend: str = "") -> None:
    steps = thresholds or [{"color": "green", "value": None}]
    panels.append({
        "id": nid(), "type": "stat", "title": title, "description": desc,
        "datasource": DS, "gridPos": pos(x, y, w, h),
        "targets": [target(expr, legend, instant=True)],
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "orientation": "auto", "textMode": "auto", "colorMode": "value",
            "graphMode": "none", "justifyMode": "auto",
        },
        "fieldConfig": {
            "defaults": {
                "unit": unit, "mappings": mappings or [],
                "thresholds": {"mode": "absolute", "steps": steps},
                "color": {"mode": "thresholds"},
            },
            "overrides": [],
        },
    })


def timeseries(title: str, targets: list[dict], x: int, y: int, w: int = 12,
               h: int = 8, unit: str = "short", desc: str = "") -> None:
    for i, t in enumerate(targets):
        t["refId"] = chr(65 + i)
    panels.append({
        "id": nid(), "type": "timeseries", "title": title, "description": desc,
        "datasource": DS, "gridPos": pos(x, y, w, h),
        "targets": targets,
        "options": {
            "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "multi", "sort": "none"},
        },
        "fieldConfig": {
            "defaults": {
                "unit": unit, "color": {"mode": "palette-classic"},
                "custom": {
                    "drawStyle": "line", "lineWidth": 1, "fillOpacity": 8,
                    "showPoints": "never", "spanNulls": True, "axisPlacement": "auto",
                },
            },
            "overrides": [],
        },
    })


def bargauge(title: str, targets: list[dict], x: int, y: int, w: int = 12,
             h: int = 8, unit: str = "short", desc: str = "") -> None:
    for i, t in enumerate(targets):
        t["refId"] = chr(65 + i)
    panels.append({
        "id": nid(), "type": "bargauge", "title": title, "description": desc,
        "datasource": DS, "gridPos": pos(x, y, w, h),
        "targets": targets,
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "orientation": "horizontal", "displayMode": "gradient",
            "showUnfilled": True, "valueMode": "color",
        },
        "fieldConfig": {
            "defaults": {
                "unit": unit, "min": 0,
                "thresholds": {"mode": "absolute", "steps": [{"color": "blue", "value": None}]},
            },
            "overrides": [],
        },
    })


def table(title: str, targets: list[dict], x: int, y: int, w: int = 24,
          h: int = 8, desc: str = "") -> None:
    for i, t in enumerate(targets):
        t["refId"] = chr(65 + i)
    panels.append({
        "id": nid(), "type": "table", "title": title, "description": desc,
        "datasource": DS, "gridPos": pos(x, y, w, h),
        "targets": targets,
        "options": {"showHeader": True, "cellHeight": "sm"},
        "fieldConfig": {"defaults": {"custom": {"align": "auto"}}, "overrides": []},
        "transformations": [
            {"id": "organize", "options": {"excludeByName": {"Time": True}}},
        ],
    })


def text(title: str, content: str, x: int, y: int, w: int = 24, h: int = 5) -> None:
    panels.append({
        "id": nid(), "type": "text", "title": title,
        "datasource": DS, "gridPos": pos(x, y, w, h),
        "options": {"mode": "markdown", "content": content},
        "transparent": True,
    })


UP_MAP = [{"type": "value", "options": {
    "0": {"text": "DOWN", "color": "red", "index": 0},
    "1": {"text": "UP", "color": "green", "index": 1},
}}]
OK_MAP = [{"type": "value", "options": {
    "0": {"text": "ERRORE", "color": "red", "index": 0},
    "1": {"text": "OK", "color": "green", "index": 1},
}}]

DCF = 'dc=~"$dc"'

# ---------------------------------------------------------------- Panoramica
row("Panoramica", 0)
stat("Target Prometheus", 'up{job="ad-dc"}', 0, 1, 4, 4,
     mappings=UP_MAP,
     desc="Prometheus riesce a scrapare l'exporter. Se DOWN, allarme prioritario.")
stat("Collector", f"ad_collector_success{{{DCF}}}", 4, 1, 4, 4,
     mappings=OK_MAP, desc="Esito reale dell'ultimo giro di raccolta.")
stat("Errori parziali", f"ad_collector_partial_errors{{{DCF}}}", 8, 1, 4, 4,
     thresholds=[{"color": "green", "value": None},
                 {"color": "orange", "value": 1},
                 {"color": "red", "value": 3}],
     desc="Numero di sezioni di raccolta fallite nell'ultimo giro.")
stat("Età ultima raccolta", f"time() - ad_collector_last_run_timestamp_seconds{{{DCF}}}",
     12, 1, 4, 4, unit="s",
     thresholds=[{"color": "green", "value": None},
                 {"color": "orange", "value": 120},
                 {"color": "red", "value": 300}],
     desc="Secondi dall'ultima raccolta completata.")
stat("Uptime Samba", f'ad_dc_uptime_seconds{{{DCF},service="samba-ad-dc"}}', 16, 1, 4, 4,
     unit="s", desc="Secondi dall'attivazione di samba-ad-dc.service.")
stat("DC nella foresta", f"ad_domain_controllers", 20, 1, 4, 4,
     thresholds=[{"color": "red", "value": None},
                 {"color": "green", "value": 2}],
     desc="Numero di DC. Valore 1 = nessuna ridondanza (rischio accettato).")

stat("Utenti abilitati", f"ad_directory_users_enabled{{{DCF}}}", 0, 5, 4, 4,
     desc="Account persona abilitati.")
stat("Utenti disabilitati", f"ad_directory_users_disabled{{{DCF}}}", 4, 5, 4, 4)
stat("Account bloccati", f"ad_directory_users_locked{{{DCF}}}", 8, 5, 4, 4,
     thresholds=[{"color": "green", "value": None},
                 {"color": "orange", "value": 1},
                 {"color": "red", "value": 11}])
stat("Account privilegiati", f"ad_privileged_accounts{{{DCF}}}", 12, 5, 4, 4,
     desc="Account persona con adminCount=1.")
stat("Computer", f"ad_directory_computers{{{DCF}}}", 16, 5, 4, 4)
stat("Gruppi", f"ad_directory_groups{{{DCF}}}", 20, 5, 4, 4)

# ---------------------------------------------------------------- Directory
row("Directory", 10)
timeseries("Oggetti di directory", [
    target(f"ad_directory_users{{{DCF}}}", "utenti"),
    target(f"ad_directory_users_enabled{{{DCF}}}", "utenti abilitati"),
    target(f"ad_directory_computers{{{DCF}}}", "computer"),
    target(f"ad_directory_groups{{{DCF}}}", "gruppi"),
    target(f"ad_directory_ous{{{DCF}}}", "OU"),
], 0, 11, 12, 8, desc="Conteggi LDAP sul dominio (esclusi i computer dal conteggio utenti).")

bargauge("Igiene password / account inattivi", [
    target(
        f'{{__name__=~"ad_directory_users_password_never_expires|ad_directory_users_password_expired|'
        f'ad_directory_users_stale_logon|ad_directory_computers_stale",{DCF}}}',
        "{{__name__}}", instant=True),
], 12, 11, 12, 8,
    desc="Account con password che non scade, scaduta, o senza logon da 90 giorni.")

bargauge("Membri gruppi privilegiati", [
    target(f"ad_group_members{{{DCF}}}", "{{group}}", instant=True),
], 0, 19, 12, 8, desc="Membri dei gruppi Domain/Enterprise/Schema Admins e affini.")

table("Stato sezioni collector", [
    target(f"ad_collector_section_ok{{{DCF}}}", "{{section}}", instant=True),
], 12, 19, 12, 8,
    desc="1 = sezione raccolta senza errori; 0 = errore (vedi /healthz e journal).")

# ------------------------------------------------------------ Autenticazione
row("Autenticazione e sicurezza", 27)
timeseries("Autenticazioni nell'ultima ora", [
    target(f"ad_auth_success_1h{{{DCF}}}", "successi (4624)"),
    target(f"ad_auth_failures_1h{{{DCF}}}", "fallimenti (4625)"),
    target(f"ad_auth_lockouts_1h{{{DCF}}}", "lockout (4740)"),
], 0, 28, 12, 8, desc="Eventi dal log Samba (JSON auth_audit già attivo a log level 3).")

timeseries("Fallimenti per NT_STATUS", [
    target(f"ad_auth_failures_by_status_1h{{{DCF}}}", "{{status}}"),
], 12, 28, 12, 8, desc="Classificazione dei fallimenti di autenticazione.")

bargauge("Top sorgenti di autenticazione (1h)", [
    target(f"ad_auth_failures_by_source_1h{{{DCF}}}", "{{source}}", instant=True),
], 0, 36, 12, 8, desc="IP sorgente con più eventi di autenticazione nell'ultima ora.")

text("Nota sulla privacy", """
I campi `status` e `source` provengono dal log di autenticazione Samba e possono contenere
IP interni e nomi di dominio. Per mascherare gli IP: `AD_MONITOR_ANONYMIZE=1` in
`/etc/systemd/system/ad-monitor.service`, poi `systemctl daemon-reload && systemctl restart ad-monitor`.
""", 12, 36, 12, 8)

# -------------------------------------------------------------------- DNS
row("DNS e Kerberos", 44)
timeseries("Serial SOA zone chiave", [
    target(f'ad_dns_zone_serial{{{DCF}}}', "{{zone}}"),
], 0, 45, 12, 8, desc="Serial delle zone example.lan e _msdcs (dig SOA).")

bargauge("Record SRV risolvibili", [
    target(f"ad_dns_srv_ok{{{DCF}}}", "{{record}}", instant=True),
], 12, 45, 12, 8,
    desc="Verifica SRV per LDAP e Kerberos: un valore 0 rompe il discovery del dominio.")

stat("Zone DNS", f"ad_dns_zones{{{DCF}}}", 0, 53, 4, 4)
stat("Trasferimenti differiti", f"ad_dns_xfer_deferred{{{DCF}}}", 4, 53, 4, 4,
     thresholds=[{"color": "green", "value": None},
                 {"color": "orange", "value": 1}])
stat("Trasferimenti in corso", f"ad_dns_xfer_running{{{DCF}}}", 8, 53, 4, 4)
stat("Partner di replica", f"ad_replication_partners{{{DCF}}}", 12, 53, 4, 4,
     desc="0 con un solo DC: la replica non è applicabile finché non si aggiunge un secondo DC.")
stat("SYSVOL disponibile", f"ad_sysvol_share_ok{{{DCF}}}", 16, 53, 4, 4, mappings=OK_MAP)
stat("Errori dbcheck", f"ad_dbcheck_errors{{{DCF}}}", 20, 53, 4, 4,
     thresholds=[{"color": "green", "value": None},
                 {"color": "orange", "value": 1},
                 {"color": "red", "value": 5}],
     desc="Errori dall'ultimo samba-tool dbcheck (settimanale). -1 = mai eseguito.")

# ------------------------------------------------------- Servizi e collector
row("Servizi e collector", 57)
timeseries("Servizi attivi", [
    target(f"ad_dc_service_active{{{DCF}}}", "{{service}}"),
], 0, 58, 8, 8, desc="1 = unità systemd attiva (samba-ad-dc, named).")
timeseries("Restart dei servizi", [
    target(f"ad_dc_service_restarts_total{{{DCF}}}", "{{service}}"),
], 8, 58, 8, 8, desc="Contatore NRestarts delle unità systemd.")
timeseries("Durata raccolta", [
    target(f"ad_collector_duration_seconds{{{DCF}}}", "durata"),
], 16, 58, 8, 8, unit="s",
    desc="Tempo impiegato dall'ultimo giro (scrape_timeout 20s).")

# ------------------------------------------------------------------- Note
row("Contesto e rischi", 66)
text("Rischi strutturali", """
**Single DC**: `HOMELAB.example.lan` è l'unico DC, GC, KDC e DNS del dominio.
Un guasto hardware o un riavvio non pianificato causa un outage completo del dominio.
Non è un alert di guasto: è un rischio accettato, visibile qui.

**Forest/domain level 2008 R2**: limita funzionalità e postura di sicurezza; l'upgrade è un
progetto separato e va pianificato, non eseguito in questo contesto.

**Metriche Windows non applicabili**: `dcdiag`, `repadmin`, eventi 4625 via `Get-WinEvent`,
`NTDS\\ntds.dit` non esistono su Samba. I sostituti sono `dbcheck`, il log `auth_audit`,
`rndc`/`dig` e le dimensioni su filesystem (node-exporter).
""", 0, 67, 24, 8)

dashboard = {
    "id": None,
    "uid": "active-directory",
    "title": "Active Directory — example.lan",
    "description": "Samba AD DC (Zentyal) su homelab — metriche native ad_*",
    "tags": ["active-directory", "samba", "zentyal"],
    "timezone": "browser",
    "schemaVersion": 39,
    "version": 2,
    "refresh": "1m",
    "time": {"from": "now-6h", "to": "now"},
    "editable": True,
    "graphTooltip": 1,
    "panels": panels,
    "templating": {
        "list": [{
            "name": "dc",
            "label": "Domain controller",
            "type": "query",
            "datasource": DS,
            "query": {
                "query": "label_values(ad_dc_info, dc)",
                "refId": "StandardVariableQuery",
            },
            "refresh": 2,
            "includeAll": True,
            "multi": True,
            "allValue": ".*",
            "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
            "options": [],
            "sort": 1,
        }],
    },
    "annotations": {"list": [{
        "builtIn": 1,
        "datasource": {"type": "grafana", "uid": "-- Grafana --"},
        "enable": True, "hide": True,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts", "type": "dashboard",
    }]},
}

import os
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(dashboard, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
print(f"written {OUT} ({len(panels)} panels)")
