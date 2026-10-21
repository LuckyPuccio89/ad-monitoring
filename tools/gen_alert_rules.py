#!/usr/bin/env python3
"""Genera le regole di alert Grafana-managed per l'exporter Samba AD.

Output: /opt/ad-monitoring/grafana/alerting/rules.yaml
Le soglie sono tarate sul dominio example.lan (6 utenti persona, 2 computer).
"""

from __future__ import annotations

from pathlib import Path

import yaml

DS = "dg13jav59r8cgd"
OUT = Path("/opt/ad-monitoring/grafana/alerting/rules.yaml")
FOLDER = "Active Directory"

# (uid, title, grupo, expr, operatore, soglia, for, severity, noData, summary, description)
RULES = [
    (
        "ad-target-down", "AD: collector non raggiungibile", "ad-availability",
        'up{job="ad-dc"}', "lt", 1, "3m", "critical", "Alerting",
        "Prometheus non riesce a scrapare l'exporter AD",
        "up{job=\"ad-dc\"} è 0 da 3 minuti: verificare ad-monitor.service e la rete Docker.",
    ),
    (
        "ad-collector-failed", "AD: raccolta fallita", "ad-availability",
        "ad_collector_success", "lt", 1, "5m", "warning", "NoData",
        "L'ultimo giro di raccolta ha avuto errori",
        "Una o più sezioni del collector sono fallite: vedere ad_collector_section_ok e il NOTE nel payload.",
    ),
    (
        "ad-collector-stale", "AD: metriche non aggiornate", "ad-availability",
        "time() - ad_collector_last_run_timestamp_seconds", "gt", 180, "5m", "critical", "Alerting",
        "L'ultima raccolta risale a più di 3 minuti",
        "Il collector è fermo o bloccato: systemctl status ad-monitor e journalctl -u ad-monitor.",
    ),
    (
        "ad-collector-partial", "AD: raccolta parziale", "ad-availability",
        "ad_collector_partial_errors", "gt", 1, "10m", "warning", "NoData",
        "Più sezioni di raccolta falliscono",
        "Degrado parziale ma persistente: controllare identity, directory e dns nel pannello sezioni.",
    ),
    (
        "ad-samba-down", "AD: samba-ad-dc non attivo", "ad-services",
        'ad_dc_service_active{service="samba-ad-dc"}', "lt", 1, "2m", "critical", "Alerting",
        "Il servizio Samba AD non è attivo",
        "Il DC non eroga LDAP/KDC: impatto immediato su tutto il dominio. Verificare e riavviare con cautela.",
    ),
    (
        "ad-named-down", "AD: named (DNS) non attivo", "ad-services",
        'ad_dc_service_active{service="named"}', "lt", 1, "5m", "critical", "Alerting",
        "BIND non è attivo",
        "La risoluzione DNS del dominio e dei client è compromessa: verificare named e i log.",
    ),
    (
        "ad-accounts-locked", "AD: molti account bloccati", "ad-directory",
        "ad_directory_users_locked", "gt", 2, "10m", "warning", "OK",
        "Numero anomalo di account bloccati",
        "Possibile attacco a forza bruta o password scadute su più postazioni. Controllare top sorgenti auth.",
    ),
    (
        "ad-group-membership-change", "AD: gruppo privilegiato modificato", "ad-directory",
        "abs(delta(ad_group_members[6h]))", "gt", 0, "5m", "warning", "OK",
        "Membri di un gruppo privilegiato cambiati nelle ultime 6 ore",
        "Verificare che la modifica sia autorizzata (Domain/Enterprise/Schema Admins e affini).",
    ),
    (
        "ad-auth-failure-spike", "AD: picco di autenticazioni fallite", "ad-auth",
        "ad_auth_failures_1h", "gt", 20, "5m", "critical", "OK",
        "Oltre 20 fallimenti di autenticazione nell'ultima ora",
        "Soglia tarata su un dominio piccolo. Verificare account e IP sorgente nel pannello autenticazione.",
    ),
    (
        "ad-auth-source-burst", "AD: molti eventi da una sola sorgente", "ad-auth",
        "max(ad_auth_failures_by_source_1h)", "gt", 10, "5m", "warning", "OK",
        "Una singola sorgente supera 10 eventi di autenticazione in un'ora",
        "Possibile brute force da un host: identificare l'IP e isolarlo se non atteso.",
    ),
    (
        "ad-srv-missing", "AD: record SRV non risolvibile", "ad-dns",
        "min(ad_dns_srv_ok)", "lt", 1, "5m", "critical", "Alerting",
        "Manca almeno un record SRV LDAP/Kerberos",
        "I client non trovano il DC: verificare le zone _tcp e _msdcs sul DNS.",
    ),
    (
        "ad-zone-serial-unavailable", "AD: serial DNS non leggibile", "ad-dns",
        "min(ad_dns_zone_serial)", "lt", 0, "10m", "warning", "Alerting",
        "Il serial SOA di una zona chiave non è leggibile",
        "dig SOA non risponde per example.lan o _msdcs: verificare BIND e la zona.",
    ),
    (
        "ad-dbcheck-errors", "AD: errori dbcheck", "ad-health",
        "ad_dbcheck_errors", "gt", 0, "5m", "warning", "OK",
        "samba-tool dbcheck riporta errori",
        "Eseguire samba-tool dbcheck --cross-ncs -v e valutare un intervento pianificato.",
    ),
    (
        "ad-dbcheck-stale", "AD: dbcheck non eseguito", "ad-health",
        "time() - ad_dbcheck_last_run_timestamp_seconds", "gt", 691200, "1h", "warning", "Alerting",
        "dbcheck non viene eseguito da più di 8 giorni",
        "Verificare ad-dbcheck.timer e ad-dbcheck.service.",
    ),
    (
        "ad-sysvol-unavailable", "AD: SYSVOL non disponibile", "ad-health",
        "ad_sysvol_share_ok", "lt", 1, "5m", "critical", "Alerting",
        "SYSVOL non accessibile o SMB non risponde",
        "Group Policy e script di logon non vengono distribuiti. Verificare smbd e /var/lib/samba/sysvol.",
    ),
    (
        "ad-single-dc", "AD: un solo domain controller", "ad-structural",
        "ad_domain_controllers", "lt", 2, "24h", "info", "OK",
        "La foresta non ha ridondanza",
        "Rischio strutturale accettato: un guasto HW del DC causa un outage completo del dominio.",
    ),
]


def rule(uid: str, title: str, expr: str, op: str, threshold: float, duration: str,
         severity: str, no_data: str, summary: str, description: str) -> dict:
    return {
        "uid": uid,
        "title": title,
        "condition": "C",
        "data": [
            {
                "refId": "A",
                "relativeTimeRange": {"from": 600, "to": 0},
                "datasourceUid": DS,
                "model": {
                    "editorMode": "code",
                    "expr": expr,
                    "instant": True,
                    "range": False,
                    "intervalMs": 60000,
                    "maxDataPoints": 43200,
                    "legendFormat": "__auto",
                    "refId": "A",
                },
            },
            {
                "refId": "C",
                "datasourceUid": "__expr__",
                "model": {
                    "conditions": [{
                        "evaluator": {"params": [threshold], "type": op},
                        "operator": {"type": "and"},
                        "query": {"params": ["A"]},
                        "reducer": {"params": [], "type": "last"},
                        "type": "query",
                    }],
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "A",
                    "intervalMs": 60000,
                    "maxDataPoints": 43200,
                    "refId": "C",
                    "type": "threshold",
                },
            },
        ],
        "noDataState": no_data,
        "execErrState": "Alerting",
        "for": duration,
        "labels": {"severity": severity, "domain": "example.lan"},
        "annotations": {"summary": summary, "description": description},
        "isPaused": False,
    }


def main() -> None:
    groups: dict[str, list[dict]] = {}
    for uid, title, group, expr, op, val, dur, sev, nodata, summary, desc in RULES:
        groups.setdefault(group, []).append(rule(uid, title, expr, op, val, dur, sev, nodata, summary, desc))
    doc = {
        "apiVersion": 1,
        "groups": [
            {
                "orgId": 1,
                "name": name,
                "folder": FOLDER,
                "interval": "60s",
                "rules": rules,
            }
            for name, rules in groups.items()
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True, width=120)
    print(f"scritte {len(RULES)} regole in {OUT} ({len(groups)} gruppi)")


if __name__ == "__main__":
    main()
