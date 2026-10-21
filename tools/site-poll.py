#!/usr/bin/env python3
"""Pubblica uno snapshot JSON sanitizzato del dominio AD per il sito portfolio.

Sorgente: Prometheus (job ad-dc) su localhost. Scrive api/ad.json in modo
atomico. Nessun segreto, nessun nome utente, nessun IP: solo conteggi e
stato dei servizi.

Cron/timer: ogni 60 secondi, come root (la docroot api/ e' root-owned).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import socket
import sys
import tempfile
import urllib.parse
import urllib.request

TIMEOUT_S = 10


def prom(base: str, expr: str):
    url = base.rstrip("/") + "/api/v1/query?" + urllib.parse.urlencode({"query": expr})
    with urllib.request.urlopen(url, timeout=TIMEOUT_S) as r:
        body = json.load(r)
    if body.get("status") != "success":
        raise RuntimeError("query failed: %s" % expr)
    return body["data"]["result"]


def scalar(base: str, expr: str):
    res = prom(base, expr)
    if not res:
        return None
    return float(res[0]["value"][1])


def series(base: str, expr: str):
    return [(m["metric"], float(m["value"][1])) for m in prom(base, expr)]


def range_series(base: str, expr: str, hours: int, step_s: int):
    end = datetime.datetime.now(datetime.timezone.utc).timestamp()
    start = end - hours * 3600
    params = urllib.parse.urlencode({
        "query": expr, "start": f"{start:.0f}", "end": f"{end:.0f}", "step": str(step_s),
    })
    url = base.rstrip("/") + "/api/v1/query_range?" + params
    with urllib.request.urlopen(url, timeout=TIMEOUT_S) as r:
        body = json.load(r)
    if body.get("status") != "success" or not body["data"]["result"]:
        return []
    return [(float(ts), float(val)) for ts, val in body["data"]["result"][0]["values"]]


def iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).astimezone().isoformat(timespec="seconds")


def grafana_alerts() -> dict | None:
    """Conteggi degli alert Grafana (sola lettura, accesso anonimo locale)."""
    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:3000/api/prometheus/grafana/api/v1/rules", timeout=3
        ) as r:
            data = json.load(r)
        rules = [rule for group in data["data"]["groups"] for rule in group["rules"]]
        out = {"total": len(rules), "firing": 0, "pending": 0, "inactive": 0}
        for rule in rules:
            state = rule.get("state", "inactive")
            if state in out:
                out[state] += 1
        return out
    except Exception as exc:  # la pagina resta valida anche senza Grafana
        print("grafana alerts skipped: %s" % exc, file=sys.stderr)
        return None


def build(base: str) -> dict:
    up = scalar(base, 'up{job="ad-dc"}')
    if not up:
        raise RuntimeError("target ad-dc non raggiungibile")

    info = prom(base, "ad_dc_info")[0]["metric"]
    services = [{"name": m.get("service", "?"), "ok": v == 1.0,
                 "uptime_s": int(scalar(base, 'ad_dc_uptime_seconds{service="%s"}' % m.get("service", "")) or 0)}
                for m, v in series(base, "ad_dc_service_active")]

    srv = [{"record": m.get("record", "?"), "ok": v == 1.0}
           for m, v in series(base, "ad_dns_srv_ok")]

    dbcheck_ts = scalar(base, "ad_dbcheck_last_run_timestamp_seconds")
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()

    history = []
    failures = dict(range_series(base, "ad_auth_failures_1h", 6, 300))
    success = dict(range_series(base, "ad_auth_success_1h", 6, 300))
    duration = dict(range_series(base, "ad_collector_duration_seconds", 6, 300))
    for ts in sorted(set(failures) | set(success) | set(duration)):
        history.append({
            "t": iso(ts),
            "failures": failures.get(ts),
            "success": success.get(ts),
            "duration_s": duration.get(ts),
        })

    return {
        "schema": 1,
        "generated_at": iso(now),
        "source": "prometheus",
        "domain": {
            "name": info.get("domain"),
            "dc": info.get("dc"),
            "version": info.get("version"),
            "domain_level": info.get("domain_level"),
            "forest_level": info.get("forest_level"),
            "platform": info.get("platform"),
        },
        "collector": {
            "ok": scalar(base, "ad_collector_success") == 1.0,
            "age_s": int(now - (scalar(base, "ad_collector_last_run_timestamp_seconds") or 0)),
            "duration_s": scalar(base, "ad_collector_duration_seconds"),
            "partial_errors": int(scalar(base, "ad_collector_partial_errors") or 0),
            "sections_ok": int(scalar(base, "count(ad_collector_section_ok == 1)") or 0),
            "sections_total": int(scalar(base, "count(ad_collector_section_ok)") or 0),
        },
        "services": services,
        "directory": {
            "users": int(scalar(base, "ad_directory_users") or 0),
            "users_enabled": int(scalar(base, "ad_directory_users_enabled") or 0),
            "users_disabled": int(scalar(base, "ad_directory_users_disabled") or 0),
            "users_locked": int(scalar(base, "ad_directory_users_locked") or 0),
            "pwd_never_expires": int(scalar(base, "ad_directory_users_password_never_expires") or 0),
            "pwd_expired": int(scalar(base, "ad_directory_users_password_expired") or 0),
            "computers": int(scalar(base, "ad_directory_computers") or 0),
            "groups": int(scalar(base, "ad_directory_groups") or 0),
            "ous": int(scalar(base, "ad_directory_ous") or 0),
            "privileged": int(scalar(base, "ad_privileged_accounts") or 0),
            "dcs": int(scalar(base, "ad_domain_controllers") or 0),
        },
        "auth": {
            "success_1h": int(scalar(base, "ad_auth_success_1h") or 0),
            "failures_1h": int(scalar(base, "ad_auth_failures_1h") or 0),
            "lockouts_1h": int(scalar(base, "ad_auth_lockouts_1h") or 0),
        },
        "dns": {
            "zones": int(scalar(base, "ad_dns_zones") or 0),
            "xfer_deferred": int(scalar(base, "ad_dns_xfer_deferred") or 0),
            "srv_ok": sum(1 for s in srv if s["ok"]),
            "srv_total": len(srv),
            "srv": srv,
        },
        "health": {
            "sysvol_ok": scalar(base, "ad_sysvol_share_ok") == 1.0,
            "dbcheck_errors": int(scalar(base, "ad_dbcheck_errors") or 0),
            "dbcheck_rc": int(scalar(base, "ad_dbcheck_rc") or 0),
            "dbcheck_age_s": int(now - dbcheck_ts) if dbcheck_ts else None,
        },
        "alerts": grafana_alerts(),
        "history": history,
        "stale_after_s": 180,
    }


def atomic_write(path: str, payload: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".ad-", suffix=".tmp")
    os.chmod(tmp, 0o644)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prom-url", default="http://127.0.0.1:9090")
    ap.add_argument("--out", default="/var/www/html/api/ad.json")
    args = ap.parse_args()
    try:
        payload = build(args.prom_url)
    except Exception as exc:
        print("snapshot non aggiornato: %s" % exc, file=sys.stderr)
        return 1
    atomic_write(args.out, payload)
    print("wrote %s: collector=%s servizi=%d utenti=%d alert=%s" % (
        args.out, payload["collector"]["ok"], len(payload["services"]),
        payload["directory"]["users"],
        (payload["alerts"] or {}).get("total", "n/d")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
