#!/usr/bin/env python3
"""
ad-monitor.py — exporter Prometheus per Samba AD DC (Zentyal).

Sorgenti dati, tutte locali e in sola lettura:
  - ldbsearch su sam.ldb (conteggi directory, gruppi, siti)
  - systemctl show (stato/restart/uptime dei servizi)
  - samba-tool domain level show (livelli funzionali)
  - rndc status + dig (zone, SOA, SRV)
  - log Samba JSON "type: Authentication" (eventi 4624/4625/4740)
  - socket TCP 127.0.0.1:445 + path SYSVOL

Espone /metrics (text exposition) e /healthz su 172.19.0.1:9182.
Nessuna credenziale, nessuna scrittura su AD, nessuna porta AD aggiuntiva.

Contratto metriche: namespace ad_*, label dc/domain/site; instance la aggiunge Prometheus.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

BUILD_VERSION = "1.0.0"
SAM_LDB = "/var/lib/samba/private/sam.ldb"
SAMBA_CONF = "/etc/samba/smb.conf"
SAMBA_LOG = "/var/log/samba/samba.log"
SYSVOL_ROOT = "/var/lib/samba/sysvol"
AUTH_LOG_TAIL_BYTES = 16 * 1024 * 1024
AUTH_WINDOW_SECONDS = 3600
STALE_DAYS = 90
TOP_SOURCES = 10

SERVICES = ("samba-ad-dc", "named")
DNS_KEY_ZONES = ("example.lan", "_msdcs.example.lan")
DNS_SRV_RECORDS = (
    "_ldap._tcp.example.lan",
    "_kerberos._tcp.example.lan",
    "_ldap._tcp.dc._msdcs.example.lan",
)
PRIVILEGED_GROUPS = (
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Group Policy Creator Owners",
)

UAC_DISABLED = "userAccountControl:1.2.840.113556.1.4.803:=2"
UAC_NO_EXPIRE = "userAccountControl:1.2.840.113556.1.4.803:=65536"

LEVELS = {
    0: "2000",
    1: "2003-interim",
    2: "2003",
    3: "2008",
    4: "2008-R2",
    5: "2012",
    6: "2012-R2",
    7: "2016",
}

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def run(cmd: list[str], timeout: float = 10.0) -> tuple[int, str]:
    """Esegue un comando locale con timeout. Ritorna (rc, stdout+stderr)."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return 127, f"not found: {cmd[0]}"


def unix_now() -> float:
    return time.time()


def fmt_value(v) -> str:
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v.is_integer():
            return str(int(v))
        return f"{v:.9f}".rstrip("0").rstrip(".")
    return str(v)


def escape_label(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class MetricSet:
    """Accumula serie garantendo un solo blocco HELP/TYPE per metrica."""

    def __init__(self) -> None:
        self.help: dict[str, str] = {}
        self.type: dict[str, str] = {}
        self.series: dict[str, list[tuple[dict[str, str], object]]] = {}
        self.order: list[str] = []

    def add(self, name: str, value, labels: dict[str, str] | None = None,
            mtype: str = "gauge", help_text: str = "") -> None:
        if name not in self.series:
            self.order.append(name)
            self.series[name] = []
            self.type[name] = mtype
            self.help[name] = help_text or name
        self.series[name].append((labels or {}, value))

    def render(self) -> str:
        out: list[str] = []
        for name in self.order:
            if self.help.get(name):
                out.append(f"# HELP {name} {self.help[name]}")
            out.append(f"# TYPE {name} {self.type[name]}")
            for labels, value in self.series[name]:
                if labels:
                    lbl = ",".join(f'{k}="{escape_label(str(v))}"' for k, v in labels.items())
                    out.append(f"{name}{{{lbl}}} {fmt_value(value)}")
                else:
                    out.append(f"{name} {fmt_value(value)}")
        return "\n".join(out) + "\n"


def ldb_count(base: str, ldap_filter: str, timeout: float = 15.0) -> int:
    rc, out = run(["ldbsearch", "-H", SAM_LDB, "-b", base, ldap_filter, "dn"], timeout)
    if rc != 0:
        raise RuntimeError(f"ldbsearch rc={rc}: {out.strip()[:200]}")
    return sum(1 for line in out.splitlines() if line.startswith("dn:"))


def ldb_attrs(base: str, ldap_filter: str, attrs: list[str],
              scope: str = "sub", timeout: float = 15.0) -> list[dict[str, list[str]]]:
    cmd = ["ldbsearch", "-H", SAM_LDB, "-b", base, "-s", scope, ldap_filter, *attrs]
    rc, out = run(cmd, timeout)
    if rc != 0:
        raise RuntimeError(f"ldbsearch rc={rc}: {out.strip()[:200]}")
    records: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] | None = None
    for line in out.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if line.startswith("dn:"):
            if current is not None and "dn" in current:
                records.append(current)
            current = {"dn": [line[3:].strip()]}
            continue
        if current is None:
            continue
        if ": " in line and not line.startswith(" "):
            key, val = line.split(": ", 1)
            current.setdefault(key, []).append(val)
    if current is not None and "dn" in current:
        records.append(current)
    return records


def filetime_threshold(days: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return int((cutoff - FILETIME_EPOCH).total_seconds() * 10_000_000)


def domain_dns_from_dn(dn: str) -> str:
    parts = [p.split("=", 1)[1] for p in dn.split(",") if p.upper().startswith("DC=")]
    return ".".join(parts).lower()


def tail_lines(path: str, max_bytes: int) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    size = p.stat().st_size
    with p.open("rb") as fh:
        if size > max_bytes:
            fh.seek(size - max_bytes)
            fh.readline()  # scarta la riga parziale
        data = fh.read()
    return data.decode("utf-8", errors="replace").splitlines()


class Collector:
    def __init__(self, anonymize_sources: bool = False) -> None:
        self.anonymize_sources = anonymize_sources

    # ------------------------------------------------------------------ utils
    def _base(self) -> tuple[str, str, str]:
        root = ldb_attrs("", "(objectClass=*)", ["defaultNamingContext"], scope="base", timeout=10)
        nc = root[0]["defaultNamingContext"][0] if root else "DC=home-pucci,DC=lan"
        return nc, domain_dns_from_dn(nc), f"CN=Configuration,{nc}"

    def _site(self, config_nc: str) -> str:
        try:
            recs = ldb_attrs(config_nc, "(objectClass=site)", ["cn"], timeout=10)
            if recs:
                return recs[0]["cn"][0]
        except Exception:
            pass
        return "unknown"

    # ------------------------------------------------------------- collectors
    def collect(self) -> str:
        started = time.monotonic()
        m = MetricSet()
        errors: list[str] = []
        section_ok: dict[str, int] = {}

        def section(name: str, fn: Callable[[], None]) -> None:
            try:
                fn()
                section_ok[name] = 1
            except Exception as exc:  # una sezione non deve azzerare le altre
                errors.append(f"{name}: {exc}")
                section_ok[name] = 0

        ctx: dict[str, str] = {}

        def identity() -> None:
            nc, domain, config_nc = self._base()
            ctx["nc"] = nc
            ctx["domain"] = domain
            ctx["config_nc"] = config_nc
            ctx["site"] = self._site(config_nc)
            ctx["dc"] = socket.getfqdn()

        section("identity", identity)

        dc = ctx.get("dc", socket.getfqdn())
        domain = ctx.get("domain", "unknown")
        site = ctx.get("site", "unknown")
        nc = ctx.get("nc", "DC=home-pucci,DC=lan")
        config_nc = ctx.get("config_nc", f"CN=Configuration,{nc}")
        labels = {"dc": dc, "domain": domain, "site": site}

        def version_and_levels() -> None:
            _, smb = run(["samba", "--version"], timeout=10)
            version = smb.strip().splitlines()[0].replace("Version ", "") if smb.strip() else "unknown"
            _, lvl = run(["samba-tool", "domain", "level", "show"], timeout=20)
            forest = domain_level = "unknown"
            fm = re.search(r"Forest function level:\s*\(Windows\)\s*([0-9A-Za-z .\-]+)", lvl)
            dm = re.search(r"Domain function level:\s*\(Windows\)\s*([0-9A-Za-z .\-]+)", lvl)
            if fm:
                forest = fm.group(1).strip().replace(" ", "-")
            if dm:
                domain_level = dm.group(1).strip().replace(" ", "-")
            m.add("ad_dc_info", 1,
                  {**labels, "version": version, "domain_level": domain_level,
                   "forest_level": forest, "platform": "samba"},
                  help_text="Info sul domain controller Samba (valore costante 1).")

        section("info", version_and_levels)

        def directory() -> None:
            t0 = time.monotonic()
            person_body = "(objectClass=user)(objectCategory=person)"
            person = f"(&{person_body})"
            users = ldb_count(nc, person)
            disabled = ldb_count(nc, f"(&{person_body}({UAC_DISABLED}))")
            locked = ldb_count(nc, f"(&{person_body}(lockoutTime>=1))")
            never = ldb_count(nc, f"(&{person_body}({UAC_NO_EXPIRE}))")
            expired = ldb_count(nc, f"(&{person_body}(pwdLastSet=0)(!({UAC_DISABLED})))")
            stale = ldb_count(
                nc,
                f"(&{person_body}(!({UAC_DISABLED}))(lastLogonTimestamp<={filetime_threshold(STALE_DAYS)}))",
            )
            computers = ldb_count(nc, "(objectClass=computer)")
            comp_disabled = ldb_count(nc, f"(&(objectClass=computer)({UAC_DISABLED}))")
            comp_stale = ldb_count(
                nc,
                f"(&(objectClass=computer)(!({UAC_DISABLED}))(lastLogonTimestamp<={filetime_threshold(STALE_DAYS)}))",
            )
            groups = ldb_count(nc, "(objectClass=group)")
            ous = ldb_count(nc, "(objectClass=organizationalUnit)")
            privileged = ldb_count(nc, f"(&{person_body}(adminCount=1))")
            dcs = ldb_count(nc, "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))")

            m.add("ad_directory_users", users, labels, help_text="Oggetti utente nel dominio.")
            m.add("ad_directory_users_enabled", users - disabled, labels,
                  help_text="Utenti abilitati (UAC senza ACCOUNTDISABLE).")
            m.add("ad_directory_users_disabled", disabled, labels,
                  help_text="Utenti disabilitati (ACCOUNTDISABLE).")
            m.add("ad_directory_users_locked", locked, labels,
                  help_text="Utenti con lockoutTime attivo.")
            m.add("ad_directory_users_password_never_expires", never, labels,
                  help_text="Utenti con DONT_EXPIRE_PASSWORD.")
            m.add("ad_directory_users_password_expired", expired, labels,
                  help_text="Utenti abilitati con pwdLastSet=0.")
            m.add("ad_directory_users_stale_logon", stale, labels,
                  help_text=f"Utenti abilitati senza logon da {STALE_DAYS} giorni.")
            m.add("ad_directory_computers", computers, labels,
                  help_text="Oggetti computer nel dominio.")
            m.add("ad_directory_computers_enabled", computers - comp_disabled, labels,
                  help_text="Computer abilitati.")
            m.add("ad_directory_computers_stale", comp_stale, labels,
                  help_text=f"Computer abilitati senza logon da {STALE_DAYS} giorni.")
            m.add("ad_directory_groups", groups, labels, help_text="Gruppi nel dominio.")
            m.add("ad_directory_ous", ous, labels,
                  help_text="Unita' organizzative nel dominio.")
            m.add("ad_privileged_accounts", privileged, labels,
                  help_text="Account con adminCount=1.")
            m.add("ad_domain_controllers", max(dcs, 1), {"domain": domain},
                  help_text="Domain controller rilevati (oggetti DC nel dominio).")
            m.add("ad_directory_read_duration_seconds", round(time.monotonic() - t0, 3), labels,
                  help_text="Durata delle query alla directory locale.")

        section("directory", directory)

        def groups() -> None:
            for group in PRIVILEGED_GROUPS:
                recs = ldb_attrs(nc, f"(&(objectClass=group)(sAMAccountName={group}))",
                                 ["sAMAccountName", "member"], timeout=10)
                if not recs:
                    continue
                members = recs[0].get("member", [])
                m.add("ad_group_members", len(members), {**labels, "group": group},
                      help_text="Numero di membri dei gruppi privilegiati.")

        section("groups", groups)

        def services() -> None:
            for svc in SERVICES:
                _, state = run(["systemctl", "show", "-p", "ActiveState", "--value", svc], timeout=8)
                active = 1 if state.strip() == "active" else 0
                m.add("ad_dc_service_active", active, {**labels, "service": svc},
                      help_text="1 se l'unita' systemd e' attiva.")
                _, restarts = run(["systemctl", "show", "-p", "NRestarts", "--value", svc], timeout=8)
                try:
                    nr = int(restarts.strip())
                except ValueError:
                    nr = 0
                m.add("ad_dc_service_restarts_total", nr, {**labels, "service": svc},
                      mtype="counter", help_text="Numero di restart dell'unita' systemd.")
                _, ts = run(["systemctl", "show", "-p", "ActiveEnterTimestamp",
                             "--timestamp=unix", "--value", svc], timeout=8)
                mm = re.match(r"@(\d+)", ts.strip())
                if mm:
                    m.add("ad_dc_uptime_seconds", max(0, int(unix_now()) - int(mm.group(1))),
                          {**labels, "service": svc},
                          help_text="Secondi dall'attivazione dell'unita'.")

        section("services", services)

        def replication() -> None:
            recs = ldb_attrs(nc, "(objectClass=*)", ["repsFrom", "repsTo"], scope="base", timeout=10)
            partners = 0
            if recs:
                partners = len(recs[0].get("repsFrom", [])) + len(recs[0].get("repsTo", []))
            m.add("ad_replication_partners", partners, labels,
                  help_text="Partner di replica configurati sul naming context.")

        section("replication", replication)

        def dns() -> None:
            rc, status = run(["rndc", "status"], timeout=10)
            if rc != 0:
                raise RuntimeError(status.strip()[:150])
            zones = re.search(r"number of zones:\s*(\d+)", status)
            deferred = re.search(r"xfers deferred:\s*(\d+)", status)
            running = re.search(r"xfers running:\s*(\d+)", status)
            m.add("ad_dns_zones", int(zones.group(1)) if zones else -1, labels,
                  help_text="Numero di zone servite da BIND.")
            m.add("ad_dns_xfer_deferred", int(deferred.group(1)) if deferred else -1, labels,
                  help_text="Trasferimenti di zona differiti (rndc status).")
            m.add("ad_dns_xfer_running", int(running.group(1)) if running else -1, labels,
                  help_text="Trasferimenti di zona in corso (rndc status).")
            for zone in DNS_KEY_ZONES:
                rc, soa = run(["dig", "+short", "+time=2", "+tries=1", "SOA", zone, "@127.0.0.1"], 6)
                serial = -1
                if rc == 0:
                    fields = soa.split()
                    if len(fields) >= 3 and fields[2].isdigit():
                        serial = int(fields[2])
                m.add("ad_dns_zone_serial", serial, {**labels, "zone": zone},
                      help_text="Serial SOA della zona (dig).")
            for record in DNS_SRV_RECORDS:
                rc, srv = run(["dig", "+short", "+time=2", "+tries=1", "SRV", record, "@127.0.0.1"], 6)
                ok = 1 if rc == 0 and any(line.strip() and line.strip() != "." for line in srv.splitlines()) else 0
                m.add("ad_dns_srv_ok", ok, {**labels, "record": record},
                      help_text="1 se il record SRV risolve.")

        section("dns", dns)

        def sysvol() -> None:
            domain_path = Path(SYSVOL_ROOT) / domain
            path_ok = domain_path.is_dir()
            port_ok = False
            try:
                with socket.create_connection(("127.0.0.1", 445), timeout=3):
                    port_ok = True
            except OSError:
                port_ok = False
            m.add("ad_sysvol_share_ok", 1 if (path_ok and port_ok) else 0, labels,
                  help_text="1 se la directory SYSVOL esiste e SMB risponde su 445.")

        section("sysvol", sysvol)

        def dbcheck() -> None:
            state_path = Path("/var/lib/ad-monitoring/dbcheck.json")
            if not state_path.exists():
                m.add("ad_dbcheck_errors", -1, labels,
                      help_text="Errori riportati dall'ultimo dbcheck (-1 = mai eseguito).")
                m.add("ad_dbcheck_last_run_timestamp_seconds", 0, labels,
                      help_text="Timestamp Unix dell'ultimo dbcheck eseguito.")
                return
            state = json.loads(state_path.read_text(encoding="utf-8"))
            m.add("ad_dbcheck_errors", int(state.get("errors", -1)), labels,
                  help_text="Errori riportati dall'ultimo dbcheck (-1 = mai eseguito).")
            m.add("ad_dbcheck_rc", int(state.get("rc", -1)), labels,
                  help_text="Exit code dell'ultimo dbcheck.")
            m.add("ad_dbcheck_last_run_timestamp_seconds",
                  float(state.get("timestamp", 0)), labels,
                  help_text="Timestamp Unix dell'ultimo dbcheck eseguito.")

        section("dbcheck", dbcheck)

        def auth_events() -> None:
            now = datetime.now(timezone.utc)
            cutoff = now.timestamp() - AUTH_WINDOW_SECONDS
            counts: dict[int, int] = {}
            statuses: dict[str, int] = {}
            sources: dict[str, int] = {}
            for line in tail_lines(SAMBA_LOG, AUTH_LOG_TAIL_BYTES):
                idx = line.find('{"timestamp"')
                if idx < 0:
                    continue
                try:
                    ev = json.loads(line[idx:])
                except json.JSONDecodeError:
                    continue
                if ev.get("type") != "Authentication":
                    continue
                ts_raw = ev.get("timestamp")
                if not ts_raw:
                    continue
                try:
                    ts = datetime.fromisoformat(ts_raw).timestamp()
                except ValueError:
                    continue
                if ts < cutoff:
                    continue
                auth = ev.get("Authentication", {})
                event_id = auth.get("eventId")
                status = auth.get("status") or "UNKNOWN"
                counts[event_id] = counts.get(event_id, 0) + 1
                statuses[status] = statuses.get(status, 0) + 1
                remote = auth.get("remoteAddress") or ""
                ip = remote.split(":", 1)[1].rsplit(":", 1)[0] if remote.startswith("ipv4:") else remote
                if ip:
                    key = ip if not self.anonymize_sources else "anonymized"
                    sources[key] = sources.get(key, 0) + 1

            m.add("ad_auth_success_1h", counts.get(4624, 0), labels,
                  help_text="Autenticazioni riuscite nell'ultima ora (evento 4624).")
            m.add("ad_auth_failures_1h", counts.get(4625, 0), labels,
                  help_text="Autenticazioni fallite nell'ultima ora (evento 4625).")
            m.add("ad_auth_lockouts_1h", counts.get(4740, 0), labels,
                  help_text="Account lockout nell'ultima ora (evento 4740).")
            for status, n in sorted(statuses.items()):
                m.add("ad_auth_failures_by_status_1h", n, {**labels, "status": status},
                      help_text="Autenticazioni fallite per NT_STATUS nell'ultima ora.")
            for ip, n in sorted(sources.items(), key=lambda kv: kv[1], reverse=True)[:TOP_SOURCES]:
                m.add("ad_auth_failures_by_source_1h", n, {**labels, "source": ip},
                      help_text="Eventi di autenticazione per sorgente (top N), ultima ora.")

        section("auth", auth_events)

        for name, ok in sorted(section_ok.items()):
            m.add("ad_collector_section_ok", ok, {**labels, "section": name},
                  help_text="1 se la sezione di raccolta ha completato senza errori.")

        duration = time.monotonic() - started
        m.add("ad_collector_success", 1 if not errors else 0, labels,
              help_text="1 se il giro di raccolta non ha avuto errori.")
        m.add("ad_collector_partial_errors", len(errors), labels,
              help_text="Numero di sezioni fallite nell'ultimo giro.")
        m.add("ad_collector_duration_seconds", round(duration, 3), labels,
              help_text="Durata dell'ultimo giro di raccolta.")
        m.add("ad_collector_last_run_timestamp_seconds", unix_now(), labels,
              help_text="Timestamp Unix dell'ultima raccolta completata.")
        m.add("ad_collector_build_info", 1,
              {"version": BUILD_VERSION, "python": "3", "platform": "samba"}, 
              help_text="Versione dell'exporter (valore costante 1).")

        text = m.render()
        if errors:
            text = text.replace(
                f"# HELP ad_collector_success {m.help['ad_collector_success']}",
                f"# HELP ad_collector_success {m.help['ad_collector_success']}\n"
                f"# NOTE errors: {' | '.join(errors)[:1000]}",
            )
        return text


class Cache:
    def __init__(self, collector: Collector, ttl: int) -> None:
        self.collector = collector
        self.ttl = ttl
        self.lock = threading.Lock()
        self.text = "# ad-monitor: not collected yet\n"
        self.collected_at = 0.0
        self.duration = 0.0

    def get(self) -> str:
        with self.lock:
            if time.time() - self.collected_at > self.ttl:
                t0 = time.monotonic()
                self.text = self.collector.collect()
                self.duration = time.monotonic() - t0
                self.collected_at = time.time()
            return self.text

    def health(self) -> dict:
        return {
            "ok": self.collected_at > 0 and (time.time() - self.collected_at) < 300,
            "last_run": self.collected_at,
            "age_seconds": round(time.time() - self.collected_at, 1) if self.collected_at else None,
            "collect_duration_seconds": round(self.duration, 3),
            "ttl_seconds": self.ttl,
            "version": BUILD_VERSION,
        }


class Handler(BaseHTTPRequestHandler):
    cache: Cache | None = None
    server_version = "ad-monitor/" + BUILD_VERSION

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?")[0] in ("/metrics", "/"):
            body = self.cache.get().encode("utf-8") if self.cache else b"# no cache\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.split("?")[0] == "/healthz":
            body = json.dumps(self.cache.health() if self.cache else {}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, fmt: str, *args) -> None:
        # log solo gli errori, per non riempire journald ad ogni scrape
        if args and str(args[1]).startswith(("4", "5")):
            print(f"{self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Samba AD metrics exporter")
    ap.add_argument("--bind", default=os.environ.get("AD_MONITOR_BIND", "172.19.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("AD_MONITOR_PORT", "9182")))
    ap.add_argument("--ttl", type=int, default=int(os.environ.get("AD_MONITOR_TTL", "30")))
    ap.add_argument("--anonymize-sources", action="store_true",
                    default=os.environ.get("AD_MONITOR_ANONYMIZE", "0") == "1")
    args = ap.parse_args()

    cache = Cache(Collector(anonymize_sources=args.anonymize_sources), args.ttl)
    Handler.cache = cache
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.daemon_threads = True
    print(f"ad-monitor {BUILD_VERSION} listening on {args.bind}:{args.port} "
          f"(ttl={args.ttl}s)", flush=True)
    # primo giro in background: il server risponde subito, Prometheus riprova
    threading.Thread(target=cache.get, daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
