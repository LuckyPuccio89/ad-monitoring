# RUNBOOK — Monitoraggio Active Directory (Samba/Zentyal)

Aggiornato: 2026-10-21 · Host: `homelab.example.lan` (192.168.1.10)

## 1. Componenti e percorsi

| Componente | Percorso / endpoint | Note |
|---|---|---|
| Exporter AD | `/opt/ad-monitoring/ad-monitor.py` | Python 3, servizio systemd |
| Servizio exporter | `ad-monitor.service` → `172.19.0.1:9182` | solo rete Docker, non LAN |
| dbcheck settimanale | `ad-dbcheck.service` + `.timer` | stato in `/var/lib/ad-monitoring/dbcheck.json` |
| Dashboard | Grafana uid `active-directory` | folder "Active Directory" |
| Sorgente dashboard | `/opt/ad-monitoring/tools/gen_dashboard.py` → `grafana/ad.json` | non modificare il JSON a mano |
| Provider Grafana | `/opt/ad-monitoring/grafana/ad.yml` | `/etc/grafana` è effimero: usare `apply.sh` |
| Config Prometheus | `/opt/monitoring/prometheus.yml` | job `ad-dc`, `ad-blackbox` |
| Persistenza provisioning | `/opt/monitoring/grafana/apply.sh` | ricopia firewall + AD e riavvia Grafana |
| Backup | `/opt/ad-monitoring/backup/<timestamp>/` | `LATEST` indica l'ultimo |
| Runbook | `/opt/ad-monitoring/docs/RUNBOOK.md` | questo file |

## 2. Comandi operativi

```bash
# stato
systemctl status ad-monitor --no-pager
systemctl status ad-dbcheck.timer --no-pager
ss -ltnp | grep 9182

# metriche e health locali
curl -s http://172.19.0.1:9182/healthz
curl -s http://172.19.0.1:9182/metrics | grep '^ad_collector'

# log exporter
journalctl -u ad-monitor -n 100 --no-pager
journalctl -u ad-dbcheck -n 50 --no-pager

# riavvio exporter dopo modifiche
systemctl restart ad-monitor

# ricarica Prometheus senza downtime
docker exec monitoring-prometheus-1 promtool check config /etc/prometheus/prometheus.yml
docker kill -s HUP monitoring-prometheus-1

# verifica target
curl -s 'http://127.0.0.1:9090/api/v1/targets?state=active' | \
  python3 -c 'import sys,json;[print(t["labels"]["job"],t["health"]) for t in json.load(sys.stdin)["data"]["activeTargets"]]'

# dbcheck manuale
systemctl start ad-dbcheck.service && cat /var/lib/ad-monitoring/dbcheck.json

# rigenerare e ridistribuire la dashboard
python3 /opt/ad-monitoring/tools/gen_dashboard.py
docker cp /opt/ad-monitoring/grafana/ad.json monitoring-grafana-1:/var/lib/grafana/dashboards-ad/ad.json
# oppure, per ripristinare tutto il provisioning Grafana:
bash /opt/monitoring/grafana/apply.sh
```

## 3. Verifiche rapide

1. `ad_collector_success == 1` e `ad_collector_partial_errors == 0`.
2. `up{job="ad-dc"} == 1`.
3. `time() - ad_collector_last_run_timestamp_seconds < 120`.
4. `ad_dc_service_active{service=~"samba-ad-dc|named"} == 1`.
5. `ad_dns_srv_ok == 1` per tutti e tre i record.
6. `ad_sysvol_share_ok == 1`.
7. `ad_dbcheck_last_run_timestamp_seconds` non più vecchio di 8 giorni.

## 4. Interpretazione

| Metrica | Significato | Attenzione |
|---|---|---|
| `ad_collector_success` | 0 se una sezione è fallita | controllare `/healthz` e `# NOTE errors` nel payload |
| `ad_collector_partial_errors` | numero sezioni fallite | 1–2 = degrado parziale; ≥3 = intervento |
| `ad_auth_failures_1h` | eventi 4625 dal log Samba | baseline tipica 0–2/h su questo dominio |
| `ad_auth_failures_by_status_1h` | classificazione NT_STATUS | `WRONG_PASSWORD`/`NO_SUCH_USER` = tentativi |
| `ad_auth_failures_by_source_1h` | IP sorgente (top 10) | contiene IP interni: mascherabile (vedi §6) |
| `ad_directory_users_stale_logon` | utenti senza logon da 90 g | igiene directory, non guasto |
| `ad_privileged_accounts` | account persona con `adminCount=1` | valore attuale 2 |
| `ad_group_members` | membri gruppi privilegiati | modifiche inattese = alert |
| `ad_dbcheck_errors` | errori dbcheck settimanale | -1 = mai eseguito |
| `ad_replication_partners` | 0 con un solo DC | non è un guasto, è il design attuale |

## 5. Troubleshooting

**`up{job="ad-dc"} == 0`**
- `systemctl status ad-monitor`; se attivo, `curl -s http://172.19.0.1:9182/healthz`.
- Se il servizio è attivo ma irraggiungibile da Prometheus: verificare che l'IP del bridge
  (`docker inspect monitoring-prometheus-1` → Gateway) sia ancora `172.19.0.1`.

**Collector ok ma sezioni in errore**
- `curl -s http://172.19.0.1:9182/metrics | grep NOTE` riporta l'errore per sezione.
- Errori tipici: `ldbsearch rc != 0` (permessi/lock), `rndc status` (named fermo), `dig` (timeout).
- `identity`/`directory` in errore: verificare che `samba-ad-dc` sia attivo; il collector apre
  `sam.ldb` in sola lettura ma tdb richiede il lock, quindi `/var/lib/samba` **non** è montato
  read-only nel servizio.

**Pannello autenticazione vuoto**
- Normale se non ci sono eventi nell'ora. Verificare con
  `grep -c '"eventId": 4625' /var/log/samba/samba.log` e che `log level = 3` sia attivo.
- Dopo una rotazione del log il parser legge gli ultimi 16 MB: nessuna azione necessaria.

**Grafana mostra "Dashboard not found" dopo un recreate del container**
- `/etc/grafana` è effimero: eseguire `bash /opt/monitoring/grafana/apply.sh`.

**Prometheus non vede il nuovo job**
- La config è montata read-only: modificare `/opt/monitoring/prometheus.yml`, validare con
  `promtool check config`, poi `docker kill -s HUP monitoring-prometheus-1`.

## 6. Sicurezza

- L'exporter ascolta solo su `172.19.0.1:9182` (gateway del bridge Docker): non è raggiungibile
  dalla LAN. Non pubblicarlo su `0.0.0.0`.
- Gira come root perché `ldbsearch`, `samba-tool` e la lettura dei log lo richiedono. Il codice
  non scrive su AD; l'unica scrittura è lo stato dbcheck in `/var/lib/ad-monitoring`.
- `sam.ldb` resta scrivibile a livello di permessi perché tdb usa lock sul file: non aggiungere
  `ReadOnlyPaths=/var/lib/samba` al servizio (rompe la raccolta: verificato).
- `auth_audit` è già attivo con `log level = 3`; non è stato modificato `smb.conf`.
- Privacy: per mascherare gli IP sorgente aggiungere `Environment=AD_MONITOR_ANONYMIZE=1` al
  servizio e riavviarlo.
- Grafana è in accesso anonimo viewer (configurato da `apply.sh`): chi raggiunge `:3000` vede
  anche i dati AD. Da restringere se l'host non è su rete fidata.
- Le credenziali admin di Grafana **non sono note**: l'accesso API in lettura usato nei test
  funzionava come anonimo viewer, non come admin. Verificare/recuperare la password admin e
  cambiarla se è ancora quella di default.
- SMTP: password in `/etc/ad-monitoring/smtp.env` (0600 root). Non copiarla in questo repo.
  `apply-smtp.py` la scrive in `grafana.ini`; `apply.sh` la riapplica dopo un recreate.

## 7. Rollback

| Modifica | Rollback |
|---|---|
| Nuovo job Prometheus | ripristinare `/opt/ad-monitoring/backup/<ts>/prometheus/prometheus.yml` e SIGHUP |
| Dashboard/provider Grafana | rimuovere `ad.json`/`ad.yml` dal container e riavviare, oppure `apply.sh` con i file precedenti |
| Exporter | `systemctl disable --now ad-monitor` |
| dbcheck | `systemctl disable --now ad-dbcheck.timer` |
| Rotazione log | rimuovere `/etc/logrotate.d/ad-monitoring-samba` |

Nessuna modifica è stata fatta a `smb.conf`, ai servizi AD o alle porte AD.

## 8. Manutenzione

- **Log Samba**: 41 MB al 2026-10-21, ~4 MB/giorno, senza rotazione precedente. Aggiunto
  `/etc/logrotate.d/ad-monitoring-samba` (weekly, 8 copie, copytruncate).
- **Backup**: prima di ogni modifica creare `/opt/ad-monitoring/backup/<timestamp>/`.
- **Aggiornare l'exporter**: modificare `ad-monitor.py`, `python3 -m py_compile`, `systemctl restart`,
  verificare `healthz` e `promtool check metrics`.
- **Aggiornare la dashboard**: modificare il generatore, rigenerare, copiare nel container.

## 9. Alerting email (Grafana-managed)

| Elemento | Percorso |
|---|---|
| Regole (16) | `/opt/ad-monitoring/grafana/alerting/rules.yaml` (generato da `tools/gen_alert_rules.py`) |
| Policy | `notification-policies.yaml` → receiver `email-ad` |
| Contact point | `contact-points.yaml.tmpl`, renderizzato con `ALERT_EMAIL` |
| SMTP | `/etc/ad-monitoring/smtp.env` (0600) → `grafana.ini` `[smtp]` |
| Deploy | `tools/deploy-alerting.sh` (applica SMTP, copia i file, riavvia Grafana) |

```bash
# applicare modifiche a regole/policy
python3 /opt/ad-monitoring/tools/gen_alert_rules.py
/opt/ad-monitoring/tools/deploy-alerting.sh

# verificare stato regole (in lettura; l'accesso admin non è configurato)
curl -s http://127.0.0.1:3000/api/prometheus/grafana/api/v1/rules | \
  python3 -c 'import sys,json;[print(r["name"],r.get("state")) for g in json.load(sys.stdin)["data"]["groups"] for r in g["rules"]]'

# test SMTP indipendente da Grafana
printf 'Subject: test\n\nok\n' | msmtp -a gmail admin@example.com

# errori di invio
docker logs --since 10m monitoring-grafana-1 2>&1 | grep -iE 'smtp|notifier|failed to send'
```

**Test end-to-end** (già eseguito il 2026-10-21, esito positivo): si crea una regola temporanea
con `expr: vector(1)` e soglia `> 0`; dopo 1–2 minuti lo stato passa a `firing` e il notifier invia.
La regola si rimuove con un file di provisioning `deleteRules` (uid) e un riavvio; non usare
`DELETE` API se non si hanno credenziali admin.

**Attenzione**: il provisioning non elimina una regola quando la si toglie dal file. Usare
`deleteRules` oppure rimuoverla dalla UI.

## 10. Manutenzione alerting

- Le regole sono in `/etc/grafana/provisioning/alerting/` (effimero): dopo un recreate eseguire
  `deploy-alerting.sh`.
- `apply-smtp.py` va eseguito dopo ogni `apply.sh` (già integrato).
- Il contact point email è unico; per aggiungere un secondo canale creare un nuovo receiver e
  una route, non duplicare le regole.

