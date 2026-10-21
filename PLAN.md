# Piano di costruzione — Dashboard Active Directory `example.lan`

Data: 2026-10-21 · Host di monitoraggio: `homelab` (192.168.1.10, Ubuntu 24.04.5)

---

## 0. Verdetto in una pagina

Il kit in questa cartella è scritto per **un Domain Controller Windows** (WinRM, `Get-AD*`,
`repadmin`, `dcdiag`, `Get-WinEvent`, task SYSTEM, `NTDS\ntds.dit`).
Il DC reale è **Samba 4.19 AD DC su Zentyal 8.1, Linux**, sullo stesso host del monitoring.
Conseguenza: **circa il 90% degli artefatti non è eseguibile su questa infrastruttura**.
Non è un problema di rifinitura, è un cambio di sorgente dati.

Il piano quindi:

1. **butta l'approccio agentless Windows** (WinRM/ADWS) e sostituisce il collector con un
   exporter **nativo Samba/Linux** (Python + `ldb` + `samba-tool` + `rndc` + journald);
2. **conserva** ciò che è già corretto e utile: convenzione `ad_*`, impianto dell'esposizione
   Prometheus text format, job blackbox `tcp_connect`, idea della dashboard Grafana;
3. **corregge** i difetti bloccanti già presenti (metriche con HELP/TYPE duplicati, metriche
   semanticamente invertite, label incoerenti, alert che non possono funzionare, blackbox senza
   modulo DNS, regole non montate);
4. consegna in **5 fasi** con criteri di accettazione e rollback, senza toccare l'AD se non per
   una singola direttiva di logging (reversibile).

Stima realistica: **3–4 giornate** di lavoro, di cui ~0,5 di finestra di manutenzione per
abilitare `auth_audit` su Samba.

**Decisioni chiuse (2026-10-21):**
- target = **Samba/Zentyal attuale** (nessun DC Windows in arrivo) → niente biforcazione del piano;
- notifiche = **alert Grafana-managed** con canale **email** (SMTP Gmail già presente sull'host,
  credenziali in `/etc/ad-monitoring/smtp.env` 0600, mai nel repo) → nessun container Alertmanager,
  nessun mount di `rule_files` in Prometheus.

### Stato di avanzamento (2026-10-21)

| Fase | Stato | Evidenza |
|---|---|---|
| 0 — preparazione | **fatto** | backup in `/opt/ad-monitoring/backup/20261021-154539/`, struttura creata |
| 1 — exporter MVP | **fatto** | `ad-monitor.service` attivo su `172.19.0.1:9182`, `up{job="ad-dc"}=1`, metriche validate con `promtool` |
| 2 — auth/salute | **parziale** | auth da log Samba e `dbcheck` settimanale attivi; restano probe `kinit` e account LDAP dedicato |
| 3 — dashboard | **fatto** | uid `active-directory`, 38 pannelli, provisioning persistente via `apply.sh` |
| 4 — alerting | **fatto** | 16 regole Grafana-managed, contact point email, test end-to-end passato (`firing` → notifier → email), regola di test rimossa |
| 5 — consolidamento | **parziale** | README/RUNBOOK riscritti, logrotate aggiunto; Grafana anonimo e credenziali admin da verificare |
| 6 — pubblicazione sito | **fatto** | pagina `ad-monitoring.html` + `api/ad.json` (poller 60 s), card in `projects.html`, sitemap |

Modifiche effettive: nuovo servizio systemd, nuova config Prometheus (job `ad-dc`, blackbox
corretto, rimosso job DNS con modulo inesistente), dashboard Grafana, timer `dbcheck`, logrotate,
SMTP Grafana e 16 regole di alert con notifica email.
Nessuna modifica a `smb.conf`, ai servizi AD o alle porte AD.

---

## 1. Stato verificato (evidenza live, 2026-10-21)

| Elemento | Valore reale | Impatto sul kit |
|---|---|---|
| Host monitoring | `homelab`, Ubuntu 24.04.5, `192.168.1.10/24` | — |
| DC | **Samba 4.19.5 AD DC** (`samba-ad-dc.service`, Zentyal 8.1) | `01/02/03/04/07` inutilizzabili |
| Dominio | `HOME-PUCCI.LAN` / `DC=home-pucci,DC=lan`, forest+domain level **2008 R2** | niente requisiti 2016+ |
| DC nella foresta | **1** (single point of failure confermato) | ridondanza da trattare come rischio, non come metrica di guasto |
| Oggetti | 8 utenti (2 disabilitati), 2 computer, 39 gruppi, 1 OU, 13 con `adminCount=1`, 0 lockout | soglie alert da tarare su scala piccola |
| Porte su 192.168.1.10 | 53, 88, 389, 445, 636, 3268, 3269 **open**; 5985, 5986, 9389, 9182 **closed** | blackbox attuale segnalerebbe 4 falsi down permanenti |
| Servizi | `samba-ad-dc`, `named`, `zentyal.*` attivi da ~2h30m | metrica di stato = `systemctl`, non `Get-Service` |
| DNS | BIND 9.18, 106 zone, `rndc status` funzionante, SRV `_ldap._tcp.dc._msdcs` risolve | sorgente DNS nativa disponibile |
| Lettura directory locale | `ldbsearch`/`python3 -c "import ldb"` → **ok** (ldb 2.8.0) | collector possibile senza WinRM |
| Prometheus | 3.15.0, retention 7g/2GB, config `/opt/monitoring/prometheus.yml`, **nessun `rule_files`** | le 28 alert rules non sono caricate |
| Grafana | 13.0.2, provisioning solo `firewall.yml`, dashboards in `/var/lib/grafana/dashboards` | pattern di provisioning già esistente da riusare |
| Datasource Prometheus | uid `dg13jav59r8cgd`, url `http://prometheus:9090`, default | il JSON dashboard è coerente: **non toccare l'uid** |
| Blackbox | `tcp_connect`, `http_2xx`, … **nessun modulo `dns`**; config non montata (baked nell'immagine) | job `ad-dns-blackbox` fallirebbe sempre |
| Rete container→host | precedente già in uso: `172.19.0.1:9101` (job `firewall`) | usare `172.19.0.1:9182` come target |
| Uscita Internet | GitHub e Docker Hub raggiungibili (contrariamente a nota README) | immagini/estensioni scaricabili se servono |

### Cosa è già buono e va conservato

- Namespace `ad_*` e formato text exposition: contratto semplice, leggibile, senza dipendenze.
- Separazione collect / serve e idea di cache su file (concetto, non implementazione).
- Job blackbox TCP per le porte AD e idea di probe DNS SRV.
- Struttura a "row" della dashboard e variabili `$instance`/`$site`.
- Provisioning Grafana via file (`firewall.yml`) come modello da replicare.

### Difetti bloccanti trovati nel kit attuale

| # | File | Problema | Effetto |
|---|---|---|---|
| B1 | `02-Collect-ADMetrics.ps1` | `M()` emette `# HELP`/`# TYPE` **per ogni serie**: con più serie (repliche, IP, volumi) si producono HELP duplicati | Prometheus **rifiuta l'intero scrape** (`second HELP line for metric name`) |
| B2 | `02` | `ad_replication_failed` = `1` quando la replica **funziona** | nome e alert invertiti: `ADReplicationFailed` scatta su sistema sano |
| B3 | `02` | `ad_directory_privileged_users` usa il filtro dei **disabilitati** (`UAC … :=2`) | duplica `ad_directory_disabled_users`; il pannello "privilegiati" mente |
| B4 | `02` | `Get-Service -Name 'Kerberos Key Distribution Center'` (display name) | metrica KDC mai emessa |
| B5 | `02` | `$d.OperatingSystem.CreationDate` su `Get-ADDomainController` | uptime non emesso (eccezione silenziata) |
| B6 | `02` | `site`/`fqdn`/`domain` presenti solo su 2 metriche | tutti i pannelli con `site=~"$site"` restano vuoti |
| B7 | `02` | `ad_dc_up` sempre `1`, `ad_collector_success` sempre `1` anche con sezioni fallite | impossibile distinguere "sano" da "collettore che non ha raccolto nulla" |
| B8 | `02` | `ad_failed_logon_source_total` è un `counter` ma vale `1` per evento ad ogni scrape | `rate()` in dashboard privo di senso (contatore che si resetta) |
| B9 | `02` | `dcdiag /e /c /q /v` ogni 60 s | carico inutile su DC; su Samba non esiste |
| B10 | `03` | `Add-Type -ReferencedAssemblies System.Net.Http` senza uso, e `HttpListener http://+:` richiede URL ACL | rischio di listener che non parte come SYSTEM |
| B11 | `04` | parametro formale `$args` (variabile automatica) e verifica endpoint solo locale | fragilità dello script di install |
| B12 | `05` | `05` è un frammento con `scrape_configs`; README dice "aggiungi a prometheus.yml" | merge manuale, nessuna `rule_files`, niente mount delle regole |
| B13 | `05` | target `5985/5986/9389/9182` chiusi; job DNS con modulo `dns` inesistente | 5 alert `probe_success == 0` permanenti |
| B14 | `06` | 28 regole mai caricate (`rule_files` assente) e nessun Alertmanager/contact point | alerting **non operativo**, solo file decorativo; le regole verranno riscritte come alert Grafana-managed |
| B15 | `06` | `ADReplicationConsecutiveFailures` usa `{{ $labels.consecutive_failures }}` (label inesistente); `ADCoreServiceStoppedWarning` fa vector matching su stessa metrica; `ADNtdsDitGrowing` confronta la dimensione assoluta, non la crescita; assenza di `absent()` per collector morto | alert duplicati/muti/falsi |
| B16 | dashboard | pannello "Età ultimo sync": `max(a) and on() (time()-max(a))` restituisce il timestamp, non l'età; "Repliche fallite" somma la metrica invertita; "Top IP" usa `rate()` su pseudo-counter; tabella replicazione mostra il lag, non lo stato | pannelli fuorvianti |
| B17 | dashboard | datasource `null` su alcuni pannelli; nessun datasource provisioning; uid hardcoded | import fragile su altri ambienti |
| B18 | Grafana | `apply.sh` abilita `auth.anonymous` con ruolo Viewer globale | dati AD (utenti, IP, lockout) leggibili senza login |

---

## 2. Architettura target

```
┌──────────────────────────── homelab (192.168.1.10) ────────────────────────────┐
│                                                                                  │
│  samba-ad-dc.service   named.service   Zentyal                                   │
│        │                    │                                                    │
│        │ sam.ldb (LDAP locale 127.0.0.1:389) / samba-tool / rndc                │
│        ▼                    ▼                                                    │
│  ┌──────────────────────────────────────────┐   systemd unit ad-monitor.service  │
│  │ ad-monitor (Python 3, stdlib + ldb)      │   User=admonitor?  (vedi §6)       │
│  │  - raccolta con cache TTL 30s            │   bind 172.19.0.1:9182            │
│  │  - espone /metrics, /healthz             │   firewall: solo 172.19.0.0/16    │
│  └──────────────────────────────────────────┘                                    │
│                    ▲ scrape 60s                                                  │
│  ┌─────────────────┴──────────────────────────────────────────────────────────┐  │
│  │ docker: prometheus:9090  →  grafana:3000   (+ node-exporter, blackbox)     │  │
│  │         └─ sola sorgente dati (nessuna rule_files)                         │  │
│  │         └─ Grafana unified alerting: regole + contact point (§7)           │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

Scelte e motivazioni:

- **Exporter come servizio systemd sull'host, non container.** Ha bisogno di `ldb`/`samba-tool`,
  `rndc` e dei log locali; un container richiederebbe immagine custom, mount di `/var/lib/samba`
  e socket. Il servizio host è più semplice, aggiornabile con `systemctl restart`, e non dipende
  da pull di immagini. Precedente già in uso: servizio su `172.19.0.1:9101`.
- **Nessun WinRM/ADWS.** Non serve abilitare nulla sul DC: riduce superficie d'attacco e non
  richiede modifiche a Samba (eccezione: livello di log `auth_audit`, §6).
- **LDAP locale con account di servizio read-only** invece di leggere `sam.ldb` come root:
  stessa informazione, privilegio minimo, e la latenza di bind diventa una metrica reale.
- **Raccolta on-demand con cache** invece di timer + file: elimina la classe di bug "file vecchio
  servito come fresco" e rende `up`/staleness affidabili.
- **Un solo motore di alerting: Grafana unified alerting.** Decisione presa per evitare un
  container aggiuntivo e un mount di `rule_files` (che avrebbe richiesto di ricreare lo stack).
  Regole provisionate via file, query sul datasource Prometheus, contact point e silenzi in
  Grafana. Prometheus resta solo sorgente dati.

---

## 3. Contratto metriche v2 (`ad_*`)

Regole trasversali:

- `instance` **non** viene messa dall'exporter (la aggiunge Prometheus dal target).
- Label comuni a tutte le metriche: `domain`, `dc`, `site` (valore reale: sito AD unico, es. `Default-First-Site-Name`).
- Ogni metrica ha **un solo** blocco HELP/TYPE, emesso una volta.
- Le metriche "di esito" valgono `1` = successo/OK, `0` = fallimento; i nomi lo dichiarano.
- Timestamp in secondi Unix; durate in secondi; ratio 0–1.

| Metrica | Tipo | Label | Sorgente | Cadenza |
|---|---|---|---|---|
| `ad_dc_info` | gauge=1 | `dc,domain,site,version,domain_level,forest_level` | `samba-tool domain level show`, `samba --version` | 300s |
| `ad_ldap_bind_success` | gauge | `dc` | bind LDAP su `127.0.0.1:389` con account servizio | 60s |
| `ad_ldap_bind_duration_seconds` | gauge | `dc` | idem | 60s |
| `ad_ldap_search_duration_seconds` | gauge | `dc` | query di conteggio | 60s |
| `ad_kdc_tgt_success` / `ad_kdc_tgt_duration_seconds` | gauge | `dc` | `kinit` con keytab/credenziale servizio, ticket distrutto subito | 300s |
| `ad_dc_service_active` | gauge | `dc,service` | `systemctl is-active` per `samba-ad-dc`, `named` | 60s |
| `ad_dc_service_restarts_total` | counter | `dc,service` | `systemctl show -p NRestarts` | 60s |
| `ad_dc_uptime_seconds` | gauge | `dc` | `systemctl show samba-ad-dc -p ActiveEnterTimestamp` | 60s |
| `ad_directory_users` | gauge | `dc` | LDAP `(objectClass=user)` | 300s |
| `ad_directory_users_enabled` | gauge | `dc` | UAC `:=2` negato | 300s |
| `ad_directory_users_disabled` | gauge | `dc` | UAC `:=2` | 300s |
| `ad_directory_users_locked` | gauge | `dc` | `(lockoutTime>=1)` | 60s |
| `ad_directory_users_password_never_expires` | gauge | `dc` | `(userAccountControl:…:=65536)` | 300s |
| `ad_directory_users_password_expired` | gauge | `dc` | `pwdLastSet=0` (solo account abilitati) | 300s |
| `ad_directory_users_stale_logon` | gauge | `dc` | `lastLogonTimestamp` più vecchio di 90g, abilitati | 3600s |
| `ad_directory_computers` / `_enabled` / `_stale` | gauge | `dc` | LDAP `(objectClass=computer)`, UAC, `lastLogonTimestamp` | 300s |
| `ad_directory_groups` / `ad_directory_ous` | gauge | `dc` | LDAP | 300s |
| `ad_privileged_accounts` | gauge | `dc` | `(adminCount=1)` | 300s |
| `ad_group_members` | gauge | `dc,group` | membri di `Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Administrators`, `Account Operators` | 300s |
| `ad_auth_failures_1h` | gauge | `dc,status` | log Samba `auth_audit` (`NT_STATUS_WRONG_PASSWORD`, `LOGON_FAILURE`, `ACCOUNT_LOCKED_OUT`) | 60s |
| `ad_auth_failures_by_source_1h` | gauge | `dc,source` (IP, top N) | idem, aggregato, anonimizzabile | 60s |
| `ad_auth_success_1h` | gauge | `dc` | idem | 60s |
| `ad_dns_zone_count` | gauge | `dc` | `rndc status` | 300s |
| `ad_dns_zone_serial` | gauge | `dc,zone` | `dig SOA` per zone AD-integrate chiave | 300s |
| `ad_dns_srv_ok` | gauge | `dc,record` | `dig SRV` per `_ldap._tcp`, `_kerberos._tcp`, `_ldap._tcp.dc._msdcs` | 120s |
| `ad_dns_xfer_deferred` | gauge | `dc` | `rndc status` | 120s |
| `ad_sysvol_share_ok` | gauge | `dc` | `smbclient //127.0.0.1/sysvol` con account servizio | 300s |
| `ad_dbcheck_errors` | gauge | `dc` | `samba-tool dbcheck --cross-ncs --quiet` (settimanale) | 7d |
| `ad_domain_controller_count` | gauge | `domain` | LDAP su `CN=Domain Controllers` | 900s |
| `ad_replication_partners` | gauge | `dc` | attributi `repsFrom`/`repsTo` sui naming context | 900s |
| `ad_replication_last_attempt_failed` | gauge | `dc,partner,partition` | `samba-tool drs showrepl --json` (solo se >1 DC) | 900s |
| `ad_replication_lag_seconds` | gauge | `dc,partner,partition` | idem | 900s |
| `ad_collector_success` / `ad_collector_partial_errors` | gauge | `dc` | esito reale del giro | 60s |
| `ad_collector_duration_seconds` / `_last_run_timestamp_seconds` | gauge | `dc` | misura interna | 60s |
| `ad_collector_build_info` | gauge=1 | `version,python,ldb` | costanti | 300s |

**Non replicabili su Samba (da eliminare dal contratto):** `dcdiag`, `repadmin` per-partizione,
`Get-ADReplicationFailure`, eventi 4625/4672/4728/4740/4768 (`Get-WinEvent`), `NTDS\ntds.dit`,
`Get-DnsServerZone`, stato dei servizi Windows. Sostituti: `dbcheck` periodico, `auth_audit`,
`rndc`/`dig`, dimensione di `sam.ldb` + `sam.ldb.d/` (via `node-exporter`, non metrica AD).

**Metriche Windows-only che non vanno emulate:** uptime del DC Windows, "privileged logons 4672",
"Kerberos service ticket errors" come conteggi di eventi: su Samba il segnale equivalente è
l'esito `auth_audit` + `kinit`.

---

## 4. Fasi di lavoro

### Fase 0 — Preparazione e sicurezza del contesto (0,5 g)

1. Assunzione confermata: target Samba/Zentyal (decisione 2026-10-21, §9). Registrarla nel
   `CHANGELOG.md` e nella finestra di manutenzione per `auth_audit`.
2. Backup versionato di: `/opt/monitoring/prometheus.yml`, `/opt/monitoring/grafana/`,
   `/etc/samba/smb.conf`, stack Docker corrente (esporta la definizione da Portainer).
3. Creazione di `/opt/ad-monitoring/` con: `ad-monitor.py`, `systemd/`, `prometheus/`,
   `grafana/`, `docs/`, `CHANGELOG.md`.
4. Definizione del contact point Grafana (endpoint/credenziale) e dell'account di servizio LDAP (§6).

**Accettazione:** backup ripristinabile, cartelle e ownership definite, nessuna modifica ai servizi.

### Fase 1 — Exporter MVP (1 g)

1. Account AD `svc-admonitor` (solo lettura, password robusta, scadenza gestita), test di bind su
   `ldap://127.0.0.1` e `ldaps://192.168.1.10`.
2. `ad-monitor.py`: HTTP server `ThreadingHTTPServer`, cache TTL 30 s, `/metrics`, `/healthz`,
   gestione errori per-sezione (una sezione che fallisce non azzera le altre), HELP/TYPE una volta.
3. Metriche Fase 1: `ad_dc_info`, bind/search latency, `ad_dc_service_active`, `_restarts_total`,
   `_uptime_seconds`, conteggi directory, gruppi privilegiati, SRV/DNS zone, `sysvol`, collector self.
4. `ad-monitor.service`: `User=admonitor`? (o root con sandbox, §6), `Restart=always`,
   `NoNewPrivileges`, `ProtectSystem=strict`, `ReadOnlyPaths` necessari, bind `172.19.0.1:9182`.
5. Firewall: allow `9182` solo da `172.19.0.0/16` e `127.0.0.1`; nessuna esposizione LAN.
6. `prometheus.yml`: aggiunta job `ad-dc` con target `172.19.0.1:9182`, label
   `domain/dc/site/role/platform`, `scrape_interval 60s`, `scrape_timeout 20s`; **rimozione** dei
   target chiusi dal job blackbox e del job `ad-dns-blackbox` (sostituito dalle metriche `ad_dns_*`).
7. `systemctl restart ad-monitor`, `curl` locale, reload Prometheus (config montata).

**Accettazione:** target `ad-dc` `UP`; `/metrics` valida (`promtool check metrics`); scrape
completo in < 5 s; nessuna metrica con HELP duplicati; nessuna porta AD modificata.

### Fase 2 — Sicurezza, autenticazione, salute (1 g)

1. Samba: introdurre `log level = 1 auth_audit:3` (o equivalente Zentyal), validare con
   `testparm -s`, applicare in finestra, rollback = ripristino `smb.conf` + reload.
2. Parser `auth_audit`: estrarre timestamp, account, IP sorgente, `NT_STATUS`; aggregare 1h;
   label `source` limitata ai top N (default 10) e opzione di mascheramento.
3. Lockout e password hygiene (metriche `locked`, `never_expires`, `expired`, `stale_logon`).
4. Probe funzionali: `kinit` TGT, LDAP, `smbclient` su SYSVOL, `dig` SRV; timeout aggressivi.
5. `samba-tool dbcheck --cross-ncs` settimanale via timer dedicato `ad-dbcheck.timer` →
   `ad_dbcheck_errors` (nessun impatto sui run da 60 s).
6. Metriche di replica (partner/lag) predisposte ma inattive finché resta 1 DC; nota esplicita
   in dashboard "single DC: replica non applicabile".

**Accettazione:** dopo 24 h `ad_collector_partial_errors == 0`; almeno un tentativo di auth
fallita di test visibile in `ad_auth_failures_1h` (test su account usa-e-getta, poi rimosso);
`dbcheck` eseguito una volta con esito registrato.

### Fase 3 — Dashboard (1 g)

1. Ricostruzione `grafana-dashboard-ad.json` sul contratto v2, **uid `active-directory` invariato**,
   datasource fissato a `dg13jav59r8cgd` (verificato) e provisioning file per portabilità.
2. Sezioni:
   - **Panoramica**: `up{job="ad-dc"}`, `ad_collector_success`, bind latency, servizi attivi,
     account/computer/gruppi, lockout, privilegiati, ultimo `dbcheck`.
   - **Autenticazione & sicurezza**: fallimenti 1h per status, top sorgenti, successi, lockout,
     account con password scaduta/mai scaduta/stale.
   - **DNS & Kerberos**: zone, serial, SRV ok, xfer deferred, TGT duration.
   - **Salute DC**: uptime, restart dei servizi, durata raccolta, errori parziali.
   - **Capacità** (da `node_exporter`, già disponibile): filesystem, memoria, carico, rete —
     niente metriche AD duplicate.
   - **Rischi strutturali**: single DC (testo + badge), forest level 2008 R2.
3. Variabili: `instance` (label `dc`), `domain`, `service`, `zone`; niente filtri su label
   inesistenti; ogni pannello con unità e soglie coerenti.
4. Provisioning: `/opt/monitoring/grafana/dashboards/ad.json` + `ad.yml` (cartella `Active Directory`),
   aggiornare `apply.sh` (che è il meccanismo reale usato per il firewall) e documentare che
   `/etc/grafana` è effimero.

**Accettazione:** dashboard importabile e provisionata, zero pannelli "No data" a collector sano,
query validate in Explore, nessun `rate()` su gauge.

### Fase 4 — Alerting operativo (0,5 g)

1. Regole **Grafana-managed** (unified alerting) sul datasource Prometheus `dg13jav59r8cgd`,
   gruppi: availability, services, directory, auth, dns, kerberos, health, structural.
   Soglie tarate sul dominio piccolo (§7).
2. Provisioning versionato in `/opt/monitoring/grafana/alerting/`:
   `contact-points.yaml`, `notification-policies.yaml`, `rules.yaml`; deploy con `docker cp` +
   estensione di `apply.sh` (pattern già usato per il firewall, `/etc/grafana` è effimero).
   In alternativa, creazione in UI e export JSON/YAML nel repo: una sola fonte di verità.
3. Contact point: **email** verso `ALERT_EMAIL` in `smtp.env`; provisioning versionato e testato
   con una regola temporanea. Un solo contact point di default, nessuna duplicazione di notifiche.
4. Test end-to-end senza toccare la produzione: query con soglia temporanea forzata, oppure
   metrica sintetica `ad_test_probe` esposta solo in fase di test; verifica ricezione, silenzi,
   `No data` → `Alerting` (impostare "No data" come condizione esplicita per il collector morto).
5. Runbook in `docs/RUNBOOK.md`: cosa fare per ciascun alert, comandi di verifica, escalation.

**Accettazione:** regole `health=ok` in Grafana, notifica reale ricevuta in < 2 min dall'innesco,
nessun alert duplicato sullo stesso sintomo, `No data` trattato come guasto del collector,
nessuna modifica al container Prometheus.

### Fase 5 — Consolidamento (0,5 g)

1. Documentazione finale (sostituire il README Windows con quello reale, tabella metriche,
   diagramma, procedura di ripristino).
2. Hardening Grafana: rimuovere `auth.anonymous` globale o limitarlo alla sola dashboard firewall;
   utente viewer dedicato per l'AD.
3. Retention: valutare 30 g per le metriche AD (attuale 7 g) o recording rules orarie.
4. Definition of Done: rieseguibilità da zero, backup, test di ripristino, nessuna credenziale
   in chiaro nel repo.

---

## 5. Correzioni puntuali al materiale esistente

- **Da archiviare** (non cancellare, spostare in `legacy-windows/`): `01`, `02`, `03`, `04`, `07-*`.
  Restano utili solo se in futuro arriverà un DC Windows.
- **Da riscrivere**: `05-prometheus-ad.yml` come frammento corretto per il nuovo target;
  `06-ad-alert-rules.yml` come bozza di soglie (espressioni da rifare).
- **Da sostituire**: `grafana-dashboard-ad.json` (contratto v2).
- **Da riusare come modello**: `07-grafana-provisioning-ad.yaml` → `ad.yml`.
- **README**: riscrivere con la realtà Samba; la nota "Docker Hub non raggiungibile" è falsa
  (verificata oggi) e va rimossa.

---

## 6. Sicurezza

| Tema | Scelta |
|---|---|
| Superficie AD | nessun WinRM/ADWS; solo LDAP locale + `samba-tool` in lettura |
| Account collector | `svc-admonitor` con sola lettura; credenziale in `/etc/ad-monitor/credentials` (0600) o `systemd LoadCredential=`; rotazione documentata |
| Endpoint metriche | bind su `172.19.0.1:9182` (raggiungibile solo dalle reti Docker dell'host); `ufw`/nftables in allow da `172.19.0.0/16`; nessuna pubblicazione LAN |
| Dati sensibili | niente username in label di default; `source` IP solo top N e mascherabile; niente password/keytab nelle metriche |
| Sandbox servizio | `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `CapabilityBoundingSet=` vuoto (se possibile senza root) |
| Log Samba | `auth_audit` alza il dettaglio: verificare spazio in `/var/log/samba`, logrotate, e RPO privacy (IP interni) |
| Grafana | rimuovere l'anonimo globale; se serve embed, limitarlo al folder `Homelab`/dashboard firewall |
| Segreti nel repo | la cartella `ad-monitoring` non deve contenere credenziali; aggiungere `.gitignore` se versionata |

Nota su `root`: se si preferisce non creare l'account LDAP, l'alternativa è lettura di `sam.ldb`
come root, ma è **peggiore** (accesso al DB completo, nessuna metrica di bind) e va controbilanciata
da sandbox systemd molto stretta. Raccomandazione: account LDAP.

---

## 7. Alerting: principi e soglie (Grafana unified alerting)

- Motore unico: Grafana valuta query Prometheus ogni 1 m; stato e silenzi in Grafana; nessun
  Alertmanager, nessun `rule_files` lato Prometheus.
- Un alert per sintomo, non per metrica: niente doppioni critical/warning sullo stesso evento
  (oggi `ADCoreServiceStopped` + `ADCoreServiceStoppedWarning`).
- Collector morto = **`No data` configurato come `Alerting`** sulla condizione principale
  (`up{job="ad-dc"} == 0` oppure `absent(ad_collector_last_run_timestamp_seconds)`), più
  `ad_collector_stale` come secondo livello. Senza questo, la metrica sparisce e nessuno avvisa.
- `for` realistici: 5 m disponibilità, 15 m sicurezza, 1 h/24 h rischi strutturali.
- Soglie tarate sul dominio: 8 utenti, 2 computer → `failed logons > 20/h` è già anomalo;
  `> 50/h` è quasi impossibile e non protegge. Lockout: soglia `> 2` su 6 utenti persona.
- Alert strutturali (single DC, forest 2008 R2) a severità `info`/`warning` e `for: 24h`, non
  critical: non sono guasti, sono rischi accettati.
- Provisioning versionato (`contact-points.yaml`, `notification-policies.yaml`, `rules.yaml`)
  e ridistribuito da `tools/deploy-alerting.sh`; nessuna regola creata solo a mano in UI senza export.

Bozza di gruppi:

```
availability : AdTargetDown (up==0), AdCollectorStale (time()-last_run>300), AdCollectorPartialErrors
services     : AdSambaDown, AdNamedDown, AdServiceRestarting (NRestarts crescente)
directory    : AdLockedAccounts, AdManyDisabled, AdPrivilegedGroupChanged (con recording rule delta)
auth         : AdAuthFailureSpike, AdAuthFailureFromSingleSource, AdAuthSuccessDrop
dns          : AdSrvRecordMissing, AdZoneSerialUnavailable, AdXferDeferred
kerberos     : AdTgtProbeFailing
health       : AdDbcheckErrors, AdSysvolUnavailable, AdLdapSlow
structural   : AdSingleDomainController, AdLegacyForestLevel
```

---

## 8. Rischi e mitigazioni

| Rischio | Prob. | Impatto | Mitigazione |
|---|---|---|---|
| Modifica `smb.conf` (auth_audit) mal applicata | Bassa | Alto (DC) | `testparm -s`, backup, finestra, reload non restart, rollback pronto |
| Recreate stack Docker | **Bassa** | Breve downtime monitoring (non AD) | evitata: alert Grafana-managed, nessun mount nuovo in Prometheus; solo `docker cp` verso Grafana |
| Provisioning Grafana effimero (`/etc/grafana`) | Media | Regole perse al recreate | `apply.sh` esteso e versionato; verifica post-restart in DoD |
| Account servizio mal configurato | Media | Metrica assente | test bind pre-deploy, fallback lettura locale documentato |
| Parser log fragile (formato Samba) | Media | Dati auth mancanti | test su log reali, `ad_collector_partial_errors` visibile, parser versionato |
| Soglie inadatte a dominio piccolo | Alta | Alert rumorosi | taratura dopo 7 g di baseline, alert `info` per i primi giorni |
| Single DC | Certezza | Outage totale | fuori scope monitoraggio: rischio documentato, alert informativo |
| Forest level 2008 R2 | Certezza | Vincoli sicurezza/funzioni | rischio documentato, non modificabile in questo piano |
| Grafana anonimo | Certezza | Esposizione dati | hardening Fase 5 |

---

## 9. Decisioni

**Chiuse il 2026-10-21:**
1. Target = **Samba/Zentyal attuale** (`HOME-PUCCI.LAN`, Samba 4.19.5). Gli script PowerShell sono
   un'ipotesi superata e vengono archiviati in `legacy-windows/`.
2. Notifiche = **Grafana unified alerting** con **email**. Nessun Alertmanager, nessuna regola
   Prometheus, nessuna ricreazione dello stack. SMTP riusato da `msmtp` (Gmail, porta 587/TLS);
   credenziali in `/etc/ad-monitoring/smtp.env` (0600), destinatario `admin@example.com`.

**Ancora aperte (non bloccanti):**
3. **Account di servizio LDAP** `svc-admonitor`: ok crearlo, o preferisci lettura locale come root
   con sandbox systemd? (oggi funziona in locale come root, DB in sola lettura logica)
4. **Log `auth_audit`**: non serve abilitarlo, `log level = 3` emette già gli eventi JSON.
5. **Grafana**: accesso anonimo viewer attivo e credenziali admin non note. Restringere?
6. **Secondo DC**: resta un rischio strutturale, fuori scope monitoraggio.
6. **Grafana anonimo**: lo consideri voluto (embed) o va ristretto?

---

## 10. Definition of Done

- [ ] `ad-dc` UP e stabile per 7 giorni, `ad_collector_partial_errors == 0`.
- [ ] `/metrics` valida con `promtool`, nessun HELP/TYPE duplicato.
- [ ] Dashboard provisionata, zero pannelli vuoti a collector sano, variabili funzionanti.
- [ ] Regole Grafana `health=ok`, notifica reale ricevuta, `No data` = `Alerting`,
      runbook associato, provisioning ridistribuito dopo un restart di Grafana.
- [ ] Nessuna porta AD aggiuntiva aperta; `9182` raggiungibile solo dal bridge Docker.
- [ ] Backup di configurazione e procedura di ripristino provata.
- [ ] README allineato alla realtà (Samba, non Windows) e materiale legacy archiviato.
