#!/bin/bash
# Provisiona SMTP + contact point email + policy + regole di alert in Grafana.
# Richiede /etc/ad-monitoring/smtp.env (root, 0600) e /etc/grafana/grafana.ini
# gestito da apply-smtp.py. Riavvia Grafana per applicare il provisioning.
set -euo pipefail

BASE=/opt/ad-monitoring/grafana/alerting
ENVF=/etc/ad-monitoring/smtp.env
C=monitoring-grafana-1

[ -f "$ENVF" ] || { echo "mancante $ENVF"; exit 1; }
# shellcheck disable=SC1090
ALERT_EMAIL=$(grep '^ALERT_EMAIL=' "$ENVF" | cut -d= -f2-)
[ -n "$ALERT_EMAIL" ] || { echo "ALERT_EMAIL mancante in $ENVF"; exit 1; }

echo "==> SMTP"
python3 /opt/ad-monitoring/tools/apply-smtp.py

echo "==> Rendering contact point"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
sed "s|__ALERT_EMAIL__|$ALERT_EMAIL|g" "$BASE/contact-points.yaml.tmpl" > "$TMP"

echo "==> Copia provisioning alerting"
docker exec "$C" mkdir -p /etc/grafana/provisioning/alerting
docker cp "$TMP" "$C":/etc/grafana/provisioning/alerting/contact-points.yaml
docker cp "$BASE/notification-policies.yaml" "$C":/etc/grafana/provisioning/alerting/notification-policies.yaml
docker cp "$BASE/rules.yaml" "$C":/etc/grafana/provisioning/alerting/rules.yaml
docker exec -u root "$C" sh -c 'chmod 644 /etc/grafana/provisioning/alerting/*.yaml'

echo "==> Restart Grafana"
docker restart "$C" >/dev/null
sleep 10

echo "==> Log provisioning (errori se presenti)"
docker logs --since 2m "$C" 2>&1 | grep -iE 'alerting|provision|smtp' | grep -iE 'error|warn|fail' | tail -10 || true
docker logs --since 2m "$C" 2>&1 | grep -iE 'finished to provision alerting|provisioning alerting' | tail -5 || true

echo "Fatto. Verifica: Alerting > Alert rules in Grafana, e invio con una regola di test."
