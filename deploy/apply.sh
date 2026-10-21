#!/bin/bash
# Ri-applica provisioning e configurazione Grafana per firewall e Active Directory.
# Necessario dopo un recreate del container (i file in /etc sono effimeri).
set -e
C=monitoring-grafana-1
docker exec "$C" mkdir -p /var/lib/grafana/dashboards /var/lib/grafana/dashboards-ad
docker cp /opt/monitoring/grafana/dashboards/firewall.json "$C":/var/lib/grafana/dashboards/firewall.json
docker cp /opt/monitoring/grafana/dashboards/firewall.yml  "$C":/etc/grafana/provisioning/dashboards/firewall.yml
# Dashboard Active Directory (Samba AD DC): file generato da /opt/ad-monitoring/tools/gen_dashboard.py
docker cp /opt/ad-monitoring/grafana/ad.json "$C":/var/lib/grafana/dashboards-ad/ad.json
docker cp /opt/ad-monitoring/grafana/ad.yml  "$C":/etc/grafana/provisioning/dashboards/ad.yml
docker exec -u root "$C" sh -c "
sed -i 's|^;root_url = .*|root_url = %(protocol)s://%(domain)s:%(http_port)s/grafana/|' /etc/grafana/grafana.ini
sed -i 's|^;serve_from_sub_path = false|serve_from_sub_path = true|' /etc/grafana/grafana.ini
sed -i 's|^;allow_embedding = false|allow_embedding = true|' /etc/grafana/grafana.ini
sed -i '/^\[auth.anonymous\]/,/^\[/ s/^;enabled = false/enabled = true/' /etc/grafana/grafana.ini
sed -i '/^\[auth.anonymous\]/,/^\[/ s/^;org_name = Main Org./org_name = Main Org./' /etc/grafana/grafana.ini
sed -i '/^\[auth.anonymous\]/,/^\[/ s/^;org_role = Viewer/org_role = Viewer/' /etc/grafana/grafana.ini
"
# SMTP per gli alert email (secret in /etc/ad-monitoring/smtp.env, non nel repo)
if [ -f /etc/ad-monitoring/smtp.env ]; then
  python3 /opt/ad-monitoring/tools/apply-smtp.py
fi
docker restart "$C" >/dev/null
echo "Grafana riconfigurato."
