#!/bin/sh
set -eu

DASHBOARD_ID="${GRAFANA_DASHBOARD_ID:-24085}"
DASHBOARD_REVISION="${GRAFANA_DASHBOARD_REVISION:-3}"
DASHBOARD_PATH="/var/lib/grafana/dashboards/smap.json"
DASHBOARD_URL="https://grafana.com/api/dashboards/${DASHBOARD_ID}/revisions/${DASHBOARD_REVISION}/download"

echo "[startup] Downloading dashboard ${DASHBOARD_ID} rev ${DASHBOARD_REVISION} from grafana.com"
if curl -fsSL "$DASHBOARD_URL" -o "$DASHBOARD_PATH"; then
  sed -i 's/${DS_SQLITE}/SQLite/g' "$DASHBOARD_PATH"
  echo "[startup] Dashboard saved to $DASHBOARD_PATH"
else
  echo "[startup] Warning: dashboard download failed, keeping existing file if present"
fi

exec "$@"
