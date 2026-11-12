#!/usr/bin/env bash
# Checks Loki readiness and confirms log ingestion from node-01

echo "[*] Checking Loki readiness..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3100/ready)

if [ "$STATUS" -eq 200 ]; then
    echo "[✓] Loki is ready (HTTP 200)."
else
    echo "[!] Loki not ready yet. Status: $STATUS"
    exit 1
fi

echo "[*] Querying logs for host='node-01'..."
QUERY_RESULT=$(curl -s -G "http://localhost:3100/loki/api/v1/query" --data-urlencode 'query={host="node-01"}')

if [[ $QUERY_RESULT == *"node-01"* ]]; then
    echo "[✓] Verified: Logs from node-01 found in Loki."
else
    echo "[!] No logs found yet for node-01. Run simulate_attack.sh first."
fi
