import csv
import io
import hmac
import ipaddress
import json
import logging
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from engine.responder import FirewallResponder
from engine.storage import IncidentStore

logger = logging.getLogger("homelab-auditor.dashboard")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Homelab Mini-SIEM &amp; Active IPS Dashboard</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }
    .header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; }
    h1 { font-size: 1.5rem; margin: 0; color: #38bdf8; }
    .exports a { background: #1e293b; color: #38bdf8; border: 1px solid #334155; padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 600; margin-left: 8px; }
    .exports a:hover { background: #334155; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; }
    .metric { font-size: 2rem; font-weight: 700; color: #f8fafc; }
    table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; margin-bottom: 24px; }
    th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid #334155; font-size: 0.9rem; }
    th { background: #0f172a; color: #94a3b8; }
    .badge { padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.78rem; }
    .CRITICAL { background: #7f1d1d; color: #fecaca; }
    .HIGH { background: #7c2d12; color: #fed7aa; }
    .MEDIUM { background: #713f12; color: #fef08a; }
    .LOW { background: #1e3a8a; color: #bfdbfe; }
    button { background: #ef4444; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: 600; }
    button:hover { background: #dc2626; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.82rem; color: #cbd5e1; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Homelab Log Auditor — Mini-SIEM &amp; Active IPS</h1>
    <div class="exports">
      <a href="/api/export?format=csv">Export CSV</a>
      <a href="/api/export?format=json">Export JSON</a>
    </div>
  </div>
  <div class="grid">
    <div class="card"><div>Total Incidents</div><div id="total-alerts" class="metric">-</div></div>
    <div class="card"><div>Active IPS Bans</div><div id="active-bans" class="metric">-</div></div>
  </div>

  <h2>Active Bans (IPS)</h2>
  <table>
    <thead><tr><th>IP Address</th><th>Rule</th><th>Remaining TTL</th><th>Action</th></tr></thead>
    <tbody id="bans-body"></tbody>
  </table>

  <h2>Recent Security Alerts</h2>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Source IP</th><th>Description</th><th>Raw Log</th></tr></thead>
    <tbody id="alerts-body"></tbody>
  </table>

  <script>
    function cellWithText(text, isCode = false) {
      const td = document.createElement('td');
      if (isCode) {
        const code = document.createElement('code');
        code.textContent = text;
        td.appendChild(code);
      } else {
        td.textContent = text;
      }
      return td;
    }

    async function unbanIp(ip) {
      await fetch('/api/unban', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip})
      });
      refresh();
    }

    async function refresh() {
      const [statsRes, bansRes, alertsRes] = await Promise.all([
        fetch('/api/stats'), fetch('/api/bans'), fetch('/api/alerts')
      ]);
      const stats = await statsRes.json();
      const bans = await bansRes.json();
      const alerts = await alertsRes.json();

      document.getElementById('total-alerts').textContent = stats.total_alerts;
      document.getElementById('active-bans').textContent = stats.active_bans;

      const bansBody = document.getElementById('bans-body');
      bansBody.replaceChildren();
      if (!bans.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 4;
        td.textContent = 'No active bans';
        tr.appendChild(td);
        bansBody.appendChild(tr);
      } else {
        for (const b of bans) {
          const tr = document.createElement('tr');
          tr.appendChild(cellWithText(b.ip, true));
          tr.appendChild(cellWithText(b.reason));
          tr.appendChild(cellWithText(`${b.remaining_seconds}s`));
          const actionTd = document.createElement('td');
          const btn = document.createElement('button');
          btn.textContent = 'Unban';
          btn.addEventListener('click', () => unbanIp(b.ip));
          actionTd.appendChild(btn);
          tr.appendChild(actionTd);
          bansBody.appendChild(tr);
        }
      }

      const alertsBody = document.getElementById('alerts-body');
      alertsBody.replaceChildren();
      if (!alerts.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 5;
        td.textContent = 'No security alerts recorded';
        tr.appendChild(td);
        alertsBody.appendChild(tr);
      } else {
        for (const a of alerts) {
          const tr = document.createElement('tr');
          const sevTd = document.createElement('td');
          const badge = document.createElement('span');
          const allowed = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
          const safeSev = allowed.includes(a.severity) ? a.severity : 'LOW';
          badge.className = `badge ${safeSev}`;
          badge.textContent = safeSev;
          sevTd.appendChild(badge);
          tr.appendChild(sevTd);
          tr.appendChild(cellWithText(a.rule_id));
          tr.appendChild(cellWithText(a.source_ip, true));
          tr.appendChild(cellWithText(a.description));
          tr.appendChild(cellWithText(a.raw_log, true));
          alertsBody.appendChild(tr);
        }
      }
    }
    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>
"""

def render_alerts_csv(alerts: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "timestamp_utc", "rule_id", "severity", "source_ip", "description", "raw_log"])
    for a in alerts:
        ts_iso = datetime.fromtimestamp(a["timestamp"], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        writer.writerow([a["id"], ts_iso, a["rule_id"], a["severity"], a["source_ip"], a["description"], a["raw_log"]])
    return buf.getvalue()

class DashboardServer:
    def __init__(self, store: IncidentStore, responder: FirewallResponder, host: str = "127.0.0.1", port: int = 8080, api_key: str | None = None):
        self.store = store
        self.responder = responder
        self.host = host
        self.port = port
        self.api_key = api_key
        self._server: ThreadingHTTPServer | None = None

    def start(self) -> None:
        store = self.store
        responder = self.responder
        api_key = self.api_key

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def _is_authorized(self) -> bool:
                if not api_key:
                    return True
                header_key = self.headers.get("X-API-Key", "")
                auth_header = self.headers.get("Authorization", "")
                bearer = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
                candidate = header_key or bearer
                return hmac.compare_digest(candidate, api_key)

            def _apply_security_headers(self):
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")

            def _send_json(self, data, status: int = 200):
                body = json.dumps(data, indent=2).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self._apply_security_headers()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                if path == "/":
                    html = DASHBOARD_HTML.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self._apply_security_headers()
                    self.send_header("Content-Length", str(len(html)))
                    self.end_headers()
                    self.wfile.write(html)
                elif path == "/api/stats":
                    total, active, top = store.get_summary_stats()
                    self._send_json({"total_alerts": total, "active_bans": active, "top_ips": top})
                elif path == "/api/bans":
                    self._send_json(store.get_active_bans_list())
                elif path == "/api/alerts":
                    self._send_json(store.get_recent_alerts(limit=25))
                elif path == "/metrics":
                    total, active, _ = store.get_summary_stats()
                    alerts = store.get_recent_alerts(limit=10000)
                    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                    for a in alerts:
                        s = a.get("severity", "LOW")
                        sev_counts[s] = sev_counts.get(s, 0) + 1
                    lines = [
                        "# HELP siem_alerts_total Total recorded security alerts",
                        "# TYPE siem_alerts_total counter",
                        f"siem_alerts_total {total}",
                        "# HELP siem_active_bans Currently active IPS firewall bans",
                        "# TYPE siem_active_bans gauge",
                        f"siem_active_bans {active}",
                        "# HELP siem_alerts_by_severity Security alerts partitioned by severity",
                        "# TYPE siem_alerts_by_severity counter",
                    ]
                    for sev, cnt in sev_counts.items():
                        lines.append(f'siem_alerts_by_severity{{severity="{sev}"}} {cnt}')
                    body = ("\n".join(lines) + "\n").encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                    self._apply_security_headers()
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif path == "/api/export":
                    if not self._is_authorized():
                        self._send_json({"error": "Unauthorized"}, status=401)
                        return
                    fmt = parse_qs(parsed.query).get("format", ["json"])[0].lower()
                    alerts = store.get_recent_alerts(limit=1000)
                    if fmt == "csv":
                        body = render_alerts_csv(alerts).encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/csv; charset=utf-8")
                        self.send_header("Content-Disposition", 'attachment; filename="siem_incidents.csv"')
                        self._apply_security_headers()
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                    else:
                        self._send_json(alerts)
                else:
                    self._send_json({"error": "Not found"}, status=404)

            def do_POST(self):
                if urlparse(self.path).path != "/api/unban":
                    self._send_json({"error": "Not found"}, status=404)
                    return
                if not self._is_authorized():
                    self._send_json({"error": "Unauthorized"}, status=401)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    payload = json.loads(self.rfile.read(length) or b"{}")
                    ip_raw = str(payload.get("ip", "")).strip()
                    ip_obj = ipaddress.ip_address(ip_raw)
                except (ValueError, json.JSONDecodeError):
                    self._send_json({"error": "Invalid IP address payload"}, status=400)
                    return

                clean_ip = str(ip_obj)
                if responder.unblock_ip(clean_ip):
                    store.remove_ban(clean_ip)
                    self._send_json({"status": "unbanned", "ip": clean_ip})
                else:
                    self._send_json({"error": "Failed to unban IP"}, status=500)

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.start()
        logger.info(f"Web Dashboard & REST API listening on http://{self.host}:{self.port}")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
