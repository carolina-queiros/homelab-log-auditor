import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from engine.responder import FirewallResponder
from engine.storage import IncidentStore

logger = logging.getLogger("homelab-auditor.dashboard")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="pt">
<head>
  <meta charset="UTF-8">
  <title>Homelab Mini-SIEM &amp; IPS Dashboard</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }
    h1 { font-size: 1.5rem; margin-bottom: 16px; color: #38bdf8; }
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
    button { background: #ef4444; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: 600; }
    button:hover { background: #dc2626; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.82rem; color: #cbd5e1; }
  </style>
</head>
<body>
  <h1>Homelab Log Auditor — Mini-SIEM &amp; Active IPS</h1>
  <div class="grid">
    <div class="card"><div>Total de Incidentes</div><div id="total-alerts" class="metric">-</div></div>
    <div class="card"><div>Bloqueios IPS Ativos</div><div id="active-bans" class="metric">-</div></div>
  </div>

  <h2>Bloqueios Ativos (IPS)</h2>
  <table>
    <thead><tr><th>IP</th><th>Regra</th><th>Tempo Restante</th><th>Ação</th></tr></thead>
    <tbody id="bans-body"></tbody>
  </table>

  <h2>Alertas Recentes</h2>
  <table>
    <thead><tr><th>Severidade</th><th>Regra</th><th>IP Origem</th><th>Descrição</th><th>Log Bruto</th></tr></thead>
    <tbody id="alerts-body"></tbody>
  </table>

  <script>
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

      document.getElementById('bans-body').innerHTML = bans.map(b =>
        `<tr><td><code>${b.ip}</code></td><td>${b.reason}</td><td>${b.remaining_seconds}s</td>` +
        `<td><button onclick="unbanIp('${b.ip}')">Desbloquear</button></td></tr>`
      ).join('') || '<tr><td colspan="4">Sem bloqueios ativos</td></tr>';

      document.getElementById('alerts-body').innerHTML = alerts.map(a =>
        `<tr><td><span class="badge ${a.severity}">${a.severity}</span></td><td>${a.rule_id}</td>` +
        `<td><code>${a.source_ip}</code></td><td>${a.description}</td><td><code>${a.raw_log}</code></td></tr>`
      ).join('') || '<tr><td colspan="5">Sem alertas registados</td></tr>';
    }
    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>
"""

class DashboardServer:
    def __init__(self, store: IncidentStore, responder: FirewallResponder, host: str = "0.0.0.0", port: int = 8080):
        self.store = store
        self.responder = responder
        self.host = host
        self.port = port
        self._server: ThreadingHTTPServer | None = None

    def start(self) -> None:
        store = self.store
        responder = self.responder

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def _send_json(self, data, status: int = 200):
                body = json.dumps(data).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urlparse(self.path).path
                if path == "/":
                    html = DASHBOARD_HTML.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
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
                else:
                    self._send_json({"error": "Not found"}, status=404)

            def do_POST(self):
                if urlparse(self.path).path != "/api/unban":
                    self._send_json({"error": "Not found"}, status=404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
                ip = payload.get("ip", "")
                if responder.unblock_ip(ip):
                    store.remove_ban(ip)
                    self._send_json({"status": "unbanned", "ip": ip})
                else:
                    self._send_json({"error": "Failed to unban IP"}, status=500)

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.start()
        logger.info(f"Dashboard Web & API REST ativos em http://{self.host}:{self.port}")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
