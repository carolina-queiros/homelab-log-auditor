import json
import logging
import urllib.error
import urllib.request
from engine.detector import SecurityAlert

logger = logging.getLogger("homelab-auditor.notifier")

class WebhookNotifier:
    """
    Envia alertas de segurança formatados em JSON para webhooks (Discord/Slack)
    usando apenas a biblioteca padrão Python, sem dependências externas.
    """

    SEVERITY_COLORS = {
        "LOW": 3447003,       # Azul
        "MEDIUM": 16776960,   # Amarelo
        "HIGH": 15105570,     # Laranja
        "CRITICAL": 15158332, # Vermelho
    }

    def __init__(self, webhook_url: str | None = None, timeout: float = 4.0):
        self.webhook_url = webhook_url
        self.timeout = timeout

    def send_alert(self, alert: SecurityAlert, action_taken: str) -> bool:
        if not self.webhook_url:
            return False

        payload = {
            "username": "Homelab Log Auditor (Mini-SIEM)",
            "embeds": [
                {
                    "title": f"[{alert.severity}] {alert.rule_id} — {alert.source_ip}",
                    "description": alert.description,
                    "color": self.SEVERITY_COLORS.get(alert.severity, 15158332),
                    "fields": [
                        {"name": "Origem", "value": f"`{alert.source_ip}`", "inline": True},
                        {"name": "Ação IPS", "value": action_taken, "inline": True},
                        {"name": "Log Bruto", "value": f"```{alert.raw_log[:400]}```", "inline": False},
                    ],
                }
            ],
        }

        req = urllib.request.Request(
            self.webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "HomelabLogAuditor/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except urllib.error.URLError as exc:
            logger.error(f"Falha ao enviar alerta para webhook: {exc}")
            return False
