import json
import logging
import urllib.request
from datetime import datetime, timezone
from engine.detector import SecurityAlert

logger = logging.getLogger("homelab-auditor.notifier")

class WebhookNotifier:
    """
    Sends structured security alerts to Discord/Slack webhooks using Python's
    standard urllib.request without external dependencies.
    """

    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url

    def send_alert(self, alert: SecurityAlert, action_taken: str) -> bool:
        if not self.webhook_url:
            return False

        ts_iso = datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        payload = {
            "username": "Homelab Mini-SIEM",
            "embeds": [
                {
                    "title": f"[{alert.severity}] Alert {alert.rule_id}",
                    "description": alert.description,
                    "color": 15158332 if alert.severity in ("HIGH", "CRITICAL") else 15844367,
                    "fields": [
                        {"name": "Source IP", "value": f"`{alert.source_ip}`", "inline": True},
                        {"name": "IPS Action", "value": action_taken, "inline": True},
                        {"name": "Timestamp", "value": ts_iso, "inline": False},
                        {"name": "Raw Log", "value": f"```{alert.raw_log[:300]}```", "inline": False},
                    ],
                }
            ],
        }

        req = urllib.request.Request(
            self.webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "Homelab-Log-Auditor/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return 200 <= resp.status < 300
        except Exception as exc:
            logger.error(f"Failed to dispatch webhook notification: {exc}")
            return False
