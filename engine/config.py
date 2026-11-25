import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("homelab-auditor.config")

@dataclass
class CustomRuleConfig:
    rule_id: str
    severity: str
    pattern: re.Pattern[str]
    description: str

@dataclass
class AuditorConfig:
    log_files: list[str] = field(default_factory=lambda: ["/var/log/auth.log", "/var/log/nginx/access.log"])
    database_path: str = "auditor_state.db"
    brute_force_threshold: int = 5
    window_seconds: int = 60
    custom_rules: list[CustomRuleConfig] = field(default_factory=list)
    enforce: bool = False
    ban_ttl_seconds: int = 3600
    whitelist: list[str] = field(default_factory=list)
    webhook_url: str = ""

    @classmethod
    def from_file(cls, path: str | Path) -> "AuditorConfig":
        cfg_path = Path(path)
        if not cfg_path.exists():
            logger.warning(f"Configuration file '{cfg_path}' not found; falling back to defaults.")
            return cls()

        raw: dict[str, Any] = json.loads(cfg_path.read_text(encoding="utf-8"))
        detection = raw.get("detection", {})
        ips = raw.get("ips", {})
        notifications = raw.get("notifications", {})

        valid_rules: list[CustomRuleConfig] = []
        for entry in detection.get("custom_rules", []):
            rule_id = entry.get("id", "CUSTOM-UNKNOWN")
            raw_pattern = entry.get("pattern", "")
            try:
                compiled = re.compile(raw_pattern)
                if "ip" not in compiled.groupindex:
                    logger.error(f"Rule '{rule_id}' skipped: pattern must define a named (?P<ip>...) group.")
                    continue
                valid_rules.append(
                    CustomRuleConfig(
                        rule_id=rule_id,
                        severity=entry.get("severity", "MEDIUM").upper(),
                        pattern=compiled,
                        description=entry.get("description", "Custom detection rule triggered"),
                    )
                )
            except re.error as exc:
                logger.error(f"Rule '{rule_id}' skipped due to invalid regex ({exc}): {raw_pattern}")

        return cls(
            log_files=raw.get("log_files", ["/var/log/auth.log", "/var/log/nginx/access.log"]),
            database_path=raw.get("database_path", "auditor_state.db"),
            brute_force_threshold=int(detection.get("brute_force_threshold", 5)),
            window_seconds=int(detection.get("window_seconds", 60)),
            custom_rules=valid_rules,
            enforce=bool(ips.get("enforce", False)),
            ban_ttl_seconds=int(ips.get("ban_ttl_seconds", 3600)),
            whitelist=list(ips.get("whitelist", [])),
            webhook_url=str(notifications.get("webhook_url", "")),
        )
