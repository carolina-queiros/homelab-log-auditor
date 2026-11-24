import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

@dataclass
class CustomRuleConfig:
    rule_id: str
    severity: str
    pattern: str
    description: str

@dataclass
class AuditorConfig:
    log_files: list[str]
    database_path: str
    brute_force_threshold: int
    window_seconds: int
    custom_rules: list[CustomRuleConfig]
    enforce: bool
    ban_ttl_seconds: int
    whitelist: list[str]
    webhook_url: str

    @classmethod
    def from_file(cls, path: str | Path) -> "AuditorConfig":
        raw: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))

        rules = [
            CustomRuleConfig(
                rule_id=r["id"],
                severity=r["severity"],
                pattern=r["pattern"],
                description=r["description"],
            )
            for r in raw["detection"]["custom_rules"]
        ]

        return cls(
            log_files=raw["log_files"],
            database_path=raw["database_path"],
            brute_force_threshold=raw["detection"]["brute_force_threshold"],
            window_seconds=raw["detection"]["window_seconds"],
            custom_rules=rules,
            enforce=raw["ips"]["enforce"],
            ban_ttl_seconds=raw["ips"]["ban_ttl_seconds"],
            whitelist=raw["ips"]["whitelist"],
            webhook_url=raw["notifications"]["webhook_url"],
        )
