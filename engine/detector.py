import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional, Sequence
from engine.config import CustomRuleConfig

@dataclass
class SecurityAlert:
    timestamp: float
    rule_id: str
    severity: str
    source_ip: str
    description: str
    raw_log: str

class LogDetector:
    """
    Regex-based log analysis engine (built-in + custom rules) with sliding-window
    temporal correlation for intrusion detection.
    """

    SSH_FAILED_RE = re.compile(
        r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )
    HTTP_ACCESS_RE = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?P<method>\S+) (?P<path>\S+) HTTP/.*?" (?P<status>\d{3})'
    )

    SQLI_PATTERNS = re.compile(
        r"(?:UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|'--|%27%20OR|SLEEP\(\d+\))", re.IGNORECASE
    )
    PATH_TRAVERSAL_RE = re.compile(r"(?:\.\./|\.\.%2f|/etc/passwd|/etc/shadow|\.env)", re.IGNORECASE)
    SCANNER_PATHS_RE = re.compile(r"(?:/wp-admin|/wp-login\.php|/phpmyadmin|/\.git/config|/xmlrpc\.php)", re.IGNORECASE)

    def __init__(
        self,
        brute_force_threshold: int = 5,
        window_seconds: int = 60,
        custom_rules: Sequence[CustomRuleConfig] = (),
    ):
        self.threshold = brute_force_threshold
        self.window = window_seconds
        self.custom_rules: list[CustomRuleConfig] = list(custom_rules)
        self.failed_attempts: dict[str, deque[float]] = defaultdict(deque)

    def update_rules(
        self,
        brute_force_threshold: int,
        window_seconds: int,
        custom_rules: Sequence[CustomRuleConfig],
    ) -> None:
        self.threshold = brute_force_threshold
        self.window = window_seconds
        self.custom_rules = list(custom_rules)

    def _check_brute_force(self, ip: str, now: float) -> bool:
        attempts = self.failed_attempts[ip]
        attempts.append(now)
        while attempts and (now - attempts[0]) > self.window:
            attempts.popleft()
        return len(attempts) >= self.threshold

    def inspect_line(self, line: str, now: Optional[float] = None) -> Optional[SecurityAlert]:
        now = now or time.time()
        line = line.strip()
        if not line:
            return None

        for rule in self.custom_rules:
            match = rule.pattern.search(line)
            if match:
                return SecurityAlert(
                    timestamp=now,
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    source_ip=match.group("ip"),
                    description=rule.description,
                    raw_log=line,
                )

        ssh_match = self.SSH_FAILED_RE.search(line)
        if ssh_match:
            ip = ssh_match.group("ip")
            user = ssh_match.group("user")
            if self._check_brute_force(ip, now):
                self.failed_attempts[ip].clear()
                return SecurityAlert(
                    timestamp=now,
                    rule_id="SSH-BRUTE-001",
                    severity="HIGH",
                    source_ip=ip,
                    description=f"SSH brute-force detected ({self.threshold}+ failures within {self.window}s, last user: '{user}')",
                    raw_log=line,
                )
            return None

        http_match = self.HTTP_ACCESS_RE.search(line)
        if http_match:
            ip = http_match.group("ip")
            path = http_match.group("path")
            status = int(http_match.group("status"))

            if self.SQLI_PATTERNS.search(path):
                return SecurityAlert(
                    timestamp=now,
                    rule_id="WEB-SQLI-002",
                    severity="CRITICAL",
                    source_ip=ip,
                    description=f"SQL Injection payload detected in HTTP request: {path}",
                    raw_log=line,
                )

            if self.PATH_TRAVERSAL_RE.search(path):
                return SecurityAlert(
                    timestamp=now,
                    rule_id="WEB-LFI-003",
                    severity="HIGH",
                    source_ip=ip,
                    description=f"Path Traversal / sensitive file probe detected: {path}",
                    raw_log=line,
                )

            if status in (401, 403, 404) and self.SCANNER_PATHS_RE.search(path):
                if self._check_brute_force(ip, now):
                    self.failed_attempts[ip].clear()
                    return SecurityAlert(
                        timestamp=now,
                        rule_id="WEB-SCAN-004",
                        severity="MEDIUM",
                        source_ip=ip,
                        description=f"Automated web vulnerability scanner activity detected ({path})",
                        raw_log=line,
                    )

        return None
