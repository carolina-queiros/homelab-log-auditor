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
    Motor de análise de logs baseado em regras Regex (nativas e customizadas)
    e correlação temporal (janela deslizante) para deteção de intrusões.
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

        # 1. Regras customizadas carregadas via config.json
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

        # 2. Análise de logs SSH (auth.log)
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
                    description=f"Força bruta SSH detetada ({self.threshold}+ falhas em {self.window}s, último user: '{user}')",
                    raw_log=line,
                )
            return None

        # 3. Análise de logs HTTP (Nginx / Apache)
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
                    description=f"Tentativa de SQL Injection detetada no pedido: {path}",
                    raw_log=line,
                )

            if self.PATH_TRAVERSAL_RE.search(path):
                return SecurityAlert(
                    timestamp=now,
                    rule_id="WEB-LFI-003",
                    severity="HIGH",
                    source_ip=ip,
                    description=f"Tentativa de Path Traversal / leitura de ficheiros sensíveis: {path}",
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
                        description=f"Reconhecimento automatizado / Web Vulnerability Scanner detetado ({path})",
                        raw_log=line,
                    )

        return None
