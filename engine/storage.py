import sqlite3
import time
from pathlib import Path
from typing import List, Tuple
from engine.detector import SecurityAlert

class IncidentStore:
    """
    Persistência local em SQLite para histórico de alertas SIEM, controlo
    de bloqueios ativos (IPS) e histórico de reincidência (escalation).
    """

    def __init__(self, db_path: str = "auditor_state.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    description TEXT NOT NULL,
                    raw_log TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS active_bans (
                    ip TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    banned_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ban_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    banned_at REAL NOT NULL,
                    ttl_applied INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip);
                CREATE INDEX IF NOT EXISTS idx_bans_exp ON active_bans(expires_at);
                CREATE INDEX IF NOT EXISTS idx_history_ip ON ban_history(ip);
                """
            )

    def record_alert(self, alert: SecurityAlert) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alerts (timestamp, rule_id, severity, source_ip, description, raw_log)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (alert.timestamp, alert.rule_id, alert.severity, alert.source_ip, alert.description, alert.raw_log),
            )

    def is_banned(self, ip: str, now: float | None = None) -> bool:
        now = now or time.time()
        with self._connect() as conn:
            row = conn.execute("SELECT expires_at FROM active_bans WHERE ip = ?", (ip,)).fetchone()
            return bool(row and row[0] > now)

    def get_offense_count(self, ip: str) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM ban_history WHERE ip = ?", (ip,)).fetchone()
            return int(row[0]) if row else 0

    MAX_BAN_TTL_SECONDS = 604800  # Teto máximo de 7 dias

    def register_ban(self, ip: str, reason: str, base_ttl_seconds: int = 3600) -> int:
        now = time.time()
        with self._connect() as conn:
            prior_offenses = conn.execute("SELECT COUNT(*) FROM ban_history WHERE ip = ?", (ip,)).fetchone()[0]
            escalated_ttl = min(base_ttl_seconds * (4 ** prior_offenses), self.MAX_BAN_TTL_SECONDS)
            conn.execute(
                "INSERT INTO ban_history (ip, reason, banned_at, ttl_applied) VALUES (?, ?, ?, ?)",
                (ip, reason, now, escalated_ttl),
            )

            conn.execute(
                """
                INSERT INTO active_bans (ip, reason, banned_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    reason = excluded.reason,
                    banned_at = excluded.banned_at,
                    expires_at = excluded.expires_at
                """,
                (ip, reason, now, now + escalated_ttl),
            )
        return escalated_ttl

    def get_expired_bans(self, now: float | None = None) -> List[str]:
        now = now or time.time()
        with self._connect() as conn:
            rows = conn.execute("SELECT ip FROM active_bans WHERE expires_at <= ?", (now,)).fetchall()
            return [r[0] for r in rows]

    def remove_ban(self, ip: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM active_bans WHERE ip = ?", (ip,))

    def get_summary_stats(self) -> Tuple[int, int, List[Tuple[str, int]]]:
        with self._connect() as conn:
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            active_bans = conn.execute("SELECT COUNT(*) FROM active_bans WHERE expires_at > ?", (time.time(),)).fetchone()[0]
            top_ips = conn.execute(
                "SELECT source_ip, COUNT(*) as cnt FROM alerts GROUP BY source_ip ORDER BY cnt DESC LIMIT 5"
            ).fetchall()
            return total_alerts, active_bans, top_ips
