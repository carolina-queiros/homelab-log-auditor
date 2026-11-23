import tempfile
import unittest
from pathlib import Path

from engine.detector import LogDetector
from engine.responder import FirewallResponder
from engine.storage import IncidentStore


class TestMiniSIEM(unittest.TestCase):
    def test_ssh_brute_force_sliding_window(self):
        detector = LogDetector(brute_force_threshold=3, window_seconds=30)
        sample = "Nov 23 14:10:01 homelab sshd[1021]: Failed password for invalid user admin from 185.220.101.4 port 44122 ssh2"

        self.assertIsNone(detector.inspect_line(sample, now=100.0))
        self.assertIsNone(detector.inspect_line(sample, now=110.0))
        alert = detector.inspect_line(sample, now=120.0)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_id, "SSH-BRUTE-001")
        self.assertEqual(alert.source_ip, "185.220.101.4")

    def test_ssh_window_expiration_resets_counter(self):
        detector = LogDetector(brute_force_threshold=3, window_seconds=30)
        sample = "Nov 23 14:10:01 homelab sshd[1021]: Failed password for root from 45.33.32.156 port 51200 ssh2"

        self.assertIsNone(detector.inspect_line(sample, now=100.0))
        self.assertIsNone(detector.inspect_line(sample, now=110.0))
        # 50 segundos depois (> window de 30s), as duas primeiras tentativas já expiraram
        self.assertIsNone(detector.inspect_line(sample, now=150.0))

    def test_http_sqli_and_lfi_detection(self):
        detector = LogDetector()
        sqli_log = '91.240.118.172 - - [23/Nov/2026:15:02:11 +0000] "GET /login?user=admin%27%20OR%201=1-- HTTP/1.1" 200 512'
        lfi_log = '91.240.118.172 - - [23/Nov/2026:15:02:14 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 198'

        alert_sqli = detector.inspect_line(sqli_log)
        alert_lfi = detector.inspect_line(lfi_log)

        self.assertIsNotNone(alert_sqli)
        self.assertEqual(alert_sqli.rule_id, "WEB-SQLI-002")
        self.assertEqual(alert_sqli.severity, "CRITICAL")

        self.assertIsNotNone(alert_lfi)
        self.assertEqual(alert_lfi.rule_id, "WEB-LFI-003")

    def test_whitelist_prevents_self_lockout(self):
        responder = FirewallResponder(dry_run=True, whitelist_cidrs=["192.168.1.0/24"])
        self.assertFalse(responder.block_ip("127.0.0.1", "test"))
        self.assertFalse(responder.block_ip("192.168.1.45", "test"))
        self.assertTrue(responder.block_ip("203.0.113.99", "malicious scan"))

    def test_sqlite_ban_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "test.db"
            store = IncidentStore(db_path=str(db_file))

            store.register_ban("198.51.100.23", "SSH-BRUTE-001", ttl_seconds=60)
            self.assertTrue(store.is_banned("198.51.100.23"))

            expired = store.get_expired_bans(now=9999999999.0)
            self.assertIn("198.51.100.23", expired)
            store.remove_ban("198.51.100.23")
            self.assertFalse(store.is_banned("198.51.100.23"))


if __name__ == "__main__":
    unittest.main()
