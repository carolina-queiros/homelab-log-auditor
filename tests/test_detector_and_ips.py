import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from engine.config import AuditorConfig
from engine.dashboard import DashboardServer
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

    def test_custom_config_and_invalid_regex_filtering(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "detection": {
                            "brute_force_threshold": 4,
                            "custom_rules": [
                                {
                                    "id": "CUSTOM-VPN-01",
                                    "severity": "HIGH",
                                    "pattern": r"openvpn.*TLS Error from (?P<ip>\d+\.\d+\.\d+\.\d+)",
                                    "description": "Falha TLS OpenVPN",
                                },
                                {
                                    "id": "BROKEN-REGEX",
                                    "pattern": "[unclosed",
                                },
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )
            cfg = AuditorConfig.from_file(cfg_path)
            self.assertEqual(cfg.brute_force_threshold, 4)
            self.assertEqual(len(cfg.custom_rules), 1)
            self.assertEqual(cfg.custom_rules[0].rule_id, "CUSTOM-VPN-01")

            detector = LogDetector(custom_rules=cfg.custom_rules)
            alert = detector.inspect_line("Nov 24 12:00:00 gw openvpn[512]: TLS Error from 203.0.113.42")
            self.assertIsNotNone(alert)
            self.assertEqual(alert.rule_id, "CUSTOM-VPN-01")
            self.assertEqual(alert.source_ip, "203.0.113.42")

    def test_whitelist_prevents_self_lockout(self):
        responder = FirewallResponder(dry_run=True, whitelist_cidrs=["192.168.1.0/24"])
        self.assertFalse(responder.block_ip("127.0.0.1", "test"))
        self.assertFalse(responder.block_ip("192.168.1.45", "test"))
        self.assertTrue(responder.block_ip("203.0.113.99", "malicious scan"))

    def test_sqlite_progressive_escalation_and_cap(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "test.db"
            store = IncidentStore(db_path=str(db_file))

            ttl1 = store.register_ban("198.51.100.23", "SSH-BRUTE-001", base_ttl_seconds=100)
            ttl2 = store.register_ban("198.51.100.23", "SSH-BRUTE-001", base_ttl_seconds=100)
            ttl3 = store.register_ban("198.51.100.23", "SSH-BRUTE-001", base_ttl_seconds=100)

            self.assertEqual(ttl1, 100)
            self.assertEqual(ttl2, 400)
            self.assertEqual(ttl3, 1600)
            self.assertTrue(store.is_banned("198.51.100.23"))

            expired = store.get_expired_bans(now=9999999999.0)
            self.assertIn("198.51.100.23", expired)
            store.remove_ban("198.51.100.23")
            self.assertFalse(store.is_banned("198.51.100.23"))

    def test_dashboard_api_endpoints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = IncidentStore(db_path=str(Path(tmpdir) / "web.db"))
            responder = FirewallResponder(dry_run=True)
            server = DashboardServer(store=store, responder=responder, host="127.0.0.1", port=0)
            server.start()
            port = server._server.server_address[1]
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/stats") as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(data["total_alerts"], 0)
                    self.assertEqual(data["active_bans"], 0)

                bad_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/unban",
                    data=json.dumps({"ip": "not-an-ip; rm -rf /"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(bad_req)
                self.assertEqual(ctx.exception.code, 400)
            finally:
                server.stop()


if __name__ == "__main__":
    unittest.main()
