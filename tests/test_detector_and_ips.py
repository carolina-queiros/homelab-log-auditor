import csv
import io
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from engine.config import AuditorConfig
from engine.dashboard import DashboardServer, render_alerts_csv
from engine.detector import LogDetector, SecurityAlert
from engine.responder import FirewallResponder
from engine.storage import IncidentStore
from engine.tailer import LogTailer


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
        self.assertEqual(alert_sqli.rule_id, "WEB-SQLI-002")
        self.assertEqual(alert_sqli.severity, "CRITICAL")
        self.assertEqual(alert_lfi.rule_id, "WEB-LFI-003")

    def test_web_scanner_burst_detection(self):
        detector = LogDetector(brute_force_threshold=3, window_seconds=60)
        paths = ["/wp-login.php", "/.git/config", "/phpmyadmin"]
        alert = None
        for idx, p in enumerate(paths):
            line = f'198.51.100.77 - - [25/Nov/2026:14:00:0{idx} +0000] "GET {p} HTTP/1.1" 404 162'
            alert = detector.inspect_line(line, now=200.0 + idx)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_id, "WEB-SCAN-004")

    def test_custom_config_and_invalid_regex_filtering(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            cfg_path.write_text(json.dumps({
                "detection": {
                    "brute_force_threshold": 4,
                    "custom_rules": [
                        {"id": "CUSTOM-VPN-01", "severity": "HIGH", "pattern": r"openvpn.*TLS Error from (?P<ip>\d+\.\d+\.\d+\.\d+)", "description": "OpenVPN TLS failure"},
                        {"id": "BROKEN-REGEX", "pattern": "[unclosed"},
                        {"id": "MISSING-IP-GROUP", "pattern": r"sshd.*error"},
                    ],
                }
            }), encoding="utf-8")
            cfg = AuditorConfig.from_file(cfg_path)
            self.assertEqual(len(cfg.custom_rules), 1)
            detector = LogDetector(custom_rules=cfg.custom_rules)
            alert = detector.inspect_line("Nov 24 12:00:00 gw openvpn[512]: TLS Error from 203.0.113.42")
            self.assertEqual(alert.rule_id, "CUSTOM-VPN-01")

    def test_dynamic_rule_reload_without_restart(self):
        detector = LogDetector(brute_force_threshold=5, window_seconds=60)
        sample = "Nov 25 14:10:01 homelab sshd[1021]: Failed password for root from 203.0.113.88 port 2222 ssh2"
        self.assertIsNone(detector.inspect_line(sample, now=10.0))
        detector.update_rules(brute_force_threshold=2, window_seconds=60, custom_rules=())
        self.assertEqual(detector.inspect_line(sample, now=11.0).rule_id, "SSH-BRUTE-001")

    def test_whitelist_prevents_self_lockout(self):
        responder = FirewallResponder(dry_run=True, whitelist_cidrs=["192.168.1.0/24"])
        self.assertFalse(responder.block_ip("127.0.0.1", "test"))
        self.assertFalse(responder.block_ip("192.168.1.45", "test"))
        self.assertTrue(responder.block_ip("203.0.113.99", "malicious scan"))

    def test_sqlite_progressive_escalation_and_7day_cap(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = IncidentStore(db_path=str(Path(tmpdir) / "test.db"))
            self.assertEqual(store.register_ban("198.51.100.23", "SSH-BRUTE-001", base_ttl_seconds=100), 100)
            self.assertEqual(store.register_ban("198.51.100.23", "SSH-BRUTE-001", base_ttl_seconds=100), 400)
            self.assertEqual(store.register_ban("198.51.100.23", "SSH-BRUTE-001", base_ttl_seconds=100), 1600)
            for _ in range(6):
                capped = store.register_ban("198.51.100.23", "SSH-BRUTE-001", base_ttl_seconds=100)
            self.assertEqual(capped, 604800)
            store.remove_ban("198.51.100.23")
            self.assertFalse(store.is_banned("198.51.100.23"))

    def test_log_tailer_handles_truncation_and_rotation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "app.log"
            log_path.write_text("initial line\n", encoding="utf-8")
            seen = []
            tailer = LogTailer(file_paths=[str(log_path)], poll_interval=0.05)
            worker = threading.Thread(target=tailer.follow, kwargs={"on_line": lambda l, _: seen.append(l.strip()), "from_end": True}, daemon=True)
            worker.start()
            time.sleep(0.12)
            log_path.write_text("initial line\nafter append\n", encoding="utf-8")
            time.sleep(0.12)
            log_path.write_text("after truncate\n", encoding="utf-8")
            time.sleep(0.15)
            tailer.stop()
            worker.join(timeout=1.0)
            self.assertIn("after append", seen)
            self.assertIn("after truncate", seen)

    def test_forensic_csv_export_formatting(self):
        csv_text = render_alerts_csv([{"id": 1, "timestamp": 1732543200.0, "rule_id": "WEB-SQLI-002", "severity": "CRITICAL", "source_ip": "91.240.118.172", "description": "SQLi", "raw_log": "GET /"}])
        rows = list(csv.reader(io.StringIO(csv_text)))
        self.assertEqual(rows[1][2], "WEB-SQLI-002")

    def test_dashboard_api_security_headers_and_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = IncidentStore(db_path=str(Path(tmpdir) / "web.db"))
            store.record_alert(SecurityAlert(timestamp=time.time(), rule_id="WEB-SQLI-002", severity="CRITICAL", source_ip="91.240.118.172", description="SQLi", raw_log='<script>alert(1)</script>'))
            server = DashboardServer(store=store, responder=FirewallResponder(dry_run=True), host="127.0.0.1", port=0)
            server.start()
            port = server._server.server_address[1]
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/stats") as resp:
                    self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
                    self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/export?format=csv") as resp:
                    self.assertIn("WEB-SQLI-002", resp.read().decode("utf-8"))
                bad_req = urllib.request.Request(f"http://127.0.0.1:{port}/api/unban", data=json.dumps({"ip": "bad-ip"}).encode(), headers={"Content-Type": "application/json"}, method="POST")
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(bad_req)
                self.assertEqual(ctx.exception.code, 400)
            finally:
                server.stop()


if __name__ == "__main__":
    unittest.main()
