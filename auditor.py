#!/usr/bin/env python3
import argparse
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

from engine.config import AuditorConfig
from engine.dashboard import DashboardServer, render_alerts_csv
from engine.detector import LogDetector
from engine.notifier import WebhookNotifier
from engine.responder import FirewallResponder
from engine.storage import IncidentStore
from engine.tailer import LogTailer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("homelab-auditor")

def print_report(store: IncidentStore) -> None:
    total_alerts, active_bans, top_ips = store.get_summary_stats()
    print("\n=== SECURITY INCIDENT REPORT (HOMELAB MINI-SIEM) ===")
    print(f"Generated at (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total recorded alerts: {total_alerts}")
    print(f"Currently active IPS bans: {active_bans}")
    print("\nTop Offending Source IPs:")
    if not top_ips:
        print("  (no incidents recorded)")
    for ip, count in top_ips:
        print(f"  - {ip}: {count} alert(s)")
    print("====================================================\n")

def main() -> int:
    parser = argparse.ArgumentParser(description="Homelab Log Auditor — Real-time Mini-SIEM & Active IPS")
    parser.add_argument("--config", default="config.json", help="Path to JSON configuration file")
    parser.add_argument("--logs", nargs="+", help="Override log file paths to monitor")
    parser.add_argument("--db", help="Override SQLite database path")
    parser.add_argument("--threshold", type=int, help="Override brute-force failure threshold")
    parser.add_argument("--window", type=int, help="Override sliding window in seconds")
    parser.add_argument("--ban-ttl", type=int, help="Override base IPS ban TTL in seconds")
    parser.add_argument("--whitelist", nargs="*", help="Override protected CIDR/IP list")
    parser.add_argument("--webhook", default=os.getenv("AUDITOR_WEBHOOK_URL"), help="Discord/Slack webhook URL")
    parser.add_argument("--enforce", action="store_true", help="Enable active firewall enforcement (nftables/iptables)")
    parser.add_argument("--from-start", action="store_true", help="Process existing log files from beginning")
    parser.add_argument("--report", action="store_true", help="Print summary security report and exit")
    parser.add_argument("--export-csv", help="Export recorded alerts to a CSV file and exit")
    parser.add_argument("--export-json", help="Export recorded alerts to a JSON file and exit")
    parser.add_argument("--web", action="store_true", help="Start real-time Web Dashboard and REST API")
    parser.add_argument("--web-port", type=int, default=8080, help="HTTP port for Web Dashboard (default: 8080)")
    parser.add_argument("--api-key", default=os.getenv("AUDITOR_API_KEY"), help="Optional API key required for /api/unban and /api/export")
    args = parser.parse_args()

    cfg = AuditorConfig.from_file(args.config)
    log_files = args.logs or cfg.log_files
    db_path = args.db or cfg.database_path
    threshold = args.threshold if args.threshold is not None else cfg.brute_force_threshold
    window = args.window if args.window is not None else cfg.window_seconds
    ban_ttl = args.ban_ttl if args.ban_ttl is not None else cfg.ban_ttl_seconds
    whitelist = args.whitelist if args.whitelist is not None else cfg.whitelist
    webhook_url = args.webhook or cfg.webhook_url
    enforce = args.enforce or cfg.enforce

    store = IncidentStore(db_path=db_path)
    if args.report:
        print_report(store)
        return 0

    if args.export_csv:
        alerts = store.get_recent_alerts(limit=10000)
        Path(args.export_csv).write_text(render_alerts_csv(alerts), encoding="utf-8")
        logger.info(f"Exported {len(alerts)} alert(s) to CSV: {args.export_csv}")
        return 0

    if args.export_json:
        alerts = store.get_recent_alerts(limit=10000)
        Path(args.export_json).write_text(json.dumps(alerts, indent=2), encoding="utf-8")
        logger.info(f"Exported {len(alerts)} alert(s) to JSON: {args.export_json}")
        return 0

    detector = LogDetector(
        brute_force_threshold=threshold,
        window_seconds=window,
        custom_rules=cfg.custom_rules,
    )
    responder = FirewallResponder(dry_run=not enforce, whitelist_cidrs=whitelist)
    notifier = WebhookNotifier(webhook_url=webhook_url or None)
    tailer = LogTailer(file_paths=log_files)
    dashboard = DashboardServer(store=store, responder=responder, port=args.web_port, api_key=args.api_key or None) if args.web else None
    if dashboard:
        dashboard.start()

    def reload_config(*_args) -> None:
        logger.info(f"SIGHUP received: reloading rules from '{args.config}'...")
        new_cfg = AuditorConfig.from_file(args.config)
        detector.update_rules(
            brute_force_threshold=args.threshold if args.threshold is not None else new_cfg.brute_force_threshold,
            window_seconds=args.window if args.window is not None else new_cfg.window_seconds,
            custom_rules=new_cfg.custom_rules,
        )
        logger.info(f"Configuration reloaded ({len(new_cfg.custom_rules)} custom rule(s) active).")

    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, reload_config)

    mode = "ENFORCE (ACTIVE FIREWALL)" if enforce else "DRY-RUN (SIMULATION)"
    logger.info(f"Starting Homelab Log Auditor in {mode} mode | Backend: {responder.backend}")

    def handle_line(line: str, source: Path) -> None:
        alert = detector.inspect_line(line)
        if not alert:
            return

        store.record_alert(alert)
        logger.warning(f"[{alert.rule_id}] {alert.severity} | IP: {alert.source_ip} | {alert.description}")

        if store.is_banned(alert.source_ip):
            return

        if responder.block_ip(alert.source_ip, alert.description):
            applied_ttl = store.register_ban(alert.source_ip, alert.rule_id, base_ttl_seconds=ban_ttl)
            notifier.send_alert(alert, f"Blocked for {applied_ttl}s ({responder.backend})")

    def cleanup_expired() -> None:
        for ip in store.get_expired_bans():
            if responder.unblock_ip(ip):
                store.remove_ban(ip)

    try:
        tailer.follow(on_line=handle_line, tick_callback=cleanup_expired, from_end=not args.from_start)
    except SystemExit:
        if dashboard:
            dashboard.stop()
        logger.info("Shutting down Homelab Log Auditor cleanly.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
