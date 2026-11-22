#!/usr/bin/env python3
import argparse
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

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
    print("\n=== RELATÓRIO DE SEGURANÇA (HOMELAB MINI-SIEM) ===")
    print(f"Gerado em (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total de incidentes registados: {total_alerts}")
    print(f"Bloqueios IPS atualmente ativos: {active_bans}")
    print("\nTop IPs ofensores:")
    if not top_ips:
        print("  (nenhum incidente registado)")
    for ip, count in top_ips:
        print(f"  - {ip}: {count} alerta(s)")
    print("==================================================\n")

def main() -> int:
    parser = argparse.ArgumentParser(description="Homelab Log Auditor — Mini-SIEM & IPS em tempo real")
    parser.add_argument("--logs", nargs="+", default=["/var/log/auth.log", "/var/log/nginx/access.log"], help="Ficheiros de log a monitorizar")
    parser.add_argument("--db", default="auditor_state.db", help="Caminho para a base de dados SQLite")
    parser.add_argument("--threshold", type=int, default=5, help="Número de falhas até bloquear")
    parser.add_argument("--window", type=int, default=60, help="Janela temporal em segundos")
    parser.add_argument("--ban-ttl", type=int, default=3600, help="Duração do bloqueio IPS em segundos")
    parser.add_argument("--whitelist", nargs="*", default=[], help="CIDRs ou IPs protegidos contra bloqueio")
    parser.add_argument("--webhook", default=os.getenv("AUDITOR_WEBHOOK_URL"), help="URL de webhook Discord/Slack")
    parser.add_argument("--enforce", action="store_true", help="Aplica regras reais na firewall (sem esta flag corre em dry-run)")
    parser.add_argument("--from-start", action="store_true", help="Lê os logs desde o início em vez de apenas novas linhas")
    parser.add_argument("--report", action="store_true", help="Mostra o resumo estatístico da base de dados e sai")
    args = parser.parse_args()

    store = IncidentStore(db_path=args.db)
    if args.report:
        print_report(store)
        return 0

    detector = LogDetector(brute_force_threshold=args.threshold, window_seconds=args.window)
    responder = FirewallResponder(dry_run=not args.enforce, whitelist_cidrs=args.whitelist)
    notifier = WebhookNotifier(webhook_url=args.webhook)
    tailer = LogTailer(file_paths=args.logs)

    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    mode = "ENFORCE (FIREWALL ATIVA)" if args.enforce else "DRY-RUN (SIMULAÇÃO)"
    logger.info(f"A iniciar Homelab Log Auditor em modo {mode} | Backend: {responder.backend}")

    def handle_line(line: str, source: Path) -> None:
        alert = detector.inspect_line(line)
        if not alert:
            return

        store.record_alert(alert)
        logger.warning(f"[{alert.rule_id}] {alert.severity} | IP: {alert.source_ip} | {alert.description}")

        if store.is_banned(alert.source_ip):
            return

        if responder.block_ip(alert.source_ip, alert.description):
            store.register_ban(alert.source_ip, alert.rule_id, ttl_seconds=args.ban_ttl)
            notifier.send_alert(alert, f"Bloqueado por {args.ban_ttl}s ({responder.backend})")

    def cleanup_expired() -> None:
        for ip in store.get_expired_bans():
            if responder.unblock_ip(ip):
                store.remove_ban(ip)

    try:
        tailer.follow(on_line=handle_line, tick_callback=cleanup_expired, from_end=not args.from_start)
    except SystemExit:
        logger.info("A encerrar Homelab Log Auditor de forma limpa.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
