#!/usr/bin/env python3
import argparse
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

from engine.config import AuditorConfig
from engine.dashboard import DashboardServer
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
    parser.add_argument("--config", default="config.json", help="Ficheiro de configuração JSON")
    parser.add_argument("--logs", nargs="+", help="Sobrepõe ficheiros de log a monitorizar")
    parser.add_argument("--db", help="Sobrepõe caminho para a base de dados SQLite")
    parser.add_argument("--threshold", type=int, help="Sobrepõe número de falhas até bloquear")
    parser.add_argument("--window", type=int, help="Sobrepõe janela temporal em segundos")
    parser.add_argument("--ban-ttl", type=int, help="Sobrepõe duração do bloqueio IPS em segundos")
    parser.add_argument("--whitelist", nargs="*", help="Sobrepõe CIDRs/IPs protegidos")
    parser.add_argument("--webhook", default=os.getenv("AUDITOR_WEBHOOK_URL"), help="URL de webhook Discord/Slack")
    parser.add_argument("--enforce", action="store_true", help="Ativa regras reais na firewall")
    parser.add_argument("--from-start", action="store_true", help="Lê os logs desde o início")
    parser.add_argument("--report", action="store_true", help="Mostra o resumo estatístico e sai")
    parser.add_argument("--web", action="store_true", help="Ativa o dashboard web e API REST")
    parser.add_argument("--web-port", type=int, default=8080, help="Porta do servidor web (default: 8080)")
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

    detector = LogDetector(
        brute_force_threshold=threshold,
        window_seconds=window,
        custom_rules=cfg.custom_rules,
    )
    responder = FirewallResponder(dry_run=not enforce, whitelist_cidrs=whitelist)
    notifier = WebhookNotifier(webhook_url=webhook_url or None)
    tailer = LogTailer(file_paths=log_files)
    dashboard = DashboardServer(store=store, responder=responder, port=args.web_port) if args.web else None
    if dashboard:
        dashboard.start()

    def reload_config(*_args) -> None:
        logger.info(f"Sinal SIGHUP recebido: a recarregar regras de '{args.config}'...")
        new_cfg = AuditorConfig.from_file(args.config)
        detector.update_rules(
            brute_force_threshold=args.threshold if args.threshold is not None else new_cfg.brute_force_threshold,
            window_seconds=args.window if args.window is not None else new_cfg.window_seconds,
            custom_rules=new_cfg.custom_rules,
        )
        logger.info(f"Configuração recarregada ({len(new_cfg.custom_rules)} regra(s) customizada(s) ativa(s)).")

    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, reload_config)

    mode = "ENFORCE (FIREWALL ATIVA)" if enforce else "DRY-RUN (SIMULAÇÃO)"
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
            applied_ttl = store.register_ban(alert.source_ip, alert.rule_id, base_ttl_seconds=ban_ttl)
            notifier.send_alert(alert, f"Bloqueado por {applied_ttl}s ({responder.backend})")

    def cleanup_expired() -> None:
        for ip in store.get_expired_bans():
            if responder.unblock_ip(ip):
                store.remove_ban(ip)

    try:
        tailer.follow(on_line=handle_line, tick_callback=cleanup_expired, from_end=not args.from_start)
    except SystemExit:
        if dashboard:
            dashboard.stop()
        logger.info("A encerrar Homelab Log Auditor de forma limpa.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
