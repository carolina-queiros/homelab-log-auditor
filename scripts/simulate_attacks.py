#!/usr/bin/env python3
import argparse
import time
from datetime import datetime, timezone
from pathlib import Path

def main() -> int:
    parser = argparse.ArgumentParser(description="Simulate security events into auth and HTTP access logs")
    parser.add_argument("--auth-log", default="/tmp/sim_logs/auth.log", help="Target auth.log path")
    parser.add_argument("--access-log", default="/tmp/sim_logs/access.log", help="Target HTTP access.log path")
    parser.add_argument("--delay", type=float, default=0.15, help="Delay between injected events in seconds")
    args = parser.parse_args()

    auth_path = Path(args.auth_log)
    access_path = Path(args.access_log)
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    access_path.parent.mkdir(parents=True, exist_ok=True)
    auth_path.touch(exist_ok=True)
    access_path.touch(exist_ok=True)

    now_syslog = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    now_clf = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")

    auth_events = [
        f"{now_syslog} homelab sshd[1101]: Failed password for ops from 192.168.1.50 port 51200 ssh2",
        f"{now_syslog} homelab sshd[1102]: Failed password for invalid user admin from 185.220.101.4 port 44120 ssh2",
        f"{now_syslog} homelab sshd[1103]: Failed password for invalid user root from 185.220.101.4 port 44121 ssh2",
        f"{now_syslog} homelab sshd[1104]: Failed password for invalid user ubuntu from 185.220.101.4 port 44122 ssh2",
        f"{now_syslog} homelab sshd[1105]: Failed password for invalid user deploy from 185.220.101.4 port 44123 ssh2",
        f"{now_syslog} homelab sshd[1106]: Failed password for invalid user postgres from 185.220.101.4 port 44124 ssh2",
    ]

    http_events = [
        f'203.0.113.10 - - [{now_clf}] "GET /index.html HTTP/1.1" 200 2048',
        f'91.240.118.172 - - [{now_clf}] "GET /login?user=admin%27%20OR%201=1-- HTTP/1.1" 200 512',
        f'45.155.205.88 - - [{now_clf}] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 198',
        f'198.51.100.77 - - [{now_clf}] "GET /wp-login.php HTTP/1.1" 404 162',
        f'198.51.100.77 - - [{now_clf}] "GET /.git/config HTTP/1.1" 404 162',
        f'198.51.100.77 - - [{now_clf}] "GET /phpmyadmin HTTP/1.1" 404 162',
        f'198.51.100.77 - - [{now_clf}] "GET /xmlrpc.php HTTP/1.1" 404 162',
        f'198.51.100.77 - - [{now_clf}] "GET /wp-admin HTTP/1.1" 404 162',
    ]

    with auth_path.open("a", encoding="utf-8") as fh:
        for line in auth_events:
            fh.write(line + "\n")
            fh.flush()
            time.sleep(args.delay)

    with access_path.open("a", encoding="utf-8") as fh:
        for line in http_events:
            fh.write(line + "\n")
            fh.flush()
            time.sleep(args.delay)

    print("[+] Attack simulation completed.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
