import ipaddress
import logging
import shutil
import subprocess
from typing import Iterable

logger = logging.getLogger("homelab-auditor.responder")

class FirewallResponder:
    """
    Módulo de resposta ativa (IPS) que aplica bloqueios dinâmicos no Linux
    via nftables (preferencial) ou iptables, com proteção contra auto-bloqueio.
    """

    DEFAULT_WHITELIST = ("127.0.0.0/8", "::1/128")

    def __init__(self, dry_run: bool = True, whitelist_cidrs: Iterable[str] = ()):
        self.dry_run = dry_run
        self.whitelist = [
            ipaddress.ip_network(cidr, strict=False)
            for cidr in (*self.DEFAULT_WHITELIST, *whitelist_cidrs)
        ]
        self.backend = self._detect_backend()

    def _detect_backend(self) -> str:
        if shutil.which("nft"):
            return "nftables"
        if shutil.which("iptables"):
            return "iptables"
        return "none"

    def is_whitelisted(self, ip_str: str) -> bool:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in self.whitelist)

    def _ensure_nft_table(self) -> None:
        subprocess.run(["nft", "add", "table", "inet", "homelab_ips"], check=False, capture_output=True)
        subprocess.run(
            ["nft", "add", "chain", "inet", "homelab_ips", "input", "{ type filter hook input priority 0 ; policy accept ; }"],
            check=False,
            capture_output=True,
        )

    def block_ip(self, ip: str, reason: str) -> bool:
        if self.is_whitelisted(ip):
            logger.warning(f"[WHITELIST] Bloqueio ignorado para IP protegido: {ip}")
            return False

        if self.dry_run:
            logger.info(f"[DRY-RUN][IPS] Bloqueio simulado aplicado a {ip} | Motivo: {reason}")
            return True

        try:
            if self.backend == "nftables":
                self._ensure_nft_table()
                subprocess.run(
                    ["nft", "add", "rule", "inet", "homelab_ips", "input", "saddr", ip, "drop"],
                    check=True,
                    capture_output=True,
                )
            elif self.backend == "iptables":
                subprocess.run(
                    ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                    check=True,
                    capture_output=True,
                )
            else:
                logger.error("Nenhum backend de firewall (nft/iptables) disponível neste sistema.")
                return False

            logger.warning(f"[IPS][{self.backend.upper()}] IP bloqueado na firewall: {ip} ({reason})")
            return True
        except subprocess.CalledProcessError as exc:
            logger.error(f"Falha ao aplicar regra de firewall para {ip}: {exc.stderr.decode().strip()}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        if self.dry_run:
            logger.info(f"[DRY-RUN][IPS] Expiração TTL — desbloqueio simulado para {ip}")
            return True

        try:
            if self.backend == "iptables":
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True)
            elif self.backend == "nftables":
                out = subprocess.check_output(["nft", "-a", "list", "chain", "inet", "homelab_ips", "input"], text=True)
                for line in out.splitlines():
                    if f"ip saddr {ip} drop" in line and "# handle " in line:
                        handle = line.split("# handle ")[1].strip()
                        subprocess.run(
                            ["nft", "delete", "rule", "inet", "homelab_ips", "input", "handle", handle],
                            check=True,
                            capture_output=True,
                        )
            logger.info(f"[IPS][{self.backend.upper()}] IP desbloqueado após expiração TTL: {ip}")
            return True
        except Exception as exc:
            logger.error(f"Erro ao desbloquear {ip}: {exc}")
            return False
