import ipaddress
import logging
import shutil
import subprocess

logger = logging.getLogger("homelab-auditor.ips")

class FirewallResponder:
    """
    Active Intrusion Prevention (IPS) module supporting Linux nftables (default)
    and iptables fallback, with CIDR whitelisting to prevent self-lockout.
    """

    def __init__(self, dry_run: bool = True, whitelist_cidrs: list[str] | None = None):
        self.dry_run = dry_run
        self.whitelist = [
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("::1/128"),
        ]
        for cidr in whitelist_cidrs or []:
            try:
                self.whitelist.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning(f"Invalid whitelist CIDR ignored: {cidr}")

        self.backend = self._detect_backend()

    def _detect_backend(self) -> str:
        if shutil.which("nft"):
            return "nftables"
        if shutil.which("iptables"):
            return "iptables"
        return "none"

    def is_whitelisted(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in self.whitelist)
        except ValueError:
            return True

    def block_ip(self, ip_str: str, reason: str) -> bool:
        if self.is_whitelisted(ip_str):
            logger.info(f"[WHITELIST] Block ignored for protected IP: {ip_str}")
            return False

        if self.dry_run or self.backend == "none":
            logger.warning(f"[DRY-RUN][IPS] Simulated block applied to {ip_str} | Reason: {reason}")
            return True

        try:
            if self.backend == "nftables":
                subprocess.run(["nft", "add", "table", "inet", "homelab_ips"], check=False)
                subprocess.run(
                    ["nft", "add", "chain", "inet", "homelab_ips", "input", "{ type filter hook input priority 0; }"],
                    check=False,
                )
                subprocess.run(
                    ["nft", "add", "rule", "inet", "homelab_ips", "input", "ip", "saddr", ip_str, "drop"],
                    check=True,
                )
            elif self.backend == "iptables":
                subprocess.run(["iptables", "-I", "INPUT", "-s", ip_str, "-j", "DROP"], check=True)

            logger.warning(f"[ENFORCE][IPS] IP {ip_str} blocked via {self.backend} | Reason: {reason}")
            return True
        except subprocess.CalledProcessError as exc:
            logger.error(f"Failed to execute firewall rule for {ip_str}: {exc}")
            return False

    def unblock_ip(self, ip_str: str) -> bool:
        if self.dry_run or self.backend == "none":
            logger.info(f"[DRY-RUN][IPS] Simulated unblock for expired ban: {ip_str}")
            return True

        try:
            if self.backend == "iptables":
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip_str, "-j", "DROP"], check=False)
            logger.info(f"[ENFORCE][IPS] IP {ip_str} unblocked after TTL expiration.")
            return True
        except subprocess.CalledProcessError as exc:
            logger.error(f"Failed to unblock IP {ip_str}: {exc}")
            return False
