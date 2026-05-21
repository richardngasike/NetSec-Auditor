"""
SSH Auditor Module — checks SSH configuration, cipher suites, authentication policies.
"""

from __future__ import annotations
import socket
import re
from typing import List, Optional

from core.config import Config
from core.models import AuditResults, Finding, Severity
from utils.display import Console
from utils.logger import get_logger

logger = get_logger(__name__)

WEAK_KEX = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "gss-gex-sha1-", "gss-group1-sha1-"]
WEAK_MACS = ["hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com"]
WEAK_CIPHERS = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "blowfish-cbc", "cast128-cbc"]
SAFE_VERSION_REGEX = re.compile(r"OpenSSH[_ ](\d+)\.(\d+)", re.IGNORECASE)


class Scanner:
    def __init__(self, config: Config):
        self.config = config
        self.host = config.target

    def run(self, results: AuditResults):
        ssh_ports = [p for p in results.open_ports if p.service == "ssh" or p.port == 22]

        if not ssh_ports:
            Console.warning("    [-] No SSH ports detected — skipping SSH audit")
            return

        for port in ssh_ports:
            Console.info(f"[*] Auditing SSH on port {port.port}...")
            banner = self._get_ssh_banner(port.port)
            kex_data = self._get_kex_algorithms(port.port)

            self._check_version(banner, port.port, results)
            if kex_data:
                self._check_kex(kex_data, port.port, results)

    def _get_ssh_banner(self, port: int) -> str:
        try:
            with socket.create_connection((self.host, port), timeout=self.config.timeout) as s:
                banner = s.recv(256).decode("utf-8", errors="replace").strip()
                return banner
        except Exception as e:
            logger.debug(f"Failed to get SSH banner on port {port}: {e}")
            return ""

    def _get_kex_algorithms(self, port: int) -> Optional[bytes]:
        """Grab the raw SSH handshake to extract algorithm lists."""
        try:
            with socket.create_connection((self.host, port), timeout=self.config.timeout) as s:
                s.recv(256)  # read banner
                s.sendall(b"SSH-2.0-NetSecAuditor_1.0\r\n")
                data = s.recv(4096)
                return data
        except Exception as e:
            logger.debug(f"Failed to get SSH KEX on port {port}: {e}")
            return None

    def _check_version(self, banner: str, port: int, results: AuditResults):
        if not banner:
            return

        Console.success(f"    [+] SSH Banner: {banner[:80]}")

        match = SAFE_VERSION_REGEX.search(banner)
        if match:
            major, minor = int(match.group(1)), int(match.group(2))
            # Flag OpenSSH < 8.0 as potentially outdated
            if major < 8:
                results.add_finding(Finding(
                    id=f"SSH-OLDVERSION-{port}",
                    title=f"Outdated OpenSSH Version: {major}.{minor}",
                    severity=Severity.MEDIUM,
                    module="ssh",
                    description=f"OpenSSH {major}.{minor} may be missing security patches. Recent CVEs affect versions below 9.x.",
                    evidence=f"Banner: {banner}",
                    recommendation="Upgrade to the latest OpenSSH version. Enable automatic security updates.",
                    host=self.host,
                    port=port,
                    cve_ids=["CVE-2023-38408", "CVE-2024-6387"],
                    tags=["ssh", "version", "outdated"],
                ))
                Console.finding("MEDIUM", f"Outdated OpenSSH {major}.{minor}")
            else:
                Console.success(f"    [+] OpenSSH version {major}.{minor} is reasonably current")

        # Protocol version check
        if "SSH-1." in banner:
            results.add_finding(Finding(
                id=f"SSH-PROTO-V1-{port}",
                title="SSH Protocol Version 1 Supported",
                severity=Severity.CRITICAL,
                module="ssh",
                description="SSHv1 is cryptographically broken and vulnerable to multiple attacks including man-in-the-middle.",
                evidence=f"Banner indicates SSHv1: {banner}",
                recommendation="Disable SSHv1 immediately. Set 'Protocol 2' in sshd_config.",
                host=self.host,
                port=port,
                tags=["ssh", "protocol", "deprecated"],
            ))
            Console.finding("CRITICAL", "SSHv1 detected — cryptographically broken!")

    def _check_kex(self, data: bytes, port: int, results: AuditResults):
        """Parse KEX_INIT packet to detect weak algorithms."""
        try:
            data_str = data.decode("latin-1", errors="replace")
        except Exception:
            return

        weak_found = {
            "kex": [k for k in WEAK_KEX if k in data_str],
            "cipher": [c for c in WEAK_CIPHERS if c in data_str],
            "mac": [m for m in WEAK_MACS if m in data_str],
        }

        for algo_type, algos in weak_found.items():
            if algos:
                severity = Severity.HIGH if algo_type == "kex" else Severity.MEDIUM
                results.add_finding(Finding(
                    id=f"SSH-WEAK-{algo_type.upper()}-{port}",
                    title=f"Weak SSH {algo_type.upper()} Algorithm(s): {', '.join(algos[:3])}",
                    severity=severity,
                    module="ssh",
                    description=f"Weak {algo_type} algorithms are offered during SSH handshake, enabling downgrade attacks.",
                    evidence=f"Offered algorithms: {', '.join(algos)}",
                    recommendation=f"Remove weak {algo_type} algorithms from sshd_config. Use only modern, secure options.",
                    host=self.host,
                    port=port,
                    tags=["ssh", "cipher", "weak-algorithm"],
                ))
                Console.finding(severity.value, f"Weak SSH {algo_type}: {', '.join(algos[:3])}")

        if not any(weak_found.values()):
            Console.success("    [+] No weak SSH algorithms detected in KEX")
