"""
Port Scanner Module — concurrent TCP port scanning with service fingerprinting.
"""

from __future__ import annotations
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from core.config import Config
from core.models import AuditResults, OpenPort
from utils.display import Console
from utils.logger import get_logger
from utils.net import grab_banner, guess_service, resolve_host, is_cidr, expand_cidr

logger = get_logger(__name__)

# Ports that are HIGH risk when exposed to the internet
DANGEROUS_PORTS = {
    21: ("FTP Exposed", "FTP transmits credentials in plaintext. Prefer SFTP/FTPS."),
    23: ("Telnet Exposed", "Telnet is unencrypted. Replace with SSH immediately."),
    445: ("SMB Exposed", "SMB exposed to network. Restrict access — EternalBlue risk."),
    1433: ("MSSQL Exposed", "Database port exposed. Restrict to application servers only."),
    1521: ("Oracle DB Exposed", "Database port exposed. Restrict to application servers only."),
    3306: ("MySQL Exposed", "Database port directly accessible. Use a firewall rule."),
    3389: ("RDP Exposed", "RDP is a common ransomware vector. Restrict or use VPN."),
    5432: ("PostgreSQL Exposed", "Database port exposed. Restrict to application servers only."),
    5900: ("VNC Exposed", "VNC exposed. Often unencrypted and weakly authenticated."),
    6379: ("Redis Exposed", "Redis often runs with no authentication. Critical exposure."),
    9200: ("Elasticsearch Exposed", "Elasticsearch exposed. No auth by default — data leak risk."),
    27017: ("MongoDB Exposed", "MongoDB exposed. Frequently misconfigured without auth."),
    50070: ("Hadoop HDFS Exposed", "Hadoop HDFS web UI exposed. Data lake access risk."),
}


class Scanner:
    def __init__(self, config: Config):
        self.config = config
        self.host = resolve_host(config.target)
        if not self.host:
            self.host = config.target

    def run(self, results: AuditResults):
        hosts = expand_cidr(self.config.target) if is_cidr(self.config.target) else [self.host]

        for host in hosts:
            self._scan_host(host, results)

    def _scan_host(self, host: str, results: AuditResults):
        Console.info(f"[*] Scanning {host} ({len(self.config.ports)} ports)...")
        open_ports = self._concurrent_scan(host)

        Console.info(f"[+] {len(open_ports)} open port(s) found on {host}")
        Console.info(f"\n  {'PORT':<8}  {'STATE':<8}  {'SERVICE':<20}  BANNER")
        Console.separator()

        for op in sorted(open_ports, key=lambda x: x.port):
            Console.port(op.port, op.state, op.service, op.banner)
            results.open_ports.append(op)

        # Generate findings for dangerous exposed ports
        self._analyze_ports(open_ports, results, host)

    def _scan_port(self, host: str, port: int) -> OpenPort | None:
        if self.config.rate_limit > 0:
            time.sleep(self.config.rate_limit)
        try:
            with socket.create_connection((host, port), timeout=self.config.timeout):
                service = guess_service(port)
                banner = grab_banner(host, port, timeout=self.config.timeout)
                return OpenPort(
                    port=port,
                    protocol="tcp",
                    state="open",
                    service=service,
                    banner=banner[:100] if banner else "",
                )
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _concurrent_scan(self, host: str) -> List[OpenPort]:
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {
                executor.submit(self._scan_port, host, port): port
                for port in self.config.ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        return open_ports

    def _analyze_ports(self, open_ports: List[OpenPort], results: AuditResults, host: str):
        from core.models import Finding, Severity

        for op in open_ports:
            if op.port in DANGEROUS_PORTS:
                title, desc = DANGEROUS_PORTS[op.port]
                sev = Severity.HIGH if op.port not in (21, 5900) else Severity.CRITICAL
                if op.port == 23:
                    sev = Severity.CRITICAL
                results.add_finding(Finding(
                    id=f"PORT-{op.port}",
                    title=title,
                    severity=sev,
                    module="ports",
                    description=desc,
                    evidence=f"Port {op.port}/tcp open on {host}. Banner: {op.banner[:80] or 'N/A'}",
                    recommendation=f"Firewall port {op.port} from external access. Require VPN or restrict to trusted CIDRs.",
                    host=host,
                    port=op.port,
                    tags=["network-exposure", "firewall"],
                ))
