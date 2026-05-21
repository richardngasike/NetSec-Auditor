"""
DNS Enumerator Module — zone transfer, common record checks, misconfiguration detection.
"""

from __future__ import annotations
import socket
import subprocess
import shutil
from typing import List, Dict

from core.config import Config
from core.models import AuditResults, Finding, Severity
from utils.display import Console
from utils.logger import get_logger

logger = get_logger(__name__)

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "vpn", "remote", "git", "ci", "jenkins", "jira", "confluence",
    "smtp", "pop", "imap", "ns1", "ns2", "mx", "webmail",
]


class Scanner:
    def __init__(self, config: Config):
        self.config = config
        self.target = config.target

    def run(self, results: AuditResults):
        # Skip if target is an IP
        try:
            socket.inet_aton(self.target)
            Console.warning("    [-] Target is an IP address — skipping DNS enumeration")
            return
        except socket.error:
            pass

        Console.info(f"[*] DNS enumeration for {self.target}...")

        self._check_zone_transfer(results)
        self._enumerate_subdomains(results)
        self._check_dns_records(results)

    def _check_zone_transfer(self, results: AuditResults):
        """Attempt zone transfer (AXFR) — a critical misconfiguration if successful."""
        if not shutil.which("dig"):
            logger.debug("dig not available — skipping zone transfer check")
            return

        try:
            # Get nameservers
            ns_result = subprocess.run(
                ["dig", "+short", "NS", self.target],
                capture_output=True, text=True, timeout=10,
            )
            nameservers = [ns.rstrip(".") for ns in ns_result.stdout.strip().splitlines() if ns]

            for ns in nameservers[:3]:  # Only try first 3 NS
                axfr_result = subprocess.run(
                    ["dig", f"@{ns}", "AXFR", self.target],
                    capture_output=True, text=True, timeout=10,
                )
                if "Transfer failed" not in axfr_result.stdout and len(axfr_result.stdout) > 200:
                    results.add_finding(Finding(
                        id="DNS-ZONE-TRANSFER",
                        title="DNS Zone Transfer Allowed (AXFR)",
                        severity=Severity.CRITICAL,
                        module="dns",
                        description="The nameserver allows unauthenticated zone transfers, exposing the entire DNS zone including internal hostnames, IPs, and infrastructure layout.",
                        evidence=f"Zone transfer succeeded from nameserver: {ns}",
                        recommendation="Restrict AXFR transfers to authorized secondary nameservers only via ACLs.",
                        host=self.target,
                        references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0532"],
                        tags=["dns", "zone-transfer", "information-disclosure"],
                    ))
                    Console.finding("CRITICAL", f"Zone transfer ALLOWED from {ns}")
                    return
            Console.success("    [+] Zone transfers restricted (AXFR denied)")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"Zone transfer check failed: {e}")

    def _enumerate_subdomains(self, results: AuditResults):
        found = []
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append((fqdn, ip))
                Console.info(f"    [+] Subdomain: {fqdn} → {ip}")
            except socket.gaierror:
                pass

        if found:
            results.metadata["subdomains"] = [{"name": f, "ip": ip} for f, ip in found]
            results.add_finding(Finding(
                id="DNS-SUBDOMAINS",
                title=f"{len(found)} Subdomains Discovered",
                severity=Severity.INFO,
                module="dns",
                description="Active subdomains were discovered. Review each for unintended exposure.",
                evidence="\n".join([f"{f} → {ip}" for f, ip in found]),
                recommendation="Ensure all discovered subdomains are intentional and secured. Remove stale entries.",
                host=self.target,
                tags=["dns", "recon", "subdomains"],
            ))
        else:
            Console.info("    [-] No common subdomains resolved")

    def _check_dns_records(self, results: AuditResults):
        """Check for SPF, DMARC, DKIM — email spoofing mitigations."""
        if not shutil.which("dig"):
            return

        # SPF check
        spf = self._dig_txt(f"{self.target}")
        has_spf = any("v=spf1" in r for r in spf)
        if not has_spf:
            results.add_finding(Finding(
                id="DNS-NO-SPF",
                title="Missing SPF Record",
                severity=Severity.MEDIUM,
                module="dns",
                description="No SPF record found. Attackers can send emails spoofed as your domain.",
                evidence=f"No TXT record with v=spf1 found for {self.target}",
                recommendation='Add a TXT record: "v=spf1 include:mail.example.com ~all"',
                host=self.target,
                tags=["dns", "email", "spf", "spoofing"],
            ))
            Console.finding("MEDIUM", "Missing SPF record — email spoofing risk")
        else:
            Console.success(f"    [+] SPF record present")

        # DMARC check
        dmarc = self._dig_txt(f"_dmarc.{self.target}")
        has_dmarc = any("v=DMARC1" in r for r in dmarc)
        if not has_dmarc:
            results.add_finding(Finding(
                id="DNS-NO-DMARC",
                title="Missing DMARC Record",
                severity=Severity.MEDIUM,
                module="dns",
                description="No DMARC record found. Without DMARC, SPF/DKIM failures are not reported or enforced.",
                evidence=f"No TXT record found at _dmarc.{self.target}",
                recommendation='Add: _dmarc TXT "v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com"',
                host=self.target,
                tags=["dns", "email", "dmarc"],
            ))
            Console.finding("MEDIUM", "Missing DMARC record")
        else:
            Console.success(f"    [+] DMARC record present")

    def _dig_txt(self, name: str) -> List[str]:
        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", name],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip().splitlines()
        except Exception:
            return []
