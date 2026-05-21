"""
Vulnerability Checker Module — known CVE checks based on open ports and banners.
"""

from __future__ import annotations
import re
from typing import List, Dict, Tuple, Optional

from core.config import Config
from core.models import AuditResults, Finding, Severity
from utils.display import Console
from utils.logger import get_logger

logger = get_logger(__name__)

# Structured CVE/vulnerability knowledge base
# Format: (pattern_in_banner, port, cve_id, title, severity, description, recommendation)
VULN_SIGNATURES: List[Dict] = [
    {
        "port": 21,
        "banner_pattern": r"vsftpd 2\.[01]\.",
        "id": "VULN-CVE-2011-2523",
        "cve": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 Backdoor (CVE-2011-2523)",
        "severity": Severity.CRITICAL,
        "cvss": 10.0,
        "description": "vsftpd 2.3.4 contains a backdoor that opens a shell on port 6200 when a smiley face ':)' is appended to the username.",
        "recommendation": "Upgrade vsftpd immediately. Audit all FTP server installations.",
    },
    {
        "port": 22,
        "banner_pattern": r"OpenSSH[_ ]([1-6]\.|7\.[0-6])",
        "id": "VULN-OPENSSH-OLD",
        "cve": "CVE-2023-38408",
        "title": "Outdated OpenSSH Version Detected",
        "severity": Severity.HIGH,
        "cvss": 9.8,
        "description": "The detected OpenSSH version may be affected by multiple CVEs including remote code execution vulnerabilities (e.g. CVE-2023-38408, regreSSHion CVE-2024-6387).",
        "recommendation": "Upgrade to the latest OpenSSH release. Restrict SSH access via firewall.",
    },
    {
        "port": 80,
        "banner_pattern": r"Apache[/ ]([01]\.|2\.[0-3]\.)",
        "id": "VULN-APACHE-OLD",
        "cve": "CVE-2021-41773",
        "title": "Outdated Apache HTTP Server Detected",
        "severity": Severity.HIGH,
        "cvss": 9.8,
        "description": "The detected Apache version may be vulnerable to critical CVEs including path traversal and RCE (CVE-2021-41773, CVE-2021-42013).",
        "recommendation": "Upgrade Apache to the latest stable release immediately.",
    },
    {
        "port": 80,
        "banner_pattern": r"nginx[/ ](0\.|1\.[0-9]\.|1\.1[0-5]\.)",
        "id": "VULN-NGINX-OLD",
        "cve": "CVE-2021-23017",
        "title": "Outdated nginx Version Detected",
        "severity": Severity.MEDIUM,
        "cvss": 7.7,
        "description": "Older nginx versions are affected by DNS resolver off-by-one heap write (CVE-2021-23017) and other vulnerabilities.",
        "recommendation": "Upgrade to the latest stable nginx release.",
    },
    {
        "port": 3306,
        "banner_pattern": r".*",
        "id": "VULN-MYSQL-NOAUTH",
        "cve": None,
        "title": "MySQL Port Exposed Without Authentication Enforcement",
        "severity": Severity.HIGH,
        "cvss": 8.6,
        "description": "MySQL is directly accessible. Without proper authentication and network restrictions, unauthorized access is possible.",
        "recommendation": "Bind MySQL to 127.0.0.1. Use firewall rules. Enable require_secure_transport.",
    },
    {
        "port": 6379,
        "banner_pattern": r".*",
        "id": "VULN-REDIS-EXPOSED",
        "cve": "CVE-2022-0543",
        "title": "Redis Exposed — Likely Unauthenticated",
        "severity": Severity.CRITICAL,
        "cvss": 10.0,
        "description": "Redis is accessible on the network. Redis historically defaults to no authentication and can be exploited for RCE via config manipulation (CVE-2022-0543, CVE-2015-4335).",
        "recommendation": "Bind Redis to localhost. Enable requirepass. Disable dangerous commands.",
    },
    {
        "port": 9200,
        "banner_pattern": r".*",
        "id": "VULN-ES-EXPOSED",
        "cve": "CVE-2014-3120",
        "title": "Elasticsearch Exposed — No Authentication by Default",
        "severity": Severity.CRITICAL,
        "cvss": 9.0,
        "description": "Elasticsearch is accessible without authentication by default. Full data access and RCE via dynamic scripts are possible.",
        "recommendation": "Enable X-Pack security. Restrict access to trusted IPs only. Enable TLS.",
    },
    {
        "port": 27017,
        "banner_pattern": r".*",
        "id": "VULN-MONGO-EXPOSED",
        "cve": "CVE-2019-2386",
        "title": "MongoDB Exposed — Possibly Unauthenticated",
        "severity": Severity.CRITICAL,
        "cvss": 9.8,
        "description": "MongoDB is network-accessible. Versions without mandatory auth expose all databases to read/write access.",
        "recommendation": "Enable --auth flag. Use access control. Bind to localhost or VPN.",
    },
    {
        "port": 445,
        "banner_pattern": r".*",
        "id": "VULN-SMB-EXPOSED",
        "cve": "CVE-2017-0144",
        "title": "SMB Port Exposed — EternalBlue Risk",
        "severity": Severity.CRITICAL,
        "cvss": 9.3,
        "description": "SMB port 445 is exposed. MS17-010 (EternalBlue) remains one of the most exploited vulnerabilities used in ransomware campaigns (WannaCry, NotPetya).",
        "recommendation": "Block port 445 at perimeter firewall. Apply MS17-010 patch. Disable SMBv1.",
        "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144"],
    },
]


class Scanner:
    def __init__(self, config: Config):
        self.config = config
        self.host = config.target

    def run(self, results: AuditResults):
        Console.info(f"[*] Checking {len(results.open_ports)} open port(s) against vulnerability signatures...")

        checked = 0
        for sig in VULN_SIGNATURES:
            matching_ports = [p for p in results.open_ports if p.port == sig["port"]]
            for port in matching_ports:
                self._check_signature(sig, port, results)
                checked += 1

        Console.info(f"    [*] {checked} signature check(s) performed")

        # Generic checks
        self._check_default_credentials(results)

    def _check_signature(self, sig: Dict, port_info, results: AuditResults):
        banner = port_info.banner or ""
        pattern = sig.get("banner_pattern", ".*")

        if re.search(pattern, banner, re.IGNORECASE) or (not banner and sig["port"] in (3306, 6379, 9200, 27017, 445)):
            finding = Finding(
                id=sig["id"],
                title=sig["title"],
                severity=sig["severity"],
                module="vuln",
                description=sig["description"],
                evidence=f"Port {port_info.port} open. Banner: {banner[:100] or 'No banner captured'}",
                recommendation=sig["recommendation"],
                host=self.host,
                port=port_info.port,
                cvss_score=sig.get("cvss"),
                cve_ids=[sig["cve"]] if sig.get("cve") else [],
                tags=["cve", "known-vulnerability"],
                references=sig.get("references", []),
            )
            results.add_finding(finding)
            Console.finding(
                sig["severity"].value,
                sig["title"],
                f"CVE: {sig.get('cve', 'N/A')} | CVSS: {sig.get('cvss', 'N/A')}",
            )

    def _check_default_credentials(self, results: AuditResults):
        """Flag services commonly configured with default credentials."""
        default_cred_ports = {
            7001: ("WebLogic", "Default admin credentials (weblogic/weblogic) are frequently left unchanged."),
            5900: ("VNC", "VNC is often configured with weak or no passwords."),
            9200: ("Elasticsearch", "Elasticsearch open ports often lack authentication."),
        }
        for port_obj in results.open_ports:
            if port_obj.port in default_cred_ports:
                service, desc = default_cred_ports[port_obj.port]
                results.add_finding(Finding(
                    id=f"VULN-DEFAULTCRED-{port_obj.port}",
                    title=f"Possible Default Credentials: {service} on port {port_obj.port}",
                    severity=Severity.HIGH,
                    module="vuln",
                    description=desc,
                    evidence=f"Service {service} detected on port {port_obj.port}",
                    recommendation=f"Change default credentials on {service} immediately and restrict network access.",
                    host=self.host,
                    port=port_obj.port,
                    tags=["default-credentials", "authentication"],
                ))
                Console.finding("HIGH", f"Possible default credentials: {service}:{port_obj.port}")
