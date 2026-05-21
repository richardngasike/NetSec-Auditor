"""
SSL/TLS Analyzer Module — certificate validation, cipher analysis, protocol checks.
"""

from __future__ import annotations
import ssl
import socket
import datetime
from typing import Dict, Any, List, Optional

from core.config import Config
from core.models import AuditResults, Finding, Severity
from utils.display import Console
from utils.logger import get_logger
from utils.net import resolve_host

logger = get_logger(__name__)

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS_KEYWORDS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5"]
RECOMMENDED_MIN_KEY_SIZE = 2048


class Scanner:
    def __init__(self, config: Config):
        self.config = config
        self.host = resolve_host(config.target) or config.target
        self.hostname = config.target  # for SNI

    def run(self, results: AuditResults):
        ssl_ports = [p for p in results.open_ports if p.service in ("https", "https-alt", "imaps", "smtps") or p.port in (443, 8443, 465, 993, 995)]

        if not ssl_ports:
            # Try 443 regardless
            ssl_ports_to_try = [443]
        else:
            ssl_ports_to_try = [p.port for p in ssl_ports]

        for port in ssl_ports_to_try:
            Console.info(f"[*] Analyzing SSL/TLS on {self.hostname}:{port}...")
            self._analyze(port, results)

    def _analyze(self, port: int, results: AuditResults):
        cert_info = self._get_certificate(port)
        if not cert_info:
            Console.warning(f"    [-] Could not retrieve SSL certificate on port {port}")
            return

        self._check_certificate(cert_info, port, results)
        self._check_protocols(port, results)
        self._check_ciphers(port, results)

        Console.success(f"    [+] SSL analysis complete for port {port}")

    def _get_certificate(self, port: int) -> Optional[Dict[str, Any]]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.host, port), timeout=self.config.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return {
                        "cert": cert,
                        "cipher_name": cipher[0] if cipher else "unknown",
                        "cipher_bits": cipher[2] if cipher else 0,
                        "protocol_version": version,
                    }
        except Exception as e:
            logger.debug(f"SSL cert retrieval failed on {self.host}:{port}: {e}")
            return None

    def _check_certificate(self, info: Dict, port: int, results: AuditResults):
        cert = info.get("cert", {})

        # Check expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_left = (not_after - now).days

                if days_left < 0:
                    results.add_finding(Finding(
                        id=f"SSL-EXPIRED-{port}",
                        title="SSL Certificate Expired",
                        severity=Severity.CRITICAL,
                        module="ssl",
                        description=f"The SSL certificate expired {abs(days_left)} days ago.",
                        evidence=f"Certificate expired: {not_after_str}",
                        recommendation="Renew the SSL certificate immediately. Consider using Let's Encrypt for auto-renewal.",
                        host=self.host, port=port,
                        tags=["ssl", "certificate", "expired"],
                    ))
                    Console.finding("CRITICAL", f"Certificate EXPIRED ({abs(days_left)}d ago)", not_after_str)
                elif days_left < 30:
                    sev = Severity.HIGH if days_left < 7 else Severity.MEDIUM
                    results.add_finding(Finding(
                        id=f"SSL-EXPIRING-{port}",
                        title=f"SSL Certificate Expiring Soon ({days_left} days)",
                        severity=sev,
                        module="ssl",
                        description=f"The SSL certificate will expire in {days_left} days.",
                        evidence=f"Expiry: {not_after_str}",
                        recommendation="Renew before expiry to avoid service disruption and browser warnings.",
                        host=self.host, port=port,
                        tags=["ssl", "certificate"],
                    ))
                    Console.finding(sev.value, f"Certificate expiring in {days_left} days", not_after_str)
                else:
                    Console.success(f"    [+] Certificate valid — expires in {days_left} days ({not_after_str})")
            except ValueError:
                pass

        # Check self-signed (issuer == subject)
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        if subject == issuer:
            results.add_finding(Finding(
                id=f"SSL-SELFSIGNED-{port}",
                title="Self-Signed SSL Certificate",
                severity=Severity.MEDIUM,
                module="ssl",
                description="The certificate is self-signed and will not be trusted by browsers.",
                evidence=f"Subject: {subject}. Issuer: {issuer}",
                recommendation="Replace with a certificate from a trusted CA (e.g., Let's Encrypt, DigiCert).",
                host=self.host, port=port,
                tags=["ssl", "certificate"],
            ))
            Console.finding("MEDIUM", "Self-signed certificate detected")

    def _check_protocols(self, port: int, results: AuditResults):
        """Check for support of deprecated TLS versions."""
        weak_supported = []

        for proto_name, proto_const in [
            ("TLSv1", ssl.TLSVersion.TLSv1) if hasattr(ssl.TLSVersion, "TLSv1") else (None, None),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1) if hasattr(ssl.TLSVersion, "TLSv1_1") else (None, None),
        ]:
            if proto_name is None:
                continue
            if self._test_protocol(port, proto_const):
                weak_supported.append(proto_name)

        if weak_supported:
            results.add_finding(Finding(
                id=f"SSL-WEAKPROTO-{port}",
                title=f"Deprecated TLS Protocol(s) Supported: {', '.join(weak_supported)}",
                severity=Severity.HIGH,
                module="ssl",
                description="Deprecated TLS versions are vulnerable to POODLE, BEAST, and downgrade attacks.",
                evidence=f"Supported: {', '.join(weak_supported)}",
                recommendation="Disable TLS 1.0 and 1.1. Enforce TLS 1.2 minimum; prefer TLS 1.3.",
                host=self.host, port=port,
                tags=["ssl", "protocol", "downgrade"],
                references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566"],
            ))
            Console.finding("HIGH", f"Weak TLS protocols supported: {', '.join(weak_supported)}")
        else:
            Console.success(f"    [+] No deprecated TLS protocols detected")

    def _test_protocol(self, port: int, version) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((self.host, port), timeout=self.config.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=self.hostname):
                    return True
        except Exception:
            return False

    def _check_ciphers(self, port: int, results: AuditResults):
        info = self._get_certificate(port)
        if not info:
            return
        cipher_name = info.get("cipher_name", "")
        cipher_bits = info.get("cipher_bits", 0)

        weak_keywords_found = [kw for kw in WEAK_CIPHERS_KEYWORDS if kw in cipher_name.upper()]

        if weak_keywords_found:
            results.add_finding(Finding(
                id=f"SSL-WEAKCIPHERS-{port}",
                title=f"Weak Cipher Suite in Use: {cipher_name}",
                severity=Severity.HIGH,
                module="ssl",
                description="Weak cipher suites allow decryption of intercepted traffic.",
                evidence=f"Active cipher: {cipher_name} ({cipher_bits}-bit)",
                recommendation="Configure server to use only strong cipher suites (AES-GCM, CHACHA20-POLY1305).",
                host=self.host, port=port,
                tags=["ssl", "cipher"],
            ))
            Console.finding("HIGH", f"Weak cipher detected: {cipher_name}")
        else:
            Console.success(f"    [+] Cipher suite OK: {cipher_name} ({cipher_bits}-bit)")
