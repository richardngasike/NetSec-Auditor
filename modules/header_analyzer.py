"""
HTTP Security Headers Analyzer — checks for missing or misconfigured security headers.
"""

from __future__ import annotations
import urllib.request
import urllib.error
from typing import Dict, Optional

from core.config import Config
from core.models import AuditResults, Finding, Severity
from utils.display import Console
from utils.logger import get_logger

logger = get_logger(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HSTS is not set. Browsers will not enforce HTTPS, enabling downgrade attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cve": [],
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "No CSP header. XSS attacks can execute arbitrary scripts in the user's browser.",
        "recommendation": "Define a strict Content-Security-Policy to whitelist trusted content sources.",
        "cve": [],
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "Missing X-Frame-Options allows clickjacking attacks via iframe embedding.",
        "recommendation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing is needed internally).",
        "cve": [],
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "Missing X-Content-Type-Options allows MIME-sniffing attacks.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "cve": [],
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "No Referrer-Policy set. Sensitive URLs may leak via Referer header.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cve": [],
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "No Permissions-Policy (formerly Feature-Policy). Browser features are unrestricted.",
        "recommendation": "Add Permissions-Policy to restrict camera, microphone, geolocation access.",
        "cve": [],
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "X-XSS-Protection header not set (legacy but still useful for older browsers).",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
        "cve": [],
    },
}

INSECURE_HEADER_CHECKS = {
    "Server": "Server header discloses software version, aiding targeted attacks.",
    "X-Powered-By": "X-Powered-By discloses technology stack (e.g. PHP version).",
    "X-AspNet-Version": "X-AspNet-Version reveals .NET framework version.",
}


class Scanner:
    def __init__(self, config: Config):
        self.config = config
        self.target = config.target

    def run(self, results: AuditResults):
        http_ports = [p for p in results.open_ports if p.service in ("http", "http-alt", "https", "https-alt") or p.port in (80, 443, 8080, 8443)]

        if not http_ports:
            http_ports_to_try = [(80, "http"), (443, "https")]
        else:
            http_ports_to_try = [(p.port, p.service) for p in http_ports]

        for port, service in http_ports_to_try:
            scheme = "https" if "https" in service or port in (443, 8443) else "http"
            url = f"{scheme}://{self.target}:{port}/"
            Console.info(f"[*] Checking HTTP security headers: {url}")
            headers = self._fetch_headers(url)
            if headers is not None:
                self._analyze_headers(headers, url, port, results)
            else:
                Console.warning(f"    [-] Could not fetch headers from {url}")

    def _fetch_headers(self, url: str) -> Optional[Dict[str, str]]:
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers={"User-Agent": "NetSecAuditor/1.0"})
            with urllib.request.urlopen(req, timeout=self.config.timeout, context=ctx) as resp:
                return dict(resp.headers)
        except urllib.error.HTTPError as e:
            # Still get headers from error responses
            return dict(e.headers)
        except Exception as e:
            logger.debug(f"Failed to fetch headers from {url}: {e}")
            return None

    def _analyze_headers(self, headers: Dict[str, str], url: str, port: int, results: AuditResults):
        # Normalize header names to lowercase for comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}

        missing = []
        for header, meta in SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                missing.append(header)
                results.add_finding(Finding(
                    id=f"HEADER-MISSING-{header.upper().replace('-','_')}-{port}",
                    title=f"Missing Security Header: {header}",
                    severity=meta["severity"],
                    module="headers",
                    description=meta["description"],
                    evidence=f"Header '{header}' absent in response from {url}",
                    recommendation=meta["recommendation"],
                    host=self.target,
                    port=port,
                    tags=["http", "headers", "owasp"],
                ))
                Console.finding(meta["severity"].value, f"Missing: {header}")
            else:
                Console.success(f"    [+] Present: {header}: {headers_lower[header.lower()][:60]}")

        # Check for information disclosure headers
        for header, desc in INSECURE_HEADER_CHECKS.items():
            if header.lower() in headers_lower:
                value = headers_lower[header.lower()]
                results.add_finding(Finding(
                    id=f"HEADER-DISCLOSURE-{header.upper()}-{port}",
                    title=f"Information Disclosure via {header} Header",
                    severity=Severity.LOW,
                    module="headers",
                    description=desc,
                    evidence=f"{header}: {value}",
                    recommendation=f"Remove or suppress the '{header}' response header in server config.",
                    host=self.target,
                    port=port,
                    tags=["http", "headers", "information-disclosure"],
                ))
                Console.finding("LOW", f"Info disclosure: {header}: {value}")

        if not missing:
            Console.success("    [+] All critical security headers are present")
