"""
Unit tests for NetSec Auditor core components.
Run with: python -m pytest tests/ -v
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Finding, Severity, OpenPort, AuditResults
from core.config import Config, COMMON_PORTS
from utils.net import guess_service, is_cidr, expand_cidr


class TestSeverity(unittest.TestCase):
    def test_ordering(self):
        self.assertGreater(Severity.CRITICAL.score, Severity.HIGH.score)
        self.assertGreater(Severity.HIGH.score, Severity.MEDIUM.score)
        self.assertGreater(Severity.MEDIUM.score, Severity.LOW.score)
        self.assertGreater(Severity.LOW.score, Severity.INFO.score)

    def test_values(self):
        self.assertEqual(Severity.CRITICAL.value, "CRITICAL")
        self.assertEqual(Severity.INFO.value, "INFO")


class TestFinding(unittest.TestCase):
    def _make_finding(self):
        return Finding(
            id="TEST-001",
            title="Test Finding",
            severity=Severity.HIGH,
            module="test",
            description="Test description",
            host="192.168.1.1",
            port=80,
            cve_ids=["CVE-2021-99999"],
        )

    def test_to_dict(self):
        f = self._make_finding()
        d = f.to_dict()
        self.assertEqual(d["id"], "TEST-001")
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["cve_ids"], ["CVE-2021-99999"])
        self.assertEqual(d["port"], 80)

    def test_default_fields(self):
        f = Finding(id="X", title="T", severity=Severity.INFO, module="m", description="d")
        self.assertEqual(f.references, [])
        self.assertEqual(f.cve_ids, [])
        self.assertIsNone(f.cvss_score)


class TestAuditResults(unittest.TestCase):
    def setUp(self):
        from datetime import datetime
        self.results = AuditResults(target="example.com", start_time=datetime.now())

    def test_add_finding(self):
        f = Finding(id="F1", title="T", severity=Severity.MEDIUM, module="m", description="d")
        self.results.add_finding(f)
        self.assertEqual(self.results.total_findings, 1)

    def test_findings_by_severity(self):
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.LOW]:
            self.results.add_finding(Finding(id=f"F-{sev}", title="T", severity=sev, module="m", description="d"))
        by_sev = self.results.findings_by_severity
        self.assertEqual(len(by_sev["CRITICAL"]), 1)
        self.assertEqual(len(by_sev["HIGH"]), 2)
        self.assertEqual(len(by_sev["LOW"]), 1)
        self.assertEqual(len(by_sev["MEDIUM"]), 0)

    def test_to_dict_structure(self):
        d = self.results.to_dict()
        self.assertIn("target", d)
        self.assertIn("summary", d)
        self.assertIn("open_ports", d)
        self.assertIn("findings", d)


class TestConfig(unittest.TestCase):
    def test_parse_ports_common(self):
        ports, display = Config._parse_ports("common")
        self.assertEqual(ports, COMMON_PORTS)
        self.assertIn("common", display)

    def test_parse_ports_range(self):
        ports, display = Config._parse_ports("22-25")
        self.assertEqual(ports, [22, 23, 24, 25])

    def test_parse_ports_list(self):
        ports, display = Config._parse_ports("22,80,443")
        self.assertEqual(set(ports), {22, 80, 443})

    def test_parse_ports_all(self):
        ports, display = Config._parse_ports("all")
        self.assertEqual(len(ports), 65535)
        self.assertIn("all", display)


class TestNetUtils(unittest.TestCase):
    def test_guess_service(self):
        self.assertEqual(guess_service(22), "ssh")
        self.assertEqual(guess_service(443), "https")
        self.assertEqual(guess_service(3306), "mysql")
        self.assertEqual(guess_service(9999), "unknown")

    def test_is_cidr(self):
        self.assertTrue(is_cidr("192.168.1.0/24"))
        self.assertFalse(is_cidr("192.168.1.1"))
        self.assertFalse(is_cidr("example.com"))

    def test_expand_cidr(self):
        hosts = expand_cidr("192.168.1.0/30")
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_expand_cidr_single(self):
        hosts = expand_cidr("10.0.0.1")
        self.assertEqual(hosts, ["10.0.0.1"])


class TestOpenPort(unittest.TestCase):
    def test_to_dict(self):
        p = OpenPort(port=443, protocol="tcp", state="open", service="https", banner="nginx/1.24")
        d = p.to_dict()
        self.assertEqual(d["port"], 443)
        self.assertEqual(d["service"], "https")
        self.assertEqual(d["banner"], "nginx/1.24")


if __name__ == "__main__":
    unittest.main(verbosity=2)
