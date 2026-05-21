"""
Console Report — formatted terminal output of audit results.
"""

from __future__ import annotations
from core.config import Config
from core.models import AuditResults, Severity
from utils.display import Console


class ConsoleReport:
    def __init__(self, config: Config):
        self.config = config

    def generate(self, results: AuditResults):
        Console.section("AUDIT SUMMARY")

        # Stats
        by_sev = results.findings_by_severity
        print(f"\n  Target        : {results.target}")
        print(f"  Duration      : {results.duration_seconds:.1f}s")
        print(f"  Open Ports    : {len(results.open_ports)}")
        print(f"  Total Findings: {results.total_findings}")
        print()

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = len(by_sev[sev.value])
            if count:
                marker = "!!" if sev in (Severity.CRITICAL, Severity.HIGH) else "  "
                Console.finding(sev.value, f"{count} {sev.value} finding(s)", "")

        # Findings detail
        if results.findings:
            Console.section("FINDINGS DETAIL")
            for finding in sorted(results.findings, key=lambda f: -f.severity.score):
                print()
                Console.finding(finding.severity.value, finding.title)
                print(f"    ID          : {finding.id}")
                if finding.host:
                    print(f"    Host        : {finding.host}" + (f":{finding.port}" if finding.port else ""))
                if finding.cve_ids:
                    print(f"    CVE(s)      : {', '.join(finding.cve_ids)}")
                if finding.cvss_score is not None:
                    print(f"    CVSS Score  : {finding.cvss_score}")
                print(f"    Description : {finding.description}")
                if finding.evidence:
                    print(f"    Evidence    : {finding.evidence[:120]}")
                print(f"    Fix         : {finding.recommendation}")
                if finding.references:
                    print(f"    References  : {finding.references[0]}")
        else:
            Console.success("\n  [+] No findings identified. Target appears clean.")

        Console.separator()
