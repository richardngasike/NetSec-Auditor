"""
Data models for audit findings and results.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "\033[91m",
            "HIGH": "\033[31m",
            "MEDIUM": "\033[33m",
            "LOW": "\033[34m",
            "INFO": "\033[36m",
        }[self.value]

    @property
    def score(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    module: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    host: str = ""
    port: Optional[int] = None
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "module": self.module,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "references": self.references,
            "host": self.host,
            "port": self.port,
            "cvss_score": self.cvss_score,
            "cve_ids": self.cve_ids,
            "tags": self.tags,
        }


@dataclass
class OpenPort:
    port: int
    protocol: str
    state: str
    service: str = "unknown"
    version: str = ""
    banner: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
        }


@dataclass
class AuditResults:
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    open_ports: List[OpenPort] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            result[f.severity.value].append(f)
        return result

    @property
    def duration_seconds(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total_findings": self.total_findings,
                "by_severity": {k: len(v) for k, v in self.findings_by_severity.items()},
                "open_ports_count": len(self.open_ports),
            },
            "metadata": self.metadata,
        }
