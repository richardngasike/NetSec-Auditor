"""
Configuration management for NetSec Auditor.
"""

from __future__ import annotations
import argparse
from dataclasses import dataclass, field
from typing import List


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 2049, 2121,
    3306, 3389, 5432, 5900, 6379, 7001, 8080, 8443, 8888, 9200,
    27017, 27018, 50070,
]

ALL_MODULES = ["ports", "ssl", "headers", "vuln", "dns", "ssh"]


@dataclass
class Config:
    target: str
    ports: List[int]
    ports_display: str
    scan_type: str
    threads: int
    timeout: float
    rate_limit: float
    modules: List[str]
    report_formats: List[str]
    output_dir: str
    verbose: bool
    quiet: bool

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "Config":
        ports, ports_display = cls._parse_ports(args.ports)
        modules = cls._resolve_modules(args)

        return cls(
            target=args.target,
            ports=ports,
            ports_display=ports_display,
            scan_type=args.scan_type,
            threads=args.threads,
            timeout=args.timeout,
            rate_limit=args.rate_limit,
            modules=modules,
            report_formats=[f.strip() for f in args.report.split(",")],
            output_dir=args.output_dir,
            verbose=args.verbose,
            quiet=args.quiet,
        )

    @staticmethod
    def _parse_ports(spec: str):
        if spec == "common":
            return COMMON_PORTS, f"common ({len(COMMON_PORTS)} ports)"
        if spec == "all":
            return list(range(1, 65536)), "all (1-65535)"
        ports = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports, spec

    @staticmethod
    def _resolve_modules(args) -> List[str]:
        if args.full_audit:
            base = ALL_MODULES[:]
        else:
            base = [m.strip() for m in args.modules.split(",") if m.strip()]
        skip = {m.strip() for m in args.skip_modules.split(",") if m.strip()}
        return [m for m in base if m not in skip]
