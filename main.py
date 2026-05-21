#!/usr/bin/env python3
"""
NetSec Auditor — Production-Grade Network Security Assessment Tool
Author: Security Engineering Team
License: MIT
"""

import sys
import argparse
import signal
from datetime import datetime
from pathlib import Path

from core.engine import AuditEngine
from core.config import Config
from utils.logger import get_logger
from utils.display import Banner, Console

logger = get_logger(__name__)


def signal_handler(sig, frame):
    Console.warning("\n[!] Interrupt received. Shutting down gracefully...")
    sys.exit(0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsec-auditor",
        description="NetSec Auditor — Network Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1
  %(prog)s -t example.com --ports 22,80,443,8080
  %(prog)s -t 10.0.0.0/24 --scan-type stealth --threads 50
  %(prog)s -t example.com --modules ssl,vuln,headers --report html
  %(prog)s -t 192.168.1.1 --full-audit --report json,html

Modules:
  ports     TCP/UDP port scanning with service fingerprinting
  ssl       SSL/TLS certificate and configuration analysis
  headers   HTTP security headers analysis
  vuln      Known vulnerability checks (CVE database)
  dns       DNS enumeration and misconfiguration checks
  ssh       SSH configuration and weak cipher detection
        """,
    )

    # Target
    target_group = parser.add_argument_group("Target")
    target_group.add_argument("-t", "--target", required=True, help="Target IP, hostname, or CIDR range")
    target_group.add_argument("-p", "--ports", default="common", help="Ports: 'common', 'all', '1-1024', or '22,80,443'")

    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--scan-type", choices=["connect", "stealth", "udp"], default="connect", help="Scan technique (default: connect)")
    scan_group.add_argument("--threads", type=int, default=100, help="Concurrent threads (default: 100)")
    scan_group.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds (default: 2.0)")
    scan_group.add_argument("--rate-limit", type=float, default=0.0, help="Delay between probes in seconds (default: 0)")

    # Modules
    module_group = parser.add_argument_group("Modules")
    module_group.add_argument("--modules", default="ports,ssl,headers,vuln,dns", help="Comma-separated list of modules to run")
    module_group.add_argument("--full-audit", action="store_true", help="Run all available modules")
    module_group.add_argument("--skip-modules", default="", help="Comma-separated list of modules to skip")

    # Output
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("--report", default="console", help="Report format(s): console, json, html (comma-separated)")
    output_group.add_argument("--output-dir", default="./reports", help="Directory for report files (default: ./reports)")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    output_group.add_argument("-q", "--quiet", action="store_true", help="Suppress banner and progress")

    return parser


def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = build_parser()
    args = parser.parse_args()

    if not args.quiet:
        Banner.print()

    # Build config
    config = Config.from_args(args)

    Console.info(f"[*] Target     : {config.target}")
    Console.info(f"[*] Ports      : {config.ports_display}")
    Console.info(f"[*] Modules    : {', '.join(config.modules)}")
    Console.info(f"[*] Threads    : {config.threads}")
    Console.info(f"[*] Started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    Console.separator()

    # Ensure output directory exists
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)

    # Run audit
    engine = AuditEngine(config)
    results = engine.run()

    Console.separator()
    Console.success(f"[+] Audit complete. {results.total_findings} finding(s) identified.")

    # Generate reports
    engine.generate_reports(results)

    return 0 if results.total_findings == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
