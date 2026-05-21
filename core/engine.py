"""
Audit Engine — orchestrates all scanning modules and report generation.
"""

from __future__ import annotations
import importlib
import traceback
from datetime import datetime
from typing import List

from core.config import Config
from core.models import AuditResults
from utils.logger import get_logger
from utils.display import Console

logger = get_logger(__name__)

MODULE_MAP = {
    "ports": "modules.port_scanner",
    "ssl": "modules.ssl_analyzer",
    "headers": "modules.header_analyzer",
    "vuln": "modules.vuln_checker",
    "dns": "modules.dns_enumerator",
    "ssh": "modules.ssh_auditor",
}


class AuditEngine:
    def __init__(self, config: Config):
        self.config = config

    def run(self) -> AuditResults:
        results = AuditResults(
            target=self.config.target,
            start_time=datetime.now(),
        )

        for module_name in self.config.modules:
            module_path = MODULE_MAP.get(module_name)
            if not module_path:
                Console.warning(f"[!] Unknown module: {module_name} — skipping")
                continue

            Console.section(f"Module: {module_name.upper()}")
            try:
                mod = importlib.import_module(module_path)
                scanner = mod.Scanner(self.config)
                scanner.run(results)
            except ModuleNotFoundError:
                Console.warning(f"[!] Module '{module_name}' not found — skipping")
            except Exception as exc:
                logger.debug(traceback.format_exc())
                Console.warning(f"[!] Module '{module_name}' error: {exc}")

        results.end_time = datetime.now()
        return results

    def generate_reports(self, results: AuditResults):
        from reports.console_report import ConsoleReport
        from reports.json_report import JsonReport
        from reports.html_report import HtmlReport

        reporters = {
            "console": ConsoleReport,
            "json": JsonReport,
            "html": HtmlReport,
        }

        for fmt in self.config.report_formats:
            cls = reporters.get(fmt.strip())
            if cls:
                reporter = cls(self.config)
                reporter.generate(results)
            else:
                Console.warning(f"[!] Unknown report format: {fmt}")
