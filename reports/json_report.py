"""
JSON Report — machine-readable output for CI/CD pipelines and SIEM integration.
"""

from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path

from core.config import Config
from core.models import AuditResults
from utils.display import Console


class JsonReport:
    def __init__(self, config: Config):
        self.config = config

    def generate(self, results: AuditResults):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_{results.target.replace('/', '_')}_{timestamp}.json"
        output_path = Path(self.config.output_dir) / filename

        payload = {
            "schema_version": "1.0",
            "tool": "NetSec Auditor v1.0.0",
            **results.to_dict(),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)

        Console.success(f"[+] JSON report saved: {output_path}")
