"""
HTML Report — professional self-contained HTML report with severity breakdown.
"""

from __future__ import annotations
from datetime import datetime
from pathlib import Path

from core.config import Config
from core.models import AuditResults, Severity
from utils.display import Console

SEV_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#0891b2",
}

SEV_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#eff6ff",
    "INFO":     "#f0f9ff",
}


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


class HtmlReport:
    def __init__(self, config: Config):
        self.config = config

    def generate(self, results: AuditResults):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_{results.target.replace('/', '_')}_{timestamp}.html"
        output_path = Path(self.config.output_dir) / filename

        html = self._render(results)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        Console.success(f"[+] HTML report saved: {output_path}")

    def _render(self, results: AuditResults) -> str:
        by_sev = results.findings_by_severity
        findings_sorted = sorted(results.findings, key=lambda f: -f.severity.score)

        summary_cards = ""
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = len(by_sev[sev.value])
            color = SEV_COLORS[sev.value]
            summary_cards += f"""
            <div class="card" style="border-left: 4px solid {color}">
                <div class="card-count" style="color:{color}">{count}</div>
                <div class="card-label">{sev.value}</div>
            </div>"""

        port_rows = ""
        for p in sorted(results.open_ports, key=lambda x: x.port):
            port_rows += f"""
            <tr>
                <td><strong>{_esc(p.port)}</strong></td>
                <td><span class="badge badge-open">open</span></td>
                <td>{_esc(p.protocol.upper())}</td>
                <td>{_esc(p.service)}</td>
                <td class="banner-cell">{_esc(p.banner[:80])}</td>
            </tr>"""

        findings_html = ""
        for f in findings_sorted:
            color = SEV_COLORS[f.severity.value]
            bg = SEV_BG[f.severity.value]
            cves = ", ".join(f.cve_ids) if f.cve_ids else "N/A"
            refs = "".join(f'<a href="{_esc(r)}" target="_blank">{_esc(r)}</a><br>' for r in f.references)
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; background:{bg}">
                <div class="finding-header">
                    <span class="severity-badge" style="background:{color}">{_esc(f.severity.value)}</span>
                    <span class="finding-title">{_esc(f.title)}</span>
                    {"<span class='cvss-badge'>CVSS " + str(f.cvss_score) + "</span>" if f.cvss_score else ""}
                </div>
                <div class="finding-body">
                    <div class="finding-meta">
                        <span><strong>ID:</strong> {_esc(f.id)}</span>
                        {"<span><strong>Host:</strong> " + _esc(f.host) + (":" + str(f.port) if f.port else "") + "</span>" if f.host else ""}
                        {"<span><strong>CVE:</strong> " + _esc(cves) + "</span>" if cves != "N/A" else ""}
                        <span><strong>Module:</strong> {_esc(f.module)}</span>
                    </div>
                    <p><strong>Description:</strong> {_esc(f.description)}</p>
                    {"<p><strong>Evidence:</strong> <code>" + _esc(f.evidence[:200]) + "</code></p>" if f.evidence else ""}
                    <p><strong>Recommendation:</strong> {_esc(f.recommendation)}</p>
                    {"<p><strong>References:</strong> " + refs + "</p>" if refs else ""}
                </div>
            </div>"""

        if not findings_html:
            findings_html = '<div class="no-findings">✅ No findings identified. Target appears well-configured.</div>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetSec Audit Report — {_esc(results.target)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #0f172a, #1e3a5f); color: white; padding: 2.5rem 3rem; }}
  .header h1 {{ font-size: 1.8rem; font-weight: 700; letter-spacing: -0.5px; }}
  .header .subtitle {{ opacity: 0.7; font-size: 0.95rem; margin-top: 0.3rem; }}
  .header .meta {{ display: flex; gap: 2rem; margin-top: 1.5rem; font-size: 0.9rem; opacity: 0.85; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
  .section {{ background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 2rem; overflow: hidden; }}
  .section-header {{ background: #f1f5f9; padding: 1rem 1.5rem; font-weight: 600; font-size: 1rem; border-bottom: 1px solid #e2e8f0; color: #334155; text-transform: uppercase; letter-spacing: 0.5px; font-size: 0.85rem; }}
  .section-body {{ padding: 1.5rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; }}
  .card {{ text-align: center; padding: 1.2rem; border-radius: 8px; background: #f8fafc; border: 1px solid #e2e8f0; }}
  .card-count {{ font-size: 2.2rem; font-weight: 700; line-height: 1; }}
  .card-label {{ font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; margin-top: 0.3rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th {{ background: #f1f5f9; padding: 0.75rem 1rem; text-align: left; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; color: #475569; border-bottom: 2px solid #e2e8f0; }}
  td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8fafc; }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }}
  .badge-open {{ background: #dcfce7; color: #16a34a; }}
  .banner-cell {{ font-family: monospace; font-size: 0.8rem; color: #64748b; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .finding {{ border-radius: 8px; margin-bottom: 1rem; overflow: hidden; border: 1px solid #e2e8f0; }}
  .finding-header {{ display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1.25rem; background: rgba(255,255,255,0.6); }}
  .finding-title {{ font-weight: 600; font-size: 0.95rem; flex: 1; }}
  .severity-badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.72rem; font-weight: 700; color: white; text-transform: uppercase; letter-spacing: 0.5px; }}
  .cvss-badge {{ background: #334155; color: white; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  .finding-body {{ padding: 1rem 1.25rem; border-top: 1px solid rgba(0,0,0,0.06); }}
  .finding-meta {{ display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 0.75rem; font-size: 0.85rem; color: #475569; }}
  .finding-body p {{ margin-bottom: 0.5rem; font-size: 0.9rem; }}
  .finding-body code {{ background: #f1f5f9; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.82rem; word-break: break-all; }}
  .finding-body a {{ color: #2563eb; text-decoration: none; }}
  .finding-body a:hover {{ text-decoration: underline; }}
  .no-findings {{ text-align: center; padding: 3rem; color: #16a34a; font-size: 1.1rem; font-weight: 600; }}
  .footer {{ text-align: center; padding: 2rem; color: #94a3b8; font-size: 0.85rem; }}
  @media (max-width: 700px) {{ .cards {{ grid-template-columns: repeat(3, 1fr); }} .meta {{ flex-direction: column; gap: 0.5rem; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ NetSec Audit Report</h1>
  <div class="subtitle">Network Security Assessment — For authorized use only</div>
  <div class="meta">
    <span><strong>Target:</strong> {_esc(results.target)}</span>
    <span><strong>Started:</strong> {results.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
    <span><strong>Duration:</strong> {results.duration_seconds:.1f}s</span>
    <span><strong>Findings:</strong> {results.total_findings}</span>
    <span><strong>Open Ports:</strong> {len(results.open_ports)}</span>
  </div>
</div>
<div class="container">
  <div class="section">
    <div class="section-header">Executive Summary</div>
    <div class="section-body">
      <div class="cards">{summary_cards}</div>
    </div>
  </div>
  <div class="section">
    <div class="section-header">Open Ports ({len(results.open_ports)})</div>
    {"<div class='section-body'><em>No open ports detected.</em></div>" if not results.open_ports else f"<table><thead><tr><th>Port</th><th>State</th><th>Protocol</th><th>Service</th><th>Banner</th></tr></thead><tbody>{port_rows}</tbody></table>"}
  </div>
  <div class="section">
    <div class="section-header">Findings ({results.total_findings})</div>
    <div class="section-body">{findings_html}</div>
  </div>
</div>
<div class="footer">Generated by NetSec Auditor v1.0.0 · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · For authorized use only</div>
</body>
</html>"""
