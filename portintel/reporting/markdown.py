import logging
from pathlib import Path

from portintel.models.schemas import ScanSummary
from portintel.reporting.base import ReportStrategy

logger = logging.getLogger(__name__)

class MarkdownReport(ReportStrategy):
    """
    Generates a Markdown report suitable for GitHub, GitLab, or Obsidian.
    """
    def generate(self, summary: ScanSummary, filename: str = "") -> None:
        if not filename:
            return

        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)

        md = []
        md.append(f"# PortIntel Security Assessment: `{summary.target}`\n")

        md.append("## Executive Summary\n")
        md.append(f"- **Total Ports Scanned**: {summary.total_ports_scanned}")
        md.append(f"- **Open Ports**: {summary.open_ports_count}")
        md.append(f"- **Start Time**: {summary.start_time}")
        md.append(f"- **End Time**: {summary.end_time}\n")

        md.append("## Detailed Findings\n")
        md.append("| Port | Service | Version | CPE | Risk | CVSS | CVEs | MITRE ATT&CK | Exposure Concern |")
        md.append("|------|---------|---------|-----|------|------|------|--------------|------------------|")

        for pr in summary.results:
            risk = pr.risk or "Info"
            cves = ", ".join(pr.cves) if pr.cves else "None"
            mitre = "<br>".join(pr.mitre) if pr.mitre else "None"
            cpe = pr.cpe or "N/A"
            cvss_str = f"{pr.cvss_score} (v{pr.cvss_version or '3.1'})" if pr.cvss_score is not None else "N/A"
            exposure_str = pr.exposure_concern or "None"
            md.append(f"| {pr.port} | {pr.service} | {pr.version or 'N/A'} | {cpe} | {risk} | {cvss_str} | {cves} | {mitre} | {exposure_str} |")

        try:
            with open(path, mode='w', encoding='utf-8') as f:
                f.write("\n".join(md))
            logger.info(f"[+] Markdown report generated: {path}")
        except Exception as e:
            logger.error(f"[-] Failed to generate Markdown report: {e}")
