import logging
from pathlib import Path

from portintel.models.schemas import ScanSummary
from portintel.reporting.base import ReportStrategy

logger = logging.getLogger(__name__)

class HTMLReport(ReportStrategy):
    """
    Generates a professional HTML security assessment report.
    """
    def generate(self, summary: ScanSummary, filename: str = "") -> None:
        if not filename:
            return

        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>PortIntel Security Assessment</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; color: #333; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 5px solid #3498db; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        th, td {{ border: 1px solid #e9ecef; padding: 12px; text-align: left; }}
        th {{ background-color: #34495e; color: white; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        .risk-Critical {{ color: white; background-color: #e74c3c; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .risk-High {{ color: white; background-color: #e67e22; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .risk-Medium {{ color: white; background-color: #f1c40f; padding: 4px 8px; border-radius: 4px; color: #333; font-weight: bold; }}
        .risk-Low {{ color: white; background-color: #3498db; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .risk-Info {{ color: white; background-color: #2ecc71; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>PortIntel Security Assessment</h1>
    <h2>Executive Summary</h2>
    <div class="summary-card">
        <p><strong>Target:</strong> {summary.target}</p>
        <p><strong>Total Ports Scanned:</strong> {summary.total_ports_scanned}</p>
        <p><strong>Open Ports:</strong> {summary.open_ports_count}</p>
        <p><strong>Start Time:</strong> {summary.start_time}</p>
        <p><strong>End Time:</strong> {summary.end_time}</p>
    </div>
    <h2>Open Ports & Findings</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Version</th>
            <th>CPE</th>
            <th>Risk</th>
            <th>CVSS</th>
            <th>CVEs</th>
            <th>MITRE ATT&CK</th>
            <th>Exposure Concern</th>
        </tr>
"""
        for pr in summary.results:
            risk = pr.risk or "Info"
            cves = ", ".join(pr.cves) if pr.cves else "None"
            mitre = "<br>".join(pr.mitre) if pr.mitre else "None"
            cpe = pr.cpe or "N/A"
            cvss_str = f"{pr.cvss_score} (v{pr.cvss_version or '3.1'})" if pr.cvss_score is not None else "N/A"
            exposure_str = pr.exposure_concern or "None"
            html_content += f"""
        <tr>
            <td><strong>{pr.port}</strong> ({pr.status})</td>
            <td>{pr.service}</td>
            <td>{pr.version or 'N/A'}</td>
            <td>{cpe}</td>
            <td><span class="risk-{risk}">{risk}</span></td>
            <td>{cvss_str}</td>
            <td>{cves}</td>
            <td>{mitre}</td>
            <td>{exposure_str}</td>
        </tr>
"""
        html_content += """
    </table>
</body>
</html>
"""
        try:
            with open(path, mode='w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"[+] HTML report generated: {path}")
        except Exception as e:
            logger.error(f"[-] Failed to generate HTML report: {e}")
