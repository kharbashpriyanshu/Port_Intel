import json
import logging
from pathlib import Path

from portintel.models.schemas import ScanSummary
from portintel.reporting.base import ReportStrategy

logger = logging.getLogger(__name__)

class JSONReport(ReportStrategy):
    """
    Exports scan results to a structured JSON file suitable for APIs.
    """
    def generate(self, summary: ScanSummary, filename: str = "") -> None:
        if not filename:
            return

        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)

        try:
            data = {
                "metadata": {
                    "target": summary.target,
                    "start_time": summary.start_time.isoformat() if summary.start_time else None,
                    "end_time": summary.end_time.isoformat() if summary.end_time else None,
                    "total_ports_scanned": summary.total_ports_scanned,
                    "open_ports_count": summary.open_ports_count
                },
                "findings": []
            }

            for pr in summary.results:
                data["findings"].append({
                    "port": pr.port,
                    "service": pr.service,
                    "status": pr.status,
                    "version": pr.version,
                    "cpe": pr.cpe,
                    "risk": pr.risk,
                    "cvss_score": pr.cvss_score,
                    "cvss_version": pr.cvss_version,
                    "exposure_concern": pr.exposure_concern,
                    "mitre": pr.mitre,
                    "cves": pr.cves,
                    "vulnerabilities": [
                        {
                            "cve_id": v.cve_id,
                            "description": v.description,
                            "cvss_score": v.cvss_score,
                            "cvss_version": v.cvss_version,
                            "severity": v.severity,
                        }
                        for v in pr.vulnerabilities
                    ],
                    "banner": pr.banner
                })

            with open(path, mode='w', encoding='utf-8') as json_file:
                json.dump(data, json_file, indent=4)

            logger.info(f"[+] JSON report generated: {path}")
        except Exception as e:
            logger.error(f"[-] Failed to generate JSON report: {e}")
