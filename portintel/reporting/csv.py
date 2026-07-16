import csv
import logging
from pathlib import Path

from portintel.models.schemas import ScanSummary
from portintel.reporting.base import ReportStrategy

logger = logging.getLogger(__name__)

class CSVReport(ReportStrategy):
    """
    Exports scan results to a CSV file.
    """
    def generate(self, summary: ScanSummary, filename: str = "") -> None:
        if not filename:
            return

        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(path, mode='w', newline='', encoding='utf-8') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(['Port', 'Service', 'Version', 'CPE', 'Risk', 'Status', 'Banner', 'CVEs', 'MITRE'])

                for pr in summary.results:
                    cves_str = ", ".join(pr.cves) if pr.cves else ""
                    mitre_str = ", ".join(pr.mitre) if pr.mitre else ""
                    writer.writerow([
                        pr.port, pr.service, pr.version or "", pr.cpe or "",
                        pr.risk or "", pr.status, pr.banner or "", cves_str, mitre_str
                    ])

            logger.info(f"[+] CSV report generated: {path}")
        except Exception as e:
            logger.error(f"[-] Failed to generate CSV report: {e}")
