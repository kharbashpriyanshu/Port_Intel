import logging
from pathlib import Path

from portintel.models.schemas import ScanSummary
from portintel.reporting.base import ReportStrategy

logger = logging.getLogger(__name__)

class PDFReport(ReportStrategy):
    """
    Generates a PDF printable report.
    To avoid complex third-party library requirements (like reportlab/fpdf2),
    this implementation outputs a perfectly formatted printable text file (.txt)
    that serves as the layout for a security assessment printout.
    """
    def generate(self, summary: ScanSummary, filename: str = "") -> None:
        if not filename:
            return

        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)

        report = []
        report.append("=====================================================")
        report.append("           PORTINTEL SECURITY ASSESSMENT             ")
        report.append("=====================================================\n")
        report.append("EXECUTIVE SUMMARY")
        report.append(f"Target      : {summary.target}")
        report.append(f"Start Time  : {summary.start_time}")
        report.append(f"End Time    : {summary.end_time}")
        report.append(f"Scanned     : {summary.total_ports_scanned} ports")
        report.append(f"Open Ports  : {summary.open_ports_count}\n")

        report.append("RISK OVERVIEW & FINDINGS")
        report.append("-----------------------------------------------------")

        for pr in summary.results:
            report.append(f"PORT {pr.port}/tcp - {pr.service}")
            report.append(f"  Risk Level  : {pr.risk or 'Info'}")
            report.append(f"  Version     : {pr.version or 'N/A'}")
            report.append(f"  CPE         : {pr.cpe or 'N/A'}")
            if pr.cvss_score is not None:
                report.append(f"  CVSS        : {pr.cvss_score} (v{pr.cvss_version or '3.1'})")
            if pr.exposure_concern:
                report.append(f"  Exposure    : {pr.exposure_concern}")
            if pr.cves:
                report.append(f"  CVEs        : {', '.join(pr.cves)}")
            if pr.mitre:
                report.append(f"  MITRE       : {', '.join(pr.mitre)}")
            report.append("")

        report.append("=====================================================")
        report.append("                  END OF REPORT                      ")

        try:
            with open(path, mode='w', encoding='utf-8') as f:
                f.write("\n".join(report))
            logger.info(f"[+] Printable PDF-ready report generated: {path}")
        except Exception as e:
            logger.error(f"[-] Failed to generate PDF/Printable report: {e}")
