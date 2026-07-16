import logging
from portintel.models.schemas import ScanSummary
from portintel.reporting.base import ReportStrategy

logger = logging.getLogger(__name__)

# ANSI escape codes for basic colors
COLORS = {
    "Critical": "\033[91m", # Red
    "High": "\033[93m",     # Yellow
    "Medium": "\033[95m",   # Magenta
    "Low": "\033[94m",      # Blue
    "Info": "\033[92m",     # Green
    "RESET": "\033[0m"
}

class ConsoleReport(ReportStrategy):
    """
    Outputs a nicely formatted, colorized report to the terminal.
    """
    def generate(self, summary: ScanSummary, filename: str = "") -> None:
        logger.info("\n" + "=" * 60)
        logger.info(f"SCAN SUMMARY FOR {summary.target}")
        logger.info("=" * 60)
        
        # Calculate timing
        duration = summary.end_time - summary.start_time if summary.end_time and summary.start_time else None
        if duration:
            logger.info(f"Total Time : {duration.total_seconds():.2f} seconds")
            
        logger.info(f"Scanned    : {summary.total_ports_scanned} ports")
        logger.info(f"Open Ports : {summary.open_ports_count}")
        logger.info("-" * 60)
        
        if not summary.results:
            logger.info("No open ports found.")
            logger.info("=" * 60 + "\n")
            return

        logger.info(f"{'PORT':<6} {'SERVICE':<15} {'RISK':<10} {'STATUS'}")
        logger.info("-" * 60)
        
        for pr in summary.results:
            risk = pr.risk or "Info"
            color = COLORS.get(risk, COLORS["RESET"])
            
            logger.info(f"{pr.port:<6} {pr.service:<15} {color}{risk:<10}{COLORS['RESET']} {pr.status}")
            
            if pr.version:
                logger.info(f"       |- Version: {pr.version}")
            if pr.cpe:
                logger.info(f"       |- CPE: {pr.cpe}")
            if pr.mitre:
                logger.info(f"       |- MITRE: {', '.join(pr.mitre)}")
            if pr.cves:
                logger.info(f"       |- CVEs: {', '.join(pr.cves)}")
            if pr.banner:
                display_banner_str = pr.banner if len(pr.banner) <= 60 else pr.banner[:57] + "..."
                logger.info(f"       |- Banner: {display_banner_str}")
                
        logger.info("=" * 60 + "\n")
