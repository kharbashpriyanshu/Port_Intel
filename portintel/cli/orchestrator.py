import logging
from datetime import datetime
from typing import List, Optional

from portintel.discovery.engine import DiscoveryEngine
from portintel.discovery.icmp import ICMPDiscoveryStrategy
from portintel.fingerprint.engine import FingerprintEngine
from portintel.intel.cve import CVELookup
from portintel.intel.engine import IntelligenceEngine
from portintel.intel.providers import NVDProvider
from portintel.models.schemas import PortResult, ScanSummary
from portintel.reporting.csv import CSVReport
from portintel.reporting.engine import ReportingEngine
from portintel.reporting.html import HTMLReport
from portintel.reporting.json import JSONReport
from portintel.reporting.markdown import MarkdownReport
from portintel.reporting.pdf import PDFReport
from portintel.scanner.tcp_udp import scan_range_threaded

logger = logging.getLogger(__name__)

class Orchestrator:
    def __init__(self, threads: int, timeout: float, is_udp: bool, vuln_lookup: bool, export_path: Optional[str] = None):
        self.threads = threads
        self.timeout = timeout
        self.is_udp = is_udp
        self.vuln_lookup = vuln_lookup
        self.export_path = export_path

    def run_discovery(self, network: str):
        logger.info(f"Mapping Network: {network}\n")

        # Instantiate engine with the chosen strategy
        engine = DiscoveryEngine(
            strategy=ICMPDiscoveryStrategy(),
            threads=self.threads,
            timeout=self.timeout
        )
        alive_hosts = engine.sweep(network)

        if not alive_hosts:
            logger.info("No alive hosts found.")
        else:
            for host in alive_hosts:
                logger.info(f"{host.ip} Alive")

        logger.info("\nDiscovery Complete")

    def run_scan(self, target: str, start_port: int, end_port: int):
        logger.info(f"Scanning {target}...\n")

        start_time = datetime.now()

        open_ports: List[PortResult] = scan_range_threaded(
            target=target,
            start_port=start_port,
            end_port=end_port,
            threads=self.threads,
            timeout=self.timeout,
            is_udp=self.is_udp
        )

        # Enrich ports with fingerprinting engine
        fingerprint_engine = FingerprintEngine(timeout=self.timeout)
        open_ports = fingerprint_engine.enrich(target, open_ports, self.is_udp)

        # Enrich with Intelligence Engine
        cve_provider = NVDProvider() if self.vuln_lookup and not self.is_udp else None
        cve_lookup = CVELookup(cve_provider) if cve_provider else None
        intel_engine = IntelligenceEngine(cve_lookup=cve_lookup)

        open_ports = intel_engine.enrich(open_ports)

        end_time = datetime.now()

        # Build ScanSummary
        summary = ScanSummary(
            target=target,
            start_time=start_time,
            end_time=end_time,
            total_ports_scanned=(end_port - start_port + 1),
            open_ports_count=len(open_ports),
            results=open_ports
        )

        # Initialize Reporting Engine
        reporting_engine = ReportingEngine()

        filenames = {}
        if self.export_path:
            if self.export_path.endswith('.json'):
                reporting_engine.add_strategy("json", JSONReport())
                filenames["json"] = self.export_path
            elif self.export_path.endswith('.csv'):
                reporting_engine.add_strategy("csv", CSVReport())
                filenames["csv"] = self.export_path
            elif self.export_path.endswith('.html'):
                reporting_engine.add_strategy("html", HTMLReport())
                filenames["html"] = self.export_path
            elif self.export_path.endswith('.pdf') or self.export_path.endswith('.txt'):
                reporting_engine.add_strategy("pdf", PDFReport())
                filenames["pdf"] = self.export_path
            elif self.export_path.endswith('.md'):
                reporting_engine.add_strategy("markdown", MarkdownReport())
                filenames["markdown"] = self.export_path

        # Generate Reports
        reporting_engine.report(summary, filenames)
