import logging
from typing import List, Optional
from portintel.models.schemas import PortResult, HostResult
from portintel.discovery.engine import DiscoveryEngine
from portintel.discovery.icmp import ICMPDiscoveryStrategy
from portintel.scanner.tcp_udp import scan_range_threaded
from portintel.intel.nvd import check_vulnerabilities
from portintel.reporting.exporters import ConsoleExporter, CSVExporter, JSONExporter
from portintel.fingerprint.engine import FingerprintEngine
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
                
        # Enrich with CVEs if requested
        if self.vuln_lookup and not self.is_udp:
            for pr in open_ports:
                if pr.banner:
                    pr.cves = check_vulnerabilities(pr.banner)
        
        # Display to console
        ConsoleExporter().export("", open_ports)
        logger.info("\nScan Complete")
        
        # Export to file if requested
        if self.export_path and open_ports:
            if self.export_path.endswith('.json'):
                JSONExporter().export(self.export_path, open_ports)
            else:
                CSVExporter().export(self.export_path, open_ports)
