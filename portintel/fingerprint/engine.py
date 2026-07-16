import logging
from typing import List
from portintel.models.schemas import PortResult
from portintel.fingerprint.banner import BannerGrabber
from portintel.fingerprint.service import ServiceDetector
from portintel.fingerprint.version import VersionParser

logger = logging.getLogger(__name__)

class FingerprintEngine:
    """
    Coordinates the enrichment of PortResult objects.
    Acts as a single entry point for all fingerprinting tasks.
    """
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        
    def enrich(self, target: str, open_ports: List[PortResult], is_udp: bool = False) -> List[PortResult]:
        """
        Iterates over discovered ports and enriches them with service names,
        banners, and extracted versions without modifying the scanner logic.
        """
        logger.debug(f"Starting FingerprintEngine for {target}")
        
        for pr in open_ports:
            # 1. Service Detection
            pr.service = ServiceDetector.detect(pr.port)
            
            # 2. Banner Grabbing (TCP only)
            if not is_udp:
                pr.banner = BannerGrabber.grab(target, pr.port, self.timeout)
                
            # 3. Version Parsing
            pr.version = VersionParser.parse(pr.banner)
            
        return open_ports
