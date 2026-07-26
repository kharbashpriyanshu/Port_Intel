import logging
from typing import List

from portintel.intel.cpe import CPEResolver
from portintel.intel.cve import CVELookup
from portintel.intel.mitre import MITREMapper
from portintel.intel.risk import RiskScorer
from portintel.models.schemas import PortResult

logger = logging.getLogger(__name__)

class IntelligenceEngine:
    """
    Coordinates the enrichment of PortResult objects with threat intelligence.
    Operates strictly after the FingerprintEngine.
    """
    def __init__(self, cve_lookup: CVELookup = None):
        # Using dependency injection for CVE lookups to allow different providers
        self.cve_lookup = cve_lookup

    def enrich(self, results: List[PortResult]) -> List[PortResult]:
        """
        Iterates over fingerprinted ports and appends security context.
        """
        logger.debug("Starting Intelligence Engine enrichment...")

        for pr in results:
            # 1. Resolve CPE string
            pr.cpe = CPEResolver.resolve(pr)

            # 2. MITRE ATT&CK Mapping
            pr.mitre = MITREMapper.map_service(pr)

            # 3. CVE/Vulnerability Lookup (if a provider is configured and not UDP)
            if self.cve_lookup:
                pr.vulnerabilities = self.cve_lookup.find_vulnerabilities(cpe=pr.cpe, banner=pr.banner)
                pr.cves = [v.cve_id for v in pr.vulnerabilities]

            # 4. Risk Scoring
            pr.risk = RiskScorer.score(pr)

        return results
