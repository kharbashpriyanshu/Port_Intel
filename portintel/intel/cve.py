import logging
from typing import List

from portintel.intel.providers import CVEProvider
from portintel.models.schemas import VulnerabilityInfo

logger = logging.getLogger(__name__)


class CVELookup:
    """
    Coordinates CVE lookups using an injected CVEProvider.
    Decoupled from any specific external API.
    """

    def __init__(self, provider: CVEProvider):
        self.provider = provider

    def find_vulnerabilities(
        self, cpe: str = None, banner: str = None
    ) -> List[VulnerabilityInfo]:
        """
        Derives search keywords from CPE or banner and queries the provider
        for structured vulnerability objects.
        """
        keyword = ""

        # Prefer CPE for searching if available
        if cpe:
            # Extract Vendor and Product from CPE string for the search
            parts = cpe.split(":")
            if len(parts) >= 5:
                keyword = f"{parts[3]} {parts[4]}"

        # Fallback to banner heuristic
        if not keyword and banner and len(banner) > 3:
            clean_banner = banner.replace("-", " ").replace("_", " ")
            keyword = " ".join(clean_banner.split()[:2])

        if not keyword:
            return []

        return self.provider.get_vulnerabilities(keyword)

    def find_cves(self, cpe: str = None, banner: str = None) -> List[str]:
        """
        Derives search keywords from CPE or banner and queries the provider for CVE ID strings.
        """
        return [v.cve_id for v in self.find_vulnerabilities(cpe=cpe, banner=banner)]
