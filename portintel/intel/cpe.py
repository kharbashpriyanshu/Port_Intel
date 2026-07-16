from typing import Optional
from portintel.models.schemas import PortResult

class CPEResolver:
    """
    Reusable resolver to build Common Platform Enumeration (CPE) identifiers.
    """
    @staticmethod
    def resolve(pr: PortResult) -> Optional[str]:
        """
        Attempts to generate a CPE 2.3 formatted string based on service and version.
        Format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
        """
        if not pr.service or pr.service == "UNKNOWN":
            return None
            
        # Simplistic mapping (in reality, a robust DB or fuzzy matcher would be used)
        vendor = pr.service.lower()
        product = pr.service.lower()
        version = pr.version if pr.version else "*"
        
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
