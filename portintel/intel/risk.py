from portintel.models.schemas import PortResult

class RiskScorer:
    """
    Dedicated logic to determine the severity risk of a discovered port.
    """
    @staticmethod
    def score(pr: PortResult) -> str:
        """
        Populates Critical, High, Medium, Low, or Info based on vulnerabilities
        and service exposure.
        """
        if pr.cves:
            return "Critical" if len(pr.cves) > 1 else "High"
            
        # Inherently risky protocols mapped to Medium risk when exposed
        risky_services = {"TELNET", "FTP", "SMB", "RDP", "MSSQL", "MYSQL"}
        if pr.service in risky_services:
            return "Medium"
            
        return "Info"
