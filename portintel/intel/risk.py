from portintel.models.schemas import PortResult


class RiskScorer:
    """
    Dedicated logic to determine the severity risk and service exposure concern
    of a discovered port using standard CVSS base-score bands.
    """
    RISKY_SERVICES = {"TELNET", "FTP", "SMB", "RDP", "MSSQL", "MYSQL"}

    @classmethod
    def score(cls, pr: PortResult) -> str:
        """
        Evaluates and populates CVSS severity risk (Critical, High, Medium, Low, Info, None)
        and explicitly distinguishes service exposure/security concern.
        """
        # 1. Determine service exposure concern independently of CVEs
        if pr.service in cls.RISKY_SERVICES:
            pr.exposure_concern = (
                f"Insecure or high-exposure service ({pr.service}) exposed on network."
            )
        else:
            pr.exposure_concern = None

        # 2. Check for structured vulnerabilities with CVSS scores
        scored_vulns = [
            v for v in pr.vulnerabilities if v.cvss_score is not None
        ]

        if scored_vulns:
            max_score = max(v.cvss_score for v in scored_vulns)
            best_vuln = next(
                v for v in scored_vulns if v.cvss_score == max_score
            )
            pr.cvss_score = max_score
            pr.cvss_version = best_vuln.cvss_version

            if max_score >= 9.0:
                risk = "Critical"
            elif max_score >= 7.0:
                risk = "High"
            elif max_score >= 4.0:
                risk = "Medium"
            elif max_score >= 0.1:
                risk = "Low"
            else:
                risk = "None"

            pr.risk = risk
            return risk

        # 3. Fallback when CVE IDs are present but no CVSS score is available
        if pr.vulnerabilities or pr.cves:
            pr.risk = "Medium"
            return "Medium"

        # 4. No vulnerability information available; preserve network/service risk signals
        if pr.service in cls.RISKY_SERVICES:
            pr.risk = "Medium"
            return "Medium"

        pr.risk = "Info"
        return "Info"
