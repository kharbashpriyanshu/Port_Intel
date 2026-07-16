from typing import List

from portintel.models.schemas import PortResult


class MITREMapper:
    """
    Maps discovered services to potential MITRE ATT&CK tactics or techniques.
    """

    # Modular mapping of services to ATT&CK matrix
    MAPPING = {
        "SMB": ["T1021 - Remote Services (Lateral Movement)"],
        "RDP": ["T1021 - Remote Services (Lateral Movement)"],
        "SSH": ["T1021 - Remote Services (Lateral Movement)"],
        "FTP": ["T1048 - Exfiltration Over Alternative Protocol"],
        "TELNET": ["T1021 - Unencrypted Remote Services"],
        "MSSQL": ["T1190 - Exploit Public-Facing Application"],
        "MYSQL": ["T1190 - Exploit Public-Facing Application"]
    }

    @staticmethod
    def map_service(pr: PortResult) -> List[str]:
        if not pr.service:
            return []
        return MITREMapper.MAPPING.get(pr.service, [])
