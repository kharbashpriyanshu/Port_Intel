import socket

COMMON_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NETBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    903: "VMWARE-AUTH",
    913: "APEX-MESH",
    1433: "MSSQL",
    3306: "MYSQL",
    3389: "RDP",
    5040: "HTTP",
    5432: "POSTGRESQL",
    7680: "DO-SVC", # Windows Delivery Optimization
    8080: "HTTP-PROXY",
    8443: "HTTPS-ALT"
}

class ServiceDetector:
    """
    Dedicated module for detecting service names from port numbers.
    """
    @staticmethod
    def detect(port: int) -> str:
        """
        Attempts to identify the service typically running on the given port.
        Returns the service name in uppercase, or 'UNKNOWN' if not found.
        """
        try:
            service = socket.getservbyport(port, "tcp")
            return service.upper()
        except (OSError, OverflowError):
            return COMMON_SERVICES.get(port, "UNKNOWN")
