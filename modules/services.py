import socket

# Common ports fallback dictionary in case socket.getservbyport fails
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

def get_service_name(port: int) -> str:
    """
    Attempts to identify the service typically running on the given port.
    Returns the service name in uppercase, or 'UNKNOWN' if not found.
    """
    try:
        # First try to get it from the OS's well-known ports database
        service = socket.getservbyport(port, "tcp")
        return service.upper()
    except OSError:
        # Fallback to our hardcoded dictionary if the OS doesn't know it
        return COMMON_SERVICES.get(port, "UNKNOWN")
