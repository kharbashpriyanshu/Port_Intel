import socket

def scan_port(target: str, port: int) -> bool:
    """
    Attempts to connect to a specific port on the target.
    Returns True if the port is open, False otherwise.
    """
    # Create a socket object (IPv4, TCP)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Set a short timeout
        s.settimeout(0.5)
        # connect_ex returns 0 if successful
        result = s.connect_ex((target, port))
        return result == 0

def scan_range(target: str, start_port: int, end_port: int) -> list:
    """
    Scans a range of ports on the target.
    Returns a list of open ports.
    """
    open_ports = []
    for port in range(start_port, end_port + 1):
        if scan_port(target, port):
            open_ports.append(port)
            
    return open_ports
