import socket
from concurrent.futures import ThreadPoolExecutor
from modules.banner import grab_banner

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

def scan_range_threaded(target: str, start_port: int, end_port: int, threads: int) -> list:
    """
    Scans a range of ports on the target using multithreading.
    Returns a list of open ports.
    """
    open_ports = []
    
    def check_port(port):
        if scan_port(target, port):
            banner = grab_banner(target, port)
            return (port, banner)
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(check_port, range(start_port, end_port + 1))
        
    for res in results:
        if res is not None:
            open_ports.append(res)
            
    return open_ports
