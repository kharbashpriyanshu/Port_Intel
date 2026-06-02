import socket
from concurrent.futures import ThreadPoolExecutor
from modules.banner import grab_banner

def scan_port(target: str, port: int, timeout: float = 0.5, is_udp: bool = False) -> bool:
    """
    Attempts to connect to a specific port on the target.
    Returns True if the port is open, False otherwise.
    """
    if is_udp:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                # Send a blank payload to trigger a response
                s.sendto(b'\x00\x00\x00\x00', (target, port))
                s.recvfrom(1024)
                return True
            except Exception:
                return False
    else:
        # Create a socket object (IPv4, TCP)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            return result == 0

def scan_range_threaded(target: str, start_port: int, end_port: int, threads: int, timeout: float = 0.5, is_udp: bool = False) -> list:
    """
    Scans a range of ports on the target using multithreading.
    Returns a list of open ports.
    """
    open_ports = []
    
    def check_port(port):
        if scan_port(target, port, timeout, is_udp):
            # Only grab banners for TCP connections
            banner = ""
            if not is_udp:
                banner = grab_banner(target, port, timeout)
            return (port, banner)
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(check_port, range(start_port, end_port + 1))
        
    for res in results:
        if res is not None:
            open_ports.append(res)
            
    return open_ports
