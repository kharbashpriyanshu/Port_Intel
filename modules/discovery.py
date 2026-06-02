import subprocess
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def ping_host(ip: str) -> bool:
    """
    Sends a single ICMP ping request to the specified IP.
    Returns True if the host responds, False otherwise.
    """
    # Adjust ping arguments based on the Operating System
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    # Windows timeout is milliseconds, Unix is seconds
    timeout_val = '1000' if platform.system().lower() == 'windows' else '1'
    
    command = ['ping', param, '1', timeout_param, timeout_val, ip]
    
    try:
        # Execute ping. stdout and stderr are piped so they don't print to the console
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # returncode 0 means the ping was successful
        return output.returncode == 0
    except Exception:
        return False

def discover_network(network: str, threads: int = 100) -> list:
    """
    Performs a ping sweep over a given network CIDR.
    Returns a list of alive IP addresses.
    """
    alive_hosts = []
    try:
        # Generate all valid IP addresses in the network range
        net = ipaddress.ip_network(network, strict=False)
        ips = [str(ip) for ip in net.hosts()]
        
        def check_ip(ip):
            if ping_host(ip):
                return ip
            return None
            
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Map the IPs to our thread pool for concurrent pinging
            results = executor.map(check_ip, ips)
            
        for res in results:
            if res is not None:
                alive_hosts.append(res)
                
    except ValueError as e:
        print(f"\n[-] Invalid network format. Use CIDR notation (e.g., 192.168.1.0/24).")
        
    return alive_hosts
