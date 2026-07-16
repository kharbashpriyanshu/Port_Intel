import logging
import socket
from typing import Optional

from portintel.discovery.engine import DiscoveryStrategy
from portintel.models.schemas import HostResult

logger = logging.getLogger(__name__)

class TCPDiscoveryStrategy(DiscoveryStrategy):
    """
    Discovers hosts by attempting to establish a TCP connection to common ports.
    This serves as an example of extending the engine.
    """
    def __init__(self, ports=(80, 443, 22, 445)):
        self.ports = ports

    def discover(self, ip: str, timeout: float) -> Optional[HostResult]:
        for port in self.ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        return HostResult(ip=ip, is_alive=True)
            except OSError as e:
                logger.debug(f"OS error during TCP discovery on {ip}:{port} : {e}")
            except Exception as e:
                logger.debug(f"Unexpected error during TCP discovery on {ip}:{port} : {e}")

        return None
