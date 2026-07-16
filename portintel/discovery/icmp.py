import subprocess
import platform
import logging
from typing import Optional
from portintel.models.schemas import HostResult
from portintel.discovery.engine import DiscoveryStrategy

logger = logging.getLogger(__name__)

class ICMPDiscoveryStrategy(DiscoveryStrategy):
    """
    Discovers hosts using ICMP Ping packets.
    """
    def discover(self, ip: str, timeout: float) -> Optional[HostResult]:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        
        # Convert timeout appropriately for the OS ping command
        timeout_val = str(int(timeout * 1000)) if platform.system().lower() == 'windows' else str(max(1, int(timeout)))
        
        command = ['ping', param, '1', timeout_param, timeout_val, ip]
        
        try:
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if output.returncode == 0:
                return HostResult(ip=ip, is_alive=True)
        except OSError as e:
            logger.debug(f"OS error during ICMP ping for {ip}: {e}")
        except Exception as e:
            logger.debug(f"Unexpected error during ICMP ping for {ip}: {e}")
            
        return None
