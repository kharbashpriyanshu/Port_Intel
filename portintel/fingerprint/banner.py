import socket
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class BannerGrabber:
    """
    Dedicated module for connecting to open ports and extracting welcome banners.
    """
    @staticmethod
    def grab(target: str, port: int, timeout: float = 1.0) -> Optional[str]:
        """
        Attempts to connect to the target port and grab its banner.
        Features graceful exception handling and socket cleanup.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))
                
                # Send a basic probe to encourage a response
                if port in [80, 443, 8080]:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                else:
                    s.sendall(b"\r\n")
                
                # Receive up to 1024 bytes of data
                raw_banner = s.recv(1024)
                
                if not raw_banner:
                    return None
                
                # Decode and clean the string
                banner = raw_banner.decode('utf-8', errors='ignore').strip()
                
                # Collapse multiple spaces or newlines into a single line for display
                banner = " ".join(banner.split())
                return banner if banner else None
                
        except socket.timeout:
            logger.debug(f"Timeout while grabbing banner on {target}:{port}")
        except ConnectionRefusedError:
            logger.debug(f"Connection refused while grabbing banner on {target}:{port}")
        except OSError as e:
            logger.debug(f"OS Error while grabbing banner on {target}:{port}: {e}")
        except Exception as e:
            logger.debug(f"Unexpected error while grabbing banner on {target}:{port}: {e}")
            
        return None
