import abc
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from portintel.models.schemas import HostResult

logger = logging.getLogger(__name__)

class DiscoveryStrategy(abc.ABC):
    """
    Base class for discovery strategies.
    Any new discovery method (e.g., ARP, IPv6, DNS) must inherit from this
    and implement the discover() method.
    """
    @abc.abstractmethod
    def discover(self, ip: str, timeout: float) -> Optional[HostResult]:
        """
        Takes an IP address and returns a HostResult if the host is alive,
        or None if the host is unreachable.
        """
        pass

class DiscoveryEngine:
    """
    The core discovery engine responsible for sweeping networks.
    It takes a DiscoveryStrategy, meaning new methods can be added without
    modifying this engine (Open-Closed Principle).
    """
    def __init__(self, strategy: DiscoveryStrategy, threads: int = 100, timeout: float = 1.0):
        self.strategy = strategy
        self.threads = threads
        self.timeout = timeout

    def sweep(self, network: str) -> List[HostResult]:
        """
        Sweeps a given CIDR network and returns a list of alive HostResults.
        """
        alive_hosts = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            ips = [str(ip) for ip in net.hosts()]

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                try:
                    futures = {executor.submit(self.strategy.discover, ip, self.timeout): ip for ip in ips}
                    for future in as_completed(futures):
                        try:
                            res = future.result()
                            if res is not None and res.is_alive:
                                alive_hosts.append(res)
                        except Exception as e:
                            logger.debug(f"Worker thread error during discovery: {e}")
                except KeyboardInterrupt:
                    logger.info("Discovery interrupted by user. Shutting down gracefully...")
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise

            # Sort IPs for predictable output
            alive_hosts.sort(key=lambda x: ipaddress.ip_address(x.ip))
        except ValueError as e:
            logger.error(f"Invalid network format: {e}. Use CIDR notation (e.g., 192.168.1.0/24).")
        except Exception as e:
            logger.error(f"Unexpected error during network discovery: {e}")

        return alive_hosts
