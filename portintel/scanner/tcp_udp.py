import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable, Optional
from portintel.models.schemas import PortResult

logger = logging.getLogger(__name__)

class ThreadedScanner:
    """Reusable thread pool executor for concurrent scanning operations."""
    
    def __init__(self, threads: int):
        self.threads = threads

    def execute(self, worker_func: Callable[[int], Optional[PortResult]], items: List[int]) -> List[PortResult]:
        """
        Executes a worker function concurrently over a list of items.
        Features graceful shutdown and exception handling.
        """
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            try:
                # Map futures to their respective item for potential tracking
                futures = {executor.submit(worker_func, item): item for item in items}
                for future in as_completed(futures):
                    try:
                        res = future.result()
                        if res is not None:
                            results.append(res)
                    except Exception as e:
                        logger.debug(f"Worker thread encountered an error: {e}")
            except KeyboardInterrupt:
                logger.info("Scan interrupted by user. Initiating graceful shutdown...")
                executor.shutdown(wait=False, cancel_futures=True)
                raise
        
        # Maintain order by sorting results by port number
        results.sort(key=lambda x: x.port)
        return results

def scan_tcp_port(target: str, port: int, timeout: float) -> Optional[PortResult]:
    """
    Scans a single TCP port.
    Catches specific exceptions and returns a PortResult if open.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                # Note: service and banner will be enriched by the orchestrator
                return PortResult(port=port, service="", status="OPEN")
    except socket.timeout:
        logger.debug(f"Timeout connecting to {target}:{port} (TCP)")
    except ConnectionRefusedError:
        logger.debug(f"Connection refused by {target}:{port} (TCP)")
    except PermissionError:
        logger.debug(f"Permission denied to connect to {target}:{port} (TCP)")
    except OSError as e:
        logger.debug(f"OS error connecting to {target}:{port} (TCP): {e}")
    except Exception as e:
        logger.debug(f"Unexpected error connecting to {target}:{port} (TCP): {e}")
    return None

def scan_udp_port(target: str, port: int, timeout: float) -> Optional[PortResult]:
    """
    Scans a single UDP port.
    Catches specific exceptions and returns a PortResult if open.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(bytes([0, 0, 0, 0]), (target, port))
            # Wait for response (if any) or ICMP port unreachable
            s.recvfrom(1024)
            return PortResult(port=port, service="", status="OPEN")
    except socket.timeout:
        logger.debug(f"Timeout connecting to {target}:{port} (UDP)")
    except ConnectionRefusedError:
        logger.debug(f"Connection refused by {target}:{port} (UDP)")
    except PermissionError:
        logger.debug(f"Permission denied to connect to {target}:{port} (UDP)")
    except OSError as e:
        logger.debug(f"OS error connecting to {target}:{port} (UDP): {e}")
    except Exception as e:
        logger.debug(f"Unexpected error connecting to {target}:{port} (UDP): {e}")
    return None

def scan_range_threaded(target: str, start_port: int, end_port: int, threads: int, timeout: float = 0.5, is_udp: bool = False) -> List[PortResult]:
    """
    Scans a range of ports on the target using a reusable threaded engine.
    """
    logger.debug(f"Starting engine for {target} ports {start_port}-{end_port} (Threads: {threads})")
    scanner = ThreadedScanner(threads=threads)
    ports = list(range(start_port, end_port + 1))
    
    if is_udp:
        worker = lambda p: scan_udp_port(target, p, timeout)
    else:
        worker = lambda p: scan_tcp_port(target, p, timeout)

    return scanner.execute(worker, ports)
