import argparse
import ipaddress
import re


def valid_target(value: str) -> str:
    """Validates an IP address or hostname."""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        # Allow localhost or simple hostnames
        if value.lower() == "localhost":
            return value
        hostname_re = re.compile(
            r'^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$'
        )
        if hostname_re.match(value):
            return value
        raise argparse.ArgumentTypeError(f"Invalid IP address or hostname: '{value}'. Ensure it is correctly formatted.")

def valid_network(value: str) -> str:
    """Validates a CIDR network block."""
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid CIDR network format: '{value}'. Example: 192.168.1.0/24")

def valid_port(value: str) -> int:
    """Validates a port number (1-65535)."""
    try:
        port = int(value)
        if 1 <= port <= 65535:
            return port
    except ValueError:
        pass
    raise argparse.ArgumentTypeError(f"Invalid port number: '{value}'. Must be an integer between 1 and 65535.")

def valid_threads(value: str) -> int:
    """Validates thread count (1-5000)."""
    try:
        threads = int(value)
        if 1 <= threads <= 5000:
            return threads
    except ValueError:
        pass
    raise argparse.ArgumentTypeError(f"Invalid thread count: '{value}'. Must be between 1 and 5000.")

def valid_timeout(value: str) -> float:
    """Validates timeout (0.1 - 60.0)."""
    try:
        timeout = float(value)
        if 0.1 <= timeout <= 60.0:
            return timeout
    except ValueError:
        pass
    raise argparse.ArgumentTypeError(f"Invalid timeout: '{value}'. Must be between 0.1 and 60.0 seconds.")
