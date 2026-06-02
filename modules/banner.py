import socket

def grab_banner(target: str, port: int, timeout: float = 1.0) -> str:
    """
    Attempts to connect to the target port and grab its banner/welcome message.
    Returns the banner string, or an empty string if none is found.
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
            
            # Decode and clean the string
            banner = raw_banner.decode('utf-8', errors='ignore').strip()
            
            # Collapse multiple spaces or newlines into a single line for display
            banner = " ".join(banner.split())
            
            return banner
            
    except Exception:
        # If the connection drops, times out, or the server sends no data
        return ""
