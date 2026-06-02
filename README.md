# PortIntel

Intelligent Network Reconnaissance and Port Analysis Tool

## Version History

### v7.0 (Current - The Ultimate Update)
- **UDP Scanning**: Added support for connectionless UDP port scanning via the `--udp` flag.
- **Custom Timeouts**: Configure the socket timeout with `--timeout` to scan over slow networks or speed up local scans.
- **JSON Report Export**: Support for exporting data as API-friendly `.json` files.
- **Vulnerability Lookups**: Automatically cross-references grabbed banners with the National Vulnerability Database (NVD) via the `--vuln` flag to find known CVEs.

### v6.0
- **Host Discovery**: Perform rapid ping sweeps across an entire subnet (e.g., `192.168.1.0/24`) to find live hosts before scanning their ports.

### v5.0
- **CSV Report Export**: Added the ability to dynamically export scan results (Port, Service, Status, Banner) into a formatted CSV file.

### v4.0
- **Banner Grabbing**: Actively connects to open ports to retrieve the server's welcome banner, identifying the exact software and version running (e.g., `OpenSSH_8.2p1`).

### v3.0
- **Service Detection**: Automatically maps open port numbers to their standard service names (e.g., Port 80 to HTTP, Port 3306 to MySQL).
- **Formatted Output**: Displays results in a clean, professional table layout.

### v2.0
- **Multi-threading**: Utilizes concurrent threads to scan hundreds of ports simultaneously, drastically reducing scan time.

### v1.0
- **Basic TCP Scanning**: Core engine built with Python sockets to perform full connect scans.
- **Port Ranges**: Allows users to specify a start and end port.

## Usage
```bash
# Discover all live hosts on a local network
python portintel.py --network 192.168.1.0/24 --threads 100

# Advanced TCP scan with vulnerability lookup and JSON export
python portintel.py --target 127.0.0.1 --start 1 --end 1024 --threads 500 --vuln --export reports/results.json

# UDP scan with a custom 2.0 second timeout
python portintel.py --target 127.0.0.1 --start 1 --end 1024 --udp --timeout 2.0
```
