# PortIntel

Intelligent Network Reconnaissance and Port Analysis Tool

## Version History

### v5.0 (Current)
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
# Scan a target using 500 concurrent threads and export results to a CSV
python portintel.py --target 127.0.0.1 --start 1 --end 65535 --threads 500 --export reports/results.csv
```
