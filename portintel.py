import argparse
import sys
from modules.scanner import scan_range_threaded
from modules.services import get_service_name
from modules.exporter import export_to_csv
from modules.discovery import discover_network

def display_banner():
    print("-" * 40)
    print("PORTINTEL v6.0")
    print("-" * 40)

def main():
    parser = argparse.ArgumentParser(description="Intelligent Network Reconnaissance and Port Analysis Tool")
    parser.add_argument("--target", help="Target IP address or hostname for port scanning")
    parser.add_argument("--network", help="Network CIDR for host discovery (e.g., 192.168.1.0/24)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("--export", type=str, help="Export results to a CSV file (e.g., reports/scan.csv)")
    
    args = parser.parse_args()
    
    if not args.target and not args.network:
        parser.error("You must provide either --target (for port scanning) or --network (for host discovery)")
        
    display_banner()
    
    try:
        if args.network:
            print(f"Mapping Network: {args.network}\n")
            alive_hosts = discover_network(args.network, args.threads)
            
            if not alive_hosts:
                print("No alive hosts found.")
            else:
                for host in alive_hosts:
                    print(f"{host} Alive")
                    
            print("\nDiscovery Complete")
            
        elif args.target:
            print(f"Scanning {args.target}...\n")
            open_ports = scan_range_threaded(args.target, args.start, args.end, args.threads)
            
            if not open_ports:
                print("No open ports found.")
            else:
                print(f"{'PORT':<6} {'SERVICE':<15} {'STATUS'}")
                print("-" * 35)
                for port, banner in open_ports:
                    service = get_service_name(port)
                    print(f"{port:<6} {service:<15} OPEN")
                    if banner:
                        # Truncate very long banners to avoid messing up the terminal
                        display_banner_str = banner if len(banner) <= 60 else banner[:57] + "..."
                        print(f"       └─ Banner: {display_banner_str}")
                    
            print("\nScan Complete")
            
            if args.export and open_ports:
                export_to_csv(args.export, open_ports)
        
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
