import argparse
import sys
from modules.scanner import scan_range

def display_banner():
    print("-" * 40)
    print("PORTINTEL v1.0")
    print("-" * 40)

def main():
    parser = argparse.ArgumentParser(description="Intelligent Network Reconnaissance and Port Analysis Tool")
    parser.add_argument("--target", required=True, help="Target IP address or hostname")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    
    args = parser.parse_args()
    
    display_banner()
    print(f"Scanning {args.target}...\n")
    
    try:
        open_ports = scan_range(args.target, args.start, args.end)
        
        if not open_ports:
            print("No open ports found.")
        else:
            for port in open_ports:
                print(f"[OPEN] {port}")
                
        print("\nScan Complete")
        
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
