import argparse
import sys
import logging
from portintel.config.settings import config
from portintel.utils.logger import setup_logger
from portintel.cli.orchestrator import Orchestrator

def display_banner(logger: logging.Logger):
    logger.info("-" * 40)
    logger.info("PORTINTEL v7.0")
    logger.info("-" * 40)

def main():
    parser = argparse.ArgumentParser(description="Intelligent Network Reconnaissance and Port Analysis Tool")
    parser.add_argument("--target", help="Target IP address or hostname for port scanning")
    parser.add_argument("--network", help="Network CIDR for host discovery (e.g., 192.168.1.0/24)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--threads", type=int, default=config.DEFAULT_THREADS, help=f"Number of concurrent threads (default: {config.DEFAULT_THREADS})")
    parser.add_argument("--timeout", type=float, default=config.DEFAULT_TIMEOUT, help=f"Timeout in seconds for port scanning (default: {config.DEFAULT_TIMEOUT})")
    parser.add_argument("--udp", action="store_true", help="Perform UDP scanning instead of TCP")
    parser.add_argument("--vuln", action="store_true", help="Look up potential CVEs based on the grabbed banner")
    parser.add_argument("--export", type=str, help="Export results to a CSV or JSON file (e.g., reports/scan.json)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    if not args.target and not args.network:
        parser.error("You must provide either --target (for port scanning) or --network (for host discovery)")
        
    # Setup global logger
    logger = setup_logger("portintel", verbose=args.verbose, debug=args.debug)
    
    # Initialize Settings directories
    config.setup_directories()
        
    display_banner(logger)
    
    orchestrator = Orchestrator(
        threads=args.threads,
        timeout=args.timeout,
        is_udp=args.udp,
        vuln_lookup=args.vuln,
        export_path=args.export
    )
    
    try:
        if args.network:
            orchestrator.run_discovery(args.network)
        elif args.target:
            orchestrator.run_scan(args.target, args.start, args.end)
            
    except KeyboardInterrupt:
        logger.info("\nScan aborted by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\nAn error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
