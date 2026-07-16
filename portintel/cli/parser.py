import argparse
import platform
import sys

from portintel import __version__
from portintel.cli.orchestrator import Orchestrator
from portintel.cli.validators import (
    valid_network,
    valid_port,
    valid_target,
    valid_threads,
    valid_timeout,
)
from portintel.config.settings import config
from portintel.utils.logger import setup_logger


def display_banner():
    print("\033[96m" + "=" * 60 + "\033[0m")
    print("\033[1m   PORTINTEL v" + __version__[:3] + " - Intelligent Network Reconnaissance\033[0m")
    print("\033[96m" + "=" * 60 + "\033[0m")

def print_custom_help():
    display_banner()
    help_text = """
\033[1mDESCRIPTION:\033[0m
  PortIntel is a professional-grade, high-performance network scanning
  and intelligence gathering tool. It performs host discovery, port scanning,
  service fingerprinting, and vulnerability intelligence enrichment.

\033[1mAVAILABLE COMMANDS:\033[0m
  scan        Perform a detailed port scan against a target host
  discover    Perform a ping sweep to map a network CIDR
  config      Display the current configuration defaults
  version     Display version and system information
  help        Show this professional help menu

\033[1mEXAMPLES:\033[0m
  # Scan a single host (ports 1-1000)
  portintel scan --target 192.168.1.10 --start 1 --end 1000

  # Scan with vulnerability lookup and export to HTML
  portintel scan --target example.com --vuln --export reports/scan.html

  # Discover alive hosts in a subnet
  portintel discover --network 10.0.0.0/24

\033[1mEXPORT FORMATS:\033[0m
  Supported file extensions for the --export flag:
  .json, .csv, .html, .pdf, .md

\033[1mEXIT CODES:\033[0m
  0 : Success
  1 : General Error / Keyboard Interrupt
  2 : Input Validation Error
"""
    print(help_text)

def show_version():
    display_banner()
    print(f"  \033[1mPortIntel Version\033[0m : {__version__}")
    print(f"  \033[1mPython Version\033[0m    : {sys.version.split(' ')[0]}")
    print(f"  \033[1mOperating System\033[0m  : {platform.system()} {platform.release()} ({platform.architecture()[0]})")
    print("  \033[1mProject Website\033[0m   : https://github.com/kharbashpriyanshu/Port_Intel\n")

def show_config():
    display_banner()
    print("\033[1mCURRENT CONFIGURATION DEFAULTS:\033[0m\n")
    print(f"  Default Timeout : {config.DEFAULT_TIMEOUT} seconds")
    print(f"  Default Threads : {config.DEFAULT_THREADS}")
    print(f"  Max Threads     : {config.MAX_THREADS}")
    print(f"  Report Dir      : {config.DEFAULT_OUTPUT_DIR}")
    print(f"  NVD API URL     : {config.NVD_API_URL}")
    print(f"  User Agent      : {config.USER_AGENT}\n")

class ProfessionalArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        print(f"\n\033[91m[!] Input Error: {message}\033[0m")
        print("Use 'portintel help' for usage instructions.\n")
        sys.exit(2)

def main():
    # Pre-process sys.argv to preserve backward compatibility seamlessly
    if len(sys.argv) > 1 and sys.argv[1] not in ['scan', 'discover', 'config', 'version', 'help', '-h', '--help']:
        if '--target' in sys.argv:
            sys.argv.insert(1, 'scan')
        elif '--network' in sys.argv:
            sys.argv.insert(1, 'discover')

    parser = ProfessionalArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest="command")

    # SCAN COMMAND
    scan_parser = subparsers.add_parser('scan')
    scan_parser.add_argument("--target", required=True, type=valid_target, help="Target IP or hostname")
    scan_parser.add_argument("--start", type=valid_port, default=1, help="Start port (default: 1)")
    scan_parser.add_argument("--end", type=valid_port, default=1024, help="End port (default: 1024)")
    scan_parser.add_argument("--threads", type=valid_threads, default=config.DEFAULT_THREADS, help="Thread count")
    scan_parser.add_argument("--timeout", type=valid_timeout, default=config.DEFAULT_TIMEOUT, help="Timeout in seconds")
    scan_parser.add_argument("--udp", action="store_true", help="Perform UDP scanning")
    scan_parser.add_argument("--vuln", action="store_true", help="Look up CVEs")
    scan_parser.add_argument("--export", type=str, help="Export path (e.g., scan.json)")
    scan_parser.add_argument("--verbose", action="store_true", help="Verbose output")
    scan_parser.add_argument("--debug", action="store_true", help="Debug output")

    # DISCOVER COMMAND
    disc_parser = subparsers.add_parser('discover')
    disc_parser.add_argument("--network", required=True, type=valid_network, help="Network CIDR (e.g., 192.168.1.0/24)")
    disc_parser.add_argument("--threads", type=valid_threads, default=config.DEFAULT_THREADS, help="Thread count")
    disc_parser.add_argument("--timeout", type=valid_timeout, default=config.DEFAULT_TIMEOUT, help="Timeout in seconds")
    disc_parser.add_argument("--export", type=str, help="Export path")
    disc_parser.add_argument("--verbose", action="store_true", help="Verbose output")
    disc_parser.add_argument("--debug", action="store_true", help="Debug output")

    # OTHER COMMANDS
    subparsers.add_parser('config')
    subparsers.add_parser('version')
    subparsers.add_parser('help')

    # Intercept empty args or help flags
    if len(sys.argv) == 1 or sys.argv[1] in ['help', '-h', '--help']:
        print_custom_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.command == 'version':
        show_version()
        sys.exit(0)
    elif args.command == 'config':
        show_config()
        sys.exit(0)

    # Setup logger for functional commands
    logger = setup_logger("portintel", verbose=getattr(args, 'verbose', False), debug=getattr(args, 'debug', False))
    config.setup_directories()

    orchestrator = Orchestrator(
        threads=args.threads,
        timeout=args.timeout,
        is_udp=getattr(args, 'udp', False),
        vuln_lookup=getattr(args, 'vuln', False),
        export_path=args.export
    )

    try:
        if args.command == 'scan':
            if args.start > args.end:
                logger.error("\n\033[91m[!] Input Error: Start port cannot be greater than end port.\033[0m")
                sys.exit(2)
            display_banner()
            orchestrator.run_scan(args.target, args.start, args.end)
        elif args.command == 'discover':
            display_banner()
            orchestrator.run_discovery(args.network)
    except KeyboardInterrupt:
        logger.warning("\n\033[93m[!] Operation aborted by user.\033[0m")
        sys.exit(1)
    except PermissionError as e:
        logger.error(f"\n\033[91m[!] Permission Denied: {e}. You may need elevated privileges.\033[0m")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n\033[91m[!] An unexpected error occurred: {e}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()
