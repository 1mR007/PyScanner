#!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# scanner.py

"""This script provides a command-line interface for scanning networks and hosts for open ports, 
services, and vulnerabilities. It supports both single host and network scanning modes, 
with options for exporting results in TXT or JSON formats."""

import signal, os
from .ui.logging import Colors, sys, logger, display_program_info, disable_colors, signal_handler
from .utils.data_classes import datetime
from .utils.scanning import socket, network_port_scan, network_scan, NmapScanner, multi_scan, NVDVulnerabilityScanner
from .utils import stop_event
from .utils.reporting import ScanReport
from .utils.scanner_config import ScannerConfig

def main():
    """
    Main function for the PyScanner program.
    This function initializes the program, parses command-line arguments, sets up scan parameters, 
    and performs network or single host scanning based on the provided arguments. It also handles 
    signal interruptions and generates scan reports.
    
    Steps:
    1. Display program information.
    2. Install signal handler for SIGINT.
    3. Parse command-line arguments.
    4. Disable colors if requested.
    5. Setup scan parameters including ports and scan options.
    6. Create a vulnerability scanner if version scanning and vulnerability checking are enabled.
    7. Perform network scan if network mode is specified.
        - Scan ports on discovered hosts.
        - Get service information for each host if version scanning is enabled.
        - Generate and display network scan report.
    8. Perform single host scan if target mode is specified.
        - Scan open ports on the target host.
        - Get service and OS information if version scanning is enabled.
        - Generate and display host scan report.
    9. Export scan results to a file if requested.
    Raises:
        Exception: If any error occurs during the scanning process.
    """

    # Display informations about the program
    display_program_info()

    # Install signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Parse arguments
    config = ScannerConfig()
    args = config.parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        disable_colors()

    # Setup scan parameters
    ports = config.parse_ports(args.ports)
    start_time = datetime.datetime.now()

    scan_options = []

    version_flag = False

    if args.vscan:
        scan_options.append("-sV")
        version_flag = True
    if args.osscan:
        scan_options.append("-O")
    if args.noping:
        scan_options.append("-Pn")

    batch_size = config.check_batch_size(args.batchsize)

    try:
        # Create the vulnerability scanner
        vuln_scanner = None
        if version_flag and args.checkvulns:
            api_key = args.apikey or os.environ.get("NVD_API_KEY")
            vuln_scanner = NVDVulnerabilityScanner(api_key=api_key)
            
            print(f"{Colors.CYAN}Checking NVD API connection...{Colors.ENDC}")
            if vuln_scanner.test_api_connection():
                logger.info("NVD API is accessible. Proceeding with scan.")
            else:
                logger.warning("NVD API may have rate limiting. Continuing with basic functionality.")

        if args.network:
            # Network scan mode
            logger.info(f"{Colors.CYAN}Starting network scan on {args.network}{Colors.ENDC}")
            network_results = network_scan(args.network, stop_event)

            if network_results and not stop_event.is_set():
                # Scan ports on discovered hosts
                network_port_scan(network_results, ports, batch_size)

                # If version scanning is enabled, get service information for each host
                if version_flag:
                    logger.info("Getting service information for discovered hosts...")

                    for ip, result in network_results.items():
                        if result.open_ports:
                            scanner = NmapScanner(ip, result.open_ports, scan_options)
                            services, os_info = scanner.scan()
                            result.services = services
                            result.os_info = os_info

            # Generate report
            report = ScanReport(start_time)
            report.display_network_report(args.network, network_results, vuln_scanner)

            if args.txt or args.json:
                report.export_network_file(args.network, network_results, args.txt, args.json, vuln_scanner)

        else:
            # Single host scan mode
            target_ip = socket.gethostbyname(
                args.target.replace("https://", "").replace("http://", "").split('/')[0]
            )

            print(f"\nStarting PyScanner at {Colors.YELLOW}{start_time.strftime('%Y-%m-%d %H:%M')}{Colors.ENDC}")
            logger.info(f"Scanning {target_ip} ({args.target}) for open ports {args.ports}")

            open_ports = multi_scan(target_ip, ports, batch_size)
            report = ScanReport(start_time)

            if not open_ports:
                report.display_host_down(target_ip)
                return

            services = {}
            os_info = None

            scanner = NmapScanner(target_ip, open_ports, scan_options)
            services, os_info = scanner.scan()

            # Display report with vulnerability information if available
            scan_data = report.display_host_report(target_ip, open_ports, len(ports),
                                                    services, version_flag, os_info, vuln_scanner)

            if args.txt or args.json:
                report.export_file(scan_data, args.txt, args.json)

    except Exception as e:
        logger.error(f"Scan error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()