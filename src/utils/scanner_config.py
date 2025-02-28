# scanner_config.py

"""
This module contains the ScannerConfig class, which is responsible for handling
the configuration of the PyScanner network scanner. It uses argparse to parse
command-line arguments and provides methods to validate and process these arguments.
"""

import argparse
import sys
from src.ui import Colors, logger

class ScannerConfig:
    """Configuration class for scanner settings."""

    def __init__(self):
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create and configure argument parser."""
        parser = argparse.ArgumentParser(
            description=f"{Colors.CYAN}PyScanner: A simple network scanner made in Python{Colors.ENDC}",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        target_group = parser.add_mutually_exclusive_group(required=True)
        target_group.add_argument("-t", "--target", help="Target IP or domain name")
        target_group.add_argument("-n", "--network", help="Network to scan (CIDR format, e.g. 192.168.1.0/24)")

        parser.add_argument(
            "-p", "--ports",
            type=str,
            help="Port range (e.g., 20-100)",
            default="1-1024"
        )

        parser.add_argument(
            "-b", "--batchsize",
            type=int,
            help="Port batch size (Increase scan speed)",
            default=500
        )

        parser.add_argument(
            "--txt",
            type=str,
            help="Export results as TXT file (provide filename)",
            metavar="FILENAME"
        )

        parser.add_argument(
            "--json",
            type=str,
            help="Export results as JSON file (provide filename)",
            metavar="FILENAME"
        )

        parser.add_argument(
            "--apikey",
            type=str,
            help="Vulners API key for vulnerability scanning",
            metavar="API_KEY"
        )

        parser.add_argument("-sV", "--vscan", help="Enable version scan", action="store_true")
        parser.add_argument("-O", "--osscan", help="Enable OS detection", action="store_true")
        parser.add_argument("-Pn", "--noping", help="No ping scan", action="store_true")
        parser.add_argument("--no-color", help="Disable colored output", action="store_true")
        parser.add_argument("-V", "--checkvulns", help="Check for known vulnerabilities in NVD db (requires --vscan or -sV)", action="store_true")

        return parser

    def parse_ports(self, ports_str: str) -> range:
        """Parse and validate port range."""
        try:
            start_port, end_port = map(int, ports_str.split("-"))

            if start_port > end_port:
                raise ValueError("Start port must be less than or equal to end port")
            if start_port < 1 or end_port > 65535:
                raise ValueError("Ports must be between 1 and 65535")

            return range(start_port, end_port + 1)

        except ValueError as e:
            logger.error(f"Invalid port range: {e}")
            sys.exit(1)

    @staticmethod
    def check_batch_size(batch_size: int, max_batch_size: int = 5000) -> int:
        """Check and validate the provided ports batchsize."""
        if not isinstance(batch_size, int):
            logger.error("The batchsize argument must be an integer.")

        if batch_size <= 0:
            logger.error("The batchsize argument must be positive and not null.")
            print(f"{Colors.RED}QUITTING!{Colors.ENDC}")
            sys.exit(1)

        if batch_size > max_batch_size:
            logger.error(f"The batchsize argument must be inferior to {max_batch_size}.")
            print(f"{Colors.RED}QUITTING!{Colors.ENDC}")
            sys.exit(1)

        return batch_size