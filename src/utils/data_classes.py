# data_classes.py

"""
This module defines data classes and enumerations for storing and managing
network scan results, including information about services, operating systems,
and vulnerabilities.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple, Dict, Optional
import datetime

@dataclass
class ServiceInfo:
    """Data class to store information about a service running on a port."""
    name: str = "Unknown"
    version: str = "Unknown"
    product: str = "Unknown"

@dataclass
class OSInfo:
    """Data class to store information about the detected operating system."""
    name: str = "Unknown"
    accuracy: int = 0

    @property
    def description(self) -> str:
        """Return a formatted description of the OS information."""
        return f"{self.name} (Accuracy: {self.accuracy}%)"
    
@dataclass
class ScanResult:
    """Class to store scan results for a host."""
    ip: str
    hostname: str = "Unknown"
    mac_address: str = "Unknown"
    latency: Optional[float] = None
    open_ports: List[Tuple[int, str]] = field(default_factory=list)
    os_info: Optional[OSInfo] = None
    services: Dict[int, ServiceInfo] = field(default_factory=dict)
    
    # Add vulnerability tracking
    def add_vulnerabilities(self, port: int, vulnerabilities: list) -> None:
        """Add vulnerabilities for a specific port."""
        setattr(self, f"vulns_{port}", vulnerabilities)
    
    def get_vulnerabilities(self, port: int = None) -> list:
        """Get vulnerabilities for a specific port or all ports."""
        if port is not None:
            return getattr(self, f"vulns_{port}", [])
        
        # Get all vulnerabilities across all ports
        all_vulns = []
        for port, _ in self.open_ports:
            all_vulns.extend(getattr(self, f"vulns_{port}", []))
        return all_vulns
    
    @property
    def total_vulnerabilities(self) -> int:
        """Get the total count of vulnerabilities across all ports."""
        return len(self.get_vulnerabilities())
    
    @property
    def high_vulnerabilities(self) -> int:
        """Get the count of high severity vulnerabilities (CVSS >= 7.0)."""
        return sum(1 for v in self.get_vulnerabilities() if isinstance(v, dict) and v.get('cvss', 0) >= 7.0)

@dataclass
class NetworkScanResult:
    """Data class to store the result of a network-wide scan."""
    network: str
    hosts: Dict[str, ScanResult]
    start_time: datetime.datetime
    duration: float

# Type definitions
class ScanType(Enum):
    """Enumeration for different types of network scans."""
    TCP = "tcp"