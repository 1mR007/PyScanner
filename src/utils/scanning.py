# scanning.py

"""This module provides various network scanning utilities, including TCP scanning, 
Nmap scanning, network discovery, and vulnerability analysis using the NVD API."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import sr1, IP, ICMP, Ether, srp, ARP
import socket
import nmap
import time
import ipaddress
import threading
from typing import List, Tuple, Dict, Optional, Any
from src.utils.data_classes import ServiceInfo, OSInfo, ScanResult
from src.utils import stop_event
from src.ui import logger, Colors
import requests
import psutil
import os

class NmapScanner:
    """Class to handle Nmap scanning operations."""

    def __init__(self, ip: str, open_ports: List[Tuple[int, str]], option_flags: List[str]):
        self.ip = ip
        self.open_ports = open_ports
        self.option_flags = option_flags
        self.nm = nmap.PortScanner()

    def _build_port_range(self) -> str:
        """Convert open ports list to Nmap-compatible port range string."""
        return ",".join(str(port) for port, _ in self.open_ports)

    def _scan_services(self, host: str) -> Dict[int, ServiceInfo]:
        """Scan for service information on open ports."""
        services = {}
        try:
            for port, _ in self.open_ports:
                try:
                    service_data = self.nm[host]["tcp"][port]
                    services[port] = ServiceInfo(
                        name=service_data.get("name", "Unknown"),
                        version=service_data.get("version", "") if "-sV" in self.option_flags else "",
                        product=service_data.get("product", "") if "-sV" in self.option_flags else ""
                    )
                except KeyError:
                    services[port] = ServiceInfo()
        except Exception as e:
            logger.debug(f"Error scanning services: {e}")
            
        return services

    def _scan_os(self, host: str) -> OSInfo:
        """Perform OS detection scan."""
        try:
            os_data = self.nm[host]["osmatch"]
            if os_data:
                return OSInfo(
                    name=os_data[0]["name"],
                    accuracy=int(os_data[0]["accuracy"])
                )
        except (KeyError, IndexError):
            pass
        return OSInfo()

    def scan(self) -> Tuple[Dict[int, ServiceInfo], OSInfo]:
        """Perform the Nmap scan with specified options."""
        if not self.open_ports:
            return {}, OSInfo()

        try:
            services = {}
            os_info = OSInfo()

            if "-sV" not in self.option_flags:
                scan_args = " ".join(self.option_flags + ["-sT"])
            else:
                scan_args = " ".join(self.option_flags)

            port_range = self._build_port_range()
            
            # Show progress for Nmap scan
            print(f"{Colors.BLUE}Running Nmap scan on {self.ip} to get more infos...{Colors.ENDC}")
            self.nm.scan(self.ip, port_range, scan_args)
            
            for host in self.nm.all_hosts():
                if stop_event.is_set():
                    break

                services = self._scan_services(host)

                if "-O" in self.option_flags:
                    os_info = self._scan_os(host)

            return services, os_info

        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return {}, OSInfo()

def tcp_scan(ip: str, port: int, timeout: float = 0.5) -> Optional[Tuple[int, str]]:
    """
    Perform a TCP scan on a specified IP and port.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            return (port, "tcp")
        return None
    except (socket.error, OSError) as e:
        logger.debug(f"{Colors.RED}TCP scan error on {ip}:{port} - {e}{Colors.ENDC}")
        return None

def expand_cidr(network: str) -> List[str]:
    """
    Expand a CIDR network notation to a list of IP addresses.
    """
    try:
        net = ipaddress.IPv4Network(network, strict=False)
        if net.num_addresses > 65536:
            raise ValueError(f"{Colors.RED}Network too large - maximum /16 network allowed{Colors.ENDC}")
        return [str(ip) for ip in net.hosts()]
    except ValueError as e:
        logger.error(f"{Colors.RED}Invalid network address: {e}{Colors.ENDC}")
        return []

def resolve_hostname(ip: str) -> str:
    """
    Resolve the hostname for a given IP address.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def ping_host(ip: str, timeout: float = 0.5) -> Optional[float]:
    """
    Send a single ping to check if host is up, returns latency if successful.
    """
    try:
        start_time = time.time()
        response = sr1(IP(dst=ip)/ICMP(), timeout=timeout, verbose=0)
        if response:
            return time.time() - start_time
        return None
    except Exception:
        return None

def scan_host(ip: str, stop_event: threading.Event) -> Optional[Tuple[str, str, str, Optional[float]]]:
    """
    Scan a single IP address to determine its hostname, MAC address, and latency.
    Optimized version that returns early if host is unreachable.
    """
    if stop_event.is_set():
        return None
    
    # Quick ping test first
    latency = ping_host(ip)
    if latency is None:
        return None
    
    try:
        hostname = resolve_hostname(ip)
        
        # ARP request for MAC address
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        response, _ = srp(arp_request, timeout=0.5, verbose=0)
        
        mac_address = "Unknown"
        if response:
            _, resp = response[0]
            mac_address = resp.hwsrc
            
        return (ip, hostname, mac_address, latency)
    except Exception as e:
        logger.debug(f"{Colors.RED}Error scanning host {ip}: {e}{Colors.ENDC}")
        return None

def network_scan(network: str, stop_event: threading.Event, max_threads: int = 200) -> Dict[str, ScanResult]:
    """
    Scan a network to discover active hosts with progress display.
    """
    try:
        if stop_event.is_set():
            return {}
        
        ip_list = expand_cidr(network)
        number_of_hosts = len(ip_list)
        if not ip_list:
            logger.error(f"{Colors.RED}No valid IP addresses found in network {network}{Colors.ENDC}")
            return {}

        logger.info(f"{Colors.CYAN}Starting network discovery on {network}{Colors.ENDC}")
        logger.info(f"{Colors.CYAN}Scanning {number_of_hosts} potential hosts...{Colors.ENDC}\n")

        scan_results = {}
        completed = 0
        
        with ThreadPoolExecutor(max(200, min(max_threads, number_of_hosts))) as executor:
            futures = {executor.submit(scan_host, ip, stop_event): ip for ip in ip_list}
            
            for future in as_completed(futures):
                if stop_event.is_set():
                    break
                    
                ip = futures[future]
                completed += 1
                
                # Update progress
                progress = (completed / number_of_hosts) * 100
                print(f"{Colors.BLUE}Network scan progress: {progress:.1f}% ({completed}/{number_of_hosts} hosts){Colors.ENDC}", end='\r')
                
                try:
                    result = future.result(timeout=1)
                    if result:
                        ip_res, hostname, mac, latency = result
                        scan_results[ip_res] = ScanResult(
                            ip=ip_res,
                            hostname=hostname,
                            mac_address=mac,
                            latency=latency,
                            open_ports=[],
                            services={},  # Initialize empty services dict
                        )
                except Exception as e:
                    if not stop_event.is_set():
                        logger.debug(f"Error scanning {ip}: {e}")
            
        # Clear the progress line
        print(" " * 80, end='\r')
        
        if scan_results:
            print("\nDiscovered Hosts:")
            for ip, result in scan_results.items():
                latency_str = f"{result.latency*1000:.1f}ms" if result.latency is not None else "Unknown"
                print(f"{Colors.BLUE}{result.hostname} ({ip}){Colors.ENDC} -{Colors.RED} MAC: {result.mac_address}{Colors.ENDC} - {Colors.YELLOW}Latency: {latency_str}{Colors.ENDC}")
        else:
            logger.warning("No active hosts found.")

        print(f"\nScan completed: {len(scan_results)} hosts up")
        return scan_results

    except Exception as e:
        logger.error(f"Error during network scan: {e}")
        return {}
    
def scan_host_ports(ip: str, result: ScanResult, ports: range, batch_size: int) -> None:
    """Scan ports for a specific host in a network scan."""
    try:
        print(f"{Colors.BLUE}Scanning ports for {ip}...{Colors.ENDC}")
        open_ports = multi_scan(ip, ports, batch_size)
        result.open_ports = open_ports
    except Exception as e:
        logger.error(f"Error scanning ports for {ip}: {e}")

def network_port_scan(results: Dict[str, ScanResult], ports: range, batch_size: int = 500, max_threads: int = 100) -> None:
    """Scan ports for all hosts in the network scan results."""
    if not results:
        return
        
    logger.info(f"Starting port scanning for {len(results)} hosts")
    
    with ThreadPoolExecutor(max(100, min(max_threads, len(results)))) as exe:
        futures = {}
        for ip, result in results.items():
            futures[exe.submit(scan_host_ports, ip, result, ports, batch_size)] = ip
            
        # Wait for all scans to complete
        completed = 0

        for future in as_completed(futures):
            ip = futures[future]
            completed += 1
            
            # Update progress
            progress = (completed / len(results)) * 100
            print(f"{Colors.BLUE}Network port scan progress: {progress:.1f}% ({completed}/{len(results)} hosts){Colors.ENDC}", end='\r')
            
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error scanning ports for {ip}: {e}")
                
    # Clear progress line
    print(" " * 80, end='\r')
    logger.info("Port scanning completed for all hosts")

def multi_scan(ip: str, ports: range, batch_size: int = 500) -> List[Tuple[int, str]]:
    """
    Perform a multi-threaded scan on a range of ports using the specified scan type.
    Dynamically adjusts thread count based on system resources.
    """
    global executor
    open_ports = []

    try:
        total_ports = len(ports)

        # Calculate optimal thread count based on system resources and number of ports        
        
        # Get available CPU cores and memory
        cpu_count = os.cpu_count() or 4
        available_memory = psutil.virtual_memory().available / (1024 * 1024)  # In MB
        
        # Determine optimal thread count
        # Each thread consumes roughly 1MB memory
        memory_based_threads = int(available_memory / 2)  # Use max 50% of available memory
        cpu_based_threads = cpu_count * 50  # 50 threads per CPU core is reasonable
        
        # Take the minimum of memory-based and CPU-based thread counts
        optimal_threads = min(memory_based_threads, cpu_based_threads)
        
        # Limit by number of ports
        max_workers = min(optimal_threads, total_ports, 10000)
        
        logger.debug(f"Scanning with {max_workers} threads (CPU: {cpu_count}, Available Memory: {int(available_memory)}MB)")
        
        executor = ThreadPoolExecutor(max_workers=max_workers)
        completed = 0

        # Create an adaptive batch size
        adaptive_batch_size = min(batch_size, max(200, int(total_ports / max_workers)))
        logger.debug(f"Using adaptive batch size: {adaptive_batch_size}")

        for i in range(0, total_ports, adaptive_batch_size):
            if stop_event.is_set():
                break

            batch = list(ports)[i:i + adaptive_batch_size]
            futures = [executor.submit(tcp_scan, ip, port) for port in batch]

            for future in as_completed(futures):
                try:
                    result = future.result(timeout=1)
                    if result is not None:
                        open_ports.append(result)
                    completed += 1

                    # Update progress on the same line with colors
                    progress = (completed / total_ports) * 100
                    print(f"{Colors.BLUE}Port scan progress: {progress:.1f}% ({completed}/{total_ports} ports){Colors.ENDC}", end='\r')

                except Exception as e:
                    completed += 1
                    continue

        # Clear the progress line before returning
        print(" " * 80, end='\r')
        print(f"{Colors.GREEN}Finishing...{Colors.ENDC}")

    except ImportError:
        # If psutil is not available, fall back to default behavior
        logger.warning("psutil not available, using default thread configuration")
        max_workers = min(5000, total_ports)
        executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Continue with the default scanning logic
        total_ports = total_ports
        completed = 0

        for i in range(0, total_ports, batch_size):
            if stop_event.is_set():
                break

            batch = list(ports)[i:i + batch_size]
            futures = [executor.submit(tcp_scan, ip, port) for port in batch]

            for future in as_completed(futures):
                try:
                    result = future.result(timeout=1)
                    if result is not None:
                        open_ports.append(result)
                    completed += 1

                    # Update progress on the same line with colors
                    progress = (completed / total_ports) * 100
                    print(f"{Colors.BLUE}Port scan progress: {progress:.1f}% ({completed}/{total_ports} ports){Colors.ENDC}", end='\r')

                except Exception as e:
                    completed += 1
                    continue

        # Clear the progress line before returning
        print(" " * 80, end='\r')
        print(f"{Colors.GREEN}Finishing...{Colors.ENDC}")
        
    except Exception as e:
        if not stop_event.is_set():
            logger.error(f"Error during scan: {e}")
    finally:
        if executor:
            executor.shutdown(wait=False)
            executor = None

    return sorted(open_ports)

class NVDVulnerabilityScanner:
    """Class to handle vulnerability scanning using the NVD API."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.enabled = True  # NVD API is free to use, with rate limiting. You can always use a key for less rate limiting
        self._cache = {}  # Simple cache
        self._threat_lookup = {
            "critical": f"{Colors.RED}Critical{Colors.ENDC}",
            "high": f"{Colors.MAGENTA}High{Colors.ENDC}",
            "medium": f"{Colors.YELLOW}Medium{Colors.ENDC}",
            "low": f"{Colors.BLUE}Low{Colors.ENDC}",
        }
        
    def fetch_vulnerabilities(self, software: str, version: str, port: int = None) -> list:
        """Fetch vulnerabilities for a specific software and version from NVD."""
        cache_key = f"{software}:{version}"
        if cache_key in self._cache:
            logger.debug(f"Cache hit for {cache_key}")
            vulns = self._cache[cache_key]
            # Add port information if needed
            if port:
                for vuln in vulns:
                    vuln['service_port'] = port
            return vulns

        try:
            # Format product and version for NVD CPE format
            # Example: apache:http_server:2.4.49
            # Convert common naming conventions
            # Convert spaces to underscores
            product_formatted = software.lower().replace(' ', '_')
            
            # Build query parameters
            params = {
                "keywordSearch": f"{software} {version}",
                "resultsPerPage": 20  # Limit results
            }
            
            # Add API key if provided
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
                
            logger.debug(f"Fetching vulnerabilities for {software} {version}")
            
            data = self._make_api_request(self.base_url, params)

            if data is None:
                logger.warning(f"Failed to fetch vulnerabilities for {software} {version}")
                return []
            
            vulnerabilities = data.get("vulnerabilities", [])
            formatted_vulns = self._format_vulnerabilities(vulnerabilities)
            
            # Add service information
            for vuln in formatted_vulns:
                vuln['service_name'] = software
                vuln['service_version'] = version
                if port:
                    vuln['service_port'] = port
            
            self._cache[cache_key] = formatted_vulns
            return formatted_vulns

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching vulnerabilities: {e}")
            return []
        
    def _make_api_request(self, url, params, max_retries=3):
        """
        Makes an API request to the specified URL with the given parameters and handles retries in case of rate limiting or request failures.
        """
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        retry_count = 0
        base_wait_time = 30
        
        while retry_count < max_retries:
            try:
                response = requests.get(url, params=params, headers=headers)
                
                if response.status_code == 200:
                    return response.json()
                    
                elif response.status_code == 429:
                    retry_count += 1
                    
                    # Backoff exponentiel
                    wait_time = base_wait_time * (2 ** retry_count)
                    logger.warning(f"Rate limit exceeded. Waiting {wait_time} seconds before retry.")
                    print(f"{Colors.YELLOW}NVD API rate limit reached. Waiting {wait_time} seconds...{Colors.ENDC}")
                    time.sleep(wait_time)
                else:
                    logger.error(f"API request failed with status code: {response.status_code}")
                    return None
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error: {e}")
                return None
                
        logger.error(f"Maximum retries ({max_retries}) reached. Giving up.")
        return None

    def _format_vulnerabilities(self, vulnerabilities: list) -> list:
        """Format the list of vulnerabilities returned by the NVD API."""
        formatted_vulnerabilities = []
        
        for vuln_item in vulnerabilities:
            try:
                vuln = vuln_item.get("cve", {})
                
                # Extract basic information
                cve_id = vuln.get("id", "N/A")
                description = "No description available"
                
                # Get the English description
                descriptions = vuln.get("descriptions", [])
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "No description available")
                        break
                
                # Extract CVSS data
                cvss = "N/A"
                
                metrics = vuln.get("metrics", {})
                
                # Try CVSS 3.1 first
                cvss31 = metrics.get("cvssMetricV31", [])
                if cvss31:
                    base_score = cvss31[0].get("cvssData", {}).get("baseScore")
                    if base_score is not None:
                        cvss = base_score
                
                # If CVSS 3.1 not available, try CVSS 3.0
                if cvss == "N/A":
                    cvss30 = metrics.get("cvssMetricV30", [])
                    if cvss30:
                        base_score = cvss30[0].get("cvssData", {}).get("baseScore")
                        if base_score is not None:
                            cvss = base_score
                
                # If neither 3.0 nor 3.1 available, try CVSS 2.0
                if cvss == "N/A":
                    cvss2 = metrics.get("cvssMetricV2", [])
                    if cvss2:
                        base_score = cvss2[0].get("cvssData", {}).get("baseScore")
                        if base_score is not None:
                            cvss = base_score
                
                # Get severity level (both raw and formatted)
                severity_info = self._get_severity_level(cvss)
                
                # Get published and last modified dates
                published = vuln.get("published", "Unknown")
                modified = vuln.get("lastModified", "Unknown")
                
                # Get references
                references = []
                refs = vuln.get("references", [])
                for ref in refs:
                    url = ref.get("url")
                    if url:
                        references.append(url)
                
                # Check if there are known exploits
                has_exploit = False
                for ref in refs:
                    tags = ref.get("tags", [])
                    if "Exploit" in tags or "exploit" in tags:
                        has_exploit = True
                        break
                
                formatted = {
                    "title": description[:60] + "..." if len(description) > 60 else description,
                    "id": cve_id,
                    "severity": severity_info["formatted"],  # Colored version for display
                    "severity_raw": severity_info["raw"],    # Raw version for counting and filtering
                    "cvss": cvss,
                    "description": self._truncate_description(description),
                    "published": published,
                    "modified": modified,
                    "references": references,
                    "has_exploit": has_exploit,
                    "affected_version": []
                }
                
                formatted_vulnerabilities.append(formatted)
            except Exception as e:
                logger.error(f"Error formatting vulnerability: {e}")
                continue

        # Sort by CVSS score (highest first)
        return sorted(
            formatted_vulnerabilities, 
            key=lambda x: float(x["cvss"]) if isinstance(x["cvss"], (int, float, str)) and x["cvss"] != "N/A" else 0,
            reverse=True
        )
    
    def _truncate_description(self, description: str, max_length: int = 200) -> str:
        """Truncate long descriptions for display purposes."""
        if len(description) > max_length:
            return description[:max_length] + "..."
        return description
    
    def _get_severity_level(self, cvss) -> dict:
        """
        Get the severity level based on CVSS score.
        Returns both raw level and formatted level with colors.
        """
        try:
            if cvss == "N/A":
                return {
                    "raw": "Unknown",
                    "formatted": "Unknown"
                }
            
            score = float(cvss)
            if score >= 9.0:
                return {
                    "raw": "Critical",
                    "formatted": self._threat_lookup["critical"]
                }
            elif score >= 7.0:
                return {
                    "raw": "High",
                    "formatted": self._threat_lookup["high"]
                }
            elif score >= 4.0:
                return {
                    "raw": "Medium",
                    "formatted": self._threat_lookup["medium"]
                }
            else:
                return {
                    "raw": "Low",
                    "formatted": self._threat_lookup["low"]
                }
        except (ValueError, TypeError):
            return {
                "raw": "Unknown",
                "formatted": "Unknown"
            }

    def analyze_service(self, service_name: str, service_version: str, port: int = None) -> list:
        """Analyze a single service and return potential vulnerabilities."""
        if not self.enabled or service_name == "Unknown" or not service_version:
            return []
        
        try:
            logger.debug(f"Analyzing service {service_name}:{service_version} on port {port}")
            vulnerabilities = self.fetch_vulnerabilities(service_name, service_version, port)
            
            # Ensure each vulnerability has the associated port
            for vuln in vulnerabilities:
                if port is not None and 'service_port' not in vuln:
                    vuln['service_port'] = port
                
            logger.debug(f"Found {len(vulnerabilities)} vulnerabilities for {service_name}")
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error analyzing service {service_name}:{service_version} - {e}")
            return []

    def analyze_services_parallel(self, services_dict: Dict[int, ServiceInfo]) -> Dict[int, list]:
        """Analyze multiple services in parallel and return results."""
        if not self.enabled:
            return {}
        
        results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for port, service in services_dict.items():
                if service.name != "Unknown" and service.version:
                    future = executor.submit(self.analyze_service, service.name, service.version, port)
                    futures[future] = port
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    vulnerabilities = future.result()
                    if vulnerabilities:
                        results[port] = vulnerabilities
                except Exception as e:
                    logger.error(f"Error in vulnerability analysis for port {port}: {e}")
        
        return results
    
    def test_api_connection(self) -> bool:
        """Test the connection to the NVD API."""
        try:
            # Simple query to test the API
            response = requests.get(
                self.base_url,
                params={"keywordSearch": "test", "resultsPerPage": 1}
            )
            
            if response.status_code == 200:
                print(f"{Colors.GREEN}Successfully connected to NVD API.{Colors.ENDC}")
                return True
            else:
                logger.error(f"Failed to connect to NVD API. Status code: {response.status_code}")
                print(f"{Colors.RED}Failed to connect to NVD API. Status code: {response.status_code}{Colors.ENDC}")
            
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error testing NVD API connection: {e}")
            print(f"{Colors.RED}Error testing NVD API connection: {e}{Colors.ENDC}")
            return False