# reporting.py

"""Module for handling scan result reporting in PyScanner."""

from src.utils.data_classes import datetime, List, Tuple, Dict, Optional, ServiceInfo, OSInfo, ScanResult
from src.utils.scanning import NVDVulnerabilityScanner
from src.ui import Colors, logger
from src.utils import stop_event
import json

class ScanReport:
    """Class to handle scan result reporting."""

    def __init__(self, start_time: datetime.datetime):
        self.start_time = start_time
        self.end_time = datetime.datetime.now()

    @property
    def duration(self) -> float:
        """Calculate the duration of the scan."""
        return (self.end_time - self.start_time).total_seconds()

    def _format_header(self, width: int = 50) -> str:
        """Format a header line for the report."""
        return Colors.CYAN + "-" * width + Colors.ENDC

    def display_host_down(self, ip: str) -> None:
        """Display report for unreachable host."""
        print(f"\nStarting PyScanner at {self.start_time.strftime('%Y-%m-%d %H:%M')}")
        print(f"PyScanner scan report for {Colors.BOLD}{ip}{Colors.ENDC}")
        print(f"PyScanner done: 1 IP address ({Colors.RED}0 hosts up{Colors.ENDC}) scanned in {Colors.YELLOW}{self.duration:.2f} seconds{Colors.ENDC}")
        
    def display_host_report(
        self,
        ip: str,
        open_ports: List[Tuple[int, str]],
        total_ports: int,
        services: Dict[int, ServiceInfo],
        version_flag: bool,
        os_info: Optional[OSInfo] = None,
        vuln_scanner: Optional[NVDVulnerabilityScanner] = None
    ) -> Dict:
        """Display detailed scan report for a single host and return structured data."""
        
        if stop_event.is_set():
            return {}

        display_note = False

        scan_data = {
            "target": ip,
            "status": "up" if open_ports else "down",
            "latency": self.duration,
            "ports": [],
            "os_info": os_info.description if os_info and os_info.name != "Unknown" else "Unknown",
            "vulnerabilities": []
        }

        print(f"\n{Colors.BOLD}PyScanner scan report for {Colors.CYAN}{ip}{Colors.ENDC}{Colors.BOLD} :{Colors.ENDC}\n")

        if not open_ports:
            print(f"{Colors.RED}No open ports found{Colors.ENDC}")
            print(f"Not shown: {total_ports} closed ports")
        else:
            print(f"{Colors.GREEN}Host is up{Colors.ENDC} ({Colors.YELLOW}{self.duration:.5f}s latency{Colors.ENDC}).")
            print(f"Not shown: {total_ports - len(open_ports)} closed ports")

            header = self._format_header(60 if version_flag else 30)
            print(header)
            if version_flag:
                print(f"{Colors.BOLD}{'PORT':<10}{'STATE':<10}{'SERVICE':<14}{'VERSION':<26}{Colors.ENDC}")
            else:
                print(f"{Colors.BOLD}{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{Colors.ENDC}")
            print(header)

            # Group vulnerabilities by severity for summary
            all_vulnerabilities = []
            critical_vulns = 0
            high_vulns = 0
            medium_vulns = 0
            low_vulns = 0
            
            for port, proto in sorted(open_ports):
                if stop_event.is_set():
                    break

                service_info = services.get(port, ServiceInfo())
                name = service_info.name or "Unknown"
                
                # Prepare version display string
                if version_flag:
                    version_str = f"{service_info.product} {service_info.version}".strip()
                    version_display = version_str if version_str else "N/A"
                    print(f"{f'{port}/{proto}':<10}{Colors.GREEN}{'open':<10}{Colors.ENDC}{Colors.BLUE}{name:<14}{Colors.ENDC}{Colors.YELLOW}{version_display:<26}{Colors.ENDC}")
                else:
                    version_display = "N/A"
                    print(f"{f'{port}/{proto}':<10}{Colors.GREEN}{'open':<10}{Colors.ENDC}{Colors.BLUE}{name:<15}{Colors.ENDC}")

                # Add port information to scan data
                port_data = {
                    "port": port,
                    "protocol": proto,
                    "state": "open",
                    "service": name,
                    "version": version_display if version_flag else "N/A",
                    "vulnerabilities": []
                }
                
                # Check for vulnerabilities if scanner is available and we have version info
                if vuln_scanner and vuln_scanner.enabled and version_flag and name != "Unknown" and version_display != "N/A":
                    vulnerabilities = vuln_scanner.analyze_service(name, version_display)

                    if vulnerabilities:
                        port_data["vulnerabilities"] = vulnerabilities
                        scan_data["vulnerabilities"].extend(vulnerabilities)
                        all_vulnerabilities.extend(vulnerabilities)
                        
                        for vuln in vulnerabilities:
                            severity_raw = vuln.get('severity_raw', '').lower()
                            if "critical" in severity_raw:
                                critical_vulns += 1
                            elif "high" in severity_raw:
                                high_vulns += 1
                            elif "medium" in severity_raw:
                                medium_vulns += 1
                            elif "low" in severity_raw:
                                low_vulns += 1
                    
                    # Display vulnerability summary if we found any
                    if all_vulnerabilities:
                        print(f"\n{Colors.RED}Potential vulnerabilities found on target !{Colors.ENDC}")
                        self.display_threat_gauge(all_vulnerabilities)

                        total_vulns = len(all_vulnerabilities)

                        print(f"\n{Colors.BOLD}{Colors.YELLOW}VULNERABILITY SUMMARY:{Colors.ENDC}")
                        print(f"{self._format_header(60)}")
                        print(f"{Colors.BOLD}Found {total_vulns} potential vulnerabilities across all services:{Colors.ENDC}")
                        print(f" • {Colors.RED}Critical: {critical_vulns}{Colors.ENDC}")
                        print(f" • {Colors.MAGENTA}High: {high_vulns}{Colors.ENDC}")
                        print(f" • {Colors.YELLOW}Medium: {medium_vulns}{Colors.ENDC}")
                        print(f" • {Colors.BLUE}Low: {low_vulns}{Colors.ENDC}")
                        
                        if total_vulns > 0:
                            print(f"\n{Colors.BOLD}TOP VULNERABILITIES:{Colors.ENDC}")
                            
                            # Sort vulnerabilities by CVSS score (highest first)
                            sorted_vulns = sorted(all_vulnerabilities, 
                                                key=lambda v: float(v['cvss']) if isinstance(v['cvss'], (int, float, str)) and v['cvss'] != 'N/A' else 0, 
                                                reverse=True)
                            
                            # Show top 5 or fewer vulnerabilities
                            top_vulns = sorted_vulns[:5]
                            
                            for i, vuln in enumerate(top_vulns, 1):
                                cvss = vuln.get('cvss', 'N/A')
                                cvss_display = f"{cvss}" if cvss != 'N/A' else 'N/A'
                                
                                severity = vuln.get('severity', 'Unknown')
                                title = vuln.get('title', 'Unknown vulnerability')
                                vuln_id = vuln.get('id', 'N/A')
                                
                                print(f"{Colors.BOLD}{i}. [{severity}] {Colors.CYAN}{title}{Colors.ENDC}")
                                print(f"   ID: {vuln_id} | CVSS: {cvss_display}")
                    else:
                        print(f"\n{Colors.GREEN}No vulnerabilities were found on this service.{Colors.ENDC}\n")
                
                scan_data["ports"].append(port_data)

        if os_info and os_info.name != "Unknown":
            print(f"\n{Colors.CYAN}OS Detection:{Colors.ENDC} {Colors.YELLOW}{os_info.description}{Colors.ENDC}")

        print(f"\nPyScanner done: 1 IP address ({Colors.GREEN}1 host up{Colors.ENDC}) scanned in {Colors.YELLOW}{self.duration:.2f} seconds{Colors.ENDC}")

        if display_note:
            logger.warning(f"Services discovery has failed. Try again using -Pn")

        if vuln_scanner and vuln_scanner.enabled and all_vulnerabilities:
            # Save detailed vulnerability information to a JSON file
            json_filename = f"{ip}_vulnerabilities.json"
            try:
                with open(json_filename, "w", encoding="utf-8") as json_file:
                    json.dump(scan_data, json_file, indent=4)
                print(f"{Colors.GREEN}Detailed vulnerability information saved to {json_filename}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.RED}Error saving JSON file: {e}{Colors.ENDC}")

        return scan_data

    def display_network_report(
        self,
        network: str,
        scan_results: Dict[str, ScanResult],
        vuln_scanner: Optional[NVDVulnerabilityScanner] = None
    ) -> None:
        """Display network scan report with vulnerability summary."""
        if stop_event.is_set():
            return

        total_hosts = len(scan_results)
        total_vulns = 0
        high_vulns = 0

        print(f"\nStarting PyScanner at {self.start_time.strftime('%Y-%m-%d %H:%M')}")
        print(f"PyScanner scan report for {Colors.BOLD}{network}{Colors.ENDC}")
        print(f"{Colors.GREEN}{total_hosts} hosts up{Colors.ENDC}")
        
        if total_hosts > 0:
            print(f"\n{self._format_header(80)}")
            print(f"{Colors.BOLD}{'HOST':<19}{'STATUS':<10}{'LATENCY':<12}{'MAC ADDRESS':<20}{'OPEN PORTS':<20}{Colors.ENDC}")
            print(f"{self._format_header(80)}")

            for ip, result in scan_results.items():
                latency_str = f"{result.latency*1000:.1f}ms" if result.latency else "Unknown"
                hostname_display = f"{result.hostname}" if result.hostname != "Unknown" else ""
                ip_display = f"{ip}"
                if hostname_display:
                    host_str = f"{hostname_display} ({ip_display})"
                else:
                    host_str = ip_display
                
                host_str = host_str[:15] + "..." if len(host_str) > 15 else host_str.ljust(15)
                
                # Format open ports as a comma-separated list
                ports_str = ", ".join([f"{port}/{proto}" for port, proto in result.open_ports]) if result.open_ports else "None"
                
                # Count vulnerabilities if available
                host_vulns = 0
                host_high_vulns = 0
                
                if hasattr(result, 'services') and result.services:
                    for port, proto in result.open_ports:
                        service_info = result.services.get(port, ServiceInfo())
                        name = service_info.name or "Unknown"
                        version_str = f"{service_info.product} {service_info.version}".strip()
                        version_display = version_str if version_str else "N/A"
                        
                        # Count vulnerabilities for this service
                        if name != "Unknown" and version_display != "N/A":
                            vulnerabilities = vuln_scanner.analyze_service(name, version_display)
                            host_vulns += len(vulnerabilities)
                            
                            # Count high severity vulnerabilities (CVSS >= 7.0)
                            for vuln in vulnerabilities:
                                if isinstance(vuln, dict) and vuln.get('cvss', 0) >= 7.0:
                                    host_high_vulns += 1
                                    high_vulns += 1
                
                total_vulns += host_vulns
                vuln_display = f" [{Colors.RED}{host_vulns} vulns{Colors.ENDC}]" if host_vulns > 0 else ""
                
                print(f"{host_str} {Colors.GREEN}{'up':<10}{Colors.ENDC}{Colors.YELLOW}{latency_str:<12}{Colors.ENDC}{Colors.BLUE}{result.mac_address:<20}{Colors.ENDC}{ports_str}{vuln_display}")
            
            print(f"{self._format_header(80)}")
            
            if total_vulns > 0:
                print(f"\n{Colors.RED}Vulnerability Summary:{Colors.ENDC}")
                print(f"{Colors.RED}Total vulnerabilities found: {total_vulns}{Colors.ENDC}")
                print(f"{Colors.RED}High/Critical severity vulnerabilities: {high_vulns}{Colors.ENDC}")
                print(f"{Colors.YELLOW}Run with --json or --txt options for detailed vulnerability information{Colors.ENDC}")
        
                all_vulns = []

                for ip, result in scan_results.items():
                    if hasattr(result, 'vulnerabilities') and result.vulnerabilities:
                        all_vulns.extend(result.vulnerabilities)
                        
                if all_vulns:
                    self.display_threat_gauge(all_vulns)

        print(f"\nPyScanner done: {Colors.GREEN}{total_hosts} hosts up{Colors.ENDC} scanned in {Colors.YELLOW}{self.duration:.2f} seconds{Colors.ENDC}")
        
    def calculate_threat_level(self, vulnerabilities: List[Dict]) -> Tuple[str, float, str]:
        """
        Calculate the overall threat level based on vulnerability severity.
        """
        if not vulnerabilities:
            return "Safe", 0.0, f"{Colors.GREEN}"
        
        # Calculate threat score based on CVSS values
        total_score = 0.0
        critical_count = 0
        high_count = 0
        medium_count = 0
        
        for vuln in vulnerabilities:
            cvss = vuln.get('cvss', 'N/A')
            severity = vuln.get('severity', '').replace(Colors.RED, '').replace(Colors.YELLOW, '').replace(Colors.BLUE, '').replace(Colors.ENDC, '')
            
            # Count by severity
            if "Critical" in severity:
                critical_count += 1
            elif "High" in severity:
                high_count += 1
            elif "Medium" in severity:
                medium_count += 1
                
            # Add to score if CVSS available
            try:
                if cvss != 'N/A':
                    total_score += float(cvss)
            except (ValueError, TypeError):
                pass
        
        # Normalize score (0-10 scale)
        max_score = 10.0
        num_vulns = len(vulnerabilities)
        if num_vulns > 0:
            avg_score = min(total_score / num_vulns, max_score)
        else:
            avg_score = 0.0
            
        # Determine threat level based on score and critical/high counts
        if critical_count > 0 or avg_score >= 9.0:
            return "Critical", avg_score, f"{Colors.RED}"
        elif high_count > 0 or avg_score >= 7.0:
            return "High", avg_score, f"{Colors.MAGENTA}"
        elif medium_count > 0 or avg_score >= 4.0:
            return "Medium", avg_score, f"{Colors.YELLOW}"
        elif avg_score > 0:
            return "Low", avg_score, f"{Colors.BLUE}"
        else:
            return "Safe", 0.0, f"{Colors.GREEN}"

    def display_threat_gauge(self, vulnerabilities: List[Dict]) -> None:
        """
        Display a simple ASCII threat gauge based on vulnerabilities.
        """
        threat_level, score, color = self.calculate_threat_level(vulnerabilities)
        
        # Create ASCII gauge
        gauge_width = 30
        filled_width = int((score / 10.0) * gauge_width)
        empty_width = gauge_width - filled_width
        
        print("\n" + self._format_header(50))
        print(f"{Colors.BOLD}THREAT ASSESSMENT{Colors.ENDC}")
        print(self._format_header(50))
        
        print(f"Threat Level: {color}{threat_level}{Colors.ENDC}")
        print(f"Threat Score: {color}{score:.1f}/10{Colors.ENDC}")
        
        # Display gauge
        print("\n[" + color + "=" * filled_width + Colors.ENDC + " " * empty_width + "] " + f"{color}{score:.1f}/10{Colors.ENDC}")
        
        # Recommendations based on threat level
        print("\nRecommendations:")
        if threat_level == "Critical":
            print(f"{color}• Immediate action required!{Colors.ENDC}")
            print(f"{color}• Isolate affected services until patched{Colors.ENDC}")
            print(f"{color}• Update to latest software versions{Colors.ENDC}")
        elif threat_level == "High":
            print(f"{color}• Urgent updates required{Colors.ENDC}")
            print(f"{color}• Schedule maintenance window for patching{Colors.ENDC}")
            print(f"{color}• Review access controls{Colors.ENDC}")
        elif threat_level == "Medium":
            print(f"{color}• Plan updates within 30 days{Colors.ENDC}")
            print(f"{color}• Consider additional security controls{Colors.ENDC}")
        elif threat_level == "Low":
            print(f"{color}• Update during next maintenance window{Colors.ENDC}")
            print(f"{color}• Continue regular security practices{Colors.ENDC}")
        else:
            print(f"{color}• No immediate action needed{Colors.ENDC}")
            print(f"{color}• Continue regular updates{Colors.ENDC}")
        
        print(self._format_header(50))

    def format_network_scan_data(
        self,
        network: str,
        scan_results: Dict[str, ScanResult],
        vuln_scanner: Optional[NVDVulnerabilityScanner] = None
    ) -> Dict:
        """Format network scan results as structured data with vulnerability information for export."""
        
        network_data = {
            "target_network": network,
            "scan_time": self.start_time.strftime("%Y-%m-%d %H:%M"),
            "duration": self.duration,
            "hosts": []
        }
        
        for ip, result in scan_results.items():
            host_data = {
                "ip": ip,
                "hostname": result.hostname,
                "mac_address": result.mac_address,
                "status": "up" if result.latency else "down",
                "latency": f"{result.latency*1000:.1f}ms" if result.latency else "Unknown",
                "ports": [],
                "vulnerabilities": []
            }
            
            # Add port information
            for port, proto in result.open_ports:
                port_info = {
                    "port": port,
                    "protocol": proto,
                    "service": "Unknown",
                    "version": "N/A",
                    "vulnerabilities": []
                }
                
                # Add service information if available
                if hasattr(result, 'services') and result.services:
                    service_info = result.services.get(port, ServiceInfo())
                    port_info["service"] = service_info.name or "Unknown"
                    version_str = f"{service_info.product} {service_info.version}".strip()
                    port_info["version"] = version_str if version_str else "N/A"
                    
                    # Check for vulnerabilities if we have service info and a scanner
                    if vuln_scanner and vuln_scanner.enabled and port_info["service"] != "Unknown" and port_info["version"] != "N/A":
                        vulnerabilities = vuln_scanner.analyze_services_parallel(result.services)
                        
                        # Store vulnerability data without color codes
                        clean_vulns = []
                        for vuln in vulnerabilities:
                            clean_vuln = vuln.copy()
                            
                            # Remove color codes from severity
                            if "severity" in clean_vuln:
                                severity_text = clean_vuln["severity"]
                                # Remove ANSI color codes
                                for color in [Colors.RED, Colors.YELLOW, Colors.BLUE, Colors.ENDC]:
                                    severity_text = severity_text.replace(color, "")
                                clean_vuln["severity"] = severity_text
                                
                            clean_vulns.append(clean_vuln)
                        
                        port_info["vulnerabilities"] = clean_vulns
                        host_data["vulnerabilities"].extend(clean_vulns)
                
                host_data["ports"].append(port_info)
            
            # Add OS information if available
            if hasattr(result, 'os_info') and result.os_info:
                host_data["os_info"] = {
                    "name": result.os_info.name,
                    "accuracy": result.os_info.accuracy,
                    "description": result.os_info.description
                }
            
            network_data["hosts"].append(host_data)
        
        return network_data

    def export_network_file(
        self,
        network: str,
        results: Dict[str, ScanResult],
        txt_filename: Optional[str] = None,
        json_filename: Optional[str] = None,
        vuln_scanner: Optional[NVDVulnerabilityScanner] = None
    ) -> None:
        """Save network scan results as JSON and/or TXT file."""
        
        # Format data for export
        network_data = self.format_network_scan_data(network, results, vuln_scanner)
        
        if json_filename:
            try:
                with open(json_filename, "w", encoding="utf-8") as json_file:
                    json.dump(network_data, json_file, indent=4)
                print(f"{Colors.GREEN}Network scan results saved to {json_filename}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.RED}Error saving JSON file: {e}{Colors.ENDC}")

        if txt_filename:
            try:
                with open(txt_filename, "w", encoding="utf-8") as txt_file:
                    txt_file.write(f"PyScanner Network Report\n")
                    txt_file.write(f"Target Network: {network}\n")
                    txt_file.write(f"Scan Time: {self.start_time.strftime('%Y-%m-%d %H:%M')}\n")
                    txt_file.write(f"Duration: {self.duration:.2f} seconds\n\n")
                    
                    txt_file.write(f"Discovered Hosts ({len(results)} total):\n")
                    txt_file.write("-" * 80 + "\n")
                    txt_file.write(f"{'HOST':<19}{'STATUS':<10}{'LATENCY':<12}{'MAC ADDRESS':<20}{'OPEN PORTS'}\n")
                    txt_file.write("-" * 80 + "\n")
                    
                    for ip, result in results.items():
                        latency_str = f"{result.latency*1000:.1f}ms" if result.latency else "Unknown"
                        hostname_display = f"{result.hostname}" if result.hostname != "Unknown" else ""
                        ip_display = f"{ip}"
                        if hostname_display:
                            host_str = f"{hostname_display} ({ip_display})"
                        else:
                            host_str = ip_display
                        
                        host_str = host_str[:15] + "..." if len(host_str) > 15 else host_str.ljust(15)
                        
                        # Format open ports as a comma-separated list
                        ports_str = ", ".join([f"{port}/{proto}" for port, proto in result.open_ports]) if result.open_ports else "None"
                        
                        txt_file.write(f"{host_str} {'up':<10}{latency_str:<12}{result.mac_address:<20}{ports_str}\n")
                    
                print(f"{Colors.GREEN}Network scan results saved to {txt_filename}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.RED}Error saving TXT file: {e}{Colors.ENDC}")

    def export_file(
        self,
        results: Dict,
        txt_filename: Optional[str] = None,
        json_filename: Optional[str] = None,
    ) -> None:
        """Save scan results as JSON and/or TXT file with enhanced vulnerability information."""
        
        if json_filename:
            try:
                with open(json_filename, "w", encoding="utf-8") as json_file:
                    json.dump(results, json_file, indent=4)
                print(f"{Colors.GREEN}Results saved to {json_filename}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.RED}Error saving JSON file: {e}{Colors.ENDC}")

        if txt_filename:
            try:
                with open(txt_filename, "w", encoding="utf-8") as txt_file:
                    txt_file.write(f"PyScanner Report\n")
                    txt_file.write(f"=======================================\n")
                    txt_file.write(f"Target: {results['target']}\n")
                    txt_file.write(f"Status: {results['status']}\n")
                    txt_file.write(f"Latency: {results['latency']}s\n")
                    txt_file.write(f"OS Info: {results['os_info']}\n\n")
                    
                    txt_file.write("Open Ports:\n")
                    txt_file.write("-" * 50 + "\n")
                    txt_file.write(f"{'PORT':<15}{'SERVICE':<20}{'VERSION':<20}\n")
                    txt_file.write("-" * 50 + "\n")
                    
                    for port in results["ports"]:
                        txt_file.write(f"{port['port']}/{port['protocol']:<10} {port['service']:<20} {port['version']:<20}\n")
                    
                    # Add vulnerability information
                    if results.get("vulnerabilities"):
                        txt_file.write("\n\nVulnerabilities:\n")
                        txt_file.write("=" * 80 + "\n")
                        
                        for vuln in results["vulnerabilities"]:
                            txt_file.write(f"ID: {vuln['id']}\n")
                            txt_file.write(f"Title: {vuln['title']}\n")
                            txt_file.write(f"CVSS Score: {vuln['cvss']}\n")
                            txt_file.write(f"Description: {vuln['description']}\n")
                            
                            if vuln.get('references'):
                                txt_file.write("References:\n")
                                for ref in vuln.get('references', []):
                                    txt_file.write(f"- {ref}\n")
                                    
                            txt_file.write("-" * 80 + "\n")
                    
                print(f"{Colors.GREEN}Results saved to {txt_filename}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.RED}Error saving TXT file: {e}{Colors.ENDC}")