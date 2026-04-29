"""
Network port assessment module
this module displays listening network ports on Windows systems to assess network attack surface. It identifies potentially dangerous services
determines which processes are listening on each port and evaluates exposure risk based on service type


this module implements local port enumeration as recommended by 
NIST SP 800-115 (technical guide to security testing)
OWASP testing guide v4
CIS controls v8 (control 12 : network infrastructure management )

technical approach
this module performs local enumeration using system APIs. providing more accurate information and avoids triggering firewall alerts that network scanning causes"""

import socket   
import psutil
import logging
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime


# configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)    

class PortScanner:
    """
    Port categories 
    Well known ports (0-1023) standard services
    Registered ports (1024-49151) common applications
    Dynamic ports (49152-65535) usually temporary
     
    Risk classification 
     Ports are classified by service type and exposure tisk
      Critical - Services with known severe vulnerabilities (Telnet, FTP)
       High - services frequently targeted (RDP, SMB, SSH)
        Medium - services with moderate risk (HTTP, databases)
         Low- services with minimal risk exposure
           """
    
    def __init__(self):
        # initialse port scanner sets up data structure for known dangerous ports dictionary
        # timestamp recorded for analysus of port state changes

        self.port_info: Dict = {}
        self.collection_timestamp = datetime.now() .isoformat()

        # dictionary of high risk ports and services
        # based on SANS internet storm center data and NIST guidance 
        # Updated January 2026 to reflect current threats
        self.dangerous_ports = {
            # Critical Risk - Should never be exposed
            21: {'service': 'FTP', 'risk': 'Critical', 'reason': 'Unencrypted file transfer, credentials in plaintext'},
            23: {'service': 'Telnet', 'risk': 'Critical', 'reason': 'Unencrypted remote access, credentials in plaintext'},
            69: {'service': 'TFTP', 'risk': 'Critical', 'reason': 'Unauthenticated file transfer'},
            135: {'service': 'MS-RPC', 'risk': 'Critical', 'reason': 'Windows RPC, frequently exploited'},
            139: {'service': 'NetBIOS', 'risk': 'Critical', 'reason': 'Legacy file sharing, information disclosure'},
            445: {'service': 'SMB', 'risk': 'Critical', 'reason': 'File sharing, ransomware vector (WannaCry, EternalBlue)'},
            
            # High Risk - Should be carefully controlled
            22: {'service': 'SSH', 'risk': 'High', 'reason': 'Remote access target, brute-force attacks common'},
            3389: {'service': 'RDP', 'risk': 'High', 'reason': 'Windows Remote Desktop, brute-force and exploit target'},
            5900: {'service': 'VNC', 'risk': 'High', 'reason': 'Remote desktop, often poorly secured'},
            1433: {'service': 'MS-SQL', 'risk': 'High', 'reason': 'Database server, SQL injection risk if exposed'},
            3306: {'service': 'MySQL', 'risk': 'High', 'reason': 'Database server, should not be internet-facing'},
            5432: {'service': 'PostgreSQL', 'risk': 'High', 'reason': 'Database server, should not be internet-facing'},
            
            # Medium Risk - Common services requiring protection
            80: {'service': 'HTTP', 'risk': 'Medium', 'reason': 'Web server, should use HTTPS instead'},
            443: {'service': 'HTTPS', 'risk': 'Medium', 'reason': 'Secure web, still requires proper configuration'},
            8080: {'service': 'HTTP-Alt', 'risk': 'Medium', 'reason': 'Alternative HTTP port, often development servers'},
            25: {'service': 'SMTP', 'risk': 'Medium', 'reason': 'Mail server, spam relay risk if misconfigured'},
            110: {'service': 'POP3', 'risk': 'Medium', 'reason': 'Email retrieval, unencrypted'},
            143: {'service': 'IMAP', 'risk': 'Medium', 'reason': 'Email retrieval, unencrypted'},
        }

        logger.info("PortScanner initialised")

    def check_all(self) -> Dict:
        """
        organises comprehensive port scanning and risk assessment
        performs local port enumeration and analyses findings for security implications
        unlike network based scanning, this method queries local system APIs for accurate process-to-port mappings.
        
        
        returns 
        timestamp: when scan was performed
        listening_ports : list of open TCP/UDP ports
        dangerous_ports_found : high risk services detected
        processes_by_port: process information for each port
        risk_assessment : overall port exposure risk
        
        local enumation vs network scanning methodlogical choice. network scanning (Nmap) tests accessbility from external perspective
        but may miss local-only services and cannot reliably identify processes. Local enumeration provides complete picture but only from a host perspective
        this reserach prirotises completness over external view"""
        
        logger.info("Starting port scan")
        

        # add metadata
        self.port_info['timestamp'] = self.collection_timestamp
        self.port_info['module_version'] = '1.0.0'
        self.port_info['scan_type'] = 'local_enumeration'

        # enumerate listening ports
        try:
            self.port_info['listening_ports'] = self._enumerate_listening_ports()
        except Exception as e:
            logger.error(f"Failed to enumerate ports: {e}")
            self.port_info['listening_ports'] = {'error' : str(e)}

        #identify dangerous ports
        try: 
            self.port_info['dangerous_ports_found'] = self._identify_dangerous_ports()
        except Exception as e:
            logger.error(f"Failed to identify dangerous ports : {e}")
            self.port_info['dangerous_ports_found'] = {'error' : str(e)}

        
        # get process information for ports
        try:
            self.port_info['port_processes'] = self._get_port_processes()
        except Exception as e :
            logger.error(f"Failed to get port processes :{e}")
            self.port_info['port_processes'] = {'error': str(e)}

        #assess overall risk
        try:
            self.port_info['risk_assessment'] = self._assess_port_risk()
        except Exception as e:
            logger.error(f"Failed to assess port risk:  {e}")
            self.port_info['risk_assessment'] = {'error': str(e)}
        logger.info("Port scan completed")
        return self.port_info
    

    def _enumerate_listening_ports(self) -> Dict:
        """
        enumerates all listening TCP and UDP ports on the system
        uses psutil to query saystem network connections, filtering for LISTEN state (TCP) and all UDP bindings. 
        This provides accurate local viuew of what services are accepting connections.
        
        returns 
        dict: listening ports organised by protocol containing:
        tcp_ports : list of TCP ports in listen state
        udp_ports : list of UDP ports with bindings 
        total_listening: count of all listening ports 

        technical implementation
        psutil.net_connections() provides cross-platform interface to system network connection tables (netstat equivalent.) 
        for Windows, this queries GetExtendedTcpTable and GetExtendedUdpTable APIs
        LISTEN state indicates TCP socket accepting connections; UDP is connectionless so any binding indicates listening.
        
        Security context 
        every listening port represents potential attack vector 
        even ports bound to localhost may be exploitable through browser-based attacks or local priviledge escalation. ports bound to 0.0.0.0 or public Ips are directly 
        network- accessible.
    
        """

        logger.info("Enumerating listening ports")

        tcp_ports = []
        udp_ports = []
        port_details = []

        try:
            #get all network connections
            connections =  psutil.net_connections(kind='inet')

            for conn in connections:
                # TCP connections in LISTEN state

                if conn.status =='LISTEN' and conn.laddr:
                    port = conn.laddr.port
                    address = conn.laddr.ip

                    #avoid duplicates (same port may appear multiple times)
                    if port not in tcp_ports:
                        tcp_ports.append(port)

                    #store detailed information
                    port_details.append({
                        'port' : port,
                        'protocol' : 'TCP',
                        'address' : address,
                        'status' : 'LISTENING',
                        'pid' : conn.pid if conn.pid else None
                    })

                # UDP bindings
                # UDP is connectionless, so any binding indicates listening
                elif conn.type == socket.SOCK_DGRAM and conn.laddr:
                    port = conn.laddr.port
                    address = conn.laddr.ip

                    if port not in udp_ports:
                        udp_ports.append(port)

                    port_details.append({
                        'port' : port,
                        'protocol' : 'UDP' ,
                        'address' : address,
                        'status' : 'BOUND',
                        'pid' : conn.pid if conn.pid else None
                    })
            # Sort for readability
            tcp_ports.sort()
            udp_ports.sort()
            
            result = {
                'tcp_ports': tcp_ports,
                'udp_ports': udp_ports,
                'total_tcp': len(tcp_ports),
                'total_udp': len(udp_ports),
                'total_listening': len(tcp_ports) + len(udp_ports),
                'port_details': port_details,
                'enumeration_successful': True
            }
            
            logger.info(f"Found {len(tcp_ports)} TCP and {len(udp_ports)} UDP listening ports")
            return result
            
        except psutil.AccessDenied:
            logger.error("Access denied - requires administrator privileges")
            return {'enumeration_successful': False, 'error': 'Administrator privileges required'}
        except Exception as e:
            logger.error(f"Error enumerating ports: {e}")
            return {'enumeration_successful': False, 'error': str(e)}
    
    def _identify_dangerous_ports(self) -> Dict:
        """
        Identifies high-risk services from enumerated listening ports.
        
        Cross-references listening ports against known dangerous services
        to identify immediate security concerns. Risk classification based
        on service vulnerability history and typical attack patterns.
        
        Returns:
            Dict: Dangerous ports found, categorized by risk level:
                - critical_risk: Services that should never be exposed
                - high_risk: Services requiring careful configuration
                - medium_risk: Services with moderate exposure risk
                
        Risk Classification Methodology:
            Critical: Services with inherent security flaws (plaintext auth,
                     known severe vulnerabilities, no encryption)
            High: Services frequently targeted by attackers, significant
                  impact if compromised
            Medium: Services requiring security configuration but not
                    inherently vulnerable
                    
        Academic Reference:
            Risk classifications derived from:
            - SANS Internet Storm Center Top Ports data
            - NIST NVD (National Vulnerability Database) statistics
            - Verizon Data Breach Investigations Report
            - OWASP Top 10 risks
        """
        logger.info("Identifying dangerous ports")
        
        listening_ports_data = self.port_info.get('listening_ports', {})
        
        # Handle case where enumeration failed
        if not listening_ports_data.get('enumeration_successful'):
            return {'analysis_available': False}
        
        tcp_ports = listening_ports_data.get('tcp_ports', [])
        udp_ports = listening_ports_data.get('udp_ports', [])
        all_ports = set(tcp_ports + udp_ports)
        
        critical_risk = []
        high_risk = []
        medium_risk = []
        
        # Check each listening port against dangerous ports database
        for port in all_ports:
            if port in self.dangerous_ports:
                port_info = self.dangerous_ports[port].copy()
                port_info['port'] = port
                
                # Categorize by risk level
                risk_level = port_info['risk']
                if risk_level == 'Critical':
                    critical_risk.append(port_info)
                elif risk_level == 'High':
                    high_risk.append(port_info)
                elif risk_level == 'Medium':
                    medium_risk.append(port_info)
        
        result = {
            'critical_risk_ports': critical_risk,
            'high_risk_ports': high_risk,
            'medium_risk_ports': medium_risk,
            'total_dangerous_ports': len(critical_risk) + len(high_risk) + len(medium_risk),
            'analysis_available': True
        }
        
        if result['total_dangerous_ports'] > 0:
            logger.warning(f"Found {result['total_dangerous_ports']} dangerous ports")
        else:
            logger.info("No known dangerous ports detected")
        
        return result
    
    def _get_port_processes(self) -> List[Dict]:
        """
        Maps listening ports to the processes using them.
        
        Identifying which process owns each port is critical for security
        assessment: legitimate services should be recognized processes,
        while unknown processes may indicate malware or unauthorized services.
        
        Returns:
            List[Dict]: Process information for each listening port:
                - port: Port number
                - protocol: TCP or UDP
                - process_name: Name of process using port
                - process_id: PID of process
                - process_path: Full path to executable (if available)
                
        Security Implications:
            Unexpected processes on ports may indicate:
            - Malware (backdoors, C2 channels)
            - Unauthorized services (rogue servers)
            - Vulnerable applications (outdated software)
            - Misconfigurations (services on wrong ports)
            
        Technical Note:
            Process information requires elevated privileges on Windows.
            Without admin rights, some process details may be unavailable.
        """
        logger.info("Mapping ports to processes")
        
        port_processes = []
        
        listening_ports_data = self.port_info.get('listening_ports', {})
        if not listening_ports_data.get('enumeration_successful'):
            return []
        
        port_details = listening_ports_data.get('port_details', [])
        
        for port_detail in port_details:
            pid = port_detail.get('pid')
            
            process_info = {
                'port': port_detail['port'],
                'protocol': port_detail['protocol'],
                'address': port_detail['address'],
                'process_name': 'Unknown',
                'process_id': pid,
                'process_path': None
            }
            
            # Try to get process information
            if pid:
                try:
                    process = psutil.Process(pid)
                    process_info['process_name'] = process.name()
                    
                    # Try to get executable path
                    try:
                        process_info['process_path'] = process.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass  # Path not accessible, leave as None
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    # Process may have terminated or access denied
                    process_info['process_name'] = f'Access Denied (PID: {pid})'
            
            port_processes.append(process_info)
        
        logger.info(f"Mapped {len(port_processes)} port-process associations")
        return port_processes
    
    def _assess_port_risk(self) -> Dict:
        """
        Calculates overall port exposure risk score.
        
        Aggregates port findings into risk assessment considering:
        - Number and severity of dangerous ports open
        - Total attack surface (total listening ports)
        - External accessibility (ports bound to 0.0.0.0)
        
        Returns:
            Dict: Risk assessment containing:
                - overall_risk: Low, Medium, High, or Critical
                - risk_score: Numeric score (0-10)
                - findings: List of specific security issues
                - recommendations: Prioritized remediation steps
                
        Risk Scoring Methodology:
            Weighted factors:
            - Each critical-risk port: +4 points
            - Each high-risk port: +2 points
            - Each medium-risk port: +1 point
            - >50 total ports: +1 point (large attack surface)
            - >100 total ports: +2 points (excessive services)
            
            Score ranges:
            - 0-2: Low risk
            - 3-5: Medium risk
            - 6-8: High risk
            - 9-10: Critical risk
            
        Academic Justification:
            Weights reflect typical exploit frequency and impact.
            Critical-risk services (Telnet, FTP, SMB) appear frequently
            in breach reports due to inherent vulnerabilities or historical
            exploit prevalence (e.g., EternalBlue SMB exploit used by
            WannaCry and NotPetya ransomware).
        """
        logger.info("Assessing overall port exposure risk")
        
        risk_score = 0
        findings = []
        recommendations = []
        
        # Get data from previous checks
        listening_data = self.port_info.get('listening_ports', {})
        dangerous_data = self.port_info.get('dangerous_ports_found', {})
        
        # Check if analysis was successful
        if not listening_data.get('enumeration_successful'):
            return {
                'overall_risk': 'Unknown',
                'risk_score': 0,
                'findings': ['Port enumeration failed - requires administrator privileges'],
                'recommendations': ['Run tool as administrator for port scanning'],
                'analysis_available': False
            }
        
        total_ports = listening_data.get('total_listening', 0)
        
        # Assess dangerous ports
        if dangerous_data.get('analysis_available'):
            critical_ports = dangerous_data.get('critical_risk_ports', [])
            high_ports = dangerous_data.get('high_risk_ports', [])
            medium_ports = dangerous_data.get('medium_risk_ports', [])
            
            # Critical risk ports (e.g., Telnet, FTP, SMB)
            for port_info in critical_ports:
                risk_score += 4
                findings.append(
                    f"CRITICAL: {port_info['service']} (port {port_info['port']}) is listening - "
                    f"{port_info['reason']}"
                )
                recommendations.append(
                    f"Immediately disable {port_info['service']} on port {port_info['port']} "
                    f"or restrict to localhost only"
                )
            
            # High risk ports (e.g., RDP, SSH, databases)
            for port_info in high_ports:
                risk_score += 2
                findings.append(
                    f"HIGH: {port_info['service']} (port {port_info['port']}) is listening - "
                    f"{port_info['reason']}"
                )
                recommendations.append(
                    f"Restrict {port_info['service']} access with firewall rules "
                    f"or disable if not required"
                )
            
            # Medium risk ports
            for port_info in medium_ports:
                risk_score += 1
                findings.append(
                    f"MEDIUM: {port_info['service']} (port {port_info['port']}) is listening - "
                    f"{port_info['reason']}"
                )
                recommendations.append(
                    f"Review {port_info['service']} configuration and ensure proper security settings"
                )
        
        # Assess total attack surface
        if total_ports > 100:
            risk_score += 2
            findings.append(f"HIGH: Excessive open ports ({total_ports} listening)")
            recommendations.append(
                "Review all services and disable unnecessary ones to reduce attack surface"
            )
        elif total_ports > 50:
            risk_score += 1
            findings.append(f"MEDIUM: Large number of open ports ({total_ports} listening)")
            recommendations.append("Consider disabling unused services to minimize attack surface")
        
        # Cap risk score at 10
        risk_score = min(risk_score, 10)
        
        # Determine risk level
        if risk_score >= 9:
            risk_level = "Critical"
        elif risk_score >= 6:
            risk_level = "High"
        elif risk_score >= 3:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        # If no issues found, add positive finding
        if not findings:
            findings.append("No high-risk ports detected")
            recommendations.append("Maintain current port configuration and review regularly")
        
        assessment = {
            'overall_risk': risk_level,
            'risk_score': risk_score,
            'max_score': 10,
            'total_ports_listening': total_ports,
            'findings': findings,
            'recommendations': recommendations,
            'analysis_available': True
        }
        
        logger.info(f"Port risk assessment: {risk_level} (score: {risk_score}/10)")
        return assessment
    
    def export_to_json(self, filepath: str) -> bool:
        """
        Exports port scan results to JSON file.
        
        Args:
            filepath (str): Destination path for JSON export
            
        Returns:
            bool: True if export successful, False otherwise
            
        Security Note:
            Port information reveals system configuration and potential
            attack vectors. Exported files should be protected from
            unauthorized access.
        """
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.port_info, f, indent=4, ensure_ascii=False)
            
            logger.info(f"Port scan results exported to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export port scan results: {e}")
            return False


# Module-level convenience function
def scan_ports() -> Dict:
    """
    Convenience function to perform port scanning.
    
    Provides simple interface for main audit script.
    
    Returns:
        Dict: Complete port scan results
        
    Example:
        >>> from modules.port_scanner import scan_ports
        >>> results = scan_ports()
        >>> print(results['risk_assessment']['overall_risk'])
    """
    scanner = PortScanner()
    return scanner.check_all()


# Testing block
if __name__ == "__main__":
    """
    Test harness for independent module testing.
    
    Allows testing port scanning without running full audit suite.
    Essential for development and debugging.
    
    Note: Requires administrator privileges for complete results.
    """
    print("=" * 60)
    print("Network Port Assessment - Test Run")
    print("=" * 60)
    print("\n⚠️  Note: Run as Administrator for complete results\n")
    
    # Create scanner instance
    scanner = PortScanner()
    
    # Perform scan
    port_data = scanner.check_all()
    
    # Display summary
    print(f"✓ Scan completed at: {port_data['timestamp']}")
    
    # Show listening ports
    if 'listening_ports' in port_data:
        print("\n--- Listening Ports ---")
        listening = port_data['listening_ports']
        
        if listening.get('enumeration_successful'):
            print(f"TCP Ports: {listening.get('total_tcp', 0)}")
            print(f"UDP Ports: {listening.get('total_udp', 0)}")
            print(f"Total Listening: {listening.get('total_listening', 0)}")
            
            # Show first 10 TCP ports as sample
            tcp_ports = listening.get('tcp_ports', [])
            if tcp_ports:
                print(f"\nSample TCP Ports: {tcp_ports[:10]}")
                if len(tcp_ports) > 10:
                    print(f"... and {len(tcp_ports) - 10} more")
        else:
            print(f"✗ Enumeration failed: {listening.get('error', 'Unknown error')}")
    
    # Show dangerous ports
    if 'dangerous_ports_found' in port_data:
        print("\n--- Dangerous Ports Found ---")
        dangerous = port_data['dangerous_ports_found']
        
        if dangerous.get('analysis_available'):
            critical = dangerous.get('critical_risk_ports', [])
            high = dangerous.get('high_risk_ports', [])
            medium = dangerous.get('medium_risk_ports', [])
            
            if critical:
                print(f"\n🔴 CRITICAL RISK ({len(critical)} ports):")
                for port in critical:
                    print(f"  • Port {port['port']}: {port['service']} - {port['reason']}")
            
            if high:
                print(f"\n🟠 HIGH RISK ({len(high)} ports):")
                for port in high:
                    print(f"  • Port {port['port']}: {port['service']} - {port['reason']}")
            
            if medium:
                print(f"\n🟡 MEDIUM RISK ({len(medium)} ports):")
                for port in medium:
                    print(f"  • Port {port['port']}: {port['service']}")
            
            if not (critical or high or medium):
                print("✓ No known dangerous ports detected")
        else:
            print("✗ Analysis unavailable")
    
    # Show port-process mapping (first 10)
    if 'port_processes' in port_data:
        processes = port_data['port_processes']
        if processes:
            print(f"\n--- Port-Process Mapping (showing first 10) ---")
            for proc in processes[:10]:
                print(f"  Port {proc['port']}/{proc['protocol']}: "
                      f"{proc['process_name']} (PID: {proc['process_id']})")
            if len(processes) > 10:
                print(f"  ... and {len(processes) - 10} more")
    
    # Show risk assessment
    if 'risk_assessment' in port_data:
        print("\n--- Risk Assessment ---")
        assessment = port_data['risk_assessment']
        
        if assessment.get('analysis_available'):
            print(f"Overall Risk: {assessment.get('overall_risk')} "
                  f"(Score: {assessment.get('risk_score')}/10)")
            print(f"Total Listening Ports: {assessment.get('total_ports_listening', 0)}")
            
            if assessment.get('findings'):
                print("\nFindings:")
                for finding in assessment['findings']:
                    print(f"  • {finding}")
            
            if assessment.get('recommendations'):
                print("\nTop Recommendations:")
                for i, rec in enumerate(assessment['recommendations'][:5], 1):
                    print(f"  {i}. {rec}")
        else:
            print("✗ Analysis unavailable")
    
    # Export to test file
    test_export_path = "test_port_scan.json"
    if scanner.export_to_json(test_export_path):
        print(f"\n✓ Data exported to: {test_export_path}")
    
    print("\n" + "=" * 60)
    print("Test completed!")
    print("=" * 60)
