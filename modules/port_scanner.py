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
        
        logger.info

        # add metadata
        self.port_info['timestamp'] = self.collection_timestamp
        self.port_info['module_version'] = '1.0.0'
        self.port_info['scan_type'] = 'local_enumeration'

        # enumerate listening ports
        try:
            self.port_info['listening_ports'] = self._enumeration_listening_ports()
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
                    port = conn.laddr.portaddress = conn.laddr.ip

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

        
