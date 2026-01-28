"""
System Information Collection Module

This module handles the collection of system-level information from Windows machines
for security assessment purposes. It gathers OS details, patch levels, installed
software, and hardware information to establish a baseline security posture.


    
Security Considerations:
    - Requires administrative privileges for full system access
    - Information gathered is sensitive and should be handled securely
    - Output should be sanitized before external transmission
"""

import platform
import subprocess
import psutil
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

# Configure logging for audit trail purposes
# Logging is essential for forensic analysis and debugging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SystemInfoCollector:
    """
    Collects comprehensive system information for security assessment.
    
    This class encapsulates all system information gathering methods,
    providing a clean interface for the main audit script. Design follows
    the Single Responsibility Principle (SRP) from SOLID principles.
    
    Attributes:
        info (Dict): Stores all collected system information
        collection_timestamp (str): ISO format timestamp of data collection
    """
    
    def __init__(self):
        """
        Initialise the SystemInfoCollector.
        
        Sets up the data structure and records collection timestamp for
        audit trail purposes. Timestamp is critical for temporal analysis
        of security posture changes.
        """
        self.info: Dict = {}
        self.collection_timestamp = datetime.now().isoformat()
        logger.info("SystemInfoCollector initialised")
    
    def collect_all(self) -> Dict:
        """
        Orchestrates collection of all system information.
        
        This method calls individual collection methods in sequence and
        aggregates results. Using a try-except pattern for each component
        ensures partial data collection even if individual components fail.
        
        Returns:
            Dict: Complete system information dictionary containing:
                - timestamp: When data was collected
                - os_info: Operating system details
                - hardware_info: CPU, memory, disk information
                - network_info: Network interfaces and configuration
                - installed_software: List of installed applications
                - services: Running Windows services
                - users: Local user accounts
                
       
        """
        logger.info("Starting comprehensive system information collection")
        
        # Add metadata for report generation and temporal tracking
        self.info['timestamp'] = self.collection_timestamp
        self.info['audit_version'] = '1.0.0'
        
        # Collect each category of information
        # Each method is wrapped in try-except to ensure resilience
        try:
            self.info['os_info'] = self._collect_os_info()
        except Exception as e:
            logger.error(f"Failed to collect OS info: {e}")
            self.info['os_info'] = {'error': str(e)}
        
        try:
            self.info['hardware_info'] = self._collect_hardware_info()
        except Exception as e:
            logger.error(f"Failed to collect hardware info: {e}")
            self.info['hardware_info'] = {'error': str(e)}
        
        try:
            self.info['network_info'] = self._collect_network_info()
        except Exception as e:
            logger.error(f"Failed to collect network info: {e}")
            self.info['network_info'] = {'error': str(e)}
        
        try:
            self.info['installed_software'] = self._collect_installed_software()
        except Exception as e:
            logger.error(f"Failed to collect installed software: {e}")
            self.info['installed_software'] = {'error': str(e)}
        
        try:
            self.info['services'] = self._collect_services()
        except Exception as e:
            logger.error(f"Failed to collect services: {e}")
            self.info['services'] = {'error': str(e)}
        
        try:
            self.info['users'] = self._collect_users()
        except Exception as e:
            logger.error(f"Failed to collect users: {e}")
            self.info['users'] = {'error': str(e)}
        
        logger.info("System information collection completed")
        return self.info
    
    def _collect_os_info(self) -> Dict:
        """
        Collects operating system information and patch level.
        
        OS version and patch level are critical for vulnerability assessment
        as many exploits target specific OS versions or unpatched systems.
        This follows NIST guidelines for asset inventory.
        
        Returns:
            Dict: Operating system details including:
                - system: OS name (e.g., 'Windows')
                - release: OS release (e.g., '10', '11')
                - version: Build version number
                - architecture: 32-bit or 64-bit
                - hostname: Computer name
                - domain: Domain/workgroup membership
                
        Security Implications:
            Outdated OS versions (e.g., Windows 7, 8) represent critical
            security risks as they no longer receive security updates.
            This data feeds into the risk scoring algorithm.
        """
        logger.info("Collecting OS information")
        
        os_info = {
            'system': platform.system(),  # Should return 'Windows' for target systems
            'release': platform.release(),  # e.g., '10', '11', '8.1'
            'version': platform.version(),  # Build number, e.g., '10.0.19041'
            'architecture': platform.machine(),  # e.g., 'AMD64', 'x86'
            'hostname': platform.node(),  # Computer name on network
            'processor': platform.processor(),  # CPU description
        }
        
        # Attempt to get more detailed Windows version info
        # This is important for identifying specific vulnerable builds
        try:
            # Using systeminfo command for detailed Windows information
            # This provides patch level and installation date
            result = subprocess.run(
                ['systeminfo'],
                capture_output=True,
                text=True,
                timeout=30,  # Prevent hanging on slow systems
                encoding='utf-8',
                errors='ignore'  # Handle encoding issues gracefully
            )
            
            if result.returncode == 0:
                # Parse systeminfo output for key security-relevant fields
                lines = result.stdout.split('\n')
                for line in lines:
                    # Extract OS Name (full version string)
                    if 'OS Name:' in line:
                        os_info['os_name'] = line.split(':', 1)[1].strip()
                    # Extract OS Version (detailed build)
                    elif 'OS Version:' in line:
                        os_info['os_version_detailed'] = line.split(':', 1)[1].strip()
                    # Extract Original Install Date (system age indicator)
                    elif 'Original Install Date:' in line:
                        os_info['install_date'] = line.split(':', 1)[1].strip()
                    # Extract System Boot Time (uptime - important for patch application)
                    elif 'System Boot Time:' in line:
                        os_info['last_boot'] = line.split(':', 1)[1].strip()
                    # Extract Domain information (network security context)
                    elif 'Domain:' in line:
                        os_info['domain'] = line.split(':', 1)[1].strip()
                
                logger.info("Detailed OS information collected via systeminfo")
        
        except subprocess.TimeoutExpired:
            logger.warning("systeminfo command timed out")
        except Exception as e:
            logger.warning(f"Could not get detailed Windows info: {e}")
        
        # Check if OS is End-of-Life (EOL) - critical security risk
        # EOL systems no longer receive security patches
        os_info['eol_status'] = self._check_eol_status(os_info.get('release', ''))
        
        return os_info
    
    def _check_eol_status(self, release: str) -> Dict:
        """
        Determines if the OS version has reached End-of-Life.
        
        EOL operating systems no longer receive security updates and represent
        a critical vulnerability. This check is essential for risk assessment.
        
        Args:
            release (str): OS release version (e.g., '7', '10', '11')
            
        Returns:
            Dict: EOL status information containing:
                - is_eol: Boolean indicating if OS is past EOL
                - eol_date: Date when support ended (if applicable)
                - risk_level: Associated risk (Critical, High, Low)
                
       
        """
        # Known EOL dates for Windows versions (as of 2025)
        # This dictionary should be externalized to a config file in production
        eol_dates = {
            'XP': {'date': '2014-04-08', 'risk': 'Critical'},
            'Vista': {'date': '2017-04-11', 'risk': 'Critical'},
            '7': {'date': '2020-01-14', 'risk': 'Critical'},
            '8': {'date': '2016-01-12', 'risk': 'Critical'},
            '8.1': {'date': '2023-01-10', 'risk': 'Critical'},
            '10': {'date': '2025-10-14', 'risk': 'Low'},  # Still supported as of Dec 2025
            '11': {'date': '2031-10-14', 'risk': 'Low'},  # Current version
        }
        
        eol_info = {
            'is_eol': False,
            'eol_date': None,
            'risk_level': 'Low'
        }
        
        # Check if current OS version is in EOL dictionary
        if release in eol_dates:
            eol_data = eol_dates[release]
            eol_date = datetime.strptime(eol_data['date'], '%Y-%m-%d')
            current_date = datetime.now()
            
            # Compare current date with EOL date
            if current_date > eol_date:
                eol_info['is_eol'] = True
                eol_info['eol_date'] = eol_data['date']
                eol_info['risk_level'] = eol_data['risk']
                logger.warning(f"OS version {release} is End-of-Life (EOL since {eol_data['date']})")
        
        return eol_info
    
    def _collect_hardware_info(self) -> Dict:
        """
        Collects hardware specifications and resource utilization.
        
        Hardware information helps assess if security tools can run effectively
        and identifies resource constraints. Low-spec systems may struggle
        with security software, creating gaps in protection.
        
        Returns:
            Dict: Hardware details including:
                - cpu_count: Number of CPU cores
                - cpu_freq: CPU frequency in MHz
                - ram_total: Total RAM in GB
                - ram_available: Available RAM in GB
                - disk_info: List of disk partitions and usage
                
        Security Context:
            Insufficient RAM or CPU may prevent proper AV operation or
            cause users to disable security features for performance.
        """
        logger.info("Collecting hardware information")
        
        # CPU information using psutil
        cpu_freq = psutil.cpu_freq()
        hardware_info = {
            'cpu_count': psutil.cpu_count(logical=True),  # Logical cores (includes hyperthreading)
            'cpu_count_physical': psutil.cpu_count(logical=False),  # Physical cores
            'cpu_freq_current': cpu_freq.current if cpu_freq else None,  # Current MHz
            'cpu_freq_max': cpu_freq.max if cpu_freq else None,  # Max MHz
        }
        
        # Memory information
        # Converting bytes to GB for readability (1 GB = 1073741824 bytes)
        virtual_mem = psutil.virtual_memory()
        hardware_info['ram_total_gb'] = round(virtual_mem.total / (1024**3), 2)
        hardware_info['ram_available_gb'] = round(virtual_mem.available / (1024**3), 2)
        hardware_info['ram_percent_used'] = virtual_mem.percent
        
        # Disk information for all partitions
        # Multiple disks may have different security configurations (encryption, etc.)
        disk_info = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,  # File system type (NTFS, FAT32, etc.)
                    'total_gb': round(usage.total / (1024**3), 2),
                    'used_gb': round(usage.used / (1024**3), 2),
                    'free_gb': round(usage.free / (1024**3), 2),
                    'percent_used': usage.percent
                })
            except PermissionError:
                # Some partitions may not be accessible without elevated privileges
                logger.warning(f"Permission denied accessing {partition.mountpoint}")
                continue
        
        hardware_info['disks'] = disk_info
        
        return hardware_info
    
    def _collect_network_info(self) -> Dict:
        """
        Collects network interface configuration and connectivity status.
        
        Network configuration affects attack surface. Multiple interfaces,
        public IPs, or misconfigured adapters can create security risks.
        
        Returns:
            Dict: Network information including:
                - interfaces: List of network adapters and their addresses
                - default_gateway: Primary gateway IP
                - dns_servers: Configured DNS servers
                
        Security Relevance:
            - Multiple NICs may create routing issues
            - Public IPs on workstations increase exposure
            - Misconfigured DNS can enable MitM attacks
        """
        logger.info("Collecting network information")
        
        network_info = {
            'interfaces': []
        }
        
        # Iterate through all network interfaces
        # psutil provides cross-platform network interface enumeration
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
        
        for interface_name, addresses in if_addrs.items():
            interface_data = {
                'name': interface_name,
                'is_up': if_stats[interface_name].isup if interface_name in if_stats else False,
                'addresses': []
            }
            
            # Each interface can have multiple addresses (IPv4, IPv6, MAC)
            for addr in addresses:
                addr_info = {
                    'family': str(addr.family),  # Address family (AF_INET, AF_INET6, etc.)
                    'address': addr.address,
                }
                
                # Add netmask for IPv4 addresses (needed for subnet analysis)
                if addr.netmask:
                    addr_info['netmask'] = addr.netmask
                
                interface_data['addresses'].append(addr_info)
            
            network_info['interfaces'].append(interface_data)
        
        # Attempt to get default gateway via ipconfig
        # Gateway information is important for network topology understanding
        try:
            result = subprocess.run(
                ['ipconfig'],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0:
                # Parse ipconfig output for default gateway
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Default Gateway' in line or 'Puertas de enlace' in line:
                        gateway = line.split(':', 1)[1].strip()
                        if gateway:  # Ignore empty gateway entries
                            network_info['default_gateway'] = gateway
                            break
        except Exception as e:
            logger.warning(f"Could not determine default gateway: {e}")
        
        return network_info
    
    def _collect_installed_software(self) -> List[Dict]:
        """
        Enumerates installed software from Windows Registry.
        
        Software inventory is critical for identifying:
        - Outdated/vulnerable applications
        - Unauthorized software installations
        - Missing security tools (antivirus, etc.)
        
        Returns:
            List[Dict]: List of installed applications with:
                - name: Software name
                - version: Version number
                - publisher: Software vendor
                - install_date: When software was installed
                
    
            
        Technical Note:
            Queries both 32-bit and 64-bit registry paths to ensure
            complete software enumeration on 64-bit systems.
        """
        logger.info("Collecting installed software list")
        
        software_list = []
        
        try:
            import winreg
            
            # Registry paths where Windows stores installed software information
            # Need to check both 32-bit and 64-bit paths on 64-bit systems
            registry_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",  # 64-bit software
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"  # 32-bit on 64-bit
            ]
            
            for path in registry_paths:
                try:
                    # Open the registry key
                    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                    
                    # Enumerate all subkeys (each represents an installed application)
                    for i in range(winreg.QueryInfoKey(reg_key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(reg_key, i)
                            subkey = winreg.OpenKey(reg_key, subkey_name)
                            
                            # Try to get software name (DisplayName value)
                            try:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                
                                # Create software entry
                                software = {'name': name}
                                
                                # Attempt to get additional metadata (may not always exist)
                                try:
                                    software['version'] = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                except:
                                    software['version'] = "Unknown"
                                
                                try:
                                    software['publisher'] = winreg.QueryValueEx(subkey, "Publisher")[0]
                                except:
                                    software['publisher'] = "Unknown"
                                
                                try:
                                    software['install_date'] = winreg.QueryValueEx(subkey, "InstallDate")[0]
                                except:
                                    software['install_date'] = "Unknown"
                                
                                software_list.append(software)
                                
                            except:
                                # Skip entries without DisplayName (usually system components)
                                pass
                            
                            winreg.CloseKey(subkey)
                            
                        except Exception as e:
                            # Some keys may not be accessible
                            continue
                    
                    winreg.CloseKey(reg_key)
                    
                except FileNotFoundError:
                    # Registry path doesn't exist (normal on 32-bit systems)
                    continue
                except Exception as e:
                    logger.error(f"Error accessing registry path {path}: {e}")
            
            logger.info(f"Found {len(software_list)} installed applications")
            
        except ImportError:
            logger.error("winreg module not available (not on Windows?)")
        except Exception as e:
            logger.error(f"Failed to collect software list: {e}")
        
        return software_list
    
    def _collect_services(self) -> List[Dict]:
        """
        Enumerates running Windows services.
        
        Services analysis helps identify:
        - Unnecessary services increasing attack surface
        - Critical security services that are stopped
        - Suspicious or malicious services
        
        Returns:
            List[Dict]: Running services with:
                - name: Service name
                - display_name: User-friendly name
                - status: Running, Stopped, etc.
                - start_type: Automatic, Manual, Disabled
                
        Security Context:
            Unnecessary services (e.g., Telnet, FTP) should be disabled.
            Critical services (e.g., Windows Defender) should be running.
            This data feeds into the security posture assessment.
        """
        logger.info("Collecting Windows services information")
        
        services_list = []
        
        try:
            # psutil provides cross-platform service enumeration
            # However, detailed service info requires Windows-specific APIs
            for service in psutil.win_service_iter():
                try:
                    service_info = service.as_dict()
                    
                    # Extract relevant service information
                    services_list.append({
                        'name': service_info.get('name', 'Unknown'),
                        'display_name': service_info.get('display_name', 'Unknown'),
                        'status': service_info.get('status', 'Unknown'),
                        'start_type': service_info.get('start_type', 'Unknown'),
                        'username': service_info.get('username', 'Unknown'),  # Account service runs under
                    })
                    
                except Exception as e:
                    # Some services may not be accessible
                    continue
            
            logger.info(f"Found {len(services_list)} Windows services")
            
        except AttributeError:
            # win_service_iter not available (not on Windows)
            logger.error("Service enumeration not available (not on Windows platform)")
        except Exception as e:
            logger.error(f"Failed to collect services: {e}")
        
        return services_list
    
    def _collect_users(self) -> List[Dict]:
        """
        Enumerates local user accounts on the system.
        
        User account analysis identifies:
        - Presence of default/guest accounts (security risk)
        - Unnecessary administrator accounts
        - Account naming conventions
        - Disabled vs enabled accounts
        
        Returns:
            List[Dict]: Local user accounts with basic information
            
        Security Implications:
            - Multiple admin accounts increase risk
            - Enabled guest accounts are critical vulnerabilities
            - Inactive accounts should be disabled
            
        Note:
            This provides basic user enumeration. The password_policy module
            will provide detailed password configuration analysis.
        """
        logger.info("Collecting user account information")
        
        users_list = []
        
        try:
            # Use net user command to enumerate local accounts
            # This is more reliable than WMI for basic enumeration
            result = subprocess.run(
                ['net', 'user'],
                capture_output=True,
                text=True,
                timeout=30,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0:
                # Parse output to extract usernames
                lines = result.stdout.split('\n')
                in_user_section = False
                
                for line in lines:
                    # Skip header lines
                    if '---' in line:
                        in_user_section = True
                        continue
                    
                    # Parse usernames (they appear in columns)
                    if in_user_section and line.strip():
                        # Split line into potential usernames
                        potential_users = line.split()
                        for user in potential_users:
                            if user.strip():
                                users_list.append({'username': user.strip()})
                
                logger.info(f"Found {len(users_list)} local user accounts")
        
        except subprocess.TimeoutExpired:
            logger.warning("net user command timed out")
        except Exception as e:
            logger.error(f"Failed to enumerate users: {e}")
        
        return users_list
    
    def export_to_json(self, filepath: str) -> bool:
        """
        Exports collected system information to JSON file.
        
        JSON format is chosen for:
        - Easy parsing by report generation module
        - Human-readable for debugging
        - Standard format for data interchange
        
        Args:
            filepath (str): Destination file path for JSON export
            
        Returns:
            bool: True if export successful, False otherwise
            
        Security Note:
            Exported file contains sensitive system information and should
            be protected with appropriate file permissions.
        """
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.info, f, indent=4, ensure_ascii=False)
            
            logger.info(f"System information exported to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export system info to JSON: {e}")
            return False


# Module-level function for convenient usage
def collect_system_info() -> Dict:
    """
    Convenience function to collect all system information.
    
    This provides a simple interface for the main audit script without
    needing to instantiate the class directly.
    
    Returns:
        Dict: Complete system information
        
    Example:
        >>> from modules.system_info import collect_system_info
        >>> info = collect_system_info()
        >>> print(info['os_info']['system'])
    """
    collector = SystemInfoCollector()
    return collector.collect_all()


# Testing block - only executes when module is run directly
if __name__ == "__main__":
    """
    Test harness for module development and debugging.
    
    This block allows testing the module independently without running
    the full audit suite. Essential for iterative development.
    """
    print("=" * 60)
    print("System Information Collection Module - Test Run")
    print("=" * 60)
    
    # Create collector instance
    collector = SystemInfoCollector()
    
    # Collect all information
    system_data = collector.collect_all()
    
    # Display summary of collected data
    print(f"\n✓ Collection completed at: {system_data['timestamp']}")
    print(f"✓ Operating System: {system_data['os_info'].get('os_name', 'N/A')}")
    print(f"✓ CPU Cores: {system_data['hardware_info'].get('cpu_count', 'N/A')}")
    print(f"✓ RAM: {system_data['hardware_info'].get('ram_total_gb', 'N/A')} GB")
    print(f"✓ Network Interfaces: {len(system_data['network_info'].get('interfaces', []))}")
    print(f"✓ Installed Software: {len(system_data.get('installed_software', []))} applications")
    print(f"✓ Running Services: {len(system_data.get('services', []))} services")
    print(f"✓ User Accounts: {len(system_data.get('users', []))} accounts")
    
    # Check EOL status
    eol_status = system_data['os_info'].get('eol_status', {})
    if eol_status.get('is_eol'):
        print(f"\n⚠ WARNING: Operating System is End-of-Life!")
        print(f"  Risk Level: {eol_status.get('risk_level')}")
    else:
        print(f"\n✓ Operating System is currently supported")
    
    # Export to test file
    test_export_path = "test_system_info.json"
    if collector.export_to_json(test_export_path):
        print(f"\n✓ Data exported to: {test_export_path}")
    
    print("\n" + "=" * 60)
    print("Test completed successfully!")
    print("=" * 60)
                                                           
