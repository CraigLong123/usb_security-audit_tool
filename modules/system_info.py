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
                - risk_assessment: Overall system risk score and findings
        """
        logger.info("Starting comprehensive system information collection")
 
        # Add metadata for report generation and temporal tracking
        self.info['timestamp'] = self.collection_timestamp
        self.info['audit_version'] = '1.0.0'
 
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
 
        # FIX: Added missing risk_assessment — required by risk_calculator.py
        try:
            self.info['risk_assessment'] = self._assess_system_risk()
        except Exception as e:
            logger.error(f"Failed to assess system risk: {e}")
            self.info['risk_assessment'] = {'error': str(e)}
 
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
            'system':       platform.system(),
            'release':      platform.release(),
            'version':      platform.version(),
            'architecture': platform.machine(),
            'hostname':     platform.node(),
            'processor':    platform.processor(),
        }
 
        # FIX: Increased timeout from 30s to 90s — systeminfo can take 60s+
        try:
            result = subprocess.run(
                ['systeminfo'],
                capture_output=True,
                text=True,
                timeout=90,
                encoding='utf-8',
                errors='ignore'
            )
 
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'OS Name:' in line:
                        os_info['os_name'] = line.split(':', 1)[1].strip()
                    elif 'OS Version:' in line:
                        os_info['os_version_detailed'] = line.split(':', 1)[1].strip()
                    elif 'Original Install Date:' in line:
                        os_info['install_date'] = line.split(':', 1)[1].strip()
                    elif 'System Boot Time:' in line:
                        os_info['last_boot'] = line.split(':', 1)[1].strip()
                    elif 'Domain:' in line:
                        os_info['domain'] = line.split(':', 1)[1].strip()
 
                logger.info("Detailed OS information collected via systeminfo")
 
        except subprocess.TimeoutExpired:
            logger.warning("systeminfo command timed out — using platform module data only")
        except Exception as e:
            logger.warning(f"Could not get detailed Windows info: {e}")
 
        # Check EOL status
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
        # Known EOL dates for Windows versions
        # FIX: Windows 10 EOL date (Oct 2025) has now passed — updated to High risk
        eol_dates = {
            'XP':  {'date': '2014-04-08', 'risk': 'Critical'},
            'Vista': {'date': '2017-04-11', 'risk': 'Critical'},
            '7':   {'date': '2020-01-14', 'risk': 'Critical'},
            '8':   {'date': '2016-01-12', 'risk': 'Critical'},
            '8.1': {'date': '2023-01-10', 'risk': 'Critical'},
            '10':  {'date': '2025-10-14', 'risk': 'High'},   # FIX: Now EOL, was 'Low'
            '11':  {'date': '2031-10-14', 'risk': 'Low'},    # Still fully supported
        }
 
        eol_info = {
            'is_eol':     False,
            'eol_date':   None,
            'risk_level': 'Low'
        }
 
        if release in eol_dates:
            eol_data = eol_dates[release]
            eol_date     = datetime.strptime(eol_data['date'], '%Y-%m-%d')
            current_date = datetime.now()
 
            if current_date > eol_date:
                eol_info['is_eol']     = True
                eol_info['eol_date']   = eol_data['date']
                eol_info['risk_level'] = eol_data['risk']
                logger.warning(
                    f"OS version {release} is End-of-Life "
                    f"(EOL since {eol_data['date']})"
                )
 
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
 
        cpu_freq = psutil.cpu_freq()
        hardware_info = {
            'cpu_count':          psutil.cpu_count(logical=True),
            'cpu_count_physical': psutil.cpu_count(logical=False),
            'cpu_freq_current':   cpu_freq.current if cpu_freq else None,
            'cpu_freq_max':       cpu_freq.max if cpu_freq else None,
        }
 
        virtual_mem = psutil.virtual_memory()
        hardware_info['ram_total_gb']     = round(virtual_mem.total / (1024**3), 2)
        hardware_info['ram_available_gb'] = round(virtual_mem.available / (1024**3), 2)
        hardware_info['ram_percent_used'] = virtual_mem.percent
 
        disk_info = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    'device':       partition.device,
                    'mountpoint':   partition.mountpoint,
                    'fstype':       partition.fstype,
                    'total_gb':     round(usage.total / (1024**3), 2),
                    'used_gb':      round(usage.used / (1024**3), 2),
                    'free_gb':      round(usage.free / (1024**3), 2),
                    'percent_used': usage.percent
                })
            except PermissionError:
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
 
        Security Relevance:
            - Multiple NICs may create routing issues
            - Public IPs on workstations increase exposure
            - Misconfigured DNS can enable MitM attacks
        """
        logger.info("Collecting network information")
 
        network_info = {'interfaces': []}
 
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
 
        for interface_name, addresses in if_addrs.items():
            interface_data = {
                'name':      interface_name,
                'is_up':     if_stats[interface_name].isup if interface_name in if_stats else False,
                'addresses': []
            }
 
            for addr in addresses:
                addr_info = {
                    'family':  str(addr.family),
                    'address': addr.address,
                }
                if addr.netmask:
                    addr_info['netmask'] = addr.netmask
 
                interface_data['addresses'].append(addr_info)
 
            network_info['interfaces'].append(interface_data)
 
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
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Default Gateway' in line or 'Puertas de enlace' in line:
                        gateway = line.split(':', 1)[1].strip()
                        if gateway:
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
 
            registry_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
 
            for path in registry_paths:
                try:
                    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
 
                    for i in range(winreg.QueryInfoKey(reg_key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(reg_key, i)
                            subkey = winreg.OpenKey(reg_key, subkey_name)
 
                            try:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                software = {'name': name}
 
                                try:
                                    software['version'] = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                except Exception:
                                    software['version'] = "Unknown"
 
                                try:
                                    software['publisher'] = winreg.QueryValueEx(subkey, "Publisher")[0]
                                except Exception:
                                    software['publisher'] = "Unknown"
 
                                try:
                                    software['install_date'] = winreg.QueryValueEx(subkey, "InstallDate")[0]
                                except Exception:
                                    software['install_date'] = "Unknown"
 
                                software_list.append(software)
 
                            except Exception:
                                pass
 
                            winreg.CloseKey(subkey)
 
                        except Exception:
                            continue
 
                    winreg.CloseKey(reg_key)
 
                except FileNotFoundError:
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
        """
        logger.info("Collecting Windows services information")
 
        services_list = []
 
        try:
            for service in psutil.win_service_iter():
                try:
                    service_info = service.as_dict()
                    services_list.append({
                        'name':         service_info.get('name', 'Unknown'),
                        'display_name': service_info.get('display_name', 'Unknown'),
                        'status':       service_info.get('status', 'Unknown'),
                        'start_type':   service_info.get('start_type', 'Unknown'),
                        'username':     service_info.get('username', 'Unknown'),
                    })
                except Exception:
                    continue
 
            logger.info(f"Found {len(services_list)} Windows services")
 
        except AttributeError:
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
        - Inactive accounts that should be disabled
 
        Returns:
            List[Dict]: Local user accounts with basic information
 
        Security Implications:
            - Multiple admin accounts increase risk
            - Enabled guest accounts are critical vulnerabilities
            - Inactive accounts should be disabled
        """
        logger.info("Collecting user account information")
 
        users_list = []
 
        try:
            result = subprocess.run(
                ['net', 'user'],
                capture_output=True,
                text=True,
                timeout=30,
                encoding='utf-8',
                errors='ignore'
            )
 
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                in_user_section = False
 
                for line in lines:
                    if '---' in line:
                        in_user_section = True
                        continue
 
                    if in_user_section and line.strip():
                        # Last line of net user output is a status message — skip it
                        if 'The command completed' in line:
                            break
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
 
    def _assess_system_risk(self) -> Dict:
        """
        Calculates overall system risk score from collected information.
 
        Evaluates OS end-of-life status, risky legacy services, and user
        account hygiene to produce a risk score compatible with the
        risk_calculator module.
 
        Returns:
            Dict: Risk assessment containing:
                - overall_risk: Low, Medium, High, or Critical
                - risk_score: Numeric score (0-10)
                - findings: List of specific security issues
                - recommendations: Prioritised remediation steps
 
        Risk Scoring Methodology:
            - EOL operating system:        +4 points (critical)
            - Risky legacy service running: +3 points per service (high)
            - Guest account present:        +2 points (medium)
 
        Score ranges:
            0-2: Low | 3-5: Medium | 6-8: High | 9-10: Critical
        """
        # FIX: Added missing method — required for risk_calculator.py integration
        logger.info("Assessing overall system risk")
 
        risk_score = 0
        findings = []
        recommendations = []
 
        # Check OS EOL status
        os_info = self.info.get('os_info', {})
        eol = os_info.get('eol_status', {})
 
        if eol.get('is_eol'):
            risk_score += 4
            findings.append(
                f"CRITICAL: Operating system is End-of-Life "
                f"(EOL since {eol.get('eol_date', 'unknown')}). "
                f"No further security patches will be issued."
            )
            recommendations.append(
                "Upgrade to a supported operating system immediately. "
                "Windows 11 is the current supported version."
            )
        else:
            release = os_info.get('release', 'Unknown')
            findings.append(
                f"INFO: Operating system (Windows {release}) is currently supported"
            )
 
        # Check for risky legacy services
        risky_services = {
            'telnet':  'Telnet — unencrypted remote access',
            'ftpsvc':  'FTP — unencrypted file transfer',
            'tftpd':   'TFTP — unauthenticated file transfer',
            'rsh':     'RSH — legacy remote shell, no encryption',
            'rexec':   'REXEC — legacy remote execution, no encryption',
        }
 
        services = self.info.get('services', [])
        for svc in services:
            name   = svc.get('name', '').lower()
            status = svc.get('status', '').lower()
            if name in risky_services and status == 'running':
                risk_score += 3
                findings.append(
                    f"HIGH: Insecure legacy service is running — "
                    f"{risky_services[name]}"
                )
                recommendations.append(
                    f"Disable the {svc.get('display_name', name)} service. "
                    f"It uses unencrypted protocols and is a known attack vector."
                )
 
        # Check for guest account
        users = self.info.get('users', [])
        for user in users:
            if user.get('username', '').lower() == 'guest':
                risk_score += 2
                findings.append(
                    "MEDIUM: Guest account exists on this system. "
                    "Guest accounts allow unauthenticated access."
                )
                recommendations.append(
                    "Disable the Guest account via: "
                    "Computer Management → Local Users and Groups → Users"
                )
                break
 
        # Cap at 10
        risk_score = min(risk_score, 10)
 
        # Determine risk label
        if risk_score >= 9:
            risk_level = "Critical"
        elif risk_score >= 6:
            risk_level = "High"
        elif risk_score >= 3:
            risk_level = "Medium"
        else:
            risk_level = "Low"
 
        if not findings:
            findings.append("No significant system risk factors detected")
            recommendations.append("Maintain current system configuration and patch schedule")
 
        assessment = {
            'overall_risk':    risk_level,
            'risk_score':      risk_score,
            'max_score':       10,
            'findings':        findings,
            'recommendations': recommendations,
        }
 
        logger.info(f"System risk assessment: {risk_level} (score: {risk_score}/10)")
        return assessment
 
    def export_to_json(self, filepath: str) -> bool:
        """
        Exports collected system information to JSON file.
 
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
 
 
# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------
 
def collect_system_info() -> Dict:
    """
    Convenience function to collect all system information.
 
    Provides simple interface for audit.py without needing to
    instantiate the class directly.
 
    Returns:
        Dict: Complete system information
 
    Example:
        >>> from modules.system_info import collect_system_info
        >>> info = collect_system_info()
        >>> print(info['os_info']['system'])
    """
    collector = SystemInfoCollector()
    return collector.collect_all()
 
 
# ---------------------------------------------------------------------------
# Testing block
# ---------------------------------------------------------------------------
 
if __name__ == "__main__":
    print("=" * 60)
    print("System Information Collection Module - Test Run")
    print("=" * 60)
    print("\n  Note: systeminfo command may take up to 90 seconds...\n")
 
    collector = SystemInfoCollector()
    system_data = collector.collect_all()
 
    print(f"\n✓ Collection completed at: {system_data['timestamp']}")
    print(f"✓ Operating System: {system_data['os_info'].get('os_name', 'N/A')}")
    print(f"✓ CPU Cores: {system_data['hardware_info'].get('cpu_count', 'N/A')}")
    print(f"✓ RAM: {system_data['hardware_info'].get('ram_total_gb', 'N/A')} GB")
    print(f"✓ Network Interfaces: {len(system_data['network_info'].get('interfaces', []))}")
    print(f"✓ Installed Software: {len(system_data.get('installed_software', []))} applications")
    print(f"✓ Running Services: {len(system_data.get('services', []))} services")
    print(f"✓ User Accounts: {len(system_data.get('users', []))} accounts")
 
    # EOL status
    eol_status = system_data['os_info'].get('eol_status', {})
    if eol_status.get('is_eol'):
        print(f"\n⚠  WARNING: Operating System is End-of-Life!")
        print(f"   EOL Date:   {eol_status.get('eol_date')}")
        print(f"   Risk Level: {eol_status.get('risk_level')}")
    else:
        print(f"\n✓ Operating System is currently supported")
 
    # Risk assessment
    if 'risk_assessment' in system_data:
        print("\n--- Risk Assessment ---")
        assessment = system_data['risk_assessment']
        print(f"Overall Risk: {assessment.get('overall_risk')} "
              f"(Score: {assessment.get('risk_score')}/10)")
 
        if assessment.get('findings'):
            print("\nFindings:")
            for finding in assessment['findings']:
                print(f"  • {finding}")
 
        if assessment.get('recommendations'):
            print("\nRecommendations:")
            for rec in assessment['recommendations']:
                print(f"  • {rec}")
 
    # Export
    test_export_path = "test_system_info.json"
    if collector.export_to_json(test_export_path):
        print(f"\n✓ Data exported to: {test_export_path}")
 
    print("\n" + "=" * 60)
    print("Test completed successfully!")
    print("=" * 60)
                                                           
