"""
Firewall configuration assessment module
this module evaulates windows firewall configuration and security settings.
It checks firewall status across different network profiles, analyses rules, and assesses Windows Defender status to determine the systems perimeter defence posture.


The firewall is a critical defence mechanism. A disabled or misconfigured firewall is increased threat to a device and exposure to network based threats.
"""

import subprocess
import logging
import json
from typing import Dict, List, Optional
from datetime import datetime

#Configure logging for audit trail
#Consistent logging accross modules enables centralised audit analysis

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FirewallChecker:
    """
    Assesses windows firewall configuration and security status.

    This class provides methods to check firewall status across different network profiles
    (Domain, Private, Public) and evaluate the overall firewall security posture. Windows uses profile-based firewall rules to adapt security based on network trust level.

    Attributes: firewall_info (Dict): Stores all collected firewall information
    collection_timestamp (str): ISO format timestamp of assessment 

    Network profile context:
    -Domain : WHen connected to corporate domain network (highest trust)
    - Private Home or work networks markjed as private (medium trust)
    - Public: Public networks like coffee shops (lowest trust, strictest rules)

    """

    def __init__(self):
        """
      Initialise the firewallchecker.
      Sets up data structure and records timestamp for temporal analysis 
      of firewall configuration changes over time.
        """
        self.firewall_info: Dict = {}
        self.collection_timestamp = datetime.now().isoformat()
        logger.info("FirewallChecker initialised")

    
    def check_all(self) -> Dict:
        """
         Orchestrates comprehensive firewall assessment..
         This method executes all firewall checks and aggregates results into a single dictionary.
         Each check is wrapped in try-except to ensure partial data collection even if individual checks fail.

         Returns:
         Dict: Complete firewall assessment containing:
         -timestamp: When assessment was performed
         -firewall_status: Status per network profile
         - defender_status: Windows Defender Configuration
         - overall_risk: Aggregated risk assessment

         Design patter:
         uses the facade pattern to provide a simple interface to complex subsystem operations (similar to system_info module).
        """

        logger.info("Starting comprehensive firewall assessment")

        # Add metadata for report generation
        self.firewall_info['timestamp'] = self.collection_timestamp
        self.firewall_info['module_version'] = '1.0.0'


        #Check firewall status for each network profile
        try:
            self.firewall_info['firewall_profiles'] = self._check_firewall_status()
        except Exception as e:
            logger.error(f"Failed to check firewall status: {e}")
            self.firewall_info['firewall_profiles'] = {'error': str(e)}


        #check windows defender status
        try:
            self.firewall_info['defender_status'] = self._check_defender_status()
        except Exception as e:
            logger.error(f"Failed to check Windows Defender: {e}")
            self.firewall_info['defender_status'] = {'error': str(e)}

        
        #analuse firewall rules (basic check for rule count)
        try:
            self.firewall_info['firewall_rules'] = self._analyse_firewall_rules()
        except Exception as e:
            logger.error(f"Failed to analyse firewall rules: {e}")
            self.firewall_info['firewall_rules'] = {'error': str(e)}


        #calculate overall firewall risk level
        try:
            self.firewall_info['risk_assessment'] = self._assess_firewall_risk()
        except Exception as e:
            logger.error(f"Failed to assess firewall risl: {e}")
            self.firewall_info['risk_assessment'] = {'error': str(e)}



        logger.info("Firewall assessment completed")
        return self.firewall_info
    

    def _check_firewall_status(self) -> Dict:
        """
        Checks windows firewall status for all network profiles.
        Windows firewall maintains seperate configs for Domain, private and public network profiles. 
        Each profile should be independently verified as they can have different states.

        Returns:
        Dict: Firewall status per profile containing:
            - domain: firewall stats on domain networks
            - private: firewall state on private networks
            -public: firewall state on publick networks.


            Technical implementation:
            uses netsh command-line utility to query firewall state.
            netsh (network shell) is a Windows built in tool for configuring network settings including firewall.

            Security implementations:
                - disabled firewall on any profile is a critical vulnerability
                - public profile should ALWAYS be enabled (highest risk networks)
                - domain profile may be disabled if corporate firewall exists
        """
        logger.info("Checking Windows Firewall status accross all profiles")

        profiles = {
            'domain': {'enabled': None, 'risk_level': 'Unknown'},
            'private': {'enabled': None, 'risk_level': 'Unknown'},
            'public': {'enabled': None, 'risk_level': 'Unknown'}
        }

        try:
            #execute netsh command to show firewall state
            #netsh advfirewall show allprofiles returns status for all profiles

            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                capture_output=True,
                text=True,
                timeout=300,
                encoding='utf-8',
                errors='ignore'
            )

            if result.returncode == 0:
                #parse output to extract firewall state for each profile
                lines = result.stdout.split('\n')
                current_profile = None
                for line in lines:
                    line = line.strip()


                    #identify which profile is being read
                    if 'Domain Profile' in line:
                        current_profile = 'domain'
                    elif 'Private Profile' in line:
                        current_profile = 'private'
                    elif 'Public Profile' in line:
                        current_profile = 'public'

                    #extract the state value (ON or OFF)
                    if 'State' in line and current_profile:
                        if 'ON' in line.upper():
                            profiles[current_profile]['enabled'] = True
                            profiles[current_profile]['risk_level'] = 'Low' 
                        elif 'OFF' in line.upper():
                            profiles[current_profile]['enabled'] = False
                            # disabled firewall is a a critical risk
                            profiles[current_profile]['risk_level'] = 'Critical'



                logger.info("Firewall status retrieved successfully")
            else:
                logger.warning(f"netsh command failed with return code {result.returncode}")
        except subprocess.TimeoutExpired:
            logger.error("firewall status check timed out")
        except FileNotFoundError:
            logger.error("netsh command not found (not on Windows?)")
        except Exception as e:
            logger.error(f"Unexpected error checking firewall status: {e}")

        return profiles

    def _check_defender_status(self) -> Dict:
        """
        Checks windows defender antivirus and protection status.
        windows defender is the built in antivirus in windows. This check verifies if real-time protection is active and if definitions are up to date.

        Returns:
        Dict: Windows defender status containing:
        -service_runnning: Whether defender service is active
        -realtime_protection: if real-time scanning is enabled
        -definitions_updated: if virus definitions are current

        Security context 
        disabled or outdated antivirus significantly increases malware infection risk. Many ransomware attacks succeed due to disabled or outdated AV solutions.

        Technical note: 
        uses powershell Get-MpComputerStatus cmdlet which requires windows 8/Server 2012 or later with defender installed.
        """
        logger.info("Checking Windows Defender status")

        defender_status = {
            'service_running': None,
            'realtime_protection_enabled': None,
            'antivirus_enabled': None,
            'antispyware_enabled': None,
            'status_available': False
        }
        try:
            # Use powershell to query windows defender status
            # Get-MpComputerStatus returns detailed Defender configuration
            result = subprocess.run(
                ['powershell', '-Command', 'Get-MpComputerStatus | ConvertTo-Json'],
                capture_output=True,
                text=True,
                timeout=30,
                encoding='utf-8',
                errors='ignore'
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    #Parse JSON output from powershell
                    defender_data = json.loads(result.stdout)

                    #extract key security settings
                    defender_status['status_available'] = True
                    defender_status['realtime_protection_enabled'] = defender_data.get('RealTimeProtectionEnabled', False)
                    defender_status['antivirus_enabled'] = defender_data.get('AntivirusEnabled', False)
                    defender_status['antispyware_enabled'] = defender_data.get('AntispywareEnabled', False)
                    defender_status['service_running'] = defender_data.get('AMServiceEnabled', False)

                    #check if definitions are outdated (7+ days)
                    #Outdated definitions cannot detect new threats
                    signature_age = defender_data.get('AntivirusSignatureAge', None)
                    if signature_age is not None:
                        defender_status['signature_age_days'] = signature_age
                        #defnitions older than 7 days are considered outdated
                        defender_status['signatures_outdated'] = signature_age > 7

                    logger.info("Windows Defender status retrieved successfully")
                except json.JSONDecodeError:
                    logger.error("Failed to parse Defender status JSON")
            else:
                logger.warning("Could not retrieve WIndows Defender status (may be not installed?)")
        
        except subprocess.TimeoutExpired:
            logger.error("Windows Defender check timed out")
        except FileNotFoundError:
            logger.error("Powershell not found")
        except Exception as e:
            logger.error(f"Unexpected error checking Defender status: {e}")
        
        return defender_status


    def _analyse_firewall_rules(self) -> Dict:
        """
       Analyses Windows firewall rules configuration.

       Firewall rules define which network traffic is allowed or blocked. 
       While comprehensive rule analysis is complex, this method provides basic stats about rule configs.

       Returns:
       Dict: Firewall rules summary containing:
       -total_rules: Count of configured rules
       - enabled_rules: count of active rules
       -inbound_rules: rules for incoming connections
       -outbound_rules: rules for outgoing connections

       Security considerations:
       -Too few rules may indicate insufficient protection
       -too many rules can create management issues and conflicts
       - default- allow policies are generally insecure
       -inbound rules require stricter scrutiny than outbound

       Performance note:
       full rule enumeration can be slow (thousands of rules)
       this implementation provides counts rather than full enumeration
       to maintain reasonable exectution time
        """
        logger.info("Analysing firewall rules")
        
        rules_info = {
            'total_rules': 0,
            'enabled_rules': 0,
            'analysis_available': False
        }
        
        try:
            # Get count of all firewall rules
            # netsh advfirewall firewall show rule name=all provides complete list
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                capture_output=True,
                text=True,
                timeout=30,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                # Count rules by looking for "Rule Name:" entries
                # Each rule starts with "Rule Name:" in netsh output
                rule_count = 0
                enabled_count = 0
                currently_enabled = False
                
                for line in lines:
                    if 'Rule Name:' in line:
                        rule_count += 1
                        if currently_enabled:
                            enabled_count += 1
                        currently_enabled = False  # Reset for next rule
                    
                    # Check if current rule is enabled
                    if 'Enabled:' in line:
                        if 'Yes' in line:
                            currently_enabled = True
                
                # Handle last rule (OUTSIDE the for loop)
                if currently_enabled:
                    enabled_count += 1
                
                rules_info['total_rules'] = rule_count
                rules_info['enabled_rules'] = enabled_count
                rules_info['analysis_available'] = True
                
                logger.info(f"Found {rule_count} firewall rules ({enabled_count} enabled)")
            else:
                logger.warning("Could not retrieve firewall rules")
        
        except subprocess.TimeoutExpired:
            logger.error("Firewall rules analysis timed out")
        except Exception as e:
            logger.error(f"Error analyzing firewall rules: {e}")
        
        return rules_info

    def _assess_firewall_risk(self) -> Dict:
        """
     Calculates overall firewall security risk level.

     This method aggregates findings from all firewall checks to determine an overall risk score. RIsk assessment considers:
     - Firewall enabled/disabled status per profile
     - Windows defender status
     - Configuration completeness

     Returns: 
        Dict:Risk assessment containing:
        - overall_risk: Low, Medium, High, or Critical
                    - risk_score: Numeric score (0-10, higher = more risk)
                    - findings: List of specific security issues
                    - recommendations: Remediation suggestions
                    
            Risk Scoring Methodology:
                Based on weighted risk factors:
                - Any firewall disabled: +4 points (critical)
                - Public firewall disabled: +5 points (severe)
                - Defender disabled: +3 points (high)
                - Defender outdated: +2 points (medium)
                - No firewall rules: +2 points (medium)
                
                Score ranges:
                - 0-2: Low risk
                - 3-5: Medium risk
                - 6-8: High risk
                - 9-10: Critical risk
        """
        logger.info("Assessing overall firewall risk")

        risk_score = 0
        findings = []
        recommendations = []


        # Assess firewall profile status 
        if 'firewall_profiles' in self.firewall_info:
            profiles = self.firewall_info['firewall_profiles']

            # Check each profile for disabled firewall
            for profile_name, profile_data in profiles.items():
                if isinstance(profile_data, dict) and profile_data.get('enabled') == False:
                    if profile_name == 'public':
                        # public profile is most critical (untrusted networks)
                        risk_score += 5
                        findings.append(f"CRITICAL: {profile_name.capitalize()} firewall is DISABLED")
                        recommendations.append(f"Enable {profile_name} profile firewall immediately")
                    else:
                        risk_score += 4
                        findings.append(f"HIGH: {profile_name.capitalize()} firewall is DISABLED")
                elif isinstance(profile_data, dict) and profile_data.get('enabled') is None:
                        findings.append(f"UNKNOWN: Could not determine {profile_name.capitalize()} firewall state")
                        recommendations.append(f"Manually verify {profile_name} firewall is enabled")
                    
        # Assess windows defender status
        if 'defender_status' in self.firewall_info:
            defender = self.firewall_info['defender_status']

            if isinstance(defender, dict):
                #Check if real time protection is disabled
                if defender.get('realtime_protection_enabled') == False:
                    risk_score += 3
                    findings.append("HIGH: Windows Defender real-time protection is DISABLED")
                    recommendations.append("Enable Windows Defender real-time protection")

                # check if antivirus is disabled
                if defender.get('antivirus_enabled') == False:
                    risk_score += 3
                    findings.append("HIGH: Window Defender antivirus is DISABLED")
                    recommendations.append("Enable Windows Defender antiirus immediately")

                #check for outdated definitions
                if defender.get('signatures_outdated') == True:
                    risk_score += 2
                    age = defender.get('signature_age_days', 'unknown')
                    findings.append(f"MEDIUM: Defender definitionsoutdated ({age} days old)")
                    recommendations.append("Update Windows Defender virus definitions")


        # Assess firewall rules configuration
        if 'firewall_rules' in self.firewall_info:
            rules = self.firewall_info['firewall_rules']

            if isinstance(rules, dict) and rules.get('analysis_available'):
                # check if there are very few rules (potential misconfiguration)
                if rules.get('total_rules', 0) < 10:
                    risk_score += 1
                    findings.append("LOW: Very few firewall rules configured")
                    recommendations.append("Review and configure appropriate firewall rules")


        # Cap risk score at 10 (maximum)
        risk_score = min(risk_score, 10)

        #determine risk level based on score
        if risk_score >= 9:
            risk_level = "Critical"
        elif risk_score >= 6:
            risk_level = "High"
        elif risk_score >= 3:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # if no issues found, add positive finding

        if not findings:
            findings.append("No significant firewall security issues detected")
            recommendations.append("Maintain current firewall configuration")

        assessment = {
            'overall_risk': risk_level,
            'risk_score': risk_score,
            'max_score': 10,
            'findings': findings,
            'recommendations': recommendations
        
        }

        logger.info(f"Firewall risk assessment: {risk_level} (score: {risk_score}/10)")
        return assessment
    

    def export_to_json(self, filepath: str) -> bool:
        """
       Exports firewall assessment results to JSON file.
       
       JSON export enables integration with reporting tools and provides machine-readable output for automated analysis.

       Args: 
            filepath (str): Destination path for JSON export

        Returns:
            bool: true if export successful, false otherwise

        Security note:
            Exported file contains security configuration details
            which should be protected from unauthorised access.
        """
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.firewall_info, f, indent=4, ensure_ascii=False)
            logger.info(f"Firewall assessment exported to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to export firewall assessment: {e}")
            return False
        

# Module-level convenience function
def check_firewall() -> Dict:
    """
    Convenience function to perform firewall assessment. 

    provides simple interface for main audit script with needing to start the class directly.

    Returns:
            Dict: Complete firewall assessment results

    Example: 
    >>> from modules.firewall_check import check_firewall
    >>> results = check_firewall ()
    >>> print(results['risk_assessment']['overall_risk'])
    """
    checker = FirewallChecker()
    return checker.check_all()
    



# testing block - only executes when the module is ran directly
if __name__ == "__main__":
    """
    Test harness for independent module testing.
    
    Allows testing firewall checks without running full audit suite.
    Essential for iterative development and debugging.
    """
    print("=" * 60)
    print("Firewall Configuration Assessment - Test Run")
    print("=" * 60)

    # Create checker instance
    checker = FirewallChecker()

    # Perform assessment
    firewall_data = checker.check_all()

    # Display summary
    print(f"\n✓ Assessment completed at: {firewall_data['timestamp']}")

    # Show firewall profile status
    if 'firewall_profiles' in firewall_data:
        print("\n--- Firewall Profile Status ---")
        for profile, status in firewall_data['firewall_profiles'].items():
            if isinstance(status, dict):
                enabled = status.get('enabled')
                risk = status.get('risk_level')
                state = "ENABLED ✓" if enabled else "DISABLED ✗"
                print(f"{profile.capitalize():10} : {state:15} Risk: {risk}")

    # Show Windows Defender status
    if 'defender_status' in firewall_data:
        print("\n--- Windows Defender Status ---")
        defender = firewall_data['defender_status']
        if isinstance(defender, dict) and defender.get('status_available'):
            rt = "Enabled ✓" if defender.get('realtime_protection_enabled') else "Disabled ✗"
            av = "Enabled ✓" if defender.get('antivirus_enabled') else "Disabled ✗"
            print(f"Real-time Protection: {rt}")
            print(f"Antivirus: {av}")
            
            if 'signature_age_days' in defender:
                age = defender['signature_age_days']
                status = "Current ✓" if age <= 7 else "Outdated ✗"
                print(f"Definitions: {age} days old ({status})")
        else:
            print("Status unavailable")

    # Show firewall rules summary
    if 'firewall_rules' in firewall_data:
        print("\n--- Firewall Rules ---")
        rules = firewall_data['firewall_rules']
        if isinstance(rules, dict) and rules.get('analysis_available'):
            print(f"Total Rules: {rules.get('total_rules', 0)}")
            print(f"Enabled Rules: {rules.get('enabled_rules', 0)}")

    # Show risk assessment
    if 'risk_assessment' in firewall_data:
        print("\n--- Risk Assessment ---")
        assessment = firewall_data['risk_assessment']
        if isinstance(assessment, dict):
            print(f"Overall Risk: {assessment.get('overall_risk')} (Score: {assessment.get('risk_score')}/10)")
            
            if assessment.get('findings'):
                print("\nFindings:")
                for finding in assessment['findings']:
                    print(f"  • {finding}")
            
            if assessment.get('recommendations'):
                print("\nRecommendations:")
                for rec in assessment['recommendations']:
                    print(f"  • {rec}")

    # Export to test file
    test_export_path = "test_firewall_check.json"
    if checker.export_to_json(test_export_path):
        print(f"\n✓ Data exported to: {test_export_path}")

    print("\n" + "=" * 60)
    print("Test completed successfully!")
    print("=" * 60)