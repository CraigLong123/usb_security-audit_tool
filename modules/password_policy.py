"""
Docstring for modules.password_policy

This module implements password policy assessment based on:
nist sp 800-63B digital identity guidelines
CIS control 5 (Account management)
microsoft security baseline recommendations
OWASP authentication guidelines



Security rationale: weak password policies are consistently ranked in OWASP top 10 and are the leading route for credential based attacks.
Strong password policies are a fundamental control for protecting against unauthorised access, brute force attacks and credential stuffing
"""
import subprocess
import logging 
import json
from typing import Dict, List, Optional
from datetime import datetime


# Configure logging for audit trail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)



class PasswordPoliciyChecker:

    """
assesses windows password policy configuration and compliance
This class evaluates local security policy setting related to passwords and account lockout. Windows stores these settings in 
in the security account manager and they can be queried via net accounts command or security policy tools

Attributes: policy_info (Dict): stores collected password policy information
collection_timestamp (str): ISO format timestamp of assessment

Policy categories: 
password requirements: length, complexity, age
account lokcout: threshold, duration, reset timer
password history: prevention of password reuse
    """

    def __init__(self):
        self.policy_info: Dict = {}
        self.collection_timestamp = datetime.now().isoformat()
        logger.info("PasswordPolicyChecker initialised")


    def check_all(self) -> Dict:
        """
        Docstring for check_all
        organises the comprehensive password polcy assessment. 

        executes all password polcy checks and aggregates results.
        each check is wrapped in try-except to ensure resilience and partial data collection even if individual checks fail.

        returns
        Dict: complete password policy assessment containing:
        timestamp
        password_policy: password config settings
        lockout_policy: account lockout settings
        compliance_assessment: policy vs best practices
        risk_assessment: overall password security risk


        
    
        """

        logger.info("Starting comprehensive password polcy assessment")

        #add metadata
        self.policy_info['timestamp'] = self.collection_timestamp
        self.policy_info['module_version'] = '1.0.0'


        # collect password policy settings
        try:
            self.policy_info['password_policy'] = self._check_password_policy()
        except Exception as e:
            logger.error(f"Failed to check password policy: {e}")
            self.policy_info['password_policy'] = {'error' :str(e)}

        
        #collect account lockout policy
        try:
            self.policy_info['lockout_policy'] + self._assess_compliance()
        except Exception as e:
            logger.error(f"Failed to assess compliance: {e}")
            self.policy_info['compliance'] = {'error' : str(e)}




        #calculate overall risk
        try:
            self.policy_info['risk_assessment'] = self._assess_policy_risk()
        except Exception as e:
            logger.error(f"Failed to assess policy risk: {e}")
            self.policy_info['risk_assessment'] = {'error': str(e)}
        
        logger.info("Password policy assessment completed")
        return self.policy_info

    def _check_password_policy(self) -> Dict:
        """
        Docstring for _check_password_policy
        
        retrieves windows password policy config

        uses 'net accounts' command to query local security policy settings related to passwords. this command returns settings form the security account manager
        database

        returns:

        Dict: password policy settings including:
        min_password_length: minimum required
        max_password_age: days before password expires
        min_password_age: days before password can be changed
        password_history: number of passwords rememebered
        complexity_enabled: whether complexity rules are enforced

        password policy settings directly impact resistance to 
        brute force attacks
        credential reuse attacks
        social engineering


        security standards
        NIST SP 800-63B recommends 8+ Character minimum
        CIS benchmark recommends 14+ characters
        complexity should require multiple character types
        history should prevent reuse of last 24 passwords

        """
        logger.info("Checking password policy settings")

        policy = { 'min_password_length': None,
            'max_password_age_days': None,
            'min_password_age_days': None,
            'password_history_count': None,
            'lockout_threshold': None,
            'lockout_duration_minutes': None,
            'lockout_window_minutes': None,
            'complexity_enabled': None,
            'retrieval_successful': False
        }

        
        try: 
            #execute net accounts command 
            #this command displays apssword and logon requirements
            result = subprocess.run(
                  ['net', 'accounts'],
                capture_output=True,
                text=True,
                timeout=30,
                encoding='utf-8',
                errors='replace'
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')

                # parse each line for policy settings
                for line in lines:
                    line = line.strip()

                    # Minimum password length
                    if 'Minimum password length' in line or 'Length of password history' in line:
                        # Extract number from line like "Minimum password length:        8"
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                if 'Minimum password length' in line:
                                    policy['min_password_length'] = int(parts[1].strip())
                            except ValueError:
                                pass
                    

                     # Maximum password age
                    if 'Maximum password age' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                age_str = parts[1].strip().lower()
                                # Handle "Unlimited" or number of days
                                if 'unlimited' in age_str or 'never' in age_str:
                                    policy['max_password_age_days'] = -1  # -1 indicates unlimited
                                else:
                                    # Extract number (e.g., "42 days" -> 42)
                                    policy['max_password_age_days'] = int(age_str.split()[0])
                            except (ValueError, IndexError):
                                pass
                    

                    # Minimum password age
                    if 'Minimum password age' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                age_str = parts[1].strip().lower()
                                if 'unlimited' in age_str or 'never' in age_str:
                                    policy['min_password_age_days'] = 0
                                else:
                                    policy['min_password_age_days'] = int(age_str.split()[0])
                            except (ValueError, IndexError):
                                pass
                    
                    # Password history (how many old passwords are remembered)
                    if 'Length of password history maintained' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                policy['password_history_count'] = int(parts[1].strip().split()[0])
                            except (ValueError, IndexError):
                                pass
                    
                    # Lockout threshold
                    if 'Lockout threshold' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                threshold_str = parts[1].strip().lower()
                                if 'never' in threshold_str:
                                    policy['lockout_threshold'] = 0  # 0 means lockout disabled
                                else:
                                    policy['lockout_threshold'] = int(threshold_str.split()[0])
                            except (ValueError, IndexError):
                                pass
                    
                    # Lockout duration
                    if 'Lockout duration' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                duration_str = parts[1].strip().lower()
                                if 'forever' in duration_str or 'until admin' in duration_str:
                                    policy['lockout_duration_minutes'] = -1  # -1 indicates manual unlock
                                else:
                                    policy['lockout_duration_minutes'] = int(duration_str.split()[0])
                            except (ValueError, IndexError):
                                pass
                    
                    # Lockout observation window
                    if 'Lockout observation window' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                policy['lockout_window_minutes'] = int(parts[1].strip().split()[0])
                            except (ValueError, IndexError):
                                pass
                
                policy['retrieval_successful'] = True
                logger.info("Password policy retrieved successfully")
            else:
                logger.warning(f"net accounts command failed with code {result.returncode}")
        
        except subprocess.TimeoutExpired:
            logger.error("Password policy check timed out")
        except FileNotFoundError:
            logger.error("net accounts command not found")
        except Exception as e:
            logger.error(f"Unexpected error checking password policy: {e}")
        
        # Check complexity requirement separately (requires different command)
        try:
            policy['complexity_enabled'] = self._check_complexity_requirement()
        except Exception as e:
            logger.warning(f"Could not check complexity requirement: {e}")
        
        return policy
    

    def _check_complexity_requirement(self) -> Optional[bool]:

        """
      Checks if password complexity requirement is enabled.
      password complexity requires passwords to contain characters from at least 3 of these categories:
      Uppercase letters
      Lowercase letters
      digits
      special characters

      Returns:
      Optional[bool]: tru if complexity enabled, false if disabled, none if unable to determine





      Technical
      uses powershell Get-LocalUser or secedit to check complexity setting. this is seperate from ' net accounts' output.

      security impact 
      complexity requirements significantly increase password entropy and resistance to dictionary attacks. 


        """


        try: 
            # Method 1: try powershell (windows 10+)
            result = subprocess.run(
                ['powershell', '-Command', 
                 '(Get-LocalUser | Select-Object -First 1).PasswordComplexity'],
                 capture_output=True,
                 timeout=10,
                 encoding='utf-8',
                 errors='replace'
            )
            
            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip().lower()
                if 'true' in output:
                    return True
                elif 'false' in output:
                    return False
        except:
            pass


        #Method 2: try secedit (more reliable but slower)
        try:
            #Export security policy to temp file
            import tempfile
            import os
            with tempfile.NamedTemporaryfile(mode='w' , suffix=' .cfg', delete=False) as tmp:
                temp_path = tmp.name

            # export current security policy
            result = subprocess.run(
                ['secedit' , '/export' , '/cfg' , temp_path],
                capture_output=True,
                timeout=30
            )


            if result.returncode == 0 and os.path.exists(temp_path):
                #Read and parse the exported policy
                with open(temp_path, 'r' , encoding='utf-16') as f:
                    content = f.read()
                    #Look for password complexity setting
                    #format password complexity = 1 (enabled) or 0 (disabled)
                    for line in content.split ('\n'):
                        if 'PassowrdComplexity' in line:
                            if '= 1' in line or ' =1' in line:
                                os.unlink(temp_path)
                                return False
                            

                #Cleanup temp file
                os.unlink(temp_path)
        except Exception as e:
            logger.debuyg(f"secedit method failed: {e}")

        # if both methods failed, return none (unknown)
        return None



    def _check_lockout_poliicy(self) -> Dict:
        """
        Docstring for _check_lookout_poliicy
        
        retrieves account lockout policy settings. 
        Accoun t lookout policies protect against brute force attacks by temporarily disabling accounts after repeated failed login attempts

        Returns:
        Dict: Lockout policy details (already collected in password_policy but seperated here for clarity in reporting)

        Security considerations:
        lockout threshhold too low: Enabled denial-of-service attacks
        Lockout threshold too high: Allows more brute force attempts
        No lockout: unlimited brute force attempts possible
        lockout duration: balance between security and useability

        Best practices 
        Threshold: 5-10 faile dattempts (CIS recommends 5)
        Duration: 15-30 minutes (or until admin unlocks)
        Window: 15-30 minutes        
                                """
        
        logger.info("Checking account lockout policy")

        #lockout settings are already collected in _check_password_policy
        #this method extracts them for seperat analysis
        password_policy = self.policy_infoget('password_policy' , {})

        lockout = {
            'threshold' : password_policy.get('lockout_threshhold'),
            'duration_minutes' : password_policy.get('lockout_duration_minutes'),
            'windows_minutes': password_policy.get('lockout_window_minutes'),
            'enabled' : password_policy.get('lockout_threshhold' , 0) >0
        }

        return lockout
    
    def _assess_compliance(self) -> Dict:
        """
        assesses password policy compliance with security standards.
        compares current policy settings against multiple security frameworks to determine copliance levels and identify gaps
        returns
        Dict: Compliance assessment containing
        nist_compliance: alignment with NIST sp 800-63B
        cis_compliance: alignment with CIS benchmarks
        microsoft_baseline: Alignment with Microsoft recommendations
        overall_score: percentage compliance (0-100)
        
        Frameworks used
        NIST SP 800-63B: Modern password guidelines (favours length)
        CIS Benchmarks: Industry consensus standards
        Microsoft security baseline: vendor best practices
        """
        logger.info("Assessing password policy compliance")
        
        password_policy = self.policy_info.get('password_policy' , {})

        compliance = {
            'checks_passed' : 0,
            'checks_total' : 0,
            'issues' : [],
            'recommendations' : []
        }

        # define compliance critera based on multiple standards
        compliance['checks_total'] = 8 # total number of compliance checks

        #check 1 : minimum password length (NIST: 8+, CIS: 14+)
        min_length = password_policy.get('min_password_length' , 0)
        if min_length >= 14:
            compliance['checks_passed'] += 1
        elif min_length >= 8:
            compliance['checks_passed'] += 0.5
            compliance['issues'].append(f"Password length is{min_length} (good), but CIS recommends 14+")
            compliance['recommendations'].append("Increase minumum password length to 14 characters")
        else:
            compliance['issues'].append(f"Password length is only {min_length} (critical)")
            compliance['recommendations'].append("Increase minimum password length to at least 8 characters (14+ recommended)")


        # check 2: password complexity 
        complexity = password_policy.get('complexity_enabled')
        if complexity is True:
            compliance['checks_passed'] += 1
        elif complexity is False:
            compliance['issues'].append("Passowrd complexity is disabled")
            compliance['recommendations'].append("Enable password complexity requirements")
        else:
            compliance['issues'].append("Password complexity setting could not be determined")


        #check 3: password history (should remember 24+ passwords)
        history= password_policy.get('password_history_count' , 0)
        if history >= 24:
            compliance['checks_passed'] +=1
        elif history >=12:
            compliance['checks_passed'] +=0.5
            compliance['issues'].append(f"Password history is only {history} (critical)")
            compliance['recommendations'].append("Increase password history to at least 24 passwords")




        #check 4: maximum password age (should be 60-90 days, not unlimited)
        max_age = password_policy.get('max_password_age_days' , -1)
        if max_age == -1:
            compliance['issues'].append("Passwords never expire (security risk)")
            compliance['recommendations'].append("Set maximum password age to 60-90 days")
        elif 60 <= max_age <= 90:
            compliance['checks_passed'] += 1
        elif max_age > 90:
            compliance['checks_passed'] += 0.5
            compliance['issues'].append(f"Password expiration is {max_age} days (too long)")
            compliance['recommendations'].append("Reduce maximum password age to 60-90 days")
        elif max_age <60:
            compliance['checks_passed'] += 0.5
            compliance['issues'].append(f"Password expiration is {max_age} days (too short, user fatigue)")
            compliance['recommendations'].append("Consider increasing to 60-90days to reduce user fatigue")


        #check 5: minimum password age
        