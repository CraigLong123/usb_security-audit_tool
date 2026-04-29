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
import tempfile
import os
from typing import Dict, List, Optional
from datetime import datetime
 
 
# Configure logging for audit trail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
 
 
 
class PasswordPolicyChecker:
 
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
        """"
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
 
        logger.info("Starting comprehensive password policy assessment")
 
        # add metadata
        self.policy_info['timestamp'] = self.collection_timestamp
        self.policy_info['module_version'] = '1.0.0'
 
        # collect password policy settings
        try:
            self.policy_info['password_policy'] = self._check_password_policy()
        except Exception as e:
            logger.error(f"Failed to check password policy: {e}")
            self.policy_info['password_policy'] = {'error': str(e)}
 
        # collect account lockout policy
        # FIX: corrected method name (was _check_lockout_poliicy) and error key
        try:
            self.policy_info['lockout_policy'] = self._check_lockout_policy()
        except Exception as e:
            logger.error(f"Failed to check lockout policy: {e}")
            self.policy_info['lockout_policy'] = {'error': str(e)}
 
        # FIX: _assess_compliance() was never called - added missing block
        try:
            self.policy_info['compliance'] = self._assess_compliance()
        except Exception as e:
            logger.error(f"Failed to assess compliance: {e}")
            self.policy_info['compliance'] = {'error': str(e)}
 
        # calculate overall risk
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
 
        policy = {
            'min_password_length': None,
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
            # execute net accounts command
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
 
                for line in lines:
                    line = line.strip()
 
                    # Minimum password length
                    if 'Minimum password length' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                policy['min_password_length'] = int(parts[1].strip())
                            except ValueError:
                                pass
 
                    # Maximum password age
                    if 'Maximum password age' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                age_str = parts[1].strip().lower()
                                if 'unlimited' in age_str or 'never' in age_str:
                                    policy['max_password_age_days'] = -1
                                else:
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
 
                    # Password history
                    # FIX: Windows returns "None" as text when no history is set
                    if 'Length of password history maintained' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                value_str = parts[1].strip().lower()
                                if 'none' in value_str:
                                    policy['password_history_count'] = 0
                                else:
                                    policy['password_history_count'] = int(value_str.split()[0])
                            except (ValueError, IndexError):
                                pass
 
                    # Lockout threshold
                    if 'Lockout threshold' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                threshold_str = parts[1].strip().lower()
                                if 'never' in threshold_str:
                                    policy['lockout_threshold'] = 0
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
                                    policy['lockout_duration_minutes'] = -1
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
 
        # Check complexity requirement separately
        try:
            policy['complexity_enabled'] = self._check_complexity_requirement()
        except Exception as e:
            logger.warning(f"Could not check complexity requirement: {e}")
 
        return policy
 
 
    def _check_complexity_requirement(self) -> Optional[bool]:
        """
        Checks if password complexity requirement is enabled.
 
        Password complexity requires passwords to contain characters from at least 3 of:
        - Uppercase letters
        - Lowercase letters  
        - Digits
        - Special characters
 
        Returns:
            Optional[bool]: True if complexity enabled, False if disabled, None if unable to determine
 
        Technical:
            Uses secedit to export and read the security policy configuration.
            Method 1 (Get-LocalUser.PasswordComplexity) removed as it does not exist
            and was silently failing every time.
 
        Security impact:
            Complexity requirements significantly increase password entropy
            and resistance to dictionary attacks.
        """
 
        # Use secedit to check complexity (most reliable method on Windows)
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.cfg', delete=False) as tmp:
                # FIX: NamedTemporaryFile (capital F), removed space from suffix
                temp_path = tmp.name
 
            result = subprocess.run(
                ['secedit', '/export', '/cfg', temp_path],
                capture_output=True,
                timeout=30
            )
 
            if result.returncode == 0 and os.path.exists(temp_path):
                with open(temp_path, 'r', encoding='utf-16') as f:
                    content = f.read()
                    for line in content.split('\n'):
                        if 'PasswordComplexity' in line:
                            if '= 1' in line or '=1' in line:
                                os.unlink(temp_path)
                                return True
                            elif '= 0' in line or '=0' in line:
                                os.unlink(temp_path)
                                return False
 
                os.unlink(temp_path)
 
        except Exception as e:
            logger.debug(f"secedit method failed: {e}")
 
        return None
 
 
    def _check_lockout_policy(self) -> Dict:
        # FIX: renamed from _check_lockout_poliicy (double ii typo)
        """
        Retrieves account lockout policy settings.
 
        Account lockout policies protect against brute force attacks by temporarily
        disabling accounts after repeated failed login attempts.
 
        Returns:
            Dict: Lockout policy details extracted from password_policy data.
 
        Security considerations:
            - Lockout threshold too low: enables denial-of-service attacks
            - Lockout threshold too high: allows more brute force attempts
            - No lockout: unlimited brute force attempts possible
 
        Best practices:
            Threshold: 5-10 failed attempts (CIS recommends 5)
            Duration: 15-30 minutes (or until admin unlocks)
            Window: 15-30 minutes
        """
        logger.info("Checking account lockout policy")
 
        password_policy = self.policy_info.get('password_policy', {})
 
        lockout = {
            'threshold': password_policy.get('lockout_threshold'),
            'duration_minutes': password_policy.get('lockout_duration_minutes'),
            # FIX: standardised key to 'window_minutes' (was 'windows_minutes')
            'window_minutes': password_policy.get('lockout_window_minutes'),
            'enabled': (password_policy.get('lockout_threshold') or 0) > 0
        }
 
        return lockout
 
 
    def _assess_compliance(self) -> Dict:
        """
        Assesses password policy compliance with security standards.
 
        Compares current policy settings against multiple security frameworks
        to determine compliance levels and identify gaps.
 
        Returns:
            Dict: Compliance assessment containing:
                - checks_passed: number of checks passed
                - checks_total: total checks performed
                - compliance_percentage: percentage score
                - compliance_level: Excellent / Good / Fair / Poor
                - issues: list of identified gaps
                - recommendations: remediation steps
 
        Frameworks used:
            NIST SP 800-63B: Modern password guidelines (favours length)
            CIS Benchmarks: Industry consensus standards
            Microsoft security baseline: vendor best practices
        """
        logger.info("Assessing password policy compliance")
 
        password_policy = self.policy_info.get('password_policy', {})
 
        compliance = {
            'checks_passed': 0,
            'checks_total': 8,
            'issues': [],
            'recommendations': []
        }
 
        # FIX: guard all values against None using 'or' fallback
        min_length = password_policy.get('min_password_length') or 0
        complexity = password_policy.get('complexity_enabled')
        history = password_policy.get('password_history_count') or 0
        max_age = password_policy.get('max_password_age_days') or -1
        min_age = password_policy.get('min_password_age_days') or 0
        lockout_threshold = password_policy.get('lockout_threshold') or 0
        lockout_duration = password_policy.get('lockout_duration_minutes') or 0
        lockout_window = password_policy.get('lockout_window_minutes') or 0
 
        # Check 1: Minimum password length (NIST: 8+, CIS: 14+)
        if min_length >= 14:
            compliance['checks_passed'] += 1
        elif min_length >= 8:
            compliance['checks_passed'] += 0.5
            compliance['issues'].append(f"Password length is {min_length} (good), but CIS recommends 14+")
            compliance['recommendations'].append("Increase minimum password length to 14 characters")
        else:
            compliance['issues'].append(f"Password length is only {min_length} (critical)")
            compliance['recommendations'].append("Increase minimum password length to at least 8 characters (14+ recommended)")
 
        # Check 2: Password complexity
        if complexity is True:
            compliance['checks_passed'] += 1
        elif complexity is False:
            compliance['issues'].append("Password complexity is disabled")
            compliance['recommendations'].append("Enable password complexity requirements")
        else:
            compliance['issues'].append("Password complexity setting could not be determined")
 
        # Check 3: Password history (should remember 24+ passwords)
        if history >= 24:
            compliance['checks_passed'] += 1
        elif history >= 12:
            compliance['checks_passed'] += 0.5
            compliance['issues'].append(f"Password history is {history} (recommend 24+)")
            compliance['recommendations'].append("Increase password history to at least 24 passwords")
        else:
            compliance['issues'].append(f"Password history is only {history} (critical)")
            compliance['recommendations'].append("Increase password history to at least 24 passwords")
 
        # Check 4: Maximum password age
        if max_age == -1:
            compliance['issues'].append("Passwords never expire (security risk)")
            compliance['recommendations'].append("Set maximum password age to 60-90 days")
        elif 60 <= max_age <= 90:
            compliance['checks_passed'] += 1
        elif max_age > 90:
            compliance['checks_passed'] += 0.5
            compliance['issues'].append(f"Password expiration is {max_age} days (too long)")
            compliance['recommendations'].append("Reduce maximum password age to 60-90 days")
        elif max_age < 60:
            compliance['checks_passed'] += 0.5
            compliance['issues'].append(f"Password expiration is {max_age} days (may cause user fatigue)")
            compliance['recommendations'].append("Consider increasing to 60-90 days to reduce user fatigue")
 
        # Check 5: Minimum password age
        if min_age >= 1:
            compliance['checks_passed'] += 1
        else:
            compliance['issues'].append("Minimum password age is 0 (allows immediate password changes)")
            compliance['recommendations'].append("Set minimum password age to 1 day to prevent password cycling")
 
        # Check 6: Account lockout enabled
        if lockout_threshold > 0:
            compliance['checks_passed'] += 1
            if lockout_threshold < 3:
                compliance['issues'].append(f"Lockout threshold is {lockout_threshold} (too low, DoS risk)")
                compliance['recommendations'].append("Consider increasing lockout threshold to 5-10 attempts")
            elif lockout_threshold > 20:
                compliance['issues'].append(f"Lockout threshold is {lockout_threshold} (too high)")
                compliance['recommendations'].append("Reduce lockout threshold to 5-10 attempts")
        else:
            compliance['issues'].append("Account lockout is disabled (brute force attacks possible)")
            compliance['recommendations'].append("Enable account lockout with threshold of 5-10 attempts")
 
        # Check 7: Lockout duration
        if lockout_duration == -1:
            compliance['checks_passed'] += 1
        elif 15 <= lockout_duration <= 60:
            compliance['checks_passed'] += 1
        elif lockout_duration > 0:
            compliance['checks_passed'] += 0.5
            compliance['issues'].append(f"Lockout duration is {lockout_duration} minutes (consider 15-60 minutes)")
 
        # Check 8: Lockout observation window
        if 15 <= lockout_window <= 60:
            compliance['checks_passed'] += 1
        elif lockout_window > 0:
            compliance['checks_passed'] += 0.5
            compliance['issues'].append(f"Lockout observation window is {lockout_window} minutes (consider 15-60 minutes)")
 
        # Calculate compliance percentage
        compliance['compliance_percentage'] = (compliance['checks_passed'] / compliance['checks_total']) * 100
 
        # Determine compliance level
        if compliance['compliance_percentage'] >= 90:
            compliance['compliance_level'] = "Excellent"
        elif compliance['compliance_percentage'] >= 75:
            compliance['compliance_level'] = "Good"
        elif compliance['compliance_percentage'] >= 50:
            compliance['compliance_level'] = "Fair"
        else:
            compliance['compliance_level'] = "Poor"
 
        logger.info(f"Compliance assessment: {compliance['compliance_level']} ({compliance['compliance_percentage']:.1f}%)")
        return compliance
 
 
    def _assess_policy_risk(self) -> Dict:
        """
        Calculates overall password policy risk level.
 
        Aggregates findings from policy assessment to determine risk score.
        Uses weighted factors based on severity of policy weaknesses.
 
        Returns:
            Dict: Risk assessment containing:
                - overall_risk: Low, Medium, High, or Critical
                - risk_score: Numeric score (0-10, higher = more risk)
                - findings: List of specific security issues
                - recommendations: Prioritized remediation steps
 
        Risk Scoring Methodology:
            - Password length < 8: +4 points (critical)
            - No password complexity: +3 points (high)
            - No lockout policy: +3 points (high)
            - No password expiration: +2 points (medium)
            - Low password history: +2 points (medium)
            - No minimum password age: +1 point (low)
 
        Score ranges:
            0-2: Low | 3-5: Medium | 6-8: High | 9-10: Critical
        """
        logger.info("Assessing password policy risk")
 
        risk_score = 0
        findings = []
        recommendations = []
 
        password_policy = self.policy_info.get('password_policy', {})
 
        # FIX: guard all values against None to prevent TypeError on comparisons
        min_length = password_policy.get('min_password_length') or 0
        complexity = password_policy.get('complexity_enabled')
        lockout_threshold = password_policy.get('lockout_threshold') or 0
        max_age = password_policy.get('max_password_age_days') or -1
        history = password_policy.get('password_history_count') or 0
        min_age = password_policy.get('min_password_age_days') or 0
 
        # Critical: Password length too short
        if min_length < 8:
            risk_score += 4
            findings.append(f"CRITICAL: Minimum password length is only {min_length} characters")
            recommendations.append("Immediately increase minimum password length to at least 8 characters")
        elif min_length < 14:
            risk_score += 1
            findings.append(f"MEDIUM: Password length is {min_length} (CIS recommends 14+)")
 
        # High: No password complexity
        if complexity is False:
            risk_score += 3
            findings.append("HIGH: Password complexity requirements are disabled")
            recommendations.append("Enable password complexity to require mixed character types")
 
        # High: No account lockout
        if lockout_threshold == 0:
            risk_score += 3
            findings.append("HIGH: Account lockout is disabled (unlimited brute force attempts)")
            recommendations.append("Enable account lockout with 5-10 attempt threshold")
        elif lockout_threshold > 20:
            risk_score += 1
            findings.append(f"LOW: Lockout threshold is high ({lockout_threshold} attempts)")
 
        # Medium: No password expiration
        if max_age == -1:
            risk_score += 2
            findings.append("MEDIUM: Passwords never expire")
            recommendations.append("Set password expiration to 60-90 days")
 
        # Medium: Insufficient password history
        if history < 5:
            risk_score += 2
            findings.append(f"MEDIUM: Password history only remembers {history} passwords")
            recommendations.append("Increase password history to at least 24 passwords")
        elif history < 24:
            risk_score += 1
            findings.append(f"LOW: Password history is {history} (recommend 24)")
 
        # Low: No minimum password age
        if min_age == 0:
            risk_score += 1
            findings.append("LOW: No minimum password age (allows password cycling)")
            recommendations.append("Set minimum password age to 1 day")
 
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
 
        if not findings:
            findings.append("No significant password policy issues detected")
            recommendations.append("Maintain current password policy configuration")
 
        assessment = {
            'overall_risk': risk_level,
            'risk_score': risk_score,
            'max_score': 10,
            'findings': findings,
            'recommendations': recommendations
        }
 
        logger.info(f"Password policy risk: {risk_level} (score: {risk_score}/10)")
        return assessment
 
 
    def export_to_json(self, filepath: str) -> bool:
        """
        Exports password policy assessment to JSON file.
 
        Args:
            filepath (str): Destination path for JSON export
 
        Returns:
            bool: True if export successful, False otherwise
 
        Security Note:
            While this doesn't contain actual passwords, policy settings
            can inform attackers about password requirements for targeted
            attacks. Protect exported files appropriately.
        """
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.policy_info, f, indent=4, ensure_ascii=False)
            logger.info(f"Password policy assessment exported to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to export password policy assessment: {e}")
            return False
 
 
# Module-level convenience function
def check_password_policy() -> Dict:
    """
    Convenience function to check password policy.
 
    Provides simple interface for main audit script.
 
    Returns:
        Dict: Complete password policy assessment
 
    Example:
        >>> from modules.password_policy import check_password_policy
        >>> results = check_password_policy()
        >>> print(results['risk_assessment']['overall_risk'])
    """
    checker = PasswordPolicyChecker()
    return checker.check_all()
 
 
# Testing block
if __name__ == "__main__":
    """
    Test harness for independent module testing.
    """
    print("=" * 60)
    print("Password Policy Assessment - Test Run")
    print("=" * 60)
 
    checker = PasswordPolicyChecker()
    policy_data = checker.check_all()
 
    print(f"\n✓ Assessment completed at: {policy_data['timestamp']}")
 
    # Show password policy
    if 'password_policy' in policy_data:
        print("\n--- Password Policy ---")
        policy = policy_data['password_policy']
        if isinstance(policy, dict) and policy.get('retrieval_successful'):
            print(f"Minimum Length: {policy.get('min_password_length', 'N/A')} characters")
 
            max_age = policy.get('max_password_age_days', 'N/A')
            if max_age == -1:
                print("Maximum Age: Never expires")
            else:
                print(f"Maximum Age: {max_age} days")
 
            print(f"Minimum Age: {policy.get('min_password_age_days', 'N/A')} days")
            print(f"Password History: {policy.get('password_history_count', 'N/A')} passwords")
 
            complexity = policy.get('complexity_enabled')
            if complexity is True:
                print("Complexity: Enabled ✓")
            elif complexity is False:
                print("Complexity: Disabled ✗")
            else:
                print("Complexity: Unknown")
        else:
            print("Could not retrieve password policy")
 
    # Show lockout policy
    if 'lockout_policy' in policy_data:
        print("\n--- Account Lockout Policy ---")
        lockout = policy_data['lockout_policy']
        if isinstance(lockout, dict):
            threshold = lockout.get('threshold') or 0
            if threshold > 0:
                print(f"Lockout Threshold: {threshold} failed attempts")
 
                duration = lockout.get('duration_minutes', 'N/A')
                if duration == -1:
                    print("Lockout Duration: Until admin unlocks")
                else:
                    print(f"Lockout Duration: {duration} minutes")
 
                print(f"Observation Window: {lockout.get('window_minutes', 'N/A')} minutes")
            else:
                print("Account Lockout: Disabled ✗")
 
    # Show compliance
    if 'compliance' in policy_data:
        print("\n--- Compliance Assessment ---")
        compliance = policy_data['compliance']
        if isinstance(compliance, dict):
            print(f"Compliance Level: {compliance.get('compliance_level', 'Unknown')}")
            print(f"Compliance Score: {compliance.get('compliance_percentage', 0):.1f}%")
            print(f"Checks Passed: {compliance.get('checks_passed', 0)}/{compliance.get('checks_total', 0)}")
 
            if compliance.get('issues'):
                print(f"\nIssues Found ({len(compliance['issues'])}):")
                for issue in compliance['issues']:
                    print(f"  • {issue}")
 
    # Show risk assessment
    if 'risk_assessment' in policy_data:
        print("\n--- Risk Assessment ---")
        assessment = policy_data['risk_assessment']
        if isinstance(assessment, dict):
            print(f"Overall Risk: {assessment.get('overall_risk')} (Score: {assessment.get('risk_score')}/10)")
 
            if assessment.get('findings'):
                print("\nFindings:")
                for finding in assessment['findings']:
                    print(f"  • {finding}")
 
            if assessment.get('recommendations'):
                print("\nTop Recommendations:")
                for i, rec in enumerate(assessment['recommendations'][:5], 1):
                    print(f"  {i}. {rec}")
 
    # Export to test file
    test_export_path = "test_password_policy.json"
    if checker.export_to_json(test_export_path):
        print(f"\n✓ Data exported to: {test_export_path}")
 
    print("\n" + "=" * 60)
    print("Test completed successfully!")
    print("=" * 60)
        