
"""
Risk calculation and aggregation module.
 
This module aggregates security findings from all assessment modules
and calculates an overall risk score for the audited system.
 
Each module contributes a weighted score to the final result, reflecting
the relative importance of each security domain. The methodology is based on:
 
    NIST SP 800-30 Rev 1 - Guide for Conducting Risk Assessments
    CIS Controls v8 - Prioritised security controls
    CVSS v3.1 scoring concepts - Weighted severity aggregation
 
Design rationale:
    Individual modules collect and report raw findings.
    This module is solely responsible for aggregation and scoring.
    This separation of concerns means scoring logic can be adjusted
    without modifying data collection modules.
"""
 
import logging
import json
from typing import Dict, List, Optional
from datetime import datetime
 
 
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
 
 
# ---------------------------------------------------------------------------
# Module weights
# ---------------------------------------------------------------------------
# Weights reflect the relative importance of each security domain.
# They must sum to 1.0.
#
# Justification (based on Verizon DBIR and CIS Controls v8 prioritisation):
#   Firewall    (0.30) - Perimeter defence; first line against network threats
#   Password    (0.25) - Credential attacks account for majority of breaches
#   Port        (0.25) - Attack surface directly determines exposure
#   System Info (0.20) - OS/patch currency affects vulnerability exposure
#
# Academic reference:
#   Verizon Data Breach Investigations Report 2024 identifies credential
#   theft and network-level attacks as the two leading breach categories,
#   justifying the combined 55% weight for firewall and password modules.
# ---------------------------------------------------------------------------
 
MODULE_WEIGHTS = {
    'firewall':  0.30,
    'password':  0.25,
    'port':      0.25,
    'system':    0.20,
}
 
 
class RiskCalculator:
    """
    Aggregates module findings into an overall system risk assessment.
 
    Accepts output dictionaries from each assessment module and applies
    weighted scoring to produce a single, justified risk verdict.
 
    Attributes:
        results (Dict): Stores the complete aggregated risk report.
        collection_timestamp (str): ISO timestamp of calculation.
        module_data (Dict): Raw data received from each module.
    """
 
    def __init__(self):
        self.results: Dict = {}
        self.collection_timestamp = datetime.now().isoformat()
        self.module_data: Dict = {}
        logger.info("RiskCalculator initialised")
 
    # -----------------------------------------------------------------------
    # Public interface
    # -----------------------------------------------------------------------
 
    def calculate(
        self,
        firewall_data: Optional[Dict] = None,
        password_data: Optional[Dict] = None,
        port_data:     Optional[Dict] = None,
        system_data:   Optional[Dict] = None,
    ) -> Dict:
        """
        Performs the full risk aggregation and returns the complete report.
 
        Each argument accepts the dict returned by the corresponding module's
        check_all() method. Passing None for a module excludes it from scoring
        and adjusts weights proportionally so the result remains on a 0-10 scale.
 
        Args:
            firewall_data: Output of FirewallChecker.check_all()
            password_data: Output of PasswordPolicyChecker.check_all()
            port_data:     Output of PortScanner.check_all()
            system_data:   Output of SystemInfo.check_all()
 
        Returns:
            Dict: Complete risk report containing:
                - timestamp
                - module_scores:   per-module weighted scores and findings
                - overall_score:   final numeric score (0-10)
                - overall_risk:    Low / Medium / High / Critical label
                - all_findings:    deduplicated list of all findings
                - all_recommendations: prioritised remediation list
                - summary:         human-readable executive summary
        """
        logger.info("Starting risk calculation")
 
        # Store raw module data for reference
        self.module_data = {
            'firewall': firewall_data,
            'password': password_data,
            'port':     port_data,
            'system':   system_data,
        }
 
        self.results['timestamp'] = self.collection_timestamp
        self.results['module_version'] = '1.0.0'
 
        # Score each module
        self.results['module_scores'] = self._score_all_modules()
 
        # Aggregate into overall score
        self.results['overall_score'] = self._calculate_overall_score()
        self.results['overall_risk']  = self._score_to_label(
            self.results['overall_score']
        )
 
        # Collect all findings and recommendations
        self.results['all_findings']        = self._aggregate_findings()
        self.results['all_recommendations'] = self._aggregate_recommendations()
 
        # Build executive summary
        self.results['summary'] = self._build_summary()
 
        logger.info(
            f"Risk calculation complete: "
            f"{self.results['overall_risk']} "
            f"(score: {self.results['overall_score']:.1f}/10)"
        )
        return self.results
 
    # -----------------------------------------------------------------------
    # Module scoring
    # -----------------------------------------------------------------------
 
    def _score_all_modules(self) -> Dict:
        """
        Scores each module individually and records findings.
 
        Returns:
            Dict: Per-module results, each containing:
                - raw_score:      score on 0-10 scale from the module
                - weight:         this module's weighting
                - weighted_score: raw_score * weight
                - findings:       list of findings from this module
                - recommendations:list of recommendations from this module
                - data_available: whether module data was provided
        """
        module_scores = {}
 
        scorers = {
            'firewall': self._score_firewall,
            'password': self._score_password,
            'port':     self._score_port,
            'system':   self._score_system,
        }
 
        for module_name, scorer in scorers.items():
            try:
                module_scores[module_name] = scorer()
            except Exception as e:
                logger.error(f"Failed to score {module_name} module: {e}")
                module_scores[module_name] = self._unavailable_score(module_name)
 
        return module_scores
 
    def _score_firewall(self) -> Dict:
        """
        Derives firewall risk score from FirewallChecker output.
 
        Reads the risk_assessment produced by the firewall module.
        Also applies additional context checks that the individual
        module cannot make (e.g. cross-module comparisons).
 
        Returns:
            Dict: Firewall module score entry.
        """
        data = self.module_data.get('firewall')
 
        if not data:
            return self._unavailable_score('firewall')
 
        risk_assessment = data.get('risk_assessment', {})
        raw_score = risk_assessment.get('risk_score', 0) or 0
        findings = risk_assessment.get('findings', [])
        recommendations = risk_assessment.get('recommendations', [])
 
        # Additional context: check if all profiles are confirmed enabled
        profiles = data.get('firewall_profiles', {})
        all_enabled = all(
            p.get('enabled') is True
            for p in profiles.values()
            if isinstance(p, dict)
        )
        if all_enabled and raw_score == 0:
            findings = findings or ["All firewall profiles are enabled"]
 
        return {
            'raw_score':       raw_score,
            'weight':          MODULE_WEIGHTS['firewall'],
            'weighted_score':  round(raw_score * MODULE_WEIGHTS['firewall'], 2),
            'findings':        findings,
            'recommendations': recommendations,
            'data_available':  True,
        }
 
    def _score_password(self) -> Dict:
        """
        Derives password policy risk score from PasswordPolicyChecker output.
 
        Reads risk_assessment and augments with compliance data where available.
 
        Returns:
            Dict: Password module score entry.
        """
        data = self.module_data.get('password')
 
        if not data:
            return self._unavailable_score('password')
 
        risk_assessment = data.get('risk_assessment', {})
        raw_score = risk_assessment.get('risk_score', 0) or 0
        findings = list(risk_assessment.get('findings', []))
        recommendations = list(risk_assessment.get('recommendations', []))
 
        # Augment with compliance info if available
        compliance = data.get('compliance', {})
        if isinstance(compliance, dict) and 'compliance_level' in compliance:
            level = compliance['compliance_level']
            pct   = compliance.get('compliance_percentage', 0)
            findings.append(
                f"INFO: Password policy compliance level is "
                f"{level} ({pct:.1f}%)"
            )
 
        return {
            'raw_score':       raw_score,
            'weight':          MODULE_WEIGHTS['password'],
            'weighted_score':  round(raw_score * MODULE_WEIGHTS['password'], 2),
            'findings':        findings,
            'recommendations': recommendations,
            'data_available':  True,
        }
 
    def _score_port(self) -> Dict:
        """
        Derives port exposure risk score from PortScanner output.
 
        Applies contextual adjustment: standard Windows services (135, 139, 445)
        on a machine with firewall enabled are scored less harshly than the
        same ports exposed with no perimeter protection.
 
        Returns:
            Dict: Port module score entry.
 
        Academic note:
            Contextual scoring reflects NIST SP 800-30 guidance that risk
            depends on both likelihood AND impact. A port behind an active
            firewall carries lower likelihood of exploitation.
        """
        data = self.module_data.get('port')
 
        if not data:
            return self._unavailable_score('port')
 
        risk_assessment = data.get('risk_assessment', {})
        raw_score  = risk_assessment.get('risk_score', 0) or 0
        findings   = list(risk_assessment.get('findings', []))
        recommendations = list(risk_assessment.get('recommendations', []))
 
        # Context: if firewall is active, reduce score for expected Windows ports
        firewall_data = self.module_data.get('firewall', {})
        firewall_profiles = firewall_data.get('firewall_profiles', {}) if firewall_data else {}
        firewall_active = any(
            p.get('enabled') is True
            for p in firewall_profiles.values()
            if isinstance(p, dict)
        )
 
        # Expected Windows services that should not max out the score
        expected_windows_ports = {135, 139, 445}
        dangerous = data.get('dangerous_ports_found', {})
        critical_ports = dangerous.get('critical_risk_ports', [])
 
        # Identify which critical ports are just standard Windows services
        unexpected_critical = [
            p for p in critical_ports
            if p.get('port') not in expected_windows_ports
        ]
        expected_critical = [
            p for p in critical_ports
            if p.get('port') in expected_windows_ports
        ]
 
        # If all critical ports are just expected Windows services and firewall
        # is active, apply a contextual reduction
        if firewall_active and expected_critical and not unexpected_critical:
            adjustment = len(expected_critical) * 2  # reduce 2pts per expected port
            raw_score = max(0, raw_score - adjustment)
            findings.append(
                f"INFO: {len(expected_critical)} standard Windows service port(s) "
                f"(135/139/445) score-adjusted because firewall is active"
            )
 
        return {
            'raw_score':       raw_score,
            'weight':          MODULE_WEIGHTS['port'],
            'weighted_score':  round(raw_score * MODULE_WEIGHTS['port'], 2),
            'findings':        findings,
            'recommendations': recommendations,
            'data_available':  True,
        }
 
    def _score_system(self) -> Dict:
        """
        Derives system risk score from SystemInfo output.
 
        Evaluates OS currency, patch status, and end-of-life exposure.
        Falls back gracefully if system info fields are missing,
        as the SystemInfo module may vary in what it collects.
 
        Returns:
            Dict: System module score entry.
        """
        data = self.module_data.get('system')
 
        if not data:
            return self._unavailable_score('system')
 
        raw_score = 0
        findings = []
        recommendations = []
 
        # Check if module has its own risk assessment first
        risk_assessment = data.get('risk_assessment', {})
        if isinstance(risk_assessment, dict) and risk_assessment.get('risk_score') is not None:
            raw_score      = risk_assessment.get('risk_score', 0) or 0
            findings       = list(risk_assessment.get('findings', []))
            recommendations = list(risk_assessment.get('recommendations', []))
        else:
            # Manually assess from raw system info fields
            os_info = data.get('os_info', {})
            patch_info = data.get('patch_info', {})
 
            # Check OS end-of-life status
            if isinstance(os_info, dict):
                eol = os_info.get('end_of_life', False)
                if eol:
                    raw_score += 4
                    findings.append("CRITICAL: Operating system is end-of-life (no security updates)")
                    recommendations.append("Upgrade to a supported operating system immediately")
 
                os_version = os_info.get('version', '')
                if os_version:
                    findings.append(f"INFO: Operating system: {os_version}")
 
            # Check patch status
            if isinstance(patch_info, dict):
                missing_patches = patch_info.get('missing_critical_patches', 0) or 0
                if missing_patches > 10:
                    raw_score += 4
                    findings.append(f"CRITICAL: {missing_patches} missing critical patches")
                    recommendations.append("Apply all critical security patches immediately")
                elif missing_patches > 0:
                    raw_score += 2
                    findings.append(f"HIGH: {missing_patches} missing critical patches")
                    recommendations.append("Apply outstanding critical security patches")
 
            if not findings:
                findings.append("System information collected - no critical issues identified")
 
        raw_score = min(raw_score, 10)
 
        return {
            'raw_score':       raw_score,
            'weight':          MODULE_WEIGHTS['system'],
            'weighted_score':  round(raw_score * MODULE_WEIGHTS['system'], 2),
            'findings':        findings,
            'recommendations': recommendations,
            'data_available':  True,
        }
 
    # -----------------------------------------------------------------------
    # Aggregation helpers
    # -----------------------------------------------------------------------
 
    def _calculate_overall_score(self) -> float:
        """
        Calculates the final weighted overall risk score.
 
        Uses proportional weighting: if a module is unavailable its weight
        is redistributed across available modules so the score remains
        meaningful on a 0-10 scale.
 
        Returns:
            float: Overall risk score, 0.0 to 10.0.
        """
        module_scores = self.results.get('module_scores', {})
 
        available = {
            name: entry
            for name, entry in module_scores.items()
            if entry.get('data_available')
        }
 
        if not available:
            logger.warning("No module data available for scoring")
            return 0.0
 
        # Sum weights of available modules for proportional redistribution
        total_weight = sum(MODULE_WEIGHTS[name] for name in available)
 
        weighted_sum = sum(
            entry['raw_score'] * (MODULE_WEIGHTS[name] / total_weight)
            for name, entry in available.items()
        )
 
        return round(min(weighted_sum, 10.0), 2)
 
    def _score_to_label(self, score: float) -> str:
        """
        Converts a numeric score to a risk label.
 
        Score ranges:
            0.0 - 2.9  : Low
            3.0 - 5.9  : Medium
            6.0 - 7.9  : High
            8.0 - 10.0 : Critical
 
        Args:
            score: Numeric risk score (0-10).
 
        Returns:
            str: Risk label.
        """
        if score >= 8.0:
            return "Critical"
        elif score >= 6.0:
            return "High"
        elif score >= 3.0:
            return "Medium"
        else:
            return "Low"
 
    def _aggregate_findings(self) -> List[Dict]:
        """
        Collects all findings from every module into a single prioritised list.
 
        Findings are sorted by severity so the report generator can present
        the most important issues first.
 
        Returns:
            List[Dict]: All findings, each tagged with source module and severity.
        """
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
 
        all_findings = []
        module_scores = self.results.get('module_scores', {})
 
        for module_name, entry in module_scores.items():
            for finding in entry.get('findings', []):
                # Determine severity from finding prefix
                severity = 'INFO'
                upper = finding.upper()
                for sev in severity_order:
                    if upper.startswith(sev):
                        severity = sev
                        break
 
                all_findings.append({
                    'module':   module_name.capitalize(),
                    'severity': severity,
                    'finding':  finding,
                    'sort_key': severity_order.get(severity, 99),
                })
 
        # Sort: severity first, then module name alphabetically
        all_findings.sort(key=lambda x: (x['sort_key'], x['module']))
 
        return all_findings
 
    def _aggregate_recommendations(self) -> List[Dict]:
        """
        Collects all recommendations from every module, deduplicated and
        ordered by the risk score of their source module (highest first).
 
        Returns:
            List[Dict]: All recommendations tagged with source module.
        """
        module_scores = self.results.get('module_scores', {})
 
        all_recommendations = []
        seen = set()
 
        # Process modules in descending raw score order (worst first)
        sorted_modules = sorted(
            module_scores.items(),
            key=lambda x: x[1].get('raw_score', 0),
            reverse=True
        )
 
        for module_name, entry in sorted_modules:
            for rec in entry.get('recommendations', []):
                # Deduplicate by normalised text
                normalised = rec.strip().lower()
                if normalised not in seen:
                    seen.add(normalised)
                    all_recommendations.append({
                        'module':         module_name.capitalize(),
                        'recommendation': rec,
                    })
 
        return all_recommendations
 
    def _build_summary(self) -> Dict:
        """
        Builds a human-readable executive summary of the risk assessment.
 
        Returns:
            Dict: Summary containing:
                - overall_risk:    risk label
                - overall_score:   numeric score
                - modules_assessed: count
                - critical_count:  number of critical findings
                - high_count:      number of high findings
                - headline:        one-sentence summary string
                - module_breakdown: per-module score overview
        """
        overall_risk  = self.results.get('overall_risk', 'Unknown')
        overall_score = self.results.get('overall_score', 0)
        all_findings  = self.results.get('all_findings', [])
        module_scores = self.results.get('module_scores', {})
 
        critical_count = sum(1 for f in all_findings if f['severity'] == 'CRITICAL')
        high_count     = sum(1 for f in all_findings if f['severity'] == 'HIGH')
        medium_count   = sum(1 for f in all_findings if f['severity'] == 'MEDIUM')
        modules_assessed = sum(
            1 for e in module_scores.values() if e.get('data_available')
        )
 
        # Build headline sentence
        if overall_risk == 'Critical':
            headline = (
                f"The system presents a CRITICAL security risk (score {overall_score}/10) "
                f"with {critical_count} critical and {high_count} high severity findings "
                f"requiring immediate attention."
            )
        elif overall_risk == 'High':
            headline = (
                f"The system presents a HIGH security risk (score {overall_score}/10) "
                f"with {high_count} high severity findings that should be addressed promptly."
            )
        elif overall_risk == 'Medium':
            headline = (
                f"The system presents a MEDIUM security risk (score {overall_score}/10). "
                f"Several security improvements are recommended."
            )
        else:
            headline = (
                f"The system presents a LOW security risk (score {overall_score}/10). "
                f"The security posture is acceptable but regular reviews are recommended."
            )
 
        # Per-module breakdown for the report
        module_breakdown = {}
        label_map = {
            'firewall': 'Firewall Configuration',
            'password': 'Password Policy',
            'port':     'Port Exposure',
            'system':   'System Information',
        }
 
        for module_name, entry in module_scores.items():
            module_breakdown[module_name] = {
                'label':          label_map.get(module_name, module_name.capitalize()),
                'raw_score':      entry.get('raw_score', 0),
                'weighted_score': entry.get('weighted_score', 0),
                'weight_pct':     f"{MODULE_WEIGHTS.get(module_name, 0) * 100:.0f}%",
                'risk_label':     self._score_to_label(entry.get('raw_score', 0)),
                'data_available': entry.get('data_available', False),
            }
 
        return {
            'overall_risk':      overall_risk,
            'overall_score':     overall_score,
            'max_score':         10,
            'modules_assessed':  modules_assessed,
            'critical_findings': critical_count,
            'high_findings':     high_count,
            'medium_findings':   medium_count,
            'headline':          headline,
            'module_breakdown':  module_breakdown,
            'assessment_timestamp': self.collection_timestamp,
        }
 
    # -----------------------------------------------------------------------
    # Fallback helper
    # -----------------------------------------------------------------------
 
    def _unavailable_score(self, module_name: str) -> Dict:
        """
        Returns a placeholder score entry for modules with no data.
 
        Args:
            module_name: Name of the unavailable module.
 
        Returns:
            Dict: Score entry indicating data was unavailable.
        """
        return {
            'raw_score':       0,
            'weight':          MODULE_WEIGHTS.get(module_name, 0),
            'weighted_score':  0,
            'findings':        [f"INFO: {module_name.capitalize()} module data unavailable"],
            'recommendations': [f"Ensure {module_name} module runs successfully"],
            'data_available':  False,
        }
 
    # -----------------------------------------------------------------------
    # Export
    # -----------------------------------------------------------------------
 
    def export_to_json(self, filepath: str) -> bool:
        """
        Exports the complete risk report to a JSON file.
 
        Args:
            filepath: Destination path for JSON export.
 
        Returns:
            bool: True if export successful, False otherwise.
        """
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
            logger.info(f"Risk report exported to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to export risk report: {e}")
            return False
 
 
# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------
 
def calculate_risk(
    firewall_data: Optional[Dict] = None,
    password_data: Optional[Dict] = None,
    port_data:     Optional[Dict] = None,
    system_data:   Optional[Dict] = None,
) -> Dict:
    """
    Convenience function for use by audit.py.
 
    Args:
        firewall_data: Output of FirewallChecker.check_all()
        password_data: Output of PasswordPolicyChecker.check_all()
        port_data:     Output of PortScanner.check_all()
        system_data:   Output of SystemInfo.check_all()
 
    Returns:
        Dict: Complete risk report.
 
    Example:
        >>> from modules.risk_calculator import calculate_risk
        >>> report = calculate_risk(firewall_data=fw, password_data=pw)
        >>> print(report['overall_risk'])
    """
    calculator = RiskCalculator()
    return calculator.calculate(
        firewall_data=firewall_data,
        password_data=password_data,
        port_data=port_data,
        system_data=system_data,
    )
 
 
# ---------------------------------------------------------------------------
# Testing block
# ---------------------------------------------------------------------------
 
if __name__ == "__main__":
    """
    Test harness using realistic mock data.
    Simulates output from each module so the calculator can be tested
    independently without running the full audit suite.
    """
 
    print("=" * 60)
    print("Risk Calculator - Test Run (using mock module data)")
    print("=" * 60)
 
    # --- Mock data simulating a typical Windows workstation ---
 
    mock_firewall = {
        'firewall_profiles': {
            'domain':  {'enabled': True,  'risk_level': 'Low'},
            'private': {'enabled': True,  'risk_level': 'Low'},
            'public':  {'enabled': True,  'risk_level': 'Low'},
        },
        'defender_status': {
            'realtime_protection_enabled': True,
            'antivirus_enabled': True,
            'signatures_outdated': False,
            'status_available': True,
        },
        'risk_assessment': {
            'risk_score': 0,
            'findings': ['No significant firewall security issues detected'],
            'recommendations': ['Maintain current firewall configuration'],
        }
    }
 
    mock_password = {
        'password_policy': {
            'min_password_length': 0,
            'max_password_age_days': 42,
            'min_password_age_days': 0,
            'password_history_count': 0,
            'lockout_threshold': 0,
            'complexity_enabled': None,
            'retrieval_successful': True,
        },
        'compliance': {
            'compliance_level': 'Poor',
            'compliance_percentage': 25.0,
        },
        'risk_assessment': {
            'risk_score': 8,
            'findings': [
                'CRITICAL: Minimum password length is only 0 characters',
                'HIGH: Account lockout is disabled (unlimited brute force attempts)',
                'MEDIUM: Password history only remembers 0 passwords',
                'LOW: No minimum password age (allows password cycling)',
            ],
            'recommendations': [
                'Immediately increase minimum password length to at least 8 characters',
                'Enable account lockout with 5-10 attempt threshold',
                'Increase password history to at least 24 passwords',
            ]
        }
    }
 
    mock_port = {
        'listening_ports': {
            'enumeration_successful': True,
            'tcp_ports': [135, 139, 445, 80, 443],
            'udp_ports': [],
            'total_listening': 63,
            'port_details': [
                {'port': 135, 'protocol': 'TCP', 'address': '0.0.0.0', 'status': 'LISTENING', 'pid': 1234},
                {'port': 139, 'protocol': 'TCP', 'address': '0.0.0.0', 'status': 'LISTENING', 'pid': 1234},
                {'port': 445, 'protocol': 'TCP', 'address': '0.0.0.0', 'status': 'LISTENING', 'pid': 1234},
            ]
        },
        'dangerous_ports_found': {
            'critical_risk_ports': [
                {'port': 135, 'service': 'MS-RPC',   'risk': 'Critical', 'reason': 'Windows RPC, frequently exploited'},
                {'port': 139, 'service': 'NetBIOS',  'risk': 'Critical', 'reason': 'Legacy file sharing'},
                {'port': 445, 'service': 'SMB',      'risk': 'Critical', 'reason': 'Ransomware vector'},
            ],
            'high_risk_ports': [],
            'medium_risk_ports': [],
            'analysis_available': True,
        },
        'risk_assessment': {
            'risk_score': 10,
            'findings': [
                'CRITICAL: MS-RPC (port 135) is listening',
                'CRITICAL: NetBIOS (port 139) is listening',
                'CRITICAL: SMB (port 445) is listening',
                'MEDIUM: Large number of open ports (63 listening)',
            ],
            'recommendations': [
                'Verify Windows Firewall is blocking ports from external access',
            ]
        }
    }
 
    mock_system = {
        'os_info': {
            'version': 'Windows 11 Pro 23H2',
            'end_of_life': False,
        },
        'patch_info': {
            'missing_critical_patches': 0,
        },
        'risk_assessment': {
            'risk_score': 1,
            'findings': ['INFO: Operating system is current and supported'],
            'recommendations': ['Keep system updated with latest patches'],
        }
    }
 
    # Run calculator
    calculator = RiskCalculator()
    report = calculator.calculate(
        firewall_data=mock_firewall,
        password_data=mock_password,
        port_data=mock_port,
        system_data=mock_system,
    )
 
    # Display results
    summary = report.get('summary', {})
    print(f"\n{'=' * 60}")
    print("EXECUTIVE SUMMARY")
    print('=' * 60)
    print(f"\n{summary.get('headline', '')}\n")
 
    print("--- Module Breakdown ---")
    for module_name, breakdown in summary.get('module_breakdown', {}).items():
        available = "✓" if breakdown['data_available'] else "✗"
        print(
            f"  {available} {breakdown['label']:30} "
            f"Score: {breakdown['raw_score']:4}/10  "
            f"Weight: {breakdown['weight_pct']}  "
            f"Risk: {breakdown['risk_label']}"
        )
 
    print(f"\n  Overall Score : {summary.get('overall_score')}/10")
    print(f"  Overall Risk  : {summary.get('overall_risk')}")
    print(f"  Modules Run   : {summary.get('modules_assessed')}")
 
    print("\n--- All Findings (by severity) ---")
    for item in report.get('all_findings', []):
        print(f"  [{item['severity']:8}] [{item['module']:10}] {item['finding']}")
 
    print("\n--- Prioritised Recommendations ---")
    for i, item in enumerate(report.get('all_recommendations', [])[:10], 1):
        print(f"  {i:2}. [{item['module']}] {item['recommendation']}")
 
    # Export
    export_path = "test_risk_report.json"
    if calculator.export_to_json(export_path):
        print(f"\n✓ Full report exported to: {export_path}")
 
    print("\n" + "=" * 60)
    print("Test completed!")
    print("=" * 60)
