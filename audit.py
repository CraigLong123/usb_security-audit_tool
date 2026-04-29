"""
Windows Security Audit Tool - Main Entry Point
 
This module orchestrates the complete security assessment by coordinating
all individual assessment modules and producing a consolidated risk report.
 
Usage:
    Run as Administrator:
        python audit.py
 
    Optional arguments:
        --output <path>   Custom output directory for reports (default: ./reports)
        --json            Also export raw JSON data alongside the report
        --quiet           Suppress progress output (report still generated)
 
Academic context:
    This tool addresses the accessibility gap in security assessment tooling
    identified in the research introduction. By automating multi-module
    assessment and report generation, it enables organisations without
    dedicated security teams to conduct rigorous configuration audits.
 
    Assessment frameworks applied:
        NIST SP 800-63B  - Password and authentication guidelines
        NIST SP 800-115  - Technical guide to security testing
        CIS Controls v8  - Prioritised security controls
        Microsoft Security Baseline - Windows configuration standards
 
References:
    Verizon (2023) Data Breach Investigations Report.
    NIST SP 800-30 Rev 1 - Guide for Conducting Risk Assessments.
"""
 
import sys
import os
import ctypes
import argparse
import logging
import json
from datetime import datetime
from typing import Dict, Optional
 
# ---------------------------------------------------------------------------
# Configure logging before any imports that might trigger logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
 
# ---------------------------------------------------------------------------
# Module imports
# ---------------------------------------------------------------------------
# Each module is imported inside a try/except so a missing or broken module
# does not prevent the rest of the audit from running.
 
try:
    from modules.firewall_check import check_firewall
    FIREWALL_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Firewall module unavailable: {e}")
    FIREWALL_AVAILABLE = False
 
try:
    from modules.password_policy import check_password_policy
    PASSWORD_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Password policy module unavailable: {e}")
    PASSWORD_AVAILABLE = False
 
try:
    from modules.port_scanner import scan_ports
    PORT_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Port scanner module unavailable: {e}")
    PORT_AVAILABLE = False
 
try:
    from modules.system_info import collect_system_info
    SYSTEM_AVAILABLE = True
except ImportError as e:
    logger.warning(f"System info module unavailable: {e}")
    SYSTEM_AVAILABLE = False
 
try:
    from modules.risk_calculator import calculate_risk
    CALCULATOR_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Risk calculator unavailable: {e}")
    CALCULATOR_AVAILABLE = False
 
try:
    from modules.report_generator import generate_report
    REPORT_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Report generator unavailable: {e}")
    REPORT_AVAILABLE = False
 
 
# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
 
TOOL_NAME    = "Windows Security Audit Tool"
TOOL_VERSION = "1.0.0"
DEFAULT_OUTPUT_DIR = "reports"
 
 
# ---------------------------------------------------------------------------
# Admin rights check
# ---------------------------------------------------------------------------
 
def is_admin() -> bool:
    """
    Checks whether the current process has administrator privileges.
 
    Several assessment modules (port scanning, password complexity via secedit)
    require elevated privileges to access system APIs and security policy data.
    Without admin rights, results will be incomplete.
 
    Returns:
        bool: True if running as administrator, False otherwise.
 
    Technical note:
        Uses ctypes.windll.shell32.IsUserAnAdmin() which calls the Windows
        Shell API. Returns False on non-Windows platforms.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # Not on Windows
        return False
    except Exception:
        return False
 
 
def check_admin_rights() -> bool:
    """
    Verifies admin rights and prints a clear warning if they are missing.
 
    Returns:
        bool: True if admin, False if not (audit can still proceed with warning).
    """
    if is_admin():
        print("  ✓ Running as Administrator")
        return True
    else:
        print("  ⚠️  WARNING: Not running as Administrator")
        print("     Some checks will be incomplete:")
        print("     - Port scanner cannot retrieve process names (PIDs)")
        print("     - Password complexity check (secedit) may fail")
        print("     - Some firewall data may be unavailable")
        print()
        print("     To run as admin: right-click your terminal → Run as Administrator")
        print()
 
        # Give user chance to abort
        try:
            response = input("  Continue without admin rights? (y/n): ").strip().lower()
            if response != 'y':
                print("\n  Audit cancelled. Please re-run as Administrator.")
                return False
        except KeyboardInterrupt:
            print("\n  Audit cancelled.")
            return False
 
        return True
 
 
# ---------------------------------------------------------------------------
# Progress display helpers
# ---------------------------------------------------------------------------
 
def print_banner():
    """Prints the tool header banner."""
    print()
    print("=" * 65)
    print(f"  {TOOL_NAME}")
    print(f"  Version {TOOL_VERSION}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)
    print()
 
 
def print_section(title: str):
    """Prints a section header."""
    print(f"\n  [{title}]")
    print("  " + "-" * 50)
 
 
def print_step(message: str, status: str = ""):
    """Prints a progress step."""
    if status:
        print(f"  {status} {message}")
    else:
        print(f"    → {message}")
 
 
def print_module_result(module_name: str, success: bool, detail: str = ""):
    """Prints the result of a module run."""
    icon = "✓" if success else "✗"
    line = f"  {icon} {module_name}"
    if detail:
        line += f" — {detail}"
    print(line)
 
 
# ---------------------------------------------------------------------------
# Module runners
# ---------------------------------------------------------------------------
 
def run_firewall_check() -> Optional[Dict]:
    """
    Runs the firewall configuration assessment module.
 
    Returns:
        Dict: Firewall assessment results, or None if module failed.
    """
    if not FIREWALL_AVAILABLE:
        print_module_result("Firewall Check", False, "module not available")
        return None
    try:
        print_step("Checking firewall configuration...")
        data = check_firewall()
        risk = data.get('risk_assessment', {}).get('overall_risk', 'Unknown')
        print_module_result("Firewall Check", True, f"Risk: {risk}")
        return data
    except Exception as e:
        logger.error(f"Firewall check failed: {e}")
        print_module_result("Firewall Check", False, str(e))
        return None
 
 
def run_password_check() -> Optional[Dict]:
    """
    Runs the password policy assessment module.
 
    Returns:
        Dict: Password policy results, or None if module failed.
    """
    if not PASSWORD_AVAILABLE:
        print_module_result("Password Policy", False, "module not available")
        return None
    try:
        print_step("Checking password policy...")
        data = check_password_policy()
        risk = data.get('risk_assessment', {}).get('overall_risk', 'Unknown')
        print_module_result("Password Policy", True, f"Risk: {risk}")
        return data
    except Exception as e:
        logger.error(f"Password policy check failed: {e}")
        print_module_result("Password Policy", False, str(e))
        return None
 
 
def run_port_scan() -> Optional[Dict]:
    """
    Runs the network port exposure assessment module.
 
    Returns:
        Dict: Port scan results, or None if module failed.
    """
    if not PORT_AVAILABLE:
        print_module_result("Port Scanner", False, "module not available")
        return None
    try:
        print_step("Scanning listening ports (this may take a moment)...")
        data = scan_ports()
        total = data.get('listening_ports', {}).get('total_listening', 0)
        risk  = data.get('risk_assessment', {}).get('overall_risk', 'Unknown')
        print_module_result("Port Scanner", True, f"{total} ports found — Risk: {risk}")
        return data
    except Exception as e:
        logger.error(f"Port scan failed: {e}")
        print_module_result("Port Scanner", False, str(e))
        return None
 
 
def run_system_info() -> Optional[Dict]:
    """
    Runs the system information collection module.
 
    Returns:
        Dict: System information results, or None if module failed.
    """
    if not SYSTEM_AVAILABLE:
        print_module_result("System Info", False, "module not available")
        return None
    try:
        print_step("Collecting system information...")
        data = collect_system_info()
        print_module_result("System Info", True, "collected")
        return data
    except Exception as e:
        logger.error(f"System info collection failed: {e}")
        print_module_result("System Info", False, str(e))
        return None
 
 
# ---------------------------------------------------------------------------
# Risk calculation
# ---------------------------------------------------------------------------
 
def run_risk_calculation(
    firewall_data: Optional[Dict],
    password_data: Optional[Dict],
    port_data:     Optional[Dict],
    system_data:   Optional[Dict],
) -> Optional[Dict]:
    """
    Passes all module results to the risk calculator.
 
    Args:
        firewall_data: Output from firewall module (or None).
        password_data: Output from password module (or None).
        port_data:     Output from port scanner module (or None).
        system_data:   Output from system info module (or None).
 
    Returns:
        Dict: Aggregated risk report, or None if calculation failed.
    """
    if not CALCULATOR_AVAILABLE:
        print_module_result("Risk Calculator", False, "module not available")
        return None
    try:
        print_step("Calculating overall risk score...")
        report = calculate_risk(
            firewall_data=firewall_data,
            password_data=password_data,
            port_data=port_data,
            system_data=system_data,
        )
        overall = report.get('overall_risk', 'Unknown')
        score   = report.get('overall_score', 0)
        print_module_result(
            "Risk Calculator", True,
            f"Overall Risk: {overall} ({score}/10)"
        )
        return report
    except Exception as e:
        logger.error(f"Risk calculation failed: {e}")
        print_module_result("Risk Calculator", False, str(e))
        return None
 
 
# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
 
def run_report_generation(
    risk_report:   Optional[Dict],
    output_dir:    str,
    export_json:   bool,
    firewall_data: Optional[Dict],
    password_data: Optional[Dict],
    port_data:     Optional[Dict],
    system_data:   Optional[Dict],
) -> Optional[str]:
    """
    Generates the final assessment report.
 
    Args:
        risk_report:   Output from risk calculator.
        output_dir:    Directory to write the report to.
        export_json:   Whether to also export raw JSON data.
        firewall_data: Raw firewall module data (for JSON export).
        password_data: Raw password module data (for JSON export).
        port_data:     Raw port module data (for JSON export).
        system_data:   Raw system info data (for JSON export).
 
    Returns:
        str: Path to the generated report, or None if generation failed.
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
 
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
 
    # Export raw JSON data if requested
    if export_json and risk_report:
        json_path = os.path.join(output_dir, f"audit_raw_{timestamp}.json")
        raw_data = {
            'risk_report':   risk_report,
            'firewall_data': firewall_data,
            'password_data': password_data,
            'port_data':     port_data,
            'system_data':   system_data,
        }
        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(raw_data, f, indent=4, ensure_ascii=False)
            print_step(f"Raw JSON exported to: {json_path}")
        except Exception as e:
            logger.error(f"JSON export failed: {e}")
 
    # Generate the main report
    if not REPORT_AVAILABLE:
        print_module_result("Report Generator", False, "module not available")
        # Fall back to a basic terminal summary if report generator is missing
        _print_terminal_summary(risk_report)
        return None
 
    try:
        report_path = os.path.join(output_dir, f"audit_report_{timestamp}")
        path = generate_report(risk_report, report_path)
        print_module_result("Report Generator", True, f"Report saved to: {path}")
        return path
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        print_module_result("Report Generator", False, str(e))
        _print_terminal_summary(risk_report)
        return None
 
 
def _print_terminal_summary(risk_report: Optional[Dict]):
    """
    Fallback terminal summary if the report generator is unavailable.
 
    Args:
        risk_report: Output from risk calculator.
    """
    if not risk_report:
        print("\n  No risk report data available.")
        return
 
    summary = risk_report.get('summary', {})
 
    print("\n" + "=" * 65)
    print("  AUDIT SUMMARY")
    print("=" * 65)
    print(f"\n  {summary.get('headline', 'Assessment complete.')}\n")
 
    print("  Module Breakdown:")
    for module_name, breakdown in summary.get('module_breakdown', {}).items():
        available = "✓" if breakdown['data_available'] else "✗"
        print(
            f"    {available} {breakdown['label']:30} "
            f"Score: {breakdown['raw_score']:2}/10  "
            f"Risk: {breakdown['risk_label']}"
        )
 
    print(f"\n  Overall Score : {summary.get('overall_score')}/10")
    print(f"  Overall Risk  : {summary.get('overall_risk')}")
 
    findings = risk_report.get('all_findings', [])
    critical = [f for f in findings if f['severity'] == 'CRITICAL']
    high     = [f for f in findings if f['severity'] == 'HIGH']
 
    if critical or high:
        print("\n  Priority Findings:")
        for item in (critical + high)[:5]:
            print(f"    • [{item['module']}] {item['finding']}")
 
    recs = risk_report.get('all_recommendations', [])
    if recs:
        print("\n  Top Recommendations:")
        for i, item in enumerate(recs[:5], 1):
            print(f"    {i}. {item['recommendation']}")
 
    print()
 
 
# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
 
def parse_arguments():
    """
    Parses command-line arguments.
 
    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{TOOL_VERSION}",
        epilog="Must be run as Administrator for complete results."
    )
    parser.add_argument(
        '--output',
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for reports (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help="Also export raw JSON data alongside the report"
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help="Suppress progress output (report still generated)"
    )
    return parser.parse_args()
 
 
# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
 
def main():
    """
    Main orchestration function.
 
    Runs all assessment modules in sequence, passes results to the risk
    calculator, and generates the final report. Each stage is independently
    error-handled so a failure in one module does not halt the audit.
 
    Exit codes:
        0 - Audit completed successfully
        1 - Audit completed with errors
        2 - Audit aborted (e.g. user cancelled admin prompt)
    """
    args = parse_arguments()
 
    # Suppress progress output if --quiet
    if args.quiet:
        logging.disable(logging.CRITICAL)
 
    print_banner()
 
    # --- Step 1: Check admin rights ---
    print_section("Pre-flight Checks")
    if not check_admin_rights():
        sys.exit(2)
 
    # Check available modules
    available = sum([
        FIREWALL_AVAILABLE, PASSWORD_AVAILABLE,
        PORT_AVAILABLE, SYSTEM_AVAILABLE
    ])
    print_step(f"{available}/4 assessment modules available")
 
    if available == 0:
        print("\n  ✗ No assessment modules found. Check your modules/ directory.")
        sys.exit(1)
 
    # --- Step 2: Run all modules ---
    print_section("Running Assessment Modules")
 
    firewall_data = run_firewall_check()
    password_data = run_password_check()
    port_data     = run_port_scan()
    system_data   = run_system_info()
 
    # --- Step 3: Calculate risk ---
    print_section("Calculating Risk")
 
    risk_report = run_risk_calculation(
        firewall_data=firewall_data,
        password_data=password_data,
        port_data=port_data,
        system_data=system_data,
    )
 
    # --- Step 4: Generate report ---
    print_section("Generating Report")
 
    report_path = run_report_generation(
        risk_report=risk_report,
        output_dir=args.output,
        export_json=args.json,
        firewall_data=firewall_data,
        password_data=password_data,
        port_data=port_data,
        system_data=system_data,
    )
 
    # --- Step 5: Final summary ---
    print()
    print("=" * 65)
    if risk_report:
        overall = risk_report.get('overall_risk', 'Unknown')
        score   = risk_report.get('overall_score', 0)
        print(f"  Audit complete — Overall Risk: {overall} ({score}/10)")
    else:
        print("  Audit complete — Risk calculation unavailable")
 
    if report_path:
        print(f"  Report saved to: {report_path}")
 
    print("=" * 65)
    print()
 
    # Exit with code 1 if any module failed to indicate partial results
    modules_failed = sum([
        firewall_data is None,
        password_data is None,
        port_data     is None,
        system_data   is None,
    ])
 
    sys.exit(1 if modules_failed > 0 else 0)
 
 
# ---------------------------------------------------------------------------
# Entry point guard
# ---------------------------------------------------------------------------
 
if __name__ == "__main__":
    main()