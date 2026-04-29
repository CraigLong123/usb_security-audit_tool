"""
Windows Security Audit Tool - Package Initialisation
 
This file makes the modules directory a proper Python package and provides
centralised dependency checking and version information.
 
When packaged as a standalone executable via PyInstaller, all dependencies
are bundled inside the .exe. This __init__.py still runs on first import
to verify the internal environment is healthy.
 
Academic context:
    Packaging as a standalone executable directly addresses the accessibility
    barrier identified in the research introduction — removing the requirement
    for Python installation or technical setup on the target machine.
"""
 
__version__     = '1.0.0'
__author__      = 'Windows Security Audit Tool'
__description__ = 'Automated Windows security configuration assessment tool'
 
# ---------------------------------------------------------------------------
# Required third-party packages
# Each entry: (import_name, pip_name, minimum_version)
# ---------------------------------------------------------------------------
REQUIRED_PACKAGES = [
    ('psutil',     'psutil',     '5.9.0'),
    ('reportlab',  'reportlab',  '3.6.0'),
]
 
 
def check_dependencies() -> dict:
    """
    Verifies all required packages are available.
 
    When running as a compiled .exe, all packages are bundled by PyInstaller
    and this check should always pass. When running from source, this check
    identifies any missing packages before the audit begins.
 
    Returns:
        dict: {
            'all_available': bool,
            'packages': [
                {'name': str, 'available': bool, 'version': str or None}
            ]
        }
    """
    import importlib
    results = []
 
    for import_name, pip_name, min_version in REQUIRED_PACKAGES:
        entry = {
            'name':      pip_name,
            'available': False,
            'version':   None,
        }
        try:
            mod = importlib.import_module(import_name)
            entry['available'] = True
            entry['version']   = getattr(mod, '__version__', 'unknown')
        except ImportError:
            entry['available'] = False
        results.append(entry)
 
    return {
        'all_available': all(r['available'] for r in results),
        'packages':      results,
    }
 
 
def install_dependencies() -> bool:
    """
    Attempts to install any missing dependencies via pip.
 
    This is used when running from source — the compiled .exe bundles
    everything and never needs to call this.
 
    Returns:
        bool: True if all dependencies installed successfully.
    """
    import subprocess
    import sys
 
    status = check_dependencies()
    if status['all_available']:
        return True
 
    missing = [
        pkg['name']
        for pkg in status['packages']
        if not pkg['available']
    ]
 
    print(f"  Installing missing packages: {', '.join(missing)}")
 
    for package in missing:
        try:
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', package, '--quiet'],
                timeout=120
            )
            print(f"  ✓ Installed: {package}")
        except subprocess.CalledProcessError as e:
            print(f"  ✗ Failed to install {package}: {e}")
            return False
        except subprocess.TimeoutExpired:
            print(f"  ✗ Timed out installing {package}")
            return False
 
    return True
 
 
# ---------------------------------------------------------------------------
# Expose module convenience functions at package level
# This allows:  from modules import scan_ports
# instead of:  from modules.port_scanner import scan_ports
# ---------------------------------------------------------------------------
 
try:
    from modules.firewall_check   import check_firewall
    from modules.password_policy  import check_password_policy
    from modules.port_scanner     import scan_ports
    from modules.system_info      import collect_system_info
    from modules.risk_calculator  import calculate_risk
    from modules.report_generator import generate_report
except ImportError:
    # Gracefully handle partial installs during build process
    pass