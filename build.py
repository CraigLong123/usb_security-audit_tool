"""
Build Script — Windows Security Audit Tool
 
Compiles the audit tool into a single standalone Windows executable (.exe)
using PyInstaller. The resulting .exe:
 
    - Requires no Python installation on the target machine
    - Bundles all dependencies (psutil, reportlab, etc.)
    - Automatically requests administrator privileges on launch
    - Can be run directly from a USB drive
    - Saves reports alongside the executable
 
Usage:
    python build.py              # Standard build
    python build.py --clean      # Remove previous build artifacts first
    python build.py --debug      # Build with console window (for debugging)
 
Output:
    dist/SecurityAudit.exe       # The standalone executable
 
Academic context:
    Distributing as a single executable addresses the accessibility
    barrier identified in the research introduction. Target users
    (small organisations, educational institutions) require no technical
    setup — they simply run the .exe as administrator.
"""
 
import os
import sys
import shutil
import argparse
import subprocess
 
 
# ---------------------------------------------------------------------------
# Build configuration
# ---------------------------------------------------------------------------
 
EXE_NAME      = "SecurityAudit"
ENTRY_SCRIPT  = "audit.py"
ICON_FILE     = "tools/icon.ico"       # Optional — remove if you don't have one
BUILD_DIR     = "build"
DIST_DIR      = "dist"
SPEC_FILE     = f"{EXE_NAME}.spec"
 
 
# Python packages to explicitly include
# PyInstaller sometimes misses packages used via importlib or subprocess
HIDDEN_IMPORTS = [
    "psutil",
    "reportlab",
    "reportlab.lib",
    "reportlab.lib.pagesizes",
    "reportlab.lib.styles",
    "reportlab.lib.units",
    "reportlab.lib.colors",
    "reportlab.lib.enums",
    "reportlab.platypus",
    "reportlab.platypus.tables",
    "reportlab.platypus.flowables",
    "reportlab.pdfgen",
    "reportlab.pdfbase",
    "reportlab.pdfbase.ttfonts",
    "reportlab.pdfbase.pdfmetrics",
    "json",
    "subprocess",
    "socket",
    "ctypes",
    "tempfile",
    "logging",
]
 
# Data files to bundle alongside the executable
# Format: ('source_path', 'destination_folder_inside_exe')
DATA_FILES = [
    # Add any config files, templates, or assets here
    # Example: ('config/settings.json', 'config'),
]
 
 
# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
 
def check_pyinstaller() -> bool:
    """
    Checks PyInstaller is installed and installs it if not.
 
    Returns:
        bool: True if PyInstaller is available after this call.
    """
    try:
        import PyInstaller
        print(f"  ✓ PyInstaller {PyInstaller.__version__} found")
        return True
    except ImportError:
        print("  PyInstaller not found — installing...")
        try:
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', 'pyinstaller', '--quiet'],
                timeout=120
            )
            print("  ✓ PyInstaller installed")
            return True
        except Exception as e:
            print(f"  ✗ Failed to install PyInstaller: {e}")
            return False
 
 
def clean_build_artifacts():
    """Removes previous build and dist directories."""
    for directory in [BUILD_DIR, DIST_DIR]:
        if os.path.exists(directory):
            shutil.rmtree(directory)
            print(f"  ✓ Removed: {directory}/")
 
    if os.path.exists(SPEC_FILE):
        os.remove(SPEC_FILE)
        print(f"  ✓ Removed: {SPEC_FILE}")
 
 
def write_manifest() -> str:
    """
    Writes a Windows manifest file that requests administrator privileges.
 
    The manifest is embedded into the .exe by PyInstaller. When a user
    runs the .exe, Windows automatically shows the UAC elevation prompt
    requesting admin rights — no manual 'Run as Administrator' needed.
 
    Returns:
        str: Path to the generated manifest file.
    """
    manifest_content = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
      version="1.0.0.0"
      processorArchitecture="amd64"
      name="SecurityAuditTool"
      type="win32"
  />
  <description>Windows Security Audit Tool</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel
            level="requireAdministrator"
            uiAccess="false"
        />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10 and 11 -->
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
"""
    manifest_path = "SecurityAudit.manifest"
    with open(manifest_path, 'w', encoding='utf-8') as f:
        f.write(manifest_content)
    print(f"  ✓ Manifest written: {manifest_path}")
    return manifest_path
 
 
def build_exe(debug: bool = False) -> bool:
    """
    Runs PyInstaller to compile the executable.
 
    Args:
        debug: If True, builds with a visible console window for debugging.
               If False, builds as a windowless background process.
 
    Returns:
        bool: True if build succeeded.
    """
    manifest_path = write_manifest()
 
    # Build the PyInstaller command
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--name', EXE_NAME,
        '--onefile',                          # Single .exe file
        '--noconfirm',                        # Overwrite without asking
        '--clean',                            # Clean cache before build
    ]
 
    # Console window — keep open for debugging, hide for production
    if debug:
        cmd.append('--console')
    else:
        cmd.append('--console')  # Keep console so user can see progress
                                 # Change to '--windowed' if you want no terminal
 
    # Embed the admin manifest
    cmd += ['--manifest', manifest_path]
 
    # Add icon if it exists
    if os.path.exists(ICON_FILE):
        cmd += ['--icon', ICON_FILE]
        print(f"  ✓ Using icon: {ICON_FILE}")
    else:
        print(f"  ℹ No icon found at {ICON_FILE} — building without icon")
 
    # Hidden imports
    for imp in HIDDEN_IMPORTS:
        cmd += ['--hidden-import', imp]
 
    # Data files
    for src, dst in DATA_FILES:
        if os.path.exists(src):
            cmd += ['--add-data', f'{src};{dst}']
 
    # Add the modules folder explicitly
    cmd += ['--add-data', 'modules;modules']
 
    # Entry point
    cmd.append(ENTRY_SCRIPT)
 
    print(f"\n  Running PyInstaller...")
    print(f"  Command: {' '.join(cmd[:6])} ... (truncated)\n")
 
    try:
        result = subprocess.run(cmd, timeout=300)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("  ✗ Build timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"  ✗ Build failed: {e}")
        return False
 
 
def verify_output() -> bool:
    """
    Checks the output .exe exists and reports its size.
 
    Returns:
        bool: True if the exe was found.
    """
    exe_path = os.path.join(DIST_DIR, f"{EXE_NAME}.exe")
    if os.path.exists(exe_path):
        size_mb = os.path.getsize(exe_path) / (1024 * 1024)
        print(f"\n  ✓ Executable created: {exe_path}")
        print(f"  ✓ File size: {size_mb:.1f} MB")
        return True
    else:
        print(f"  ✗ Expected output not found: {exe_path}")
        return False
 
 
def print_usb_instructions():
    """Prints instructions for USB deployment."""
    exe_path = os.path.join(DIST_DIR, f"{EXE_NAME}.exe")
    print("""
  ┌─────────────────────────────────────────────────────┐
  │              USB Deployment Instructions             │
  ├─────────────────────────────────────────────────────┤
  │                                                     │
  │  1. Copy the following to your USB drive:           │
  │       dist/SecurityAudit.exe                        │
  │                                                     │
  │  2. On the target machine:                          │
  │       - Plug in the USB drive                       │
  │       - Right-click SecurityAudit.exe               │
  │         (UAC prompt will appear automatically)      │
  │       - Click Yes to grant admin rights             │
  │       - The audit will run and save a PDF report    │
  │         in a 'reports' folder next to the .exe      │
  │                                                     │
  │  Note: Windows Defender may scan the .exe on        │
  │  first run — this is normal for new executables.   │
  │                                                     │
  └─────────────────────────────────────────────────────┘
""")
 
 
# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
 
def main():
    parser = argparse.ArgumentParser(
        description="Build SecurityAudit.exe from source"
    )
    parser.add_argument(
        '--clean',
        action='store_true',
        help="Remove previous build artifacts before building"
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help="Build with console window visible (for debugging)"
    )
    args = parser.parse_args()
 
    print()
    print("=" * 60)
    print("  Windows Security Audit Tool — Build Script")
    print("=" * 60)
 
    # Step 1: Check we're in the right directory
    print("\n  [Pre-flight]")
    if not os.path.exists(ENTRY_SCRIPT):
        print(f"  ✗ Cannot find {ENTRY_SCRIPT}")
        print(f"    Run this script from the project root directory.")
        sys.exit(1)
    print(f"  ✓ Found {ENTRY_SCRIPT}")
 
    if not os.path.exists('modules'):
        print("  ✗ Cannot find modules/ directory")
        sys.exit(1)
    print("  ✓ Found modules/ directory")
 
    # Step 2: Check/install PyInstaller
    print("\n  [Dependencies]")
    if not check_pyinstaller():
        print("  ✗ Cannot proceed without PyInstaller")
        sys.exit(1)
 
    # Step 3: Clean if requested
    if args.clean:
        print("\n  [Cleaning]")
        clean_build_artifacts()
 
    # Step 4: Build
    print("\n  [Building]")
    success = build_exe(debug=args.debug)
 
    if not success:
        print("\n  ✗ Build failed — check the output above for errors")
        sys.exit(1)
 
    # Step 5: Verify
    print("\n  [Verifying]")
    if not verify_output():
        sys.exit(1)
 
    # Step 6: Clean up manifest
    if os.path.exists("SecurityAudit.manifest"):
        os.remove("SecurityAudit.manifest")
 
    # Step 7: Print USB instructions
    print_usb_instructions()
 
    print("=" * 60)
    print("  Build complete!")
    print("=" * 60)
    print()
 
 
if __name__ == "__main__":
    main()
 